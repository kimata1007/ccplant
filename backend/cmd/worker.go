package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/controlapi"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/schedule"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/slackbot"
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
	slackbotcleanup "github.com/takutakahashi/agentapi-proxy/pkg/slackbot_cleanup"
	"github.com/takutakahashi/agentapi-proxy/pkg/telemetry"
	"k8s.io/client-go/kubernetes/fake"
)

var workerConfigPath string
var workerVerbose bool

var WorkerCmd = &cobra.Command{Use: "worker", Short: "Start AgentAPI background workers", Args: cobra.NoArgs, RunE: runWorkers}

func init() {
	WorkerCmd.Flags().StringVarP(&workerConfigPath, "config", "c", "config.json", "Configuration file path")
	WorkerCmd.Flags().BoolVarP(&workerVerbose, "verbose", "v", false, "Enable verbose logging")
}

func runWorkers(_ *cobra.Command, _ []string) error {
	shutdownTelemetry, err := telemetry.Setup(context.Background())
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTelemetry(shutdownCtx)
	}()

	cfg, err := loadRuntimeConfig(workerConfigPath)
	if err != nil {
		return err
	}
	if err := cfg.ValidateTaskQueue(); err != nil {
		return err
	}
	if workerVerbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	controlURL := cfg.Worker.ControlAPIURL
	if controlURL == "" {
		// Keep config-file compatibility while charts migrate to worker.controlApi.
		// The credential is intentionally not inherited: a provisioner credential
		// must never grant worker-control access.
		controlURL = cfg.KubernetesSession.ProvisionerProxyURL
	}
	if controlURL == "" || cfg.Worker.ControlAPIToken == "" {
		return errors.New("worker control API URL and worker control token are required")
	}
	if cfg.Worker.SessionAPIURL == "" {
		cfg.Worker.SessionAPIURL = controlURL
	}
	runtimeNamespace := resolveKubernetesNamespace(cfg.ScheduleWorker.Namespace, cfg.KubernetesSession.Namespace)
	if err := configureWorkerSlackCredential(cfg); err != nil {
		return err
	}
	remote := controlapi.NewSessionManager(controlURL, cfg.Worker.ControlAPIToken).
		WithExecutionTokenSigningKey(cfg.Worker.ExecutionTokenSigningKey).
		WithSessionAPIURL(cfg.Worker.SessionAPIURL)
	slackRepo := controlapi.NewSlackBotRepository(remote)
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, err = slackRepo.ListAll(startupCtx)
	startupCancel()
	if err != nil {
		return fmt.Errorf("worker control API startup check failed: %w", err)
	}
	leaseClient := remote

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	controlFailure := monitorWorkerControlAPI(ctx, slackRepo, 30*time.Second, 4)
	var mu sync.Mutex
	var workers sync.WaitGroup
	if cfg.TaskQueue.Enabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runTaskWorker(ctx, remote, cfg.TaskQueue.MaxStartingGlobal)
		}()
	}
	var scheduleWorker *remoteScheduleWorker
	var cleanupWorker *slackbotcleanup.LeaderCleanupWorker
	if cfg.ScheduleWorker.Enabled {
		scheduleWorker = newRemoteScheduleWorker(cfg, remote, leaseClient, runtimeNamespace)
		workers.Add(1)
		go func() {
			defer workers.Done()
			scheduleWorker.Run(ctx)
		}()
	}
	if cfg.SlackbotCleanupWorker.Enabled {
		cleanupWorker = newRemoteCleanupWorker(cfg, remote, leaseClient, runtimeNamespace)
		workers.Add(1)
		go func() {
			defer workers.Done()
			cleanupWorker.Run(ctx)
		}()
	}
	socketManager := newRemoteSlackSocketManager(cfg, runtimeNamespace, remote, slackRepo, leaseClient)
	workers.Add(1)
	go func() {
		defer workers.Done()
		socketManager.Run(ctx)
	}()
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-controlFailure:
		cancel()
	}
	mu.Lock()
	defer mu.Unlock()
	if scheduleWorker != nil {
		scheduleWorker.Stop()
	}
	if cleanupWorker != nil {
		cleanupWorker.Stop()
	}
	workers.Wait()
	return runErr
}

func monitorWorkerControlAPI(ctx context.Context, repo *controlapi.SlackBotRepository, interval time.Duration, maxTransientFailures int) <-chan error {
	failed := make(chan error, 1)
	go func() {
		defer close(failed)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		consecutiveFailures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				_, err := repo.ListAll(checkCtx)
				cancel()
				if err == nil {
					consecutiveFailures = 0
					continue
				}
				var statusErr *controlapi.HTTPStatusError
				if errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden || statusErr.StatusCode == http.StatusNotFound) {
					failed <- fmt.Errorf("worker control API permanent failure: %w", err)
					return
				}
				consecutiveFailures++
				log.Printf("[WORKER_CONTROL] API check failed (%d/%d): %v", consecutiveFailures, maxTransientFailures, err)
				if consecutiveFailures >= maxTransientFailures {
					failed <- fmt.Errorf("worker control API unavailable after %d consecutive checks: %w", consecutiveFailures, err)
					return
				}
			}
		}
	}()
	return failed
}

const workerDefaultSlackSecretName = "agentapi-worker-slack-default"

func configureWorkerSlackCredential(cfg *config.Config) error {
	if cfg.Slack.AppToken == "" && cfg.Slack.BotToken == "" {
		return nil
	}
	if cfg.Slack.AppToken == "" || cfg.Slack.BotToken == "" {
		return errors.New("worker Slack Socket Mode requires both app and bot tokens")
	}

	cfg.Slack.AppTokenSecretName = workerDefaultSlackSecretName
	cfg.Slack.AppTokenSecretKey = "app-token"
	cfg.KubernetesSession.SlackBotTokenSecretName = workerDefaultSlackSecretName
	cfg.KubernetesSession.SlackBotTokenSecretKey = "bot-token"
	return nil
}

func newRemoteSlackSocketManager(cfg *config.Config, runtimeNamespace string, remote *controlapi.SessionManager, repo *controlapi.SlackBotRepository, leaseClient schedule.LeaseClient) *slackbot.SlackSocketManager {
	resolver := slackbot.NewSlackChannelResolver(fake.NewSimpleClientset(), "worker").WithoutPersistentCache()
	eventClient := &workerSlackEventClient{SlackChannelResolver: resolver, repo: repo, defaultAppToken: cfg.Slack.AppToken, defaultBotToken: cfg.Slack.BotToken}
	handler := slackbot.NewSlackBotEventHandler(repo, remote, cfg.KubernetesSession.SlackBotTokenSecretName, cfg.KubernetesSession.SlackBotTokenSecretKey, eventClient, cfg.Webhook.BaseURL, cfg.Slack.DryRun, nil)
	appSecret := cfg.Slack.AppTokenSecretName
	if appSecret == "" {
		appSecret = cfg.KubernetesSession.SlackBotTokenSecretName
	}
	appKey := cfg.Slack.AppTokenSecretKey
	if appKey == "" {
		appKey = "app-token"
	}
	election := workerElection(cfg.ScheduleWorker.LeaseDuration, cfg.ScheduleWorker.RenewDeadline, cfg.ScheduleWorker.RetryPeriod, "", runtimeNamespace)
	return slackbot.NewSlackSocketManager(fake.NewSimpleClientset(), runtimeNamespace, repo, handler, resolver, slackbot.SlackSocketManagerConfig{DefaultAppToken: cfg.Slack.AppToken, DefaultBotToken: cfg.Slack.BotToken, DefaultAppTokenSecretName: appSecret, DefaultAppTokenSecretKey: appKey, DefaultBotTokenSecretName: cfg.KubernetesSession.SlackBotTokenSecretName, DefaultBotTokenSecretKey: cfg.KubernetesSession.SlackBotTokenSecretKey, LeaderElectionConfig: election, LeaderElectionClient: leaseClient})
}

type workerSlackEventClient struct {
	*slackbot.SlackChannelResolver
	repo                             *controlapi.SlackBotRepository
	defaultAppToken, defaultBotToken string
}

func (c *workerSlackEventClient) GetBotToken(ctx context.Context, secretName, secretKey string) (string, error) {
	if secretName == workerDefaultSlackSecretName {
		if secretKey == "app-token" {
			return c.defaultAppToken, nil
		}
		return c.defaultBotToken, nil
	}
	bots, err := c.repo.ListAll(ctx)
	if err != nil {
		return "", err
	}
	for _, bot := range bots {
		if bot.BotTokenSecretName() == secretName {
			app, token, err := c.repo.Credentials(ctx, bot.ID())
			if secretKey == bot.AppTokenSecretKey() {
				return app, err
			}
			return token, err
		}
	}
	return "", fmt.Errorf("Slack credential not found")
}

func (c *workerSlackEventClient) GetSettingsSecretValue(ctx context.Context, _ string, secretID, key string) (string, error) {
	bots, err := c.repo.ListAll(ctx)
	if err != nil {
		return "", err
	}
	for _, bot := range bots {
		if bot.SettingsSecretID() == secretID {
			app, token, err := c.repo.Credentials(ctx, bot.ID())
			if key == bot.SettingsAppTokenKey() {
				return app, err
			}
			return token, err
		}
	}
	return "", fmt.Errorf("Slack credential not found")
}

type remoteScheduleWorker struct {
	client        *controlapi.SessionManager
	sessionAPIURL string
	elector       *schedule.LeaderElector
	interval      time.Duration
}

func newRemoteScheduleWorker(cfg *config.Config, remote *controlapi.SessionManager, leaseClient schedule.LeaseClient, namespace string) *remoteScheduleWorker {
	interval, _ := time.ParseDuration(cfg.ScheduleWorker.CheckInterval)
	if interval <= 0 {
		interval = 30 * time.Second
	}
	election := workerElection(cfg.ScheduleWorker.LeaseDuration, cfg.ScheduleWorker.RenewDeadline, cfg.ScheduleWorker.RetryPeriod, schedule.ScheduleWorkerLeaseName, namespace)
	return &remoteScheduleWorker{client: remote, sessionAPIURL: cfg.Worker.SessionAPIURL, elector: schedule.NewLeaderElector(leaseClient, election), interval: interval}
}

func (w *remoteScheduleWorker) Run(ctx context.Context) {
	w.elector.Run(ctx, func(leaderCtx context.Context) {
		log.Printf("[SCHEDULE_WORKER] Started API polling with check interval %v", w.interval)
		w.process(leaderCtx)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-leaderCtx.Done():
				return
			case <-ticker.C:
				w.process(leaderCtx)
			}
		}
	}, nil)
}

func (w *remoteScheduleWorker) process(ctx context.Context) {
	telemetry.OperationVoid(ctx, "cmd.remoteScheduleWorker.process", w.processOnce)
}

func (w *remoteScheduleWorker) processOnce(ctx context.Context) {
	jobs, err := w.client.ClaimDueSchedules(ctx)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] Claim API failed: %v", err)
		return
	}
	for _, job := range jobs {
		var sessionID string
		var sessionReused bool
		var createErr error
		for attempt := 1; attempt <= 3; attempt++ {
			sessionID, sessionReused, createErr = w.client.StartScheduledSession(ctx, w.sessionAPIURL, job)
			if createErr == nil {
				break
			}
			if attempt < 3 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(attempt) * time.Second):
				}
			}
		}
		status, message := "success", ""
		if createErr != nil {
			status, message = "failed", createErr.Error()
		}
		if err := w.client.FinalizeSchedule(ctx, job, status, sessionID, message, sessionReused); err != nil {
			log.Printf("[SCHEDULE_WORKER] Finalize failed for %s: %v", job.ScheduleID, err)
			continue
		}
		log.Printf("[SCHEDULE_WORKER] schedule=%s execution=%s status=%s session=%s reused=%t", job.ScheduleID, job.ExecutionID, status, sessionID, sessionReused)
	}
}

func (w *remoteScheduleWorker) Stop() {}

func newRemoteCleanupWorker(cfg *config.Config, remote *controlapi.SessionManager, leaseClient schedule.LeaseClient, namespace string) *slackbotcleanup.LeaderCleanupWorker {
	check, _ := time.ParseDuration(cfg.SlackbotCleanupWorker.CheckInterval)
	ttl, _ := time.ParseDuration(cfg.SlackbotCleanupWorker.SessionTTL)
	ttlCheck, _ := time.ParseDuration(cfg.SlackbotCleanupWorker.SessionTTLCheckInterval)
	election := workerElection(cfg.SlackbotCleanupWorker.LeaseDuration, cfg.SlackbotCleanupWorker.RenewDeadline, cfg.SlackbotCleanupWorker.RetryPeriod, schedule.SlackbotCleanupWorkerLeaseName, namespace)
	return slackbotcleanup.NewLeaderCleanupWorker(remote, leaseClient, slackbotcleanup.CleanupWorkerConfig{CheckInterval: check, SessionTTL: ttl, SessionTTLCheckInterval: ttlCheck, Enabled: true, DryRun: cfg.SlackbotCleanupWorker.DryRun}, election)
}

func workerElection(lease, renew, retry, name, namespace string) schedule.LeaderElectionConfig {
	l, _ := time.ParseDuration(lease)
	r, _ := time.ParseDuration(renew)
	p, _ := time.ParseDuration(retry)
	if l <= 0 {
		l = 9 * time.Minute
	}
	if r <= 0 {
		r = 6 * time.Minute
	}
	if p <= 0 {
		p = time.Minute
	}
	return schedule.LeaderElectionConfig{LeaseDuration: l, RenewDeadline: r, RetryPeriod: p, LeaseName: name, Namespace: namespace}
}

func loadRuntimeConfig(path string) (*config.Config, error) {
	cfg, err := config.LoadConfig(path)
	if err == nil {
		return cfg, nil
	}
	log.Printf("Failed to load config from %s, trying environment: %v", path, err)
	return config.LoadConfig("")
}
