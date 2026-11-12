package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/takutakahashi/agentapi-proxy/internal/app"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/controlapi"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	mcpiface "github.com/takutakahashi/agentapi-proxy/internal/interfaces/mcp"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/schedule"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/slackbot"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/webhook"
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
	prommetrics "github.com/takutakahashi/agentapi-proxy/pkg/metrics"
	slackbotcleanup "github.com/takutakahashi/agentapi-proxy/pkg/slackbot_cleanup"
	stock_inventory "github.com/takutakahashi/agentapi-proxy/pkg/stock_inventory"
	"github.com/takutakahashi/agentapi-proxy/pkg/telemetry"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	port        string
	cfg         string
	verbose     bool
	metricsPort int
)

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the AgentAPI Proxy Server",
	Long:  "Start the reverse proxy server for AgentAPI that routes requests based on configuration",
	Run:   runProxy,
}

// Legacy constructors remain temporarily for focused unit coverage while all
// production worker wiring lives in worker.go and uses the control API.
var _ = []any{startScheduleWorker, startSlackbotCleanupWorker, startStockInventoryWorker, startSlackSocketManager}

func resolveKubernetesNamespace(candidates ...string) string {
	for _, candidate := range candidates {
		if namespace := strings.TrimSpace(candidate); namespace != "" {
			return namespace
		}
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if namespace := strings.TrimSpace(string(data)); namespace != "" {
			return namespace
		}
	}
	return "default"
}

func resolvePersistenceNamespace(configData *config.Config) string {
	if configData != nil {
		if namespace := strings.TrimSpace(configData.KVStore.Namespace); namespace != "" {
			return namespace
		}
	}
	if namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); namespace != "" {
		return namespace
	}
	return "default"
}

func init() {
	ServerCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to listen on")
	ServerCmd.Flags().StringVarP(&cfg, "config", "c", "config.json", "Configuration file path")
	ServerCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	ServerCmd.Flags().IntVar(&metricsPort, "metrics-port", 0, "Prometheus metrics port (disabled when 0)")

	// Bind flags to viper
	if err := viper.BindPFlag("port", ServerCmd.Flags().Lookup("port")); err != nil {
		log.Printf("Failed to bind port flag: %v", err)
	}
	if err := viper.BindPFlag("config", ServerCmd.Flags().Lookup("config")); err != nil {
		log.Printf("Failed to bind config flag: %v", err)
	}
	if err := viper.BindPFlag("verbose", ServerCmd.Flags().Lookup("verbose")); err != nil {
		log.Printf("Failed to bind verbose flag: %v", err)
	}
}

func runProxy(cmd *cobra.Command, args []string) {
	// Register shutdown handling before initialization so an early SIGTERM is
	// never delivered with the default (process-terminating) behavior.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)

	shutdownTelemetry, err := telemetry.Setup(context.Background())
	if err != nil {
		log.Printf("[OTEL] OpenTelemetry initialization failed; continuing without export: %v", err)
		shutdownTelemetry = func(context.Context) error { return nil }
	} else if telemetry.Enabled() {
		log.Printf("[OTEL] OpenTelemetry OTLP trace and metric export enabled")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownTelemetry(ctx); err != nil {
			log.Printf("[OTEL] OpenTelemetry shutdown failed: %v", err)
		}
	}()

	if verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	configData, err := config.LoadConfig(cfg)
	if err != nil {
		log.Printf("Failed to load config from %s, trying to load from environment variables: %v", cfg, err)
		// Try to load configuration from environment variables
		var envErr error
		configData, envErr = config.LoadConfig("")
		if envErr != nil {
			log.Printf("Failed to load config from environment variables, using defaults: %v", envErr)
			configData = config.DefaultConfig()
		}
	}
	if err := configData.ValidateTaskQueue(); err != nil {
		log.Fatal(err)
	}
	if err := validateServerRedis(configData); err != nil {
		log.Fatal(err)
	}

	proxyServer := app.NewServer(configData, verbose)
	// From this point onward every subsystem is initialized from the effective
	// runtime snapshot (startup config overlaid with the latest versioned KV
	// settings), rather than from the raw Helm/environment layer.
	configData = proxyServer.GetConfig()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	collectors := []prometheus.Collector{prommetrics.NewStatusCollector(
		"agentapi_sessions",
		"Current number of AgentAPI sessions by status.",
		[]string{"creating", "starting", "running", "active", "stable", "suspending", "suspended", "resuming", "restoring", "unhealthy", "stopped", "error", "timeout", "unknown"},
		func(context.Context) (map[string]int, error) {
			counts := make(map[string]int)
			for _, session := range proxyServer.GetSessionManager().ListSessions(entities.SessionFilter{}) {
				counts[session.Status()]++
			}
			return counts, nil
		},
	)}
	if metrics := proxyServer.TaskQueueMetrics(); metrics != nil {
		collectors = append(collectors, metrics)
	}
	startMetricsServer(serverCtx, metricsPort, collectors...)

	// Run the idempotent legacy→multi API token migration and load all named
	// tokens into the auth service. Any migration conflict or bootstrap load
	// error is fatal here: serving traffic with a partially migrated or
	// partially loaded auth map would be unsafe. This keeps log.Fatal out of
	// library code (internal/app) while still making startup fail-safe.
	if err := proxyServer.InitAPITokens(context.Background()); err != nil {
		log.Fatalf("[SERVER] API token initialization failed, refusing to serve: %v", err)
	}

	// Keep named-token revocation eventually consistent across replicas.
	// Local revocation is immediate; other replicas drop a deleted token on
	// the next reconciliation pass. Legacy static/personal API keys are
	// unaffected.
	proxyServer.StartAPITokenReconciler(serverCtx, 30*time.Second)
	proxyServer.StartSessionCountWorker(serverCtx)
	// Finalize routes whose owning manager/runner is gone so lost lifecycle
	// events can never leave undeletable stale sessions behind.
	proxyServer.StartSessionRouteReconciler(serverCtx)

	// Start session monitoring after proxy is initialized
	proxyServer.StartMonitoring()

	// Register schedule handlers (independent of worker status, but requires Kubernetes mode)
	registerScheduleHandlers(proxyServer)

	// Register webhook handlers (requires Kubernetes mode)
	registerWebhookHandlers(configData, proxyServer)

	// Register SlackBot handlers (requires Kubernetes mode)
	registerSlackBotHandlers(configData, proxyServer)

	// Register MCP handler
	registerMCPHandler(proxyServer, port)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting agentapi-proxy on port %s", port)
		if err := proxyServer.GetEcho().Start(":" + port); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	<-quit

	log.Println("Shutdown signal received, shutting down gracefully...")
	cancelServer()

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the proxy and all sessions
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- proxyServer.Shutdown(25 * time.Second)
	}()

	// Shutdown the HTTP server
	serverShutdownDone := make(chan error, 1)
	go func() {
		serverShutdownDone <- proxyServer.GetEcho().Shutdown(ctx)
	}()

	// Wait for both shutdowns to complete
	var proxyErr, serverErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-shutdownDone:
			proxyErr = err
		case err := <-serverShutdownDone:
			serverErr = err
		case <-ctx.Done():
			log.Printf("Shutdown timeout reached")
			return
		}
	}

	if proxyErr != nil {
		log.Printf("Proxy shutdown error: %v", proxyErr)
	}
	if serverErr != nil {
		log.Printf("Server shutdown error: %v", serverErr)
	}

	log.Printf("Server shutdown complete")
}

func validateServerRedis(cfg *config.Config) error {
	if cfg == nil || strings.TrimSpace(cfg.Redis.Addr) == "" {
		return errors.New("Redis is required; configure redis.addr or AGENTAPI_REDIS_ADDR")
	}
	return nil
}

// newTriggerSessionManager routes API-side triggers through the same /start
// endpoint as workers, so pool selection and provisioning remain API-owned.
func newTriggerSessionManager(cfg *config.Config) *controlapi.SessionManager {
	localURL := "http://127.0.0.1:" + port
	apiURL := cfg.Worker.SessionAPIURL
	if apiURL == "" {
		apiURL = localURL
	}
	return controlapi.NewSessionManager(localURL, cfg.Worker.ControlAPIToken).
		WithExecutionTokenSigningKey(cfg.Worker.ExecutionTokenSigningKey).
		WithSessionAPIURL(apiURL)
}

// registerScheduleHandlers registers schedule REST API handlers
func registerScheduleHandlers(proxyServer *app.Server) {
	log.Printf("[SCHEDULE_HANDLERS] Registering schedule handlers...")

	// Use the API-owned manager shared with the worker-control endpoint.
	scheduleManager := proxyServer.GetScheduleManager()

	// Create and register schedule handlers
	scheduleHandlers := schedule.NewHandlers(scheduleManager, newTriggerSessionManager(proxyServer.GetConfig()), proxyServer.GetSessionProfileRepository()).
		WithSettingsRepository(proxyServer.GetSettingsRepository())
	proxyServer.AddCustomHandler(scheduleHandlers)

	log.Printf("[SCHEDULE_HANDLERS] Schedule handlers registered successfully")
}

// startScheduleWorker starts the schedule worker with leader election
func startScheduleWorker(configData *config.Config, proxyServer *app.Server) *schedule.LeaderWorker {
	log.Printf("[SCHEDULE_WORKER] Initializing schedule worker...")

	redisClient, err := newWorkerRedisClient(configData)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] %v", err)
		return nil
	}

	// Determine namespace
	namespace := resolveKubernetesNamespace(configData.ScheduleWorker.Namespace, configData.KubernetesSession.Namespace)

	// Create schedule manager
	scheduleManager := schedule.NewKubernetesManager(proxyServer.GetPersistenceClient(), namespace)

	// Parse worker config durations
	checkInterval, err := time.ParseDuration(configData.ScheduleWorker.CheckInterval)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] Invalid check_interval, using default 30s: %v", err)
		checkInterval = 30 * time.Second
	}

	workerConfig := schedule.WorkerConfig{
		CheckInterval: checkInterval,
		Enabled:       true,
	}

	// Parse leader election config durations
	leaseDuration, err := time.ParseDuration(configData.ScheduleWorker.LeaseDuration)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] Invalid lease_duration, using default 9m: %v", err)
		leaseDuration = 9 * time.Minute
	}

	renewDeadline, err := time.ParseDuration(configData.ScheduleWorker.RenewDeadline)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] Invalid renew_deadline, using default 6m: %v", err)
		renewDeadline = 6 * time.Minute
	}

	retryPeriod, err := time.ParseDuration(configData.ScheduleWorker.RetryPeriod)
	if err != nil {
		log.Printf("[SCHEDULE_WORKER] Invalid retry_period, using default 1m: %v", err)
		retryPeriod = time.Minute
	}

	electionConfig := schedule.LeaderElectionConfig{
		LeaseDuration: leaseDuration,
		RenewDeadline: renewDeadline,
		RetryPeriod:   retryPeriod,
		LeaseName:     schedule.ScheduleWorkerLeaseName,
		Namespace:     namespace,
	}

	// Create leader worker
	leaderWorker := schedule.NewLeaderWorker(
		scheduleManager,
		proxyServer.GetSessionManager(),
		schedule.NewRedisLeaseClient(redisClient),
		workerConfig,
		electionConfig,
		proxyServer.GetSessionProfileRepository(),
	).WithSettingsRepository(proxyServer.GetSettingsRepository())

	// Start leader worker in background
	go leaderWorker.Run(context.Background())

	log.Printf("[SCHEDULE_WORKER] Schedule worker started in namespace: %s", namespace)
	return leaderWorker
}

// startSlackbotCleanupWorker starts the Slackbot session cleanup worker with leader election.
// It follows the same pattern as startScheduleWorker.
func startSlackbotCleanupWorker(configData *config.Config, proxyServer *app.Server) *slackbotcleanup.LeaderCleanupWorker {
	log.Printf("[SLACKBOT_CLEANUP] Initializing Slackbot cleanup worker...")

	redisClient, err := newWorkerRedisClient(configData)
	if err != nil {
		log.Printf("[SLACKBOT_CLEANUP] %v", err)
		return nil
	}

	namespace := resolveKubernetesNamespace(configData.KubernetesSession.Namespace)

	checkInterval, err := time.ParseDuration(configData.SlackbotCleanupWorker.CheckInterval)
	if err != nil || checkInterval <= 0 {
		log.Printf("[SLACKBOT_CLEANUP] Invalid check_interval, using default 1h: %v", err)
		checkInterval = 1 * time.Hour
	}

	sessionTTL, err := time.ParseDuration(configData.SlackbotCleanupWorker.SessionTTL)
	if err != nil || sessionTTL <= 0 {
		log.Printf("[SLACKBOT_CLEANUP] Invalid session_ttl, using default 72h: %v", err)
		sessionTTL = 72 * time.Hour
	}

	sessionTTLCheckInterval := 1 * time.Minute
	if configData.SlackbotCleanupWorker.SessionTTLCheckInterval != "" {
		if d, err := time.ParseDuration(configData.SlackbotCleanupWorker.SessionTTLCheckInterval); err == nil && d > 0 {
			sessionTTLCheckInterval = d
		} else {
			log.Printf("[SLACKBOT_CLEANUP] Invalid session_ttl_check_interval, using default 1m: %v", err)
		}
	}

	workerConfig := slackbotcleanup.CleanupWorkerConfig{
		CheckInterval:           checkInterval,
		SessionTTLCheckInterval: sessionTTLCheckInterval,
		SessionTTL:              sessionTTL,
		Enabled:                 true,
		DryRun:                  configData.SlackbotCleanupWorker.DryRun,
	}

	leaseDuration, err := time.ParseDuration(configData.SlackbotCleanupWorker.LeaseDuration)
	if err != nil || leaseDuration <= 0 {
		log.Printf("[SLACKBOT_CLEANUP] Invalid lease_duration, using default 9m: %v", err)
		leaseDuration = 9 * time.Minute
	}

	renewDeadline, err := time.ParseDuration(configData.SlackbotCleanupWorker.RenewDeadline)
	if err != nil || renewDeadline <= 0 {
		log.Printf("[SLACKBOT_CLEANUP] Invalid renew_deadline, using default 6m: %v", err)
		renewDeadline = 6 * time.Minute
	}

	retryPeriod, err := time.ParseDuration(configData.SlackbotCleanupWorker.RetryPeriod)
	if err != nil || retryPeriod <= 0 {
		log.Printf("[SLACKBOT_CLEANUP] Invalid retry_period, using default 1m: %v", err)
		retryPeriod = time.Minute
	}

	electionConfig := schedule.LeaderElectionConfig{
		LeaseDuration: leaseDuration,
		RenewDeadline: renewDeadline,
		RetryPeriod:   retryPeriod,
		Namespace:     namespace,
		// LeaseName is overridden inside NewLeaderCleanupWorker to "agentapi-slackbot-cleanup-worker"
	}

	leaderCleanupWorker := slackbotcleanup.NewLeaderCleanupWorker(
		proxyServer.GetSessionManager(),
		schedule.NewRedisLeaseClient(redisClient),
		workerConfig,
		electionConfig,
	)

	go leaderCleanupWorker.Run(context.Background())

	dryRunNote := ""
	if configData.SlackbotCleanupWorker.DryRun {
		dryRunNote = " [DRY-RUN]"
	}
	log.Printf("[SLACKBOT_CLEANUP] Slackbot cleanup worker started in namespace: %s (TTL: %v)%s", namespace, sessionTTL, dryRunNote)
	return leaderCleanupWorker
}

// startStockInventoryWorker starts the stock session inventory worker with leader election.
// It ensures a configurable number of pre-warmed stock sessions are always available.
func startStockInventoryWorker(configData *config.Config, proxyServer *app.Server) *stock_inventory.LeaderWorker {
	log.Printf("[STOCK_INVENTORY] Initializing stock inventory worker...")

	redisClient, err := newWorkerRedisClient(configData)
	if err != nil {
		log.Printf("[STOCK_INVENTORY] %v", err)
		return nil
	}

	namespace := resolveKubernetesNamespace(configData.StockInventoryWorker.Namespace, configData.KubernetesSession.Namespace)

	// KubernetesSessionManager implements StockRepository.
	stockRepo, ok := proxyServer.GetSessionManager().(stock_inventory.StockRepository)
	if !ok {
		log.Printf("[STOCK_INVENTORY] Session manager does not implement StockRepository, stock inventory worker disabled")
		return nil
	}

	checkInterval, err := time.ParseDuration(configData.StockInventoryWorker.CheckInterval)
	if err != nil {
		log.Printf("[STOCK_INVENTORY] Invalid check_interval, using default 30s: %v", err)
		checkInterval = 30 * time.Second
	}

	targetCount := configData.StockInventoryWorker.TargetCount
	if targetCount <= 0 {
		targetCount = 2
	}
	pools := buildStockInventoryPools(configData.StockInventoryWorker, targetCount)

	// Note: Sandbox (network filter) is always enabled - the SandboxEnabled config is ignored.
	workerConfig := stock_inventory.WorkerConfig{
		CheckInterval: checkInterval,
		TargetCount:   targetCount,
		Requirements: stock_inventory.StockRequirements{
			DinD: configData.StockInventoryWorker.DockerEnabled,
		},
		Pools:   pools,
		Enabled: true,
	}

	leaseDuration, err := time.ParseDuration(configData.StockInventoryWorker.LeaseDuration)
	if err != nil {
		leaseDuration = 9 * time.Minute
	}
	renewDeadline, err := time.ParseDuration(configData.StockInventoryWorker.RenewDeadline)
	if err != nil {
		renewDeadline = 6 * time.Minute
	}
	retryPeriod, err := time.ParseDuration(configData.StockInventoryWorker.RetryPeriod)
	if err != nil {
		retryPeriod = time.Minute
	}

	electionConfig := schedule.LeaderElectionConfig{
		LeaseDuration: leaseDuration,
		RenewDeadline: renewDeadline,
		RetryPeriod:   retryPeriod,
		LeaseName:     schedule.StockInventoryWorkerLeaseName,
		Namespace:     namespace,
	}

	leaderWorker := stock_inventory.NewLeaderWorker(stockRepo, schedule.NewRedisLeaseClient(redisClient), workerConfig, electionConfig)

	go leaderWorker.Run(context.Background())

	poolCount := len(pools)
	if poolCount == 0 {
		poolCount = 1
	}
	log.Printf("[STOCK_INVENTORY] Stock inventory worker started in namespace: %s (pools: %d)",
		namespace, poolCount)
	return leaderWorker
}

func buildStockInventoryPools(workerConfig config.StockInventoryWorkerConfig, defaultTargetCount int) []stock_inventory.StockPool {
	if len(workerConfig.Pools) == 0 {
		return nil
	}

	pools := make([]stock_inventory.StockPool, 0, len(workerConfig.Pools))
	for _, poolConfig := range workerConfig.Pools {
		targetCount := poolConfig.TargetCount
		if targetCount < 0 {
			targetCount = defaultTargetCount
		}
		// Note: Sandbox (network filter) is always enabled - SandboxEnabled is ignored.
		pools = append(pools, stock_inventory.StockPool{
			Name:        poolConfig.Name,
			TargetCount: targetCount,
			Requirements: stock_inventory.StockRequirements{
				DinD: poolConfig.DockerEnabled,
			},
		})
	}
	return pools
}

// registerWebhookHandlers registers webhook REST API handlers
func registerWebhookHandlers(configData *config.Config, proxyServer *app.Server) {
	log.Printf("[WEBHOOK_HANDLERS] Registering webhook handlers...")

	// Webhooks are persisted through the application KV store, so their logical
	// namespace must not depend on a mounted Kubernetes ServiceAccount token.
	namespace := resolvePersistenceNamespace(configData)

	// Create webhook repository (clean architecture)
	webhookRepo := repositories.NewKubernetesWebhookRepository(proxyServer.GetPersistenceClient(), namespace)

	// Set default GitHub Enterprise host if configured
	if configData.Webhook.GitHubEnterpriseHost != "" {
		webhookRepo.SetDefaultGitHubEnterpriseHost(configData.Webhook.GitHubEnterpriseHost)
		log.Printf("[WEBHOOK_HANDLERS] Default GitHub Enterprise host configured: %s", configData.Webhook.GitHubEnterpriseHost)
	}

	// Create and register webhook handlers with baseURL from config
	webhookHandlers := webhook.NewHandlers(webhookRepo, newTriggerSessionManager(configData), configData.Webhook.BaseURL, proxyServer.GetSessionProfileRepository()).
		WithSettingsRepository(proxyServer.GetSettingsRepository()).
		WithGitHubApplicationUserResolver(proxyServer)
	proxyServer.AddCustomHandler(webhookHandlers)

	if configData.Webhook.BaseURL != "" {
		log.Printf("[WEBHOOK_HANDLERS] Webhook base URL configured: %s", configData.Webhook.BaseURL)
	} else {
		log.Printf("[WEBHOOK_HANDLERS] Webhook base URL not configured, will auto-detect from request headers")
	}
	log.Printf("[WEBHOOK_HANDLERS] Webhook handlers registered successfully")
}

func newWorkerRedisClient(configData *config.Config) (redis.UniversalClient, error) {
	if strings.TrimSpace(configData.Redis.Addr) == "" {
		return nil, schedule.ErrRedisRequired
	}
	opts := &redis.Options{Addr: configData.Redis.Addr, Password: configData.Redis.Password, DB: configData.Redis.DB}
	if d, err := time.ParseDuration(configData.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(configData.Redis.ReadTimeout); err == nil && d > 0 {
		opts.ReadTimeout = d
	}
	if d, err := time.ParseDuration(configData.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if configData.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

// registerSlackBotHandlers registers SlackBot management REST API handlers
func registerSlackBotHandlers(configData *config.Config, proxyServer *app.Server) {
	log.Printf("[SLACKBOT_HANDLERS] Registering slackbot handlers...")

	// SlackBots are persisted through the application KV store, so their logical
	// namespace must not depend on a mounted Kubernetes ServiceAccount token.
	namespace := resolvePersistenceNamespace(configData)

	// Create SlackBot repository
	slackbotRepo := repositories.NewKubernetesSlackBotRepository(proxyServer.GetPersistenceClient(), namespace)

	// Create and register SlackBot management handlers (no event reception - handled by Socket Mode)
	slackbotHandlers := slackbot.NewHandlers(slackbotRepo, newTriggerSessionManager(configData), proxyServer.GetSessionProfileRepository(), proxyServer.GetSettingsRepository())
	proxyServer.AddCustomHandler(slackbotHandlers)

	log.Printf("[SLACKBOT_HANDLERS] SlackBot management handlers registered successfully")
}

// startSlackSocketManager starts the Slack Socket Mode manager with per-bot leader election
func startSlackSocketManager(configData *config.Config, proxyServer *app.Server) {
	log.Printf("[SOCKET_MANAGER] Initializing Slack Socket Mode manager...")

	// Create Kubernetes client
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		log.Printf("[SOCKET_MANAGER] Kubernetes config not available, skipping Socket Mode: %v", err)
		return
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Printf("[SOCKET_MANAGER] Failed to create Kubernetes client, skipping Socket Mode: %v", err)
		return
	}

	// Keep application records in the KV-store namespace. The runtime namespace
	// remains responsible for Kubernetes leases and operational Secrets.
	persistenceNamespace := resolvePersistenceNamespace(configData)
	runtimeNamespace := resolveKubernetesNamespace(configData.ScheduleWorker.Namespace, configData.KubernetesSession.Namespace)

	// Create dependencies
	slackbotRepo := repositories.NewKubernetesSlackBotRepository(proxyServer.GetPersistenceClient(), persistenceNamespace)
	channelResolver := slackbot.NewSlackChannelResolver(proxyServer.GetPersistenceClient(), persistenceNamespace).WithSecretClient(client).WithSettingsRepository(proxyServer.GetSettingsRepository())

	eventHandler := slackbot.NewSlackBotEventHandler(
		slackbotRepo,
		newTriggerSessionManager(configData),
		configData.KubernetesSession.SlackBotTokenSecretName,
		configData.KubernetesSession.SlackBotTokenSecretKey,
		channelResolver,
		configData.Webhook.BaseURL,
		configData.Slack.DryRun,
		proxyServer.GetSessionProfileRepository(),
	).WithSettingsRepository(proxyServer.GetSettingsRepository())
	if configData.Slack.DryRun {
		log.Printf("[SOCKET_MANAGER] Slack dry-run mode enabled: session creation and Slack posts will be logged only")
	}

	// Resolve App token secret (defaults to SlackBotTokenSecretName if not set)
	appTokenSecretName := configData.Slack.AppTokenSecretName
	if appTokenSecretName == "" {
		appTokenSecretName = configData.KubernetesSession.SlackBotTokenSecretName
	}
	appTokenSecretKey := configData.Slack.AppTokenSecretKey
	if appTokenSecretKey == "" {
		appTokenSecretKey = "app-token"
	}

	// Parse leader election config durations
	leaseDuration, err := time.ParseDuration(configData.ScheduleWorker.LeaseDuration)
	if err != nil {
		leaseDuration = 9 * time.Minute
	}
	renewDeadline, err := time.ParseDuration(configData.ScheduleWorker.RenewDeadline)
	if err != nil {
		renewDeadline = 6 * time.Minute
	}
	retryPeriod, err := time.ParseDuration(configData.ScheduleWorker.RetryPeriod)
	if err != nil {
		retryPeriod = time.Minute
	}

	electionConfig := schedule.LeaderElectionConfig{
		LeaseDuration: leaseDuration,
		RenewDeadline: renewDeadline,
		RetryPeriod:   retryPeriod,
		Namespace:     runtimeNamespace,
	}

	managerConfig := slackbot.SlackSocketManagerConfig{
		DefaultAppTokenSecretName: appTokenSecretName,
		DefaultAppTokenSecretKey:  appTokenSecretKey,
		DefaultBotTokenSecretName: configData.KubernetesSession.SlackBotTokenSecretName,
		DefaultBotTokenSecretKey:  configData.KubernetesSession.SlackBotTokenSecretKey,
		LeaderElectionConfig:      electionConfig,
	}
	redisClient, err := newWorkerRedisClient(configData)
	if err != nil {
		log.Printf("[SOCKET_MANAGER] %v", err)
		return
	}
	managerConfig.RedisClient = redisClient

	manager := slackbot.NewSlackSocketManager(
		client,
		persistenceNamespace,
		slackbotRepo,
		eventHandler,
		channelResolver,
		managerConfig,
	)

	go manager.Run(context.Background())

	log.Printf("[SOCKET_MANAGER] Slack Socket Mode manager started with persistence namespace %s and runtime namespace %s", persistenceNamespace, runtimeNamespace)
}

// registerMCPHandler registers MCP HTTP handler
func registerMCPHandler(proxyServer *app.Server, port string) {
	log.Printf("[MCP_HANDLER] Registering MCP handler...")

	// Create and register MCP handler with server dependencies
	mcpHandler := mcpiface.NewMCPHandler(proxyServer)
	proxyServer.AddCustomHandler(mcpHandler)

	log.Printf("[MCP_HANDLER] MCP handler registered successfully at /mcp")
}
