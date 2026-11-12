package cmd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	taskrepos "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
)

const localTaskOwner = "local"

type taskBackend interface {
	SubmitTask(context.Context, entities.TaskSpec, string) (client.TaskSubmission, error)
	ListTasks(context.Context, url.Values) (entities.TaskList, error)
	ShowTask(context.Context, string) (entities.Task, error)
	CancelTask(context.Context, string) (entities.Task, error)
	RetryTask(context.Context, string, string) (client.TaskSubmission, error)
	WatchTaskChanges(context.Context, url.Values) (<-chan struct{}, <-chan error)
}

type taskCLIClient struct {
	*client.Client
	tasks taskBackend
	local *localTaskQueue
}

type localTaskQueue struct {
	queue *task.Queue
	kv    *kvstore.LibSQLStore
	api   *client.Client
}

func openLocalTaskQueue(ctx context.Context, path, endpoint, credential string, api *client.Client) (*localTaskQueue, error) {
	if path == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("find local task database directory: %w", err)
		}
		path = filepath.Join(base, "ccplant", "tasks.sqlite3")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("the local task database must be a private regular file (permissions 0600)")
	}

	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	kv, err := kvstore.NewLibSQLStore(ctx, dsn.String(), "")
	if err != nil {
		return nil, fmt.Errorf("open local task database: %w", err)
	}
	// Keep jobs for different endpoints and credentials separate, including
	// when the user reuses one SQLite file for multiple accounts.
	hash := sha256.Sum256([]byte(endpoint + "\x00" + credential))
	repo := repositories.NewTaskRepository(kv, fmt.Sprintf("local-%x", hash[:16]))
	local := &localTaskQueue{kv: kv, api: api}
	local.queue = &task.Queue{Repo: repo, Local: true, RecoverAllocation: local.findSession}
	return local, nil
}

func (l *localTaskQueue) SubmitTask(ctx context.Context, spec entities.TaskSpec, key string) (client.TaskSubmission, error) {
	if spec.Spec.Start.Scope == entities.ScopeTeam && spec.Spec.Start.TeamID == "" {
		return client.TaskSubmission{}, errors.New("team_id is required for a team task")
	}
	return l.submit(ctx, spec, key, nil)
}

func (l *localTaskQueue) submit(ctx context.Context, spec entities.TaskSpec, key string, previous *taskrepos.TaskRecord) (client.TaskSubmission, error) {
	if len(key) > 256 {
		return client.TaskSubmission{}, errors.New("idempotency key must be at most 256 bytes")
	}
	record, err := l.queue.Submit(ctx, spec, localTaskOwner, key, nil, previous)
	if err != nil {
		return client.TaskSubmission{}, err
	}
	return client.TaskSubmission{TaskID: record.ID, State: record.State, SessionID: record.SessionID, RetryOf: record.RetryOf}, nil
}

func (l *localTaskQueue) ListTasks(ctx context.Context, query url.Values) (entities.TaskList, error) {
	team := query.Get("team_id")
	scope := query.Get("scope")
	if scope == "user" && team != "" {
		return entities.TaskList{}, errors.New("team-id cannot be combined with user scope")
	}
	filter := taskrepos.TaskFilter{Team: team, AllTeams: scope == "team" && team == ""}
	if scope == "user" {
		filter.Owner = localTaskOwner
	}
	records, err := l.queue.Repo.List(ctx, filter)
	if err != nil {
		return entities.TaskList{}, err
	}
	result := entities.TaskList{Items: make([]entities.Task, 0, len(records))}
	for _, record := range records {
		result.Items = append(result.Items, record.Task)
	}
	return result, nil
}

func (l *localTaskQueue) ShowTask(ctx context.Context, id string) (entities.Task, error) {
	record, err := l.queue.Repo.Get(ctx, id)
	if err != nil {
		return entities.Task{}, localTaskError(err)
	}
	return record.Task, nil
}

func (l *localTaskQueue) CancelTask(ctx context.Context, id string) (entities.Task, error) {
	record, err := l.queue.Cancel(ctx, id, localTaskOwner)
	if err != nil {
		return entities.Task{}, localTaskError(err)
	}
	return record.Task, nil
}

func (l *localTaskQueue) RetryTask(ctx context.Context, id, key string) (client.TaskSubmission, error) {
	record, err := l.queue.Repo.Get(ctx, id)
	if err != nil {
		return client.TaskSubmission{}, localTaskError(err)
	}
	if record.State != entities.TaskFailed && record.State != entities.TaskCancelled && record.State != entities.TaskExpired {
		return client.TaskSubmission{}, errors.New("only failed, cancelled, or expired tasks can be retried")
	}
	return l.submit(ctx, record.Spec, key, record)
}

func (l *localTaskQueue) WatchTaskChanges(context.Context, url.Values) (<-chan struct{}, <-chan error) {
	// The CLI polls the SQLite database for changes made by other processes.
	return nil, nil
}

func localTaskError(err error) error {
	switch {
	case errors.Is(err, kvstore.ErrNotFound):
		return &client.TaskAPIError{Status: http.StatusNotFound, Message: "local task not found"}
	case errors.Is(err, task.ErrState):
		return &client.TaskAPIError{Status: http.StatusConflict, Message: err.Error()}
	default:
		return err
	}
}

func (l *localTaskQueue) findSession(ctx context.Context, record *taskrepos.TaskRecord) (task.SessionSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tags := map[string]string{entities.LocalTaskTag: record.DispatchID}
	if value, ok := record.Spec.Spec.Start.Tags["hidden"]; ok {
		tags["hidden"] = value
	}
	response, err := l.api.SearchScoped(ctx, "", tags, string(record.Scope), record.TeamID)
	if err != nil {
		return task.SessionSnapshot{}, err
	}
	var match task.SessionSnapshot
	for _, session := range response.Sessions {
		if session.SessionID == "" || session.Tags[entities.LocalTaskTag] != record.DispatchID {
			continue
		}
		if record.SessionID != nil && session.SessionID != *record.SessionID {
			continue
		}
		if match.ID != "" && match.ID != session.SessionID {
			return task.SessionSnapshot{}, errors.New("multiple sessions match this local task")
		}
		match = task.SessionSnapshot{ID: session.SessionID, Status: session.Status}
		if match.Status == "" {
			match.Status = "creating"
		}
	}
	return match, nil
}

func newLocalTaskWorkerCommand() *cobra.Command {
	return taskCLIWithQueue("worker", "Run the SQLite task queue on this computer", cobra.NoArgs, "sqlite", func(cmd *cobra.Command, api *taskCLIClient, _ []string) error {
		if api.local == nil {
			return errors.New("task worker requires --queue sqlite")
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Local task worker is running. Press Ctrl+C to stop.")
		return api.local.run(cmd.Context(), cmd.ErrOrStderr())
	})
}

func (l *localTaskQueue) run(ctx context.Context, out io.Writer) error {
	worker := uuid.NewString()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	nextPrune := time.Now()
	for ctx.Err() == nil {
		claims, err := l.queue.Claim(ctx, worker, 1)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(out, "Local task worker could not read or claim tasks:", err)
		}
		for _, record := range claims {
			if err := l.start(ctx, worker, record); err != nil && !errors.Is(err, task.ErrState) && ctx.Err() == nil {
				fmt.Fprintf(out, "Local task %s could not record startup: %v\n", record.ID, err)
			}
		}
		if time.Now().After(nextPrune) && ctx.Err() == nil {
			if err := l.queue.Prune(ctx); err != nil {
				fmt.Fprintln(out, "Local task history cleanup failed:", err)
			}
			nextPrune = time.Now().Add(time.Hour)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}

func (l *localTaskQueue) start(ctx context.Context, worker string, claimed *taskrepos.TaskRecord) error {
	record, err := l.queue.Begin(ctx, claimed.ID, "", worker, claimed.Generation)
	if err != nil {
		return err
	}
	req := record.Spec.Spec.Start.Request()
	req.Tags = maps.Clone(req.Tags)
	if req.Tags == nil {
		req.Tags = make(map[string]string)
	}
	req.Tags[entities.LocalTaskTag] = record.DispatchID
	startCtx, cancel := context.WithTimeout(ctx, task.StartTimeout)
	id, err := l.api.StartLocalTaskSession(startCtx, req)
	cancel()

	status := http.StatusOK
	notSent := false
	if err != nil {
		status = 0
		var response *client.TaskAPIError
		var dial *net.OpError
		var dns *net.DNSError
		switch {
		case errors.As(err, &response):
			status = response.Status
		case errors.As(err, &dial) && dial.Op == "dial", errors.As(err, &dns):
			// No connection was made. This attempt can be retried safely.
			notSent = true
		}
	}
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finishCancel()
	_, err = l.queue.FinalizeLocalStart(finishCtx, record.ID, worker, record.Generation, status, id, notSent)
	return err
}

func normalizeLocalTaskEndpoint(endpoint string) (string, error) {
	target, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" ||
		(target.Scheme != "http" && target.Scheme != "https") {
		return "", errors.New("SQLite task mode requires an HTTP or HTTPS API endpoint")
	}
	target.Host = strings.ToLower(target.Host)
	return strings.TrimRight(target.String(), "/"), nil
}
