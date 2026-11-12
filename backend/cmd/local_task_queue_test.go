package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/pkg/client"
)

const localTaskYAML = `apiVersion: ccplant.io/v1alpha1
kind: Task
metadata:
  name: Work from a laptop
spec:
  start:
    session_profile_id: demo
    params:
      message: Check the project.
`

func TestSQLiteTaskCommandsWorkOffline(t *testing.T) {
	t.Setenv("CCPLANT_TASK_QUEUE", "")
	t.Setenv("AGENTAPI_KEY", "test-credential")
	dir := t.TempDir()
	database, spec := filepath.Join(dir, "task queue.sqlite3"), filepath.Join(dir, "task.yaml")
	require.NoError(t, os.WriteFile(spec, []byte(localTaskYAML), 0600))
	run := func(args ...string) string {
		t.Helper()
		root := &cobra.Command{Use: "ccplant"}
		root.AddCommand(TaskCommands()...)
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs(append(args, "--queue", "sqlite", "--sqlite-path", database, "--endpoint", "http://127.0.0.1:1"))
		require.NoError(t, root.ExecuteContext(t.Context()))
		return out.String()
	}

	var submitted client.TaskSubmission
	require.NoError(t, json.Unmarshal([]byte(run("submit", spec, "--json", "--idempotency-key", "offline")), &submitted))
	require.Equal(t, entities.TaskQueued, submitted.State)
	require.Nil(t, submitted.SessionID)
	require.Contains(t, run("list", "--json"), submitted.TaskID)
	require.Contains(t, run("task", "show", submitted.TaskID, "--json"), "QUEUED")
	require.Contains(t, run("task", "cancel", submitted.TaskID), "CANCELLED")
	require.Contains(t, run("task", "retry", submitted.TaskID), "QUEUED")

	t.Setenv("AGENTAPI_KEY", "other-credential")
	require.NotContains(t, run("list", "--json"), submitted.TaskID)
}

func TestSQLiteWorkerRetriesCapacityAndReconcilesLostStart(t *testing.T) {
	var starts atomic.Int32
	var dispatch atomic.Value
	var searchable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			attempt := starts.Add(1)
			var req entities.StartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tags[entities.LocalTaskTag] == "" {
				http.Error(w, "missing task tag", http.StatusBadRequest)
				return
			}
			if attempt == 1 {
				http.Error(w, "session quota is full", http.StatusTooManyRequests)
				return
			}
			dispatch.Store(req.Tags[entities.LocalTaskTag])
			// Simulate a server that accepted the request before the response failed.
			http.Error(w, "start response lost", http.StatusBadGateway)
		case "/search":
			result := client.SearchResponse{}
			tag := r.URL.Query().Get("tag." + entities.LocalTaskTag)
			if searchable.Load() && (tag == "" || tag == dispatch.Load()) {
				result.Sessions = []client.SessionInfo{{SessionID: "assigned-by-server", Status: "active", Tags: map[string]string{entities.LocalTaskTag: dispatch.Load().(string)}}}
			}
			_ = json.NewEncoder(w).Encode(result)
		default:
			t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := t.Context()
	db := filepath.Join(t.TempDir(), "tasks.sqlite3")
	api := client.NewClient(server.URL)
	local, err := openLocalTaskQueue(ctx, db, server.URL, "", api)
	require.NoError(t, err)
	now := time.Now().UTC()
	local.queue.Now = func() time.Time { return now }
	spec, err := entities.DecodeTaskSpec([]byte(localTaskYAML), true)
	require.NoError(t, err)
	submitted, err := local.SubmitTask(ctx, spec, "")
	require.NoError(t, err)
	claims, err := local.queue.Claim(ctx, "first-worker", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.NoError(t, local.start(ctx, "first-worker", claims[0]))
	waiting, err := local.ShowTask(ctx, submitted.TaskID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskQueued, waiting.State)
	require.Equal(t, "WAITING_CAPACITY", waiting.Reason)
	require.Nil(t, waiting.SessionID)
	require.NoError(t, local.kv.Close())

	local, err = openLocalTaskQueue(ctx, db, server.URL, "", api)
	require.NoError(t, err)
	now = now.Add(16 * time.Second)
	local.queue.Now = func() time.Time { return now }
	claims, err = local.queue.Claim(ctx, "second-worker", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.NoError(t, local.start(ctx, "second-worker", claims[0]))
	require.NoError(t, local.kv.Close())

	local, err = openLocalTaskQueue(ctx, db, server.URL, "", api)
	require.NoError(t, err)
	defer local.kv.Close()
	local.queue.Now = func() time.Time { return now }
	claims, err = local.queue.Claim(ctx, "recovery-worker", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	unconfirmed, err := local.ShowTask(ctx, submitted.TaskID)
	require.NoError(t, err)
	require.Equal(t, "START_UNCERTAIN", unconfirmed.Reason)
	require.Nil(t, unconfirmed.SessionID)

	searchable.Store(true)
	claims, err = local.queue.Claim(ctx, "recovery-worker", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	ready, err := local.ShowTask(ctx, submitted.TaskID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskReady, ready.State)
	require.Equal(t, "assigned-by-server", *ready.SessionID)
	session, err := resolveTaskSession(ctx, &taskCLIClient{Client: api, tasks: local, local: local}, submitted.TaskID, false, &bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, "assigned-by-server", session.SessionID)
	require.EqualValues(t, 2, starts.Load(), "only the explicit quota rejection permits another start attempt")
}

func TestSQLiteWorkersClaimEachTaskOnce(t *testing.T) {
	ctx := t.Context()
	db := filepath.Join(t.TempDir(), "tasks.sqlite3")
	first, err := openLocalTaskQueue(ctx, db, "http://127.0.0.1:1", "", nil)
	require.NoError(t, err)
	defer first.kv.Close()
	second, err := openLocalTaskQueue(ctx, db, "http://127.0.0.1:1", "", nil)
	require.NoError(t, err)
	defer second.kv.Close()

	spec, err := entities.DecodeTaskSpec([]byte(localTaskYAML), true)
	require.NoError(t, err)
	submitted, err := first.SubmitTask(ctx, spec, "")
	require.NoError(t, err)

	var group sync.WaitGroup
	claimed := make([]int, 2)
	errs := make([]error, 2)
	for i, local := range []*localTaskQueue{first, second} {
		group.Go(func() {
			jobs, err := local.queue.Claim(ctx, []string{"first", "second"}[i], 1)
			claimed[i], errs[i] = len(jobs), err
		})
	}
	group.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.Equal(t, 1, claimed[0]+claimed[1])
	task, err := first.ShowTask(ctx, submitted.TaskID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskClaimed, task.State)
	require.Nil(t, task.SessionID)
}
