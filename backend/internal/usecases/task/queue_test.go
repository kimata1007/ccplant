package task_test

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	port "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
)

const yamlTask = `apiVersion: ccplant.io/v1alpha1
kind: Task
metadata:
  name: Repository review
spec:
  start:
    scope: user
    session_profile_id: profile
    tags:
      repository: kimata1007/ccplant
    params:
      message: Review the repository.
  queue:
    priority: 1
    max_wait: 24h
`

func newQueue(t *testing.T, path string, now *time.Time, sessions map[string]task.SessionSnapshot) *task.Queue {
	t.Helper()
	store, err := kvstore.NewLibSQLStore(context.Background(), "file:"+path, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return &task.Queue{Repo: repositories.NewTaskRepository(store, "test"), Now: func() time.Time { return *now }, Sessions: func(context.Context) (map[string]task.SessionSnapshot, error) { return sessions, nil }}
}

func TestDurableSubmissionAndParallelClaims(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "queue.db")
	now := time.Now().UTC()
	sessions := map[string]task.SessionSnapshot{}
	api1 := newQueue(t, path, &now, sessions)
	api2 := newQueue(t, path, &now, sessions)
	spec, err := entities.DecodeTaskSpec([]byte(yamlTask), true)
	require.NoError(t, err)

	first, err := api1.Submit(ctx, spec, "alice", "request-1", nil, nil)
	require.NoError(t, err)
	retry, err := api2.Submit(ctx, spec, "alice", "request-1", nil, nil)
	require.NoError(t, err)
	require.Equal(t, first.ID, retry.ID)
	require.Nil(t, retry.SessionID)

	modified := spec
	modified.Metadata.Name = "Different request"
	_, err = api2.Submit(ctx, modified, "alice", "request-1", nil, nil)
	require.ErrorIs(t, err, task.ErrIdempotency)

	_, err = api1.Submit(ctx, spec, "alice", "request-2", nil, nil)
	require.NoError(t, err)
	_, err = api1.Submit(ctx, spec, "bob", "request-1", nil, nil)
	require.NoError(t, err)

	var running sync.WaitGroup
	results := make([][]*port.TaskRecord, 2)
	errs := make([]error, 2)
	for i, api := range []*task.Queue{api1, api2} {
		running.Go(func() { results[i], errs[i] = api.Claim(ctx, []string{"worker1", "worker2"}[i], 2) })
	}
	running.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	claims := append(results[0], results[1]...)
	require.Len(t, claims, 3)
	ids := make(map[string]bool)
	for _, claim := range claims {
		require.False(t, ids[claim.ID], "each task should be claimed once")
		ids[claim.ID] = true
	}
	visible, err := api2.Repo.List(ctx, port.TaskFilter{Owner: "alice"})
	require.NoError(t, err)
	require.Len(t, visible, 2)
}

func TestRecoverLostStartAndCancellationRace(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	sessions := map[string]task.SessionSnapshot{}
	q := newQueue(t, filepath.Join(t.TempDir(), "queue.db"), &now, sessions)
	spec, err := entities.DecodeTaskSpec([]byte(yamlTask), true)
	require.NoError(t, err)

	submitted, err := q.Submit(ctx, spec, "owner", "", nil, nil)
	require.NoError(t, err)
	claims, err := q.Claim(ctx, "worker1", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	claim := claims[0]
	id := *claim.SessionID
	_, err = q.Begin(ctx, claim.ID, id, "worker1", claim.Generation)
	require.NoError(t, err)
	_, err = q.Begin(ctx, claim.ID, id, "worker1", claim.Generation)
	require.ErrorIs(t, err, task.ErrState)

	_, err = q.Finalize(ctx, claim.ID, "worker1", claim.Generation, 0)
	require.NoError(t, err)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Empty(t, claims)

	sessions[id] = task.SessionSnapshot{Status: "active"}
	now = now.Add(task.Lease + time.Minute)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	ready, err := q.Repo.Get(ctx, submitted.ID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskReady, ready.State)
	require.Equal(t, id, *ready.SessionID)

	second, err := q.Submit(ctx, spec, "owner", "", nil, nil)
	require.NoError(t, err)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	claim = claims[0]
	id = *claim.SessionID
	_, err = q.Begin(ctx, second.ID, id, "worker2", claim.Generation)
	require.NoError(t, err)
	cancelled, err := q.Cancel(ctx, second.ID, "owner")
	require.NoError(t, err)
	require.True(t, cancelled.CancelRequested)
	sessions[id] = task.SessionSnapshot{Status: "creating"}
	_, err = q.Finalize(ctx, second.ID, "worker2", claim.Generation, 200)
	require.NoError(t, err)
	_, err = q.Claim(ctx, "worker3", 1)
	require.NoError(t, err)
	cancelled, err = q.Repo.Get(ctx, second.ID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskCancelled, cancelled.State)
	require.Equal(t, id, *cancelled.SessionID)
}

func TestTaskRetriesWhenSessionQuotaIsFull(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	q := newQueue(t, filepath.Join(t.TempDir(), "queue.db"), &now, map[string]task.SessionSnapshot{})
	spec, err := entities.DecodeTaskSpec([]byte(yamlTask), true)
	require.NoError(t, err)
	submitted, err := q.Submit(ctx, spec, "owner", "", nil, nil)
	require.NoError(t, err)
	claims, err := q.Claim(ctx, "worker1", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	claim := claims[0]
	_, err = q.Begin(ctx, claim.ID, *claim.SessionID, "worker1", claim.Generation)
	require.NoError(t, err)
	waiting, err := q.Finalize(ctx, claim.ID, "worker1", claim.Generation, http.StatusTooManyRequests)
	require.NoError(t, err)
	require.Equal(t, entities.TaskQueued, waiting.State)
	require.Equal(t, "WAITING_CAPACITY", waiting.Reason)

	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	now = now.Add(16 * time.Second)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.Equal(t, submitted.ID, claims[0].ID)
	require.Equal(t, claim.SessionID, claims[0].SessionID)

	_, err = q.Begin(ctx, claims[0].ID, *claims[0].SessionID, "worker2", claims[0].Generation)
	require.NoError(t, err)
	_, err = q.Finalize(ctx, claims[0].ID, "worker2", claims[0].Generation, http.StatusTooManyRequests)
	require.NoError(t, err)
	now = now.Add(25 * time.Hour)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	item, err := q.Repo.Get(ctx, submitted.ID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskExpired, item.State)
}
