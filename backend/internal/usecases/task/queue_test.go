package task_test

import (
	"context"
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
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
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
	return &task.Queue{Repo: repositories.NewTaskRepository(store, "test"), Config: config.TaskQueueConfig{
		MaxStartingGlobal: 2, MaxStartingPerUser: 1, MaxStartingPerTeam: 1, MaxLivePerUser: 3, MaxLivePerTeam: 3, MaxPending: 1000, RetentionDays: 90, TeamRetentionDays: 90,
	}, Now: func() time.Time { return *now }, Sessions: func(context.Context) (map[string]task.SessionSnapshot, error) { return sessions, nil }}
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
	require.Len(t, claims, 2)
	require.NotEqual(t, claims[0].OwnerUserID, claims[1].OwnerUserID)
	require.NotEqual(t, *claims[0].SessionID, *claims[1].SessionID)
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

	sessions[id] = task.SessionSnapshot{Status: "active", TaskID: submitted.ID, Owner: "owner"}
	now = now.Add(task.Lease + time.Minute)
	claims, err = q.Claim(ctx, "worker2", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	ready, err := q.Repo.Get(ctx, claim.ID)
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
	sessions[id] = task.SessionSnapshot{Status: "creating", TaskID: second.ID, Owner: "owner"}
	_, err = q.Finalize(ctx, second.ID, "worker2", claim.Generation, 200)
	require.NoError(t, err)
	_, err = q.Claim(ctx, "worker3", 1)
	require.NoError(t, err)
	cancelled, err = q.Repo.Get(ctx, second.ID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskCancelled, cancelled.State)
	require.Equal(t, id, *cancelled.SessionID)
}

func TestZeroCapacityAndExpiry(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	q := newQueue(t, filepath.Join(t.TempDir(), "queue.db"), &now, map[string]task.SessionSnapshot{})
	q.Config.MaxStartingGlobal = 0
	spec, err := entities.DecodeTaskSpec([]byte(yamlTask), true)
	require.NoError(t, err)
	submitted, err := q.Submit(ctx, spec, "owner", "", nil, nil)
	require.NoError(t, err)
	claims, err := q.Claim(ctx, "worker1", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	now = now.Add(25 * time.Hour)
	claims, err = q.Claim(ctx, "worker1", 1)
	require.NoError(t, err)
	require.Empty(t, claims)
	item, err := q.Repo.Get(ctx, submitted.ID)
	require.NoError(t, err)
	require.Equal(t, entities.TaskExpired, item.State)
}
