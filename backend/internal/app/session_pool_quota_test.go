package app

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	sessionrunnercore "github.com/takutakahashi/agentapi-proxy/internal/core/sessionrunner"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	infrasessionrunner "github.com/takutakahashi/agentapi-proxy/internal/infrastructure/sessionrunner"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCheckSessionPoolQuota(t *testing.T) {
	ctx := context.Background()
	store := infrasessionrunner.NewStore(kvstore.NewKubernetesStore(fake.NewSimpleClientset()), "test")
	binding := &sessionrunnercore.Binding{
		Pool: "linux", SubjectType: sessionrunnercore.SubjectUser, SubjectID: "alice",
		Enabled: true, MaxConcurrent: 2,
	}
	if err := store.CreateBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, &sessionrunnercore.Allocation{SessionID: "session-1", Pool: "linux", BindingID: binding.ID}); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, &sessionrunnercore.Allocation{SessionID: "legacy", Pool: "linux"}); err != nil {
		t.Fatal(err)
	}

	server := &Server{sessionRunnerStore: store}
	route := testAuthorizedRoute(t, "linux", binding)
	if err := server.checkSessionPoolQuota(ctx, route); err != nil {
		t.Fatalf("quota below limit: %v", err)
	}
	if err := store.Enqueue(ctx, &sessionrunnercore.Allocation{SessionID: "session-2", Pool: "linux", BindingID: binding.ID}); err != nil {
		t.Fatal(err)
	}

	err := server.checkSessionPoolQuota(ctx, route)
	var quotaErr *sessionrunnercore.QuotaExceededError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("quota error = %v, want QuotaExceededError", err)
	}
	if quotaErr.Active != 2 || quotaErr.MaxConcurrent != 2 || quotaErr.BindingID != binding.ID {
		t.Fatalf("unexpected quota error: %+v", quotaErr)
	}
}

func TestCheckSessionPoolQuotaUnlimited(t *testing.T) {
	server := &Server{}
	if err := server.checkSessionPoolQuota(context.Background(), testAuthorizedRoute(t, "linux", &sessionrunnercore.Binding{MaxConcurrent: 0})); err != nil {
		t.Fatalf("unlimited quota returned error: %v", err)
	}
}

func TestDeleteSessionPoolAllocation(t *testing.T) {
	ctx := context.Background()
	store := infrasessionrunner.NewStore(kvstore.NewKubernetesStore(fake.NewSimpleClientset()), "test")
	if err := store.Enqueue(ctx, &sessionrunnercore.Allocation{SessionID: "session-1", Pool: "linux", BindingID: "binding-alice"}); err != nil {
		t.Fatal(err)
	}
	server := &Server{sessionRunnerStore: store}
	if err := server.DeleteSessionPoolAllocation(ctx, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAllocation(ctx, "session-1"); !errors.Is(err, sessionrunnercore.ErrNotFound) {
		t.Fatalf("allocation remains after deletion: %v", err)
	}
}

func TestAllocationCountsTowardQuota(t *testing.T) {
	active := []sessionrunnercore.AllocationStatus{
		sessionrunnercore.AllocationPending,
		sessionrunnercore.AllocationLeased,
		sessionrunnercore.AllocationClaimed,
		sessionrunnercore.AllocationRunning,
	}
	for _, status := range active {
		if !allocationCountsTowardQuota(status) {
			t.Errorf("status %q should count toward quota", status)
		}
	}
	for _, status := range []sessionrunnercore.AllocationStatus{sessionrunnercore.AllocationCompleted, sessionrunnercore.AllocationFailed} {
		if allocationCountsTowardQuota(status) {
			t.Errorf("status %q should not count toward quota", status)
		}
	}
}

func TestConcurrentStartsShareSessionPoolQuota(t *testing.T) {
	ctx := t.Context()
	database := "file:" + filepath.Join(t.TempDir(), "shared-quota.db")
	var servers []*Server
	for i := 0; i < 2; i++ {
		kv, err := kvstore.NewLibSQLStore(ctx, database, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = kv.Close() })
		servers = append(servers, &Server{kvStore: kv, namespace: "test", sessionRunnerStore: infrasessionrunner.NewStore(kv, "test")})
	}
	binding := &sessionrunnercore.Binding{ID: "shared", Pool: "linux", SubjectType: sessionrunnercore.SubjectUser, SubjectID: "alice", Enabled: true, MaxConcurrent: 1}
	route := testAuthorizedRoute(t, "linux", binding)
	ids := []string{"interactive-session", "queued-task-session"}
	results := make([]error, len(ids))
	var workers sync.WaitGroup
	for i, id := range ids {
		workers.Go(func() {
			allocation := &sessionrunnercore.Allocation{SessionID: id, Pool: route.PoolName(), BindingID: route.BindingID()}
			results[i] = servers[i].admitPoolAllocation(ctx, route, allocation)
		})
	}
	workers.Wait()
	winner, waiting := -1, -1
	for i, err := range results {
		var quotaErr *sessionrunnercore.QuotaExceededError
		switch {
		case err == nil:
			winner = i
		case errors.As(err, &quotaErr):
			waiting = i
		default:
			t.Fatal(err)
		}
	}
	if winner < 0 || waiting < 0 {
		t.Fatalf("expected one admitted start and one waiting start, got %v", results)
	}
	if err := servers[winner].DeleteSessionPoolAllocation(ctx, ids[winner]); err != nil {
		t.Fatal(err)
	}
	allocation := &sessionrunnercore.Allocation{SessionID: ids[waiting], Pool: route.PoolName(), BindingID: route.BindingID()}
	if err := servers[waiting].admitPoolAllocation(ctx, route, allocation); err != nil {
		t.Fatalf("waiting session should be admitted after a slot opens: %v", err)
	}
}
