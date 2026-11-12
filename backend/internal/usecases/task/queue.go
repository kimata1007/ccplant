package task

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	repo "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
)

const Lease = 3 * time.Minute
const StartTimeout = 140 * time.Second

var ErrWaitingCapacity = errors.New("no authorized session capacity is currently available")
var ErrState = errors.New("task is no longer in an eligible state")
var ErrIdempotency = errors.New("idempotency key already used for another task definition")

type SessionSnapshot struct {
	Status string
}

func (s SessionSnapshot) Failed() bool {
	return s.Status == "error" || s.Status == "failed" || s.Status == "timeout"
}

func (s SessionSnapshot) Ready() bool {
	switch s.Status {
	case "active", "running", "stable", "suspended", "idle", "ready":
		return true
	}
	return false
}

type Queue struct {
	Repo              repo.TaskRepository
	Metrics           *Metrics
	Sessions          func(context.Context) (map[string]SessionSnapshot, error)
	RecoverAllocation func(context.Context, *repo.TaskRecord) (SessionSnapshot, error)
	Now               func() time.Time
}

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now().UTC()
	}
	return time.Now().UTC()
}

func NewID() string { return "tsk_" + uuid.NewString() }

func hashedID(owner, key string) string {
	raw := sha256.Sum256([]byte(owner + "\x00" + key))
	return "tsk_" + hex.EncodeToString(raw[:24])
}

func (q *Queue) Submit(ctx context.Context, spec entities.TaskSpec, owner, key string, teams []string, previous *repo.TaskRecord) (*repo.TaskRecord, error) {
	now := q.now()
	wait, _ := time.ParseDuration(spec.Spec.Queue.MaxWait)
	start := spec.Spec.Start
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	id := NewID()
	attempt, retryOf := 1, ""
	if previous != nil {
		attempt, retryOf = previous.Attempt+1, previous.ID
	}
	fingerprint := sha256.Sum256(append(data, retryOf...))
	record := &repo.TaskRecord{Task: entities.Task{ID: id, Name: spec.Metadata.Name, OwnerUserID: owner, Scope: start.Scope, TeamID: start.TeamID,
		Priority: spec.Spec.Queue.Priority, CreatedAt: now, ExpiresAt: now.Add(wait), Attempt: attempt, RetryOf: retryOf},
		Spec: spec, AuthorizedTeams: teams, Fingerprint: hex.EncodeToString(fingerprint[:])}
	if key != "" {
		record.ID = hashedID(owner, key)
	}
	change(record, now, owner, "submitted", entities.TaskQueued, "")
	for attempt := 0; attempt < 2; attempt++ {
		err = q.Repo.Create(ctx, record)
		if err == nil {
			if q.Metrics != nil {
				q.Metrics.submitted.Inc()
			}
			return record, nil
		}
		if key == "" || !errors.Is(err, kvstore.ErrConflict) {
			return nil, err
		}
		existing, err := q.Repo.Get(ctx, record.ID)
		if errors.Is(err, kvstore.ErrNotFound) {
			// Another replica may have pruned the record after Create saw it.
			continue
		}
		if err != nil {
			return nil, err
		}
		if existing.OwnerUserID != owner || existing.Fingerprint != record.Fingerprint {
			return nil, ErrIdempotency
		}
		return existing, nil
	}
	return nil, kvstore.ErrConflict
}

func change(t *repo.TaskRecord, now time.Time, actor, event string, state entities.TaskState, reason string) {
	t.State, t.Reason, t.UpdatedAt = state, reason, now
	t.Seq++
	t.Events = append(t.Events, entities.TaskEvent{Seq: t.Seq, At: now, Actor: actor, Type: event, State: state})
	if !state.Pending() {
		t.FinishedAt = &now
		t.LeaseOwner, t.LeaseUntil = "", time.Time{}
	}
}

func (q *Queue) mutate(ctx context.Context, id string, update func(*repo.TaskRecord, time.Time) error) (*repo.TaskRecord, error) {
	for attempt := 0; attempt < 8; attempt++ {
		record, err := q.Repo.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if err := update(record, q.now()); err != nil {
			return nil, err
		}
		err = q.Repo.Update(ctx, record)
		if !errors.Is(err, kvstore.ErrConflict) {
			return record, err
		}
	}
	return nil, kvstore.ErrConflict
}

func (q *Queue) Cancel(ctx context.Context, id, actor string) (*repo.TaskRecord, error) {
	return q.mutate(ctx, id, func(t *repo.TaskRecord, now time.Time) error {
		if !t.State.Pending() {
			return ErrState
		}
		if t.CancelRequested {
			return nil
		}
		t.CancelRequested = true
		if t.Dispatched || t.Accepted {
			change(t, now, actor, "cancellation_requested", t.State, "CANCELLATION_REQUESTED")
		} else {
			t.SessionID = nil
			change(t, now, actor, "cancelled", entities.TaskCancelled, "")
		}
		return nil
	})
}

func checkLease(t *repo.TaskRecord, worker string, generation int64, now time.Time) error {
	if !t.State.Pending() || t.LeaseOwner != worker || t.Generation != generation || !t.LeaseUntil.After(now) {
		return ErrState
	}
	return nil
}

func (q *Queue) Begin(ctx context.Context, id, sessionID, worker string, generation int64) (*repo.TaskRecord, error) {
	return q.mutate(ctx, id, func(t *repo.TaskRecord, now time.Time) error {
		if err := checkLease(t, worker, generation, now); err != nil {
			return err
		}
		if t.State != entities.TaskClaimed || t.Dispatched || t.CancelRequested || t.SessionID == nil || *t.SessionID != sessionID {
			return ErrState
		}
		t.Dispatched, t.LeaseUntil = true, now.Add(Lease)
		if t.StartedAt == nil {
			t.StartedAt = &now
		}
		change(t, now, worker, "starting", entities.TaskStarting, "")
		return nil
	})
}

func (q *Queue) Heartbeat(ctx context.Context, id, worker string, generation int64) (*repo.TaskRecord, error) {
	return q.mutate(ctx, id, func(t *repo.TaskRecord, now time.Time) error {
		if err := checkLease(t, worker, generation, now); err != nil {
			return err
		}
		t.LeaseUntil = now.Add(Lease)
		return nil
	})
}

// Finalize accepts only the status of /start. Route status determines readiness.
func (q *Queue) Finalize(ctx context.Context, id, worker string, generation int64, status int) (*repo.TaskRecord, error) {
	record, err := q.mutate(ctx, id, func(t *repo.TaskRecord, now time.Time) error {
		if err := checkLease(t, worker, generation, now); err != nil {
			return err
		}
		if t.State != entities.TaskStarting || !t.Dispatched {
			return ErrState
		}
		switch {
		case status >= 200 && status < 300:
			t.LeaseOwner, t.LeaseUntil = "", time.Time{}
			t.Accepted = true
			change(t, now, worker, "allocated", entities.TaskStarting, "")
		case status == 429:
			t.LeaseOwner, t.LeaseUntil = "", time.Time{}
			t.Dispatched = false
			t.RetryAfter = now.Add(15 * time.Second)
			if t.CancelRequested {
				t.SessionID = nil
				change(t, now, worker, "cancelled", entities.TaskCancelled, "")
			} else {
				change(t, now, worker, "capacity", entities.TaskQueued, "WAITING_CAPACITY")
			}
		case status >= 400 && status < 500 && status != 408 && status != 409:
			t.SessionID = nil
			change(t, now, worker, "failed", entities.TaskFailed, fmt.Sprintf("START_HTTP_%d", status))
		default:
			// The client can time out before the API finishes writing. Keep
			// its reservation until the original dispatch lease has drained.
			t.RetryAfter = t.LeaseUntil.Add(retryDelay(t.Generation))
			change(t, now, worker, "start_uncertain", entities.TaskStarting, "START_UNCERTAIN")
		}
		return nil
	})
	if err == nil && q.Metrics != nil && record.State == entities.TaskFailed {
		q.Metrics.failed.WithLabelValues(record.Reason).Inc()
	}
	return record, err
}

func retryDelay(generation int64) time.Duration {
	return time.Duration(1<<min(generation, 6)) * time.Second
}

func taskSubject(t *repo.TaskRecord) string {
	if t.Scope == entities.ScopeTeam {
		return "team:" + t.TeamID
	}
	return "user:" + t.OwnerUserID
}

func (q *Queue) Claim(ctx context.Context, worker string, limit int) ([]*repo.TaskRecord, error) {
	var claimed []*repo.TaskRecord
	err := q.Repo.SerializeClaim(ctx, func(ctx context.Context) error {
		now := q.now()
		items, err := q.Repo.List(ctx, repo.TaskFilter{Pending: true})
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		sessions, err := q.Sessions(ctx)
		if err != nil {
			return err
		}
		candidates := make([]*repo.TaskRecord, 0, len(items))
		for _, item := range items {
			var session SessionSnapshot
			if item.SessionID != nil {
				session = sessions[*item.SessionID]
			}
			if item.LeaseUntil.After(now) {
				continue
			}
			if !session.Ready() && !session.Failed() && item.SessionID != nil && (item.Dispatched || item.Accepted) && q.RecoverAllocation != nil {
				recovered, recoveryErr := q.RecoverAllocation(ctx, item)
				if recoveryErr != nil {
					return recoveryErr
				}
				if recovered.Status != "" {
					session = recovered
				}
			}
			state, reason := item.State, item.Reason
			switch {
			case (session.Status != "" || item.Accepted) && item.CancelRequested:
				state, reason = entities.TaskCancelled, "SESSION_CREATED"
			case session.Failed():
				state, reason = entities.TaskFailed, "SESSION_START_FAILED"
			case session.Ready():
				state, reason = entities.TaskReady, ""
			case item.Accepted && session.Status == "":
				if now.Sub(item.UpdatedAt) < 30*time.Second {
					continue
				}
				state, reason = entities.TaskFailed, "SESSION_MISSING"
			case session.Status != "":
				// Allocated sessions are provisioned by the existing runner. Recheck on each claim.
				continue
			case item.CancelRequested:
				state, reason, item.SessionID = entities.TaskCancelled, "", nil
			case !item.Dispatched && !item.ExpiresAt.After(now):
				state, reason, item.SessionID = entities.TaskExpired, "QUEUE_DEADLINE_EXCEEDED", nil
			}
			if state != item.State {
				change(item, now, worker, "reconciled", state, reason)
				if err := q.Repo.Update(ctx, item); err != nil {
					if !errors.Is(err, kvstore.ErrConflict) {
						return err
					}
				} else if q.Metrics != nil {
					q.Metrics.reconciled.Inc()
					switch {
					case state == entities.TaskFailed:
						q.Metrics.failed.WithLabelValues(reason).Inc()
					case state == entities.TaskReady && item.StartedAt != nil:
						q.Metrics.start.Observe(now.Sub(*item.StartedAt).Seconds())
					}
				}
				continue
			}
			if !item.RetryAfter.After(now) {
				candidates = append(candidates, item)
			}
		}
		// Age the priority so a steady stream of higher priority tasks cannot
		// starve older work. Rotate between subjects within a claim batch.
		sort.SliceStable(candidates, func(i, j int) bool {
			a, b := candidates[i], candidates[j]
			ap := a.Priority + int(now.Sub(a.CreatedAt)/time.Minute)
			bp := b.Priority + int(now.Sub(b.CreatedAt)/time.Minute)
			if ap != bp {
				return ap > bp
			}
			if !a.CreatedAt.Equal(b.CreatedAt) {
				return a.CreatedAt.Before(b.CreatedAt)
			}
			return a.ID < b.ID
		})
		for len(candidates) > 0 && len(claimed) < limit {
			used := map[string]bool{}
			next := candidates[:0]
			for _, item := range candidates {
				if len(claimed) >= limit {
					break
				}
				subject := taskSubject(item)
				if used[subject] {
					next = append(next, item)
					continue
				}
				if item.SessionID == nil {
					id := uuid.NewString()
					item.SessionID = &id
				}
				item.Generation++
				item.LeaseOwner, item.LeaseUntil, item.ClaimedAt, item.Dispatched = worker, now.Add(Lease), &now, false
				change(item, now, worker, "claimed", entities.TaskClaimed, "")
				if err := q.Repo.Update(ctx, item); errors.Is(err, kvstore.ErrConflict) {
					if q.Metrics != nil {
						q.Metrics.conflicts.Inc()
					}
					continue
				} else if err != nil {
					return err
				}
				if q.Metrics != nil {
					q.Metrics.claimed.Inc()
					if item.Generation == 1 {
						q.Metrics.wait.Observe(now.Sub(item.CreatedAt).Seconds())
					}
				}
				claimed = append(claimed, item)
				used[subject] = true
			}
			candidates = next
		}
		return nil
	})
	return claimed, err
}

const taskHistoryDays = 90

func (q *Queue) Prune(ctx context.Context) error {
	items, err := q.Repo.List(ctx, repo.TaskFilter{States: []entities.TaskState{entities.TaskReady, entities.TaskCancelled, entities.TaskFailed, entities.TaskExpired}})
	if err != nil {
		return err
	}
	now := q.now()
	for _, item := range items {
		if item.FinishedAt != nil && now.After(item.FinishedAt.AddDate(0, 0, taskHistoryDays)) {
			if err := q.Repo.Delete(ctx, item); err != nil && !errors.Is(err, kvstore.ErrConflict) && !errors.Is(err, kvstore.ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

func ExecutionID(id string, generation int64) string {
	return id + "/" + strconv.FormatInt(generation, 10)
}
