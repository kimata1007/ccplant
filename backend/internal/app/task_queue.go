package app

import (
	"context"
	"encoding/json"
	"errors"
	runner "github.com/takutakahashi/agentapi-proxy/internal/core/sessionrunner"
	"github.com/takutakahashi/agentapi-proxy/pkg/sessionsettings"
	"strings"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	repo "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
)

func (s *Server) taskSessionSnapshot(ctx context.Context) (map[string]task.SessionSnapshot, error) {
	result := make(map[string]task.SessionSnapshot)
	if s.sessionRouteRepo != nil {
		var routes []*repo.SessionRoute
		var err error
		if filtered, ok := s.sessionRouteRepo.(repo.FilteredSessionRouteRepository); ok {
			routes, err = filtered.ListFiltered(ctx, repo.SessionRouteFilter{})
		} else {
			routes, err = s.sessionRouteRepo.List(ctx, "")
		}
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if route.Tags["task_id"] == "" {
				continue
			}
			status := route.Status
			if status == "" {
				status = "creating"
			}
			if route.DeletionRequestID != "" {
				status = "deleting"
			}
			result[route.SessionID] = task.SessionSnapshot{Status: status, Owner: route.UserID, Team: route.TeamID, TaskID: route.Tags["task_id"]}
		}
	}
	var sessions []entities.Session
	if manager, ok := s.sessionManager.(interface {
		ListSessionsContext(context.Context, entities.SessionFilter) ([]entities.Session, error)
	}); ok {
		var err error
		sessions, err = manager.ListSessionsContext(ctx, entities.SessionFilter{})
		if err != nil {
			return nil, err
		}
	} else if s.sessionManager != nil {
		sessions = s.sessionManager.ListSessions(entities.SessionFilter{})
	}
	for _, session := range sessions {
		if session.Tags()["task_id"] == "" {
			continue
		}
		id := session.ID()
		if existing, ok := result[id]; ok && existing.Ready() {
			continue
		}
		result[id] = task.SessionSnapshot{Status: session.Status(), Owner: session.UserID(), Team: session.TeamID(), TaskID: session.Tags()["task_id"]}
	}
	return result, nil
}

// The pool persists the allocation before its public route. Repair that gap
// after a lost response instead of asking the runner to provision again.
func (s *Server) recoverTaskAllocation(ctx context.Context, t *repo.TaskRecord) (task.SessionSnapshot, error) {
	if s.sessionRunnerStore == nil || s.sessionRouteRepo == nil || t.SessionID == nil {
		return task.SessionSnapshot{}, nil
	}
	id := *t.SessionID
	existing, err := s.sessionRouteRepo.Get(ctx, id)
	if err != nil {
		return task.SessionSnapshot{}, err
	}
	a, err := s.sessionRunnerStore.GetAllocation(ctx, id)
	if err != nil && !errors.Is(err, runner.ErrNotFound) {
		return task.SessionSnapshot{}, err
	}
	if existing != nil {
		status := existing.Status
		if status == "" {
			status = "creating"
		}
		if err == nil && a.Status == runner.AllocationFailed {
			status = "error"
		}
		return task.SessionSnapshot{Status: status, Owner: t.OwnerUserID, Team: t.TeamID, TaskID: t.ID}, nil
	}
	if errors.Is(err, runner.ErrNotFound) {
		return task.SessionSnapshot{}, nil
	}
	var settings sessionsettings.SessionSettings
	if err := json.Unmarshal(a.ProvisionSettings, &settings); err != nil {
		return task.SessionSnapshot{}, err
	}
	status := "creating"
	switch a.Status {
	case runner.AllocationFailed, runner.AllocationCompleted:
		status = "error"
	case runner.AllocationRunning:
		// A running runner will report the actual runtime status through its
		// normal callback once the missing route accepts its generation token.
		status = "starting"
	}
	tags := make(map[string]string, len(t.Spec.Spec.Start.Tags)+2)
	for key, value := range t.Spec.Spec.Start.Tags {
		tags[key] = value
	}
	tags["task_id"] = t.ID
	if id := strings.TrimSpace(t.Spec.Spec.Start.SessionProfileID); id != "" {
		tags["session_profile_id"] = id
	}
	if err := s.sessionRouteRepo.Save(ctx, &repo.SessionRoute{
		SessionID: a.SessionID, RemoteSessionID: a.RunnerID, ManagerID: a.ManagerID, Transport: repo.SessionRouteTransportDirectRuntime,
		Generation: a.Generation, RuntimeTokenHash: a.RuntimeTokenHash, UserID: t.OwnerUserID, Scope: string(t.Scope), TeamID: t.TeamID,
		Pool: a.Pool, Tags: tags, StartedAt: a.CreatedAt, InitialMessage: settings.InitialMessage, Status: status, StatusUpdatedAt: time.Now().UTC(),
	}); err != nil {
		return task.SessionSnapshot{}, err
	}
	return task.SessionSnapshot{Status: status, Owner: t.OwnerUserID, Team: t.TeamID, TaskID: t.ID}, nil
}

// TaskQueueMetrics is nil when the feature is disabled.
func (s *Server) TaskQueueMetrics() *task.Metrics {
	if s.router == nil || s.router.handlers.taskController == nil {
		return nil
	}
	return s.router.handlers.taskController.Queue.Metrics
}
