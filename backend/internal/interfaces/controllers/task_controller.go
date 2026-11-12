package controllers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	repo "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/auth"
	"github.com/takutakahashi/agentapi-proxy/pkg/executiontoken"
)

type TaskController struct {
	Queue      *task.Queue
	SigningKey string
}

type TaskClaim struct {
	TaskID         string `json:"task_id"`
	SessionID      string `json:"session_id"`
	Generation     int64  `json:"generation"`
	ExecutionToken string `json:"execution_token"`
}

var taskIDPattern = regexp.MustCompile(`^tsk_([0-9a-f-]{36}|[0-9a-f]{48})$`)

func taskHTTPError(err error) error {
	switch {
	case errors.Is(err, kvstore.ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "task not found")
	case errors.Is(err, task.ErrState), errors.Is(err, task.ErrIdempotency), errors.Is(err, kvstore.ErrConflict):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case errors.Is(err, task.ErrQueueFull):
		return echo.NewHTTPError(http.StatusTooManyRequests, "QUOTA_EXCEEDED: retry when the task queue has capacity")
	default:
		return echo.NewHTTPError(http.StatusServiceUnavailable, "task queue storage unavailable").SetInternal(err)
	}
}

func (c *TaskController) Submit(ctx echo.Context) error {
	body, err := io.ReadAll(http.MaxBytesReader(ctx.Response(), ctx.Request().Body, entities.TaskBodyLimit))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid task body or body exceeds 256 KiB")
	}
	spec, err := entities.DecodeTaskSpec(body, false)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, entities.ErrTaskEnvironment) {
			status = http.StatusUnprocessableEntity
		}
		return echo.NewHTTPError(status, err.Error())
	}
	return c.submit(ctx, spec, nil)
}

func (c *TaskController) submit(ctx echo.Context, spec entities.TaskSpec, previous *repo.TaskRecord) error {
	a := auth.GetAuthorizationContext(ctx)
	start := &spec.Spec.Start
	scope, team := a.ResolveScope(string(start.Scope), start.TeamID)
	if (scope == "team" && team == "") || !a.CanCreateResource(scope, team) {
		return echo.NewHTTPError(http.StatusForbidden, "task scope is not permitted")
	}
	start.Scope, start.TeamID = entities.ResourceScope(scope), team
	key := ctx.Request().Header.Get("Idempotency-Key")
	if len(key) > 256 {
		return echo.NewHTTPError(http.StatusBadRequest, "Idempotency-Key may be at most 256 bytes")
	}
	var teams []string
	if team != "" {
		teams = []string{team}
	} else {
		for _, membership := range a.TeamScope.Teams {
			if a.CanReadInTeam(membership) {
				teams = append(teams, membership)
			}
		}
	}
	result, err := c.Queue.Submit(ctx.Request().Context(), spec, string(a.User.ID()), key, teams, previous)
	if err != nil {
		return taskHTTPError(err)
	}
	return ctx.JSON(http.StatusAccepted, map[string]any{"task_id": result.ID, "state": result.State, "session_id": result.SessionID, "retry_of": result.RetryOf})
}

func canReadTask(a *auth.AuthorizationContext, t *repo.TaskRecord) bool {
	if t.Scope == entities.ScopeTeam {
		return a.CanReadInTeam(t.TeamID)
	}
	return a.PersonalScope.CanRead && a.PersonalScope.UserID == t.OwnerUserID
}

func (c *TaskController) authorizedTask(ctx echo.Context) (*repo.TaskRecord, error) {
	id := ctx.Param("id")
	if !taskIDPattern.MatchString(id) {
		return nil, taskHTTPError(kvstore.ErrNotFound)
	}
	record, err := c.Queue.Repo.Get(ctx.Request().Context(), id)
	if err != nil {
		return nil, taskHTTPError(err)
	}
	if !canReadTask(auth.GetAuthorizationContext(ctx), record) {
		return nil, taskHTTPError(kvstore.ErrNotFound)
	}
	return record, nil
}

func (c *TaskController) Show(ctx echo.Context) error {
	t, err := c.authorizedTask(ctx)
	if err != nil {
		return err
	}
	if t.SessionID != nil && !t.State.Pending() {
		sessions, err := c.Queue.Sessions(ctx.Request().Context())
		if err != nil {
			return taskHTTPError(err)
		}
		_, exists := sessions[*t.SessionID]
		t.SessionMissing = !exists
	}
	return ctx.JSON(http.StatusOK, t.Task)
}

func (c *TaskController) Cancel(ctx echo.Context) error {
	t, err := c.authorizedTask(ctx)
	if err != nil {
		return err
	}
	a := auth.GetAuthorizationContext(ctx)
	if !a.CanModifyResource(t.OwnerUserID, string(t.Scope), t.TeamID) ||
		(t.Scope == entities.ScopeTeam && !a.CanCreateInTeam(t.TeamID)) {
		return echo.NewHTTPError(http.StatusForbidden, "task cancellation is not permitted")
	}
	t, err = c.Queue.Cancel(ctx.Request().Context(), t.ID, string(a.User.ID()))
	if errors.Is(err, task.ErrState) {
		return echo.NewHTTPError(http.StatusConflict, "task cannot be cancelled in its current state; use the existing session controls for an allocated session")
	}
	if err != nil {
		return taskHTTPError(err)
	}
	return ctx.JSON(http.StatusOK, t.Task)
}

func (c *TaskController) Retry(ctx echo.Context) error {
	t, err := c.authorizedTask(ctx)
	if err != nil {
		return err
	}
	if t.State != entities.TaskFailed && t.State != entities.TaskCancelled && t.State != entities.TaskExpired {
		return echo.NewHTTPError(http.StatusConflict, "only failed, cancelled, or expired tasks can be retried")
	}
	return c.submit(ctx, t.Spec, t)
}

func taskFilters(ctx echo.Context) ([]repo.TaskFilter, error) {
	a := auth.GetAuthorizationContext(ctx)
	scope, team := a.ResolveScope(ctx.QueryParam("scope"), ctx.QueryParam("team_id"))
	if (scope != "" && scope != "user" && scope != "team") || (scope == "user" && team != "") {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid scope or team_id")
	}
	var states []entities.TaskState
	if filter := ctx.QueryParam("state"); filter != "" {
		for _, value := range strings.Split(filter, ",") {
			state := entities.TaskState(strings.ToUpper(value))
			if !state.Valid() {
				return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid task state")
			}
			states = append(states, state)
		}
	}
	var filters []repo.TaskFilter
	if scope != "team" && team == "" && a.PersonalScope.CanRead {
		filters = append(filters, repo.TaskFilter{Owner: a.PersonalScope.UserID, States: states})
	}
	if scope == "user" {
		return filters, nil
	}
	switch {
	case team != "":
		if !a.CanReadInTeam(team) {
			return nil, echo.NewHTTPError(http.StatusForbidden, "team scope is not permitted")
		}
		filters = append(filters, repo.TaskFilter{Team: team, States: states})
	case a.TeamScope.IsAdmin:
		filters = append(filters, repo.TaskFilter{AllTeams: true, States: states})
	default:
		for _, team := range a.TeamScope.Teams {
			if a.CanReadInTeam(team) {
				filters = append(filters, repo.TaskFilter{Team: team, States: states})
			}
		}
	}
	return filters, nil
}

func (c *TaskController) list(ctx echo.Context, filters []repo.TaskFilter) ([]entities.Task, error) {
	a := auth.GetAuthorizationContext(ctx)
	items := make([]entities.Task, 0)
	for _, filter := range filters {
		records, err := c.Queue.Repo.List(ctx.Request().Context(), filter)
		if err != nil {
			return nil, taskHTTPError(err)
		}
		for _, record := range records {
			if canReadTask(a, record) {
				items = append(items, record.Task)
			}
		}
	}
	return items, nil
}

type taskCursor struct {
	Created time.Time `json:"created_at"`
	ID      string    `json:"id"`
}

func (c *TaskController) List(ctx echo.Context) error {
	filters, err := taskFilters(ctx)
	if err != nil {
		return err
	}
	limit := 50
	if raw := ctx.QueryParam("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return echo.NewHTTPError(http.StatusBadRequest, "limit must be between 1 and 200")
		}
	}
	var cursor taskCursor
	if raw := ctx.QueryParam("cursor"); raw != "" {
		data, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Created.IsZero() || !taskIDPattern.MatchString(cursor.ID) {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cursor")
		}
	}
	items, err := c.list(ctx, filters)
	if err != nil {
		return err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	first := sort.Search(len(items), func(i int) bool {
		return cursor.Created.IsZero() || items[i].CreatedAt.Before(cursor.Created) || (items[i].CreatedAt.Equal(cursor.Created) && items[i].ID < cursor.ID)
	})
	items = items[first:]
	result := entities.TaskList{Items: items}
	if len(items) > limit {
		result.Items = items[:limit]
		last := result.Items[limit-1]
		data, _ := json.Marshal(taskCursor{last.CreatedAt, last.ID})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return ctx.JSON(http.StatusOK, result)
}

func (c *TaskController) Stream(ctx echo.Context) error {
	filters, err := taskFilters(ctx)
	if err != nil {
		return err
	}
	items, err := c.list(ctx, filters)
	if err != nil {
		return err
	}
	resp := ctx.Response()
	resp.Header().Set(echo.HeaderContentType, "text/event-stream")
	resp.Header().Set("Cache-Control", "no-cache")
	resp.Header().Set("X-Accel-Buffering", "no")
	if _, err = fmt.Fprint(resp, ": connected\n\n"); err != nil {
		return nil
	}
	resp.Flush()
	seen := map[string]int64{}
	for _, item := range items {
		seen[item.ID] = item.Seq
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	// Reconnect periodically to pick up changes to membership and permissions.
	timer := time.NewTimer(55 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Request().Context().Done():
			return nil
		case <-timer.C:
			return nil
		case <-ticker.C:
			items, err = c.list(ctx, filters)
			if err != nil {
				return nil
			}
			next := make(map[string]int64, len(items))
			for _, t := range items {
				next[t.ID] = t.Seq
				if seen[t.ID] == t.Seq {
					continue
				}
				event, _ := json.Marshal(map[string]any{"task_id": t.ID, "seq": t.Seq, "state": t.State, "session_id": t.SessionID})
				if _, err = fmt.Fprintf(resp, "data: %s\n\n", event); err != nil {
					return nil
				}
			}
			for id, seq := range seen {
				if _, exists := next[id]; exists {
					continue
				}
				event, _ := json.Marshal(map[string]any{"task_id": id, "seq": seq})
				if _, err = fmt.Fprintf(resp, "data: %s\n\n", event); err != nil {
					return nil
				}
			}
			seen = next
			if _, err = fmt.Fprint(resp, ": keepalive\n\n"); err != nil {
				return nil
			}
			resp.Flush()
		}
	}
}

var taskWorkerPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,100}$`)

func taskWorker(ctx echo.Context) (string, error) {
	worker := ctx.Request().Header.Get("X-Task-Worker")
	if !taskWorkerPattern.MatchString(worker) {
		return "", echo.NewHTTPError(http.StatusBadRequest, "valid X-Task-Worker required")
	}
	return worker, nil
}

func (c *TaskController) Claim(ctx echo.Context) error {
	worker, err := taskWorker(ctx)
	if err != nil {
		return err
	}
	limit, err := strconv.Atoi(ctx.QueryParam("limit"))
	if err != nil || limit < 1 || limit > 100 {
		return echo.NewHTTPError(http.StatusBadRequest, "limit must be between 1 and 100")
	}
	records, err := c.Queue.Claim(ctx.Request().Context(), worker, limit)
	if err != nil {
		return taskHTTPError(err)
	}
	claims := make([]TaskClaim, 0, len(records))
	for _, t := range records {
		identity := executiontoken.ExecutionClaims{TaskID: t.ID, TaskGeneration: t.Generation, TaskWorker: worker, ExecutionID: task.ExecutionID(t.ID, t.Generation), SessionID: *t.SessionID,
			UserID: t.OwnerUserID, TriggeredUserID: t.OwnerUserID, Scope: t.Scope, TeamID: t.TeamID, ExpiresAt: t.LeaseUntil.Unix()}
		identity.Teams = t.AuthorizedTeams
		token, err := executiontoken.SignExecutionToken([]byte(c.SigningKey), identity)
		if err != nil {
			return taskHTTPError(err)
		}
		claims = append(claims, TaskClaim{t.ID, *t.SessionID, t.Generation, token})
	}
	return ctx.JSON(http.StatusOK, map[string]any{"jobs": claims})
}

func (c *TaskController) updateLease(ctx echo.Context, finalize bool) error {
	worker, err := taskWorker(ctx)
	if err != nil {
		return err
	}
	var body struct {
		Generation int64 `json:"generation"`
		Status     int   `json:"status"`
	}
	if err := ctx.Bind(&body); err != nil || body.Generation <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "generation required")
	}
	id := ctx.Param("id")
	if !taskIDPattern.MatchString(id) {
		return taskHTTPError(kvstore.ErrNotFound)
	}
	var record *repo.TaskRecord
	if finalize {
		record, err = c.Queue.Finalize(ctx.Request().Context(), id, worker, body.Generation, body.Status)
	} else {
		record, err = c.Queue.Heartbeat(ctx.Request().Context(), id, worker, body.Generation)
	}
	if err != nil {
		return taskHTTPError(err)
	}
	return ctx.JSON(http.StatusOK, map[string]any{"state": record.State, "lease_expires_at": record.LeaseUntil})
}

func (c *TaskController) Heartbeat(ctx echo.Context) error { return c.updateLease(ctx, false) }
func (c *TaskController) Finalize(ctx echo.Context) error  { return c.updateLease(ctx, true) }
