package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	portrepos "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/pkg/telemetry"
	"github.com/takutakahashi/agentapi-proxy/pkg/utils"
)

// SessionManager is a worker-side port that delegates every session operation
// to HTTP APIs. Trigger-backed creation uses the normal /start API; lifecycle
// operations use the control API. It has no Kubernetes dependency.
type SessionManager struct {
	baseURL, token    string
	sessionAPIURL     string
	executionTokenKey string
	client            *http.Client
}

// HTTPStatusError preserves the response status so callers can distinguish a
// permanent authentication/contract failure from a transient API outage.
type HTTPStatusError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("control API %s %s returned %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

type sessionInfo struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id"`
	Scope         entities.ResourceScope `json:"scope"`
	TeamID        string                 `json:"team_id"`
	Tags          map[string]string      `json:"tags"`
	Status        string                 `json:"status"`
	StartedAt     time.Time              `json:"started_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	LastMessageAt time.Time              `json:"last_message_at"`
}

type ScheduleJob struct {
	ScheduleID     string                `json:"schedule_id"`
	ExecutionID    string                `json:"execution_id"`
	SessionID      string                `json:"session_id"`
	ExecutionToken string                `json:"execution_token"`
	StartRequest   entities.StartRequest `json:"start_request"`
}

func (m *SessionManager) ClaimDueSchedules(ctx context.Context) ([]ScheduleJob, error) {
	var result struct {
		Jobs []ScheduleJob `json:"jobs"`
	}
	err := m.do(ctx, http.MethodPost, "/internal/worker/schedules/claim-due", nil, &result)
	return result.Jobs, err
}

func (m *SessionManager) StartScheduledSession(ctx context.Context, apiURL string, job ScheduleJob) (string, bool, error) {
	return m.startSession(ctx, apiURL, job.StartRequest, job.ExecutionToken, job.ExecutionID)
}

func (m *SessionManager) startSession(ctx context.Context, apiURL string, start entities.StartRequest, token, executionID string) (string, bool, error) {
	type startResult struct {
		id     string
		reused bool
	}
	result, err := telemetry.LoggedOperation(ctx, "controlapi.StartSession", func(operationCtx context.Context) (startResult, error) {
		id, reused, requestErr := m.startSessionRequest(operationCtx, apiURL, start, token, executionID)
		return startResult{id: id, reused: reused}, requestErr
	}, telemetry.String("session.execution_id", executionID), telemetry.Bool("session.reuse_requested", len(start.ReuseMatchTags) > 0))
	return result.id, result.reused, err
}

func (m *SessionManager) startSessionRequest(ctx context.Context, apiURL string, start entities.StartRequest, token, executionID string) (string, bool, error) {
	data, err := m.startSessionResponse(ctx, apiURL, start, token, executionID, false)
	if err != nil {
		return "", false, err
	}
	var result struct {
		SessionID     string `json:"session_id"`
		SessionReused bool   `json:"session_reused"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", false, err
	}
	if result.SessionID == "" {
		return "", false, fmt.Errorf("session creation API returned no session_id")
	}
	return result.SessionID, result.SessionReused, nil
}

func (m *SessionManager) startSessionResponse(ctx context.Context, apiURL string, start entities.StartRequest, token, executionID string, dryRun bool) ([]byte, error) {
	body, err := json.Marshal(start)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/start"
	if dryRun {
		endpoint += "?dry_run=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", executionID)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("session creation API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func (m *SessionManager) FinalizeSchedule(ctx context.Context, job ScheduleJob, status, sessionID, message string, sessionReused bool) error {
	return m.do(ctx, http.MethodPost, "/internal/worker/schedules/"+url.PathEscape(job.ScheduleID)+"/finalize", map[string]any{"execution_id": job.ExecutionID, "session_id": sessionID, "status": status, "error": message, "session_reused": sessionReused}, nil)
}

func NewSessionManager(baseURL, token string) *SessionManager {
	// Stock creation waits for a Kubernetes workload to become ready. Keep the
	// transport timeout above the session manager's 120-second pod start timeout
	// so the caller does not cancel an otherwise healthy startup prematurely.
	return &SessionManager{baseURL: strings.TrimRight(baseURL, "/"), token: token, client: utils.NewHTTPClient(utils.HTTPClientConfig{Timeout: 150 * time.Second})}
}

func (m *SessionManager) WithExecutionTokenSigningKey(key string) *SessionManager {
	m.executionTokenKey = key
	return m
}

func (m *SessionManager) CreateSession(ctx context.Context, id string, request *entities.RunServerRequest, webhookPayload []byte) (entities.Session, error) {
	if request.Tags["slackbot_id"] != "" || request.Tags["schedule_id"] != "" || request.Tags["webhook_id"] != "" {
		return m.startTriggerSession(ctx, id, request, webhookPayload)
	}
	var info sessionInfo
	if err := m.do(ctx, http.MethodPost, "/internal/worker/sessions/"+url.PathEscape(id), request, &info); err != nil {
		return nil, err
	}
	return info.entity(), nil
}
func (m *SessionManager) GetSession(id string) entities.Session {
	sessions := m.ListSessions(entities.SessionFilter{})
	for _, session := range sessions {
		if session.ID() == id {
			return session
		}
	}
	return nil
}
func (m *SessionManager) ListSessions(filter entities.SessionFilter) []entities.Session {
	result, _ := m.ListSessionsContext(context.Background(), filter)
	return result
}
func (m *SessionManager) ListSessionsContext(ctx context.Context, filter entities.SessionFilter) ([]entities.Session, error) {
	return telemetry.LoggedOperation(ctx, "controlapi.ListSessions", func(operationCtx context.Context) ([]entities.Session, error) {
		return m.listSessionsContext(operationCtx, filter)
	}, telemetry.Int64("session.filter_tag_count", int64(len(filter.Tags))))
}

func (m *SessionManager) listSessionsContext(ctx context.Context, filter entities.SessionFilter) ([]entities.Session, error) {
	query := make(url.Values)
	if filter.UserID != "" {
		query.Set("user_id", filter.UserID)
	}
	if filter.Status != "" {
		query.Set("status", filter.Status)
	}
	if filter.Scope != "" {
		query.Set("scope", string(filter.Scope))
	}
	if filter.TeamID != "" {
		query.Set("team_id", filter.TeamID)
	}
	if len(filter.TeamIDs) > 0 {
		query.Set("team_ids", strings.Join(filter.TeamIDs, ","))
	}
	keys := make([]string, 0, len(filter.Tags))
	for key := range filter.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		query.Set("tag."+key, filter.Tags[key])
	}
	path := "/internal/worker/sessions"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var infos []sessionInfo
	if err := m.do(ctx, http.MethodGet, path, nil, &infos); err != nil {
		return nil, err
	}
	result := make([]entities.Session, 0, len(infos))
	for _, info := range infos {
		session := info.entity()
		if matches(session, filter) {
			result = append(result, session)
		}
	}
	return result, nil
}
func (m *SessionManager) DeleteSession(id string) error {
	return m.do(context.Background(), http.MethodDelete, "/internal/worker/sessions/"+url.PathEscape(id), nil, nil)
}
func (m *SessionManager) SendMessage(ctx context.Context, id, message string) error {
	return m.do(ctx, http.MethodPost, "/internal/worker/sessions/"+url.PathEscape(id)+"/messages", map[string]string{"message": message}, nil)
}
func (m *SessionManager) StopAgent(ctx context.Context, id string) error {
	return m.do(ctx, http.MethodPost, "/internal/worker/sessions/"+url.PathEscape(id)+"/stop", nil, nil)
}
func (m *SessionManager) GetMessages(context.Context, string) ([]portrepos.Message, error) {
	return nil, fmt.Errorf("messages are not supported by worker control API")
}
func (m *SessionManager) Shutdown(time.Duration) error { return nil }
func (m *SessionManager) CreateStockSession(ctx context.Context, dind bool) error {
	return m.do(ctx, http.MethodPost, "/internal/worker/stock?dind="+strconv.FormatBool(dind), nil, nil)
}
func (m *SessionManager) CountStockSessions(ctx context.Context, dind bool) (int, error) {
	var result struct {
		Count int `json:"count"`
	}
	err := m.do(ctx, http.MethodGet, "/internal/worker/stock?dind="+strconv.FormatBool(dind), nil, &result)
	return result.Count, err
}
func (m *SessionManager) PurgeStaleStockSessions(ctx context.Context) error {
	return m.do(ctx, http.MethodDelete, "/internal/worker/stock", nil, nil)
}

type leaseRequest struct {
	Action     string `json:"action"`
	Identity   string `json:"identity"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

func (m *SessionManager) lease(ctx context.Context, key, identity, action string, duration time.Duration) (bool, error) {
	var result struct {
		Acquired bool `json:"acquired"`
	}
	err := m.do(ctx, http.MethodPost, "/internal/worker/leases/"+url.PathEscape(key), leaseRequest{Action: action, Identity: identity, DurationMS: duration.Milliseconds()}, &result)
	return result.Acquired, err
}

func (m *SessionManager) Acquire(ctx context.Context, key, identity string, duration time.Duration) (bool, error) {
	return m.lease(ctx, key, identity, "acquire", duration)
}
func (m *SessionManager) Renew(ctx context.Context, key, identity string, duration time.Duration) (bool, error) {
	return m.lease(ctx, key, identity, "renew", duration)
}
func (m *SessionManager) Release(ctx context.Context, key, identity string) (bool, error) {
	return m.lease(ctx, key, identity, "release", 0)
}

func (m *SessionManager) do(ctx context.Context, method, path string, input, output any) error {
	return m.doWithWorker(ctx, method, path, "", input, output)
}

func (m *SessionManager) doWithWorker(ctx context.Context, method, path, worker string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	if worker != "" {
		req.Header.Set("X-Task-Worker", worker)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return &HTTPStatusError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if output != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(output)
	}
	return nil
}

func (i sessionInfo) entity() entities.Session {
	session := entities.NewProxySessionWithStatus(i.ID, i.UserID, i.Scope, i.TeamID, i.Tags, i.StartedAt, i.Status)
	session.SetUpdatedAt(i.UpdatedAt)
	session.SetLastMessageAt(i.LastMessageAt)
	return session
}
func matches(session entities.Session, filter entities.SessionFilter) bool {
	if filter.UserID != "" && session.UserID() != filter.UserID {
		return false
	}
	if filter.Status != "" && session.Status() != filter.Status {
		return false
	}
	if filter.Scope != "" && session.Scope() != filter.Scope {
		return false
	}
	if filter.TeamID != "" && session.TeamID() != filter.TeamID {
		return false
	}
	for key, value := range filter.Tags {
		if session.Tags()[key] != value {
			return false
		}
	}
	return true
}
