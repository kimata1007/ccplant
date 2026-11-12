package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/pkg/utils"
)

// HTTPClient defines the interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ReportUsage sends response-level usage events collected by a session Stop hook.
func (c *Client) ReportUsage(ctx context.Context, batch *entities.UsageEventBatch) (*entities.UsageInsertResult, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("marshal usage events: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/usage-events", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.applyMiddlewares(req); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("report usage failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var result entities.UsageInsertResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RequestMiddleware is a function that modifies an HTTP request
type RequestMiddleware func(*http.Request) error

// Client represents an agentapi-proxy client
type Client struct {
	baseURL     string
	httpClient  HTTPClient
	middlewares []RequestMiddleware
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// NewClient creates a new agentapi-proxy client with options
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:     baseURL,
		httpClient:  utils.NewDefaultHTTPClient(),
		middlewares: []RequestMiddleware{},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithAPIKeyAuth adds API key authentication middleware
func WithAPIKeyAuth(apiKey string) ClientOption {
	return func(c *Client) {
		c.middlewares = append(c.middlewares, func(req *http.Request) error {
			if apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
			return nil
		})
	}
}

// WithRequestMiddleware adds a custom request middleware
func WithRequestMiddleware(middleware RequestMiddleware) ClientOption {
	return func(c *Client) {
		c.middlewares = append(c.middlewares, middleware)
	}
}

// applyMiddlewares applies all registered middlewares to the request
func (c *Client) applyMiddlewares(req *http.Request) error {
	for _, middleware := range c.middlewares {
		if err := middleware(req); err != nil {
			return fmt.Errorf("middleware error: %w", err)
		}
	}
	return nil
}

// StartParams contains optional session startup parameters.
type StartParams struct {
	Message      string `json:"message,omitempty"`
	Oneshot      bool   `json:"oneshot,omitempty"`
	AgentType    string `json:"agent_type,omitempty"`
	AuthProxy    *bool  `json:"auth_proxy,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
}

// StartRequest represents the request body for starting a new agentapi server
type StartRequest struct {
	ContextTemplateID string            `json:"context_template_id,omitempty"`
	Environment       map[string]string `json:"environment,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	Params            *StartParams      `json:"params,omitempty"`
	Scope             string            `json:"scope,omitempty"`
	TeamID            string            `json:"team_id,omitempty"`
}

// StartResponse represents the response from starting a new agentapi server
type StartResponse struct {
	SessionID string `json:"session_id"`
}

// StartDryRunResponse describes a resolved start without creating a session.
type StartDryRunResponse struct {
	DryRun                   bool                     `json:"dry_run"`
	SessionID                string                   `json:"session_id"`
	Decision                 string                   `json:"decision"`
	EffectiveRequest         map[string]interface{}   `json:"effective_request,omitempty"`
	ResolvedSessionProfileID string                   `json:"resolved_session_profile_id,omitempty"`
	Placement                map[string]interface{}   `json:"placement,omitempty"`
	Settings                 map[string]interface{}   `json:"settings,omitempty"`
	Reuse                    map[string]interface{}   `json:"reuse,omitempty"`
	Effects                  []map[string]interface{} `json:"effects,omitempty"`
	Redactions               []string                 `json:"redactions,omitempty"`
	Warnings                 []string                 `json:"warnings,omitempty"`
}

// SessionInfo represents information about a session
type SessionInfo struct {
	SessionID          string             `json:"session_id"`
	AllocatedSessionID string             `json:"allocated_session_id,omitempty"`
	UserID             string             `json:"user_id"`
	Status             string             `json:"status"`
	Scope              string             `json:"scope"`
	TeamID             string             `json:"team_id"`
	UpdatedAt          time.Time          `json:"updated_at"`
	StartedAt          time.Time          `json:"started_at"`
	Port               int                `json:"port"`
	Tags               map[string]string  `json:"tags,omitempty"`
	Annotations        SessionAnnotations `json:"annotations,omitempty"`
	Metadata           SessionMetadata    `json:"metadata,omitempty"`
}

// SearchResponse represents the response from searching sessions
type SearchResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

// SessionAnnotations contains user-managed annotations attached to a session.
type SessionAnnotations struct {
	PRURL       string `json:"pr_url,omitempty"`
	IssueURL    string `json:"issue_url,omitempty"`
	Description string `json:"description,omitempty"`
	RunningTask string `json:"running_task,omitempty"`
}

// SessionMetadata contains additional session metadata returned by /search.
type SessionMetadata struct {
	Description string `json:"description,omitempty"`
}

// UpdateSessionAnnotationsRequest partially updates user-managed session annotations.
// Nil fields are left unchanged; an explicit empty string clears that annotation.
type UpdateSessionAnnotationsRequest struct {
	PRURL       *string `json:"pr_url,omitempty"`
	IssueURL    *string `json:"issue_url,omitempty"`
	Description *string `json:"description,omitempty"`
	RunningTask *string `json:"running_task,omitempty"`
}

// UpdateSessionAnnotationsResponse is returned after updating session annotations.
type UpdateSessionAnnotationsResponse struct {
	SessionID   string             `json:"session_id"`
	Annotations SessionAnnotations `json:"annotations"`
	Metadata    SessionMetadata    `json:"metadata,omitempty"`
}

// Message represents an agentapi message
type Message struct {
	Content   string          `json:"content"`
	Type      string          `json:"type"` // "user" or "raw"
	Role      string          `json:"role,omitempty"`
	Timestamp *time.Time      `json:"timestamp,omitempty"`
	Time      *time.Time      `json:"time,omitempty"`
	ID        json.RawMessage `json:"id,omitempty"`
}

// GetTimestamp returns the message timestamp, checking both Time and Timestamp fields.
func (m *Message) GetTimestamp() *time.Time {
	if m.Time != nil {
		return m.Time
	}
	return m.Timestamp
}

// MessageResponse represents the response from sending a message
type MessageResponse struct {
	OK bool `json:"ok"`
}

// MessagesResponse represents the response from getting messages
type MessagesResponse struct {
	Messages []Message `json:"messages"`
}

// StatusResponse represents the agent status
type StatusResponse struct {
	Status string `json:"status"` // "stable" or "running"
}

// DeleteResponse represents the response from deleting a session
type DeleteResponse struct {
	Message   string `json:"message"`
	SessionID string `json:"session_id"`
}

// Start creates a new agentapi session
func (c *Client) Start(ctx context.Context, req *StartRequest) (*StartResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/start", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var startResp StartResponse
	if err := json.NewDecoder(resp.Body).Decode(&startResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &startResp, nil
}

// DryRunStart resolves a session start request without creating a session.
func (c *Client) DryRunStart(ctx context.Context, req *StartRequest) (*StartDryRunResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/start?dry_run=true", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	var preview StartDryRunResponse
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &preview, nil
}

// Search lists and filters sessions
func (c *Client) Search(ctx context.Context, status string) (*SearchResponse, error) {
	return c.SearchWithTags(ctx, status, nil)
}

// SearchWithTags lists and filters sessions with tag support
func (c *Client) SearchWithTags(ctx context.Context, status string, tags map[string]string) (*SearchResponse, error) {
	return c.SearchScoped(ctx, status, tags, "", "")
}

func (c *Client) SearchScoped(ctx context.Context, status string, tags map[string]string, scope, team string) (*SearchResponse, error) {
	u, err := url.Parse(c.baseURL + "/search")
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	if scope != "" {
		q.Set("scope", scope)
	}
	if team != "" {
		q.Set("team_id", team)
	}
	if status != "" {
		q.Set("status", status)
	}
	// Add tag filters
	for key, value := range tags {
		q.Set("tag."+key, value)
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var searchResp SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &searchResp, nil
}

// GetSessionByID retrieves a single session by its ID.
// It calls the search endpoint and returns the first session with a matching SessionID.
// Returns an error if the session is not found.
func (c *Client) GetSessionByID(ctx context.Context, sessionID string) (*SessionInfo, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}

	resp, err := c.Search(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to search sessions: %w", err)
	}

	for i := range resp.Sessions {
		if resp.Sessions[i].SessionID == sessionID {
			return &resp.Sessions[i], nil
		}
	}

	return nil, fmt.Errorf("session %s not found", sessionID)
}

// DeleteSession terminates and deletes a session
func (c *Client) DeleteSession(ctx context.Context, sessionID string) (*DeleteResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}

	url := fmt.Sprintf("%s/sessions/%s", c.baseURL, sessionID)
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("session not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var deleteResp DeleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&deleteResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &deleteResp, nil
}

// UpdateSessionAnnotations updates user-managed annotations for a session.
func (c *Client) UpdateSessionAnnotations(ctx context.Context, sessionID string, req *UpdateSessionAnnotationsRequest) (*UpdateSessionAnnotationsResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/sessions/%s/annotations", c.baseURL, sessionID)
	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var updateResp UpdateSessionAnnotationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &updateResp, nil
}

// SendMessage sends a message to an agentapi session
func (c *Client) SendMessage(ctx context.Context, sessionID string, message *Message) (*MessageResponse, error) {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	url := fmt.Sprintf("%s/%s/message", c.baseURL, sessionID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var msgResp MessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&msgResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &msgResp, nil
}

// GetMessages retrieves conversation history from an agentapi session
func (c *Client) GetMessages(ctx context.Context, sessionID string) (*MessagesResponse, error) {
	url := fmt.Sprintf("%s/%s/messages", c.baseURL, sessionID)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var messagesResp MessagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&messagesResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &messagesResp, nil
}

// GetStatus retrieves the current agent status from an agentapi session
func (c *Client) GetStatus(ctx context.Context, sessionID string) (*StatusResponse, error) {
	url := fmt.Sprintf("%s/%s/status", c.baseURL, sessionID)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var statusResp StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &statusResp, nil
}

// SendNotificationRequest represents the request for sending a push notification via API
type SendNotificationRequest struct {
	Title     string `json:"title"`
	Body      string `json:"body"`
	SessionID string `json:"session_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

// SendNotificationResponse represents the response for sending a push notification via API
type SendNotificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SendNotification sends a push notification via the API.
// Either SessionID or UserID must be specified.
func (c *Client) SendNotification(ctx context.Context, req *SendNotificationRequest) (*SendNotificationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/notifications/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var sendResp SendNotificationResponse
	if err := json.NewDecoder(resp.Body).Decode(&sendResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &sendResp, nil
}

// StreamEvents subscribes to Server-Sent Events (SSE) from an agentapi session
func (c *Client) StreamEvents(ctx context.Context, sessionID string) (<-chan string, <-chan error) {
	eventChan := make(chan string, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(eventChan)
		defer close(errorChan)

		url := fmt.Sprintf("%s/%s/events", c.baseURL, sessionID)
		httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			errorChan <- fmt.Errorf("failed to create request: %w", err)
			return
		}
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set("Cache-Control", "no-cache")

		if err := c.applyMiddlewares(httpReq); err != nil {
			errorChan <- err
			return
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			errorChan <- fmt.Errorf("failed to send request: %w", err)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			errorChan <- fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			select {
			case eventChan <- line:
			case <-ctx.Done():
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading response: %w", err)
		}
	}()

	return eventChan, errorChan
}

// ProxySessionStatusEvent is a proxy-level event emitted whenever any session's status changes.
type ProxySessionStatusEvent struct {
	SessionID string    `json:"session_id"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// WatchSessionsStatus subscribes to proxy-wide session status changes via SSE.
// The returned channel receives a ProxySessionStatusEvent whenever any accessible session
// changes status. The caller must cancel ctx to stop the stream; both channels are closed
// when the stream ends.
func (c *Client) WatchSessionsStatus(ctx context.Context) (<-chan ProxySessionStatusEvent, <-chan error) {
	eventChan := make(chan ProxySessionStatusEvent, 32)
	errorChan := make(chan error, 1)

	go func() {
		defer close(eventChan)
		defer close(errorChan)

		reqURL := fmt.Sprintf("%s/sessions/status/stream", c.baseURL)
		httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			errorChan <- fmt.Errorf("failed to create request: %w", err)
			return
		}
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set("Cache-Control", "no-cache")

		if err := c.applyMiddlewares(httpReq); err != nil {
			errorChan <- err
			return
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			errorChan <- fmt.Errorf("failed to send request: %w", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			errorChan <- fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue // skip heartbeat comments and blank lines
			}
			var evt ProxySessionStatusEvent
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt); err != nil {
				continue // skip malformed events
			}
			select {
			case eventChan <- evt:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errorChan <- fmt.Errorf("error reading stream: %w", err)
		}
	}()

	return eventChan, errorChan
}

// WaitSessionsStatus long-polls for the next proxy-wide session status change.
// It blocks until any accessible session changes status or until the timeout elapses.
// Returns the event on change, or (nil, nil) on timeout.
// timeoutSec=0 uses the server default (30 s). Valid range: 1–60.
func (c *Client) WaitSessionsStatus(ctx context.Context, timeoutSec int) (*ProxySessionStatusEvent, error) {
	u, err := url.Parse(fmt.Sprintf("%s/sessions/status/wait", c.baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	if timeoutSec > 0 {
		q := u.Query()
		q.Set("timeout", fmt.Sprintf("%d", timeoutSec))
		u.RawQuery = q.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if err := c.applyMiddlewares(httpReq); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Timeout response: {"events": []}
	var evt ProxySessionStatusEvent
	if err := json.Unmarshal(body, &evt); err != nil || evt.SessionID == "" {
		return nil, nil
	}
	return &evt, nil
}
