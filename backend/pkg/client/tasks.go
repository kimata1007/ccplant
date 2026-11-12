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

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
)

type TaskSubmission struct {
	TaskID    string             `json:"task_id"`
	State     entities.TaskState `json:"state"`
	SessionID *string            `json:"session_id"`
	RetryOf   string             `json:"retry_of,omitempty"`
}

type TaskAPIError struct {
	Status  int
	Message string
}

func (e *TaskAPIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message) }

func (c *Client) taskRequest(ctx context.Context, method, path, key string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if err := c.applyMiddlewares(req); err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var result struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
		if result.Message == "" {
			result.Message = http.StatusText(resp.StatusCode)
		}
		return &TaskAPIError{resp.StatusCode, result.Message}
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(output)
}

func (c *Client) SubmitTask(ctx context.Context, spec entities.TaskSpec, key string) (TaskSubmission, error) {
	var result TaskSubmission
	err := c.taskRequest(ctx, http.MethodPost, "/tasks", key, spec, &result)
	return result, err
}

func (c *Client) ListTasks(ctx context.Context, query url.Values) (entities.TaskList, error) {
	var result entities.TaskList
	err := c.taskRequest(ctx, http.MethodGet, "/tasks?"+query.Encode(), "", nil, &result)
	return result, err
}

func (c *Client) ShowTask(ctx context.Context, id string) (entities.Task, error) {
	var result entities.Task
	err := c.taskRequest(ctx, http.MethodGet, "/tasks/"+url.PathEscape(id), "", nil, &result)
	return result, err
}

func (c *Client) CancelTask(ctx context.Context, id string) (entities.Task, error) {
	var result entities.Task
	err := c.taskRequest(ctx, http.MethodPost, "/tasks/"+url.PathEscape(id)+"/cancel", "", nil, &result)
	return result, err
}

func (c *Client) RetryTask(ctx context.Context, id, key string) (TaskSubmission, error) {
	var result TaskSubmission
	err := c.taskRequest(ctx, http.MethodPost, "/tasks/"+url.PathEscape(id)+"/retry", key, nil, &result)
	return result, err
}

func (c *Client) ResumeAttachedSession(ctx context.Context, id string) error {
	return c.taskRequest(ctx, http.MethodPost, "/sessions/"+url.PathEscape(id)+"/resume", "", nil, nil)
}

func (c *Client) WatchTaskChanges(ctx context.Context, query url.Values) (<-chan struct{}, <-chan error) {
	events, failures := make(chan struct{}, 1), make(chan error, 1)
	go func() {
		defer close(events)
		defer close(failures)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/tasks/stream?"+query.Encode(), nil)
		if err == nil {
			err = c.applyMiddlewares(req)
		}
		if err != nil {
			failures <- err
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			failures <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			failures <- &TaskAPIError{resp.StatusCode, http.StatusText(resp.StatusCode)}
			return
		}
		notify := func() {
			select {
			case events <- struct{}{}:
			default:
			}
		}
		notify()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data:") {
				notify()
			}
		}
		if err := scanner.Err(); err != nil {
			failures <- err
		}
	}()
	return events, failures
}

// StartLocalTaskSession uses the ordinary session API and returns the
// server-assigned ID. The caller must reconcile any ambiguous result by tag.
func (c *Client) StartLocalTaskSession(ctx context.Context, request entities.StartRequest) (string, error) {
	var result StartResponse
	if err := c.taskRequest(ctx, http.MethodPost, "/start", "", request, &result); err != nil {
		return "", err
	}
	if result.SessionID == "" {
		return "", fmt.Errorf("session creation response has no session ID")
	}
	return result.SessionID, nil
}
