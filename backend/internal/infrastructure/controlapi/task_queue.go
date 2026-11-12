package controlapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
)

type TaskJob struct {
	TaskID         string `json:"task_id"`
	SessionID      string `json:"session_id"`
	Generation     int64  `json:"generation"`
	ExecutionToken string `json:"execution_token"`
}

func (m *SessionManager) ClaimTasks(ctx context.Context, worker string, limit int) ([]TaskJob, error) {
	var result struct {
		Jobs []TaskJob `json:"jobs"`
	}
	err := m.doWithWorker(ctx, http.MethodPost, "/internal/worker/tasks/claim-due?limit="+strconv.Itoa(limit), worker, nil, &result)
	return result.Jobs, err
}

// StartTask sends no task data. /start loads the persisted request only after
// validating and fencing the signed execution against the active lease.
func (m *SessionManager) StartTask(ctx context.Context, job TaskJob) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.sessionAPIURL, "/")+"/start", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+job.ExecutionToken)
	req.Header.Set("Idempotency-Key", task.ExecutionID(job.TaskID, job.Generation))
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var result struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil || result.SessionID != job.SessionID {
			return 0, fmt.Errorf("unexpected task start response")
		}
	}
	return resp.StatusCode, nil
}

func (m *SessionManager) FinalizeTask(ctx context.Context, worker string, job TaskJob, status int) error {
	return m.doWithWorker(ctx, http.MethodPost, "/internal/worker/tasks/"+job.TaskID+"/finalize", worker, map[string]any{"generation": job.Generation, "status": status}, nil)
}

func (m *SessionManager) HeartbeatTask(ctx context.Context, worker string, job TaskJob) error {
	return m.doWithWorker(ctx, http.MethodPost, "/internal/worker/tasks/"+job.TaskID+"/heartbeat", worker, map[string]any{"generation": job.Generation}, nil)
}

func (m *SessionManager) PruneTasks(ctx context.Context) error {
	return m.do(ctx, http.MethodPost, "/internal/worker/tasks/prune", nil, nil)
}
