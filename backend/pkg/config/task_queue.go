package config

import "errors"

func (c *Config) ValidateTaskQueue() error {
	q := c.TaskQueue
	if !q.Enabled {
		return nil
	}
	if c.Worker.ControlAPIToken == "" || c.Worker.ExecutionTokenSigningKey == "" {
		return errors.New("task queue requires AGENTAPI_WORKER_CONTROL_TOKEN and AGENTAPI_EXECUTION_TOKEN_SIGNING_KEY")
	}
	if q.MaxStartingGlobal < 0 || q.MaxStartingPerUser < 0 || q.MaxStartingPerTeam < 0 || q.MaxLivePerUser < 0 || q.MaxLivePerTeam < 0 ||
		q.MaxPending <= 0 || q.RetentionDays <= 0 || q.TeamRetentionDays <= 0 {
		return errors.New("task queue limits must be nonnegative and pending and retention limits must be positive")
	}
	return nil
}
