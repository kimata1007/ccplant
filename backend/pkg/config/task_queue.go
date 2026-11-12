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
	return nil
}
