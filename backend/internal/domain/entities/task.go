package entities

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const LocalTaskTag = "ccplant_local_task_dispatch"

const TaskBodyLimit = 256 << 10

type TaskState string

const (
	TaskQueued    TaskState = "QUEUED"
	TaskClaimed   TaskState = "CLAIMED"
	TaskStarting  TaskState = "STARTING"
	TaskReady     TaskState = "SESSION_READY"
	TaskFailed    TaskState = "FAILED"
	TaskCancelled TaskState = "CANCELLED"
	TaskExpired   TaskState = "EXPIRED"
)

func (s TaskState) Pending() bool {
	return s == TaskQueued || s == TaskClaimed || s == TaskStarting
}

func (s TaskState) Valid() bool {
	return s.Pending() || s == TaskReady || s == TaskFailed || s == TaskCancelled || s == TaskExpired
}

// TaskSpec is an allowlist of public StartRequest fields safe to persist.
// Credentials and runtime configuration come from the existing profile resolver.
type TaskSpec struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Metadata   struct {
		Name string `json:"name" yaml:"name"`
	} `json:"metadata" yaml:"metadata"`
	Spec struct {
		Start TaskStart `json:"start" yaml:"start"`
		Queue struct {
			Priority int    `json:"priority,omitempty" yaml:"priority,omitempty"`
			MaxWait  string `json:"max_wait,omitempty" yaml:"max_wait,omitempty"`
		} `json:"queue,omitempty" yaml:"queue,omitempty"`
	} `json:"spec" yaml:"spec"`
}

// TaskStart mirrors the persisted subset of StartRequest. SessionProfileID is
// optional: when empty, session start resolves the user's or team's default
// profile, the same as POST /start.
type TaskStart struct {
	Scope            ResourceScope     `json:"scope,omitempty" yaml:"scope,omitempty"`
	TeamID           string            `json:"team_id,omitempty" yaml:"team_id,omitempty"`
	SessionProfileID string            `json:"session_profile_id,omitempty" yaml:"session_profile_id,omitempty"`
	WorkspaceID      string            `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`
	Tags             map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Environment      map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
	Params           struct {
		Message   string `json:"message" yaml:"message"`
		Pool      string `json:"pool,omitempty" yaml:"pool,omitempty"`
		ManagerID string `json:"manager_id,omitempty" yaml:"manager_id,omitempty"`
	} `json:"params" yaml:"params"`
}

func (s TaskStart) Request() StartRequest {
	return StartRequest{Scope: s.Scope, TeamID: s.TeamID, SessionProfileID: s.SessionProfileID, WorkspaceID: s.WorkspaceID,
		Tags: s.Tags, Environment: s.Environment, Params: &SessionParams{Message: s.Params.Message, Pool: s.Params.Pool, ManagerID: s.Params.ManagerID}}
}

var ErrTaskEnvironment = errors.New("task environment must use a Session Profile or Secret for settings other than TZ, LANG and LC_ALL")

var taskLocale = regexp.MustCompile(`^(C|POSIX|[a-z]{2,3}(_[A-Z]{2})?)(\.(UTF-8|utf8))?$`)

func DecodeTaskSpec(data []byte, isYAML bool) (TaskSpec, error) {
	var spec TaskSpec
	if len(data) > TaskBodyLimit {
		return spec, errors.New("task definition exceeds 256 KiB")
	}
	if isYAML {
		// Decode scalar types before applying the JSON contract. Decoding YAML
		// straight into string fields would silently accept numbers and booleans.
		d := yaml.NewDecoder(bytes.NewReader(data))
		var value any
		if err := d.Decode(&value); err != nil {
			return spec, errors.New("invalid YAML task definition")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return spec, errors.New("exactly one task definition is required")
		}
		var err error
		data, err = json.Marshal(value)
		if err != nil {
			return spec, errors.New("invalid YAML task definition")
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	// Decoder errors can contain submitted values, including rejected secrets.
	if err := d.Decode(&spec); err != nil {
		return spec, errors.New("invalid task definition: check field names and types")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return spec, errors.New("exactly one task definition is required")
	}
	return spec, spec.Validate()
}

func (s *TaskSpec) Validate() error {
	start := &s.Spec.Start
	if s.APIVersion != "ccplant.io/v1alpha1" || s.Kind != "Task" {
		return errors.New("expected apiVersion ccplant.io/v1alpha1 and kind Task")
	}
	if s.Metadata.Name == "" || len(s.Metadata.Name) > 128 || strings.ContainsFunc(s.Metadata.Name, unicode.IsControl) {
		return errors.New("metadata.name must contain 1 to 128 bytes of plain text")
	}
	if start.Scope == "" {
		start.Scope = ScopeUser
	}
	if (start.Scope != ScopeUser && start.Scope != ScopeTeam) || (start.Scope == ScopeUser && start.TeamID != "") {
		return errors.New("invalid task scope or team_id")
	}
	start.SessionProfileID = strings.TrimSpace(start.SessionProfileID)
	if strings.TrimSpace(start.Params.Message) == "" || len(start.Params.Message) > 128<<10 {
		return errors.New("an initial message of at most 128 KiB is required")
	}
	for _, field := range []string{start.TeamID, start.SessionProfileID, start.WorkspaceID, start.Params.ManagerID, start.Params.Pool} {
		if len(field) > 256 {
			return errors.New("scope, profile, workspace, pool and manager identifiers may be at most 256 bytes")
		}
	}
	if len(start.Tags) > 32 {
		return errors.New("at most 32 tags are allowed")
	}
	for key, value := range start.Tags {
		switch key {
		case "task_id", "schedule_id", "webhook_id", "slackbot_id", LocalTaskTag:
			return errors.New("reserved session origin tag")
		}
		if key == "" || len(key) > 128 || len(value) > 512 {
			return errors.New("invalid tag length")
		}
	}
	for key, value := range start.Environment {
		switch key {
		case "TZ":
			if len(value) > 64 || value == "" || value == "Local" {
				return ErrTaskEnvironment
			}
			if _, err := time.LoadLocation(value); err != nil {
				return ErrTaskEnvironment
			}
		case "LANG", "LC_ALL":
			if !taskLocale.MatchString(value) {
				return ErrTaskEnvironment
			}
		default:
			return ErrTaskEnvironment
		}
	}
	if s.Spec.Queue.Priority < -10 || s.Spec.Queue.Priority > 10 {
		return errors.New("queue.priority must be between -10 and 10")
	}
	wait, err := time.ParseDuration(s.Spec.Queue.MaxWait)
	if s.Spec.Queue.MaxWait == "" {
		wait, err = 24*time.Hour, nil
	}
	if err != nil || wait <= 0 || wait > 30*24*time.Hour {
		return errors.New("queue.max_wait must be a positive duration of at most 720h")
	}
	s.Spec.Queue.MaxWait = wait.String()
	return nil
}

type TaskEvent struct {
	Seq   int64     `json:"seq"`
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Type  string    `json:"type"`
	State TaskState `json:"state"`
}

type Task struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	OwnerUserID     string        `json:"owner_user_id"`
	Scope           ResourceScope `json:"scope"`
	TeamID          string        `json:"team_id,omitempty"`
	State           TaskState     `json:"state"`
	SessionID       *string       `json:"session_id"`
	RetryOf         string        `json:"retry_of,omitempty"`
	Attempt         int           `json:"attempt"`
	Priority        int           `json:"priority"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	ClaimedAt       *time.Time    `json:"claimed_at,omitempty"`
	StartedAt       *time.Time    `json:"started_at,omitempty"`
	FinishedAt      *time.Time    `json:"finished_at,omitempty"`
	CancelRequested bool          `json:"cancel_requested,omitempty"`
	Reason          string        `json:"reason,omitempty"`
	SessionMissing  bool          `json:"session_missing,omitempty"`
	Seq             int64         `json:"seq"`
}

type TaskList struct {
	Items      []Task `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}
