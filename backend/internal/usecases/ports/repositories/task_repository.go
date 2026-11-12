package repositories

import (
	"context"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
)

type TaskRecord struct {
	entities.Task
	Spec            entities.TaskSpec    `json:"spec"`
	AuthorizedTeams []string             `json:"authorized_teams,omitempty"`
	Fingerprint     string               `json:"fingerprint"`
	LeaseOwner      string               `json:"lease_owner,omitempty"`
	LeaseUntil      time.Time            `json:"lease_until,omitzero"`
	RetryAfter      time.Time            `json:"retry_after,omitzero"`
	Generation      int64                `json:"generation"`
	DispatchID      string               `json:"dispatch_id,omitempty"`
	Dispatched      bool                 `json:"dispatched,omitempty"`
	Accepted        bool                 `json:"accepted,omitempty"`
	Events          []entities.TaskEvent `json:"events"`
	Version         int64                `json:"-"`
}

type TaskFilter struct {
	Owner    string
	Team     string
	AllTeams bool
	Pending  bool
	States   []entities.TaskState
}

type TaskRepository interface {
	Create(context.Context, *TaskRecord) error
	Get(context.Context, string) (*TaskRecord, error)
	List(context.Context, TaskFilter) ([]*TaskRecord, error)
	Update(context.Context, *TaskRecord) error
	Delete(context.Context, *TaskRecord) error
	// SerializeClaim coordinates task recovery and claims across API replicas.
	SerializeClaim(context.Context, func(context.Context) error) error
}
