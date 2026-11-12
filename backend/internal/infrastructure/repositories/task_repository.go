package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	port "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const taskLabel = "agentapi.proxy/task-record"

type TaskRepository struct {
	store     kvstore.Store
	namespace string
}

func NewTaskRepository(store kvstore.Store, namespace string) *TaskRepository {
	return &TaskRepository{store: store, namespace: namespace}
}

func taskLabelHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:24])
}

func taskKey(id string) string { return strings.Replace(id, "tsk_", "task-", 1) }

func (r *TaskRepository) encode(task *port.TaskRecord) (kvstore.Record, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return kvstore.Record{}, err
	}
	labels := map[string]string{
		taskLabel:            "true",
		taskLabel + "-scope": string(task.Scope),
		taskLabel + "-state": strings.ToLower(string(task.State)),
		taskLabel + "-owner": taskLabelHash(task.OwnerUserID),
	}
	if task.TeamID != "" {
		labels[taskLabel+"-team"] = taskLabelHash(task.TeamID)
	}
	object := corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: taskKey(task.ID), Namespace: r.namespace, Labels: labels},
		Data:       map[string][]byte{"task": data},
	}
	raw, err := json.Marshal(&object)
	return kvstore.Record{Kind: kvstore.KindSecret, Namespace: r.namespace, Key: object.Name, Labels: labels, Value: raw, Version: task.Version}, err
}

func decodeTask(record kvstore.Record) (*port.TaskRecord, error) {
	var object corev1.Secret
	var task port.TaskRecord
	if err := json.Unmarshal(record.Value, &object); err != nil {
		return nil, err
	}
	if object.Labels[taskLabel] != "true" {
		return nil, kvstore.ErrNotFound
	}
	if err := json.Unmarshal(object.Data["task"], &task); err != nil {
		return nil, err
	}
	task.Version = record.Version
	return &task, nil
}

func (r *TaskRepository) Create(ctx context.Context, task *port.TaskRecord) error {
	record, err := r.encode(task)
	if err != nil {
		return err
	}
	created, err := r.store.Create(ctx, record)
	if err == nil {
		task.Version = created.Version
	}
	return err
}

func (r *TaskRepository) Get(ctx context.Context, id string) (*port.TaskRecord, error) {
	record, err := r.store.Get(ctx, kvstore.KindSecret, r.namespace, taskKey(id))
	if err != nil {
		return nil, err
	}
	return decodeTask(record)
}

func (r *TaskRepository) List(ctx context.Context, filter port.TaskFilter) ([]*port.TaskRecord, error) {
	selector := []string{taskLabel + "=true"}
	switch {
	case filter.Owner != "":
		selector = append(selector, taskLabel+"-scope=user", taskLabel+"-owner="+taskLabelHash(filter.Owner))
	case filter.Team != "":
		selector = append(selector, taskLabel+"-scope=team", taskLabel+"-team="+taskLabelHash(filter.Team))
	case filter.AllTeams:
		selector = append(selector, taskLabel+"-scope=team")
	}
	states := filter.States
	if filter.Pending {
		states = []entities.TaskState{entities.TaskQueued, entities.TaskClaimed, entities.TaskStarting}
	}
	if len(states) > 0 {
		names := make([]string, 0, len(states))
		for _, state := range states {
			names = append(names, strings.ToLower(string(state)))
		}
		selector = append(selector, taskLabel+"-state in ("+strings.Join(names, ",")+")")
	}
	records, err := r.store.List(ctx, kvstore.Query{Kind: kvstore.KindSecret, Namespace: r.namespace, LabelSelector: strings.Join(selector, ",")})
	if err != nil {
		return nil, err
	}
	result := make([]*port.TaskRecord, 0, len(records))
	for _, record := range records {
		task, err := decodeTask(record)
		if errors.Is(err, kvstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(states) == 0 || slices.Contains(states, task.State) {
			result = append(result, task)
		}
	}
	return result, nil
}

func (r *TaskRepository) Update(ctx context.Context, task *port.TaskRecord) error {
	record, err := r.encode(task)
	if err != nil {
		return err
	}
	updated, err := r.store.Update(ctx, record)
	if err == nil {
		task.Version = updated.Version
	}
	return err
}

func (r *TaskRepository) Delete(ctx context.Context, task *port.TaskRecord) error {
	return r.store.Delete(ctx, kvstore.KindSecret, r.namespace, taskKey(task.ID), task.Version)
}

func (r *TaskRepository) SerializeClaim(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return kvstore.WithRecordLock(ctx, r.store, kvstore.Record{Kind: kvstore.KindSecret, Namespace: r.namespace, Key: "task-claim"}, fn)
}
