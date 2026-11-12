package kvstore

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

var ErrNotFound = errors.New("kv record not found")
var ErrConflict = errors.New("kv record version conflict")
var ErrInDoubt = errors.New("kv replication state is in doubt")
var ErrUnboundedQuery = errors.New("kv list query requires a label selector")
var ErrAccessDenied = errors.New("kv record access denied")

type Kind string

const (
	KindSecret    Kind = "secret"
	KindConfigMap Kind = "configmap"
)

// Record is the storage-neutral representation of a Kubernetes object used as
// a KV document. Value contains the complete JSON object to preserve metadata.
type Record struct {
	Kind       Kind
	Namespace  string
	Key        string
	Labels     map[string]string
	OwnerScope string
	Value      []byte
	Version    int64
}

type Query struct {
	// Unshared prevents a quota check from joining an older in-flight read.
	Unshared      bool
	Kind          Kind
	Namespace     string
	LabelSelector string
	KeyPrefix     string
}

// ScanQuery is intentionally separate from Query. Scanning is an operational
// capability used by migration and verification tooling; application code must
// use List with an indexed label selector.
type ScanQuery struct {
	Kind      Kind
	Namespace string
}

// Store is the single persistence boundary for Kubernetes-backed KV data.
type Store interface {
	Create(context.Context, Record) (Record, error)
	Update(context.Context, Record) (Record, error)
	Get(context.Context, Kind, string, string) (Record, error)
	Delete(context.Context, Kind, string, string, int64) error
	List(context.Context, Query) ([]Record, error)
	Close() error
}

// Scanner exposes unbounded iteration to offline administrative workflows.
// It must not be injected into request-serving application components.
type Scanner interface {
	Scan(context.Context, ScanQuery) ([]Record, error)
}

func ValidateListQuery(query Query) error {
	if query.LabelSelector == "" {
		return ErrUnboundedQuery
	}
	selector, err := labels.Parse(query.LabelSelector)
	if err != nil {
		return fmt.Errorf("parse label selector: %w", err)
	}
	requirements, selectable := selector.Requirements()
	if !selectable {
		return ErrUnboundedQuery
	}
	for _, requirement := range requirements {
		switch requirement.Operator() {
		case selection.Equals, selection.DoubleEquals, selection.In:
			if requirement.Values().Len() > 0 {
				return nil
			}
		}
	}
	// Negative and existence-only selectors can match an entire namespace and
	// therefore do not constitute a bounded index partition.
	return ErrUnboundedQuery
}
