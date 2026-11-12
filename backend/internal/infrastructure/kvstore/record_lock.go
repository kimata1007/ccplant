package kvstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"
)

const (
	recordLockPrefix = "agentapi-kv-replication-lock-"
	recordLockLabel  = "internal.ccplant.io/kv-replication-lock"
	recordLockTTL    = 2 * time.Minute
	recordLockPoll   = 25 * time.Millisecond
)

type recordLockDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

// WithRecordLock serializes a mutation for one logical record through the
// destination store. Replicated request writes and the online migration CLI
// both use this lock so a backfill cannot recreate a concurrently deleted
// record or overwrite a newer replicated value.
//
// Locks are short-lived ConfigMap documents in the destination namespace.
// Their deterministic names make Create the cross-process compare-and-set;
// expired locks left by a crashed process are reclaimed using a versioned
// Delete. The callback must complete within recordLockTTL.
func WithRecordLock(ctx context.Context, destination Store, target Record, callback func(context.Context) error) error {
	lock, owner, err := acquireRecordLock(ctx, destination, target)
	if err != nil {
		return err
	}
	defer releaseRecordLock(destination, lock, owner)
	return callback(ctx)
}

func acquireRecordLock(ctx context.Context, store Store, target Record) (Record, string, error) {
	ownerBytes := make([]byte, 16)
	if _, err := rand.Read(ownerBytes); err != nil {
		return Record{}, "", fmt.Errorf("generate replication lock owner: %w", err)
	}
	owner := hex.EncodeToString(ownerBytes)
	name := recordLockName(target)

	for {
		now := time.Now().UTC()
		candidate, err := newRecordLock(target.Namespace, name, owner, now.Add(recordLockTTL))
		if err != nil {
			return Record{}, "", err
		}
		created, err := store.Create(ctx, candidate)
		if err == nil {
			return created, owner, nil
		}
		if !errors.Is(err, ErrConflict) {
			return Record{}, "", fmt.Errorf("acquire replication lock for %s/%s: %w", target.Kind, target.Key, err)
		}

		existing, err := store.Get(ctx, KindConfigMap, target.Namespace, name)
		switch {
		case err == nil:
			expiresAt, err := recordLockExpiry(existing)
			if err != nil {
				return Record{}, "", fmt.Errorf("decode replication lock %s: %w", name, err)
			}
			if !expiresAt.After(now) {
				if err := store.Delete(ctx, existing.Kind, existing.Namespace, existing.Key, existing.Version); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
					return Record{}, "", fmt.Errorf("reclaim replication lock %s: %w", name, err)
				}
			}
		case !errors.Is(err, ErrNotFound):
			return Record{}, "", fmt.Errorf("read replication lock for %s/%s: %w", target.Kind, target.Key, err)
		}

		timer := time.NewTimer(recordLockPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Record{}, "", ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseRecordLock(store Store, lock Record, owner string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	existing, err := store.Get(ctx, lock.Kind, lock.Namespace, lock.Key)
	if errors.Is(err, ErrNotFound) {
		return
	}
	if err != nil {
		log.Printf("[KV_REPLICATION] read lock during release failed key=%s: %v", lock.Key, err)
		return
	}
	actualOwner, err := recordLockOwner(existing)
	if err != nil || actualOwner != owner {
		return
	}
	if err := store.Delete(ctx, existing.Kind, existing.Namespace, existing.Key, existing.Version); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
		log.Printf("[KV_REPLICATION] release lock failed key=%s: %v", lock.Key, err)
	}
}

func recordLockName(target Record) string {
	digest := sha256.Sum256([]byte(string(target.Kind) + "\x00" + target.Namespace + "\x00" + target.Key))
	return recordLockPrefix + hex.EncodeToString(digest[:])
}

func newRecordLock(namespace, name, owner string, expiresAt time.Time) (Record, error) {
	document := recordLockDocument{APIVersion: "v1", Kind: "ConfigMap"}
	document.Metadata.Name = name
	document.Metadata.Namespace = namespace
	// Keep the internal label outside the agentapi.proxy namespace: migration
	// and verification intentionally treat that namespace as application data.
	document.Metadata.Labels = map[string]string{recordLockLabel: "true"}
	document.Data = map[string]string{"owner": owner, "expires_at": expiresAt.Format(time.RFC3339Nano)}
	value, err := json.Marshal(document)
	if err != nil {
		return Record{}, err
	}
	return Record{Kind: KindConfigMap, Namespace: namespace, Key: name, Labels: document.Metadata.Labels, Value: value}, nil
}

func recordLockExpiry(record Record) (time.Time, error) {
	document, err := decodeRecordLock(record)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, document.Data["expires_at"])
}

func recordLockOwner(record Record) (string, error) {
	document, err := decodeRecordLock(record)
	if err != nil {
		return "", err
	}
	if document.Data["owner"] == "" {
		return "", errors.New("lock owner is empty")
	}
	return document.Data["owner"], nil
}

func decodeRecordLock(record Record) (recordLockDocument, error) {
	var document recordLockDocument
	if err := json.Unmarshal(record.Value, &document); err != nil {
		return document, err
	}
	if document.Metadata.Name != record.Key || document.Metadata.Namespace != record.Namespace || document.Metadata.Labels[recordLockLabel] != "true" {
		return document, errors.New("record is not a replication lock")
	}
	return document, nil
}
