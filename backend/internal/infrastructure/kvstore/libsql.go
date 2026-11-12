package kvstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tursodatabase/libsql-client-go/libsql"
	"golang.org/x/sync/singleflight"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	_ "modernc.org/sqlite" // register the sqlite driver for local file:// databases
)

type LibSQLStore struct {
	db              *sql.DB
	encryptedValues bool
	listGroup       singleflight.Group
	tableLocations  sync.Map
}

func (s *LibSQLStore) expectEncryptedValues() { s.encryptedValues = true }

func (s *LibSQLStore) validateValueMode(value []byte) error {
	isEncrypted := isEnvelopeCandidate(value)
	if s.encryptedValues && !isEncrypted {
		return ErrPlaintextInEncryptedStore
	}
	if !s.encryptedValues && isEncrypted {
		return ErrEncryptedInPlaintextStore
	}
	return nil
}

func NewLibSQLStore(ctx context.Context, databaseURL, authToken string) (*LibSQLStore, error) {
	// File-backed replicas can contend briefly when writing reservations or
	// releasing locks. Let SQLite wait instead of failing immediately with BUSY.
	if strings.HasPrefix(databaseURL, "file:") {
		dsn, err := url.Parse(databaseURL)
		if err != nil {
			return nil, fmt.Errorf("parse SQLite database URL: %w", err)
		}
		params := dsn.Query()
		hasTimeout := false
		for _, pragma := range params["_pragma"] {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(pragma)), "busy_timeout") {
				hasTimeout = true
				break
			}
		}
		if !hasTimeout {
			params.Add("_pragma", "busy_timeout(5000)")
			dsn.RawQuery = params.Encode()
			databaseURL = dsn.String()
		}
	}

	opts := []libsql.Option{}
	if authToken != "" {
		opts = append(opts, libsql.WithAuthToken(authToken))
	}
	connector, err := libsql.NewConnector(databaseURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("create libSQL connector: %w", err)
	}
	db := sql.OpenDB(connector)
	// Remote libSQL may close an autocommit stream without returning a baton.
	// The current Go driver only reports that state when the pooled connection
	// is reused. Do not retain or hand off those one-shot logical connections;
	// the underlying HTTP transport still pools its physical connections.
	if strings.HasPrefix(databaseURL, "libsql://") || strings.HasPrefix(databaseURL, "https://") || strings.HasPrefix(databaseURL, "http://") {
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(0)
	} else {
		db.SetMaxOpenConns(8)
	}
	s := &LibSQLStore{db: db}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS agentapi_kv (
kind TEXT NOT NULL, namespace TEXT NOT NULL, key TEXT NOT NULL,
version INTEGER NOT NULL, value BLOB NOT NULL, updated_at TEXT NOT NULL,
	owner_scope TEXT NOT NULL DEFAULT '',
	metadata TEXT NOT NULL DEFAULT '{"format":"agentapi-kv-metadata/v1","labels":{}}' CHECK (json_valid(metadata)),
PRIMARY KEY (kind, namespace, key))`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize libSQL schema: %w", err)
	}
	if err := ensureLibSQLMetadataColumn(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLibSQLOwnerScope(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLibSQLResourceTables(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLibSQLLookupIndexes(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureLibSQLBranchKeyTable(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func ensureLibSQLLookupIndexes(ctx context.Context, db *sql.DB) error {
	// Dedicated columns supersede the legacy JSON expression indexes. Dropping
	// them also avoids maintaining two indexes for the same lookup on fallback
	// rows left behind by older or third-party resources.
	statements := []string{
		`DROP INDEX IF EXISTS agentapi_kv_session_profile_lookup`,
		`DROP INDEX IF EXISTS agentapi_kv_session_route_reuse_lookup`,
		`DROP INDEX IF EXISTS agentapi_kv_user_session_route_reuse_lookup`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize libSQL lookup index: %w", err)
		}
	}
	return nil
}

func ensureLibSQLOwnerScope(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(agentapi_kv)`)
	if err != nil {
		return fmt.Errorf("inspect libSQL owner scope schema: %w", err)
	}
	hasColumn := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan libSQL owner scope schema: %w", err)
		}
		hasColumn = hasColumn || name == "owner_scope"
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasColumn {
		if _, err := db.ExecContext(ctx, `ALTER TABLE agentapi_kv ADD COLUMN owner_scope TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add libSQL owner scope: %w", err)
		}
	}
	backfill, err := db.QueryContext(ctx, `SELECT kind, namespace, key, metadata FROM agentapi_kv WHERE owner_scope = ''`)
	if err != nil {
		return fmt.Errorf("list libSQL owner scope backfill: %w", err)
	}
	type pendingScope struct {
		kind                  Kind
		namespace, key, scope string
	}
	var pending []pendingScope
	for backfill.Next() {
		var item pendingScope
		var metadata []byte
		if err := backfill.Scan(&item.kind, &item.namespace, &item.key, &metadata); err != nil {
			_ = backfill.Close()
			return err
		}
		labels, err := unmarshalRecordMetadata(metadata)
		if err != nil {
			_ = backfill.Close()
			return fmt.Errorf("decode owner scope metadata for %s: %w", item.key, err)
		}
		item.scope = ownerScopeForRecord(Record{Kind: item.kind, Namespace: item.namespace, Key: item.key, Labels: labels})
		pending = append(pending, item)
	}
	if err := backfill.Close(); err != nil {
		return err
	}
	for _, item := range pending {
		if _, err := db.ExecContext(ctx, `UPDATE agentapi_kv SET owner_scope = ? WHERE kind = ? AND namespace = ? AND key = ? AND owner_scope = ''`, item.scope, item.kind, item.namespace, item.key); err != nil {
			return fmt.Errorf("backfill owner scope for %s: %w", item.key, err)
		}
	}
	return nil
}

func ensureLibSQLBranchKeyTable(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS agentapi_kv_branch_keys (
provider TEXT NOT NULL, key_id TEXT NOT NULL, generation INTEGER NOT NULL,
kms_key_ref TEXT NOT NULL, wrapped_key BLOB NOT NULL, status TEXT NOT NULL,
scope TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (provider, key_id, scope, generation))`); err != nil {
		return fmt.Errorf("initialize libSQL branch key table: %w", err)
	}
	if err := migrateLibSQLBranchKeyScope(ctx, db); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS agentapi_kv_branch_keys_active`); err != nil {
		return fmt.Errorf("drop legacy libSQL active branch key index: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS agentapi_kv_branch_keys_active_scope
ON agentapi_kv_branch_keys(provider, key_id, scope) WHERE status = 'active'`); err != nil {
		return fmt.Errorf("initialize libSQL active branch key index: %w", err)
	}
	return nil
}

func migrateLibSQLBranchKeyScope(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(agentapi_kv_branch_keys)`)
	if err != nil {
		return fmt.Errorf("inspect libSQL branch key schema: %w", err)
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan libSQL branch key schema: %w", err)
		}
		found = found || name == "scope"
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close libSQL branch key schema rows: %w", err)
	}
	if found {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin libSQL branch key migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	statements := []string{
		`DROP INDEX IF EXISTS agentapi_kv_branch_keys_active`,
		`ALTER TABLE agentapi_kv_branch_keys RENAME TO agentapi_kv_branch_keys_legacy`,
		`CREATE TABLE agentapi_kv_branch_keys (
provider TEXT NOT NULL, key_id TEXT NOT NULL, generation INTEGER NOT NULL,
kms_key_ref TEXT NOT NULL, wrapped_key BLOB NOT NULL, status TEXT NOT NULL,
scope TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (provider, key_id, scope, generation))`,
		`INSERT INTO agentapi_kv_branch_keys
(provider, key_id, generation, kms_key_ref, wrapped_key, status, scope, created_at)
SELECT provider, key_id, generation, kms_key_ref, wrapped_key, status, '', created_at
FROM agentapi_kv_branch_keys_legacy`,
		`DROP TABLE agentapi_kv_branch_keys_legacy`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate libSQL branch key scope: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit libSQL branch key migration: %w", err)
	}
	return nil
}

func ensureLibSQLMetadataColumn(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(agentapi_kv)`)
	if err != nil {
		return fmt.Errorf("inspect libSQL schema: %w", err)
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan libSQL schema: %w", err)
		}
		if name == "metadata" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect libSQL schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close libSQL schema rows: %w", err)
	}
	if found {
		return backfillLegacyLibSQLMetadata(ctx, db)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE agentapi_kv ADD COLUMN metadata TEXT NOT NULL DEFAULT '{"format":"agentapi-kv-metadata/legacy","labels":{}}' CHECK (json_valid(metadata))`); err != nil {
		return fmt.Errorf("add libSQL metadata column: %w", err)
	}
	return backfillLegacyLibSQLMetadata(ctx, db)
}

func backfillLegacyLibSQLMetadata(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT kind, namespace, key, value FROM agentapi_kv
WHERE json_extract(metadata, '$.format') = 'agentapi-kv-metadata/legacy'`)
	if err != nil {
		return fmt.Errorf("list legacy libSQL metadata: %w", err)
	}
	type legacyRecord struct {
		kind           Kind
		namespace, key string
		value          []byte
	}
	var records []legacyRecord
	for rows.Next() {
		var record legacyRecord
		if err := rows.Scan(&record.kind, &record.namespace, &record.key, &record.value); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy libSQL metadata: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy libSQL metadata rows: %w", err)
	}
	for _, record := range records {
		recordLabels, err := documentLabels(record.kind, record.value)
		if err != nil {
			return fmt.Errorf("extract labels for legacy %s/%s: %w", record.kind, record.key, err)
		}
		metadata, err := marshalRecordMetadata(recordLabels)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `UPDATE agentapi_kv SET metadata = ? WHERE kind = ? AND namespace = ? AND key = ?`, metadata, record.kind, record.namespace, record.key); err != nil {
			return fmt.Errorf("backfill metadata for legacy %s/%s: %w", record.kind, record.key, err)
		}
	}
	return nil
}

func (s *LibSQLStore) Close() error { return s.db.Close() }

func (s *LibSQLStore) GetActiveBranchKey(ctx context.Context, provider, keyID, scope string) (BranchKeyRecord, error) {
	var record BranchKeyRecord
	var createdAt string
	err := s.db.QueryRowContext(ctx, `SELECT provider, key_id, scope, generation, kms_key_ref, wrapped_key, created_at
	FROM agentapi_kv_branch_keys WHERE provider = ? AND key_id = ? AND scope = ? AND status = 'active'`, provider, keyID, scope).
		Scan(&record.Provider, &record.KeyID, &record.Scope, &record.Generation, &record.KMSKeyRef, &record.WrappedKey, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BranchKeyRecord{}, ErrBranchKeyNotFound
	}
	if err != nil {
		return BranchKeyRecord{}, fmt.Errorf("get active libSQL branch key: %w", err)
	}
	record.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return BranchKeyRecord{}, fmt.Errorf("parse libSQL branch key timestamp: %w", err)
	}
	return record, nil
}

func (s *LibSQLStore) NextBranchKeyGeneration(ctx context.Context, provider, keyID, scope string) (int64, error) {
	var maximum int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0)
	FROM agentapi_kv_branch_keys WHERE provider = ? AND key_id = ? AND scope = ?`, provider, keyID, scope).Scan(&maximum); err != nil {
		return 0, fmt.Errorf("get next libSQL branch key generation: %w", err)
	}
	return maximum + 1, nil
}

func (s *LibSQLStore) CreateActiveBranchKey(ctx context.Context, record BranchKeyRecord) error {
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO agentapi_kv_branch_keys
	(provider, key_id, scope, generation, kms_key_ref, wrapped_key, status, created_at)
	VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`, record.Provider, record.KeyID, record.Scope, record.Generation,
		record.KMSKeyRef, record.WrappedKey, createdAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("create active libSQL branch key: %w", err)
	}
	return nil
}

func (s *LibSQLStore) Create(ctx context.Context, record Record) (Record, error) {
	if err := s.validateValueMode(record.Value); err != nil {
		return Record{}, err
	}
	table := libSQLTableForRecord(record)
	routedTable, routed := libSQLSessionRunnerTableForKey(record.Kind, record.Key)
	if !routed || routedTable != table {
		if _, err := s.tableContaining(ctx, record.Kind, record.Namespace, record.Key); err == nil {
			return Record{}, ErrConflict
		} else if !errors.Is(err, ErrNotFound) {
			return Record{}, err
		}
	}
	record.Version = 1
	if record.Kind == KindConfigMap && record.Labels[recordLockLabel] == "true" {
		// Recreating a lease must change its CAS version. A stale delete
		// against the expired lease must not delete its successor.
		var generation [8]byte
		rand.Read(generation[:])
		record.Version = int64(binary.BigEndian.Uint64(generation[:])>>2) + 2
	}
	metadata, err := marshalRecordMetadata(record.Labels)
	if err != nil {
		return Record{}, err
	}
	record.OwnerScope = ownerScopeForRecord(record)
	queryValues, err := libSQLQueryColumnValues(metadata)
	if err != nil {
		return Record{}, err
	}
	columns := strings.Join(libSQLQueryColumns, ", ")
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(libSQLQueryColumns)), ", ")
	var statement string
	args := []any{record.Namespace, record.Key, record.Version, metadata, record.OwnerScope, record.Value, time.Now().UTC().Format(time.RFC3339Nano)}
	if table == libSQLFallbackTable {
		statement = fmt.Sprintf(`INSERT INTO %s
	(kind, namespace, key, version, metadata, owner_scope, value, updated_at, %s)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, %s)`, table, columns, placeholders)
		args = append([]any{record.Kind}, args...)
	} else {
		statement = fmt.Sprintf(`INSERT INTO %s
	(namespace, key, version, metadata, owner_scope, value, updated_at, %s)
	VALUES (?, ?, ?, ?, ?, ?, ?, %s)`, table, columns, placeholders)
	}
	for _, value := range queryValues {
		args = append(args, value)
	}
	_, err = s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		if _, getErr := s.Get(ctx, record.Kind, record.Namespace, record.Key); getErr == nil {
			return Record{}, ErrConflict
		}
		return Record{}, fmt.Errorf("create libSQL record: %w", err)
	}
	s.tableLocations.Store(libSQLLocationKey(record.Kind, record.Namespace, record.Key), table)
	return record, nil
}

func (s *LibSQLStore) Update(ctx context.Context, record Record) (Record, error) {
	if err := s.validateValueMode(record.Value); err != nil {
		return Record{}, err
	}
	metadata, err := marshalRecordMetadata(record.Labels)
	if err != nil {
		return Record{}, err
	}
	record.OwnerScope = ownerScopeForRecord(record)
	queryValues, err := libSQLQueryColumnValues(metadata)
	if err != nil {
		return Record{}, err
	}
	locationKey := libSQLLocationKey(record.Kind, record.Namespace, record.Key)
	var table string
	if cached, ok := s.tableLocations.Load(locationKey); ok {
		table = cached.(string)
	} else if routed, ok := libSQLSessionRunnerTableForKey(record.Kind, record.Key); ok && routed == libSQLTableForRecord(record) {
		// The key and labels independently agree on the dedicated table. Avoid
		// a cold location query; records read from legacy fallback are already
		// represented in the cache and take the branch above.
		table = routed
	} else {
		var err error
		table, err = s.tableContaining(ctx, record.Kind, record.Namespace, record.Key)
		if err != nil {
			return Record{}, ErrConflict
		}
	}
	assignments := strings.Join(libSQLQueryColumns, " = ?, ") + " = ?"
	where := "namespace = ? AND key = ? AND version = ?"
	statement := fmt.Sprintf(`UPDATE %s SET version = version + 1,
metadata = ?, owner_scope = ?, value = ?, updated_at = ?, %s
WHERE %s`, table, assignments, where)
	args := []any{metadata, record.OwnerScope, record.Value, time.Now().UTC().Format(time.RFC3339Nano)}
	for _, value := range queryValues {
		args = append(args, value)
	}
	if table == libSQLFallbackTable {
		where = "kind = ? AND " + where
		statement = fmt.Sprintf(`UPDATE %s SET version = version + 1,
metadata = ?, owner_scope = ?, value = ?, updated_at = ?, %s
WHERE %s`, table, assignments, where)
		args = append(args, record.Kind)
	}
	args = append(args, record.Namespace, record.Key, record.Version)
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return Record{}, fmt.Errorf("update libSQL record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Record{}, fmt.Errorf("read libSQL update result: %w", err)
	}
	if affected == 0 {
		return Record{}, ErrConflict
	}
	s.tableLocations.Store(locationKey, table)
	record.Version++
	return record, nil
}

func (s *LibSQLStore) Get(ctx context.Context, kind Kind, namespace, key string) (Record, error) {
	record := Record{Kind: kind, Namespace: namespace, Key: key}
	var metadata []byte
	locationKey := libSQLLocationKey(kind, namespace, key)
	if _, cached := s.tableLocations.Load(locationKey); !cached {
		if dedicated, ok := libSQLSessionRunnerTableForKey(kind, key); ok {
			statement := fmt.Sprintf(`SELECT table_name, version, metadata, owner_scope, value FROM (
SELECT '%s' AS table_name, version, metadata, owner_scope, value FROM %s WHERE namespace = ? AND key = ?
UNION ALL
SELECT '%s' AS table_name, version, metadata, owner_scope, value FROM %s WHERE kind = ? AND namespace = ? AND key = ?
) LIMIT 1`, dedicated, dedicated, libSQLFallbackTable, libSQLFallbackTable)
			var table string
			err := s.db.QueryRowContext(ctx, statement, namespace, key, kind, namespace, key).
				Scan(&table, &record.Version, &metadata, &record.OwnerScope, &record.Value)
			if errors.Is(err, sql.ErrNoRows) {
				return Record{}, ErrNotFound
			}
			if err != nil {
				return Record{}, fmt.Errorf("get libSQL session-runner record: %w", err)
			}
			s.tableLocations.Store(locationKey, table)
			return s.decodeLibSQLRecord(record, metadata)
		}
	}
	table, err := s.tableContaining(ctx, kind, namespace, key)
	if err != nil {
		return Record{}, err
	}
	where := "namespace = ? AND key = ?"
	args := []any{namespace, key}
	if table == libSQLFallbackTable {
		where = "kind = ? AND " + where
		args = append([]any{kind}, args...)
	}
	statement := fmt.Sprintf(`SELECT version, metadata, owner_scope, value FROM %s WHERE %s`, table, where)
	err = s.db.QueryRowContext(ctx, statement, args...).Scan(&record.Version, &metadata, &record.OwnerScope, &record.Value)
	if errors.Is(err, sql.ErrNoRows) {
		// Another API replica may have removed a cached record. A stale
		// location would also cause future Create calls to report a conflict.
		s.tableLocations.CompareAndDelete(locationKey, table)
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("get libSQL record: %w", err)
	}
	return s.decodeLibSQLRecord(record, metadata)
}

func (s *LibSQLStore) decodeLibSQLRecord(record Record, metadata []byte) (Record, error) {
	var err error
	record.Labels, err = unmarshalRecordMetadata(metadata)
	if err != nil {
		return Record{}, fmt.Errorf("decode libSQL metadata: %w", err)
	}
	if err := s.validateValueMode(record.Value); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *LibSQLStore) Delete(ctx context.Context, kind Kind, namespace, key string, version int64) error {
	locationKey := libSQLLocationKey(kind, namespace, key)
	if _, cached := s.tableLocations.Load(locationKey); !cached {
		if routed, ok := libSQLSessionRunnerTableForKey(kind, key); ok {
			result, err := s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE namespace = ? AND key = ? AND version = ?`, routed), namespace, key, version)
			if err != nil {
				return fmt.Errorf("delete routed libSQL record: %w", err)
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("read routed libSQL delete result: %w", err)
			}
			if affected > 0 {
				return nil
			}
			// Version mismatch, missing row, and legacy fallback are uncommon.
			// Preserve their exact error semantics through the existing path.
		}
	}
	table, err := s.tableContaining(ctx, kind, namespace, key)
	if err != nil {
		return err
	}
	where := "namespace = ? AND key = ? AND version = ?"
	args := []any{namespace, key, version}
	if table == libSQLFallbackTable {
		where = "kind = ? AND " + where
		args = append([]any{kind}, args...)
	}
	statement := fmt.Sprintf(`DELETE FROM %s WHERE %s`, table, where)
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return fmt.Errorf("delete libSQL record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read libSQL delete result: %w", err)
	}
	if affected == 0 {
		if _, getErr := s.Get(ctx, kind, namespace, key); errors.Is(getErr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrConflict
	}
	s.tableLocations.Delete(locationKey)
	return nil
}

func (s *LibSQLStore) List(ctx context.Context, query Query) ([]Record, error) {
	if err := ValidateListQuery(query); err != nil {
		return nil, err
	}
	return s.list(ctx, query)
}

func (s *LibSQLStore) Scan(ctx context.Context, query ScanQuery) ([]Record, error) {
	return s.list(ctx, Query{Kind: query.Kind, Namespace: query.Namespace})
}

func (s *LibSQLStore) list(ctx context.Context, query Query) ([]Record, error) {
	key := string(query.Kind) + "\x00" + query.Namespace + "\x00" + query.KeyPrefix + "\x00" + query.LabelSelector
	value, err, _ := s.listGroup.Do(key, func() (any, error) {
		return s.listOnce(ctx, query)
	})
	if err != nil {
		return nil, err
	}
	return cloneRecords(value.([]Record)), nil
}

func (s *LibSQLStore) listOnce(ctx context.Context, query Query) ([]Record, error) {
	selector, err := labels.Parse(query.LabelSelector)
	if err != nil {
		return nil, fmt.Errorf("parse label selector: %w", err)
	}
	var records []Record
	statements := make([]string, 0, len(libSQLResourceTables)+1)
	var args []any
	tables := libSQLTablesForSelector(selector)
	for _, table := range tables {
		if resource, dedicated := libSQLResourceTableNamed(table); dedicated && resource.kind != query.Kind {
			continue
		}
		statement, tableArgs := libSQLListQuery(table, query, selector)
		statements = append(statements, statement)
		args = append(args, tableArgs...)
	}
	if len(statements) == 0 {
		return records, nil
	}
	// A selector that cannot identify a dedicated resource may span every
	// physical table. UNION ALL keeps that operation to one remote round trip.
	// The compatibility contract is enforced by the Go sort below. Avoid a
	// second remote sort, especially the temporary merge sort required for a
	// UNION spanning several physical tables.
	rows, err := s.db.QueryContext(ctx, strings.Join(statements, " UNION ALL "), args...)
	if err != nil {
		return nil, fmt.Errorf("list libSQL records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		record := Record{Kind: query.Kind, Namespace: query.Namespace}
		var metadata []byte
		if err := rows.Scan(&record.Key, &record.Version, &metadata, &record.OwnerScope, &record.Value); err != nil {
			return nil, fmt.Errorf("scan libSQL record: %w", err)
		}
		record.Labels, err = unmarshalRecordMetadata(metadata)
		if err != nil {
			return nil, fmt.Errorf("decode libSQL metadata for %s: %w", record.Key, err)
		}
		if err := s.validateValueMode(record.Value); err != nil {
			return nil, fmt.Errorf("read libSQL record %s: %w", record.Key, err)
		}
		if selector.Matches(labels.Set(record.Labels)) {
			records = append(records, record)
			if len(tables) == 1 {
				s.tableLocations.Store(libSQLLocationKey(record.Kind, record.Namespace, record.Key), tables[0])
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	return records, nil
}

func cloneRecords(records []Record) []Record {
	cloned := make([]Record, len(records))
	for i := range records {
		cloned[i] = records[i]
		cloned[i].Value = append([]byte(nil), records[i].Value...)
		if records[i].Labels != nil {
			cloned[i].Labels = make(map[string]string, len(records[i].Labels))
			for key, value := range records[i].Labels {
				cloned[i].Labels[key] = value
			}
		}
	}
	return cloned
}

// libSQLListQuery pushes label requirements into SQLite so remote libSQL does
// not return every value in a namespace before the caller-side label filter is
// applied. The caller still checks selector.Matches after scanning as a safety
// net and to preserve Kubernetes selector semantics.
func libSQLListQuery(table string, query Query, selector labels.Selector) (string, []any) {
	statement := strings.Builder{}
	fmt.Fprintf(&statement, "SELECT key, version, metadata, owner_scope, value FROM %s WHERE ", table)
	args := make([]any, 0, 2)
	if table == libSQLFallbackTable {
		statement.WriteString("kind = ? AND ")
		args = append(args, query.Kind)
	}
	statement.WriteString("namespace = ?")
	args = append(args, query.Namespace)
	if query.KeyPrefix != "" {
		if upper, ok := stringPrefixUpperBound(query.KeyPrefix); ok {
			statement.WriteString(" AND key >= ? AND key < ?")
			args = append(args, query.KeyPrefix, upper)
		} else {
			statement.WriteString(" AND substr(key, 1, length(?)) = ?")
			args = append(args, query.KeyPrefix, query.KeyPrefix)
		}
	}
	requirements, selectable := selector.Requirements()
	if !selectable {
		statement.WriteString(" AND 0")
	}
	for i, requirement := range requirements {
		alias := fmt.Sprintf("label_%d", i)
		key := requirement.Key()
		values := requirement.Values().List()
		if column, ok := libSQLLabelColumns[key]; ok {
			writeLibSQLColumnMatch(&statement, &args, column, values, requirement.Operator())
			continue
		}
		switch requirement.Operator() {
		case selection.Equals, selection.DoubleEquals, selection.In:
			writeLibSQLLabelMatch(&statement, &args, table, key, values, false)
		case selection.NotEquals, selection.NotIn:
			writeLibSQLLabelExists(&statement, &args, table, alias, key, values, true)
		case selection.Exists:
			writeLibSQLLabelExists(&statement, &args, table, alias, key, nil, false)
		case selection.DoesNotExist:
			writeLibSQLLabelExists(&statement, &args, table, alias, key, nil, true)
		case selection.GreaterThan, selection.LessThan:
			comparison := ">"
			if requirement.Operator() == selection.LessThan {
				comparison = "<"
			}
			fmt.Fprintf(&statement, " AND EXISTS (SELECT 1 FROM json_each(%s.metadata, '$.labels') AS %s WHERE %s.key = ? AND CAST(%s.value AS INTEGER) %s ?)", table, alias, alias, alias, comparison)
			args = append(args, key, values[0])
		}
	}
	return statement.String(), args
}

// stringPrefixUpperBound returns the smallest string greater than every
// string with prefix. SQLite can use it as the upper edge of a B-tree range.
func stringPrefixUpperBound(prefix string) (string, bool) {
	runes := []rune(prefix)
	for i := len(runes) - 1; i >= 0; i-- {
		if runes[i] < '\U0010FFFF' {
			runes[i]++
			return string(runes[:i+1]), true
		}
	}
	return "", false
}

func writeLibSQLColumnMatch(statement *strings.Builder, args *[]any, column string, values []string, operator selection.Operator) {
	switch operator {
	case selection.Equals, selection.DoubleEquals, selection.In:
		fmt.Fprintf(statement, " AND %s IN (%s)", column, strings.TrimSuffix(strings.Repeat("?,", len(values)), ","))
		for _, value := range values {
			*args = append(*args, value)
		}
	case selection.NotEquals, selection.NotIn:
		fmt.Fprintf(statement, " AND %s NOT IN (%s)", column, strings.TrimSuffix(strings.Repeat("?,", len(values)), ","))
		for _, value := range values {
			*args = append(*args, value)
		}
	case selection.Exists:
		fmt.Fprintf(statement, " AND %s <> ''", column)
	case selection.DoesNotExist:
		fmt.Fprintf(statement, " AND %s = ''", column)
	case selection.GreaterThan, selection.LessThan:
		comparison := ">"
		if operator == selection.LessThan {
			comparison = "<"
		}
		fmt.Fprintf(statement, " AND CAST(%s AS INTEGER) %s ?", column, comparison)
		*args = append(*args, values[0])
	}
}

func writeLibSQLLabelMatch(statement *strings.Builder, args *[]any, table, key string, values []string, negate bool) {
	// Kubernetes label keys cannot contain quotes. Keeping the JSON expression
	// literal (rather than binding the path) lets SQLite match expression indexes.
	escapedKey := strings.ReplaceAll(key, `"`, `\"`)
	if negate {
		statement.WriteString(" AND NOT")
	} else {
		statement.WriteString(" AND")
	}
	fmt.Fprintf(statement, ` json_extract(%s.metadata, '$.labels."%s"') IN (%s)`, table, escapedKey, strings.TrimSuffix(strings.Repeat("?,", len(values)), ","))
	for _, value := range values {
		*args = append(*args, value)
	}
}

func writeLibSQLLabelExists(statement *strings.Builder, args *[]any, table, alias, key string, values []string, negate bool) {
	if negate {
		statement.WriteString(" AND NOT")
	} else {
		statement.WriteString(" AND")
	}
	fmt.Fprintf(statement, " EXISTS (SELECT 1 FROM json_each(%s.metadata, '$.labels') AS %s WHERE %s.key = ?", table, alias, alias)
	*args = append(*args, key)
	if len(values) > 0 {
		fmt.Fprintf(statement, " AND %s.value IN (%s)", alias, strings.TrimSuffix(strings.Repeat("?,", len(values)), ","))
		for _, value := range values {
			*args = append(*args, value)
		}
	}
	statement.WriteString(")")
}

const recordMetadataFormat = "agentapi-kv-metadata/v1"

type recordMetadata struct {
	Format string            `json:"format"`
	Labels map[string]string `json:"labels"`
}

func marshalRecordMetadata(recordLabels map[string]string) ([]byte, error) {
	if recordLabels == nil {
		recordLabels = map[string]string{}
	}
	metadata, err := json.Marshal(recordMetadata{Format: recordMetadataFormat, Labels: recordLabels})
	if err != nil {
		return nil, fmt.Errorf("encode libSQL metadata: %w", err)
	}
	return metadata, nil
}

func unmarshalRecordMetadata(data []byte) (map[string]string, error) {
	var metadata recordMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	if metadata.Format != recordMetadataFormat {
		return nil, fmt.Errorf("unsupported metadata format %q", metadata.Format)
	}
	if metadata.Labels == nil {
		metadata.Labels = map[string]string{}
	}
	return metadata.Labels, nil
}
