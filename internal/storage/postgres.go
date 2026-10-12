// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver
)

const (
	postgresTable    = "eudi_dev_state"
	postgresVersions = "eudi_dev_state_version"
)

type postgresStore struct {
	db    *sql.DB
	label string

	// Commands routed to a server need no database connection, so the schema is
	// created on first use.
	prepareMu sync.Mutex
	prepared  bool
}

// Openers using the same connection URL share a pool within the process.
var postgresPools sync.Map

func openPostgres(dsn string) (Store, error) {
	if store, ok := postgresPools.Load(dsn); ok {
		return store.(*postgresStore), nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres storage: %w", err)
	}
	store, loaded := postgresPools.LoadOrStore(dsn, &postgresStore{db: db, label: postgresLabel(dsn)})
	if loaded {
		_ = db.Close()
	}
	return store.(*postgresStore), nil
}

// prepare creates the table, prefix index and version sequence. A failed attempt is
// retried on the next call. Concurrent creation can report duplicate-object errors
// even when the objects exist.
//
// The prefix index serves LIKE queries under collations where the primary-key index
// cannot.
func (s *postgresStore) prepare() error {
	s.prepareMu.Lock()
	defer s.prepareMu.Unlock()
	if s.prepared {
		return nil
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS ` + postgresTable + ` (
			key        TEXT PRIMARY KEY,
			data       BYTEA NOT NULL,
			version    BIGINT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS ` + postgresTable + `_prefix ON ` + postgresTable + ` (key text_pattern_ops)`,
		`CREATE SEQUENCE IF NOT EXISTS ` + postgresVersions,
	} {
		_, err := s.db.Exec(statement)
		var pgErr *pgconn.PgError
		if err != nil && !(errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "42P07" || pgErr.Code == "42710")) {
			return fmt.Errorf("preparing postgres storage at %s: %w", s.label, err)
		}
	}
	s.prepared = true
	return nil
}

// postgresLabel omits database credentials from diagnostic messages.
func postgresLabel(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return KindPostgres
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func (s *postgresStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	var data []byte
	err = s.db.QueryRow(`SELECT data FROM `+postgresTable+` WHERE key = $1`, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notExist("read", key)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", key, err)
	}
	return data, nil
}

func (s *postgresStore) ReadBlob(key string) (Blob, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Blob{}, err
	}
	if err := s.prepare(); err != nil {
		return Blob{}, err
	}
	var data []byte
	var version int64
	err = s.db.QueryRow(`SELECT data, version FROM `+postgresTable+` WHERE key = $1`, key).Scan(&data, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return Blob{}, notExist("read", key)
	}
	if err != nil {
		return Blob{}, fmt.Errorf("reading %s: %w", key, err)
	}
	return Blob{Data: data, Stamp: postgresStamp(version, int64(len(data)))}, nil
}

func (s *postgresStore) Write(key string, data []byte, _ fs.FileMode) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	if err := s.prepare(); err != nil {
		return Stamp{}, err
	}
	var version int64
	err = s.db.QueryRow(`INSERT INTO `+postgresTable+` (key, data, version, updated_at)
		VALUES ($1, $2, nextval('`+postgresVersions+`'), now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, version = nextval('`+postgresVersions+`'), updated_at = now()
		RETURNING version`, key, data).Scan(&version)
	if err != nil {
		return Stamp{}, fmt.Errorf("writing %s: %w", key, err)
	}
	return postgresStamp(version, int64(len(data))), nil
}

func (s *postgresStore) Delete(key string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	if err := s.prepare(); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM `+postgresTable+` WHERE key = $1`, key); err != nil {
		return fmt.Errorf("deleting %s: %w", key, err)
	}
	return nil
}

func (s *postgresStore) Stat(key string) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	if err := s.prepare(); err != nil {
		return Stamp{}, err
	}
	var version, size int64
	err = s.db.QueryRow(`SELECT version, octet_length(data) FROM `+postgresTable+` WHERE key = $1`, key).Scan(&version, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return Stamp{}, notExist("stat", key)
	}
	if err != nil {
		return Stamp{}, fmt.Errorf("reading %s: %w", key, err)
	}
	return postgresStamp(version, size), nil
}

func (s *postgresStore) Exists(key string) (bool, error) { return existsByStat(s.Stat, key) }

func (s *postgresStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	rows, err := s.db.Query(`SELECT key FROM `+postgresTable+` WHERE key LIKE $1 ESCAPE '\'`, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(key, prefix)
		if strings.Contains(name, "/") {
			continue
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (s *postgresStore) ReadAll(prefix string) (map[string]Blob, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	rows, err := s.db.Query(`SELECT key, data, version FROM `+postgresTable+` WHERE key LIKE $1 ESCAPE '\'`, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	blobs := make(map[string]Blob)
	for rows.Next() {
		var key string
		var data []byte
		var version int64
		if err := rows.Scan(&key, &data, &version); err != nil {
			return nil, err
		}
		blobs[key] = Blob{Data: data, Stamp: postgresStamp(version, int64(len(data)))}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return blobs, nil
}

func (s *postgresStore) Stamps(prefix string) (map[string]Stamp, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	rows, err := s.db.Query(`SELECT key, version, octet_length(data) FROM `+postgresTable+` WHERE key LIKE $1 ESCAPE '\'`, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	stamps := make(map[string]Stamp)
	for rows.Next() {
		var key string
		var version, size int64
		if err := rows.Scan(&key, &version, &size); err != nil {
			return nil, err
		}
		stamps[key] = postgresStamp(version, size)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stamps, nil
}

func (s *postgresStore) WriteIf(key string, data []byte, _ fs.FileMode, expected string) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	if err := s.prepare(); err != nil {
		return Stamp{}, err
	}
	var version int64
	if expected == "" {
		err = s.db.QueryRow(`INSERT INTO `+postgresTable+` (key, data, version, updated_at)
			VALUES ($1, $2, nextval('`+postgresVersions+`'), now()) ON CONFLICT (key) DO NOTHING RETURNING version`, key, data).Scan(&version)
	} else {
		previous, parseErr := strconv.ParseInt(expected, 10, 64)
		if parseErr != nil {
			return Stamp{}, ErrConflict
		}
		err = s.db.QueryRow(`UPDATE `+postgresTable+` SET data = $2, version = nextval('`+postgresVersions+`'), updated_at = now()
			WHERE key = $1 AND version = $3 RETURNING version`, key, data, previous).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Stamp{}, ErrConflict
	}
	if err != nil {
		return Stamp{}, fmt.Errorf("writing %s: %w", key, err)
	}
	return postgresStamp(version, int64(len(data))), nil
}

// A shared sequence gives a recreated row a new version, so cached readers detect it.
func postgresStamp(version, size int64) Stamp {
	return Stamp{Version: strconv.FormatInt(version, 10), Size: size}
}

func likePrefix(prefix string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
}

func (s *postgresStore) Locate(key string) string {
	if key == "" {
		return s.label
	}
	return s.label + "#" + key
}

func (s *postgresStore) Kind() string { return KindPostgres }
