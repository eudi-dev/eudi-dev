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

// Package testenv isolates tests from the developer's eudi-dev home and from
// other test processes on the same Postgres database.
package testenv

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver

	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

// Main runs the tests of a package with a temporary home directory. The
// default wallet, its templates and the active remote wallet live under the
// home directory, so tests that reach them must not see the real one.
// EUDI_DEV_HOME is cleared because it would restore it.
//
// Postgres keys are relative to the home directory, so every test process
// and every earlier run would share the default wallet. A Postgres
// EUDI_DEV_STORAGE gets a schema of its own for this process, the way the
// memory backend keeps one store per process.
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "eudi-dev-tests-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temporary home directory: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	for name, value := range map[string]string{"HOME": dir, "USERPROFILE": dir, "EUDI_DEV_HOME": ""} {
		set := func() error { return os.Setenv(name, value) }
		if value == "" {
			set = func() error { return os.Unsetenv(name) }
		}
		if err := set(); err != nil {
			fmt.Fprintf(os.Stderr, "setting %s: %v\n", name, err)
			return 1
		}
	}
	if dsn := os.Getenv(storage.EnvVar); strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		drop, err := usePostgresSchema(dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "isolating postgres storage: %v\n", err)
			return 1
		}
		defer drop()
	}
	return m.Run()
}

// usePostgresSchema creates a schema and points EUDI_DEV_STORAGE at it with
// the search_path connection parameter.
func usePostgresSchema(dsn string) (drop func(), err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	schema := "eudi_dev_test_" + hex.EncodeToString(suffix)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("CREATE SCHEMA " + schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	if err := os.Setenv(storage.EnvVar, u.String()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return func() {
		if _, err := db.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			fmt.Fprintf(os.Stderr, "dropping postgres schema %s: %v\n", schema, err)
		}
		_ = db.Close()
	}, nil
}
