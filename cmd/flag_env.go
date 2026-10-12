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

package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
	"github.com/eudi-dev/eudi-dev/v2/internal/storage"
	"github.com/eudi-dev/eudi-dev/v2/internal/wallet"
)

const flagEnvPrefix = "EUDI_DEV_"

// directEnvVars are read by every command that uses them, so applyFlagEnv
// leaves them alone.
var directEnvVars = []string{config.HomeEnvVar, storage.EnvVar, wallet.SeedEnvVar}

func flagEnvVar(flag string) string {
	return flagEnvPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

// applyFlagEnv sets every flag missing from the command line from its
// EUDI_DEV_<FLAG> variable. The value then counts as given on the command
// line, so it also reaches a detached server as a flag. A repeatable flag
// takes comma-separated values. A variable that names no flag is an error.
func applyFlagEnv(flags *pflag.FlagSet) error {
	byVar := map[string]*pflag.Flag{}
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" {
			byVar[flagEnvVar(flag.Name)] = flag
		}
	})
	environ := os.Environ()
	slices.Sort(environ)
	var unknown []string
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, flagEnvPrefix) || slices.Contains(directEnvVars, name) {
			continue
		}
		flag, ok := byVar[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		value = strings.TrimSpace(value)
		if flag.Changed || value == "" {
			continue
		}
		values := []string{value}
		if _, repeatable := flag.Value.(pflag.SliceValue); repeatable {
			values = strings.Split(value, ",")
		}
		for _, v := range values {
			if err := flags.Set(flag.Name, strings.TrimSpace(v)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s names no flag of this command. A flag such as --base-url is set by %s",
			strings.Join(unknown, ", "), flagEnvVar("base-url"))
	}
	return nil
}
