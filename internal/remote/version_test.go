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

package remote

import "testing"

func TestReleaseMajor(t *testing.T) {
	cases := []struct {
		raw   string
		want  int
		valid bool
	}{
		{"1.19.0", 1, true},
		{"v1.19.0", 1, true},
		{" 1.19.0 ", 1, true},
		{"1.19", 1, true},
		{"1.19.0-rc.1", 1, true},
		{"1.19.0+build.7", 1, true},
		{"dev", 0, false},
		{"", 0, false},
		{"1", 0, false},
		{"1.x.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := releaseMajor(tc.raw)
		if ok != tc.valid {
			t.Errorf("releaseMajor(%q) valid = %v, want %v", tc.raw, ok, tc.valid)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("releaseMajor(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestCheckCompatibility(t *testing.T) {
	cases := []struct {
		cli      string
		instance string
		want     Compatibility
	}{
		{"1.19.0", "1.19.0", Compatible},
		{"1.19.3", "1.19.0", Compatible},
		{"1.19.0", "1.18.11", Compatible},
		{"1.18.11", "1.19.0", Compatible},
		{"v1.19.0", "1.20.0", Compatible},
		{"1.19.0", "2.0.0", Incompatible},
		{"2.0.0", "1.19.0", Incompatible},
		{"dev", "1.19.0", CompatibilityUnknown},
		{"1.19.0", "dev", CompatibilityUnknown},
		{"1.19.0", "", CompatibilityUnknown},
	}
	for _, tc := range cases {
		if got := CheckCompatibility(tc.cli, tc.instance); got != tc.want {
			t.Errorf("CheckCompatibility(%q, %q) = %v, want %v", tc.cli, tc.instance, got, tc.want)
		}
	}
}
