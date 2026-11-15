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

package experimental

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Every feature has a name, a help text and a unique flag. Its switch has the
// same name in Settings and in Patch.
func TestEveryFeatureIsDescribedAndHasItsSwitch(t *testing.T) {
	flags := map[string]bool{AllFlag: true}
	for _, feature := range All() {
		if feature.Name == "" || !strings.HasPrefix(feature.Help, "Experimental. ") {
			t.Errorf("%+v: want a name and a help text that starts with Experimental", feature)
		}
		if feature.Flag == "" || strings.HasPrefix(feature.Flag, "-") || flags[feature.Flag] {
			t.Errorf("flag %q: want a unique flag name without leading dashes", feature.Flag)
		}
		flags[feature.Flag] = true

		var settings Settings
		feature.Set(&settings, true)
		encoded, _ := json.Marshal(settings)
		var switches map[string]bool
		_ = json.Unmarshal(encoded, &switches)
		if !switches[feature.Setting] || len(settings.Active()) != 1 {
			t.Errorf("%s: turning it on gives %s, want only %s", feature.Name, encoded, feature.Setting)
		}

		var patch Patch
		if err := json.Unmarshal([]byte(`{"`+feature.Setting+`":true}`), &patch); err != nil {
			t.Fatal(err)
		}
		settings = Settings{}
		patch.Apply(&settings)
		if !feature.On(settings) || len(settings.Active()) != 1 {
			t.Errorf("%s: the patch %s gives %+v", feature.Name, feature.Setting, settings)
		}
	}
	if fields := reflect.TypeFor[Settings]().NumField(); fields != len(All()) {
		t.Errorf("Settings has %d switches, All lists %d features", fields, len(All()))
	}
	if fields := reflect.TypeFor[Patch]().NumField(); fields != len(All()) {
		t.Errorf("Patch has %d members, want one for each of the %d features", fields, len(All()))
	}
}

func TestWarnMentionsTheFeatureAndItsFlag(t *testing.T) {
	var out strings.Builder
	Warn(&out, []Feature{DelegateSDJWT})
	want := "warning: Delegate SD-JWT is experimental (--delegate-sd-jwt). Its behavior can change in any release.\n"
	if out.String() != want {
		t.Errorf("warning: %q, want %q", out.String(), want)
	}
	out.Reset()
	Warn(&out, nil)
	if out.Len() != 0 {
		t.Errorf("without a feature: %q, want no output", out.String())
	}
}
