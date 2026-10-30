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

package findings

import (
	"fmt"
	"slices"
	"testing"
)

func TestJoinSeparatesSentencesWithOnePeriod(t *testing.T) {
	got := Join([]string{"the nonce is missing", "the state is too long.", " "})
	if want := "the nonce is missing. the state is too long"; got != want {
		t.Errorf("Join = %q, want %q", got, want)
	}
}

func TestOfFindsTheListThroughWrapping(t *testing.T) {
	refusal := &Error{Summary: "authorization request validation failed", Findings: List{Uncited("a"), Uncited("b")}}
	if got := Of(fmt.Errorf("presenting: %w", refusal)); !slices.Equal(got, refusal.Findings) {
		t.Errorf("Of = %v, want %v", got, refusal.Findings)
	}
	if want := "authorization request validation failed: a. b"; refusal.Error() != want {
		t.Errorf("Error = %q, want %q", refusal.Error(), want)
	}
}
