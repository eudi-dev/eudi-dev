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

package credtemplate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/eudi-dev/eudi-dev/v3/internal/defaults"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/predefined_credentials.json")

// The predefined templates issue credentials with the recorded claims and
// display. Dates and unique claims are compared by rule: issuance dates are
// today, expiry dates five years ahead, and unique claims are fresh.
func TestPredefinedTemplatesIssueTheRecordedCredentials(t *testing.T) {
	got := map[string]any{}
	for _, tpl := range PredefinedTemplates() {
		got[tpl.Name] = issuedContent(t, tpl)
	}
	golden := filepath.Join("testdata", "predefined_credentials.json")
	if *updateGolden {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	var gotNormalized map[string]any
	_ = json.Unmarshal(gotJSON, &gotNormalized)
	for name, w := range want {
		g, _ := json.MarshalIndent(gotNormalized[name], "", "  ")
		e, _ := json.MarshalIndent(w, "", "  ")
		if string(g) != string(e) {
			t.Errorf("template %s issues\n%s\nwant\n%s", name, g, e)
		}
	}
	if len(gotNormalized) != len(want) {
		t.Errorf("got %d predefined templates, want %d", len(gotNormalized), len(want))
	}
}

// issuedContent issues a credential from tpl and returns its claims and the
// template's issuance settings, with binary values as digests.
func issuedContent(t *testing.T, tpl Template) map[string]any {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims := tpl.WithUniqueClaims(MergeClaims(tpl.Claims, nil))
	var issued map[string]any
	switch tpl.Format {
	case "sdjwt":
		raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{VCT: tpl.VCT, IsPID: tpl.Category == CategoryPID, Claims: claims, Key: key, AlwaysDisclosed: tpl.AlwaysDisclosed})
		if err != nil {
			t.Fatal(err)
		}
		token, err := sdjwt.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		issued = token.ResolvedClaims
		var plain []string
		for name := range token.Payload {
			if !strings.HasPrefix(name, "_sd") {
				plain = append(plain, name)
			}
		}
		for _, drop := range []string{"iat", "nbf", "exp", "iss", "vct"} {
			delete(issued, drop)
		}
		slices.Sort(plain)
		issued["(plain)"] = plain
	case "mdoc":
		raw, err := mock.GenerateMDOC(mock.MDOCConfig{DocType: tpl.DocType, Namespace: tpl.Namespace, Claims: claims, Key: key})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := mdoc.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		issued = map[string]any{}
		for ns, items := range doc.NameSpaces {
			for _, item := range items {
				issued[ns+":"+item.ElementIdentifier] = item.ElementValue
			}
		}
	}
	for _, name := range tpl.UniqueClaims {
		key := name
		if tpl.Format == "mdoc" && !strings.Contains(name, ":") {
			key = tpl.Namespace + ":" + name
		}
		if v, ok := issued[key].(string); ok && v != "" {
			issued[key] = "(unique)"
		}
	}
	exp := DefaultExp
	if tpl.Exp != "" {
		exp, _ = time.ParseDuration(tpl.Exp)
	}
	settings := map[string]any{
		"format": tpl.Format, "vct": tpl.VCT, "doctype": tpl.DocType, "namespace": tpl.Namespace,
		"exp": strings.TrimSuffix(exp.String(), "0m0s"), "category": tpl.Category, "always_disclosed": tpl.AlwaysDisclosed, "unique_claims": tpl.UniqueClaims,
	}
	if d := tpl.Display; d != nil {
		settings["display"] = map[string]any{
			"name": d.Name, "description": d.Description, "background_color": d.BackgroundColor, "text_color": d.TextColor,
			"logo": imageDigest(t, d.Logo), "logo_alt_text": d.LogoAltText, "background_image": imageDigest(t, d.BackgroundImage),
		}
	}
	return map[string]any{"settings": settings, "claims": normalized(issued, tpl.Format == "mdoc")}
}

func imageDigest(t *testing.T, ref string) string {
	t.Helper()
	if ref == "" {
		return ""
	}
	_, data, ok := defaults.Resolve(ref)
	if !ok {
		t.Fatalf("image %q is not in the defaults tree", ref)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalized marks a CBOR float, because JSON can't tell 1.0 from 1.
func normalized(value any, cborFloats bool) any {
	today := time.Now().UTC().Format(time.DateOnly)
	expiry := time.Now().UTC().AddDate(5, 0, 0).Format(time.DateOnly)
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			out[k] = normalized(item, cborFloats)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, item := range v {
			out[fmt.Sprint(k)] = normalized(item, cborFloats)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normalized(item, cborFloats)
		}
		return out
	case []byte:
		sum := sha256.Sum256(v)
		return "bytes;sha256:" + hex.EncodeToString(sum[:])
	case float32, float64:
		if cborFloats {
			return fmt.Sprintf("float:%v", v)
		}
	case cbor.Tag:
		return map[string]any{"tag": v.Number, "content": normalized(v.Content, cborFloats)}
	case string:
		switch v {
		case today:
			return "(today)"
		case expiry:
			return "(today+5y)"
		}
		if head, data, ok := strings.Cut(v, ";base64,"); ok && strings.HasPrefix(head, "data:") {
			raw, err := base64.StdEncoding.DecodeString(data)
			if err == nil {
				sum := sha256.Sum256(raw)
				return head + ";sha256:" + hex.EncodeToString(sum[:])
			}
		}
		return v
	}
	return value
}
