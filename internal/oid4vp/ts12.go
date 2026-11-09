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

package oid4vp

import (
	"embed"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
)

// The payload schemas of EUDI TS12 v1.0.1 §4.3, unchanged from
// docs/technical-specifications/api of
// github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications
// (© European Union, CC BY 4.0).
//
//go:embed ts12schema/*.json
var ts12SchemaFiles embed.FS

// ts12SchemaBase is the base URL of the bundled schemas. It resolves the
// relative $ref of the e-mandate schema to the payment schema next to it.
const ts12SchemaBase = "https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/docs/technical-specifications/api/"

// ts12Members are the members of a TS12 transaction data object (§4.2).
var ts12Members = []string{"type", "credential_ids", "transaction_data_hashes_alg", "payload"}

var ts12Schemas = sync.OnceValues(compileTS12Schemas)

func ts12SchemaFile(typ string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(typ, "urn:eudi:sca:"), ":1")
	return "ts12-urn-eudi-sca-" + name + "-1-data-model.json"
}

func compileTS12Schemas() (map[string]*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseLoader(noSchemaLoader{})
	for _, typ := range TS12TransactionDataTypes {
		data, err := ts12SchemaFiles.ReadFile("ts12schema/" + ts12SchemaFile(typ))
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
		if err != nil {
			return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
		}
		if err := compiler.AddResource(ts12SchemaBase+ts12SchemaFile(typ), doc); err != nil {
			return nil, err
		}
	}
	schemas := map[string]*jsonschema.Schema{}
	for _, typ := range TS12TransactionDataTypes {
		schema, err := compiler.Compile(ts12SchemaBase + ts12SchemaFile(typ))
		if err != nil {
			return nil, fmt.Errorf("TS12 schema of %s: %w", typ, err)
		}
		schemas[typ] = schema
	}
	return schemas, nil
}

// noSchemaLoader keeps validation offline. Every TS12 schema is bundled.
type noSchemaLoader struct{}

func (noSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schema %s is not bundled", url)
}

// ts12Findings checks a TS12 entry. §4.2 makes transaction_data_hashes_alg and
// payload REQUIRED. §3.2 step 4 validates the payload against the JSON Schema
// of its type. OpenID4VP 1.0 §8.5 refuses unknown members and invalid
// fields with invalid_transaction_data.
func ts12Findings(label string, entry TransactionData) findings.List {
	var list findings.List
	for _, name := range slices.Sorted(maps.Keys(entry.Data)) {
		if !slices.Contains(ts12Members, name) {
			list = append(list, findings.OID4VP.Protocol("§8.5").Newf("%s of type %q has the unknown member %s", label, entry.Type, name))
		}
	}
	if _, present := entry.Data["transaction_data_hashes_alg"]; !present {
		list = append(list, findings.TS12.Protocol("§4.2").Newf("%s of type %q has no transaction_data_hashes_alg", label, entry.Type))
	}
	payload, ok := entry.Data["payload"].(map[string]any)
	if !ok {
		return append(list, findings.TS12.Protocol("§4.2").Newf("%s of type %q has no payload object", label, entry.Type))
	}
	schemas, err := ts12Schemas()
	if err != nil {
		return append(list, findings.Uncited(fmt.Sprintf("the TS12 schemas do not compile: %v", err)))
	}
	if err := schemas[entry.Type].Validate(payload); err != nil {
		for _, problem := range schemaProblems(err) {
			list = append(list, findings.TS12.Protocol("§3.2").Newf("payload of %s does not match the schema of %q: %s", label, entry.Type, problem))
		}
	}
	return list
}

// TS12Findings checks a decoded transaction data entry of a TS12 type like a
// request entry. An entry of any other type has no findings.
func TS12Findings(object map[string]any) findings.List {
	entry := NewTransactionData("", object)
	if !slices.Contains(TS12TransactionDataTypes, entry.Type) {
		return nil
	}
	return ts12Findings("transaction_data", entry)
}

// schemaProblems lists the leaf errors of a validation error as "at /path:
// message".
func schemaProblems(err error) []string {
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return []string{err.Error()}
	}
	printer := message.NewPrinter(language.English)
	var problems []string
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			problems = append(problems, fmt.Sprintf("at /%s: %s", strings.Join(e.InstanceLocation, "/"), e.ErrorKind.LocalizedString(printer)))
			return
		}
		for _, cause := range e.Causes {
			walk(cause)
		}
	}
	walk(validation)
	slices.Sort(problems)
	return problems
}

// ts12AMR is the amr claim of TS12 §3.6, which needs "at least two different
// objects". The wallet does not authenticate the user, so it lists the factors
// of a typical wallet unit: a PIN and a key in the native key store.
var ts12AMR = []any{
	map[string]any{"knowledge": "pin_6_or_more_digits"},
	map[string]any{"possession": "key_in_local_native_wscd"},
}

// addTS12Claims adds the Key Binding JWT claims required by TS12 §3.6: a fresh
// jti, the response mode of the answer and amr.
func addTS12Claims(claims map[string]any, responseMode string) {
	claims["jti"] = uuid.NewString()
	claims["response_mode"] = responseMode
	claims["amr"] = ts12AMR
}
