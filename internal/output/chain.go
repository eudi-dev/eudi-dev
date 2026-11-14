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

package output

import (
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/delegatepayload"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// ChainJSON is the chain member of the decoder and of decode and validate
// with --json.
type ChainJSON struct {
	Format string `json:"format"`
	// Status is "pass" or "fail".
	Status string          `json:"status"`
	Parts  []ChainPartJSON `json:"parts"`
}

// ChainPartJSON is one part of a ChainJSON. The labels and texts are the
// wording of every view of the chain.
type ChainPartJSON struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Raw   string `json:"raw"`
	Typ   string `json:"typ"`
	// SignerLabel is "Expected signer" when the signature fails.
	SignerLabel string        `json:"signerLabel"`
	Signer      *ChainKeyJSON `json:"signer"`
	// SignerText describes the signer when Signer is nil.
	SignerText    *string       `json:"signerText"`
	DelegateLabel string        `json:"delegateLabel"`
	Delegate      *ChainKeyJSON `json:"delegate"`
	// DelegateText stands for a missing Delegate.
	DelegateText *string `json:"delegateText"`
	// Exp is a NumericDate.
	Exp         *int64                  `json:"exp"`
	UntilLabel  string                  `json:"untilLabel"`
	Until       string                  `json:"until"`
	LimitsLabel string                  `json:"limitsLabel"`
	Limits      []delegatepayload.Limit `json:"limits"`
	Signature   ChainCheckJSON          `json:"signature"`
	Binding     *ChainCheckJSON         `json:"binding"`
	Problem     *string                 `json:"problem"`
	Trusted     bool                    `json:"trusted"`
	// TrustDetail says which earlier part fails when the part is not trusted.
	TrustDetail *string `json:"trustDetail"`
}

// ChainKeyJSON is a cnf key with its letter in the chain.
type ChainKeyJSON struct {
	Label      string `json:"label"`
	Thumbprint string `json:"thumbprint"`
}

// ChainCheckJSON is a check of a part. Status is "pass", "fail" or
// "not_checked".
type ChainCheckJSON struct {
	Status string `json:"status"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// The statuses of a ChainCheckJSON.
const (
	chainPass       = "pass"
	chainFail       = "fail"
	chainNotChecked = "not_checked"
)

// BuildChainJSON is the JSON form of a chain.
func BuildChainJSON(c *validate.Chain) ChainJSON {
	out := ChainJSON{Format: c.Format, Status: chainPass, Parts: make([]ChainPartJSON, 0, len(c.Parts))}
	if c.Failed() {
		out.Status = chainFail
	}
	for _, part := range c.Parts {
		entry := ChainPartJSON{
			Kind:          part.Kind,
			Label:         part.Label,
			Raw:           part.Raw,
			Typ:           part.Typ,
			SignerLabel:   "Signed by",
			Signer:        chainKeyJSON(part.Signer),
			DelegateLabel: "Delegates to",
			Delegate:      chainKeyJSON(part.Delegate),
			UntilLabel:    "Until",
			Until:         "No exp",
			LimitsLabel:   chainLimitsLabels[part.Kind],
			Limits:        part.Limits,
			Signature:     chainCheckJSON("Signature", part.Signature),
			Problem:       optionalText(part.Problem),
			Trusted:       part.Trusted,
			TrustDetail:   optionalText(part.TrustDetail),
		}
		if entry.Signature.Status == chainFail {
			entry.SignerLabel = "Expected signer"
		}
		if entry.Signer == nil {
			entry.SignerText = optionalText("The delegate key of the part before it")
			if part.Kind == validate.PartSDJWT {
				entry.SignerText = optionalText("Issuer key")
			}
		}
		if part.Kind == validate.PartSDJWT {
			entry.DelegateLabel = "Holder key"
		}
		if entry.Delegate == nil {
			entry.DelegateText = optionalText("No one. The chain ends here.")
		}
		if entry.Limits == nil {
			entry.Limits = []delegatepayload.Limit{}
		}
		if part.Expiry != nil {
			exp := part.Expiry.Unix()
			entry.Exp = &exp
			entry.Until = part.Expiry.UTC().Format("2006-01-02 15:04 UTC")
		}
		if part.Binding != nil {
			binding := chainCheckJSON("Binding", *part.Binding)
			entry.Binding = &binding
		}
		out.Parts = append(out.Parts, entry)
	}
	return out
}

// chainLimitsLabels head the limits of a part. The limits of an SD-JWT are
// its vct, and those of a Key Binding JWT are its aud and nonce.
var chainLimitsLabels = map[string]string{
	validate.PartSDJWT:   "Type",
	validate.PartKBSDJWT: "Limits",
	validate.PartKBJWT:   "Request",
}

func chainKeyJSON(key *validate.ChainKey) *ChainKeyJSON {
	if key == nil {
		return nil
	}
	return &ChainKeyJSON{Label: key.Letter, Thumbprint: key.Thumbprint}
}

func chainCheckJSON(name string, check validate.PartCheck) ChainCheckJSON {
	out := ChainCheckJSON{Status: chainNotChecked, Label: name + " not checked", Detail: check.Detail}
	switch check.Status {
	case validate.Pass:
		out.Status, out.Label = chainPass, name
	case validate.Fail:
		out.Status, out.Label = chainFail, name
	}
	return out
}

func optionalText(text string) *string {
	if text == "" {
		return nil
	}
	return &text
}

// PrintChain prints a chain with one block for each part.
func PrintChain(c ChainJSON) {
	headerColor.Printf("Delegation (%s)\n", c.Format)
	headerColor.Println(strings.Repeat("─", 50))
	for _, line := range ChainLines(c) {
		if strings.HasPrefix(line, "┌ ") {
			fmt.Println()
			headerColor.Println(line)
			continue
		}
		fmt.Println(line)
	}
	fmt.Println()
}

// ChainLines are the lines of the part blocks of PrintChain.
func ChainLines(c ChainJSON) []string {
	var lines []string
	for _, part := range c.Parts {
		lines = append(lines, fmt.Sprintf("┌ %s (%s)", part.Label, part.Typ))
		lines = append(lines, fmt.Sprintf("  %s: %s", part.SignerLabel, chainKeyText(part.Signer, part.SignerText)))
		lines = append(lines, fmt.Sprintf("  %s: %s", part.DelegateLabel, chainKeyText(part.Delegate, part.DelegateText)))
		lines = append(lines, fmt.Sprintf("  %s: %s", part.UntilLabel, part.Until))
		for _, limit := range part.Limits {
			lines = append(lines, fmt.Sprintf("  %s: %s", limit.Name, limit.Value))
		}
		lines = append(lines, chainCheckLine(part.Signature))
		if part.Binding != nil {
			lines = append(lines, chainCheckLine(*part.Binding))
		}
		if part.Problem != nil {
			lines = append(lines, "  ✗ "+*part.Problem)
		}
		if part.TrustDetail != nil {
			lines = append(lines, "  "+*part.TrustDetail)
		}
	}
	return lines
}

func chainKeyText(key *ChainKeyJSON, text *string) string {
	if key == nil {
		return *text
	}
	return fmt.Sprintf("%s (key %s)", key.Thumbprint, key.Label)
}

func chainCheckLine(check ChainCheckJSON) string {
	mark := map[string]string{chainPass: "✓", chainFail: "✗", chainNotChecked: "○"}[check.Status]
	return fmt.Sprintf("  %s %s: %s", mark, check.Label, check.Detail)
}
