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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func DirectPostForm(payload map[string]any) (url.Values, error) {
	form := url.Values{}
	for key, value := range payload {
		switch key {
		case "vp_token":
			tokenJSON, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("marshaling vp_token: %w", err)
			}
			form.Set(key, string(tokenJSON))
		case "id_token", "state", "error", "error_description":
			if text, ok := value.(string); ok && text != "" {
				form.Set(key, text)
			}
		}
	}
	return form, nil
}

func SubmitDirectPostObject(responseURI string, payload map[string]any, clients ...*http.Client) (*DirectPostResult, error) {
	form, err := DirectPostForm(payload)
	if err != nil {
		return nil, err
	}
	resp, err := format.HTTPClient(clients...).PostForm(responseURI, form)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "verifier response")
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
	if err := applyVerifierResponse(result, resp.Header, body); err != nil {
		return nil, &VerifierResponseError{err: err, body: string(body)}
	}

	return result, nil
}

type DirectPostResult struct {
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

type VerifierResponseError struct {
	err  error
	body string
}

func (e *VerifierResponseError) Error() string { return e.err.Error() }
func (e *VerifierResponseError) Unwrap() error { return e.err }

// Body is the response body of the verifier.
func (e *VerifierResponseError) Body() string { return e.body }

// SubmitDirectPostJWT exposes a supplied CEK in X-Debug-JWE-CEK for proxy debugging.
func SubmitDirectPostJWT(responseURI string, responseJWT string, cek []byte, clients ...*http.Client) (*DirectPostResult, error) {
	form := url.Values{}
	form.Set("response", responseJWT)

	// OID4VP 1.0 §8.2 sends the response to the verifier's response_uri. The
	// wallet's client limits the addresses it dials (ADR-0024).
	req, err := http.NewRequest("POST", responseURI, strings.NewReader(form.Encode())) //nolint:gosec // G704: see above
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if len(cek) > 0 {
		cekB64 := base64.RawURLEncoding.EncodeToString(cek)
		req.Header.Set("X-Debug-JWE-CEK", cekB64)
		log.Printf("[VP] JWE content encryption key for proxy debugging: %s", cekB64)
	}

	resp, err := format.HTTPClient(clients...).Do(req) //nolint:gosec // G704: the response_uri of OID4VP 1.0 §8.2
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := format.ReadRemoteBody(resp.Body, "verifier response")
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
	if err := applyVerifierResponse(result, resp.Header, body); err != nil {
		return nil, &VerifierResponseError{err: err, body: string(body)}
	}

	return result, nil
}

func BuildFragmentRedirect(redirectURI, state string, vpToken any, idToken string) (string, error) {
	fragment := url.Values{}
	if vpToken != nil {
		tokenJSON, err := json.Marshal(vpToken)
		if err != nil {
			return "", fmt.Errorf("marshaling vp_token: %w", err)
		}
		fragment.Set("vp_token", string(tokenJSON))
	}
	if idToken != "" {
		fragment.Set("id_token", idToken)
	}
	if state != "" {
		fragment.Set("state", state)
	}

	return appendFragmentParams(redirectURI, fragment), nil
}

// RFC 6749 §4.2.2 adds response parameters to the redirect URI's fragment. Merge with
// existing values, since RFC 3986 §3.5 treats a second # as part of the fragment.
func appendFragmentParams(redirectURI string, params url.Values) string {
	encoded := params.Encode()
	base, existing, hadFragment := strings.Cut(redirectURI, "#")
	if !hadFragment || existing == "" {
		return base + "#" + encoded
	}
	if encoded == "" {
		return redirectURI
	}
	return base + "#" + existing + "&" + encoded
}

func BuildFragmentErrorRedirect(redirectURI, state, errorCode, errorDescription string) string {
	fragment := url.Values{}
	fragment.Set("error", errorCode)
	if errorDescription != "" {
		fragment.Set("error_description", oid4vc.ErrorDescription(errorDescription))
	}
	if state != "" {
		fragment.Set("state", state)
	}
	return appendFragmentParams(redirectURI, fragment)
}

func FormatDirectPostResult(result *DirectPostResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Response: %d", result.StatusCode)
	if result.RedirectURI != "" {
		fmt.Fprintf(&sb, " → %s", result.RedirectURI)
	}
	return sb.String()
}

func applyVerifierResponse(result *DirectPostResult, headers http.Header, body []byte) error {
	if len(body) > 0 {
		var respJSON map[string]any
		if err := json.Unmarshal(body, &respJSON); err == nil {
			if redirectURI, ok := respJSON["redirect_uri"].(string); ok && redirectURI != "" {
				if err := format.ValidateAbsoluteURI("redirect_uri", redirectURI); err != nil {
					return err
				}
				result.RedirectURI = redirectURI
			}
		}
	}

	if loc := headers.Get("Location"); loc != "" {
		if err := format.ValidateAbsoluteURI("Location", loc); err != nil {
			return err
		}
		result.RedirectURI = loc
	}

	return nil
}
