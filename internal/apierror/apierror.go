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

// Package apierror writes the error object of the HTTP APIs under /api. It has
// the shape of an OAuth 2.0 error response (RFC 6749 §5.2), so a client reads
// API errors and protocol errors the same way.
package apierror

import (
	"encoding/json"
	"net/http"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
)

// Error codes. invalid_request and server_error come from RFC 6749 §5.2,
// temporarily_unavailable from RFC 6749 §4.1.2.1. The others describe the
// HTTP condition.
const (
	InvalidRequest         = "invalid_request"
	Forbidden              = "forbidden"
	NotFound               = "not_found"
	ConsentTimeout         = "consent_timeout"
	Conflict               = "conflict"
	TooManyRequests        = "too_many_requests"
	NotImplemented         = "not_implemented"
	TemporarilyUnavailable = "temporarily_unavailable"
	ServerError            = "server_error"
)

// Body is the error object.
type Body struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Findings list the failed checks of a refusal as text, one per entry.
	// FindingDetails adds the structured form of each.
	Findings       findings.List      `json:"findings,omitempty"`
	FindingDetails []findings.Finding `json:"finding_details,omitempty"`
}

// Write answers with the error object.
func Write(w http.ResponseWriter, status int, code, description string) {
	writeBody(w, status, Body{Error: code, Description: description})
}

func writeBody(w http.ResponseWriter, status int, body Body) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

// WriteErr answers with the error object for err. A refusal on findings
// adds them as a list.
func WriteErr(w http.ResponseWriter, status int, code string, err error) {
	list := findings.Of(err)
	writeBody(w, status, Body{Error: code, Description: err.Error(), Findings: list, FindingDetails: list.Details()})
}

// WriteStatusErr is WriteErr with the code of the status.
func WriteStatusErr(w http.ResponseWriter, status int, err error) {
	WriteErr(w, status, Code(status), err)
}

// InvalidJSON answers a request body that is not the expected JSON.
func InvalidJSON(w http.ResponseWriter, err error) {
	Write(w, http.StatusBadRequest, InvalidRequest, "invalid JSON body: "+err.Error())
}

// WriteStatus answers with the error object and the code of the status.
func WriteStatus(w http.ResponseWriter, status int, description string) {
	Write(w, status, Code(status), description)
}

// Code returns the error code of an HTTP status.
func Code(status int) string {
	switch status {
	case http.StatusForbidden:
		return Forbidden
	case http.StatusNotFound:
		return NotFound
	case http.StatusGatewayTimeout:
		return ConsentTimeout
	case http.StatusConflict:
		return Conflict
	case http.StatusTooManyRequests:
		return TooManyRequests
	case http.StatusNotImplemented:
		return NotImplemented
	case http.StatusServiceUnavailable:
		return TemporarilyUnavailable
	}
	if status >= 500 {
		return ServerError
	}
	return InvalidRequest
}
