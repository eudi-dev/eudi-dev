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

import "errors"

// OpenID4VP 1.0 §8.5 uses invalid_request and access_denied from OAuth 2.0. Appendix
// E.3 registers the additional error codes.
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorAccessDenied            = "access_denied"
	ErrorVPFormatsNotSupported   = "vp_formats_not_supported"
	ErrorInvalidRequestURIMethod = "invalid_request_uri_method"
	ErrorInvalidTransactionData  = "invalid_transaction_data"
)

// Error is a refusal with the error code of OpenID4VP 1.0 §8.5. An error
// without a code is reported as invalid_request.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// ErrorCode is the code of err. It defaults to invalid_request for requests
// the wallet cannot parse (OpenID4VP 1.0 §8.5).
func ErrorCode(err error) string {
	var authErr *Error
	if errors.As(err, &authErr) && authErr.Code != "" {
		return authErr.Code
	}
	return ErrorInvalidRequest
}

// RefusalCode is the error code of a refused request. An explicit error code
// takes precedence. Otherwise it inspects the request for the parameter errors
// defined by OpenID4VP 1.0 §8.5.
func RefusalCode(authReq *Request, err error) string {
	if code := ErrorCode(err); code != ErrorInvalidRequest {
		return code
	}
	if authReq == nil {
		return ErrorInvalidRequest
	}
	// §8.5 invalid_request_uri_method: "The value of the request_uri_method
	// request parameter is neither get nor post (case-sensitive)."
	switch authReq.RequestURIMethod {
	case "", "get", "post":
	default:
		return ErrorInvalidRequestURIMethod
	}
	// OpenID4VP 1.0 §8.5 uses invalid_transaction_data for unsupported transaction
	// types. This wallet supports none.
	if HasTransactionData(authReq, authReq.RequestPayload) {
		return ErrorInvalidTransactionData
	}
	return ErrorInvalidRequest
}
