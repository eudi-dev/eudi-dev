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

// OpenID4VP 1.0 §8.5 uses invalid_request and access_denied from OAuth 2.0. Appendix
// E.3 registers the additional error codes.
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorAccessDenied            = "access_denied"
	ErrorVPFormatsNotSupported   = "vp_formats_not_supported"
	ErrorInvalidRequestURIMethod = "invalid_request_uri_method"
	ErrorInvalidTransactionData  = "invalid_transaction_data"
)

// RefusalCode is the error code of a refused request. It inspects the request
// for the parameter errors defined by OpenID4VP 1.0 §8.5.
func RefusalCode(authReq *Request) string {
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
	if hasTransactionData(authReq, authReq.RequestPayload) {
		return ErrorInvalidTransactionData
	}
	return ErrorInvalidRequest
}
