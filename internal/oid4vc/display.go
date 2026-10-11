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

package oid4vc

// CredentialDisplay is an OpenID4VCI 1.0 §12.2.4 display entry in the flat
// form a wallet stores with a credential, so the card renders without
// contacting the issuer. An image field holds a data URI or an "asset:"
// reference fetched once at issuance. With --adhoc-display-images it holds the
// issuer's https URL instead.
type CredentialDisplay struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	Locale          string `json:"locale,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	LogoAltText     string `json:"logo_alt_text,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
	BackgroundURI   string `json:"background_uri,omitempty"`
}
