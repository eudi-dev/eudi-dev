# Changelog

Notable changes by release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - Unreleased

### Highlights

Version 3.0.0 adds a registrar, ARF checks, a catalogue of attestations and a trust model built on trusted lists.

- **Registrar for verifiers and issuers.** Register a verifier or an issuer and get its access and registration certificates, ready for `verifier_info` or `issuer_info` (see [registrar](docs/wallet/registrar.md) and the [registrar walkthrough](docs/wallet/registrar-api.md)).
- **ARF checks.** `--arf` checks how verifiers and issuers authenticate, the way `--haip` checks HAIP (see [presenting](docs/wallet/presenting.md#arf-checks) and [issuing](docs/wallet/issuing.md#arf-checks)).
- **Trust through trusted lists.** Every trust anchor comes from a list of trusted entities (ETSI TS 119 602): one per credential category, one for wallet providers, access certificate providers and registrars, and a list of trusted lists that points to all of them. Add your own CAs and lists with `trust` (see [ADR 0023](docs/adr/0023-trust-anchors-come-from-trusted-lists.md)).
- **Catalogue of attestations.** The registrar lists attestation types with their schemas, rulebooks and trusted lists, following the EC TS11 catalogue (see [attestation catalogue](docs/wallet/registrar.md#attestation-catalogue)).
- **Findings in debug mode.** The API response and a collapsible part of the consent dialog list the failed checks of a verifier or issuer.
- **Italian and Dutch PIDs and startup credentials.** Italian and Dutch PID templates, and `wallet serve --credentials` loads credentials on every start (see [templates](docs/templates.md)).

### Breaking changes

- **New home in the eudi-dev organization.** The repository moved to [github.com/eudi-dev/eudi-dev](https://github.com/eudi-dev/eudi-dev). The Go module path is `github.com/eudi-dev/eudi-dev/v3`, so install with `go install github.com/eudi-dev/eudi-dev/v3@latest`. The image is `ghcr.io/eudi-dev/eudi-dev`, and Homebrew installs from `eudi-dev/tap/eudi-dev`. The old image keeps its published tags. If you installed from `dominikschlosser/tap`, run `brew upgrade eudi-dev/tap/eudi-dev` once to trust and use the new tap. Old GitHub links redirect.
- **Command layout.** `registrar`, `catalog`, `trust` and `decoder` (formerly `serve`) are top-level commands. `wallet trust-list --id <list>` is `trust show <list>`, and `trust show lists` prints the list of trusted lists. An old command path fails with a message that names the new one (see [ADR 0027](docs/adr/0027-the-cli-groups-commands-by-role.md)).
- **Deprecated commands removed.** `wallet generate-pid` and `POST /api/generate-pid` are gone. Issue PIDs with `issue sdjwt --wallet --pid` and `issue mdoc --wallet --pid`, or start the wallet with `wallet serve --pid`. `wallet instances` is gone. Use `wallet ps`. `--demo-verifier-trust-anchor` is now `--demo-verifier-issuer-ca`.
- **Former name oid4vc-dev.** The `oid4vc-dev` command alias, the `ghcr.io/dominikschlosser/oid4vc-dev` image, `OID4VC_DEV_HOME` and the `~/.oid4vc-dev` directory are gone. Use `eudi`, `ghcr.io/eudi-dev/eudi-dev`, `EUDI_DEV_HOME` and `~/.eudi-dev`. Move an old state directory with `mv ~/.oid4vc-dev ~/.eudi-dev`.
- **`--category` replaces `--trust-profile`.** `issue --category` and the API field `category` replace `--trust-profile` and `trust_profile`. They take `pid`, `qeaa`, `pub-eaa`, `eaa` or `unlisted`. A credential without a category is an EAA. `unlisted` keeps it off every list (see [ADR 0022](docs/adr/0022-one-trusted-list-per-credential-category.md)).
- **Trusted lists.** Each category signs with its own key and has its own list. Only PIDs are signed with `issuer.pem`. The `local` list is renamed to `eaa`, so `/api/trustlists/local` is now `/api/trustlists/eaa`. `wallet serve --issuer-key` signs only PIDs too. The QEAA list, the EAA list and the list of trusted lists use the types `https://eudi-test.dev/LoTEType/QEAAProvidersList`, `EAAProvidersList` and `ListOfTrustedLists` instead of the unregistered `http://uri.etsi.org/19602/LoTEType/local`. A wallet from eudi-dev 2 migrates its stored types.
- **Trust anchors of the ARF checks.** Access certificates anchor only through the access certificate provider list, and registration certificates only through the registrar list. The wallet CA anchors neither. The registrar signs under its own registrar CA, and the CAs from `--relying-party-ca` are on both lists (see [ADR 0023](docs/adr/0023-trust-anchors-come-from-trusted-lists.md)).
- **Imported credentials.** An imported credential is on none of the wallet's lists.
- **Provider role `eaa`.** The provider role `local` is now `eaa`. Its certificates and CRLs moved from `/api/certificates/providers/local/...` and `/api/crl/providers/local/...` to `/api/certificates/providers/eaa/...` and `/api/crl/providers/eaa/...`.
- **Decoder trust.** The decoder no longer trusts the local wallet CA and issuer key. It anchors a credential only in the trusted lists of its catalogue entry. It reads a stored wallet and never creates one (see [decoder](docs/decoder.md)).
- **A running wallet keeps its settings.** CLI commands that talk to a running wallet refuse a setting only when it differs from the running wallet's own. The wallet applies its settings to every step of a flow. A flag with the same value changes nothing. Change a setting on `wallet serve`, through `PUT /api/config/conformance` or with `trust`.
- **Registrar API.** `GET /api/registrar/wrp` returns the TS05 v1.5 format. Its filter `providesattestation` is renamed to `providedattestation`. A provided attestation is `{"format", "type"}`, and `supportURI` is a single string.
- **Relying party identifiers.** A registration holds an identifier of a type of ETSI TS 119 475 clause B.2.5. The registrar assigns an EUID such as `NLTEST.1A2B3C4D5E6F7A8B`. Certificates and trusted lists carry its semantics identifier, such as `NTRNL-NLTEST.1A2B3C4D5E6F7A8B` (Table 2). The demo issuer is `NLTEST.00000000` and the demo verifier `NLTEST.00000001` (see [registrar](docs/wallet/registrar.md)).
- **`issuer_info` and `verifier_info`.** Both carry only the registration certificate. The wallet no longer reports a missing `registrar_dataset`, because CIR (EU) 2026/1731 Annexes XI and XII void those requirements.
- **JSON output.** `validate`, `wallet deferred check`, `wallet list` and one-shot `wallet accept` print a different `--json` document (see [ADR 0020](docs/adr/0020-cli-output-can-be-automated.md)).
- **"Trusted list" in CLI names.** `validate --trust-list` is `--trusted-list`, `issue --trust-list-type` and `--trust-entity-name` are `--trusted-list-type` and `--trusted-entity-name`, and `decode --format trustlist` is `trusted-list`, which is also the format in its `--json` output.
- **Conformance settings API.** `PUT /api/config/conformance` takes the setting names of `GET /api/config`, such as `validation_mode` and `require_arf`, and refuses other names (see [HTTP API](docs/wallet/http-api.md)).
- **Presentation API errors.** `POST /api/presentations` refuses an invalid request with `{"error": "<code>", "error_description": "<message>"}` (see [presenting](docs/wallet/presenting.md)).
- **Outbound addresses.** `decoder` and `wallet serve` reach public addresses, loopback and their own URLs only. `--allow-private-networks` or `EUDI_DEV_ALLOW_PRIVATE_NETWORKS=true` lets them reach private networks. The Docker image sets the variable (see [outbound address limits](docs/wallet/serve.md#outbound-address-limits)).
- **Exit codes.** `wallet accept` and `wallet scan` exit non-zero when a flow fails or is denied. `validate` also exits non-zero when the `typ` of an SD-JWT VC is not `dc+sd-jwt`, when a digest doesn't match, or when the credential is not valid yet. `--allow-expired` skips both validity checks.
- **`--json` on servers.** Most commands print one JSON document with `--json`. `decoder`, `wallet serve` and `completion` refuse it. `wallet serve --log-format json` writes JSON logs (see [ADR 0020](docs/adr/0020-cli-output-can-be-automated.md)).
- **Demo verifier requests.** A request without `credential_sets` needs a presentation for every credential query (OpenID4VP 1.0 §6.4.2). The verifier refuses a response for a query it did not ask, a response without the request's `state`, and an SD-JWT VC whose `typ` is `vc+sd-jwt` or missing. It checks mdoc revocation and matches claims by their full DCQL path.
- **Demo issuer authorization.** The demo issuer refuses an unknown `scope` or `issuer_state`. A code bound to a DPoP key needs that key at the token endpoint.
- **Issuer identifiers.** The wallet compares an authorization server's `issuer` and the RFC 9207 `iss` exactly. A trailing slash is a mismatch. Strict mode refuses it and debug mode warns.
- **Fragment responses.** A request with `response_mode=fragment` needs a `redirect_uri`. The wallet doesn't send the response to `response_uri`.
- **Lists in `trusted_authorities`.** The wallet uses an `etsi_tl` list only when a known operator signed it. Add the operator with `trust` or `--trusted-list-ca`.
- **Malformed DCQL in strict mode.** Strict mode refuses a malformed `dcql_query` with `invalid_request`.
- **Trusted lists in `validate`.** `validate --trusted-list` fails on a list without `NextUpdate` or past it. Only the issuance services of a list anchor the credential.
- **`POST /api/decode` removed.** Use `POST /api/validate`. It takes the same `input` and returns the decoded credential with its checks.
- **Image configured by environment.** The image no longer reads `PORT`. Its default command is `wallet serve`, with the defaults in `EUDI_DEV_PORT=8085`, `EUDI_DEV_AUTO_ACCEPT=true` and `EUDI_DEV_PID=true`. A custom `wallet serve` command gets these defaults too. Set `EUDI_DEV_AUTO_ACCEPT=false` for a wallet that asks for consent (see [Docker](docs/docker.md#configuration-by-environment)).

### Added

- **Relying party registrar.** The wallet registers verifiers and issuers and issues their access and registration certificates, with revocation through a status list. A verifier gets its registration certificate base64url encoded in a `verifier_info` value (ETSI TS 119 472-2 V1.3.1 RO-16). An issuer gets it as a plain JWT in an `issuer_info` value for its metadata. The consent dialog links the registered privacy policy. An issuer gets a provider entitlement for each category of its attestation types (see [registrar](docs/wallet/registrar.md)).
- **Registrar walkthrough.** Every registrar request with curl and its response, from registering to a signed request and signed issuer metadata (see [registrar walkthrough](docs/wallet/registrar-api.md)). **How to use** has a registrar tab.
- **ARF checks.** `--arf` checks verifiers and issuers against the ARF, the way `--haip` checks HAIP. It covers access and registration certificates, signed issuer metadata and the trusted list of each received credential. `--demo` turns the checks on (see [presenting](docs/wallet/presenting.md#arf-checks) and [issuing](docs/wallet/issuing.md#arf-checks)).
- **Your own trust.** `trust add-ca` puts the CA of your issuer or registrar on one of the wallet's lists. `trust add-list` adds an external list. `GET /api/trust` and the **Trust & certificates** section show both (see [trusted lists](docs/wallet/serve.md#trusted-lists)).
- **List of trusted lists.** `/api/trustlists/lists` points to every list of the wallet (ETSI TS 119 602 §6.3.13). The wallet follows the pointers of an external list of trusted lists. `wallet serve --trusted-list` adds a list on start.
- **Findings in debug mode.** The presentation and issuance results list the checks that failed as `findings`. The consent dialog shows them in a collapsible part.
- **Trust check in the decoder.** The decoder and `validate` check the credential against the trusted lists in the catalogue entry of its type (see [validate](docs/validate.md#catalogue-trust)).
- **Attestation catalogue.** The registrar keeps a catalogue of attestation types with their schemas, rulebooks and trusted lists, following the EC TS11 catalogue of attestations. Every predefined template is in it. Saving a user template can add it too, and `catalog add` adds other types. The UI filters it by category, security level, holder binding and source (see [attestation catalogue](docs/wallet/registrar.md#attestation-catalogue)).
- **Registered demo issuer and verifier.** **EUDI Dev Demo Issuer** and **EUDI Dev Demo Verifier** register like any relying party, each with its own access certificate from the relying party access CA. The demo verifier sends its registration certificate by default, and its requests pass the `--arf` checks. Outside a public demo you can change or delete both (see [the demo issuer and verifier](docs/wallet/registrar.md#demo-issuer-and-verifier)).
- **Startup credentials.** `wallet serve --credentials` issues or imports credentials on every start (see [startup credentials](docs/wallet/serve.md#startup-credentials)).
- **Italian and Dutch PIDs.** Templates for the IT-Wallet 1.4.7 PID and the NL Wallet PID draft, with specimen card images (see [templates](docs/templates.md)).
- **More control in debug mode.** The consent dialog lets you pick another `claim_sets` option and credentials that don't match.
- **Beta channel.** A tag such as `v3.0.0-beta.1` is a GitHub prerelease. The Docker tag `beta` follows the newest release, betas included. `latest` and Homebrew stay on the newest stable release. The wallet footer marks a beta (see [beta releases](README.md#beta-releases)).
- **Registration in one step.** `POST /api/registrar/enrolments` registers a relying party and issues its access and registration certificates together. `PUT` does the same for a change. If a certificate fails, the registration stays as it was (see [registrar](docs/wallet/registrar.md)).
- **Configuration choice for offers.** `credential_configuration_id` on `POST /api/offers` and on the approve request picks one configuration of a multi-configuration offer (see [issuing](docs/wallet/issuing.md)).
- **One registration for both roles.** **+ Add verifier registration certificate** lets an issuer ask for a PID before it issues, like the demo issuer. **+ Add issuer registration certificate** lets a verifier issue as well. The party stays one registration with both roles. Deleting a certificate removes it from the registration and revokes it. In the CLI, `verifiers add --to` and `issuers add --to` add the other role or more types, and `registration-cert` prints the current certificate (`--new` issues a new one). See the [registrar walkthrough](docs/wallet/registrar-api.md#5-pid-request-before-issuance).
- **Not yet valid credentials.** A credential card shows **Not yet valid** before its `nbf` or `validFrom`.
- **Environment configuration.** Every `wallet serve` flag can be set as `EUDI_DEV_<FLAG>`, such as `EUDI_DEV_PORT` or `EUDI_DEV_BASE_URL`. A flag on the command line wins. An unknown `EUDI_DEV_` variable stops the server, so a typo does not go unnoticed (see [configuration by environment](docs/docker.md#configuration-by-environment)).

### Changed

- **Unsigned request objects without `typ`.** The wallet warns about a missing `typ` in an unsigned Request Object but still processes it, also in strict mode. OID4VP 1.0 §5 requires `typ`, but the OIDF conformance suite sends its unsigned request objects without one (see [spec compliance](docs/spec-compliance.md)).
- **Unbound credentials and signed metadata without `iat` in debug mode.** Debug mode presents an unbound credential to a query that requires holder binding and marks it. It reads signed issuer metadata without `iat` or past `exp` with a finding. Strict mode refuses both (OpenID4VP 1.0 §6.1, OpenID4VCI 1.0 §12.2.3).
- **Strict `--arf` refusals.** An issuer that fails the checks is refused before the consent dialog. An authenticated verifier gets `access_denied` on `/authorize`, over the Digital Credentials API and from `wallet accept`.
- **HAIP checks of received credentials.** With `--haip` every received SD-JWT VC follows HAIP 1.0 §6.1.1, on every issuance path and for every copy of a batch.
- **Status list trust.** A credential's status list anchors through the revocation service of the trusted list that anchors the credential, and the credential through its issuance service (ETSI TS 119 602 V1.1.1 Table D.3). This applies in the wallet, the decoder, `validate`, DCQL `trusted_authorities` and the demo verifier.
- **Status list format.** The wallet asks for a JWT status list for an SD-JWT VC and a CWT status list for an mdoc, and accepts the other one.
- **Templates.** The default PIDs and the demo ticket come from templates. `issue --pid --vct` finds the PID templates by their type. The template field `unique_claims` gives a claim a fresh random value in every credential. **New template** and **Edit** open the issue form with a builder and the template JSON (see [templates](docs/templates.md#wallet-ui)).
- **Public demo.** Visitors can save their own templates and add providers and lists, within limits. A reset deletes the visitor templates. The demo issuer and verifier make room for new requests instead of refusing them (see [public demo hosting](docs/public-demo.md)).
- **Conformance dialog.** The settings have clearer names, and the key attestation levels match the catalogue's levels of security.
- **Signed issuer metadata.** The wallet's issuers sign their metadata when the `Accept` header ranks `application/jwt` above `application/json`. With `--arf` the wallet asks for signed metadata first.
- **Shared credential checks.** `validate`, the decoder and the demo verifier run the same checks: chain, signature, validity with one minute of clock skew, status and HAIP. A trusted list past its `NextUpdate` anchors nothing there either (see [validate](docs/validate.md#checks)).
- **Deferred credentials.** Collection checks the issuer metadata like the first request. A collected credential can be renewed.
- **Check results.** The decoder and the demo verifier show one verdict with short check details. Warnings get their own group, and the decoder names the anchoring trusted list once with a link. The demo verifier folds the passed checks.
- **UI texts.** Shorter hints in the wallet, the decoder and the demo pages, sentence case in every dialog title and labels for every input. The consent dialog names the registered relying party. The proxy writes its traffic classes in sentence case, also in `classLabel` of `--json`. The issuer CA field of the catalogue says which trusted list gets the CA, and saving over another template asks first.
- **More findings.** Batch copies that bind no proof key, an `expected_origins` mismatch in interactive authorization and an unreadable `trusted_authorities` list are findings: strict mode refuses, debug mode warns.

### Fixed

- **Registration certificate checks.** The wallet checks the fields of ETSI TS 119 475 V1.2.1 Table 7 and the shape of `issuer_info` (ETSI TS 119 472-3 V1.1.1 §4.2.3).
- **Imported PIDs.** Importing a PID leaves the wallet's own PID types on the PID list.
- **Renewals and deferred credentials.** A renewal checks the issuer before it uses the refresh token. In strict mode a deferred request waits for usable issuer metadata and stays encrypted.
- **Verifier redirect after a refusal.** The wallet follows the `redirect_uri` of an error response (OpenID4VP 1.0 §8.2).
- **mdoc without deviceKey in strict mode.** Strict mode refuses to present it (ISO 18013-5 §9.1.2.4).
- **HAIP checks of an mdoc.** `validate --haip` checks the `x5c` rules of HAIP 1.0 §6.1.1 only for SD-JWT VCs. That section does not cover mdocs.
- **Conformance settings for offers.** `wallet accept` and `wallet scan` apply `--mode`, `--haip` and `--arf` to credential offers too.
- **Running wallet presentations.** `wallet accept` passes `--session-transcript` to a running wallet and keeps the flow local with `--remote local`.
- **Long decoder links.** **Open in decoder** links carry the credential in the URL fragment. A proxy's URL length limit doesn't cut off a long request object there. Links with `?credential=` open too.
- **Template offers with an authorization code.** The demo issuer issues the offered template with an authorization code too, also with a PID presentation during issuance. It takes only the requested names of the presented PID.
- **Demo issuer offer scheme.** The demo issuer's offer links use `openid-credential-offer://`. The wallet also accepts `eu-eaa-offer://`.
- **Offer dialog.** A long credential description shows two lines with a **More** button. The status badges of a consent row don't overlap the **Show** button at phone width.
- **Phone layout.** Long check details in the decoder wrap, and the forms and relying party rows of the wallet fit a 375 px screen.
- **Demo verifier after the redirect.** The page shows the requested credential.
- **Request object signatures.** The wallet verifies a request object only with the key its client identifier prefix names. Under `verifier_attestation:` it checks the attestation and its `cnf` key. Under `decentralized_identifier:` it reports the signature as not verified.
- **`auth_via_web`.** The wallet advertises it only with an https redirect URI and sends the `code_verifier` after it (OpenID4VCI 1.1 §6.2.1.2).
- **Status list indices.** Every credential on the wallet's status list gets a unique, unpredictable index (HAIP 1.0).
- **Imported SD-JWT VCs.** Import checks `typ`, `vct`, disclosed registered claims and a key binding JWT. Strict mode refuses a failing credential.
- **Demo verifier responses.** A request accepts one verified response or error response. A response that fails verification shows why and leaves the request open.
- **Trusted lists.** The `pub-eaa` list keeps a removed service as withdrawn (ETSI TS 119 602 Table H.3). The wallet keeps an external list at most until its `NextUpdate`.
- **CLI refusals.** `issue` refuses the wallet-only flags without `--wallet`, and refuses `--iss` or a `--key` without `--cert` on a running wallet. `wallet accept` and `wallet scan` on a remote wallet refuse `--port` and `--docker`. Every command that talks to a running wallet compares the outbound HTTP flags.
- **Proxy decoding.** The proxy decodes credentials offline, so it never holds a response for a network check.
- **DNS names of `x509_san_dns`.** The wallet compares the client identifier with the certificate's DNS names case-insensitively (RFC 5280 §4.2.1.6).
- **Graceful shutdown.** `POST /api/shutdown` stops `wallet serve` like Ctrl-C.
- **Card images in the demo issuer metadata.** The issuer metadata lists the logo and card image of each template (see [templates](docs/templates.md)).

## [2.7.1] - 2026-10-12

### Changed

- **New home in the eudi-dev organization.** The repository moved to [github.com/eudi-dev/eudi-dev](https://github.com/eudi-dev/eudi-dev). The Go module path is `github.com/eudi-dev/eudi-dev/v2`, so install with `go install github.com/eudi-dev/eudi-dev/v2@latest`. The image is `ghcr.io/eudi-dev/eudi-dev`, and Homebrew installs from `eudi-dev/tap/eudi-dev`. If you installed from `dominikschlosser/tap`, run `brew upgrade eudi-dev/tap/eudi-dev` once to trust and use the new tap. The old images keep their published tags, and old GitHub links redirect. Nothing else changed since 2.7.0.

## [2.7.0] - 2026-10-10

### Added

- **News for demo visitors.** `wallet serve --demo --news-file news.html` shows an HTML snippet in a popup on the first visit and links it as **News** in the footer. A changed file opens once more (see [public demo hosting](docs/public-demo.md#news)).

## [2.6.1] - 2026-10-06

### Fixed

- **HAIP on one-shot accept.** `wallet accept --haip` and `wallet scan --haip` without a running wallet server check credential offers and presentation requests against HAIP 1.0. Before, the flag had no effect on that path. Presentation requests on that path also get the OID4VP 1.0 request checks the wallet server applies, so strict mode rejects the same requests on both, except the DC API `expected_origins` check, since the CLI has no request origin. Thanks to [Maxime Mansiet](https://github.com/AirKyzzZ) for the contribution (#23).
- **HAIP findings in JSON output.** `validate --haip --json` prints the findings as a `haipFindings` object. Before, JSON output left them out. The exit code still depends only on signature, expiry and revocation. Thanks to [Maxime Mansiet](https://github.com/AirKyzzZ) for the contribution (#23).

### Documentation

- **polaris-oid4vp in the comparison table.** The README lists the polaris-oid4vp verifier among the related tools. Thanks to [Egor Khaklin](https://github.com/EgorKhaklin) for the contribution (#22).

## [2.6.0] - 2026-10-04 

### Added

- **Path prefix support.** The wallet, its demo issuer and verifier, and the proxy dashboard can be served under a path prefix on a shared host, such as `--base-url https://example.com/some/context`. The reverse proxy can strip or keep the prefix. Redirects, page links, API links and the session cookie use the prefix the browser sees. The wallet reads it from `X-Forwarded-Prefix` or infers it from the request host. URLs in credentials and protocol messages always use `--base-url`. `eudi proxy --dashboard-base-url` sets the dashboard's public URL. See [behind a reverse proxy](docs/reverse-proxy.md).
- **Outbound proxy for the wallet.** The wallet connects to issuers and verifiers through the proxy set in `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. The flags `--https-proxy`, `--http-proxy` and `--no-proxy` override these variables. Requests to `localhost` and `host.docker.internal` bypass the proxy.
- **Health probes.** `GET /healthz` answers while the wallet server runs. `GET /readyz` also checks the storage backend and answers `503` when the backend is unreachable. See [health probes](docs/wallet/http-api.md#health-probes).
- **DCQL `multiple`.** When a verifier sets `multiple: true` on a credential query, the wallet sends all matching credentials. Before, it sent only the newest one. The consent dialog shows this and lets you deselect credentials. To try it, tick **multiple** on any demo verifier request.
- **Demo ticket + PID.** The demo verifier asks for the ticket and a PID in one request, with the ticket next to the PID or as an optional extra.
- **JSON logs.** `wallet serve --log-format json` or `EUDI_DEV_LOG_FORMAT=json` writes the console output to stdout as one JSON record per line. Each record has a level and the logging component. See [JSON logs](docs/wallet/serve.md#json-logs).

### Changed

- **Content Security Policy.** `base-uri` is now `'self'` instead of `'none'`. 
- **Approving a request with a broken body.** `POST /api/requests/{id}/approve` now answers `400` when the body is not valid JSON. Before, the wallet ignored the body and approved with its default choice.
- **mdoc spelling.** The UI, CLI output, help and documentation write `mdoc` as ISO 18013-5 does, instead of `mDoc` or `mDOC`. Format identifiers such as `mso_mdoc` and API fields are unchanged.

### Fixed

- **Credential identifier from the token response.** When the token response authorizes several credential configurations, the wallet requests the one it was offered instead of the first. When it authorizes only a different configuration, the activity log shows a warning with both identifiers.
- **Demo verifier at phone width.** Verified claims wrap inside the card and show lists as indented JSON. The option rows wrap.
- **Demo issuer credential picker.** The dropdown now matches the rest of the page in light and dark mode.

## [2.5.1] - 2026-10-02

### Fixed

- **Activity log display.** Entries start collapsed. Opening an entry shows all detail fields and formatted JSON bodies. Request and Response headings match the other labels and have space above them. Decoder and view controls share a toolbar above the body. CLI output is unchanged.
- **Activity decoder buttons.** Request JWTs and imported credentials open in the decoder. Batch imports show one credential with its stored copies, such as **Imported credential (8 copies)**, and include each copy's ID. Import and credential response entries have **Open copy 1 in decoder** buttons for every copy, including deferred batches. Sent presentations have buttons named for their query, such as **Open 'pid' in decoder**.
- **Encrypted activity display.** Show the wire value first. **View decrypted** shows the plaintext and **View encrypted** returns to the wire value. These buttons only change the log display.
- **Request object activity.** A fetched request object and its receipt share one entry, preserving the HTTP response and warnings.
- **Deferred issuance activity.** Log deferred endpoint requests and responses with their HTTP status and body, including pending replies and errors. Encrypted exchanges retain the wire value and plaintext.
- **Conformance activity exports.** Save request and response payloads using the activity API view, including encrypted wire values and plaintext.
- **Activity automation.** Activity entries and controls have stable `data-testid` selectors. Decoder links identify each presentation query and token index or each credential response index.
- **HTTPS setting label.** The Conformance panel uses "Follow validation mode" for the default certificate verification setting.

## [2.5.0] - 2026-10-02

### Added

- **HTTPS certificate settings.** Strict mode verifies server certificates by default. Debug mode skips verification. `--tls-verify=true|false` overrides either mode for every HTTPS destination. `--tls-ca` adds trusted CA certificates. Verification can also be changed in the Conformance panel or API.

### Fixed

- **EUDI signing roles.** Use separate keys and certificates for PID credentials, wallet attestations, access signatures, registrar responses, credential status and trust lists. Provider certificates include the relevant identity, purpose and policy identifiers. PID certificate countries follow the credential's `issuing_country`.
- **Signing certificate storage.** Keep certificates stable across requests and retain them across restarts with file or PostgreSQL storage. Memory storage retains them for the lifetime of the store. Changed certificate details and renewal receive unique serial numbers.
- **PID certificate references.** Include protected certificate URLs and SHA-256 fingerprints in issued PID signatures. SD-JWT certificate URLs return PEM, and mdoc URLs return DER. Published URLs contain the certificate fingerprint and remain available after renewal. The protected SD-JWT `iat` records actual signing time independently of a rounded credential issuance time.
- **Issuer discovery.** Wallet and demo issuer metadata use an access certificate for signing. Discovery returns JSON by default and signed metadata when the request accepts only `application/jwt`. Mdoc metadata advertises the COSE algorithm `-7`.
- **Registration certificates.** Include registrar-signed registration certificates in issuer metadata and demo presentation requests. The registered identifier, legal name and country match the access certificate. Registrar links point to the actual API endpoint. The existing registrar dataset remains available for compatibility.
- **Trust lists.** Publish credential signing certificates, provider CAs and status signing certificates, with a separate list operator signer. Include required addresses, English text, certificate fingerprints and signing timestamps. An unchanged list keeps the same signed instance until it expires. Changed content or expiry advances the sequence number, and previous instances remain available through `/history`.
- **Credential descriptions.** Keep an open description visible when the credential list refreshes.
- **Mdoc date encoding.** Encode recognized date attributes according to their namespace and name, including nested driving privilege dates. Preserve text claims such as German `raw_eid_birth_date`, even when their values resemble dates.
- **Credential offer links.** Support the EUDI `eu-eaa-offer://` scheme in the parser, CLI, web UI and macOS URL handler, and use it for demo offers. Help and documentation list all supported offer schemes. Existing offer schemes remain accepted.
- **Concurrent file writes.** Coordinate conditional writes across processes so servers retain the same generated keys and certificates.
- **Wallet HTTPS requests.** Strict mode verifies certificates for local endpoints and redirect destinations. Fixes [#21](https://github.com/dominikschlosser/eudi-dev/issues/21). Thanks to [Egor Khaklin](https://github.com/EgorKhaklin) for the report.
- **Wallet activity logs.** Show actual requests and responses. Encrypted exchanges are marked and also show plaintext. Useful summaries are expandable, and duplicate fields are removed from the web view. CLI output is unchanged.

### Changed

- **Generated certificate chains.** New wallets use a root CA, provider intermediate CA and credential signing certificate. Certificates advertise CA and CRL retrieval URLs. Existing stored direct CA chains remain supported. The intermediate hierarchy exercises the EUDI certificate profile and produces an advisory ISO IACA path length warning. See [test certificates](docs/test-certificates.md) for the applicable specification versions and test limits.
- **Documentation.** Simplified public demo hosting, wallet guides and integration examples. Corrected stale reset and conformance descriptions.
- **UI text.** Shortened descriptive text in wallet and decoder popups.

## [2.4.4] - 2026-09-28

### Fixed

- **Decoding of arbitrary JWTs** Fixed a bug that caused the decoder to sometimes not detect arbitrary JWTs correctly and instead showed an error.

## [2.4.3] - 2026-09-23

### Added

- **ShellCheck clean scripts.** The conformance scripts pass ShellCheck, and `.shellcheckrc` holds its settings. Thanks to [Jan Mederer](https://github.com/jmederer) for the contribution (#20).
- **OpenID certification in the README.** Added the official certification mark and the certified OpenID4VP 1.0 and OpenID4VCI 1.0 wallet profiles with HAIP 1.0 for eudi-dev v2.3.7.
- **The demo issuer offers every credential template the wallet knows** beside its ticket, selectable on the issuer page and by `?credential=<id>` on `POST /api/offers`, so it can stand in as the PID provider of a wallet under test.

### Fixed

- **Go installation for v2 releases.** The module and package imports now use `github.com/dominikschlosser/eudi-dev/v2`, so new v2 tags can be installed with `go install github.com/dominikschlosser/eudi-dev/v2@latest`. Updated install examples and build version injection. Existing tags retain their original module path. Fixes [#19](https://github.com/dominikschlosser/eudi-dev/issues/19). Thanks to [Tobias Wich](https://github.com/sake) for the report.
- **Status list signing and conformance screenshots.** Includes the certificate and screenshot fixes from 2.3.7-2 and 2.3.7-1.
- **Security contact links.** The `security.txt` contact and policy URLs point to the GitHub repository without the Go module's `/v2` suffix.
- **Conformance screenshot retries.** Monitoring stops when a module finishes or is interrupted, even if its screenshot could not be captured or uploaded.

## [2.4.2] - 2026-09-13

### Fixed

- **Wallet loading states.** Credentials and activity show centered loading spinners while their initial requests are pending, preventing empty messages from flashing on slow networks. Failed requests show a Retry button, and background refreshes keep existing content visible. Named loading statuses and existing selectors support third-party Playwright tests.

## [2.4.0] - 2026-09-06

### Added

- **Storage backends.** Store wallet state in files, memory or Postgres using `--storage` or `EUDI_DEV_STORAGE`. Files remain the CLI default. `wallet info` and `GET /api/config` report the backend. The [load test example](examples/load-test/README.md) shares Postgres between two servers.
- **Seeded keys.** `--seed` and `EUDI_DEV_SEED` derive generated keys from a string, preserving the wallet identity across fresh starts without saved state. An empty value generates random keys. The config API reports `seeded_keys`.
- **Conformance activity logs.** Each plan exports its wallet log to `results/<plan>-wallet-activity.json` before clearing it. This preserves the request and response evidence required for VCI certification before the wallet's log cap removes entries.
- **Key attestation test levels.** `--key-attestation-level` selects the storage and user authentication levels claimed in attestations. The default follows issuer requirements. `none` omits them. These are test claims, as described in [SECURITY.md](SECURITY.md). Local wallets can change the setting through the Conformance panel or API. Demo wallets display it without allowing changes.

### Changed

- **The Docker image keeps its state in memory and derives its keys from the public seed `eudi-dev`.** It needs no volume and runs on a read-only filesystem. A deployment that mounts a volume sets `EUDI_DEV_STORAGE=file` and `EUDI_DEV_SEED=`, as the public-demo and Keycloak examples do.
- The `[DCQL]` log lists matched credentials. When no credential matches, it groups rejected candidates by reason.

## [2.3.7-2] - 2026-09-19

### Fixed

- **Status list CWT certificate verification.** The demo issuer includes its certificate chain in the protected COSE header and uses a status list signing certificate without the document signer's critical extended key usage.

## [2.3.7-1] - 2026-09-18

### Fixed

- **Conformance screenshots show the current test's error.** The wallet harness processes each request before capturing its rejection and retries failed captures and uploads. This prevents the invalid-client-id-prefix test from receiving the preceding missing-nonce test's screenshot. Wallet protocol behavior is unchanged from 2.3.7.

## [2.3.7] - 2026-09-04

### Added

- **Attestation proofs.** The wallet supports `proofs.attestation` with the issuer nonce and every batch key in one attestation (OpenID4VCI Appendix F.3). It selects this when it is the only offered proof type or when JWT proofs require key attestation. The mdoc conformance plans use this configuration, allowing their batch checks to pass.
- **Wallet initiated HAIP plans.** The harness now runs all six VCI HAIP scenarios. For wallet initiated modules, it supplies an offer for the suite's issuer without `issuer_state`.
- **Proof algorithm checks.** The wallet checks whether the chosen proof type permits ES256, including key attestations (Appendix F.1 and F.3). Strict mode rejects unsupported configurations. Debug mode warns. HAIP findings cite its ES256 requirement in §7.

## [2.3.6] - 2026-09-03

### Changed

- **Single encryption algorithm advisory.** A verifier offering only A128GCM or A256GCM now receives a warning in every mode, and the wallet uses that algorithm. Offering neither still fails in strict mode. HAIP requires verifiers to list both, but one is enough to encrypt the response.

## [2.3.5] - 2026-09-03

### Fixed

- **One proof for an attested batch.** A required key attestation lists every batch key inside one JWT proof (OpenID4VCI Appendix F.1). This works with Credo issuers. The OIDF suite issues only for the JWT proof key in this configuration, so its mdoc batch module skips.

## [2.3.4] - 2026-09-03

### Fixed

- **Batch proofs with key attestation.** This release sent one JWT proof per batch copy, each carrying the shared key attestation. This replaced the single-proof behavior from 1.19.20 and made the OIDF mdoc batch module pass. Release 2.3.5 revised this approach for issuer interoperability.

## [2.3.3] - 2026-09-03

### Added

- **`robots.txt`, `security.txt` and page descriptions.** The wallet server answers `/robots.txt` (pages allowed, the API and the protocol endpoints excluded) and `/.well-known/security.txt` (RFC 9116, contact and policy of the project). The wallet, decoder, demo issuer and demo verifier pages carry a meta description.

## [2.3.2] - 2026-09-02

### Changed

- **Documentation review.** Updated guides, ADRs, diagrams, comments and CLI help. Corrections include PID claims, templates, supported authentication methods, registered URI schemes and missing API fields.
- **Updated specification references.** SD-JWT VC citations now use draft-19 section numbers. ABCA errors and metadata cite their defining sections, §7.4 and §8.

## [2.3.1] - 2026-09-02

### Changed

- **PID rulebook links.** PID template descriptions link to the EUDI Rulebook 1.7 or German Rulebook 1.0.0. The UI makes description URLs clickable. The description limit increased from 300 to 500 characters.

### Fixed

- **Deployment volume warnings.** Preview and strict wallet volumes are declared external because the deployment script creates and assigns them before compose starts.

## [2.3.0] - 2026-09-02

### Added

- **Strict conformance host.** `deploy.sh strict <tag>` deploys a separate HAIP wallet with strict validation and auto-accept. `STRICT_TAG` pins its release. Public traffic is limited to GET and HEAD, including authorization requests. The harness uses an SSH tunnel and `OIDF_WALLET_URL` for management operations.
- **Hosted certification runs.** `OIDF_WALLET_BASE_URL` supplies the public origin needed for hosted status checks. Runner TLS trust retains system roots when adding the wallet CA. A cleanup script removes owned hosted plans. See the [runbook](docs/conformance-run.md).
- **Expanded conformance matrix.** VP Final covers 36 supported format, response and request combinations. VCI Final covers 32 grant, offer, issuance and encryption combinations. VCI HAIP also covers offers by reference. See [the matrix](docs/conformance.md).
- **Certificate revocation list.** `GET /api/crl` serves an empty DER CRL signed by the wallet CA. Generated document signer certificates reference it. Credential revocation continues to use status lists.

### Changed

- **ISO certificate profiles.** Generated CA and document signer certificates follow ISO/IEC 18013-5 Annex B, including country, key identifiers, extensions and CRL references. The suite's profile checks pass without warnings. Existing stores retain their previous CA until it is regenerated.
- **Derived response URI.** A `redirect_uri:` client identifier now supplies an omitted `response_uri`, as OID4VP §5.9.3 permits. Previously these requests failed.
- **Literal plus signs in request URLs.** URI queries now follow RFC 3986, preserving `+` in values such as `dc+sd-jwt`. Generated URLs encode spaces as `%20`. POST form bodies retain form encoding.

### Fixed

- **German PID Rulebook 1.0.0.** Updated the German claim set, including `academic_title` and `raw_eid_birth_date`. Removed obsolete fields. `birth_name` remains because it can contain both given and family names at birth.
- **EUDI PID Rulebook 1.7.** Default PIDs now include a placeholder portrait. SD-JWT uses a JPEG data URL in `picture`, and mdoc uses JPEG bytes in `portrait`. `address.street_address` now includes the house number.

## [2.2.0] - 2026-09-01

### Added

- **Demo conformance harness.** The issuer and verifier are tested with the OIDF suite acting as the wallet. The harness drives offers, login, presentations and screenshot uploads. It also checks the demo verifier's own verdict, which the suite cannot observe. See [the runbook](docs/conformance-run-demorp.md).
- **Local HTTPS base URL.** `wallet serve --serve-tls` serves an HTTPS base URL using the wallet certificate. The URL must include a port. This supports suite tests that require HTTPS endpoints.
- **Additional verifier trust anchors.** Repeatable `--demo-verifier-trust-anchor` files add CAs alongside the wallet CA, allowing the demo verifier to accept externally issued test credentials.

- **Custom issuance signing material.** `issue --key <key> --cert <chain>` and the issue API accept a supplied key and certificate chain, locally or remotely. Debug mode warns if the chain includes its root. Strict mode rejects it. Demo mode rejects custom signing material.
- **Undefined parameter warnings.** Unknown OID4VP request parameters and unexpected response fields now produce warnings. RFC 6749 requires ignoring unrecognized parameters, so strict mode also continues.

### Changed

- **Clearer CLI help.** Issuance help distinguishes stdout output from `--wallet` storage and identifies flags that require a wallet.
- **Consistent finding citations.** Findings begin with their specification and rule. Grouped messages name their sources, and HAIP no longer duplicates checks inherited from other specifications.
- **Separate instance commands.** Use `wallet ps`, `wallet use` and `wallet kill` to list, select and stop instances. The former `wallet instances` commands remain hidden aliases.

### Fixed

- **Optional DPoP at PAR.** The demo issuer accepts PAR without a DPoP proof, as RFC 9449 permits. Supplied proofs are still verified, and authorization code token requests still require DPoP.
- **Authenticated token requests without client_id.** The demo issuer uses the client's attestation subject when `client_id` is omitted, following RFC 6749 §4.1.3.
- **Key Binding JWT age check.** The demo verifier rejects proofs outside the accepted creation window, as RFC 9901 §7.3 requires.
- **Recommended TLS 1.2 ciphers.** The wallet listener now offers only the applicable suites recommended by RFC 9325.
- **Rounded ticket timestamps.** Demo ticket issuance times are rounded to the hour to reduce correlation through precise timestamps, including across batch copies.
- **CI wallet logs.** Demo test output is saved under `e2e/test-results/` and uploaded on failure.

## [2.1.2] - 2026-08-31

### Changed

- **Transitional SD-JWT typ.** Debug import accepts `vc+sd-jwt` with a warning. Strict mode rejects it, and the decoder flags the deviation from the required `dc+sd-jwt` value.

### Fixed

- **HTTP connection reuse.** Shared clients now reuse connections for request objects, status lists and presentation responses. This avoids opening a new connection for every fetch and exhausting local ports during bursts.

## [2.1.1] - 2026-08-30

### Fixed

- **Complete warning sentences.** Findings displayed on their own now start with a capital letter.

## [2.1.0] - 2026-08-30

### Added

- **Custom verifier requests.** The demo verifier can build DCQL queries with chosen formats, types and claim paths. It also accepts a client identifier scheme, optional signing key and verifier information.
- **Untrusted issuer testing.** Debug mode offers credentials that fail `trusted_authorities`, with a consent warning. Matching credentials remain preferred. Strict mode offers only matches.
- **Registration certificate checks.** The wallet warns about missing certificates, missing ETSI fields, invalid validity periods and requests for unregistered attributes. These ARF checks remain warnings in every mode. The demo services now supply complete registration certificates.

### Changed

- **Grouped findings.** Multiple violations now produce one activity log entry with a count and expandable details.
- **Encryption metadata.** The wallet always advertises a request encryption key and response encryption algorithms. `--require-encrypted-request` makes use of the key mandatory. Request signing algorithms are advertised only for prefixes that permit signed requests.
- **Malformed credential handling.** Debug mode retains recoverable credentials and warns about deviations. Strict mode rejects them. Unsupported status mechanisms are reported under HAIP.

### Fixed

- **Recoverable decode errors.** The decoder displays usable credential content alongside deviations instead of returning a blank page for recoverable SD-JWT or mdoc errors.
- **Unsupported status warnings.** Status mechanisms such as W3C StatusList2021 are now reported explicitly instead of appearing absent. HAIP validation also flags them.
- **JWT VC type labels.** Listings display the credential type from the W3C VC type array in `vc` or the payload root. `jwt_vc_json` identifies the format.
- **Required wallet metadata.** Request URI POSTs now include `response_types_supported` and explicit response modes. This prevents verifiers from applying RFC 8414 defaults that do not describe the wallet.
- **Array disclosure selection.** Requesting an array alone no longer discloses its selectively disclosed elements. Verifiers must select elements with `null` or an index. The wallet warns when a request produces an empty array.
- **Accurate consent previews.** Consent shows empty arrays and missing claims as they will be presented. Complete matches are preferred. Debug mode permits partial matches with notes, while strict mode requires all claims.

## [2.0.7] - 2026-08-27

### Fixed

- **Nonce diagnostics.** Both issuance flows record nonce requests and responses. Strict mode rejects a missing nonce from an advertised endpoint. Debug mode warns and can retry GET after a POST returns 405.

## [2.0.6] - 2026-08-27

### Added

- **Client authentication debug panel.** The demo login page shows the wallet's PAR client ID and attestation headers, or indicates that authentication was omitted.

### Fixed

- **Authorization response warnings.** Debug mode now reports invalid `iss` and `state` values. Strict mode rejects them. Missing `iss` is a deviation only when the server advertises support.
- **Missing access token error.** Pre-authorized issuance now fails immediately when the token response omits the required `access_token`.
- **Response destination checks.** `x509_san_dns` requests now require the response host to match the client identifier. Debug mode warns about mismatches and strict mode rejects them (OID4VP §5.9.1).

- **HAIP validation for all formats.** `validate --haip` now checks mdoc and JWT credentials as well as SD-JWT.
- **Required endpoint checks.** Strict mode rejects missing or empty token and credential endpoints. Debug mode warns before trying conventional endpoint paths.
- **Deferred poller race.** Holder key reads now use the locked accessor during concurrent store reloads.
- **Token type checks.** Missing or unsupported `token_type` values fail in strict mode. Debug mode warns and assumes DPoP when a proof was sent, otherwise Bearer.
- **Correct SD hash algorithm.** Presentation and verification use the credential's `_sd_alg` for the Key Binding JWT `sd_hash`, including SHA-384 and SHA-512.
- **SD-JWT type warnings.** The demo verifier warns when the issuer JWT omits the expected typ or uses another value.
- **Trailing separator warning.** The parser reports a missing final SD-JWT tilde while retaining recoverable content.
- **Missing digest algorithm warning.** mdoc verification reports an absent MSO `digestAlgorithm` even when digest checks can use SHA-256.
- **Unknown mdoc validity.** The demo verifier reports that validity cannot be checked when the MSO omits its validity period.
- **Preserved transcript encoding.** mdoc verification uses the original session transcript bytes instead of decoding and re-encoding them, which could change the signed value.
- **Self-signed leaf detection.** HAIP checks now detect self-signed end entity certificates without rejecting them early as non-CA certificates.
- **Correct mdoc element selection.** Presentations use each parsed element's original bytes. Skipped or duplicate elements can no longer shift selection to another raw array entry.
- **Nested disclosures under cleartext parents.** The wallet now finds requested disclosures such as `address.street_address` even when the parent object is directly in the signed payload.
- **Atomic mutation and save within the server.** Imports, deletions and status changes hold the store lock through saving. Concurrent reloads can no longer discard those changes.

- **Hidden logo description.** The demo issue form hides logo alt text when visitor-supplied logos are disabled.
- **Issuer logo in offer consent.** The wallet fetches and embeds the issuer logo using the same address restrictions as card images. Offer logos remain embedded with `--adhoc-display-images` because they are shown only at consent.
- **Issuer PID trust requirement.** Presentation requests during demo issuance now name the accepted CA through `aki` trusted authorities, allowing the wallet to select an acceptable PID before submission.

## [2.0.5] - 2026-08-26

### Fixed

- **External wallet sign-in redirect.** The demo login page permits the request's redirect target in its form CSP. This fixes browser redirects to other origins and custom wallet schemes after sign-in.
- **Client identity in key proofs.** JWT proofs include `iss` when the access token belongs to an identified client. Anonymous pre-authorized flows still omit it. Thanks to [Massimiliano Perrone](https://github.com/massx1) for the report (#13).
- **Offer claim wrapping.** Claim names use the full preview row and long paths wrap at dots.
- **iOS card flip.** The front face now has a 3D transform so WebKit hides its backface during the flip.

## [2.0.4] - 2026-08-25

### Added

- **Images on demand.** `--adhoc-display-images` preserves HTTPS image URLs for browser fetching. Data URIs, template images and HTTP images are still stored. The config API reports the setting. Issuers can observe repeated browser image requests.

### Changed

- **Separate display assets.** Card images move from `wallet.json` into content-addressed files under `assets/`. Identical images share a file. Existing embedded images move on save, and demo resets prune unused assets.

## [2.0.3] - 2026-08-25

### Fixed

- **Faster unchanged reloads.** The file backend skips reparsing unchanged wallet files. Periodic forced reloads still detect writes hidden by coarse modification timestamps.
- **Smaller credential listings.** Overview responses omit raw credentials and claim values, and reference display images by cached URLs. Detail endpoints retain the complete credential.
- **Deferred display recovery.** Collection retries resolving display metadata when the offer provided none.
- **iOS card clipping.** Moving overflow clipping to the card art lets WebKit honor backface visibility during flips.

## [2.0.2] - 2026-08-25

### Fixed

- **RSA response encryption.** The wallet supports RSA-OAEP when the verifier supplies an RSA key and prefers ECDH-ES when both are available. HAIP still flags RSA. Keys marked only for signing produce warnings in debug mode and fail in strict mode.
- **Deferred state survives reloads.** The poller now manages deferred issuances in memory and persists changes. Request reloads no longer erase pending collections.
- **Partial batches retain their keys.** The wallet accepts fewer credentials than requested and stores each returned copy's binding key, including batches without a copy bound to the main holder key.
- **Issuance failure logging.** Errors after the credential response, including import and deferred processing failures, now appear in the activity log.
- **Stable card perspective.** Card flips retain their perspective throughout the animation.

## [2.0.1] - 2026-08-25

### Fixed

- **Single credential batch responses.** The wallet accepts a single credential from a batch request, as OpenID4VCI permits.

## [2.0.0] - 2026-08-24

### Summary

Version 2.0.0 updates credential cards to use issuer names, descriptions, logos and colors. Consent dialogs show the same cards. The wallet supports batch issuance, rotation between credential copies, deferred issuance and credentials without holder binding. Cards have short hexadecimal IDs, activity appears in a collapsible drawer, and descriptions open through an About control. The country independent PID uses the EUDI PID Rulebook's Jan Wijnand example.

### Added

- **Issuer display on cards.** Cards use the issuer's first display entry for name, description, logo, colors and background. Layout adapts to the available width. Compact consent cards prioritize the ID, issuance time and type.
- **Bounded image fetching.** Issuance fetches images once through the restricted HTTP client. Downloads are capped at 4 MB and 32 megapixels, with cached images limited to 256 KB. Invalid colors, low contrast and rejected images produce warnings without failing issuance.
- **Credential facts on cards.** Cards show validity, status, holder binding, issuer, user claim count and issuance time. Signature checks describe consistency with supplied keys and do not establish issuer trust.
- **Shared consent cards.** Presentation and offer dialogs use the same card design. They identify the requester and show signature status. Claim controls allow withholding requested fields.
- **Styled demo credentials.** The issuer, ticket and default PIDs use eudi-dev branding. The German PID uses its own name and public specimen artwork.

- **Batch rotation.** The wallet stores each batch copy with its own holder key and status index. It randomly selects among the least used copies and reuses them after a complete cycle. Listings show one credential, and deletion or revocation applies to every copy. `--batch N` also creates local batches.
- **Demo batch and deferred issuance.** Offers can request up to five copies or defer collection. Deferred responses provide a transaction ID and the wallet displays a pending card until collection succeeds.
- **Template display metadata.** Templates supply card text, colors and bundled images. Explicit form values override their defaults without removing template artwork.
- **Unbound test credentials.** `--unbound` creates bearer SD-JWT credentials or deliberately invalid mdocs without a device key. The default retains holder binding. Unbound credentials cannot form a batch.
- **Custom credential display.** CLI flags and the issue form set card text, colors and images. Images use the same restricted fetch and size limits as issuer metadata. Demo mode allows template artwork but rejects visitor-supplied images.
- **Credential descriptions.** About opens a bounded description panel on desktop or flips the card on phones. Credentials without descriptions omit the control.
- **Display limits.** Text fields and image sizes are capped when read from issuers, forms and templates.

### Changed

- **Rulebook example identity.** EUDI PID templates now use Jan Wijnand ('t Hart) from the rulebook example. German PID templates retain Erika Mustermann.
- **Display metadata in CLI output.** `wallet list` includes NAME, and `wallet show -v` includes the description.
- **Short credential IDs.** New IDs use hexadecimal strings. Commands and decoder links accept unambiguous prefixes. Exact matches take precedence and ambiguous prefixes fail.
- **Separate activity drawer.** Credentials use the main scroll area. The activity log has a collapsible drawer with its own scroll and saved visibility preference. Scrollbars follow the theme.
- **Updated Go APIs.** Key encoding uses the Go 1.26 ECDSA byte APIs with unchanged output and curve validation. The reverse proxy uses `Rewrite` instead of deprecated `Director`.

### Fixed

- **Consent resolution across tabs.** Approving, denying or expiring a request closes its dialog in every open tab.

## [1.26.2] - 2026-08-22

### Fixed

- **Phone layouts.** Credential actions wrap below content and badges stay intact at narrow widths. Checked down to 320px. [ADR-0015](docs/adr/0015-the-web-ui-lays-out-at-phone-width.md) records the layout requirement.

- **Authorization server fallback.** When the selected server explicitly excludes the grant, debug mode tries other advertised servers and uses the first that supports it. Strict mode rejects before redeeming the code. Missing grant metadata does not trigger this fallback.

## [1.26.1] - 2026-08-22

### Fixed

- **Immediate offline decoding.** The decoder displays locally available checks before fetching status or issuer metadata. The validation API accepts `offline` and marks unresolved checks with `needsNetwork`.
- **Single decode per paste.** Paste and input events no longer schedule duplicate requests.
- **Bounded claim display.** Long values show a 300-character preview with expansion. Image claims show thumbnails instead of stretching the page.
- **Draft-07 attestation compatibility.** Outgoing attestations again include the combined claim set accepted by all supported drafts, fixing issuer rejection under version 1.1. See [ADR-0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md).

## [1.26.0] - 2026-08-21

### Added

- **ABCA draft support.** Added draft-07, draft-08 and draft-10 support. This release selected outgoing claims by the configured OpenID4VCI version and retained that draft for refresh. Release 1.26.1 revised the outgoing claim policy. See [ADR-0014](docs/adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md).
- **Combined DPoP possession proof.** Servers advertising the draft-10 combined method receive the wallet attestation with DPoP and no separate attestation PoP header.
- **Attestation challenge headers.** The wallet handles response header challenges and retries once for `use_attestation_challenge` or `use_fresh_attestation`.
- **Demo attestation compatibility.** The issuer accepts valid claims from every supported draft and warns when they differ from the configured draft. Optional authentication also advertises the `none` possession method.

### Fixed

- **Authenticated pre-authorized redemption.** The demo token endpoint applies client authentication to pre-authorized grants and binds tokens to supplied DPoP keys.
- **Public confirmation keys.** Attestation `cnf.jwk` and DPoP `jwk` headers reject private key material.
- **One redemption per code.** Demo pre-authorized codes now bind to the first redeeming client. Reuse fails with `invalid_grant`.
- **Attestation header validation.** Requests with repeated attestation or PoP headers are rejected. JWT algorithms are checked against the advertised list.

## [1.25.5] - 2026-08-21

### Fixed

- **Clear holder binding badge.** The badge now reads **Wrong holder binding**, distinguishing an unavailable binding key from an unbound credential.

## [1.25.4] - 2026-08-21

### Added

- **Binding checks before presentation.** Strict mode stops when the wallet cannot sign with the credential's holder key. Debug mode sends the presentation with a warning for verifier testing.
- **Unresolved request signatures.** Requests whose signing keys cannot be resolved are reported as unverified. Multisigned DC API requests prefer signatures that actually verify.
- **DID key diagnostics.** Imports, validation and status checks explicitly report unresolved DID keys. See [ADR-0013](docs/adr/0013-only-the-eudi-stack-is-supported.md).
- **Holder binding warnings on import.** Credentials bound to unavailable keys receive CLI and log warnings, a card badge and `key_binding_not_held` in their summary. The log includes both key thumbprints.

### Fixed

- **Useful token errors.** Responses outside the OAuth error format can supply a reason through `message`, as a string or list. The full response remains in log details.

## [1.25.3] - 2026-08-20

### Fixed

- **One browser navigation per flow.** When the wallet UI owns a flow, CLI commands leave sign-in and verifier redirects to that tab. This prevents duplicate use of authorization requests.
- **Stable JWK test fixture.** The ECDSA test pads coordinates to the required width, fixing intermittent failures for keys with leading zero bytes.
- **Correct DPoP target URI.** `htu` omits both query and fragment, as RFC 9449 §4.2 requires.
- **Notification failures preserve credentials.** A rejected optional notification now produces a warning instead of discarding an issued credential. Details retain the endpoint's full response.
- **Offer resolution belongs to the wallet flow.** Scan and accept commands no longer fetch an offer before forwarding it. Local prompting preserves the fetched offer for issuers that serve it once. Missing required transaction codes fail before redemption. See [ADR-0012](docs/adr/0012-every-entry-point-runs-the-same-flow.md).

## [1.25.2] - 2026-08-20

### Added

- **Grant compatibility checks.** The wallet checks advertised grant support before redeeming an offer. Strict mode rejects an explicit mismatch and debug mode warns. Omitted grant metadata remains acceptable.

### Fixed

- **Correct HAIP certificate rules.** Removed the obsolete requirement for issuer SAN matching. Checks now enforce the supplied chain, exclusion of its trust anchor and a signing leaf that is not self-signed.
- **Browser consent ownership.** Sessions associate consent, errors and sign-in prompts with the browser that started the flow. Requests without owners remain shared for older clients. Timeouts are reported as expired. Session IDs do not authenticate users. See [ADR-0011](docs/adr/0011-a-flow-belongs-to-the-browser-that-started-it.md).
- **Complete refusal details.** Token, PAR and challenge failures preserve the HTTP status and response body in activity log details.
- **Long consent waits.** Response deadlines now cover all consent waits, including a presentation during issuance. Late approval no longer writes to a closed connection or triggers duplicate dispatch.
- **Recognizable consent candidates.** Selection rows use credential cards with status, expiry, protection and namespace details, plus a Decode link.

## [1.25.1] - 2026-08-19

### Fixed

- **One use of pushed requests.** The demo issuer rejects repeated authorization requests for the same `request_uri` while allowing its login form to complete the original request.
- **Browser owns authorization navigation.** The wallet no longer fetches a pushed authorization URL before opening it in the browser, preventing premature consumption.
- **Short offer warnings.** A failed second offer fetch keeps the response body in details instead of the log headline.

## [1.25.0] - 2026-08-18

### Added

- **Remote proxy logs.** `eudi proxy logs [dashboard-url]` prints captured traffic. `--follow` reconnects and reloads entries recorded while disconnected.
- **PID with optional ticket.** Demo requests can offer combined PID and ticket selection or a separate optional ticket set. Verdicts include ticket claims when supplied.

- **Credential selection in consent** (#8). Edit lets users choose set options and credentials. Approval sends `picks` and `set_choices`. Invalid choices return 400 without consuming consent. Auto-accept keeps the automatic selection.

## [1.24.3] - 2026-08-18

### Fixed

- **Authentication in token logs.** Token request details now indicate client attestation and DPoP headers.
- **Ticket signing profile.** Demo tickets use the local profile's certificate and registration metadata instead of the PID provider profile.
- **Stable approved offer.** If an offer changes after consent, issuance uses the approved issuer and credentials and logs the new response.
- **Offers served once.** Approval falls back to the offer cached for consent when the issuer rejects a second fetch.
- **Long-lived event streams.** Proxy and wallet streams avoid the normal response timeout. Proxy keepalives prevent idle disconnects, and reconnecting dashboards reload missed traffic.
- **Newest proxy traffic first.** Both the entry list and flow timeline show recent traffic first.
- **Shared mdoc response nonce.** All documents in an ISO presentation use the one generated nonce carried by the encrypted response.
- **Concurrent flow isolation.** Transaction codes, selections and consent results stay with their own flows. Registry access is locked and resolved requests are pruned. CA reads are protected during demo resets.
- **Consistent request media type checks.** GET and POST request URI responses both warn in debug mode and fail in strict mode when the JWT media type is incorrect.

## [1.24.2] - 2026-08-17

### Fixed

- **Correct encryption metadata names.** Wallet metadata now uses `request_object_encryption_*_values_supported` for Request Object encryption algorithms.

- **Explicit demo flags take precedence.** `--demo --pid=false` disables baseline generation. Template overrides determine the baseline used at startup and reset.

## [1.24.1] - 2026-08-17

### Added

- **Renovate.** Renovate opens pull requests for dependency updates. Thanks to [Jan-Otto Kröpke](https://github.com/jkroepke) for the contribution (#11).
- **Registered purpose in consent.** The wallet reads registration certificate purposes from `verifier_info`, preferring English. It verifies the signature against the included leaf without establishing trust in the signer.
- **Auto-accept control.** Local wallet headers show and change the runtime setting. Demo mode displays its fixed value.
- **Demo registration certificates.** Issuer and verifier presentation requests include certificates naming their purpose.

### Fixed

- **Ordered saves.** Store-level serialization prevents an older snapshot from overwriting a newer import.
- **Default callback origin.** Wallets without `--base-url` use their serving origin to recognize browser callbacks.
- **Docker demo documentation.** The guide includes the demo profile and links to the complete deployment example.
- **Conformance baseline documentation.** Updated the runbook to match the recorded `release-v5.2.2` results.
- **Stored interactive sessions.** The demo issuer retains `auth_session` returned by web authorization so the wallet can continue the challenge flow.
- **Bounded challenge requests.** The challenge endpoint now applies the same 500-entry limit as PAR and returns 429 when full.
- **Verified purpose display.** Registration certificates without a readable x5c produce a warning and contribute no purpose.
- **Purpose in unsigned requests.** Plain parameters can supply `verifier_info`. Signed requests continue to use only their Request Object.
- **Consistent signing material.** Keys and certificate chains are read together under one lock so resets cannot produce mismatched pairs.
- **Renewal survives reloads.** Saving restores the renewed credential and rotated refresh token under the reload lock.

## [1.24.0] - 2026-08-17

### Added

- **Browser interaction during issuance.** Version 1.1 supports `auth_via_web` when a redirect URI and authorization endpoint are available. The browser callback returns an authorization code or continues the challenge using `auth_session`. The demo issuer supports this interaction.

### Fixed

- **Restored local status entries.** Issuance saving re-adopts status entries removed by concurrent reloads, so demo tickets remain revocable.

### Changed

- **Plainer documentation.** Shortened the README and guides without changing commands or behavior.
- **Clear verifier trust label.** The checklist now says the issuer chains to a trusted CA, avoiding confusion with holder identity.
- **Challenge authentication documented.** Docs and tests now cover wallet attestation at the Authorization Challenge Endpoint.

## [1.23.2] - 2026-08-16

### Fixed

- **Consent during issuance.** Approving an offer also allows its browser to receive the presentation consent requested later in that flow.
- **Issuance presentation ownership.** The new `issuance_presentation` consent type limits the prompt to the browser handling issuance.
- **Named interactive requester.** Unsigned presentation consent uses the challenge endpoint origin when no client ID exists.
- **German PID format selection.** The demo applies the selected format to German PID requests and explains unsupported mdoc combinations.

## [1.23.1] - 2026-08-16

### Fixed

- **Demo authorization choice.** Authorization code offers can request browser sign-in or presentation during issuance. Wallets without interactive authorization still use sign-in.
- **Specification badges.** README badges link to the supported versions in [spec compliance](docs/spec-compliance.md).
- **API consent during issuance.** Programmatic offers no longer wait for an absent user's presentation approval midway through the flow.

### Changed

- **Verifier request toggle.** A credential toggle and one Create request button replace separate request buttons.

## [1.23.0] - 2026-08-16

### Fixed

- **HAIP checks for interactive authorization.** Presentations during issuance use OpenID4VCI's response mode and endpoint binding, so ordinary OID4VP channel checks no longer reject them. Applicable query, format and token rules still run.

### Added

- **OpenID4VCI feature level.** `--vci-version` defaults to 1.0. Version 1.1 enables advertised draft features. Local wallets can change it through the Conformance panel or API, and demo mode defaults to 1.1. See [spec compliance](docs/spec-compliance.md).
- **Interactive Authorization.** A version 1.1 wallet can answer issuer challenges with a separately consented presentation before receiving a code. Presentations bind to the challenge endpoint. This flow does not require a redirect URI.
- **PID before ticket issuance.** The demo challenge endpoint requests and verifies a PID, then issues a ticket naming its holder. Version 1.0 wallets retain the browser sign-in flow.
- **Feature negotiation diagnostics.** When an issuer offers Interactive Authorization, the log explains whether the configured version can use it and notes when the issuer requires it.

## [1.22.2] - 2026-08-15

### Fixed

- **Issuer SANs in signing certificates.** Generated signing leaves include DNS and URI SANs, or IP SANs for address hosts. This fixes interoperability with verifiers requiring the issuer identifier in the certificate.

## [1.22.1] - 2026-08-14

### Changed

- **Quieter namespace dividers.** mdoc namespace labels use ordinary text and a thin rule instead of accent chips.

## [1.22.0] - 2026-08-14

### Added

- **Credential type inheritance.** Domestic PID types can satisfy EUDI PID requests. Other aliases use `aka_vcts`. Matching is directional and does not establish issuer trust. Type Metadata `extends` resolution remains unsupported.
- **German PID templates.** Added German SD-JWT and mdoc templates. They use `urn:eudi:pid:de:1` and a German mdoc namespace under the shared PID doctype.
- **Demo rate limits.** Caddy limits flow endpoints to 120 requests per minute and 2000 per hour, and other requests to 1200 per minute per address. Excess requests receive 429 and `Retry-After`.
- **API usage statistics.** `deploy.sh stats` now includes API calls and separately lists writes.
- **mdoc namespace labels.** Cards group elements by namespace so EUDI and German PIDs can be distinguished despite sharing a doctype.
- **Four default PIDs.** The demo includes EUDI and German PIDs in both formats. Verifier requests can select a domestic SD-JWT type or the shared PID type.

### Fixed

- **No duplicate older mdocs.** Regeneration reads namespaces from the raw credential, allowing it to replace PIDs stored before namespace prefixes were added to claim keys.
- **JWT PID issuance.** `issue jwt --pid` accepts the default PID claim set despite its template's SD-JWT format. Explicitly selected templates still enforce format.
- **Fresh PID dates.** Issuance and expiry dates are computed each time the template is used.

### Changed

- **EUDI PID default claims.** Default templates now follow the EUDI rulebook. German attributes move to the German type. Tests and scripts depending on the old default claims must be updated.

## [1.21.7] - 2026-08-13

### Fixed

- **Prefix-specific x5c checks.** Request signature validation requires x5c only for x509 client identifier prefixes. Other prefixes report their own unresolved key sources.
- **Preserved visitor PIDs on restart.** Baseline refresh removes only protected defaults. Scheduled resets still clear visitor state.
- **Scans follow wallet routing.** Scanned offers and presentation requests now use the configured running or remote wallet, like `wallet accept`. Added `--tx-code` and `--haip` to scan.

## [1.21.6] - 2026-08-12

### Fixed

- **Interactive routed acceptance.** `wallet accept` opens the running wallet's consent UI unless `--auto-accept` is set.

## [1.21.5] - 2026-08-12

### Fixed

- **Simpler Conformance panel.** Shortened explanatory text and made fixed demo settings easier to read.

## [1.21.4] - 2026-08-12

### Fixed

- **Consent for Process.** Pasted requests submitted through the Process button now open consent.
- **Import log entry.** UI imports now appear in the activity log.

## [1.21.3] - 2026-08-12

### Fixed

- **No duplicate warnings.** Presentation API validation leaves warning logging to the shared flow handler.
- **Full log text on hover.** Truncated activity messages expose their complete text in tooltips.

## [1.21.2] - 2026-08-12

### Fixed

- **Attestation without advertised support.** The wallet sends an attestation when authentication metadata is absent and warns. It still respects an explicit unauthenticated-only configuration.

## [1.21.1] - 2026-08-11

### Fixed

- **Consent waits for configuration.** Early events remain in the pending banner until the page knows whether demo ownership rules apply.

## [1.21.0] - 2026-08-11

### Changed

- **Debug validation on the demo.** HAIP violations now produce warnings while flows continue, allowing interoperability testing with nonconforming services.
- **Shared runtime conformance settings.** Local UI or API changes apply to every flow in the wallet process. Demo settings are fixed. Per-request overrides were removed.
- **Warning severity.** Activity entries distinguish specification warnings from successes and failures.

### Removed

- **Removed per-request overrides.** Removed the conformance cookie, override headers, CLI command and per-flow HAIP/mode fields. The conformance harness now changes runtime settings through the API.

## [1.20.4] - 2026-08-11

### Fixed

- **Save through the original wallet.** Profile override clones delegate saving to the server's wallet and reload lock so issued credentials survive concurrent requests.

## [1.20.3] - 2026-08-11

### Fixed

- **Aligned mobile decoder header.** Brand, links and buttons now stack on the same left edge.
- **Homebrew-safe registration.** URL handlers use the stable Homebrew symlink instead of the versioned binary path, so upgrades do not break registered links.
- **Override scope warning.** Demo text now identifies CLI and URL handler flows that do not inherit browser overrides.

## [1.20.2] - 2026-08-11

### Fixed

- **Browser-only override notice.** The demo Conformance panel explains the scope of its browser cookie.
- **Boolean override values.** The former `wallet conformance` command accepts true and false for HAIP and encrypted requests.

## [1.20.1] - 2026-08-10

### Fixed

- **Accurate local configuration text.** The panel explains which wallet settings a local change affects.
- **Mobile header spacing.** The decoder logo no longer overlaps the title.

## [1.20.0] - 2026-08-10

### Added

- **Editable conformance settings.** This release added local runtime settings, browser demo overrides and remote CLI overrides. These were separate settings with explicit precedence. Release 1.21.0 replaced per-request overrides with wallet-wide settings.

### Changed

- **Renamed override headers.** The former override API used `X-Eudi-Dev-*` on all flow endpoints, including encrypted request settings.

## [1.19.22] - 2026-08-07

### Added

- **Optional demo authentication.** `--demo-issuer-client-auth optional` accepts unauthenticated wallets. Supplied attestations are still verified, and tickets record the authentication result. The default remains required.

### Changed

- **Other wallet providers.** Demo issuance accepts valid attestation signatures from unknown providers and records `untrusted`. Tickets distinguish trusted, untrusted and absent attestations.
- **ABCA draft-10 issuer support.** The demo accepts newer claim requirements and combined DPoP proof. Metadata advertises supported methods and algorithms. Invalid supplied attestations return `invalid_client_attestation`.

### Fixed

- **Prefer supported attestation.** The wallet sends an attestation when the server supports it instead of silently choosing unauthenticated access. Unauthenticated-only servers remain usable.
- **Precise certificate findings.** Warnings identify self-signed certificates by position and subject without claiming knowledge of the verifier's configured trust anchor.
- **Configurable remote timeout.** `EUDI_REMOTE_TIMEOUT` accepts a Go duration and defaults to 15 seconds. Invalid values are reported and ignored. The conformance wrapper uses 120 seconds for loaded suite servers.

## [1.19.21] - 2026-08-07

### Fixed

- **Authentication fallback.** This release preferred unauthenticated access when offered alongside attestation, except under HAIP or an explicit override. Release 1.19.22 revised that preference.
- **Unknown authentication methods.** The nonstandard `public` value fails in strict mode. Debug mode warns and treats it as unauthenticated access.
- **Cleared stale failures.** New requests clear previous errors, and incoming errors no longer replace an active consent dialog.

## [1.19.20] - 2026-08-07

### Fixed

- **Single proof with required attestation.** Credential requests use one proof containing the key attestation for the attested keys.
- **Unanchored issuer metadata.** The wallet accepts correctly signed metadata from a signer without a known trust anchor and logs that limitation. It still checks typ, algorithm, subject and signature.
- **Explicit authorization server discovery.** Demo issuer metadata now lists `authorization_servers` and leaves token endpoint configuration to that server's metadata.

## [1.19.19] - 2026-08-07

### Fixed

- **DC API refusal format.** Protocol errors use the Appendix A.4 error object. Requests that fail validation receive an API error without a protocol response.
- **Optional PAR and DPoP.** Ordinary issuance can use direct authorization requests and bearer tokens when the server does not advertise PAR or DPoP. HAIP validation remains separate.
- **Transport retries.** Request objects, referenced offers and trust lists retry when no response arrives. HTTP error responses are not retried.
- **Metadata retries.** Issuer and authorization server metadata retry transport and 5xx failures up to three attempts. Other responses, including 404, are handled immediately.
- **Attested batch requests.** This release enabled batch proofs when configurations required key attestation. Later releases refined the proof structure for compatibility.
- **Consistent issuance notifications.** Both grants and deferred collection send `credential_accepted` when the issuer provides a notification endpoint and ID.

- **Independent HAIP and validation settings.** HAIP selects additional checks. Debug mode reports their findings and strict mode rejects violations.

### Added

- **Deployment rollback.** `deploy.sh rollback` restores the previous release, or a specified tag. It pulls before switching and persists the selection. A later update returns to the latest release.

## [1.19.18] - 2026-08-06

### Fixed

- **Complete DCQL responses.** Queries require all requested credentials unless credential sets allow another option. The wallet no longer sends a partial response when no complete option matches.
- **Exact claim value matching.** DCQL `values` restrictions now compare both JSON type and value. Nonmatching claims make the credential unavailable for that query.
- **DCQL structure checks.** Removed unsupported optional claim and mdoc alias behavior. Query format, metadata and IDs are validated.
- **Verifier refusal responses.** Unsatisfied queries return `access_denied` or `vp_formats_not_supported` through the requested mode. Invalid requests are reported locally without contacting their destination.
- **Correct response encoding.** DC API errors contain only the error code. Fragment responses merge into an existing fragment instead of adding a second #.
- **One page scrollbar.** Restored a single scrolling column after separate credential and log panels made entries too small.

- **Nonce endpoint proofs.** The wallet obtains challenges from the Nonce Endpoint and retries once for `invalid_nonce`. Strict mode rejects the old token response field. Debug mode can use it with a warning.
- **Renewal metadata.** Refresh now fetches issuer metadata for the nonce endpoint, encryption requirements and credential identifier rules.
- **Issuer metadata validation.** Metadata must name the requested issuer. Signed metadata checks typ, asymmetric algorithm, subject, signature and, in this release, a trusted chain. Later releases relaxed anchoring with an explicit warning.
- **Complete demo proof checks.** The issuer validates proof type, algorithm, audience, time and key source, requires a known credential configuration and returns `invalid_nonce` for stale challenges. Legacy proof and response formats were removed.
- **Status list identity and validity.** Status checks now require a valid signature, matching subject, typ and timestamps. Failed checks return errors instead of a usable status.
- **Status index bounds.** Validate indices before multiplication to prevent overflow. Missing indices and invalid widths fail. Status values are reported by their defined names.
- **Accurate published statuses.** Lists select 1, 2, 4 or 8 bits per entry to preserve status values up to 255. Added CWT support, CORS, historical-query rejection and Appendix C vectors.
- **Additional HAIP checks.** Added signature, certificate, response type, format and encryption metadata checks. The demo verifier now advertises both AES algorithms.
- **Correct DC API identity.** Unsigned requests use the platform origin and omit client_id. The wallet discards client_id and expected_origins from these requests and rejects reserved or unsupported prefixes.
- **Findings in every mode.** Debug mode retains and reports validation findings instead of discarding them. Additional checks cover required nonce, query selection, transaction data and expected origins.
- **Strict SD-JWT processing.** Parsing enforces RFC 9901 rejection rules, including duplicate digests, overwritten claims, invalid disclosures and nested `_sd_alg`.
- **Valid generated SD-JWTs.** Empty disclosures omit `_sd` and use one trailing tilde. Protocol claims remain cleartext, reserved names are rejected and digests are sorted.
- **Tenant issuer metadata.** Discovery inserts the well-known path before the issuer path. It validates issuer identity and supports either embedded JWKS or `jwks_uri`.
- **Diagnostic decoding.** Decode displays malformed credentials with their violations while trust decisions continue to use strict processing.
- **Signed parameter precedence.** Request Objects replace outer request parameters instead of merging with them. A mismatched client_id is rejected.

- **Demo nonce endpoint.** The issuer now serves and advertises `/issuer/nonce`, allowing OpenID4VCI 1.0 wallets to obtain proof challenges.
- **Nonce source precedence.** An advertised nonce endpoint takes precedence over the old token response field.

- **One credential per query.** The wallet selects the newest matching credential and shows exactly that selection in consent and logs.
- **DC API origin exception.** `/api/dc-api` permits verifier-origin calls. Other API routes retain the origin guard.

## [1.19.17] - 2026-08-06

### Fixed

- **Optional PAR declaration.** HAIP checks require the endpoint without demanding the optional `require_pushed_authorization_requests` flag.
- **HAIP metadata and request rules.** Omitted PKCE or DPoP metadata no longer fails. Explicit unsupported algorithms still do. Signed presentation requests require x509_hash and delivery by request_uri.

### Changed

- **Separate desktop scroll areas.** Credential and activity panels each scroll on desktop. Phones retain a single page scroll.

## [1.19.16] - 2026-08-06

### Added

- **Newest credentials first.** Listings sort by credential issuance time before pagination. Missing times sort last and equal times retain insertion order.

### Documentation

- **Correct status list references.** Removed the incorrect RFC 9596 citation. The 16-byte list minimum is documented as a wallet choice. The specification requires no such minimum.

## [1.19.15] - 2026-08-06

### Added

- **Wallet and decoder navigation.** Mounted pages link to each other. Standalone decoders omit the wallet link.

### Removed

- **Complete demo traffic logs.** Removed incomplete bearer-secret redaction. Demo logs again record full traffic and must contain only public, disposable test data.

### Documentation

- **Tool comparison.** The README compares local testing, scripting, certification and production SDK use.

## [1.19.14] - 2026-08-06

### Changed

- **Bounded activity history.** Logs keep the latest thousand entries. Demo visitors cannot clear shared logs or errors, and the UI hides those controls.

### Fixed

- **Bounded remote responses.** Status downloads and decompression now have limits, including a 16 MiB decompressed list cap. Other unbounded peer response reads were capped too.
- **Demo log redaction.** This release redacted selected bearer secrets in demo logs. Release 1.19.15 removed the incomplete redaction and documented full logs as public test data.

## [1.19.13] - 2026-08-06

### Changed

- **COSE key parsing.** mdoc device keys are decoded through go-cose from their original CBOR, retaining compatibility with unpadded coordinates.
- **Strict public JWK widths.** Strict mode rejects short EC coordinates. Debug mode pads them with a warning. Locally supplied private keys remain loadable with padding.
- **Shared JWK parser.** Key parsing now uses go-jose through the keys package, retaining the EC and RSA restriction.
- **Shared JWS verification.** Four verifiers now use go-jose through `jws.Verify` with explicit algorithm lists. Local JWE remains because ISO presentations require control over apu and apv.
- **Consistent deferred naming.** Types and stored fields now use deferred issuance. Older `pending_issuances` records remain readable and are saved under the new name.
- **Shared metadata logging.** Issuer and authorization server fetches use one logging helper with unchanged output.
- **Separate serve implementation.** Wallet serve options use a struct and execution moves into `runWalletServe`, reducing the command builder and avoiding variable shadowing.
- **Ignored generated files.** Python caches and Playwright summaries are ignored at any directory depth.

### Documentation

- **Architecture decisions.** Added ADRs for validation, API access, storage, fetch restrictions, reloads, component roles and cryptographic libraries.
- **Domain glossary.** `CONTEXT.md` distinguishes overloaded project terms, including attestations, profiles, renewal and PID.
- **Shorter architecture overview.** Removed stale implementation lists and described flows through component responsibilities with ADR links.
- Agent guidance moved into `AGENTS.md` and `docs/agents/`, recording where issues live and how the domain docs are meant to be read
- Updated the architecture inventory for missing packages and the decoder server.
- Documented deferred issuance, activity log and last error endpoints in the HTTP API reference.

### Fixed

- **Template path restriction.** HTTP template reads accept only names, preventing arbitrary JSON file reads. CLI commands retain explicit file paths.
- **Safe status indices and widths.** Negative indices are rejected on import and ignored during list building. Status resolution validates the supported entry widths.
- **Stable preferred-format sorting.** The comparator checks both operands and preserves order within equally preferred groups.
- **Request size limit.** All wallet servers now enforce the one megabyte request cap previously limited to demo mode.
- **Nil mdoc input.** Verification returns an error instead of panicking on a nil document.
- **Working imprint navigation.** The back link uses the site root instead of a JavaScript URL blocked by CSP.
- **Digest comparison.** mdoc uses `bytes.Equal` so mismatched lengths cannot compare equal or cause an out-of-bounds read.
- **Browser origin guard.** API calls from another site's Origin are rejected, preventing simple cross-origin POSTs from submitting credentials without consent. CLI calls and the wallet UI remain supported.

## [1.19.12] - 2026-08-06

### Fixed

- **Credential ID completion.** Refresh and deferred management commands now complete IDs.
- **Readable OAuth refusals.** Token errors show the code and description instead of a raw JSON body with repeated HTTP status.

## [1.19.11] - 2026-08-06

### Changed

- **Validity display.** Cards and CLI listings show remaining validity. Removed the UI Renew button because background renewal, presentation renewal and `wallet refresh` cover the operation.

### Added

- **Presentation decode links.** Demo verification results link the received presentation to the decoder, including failed presentations.
- **Short decoder links.** A mounted decoder accepts `?id=` and resolves the wallet credential. Sharing retains the original link form.
- **PID format choice.** The demo verifier can request SD-JWT, mdoc or either. Tickets remain SD-JWT only.
- **Revocable demo tickets.** Offers can include a distinct local status index. Import adopts the entry, and the verifier rejects revoked presentations.

### Fixed

- **Authenticated refresh.** Stored renewal context retains the client authentication method. Refresh requests rebuild attestations or assertions and fetch fresh challenges.
- **Consistent local status numbers.** CLI rendering accepts native and JSON numeric values, fixing local status and deferred attempt counts.

### Documentation

- The wallet documentation says where credential validity is reported, and what a refresh token request carries

## [1.19.10] - 2026-08-05

### Changed

- **Shared background scheduler.** Deferred collection and certificate renewal use one loop. Tasks retry failures, stop after five consecutive failures and isolate panics.
- **Local and remote API parity.** Tests compare all fifteen wallet service methods and require coverage when methods are added.

### Added

- **Renew before presentation.** Credentials near expiry are renewed when possible. A renewal failure does not prevent testing the existing credential.
- **Renew button.** This release added a button for credentials with refresh tokens. Release 1.19.11 removed it in favor of automatic renewal and CLI refresh.
- **CLI renewal.** `wallet refresh <id>` renews immediately through either a local store or remote server.
- **Background renewal.** The server renews credentials within a minute of expiry. Failed credentials wait ten minutes before another attempt.
- **Credential renewal.** Refresh keeps the credential ID and replaces rotated refresh tokens. The API rejects renewal when no refresh token exists.
- **Unified expiry field.** Listings expose `expires_at` for JWT and mdoc credentials. Credentials without expiry are not considered expiring.

### Documentation

- Storage documentation now states that keys and issuer tokens are unencrypted.

### Fixed

- **Deferred type in local listings.** The local backend now reports the credential type already available through the API.
- **Deferred token refresh.** Pending collection can renew expired access tokens and retry once after an authorization refusal. Rotated refresh tokens are saved.
- **Stop unrecoverable collection.** Deferred collection no longer retries rejected tokens indefinitely when it cannot refresh them.

## [1.19.9] - 2026-08-05

### Fixed

- **Sign-in error ownership.** The returning browser receives its issuance error, and new flows clear stale failures.
- **Deferred API fields.** `GET /api/deferred` now includes the stored credential format and type.

## [1.19.8] - 2026-08-05

### Fixed

- **Deferred credential labels.** Pending entries use the type from issuer metadata and fall back to the configuration ID only when necessary.

## [1.19.7] - 2026-08-05

### Changed

- **Shared signing and decryption.** Consolidated JWS signing and JWE decryption in their internal packages without changing behavior.
- **Server file organization.** Handlers move into files grouped by responsibility. Server construction, routing and lifecycle remain together.

### Fixed

- **Deferred clone forwarding.** Issuances started on profile override clones now reach the original wallet's background poller.
- **Locked certificate renewal.** CA and chain reads and writes are synchronized during demo resets.
- **Flow-specific errors.** Shared wallet errors reach the initiating browser instead of every tab.

## [1.19.6] - 2026-08-05

### Added

- **Trust list discovery.** `wallet trust-list --list` shows profiles and categories. `--json` returns the index document.

### Fixed

- **Verifier redirect handling.** The CLI prints the response redirect and opens it for interactive desktop use. `--no-open` disables opening.
- **Headless consent links.** Servers without a desktop print the consent URL instead of attempting to open a browser.
- **Remote trust lists.** CLI trust list commands use the active remote wallet and its URLs.

- **Hosted authorization code flows.** Offers needing sign-in return HTTP 202 with an authorization URL and offer ID. The CLI opens the local browser and polls the outcome while the hosted wallet awaits its callback.

### Security

- **Security headers on every UI.** Decoder and proxy pages now use the wallet's CSP, framing restrictions and content type protection.
- Escaped the remaining numeric values inserted into wallet markup.

## [1.19.5] - 2026-08-05

### Added

- **Structured mdoc decoding.** The decoder shows issuer and device authentication, MSO, keys, namespaces, element salts and digest results with named COSE fields.

### Fixed

- **Visible mdoc holder binding.** CLI and browser decoding show the device key curve and thumbprint, or its absence, and identify device signature or MAC.

- **Current signing expiry.** Published key expiry now follows the signing certificate instead of a timestamp fixed at startup.
- **Automatic certificate renewal.** Signing and TLS leaves renew within a month of expiry under the same CA. TLS reads the current certificate per handshake.

## [1.19.4] - 2026-08-05

### Added

- **Pre-authorized conformance plans.** Added SD-JWT and mdoc scenarios for the pre-authorized grant.
- Demo resets renew the signing leaf under the existing CA.

### Fixed

- **Omitted empty nonce.** Credential proofs omit nonce when no challenge exists, instead of sending an empty string.
- **Immediate deferred response.** The wallet records pending issuance immediately and lets the poller collect on schedule.
- **Baseline replacement by protection.** Refresh removes the complete protected baseline so changes in credential type cannot leave old defaults behind.

### Changed

- **Certificate dialog organization.** Trust lists and certificates have separate sections with labels explaining their roles.

## [1.19.3] - 2026-08-05

### Added

- **Either PID format.** Demo requests offer SD-JWT and mdoc alternatives and verify the returned format.
- **mdoc presentation verification.** The demo checks value digests, device authentication, type, issuer chain and validity.
- **Demo grant selector.** One grant toggle controls a single Create offer button.
- **Trust list categories.** The dialog groups credential and wallet providers. The index exposes `category`.
- Demo issuer and verifier footers link to the configured imprint.
- Wallet list and show commands include pending deferred issuances and their collection details.
- **Persistent deferred collection.** Pending records retain transaction data and proof keys across restarts. The server follows issuer intervals, reports HTTP 202, and stops after collection, permanent errors or 24 hours.
- **Deferred management commands.** `wallet deferred` lists pending records, `check` collects immediately and `abandon` stops collection. Matching API and UI actions are available. Listings omit access tokens.
- **Transaction code input.** Offer consent collects the required code using the issuer's length, input mode and description.
- Interactive `wallet accept` prompts for a missing transaction code. Explicit `--tx-code` takes precedence.
- **Forced client attestation.** `--client-attestation` sends attestations even without advertised support. The config API reports `force_client_attestation`. Reuse across issuers can correlate activity.

### Fixed

- **Remote transaction codes.** `wallet accept --tx-code` now includes the code in remote offer submissions.
- **Pre-authorized security features.** Both grants share support for advertised DPoP, client attestation and key attestation requirements.
- **Shared deferred processing.** Both grants recognize deferred responses and follow issuer intervals. This release also accepted an older pending error response.
- **Bounded synchronous deferral.** This release waited up to 90 seconds before handing collection to the background poller. Release 1.19.4 changed to immediate pending responses.
- **Key attestation levels.** Generated attestations include the storage and authentication levels requested by the issuer as test claims.
- **Attestation proof count.** This release used one proof when key attestation was required to avoid rejected batch requests.
- Authorization headers now follow the token response's `token_type`.
- Credential requests advertise JWT responses only when response encryption was requested.

### Changed

- **EUDI PID identifiers.** Default PIDs use `urn:eudi:pid:1` and the shared EUDI mdoc namespace. Verifier queries matching the former German type need updating.

## [1.19.2] - 2026-08-05

### Security

- **Stored XSS fix.** All UIs escape quotes in attribute values as well as text characters. This prevents imported credentials or offers from injecting event handlers into another visitor's page.
- **Browser security headers.** Wallet responses add CSP, nosniff, framing restrictions and no-referrer. Demo scripts move into separate files.
- **Private consent stream origin.** Removed wildcard CORS from consent events so other websites cannot subscribe to requested claims.
- **Safe redirects.** Server and UI navigation accept only HTTP and HTTPS, blocking javascript: and data: response destinations.
- Demo attestation validation requires exp, and DPoP proofs must be within a five-minute creation window.

### Fixed

- **Sign-in during redemption.** Demo authorization code offers are created before login. The user authenticates between PAR and token exchange.
- **Hosted browser sign-in.** The wallet sends authorization URLs to the initiating UI and resumes through `/callback`.
- Default client ID and redirect URI use the wallet origin and its `/callback`. Explicit flags take precedence.
- **Preserved issued credentials.** Saving restores credentials discarded by concurrent request reloads.
- Only the browser that started issuance follows its sign-in prompt.
- Fixed two test data races between request and test goroutines.

## [1.19.1] - 2026-08-04

### Added

- **Instance versions.** Discovery and routing display the responding server's release from its health endpoint.
- Remote selection rejects a different major version unless forced. Minor and patch differences pass. Development builds skip comparison, and incompatible instances are marked in listings.

### Added

- **Demo authorization server.** Added PAR, authorization and token endpoints with PKCE, DPoP and client attestation. The demo account is alice/alice.
- The demo verifies attestation signatures and possession proofs, binds access tokens to DPoP and names the authenticated account in the ticket.
- **Wallet provider trust list.** `/api/trustlists/wallet-provider` always publishes the shared CA under its wallet provider profile. Credential lists remain the default.

### Fixed

- **Hosted issuance identity.** The demo deployment explicitly supplies its origin as client ID and its callback URI.

### Changed

- **Trust and certificate guidance.** The UI explains anchors for both issuer and verifier use and links to the signing JWKS.
- Shortened text across the wallet and demo pages.

## [1.19.0] - 2026-08-04

### Added

- Offer consent shows issuer identity, flow, transaction code requirements and available credential metadata. Referenced offers are fetched for preview with a host fallback on failure.
- The Conformance dialog reports active validation, HAIP, encryption, transcript and format settings.
- Added `wallet config` as an alias of info and aligned local configuration output with the remote API.

### Changed

- **HAIP demo defaults.** This release defaulted the demo to strict HAIP validation. Explicit flags could override it. Release 1.21.0 changed the demo to debug mode.
- The demo verifier uses signed requests by reference, x509_hash and encrypted direct_post.jwt responses.
- **Issuance HAIP checks.** Added checks for transport and applicable authorization code requirements alongside presentation validation.
- Demo issuer metadata now describes proof requirements, claims and display text.
- This release added per-offer mode and HAIP overrides and fixed their decoding.
- Per-request HAIP overrides could explicitly disable the setting. Omitted fields inherited server configuration.
- Demo network restrictions allow the wallet's own advertised origins at their exact address and port.
- Demo help no longer claims the profile implies auto-accept. Browser consent remains interactive.

### Fixed

- Status tokens include a JWK derived from the signing key alongside their certificate chain.
- Status tokens omit the trust anchor from x5c, matching other signed wallet documents.
- Credential imports on override clones forward to the original wallet.
- Corrected documentation for implemented batch issuance and the scope of HAIP checks.

## [1.18.11] - 2026-08-04

### Fixed

- Startup and periodic demo resets can replace the protected PID baseline. Requests and CLI commands still leave protected credentials alone. This lets an upgraded demo use the current PID templates.

## [1.18.10] - 2026-08-04

### Changed

- German PID templates now follow the [German PID Rulebook](https://demo.pid-provider.bundesdruckerei.de/credential-claims) and use its ERIKA MUSTERMANN test identity. They include the missing name, document, address and age threshold claims and omit fields that the German eID does not supply. User templates still override the defaults.
- German mdoc PID additions now use the `eu.europa.ec.eudi.pid.de.1` namespace. All issuance paths recognize `namespace:element` claim keys, including the CLI, API, templates and default PIDs.
- mdoc issuance now encodes calendar dates with CBOR tag 1004 and timestamps with tag 0, as ISO 18013-5 requires. Parsing converts them back to strings for claim matching and display.

### Fixed

- PID regeneration preserves protected credentials and skips their replacements. Previously it deleted the protected baseline and issued unprotected copies.
- Command tests now use a temporary configuration directory. They previously read the user's remote wallet setting, which allowed tests to issue and delete credentials on a live instance.
- Custom wallet links open the consent dialog again. The OS handler marks its new tab with `consent=await`, allowing that tab to claim the next request. The marker expires after 90 seconds and works once.

- Unanswered demo verification requests now expire after ten minutes, and the verifier page stops polling them. Completed requests retain their results.
- The verifier page gradually slows polling from 1.5 to 8 seconds. It pauses while the tab is hidden and resumes when the tab becomes visible.
- The wallet event stream sends a keepalive every 25 seconds to prevent proxies from closing idle connections.

### Changed

- Public demo container logs now keep at most three 10 MB files per service. Caddy access logs keep at most three 10 MiB files for up to 30 days.
- `deploy.sh push` pulls the image before recreating containers and reports the deployed version. This keeps the image compatible with the updated compose file.
- `deploy.sh stats-reset` clears the access log and rebuilds the report. `deploy.sh stats` lists pages separately from API polling traffic.

## [1.18.9] - 2026-08-04

### Added

- `GET /api/credentials` accepts `limit` and `offset` and reports the full count in `X-Total-Count`. Existing calls still return all credentials. The UI shows ten credentials per page.
- Protected credentials cannot be deleted or revoked through the UI, API or CLI. Demo mode protects its initial PIDs, and deleting all credentials preserves them. In this release the protection flag can only be changed in `wallet.json`. The UI and CLI show protection and revocation status.

### Changed

- The demo banner now shows the configured reset schedule instead of always saying that state resets daily.
- `--demo-reset` accepts a daily time such as `00:00` or `"00:00 Europe/Berlin"`, with daylight saving changes handled automatically. Durations remain supported and `0` disables resets. The public demo now resets at midnight in Berlin.

## [1.18.8] - 2026-08-04

### Added

- Browser tests cover demo consent from custom wallet links and browser requests, isolation between tabs, and restricted endpoints and controls.

### Fixed

- Demo mode shows a Review bar for pending requests that arrive without a browser redirect. This makes requests from OS handlers visible without opening a dialog in every visitor's tab.

## [1.18.7] - 2026-08-04

### Changed

- The macOS handler is now named `EUDI-Dev-Wallet.app`, with bundle identifier `dev.eudi.wallet` and logs in `/tmp/eudi-dev-wallet*.log`. Registration and removal also clean up the old `OID4VC-Dev-Wallet.app` handler.
- Security documentation now describes `--demo` as the public hosting profile, explains that the wallet CA key is persisted and shared, and records the demo verifier's revocation checks.
- Custom wallet URIs on the demo issuer and verifier pages are clickable links.

## [1.18.6] - 2026-08-04

### Changed

- The wallet action bar now links to the demo issuer and verifier.
- Wallet and decoder headers use consistent link order and spacing.
- Trust lists and certificate downloads moved into a Trust & certificates dialog.

### Fixed

- The demo verifier checks credential revocation. It fetches the referenced status list, verifies its signature against the wallet CA and rejects revoked credentials. It also identifies credentials without a status reference.
- The demo verifier displays the result of credential expiry and not-before checks.
- The demo verifier rejects credentials whose type differs from the requested type.
- Each demo verification request accepts one response. Later submissions return 409 and cannot overwrite the result.
- The demo verifier rejects duplicate SD-JWT disclosures and disclosures that no signed digest references.
- The demo verifier checks that requested claims were disclosed and that the key binding JWT uses `typ: kb+jwt`.

## [1.18.5] - 2026-08-04

- Public demo deployments can collect usage statistics. Caddy anonymizes client addresses in its access log, GoAccess builds a report, and `/stats` serves it behind basic authentication. Use `deploy.sh stats-password` to set access and `deploy.sh stats` for a terminal summary.

### Changed

- The wallet header no longer repeats the credential count shown by the list.

### Added

- Every UI footer states that the project is independent and is not affiliated with or endorsed by the European Commission or European Union.

### Fixed

- The wallet footer is reachable on phones. Below 768px the page scrolls as one document and accounts for the browser's visible viewport height.
- Wallet and demo pages use a versioned favicon URL so browsers recover from a cached 404 response in release 1.18.3.

## [1.18.4] - 2026-08-03

### Changed

- UI headers show a larger logo at its original aspect ratio and align it with the title and links.
- The decoder header no longer shows a subtitle that looked like a navigation link.

- Removed decoder keyboard shortcuts that conflicted with browser shortcuts, along with their footer hints.

### Fixed

- Timestamp tooltips now work in claim and disclosure lists. Invalid timestamp values no longer produce invalid date labels.
- The decoder title and links remain beside the logo on narrow screens.

## [1.18.3] - 2026-08-03

### Added

- `examples/public-demo/deploy.sh` supports setup, deployment, updates, status checks, verification and logs over SSH. Settings come from the environment or a gitignored `deploy.env`. Setup also assigns the wallet data volume to the container user.

### Fixed

- The wallet embeds the complete `static/` directory so its logo and favicon are included in the binary. A test checks that referenced assets are served.

## [1.18.2] - 2026-08-03

### Added

- Added a project logo to the README, UI headers and favicons. It depicts a wallet with an ID card and a terminal prompt.
- Open wallet tabs refresh credentials, status badges and activity after saved changes. The server sends state events over SSE and the UI combines updates that arrive together.

## [1.18.1] - 2026-08-03

### Fixed

- Browser redirects include the consent request ID so the initiating tab opens the correct dialog. Demo mode no longer opens every visitor's requests in every tab.
- The decoder requires at least 64 decoded bytes before treating a value as an embedded mdoc. This prevents short digests such as `sd_hash` from appearing as credential links.

## [1.18.0] - 2026-08-03

### Changed

- API submissions auto-accept by default, while browser links, OS handlers and browser DC API flows request consent. API callers can set `interactive: true`. `--auto-accept` overrides all channels, and OS registration has its own auto-accept option.
- The public demo shows consent for browser flows while continuing to auto-accept programmatic API submissions.
- Demo mode returns the newest 50 activity entries from `GET /api/log`. Local instances retain the full log.

## [1.17.1] - 2026-08-03

### Fixed

- Links inside dialogs now use the theme's link color so they remain readable on dark backgrounds.
- Deleting or changing the status of a credential immediately refreshes the activity log in the UI.
- Static UI assets use `Cache-Control: no-cache` so browsers check for updates across releases.

## [1.17.0] - 2026-08-03

### Added

- Every wallet server includes demo issuer and verifier pages at `/issuer` and `/verifier`. The issuer provides a Demo Event Ticket SD-JWT VC through the OID4VCI pre-authorized code flow. The verifier requests the ticket or PID through OID4VP and shows the signature and key binding checks. Both support external clients that can reach the server.
- `examples/keycloak-web-wallet-public` connects local Keycloak to the public demo wallet. It uses ngrok or `KEYCLOAK_PUBLIC_URL` to make Keycloak reachable and reuses the local example's realms, extension, UI and scripts. `WALLET_BASE_URL` selects another demo wallet.

- Issuance, PID regeneration, deletion and status changes now appear in the activity log as management actions.
- Demo mode shows a dismissible banner explaining that the wallet is shared and intended for demonstration. The browser remembers dismissal.
- The wallet's How to use dialog lists protocol endpoints at the current origin and explains custom wallet links and CLI handlers.

### Changed

- The decoder's Get the CLI link opens the installation dialog used by the wallet UI.
- The wallet hides TLS certificate downloads when an external server terminates HTTPS. CA downloads remain available for credential trust. `/api/config` reports whether the built-in TLS listener is enabled.

## [1.16.4] - 2026-08-03

### Changed

- The UI and docs now call the hosted instance a Public demo to distinguish it from the official German EUDI Sandbox.
- Improved dimmed text and light theme accent colors to reach a contrast ratio of at least 4.5 to 1.

## [1.16.3] - 2026-08-03

### Changed

- Demo mode hides the Templates button because template writes are disabled there.
- The embedded decoder explains that pasted credentials are sent to the demo server for decoding.

## [1.16.0] - 2026-08-03

### Added

- `wallet serve --demo` adds a public demo profile. In this release it enables auto-accept and default PIDs, restricts process and filesystem endpoints, hides host details and limits request bodies. Outbound requests cannot reach private networks.
- `wallet serve --demo-reset <duration>` restores the demo PIDs and clears activity periodically, once an hour by default. Keys, certificates and serving URLs remain stable. The footer shows the interval.
- `wallet serve --imprint-file <path>` and `serve --imprint-file <path>` serve an operator's legal notice at `/imprint`. The UI footer links to it when configured.
- Both UIs link to GitHub and CLI installation instructions and show their version in the footer. The wallet also displays trust list URLs and certificate downloads.
- Deployment recipe for public hosting: `docs/public-demo.md` and `examples/public-demo/` (Caddy with automatic TLS in front of the wallet)

### Changed

- An HTTPS `--base-url` also becomes the issuer URL, placing credential metadata, status lists and trust lists on that origin. The built-in HTTPS listener is disabled because an external server is expected to terminate TLS. HTTP base URLs keep the existing port+1 behavior.

### Fixed

- The decoder's `/api/validate` rejects local file paths in `trustListURL` and limits remote responses to 10 MB.
- `scripts/build.sh` uses the renamed Go module when embedding the version. It now builds `eudi` with the correct version and installs completions under that name.
- Documentation screenshots and the flow diagrams were refreshed for the current UI and the `eudi-dev` name
- Switching templates in the issue dialog clears fields omitted by the new template. Selecting `(none)` resets the form.

## [1.15.5] - 2026-08-03

### Fixed

- Local and remote wallet management use one service interface, with file and REST implementations. This removes duplicated command logic and keeps their output consistent.
- Local `issue --wallet` uses the same template and claim resolution as `POST /api/issue`.
- `wallet scan` routes imports through the managed wallet instead of writing files owned by a running server.
- The ACTIVE column in `wallet instances list` includes instances selected automatically. JSON output exposes the same information in an `active` field.
- Remote commands no longer announce the target on every invocation. Use `wallet instances use`, `wallet info` or `wallet instances list` to inspect it. Automatic routing still prints a notice.
- Certificate exports with `--out` print the file path to stdout for both local and remote wallets. Template save and delete messages also match.

## [1.15.4] - 2026-08-03

### Fixed

- The macOS handler submits links to the active remote wallet and opens its consent UI locally. Failed submissions no longer retry against the local wallet, which could process an offer twice.
- `wallet instances list` includes the active remote target even when local discovery cannot find it. The CLI checks its health and reads instance details from its API.
- `wallet.json` is written to a temporary file and renamed into place so readers do not see a partial write.

## [1.15.3] - 2026-08-02

### Fixed

- CLI commands route through a running server that owns the selected wallet directory. This avoids competing file writers and accidental changes to serving URLs. `--remote local` or an explicit `--templates-dir` still forces direct file access.
- Issuance preserves existing serving URLs unless `--base-url` or `--docker` is explicit. Offline commands explain that these URLs become available when the wallet server starts. The URL handler also preserves configured Docker URLs.
- Without a trust list, `validate` and `decode` can verify signatures using embedded leaf certificates. The output states that the chain was not validated. Supplying a trust list still requires chain validation.
- The web decoder trusts the local wallet CA when validating credentials issued by that wallet.
- Wallet startup warns about Docker hostnames outside Docker and stored issuer or status URLs that this server does not serve.
- `wallet info` warns when a running instance's serving URLs differ from those stored on disk.
- Wallet screenshots now include imported credentials and issuance and presentation activity.

## [1.15.2] - 2026-08-02

### Fixed

- Homebrew tap publishing runs automatically for tagged releases.

## [1.15.1] - 2026-08-02

### Added

- `brew install dominikschlosser/tap/eudi-dev` installs `eudi`, shell completions and the `oid4vc-dev` alias. Tagged releases update the formula automatically.

### Fixed

- Default directory tests use a controlled home directory to check both the new `.eudi-dev` path and the legacy fallback.
- Documentation screenshots refreshed for the renamed EUDI Dev Wallet and EUDI Dev Decoder UIs

## [1.15.0] - 2026-08-02

### Changed

- Renamed the project to **eudi-dev** and the CLI to **`eudi`**. The Go module is `github.com/dominikschlosser/eudi-dev` and the Docker image is `ghcr.io/dominikschlosser/eudi-dev`. State defaults to `~/.eudi-dev`, with `EUDI_DEV_HOME` as an override.
- The `oid4vc-dev` binary alias, legacy Docker image and `OID4VC_DEV_HOME` remain supported. Existing `~/.oid4vc-dev` directories are reused when `~/.eudi-dev` does not exist, and discovery finds either binary name. New `go install` commands must use the renamed module path.

## [1.14.1] - 2026-08-02

### Added

- Added Bash, Zsh, Fish and PowerShell completion for templates, credentials, instances and flag values. `completion install [bash|zsh|fish]` configures the selected shell or detects it from `$SHELL`.

### Changed

- Instance commands moved to `wallet instances list`, `wallet instances use <url|local>` and `wallet instances kill <pid|port|url>`. Plain `wallet instances` lists instances. The former top level `wallet use` and `wallet kill` commands were removed.

## [1.14.0] - 2026-08-02

### Added

- CLI management commands can use a running wallet's REST API. `wallet use <url>` saves a remote target, `wallet use local` restores local management, and `--remote <url>` selects a target for one command. Remote templates resolve in the server's template directory.
- The CLI discovers running wallet servers through the instance registry and process scan, then checks their health. `wallet kill` requests shutdown over HTTP with SIGTERM as a fallback. Servers register in `~/.oid4vc-dev/instances/` and remove their entries on shutdown.
- `GET /api/config` returns instance details, serving URLs, wallet settings and credential count. `wallet info` displays them for the managed wallet.
- Credential cards show status badges and controls for revoking or activating local credentials. External credentials have a Check status action. The issue dialog can select the wallet's list, a custom reference or no status list. `GET /api/credentials/{id}/status` resolves the current value.
- Wallet controls have stable IDs for browser tests. Credential, template and consent elements expose identifying data attributes.
- Credential templates provide reusable claims and format defaults across the CLI, API and UI. Use `templates list|show|save|import|delete` to manage them and `issue --template <name>` to issue from one. User templates override built-in templates with the same name. `--templates-dir` selects a shared directory.
- Default PID claims moved into `german-pid-sdjwt` and `german-pid-mdoc` templates. Overriding either template changes PID issuance through the CLI and API.
- `issue sdjwt --always-disclosed` embeds selected claims directly in the signed payload. Templates and API requests accept the same option, and the UI offers an SD checkbox for each claim. Dotted paths such as `address.country` apply to nested claims. mdoc rejects the option and JWT VC ignores it.

### Removed

- The template dropdown replaces the PID preset button and `GET /api/issue/defaults`. Clients can read the PID templates through `GET /api/templates`.
- Removed `trust_anchor` from default mdoc PID claims because the sample value did not describe the wallet's test credentials.

### Deprecated

- Deprecated `wallet generate-pid` and `POST /api/generate-pid`. Use `issue sdjwt --wallet --template german-pid-sdjwt`, `issue mdoc --wallet --template german-pid-mdoc` or `POST /api/issue` with a template. Existing calls still work. The CLI prints replacement commands and the API returns `Deprecation: true`.

### Fixed

- Local validation and status checks fall back to `localhost` when `host.docker.internal` cannot be resolved. This lets host tools inspect credentials issued by Docker wallets.
- Default PID generation includes status references when only an issuer URL is configured, matching `POST /api/issue`.
- Docker browser tests use an available port to avoid the wallet tests' HTTPS listener. Issuing tests clear prior errors and pending consent before each test.

## [1.13.0] - 2026-08-01

### Added

- The wallet UI can issue credentials with a claim builder or JSON input, format settings, expiry and not-before dates. It also links to CA and TLS certificate exports. Stable control IDs support browser tests.
- mdoc issuance supports `namespace:element` claim keys in the CLI, API and UI.
- Added HTTP endpoints to show and delete credentials, issue new credentials, regenerate PIDs and export CA or TLS certificates. These let tests manage a running wallet remotely. The API has no authentication in this release.

## [1.12.3] - 2026-08-01

### Added

- `GET /credential-offer` accepts `credential_offer`, `credential_offer_uri` and optional `tx_code` parameters. Issuers can use the wallet's web URL on platforms without a custom URI handler.
- Browser calls to `/authorize` and `/credential-offer` redirect through the consent UI. After approval, presentations continue to the verifier's redirect URI and issuance returns to the wallet. API callers continue receiving JSON.
- The `keycloak-web-wallet` example combines Keycloak 26.7.0 issuance, the OID4VP verifier extension, a wallet and a demo UI. Containers share a network namespace so host and container URLs use `localhost`. Wallet web links require verifier extension versions above 0.6.4.

### Fixed

- Credential requests send `Accept: application/jwt` only when response encryption was negotiated. Sending it unconditionally caused errors in Keycloak 26.6.

## [1.12.2] - 2026-07-30

### Added

- The wallet supports OID4VCI batch issuance. It creates a distinct proof key for each requested credential and matches returned credentials to their keys regardless of response order.

### Changed

- Wallet and decoder web UIs unified to a shared look and layout
- Wallet activity includes more detail about each flow step.

### Fixed

- Authorization server discovery removes the issuer's trailing slash as RFC 8414 §3.1 requires. Credential issuer discovery preserves the identifier path as OID4VCI 1.0 §12.2.2 requires.
- The wallet skips unsupported or signing-only encryption keys in verifier metadata and uses the first compatible key, following RFC 7517 §5.
- Updated conformance tests to release-v5.2.1, including batch issuance and unsupported encryption keys. The runner excludes the suite's broken `invalid-client-id-prefix` module.

## [1.12.1] - 2026-07-30

### Fixed

- Wallet UI shows stored credentials and allows clearing the activity log

## [1.12.0] - 2026-07-30

### Added

- The macOS URL handler detects and restarts stale wallet server processes.

## [1.11.1] - 2026-07-30

### Fixed

- Send `Accept` header on the credential request

## [1.11.0] - 2026-07-26

### Added

- `wallet ca-cert --jwks` and `wallet tls-cert --jwks` export a JWKS containing the certificate chain for use in verifier trust settings.

### Removed

- Removed the separate HAIP Keycloak example. The combined issuer and verifier app covers the same flow.

## [1.10.11] - 2026-06-05

### Fixed

- Proxy log output simplified

## [1.10.10] - 2026-06-05

### Fixed

- Do not truncate URLs in the proxy for debugging
- Exclude non-applicable conformance variants, update docs

## [1.10.9] - 2026-06-05

### Fixed

- Some edge cases with multiple wallet instances

## [1.10.8] - 2026-06-05

### Fixed

- Various bugfixes

## [1.10.7] - 2026-06-05

### Fixed

- Local scan

## [1.10.6] - 2026-06-05

### Fixed

- Scan bug

## [1.10.5] - 2026-06-05

### Fixed

- Proxy behavior

## [1.10.4] - 2026-06-05

### Fixed

- Wallet log contents

## [1.10.3] - 2026-06-05

### Fixed

- More detailed wallet logs.

## [1.10.2] - 2026-06-05

### Fixed

- Expanded wallet logs and corrected their contents.

## [1.10.1] - 2026-06-05

### Fixed

- Wallet store reuse between instances

## [1.10.0] - 2026-06-05

### Added

- `wallet logs` command

### Fixed

- Demo QR code size

## [1.9.5] - 2026-06-05

### Fixed

- Conformance tests and debug mode behavior.
- Add local wallet mode to the Keycloak demo

## [1.9.4] - 2026-04-18

### Fixed

- Do not truncate tokens in the proxy

## [1.9.3] - 2026-04-18

### Fixed

- POST headers and bodies appear in proxy output.

## [1.9.2] - 2026-04-18

### Fixed

- Do not print traffic classified as "unknown" in the proxy by default

## [1.9.1] - 2026-04-18

### Fixed

- Improved grouping of proxy traffic.

## [1.9.0] - 2026-04-18

### Changed

- The proxy learns endpoints during each flow. Calls classified as unknown are hidden by default.

## [1.8.10] - 2026-04-12

### Fixed

- Keycloak examples preserve custom wallet URIs after validating their schemes. URL normalization previously broke `openid-credential-offer://` and `haip-vci://` links.
- The wallet UI recognizes `haip-vci://` links as credential offers.

## [1.8.9] - 2026-04-12

### Fixed

- Wallet port probes bind to `127.0.0.1` and handle listener close errors.
- Keycloak examples validate wallet URI schemes before rendering offer links.

## [1.8.8] - 2026-04-12

### Fixed

- Interactive issuance fetches `credential_offer_uri` after consent.
- The wallet UI shows issuance errors and refreshes imported credentials immediately after approval.

## [1.8.7] - 2026-04-12

### Fixed

- Issuance reuses the parsed offer after approval so URLs that can only be fetched once continue to work.
- Issuance approval displays errors and refreshes credentials on success.
- Keycloak example links preserve custom wallet URI schemes.

## [1.8.6] - 2026-04-12

### Changed

- Aligned the HAIP example and documentation with the combined issuer and verifier example.

### Fixed

- `wallet accept --auto-accept` now reuses an already running wallet server instead of conflicting on the local port
- `wallet accept` without an explicit port now probes the standard wallet port before falling back to a one-shot server
- Simplified HAIP example helpers, scripts and build configuration.

## [1.8.5] - 2026-04-11

### Added

- A HAIP Keycloak example covers authorization code issuance and verifier authentication with X.509 certificates.
- wallet support for interactive authorization code issuance callbacks via the local `/callback` endpoint

### Changed

- Simplified Keycloak examples and setup scripts.
- expanded the OIDF conformance runner coverage for Browser API and HAIP flows

### Fixed

- Browser API handling for multisigned OpenID4VP request objects
- mdoc Browser API session transcript generation for `dc_api` / `dc_api.jwt`
- multiple issuance and verification issues in the combined Keycloak demo flows

## [1.8.4] - 2026-04-11

### Added

- `wallet remove --all` clears stored credentials.

### Fixed

- example setup and bootstrap issues in the combined Keycloak issuer/verifier demo
- Interactive issuance waits for consent.
- Keycloak demo setup correctly handles generated trust lists and signing material.

## [1.8.3] - 2026-04-11

### Changed

- The macOS handler distinguishes interactive issuance from imports registered with `--auto-accept`.

### Fixed

- Interactive issuance opens the wallet for consent.
- the combined Keycloak demo app now logs out through Keycloak instead of only clearing the local session

## [1.8.2] - 2026-04-11

### Added

- Keycloak examples cover issuance, verification and their combined flow.
- A combined Keycloak app includes setup scripts and smoke tests for issuance and wallet login.

### Fixed

- credential-offer and issuer metadata parsing for the new Keycloak issuance example flows

## [1.8.1] - 2026-04-09

### Fixed

- The wallet enforces SIOPv2 only mode and the requirement for encrypted requests.

## [1.8.0] - 2026-04-09

### Added

- `/api/dc-api` supports browser presentations with `dc_api` and `dc_api.jwt`, including `web-origin:` client binding.
- HAIP wallet conformance coverage for the current OID4VP 1.0 Final and OID4VCI 1.0 Final HAIP plans, including `dc_api.jwt` VP scenarios

### Changed

- the OIDF wallet conformance runner now targets the current OID4VP 1.0 Final, OID4VCI 1.0 Final, and HAIP wallet plans by default
- the wallet now requests `credential_response_encryption` when issuers advertise it and accepts encrypted JWE credential responses in the authorization code flow

### Fixed

- wallet-generated ETSI trust lists now use the required top-level `LoTE` JSON binding wrapper instead of the previously emitted unwrapped payload
- trust list parsing and format detection now reject the old non-conformant unwrapped trust list shape
- proxy JWE tests now match the current `EncryptJWE` API so the full suite builds cleanly again

## [1.7.4] - 2026-04-09

### Changed

- updated the conformance runner to target the current OpenID4VP / OID4VCI 1.0 variant names

## [1.7.3] - 2026-04-08

### Fixed

- compatibility with the then-current wallet conformance test suite

## [1.7.2] - 2026-04-08

### Fixed

- authorization errors are now returned to the verifier instead of being dropped locally
- `direct_post.jwt` responses now preserve `state`

## [1.7.1] - 2026-03-22

### Fixed

- trust list parsing and decoded output now preserve and expose `ListAndSchemeInformation.NextUpdate`

## [1.7.0] - 2026-03-22

### Changed

- `/api/trustlists` exposes a relative `path` for each profile so container clients can resolve it against their reachable origin.
- `/api/trustlists` now publishes `advertised_url` for the configured issuer URL and keeps `url` as a backward-compatible alias

### Documentation

- clarified that `/api/trustlists` is a local discovery endpoint while `/api/trustlists/{id}` serves the ETSI trust list JWT
- documented how Docker and Testcontainers callers should resolve trust list `path` values against the URL they actually used

## [1.6.0] - 2026-03-22

### Added

- multiple wallet trust list profiles with `/api/trustlists`, `/api/trustlists/{id}`, and CLI selection via `wallet trust-list --id|--vct|--doctype`
- signed OpenID Credential Issuer metadata and registrar-style authorization responses for wallet-issued credential types
- Each trust profile uses its own credential signing certificate under the shared wallet CA.

### Changed

- `issue --wallet` uses the wallet's issuer directly.
- Commands reuse stored issuer and status list URLs so credentials and served endpoints agree.
- Trust lists describe trusted certificates. Issuer metadata and registrar responses publish authorization for credential types.

### Fixed

- `issue --wallet` credentials now validate against the wallet trust list and use wallet-managed status list entries by default
- PID generation, serving, certificate exports and validation use the same stored wallet issuer state.
- trust list parsing accepts current ETSI-style `ListIssueDateTime` payloads

### Documentation

- Documented trust profiles, wallet issuance and the shared CA with a signing certificate for each profile.

## [1.5.3] - 2026-03-20

### Fixed

- `wallet tls-cert` now prints exactly one leaf PEM certificate. `wallet ca-cert` prints exactly one CA PEM certificate

## [1.5.2] - 2026-03-20

### Added

- `wallet ca-cert` to print or export the shared wallet CA certificate

### Changed

- wallets under the same wallet base directory now share one persisted CA
- the shared CA now anchors wallet trust lists, status list `x5c` chains, issuer metadata `x5c` chains, and HTTPS wallet certificates
- HTTPS wallet certificates are now signed by the shared CA instead of being self-signed
- Trust and certificate changes preserve API paths and response formats.

## [1.5.1] - 2026-03-20

### Changed

- wallet-generated PID credentials now use the HTTPS wallet status list endpoint on `port+1`
- `wallet issuer-tls-cert` was renamed to `wallet tls-cert` to reflect that the exported certificate covers all HTTPS wallet endpoints
- persisted HTTPS wallet certificate files were renamed to `wallet-tls-cert.pem` / `wallet-tls-key.pem` with legacy migration from the old issuer-prefixed names
- `wallet serve` now prints both HTTP and HTTPS endpoint URLs where both are available

### Documentation

- clarified that `/api/trustlist` and `/api/statuslist` are also exposed via HTTPS
- updated wallet, validate, docker, and README docs for `wallet tls-cert` and HTTPS status list resolution

## [1.5.0] - 2026-03-20

### Added

- persistent wallet issuer HTTPS certificate files in the wallet directory
- `wallet issuer-tls-cert` to print or export the HTTPS issuer certificate used by `/.well-known/jwt-vc-issuer`

### Changed

- The validation banner shows the status check result when available.

### Fixed

- local validation fetches now bypass proxies and correctly trust the wallet's self-signed local HTTPS endpoints for issuer metadata and status list resolution

## [1.4.5] - 2026-03-20

### Fixed

- PID generation includes status list entries, and validation checks them.

## [1.4.4] - 2026-03-20

### Fixed

- Signature verification using `kid` in the validation UI.

## [1.4.3] - 2026-03-20

### Fixed

- The validation UI resolves keys by `kid`.

## [1.4.2] - 2026-03-20

### Fixed

- `wallet generate-pid` now uses the correct local issuer `iss` instead of `https://issuer.example`

## [1.4.1] - 2026-03-20

### Fixed

- Issuer metadata resolution using `kid`.

## [1.4.0] - 2026-03-20

### Added

- HTTPS issuer metadata endpoint for wallet-issued SD-JWT credentials
- SD-JWT verification resolves keys by `kid` through issuer metadata.

## [1.3.8] - 2026-03-19

### Fixed

- disclosure of nested values in SD-JWT credentials

## [1.3.7] - 2026-03-19

### Fixed

- further mock PID structural fixes
- The proxy decodes multiple credentials in one response.

## [1.3.6] - 2026-03-19

### Fixed

- Corrected the default mdoc PID `birth_place` structure.
- Proxy results link to each decoded credential separately.

## [1.3.5] - 2026-03-19

### Fixed

- Debug mode permits credentials with claims that do not match the request.

## [1.3.4] - 2026-03-19

### Fixed

- Updated default test PID claims.

## [1.3.3] - 2026-03-18

### Fixed

- The decoder supports browser back navigation and opening nested credentials.

## [1.3.2] - 2026-03-11

### Fixed

- Request object claims and values are checked against the specification.

## [1.3.1] - 2026-03-10

### Added

- Added `aki` support for `trusted_authorities`.

## [1.3.0] - 2026-03-10

### Added

- Added `aki` support for `trusted_authorities`.

## [1.2.1] - 2026-03-09

### Fixed

- Status lists include `sub` and `ttl`.

## [1.2.0] - 2026-03-07

### Changed

- The OIDF runner defaults to the signed strict plan.

## [1.1.0] - 2026-03-05

### Added

- `wallet show <id>` prints a stored credential. Use `--decoded` to inspect its contents.

## [1.0.4] - 2026-03-04

### Fixed

- `trusted_authorities` trust list fetch: fall back to `localhost` when `host.docker.internal` is unreachable (wallet running on host, verifier in Docker)

## [1.0.3] - 2026-03-04

### Added

- Display version in `wallet serve` and `proxy` startup banners

## [1.0.2] - 2026-03-04

### Fixed

- DCQL `trusted_authorities` now reads `values` (array) per OID4VP 1.0 spec instead of `value` (string)
- Codecov ignore patterns use regex syntax to match Go coverage paths

## [1.0.1] - 2026-03-04

### Added

- Version auto-detection from Go module info for `go install` builds (falls back to ldflags, then `dev`)

## [1.0.0] - 2026-03-04

First stable release of oid4vc-dev, a developer toolkit for debugging and testing
OID4VP, OID4VCI, SD-JWT, mDoc, and related SSI/eIDAS 2.0 protocols.

### Features

- **Credential decoding:** Detect and decode SD-JWT VC, JWT VC and mdoc, including selective disclosures.
- **Credential validation:** Check signatures, certificate chains against ETSI trust lists, and token status lists.
- **Credential issuance:** Generate test credentials with configurable claims, keys and certificate chains.
- **DCQL evaluation:** Match credentials and evaluate `claim_sets` and `credential_sets`.
- **Wallet:** OID4VP wallet with a consent UI and support for:
  - All client_id schemes (x509_san_dns, x509_hash, redirect_uri, verifier_attestation, decentralized_identifier)
  - Response modes: direct_post, direct_post.jwt (JARM), fragment
  - Encrypted request objects (JWE with ECDH-ES)
  - HAIP 1.0 enforcement mode
  - SIOPv2 self-issued ID token (response_type "vp_token id_token")
  - OID4VCI pre-authorized code flow with tx_code support
  - DCQL `trusted_authorities` (`etsi_tl`) filtering
  - Session transcript generation (OID4VP and ISO 18013-7 modes)
- **Proxy:** Intercept, classify and decode protocol traffic, with:
  - Live web dashboard with SSE streaming
  - HAR export
  - Automatic JWE decryption (key extraction from subprocess stdout)
  - Subprocess management for proxied services
- **Web UI:** Decode and validate credentials in a browser.
- **QR codes:** Capture and decode QR codes on macOS.
- **Docker:** Images for multiple architectures and an HTTP API for integration tests.
### Spec Compliance

- OID4VP 1.0 Draft 28: request parsing, DCQL, JAR and response modes.
- OID4VCI 1.0: pre-authorized code grants, credential requests and proof of possession.
- HAIP 1.0: checks for required parameters and algorithms.
- SD-JWT: parsing, disclosure resolution, key binding and SHA-256/384/512 hashing.
- ISO 18013-5 mdoc: CBOR parsing, COSE_Sign1 verification and MSO validation.
- ETSI TS 119 612: trust list generation and certificate chain validation.
- Token status lists: generation and status checks.
- SIOPv2: self-issued ID tokens with a JWK thumbprint subject.

## [0.22.0] - 2026-03-04

### Fixed

- Build and lint fixes.

## [0.21.2] - 2026-03-04

### Fixed

- build

## [0.21.1] - 2026-03-04

### Fixed

- Improved maintainability and tests and corrected protocol handling.

## [0.21.0] - 2026-03-04

### Fixed

- Improved maintainability and tests and corrected protocol handling.

## [0.20.2] - 2026-03-03

### Fixed

- Corrected trust list signing.

## [0.20.1] - 2026-03-03

### Fixed

- build

## [0.20.0] - 2026-03-03

### Added

- Optional request object encryption.

## [0.19.0] - 2026-03-03

### Fixed

- Credentials and trust lists use the certificate chain when signing.

## [0.18.5] - 2026-03-02

### Added

- Added the `--docker` shortcut.

## [0.18.4] - 2026-03-02

### Fixed

- claim matching

## [0.18.3] - 2026-03-02

### Added

- A warning appears when the signature algorithm does not match the header certificate.

## [0.18.2] - 2026-03-02

### Fixed

- clickable links in proxy

## [0.18.1] - 2026-03-02

### Fixed

- proxy credential detection and decryption

## [0.18.0] - 2026-03-02

### Fixed

- proxy credential scanning improved

## [0.17.2] - 2026-03-02

### Fixed

- The wallet checks OID4VP encryption parameters and rejects invalid requests.

## [0.17.1] - 2026-03-02

### Fixed

- Windows build fixes.

## [0.17.0] - 2026-03-02

### Fixed

- The wallet reads encryption parameters from the OID4VP 1.0 `client_metadata` fields.

## [0.16.1] - 2026-02-28

### Fixed

- flaky tests

## [0.16.0] - 2026-02-28

### Added

- `--nbf` sets the not-before claim in issued credentials.

## [0.15.0] - 2026-02-28

### Added

- The proxy detects credentials and keys from the proxied service.

## [0.14.2] - 2026-02-28

### Fixed

- The Dockerfile uses Go 1.26.0.

## [0.14.1] - 2026-02-28

### Changed

- Applied code review fixes.

## [0.14.0] - 2026-02-28

### Changed

- Documented JWT issuance and wallet transaction codes and pre-authorized flows.

## [0.13.4] - 2026-02-28

### Changed

- Applied code review fixes.

## [0.13.3] - 2026-02-27

### Fixed

- Corrected presentation responses containing multiple credentials.

## [0.13.2] - 2026-02-27

### Fixed

- support JWT VC throughout the codebase

## [0.13.1] - 2026-02-27

### Fixed

- The wallet supports `jwt_vc_json` credentials.

## [0.13.0] - 2026-02-27

### Added

- Added controls for the next response and preferred credential format.

## [0.12.1] - 2026-02-27

### Fixed

- missed renames

## [0.12.0] - 2026-02-27

### Changed

- rename to oid4vc-dev

## [0.11.1] - 2026-02-27

### Added

- Added a Docker build and updated its documentation.

## [0.11.0] - 2026-02-27

### Added

- add mock wallet

## [0.10.0] - 2026-02-27

### Added

- The proxy UI decodes credentials from token responses.

## [0.9.1] - 2026-02-27

### Fixed

- Fixed decoder UI errors when used through the proxy.

## [0.9.0] - 2026-02-27

### Added

- Merged OpenID decoding into the `decode` command.

## [0.8.2] - 2026-02-26

### Fixed

- Fixed credential issuance commands.

## [0.8.1] - 2026-02-26

### Fixed

- mdoc output uses Base64 encoding.

## [0.8.0] - 2026-02-26

### Added

- issue mock credentials

## [0.7.1] - 2026-02-26

### Added

- add proxy features

## [0.7.0] - 2026-02-26

### Added

- add proxy features

## [0.6.3] - 2026-02-26

### Fixed

- Improved proxy request classification and documentation.

## [0.6.2] - 2026-02-26

### Fixed

- The proxy respects the forwarded client address header.

## [0.6.1] - 2026-02-26

### Fixed

- proxy filters out irrelevant requests

## [0.6.0] - 2026-02-26

### Added

- add proxy mode

## [0.5.0] - 2026-02-26

### Added

- Added QR code screen capture on macOS.

## [0.4.1] - 2026-02-26

### Fixed

- Fixed web UI errors.

## [0.4.0] - 2026-02-26

### Added

- Added validation to the web UI.

## [0.3.0] - 2026-02-26

### Added

- Improved web UI highlighting and structure.

## [0.2.0] - 2026-02-26

### Added

- Added the web UI.

## [0.1.0] - 2026-02-26

### Fixed

- Added the Apache 2.0 license.

[2.5.1]: https://github.com/dominikschlosser/eudi-dev/releases/tag/v2.5.1
[1.12.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.3
[1.12.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.2
[1.12.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.1
[1.12.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.12.0
[1.11.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.11.1
[1.11.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.11.0
[1.10.11]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.11
[1.10.10]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.10
[1.10.9]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.9
[1.10.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.8
[1.10.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.7
[1.10.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.6
[1.10.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.5
[1.10.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.4
[1.10.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.3
[1.10.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.2
[1.10.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.1
[1.10.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.10.0
[1.9.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.5
[1.9.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.4
[1.9.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.3
[1.9.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.2
[1.9.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.1
[1.9.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.9.0
[1.8.10]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.10
[1.8.9]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.9
[1.8.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.8
[1.8.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.7
[1.8.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.6
[1.8.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.5
[1.8.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.4
[1.8.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.3
[1.8.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.2
[1.8.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.1
[1.8.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.8.0
[1.7.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.4
[1.7.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.3
[1.7.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.2
[1.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.1
[1.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.7.0
[1.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.6.0
[1.5.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.3
[1.5.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.2
[1.5.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.1
[1.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.5.0
[1.4.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.5
[1.4.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.4
[1.4.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.3
[1.4.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.2
[1.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.1
[1.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.4.0
[1.3.8]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.8
[1.3.7]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.7
[1.3.6]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.6
[1.3.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.5
[1.3.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.4
[1.3.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.3
[1.3.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.2
[1.3.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.1
[1.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.3.0
[1.2.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.1
[1.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.2.0
[1.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.1.0
[1.0.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.4
[1.0.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.3
[1.0.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.2
[1.0.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.1
[1.0.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.0
[0.22.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.22.0
[0.21.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.2
[0.21.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.1
[0.21.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.21.0
[0.20.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.2
[0.20.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.1
[0.20.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.20.0
[0.19.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.19.0
[0.18.5]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.5
[0.18.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.4
[0.18.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.3
[0.18.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.2
[0.18.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.1
[0.18.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.18.0
[0.17.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.2
[0.17.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.1
[0.17.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.17.0
[0.16.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.1
[0.16.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.16.0
[0.15.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.15.0
[0.14.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.2
[0.14.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.1
[0.14.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.14.0
[0.13.4]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.4
[0.13.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.3
[0.13.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.2
[0.13.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.1
[0.13.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.13.0
[0.12.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.1
[0.12.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.12.0
[0.11.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.1
[0.11.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.11.0
[0.10.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.10.0
[0.9.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.1
[0.9.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.9.0
[0.8.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.2
[0.8.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.1
[0.8.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.8.0
[0.7.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.1
[0.7.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.7.0
[0.6.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.3
[0.6.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.2
[0.6.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.1
[0.6.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.6.0
[0.5.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.5.0
[0.4.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.1
[0.4.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.4.0
[0.3.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.3.0
[0.2.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.2.0
[0.1.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v0.1.0
