# Debug-by-default validation with an opt-in strict mode

Validation has two modes (`internal/wallet/mode.go`). In `debug`, the default, normative findings are logged as warnings and the flow continues. This lets developers see how a malformed request affects the exchange. In `strict`, the same findings stop the flow.

`validatePresentationRequestCore` collects findings and applies the selected mode. DCQL matching, request object signature verification and `wallet_nonce` checks use the same mode. See `docs/spec-compliance.md` for behavior by feature.

`--haip` is a separate switch. It adds the HAIP 1.0 checks on top of the base specifications. Debug mode logs HAIP violations and continues. Strict mode rejects requests that violate the profile.

## Consequences

In debug mode, the wallet can present credentials even when the request object signature is invalid. It records the failed check in the activity log. Conformance runs and any test of spec behaviour must use `--mode strict`.

## Outbound HTTPS

Strict mode verifies HTTPS server certificates by default. Debug mode skips verification. `--tls-verify=true|false` overrides either default for every destination, including redirects. The Settings dialog and the API can change the setting or restore the mode default. `--tls-ca` adds CA certificates to system trust.

[OpenID4VP 1.0 Final §14.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.6) requires TLS server certificate checks. Strict mode applies them to local and remote endpoints. Developers can turn verification off to test servers with invalid certificates. The setting does not depend on HAIP or on signature checks. Each wallet server has its own HTTP client and TLS settings.
