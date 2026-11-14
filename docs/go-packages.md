# Go packages

eudi-dev has packages for other Go programs. They parse and verify credentials. `pkg/mdoc` reads mdoc credentials (ISO/IEC 18013-5). `pkg/sdjwt` reads SD-JWT (RFC 9901) and SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19). `pkg/sdjwt/delegate` reads, verifies and creates Delegate SD-JWT chains and is experimental.

```bash
go get github.com/eudi-dev/eudi-dev/v3
```

The packages check signatures with a key from the caller. Your program decides which issuer keys it trusts, for example from a trusted list or from the `x5c` chain of the credential.

The exported API follows semantic versioning with the eudi-dev version. All other packages of the module are internal. See [ADR-0034](adr/0034-the-credential-format-packages-are-public.md).

## mdoc

```go
import "github.com/eudi-dev/eudi-dev/v3/pkg/mdoc"

doc, err := mdoc.Parse(raw) // IssuerSigned or DeviceResponse, hex or base64url
if err != nil {
    return err
}
if err := mdoc.Verify(doc, issuerKey); err != nil {
    return err
}
if err := mdoc.VerifyValueDigests(doc); err != nil {
    return err
}
if err := doc.ValidAt(time.Now()); err != nil {
    return err
}
```

| Function | Check |
|---|---|
| `Parse` | The structure and the members that ISO/IEC 18013-5 requires |
| `Verify` | The issuer signature over the MSO |
| `VerifyValueDigests` | The data elements against the digests in the MSO |
| `Document.ValidAt` | `validFrom` and `validUntil` of the MSO |
| `VerifyDeviceAuth` | The device signature over a session transcript |

`OID4VPSessionTranscript`, `OID4VPDCAPISessionTranscript` and `ISOSessionTranscript` build the session transcript of a presentation request. `OID4VCIIAESessionTranscript` builds the session transcript of an interactive authorization in OpenID4VCI 1.1 (Appendix A.2.5). `DeviceKey` returns the device key of the MSO. `Document.IssuerCertificates` returns the certificates of the `x5chain` header. The chain is not validated.

For a DeviceResponse with several documents, `Parse` reads only the first. `Document.Documents` is the number of documents.

`ParseLenient` reads an mdoc that breaks ISO/IEC 18013-5 and lists the violations in `Document.Deviations`. A required member that is missing or unreadable stays empty and is not listed there. `ParseLenient` is for tools that display a faulty credential. A verifier uses `Parse`.

## SD-JWT

```go
import "github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"

token, err := sdjwt.Parse(raw)
if err != nil {
    return err
}
if err := sdjwt.Verify(token, issuerKey); err != nil {
    return err
}
if err := sdjwt.ValidateVCType(token.Header); err != nil {
    return err
}
if err := token.ValidAt(time.Now()); err != nil {
    return err
}
err = sdjwt.VerifyKeyBinding(token, sdjwt.KeyBinding{
    Audience: clientID,
    Nonce:    nonce,
    MaxAge:   5 * time.Minute,
})
if err != nil {
    return err
}
```

| Function | Check |
|---|---|
| `Parse` | The structure and the Disclosures (RFC 9901 §7.1) |
| `Verify` | The signature of the Issuer-signed JWT |
| `Token.ValidAt` | `exp` and `nbf` |
| `VerifyKeyBinding` | The Key Binding JWT of a presentation (RFC 9901 §7.3) |
| `ValidateVCType` | The `typ` header of an SD-JWT VC, so that another JWT signed with the same issuer key does not pass as a credential |

RFC 9901 §4 requires a final `~`. `Parse` also accepts an SD-JWT without it and adds a note to `Token.Warnings`.

`Token.ResolvedClaims` holds the claims with every Disclosure applied. `Token.IssuerCertificates` returns the certificates of the `x5c` header. The chain is not validated. `Token.ConfirmationKey` returns the key of the `cnf` claim.

`VerifyKeyBinding` reads the `cnf` key from the credential. Call it after `Verify` succeeded, because only the issuer signature makes that key authentic. `KeyBinding.MaxAge` is the maximum age of the Key Binding JWT, measured from its `iat` claim. With a `MaxAge` of 0 only a Key Binding JWT created within the clock skew passes.

`ValidAt` of both packages allows a clock skew of 1 minute. It fails on an unreadable time claim.

`ParseLenient` reads an SD-JWT that breaks RFC 9901 and lists the violations in `Token.Deviations`. It is for tools that display a faulty credential. A verifier uses `Parse`.

## Errors

The verification functions return an error. `errors.Is` with `ErrSignature`, `ErrExpired` or `ErrNotYetValid` tells the cases apart. Both packages have these 3 errors. `pkg/mdoc` also has `ErrNoDeviceKey` for an MSO without a device key. `VerifyKeyBinding` also returns `ErrAudience`, `ErrNonce` and `ErrSDHash`.

## Delegate SD-JWT

`pkg/sdjwt/delegate` reads, verifies and creates a Delegate SD-JWT. It follows draft-ietf-oauth-delegate-sd-jwt-00. `delegate.Verify` runs the verifier steps of §6 of the draft. The package is experimental. Its API can change with the draft in a minor release. See [Delegation with a Delegate SD-JWT](wallet/presenting.md#delegation-with-a-delegate-sd-jwt).
