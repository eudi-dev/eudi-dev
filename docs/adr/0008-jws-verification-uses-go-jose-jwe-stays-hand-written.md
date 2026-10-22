# JWS verification uses go-jose, JWE uses local code

All JWS verification uses `jws.Verify`, a wrapper around go-jose. Each caller passes the allowed algorithms when parsing, so the token cannot choose them. This gives `sdjwt`, `statuslist`, `wallet` and `demorp` the same signature checks.

## go-jose and the JWE

When go-jose encrypts, it derives the ECDH-ES key with empty `apu` and `apv` (`DeriveECDHES(algID, []byte{}, []byte{}, ...)` in its key generator). It has no option to set them. ISO 18013-7 Annex B requires the mdoc generated nonce in `apu` and the request nonce in `apv`. This wallet sends both for mdoc presentations. With go-jose, the header would carry the nonces but the key would come from empty values. The verifier could not decrypt any of these presentations.

go-jose reads `apu` and `apv` correctly when decrypting. Using the library only for decryption would mean 2 Concat KDF implementations to maintain. Both directions use the same local code.

The proxy also decrypts captured JWEs using content encryption keys from a key log, without the private key.

## Consequences

Before moving JWE to a library, check that it can set `apu` and `apv` when encrypting. The mdoc presentation tests cover this. The JWE tests alone do not.

Comments in the JWE code explain the key derivation and the AES-CBC-HS256 path, including PKCS#7 padding. A library that supports the required nonce handling could replace this code.
