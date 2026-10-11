# Test certificates and EUDI profiles

The generated certificates identify test services. Their organization names, addresses and registration numbers are fictional. All keys are software keys. The access certificate policy describes the test profile and makes no certification claim.

## Specification versions

Checked on 1 October 2026 against [ARF v3.0.0](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/v3.0.0), [CIR (EU) 2026/1731](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32026R1731) and the Commission's [standards tracker](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications). Where the regulation pins a version or adapts a specification, the regulation takes precedence over newer standalone versions.

| Area | Version used | Source |
| --- | --- | --- |
| Issuance | OpenID4VCI 1.0 Final | [Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| Presentation | OpenID4VP 1.0 Final | [Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| High assurance profile | HAIP 1.0 Final | [Specification](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) |
| PID and wallet provider certificates | ETSI TS 119 412-6 V1.1.1, September 2025 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/11941206/01.01.01_60/ts_11941206v010101p.pdf) |
| Certificate issuer names | ETSI EN 319 412-2 V2.4.1, June 2025 | [Specification](https://www.etsi.org/deliver/etsi_en/319400_319499/31941202/02.04.01_60/en_31941202v020401p.pdf) |
| Legal person subjects | ETSI EN 319 412-3 V1.3.1, September 2023 | [Specification](https://www.etsi.org/deliver/etsi_en/319400_319499/31941203/01.03.01_60/en_31941203v010301p.pdf) |
| QCStatements | ETSI EN 319 412-5 V2.5.1, June 2025 | [Specification](https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.05.01_60/en_31941205v020501p.pdf) |
| Access certificate policy | ETSI TS 119 411-8 V1.1.1, October 2025 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf) |
| EUDI issuance profile | ETSI TS 119 472-3 V1.1.1, March 2026 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf) |
| EUDI presentation profile | ETSI TS 119 472-2 V1.2.1, March 2026 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf) |
| Attestation structure | ETSI TS 119 472-1 V1.2.1, February 2026 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947201/01.02.01_60/ts_11947201v010201p.pdf) |
| Registration information | ETSI TS 119 475 V1.2.1, March 2026 | [Specification](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf) |
| Trusted entity lists | ETSI TS 119 602 V1.1.1, November 2025 | [Specification](https://www.etsi.org/deliver/etsi_TS/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) |
| Trusted list signatures | ETSI TS 119 182-1 V1.2.1, July 2024 | [Specification](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf) |
| EU PID attributes | PID Rulebook v1.7 | [Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md) |
| German PID attributes | German PID Rulebook 1.0.0 consultation draft | [Rulebook](https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/) |

TS 119 412-6 V1.1.1 clauses 4.4.3 and 5.1 require the PID and wallet provider certificates' AIA to identify an intermediate CA certificate.

OpenID4VCI 1.0 is the baseline, with 1.1 available as an optional draft feature level. The German PID rulebook is a consultation draft, so its national attributes may change.

## Signing roles

| Role | Material |
| --- | --- |
| PID issuance | Wallet issuer key, PID provider leaf with QcType `0.4.0.194126.1.1` |
| Other credential issuance | One key per provider role and a provider leaf |
| Wallet and key attestations | Separate wallet provider key and leaf with QcType `0.4.0.194126.1.2` |
| Signed issuer metadata and demo issuer requests | Access key and certificate of the demo issuer, from the registrar like any access certificate |
| Demo verifier requests | Access key and certificate of the demo verifier, from the registrar like any access certificate |
| Registered relying parties | Access certificates issued for a CSR, with policy `0.4.0.194118.1.2`, signed by the relying party access CA (see [registrar](wallet/registrar.md)) |
| Registrar responses and registration certificates | Separate registrar key and signing certificate under the registrar CA |
| Credential status | Separate status key and signing certificate |
| Trusted lists | Separate list operator key and signing certificate |

The generated root CA permits one intermediate CA. Credential and wallet provider signing certificates use a provider intermediate for their role and country. Each provider role has its own signing key and provider intermediate. The roles are the categories `pid`, `qeaa`, `pub-eaa` and `eaa`, `wallet` for the wallet provider, `tl-<8 hex digits>` for a credential type with its own trusted list, and `unlisted` for unlisted credentials. So a trusted list anchors only the credentials signed for it. No list names the `unlisted` intermediate. Status and trusted list signing certificates are signed directly by the root.

Two more self-signed CAs sit beside the root. They have the subject organization `EUDI Dev Test CA`, the same key usage as the root and basic constraints `CA:TRUE, pathlen:0`:

- The **relying party access CA** (`CN=EUDI Dev Test Relying Party Access CA`) signs every access certificate of the registrar, including those of the demo issuer and the demo verifier. The wallet's `access-ca` list names it.
- The **registrar CA** (`CN=EUDI Dev Test Registrar CA`) signs the registrar's signing certificate. The wallet's `registrar` list names it.

Neither chains to the root. The root anchors credential issuers, and a visitor's CSR must never produce a certificate under it. Credential signer leaves carry the ISO/IEC 18013-5 document signing purpose. The credential signer's subject country matches the credential's `issuing_country`, with `NL` as the default. Its AIA and CRL URLs identify the provider intermediate and its revocation list.

In the PID Rulebook, the trust anchors are notified provider keys. ISO/IEC 18013-5:2021 Annex B uses a direct IACA hierarchy whose root has a path length of zero. The generated root has a path length of one, and the OpenID suite reports this as an ISO profile warning. Certificate signatures and trust paths are checked separately.

A configured root with a path length of zero signs provider leaves directly. That chain has no provider intermediate, so it lacks the retrieval path that clause 4.4.3 requires. The wallet uses the configured CA's keys and chain, and the trusted lists name only the signing leaves.

PID signatures include the protected certificate references that CIR (EU) 2026/1731 Annex I requires. SD-JWT uses `x5u` and `x5t#S256`. Mdoc uses `x5u` and SHA-256 `x5t`. The `x5u` URLs contain the certificate fingerprint and return PEM for JOSE or DER for COSE. The protected `iat` records the signing time, separate from the credential's issuance time. Published certificates stay available after renewal. Offline issuance has no certificate hosting endpoint.

Certificates are stored in the selected storage backend. A different subject, changed issuer URL or renewal produces a certificate with a new serial number. Memory storage keeps certificates for the lifetime of that store. With a seed, the wallet derives the same keys after a restart. A fresh memory store still generates certificates with new serial numbers.

## Certificate contents

The [complete certificate examples](test-certificate-examples.md) contain public PEM files and full decoded X.509 contents for the root, each provider intermediate and every signing role. The examples use `https://eudi-test.dev`, country `NL` and the default provider names. Serial numbers, validity timestamps, public keys, key identifiers and signatures are the values from that reference set. A separately generated wallet has its own values.

### Shared fields

| Field | Generated value |
| --- | --- |
| Version | X.509 v3 |
| Public key | EC P-256, `id-ecPublicKey` (`1.2.840.10045.2.1`), curve `prime256v1` (`1.2.840.10045.3.1.7`) |
| Signature algorithm | ECDSA with SHA-256 (`1.2.840.10045.4.3.2`) |
| Serial number | Random positive integer |
| `notBefore` | Generation time minus one hour |
| `notAfter` | Generation time plus 3650 days for the root, 1825 days for provider CAs, 365 days for signing leaves. A child certificate's expiry is capped at its issuer's expiry |
| Subject key identifier (`2.5.29.14`) | SHA-1 of the subject public key BIT STRING value, non-critical |
| Authority key identifier (`2.5.29.35`) | Issuer's subject key identifier, non-critical, present on issued certificates |
| Issuer alternative name (`2.5.29.18`) | URI `https://github.com/dominikschlosser/eudi-dev`, non-critical |

The root's subject and issuer are both `C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA`. It has critical key usage `keyCertSign, cRLSign` (`2.5.29.15`) and critical basic constraints `CA:TRUE, pathlen:1` (`2.5.29.19`).

The provider intermediates and signing leaves have `C=NL` and organization identifier `NTRNL-NLTEST.00000000` (`2.5.4.97`) in this reference configuration. For credential signers and their provider CAs, the country and identifier follow the credential's `issuing_country`. The trusted list signer uses the supplied country and operator name. Its organization is `EUDI Dev Wallet` in this reference set. The access signer of the demo verifier has organization `EUDI Dev Test Verifier` and identifier `NTRNL-NLTEST.00000001`, so it is registered as its own relying party. An access signer's common name is the trade name of its registration (ETSI TS 119 411-8 V1.1.1 GEN-6.1.1-04, ARF RPRC_06). The other intermediates and leaves use organization `EUDI Dev Test Provider`.

### Subjects and issuers

| Certificate | Subject common name | Issuer |
| --- | --- | --- |
| PID provider CA | `EUDI Dev Test pid CA NL` | Root CA |
| Wallet provider CA | `EUDI Dev Test wallet CA NL` | Root CA |
| QEAA, PuB-EAA and EAA provider CAs | `EUDI Dev Test qeaa CA NL`, `EUDI Dev Test pub-eaa CA NL`, `EUDI Dev Test eaa CA NL` | Root CA |
| Provider CA of a credential type with its own trusted list | `EUDI Dev Test tl-<8 hex digits> CA NL` | Root CA |
| Provider CA of unlisted credentials | `EUDI Dev Test unlisted CA NL` | Root CA |
| PID signer | `EUDI Dev Wallet PID Provider (pid)` | PID provider CA |
| Wallet provider signer | `EUDI Dev Wallet Provider (wallet-provider)` | Wallet provider CA |
| QEAA, PuB-EAA and EAA signers | `EUDI Dev Wallet QEAA Provider (qeaa)`, `EUDI Dev Wallet PuB-EAA Provider (pub-eaa)`, `EUDI Dev Wallet EAA Provider (eaa)` | Provider CA of the category |
| Signer of a credential type with its own trusted list | `<entity name> (tl-<8 hex digits>)` | Provider CA of that list |
| Signer of unlisted credentials | `EUDI Dev Wallet Issuer` | Provider CA of unlisted credentials |
| Access signer of the demo issuer | `EUDI Dev Demo Issuer`, organizational unit `issuance` | Relying party access CA |
| Access signer of the demo verifier | `EUDI Dev Demo Verifier`, organizational unit `verification` | Relying party access CA |
| Registrar signer | `EUDI Dev Test Registrar` | Registrar CA |
| Status signer | `EUDI Dev Status List Signer` | Root CA |
| Trusted list signer | `EUDI Dev Test List Operator` | Root CA |

Provider intermediates have critical key usage `keyCertSign, cRLSign` and critical basic constraints `CA:TRUE, pathlen:0`. Signing leaves have critical key usage `digitalSignature` and omit basic constraints. Only credential signers carry the critical extended key usage `mdlDS` (`1.0.18013.5.1.2`). The other signing roles have no extended key usage extension.

### Provider and access indicators

The PID and wallet provider signers have a non-critical QCStatements extension (`1.3.6.1.5.5.7.1.3`). It contains one QcType statement (`0.4.0.1862.1.6`) with the purpose below. The encoding follows EN 319 412-5 V2.5.1 clause 4.2.3. TS 119 412-6 V1.1.1 clauses 4.5 and 5.2 and Annex A define the purpose identifiers.

| Signer | QcType purpose | QCStatements extension value, DER hexadecimal |
| --- | --- | --- |
| PID | `0.4.0.194126.1.1` | `30153013060604008e4601063009060704008bec4e0101` |
| Wallet provider | `0.4.0.194126.1.2` | `30153013060604008e4601063009060704008bec4e0102` |

Every access certificate has a non-critical certificate policies extension (`2.5.29.32`) with policy `0.4.0.194118.1.2`, the legal person access policy identifier from TS 119 411-8 V1.1.1 clause 5.3. Its CPS qualifier (`1.3.6.1.5.5.7.2.1`) is `https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md`. Access certificates have critical basic constraints `CA:FALSE` and last one year.

### Retrieval, revocation and alternative names

The examples use the public demo origin `https://eudi-test.dev`. A configured HTTPS `--base-url` sets the issuer URL directly, including any path prefix. Each listed extension is non-critical.

| Certificate | AIA `caIssuers` (`1.3.6.1.5.5.7.1.1`) | CRL distribution point (`2.5.29.31`) | Subject alternative names (`2.5.29.17`) |
| --- | --- | --- | --- |
| PID signer | `https://eudi-test.dev/api/certificates/providers/pid/NL.der` | `https://eudi-test.dev/api/crl/providers/pid/NL` | DNS `eudi-test.dev`, URI `https://eudi-test.dev` |
| Wallet provider signer | `https://eudi-test.dev/api/certificates/providers/wallet/NL.der` | `https://eudi-test.dev/api/crl/providers/wallet/NL` | DNS `eudi-test.dev`, URI `https://eudi-test.dev` |
| EAA signer | `https://eudi-test.dev/api/certificates/providers/eaa/NL.der` | `https://eudi-test.dev/api/crl/providers/eaa/NL` | DNS `eudi-test.dev`, URI `https://eudi-test.dev` |
| Provider intermediates | `https://eudi-test.dev/api/certificates/ca.der` | `https://eudi-test.dev/api/crl` | None |
| Trusted list signer | `https://eudi-test.dev/api/certificates/ca.der` | `https://eudi-test.dev/api/crl` | DNS `eudi-test.dev`, URI `https://eudi-test.dev` |
| Access signers of the demo issuer and the demo verifier | None | None | DNS `eudi-test.dev`, URI `https://eudi-test.dev/support` |
| Registrar signer | None | None | None |
| Status signer | None | `https://eudi-test.dev/api/crl` | None |
| Root CA, relying party access CA and registrar CA | None | None | None |

### Localhost special case

The default local issuer URL is `https://localhost:8086`. The wallet's HTTP UI and API use `http://localhost:8085`. With `--port <port>`, the local HTTPS issuer uses `<port+1>`. The certificate endpoint paths stay the same. For example, the local PID signer uses:

| Field | Local value |
| --- | --- |
| AIA `caIssuers` | `https://localhost:8086/api/certificates/providers/pid/NL.der` |
| CRL distribution point | `https://localhost:8086/api/crl/providers/pid/NL` |
| Subject alternative names | DNS `localhost`, URI `https://localhost:8086` |

`--docker` uses `host.docker.internal` as the local hostname. An HTTPS `--base-url`, such as `https://eudi-test.dev`, sets the issuer URL directly. The wallet reuses its stored issuer URL unless `--base-url` or `--docker` selects another one. See [wallet server URLs](wallet/serve.md) for serving and TLS options.

An IP-based issuer URL produces an IP subject alternative name instead of a DNS name. Offline issuance has no issuer URL, so certificates omit issuer-based AIA, CRL distribution points and subject alternative names. The fixed issuer contact URI is always present.

## Discovery and trusted lists

Both issuer discovery endpoints serve JSON by default and signed metadata when the `Accept` header prefers `application/jwt`. The signed form includes the access certificate in protected `x5c`, without the relying party access CA. The `issuer_info` array contains the registrar dataset and the registration certificate of the demo issuer, signed by the wallet's registrar. The demo issuer's registration takes the identifier, legal name and country from its access certificate. Every registration certificate has the policy `0.4.0.19475.3.1` in `policy_id` (ETSI TS 119 475 V1.2.1 OVR-6.1.3-01) and links this page as `certificate_policy`.

Trusted lists publish issuance certificates, their provider CAs and status signing certificates. This keeps credentials verifiable across country overrides and certificate renewal. Protected `iat` and `x5t#S256` headers carry the signing time and the certificate reference, as JAdES requires. Trusted lists use English language code `en`, whole second UTC timestamps, postal addresses and a self pointer. An unchanged list keeps its signed instance until it expires. Changed content or expiry advances the sequence number. Append `/history` to a trusted list URL to list its retained instances, then `/history/<sequence>` to retrieve one.

The schema is ETSI's [published JSON binding](https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities), revision `e84f427f0cde99513b574ef4b5a155ac4a38eab6` from 13 November 2025. The PID, wallet provider, access certificate provider, registration certificate provider and PuB-EAA lists follow Annexes D to H. TS 119 602 defines no list type for QEAA and EAA providers. Their lists use types of this project: `https://eudi-test.dev/LoTEType/QEAAProvidersList` and `https://eudi-test.dev/LoTEType/EAAProvidersList`. The list of trusted lists has the type `https://eudi-test.dev/LoTEType/ListOfTrustedLists`.

## Public PID provider comparison

The Bundesdruckerei [demo](https://demo.pid-provider.bundesdruckerei.de/) and [preproduction](https://preprod.pid-provider.bundesdruckerei.de/) deployments publish separate credential, status and access certificate material. Their PID paths use P-521 CAs and P-256 signing leaves. Signed issuer metadata uses an access certificate.

EUDI Dev uses P-256 keys for all of those roles.

## Test scope

The [OpenID Foundation conformance tests](https://openid.net/certification/) cover the selected OpenID4VP, OpenID4VCI and HAIP plans and variants. They do not cover every EUDI requirement. ETSI certificate profiles, trusted lists, registration information, PID rulebooks and ISO mdoc requirements must be checked against their own sources.

The toolkit tests protocol exchanges, signatures, certificate structure and generated data. The [registrar](wallet/registrar.md) simulates relying party registration, including revocation through a status list. Official trust, certified hardware protection and physical presence checks require the corresponding ecosystem services. Configured key attestation assurance values are simulated. See [spec compliance](spec-compliance.md) and [conformance results](conformance-results.md) for implemented checks and remaining protocol limits.
