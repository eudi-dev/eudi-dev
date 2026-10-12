# Test certificate examples

This public reference set contains the wallet root CA, the provider intermediates, the relying party access CA, the registrar CA and the signing certificates described in [test certificates](test-certificates.md#certificate-contents). Each entry has the complete PEM certificate and its decoded X.509 contents (serial number, validity, public key, extensions and signature).

The certificates are generated with the wallet signing APIs at source revision [`b550ccc2b066`](https://github.com/eudi-dev/eudi-dev/tree/b550ccc2b06603fb29e871ffbbaeba6796834f02). The reference issuer is `https://eudi-test.dev`, the country is `NL`, and the trusted list operator is `EUDI Dev Wallet`. The names and registration identifiers are fictional. The public certificates carry no official trust.

The decoded values below are from these reference PEM files. A running wallet, including the public demo, has its own keys, serial numbers, timestamps and signatures. The [profile tables](test-certificates.md#certificate-contents) describe the certificate profiles and configurable values. The [localhost special case](test-certificates.md#localhost-special-case) lists the local issuer URL and its certificate URLs.

From the repository root, inspect a certificate with:

```bash
openssl x509 -in docs/assets/test-certificates/pid-signer.pem -noout -text
openssl asn1parse -in docs/assets/test-certificates/pid-signer.pem -i
```

OpenSSL prints QCStatements extension values as binary text, so their payloads are decoded separately below.

## Root CA

[Complete PEM certificate](assets/test-certificates/root-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:62:d3:99:03:97:69:08:09:86:63:f2:10:f7:2a:b6
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:02:26 2026 GMT
            Not After : Oct  9 21:02:26 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:0e:27:17:7c:21:5b:fd:60:93:08:d6:b0:4f:11:
                    85:6d:08:41:26:f2:ae:83:03:94:df:02:a6:86:09:
                    ff:d8:20:17:03:d9:f8:87:f7:16:ac:49:5e:7e:57:
                    1c:ea:e4:93:05:ce:90:9b:3d:fd:81:e6:04:49:28:
                    ef:bf:84:3b:f7
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:f3:ce:ee:7a:c9:d7:5d:67:3a:0b:ad:74:cf:
        29:41:e7:5c:1a:d0:e0:5a:2a:e0:91:6a:18:7b:02:a2:6b:61:
        08:02:20:0e:73:02:13:b5:da:9e:2c:43:11:bb:b9:89:fe:22:
        fd:5b:95:80:a0:2c:ab:6e:95:81:73:f3:3a:ee:f0:7d:74
```

</details>

## PID provider CA

[Complete PEM certificate](assets/test-certificates/pid-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f4:06:3c:9e:44:d7:b7:a3:37:d4:ed:02:e4:ba:24:c9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:02:26 2026 GMT
            Not After : Oct 11 21:02:26 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test pid CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:e7:c8:c5:4a:8b:ee:fe:48:d7:1c:db:a3:f8:21:
                    0c:5f:5a:8b:76:56:a8:32:7e:a6:6c:0f:a6:43:96:
                    a5:51:39:ca:c3:30:4a:8b:13:70:7b:81:e1:d9:5a:
                    75:4f:6c:9f:47:9b:97:af:43:16:28:e5:24:0d:ce:
                    b2:e5:dd:bb:df
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                9D:21:65:E9:1F:8A:A5:F4:5A:93:3C:A3:E8:0D:24:8E:80:93:A5:E4
            X509v3 Authority Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:aa:8c:7c:2a:34:41:28:8e:f1:42:9e:e9:aa:
        2b:0c:b7:9f:87:20:85:25:61:f1:45:99:a8:ab:61:18:bd:d4:
        07:02:21:00:b4:aa:e8:9d:68:d7:ad:06:c1:64:82:cd:97:97:
        76:bb:1e:27:3d:01:5b:f6:32:f9:6a:39:b8:12:90:6a:75:30
```

</details>

## Wallet provider CA

[Complete PEM certificate](assets/test-certificates/wallet-provider-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            64:fa:0a:67:c8:43:0a:39:0b:bf:1e:8d:76:dc:f5:1f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:03:18 2026 GMT
            Not After : Oct 11 21:03:18 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test wallet CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9f:ec:86:62:bf:71:3b:ad:f4:34:d6:8b:d7:71:
                    24:6c:76:cb:f4:8d:06:a9:b4:d8:98:1d:34:7d:a1:
                    fd:cb:3b:b5:e2:47:06:f8:b6:a1:26:59:6c:ef:09:
                    29:09:6d:ab:8b:92:e8:9e:6f:d9:18:10:58:58:8f:
                    3d:3a:dd:34:03
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                77:5F:3D:AC:11:17:22:8F:B3:77:05:A8:44:CE:03:45:7E:D8:74:83
            X509v3 Authority Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:a3:7e:65:ec:96:83:89:29:28:51:76:f8:75:
        db:58:f9:e2:1f:d5:a8:37:77:dc:0e:a2:f6:be:4f:b3:f9:ae:
        99:02:21:00:ce:1f:d8:2f:1c:b8:47:21:00:24:54:c8:e6:a0:
        2d:2d:30:a5:08:1f:dd:5a:23:5c:91:57:5a:11:69:df:66:88
```

</details>

## EAA provider CA

[Complete PEM certificate](assets/test-certificates/eaa-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            97:ea:a4:04:02:8c:56:bd:77:dc:32:e6:85:27:5e:b6
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:03:18 2026 GMT
            Not After : Oct 11 21:03:18 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test eaa CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b2:3b:2a:5b:04:31:79:de:e1:ef:42:7b:2c:6c:
                    da:63:79:49:68:b0:6b:63:df:52:f5:d3:fb:ff:2a:
                    0c:15:5a:d2:ba:df:70:ab:0f:5b:03:c4:66:59:5b:
                    56:3d:f7:18:91:fb:de:88:c8:14:28:80:c3:a7:69:
                    94:90:fb:90:f6
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                57:72:6A:A7:1B:C4:11:E1:8B:EA:45:21:BC:10:3E:0C:53:81:3F:6F
            X509v3 Authority Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:9c:48:30:b0:13:ff:91:28:ae:f9:24:af:51:
        14:91:fe:e9:95:81:ad:44:3e:e1:e1:6e:96:67:79:ae:9e:7a:
        22:02:21:00:a3:a5:cf:86:e4:5c:44:c4:5a:af:e9:42:1b:77:
        01:38:d4:12:c5:45:e4:e6:f6:4a:b8:3d:e5:46:fd:84:fc:50
```

</details>

## Relying party access CA

[Complete PEM certificate](assets/test-certificates/relying-party-access-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            e1:36:48:e7:52:21:91:8d:aa:5b:6d:f8:de:93:cf:aa
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct 12 20:02:52 2026 GMT
            Not After : Oct  9 21:02:52 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:17:11:e0:2a:8e:8e:e5:14:9d:1c:09:b8:c0:b8:
                    12:ba:24:97:e2:30:8b:a5:ad:40:46:47:4c:91:e0:
                    68:91:51:31:f2:b3:5e:55:2d:75:ee:aa:4b:8a:3e:
                    19:d7:90:f6:0d:bd:ae:98:3a:86:6e:7e:8d:c6:08:
                    33:42:23:ce:b9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                B0:9C:5B:3F:3A:8D:A5:3B:7B:E7:D1:C2:63:93:1E:29:A6:35:16:51
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e9:8a:e9:49:d7:58:30:50:98:46:44:14:c7:
        ce:05:5d:04:46:1e:fc:aa:f5:76:1c:4b:53:0e:3b:33:78:64:
        f7:02:20:39:4d:32:fe:d3:80:4d:b2:be:55:f3:4f:67:65:e2:
        c3:03:a5:99:92:5f:ba:84:f2:aa:ea:70:1f:bc:6a:fa:0c
```

</details>

## Registrar CA

[Complete PEM certificate](assets/test-certificates/registrar-ca.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            fe:dd:82:22:4b:85:a6:b6:b3:71:86:1b:25:b0:7d:d0
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Validity
            Not Before: Oct 12 20:02:26 2026 GMT
            Not After : Oct  9 21:02:26 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d6:7f:43:a7:81:46:40:1c:94:fe:37:89:45:f6:
                    90:ef:21:e5:9e:11:10:01:d1:2d:3b:42:f6:38:93:
                    51:38:6a:91:d7:03:35:ef:f2:8d:1e:ef:9b:a0:b2:
                    c9:b1:9c:b5:26:d8:03:55:1b:ae:e7:1c:4c:a3:13:
                    76:5d:dc:a2:93
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                0C:14:F7:E6:27:05:7B:11:84:2D:58:D0:51:64:1A:CB:B6:5C:9C:67
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:14:20:57:ab:50:c6:6d:2b:5c:4b:b4:c3:50:d7:
        d6:4e:dd:75:22:c3:69:09:e8:d4:5c:e6:bb:d2:23:80:b2:fd:
        02:20:24:06:fb:d1:ba:d3:b7:b5:9f:b3:ca:8d:4c:37:f9:be:
        1d:f8:c3:6e:f9:1d:c2:c4:2e:29:32:35:60:c8:a7:78
```

</details>

## PID signer

[Complete PEM certificate](assets/test-certificates/pid-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            eb:9e:db:a4:67:f6:2d:60:eb:de:e1:3d:89:26:7d:ef
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test pid CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct 12 20:02:26 2026 GMT
            Not After : Oct 12 21:02:26 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet PID Provider (pid), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f0:f7:54:c6:85:95:1a:f9:7b:0f:be:86:91:26:
                    49:3c:4f:da:9d:47:8f:99:0e:ab:55:ba:35:41:67:
                    5b:49:a7:cc:fb:03:6d:e9:57:d5:10:01:8b:3d:10:
                    f5:7e:3d:1e:23:35:e0:6e:4f:8b:43:fa:8d:af:8c:
                    e7:77:e8:30:26
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                F0:BA:F1:7B:5A:F0:53:F5:E8:2C:19:3E:5C:D0:64:AD:E5:59:13:1E
            X509v3 Authority Key Identifier: 
                9D:21:65:E9:1F:8A:A5:F4:5A:93:3C:A3:E8:0D:24:8E:80:93:A5:E4
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/pid/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/pid/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
            X509v3 Extended Key Usage: critical
                1.0.18013.5.1.2
            qcStatements: 
                0.0......F..0.......N..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:65:80:03:3f:93:d7:b4:c1:19:fa:d7:a1:bd:f6:
        41:f4:d5:a3:46:c2:09:f1:ba:82:e3:c5:1a:48:dc:30:7a:ed:
        02:20:49:a1:28:f3:cc:1e:e2:bc:77:a8:8e:39:c0:95:3b:3d:
        b9:3e:ae:9d:47:9e:39:c2:60:b8:79:bb:82:25:cd:df
```

QCStatements extension value:

```text
DER: 30153013060604008e4601063009060704008bec4e0101
    0:d=0  hl=2 l=  21 cons: SEQUENCE
    2:d=1  hl=2 l=  19 cons:  SEQUENCE
    4:d=2  hl=2 l=   6 prim:   OBJECT            :0.4.0.1862.1.6
   12:d=2  hl=2 l=   9 cons:   SEQUENCE
   14:d=3  hl=2 l=   7 prim:    OBJECT            :0.4.0.194126.1.1
```

</details>

## Wallet provider signer

[Complete PEM certificate](assets/test-certificates/wallet-provider-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            d0:6d:95:be:df:b1:c0:8a:d5:d1:ba:3c:1d:4e:78:07
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test wallet CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct 12 20:03:18 2026 GMT
            Not After : Oct 12 21:03:18 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet Provider (wallet-provider), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:05:b4:01:3c:79:5c:6d:aa:24:29:3d:11:3d:20:
                    85:42:5e:c9:a0:07:c7:5b:45:60:84:ae:30:b9:fb:
                    1d:61:1d:ac:61:bf:76:72:28:58:a4:6c:12:10:fe:
                    1e:37:62:b9:2c:df:ee:8c:7a:3f:d5:95:c4:57:fd:
                    62:09:e7:49:85
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                3B:8F:E7:D1:F4:A3:0C:14:AE:5A:DA:59:0F:54:E4:6C:28:0C:25:48
            X509v3 Authority Key Identifier: 
                77:5F:3D:AC:11:17:22:8F:B3:77:05:A8:44:CE:03:45:7E:D8:74:83
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/wallet/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/wallet/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
            qcStatements: 
                0.0......F..0.......N..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e0:87:ae:c9:08:e9:54:e2:69:6f:6d:68:af:
        2e:dd:d9:fc:e2:d3:0a:ab:a6:31:78:e1:6a:d0:8b:ee:93:7f:
        aa:02:20:05:3b:d0:ea:eb:df:0b:eb:ec:15:f6:80:4a:df:fd:
        33:d5:40:3f:51:93:39:8c:3b:ab:0d:be:3b:fd:02:e4:33
```

QCStatements extension value:

```text
DER: 30153013060604008e4601063009060704008bec4e0102
    0:d=0  hl=2 l=  21 cons: SEQUENCE
    2:d=1  hl=2 l=  19 cons:  SEQUENCE
    4:d=2  hl=2 l=   6 prim:   OBJECT            :0.4.0.1862.1.6
   12:d=2  hl=2 l=   9 cons:   SEQUENCE
   14:d=3  hl=2 l=   7 prim:    OBJECT            :0.4.0.194126.1.2
```

</details>

## EAA signer

[Complete PEM certificate](assets/test-certificates/eaa-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            52:2e:fa:38:6f:70:a5:85:65:73:e3:a3:09:65:b2:07
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test eaa CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct 12 20:03:18 2026 GMT
            Not After : Oct 12 21:03:18 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet EAA Provider (eaa), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:72:84:38:03:2f:ba:4e:ff:1d:b1:4f:a9:0d:0c:
                    31:e2:f3:d1:ac:83:9d:49:db:ac:7d:a9:98:ff:9d:
                    87:c2:c5:d1:89:18:41:d7:27:fd:d5:9e:3e:01:aa:
                    32:00:6f:53:c4:4b:90:5b:e8:c7:6e:b0:a8:bd:34:
                    59:7b:89:07:55
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                93:B2:B4:21:29:BC:E2:F5:2D:25:6E:F6:AA:91:D9:EC:28:0B:79:FE
            X509v3 Authority Key Identifier: 
                57:72:6A:A7:1B:C4:11:E1:8B:EA:45:21:BC:10:3E:0C:53:81:3F:6F
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/eaa/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/eaa/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
            X509v3 Extended Key Usage: critical
                1.0.18013.5.1.2
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:99:cd:de:e1:43:46:1b:6f:04:c5:1d:7a:7a:
        a3:e4:59:15:f6:94:98:3d:7f:5b:4a:d1:86:ab:ff:7a:c4:9d:
        79:02:20:5b:70:27:72:22:f5:09:d1:47:02:0d:87:9b:78:f4:
        78:05:9e:b5:a8:b5:ca:57:e4:f2:38:d7:f7:ca:bb:91:d0
```

</details>

## Access signer of the demo issuer

[Complete PEM certificate](assets/test-certificates/access-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            de:7b:15:04:12:f4:77:41:37:0a:e2:df:f0:dc:e5:25
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct 12 20:03:22 2026 GMT
            Not After : Oct 12 21:03:22 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, OU=issuance, CN=EUDI Dev Demo Issuer, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:16:ce:4e:f6:b7:ae:35:23:4f:d3:2e:a7:a0:9e:
                    03:bb:41:0e:48:95:aa:bb:3b:55:d9:28:a4:52:c5:
                    e1:1a:e8:c6:f6:84:63:83:80:24:05:81:5f:73:e5:
                    1a:6a:fc:45:8d:72:c9:6a:46:1d:a7:9e:96:d7:ea:
                    c8:61:2f:29:b8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                F1:63:91:8F:CA:51:EE:EB:FE:99:A2:63:3F:F9:3E:74:BD:D9:25:CD
            X509v3 Authority Key Identifier: 
                B0:9C:5B:3F:3A:8D:A5:3B:7B:E7:D1:C2:63:93:1E:29:A6:35:16:51
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev/support
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
            X509v3 Certificate Policies: 
                Policy: 0.4.0.194118.1.2
                  CPS: https://github.com/eudi-dev/eudi-dev/blob/main/docs/test-certificates.md
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:09:f5:f4:21:19:54:58:d7:4e:c9:3d:2e:a7:66:
        56:8d:7f:e1:d2:d2:8d:53:e9:ee:74:1c:11:f9:17:2c:85:83:
        02:20:10:ba:ca:10:61:c8:eb:9b:45:07:02:7b:37:46:52:b0:
        a0:ee:22:2b:2a:e4:91:1d:ff:25:20:67:e8:f4:75:be
```

</details>

## Access signer of the demo verifier

[Complete PEM certificate](assets/test-certificates/verifier-access-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f6:67:16:e6:15:61:67:62:1b:29:15:64:dd:5c:16:46
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct 12 20:03:29 2026 GMT
            Not After : Oct 12 21:03:29 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Verifier, OU=verification, CN=EUDI Dev Demo Verifier, organizationIdentifier=NTRNL-NLTEST.00000001
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:1a:4e:42:e2:4b:6d:07:48:80:6c:bb:3a:44:62:
                    51:11:59:14:7e:1b:bf:ea:5b:b2:c3:d7:73:2d:ff:
                    2f:d9:f7:25:0d:13:0b:89:af:2f:6c:08:78:d9:a7:
                    18:8a:bb:99:d5:68:e5:68:c0:56:9d:4b:9d:c8:74:
                    31:2d:19:a6:97
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                1C:C0:13:3C:E3:16:3E:1E:E6:91:B5:62:C3:E5:30:6A:12:8A:B6:97
            X509v3 Authority Key Identifier: 
                B0:9C:5B:3F:3A:8D:A5:3B:7B:E7:D1:C2:63:93:1E:29:A6:35:16:51
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev/support
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
            X509v3 Certificate Policies: 
                Policy: 0.4.0.194118.1.2
                  CPS: https://github.com/eudi-dev/eudi-dev/blob/main/docs/test-certificates.md
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:22:98:9b:a5:6d:e9:71:ff:b5:33:0e:21:ca:86:
        46:40:0e:43:a1:7d:43:be:6f:b9:5a:ce:1b:3a:53:1d:41:23:
        02:20:45:32:b1:95:14:dc:21:77:90:22:8d:70:15:85:20:c7:
        c1:98:c3:94:af:a4:68:93:d7:1c:02:a1:5c:c5:1e:a2
```

</details>

## Registrar signer

[Complete PEM certificate](assets/test-certificates/registrar-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            95:a2:a4:3e:c3:66:d6:9f:d9:a3:ea:f1:91:94:a8:31
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Validity
            Not Before: Oct 12 20:02:26 2026 GMT
            Not After : Oct 12 21:02:26 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test Registrar, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:53:b8:cf:53:0d:1a:1f:ac:c3:46:af:44:bf:09:
                    9c:f8:70:9e:24:ca:97:92:c0:2d:fb:f5:57:09:81:
                    09:4f:47:b1:55:63:5d:79:96:49:a9:ca:97:df:d2:
                    25:3f:56:f2:4c:d8:c8:13:55:d6:34:61:1f:72:17:
                    88:c3:ff:e3:1e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                0D:2B:44:A4:D6:10:D5:42:27:9A:A7:31:16:8F:D6:23:43:45:4B:38
            X509v3 Authority Key Identifier: 
                0C:14:F7:E6:27:05:7B:11:84:2D:58:D0:51:64:1A:CB:B6:5C:9C:67
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:80:ab:9a:1e:99:08:66:cd:4f:70:bd:91:b0:
        34:6d:4d:13:34:21:6e:01:38:32:e5:06:aa:3c:e7:bb:a9:fc:
        60:02:21:00:ec:43:2a:31:75:30:6c:25:54:bd:6d:3f:fd:14:
        6b:7a:60:e1:2b:a2:14:07:e3:36:a8:8c:8a:3d:de:c1:6d:d0
```

</details>

## Status signer

[Complete PEM certificate](assets/test-certificates/status-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            63:1a:df:4c:ef:13:5a:a2:fd:63:95:88:1c:3a:4f:21
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:03:07 2026 GMT
            Not After : Oct 12 21:03:07 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Status List Signer, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:0e:82:1b:f8:ca:17:21:64:bc:21:2d:24:ff:be:
                    c4:7f:cb:76:81:80:e2:d7:c5:57:95:88:96:f8:f9:
                    af:c9:bb:24:c9:d0:a7:28:68:20:ca:9c:24:ab:16:
                    4b:18:c4:ce:e6:7b:12:1e:e5:69:df:f5:c1:4f:4f:
                    84:6b:79:e6:ec
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                72:A0:3A:82:BC:9D:9A:81:82:11:67:F2:3E:D1:DB:82:34:68:4E:28
            X509v3 Authority Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:92:a8:bb:76:6b:f4:b8:18:45:5c:e0:95:b5:
        7c:69:42:b7:7f:f4:de:43:42:d2:c0:8b:50:1e:fe:40:66:73:
        c6:02:21:00:d9:c0:04:dc:fc:aa:de:5f:f0:41:09:6c:06:8b:
        95:75:14:65:b1:c0:67:60:7c:bc:b9:ea:ae:00:1d:13:80:6d
```

</details>

## Trusted list signer

[Complete PEM certificate](assets/test-certificates/trust-list-signer.pem)

<details>
<summary>Full decoded certificate contents</summary>

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            49:1b:c4:aa:38:b4:d2:ae:85:ad:03:91:42:a8:dd:12
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct 12 20:03:07 2026 GMT
            Not After : Oct 12 21:03:07 2027 GMT
        Subject: C=NL, O=EUDI Dev Wallet, CN=EUDI Dev Test List Operator, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:0f:1f:1f:de:9f:ef:0f:dc:42:cb:1c:87:83:1f:
                    32:8f:92:09:0d:78:9e:cc:c6:3d:83:e2:f6:d6:22:
                    db:6b:d9:c0:97:cd:4d:0e:1d:93:ec:fa:b2:65:98:
                    b9:12:3a:97:c7:9f:78:e7:b1:16:00:bd:92:96:90:
                    0d:b9:5e:93:b1
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                D8:02:18:09:57:9B:88:13:EB:D4:02:49:9B:91:60:6A:24:7D:99:42
            X509v3 Authority Key Identifier: 
                E0:AE:4D:AD:EE:7D:45:9B:7E:02:E4:2C:82:EA:BA:F2:D8:FE:F9:6E
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/eudi-dev/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:60:28:d5:46:a0:89:11:27:2b:10:13:ab:cd:03:
        05:df:02:cf:d8:21:32:f9:65:0e:b7:bc:93:2c:51:dc:a9:02:
        02:20:6d:68:79:87:c4:7b:3d:09:68:97:39:64:50:36:b1:33:
        6f:1f:c4:a9:f5:a5:f2:1e:bc:18:12:9a:b3:fa:1b:82
```

</details>
