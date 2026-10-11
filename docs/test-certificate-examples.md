# Test certificate examples

This public reference set contains the wallet root CA, the provider intermediates, the relying party access CA, the registrar CA and the signing certificates described in [test certificates](test-certificates.md#certificate-contents). Each entry has the complete PEM certificate and its decoded X.509 contents (serial number, validity, public key, extensions and signature).

The certificates are generated with the wallet signing APIs at source revision [`54d089706e31`](https://github.com/dominikschlosser/eudi-dev/tree/54d089706e314c897150c30f7464213b235dbf7e). The reference issuer is `https://eudi-test.dev`, the country is `NL`, and the trusted list operator is `EUDI Dev Wallet`. The names and registration identifiers are fictional. The public certificates carry no official trust.

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
            2b:fa:89:f8:38:2e:4b:fe:bf:c7:94:bb:81:4a:d4:f2
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  6 20:52:14 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:00:77:4b:42:ec:57:fb:07:b6:e5:78:a4:e1:0e:
                    ca:b5:2c:be:92:07:11:60:39:16:a1:28:32:51:70:
                    9b:75:f3:79:b8:bf:03:ac:b2:84:67:55:7e:91:5c:
                    ca:ae:c9:2a:7d:8b:6e:44:17:90:65:bc:40:22:b0:
                    4a:41:af:43:ec
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:b5:78:23:cd:e4:34:24:be:fd:c7:34:0a:54:
        c2:cf:56:c7:17:17:1c:b3:f0:75:75:18:a5:7c:82:92:69:57:
        0e:02:21:00:c1:d5:c2:59:ed:f1:43:9c:71:a4:86:81:66:61:
        03:e7:83:f9:0f:06:17:a8:e5:80:82:d5:2a:31:07:02:c2:90
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
            96:67:a7:1c:04:0b:a2:f6:c4:f2:99:65:8c:e2:88:2a
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  8 20:52:14 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test pid CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:5b:88:d5:88:a4:3a:56:4e:99:08:5e:b8:06:ab:
                    c2:3f:14:83:4b:99:a4:44:7e:5b:16:ba:5d:f1:47:
                    5b:b4:85:c8:ee:2f:45:ac:b8:5b:5c:36:c2:c3:c1:
                    bf:7a:b5:2b:a1:19:31:8d:dd:43:7d:39:1a:a9:66:
                    a1:ed:9f:09:2e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                7A:2A:83:1E:6D:C2:D5:5E:9F:FC:16:37:B6:8B:ED:D5:BA:ED:22:D6
            X509v3 Authority Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:47:c1:53:d6:80:b4:f2:22:28:50:a4:4b:0e:75:
        7c:31:b2:1f:96:e0:cb:44:c6:22:b9:95:d3:f4:3c:ff:a4:c5:
        02:21:00:f3:1f:5f:79:5a:24:40:e0:7f:31:c6:ba:64:b1:db:
        dd:b1:6a:d4:6d:14:76:a0:b0:57:a5:8c:fd:db:9a:b7:a6
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
            ff:4c:70:0c:f8:73:57:3b:b0:8f:6b:e5:55:37:92:6a
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  8 20:52:14 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test wallet CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a2:6b:aa:5e:32:25:c2:f1:12:53:ad:0c:b1:db:
                    9f:85:6d:b7:a2:73:a7:78:42:d9:a3:21:44:5d:7a:
                    78:25:16:41:93:cd:f2:76:c9:79:ba:0a:9c:9c:77:
                    98:dd:62:5a:17:81:ff:28:dc:fc:1a:0a:f3:a3:2c:
                    e2:72:90:12:a3
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AC:D1:00:F9:E9:54:14:78:A3:B0:67:BC:59:8D:DF:49:AC:C5:10:F5
            X509v3 Authority Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:3e:ba:20:e8:5a:f8:05:16:1d:33:37:5b:ce:9a:
        91:49:4a:f2:39:8a:0f:02:2a:c0:d2:e3:4e:5f:2f:8d:56:ce:
        02:20:20:d8:b0:ec:46:f2:b3:15:91:50:80:44:d8:c4:96:2b:
        9d:3e:8f:09:29:0a:78:28:63:c2:99:f0:78:5e:ec:1d
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
            15:db:e4:6b:65:ef:84:7f:5c:2d:30:2b:e4:19:51:23
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  8 20:52:14 2031 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test eaa CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:7e:c2:33:28:1c:44:b3:1d:cd:a3:42:c9:87:1b:
                    41:b3:26:b6:9f:2b:ae:99:5c:14:c9:ad:d1:46:b4:
                    91:89:2e:c6:bf:c9:de:78:3b:45:3c:cc:a1:28:57:
                    55:ff:78:41:a8:66:08:58:ca:bf:7d:5e:4c:a6:15:
                    c5:d4:c1:29:5b
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                28:44:CC:EA:91:15:89:9E:EF:4C:2F:68:F7:72:AF:BA:F7:8B:97:2E
            X509v3 Authority Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:b1:f6:83:54:d1:8a:7a:bd:d7:66:46:f8:71:
        04:02:0e:82:6a:a5:90:eb:77:fb:ff:fe:a1:19:ec:59:62:b8:
        a4:02:20:3e:54:f7:b0:7d:f0:6e:24:dd:78:a7:cb:b1:44:c8:
        92:91:d0:72:5c:71:aa:e7:23:ae:90:1e:0b:51:66:ed:8a
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
            49:8c:73:6c:00:0a:39:23:21:b3:14:5f:1b:e6:c7:f8
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  6 20:52:14 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:30:af:9c:0d:45:7a:e9:e0:06:96:42:f2:e4:5f:
                    d3:29:13:da:35:15:96:bd:f0:10:89:35:4c:00:a3:
                    b6:f4:6e:65:c6:a3:7e:66:36:cb:6d:6c:9d:d6:f4:
                    42:aa:fc:04:86:6a:2e:03:da:68:b8:77:07:3e:d3:
                    df:71:18:80:b0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AB:AC:15:30:D1:11:02:85:3B:C7:CB:A0:72:AA:01:B7:E0:54:CD:D4
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:3e:17:ee:02:ca:fd:4c:79:be:55:28:ce:8f:3d:
        9a:e8:01:f5:e4:cc:97:3f:e3:d5:15:a2:8e:37:94:6b:dd:25:
        02:21:00:8a:96:f5:22:9b:11:97:b2:80:db:a4:0e:7b:96:51:
        b2:46:41:8a:4c:48:d3:4f:dd:ab:48:9a:92:15:93:f2:01
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
            0e:e7:f0:c2:a1:6d:11:8c:d1:8f:f7:60:5f:c2:2b:4f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  6 20:52:14 2036 GMT
        Subject: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f6:39:80:f2:85:6b:23:cb:91:c9:9f:77:f6:82:
                    db:16:2f:0d:ea:6f:75:c6:f8:7d:1f:df:ab:8e:21:
                    7f:51:99:b7:3d:c6:fc:da:30:fc:8f:e6:00:45:f0:
                    04:52:42:60:3d:d1:9b:e9:3e:3b:30:75:19:11:cf:
                    df:4e:56:f3:0e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                40:99:CE:90:9A:17:FB:EF:A0:51:10:B3:B1:BC:A0:BD:2F:B4:9A:B7
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:e2:54:34:45:34:04:cd:7b:7c:05:40:dd:33:
        8b:9f:c9:09:9d:eb:9f:6e:85:66:27:f1:35:d8:92:76:91:6b:
        6d:02:21:00:c2:3e:47:fc:64:8a:89:fd:dd:a0:1a:fb:22:42:
        cb:a6:2f:6e:31:80:5c:b6:de:bc:28:5a:82:83:03:2e:6c:8f
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
            bf:e1:43:b0:cf:02:75:d3:11:fc:8d:09:22:1d:62:0b
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test pid CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet PID Provider (pid), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c5:ab:a5:72:52:73:56:ea:c5:c6:bd:97:01:f4:
                    46:54:bb:c1:29:32:10:e5:76:5a:92:1e:39:ad:11:
                    e5:23:99:46:07:46:77:cd:cd:3b:6c:06:22:c3:35:
                    d6:1d:c5:70:22:69:8e:08:ca:f1:0e:8e:22:b3:d4:
                    e9:15:f6:31:04
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                02:82:58:EB:FB:F4:D5:AE:40:91:BF:EA:36:03:C0:64:4F:C4:7C:18
            X509v3 Authority Key Identifier: 
                7A:2A:83:1E:6D:C2:D5:5E:9F:FC:16:37:B6:8B:ED:D5:BA:ED:22:D6
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/pid/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/pid/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
            X509v3 Extended Key Usage: critical
                1.0.18013.5.1.2
            qcStatements: 
                0.0......F..0.......N..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:c8:22:c6:fc:bf:36:51:d2:9e:e1:29:9a:ed:
        7b:94:5c:72:11:df:55:ed:c3:c2:57:7d:26:c1:96:89:cc:20:
        d1:02:21:00:c4:84:94:09:da:bd:6d:c2:1b:40:a3:7b:7a:4f:
        ff:7c:c4:49:c8:b2:a7:32:c3:11:2c:61:d6:bb:78:cb:79:0d
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
            b8:28:8a:04:1e:de:57:20:90:f6:6e:59:50:8f:cd:04
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test wallet CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet Provider (wallet-provider), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c1:78:c3:bb:bc:65:a1:10:f9:9e:27:89:14:aa:
                    47:da:20:2b:fe:50:3f:1c:cb:ed:18:c8:96:e9:35:
                    00:12:83:59:cc:ff:01:c0:21:ae:97:e1:75:91:9f:
                    c6:52:1d:00:88:22:d4:92:55:e6:4d:d9:c6:e2:fa:
                    db:fd:33:5c:a2
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                74:22:00:8D:8A:55:B0:4F:CE:BF:29:DE:AD:E3:58:33:CA:74:0C:17
            X509v3 Authority Key Identifier: 
                AC:D1:00:F9:E9:54:14:78:A3:B0:67:BC:59:8D:DF:49:AC:C5:10:F5
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/wallet/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/wallet/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
            qcStatements: 
                0.0......F..0.......N..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:7b:f7:dd:dd:76:4d:09:74:2b:76:e9:1c:ac:6f:
        ff:89:a5:71:fd:18:94:cf:ff:20:94:15:04:4b:55:85:4b:e3:
        02:20:05:14:be:21:b7:39:76:b6:e0:6c:3a:0e:b2:a9:2b:4e:
        a3:ab:95:2b:7f:95:c4:cd:40:69:85:73:46:67:3b:3d
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
            4d:28:3e:8e:20:c6:01:b1:8b:2a:01:49:50:91:93:4b
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test eaa CA NL, organizationIdentifier=NTRNL-NLTEST.00000000
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Wallet EAA Provider (eaa), organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:36:46:33:e1:83:5e:ad:39:5e:e2:f9:15:6b:94:
                    f9:b8:ec:44:73:0e:fe:c4:c6:93:94:1e:17:81:ec:
                    1a:5f:b7:2e:e3:c1:ac:ff:3a:4b:5c:2b:c6:c9:d5:
                    67:05:8c:27:9c:97:8e:2c:ac:a8:34:32:ea:f7:ec:
                    1c:30:c1:3a:53
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                F6:B4:C6:4D:EC:99:EC:E3:21:26:06:38:38:EA:02:F0:D8:40:C2:67
            X509v3 Authority Key Identifier: 
                28:44:CC:EA:91:15:89:9E:EF:4C:2F:68:F7:72:AF:BA:F7:8B:97:2E
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/providers/eaa/NL.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl/providers/eaa/NL

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
            X509v3 Extended Key Usage: critical
                1.0.18013.5.1.2
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:52:8a:c7:46:f9:6a:fc:23:0e:a1:ec:88:f8:92:
        c7:fe:94:58:56:73:89:80:97:37:7d:f5:31:b5:b3:9c:59:18:
        02:21:00:e3:4e:d0:28:2d:b4:99:da:b6:a0:2a:34:8f:06:c8:
        d2:75:37:24:75:5a:3d:97:e9:83:0a:68:f4:b2:ec:82:29
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
            6c:88:22:65:82:3a:27:f6:f0:67:70:be:81:ac:2e:22
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, OU=issuance, CN=EUDI Dev Demo Issuer, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:10:cf:0b:83:7f:98:bf:c5:d3:57:6b:f8:9c:1e:
                    0a:45:0c:f5:76:f7:80:8b:c5:a8:b7:55:56:8b:13:
                    db:79:99:eb:7a:e7:05:32:06:83:da:ad:c4:66:45:
                    47:86:3d:5d:83:9e:dc:2a:72:65:dc:4d:ff:be:5a:
                    57:37:1f:e6:e3
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                38:CF:FC:06:C1:36:B2:CD:9E:81:8A:9D:4E:87:F5:67:FE:A7:80:73
            X509v3 Authority Key Identifier: 
                AB:AC:15:30:D1:11:02:85:3B:C7:CB:A0:72:AA:01:B7:E0:54:CD:D4
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev/support
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
            X509v3 Certificate Policies: 
                Policy: 0.4.0.194118.1.2
                  CPS: https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:d7:2c:f7:1e:e9:f6:e2:e0:5d:ff:93:12:e3:
        9b:13:32:1d:73:87:44:09:1f:fd:49:bc:d8:b3:ba:9a:be:6f:
        f0:02:20:78:7f:31:7b:fb:4e:6b:f2:13:2d:16:6e:6a:ae:b9:
        2e:59:20:bc:48:20:6c:db:e6:34:1d:28:dd:0e:91:d4:d6
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
            55:10:9d:0d:65:d9:07:66:74:e2:c4:01:12:23:b5:9e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Relying Party Access CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Verifier, OU=verification, CN=EUDI Dev Demo Verifier, organizationIdentifier=NTRNL-NLTEST.00000001
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:fd:60:5d:35:b2:cc:3e:f6:e6:97:94:62:41:d5:
                    42:be:d6:69:5a:78:13:6e:0e:c9:06:b1:6d:69:5b:
                    84:60:97:bb:8c:59:00:dc:72:07:67:e5:5c:eb:34:
                    07:29:8b:57:cf:37:d7:2d:0b:32:79:10:14:95:49:
                    ff:8c:74:73:38
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                38:5D:C5:57:B1:4E:0A:CF:59:EB:B8:A0:2F:69:F2:7F:10:94:D4:FC
            X509v3 Authority Key Identifier: 
                AB:AC:15:30:D1:11:02:85:3B:C7:CB:A0:72:AA:01:B7:E0:54:CD:D4
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev/support
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
            X509v3 Certificate Policies: 
                Policy: 0.4.0.194118.1.2
                  CPS: https://github.com/dominikschlosser/eudi-dev/blob/main/docs/test-certificates.md
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:cc:0f:de:d8:0d:51:f7:75:d1:12:a0:a8:09:
        b3:b4:63:37:b4:15:53:78:1c:c1:1f:a6:1c:79:53:9f:6a:eb:
        a6:02:21:00:b2:1c:5e:76:77:4d:28:24:28:f7:92:cc:cf:9b:
        42:bb:13:eb:00:55:32:11:56:16:01:37:3e:80:3b:8f:fb:23
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
            a8:3e:cd:4f:be:97:47:ba:73:62:3a:a2:7f:65:d8:99
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Test Registrar CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Test Registrar, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b3:36:46:c1:b2:3a:fa:24:57:22:5e:d6:bb:90:
                    6e:5d:a2:1a:8a:39:9e:e0:14:9c:d7:0e:a0:91:06:
                    89:88:78:d8:58:ef:b2:4d:af:15:75:94:10:b7:7e:
                    6b:43:b2:ca:e6:a7:3b:b3:8b:32:7e:70:13:59:6f:
                    33:5c:38:5d:6a
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                3C:6D:0E:21:03:47:15:9F:6B:C6:9E:B5:0B:B7:4B:74:EA:8F:AA:09
            X509v3 Authority Key Identifier: 
                40:99:CE:90:9A:17:FB:EF:A0:51:10:B3:B1:BC:A0:BD:2F:B4:9A:B7
            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:28:98:05:0a:9f:a6:a1:b5:01:dc:4f:e2:c9:c7:
        6c:80:b8:cb:b4:f8:e8:e3:df:d1:c3:38:3e:1b:8a:0a:de:da:
        02:21:00:8a:12:2f:ca:6f:bf:5d:0f:8d:1b:94:0e:6c:5e:cf:
        45:7b:5c:37:f6:a6:a7:ed:16:5e:e3:a1:3e:92:33:ea:4c
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
            20:3e:6b:0e:5d:b7:d4:cd:89:d9:01:aa:fb:07:81:b3
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Test Provider, CN=EUDI Dev Status List Signer, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:78:e2:60:d9:b6:7f:b3:11:16:ad:85:4b:fa:d9:
                    0c:ce:54:24:15:b3:36:8b:0a:cb:3e:f2:38:a1:d8:
                    c1:00:4f:42:11:23:f2:ef:87:1a:d0:37:bc:03:5f:
                    5e:a2:da:45:cc:d6:db:4e:6c:0c:17:0c:45:52:6b:
                    da:28:26:f7:7e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                C7:07:BB:30:5F:35:19:2B:89:17:03:BB:7C:51:EA:EA:0A:A2:2D:67
            X509v3 Authority Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:92:9c:29:50:ac:9c:1e:ae:9b:d3:29:84:77:
        f9:28:eb:fa:c8:78:bd:1b:be:70:95:16:6f:72:83:12:a8:3e:
        b1:02:20:4b:17:79:f9:34:f7:ac:f5:0b:f2:a3:25:61:0e:0e:
        12:8a:e6:81:c9:26:00:aa:4d:5b:d5:20:2b:b5:f9:35:ad
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
            4e:50:a5:74:9b:a2:8c:cf:58:4d:b4:71:8b:72:1f:4e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=NL, O=EUDI Dev Test CA, CN=EUDI Dev Wallet CA
        Validity
            Not Before: Oct  9 19:52:14 2026 GMT
            Not After : Oct  9 20:52:14 2027 GMT
        Subject: C=NL, O=EUDI Dev Wallet, CN=EUDI Dev Test List Operator, organizationIdentifier=NTRNL-NLTEST.00000000
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b9:ff:0c:46:5f:16:27:ef:1b:87:c3:f0:3f:4b:
                    b8:42:f8:3c:f1:72:9b:a7:ae:88:78:6d:33:5c:62:
                    a2:2a:d3:ad:a1:0f:42:2c:06:18:38:37:7c:a9:61:
                    98:e5:5b:72:d9:ce:f6:6a:ee:c2:b8:2d:72:3d:f1:
                    4d:60:7d:e8:95
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier: 
                3C:76:78:F1:08:A3:6B:35:E1:01:8B:AD:F2:16:F0:6B:45:29:7C:8D
            X509v3 Authority Key Identifier: 
                65:1C:24:DD:AE:DD:4F:27:60:1D:88:CF:DB:71:32:91:DF:D1:3F:34
            Authority Information Access: 
                CA Issuers - URI:https://eudi-test.dev/api/certificates/ca.der
            X509v3 Subject Alternative Name: 
                DNS:eudi-test.dev, URI:https://eudi-test.dev
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://eudi-test.dev/api/crl

            X509v3 Issuer Alternative Name: 
                URI:https://github.com/dominikschlosser/eudi-dev
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:cf:8a:0e:62:e1:cf:92:6f:5b:85:29:74:45:
        ef:f7:38:35:fe:82:5d:a6:c0:54:ba:93:33:47:5e:6f:a5:ec:
        32:02:21:00:a6:6c:d5:b4:be:e0:d5:8b:14:33:d7:b5:67:1a:
        d5:3e:36:df:1f:52:df:b4:3d:50:70:64:0f:9b:c8:0b:3a:d8
```

</details>
