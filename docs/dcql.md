# DCQL

`eudi dcql` reads an SD-JWT VC, a JWT VC or an mdoc and prints a DCQL query (OpenID4VP 1.0 §6) that asks for every claim of the credential. Edit the query to keep only the claims you need, then use it in a verifier's request or with `registrar verifiers add --dcql`.

```bash
eudi dcql credential.txt
eudi issue sdjwt --pid | eudi dcql
eudi wallet show <id> | eudi dcql
```

The input is a file path, a URL, a raw credential string or stdin. The output is always JSON.

## Query contents

| Input | `format` | `meta` | Claim paths |
|---|---|---|---|
| SD-JWT VC | `dc+sd-jwt` | `vct_values` with the credential's `vct` | One path per claim. Nested objects add a segment, arrays end with `null` (all elements) |
| JWT VC | `jwt_vc_json` | `vct_values` when the credential has a `vct` | Like SD-JWT VC |
| mdoc | `mso_mdoc` | `doctype_value` with the doctype | Namespace and element identifier |

The credential query `id` is the type with every character other than letters, digits, `_` and `-` replaced by `_` (OpenID4VP 1.0 §6.1). Without a type it is `credential_0`.

## Example

```bash
eudi issue sdjwt --vct urn:example:card \
  --claims '{"given_name":"Erika","address":{"locality":"Berlin"}}' | eudi dcql
```

```json
{
  "credentials": [
    {
      "id": "urn_example_card",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:example:card"] },
      "claims": [
        { "path": ["address", "locality"] },
        { "path": ["given_name"] }
      ]
    }
  ]
}
```
