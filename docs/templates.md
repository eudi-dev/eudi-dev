# Credential templates

A credential template gives test credentials a name, type (VCT or doc type) and default claims. It can also set an expiry and claims that are always disclosed. The CLI, HTTP API and wallet UI share the same templates.

The binary includes 9 predefined templates. They are ordinary template files in [`internal/defaults/templates/`](../internal/defaults/templates/), so each one also shows the format of a user template:

| Name | Format | Contents |
|------|--------|----------|
| `pid-sdjwt` | sdjwt | EUDI PID (`urn:eudi:pid:1`) |
| `pid-mdoc` | mdoc | EUDI PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1`) |
| `german-pid-sdjwt` | sdjwt | German PID (`urn:eudi:pid:de:1`), which extends the EUDI PID |
| `german-pid-mdoc` | mdoc | German PID (ISO 18013-5 elements, `eu.europa.ec.eudi.pid.1` plus `eu.europa.ec.eudi.pid.de.1`) |
| `italian-pid-sdjwt` | sdjwt | Italian PID (`urn:eudi:pid:it:1`), which extends the EUDI PID |
| `italian-pid-mdoc` | mdoc | Italian PID (`eu.europa.ec.eudi.pid.1` plus `eu.europa.ec.eudi.pid.it.1`) |
| `dutch-pid-sdjwt` | sdjwt | Dutch PID (`urn:eudi:pid:nl:1`), which extends the EUDI PID |
| `dutch-pid-mdoc` | mdoc | Dutch PID (`eu.europa.ec.eudi.pid.1` plus `eu.europa.ec.eudi.pid.nl.1`) |
| `demo-ticket` | sdjwt | The demo issuer's event ticket (`urn:eudi-test:demo-ticket:1`) |

The `pid-*` templates follow the attribute tables of the [EUDI PID Rulebook v1.7](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md) and use its example identity Jan Wijnand ('t Hart). The `german-pid-*` templates follow the [German PID Rulebook 1.0.0 consultation draft](https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/features/PID/german-pid-rulebook/) and use the ERIKA MUSTERMANN specimen identity. The display description of each predefined PID links to its rulebook.

The `italian-pid-*` templates follow the PID data model of the [IT-Wallet Technical Specifications 1.4.7](https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/credential-data-model-pid.html) (§11.2). Their claims match Bianca Rossi from the specimen identity card. The Italian PID has no address. The wallet always discloses `sub`, `date_of_expiry`, `verification`, `issuing_authority` and `issuing_country`. `sub` is an opaque identifier. The templates list it in `unique_claims`, so every credential gets its own, including each copy in a batch. The mdoc carries `sub` and `verification` in `eu.europa.ec.eudi.pid.it.1`. The optional `personal_administrative_number` is left out.

The `dutch-pid-*` templates follow the [working draft of the Dutch PID](https://github.com/MinBZK/nl-wallet/blob/ea1402d2ad96202617bee6771ac1395c73e96322/scripts/devenv/eudi_pid_nl_1.json) in the NL Wallet reference implementation. Their claims match Willeke Liselotte De Bruijn from the specimen identity card. The address, `bsn` and `recovery_code` come from the NL Wallet sample. The draft adds `bsn`, `recovery_code` and `age_over_18` to the EUDI PID. The templates also carry the mandatory EUDI PID attributes, and country values are ISO 3166-1 codes. The `dutch-pid-mdoc` template uses the PID doctype and puts the Dutch attributes in `eu.europa.ec.eudi.pid.nl.1` (ARF PID_04, PID_05 and PID_06). The [NL Wallet mdoc](https://github.com/MinBZK/nl-wallet/blob/8f2a549cc3933e13697bfa98aea23da891380cf6/scripts/devenv/eudi_pid_nl_1_mdoc.json) uses `urn:eudi:pid:nl:1` as doctype and namespace, so a query for that doctype matches nothing here.

The German rulebook adds national attributes (`birth_name`, `academic_title`, `source_document_type`, `raw_eid_birth_date`, and the age thresholds in `age_equal_or_over`). The EU rulebook defines attributes that the German eID does not have (`sex`, `document_number`, `personal_administrative_number`, `date_of_issuance`, `birth_family_name`). Some shared attributes differ in encoding. The birth name is `birth_name` in the German PID and `birth_family_name` in the EU PID. Both PIDs include the house number in the street address. The EU PID has no separate house number (CIR (EU) 2026/1731). The rulebook's encoding table still lists `address.house_number`.

The German SD-JWT PID has the type `urn:eudi:pid:de:1`. It matches a request for the country-independent PID `urn:eudi:pid:1`. See [credential type inheritance](wallet.md#credential-type-inheritance).

The German mdoc PID uses 2 namespaces:

- `eu.europa.ec.eudi.pid.1` for European elements
- `eu.europa.ec.eudi.pid.de.1` for national additions: `birth_name`, `academic_title`, `source_document_type`, `raw_eid_birth_date` and `age_over_*`

Its doctype is `eu.europa.ec.eudi.pid.1`, like every PID. A claim key written as `namespace:element` selects that namespace. Other keys use the template's namespace. Recognized date attributes use ISO 18013-5 CBOR tags: full-date (1004) for a calendar day and tdate (0) for a timestamp. The namespace and attribute name determine the encoding. The German `raw_eid_birth_date` is encoded as a text string.

The predefined PID templates leave their issuance and expiry dates empty. See [dates and unique values](#dates-and-unique-values).

Regenerating a PID replaces the existing mdoc PID with the same doctype and namespaces. So an override of `german-pid-mdoc` needs at least one `eu.europa.ec.eudi.pid.de.1` element to stay distinguishable from `pid-mdoc`.

`issue ... --pid` and `wallet serve --pid` use these templates. They use the pair of the country-independent PID (`pid-*`) by default. With `--vct` they use the SD-JWT template of that type and the mdoc template with the PID doctype and the same display name. A user template for another PID type, such as `urn:eudi:pid:fr:1`, works the same way. A type without templates gets the EUDI PID claims under that type. A user template saved under the same name overrides the predefined one everywhere. Deleting the override restores the original.

With `--demo` the wallet holds a PID for each predefined template that sets `baseline`. These are the EUDI PID and the German PID (an extension of the EUDI PID). `--pid` alone issues the EUDI PID. An override of a baseline template changes the content of that baseline PID.

## Template files and storage

Predefined templates are compiled into the binary as template files, together with the images and portraits they reference. User templates are JSON or YAML documents under the wallet's `templates/` prefix in the selected storage backend. With file storage, the default directory is `~/.eudi-dev/wallet/templates/`, or `<dir>/templates/` with `--wallet-dir <dir>`. The extensions `.json`, `.template`, `.yaml` and `.yml` are recognized. A `.yaml` or `.yml` file is YAML. The others are JSON. The template name is its `name` field. Without one, it is the file name without its extension.

Each name has one file. 2 files such as `employee-card.json` and `employee-card.yaml` cause an error, and the error lists both files. The wallet saves templates as JSON. A template saved under the name of a YAML file replaces that file with a JSON file. Deleting a template deletes its file in either format.

`--templates-dir` points the wallet, the issue commands, and the `templates` commands at another directory, for example a folder in your project or a container mount.

```bash
eudi wallet serve --templates-dir ./my-templates
eudi issue sdjwt --template employee-card --templates-dir ./my-templates
eudi templates list --templates-dir ./my-templates
```

```json
{
  "description": "Employee badge for verifier testing",
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "exp": "720h",
  "claims": {
    "employee_id": "E-1",
    "department": "IT",
    "address": { "country": "DE", "locality": "KÖLN" }
  },
  "always_disclosed": ["department", "address.country"]
}
```

The same template in YAML:

```yaml
description: Employee badge for verifier testing
format: sdjwt
vct: urn:example:employee
exp: 720h
claims:
  employee_id: E-1
  department: IT
  address:
    country: DE
    locality: KÖLN
always_disclosed: [department, address.country]
```

All fields except `claims` are optional:

| Field | Description |
|-------|-------------|
| `name` | Template name (defaults to the file name) |
| `description` | Free text shown in listings |
| `format` | `sdjwt`, `jwt`, or `mdoc` (empty means any format). The aliases `sd-jwt`, `dc+sd-jwt`, `jwt_vc_json`, and `mso_mdoc` are accepted |
| `vct` | Credential type for sdjwt/jwt |
| `doctype`, `namespace` | Type identifiers for mdoc |
| `exp` | Default expiry as a Go duration (for example `720h`) |
| `claims` | The default claim set |
| `always_disclosed` | Claims issued plainly instead of selectively disclosable (see below) |
| `unique_claims` | Claims that get a new random value in every credential, for example an opaque subject identifier |
| `rulebook` | URL of the rulebook or specification of the credential type. The [attestation catalogue](#attestation-catalogue) links it |
| `baseline` | Marks a PID held by the demo profile. Only predefined templates use it |
| `category` | `pid`, `qeaa`, `pub-eaa` or `eaa`. Credentials from the template are on the [trusted list](wallet/serve.md#trusted-lists) of this category. Without one, the template's catalogue entry gives the category, else the credentials are EAAs. The predefined PID templates are `pid` and the demo ticket is `eaa` |
| `display` | Card appearance for credentials issued from the template (`name`, `description`, `background_color`, `text_color`, `logo`, `logo_alt_text`, `background_image`) and display names of its claims (`claims`). Image fields take `embedded:<file>`, a data URI or an http(s) URL (see [card appearance](#card-appearance-display)). The predefined PID templates set it |
| `catalog` | The template's own entry in the attestation catalogue, with the fields of a catalogue request. Its category is the template's category. See [catalogue entry in a template file](#catalogue-entry-in-a-template-file) |
| `predefined` | Set on predefined templates in listings and exports. Ignored on import |
| `visitor` | Set on templates saved by visitors of the public demo. Visitors can change and delete these templates, and a demo reset removes them |

## Claim values

Claims are JSON values. For an mdoc, a whole number becomes a CBOR integer, and a base64 `data:` URI becomes a byte string. This is how a template gives an mdoc its `portrait`. An SD-JWT keeps the `data:` URI as text, as the `picture` claim of the EUDI PID does.

A string `embedded:<file>` refers to a file in the built-in defaults, such as `embedded:portraits/dutch.jpg`. The wallet replaces it with a `data:` URI of that file when it loads the template. Every template can use it. The defaults hold these portraits:

| File | Used by |
|------|---------|
| `portraits/default.jpg` | A neutral silhouette for the EUDI PID and the German PID |
| `portraits/italian.jpg` | The photo of the Italian specimen card |
| `portraits/dutch.jpg` | The photo of the Dutch specimen card |

## Dates and unique values

Issuance from a template fills some empty claims:

- In a template of category `pid`, an empty `date_of_issuance` or `issuance_date` becomes the date of issuance. An empty `date_of_expiry` or `expiry_date` becomes the date 5 years later. A date that is set stays.
- A claim listed in `unique_claims` gets a new random value in every credential. The Italian PID lists `sub` with an empty value.

A template reference (`--template`, `--from`) with a path separator or a template file extension loads that file. Any other value is looked up in the template directory (all 4 extensions), then among the predefined templates.

`wallet serve --credentials` issues credentials from templates on every start (see [startup credentials](wallet/serve.md#startup-credentials)).

## YAML template files

A YAML template has the same fields as a JSON template. The wallet converts it to JSON and reads it like a JSON file, so both give the same template. This example uses most fields:

```yaml
name: employee-card
description: Employee badge for verifier testing
format: sdjwt
vct: urn:example:employee
exp: 720h
category: eaa
rulebook: https://example.com/rulebook
claims:
  employee_id: E-1
  sub: ""
  postal_code: "01234"
  birthdate: 1990-01-01
  address:
    country: DE
    locality: KÖLN
  age_equal_or_over:
    18: true
always_disclosed: [employee_id, address.country]
unique_claims: [sub]
display:
  name: Acme Employee
  background_color: "#0f766e"
  text_color: "#ffffff"
  logo: embedded:images/logo.svg
  logo_alt_text: Acme logo
catalog:
  name: Employee card
  category: eaa
  schema:
    version: 1.2.0
    rulebookURI: https://example.com/rulebook
```

An mdoc template writes a claim of another namespace as `namespace:element`. YAML reads such a key as written:

```yaml
format: mdoc
doctype: eu.europa.ec.eudi.pid.1
namespace: eu.europa.ec.eudi.pid.1
claims:
  family_name: MUSTERMANN
  birth_date: 1964-08-12
  eu.europa.ec.eudi.pid.de.1:birth_name: GABLER
```

Unquoted values follow YAML typing. A few rules make a YAML template match its JSON form:

| YAML value | Claim value |
|------------|-------------|
| `true`, `false` | A boolean |
| `yes`, `no`, `on`, `off` | Text |
| `42`, `-7`, `2.5` | A number |
| `01234`, `0x1F` | Text as written. Quote a postal code anyway |
| `1990-01-01`, `2026-10-12T10:00:00Z` | Text as written, like a date in a JSON template |
| `null`, `~` | `null` |
| A mapping key such as `18` | Text, as in JSON |

Quote a value that must stay text, such as `"true"` or `"42"`. Quote a color such as `"#0f766e"`, since `#` starts a comment.

## Card appearance (display)

The optional `display` object sets the card appearance of credentials issued from the template (OpenID4VCI 1.0 §12.2.4). The demo issuer publishes it in its issuer metadata. It serves built-in and uploaded images itself, at `/issuer/templates/<template>/logo` and `/issuer/templates/<template>/background_image`. The metadata links an `https://` image directly.

| Field | Description |
|-------|-------------|
| `name` | Display name (defaults to the technical type) |
| `description` | Free text |
| `background_color` | Card background, a CSS color such as `#3d59a1` |
| `text_color` | Card text, a CSS color such as `#ffffff` |
| `logo` | Card logo image (see image sources below) |
| `logo_alt_text` | Alt text for the logo image |
| `background_image` | Full card background image behind the name (see image sources below) |
| `claims` | Display names of the top-level claims, keyed by claim name, such as `{"seat": "Seat"}`. The demo issuer publishes them in its issuer metadata |

The 2 image fields (`logo`, `background_image`) take one of 3 sources:

- a `data:` URI, embedded directly
- an `http://` or `https://` URL, fetched once at issuance
- `embedded:<file>`, a bundled image such as `embedded:images/logo.svg`. A bare file name means a file under `images/`

A fetched image is stored in the wallet's size-limited cache and is embedded as a `data:` URI on the issued credential.

The predefined PID templates set `display`: `background_color` `#3d59a1`, `text_color` `#ffffff`, and `logo` `embedded:images/logo.svg`. The national PIDs show the eudi-dev logo on their country's flag instead, and add the country's specimen identity card as `background_image`:

| Template | Logo | Image | Source and licence |
|----------|------|-------|--------------------|
| `german-pid-*` | `embedded:images/logo-de.svg` | `embedded:images/german-id-specimen.jpg` | [Personalausweis specimen (2010 model)](https://commons.wikimedia.org/wiki/File:Mustermann_Deutscher_Personalausweis_(2010)_Vorderseite.jpg), Bundesministerium des Innern, public domain (§ 5 UrhG) |
| `italian-pid-*` | `embedded:images/logo-it.svg` | `embedded:images/italian-id-specimen.jpg` | [Carta d'identità elettronica specimen](https://commons.wikimedia.org/wiki/File:CIE_(fronte).jpg), Ministero dell'Interno and Istituto Poligrafico e Zecca dello Stato, resized, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| `dutch-pid-*` | `embedded:images/logo-nl.svg` | `embedded:images/dutch-id-specimen.jpg` | [Nederlandse identiteitskaart specimen](https://commons.wikimedia.org/wiki/File:Nederlandse_identiteitskaart_2021-II_(Voorkant).jpg), Rijksdienst voor Identiteitsgegevens, resized, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |

Display values supplied during issuance override individual template fields. Setting only a name keeps the template's images.

The CLI accepts `--display-name`, `--display-description`, `--background-color`, `--text-color`, `--logo`, `--logo-alt` and `--background-image`. `POST /api/issue` accepts the same fields.

```json
{
  "description": "Employee badge for verifier testing",
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "claims": { "employee_id": "E-1", "department": "IT" },
  "display": {
    "name": "Acme Employee",
    "description": "A demo employee badge issued for verifier testing.",
    "background_color": "#0f766e",
    "text_color": "#ffffff",
    "logo": "https://acme.example/badge-logo.svg",
    "logo_alt_text": "Acme logo"
  }
}
```

## Always disclosed claims

Every SD-JWT claim is selectively disclosable by default. The registered claims that SD-JWT VC §2.2.2.3 excludes from selective disclosure (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and `status`) are always embedded plainly. The wallet sets `iat` itself and embeds it plainly too. Claims listed in `always_disclosed` are embedded plainly too, so they cannot be withheld during presentation.

Entries are top level claims (`issuing_country`) or nested subclaims as dotted paths (`address.country`). A top level entry embeds the whole claim value plainly. A dotted entry keeps the parent selectively disclosable but embeds that subclaim plainly inside the parent's disclosure. Entries that match no claim are ignored.

JWT VCs carry all claims plainly, so the list is ignored there. mdoc issuance rejects it (every ISO 18013-5 element is selectively disclosable).

## CLI

```bash
# List and inspect templates
eudi templates list
eudi templates show german-pid-sdjwt

# Issue from a template, optionally overriding individual claims
eudi issue sdjwt --template pid-sdjwt
eudi issue sdjwt --template german-pid-sdjwt --claims '{"given_name": "MAX"}'

# Make claims always visible
eudi issue sdjwt --pid --always-disclosed issuing_country,address.country

# Save the current issuance as a template while issuing
eudi issue sdjwt --vct urn:example:employee --claims '{"employee_id": "E-1"}' --save-template employee-card

# Create or update a template directly
eudi templates save employee-card --format sdjwt --vct urn:example:employee --claims '{"employee_id": "E-1"}' --always-disclosed employee_id

# Customize a predefined template (the copy overrides it when saved under the same name)
eudi templates save german-pid-sdjwt --from german-pid-sdjwt --vct urn:custom:pid

# Import a shared template (JSON or YAML file, JSON string, or - for stdin)
eudi templates import shared-template.json
eudi templates import shared-template.yaml
eudi templates import '{"format":"sdjwt","claims":{"a":1}}' --name my-cred
eudi templates show employee-card > share-me.json

# Delete a user template (deleting an override restores the predefined version)
eudi templates delete employee-card
```

`templates import` reads a `.yaml` or `.yml` file as YAML and any other file as JSON. On stdin, input that starts with `{` is JSON and other input is YAML. `templates show` prints JSON for every source format.

All `templates` subcommands accept `--wallet-dir` to target a non-default wallet store. With `--remote <url>` (or after `wallet use <url>`), list, show, save, import, and delete operate on a remote instance's template store through its REST API. See [remote control](wallet/http-api.md#remote-control).

### `templates save`

| Flag | Description |
|------|-------------|
| `--from` | Copy this template (name, or JSON or YAML file) as the starting point |
| `--format` | `sdjwt`, `jwt`, or `mdoc` (empty means any) |
| `--vct` | Credential type (sdjwt/jwt) |
| `--doc-type` | Document type (mdoc) |
| `--namespace` | Default namespace (mdoc) |
| `--exp` | Default expiry duration |
| `--claims` | Claims as JSON string or `@filepath` |
| `--always-disclosed` | Comma separated claim paths issued without selective disclosure |
| `--description` | Free text description |

## HTTP API

The wallet server exposes the same template store:

| Endpoint | Description |
|----------|-------------|
| `GET /api/templates` | List all templates (predefined and user), including claims |
| `GET /api/templates/{name}` | Get one template |
| `GET /api/templates/{name}/display/{field}` | The `logo` or `background_image` of a template, when it is bundled or a data URI |
| `PUT /api/templates/{name}` | Create or replace a user template (body is a full template document, so this is also the import endpoint) |
| `DELETE /api/templates/{name}` | Delete a user template (deleting an override of a predefined template restores the predefined version) |

`POST /api/issue` accepts `template`, `always_disclosed`, and `save_as_template` fields. See the [wallet HTTP API](wallet/http-api.md#credential-issuance).

## Attestation catalogue

The predefined templates are always in the [attestation catalogue](wallet/registrar.md#attestation-catalogue). User templates are added only on request. To add one, send a `catalog` object next to the template document in `PUT /api/templates/{name}`, or next to `save_as_template` in `POST /api/issue`:

```json
{"name": "Employee card", "category": "eaa", "schema": {"rulebookURI": "https://example.com/rulebook", "attestationLoS": "iso_18045_basic", "bindingType": "key", "trustedAuthorities": [{"frameworkType": "etsi_tl", "value": "https://example.com/trusted-list", "isLOTE": true}]}}
```

The entry gets the template's format, type and claims. An empty name becomes the template's display name or its name. The entry's category defaults to the template's category, else `eaa`. The template then takes the entry's category. A user template without a category and without a catalogue entry issues EAAs. Only an SD-JWT VC template with a `vct` or an mdoc template with a `doctype` can be added. The wallet checks the entry before it saves anything. If the entry is invalid or its name is taken, it saves neither the template nor the entry, and `POST /api/issue` doesn't issue the credential. Deleting the template keeps the entry. To remove the entry, delete it in the catalogue.

```bash
# Import a template and issue from it
curl -X PUT http://localhost:8085/api/templates/employee-card \
  -H 'Content-Type: application/json' \
  -d '{"format": "sdjwt", "vct": "urn:example:employee", "claims": {"employee_id": "E-1"}, "always_disclosed": ["employee_id"]}'

curl -X POST http://localhost:8085/api/issue \
  -H 'Content-Type: application/json' \
  -d '{"template": "employee-card", "claims": {"employee_id": "E-42"}}'
```

### Catalogue entry in a template file

A JSON or YAML template file in the template directory can carry a `catalog` object. It takes the same fields as the `catalog` object of `PUT /api/templates/{name}`. The template then gets its own catalogue entry, like a predefined template:

```json
{
  "format": "sdjwt",
  "vct": "urn:example:employee",
  "claims": {"employee_id": "E-1"},
  "catalog": {"name": "Employee card", "category": "eaa", "schema": {"rulebookURI": "https://example.com/rulebook"}}
}
```

The entry exists as long as the template file and changes with it. Its id is derived from its name, so it stays the same across restarts. The catalogue API can't change it. `wallet serve` checks these objects at startup. If an object is invalid or reuses the name or a type of another entry, the start fails and reports the template name.

`GET /api/templates/{name}` shows the `catalog` object. Saving such a template keeps it. A save with a `catalog` object replaces it. A predefined template can carry one too. Its entry then uses those fields.

For a template without its own `catalog` object, `templates import` and `PUT` treat a `catalog` object as a catalogue request. They add an entry, as described above.

## Wallet UI

An unchecked SD box in the issue dialog puts the claim in `always_disclosed`. "Save as template" saves the form only after the issuance succeeds.

Pasting a template into the editor's JSON view imports it. The JSON view also accepts fields without a builder control, such as `unique_claims`. The builder keeps these fields.

For a catalogue entry made in the UI, the category sets the default level of security, and an empty trusted list links the category's list.

On a public demo, visitors can save templates too. They can't change or delete the predefined templates or the operator's templates (those present at startup). A visitor template stores its images. A linked image is fetched once when the template is saved. A demo keeps at most 50 visitor templates, and a reset deletes them.
