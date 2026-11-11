# Configuration files

`wallet serve` reads five kinds of YAML or JSON files at startup. Together they set up a wallet without any steps in the UI, for a container, a test setup or a public demo.

| Input | Flag | Variable | Content |
|-------|------|----------|---------|
| `templates` | `--templates` | `EUDI_DEV_TEMPLATES` | [Credential templates](../templates.md) to offer |
| `transaction-templates` | `--transaction-templates` | `EUDI_DEV_TRANSACTION_TEMPLATES` | [Transaction templates](presenting.md#transaction-templates) for presentation requests |
| `catalog` | `--catalog` | `EUDI_DEV_CATALOG` | [Attestation types](serve.md#pre-registered-catalogue-entries) for the catalogue |
| `relying-parties` | `--relying-parties` | `EUDI_DEV_RELYING_PARTIES` | [Verifiers and issuers](serve.md#pre-registered-relying-parties) to register |
| `credentials` | `--credentials` | `EUDI_DEV_CREDENTIALS` | [Credentials](serve.md#startup-credentials) to add to the wallet |

Each flag takes a file, a directory or `-` for stdin. The wallet reads every `.yaml`, `.yml` and `.json` file of a directory in name order.

## One directory for all inputs

`--config` (`EUDI_DEV_CONFIG`) takes a directory and finds each input in it by name. An input is either a subdirectory or a file named after it:

```text
config/
├── templates/
│   ├── employee-card.yaml
│   └── pid-sdjwt.yaml
├── transaction-templates.yaml
├── catalog.yaml
├── relying-parties/
│   ├── example-company.yaml
│   └── example-shop.yaml
└── credentials.yaml
```

```bash
eudi wallet serve --config ./config
```

An input can be left out. The start stops when an input appears twice, for example as `catalog.yaml` and `catalog/`. It also stops when an input is set both by a flag and in the directory. Other `.yaml`, `.yml` and `.json` files get a warning, because the wallet doesn't read them. Files whose names start with a dot are skipped, so the hidden entries of a Kubernetes ConfigMap volume don't count.

## The file format

A file holds one item or a list of items. A YAML file can also hold several documents separated by `---`, and their items add up:

```yaml
name: employee-card
format: sdjwt
vct: urn:example:employee:1
claims:
  employee_id: E-1
---
name: visitor-badge
format: sdjwt
vct: urn:example:visitor:1
claims:
  badge_id: V-1
```

The credentials file is the exception. It holds a `credentials` list, and the lists of several documents add up.

The wallet reads the files strictly. An unknown field stops the start, and so does a template without a name in a file with several templates. The error shows the file and the number of the document or template. Some YAML values stay text, because JSON would read them as another type: `1990-01-01` stays a date string, `01234` keeps its leading zero and `1.0` stays `1.0`.

## Templates from files

Templates from `--templates` belong to the operator. The wallet offers them like its other templates and shows them in the template list as "from config". It refuses to change or delete them. The API answers `409 Conflict`, and the error shows the file. A template from the files replaces a stored or predefined template of the same name.

Transaction templates from `--transaction-templates` work the same way. A file entry has a `name`, an optional `description` and the `transaction_data` object:

```yaml
name: shop-payment
description: A TS12 payment to Example Shop
transaction_data:
  type: urn:eudi:sca:payment:1
  transaction_data_hashes_alg: [sha-256]
  payload:
    transaction_id: 3F2504E0-4F89-11D3-9A0C-0305E82C3301
    payee: {name: Example Shop, id: NL91ABNA0417164300}
    currency: EUR
    amount: 49.9
```

The wallet refuses an entry without a `type`. A TS12 entry with a payload that breaks the TS12 schema still loads, and the template list shows the findings as warnings. Use such an entry to test how a wallet refuses it.

`--templates-dir` is different. It points the wallet at another directory for its stored templates, and the wallet saves and deletes templates there. Use `--templates` for templates that come from your configuration, and `--templates-dir` when the wallet should keep its edits in a folder of your own.

## Check the files first

`--check` loads the configuration into a fresh wallet in memory, prints what it holds and exits. It doesn't touch the wallet directory or the database.

```console
$ eudi wallet serve --config ./config --check
Generated holder key: memory:wallet/holder.pem
Generated issuer key: memory:wallet/issuer.pem
The configuration loads into a fresh wallet:
  2 templates from config/templates
  1 transaction template from config/transaction-templates.yaml
  1 catalogue entry from config/catalog.yaml
  2 relying parties from config/relying-parties
  1 credential from config/credentials.yaml
  the default PID credentials
```

The keys belong to the wallet in memory and are gone when the check exits. A server prints the summary when it starts.

## Reading the files again

`--config-reload 30s` reads the files every 30 seconds and applies them when they changed. Only the changed inputs are applied, so an unchanged credentials file doesn't issue its credentials again. A file that doesn't load leaves the wallet as it was. The log shows the error once. When the file loads again, the wallet applies it. An input that loads but can't be applied, for example while the database is down, is tried again every 30 seconds. Without the flag the wallet reads the files once at startup.

A change applies once two reads in a row agree. A new template and a credential that uses it then apply together when you save both files within one interval. A change takes effect after one or two intervals.

A reload works like a start for each input. Changed template files replace all templates from the files, and the same holds for transaction templates. The catalogue and the templates apply together, so one change can move a catalogue entry into a template or back. A changed catalogue file updates its entries and removes those no longer in the file. A changed relying parties file registers the parties again. A changed credentials file adds all its entries again with fresh dates. When one entry fails, the entries before it are already added, and the retry adds them again. A credential or a registration removed from its file stays in the wallet. With `--demo` a demo reset restores the configuration of the last reload.

The reload reads only the inputs found at startup. A new file inside an input directory counts. A new input in the `--config` directory, such as a `catalog.yaml` added later, needs a restart.

Kubernetes updates a mounted ConfigMap in place after a short delay, so a wallet with `--config-reload` picks up the change without a new pod. A ConfigMap mounted with `subPath` never changes in the pod.

## JSON Schemas

[`docs/schemas`](../schemas) has a JSON Schema for each input. An editor with a YAML language server completes and checks the fields when the first line of the file points to its schema:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/eudi-dev/eudi-dev/main/docs/schemas/templates.schema.json
name: employee-card
format: sdjwt
vct: urn:example:employee:1
```

The schemas describe the fields of each input. The wallet checks more on start, for example that each credential refers to an existing template. Run `--check` for the full check.

## CLI commands in a container

A CLI command finds a running server through its instance file. The server writes it to `~/.eudi-dev/instances` and to a private directory in the temp directory. So `docker exec <container> eudi templates import -` reaches the running wallet even when the home directory is read-only, as with a read-only root filesystem and a writable `/tmp`.

With memory storage, as in the Docker image, a command that finds no server works on a new wallet in memory and says so on stderr. Its changes are gone when it exits. Pass `--remote <url>` to reach a server that runs elsewhere. `--remote local` or `--storage memory` keeps the wallet in memory without the warning.

## Kubernetes

[`examples/kubernetes`](../../examples/kubernetes) mounts one ConfigMap per input under `/config` and sets `EUDI_DEV_CONFIG=/config`. It also shows a Helm chart and Kustomize.
