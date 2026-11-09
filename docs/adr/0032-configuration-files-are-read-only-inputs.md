# Configuration files are read-only inputs

`wallet serve` reads templates, transaction templates, catalogue entries, relying parties and credentials from files. A container or a Kubernetes deployment describes the whole wallet with them. The files belong to the operator and live in a mount that the wallet often can't write.

## Decision

The five inputs share one loader. A file holds one item or a list, and a YAML file can hold several documents. The loader refuses unknown fields and reports the file and the document of an error, because a typo in a mounted file is hard to find later. Stored templates, a template file given by path and `eudi templates import` keep their lenient loader, so files from older releases still load.

`--templates` adds templates from files as their own layer. The wallet parses them once per load. It fills the dates of a PID template on every read, and the dates stay current. A template from the files replaces a stored or predefined one of the same name. The API refuses to change or delete it with `409 Conflict`, because the next start would bring the file's version back. `--templates-dir` keeps pointing at the writable directory of stored templates. `--transaction-templates` adds transaction templates the same way.

`--config` takes one directory and finds each input by its name, as a subdirectory or as a file. One ConfigMap per input mounts as a subdirectory, so Kubernetes needs a single variable. An input set both by a flag and by the directory stops the start, because neither one should win silently.

`--config-reload` loads the files again at an interval and compares them with the applied configuration. The catalogue and the templates apply together, so one change can move an entry from one to the other. Polling works the same for a bind mount, a ConfigMap symlink swap and a network file system, where file events often don't arrive. A reload applies only the inputs that changed, in the same order as at startup, under the request lock. A configuration that doesn't load keeps the previous one. An input that loads but doesn't apply keeps its previous version, and the next tick tries it again. `--check` runs the same loading into a fresh wallet in memory and exits.

A running server writes its instance file to `~/.eudi-dev/instances` and to `eudi-dev-<uid>-<hash>/instances` in the temp directory. The hash comes from the eudi-dev home directory (`~/.eudi-dev` or `EUDI_DEV_HOME`), so two homes don't see each other's servers. The CLI reads the temp directory only when it belongs to the user and nobody else can write it. With a read-only root filesystem, the temp directory is often the only writable place, so `docker exec` commands still reach the server.

`docs/schemas` holds a JSON Schema for each input. A test generates them from the Go types and fails when they drift.

## Consequences

A configuration file with several YAML documents used to load only its first document. Now every document counts. An API change to a catalogue entry or relying party from the files lasts until the next start or until its file changes. Templates from the files can't be changed at all.
