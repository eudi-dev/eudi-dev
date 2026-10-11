# Built-in defaults are data in operator formats

The wallet ships with predefined credential templates and their images, the credential categories and the registrations of the demo issuer and demo verifier. An operator supplies the same kinds of data: templates in a template directory and relying parties through the registrar.

## Decision

The built-in defaults are files embedded in `internal/defaults`. Each file uses the format an operator uses for the same data:

- `templates/` holds template files. The parser for user templates reads them.
- `images/` and `portraits/` hold the images of these templates. A template references one as `embedded:<path>`.
- `registrations/` holds the demo issuer and demo verifier as TS05 registrations, the body of a registrar request.
- `categories.json` holds the credential categories with their trusted list fields.

A user template with the name of a predefined template overrides it everywhere. Deleting the user template restores the predefined one.

## Consequences

Changing a default means changing a data file, not Go code. An operator can copy a predefined template as the start of their own.

Each kind of data has one reader. Predefined and user templates take the same path through parsing and issuance, so a bug shows in both.
