# Themes

A theme changes the logo and the colors on every page of a self-hosted wallet: the wallet, the decoder, the demo issuer, the demo verifier and the registrar. It can set the wallet name. The wallet and the decoder show the name in their title and header. The demo issuer and the demo verifier use it in their page description. A theme can set the description of the wallet page and an edition tag. It can change the header menu, the product in the footer and the links and texts of the demo hints. It is a directory with up to 4 files:

```
acme/
  theme.css      colours and fonts
  theme.yaml     wallet name and other texts
  logo.svg       or logo.png, logo.webp, logo.jpg
  favicon.svg    or favicon.png, favicon.ico
```

Every file is optional. Without a favicon, the logo is the favicon. Other missing files and colours come from the built-in eudi-dev theme.

```sh
eudi wallet serve --theme examples/themes/acme
```

[examples/themes/acme](../../examples/themes/acme) is a complete example with a made-up brand.

## Colours

`theme.css` sets CSS variables. The wallet loads it after the built-in theme, so each variable replaces the built-in value.

```css
/* Both modes */
:root {
  --accent: #2bb39a;
}

/* Dark mode */
[data-theme="dark"] {
  --bg: #0f1a1c;
}

/* Light mode */
[data-theme="light"] {
  --bg: #f1f7f5;
  --accent: #0e7c68;
}
```

Visitors still switch between light and dark mode. A theme can set colours for both modes or for one of them.

These variables keep their names across releases:

| Variable | Use |
|----------|-----|
| `--accent` | Primary buttons, selected options, focus |
| `--on-accent` | Text on `--accent` |
| `--link` | Links |
| `--bg` | Page background |
| `--bg-header` | Header bar |
| `--bg-surface` | Cards and panels |
| `--bg-dialog` | Dialogs |
| `--text` | Text |
| `--text-dim` | Secondary text |
| `--border` | Borders |
| `--font-sans` | Text font |
| `--font-mono` | Font for code and tokens |

The [built-in theme](../../internal/webui/theme/theme.css) lists every variable. The others can change in any release.

## Logo and fonts

The logo has the height of the eudi-dev logo, 27 pixels in the wallet header. It keeps its aspect ratio and can be up to 160 pixels wide. Make sure it is readable on light and dark backgrounds.

The wallet also serves the fonts and images of the theme directory. `theme.css` links them by relative URLs:

```css
@font-face {
  font-family: "Acme Sans";
  src: url("fonts/acme-sans.woff2") format("woff2");
}
:root {
  --font-sans: "Acme Sans", system-ui, sans-serif;
}
```

The wallet serves only fonts (`.woff2`, `.woff`, `.ttf`, `.otf`) and images (`.svg`, `.png`, `.webp`, `.jpg`, `.gif`, `.avif`, `.ico`) up to 4 MiB each. It never serves hidden files or files outside the theme directory, not even through a symlink.

## Wallet name and description

`theme.yaml` sets the wallet name and the description of the wallet page:

```yaml
name: Acme Wallet
description: Test wallet of Acme.
```

The wallet page shows the name in its title and header. The decoder page shows it followed by "Decoder". Without `name` the name is "EUDI Dev Wallet".

`description` is the meta description of the wallet page. Search engines and link previews show it. Without `description` the page keeps the built-in text.

The wallet refuses to start when `theme.yaml` has an unknown key.

The name appears on the pages only. Certificates, trusted lists and credentials keep the names of the test infrastructure, such as "EUDI Dev Wallet PID Provider" and "EUDI Dev Demo Issuer". An organization states its own names in the configuration: `tradeName` and `legalName` in the [relying parties file](serve.md#pre-registered-relying-parties) and the display names in the credential templates. [`--issuer-name`](serve.md#wallet-serve) sets the name of the wallet's issuer on its pages, in its issuer metadata and on issued credentials.

## Edition tag

`edition` adds a short tag next to the wallet name in the header of the wallet page and the decoder page:

```yaml
name: Acme Wallet
edition: Business
```

The tag has up to 24 characters. The header shows it in capitals. The browser title stays the wallet name.

## Header menu

`nav` adds entries to the header menu and hides built-in ones:

```yaml
nav:
  links:
    - label: Scenarios
      url: https://acme.example/scenarios
    - label: Demo issuer
      url: issuer/
  hide:
    - get-cli
    - registrar
```

The entries of `links` follow the built-in entries, on the wallet page and the decoder page. There can be up to 8, each with a label of up to 40 characters. A `url` is one of these:

- An `http` or `https` URL. It opens in a new tab.
- A path relative to the wallet page, such as `issuer/`. It keeps the [path prefix](serve.md) of the wallet. A path with a leading slash is refused, because it would leave the prefix.

`hide` lists built-in entries by these names:

| Name | Entry |
|------|-------|
| `decoder` | Decoder |
| `how-to-use` | How to use |
| `get-cli` | Get the CLI |
| `settings` | Settings |
| `templates` | Templates |
| `trust` | Trust & certificates |
| `registrar` | Registrar |
| `github` | GitHub |

Hiding an entry only removes it from the menu. Its dialog and its API stay available.

## Product in the footer

`product` shows a product built on eudi-dev in the footer:

```yaml
product:
  name: Acme Wallet Kit
  version: 1.4.0
  url: https://acme.example/wallet-kit
```

The footer of every page then reads "Acme Wallet Kit 1.4.0" in place of the eudi-dev version and its release channel. `name` is required. `version` and `url` are optional. With `url`, the name in the footer links to it, and the GitHub entry of the header menu links there too. `url` must be an `http` or `https` URL.

## Demo hints

The wallet page links to the demo issuer and the demo verifier, for example in "No offer at hand? Get one from the demo issuer". `demo` sets the targets of these links:

```yaml
demo:
  issuer: https://acme.example/issuer
  verifier: scenarios/
```

Each value is an `http` or `https` URL or a path relative to the wallet page, as in the header menu. Both keys are optional.

`demo.hint` changes the hint below the wallet actions:

```yaml
demo:
  hint:
    text: New here?
    links:
      - label: Start the demo with case 1
        url: case-1/
      - label: All test scenarios
        url: scenarios/
```

The hint then reads "New here? Start the demo with case 1 · All test scenarios". `text` replaces "No offer at hand?" and holds up to 40 characters. `links` replaces the links to the demo issuer and the demo verifier. It has up to 4 entries. Each entry needs a `label` of up to 40 characters and a `url`. The `url` is an `http` or `https` URL or a path relative to the wallet page. Both keys are optional.

[`--no-builtins`](config-files.md) hides the demo hints. A hint stays when the theme sets one of its links. It then shows only the links from the theme. The browser extension hint always links to the built-in demo verifier, so `--no-builtins` hides it.

## Docker and Kubernetes

The wallet reads the theme files on every request. A changed file applies without a restart. When a changed `theme.yaml` has an error, the wallet logs a warning and keeps the texts it loaded before.

With Docker, mount the directory and set `EUDI_DEV_THEME`:

```sh
docker run -p 8085:8085 -v "$PWD/acme:/theme:ro" -e EUDI_DEV_THEME=/theme ghcr.io/eudi-dev/eudi-dev
```

In Kubernetes, put the files in a ConfigMap and mount it:

```sh
kubectl create configmap eudi-dev-theme --from-file=examples/themes/acme
```

```yaml
spec:
  containers:
    - name: wallet
      image: ghcr.io/eudi-dev/eudi-dev
      env:
        - name: EUDI_DEV_THEME
          value: /theme
      volumeMounts:
        - name: theme
          mountPath: /theme
          readOnly: true
  volumes:
    - name: theme
      configMap:
        name: eudi-dev-theme
```

A ConfigMap holds up to 1 MiB. For larger fonts, use another volume type.

## Hidden parts

`theme.css` can hide a part of a page. Every control has a stable `id` ([UI automation](../ui-automation.md)):

```css
#get-cli-link,
#howto-tab-extension {
  display: none;
}
```

The wallet keeps working without the hidden part. Its API stays the same.
