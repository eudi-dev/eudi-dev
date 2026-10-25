# Themes

A theme changes the logo and the colours of every page of a self-hosted wallet: the wallet, the decoder, the demo issuer, the demo verifier and the registrar. It is a directory with up to three files:

```
acme/
  theme.css      colours and fonts
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

## Docker and Kubernetes

The wallet reads the theme files on every request. A changed file applies without a restart.

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
