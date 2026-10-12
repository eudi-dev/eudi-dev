#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-dev}"
LDFLAGS="-s -w -X github.com/eudi-dev/eudi-dev/v2/cmd.Version=${VERSION}"

echo "Formatting..."
go run golang.org/x/tools/cmd/goimports@latest -w -local github.com/eudi-dev/eudi-dev/v2 .
gofmt -w .

echo "Building eudi ${VERSION}..."
go build -ldflags "$LDFLAGS" -o eudi .
echo "Done: ./eudi"

CURRENT_SHELL="$(basename "$SHELL")"
BINARY="${PROJECT_DIR}/eudi"

case "$CURRENT_SHELL" in
  zsh)
    COMP_DIR="${HOME}/.zsh/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion zsh > "$COMP_DIR/_eudi"
    echo "Installed zsh completions to $COMP_DIR/_eudi"
    echo "Run 'source $COMP_DIR/_eudi' or add $COMP_DIR to your fpath and restart your shell."
    ;;
  bash)
    COMP_DIR="${HOME}/.local/share/bash-completion/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion bash > "$COMP_DIR/eudi"
    echo "Installed bash completions to $COMP_DIR/eudi"
    echo "Run 'source $COMP_DIR/eudi' or restart your shell."
    ;;
  fish)
    COMP_DIR="${HOME}/.config/fish/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion fish > "$COMP_DIR/eudi.fish"
    echo "Installed fish completions to $COMP_DIR/eudi.fish"
    ;;
  *)
    echo "Unknown shell '$CURRENT_SHELL', skipping completion installation."
    ;;
esac
