// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package urlhandler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

// The symlinks of Homebrew and of Nix profiles survive upgrades that replace the
// versioned binary. Other symlinks may point into temporary build directories, so
// use their resolved targets.
func stableBinaryPath(executable string) string {
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return executable
	}
	if !versionedPath(resolved) {
		return resolved
	}
	if resolved != executable {
		return executable
	}
	// Linux resolves the executable through /proc/self/exe, so the link that
	// was run only shows in the command name.
	if invoked, err := exec.LookPath(os.Args[0]); err == nil {
		if abs, err := filepath.Abs(invoked); err == nil {
			if target, err := filepath.EvalSymlinks(abs); err == nil && target == resolved {
				return abs
			}
		}
	}
	return resolved
}

// versionedPath reports a binary path that a package manager replaces on
// upgrade.
func versionedPath(path string) bool {
	slashed := filepath.ToSlash(path)
	return strings.Contains(slashed, "/Cellar/") || strings.HasPrefix(slashed, "/nix/store/")
}

// The script version lets the wallet detect an outdated installed handler.
var handlerScriptVersion = "dev"

func SetScriptVersion(v string) {
	if v = strings.TrimSpace(v); v != "" {
		handlerScriptVersion = v
	}
}

// Rendering separately allows tests to run without changing the machine's URL handler
// registration.
func handlerScriptSource(binaryPath string, opts Options) string {
	handler := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(`#!/bin/bash
BINARY={{BINARY_PATH}}
URI="$1"
LISTENER="http://localhost:{{PORT}}"
PORT="{{PORT}}"
AUTO_ACCEPT="{{AUTO_ACCEPT}}"
# Scheme dispatches are user interactions: without --auto-accept they keep
# the consent dialog even though the handler submits through the API.
if [[ "$AUTO_ACCEPT" == "true" ]]; then INTERACTIVE=false; else INTERACTIVE=true; fi
SERVE_ARGS=({{SERVE_ARGS}})
# Name this script and the release that wrote it on every call. A handler
# installed once keeps running its own code long after the binary is replaced,
# so the wallet has to be able to tell an old one from a current one.
CLIENT_HEADER="{{CLIENT_HEADER}}: eudi-url-handler/{{VERSION}}"
# Set only when this script opens the page itself, below. curl drops a header
# given without a value, so the submit names no page until there is one.
OWNER=""
OWNER_HEADER="{{OWNER_HEADER}}:"
LOG_FILE="/tmp/eudi-dev-wallet.log"
SERVER_LOG="/tmp/eudi-dev-wallet-server.log"

# The active remote set by "wallet use <url>" wins over the baked-in
# local listener. remote.json lives next to this script and is removed by
# "wallet use local".
REMOTE_URL=$(sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$(dirname "$0")/remote.json" 2>/dev/null)
if [[ -n "$REMOTE_URL" ]]; then
  LISTENER="${REMOTE_URL%/}"
  echo "routing to active remote wallet $LISTENER" >>"$LOG_FILE"
fi

listener_ready() {
  curl -sf -H "$CLIENT_HEADER" "$LISTENER/api/credentials" >/dev/null 2>&1
}

# Restart the running server if it was built from an older binary than the one
# on disk. The server reports the SHA-256 of its own executable (hashed at
# startup) via /api/version; a mismatch means it outlived a rebuild.
stop_stale_listener() {
  LOCAL_ID=$(shasum -a 256 "$BINARY" 2>/dev/null | cut -d' ' -f1)
  [[ -z "$LOCAL_ID" ]] && return 0
  VERSION_JSON=$(curl -sf -H "$CLIENT_HEADER" "$LISTENER/api/version" 2>/dev/null)
  SERVER_ID=$(printf '%s' "$VERSION_JSON" | sed -n 's/.*"build_id":"\([0-9a-f]*\)".*/\1/p')
  [[ "$SERVER_ID" == "$LOCAL_ID" ]] && return 0
  echo "wallet server is running an outdated build, restarting" >>"$SERVER_LOG"
  SERVER_PID=$(printf '%s' "$VERSION_JSON" | sed -n 's/.*"pid":\([0-9]*\).*/\1/p')
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null
  else
    lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null
  fi
  for _ in $(seq 1 20); do
    listener_ready || break
    sleep 0.25
  done
}

ensure_listener() {
  # A remote instance is managed elsewhere: never restart it for a build
  # mismatch and never start a local server in its place.
  if [[ -n "$REMOTE_URL" ]]; then
    listener_ready
    return
  fi
  if listener_ready; then
    stop_stale_listener
    if listener_ready; then
      return 0
    fi
  fi
  ARGS=(wallet serve)
  if [[ ${#SERVE_ARGS[@]} -gt 0 ]]; then
    ARGS+=("${SERVE_ARGS[@]}")
  fi
  "$BINARY" "${ARGS[@]}" >>"$SERVER_LOG" 2>&1 &
  for _ in $(seq 1 40); do
    if listener_ready; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# json_string prints $1 as a JSON string. RFC 8259 §7 requires escaping the
# quotation mark, the reverse solidus and the control characters. A URI holds
# no control characters (RFC 3986 §2), so the function drops any others.
json_string() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\t'/\\t}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  printf '"%s"' "$(printf '%s' "$s" | LC_ALL=C tr -d '\000-\037')"
}

submit_offer() {
  curl -sf -X POST "$LISTENER/api/offers" \
    -H "Content-Type: application/json" -H "$CLIENT_HEADER" -H "$OWNER_HEADER" \
    -d "{\"uri\":$(json_string "$URI"),\"interactive\":$INTERACTIVE}" >/dev/null
}

# A remote wallet triggers its browser hook inside its own environment (for
# example a container), where no browser can reach this desktop. Open the
# consent UI from here instead, and before submitting: the submit blocks
# until the user decides in that UI. The local server opens its own tab.
open_remote_ui() {
  if [[ -n "$REMOTE_URL" && "$AUTO_ACCEPT" != "true" ]]; then
    # owner names this page on both acts, so the request submitted below
    # reaches it rather than every visitor of a wallet others also use.
    OWNER=$(uuidgen 2>/dev/null || od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    OWNER_HEADER="{{OWNER_HEADER}}: $OWNER"
    open "$LISTENER/?focus=overview&owner=$OWNER"
  fi
}

submit_presentation() {
  curl -sf -X POST "$LISTENER/api/presentations" \
    -H "Content-Type: application/json" -H "$CLIENT_HEADER" -H "$OWNER_HEADER" \
    -d "{\"uri\":$(json_string "$URI"),\"interactive\":$INTERACTIVE}" >/dev/null
}

accept_cli() {
  case "$1" in
    presentation)
      if [[ "$AUTO_ACCEPT" == "true" ]]; then
        "$BINARY" wallet accept --auto-accept "$URI" 2>&1 | tee -a "$LOG_FILE"
        return 0
      fi
      ;;
  esac
  "$BINARY" wallet accept "$URI" 2>&1 | tee -a "$LOG_FILE"
}

# RFC 3986 §3.1: schemes are case-insensitive.
shopt -s nocasematch
case "$URI" in
  {{OFFER_PATTERNS}})
    if ensure_listener; then
      open_remote_ui
      submit_offer 2>>"$LOG_FILE" && exit 0
      # The submit already reached the remote and created its consent
      # request there: a CLI retry would process the offer a second time.
      [[ -n "$REMOTE_URL" ]] && exit 1
    fi
    accept_cli offer
    ;;
  *)
    if [[ "$AUTO_ACCEPT" == "true" ]]; then
      submit_presentation 2>>"$LOG_FILE" && exit 0
      [[ -n "$REMOTE_URL" ]] && exit 1
      accept_cli presentation
      exit 0
    fi
    if ensure_listener; then
      open_remote_ui
      submit_presentation 2>>"$LOG_FILE" && exit 0
      [[ -n "$REMOTE_URL" ]] && exit 1
    fi
    accept_cli presentation
    ;;
esac
`, "{{BINARY_PATH}}", shellQuote(binaryPath)), "{{PORT}}", fmt.Sprintf("%d", opts.ListenerPort)), "{{AUTO_ACCEPT}}", fmt.Sprintf("%t", opts.AutoAccept))
	handler = strings.ReplaceAll(handler, "{{SERVE_ARGS}}", joinShellArgs(opts.ServeArgs))
	handler = strings.ReplaceAll(handler, "{{OFFER_PATTERNS}}", offerPatterns())
	handler = strings.ReplaceAll(handler, "{{VERSION}}", handlerScriptVersion)
	handler = strings.ReplaceAll(handler, "{{CLIENT_HEADER}}", config.ClientHeader)
	return strings.ReplaceAll(handler, "{{OWNER_HEADER}}", config.OwnerHeader)
}

// offerPatterns matches a credential offer in the handler's case statement.
func offerPatterns() string {
	patterns := make([]string, len(issuanceURLSchemes))
	for i, s := range issuanceURLSchemes {
		patterns[i] = s + "://*"
	}
	return strings.Join(patterns, "|")
}

func joinShellArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
