#!/usr/bin/env bash
# Run the cloned Oh My Pi agent with the SecureDroid extension loaded.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OMP="$ROOT/oh-my-pi/packages/coding-agent/src/cli.ts"

if [[ ! -f "$OMP" ]]; then
  echo "Oh My Pi is not checked out at $ROOT/oh-my-pi" >&2
  echo "Clone it with: git clone --depth 1 https://github.com/can1357/oh-my-pi.git oh-my-pi" >&2
  exit 1
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "Oh My Pi runs on Bun. Install Bun, then run: (cd \"$ROOT/oh-my-pi\" && bun install)" >&2
  exit 1
fi

if [[ ! -d "$ROOT/oh-my-pi/node_modules" ]]; then
  echo "Install Oh My Pi dependencies first: (cd \"$ROOT/oh-my-pi\" && bun install)" >&2
  exit 1
fi

TARGET="$PWD"
if [[ $# -gt 0 && -d "$1" ]]; then
  TARGET="$(cd "$1" && pwd)"
  shift
fi

cd "$TARGET"
exec bun "$OMP" --extension "$ROOT" --append-system-prompt "$ROOT/prompts/harness.md" "$@"
