#!/usr/bin/env bash
# Mirror the shared `shade/` engine between codex-shade and claude-shade.
#
# The two repos vendor an identical engine and differ only in hooks/. This
# copies one over the other so a fix made in either lands in both.
#
#   tools/sync-engine.sh ../claude-shade            # pull engine from there
#   tools/sync-engine.sh --check ../claude-shade    # report drift, change nothing
#   tools/sync-engine.sh --push ../claude-shade     # send this engine over there

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=pull
case "${1:-}" in
  --check) MODE=check; shift ;;
  --push)  MODE=push;  shift ;;
esac

OTHER="${1:-}"
if [ -z "$OTHER" ] || [ ! -d "$OTHER/shade" ]; then
  echo "usage: $0 [--check|--push] <path to the other checkout>" >&2
  exit 2
fi
OTHER="$(cd "$OTHER" && pwd)"

if [ "$MODE" = check ]; then
  DIFF=(diff -rq -x __pycache__ -x "*.pyc")
if "${DIFF[@]}" "$HERE/shade" "$OTHER/shade" >/dev/null 2>&1; then
    echo "engine matches $OTHER"
  else
    echo "engine DIFFERS from $OTHER:"
    "${DIFF[@]}" "$HERE/shade" "$OTHER/shade" || true
    exit 1
  fi
  exit 0
fi

if [ "$MODE" = push ]; then
  cp "$HERE"/shade/*.py "$OTHER"/shade/
  echo "pushed engine -> $OTHER/shade"
else
  cp "$OTHER"/shade/*.py "$HERE"/shade/
  echo "pulled engine <- $OTHER/shade"
fi

python3 -m unittest discover -s "$HERE/tests" >/dev/null && echo "tests pass"
