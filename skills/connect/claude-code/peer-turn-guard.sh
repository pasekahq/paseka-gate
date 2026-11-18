#!/bin/sh
# Claude Code hook: once a session reads peer content, allow only read and paseka tools.
# Reads the hook JSON on stdin; exit 2 blocks the tool call and shows stderr to the model.
set -eu
dir="${XDG_RUNTIME_DIR:-/tmp}/paseka-peer-turn"
input=$(cat)
session=$(printf '%s' "$input" | jq -r '.session_id')
tool=$(printf '%s' "$input" | jq -r '.tool_name // empty')
mark="$dir/$session"

case "$1" in
  mark)
    mkdir -p -m 0700 "$dir"
    : > "$mark"
    ;;
  check)
    [ -e "$mark" ] || exit 0
    case "$tool" in
      Read|Grep|Glob|mcp__paseka__*) exit 0 ;;
    esac
    echo "paseka peer turn: $tool is disabled for the rest of this session; answer through paseka" >&2
    exit 2
    ;;
  clear)
    rm -f "$mark"
    ;;
  *)
    echo "usage: peer-turn-guard.sh mark|check|clear" >&2
    exit 1
    ;;
esac
