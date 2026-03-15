#!/usr/bin/env bash
# Wrapper script for repomap CLI
# Uses uv to run repomap from the tool's own virtualenv

unset VIRTUAL_ENV
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --project "$SCRIPT_DIR" repomap "$@"
