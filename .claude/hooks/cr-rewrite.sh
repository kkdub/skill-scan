#!/usr/bin/env bash
# PreToolUse hook for Claude Code — rewrites whitelisted Bash commands to use cr.
# Fail-open: if jq or cr are not installed, exit 0 silently.

# Fail-open: require jq and cr on PATH
_check_available() {
    command -v "$1" >/dev/null 2>&1
}

_check_available jq || exit 0
_check_available cr || exit 0

# Read JSON payload from stdin
payload=$(cat)

# Extract command from tool_input (fail-open if jq parse fails)
command_str=$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -z "$command_str" ] && exit 0

# Strip 'cd ... &&' prefix for whitelist matching
match_str="$command_str"
cd_re='^cd[[:space:]]+[^&]+&&[[:space:]]*(.*)'
if [[ "$match_str" =~ $cd_re ]]; then
    match_str="${BASH_REMATCH[1]}"
fi

# Strip runner prefixes (uv run, python -m) to find the real command
runner_re='^(uv[[:space:]]+run|python3?[[:space:]]+-m)[[:space:]]+(.*)'
if [[ "$match_str" =~ $runner_re ]]; then
    match_str="${BASH_REMATCH[2]}"
fi

# Extract the base command (first word)
base_cmd="${match_str%% *}"

# Whitelist of commands with registered filters
whitelist=(pytest ls find git)

matched=false
for w in "${whitelist[@]}"; do
    if [ "$base_cmd" = "$w" ]; then
        matched=true
        break
    fi
done

$matched || exit 0

# Build updatedInput: copy ALL tool_input fields, only prepend 'cr ' to command
printf '%s' "$payload" | jq '{
    hookSpecificOutput: {
        updatedInput: (.tool_input | .command = "cr " + .command)
    }
}'
