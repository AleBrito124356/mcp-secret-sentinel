#!/bin/sh
# secret-sentinel agent hook, run straight from the plugin checkout.
# The hook code is pure stdlib, so any Python 3.10+ works and nothing is installed.
# The event arrives on stdin; its "cwd" field says which project it is about,
# so changing directory here does not change what is scanned.
ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 0
for py in python3 python py; do
    if command -v "$py" >/dev/null 2>&1 \
        && "$py" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
        exec "$py" -m mcp_secret_sentinel hook "$@"
    fi
done
echo "secret-sentinel: Python 3.10+ was not found, so the hook is inactive." >&2
exit 0
