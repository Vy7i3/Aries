#!/usr/bin/env bash
# Always run from project root (directory that contains this script)
cd "$(dirname "$0")" || exit 1
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m aries "$@"
