#!/usr/bin/env bash
# Runs the full computational reproduction (see ../reproduce.sh).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reproduce.sh" "$@"
