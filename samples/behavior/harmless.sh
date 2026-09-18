#!/usr/bin/env bash
# A perfectly ordinary helper script (harmless demo).
set -euo pipefail

greeting="${1:-world}"
echo "Hello, ${greeting}!"
date
