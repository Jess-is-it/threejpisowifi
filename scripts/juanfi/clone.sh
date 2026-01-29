#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "${ROOT}/external"

DEST="${ROOT}/external/juanfi-base"
if [[ -d "${DEST}/.git" ]]; then
  echo "JuanFi already cloned at ${DEST}"
  exit 0
fi

git clone https://github.com/ivanalayan15/JuanFi.git "${DEST}"
echo "Cloned JuanFi into ${DEST}"

