#!/usr/bin/env bash
# Copy the browser verifier and both vector files from this repo into the
# bitsaga webapp under their served names, stamping the source commit into
# the JS header. Usage: js/sync-webapp.sh [webapp dir]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
webapp=${1:-"$HOME/apps/bitsaga/webapp"}
commit=$(git -C "$here" rev-parse --short HEAD)
[ -z "$(git -C "$here" status --porcelain -- js/)" ] || { echo "js/ has uncommitted changes; commit first" >&2; exit 1; }

{
  echo "/* Generated from shielded-probe commit $commit (js/shielded-verify.js). Do not edit here. */"
  cat "$here/shielded-verify.js"
} > "$webapp/shielded-verify.js"
cp "$here/vectors-signet.json" "$webapp/shielded-data.json"
cp "$here/vectors-mainnet.json" "$webapp/shielded-data-mainnet.json"
echo "synced commit $commit to $webapp"
