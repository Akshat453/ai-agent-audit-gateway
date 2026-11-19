#!/usr/bin/env bash
# Render every Mermaid source in src/ to PNG (scale 3, white background) with a pinned Mermaid CLI.
set -euo pipefail
cd "$(dirname "$0")"
MMDC="npx -y @mermaid-js/mermaid-cli@11.4.2"
for f in src/*.mmd; do
  out="$(basename "${f%.mmd}").png"
  $MMDC -i "$f" -o "$out" -c src/mermaid-config.json -s 3 -b white -q
  echo "rendered $out"
done
