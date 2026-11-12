#!/usr/bin/env bash
# Genera docs/latest.json a partir de una Release ya publicada en GitHub (por defecto, la última).
# Silence lee ese archivo (servido por GitHub Pages) para avisar de actualizaciones sin las
# limitaciones de consultas de la API. Después hay que hacer commit y push de docs/latest.json.
# Uso: ./packaging/publish-latest.sh [v0.2.1]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="vezzulab/Silence"
TAG="${1:-}"
if [[ -z "$TAG" ]]; then TAG="$(gh release view --repo "$REPO" --json tagName --jq .tagName)"; fi
gh release view "$TAG" --repo "$REPO" --json tagName,name,body,url,isDraft,isPrerelease \
  | jq --arg asset "https://github.com/$REPO/releases/download/$TAG/Silence-x86_64.AppImage" '
      if .isDraft or .isPrerelease then error("la release es borrador o prelanzamiento") else
      {version: (.tagName | ltrimstr("v")), name: .name, notes: (.body // ""), page_url: .url, appimage_url: $asset} end' \
  > "$HERE/docs/latest.json"
echo "Escrito $HERE/docs/latest.json ($TAG)"
