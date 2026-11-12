#!/usr/bin/env bash
# Construye dist/Silence-x86_64.AppImage. Requiere podman y conexión a internet (imagen base de
# Ubuntu, toolchain de Rust y appimagetool). Compila en Ubuntu 22.04 para que corra en distros con
# glibc >= 2.35.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/silence-appimage"
TOOL_VERSION="1.9.0"
TOOL="$CACHE/appimagetool-$TOOL_VERSION-x86_64.AppImage"
IMAGE="silence-appimage-build"
OUT="$HERE/dist"
APPDIR="$HERE/target-appimage/AppDir"

command -v podman >/dev/null || { echo "Falta podman." >&2; exit 1; }
mkdir -p "$CACHE/home" "$CACHE/cargo" "$CACHE/rustup" "$OUT"

echo "→ Preparando el entorno de compilación…"
podman build -q -t "$IMAGE" -f "$HERE/packaging/appimage/Containerfile" "$HERE/packaging/appimage" >/dev/null

echo "→ Compilando en Ubuntu 22.04 (la primera vez tarda varios minutos)…"
podman run --rm --userns=keep-id --security-opt label=disable \
  -v "$HERE":/src -v "$CACHE":/cache -w /src \
  -e HOME=/cache/home -e CARGO_HOME=/cache/cargo -e RUSTUP_HOME=/cache/rustup \
  -e CARGO_TARGET_DIR=/src/target-appimage/cargo \
  "$IMAGE" bash -c '
    set -e
    export PATH="$CARGO_HOME/bin:$PATH"
    if ! command -v cargo >/dev/null; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable >/dev/null
    fi
    cargo build --release --locked
  '

BIN="$HERE/target-appimage/cargo/release/silence"
[[ -x "$BIN" ]] || { echo "No se generó el binario." >&2; exit 1; }

echo "→ Armando el AppDir…"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
install -m 0755 "$BIN" "$APPDIR/usr/bin/silence"
install -m 0644 "$HERE/packaging/silence.svg" "$APPDIR/silence.svg"
cp "$APPDIR/silence.svg" "$APPDIR/.DirIcon"
sed 's|^Exec=.*|Exec=silence|' "$HERE/packaging/silence.desktop" > "$APPDIR/silence.desktop"
cat > "$APPDIR/AppRun" <<'RUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/silence" "$@"
RUN
chmod +x "$APPDIR/AppRun"

if [[ ! -x "$TOOL" ]]; then
  echo "→ Descargando appimagetool $TOOL_VERSION…"
  curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/$TOOL_VERSION/appimagetool-x86_64.AppImage"
  chmod +x "$TOOL"
fi

echo "→ Empaquetando…"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" --no-appstream "$APPDIR" "$OUT/Silence-x86_64.AppImage"
echo
echo "Listo: $OUT/Silence-x86_64.AppImage"
