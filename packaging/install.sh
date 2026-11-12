#!/usr/bin/env bash
# Instala Silence en el sistema. Ejecutar con: sudo ./packaging/install.sh
# Compila en modo release (como tu usuario) si hace falta, y copia los archivos a ubicaciones de root.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta con sudo:  sudo $0" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/target/release/silence"

if [[ ! -x "$BIN" ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    echo "→ Compilando (como $SUDO_USER)…"
    sudo -u "$SUDO_USER" -H bash -lc "cd '$HERE' && cargo build --release"
  else
    echo "No existe $BIN. Compila antes con: cargo build --release" >&2
    exit 1
  fi
fi

# 1) El binario debe ser de root y no modificable por nadie más: el helper con permisos lo exige.
install -D -m 0755 -o root -g root "$BIN" /usr/local/bin/silence
# 2) Autorización de polkit atada a esa ruta exacta.
install -D -m 0644 -o root -g root "$HERE/packaging/org.silence.policy" /usr/share/polkit-1/actions/org.silence.policy
# 3) Menú de aplicaciones e ícono.
install -D -m 0644 "$HERE/packaging/silence.desktop" /usr/share/applications/silence.desktop
install -D -m 0644 "$HERE/packaging/silence.svg" /usr/share/icons/hicolor/scalable/apps/silence.svg
# 4) Guardián (temporizador de systemd a nivel de usuario).
install -D -m 0644 "$HERE/packaging/silence-guardian.service" /usr/lib/systemd/user/silence-guardian.service
install -D -m 0644 "$HERE/packaging/silence-guardian.timer" /usr/lib/systemd/user/silence-guardian.timer

# Etiquetado SELinux, si aplica.
command -v restorecon >/dev/null 2>&1 && restorecon -F /usr/local/bin/silence /usr/share/polkit-1/actions/org.silence.policy || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q /usr/share/icons/hicolor || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true

echo
echo "Silence instalado."
echo "  Abrir:         silence   (o desde el menú de aplicaciones)"
echo "  Guardián:      systemctl --user enable --now silence-guardian.timer   (ejecútalo como tu usuario)"
echo "  Desinstalar:   sudo $HERE/packaging/uninstall.sh"
