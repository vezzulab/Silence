#!/usr/bin/env bash
# Desinstala Silence. NO revierte los cambios que aplicaste: hazlo antes desde la pestaña Historial.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Ejecuta con sudo:  sudo $0" >&2; exit 1; fi
rm -f /usr/local/bin/silence \
      /usr/share/polkit-1/actions/org.silence.policy \
      /usr/share/applications/silence.desktop \
      /usr/share/icons/hicolor/scalable/apps/silence.svg \
      /usr/lib/systemd/user/silence-guardian.service \
      /usr/lib/systemd/user/silence-guardian.timer
echo "Silence desinstalado."
echo "Tu diario de cambios sigue en /var/lib/silence/ y ~/.local/share/silence/ (bórralos si quieres)."
