#!/usr/bin/env bash
# Cria "DiagTool.desktop" ao lado do executável: permite abrir com duplo clique
# SEM terminal em Ubuntu (Nautilus) e Linux Mint (Nemo).
# Uso: ./criar_atalho_linux.sh [caminho/para/DiagTool]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EXE="$(readlink -f "${1:-$HERE/DiagTool}")"
[ -x "$EXE" ] || { echo "Executável não encontrado ou sem permissão: $EXE"; exit 1; }
OUT="$(dirname "$EXE")/DiagTool.desktop"
cat > "$OUT" <<DESK
[Desktop Entry]
Type=Application
Name=DiagTool
Comment=Diagnóstico automático do computador
Exec="$EXE"
Icon=utilities-system-monitor
Terminal=false
Categories=System;
DESK
chmod +x "$OUT"
command -v gio >/dev/null && gio set "$OUT" metadata::trusted true 2>/dev/null || true
echo "Atalho criado: $OUT"
echo "Se o gerenciador de arquivos perguntar, escolha 'Permitir execução' / 'Confiar'."
