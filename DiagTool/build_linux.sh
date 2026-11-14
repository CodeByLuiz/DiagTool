#!/usr/bin/env bash
# Compila o executável Linux do DiagTool (Ubuntu / Linux Mint).
# Dica: compile na versão mais ANTIGA que pretende suportar (compatibilidade glibc).
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
python -m pytest -q
python build.py
chmod +x dist/DiagTool
echo
echo "Pronto: dist/DiagTool"
