"""Geração e gravação dos relatórios."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from .. import config
from ..models import DiagnosticReport
from ..utils import get_desktop_path, sanitize_filename
from .json_report import build_json
from .txt_report import build_txt


def prepare_output_dir(base: Optional[Path] = None) -> Path:
    """Cria <Área de Trabalho>/DiagTool-Relatorios (com alternativas se falhar)."""
    bases = [base] if base else [get_desktop_path()]
    bases += [Path.home(), Path(tempfile.gettempdir())]
    for b in bases:
        target = Path(b) / config.OUTPUT_FOLDER_NAME
        try:
            target.mkdir(parents=True, exist_ok=True)
            if os.access(target, os.W_OK):
                return target
        except OSError:
            continue
    raise OSError("Não foi possível criar a pasta de relatórios.")


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    i = 2
    while path.with_name(f"{path.stem}_{i}{path.suffix}").exists():
        i += 1
    return path.with_name(f"{path.stem}_{i}{path.suffix}")


def write_reports(report: DiagnosticReport, out_dir: Path) -> dict:
    """Grava TXT e JSON (UTF-8) com data/hora no nome. Retorna os caminhos."""
    stamp = datetime.fromisoformat(report.meta["generated_at"]).strftime("%Y-%m-%d_%H-%M-%S")
    stem = f"{config.APP_NAME}_{sanitize_filename(report.meta['hostname'])}_{stamp}"
    paths = {}
    txt = _unique(out_dir / f"{stem}.txt")
    txt.write_text(build_txt(report), encoding="utf-8-sig")  # BOM: abre bem no Bloco de Notas antigo
    paths["txt"] = txt
    js = _unique(out_dir / f"{stem}.json")
    js.write_text(build_json(report), encoding="utf-8")
    paths["json"] = js
    return paths
