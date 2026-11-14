"""Orquestra o diagnóstico: coleta -> análise -> relatório consolidado.

Cada coletor/analisador roda isolado: uma falha vira um item INDISPONÍVEL e
nunca interrompe os demais.
"""
from __future__ import annotations

import time
import traceback
from datetime import datetime

from . import config
from .analyzers import ANALYZERS
from .collectors import COLLECTORS
from .models import DiagnosticReport, Finding, SectionResult, Status
from .utils import detect_os


def run_diagnostics() -> DiagnosticReport:
    started = datetime.now()
    t_start = time.perf_counter()
    ctx: dict = {}
    sections: list = []

    for key, module in COLLECTORS:
        t0 = time.perf_counter()
        title = config.CATEGORY_TITLES[key]
        try:
            data = module.collect(ctx)
            warnings = data.pop("_warnings", [])
            result = SectionResult(key, title, True, data, warnings)
        except Exception as exc:  # noqa: BLE001
            result = SectionResult(key, title, False, {}, [], f"{type(exc).__name__}: {exc}")
            result.warnings.append(traceback.format_exc(limit=3).strip())
        result.duration = round(time.perf_counter() - t0, 2)
        ctx[key] = result.data
        sections.append(result)

    os_family = ctx.get("system", {}).get("os_family") or detect_os().capitalize()
    findings: list = []
    for sec in sections:
        if not sec.ok:
            findings.append(Finding(sec.key, f"Coleta de {sec.title}", Status.INDISPONIVEL,
                                    f"A coleta falhou: {sec.error}"))
            continue
        try:
            findings += ANALYZERS[sec.key](sec.data, os_family)
        except Exception as exc:  # noqa: BLE001
            sec.warnings.append(f"Falha na análise: {type(exc).__name__}: {exc}")
            findings.append(Finding(sec.key, f"Análise de {sec.title}", Status.INDISPONIVEL,
                                    "Não foi possível analisar os dados coletados."))

    sysdata = ctx.get("system", {})
    meta = {
        "tool": config.APP_NAME, "version": config.APP_VERSION,
        "generated_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round(time.perf_counter() - t_start, 1),
        "detected_os": detect_os(), "hostname": sysdata.get("hostname", "desconhecido"),
        "username": sysdata.get("username", "desconhecido"),
        "os_name": sysdata.get("os_name", ""),
    }
    return DiagnosticReport(meta, sections, findings)
