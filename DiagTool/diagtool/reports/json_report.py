"""Relatório JSON com todos os dados estruturados."""
from __future__ import annotations

import json

from ..models import DiagnosticReport, Status


def build_json(report: DiagnosticReport) -> str:
    sections = {}
    for s in report.sections:
        sections[s.key] = {
            "title": s.title, "status": report.section_status(s.key).value,
            "collected_ok": s.ok, "duration_seconds": s.duration,
            "error": s.error, "warnings": s.warnings, "data": s.data,
        }
    doc = {
        "meta": report.meta,
        "summary": {
            "overall_status": report.overall_status().value,
            "overall_status_code": report.overall_status().code,
            "counts": report.counts(),
            "by_category": {s.key: report.section_status(s.key).value for s in report.sections},
        },
        "findings": [f.to_dict() for f in report.findings],
        "sections": sections,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2, default=str)
