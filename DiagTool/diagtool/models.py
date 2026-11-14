"""Modelos de dados compartilhados entre coleta, análise e relatórios."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional


class Status(Enum):
    NORMAL = "NORMAL"
    ALERTA = "ALERTA"
    PROBLEMA = "PROBLEMA"
    INDISPONIVEL = "INDISPONÍVEL"

    @property
    def severity(self) -> int:
        return {"NORMAL": 0, "INDISPONIVEL": 1, "ALERTA": 2, "PROBLEMA": 3}[self.name]

    @property
    def code(self) -> str:
        return self.name.lower()


def worst(statuses: Iterable[Status]) -> Status:
    """Status consolidado: o pior entre os itens; INDISPONÍVEL só se todos forem."""
    items = list(statuses)
    real = [s for s in items if s is not Status.INDISPONIVEL]
    if not real:
        return Status.INDISPONIVEL
    return max(real, key=lambda s: s.severity)


@dataclass
class Finding:
    """Resultado de uma verificação, já classificado."""
    category: str
    item: str
    status: Status
    message: str
    value: Optional[str] = None
    recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "item": self.item,
            "status": self.status.value,
            "status_code": self.status.code,
            "message": self.message,
            "value": self.value,
            "recommendations": list(self.recommendations),
        }


@dataclass
class SectionResult:
    """Resultado bruto da coleta de uma categoria."""
    key: str
    title: str
    ok: bool
    data: dict
    warnings: list = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class DiagnosticReport:
    meta: dict
    sections: list
    findings: list

    def findings_for(self, key: str) -> list:
        return [f for f in self.findings if f.category == key]

    def section_status(self, key: str) -> Status:
        return worst(f.status for f in self.findings_for(key))

    def overall_status(self) -> Status:
        return worst(f.status for f in self.findings)

    def counts(self) -> dict:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    def get(self, key: str) -> dict:
        for s in self.sections:
            if s.key == key:
                return s.data
        return {}
