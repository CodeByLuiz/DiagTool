"""Análise de memória RAM e swap."""
from __future__ import annotations

from .. import config
from ..models import Finding, Status
from ..utils import fmt_num

CAT = "memory"


def analyze(data: dict, os_family: str) -> list:
    out: list = []
    pct, total = data.get("percent_used"), data.get("total_gb")
    if pct is None:
        return [Finding(CAT, "Uso de memória RAM", Status.INDISPONIVEL, "Não foi possível ler a memória.")]
    val = f"{fmt_num(pct)}% de {fmt_num(total, 1)} GB (livre: {fmt_num(data.get('available_gb'), 1)} GB)"
    rec = []
    if pct >= config.MEMORY_PROBLEM_PERCENT:
        st, msg = Status.PROBLEMA, "Memória quase esgotada; o computador tende a ficar lento."
    elif pct >= config.MEMORY_ALERT_PERCENT:
        st, msg = Status.ALERTA, "Uso de memória elevado."
    else:
        st, msg = Status.NORMAL, "Uso de memória normal."
    if st is not Status.NORMAL:
        tops = ", ".join(p["name"] for p in (data.get("top_processes") or [])[:3])
        rec = ["Feche programas e abas de navegador que não esteja usando e reinicie o computador."]
        if tops:
            rec.append(f"Maiores consumidores no momento: {tops}.")
        rec.append("Se o problema for recorrente, avalie aumentar a quantidade de RAM.")
    out.append(Finding(CAT, "Uso de memória RAM", st, msg, val, rec))

    if total is not None and total < config.MEMORY_MIN_TOTAL_GB:
        out.append(Finding(CAT, "Capacidade de RAM", Status.ALERTA,
                           f"Menos de {config.MEMORY_MIN_TOTAL_GB} GB de RAM instalados.", f"{fmt_num(total, 1)} GB",
                           ["Considere ampliar a memória para um desempenho adequado com sistemas atuais."]))
    swap = data.get("swap")
    if swap and swap.get("total_bytes"):
        sp = swap["percent_used"]
        name = "Arquivo de paginação" if os_family == "Windows" else "Memória swap"
        if sp >= config.SWAP_ALERT_PERCENT:
            out.append(Finding(CAT, name, Status.ALERTA, "Uso elevado de memória virtual, indicando falta de RAM.",
                               f"{fmt_num(sp)}%", ["Libere memória fechando aplicativos ou amplie a RAM."]))
        else:
            out.append(Finding(CAT, name, Status.NORMAL, "Uso de memória virtual normal.", f"{fmt_num(sp)}%"))
    return out
