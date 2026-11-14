"""Análise de volumes e saúde de discos físicos."""
from __future__ import annotations

from .. import config
from ..models import Finding, Status
from ..utils import fmt_num

CAT = "storage"


def _cleanup_tips(os_family: str) -> list:
    if os_family == "Windows":
        return ["Use Configurações > Sistema > Armazenamento (Limpeza de Disco) para remover arquivos temporários.",
                "Esvazie a Lixeira e desinstale programas que não são mais usados.",
                "Mova arquivos grandes (vídeos, backups) para um disco externo ou para a nuvem."]
    return ["Esvazie a Lixeira e remova arquivos grandes não utilizados (ex.: 'du -sh ~/*').",
            "Libere cache de pacotes com 'sudo apt clean' e remova pacotes órfãos com 'sudo apt autoremove'.",
            "Mova arquivos grandes para um disco externo ou para a nuvem."]


def analyze(data: dict, os_family: str) -> list:
    out: list = []
    volumes = data.get("volumes") or []
    if not volumes:
        out.append(Finding(CAT, "Volumes de disco", Status.INDISPONIVEL, "Nenhum volume pôde ser lido."))
    for v in volumes:
        pct = v["percent_used"]
        label = v["mountpoint"]
        val = f"{fmt_num(pct)}% usado — livre {fmt_num(v['free_gb'], 1)} GB de {fmt_num(v['total_gb'], 1)} GB"
        if pct >= config.DISK_PROBLEM_PERCENT:
            st, msg, rec = Status.PROBLEMA, "Disco praticamente cheio.", _cleanup_tips(os_family)
        elif pct >= config.DISK_ALERT_PERCENT:
            st, msg, rec = Status.ALERTA, "Pouco espaço livre.", _cleanup_tips(os_family)
        else:
            st, msg, rec = Status.NORMAL, "Espaço em disco adequado.", []
        out.append(Finding(CAT, f"Espaço no volume {label}", st, msg, val, rec))

    phys = data.get("physical_disks")
    if phys is None:
        out.append(Finding(CAT, "Saúde dos discos físicos", Status.INDISPONIVEL,
                           "Não foi possível consultar os discos físicos."))
    else:
        for d in phys:
            name = f"Disco {d.get('model') or d.get('name')}"
            h = (d.get("health") or "").lower()
            if h == "healthy":
                out.append(Finding(CAT, name, Status.NORMAL, "Saúde do disco reportada como saudável.", d.get("media_type")))
            elif h == "warning":
                out.append(Finding(CAT, name, Status.ALERTA, "O disco reporta aviso de saúde.", d.get("media_type"),
                                   ["Faça backup imediato dos dados importantes e avalie trocar o disco."]))
            elif h == "unhealthy":
                out.append(Finding(CAT, name, Status.PROBLEMA, "O disco reporta falha de saúde.", d.get("media_type"),
                                   ["Faça backup IMEDIATO e substitua o disco o quanto antes."]))
            else:
                out.append(Finding(CAT, name, Status.INDISPONIVEL,
                                   "Estado de saúde (SMART) não disponível sem privilégios de administrador.",
                                   f"{d.get('media_type')} — {fmt_num(d.get('size_gb') or 0, 0)} GB"))
    return out
