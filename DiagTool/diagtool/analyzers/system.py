"""Análise do sistema: tempo ligado, CPU, suporte do SO e hardware."""
from __future__ import annotations

from datetime import date

from .. import config
from ..models import Finding, Status
from ..utils import fmt_num, format_duration

CAT = "system"


def _os_support(data: dict, os_family: str) -> list:
    if os_family == "Windows":
        build = data.get("os_build_number") or 0
        name = data.get("os_name", "Windows")
        if build and build < 22000:
            return [Finding(CAT, "Suporte do sistema operacional", Status.ALERTA,
                            "O Windows 10 atingiu o fim do suporte em 14/10/2025 e não recebe mais "
                            "atualizações de segurança gratuitas (exceto no programa ESU).", name,
                            ["Atualize para o Windows 11 se o hardware for compatível (Configurações > "
                             "Windows Update) ou planeje a substituição do equipamento.",
                             "Se for necessário manter o Windows 10, verifique a inscrição no programa ESU."])]
        if build and build < config.WINDOWS_11_MIN_SUPPORTED_BUILD:
            return [Finding(CAT, "Suporte do sistema operacional", Status.ALERTA,
                            "Esta versão do Windows 11 está fora do período de suporte.", name,
                            ["Instale a atualização de recursos mais recente pelo Windows Update."])]
        return [Finding(CAT, "Suporte do sistema operacional", Status.NORMAL,
                        "Versão do Windows dentro do período de suporte.", name)]
    key = (data.get("os_id"), (data.get("os_version_id") or "").split(".")[0] if data.get("os_id") == "linuxmint"
           else data.get("os_version_id"))
    eol = config.LINUX_EOL.get(key)
    if eol is None:
        return []
    name = data.get("os_name", "Linux")
    if eol < date.today():
        return [Finding(CAT, "Suporte do sistema operacional", Status.PROBLEMA,
                        f"Esta versão teve o suporte encerrado em {eol.strftime('%d/%m/%Y')}.", name,
                        ["Atualize para uma versão com suporte (LTS mais recente) para voltar a receber "
                         "correções de segurança."])]
    return [Finding(CAT, "Suporte do sistema operacional", Status.NORMAL,
                    f"Suporte padrão até {eol.strftime('%d/%m/%Y')}.", name)]


def analyze(data: dict, os_family: str) -> list:
    out: list = []
    up = data.get("uptime_seconds")
    if up is None:
        out.append(Finding(CAT, "Tempo ligado", Status.INDISPONIVEL, "Não foi possível obter o tempo ligado."))
    else:
        days = up / 86400
        val = format_duration(up)
        if days >= config.UPTIME_PROBLEM_DAYS:
            st, msg = Status.PROBLEMA, f"Computador sem reiniciar há mais de {config.UPTIME_PROBLEM_DAYS} dias."
        elif days >= config.UPTIME_ALERT_DAYS:
            st, msg = Status.ALERTA, f"Computador sem reiniciar há mais de {config.UPTIME_ALERT_DAYS} dias."
        else:
            st, msg = Status.NORMAL, "Tempo ligado dentro do esperado."
        rec = []
        if st is not Status.NORMAL:
            rec.append("Reinicie o computador para aplicar atualizações e liberar recursos.")
            if os_family == "Windows":
                rec.append("No Windows use 'Reiniciar' (e não 'Desligar'): a Inicialização Rápida mantém "
                           "o sistema ativo mesmo após desligar.")
        out.append(Finding(CAT, "Tempo ligado", st, msg, val, rec))

    cpu = (data.get("cpu") or {}).get("usage_percent")
    if cpu is None:
        out.append(Finding(CAT, "Uso de CPU", Status.INDISPONIVEL, "Não foi possível medir o uso de CPU."))
    else:
        rec = []
        if cpu >= config.CPU_PROBLEM_PERCENT:
            st, msg = Status.PROBLEMA, "CPU praticamente saturada."
        elif cpu >= config.CPU_ALERT_PERCENT:
            st, msg = Status.ALERTA, "Uso de CPU elevado."
        else:
            st, msg = Status.NORMAL, "Uso de CPU normal."
        if st is not Status.NORMAL:
            rec = ["Identifique o processo responsável (Gerenciador de Tarefas no Windows; "
                   "Monitor do Sistema/htop no Linux) e encerre ou investigue-o.",
                   "Execute uma verificação de antivírus se o processo for desconhecido."]
        out.append(Finding(CAT, "Uso de CPU", st, msg, f"{fmt_num(cpu)}%", rec))

    out += _os_support(data, os_family)
    if not data.get("os_name"):
        out.append(Finding(CAT, "Sistema operacional", Status.INDISPONIVEL, "Não foi possível identificar o SO."))
    return out
