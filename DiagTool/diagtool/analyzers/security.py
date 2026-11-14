"""Análise de segurança básica: firewall, antivírus e atualizações."""
from __future__ import annotations

from .. import config
from ..models import Finding, Status

CAT = "security"


def _firewall(fw, os_family: str) -> list:
    if not fw:
        return [Finding(CAT, "Firewall", Status.INDISPONIVEL, "Não foi possível consultar o estado do firewall.")]
    if os_family == "Windows":
        out = []
        svc = fw.get("service_status")
        if svc and svc != "running":
            out.append(Finding(CAT, "Serviço do Firewall do Windows", Status.PROBLEMA,
                               "O serviço do Windows Defender Firewall não está em execução.", svc,
                               ["Inicie o serviço 'Firewall do Windows Defender' (mpssvc) ou procure o administrador."]))
        for prof, enabled in fw["profiles"].items():
            item = f"Firewall — perfil {prof}"
            if enabled is None:
                out.append(Finding(CAT, item, Status.INDISPONIVEL, "Estado não disponível."))
            elif enabled:
                out.append(Finding(CAT, item, Status.NORMAL, "Firewall ativado."))
            else:
                st = Status.PROBLEMA if prof == "Pública" else Status.ALERTA
                out.append(Finding(CAT, item, st, "Firewall desativado.", None,
                                   ["Ative o Firewall do Windows (Segurança do Windows > Firewall e proteção de rede), "
                                    "a menos que outro firewall corporativo esteja em uso."]))
        return out
    if fw.get("active") is True:
        return [Finding(CAT, "Firewall", Status.NORMAL, "Firewall ativo.", fw.get("tool"))]
    if fw.get("active") is False:
        return [Finding(CAT, "Firewall", Status.ALERTA, f"O firewall ({fw['tool']}) está instalado, mas desativado.",
                        fw.get("tool"), ["Ative com 'sudo ufw enable' (requer administrador) ou pela interface "
                                         "'Firewall' / GUFW."])]
    return [Finding(CAT, "Firewall", Status.INDISPONIVEL,
                    "Não foi possível determinar o estado do firewall sem privilégios de administrador "
                    "(ou nenhum firewall gerenciável foi encontrado).", None,
                    ["Verifique manualmente com 'sudo ufw status' ou 'sudo iptables -L'."])]


def _antivirus(av) -> list:
    if av is None or av.get("products") is None:
        return [Finding(CAT, "Antivírus", Status.INDISPONIVEL,
                        "Não foi possível consultar o antivírus (Central de Segurança indisponível).")]
    out = []
    products = av["products"]
    if not products:
        return [Finding(CAT, "Antivírus", Status.PROBLEMA, "Nenhum antivírus registrado no Windows.", None,
                        ["Ative o Microsoft Defender (Segurança do Windows) ou instale uma solução corporativa."])]
    for p in products:
        if not p["enabled"]:
            out.append(Finding(CAT, f"Antivírus — {p['name']}", Status.PROBLEMA, "Proteção desativada.", None,
                               ["Ative a proteção em tempo real ou verifique a solução de antivírus instalada."]))
        elif not p["signatures_up_to_date"]:
            out.append(Finding(CAT, f"Antivírus — {p['name']}", Status.ALERTA, "Definições de vírus desatualizadas.",
                               None, ["Execute a atualização de definições do antivírus."]))
        else:
            out.append(Finding(CAT, f"Antivírus — {p['name']}", Status.NORMAL, "Ativo e atualizado."))
    d = av.get("defender")
    active_defender = any("defender" in p["name"].lower() and p["enabled"] for p in products)
    if d and active_defender:
        age = d.get("signature_age_days", 0)
        if age >= config.AV_SIGNATURE_PROBLEM_DAYS:
            st = Status.PROBLEMA
        elif age >= config.AV_SIGNATURE_ALERT_DAYS:
            st = Status.ALERTA
        else:
            st = Status.NORMAL
        out.append(Finding(CAT, "Definições do Microsoft Defender", st,
                           "Definições atualizadas." if st is Status.NORMAL else "Definições antigas.",
                           f"{age} dia(s) — {d.get('signature_updated')}",
                           [] if st is Status.NORMAL else ["Atualize pelo Windows Update ou Segurança do Windows."]))
    return out


def _updates(upd, err, os_family: str) -> list:
    out = []
    if not upd or err:
        out.append(Finding(CAT, "Atualizações do sistema", Status.INDISPONIVEL,
                           f"Não foi possível obter informações de atualização ({err or 'sem dados'})."))
    elif os_family == "Windows":
        age = upd.get("last_hotfix_age_days")
        if age is None:
            out.append(Finding(CAT, "Atualizações do Windows", Status.INDISPONIVEL, "Sem histórico de atualizações."))
        else:
            val = f"{upd['last_hotfix_id']} em {upd['last_hotfix_date']} ({age} dias)"
            rec = ["Abra Configurações > Windows Update e instale as atualizações pendentes."]
            if age >= config.WINDOWS_PATCH_PROBLEM_DAYS:
                out.append(Finding(CAT, "Atualizações do Windows", Status.PROBLEMA,
                                   "Última atualização instalada há muito tempo.", val, rec))
            elif age >= config.WINDOWS_PATCH_ALERT_DAYS:
                out.append(Finding(CAT, "Atualizações do Windows", Status.ALERTA,
                                   "Última atualização instalada há mais de um mês.", val, rec))
            else:
                out.append(Finding(CAT, "Atualizações do Windows", Status.NORMAL,
                                   "Sistema atualizado recentemente.", val))
    else:
        total, sec = upd.get("upgradable") or 0, upd.get("security_upgradable") or 0
        age = upd.get("package_lists_age_days")
        val = f"{total} pendente(s), {sec} de segurança"
        rec = ["Atualize com o Gerenciador de Atualizações ou 'sudo apt update && sudo apt upgrade'."]
        if sec >= config.LINUX_SECURITY_PENDING_PROBLEM:
            out.append(Finding(CAT, "Atualizações de segurança", Status.PROBLEMA,
                               "Muitas atualizações de segurança pendentes.", val, rec))
        elif sec > 0 or total >= config.LINUX_PENDING_ALERT:
            out.append(Finding(CAT, "Atualizações de segurança", Status.ALERTA,
                               "Há atualizações pendentes.", val, rec))
        else:
            out.append(Finding(CAT, "Atualizações de segurança", Status.NORMAL, "Nenhuma atualização pendente.", val))
        if age is not None and age >= config.LINUX_APT_CACHE_ALERT_DAYS:
            out.append(Finding(CAT, "Lista de pacotes (apt)", Status.ALERTA,
                               "A lista de pacotes não é atualizada há muito tempo; os números acima podem estar defasados.",
                               f"{age} dias", ["Execute 'sudo apt update' para checar novas atualizações."]))
    if upd and upd.get("reboot_required"):
        out.append(Finding(CAT, "Reinício pendente", Status.ALERTA,
                           "O sistema precisa ser reiniciado para concluir atualizações.", None,
                           ["Salve seu trabalho e reinicie o computador."]))
    return out


def analyze(data: dict, os_family: str) -> list:
    out = _firewall(data.get("firewall"), os_family)
    if os_family == "Windows":
        out += _antivirus(data.get("antivirus"))
    out += _updates(data.get("updates"), data.get("update_error"), os_family)
    return out
