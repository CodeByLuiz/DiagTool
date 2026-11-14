"""Análise dos testes de conectividade (ping, DNS, HTTPS)."""
from __future__ import annotations

from .. import config
from ..models import Finding, Status
from ..utils import fmt_num

CAT = "connectivity"


def _ping_finding(p: dict, internet_ok: bool) -> Finding:
    is_gw = p["key"] == "gateway"
    item = f"Ping {p['label']}"
    if not p.get("available"):
        return Finding(CAT, item, Status.INDISPONIVEL, f"Teste não executado: {p.get('error')}.")
    method = "" if p["method"] == "icmp" else f" (via {p['method'].upper()})"
    if p["received"] == 0:
        if internet_ok:
            return Finding(CAT, item, Status.ALERTA,
                           "Sem resposta ao ping, mas a Internet responde por outros testes (possível bloqueio de ICMP).",
                           "100% de perda" + method,
                           ["Se o equipamento não for um roteador que bloqueia ping de propósito, verifique as regras do firewall."])
        rec = (["Verifique cabo/Wi-Fi e o roteador; reinicie o roteador/modem."] if is_gw else
               ["Verifique se há acesso à Internet no roteador; reinicie o modem e contate o provedor se persistir."])
        return Finding(CAT, item, Status.PROBLEMA, "Sem resposta.", "100% de perda" + method, rec)
    avg, loss = p["avg_ms"], p["loss_percent"]
    lat_alert = config.GATEWAY_LATENCY_ALERT_MS if is_gw else config.LATENCY_ALERT_MS
    lat_problem = config.GATEWAY_LATENCY_PROBLEM_MS if is_gw else config.LATENCY_PROBLEM_MS
    val = (f"latência média {fmt_num(avg)} ms (mín {fmt_num(p['min_ms'])} / máx {fmt_num(p['max_ms'])}), "
           f"perda {fmt_num(loss, 0)}%{method}")
    rec = []
    if loss >= config.PACKET_LOSS_PROBLEM_PERCENT or avg > lat_problem:
        st, msg = Status.PROBLEMA, "Conexão instável ou muito lenta."
    elif loss >= config.PACKET_LOSS_ALERT_PERCENT or avg > lat_alert:
        st, msg = Status.ALERTA, "Perda de pacotes ou latência acima do ideal."
    else:
        st, msg = Status.NORMAL, "Latência e perda de pacotes adequadas."
    if st is not Status.NORMAL:
        rec = ["Se estiver em Wi-Fi, aproxime-se do roteador ou use cabo de rede.",
               "Verifique downloads/streaming consumindo banda e reinicie o roteador.",
               "Se persistir, teste com outro dispositivo para isolar se o problema é da rede ou do computador."]
    return Finding(CAT, item, st, msg, val, rec)


def analyze(data: dict, os_family: str) -> list:
    out: list = []
    pings = data.get("pings") or []
    dns_res = data.get("dns_resolution") or []
    srv = data.get("dns_servers_test") or []
    https = data.get("https_tests") or []

    inet_pings = [p for p in pings if p["key"] != "gateway" and p.get("available")]
    ping_ok = any(p["received"] > 0 for p in inet_pings)
    https_ok = any(h["ok"] for h in https)
    internet_ok = ping_ok or https_ok
    dns_ok_any = any(d["ok"] for d in dns_res)

    if not inet_pings and not https:
        out.append(Finding(CAT, "Acesso à Internet", Status.INDISPONIVEL, "Nenhum teste de Internet pôde ser executado."))
    elif internet_ok:
        out.append(Finding(CAT, "Acesso à Internet", Status.NORMAL, "Computador consegue acessar a Internet."))
    else:
        gw = next((p for p in pings if p["key"] == "gateway" and p.get("available")), None)
        gw_ok = bool(gw and gw["received"] > 0)
        rec = ["Reinicie o roteador/modem e o computador."]
        rec.insert(0, "O gateway responde: o problema parece estar no roteador/modem ou no provedor de Internet."
                   if gw_ok else "O gateway não responde: verifique cabo, Wi-Fi e o roteador local.")
        rec.append("Verifique se há proxy ou VPN configurados que possam bloquear o acesso.")
        out.append(Finding(CAT, "Acesso à Internet", Status.PROBLEMA, "Sem acesso à Internet.", None, rec))

    for p in pings:
        out.append(_ping_finding(p, internet_ok))

    for d in dns_res:
        item = f"Resolução DNS de {d['hostname']}"
        if d["ok"]:
            t = d["time_ms"]
            if t > config.DNS_TIME_PROBLEM_MS:
                st, msg = Status.PROBLEMA, "Resolução de nomes muito lenta."
            elif t > config.DNS_TIME_ALERT_MS:
                st, msg = Status.ALERTA, "Resolução de nomes mais lenta que o esperado."
            else:
                st, msg = Status.NORMAL, "Nome resolvido com sucesso."
            rec = ([] if st is Status.NORMAL else
                   ["Teste outro servidor DNS (ex.: 8.8.8.8 ou 1.1.1.1) e limpe o cache DNS "
                    + ("('ipconfig /flushdns')." if os_family == "Windows" else "('resolvectl flush-caches').")])
            out.append(Finding(CAT, item, st, msg, f"{fmt_num(t)} ms → {', '.join(d['addresses'][:2])}", rec))
        else:
            all_fail = not dns_ok_any
            out.append(Finding(CAT, item, Status.PROBLEMA if all_fail else Status.ALERTA,
                               "Falha ao resolver o nome." if all_fail else "Falha isolada ao resolver este nome.",
                               d.get("error"),
                               ["Verifique os servidores DNS configurados e a conexão com a rede.",
                                "Limpe o cache DNS e teste com outro servidor DNS (8.8.8.8 / 1.1.1.1)."]))

    for s in srv:
        item = f"Servidor DNS {s['server']}"
        if s["ok"]:
            st = Status.ALERTA if s["time_ms"] > config.DNS_TIME_ALERT_MS else Status.NORMAL
            out.append(Finding(CAT, item, st, "Servidor respondeu à consulta." if st is Status.NORMAL
                               else "Servidor DNS respondendo lentamente.", f"{fmt_num(s['time_ms'])} ms",
                               [] if st is Status.NORMAL else ["Considere usar outro servidor DNS."]))
        else:
            st = Status.ALERTA if dns_ok_any else Status.PROBLEMA
            out.append(Finding(CAT, item, st, "Servidor DNS não respondeu corretamente.", s.get("error"),
                               ["Verifique se o servidor DNS está acessível; configure um alternativo.",
                                "Em redes corporativas, confirme com a equipe de infraestrutura."]))

    if https:
        if https_ok:
            best = min((h["time_ms"] for h in https if h["ok"] and h["time_ms"] is not None), default=None)
            out.append(Finding(CAT, "Acesso web (HTTPS/443)", Status.NORMAL, "Conexão TCP na porta 443 estabelecida.",
                               None if best is None else f"{fmt_num(best)} ms"))
        else:
            out.append(Finding(CAT, "Acesso web (HTTPS/443)", Status.ALERTA if ping_ok else Status.PROBLEMA,
                               "Não foi possível conectar na porta 443.", https[0].get("error"),
                               ["Verifique proxy, firewall e filtros de conteúdo.",
                                "Confirme se o DNS está resolvendo corretamente."]))
    return out
