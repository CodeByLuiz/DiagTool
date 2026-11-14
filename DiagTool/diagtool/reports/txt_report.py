"""Relatório TXT legível, organizado para o analista de suporte."""
from __future__ import annotations

from datetime import datetime

from .. import config
from ..models import DiagnosticReport, Finding, Status
from ..utils import fmt_num, format_bytes, format_duration

W = 78
HEAVY, LIGHT = "=" * W, "-" * W
ORDER = [Status.PROBLEMA, Status.ALERTA, Status.INDISPONIVEL, Status.NORMAL]


def _tag(status: Status) -> str:
    return f"[{status.value}]"


def _kv(label: str, value, indent: int = 2) -> str:
    return f"{' ' * indent}{label + ':':<26}{'n/d' if value in (None, '') else value}"


def _wrap(text: str, indent: int, width: int = W, bullet: bool = False) -> list:
    import textwrap
    hang = 2 if bullet else 0
    return textwrap.wrap(text, width=width, initial_indent=" " * indent,
                         subsequent_indent=" " * (indent + hang)) or [""]


# ------------------------------------------------------ detalhes por seção ----
def _system(d: dict) -> list:
    cpu, hw = d.get("cpu") or {}, d.get("hardware") or {}
    freq = f"{fmt_num(cpu['frequency_mhz'] / 1000, 2)} GHz" if cpu.get("frequency_mhz") else None
    cores = f"{cpu.get('physical_cores')} físicos / {cpu.get('logical_cores')} lógicos"
    return [
        _kv("Nome do computador", d.get("hostname")), _kv("Usuário atual", d.get("username")),
        _kv("Fabricante / modelo", " ".join(x for x in (hw.get("manufacturer"), hw.get("model")) if x)),
        _kv("Número de série", hw.get("serial_number") or "n/d (pode exigir privilégios de administrador)"),
        _kv("BIOS/UEFI", hw.get("bios_version")),
        _kv("Sistema operacional", d.get("os_name")), _kv("Versão", d.get("os_version")),
        _kv("Build / kernel", d.get("os_build")),
        _kv("Arquitetura", f"{d.get('architecture')} ({d.get('architecture_bits')} bits)"),
        _kv("Processador", cpu.get("model")), _kv("Núcleos", cores), _kv("Frequência", freq),
        _kv("Uso de CPU (amostra)", f"{fmt_num(cpu['usage_percent'])}%" if cpu.get("usage_percent") is not None else None),
        _kv("Ligado desde", (d.get("boot_time") or "").replace("T", " ")),
        _kv("Tempo ligado", format_duration(d["uptime_seconds"]) if d.get("uptime_seconds") is not None else None),
    ]


def _memory(d: dict) -> list:
    lines = [_kv("RAM total", f"{fmt_num(d.get('total_gb'), 2)} GB"),
             _kv("RAM disponível", f"{fmt_num(d.get('available_gb'), 2)} GB"),
             _kv("RAM em uso", f"{fmt_num(d.get('used_gb'), 2)} GB ({fmt_num(d.get('percent_used'))}%)")]
    sw = d.get("swap")
    if sw and sw.get("total_bytes"):
        lines.append(_kv("Swap / paginação", f"{fmt_num(sw['used_gb'], 2)} GB de {fmt_num(sw['total_gb'], 2)} GB ({fmt_num(sw['percent_used'])}%)"))
    if d.get("top_processes"):
        lines.append("  Maiores consumidores de memória:")
        for p in d["top_processes"]:
            lines.append(f"    - {p['name']:<28}{format_bytes(p['memory_bytes']):>10}"
                         + (f"  ({p['instances']} processos)" if p["instances"] > 1 else ""))
    return lines


def _storage(d: dict) -> list:
    lines = []
    for v in d.get("volumes") or []:
        lines.append(f"  {v['mountpoint']}  [{v['device']}, {v['fstype'] or '?'}]"
                     + ("  (removível)" if v.get("removable") else ""))
        lines.append(f"    Total {fmt_num(v['total_gb'], 1)} GB | Usado {fmt_num(v['used_gb'], 1)} GB "
                     f"({fmt_num(v['percent_used'])}%) | Livre {fmt_num(v['free_gb'], 1)} GB")
    if d.get("physical_disks"):
        lines.append("  Discos físicos:")
        for p in d["physical_disks"]:
            lines.append(f"    - {p.get('model') or p['name']} — {p.get('media_type')}, "
                         f"{fmt_num(p.get('size_gb') or 0, 0)} GB, saúde: {p.get('health') or 'n/d'}")
    return lines or ["  Sem dados."]


def _network(d: dict) -> list:
    px = d.get("proxy") or {}
    lines = [_kv("IP principal", d.get("primary_ipv4")), _kv("Interface principal", d.get("primary_interface")),
             _kv("Gateway padrão", d.get("default_gateway")),
             _kv("Servidores DNS", ", ".join(d.get("dns_servers") or [])),
             _kv("Domínios de busca DNS", ", ".join(d.get("dns_search_domains") or [])),
             _kv("Proxy", f"ativo ({px.get('server')})" if px.get("enabled") else "não configurado"),
             "  Adaptadores:"]
    for a in d.get("adapters") or []:
        ips = ", ".join(i["address"] for i in a["ipv4"]) or "sem IPv4"
        extra = f", {a['speed_mbps']} Mbps" if a.get("speed_mbps") else ""
        lines.append(f"    - {a['name']} [{a['type']}, {'ativo' if a['is_up'] else 'inativo'}{extra}] "
                     f"IP: {ips} | MAC: {a.get('mac') or 'n/d'}")
    return lines


def _connectivity(d: dict) -> list:
    lines = []
    for p in d.get("pings") or []:
        if not p.get("available"):
            lines.append(f"  Ping {p['label']}: indisponível ({p.get('error')})")
        else:
            avg = f"{fmt_num(p['avg_ms'])} ms" if p.get("avg_ms") is not None else "sem resposta"
            lines.append(f"  Ping {p['label']}: {p['received']}/{p['sent']} respostas, média {avg}, "
                         f"perda {fmt_num(p['loss_percent'], 0)}% [{p['method']}]")
    for r in d.get("dns_resolution") or []:
        lines.append(f"  DNS {r['hostname']}: " + (f"{', '.join(r['addresses'][:2])} em {fmt_num(r['time_ms'])} ms"
                                                    if r["ok"] else f"FALHOU ({r['error']})"))
    for s in d.get("dns_servers_test") or []:
        lines.append(f"  Servidor DNS {s['server']}: " + (f"respondeu em {fmt_num(s['time_ms'])} ms" if s["ok"]
                                                          else f"falhou ({s['error']})"))
    for h in d.get("https_tests") or []:
        lines.append(f"  TCP {h['host']}:{h['port']}: " + (f"conectou em {fmt_num(h['time_ms'])} ms" if h["ok"]
                                                          else f"falhou ({h['error']})"))
    return lines or ["  Sem dados."]


def _security(d: dict) -> list:
    lines = []
    fw = d.get("firewall")
    if fw:
        if "profiles" in fw:
            prof = ", ".join(f"{k}: {'ativado' if v else 'desativado' if v is not None else 'n/d'}"
                             for k, v in fw["profiles"].items())
            lines.append(_kv("Firewall", f"{fw['tool']} — {prof}"))
        else:
            state = {True: "ativo", False: "inativo", None: "indeterminado"}[fw.get("active")]
            lines.append(_kv("Firewall", f"{fw.get('tool') or 'não identificado'} — {state}"))
    av = d.get("antivirus")
    if av and av.get("products") is not None:
        lines.append(_kv("Antivírus", "; ".join(
            f"{p['name']} ({'ativo' if p['enabled'] else 'inativo'}, "
            f"{'atualizado' if p['signatures_up_to_date'] else 'desatualizado'})" for p in av["products"]) or "nenhum"))
    u = d.get("updates") or {}
    if u.get("last_hotfix_id"):
        lines.append(_kv("Última atualização", f"{u['last_hotfix_id']} em {u['last_hotfix_date']}"))
    if u.get("last_check"):
        lines.append(_kv("Última verificação WU", u["last_check"]))
    if u.get("upgradable") is not None:
        lines.append(_kv("Pacotes atualizáveis", f"{u['upgradable']} ({u.get('security_upgradable')} de segurança)"))
    if u.get("package_lists_age_days") is not None:
        lines.append(_kv("Lista de pacotes", f"atualizada há {u['package_lists_age_days']} dia(s)"))
    if "reboot_required" in u and u["reboot_required"] is not None:
        lines.append(_kv("Reinício pendente", "sim" if u["reboot_required"] else "não"))
    return lines or ["  Sem dados."]


RENDERERS = {"system": _system, "memory": _memory, "storage": _storage,
             "network": _network, "connectivity": _connectivity, "security": _security}


# ------------------------------------------------------------- relatório ------
def _finding_block(n: int, f: Finding) -> list:
    title = f"{n}. {_tag(f.status)} {config.CATEGORY_TITLES[f.category]} › {f.item}"
    lines = [title] + _wrap(f.message, 4)
    if f.value:
        lines += _wrap(f"Valor: {f.value}", 4)
    if f.recommendations:
        lines.append("    Recomendações:")
        for r in f.recommendations:
            lines += _wrap("• " + r, 6, bullet=True)
    return lines


def build_txt(report: DiagnosticReport) -> str:
    m = report.meta
    gen = datetime.fromisoformat(m["generated_at"]).strftime("%d/%m/%Y %H:%M:%S")
    counts = report.counts()
    out = [HEAVY, f" {config.APP_NAME} {m['version']} — RELATÓRIO DE DIAGNÓSTICO", HEAVY,
           _kv("Computador", m["hostname"], 1), _kv("Usuário", m["username"], 1),
           _kv("Sistema", m["os_name"], 1), _kv("Data/hora", gen, 1),
           _kv("Duração do diagnóstico", f"{fmt_num(m['duration_seconds'])} s", 1), "",
           f" STATUS GERAL: {_tag(report.overall_status())}", "", LIGHT, " RESUMO POR CATEGORIA", LIGHT]
    for s in report.sections:
        out.append(f"  {s.title:<16}{_tag(report.section_status(s.key))}")
    out += ["", "  Verificações: " + " | ".join(f"{counts[st.value]} {st.value}" for st in ORDER), ""]

    issues = [f for f in report.findings if f.status in (Status.PROBLEMA, Status.ALERTA)]
    issues.sort(key=lambda f: -f.status.severity)
    out += [LIGHT, " PROBLEMAS E ALERTAS — O QUE FAZER", LIGHT]
    if not issues:
        out.append("  Nenhum problema ou alerta encontrado.")
    for i, f in enumerate(issues, 1):
        out += _finding_block(i, f) + [""]

    out += [LIGHT, " DETALHES POR CATEGORIA", LIGHT]
    for n, s in enumerate(report.sections, 1):
        out += ["", f"{n}. {s.title.upper()}  {_tag(report.section_status(s.key))}", "-" * 40]
        if not s.ok:
            out.append(f"  Coleta falhou: {s.error}")
        else:
            try:
                out += RENDERERS[s.key](s.data)
            except Exception as exc:  # noqa: BLE001
                out.append(f"  (erro ao exibir detalhes: {exc})")
        out.append("  Verificações:")
        for f in report.findings_for(s.key):
            line = f"    {_tag(f.status):<16}{f.item}"
            out.append(line)
            out += _wrap(f.message + (f" [{f.value}]" if f.value else ""), 8)
    warns = [(s.title, w) for s in report.sections for w in s.warnings]
    if warns:
        out += ["", LIGHT, " AVISOS DA COLETA (itens que não puderam ser lidos)", LIGHT]
        for t, w in warns:
            out += _wrap(f"- {t}: {w.splitlines()[-1] if w else ''}", 2)
    out += ["", HEAVY, f" Gerado por {config.APP_NAME} — somente leitura; nenhum dado foi enviado à rede externa.", HEAVY, ""]
    return "\n".join(out)
