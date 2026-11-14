"""Análise da configuração de rede."""
from __future__ import annotations

from ..models import Finding, Status

CAT = "network"


def analyze(data: dict, os_family: str) -> list:
    out: list = []
    adapters = data.get("adapters") or []
    active = [a for a in adapters if a["is_up"] and not a["is_loopback"] and not a["is_virtual"]
              and a["ipv4"]]
    if not adapters:
        return [Finding(CAT, "Adaptadores de rede", Status.INDISPONIVEL, "Nenhum adaptador pôde ser listado.")]

    if not active:
        return [Finding(CAT, "Adaptadores de rede", Status.PROBLEMA,
                        "Nenhum adaptador de rede físico ativo com endereço IPv4.",
                        f"{len(adapters)} adaptador(es) listado(s)",
                        ["Verifique se o cabo de rede está conectado ou se o Wi-Fi está ligado e associado a uma rede.",
                         "Reinicie o adaptador (desative e ative) e o roteador/switch.",
                         "Confirme se o adaptador não está desabilitado no "
                         + ("Gerenciador de Dispositivos." if os_family == "Windows" else "gerenciador de rede.")])]

    names = ", ".join(f"{a['name']} ({'Wi-Fi' if a['type'] == 'wifi' else 'cabo'})" for a in active)
    out.append(Finding(CAT, "Adaptadores de rede ativos", Status.NORMAL,
                       f"{len(active)} adaptador(es) ativo(s) com IPv4.", names))

    ip = data.get("primary_ipv4")
    if not ip:
        out.append(Finding(CAT, "Endereço IP", Status.PROBLEMA, "Não foi possível determinar o IP principal.",
                           None, ["Verifique a conexão e o servidor DHCP da rede."]))
    elif ip.startswith("169.254."):
        out.append(Finding(CAT, "Endereço IP", Status.PROBLEMA,
                           "IP automático (APIPA): o computador não obteve endereço do servidor DHCP.", ip,
                           ["Verifique cabo/Wi-Fi e se o roteador/DHCP está funcionando.",
                            "Renove o IP: " + ("'ipconfig /release' e 'ipconfig /renew' no Prompt de Comando."
                                               if os_family == "Windows" else
                                               "desconecte e reconecte a rede, ou reinicie o NetworkManager.")]))
    else:
        out.append(Finding(CAT, "Endereço IP", Status.NORMAL, "Endereço IP válido obtido.",
                           f"{ip} (interface {data.get('primary_interface')})"))

    gw = data.get("default_gateway")
    if gw:
        out.append(Finding(CAT, "Gateway padrão", Status.NORMAL, "Gateway padrão configurado.", gw))
    else:
        out.append(Finding(CAT, "Gateway padrão", Status.PROBLEMA, "Nenhum gateway padrão configurado.", None,
                           ["Sem gateway o computador não acessa redes externas. Verifique o DHCP do roteador ou "
                            "a configuração manual de IP.", "Reconecte à rede ou reinicie o roteador."]))

    dns = data.get("dns_servers") or []
    if dns:
        out.append(Finding(CAT, "Servidores DNS", Status.NORMAL, "Servidores DNS configurados.", ", ".join(dns)))
    else:
        out.append(Finding(CAT, "Servidores DNS", Status.PROBLEMA, "Nenhum servidor DNS configurado.", None,
                           ["Configure o DNS automaticamente (DHCP) ou informe um servidor válido.",
                            "Como teste, use 8.8.8.8 ou 1.1.1.1 temporariamente."]))
    return out
