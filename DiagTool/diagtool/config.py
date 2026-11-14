"""Configurações centrais do DiagTool: nomes, limiares e alvos de teste.

Todos os valores podem ser ajustados aqui sem alterar a lógica do programa.
"""
from datetime import date

APP_NAME = "DiagTool"
APP_VERSION = "1.0.0"
OUTPUT_FOLDER_NAME = "DiagTool-Relatorios"

CATEGORY_TITLES = {
    "system": "Sistema",
    "memory": "Memória",
    "storage": "Armazenamento",
    "network": "Rede",
    "connectivity": "Conectividade",
    "security": "Segurança",
}

# --- Limiares (percentuais, dias, ms) ----------------------------------------
UPTIME_ALERT_DAYS = 14
UPTIME_PROBLEM_DAYS = 60
CPU_ALERT_PERCENT = 85
CPU_PROBLEM_PERCENT = 95
MEMORY_ALERT_PERCENT = 80
MEMORY_PROBLEM_PERCENT = 90
MEMORY_MIN_TOTAL_GB = 4
SWAP_ALERT_PERCENT = 85
DISK_ALERT_PERCENT = 85
DISK_PROBLEM_PERCENT = 95
LATENCY_ALERT_MS = 100
LATENCY_PROBLEM_MS = 300
GATEWAY_LATENCY_ALERT_MS = 50
GATEWAY_LATENCY_PROBLEM_MS = 200
PACKET_LOSS_ALERT_PERCENT = 1
PACKET_LOSS_PROBLEM_PERCENT = 25
DNS_TIME_ALERT_MS = 300
DNS_TIME_PROBLEM_MS = 1500
WINDOWS_PATCH_ALERT_DAYS = 45
WINDOWS_PATCH_PROBLEM_DAYS = 90
AV_SIGNATURE_ALERT_DAYS = 7
AV_SIGNATURE_PROBLEM_DAYS = 14
LINUX_APT_CACHE_ALERT_DAYS = 14
LINUX_SECURITY_PENDING_PROBLEM = 20
LINUX_PENDING_ALERT = 50

# --- Testes de conectividade --------------------------------------------------
# (host, rótulo, porta TCP usada como alternativa se o ping não estiver disponível)
PING_INTERNET_TARGETS = [
    ("8.8.8.8", "Google DNS (8.8.8.8)", 53),
    ("1.1.1.1", "Cloudflare DNS (1.1.1.1)", 53),
]
PING_COUNT = 4
PING_TIMEOUT_S = 2
DNS_TEST_HOSTNAMES = ["www.google.com", "www.microsoft.com", "www.cloudflare.com"]
DNS_SERVER_TEST_NAME = "www.google.com"
HTTPS_TEST_HOSTS = ["www.google.com", "www.microsoft.com"]

# --- Fim de suporte (edite periodicamente) -------------------------------------
# (id do SO, versão) -> data de fim do suporte padrão
LINUX_EOL = {
    ("ubuntu", "18.04"): date(2023, 5, 31),
    ("ubuntu", "20.04"): date(2025, 5, 31),
    ("ubuntu", "22.04"): date(2027, 4, 30),
    ("ubuntu", "24.04"): date(2029, 5, 31),
    ("linuxmint", "19"): date(2023, 4, 30),
    ("linuxmint", "20"): date(2025, 4, 30),
    ("linuxmint", "21"): date(2027, 4, 30),
    ("linuxmint", "22"): date(2029, 4, 30),
}
WINDOWS_11_MIN_SUPPORTED_BUILD = 22631  # 23H2; builds anteriores estão fora de suporte
