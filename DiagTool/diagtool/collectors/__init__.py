"""Coletores: obtêm dados brutos do computador, sem classificar resultados."""
from . import connectivity, memory, network, security, storage, system

# (chave, módulo) na ordem de execução; 'connectivity' usa dados de 'network'.
COLLECTORS = [
    ("system", system),
    ("memory", memory),
    ("storage", storage),
    ("network", network),
    ("connectivity", connectivity),
    ("security", security),
]
