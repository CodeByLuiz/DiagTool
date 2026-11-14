"""Analisadores: transformam dados coletados em achados classificados."""
from . import connectivity, memory, network, security, storage, system

ANALYZERS = {
    "system": system.analyze,
    "memory": memory.analyze,
    "storage": storage.analyze,
    "network": network.analyze,
    "connectivity": connectivity.analyze,
    "security": security.analyze,
}
