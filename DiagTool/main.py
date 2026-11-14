"""DiagTool — ponto de entrada.

Uso normal (duplo clique): executa em modo silencioso, grava os relatórios em
<Área de Trabalho>/DiagTool-Relatorios e encerra. Opções de linha de comando
existem apenas para desenvolvimento/testes.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

from diagtool import config
from diagtool.reports import prepare_output_dir, write_reports
from diagtool.runner import run_diagnostics


def _log_crash(out_dir: Path | None) -> None:
    """Registra falha fatal em arquivo (nunca exibe nada na tela)."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for base in (out_dir, Path(tempfile.gettempdir())):
        try:
            if base is not None:
                (base / f"DiagTool_erro_{stamp}.log").write_text(traceback.format_exc(), encoding="utf-8")
                return
        except OSError:
            continue


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog=config.APP_NAME, add_help=True)
    parser.add_argument("--output-dir", help="pasta base (padrão: Área de Trabalho)")
    parser.add_argument("--print-summary", action="store_true", help="imprime resumo no terminal (teste)")
    parser.add_argument("--version", action="version", version=f"{config.APP_NAME} {config.APP_VERSION}")
    args = parser.parse_args(argv)

    out_dir = None
    try:
        out_dir = prepare_output_dir(Path(args.output_dir) if args.output_dir else None)
        report = run_diagnostics()
        paths = write_reports(report, out_dir)
        if args.print_summary and sys.stdout:
            print(f"Status geral: {report.overall_status().value}")
            for k, p in paths.items():
                print(f"{k.upper()}: {p}")
        return 0
    except Exception:  # noqa: BLE001
        _log_crash(out_dir)
        return 1


if __name__ == "__main__":
    sys.exit(main())
