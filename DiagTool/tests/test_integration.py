"""Testes de integração: execução completa, resiliência a falhas e arquivos gerados."""
import json
from pathlib import Path

import main as diagtool_main
from diagtool import runner
from diagtool.models import Status


def test_full_run_creates_reports(tmp_path):
    rc = diagtool_main.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    folder = tmp_path / "DiagTool-Relatorios"
    txts, jsons = list(folder.glob("DiagTool_*.txt")), list(folder.glob("DiagTool_*.json"))
    assert len(txts) == 1 and len(jsons) == 1
    doc = json.loads(jsons[0].read_text(encoding="utf-8"))
    assert set(doc["sections"]) == {"system", "memory", "storage", "network", "connectivity", "security"}
    assert doc["summary"]["overall_status"] in {s.value for s in Status}
    assert all(f["status"] in {s.value for s in Status} for f in doc["findings"])
    assert "RELATÓRIO DE DIAGNÓSTICO" in txts[0].read_text(encoding="utf-8-sig")


def test_two_runs_never_overwrite(tmp_path):
    diagtool_main.main(["--output-dir", str(tmp_path)])
    diagtool_main.main(["--output-dir", str(tmp_path)])
    assert len(list((tmp_path / "DiagTool-Relatorios").glob("*.json"))) == 2


def test_collector_failure_does_not_stop_diagnosis(monkeypatch):
    def boom(ctx):
        raise RuntimeError("falha simulada")
    monkeypatch.setattr(runner.COLLECTORS[1][1], "collect", boom)  # memória
    rep = runner.run_diagnostics()
    mem = next(s for s in rep.sections if s.key == "memory")
    assert not mem.ok and rep.section_status("memory") is Status.INDISPONIVEL
    assert rep.get("system") and rep.get("storage")  # demais seções seguem normalmente


def test_analyzer_failure_is_contained(monkeypatch):
    monkeypatch.setitem(runner.ANALYZERS, "network", lambda d, o: 1 / 0)
    rep = runner.run_diagnostics()
    assert rep.section_status("network") is Status.INDISPONIVEL
    assert rep.findings_for("system")


def test_fatal_error_writes_log_and_returns_1(monkeypatch, tmp_path):
    monkeypatch.setattr(diagtool_main, "run_diagnostics", lambda: (_ for _ in ()).throw(ValueError("x")))
    assert diagtool_main.main(["--output-dir", str(tmp_path)]) == 1
    assert list((tmp_path / "DiagTool-Relatorios").glob("DiagTool_erro_*.log"))
