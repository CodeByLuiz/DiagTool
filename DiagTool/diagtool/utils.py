"""Utilitários compartilhados: execução segura de comandos, registro do Windows,
detecção de SO, pasta da Área de Trabalho e formatação."""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")


def detect_os() -> str:
    """Retorna 'windows', 'linux' ou 'unsupported'."""
    if IS_WINDOWS:
        return "windows"
    if IS_LINUX:
        return "linux"
    return "unsupported"


# ---------------------------------------------------------------- comandos ----
@dataclass
class CommandResult:
    args: list
    returncode: int
    stdout: str
    stderr: str
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


def _decode(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8").lstrip("\ufeff")
    except UnicodeDecodeError:
        pass
    if IS_WINDOWS:
        try:
            return data.decode(f"cp{ctypes.windll.kernel32.GetOEMCP()}", errors="replace")
        except Exception:
            pass
    return data.decode("latin-1", errors="replace")


def run_command(args: Sequence[str], timeout: float = 15.0) -> CommandResult:
    """Executa um comando nativo sem janela, sem stdin e com timeout.

    Nunca levanta exceção: falhas são descritas em ``CommandResult.error``.
    """
    env = os.environ.copy()
    kwargs: dict = {}
    if IS_LINUX:
        env.update({"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"})
        if getattr(sys, "frozen", False):
            # PyInstaller altera LD_LIBRARY_PATH; restaura para os processos filhos.
            orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
            if orig is not None:
                env["LD_LIBRARY_PATH"] = orig
            else:
                env.pop("LD_LIBRARY_PATH", None)
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kwargs["startupinfo"] = si
    try:
        proc = subprocess.run(
            list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, env=env, **kwargs)
    except subprocess.TimeoutExpired:
        return CommandResult(list(args), -1, "", "", f"tempo excedido ({timeout:.0f}s)")
    except FileNotFoundError:
        return CommandResult(list(args), -1, "", "", f"comando não encontrado: {args[0]}")
    except OSError as exc:
        return CommandResult(list(args), -1, "", "", f"erro ao executar {args[0]}: {exc}")
    return CommandResult(list(args), proc.returncode, _decode(proc.stdout), _decode(proc.stderr))


_PS_PREFIX = ("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
              "$ProgressPreference='SilentlyContinue'; ")


def run_powershell(script: str, timeout: float = 30.0) -> CommandResult:
    """Executa um script PowerShell (somente leitura) no Windows."""
    exe = "powershell.exe"
    root = os.environ.get("SystemRoot")
    if root:
        full = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if full.exists():
            exe = str(full)
    return run_command([exe, "-NoProfile", "-NonInteractive", "-Command", _PS_PREFIX + script],
                       timeout=timeout)


def run_powershell_json(script: str, timeout: float = 30.0) -> Any:
    """Executa PowerShell e interpreta a saída como JSON. Levanta RuntimeError em falha."""
    import json
    res = run_powershell(script, timeout)
    if res.error:
        raise RuntimeError(res.error)
    out = res.stdout.strip()
    if not out:
        raise RuntimeError(res.stderr.strip()[:200] or "saída vazia")
    try:
        return json.loads(out)
    except ValueError as exc:
        raise RuntimeError(f"JSON inválido: {exc}")


def call_with_timeout(func: Callable, timeout: float, *args, **kwargs):
    """Chama func em thread auxiliar; levanta TimeoutError se demorar demais."""
    box: dict = {}

    def target():
        try:
            box["value"] = func(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"tempo excedido ({timeout:.0f}s)")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def safe_call(func: Callable, default: Any = None, warnings: Optional[list] = None,
              label: str = "", *args, **kwargs) -> Any:
    """Executa func; em caso de erro registra aviso e devolve ``default``."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        if warnings is not None:
            warnings.append(f"{label or getattr(func, '__name__', 'coleta')}: {exc}")
        return default


# ---------------------------------------------------------- registro Windows --
def _winreg_open(hive_name: str, path: str):
    import winreg
    return winreg.OpenKey(getattr(winreg, hive_name), path, 0,
                          winreg.KEY_READ | winreg.KEY_WOW64_64KEY)


def read_registry_value(hive_name: str, path: str, name: str) -> Any:
    """Lê um valor do registro (somente leitura). Retorna None se inexistente."""
    if not IS_WINDOWS:
        return None
    import winreg
    try:
        with _winreg_open(hive_name, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def registry_key_exists(hive_name: str, path: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        with _winreg_open(hive_name, path):
            return True
    except OSError:
        return False


# -------------------------------------------------------- Área de Trabalho ----
def parse_xdg_desktop_dir(text: str, home: str) -> Optional[str]:
    """Extrai XDG_DESKTOP_DIR de ~/.config/user-dirs.dirs."""
    m = re.search(r'^\s*XDG_DESKTOP_DIR\s*=\s*"?([^"\n]+)"?', text, re.M)
    if not m:
        return None
    return m.group(1).strip().replace("${HOME}", home).replace("$HOME", home)


def _windows_desktop() -> Optional[str]:
    try:
        buf = ctypes.create_unicode_buffer(520)
        # CSIDL_DESKTOPDIRECTORY = 0x10 (respeita redirecionamento do OneDrive)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf) == 0:
            return buf.value
    except Exception:
        pass
    return None


def desktop_candidates() -> list:
    home = Path.home()
    cands: list = []
    if IS_WINDOWS:
        p = _windows_desktop()
        if p:
            cands.append(Path(p))
        profile = os.environ.get("USERPROFILE")
        if profile:
            cands.append(Path(profile) / "Desktop")
    else:
        cfg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / "user-dirs.dirs"
        try:
            d = parse_xdg_desktop_dir(cfg.read_text(encoding="utf-8", errors="replace"), str(home))
            if d:
                cands.append(Path(d))
        except OSError:
            pass
        cands += [home / "Área de Trabalho", home / "Desktop", home / "Escritorio"]
    cands.append(home)
    return cands


def get_desktop_path() -> Path:
    """Primeira pasta de Área de Trabalho existente e gravável (fallback: home/tmp)."""
    for c in desktop_candidates():
        try:
            if c.is_dir() and os.access(c, os.W_OK):
                return c
        except OSError:
            continue
    return Path(tempfile.gettempdir())


# ------------------------------------------------------------- formatação -----
def fmt_num(value: float, decimals: int = 1) -> str:
    """Formata número no padrão brasileiro (vírgula decimal)."""
    return f"{value:,.{decimals}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def format_bytes(n: Optional[float]) -> str:
    if n is None:
        return "n/d"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024 or unit == "PB":
            return f"{fmt_num(size, 0 if unit == 'B' else 1)} {unit}"
        size /= 1024
    return str(n)


def to_gb(n: Optional[float]) -> Optional[float]:
    return None if n is None else round(n / 1024 ** 3, 2)


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d:
        parts.append(f"{d} dia{'s' if d != 1 else ''}")
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m}min")
    return " ".join(parts)


def is_ipv4(value: str) -> bool:
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", value or "")
    return bool(m) and all(int(g) <= 255 for g in m.groups())


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name or "PC") or "PC"
