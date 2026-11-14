"""Gera o executável independente do DiagTool com PyInstaller.

Uso:  python build.py
O executável é criado em dist/ para o sistema operacional em que o script roda
(PyInstaller não faz compilação cruzada).
"""
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent
IS_WINDOWS = sys.platform.startswith("win")


def main() -> None:
    args = [
        str(ROOT / "main.py"),
        "--name", "DiagTool",
        "--onefile",
        "--clean", "--noconfirm",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--paths", str(ROOT),
        "--exclude-module", "tkinter",
        "--exclude-module", "unittest",
        "--exclude-module", "pydoc",
    ]
    if IS_WINDOWS:
        args.append("--noconsole")  # sem janela de terminal
        icon = ROOT / "assets" / "icon.ico"
        if icon.exists():
            args += ["--icon", str(icon)]
    PyInstaller.__main__.run(args)
    exe = "DiagTool.exe" if IS_WINDOWS else "DiagTool"
    print(f"\nExecutável gerado: {ROOT / 'dist' / exe}")


if __name__ == "__main__":
    main()
