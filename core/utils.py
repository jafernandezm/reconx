"""Utilidades compartidas por todos los módulos."""

from __future__ import annotations
import sys
from pathlib import Path


# ══════════════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════════════

class Colors:
    ENABLED = sys.stdout.isatty()
    R    = "\033[91m" if ENABLED else ""
    G    = "\033[92m" if ENABLED else ""
    Y    = "\033[93m" if ENABLED else ""
    B    = "\033[94m" if ENABLED else ""
    C    = "\033[96m" if ENABLED else ""
    W    = "\033[97m" if ENABLED else ""
    DIM  = "\033[2m"  if ENABLED else ""
    BOLD = "\033[1m"  if ENABLED else ""
    END  = "\033[0m"  if ENABLED else ""

_C = Colors

def info(msg: str):
    print(f"  {_C.B}[*]{_C.END} {msg}")

def good(msg: str):
    print(f"  {_C.G}[✓]{_C.END} {msg}")

def warn(msg: str):
    print(f"  {_C.Y}[!]{_C.END} {msg}")

def error(msg: str):
    print(f"  {_C.R}[✗]{_C.END} {msg}")

def banner(text: str):
    print(f"\n  {_C.BOLD}{_C.C}{text}{_C.END}")

def separator():
    print(f"  {_C.DIM}{'─'*56}{_C.END}")


# ══════════════════════════════════════════════════════════════
# FILE I/O
# ══════════════════════════════════════════════════════════════

def read_lines(path: str | Path) -> list[str]:
    """Lee archivo, retorna líneas no vacías."""
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip()]


def write_lines(path: str | Path, lines: list[str]):
    """Escribe líneas únicas y ordenadas."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(sorted(set(lines))) + "\n")