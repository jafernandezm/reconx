"""Carga y valida config.yaml."""

import sys
import yaml
from pathlib import Path


def load_config(path: str = "config.yaml") -> dict:
    """Carga config. Falla rápido si no existe."""
    p = Path(path)
    if not p.exists():
        print(f"[!] Config no encontrado: {p.resolve()}")
        print("    Copiá config.yaml.example → config.yaml")
        sys.exit(1)
    with open(p) as f:
        return yaml.safe_load(f)


def get_tool(cfg: dict, name: str) -> str:
    """Retorna el path del binary desde config."""
    return cfg.get("tools", {}).get(name, name)