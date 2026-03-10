"""Ejecutor de comandos externos (tools de recon)."""

from __future__ import annotations
import subprocess
from core.utils import error, Colors

C = Colors


def run_cmd(
    cmd: list[str],
    timeout: int = 300,
    silent: bool = False,
    stdin_data: str | None = None,
) -> str:
    """
    Ejecuta un comando y retorna stdout.
    - timeout: segundos máximo
    - silent: no mostrar errores
    - stdin_data: pasar data por stdin (para pipes)
    """
    try:
        r = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0 and not silent:
            error(f"Comando falló ({r.returncode}): {' '.join(cmd[:4])}...")
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines()[:5]:
                    print(f"        {C.DIM}{line}{C.END}")
        return r.stdout.strip()

    except subprocess.TimeoutExpired:
        if not silent:
            from core.utils import warn
            warn(f"Timeout ({timeout}s): {' '.join(cmd[:4])}")
        return ""

    except FileNotFoundError:
        if not silent:
            error(f"Herramienta no encontrada: {cmd[0]}")
        return ""