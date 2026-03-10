"""Módulo: DNS Resolution (dnsx)."""

from __future__ import annotations
import time

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, banner
from core.workspace import Workspace


class DnsModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("dns", {})

    def run(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        """
        Resuelve DNS de la lista de subdominios.
        Retorna (resolved, no_resolve).
        """
        banner("STEP 2 → DNS Resolution (dnsx)")

        # Escribir input temporal
        subs_file = self.ws.path / ".dnsx_input.txt"
        subs_file.write_text("\n".join(subdomains))

        # Preparar resolvers
        resolvers_args = []
        resolvers = self.mod_cfg.get("resolvers", [])
        if resolvers:
            resolver_file = self.ws.path / ".resolvers.txt"
            resolver_file.write_text("\n".join(str(r) for r in resolvers))
            resolvers_args = ["-r", str(resolver_file)]

        cmd = [
            get_tool(self.cfg, "dnsx"),
            "-l", str(subs_file),
            "-silent",
            "-t", str(self.mod_cfg.get("threads", 50)),
            "-retry", str(self.mod_cfg.get("retries", 2)),
            *resolvers_args,
        ]

        # Timeout proporcional a la cantidad de subs
        timeout = self.mod_cfg.get("timeout", 10) * len(subdomains) // 50 + 60

        info(f"Resolviendo {len(subdomains)} subdominios...")
        t0 = time.time()
        output = run_cmd(cmd, timeout=timeout)

        resolved = list(set(
            line.strip().lower()
            for line in output.splitlines()
            if line.strip()
        ))
        elapsed = time.time() - t0
        good(f"{len(resolved)}/{len(subdomains)} resuelven DNS ({elapsed:.1f}s)")

        no_resolve = sorted(set(subdomains) - set(resolved))

        # Guardar
        self.ws.save_lines("resolved.txt", resolved)
        info(f"Guardado: resolved.txt ({len(resolved)})")

        if no_resolve:
            self.ws.save_lines("no_resolve.txt", no_resolve)
            info(f"Guardado: no_resolve.txt ({len(no_resolve)})")

        # Limpiar temporales
        subs_file.unlink(missing_ok=True)

        return resolved, no_resolve