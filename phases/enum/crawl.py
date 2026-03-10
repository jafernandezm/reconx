"""Módulo: Web Crawling activo (katana)."""

from __future__ import annotations
import time

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, banner
from core.workspace import Workspace


class CrawlModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("crawl", {})

    def run(self, alive_urls: list[str]) -> list[str]:
        """
        Crawl activo con katana (sigue links, renderiza JS).
        Retorna lista de URLs descubiertas.
        """
        banner("WEB CRAWLING (katana)")

        max_targets = self.mod_cfg.get("max_targets", 10)
        targets = alive_urls[:max_targets]
        if len(alive_urls) > max_targets:
            warn(f"Limitando a {max_targets} targets (config: crawl.max_targets)")

        # Escribir input
        input_file = self.ws.path / ".katana_input.txt"
        input_file.write_text("\n".join(targets))

        depth = self.mod_cfg.get("depth", 3)
        cmd = [
            get_tool(self.cfg, "katana"),
            "-list", str(input_file),
            "-silent",
            "-d", str(depth),
            "-c", str(self.mod_cfg.get("concurrency", 2)),
            "-timeout", str(self.mod_cfg.get("timeout", 15)),
        ]
        if self.mod_cfg.get("js_crawl", True):
            cmd.append("-js-crawl")
        if self.mod_cfg.get("headless", True):
            cmd.append("-headless")

        scope = self.mod_cfg.get("scope", "strict")
        if scope == "strict":
            cmd.extend(["-fs", "dn"])

        timeout = self.mod_cfg.get("timeout", 15) * len(targets) + 120

        info(f"Crawling {len(targets)} targets (depth={depth})...")
        t0 = time.time()
        output = run_cmd(cmd, timeout=timeout)

        crawled = sorted(set(
            line.strip() for line in output.splitlines() if line.strip()
        ))
        elapsed = time.time() - t0

        good(f"{len(crawled)} URLs crawleadas ({elapsed:.1f}s)")

        self.ws.save_lines("crawled_urls.txt", crawled)
        info("Guardado: crawled_urls.txt")

        # Limpiar
        input_file.unlink(missing_ok=True)

        return crawled