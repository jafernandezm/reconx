"""
Módulo: HTTP Probe (httpx) — Clasifica hosts por status code.

Output:
  alive.txt             → TODOS los que responden (input para recon)
  alive_200.txt         → OK (200, 201, 204) — funcionando normal
  alive_redirect.txt    → Redirects (301, 302, 307) — ¿a dónde van?
  alive_forbidden.txt   → Denegados (401, 403) — candidatos a bypass
  alive_error.txt       → Errores (500, 502, 503) — posibles vulns
  dead.txt              → No responden HTTP
  httpx_results.json    → Data completa de todo
"""

from __future__ import annotations
import json
import time

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, banner, Colors
from core.workspace import Workspace

C = Colors

# Clasificación de status codes
STATUS_GROUPS = {
    "200": {
        "name": "OK",
        "file": "alive_200.txt",
        "codes": {200, 201, 204},
        "color": C.G,
    },
    "redirect": {
        "name": "Redirect",
        "file": "alive_redirect.txt",
        "codes": {301, 302, 307, 308},
        "color": C.B,
    },
    "forbidden": {
        "name": "Forbidden/Auth",
        "file": "alive_forbidden.txt",
        "codes": {401, 403, 405},
        "color": C.Y,
    },
    "error": {
        "name": "Server Error",
        "file": "alive_error.txt",
        "codes": {500, 502, 503, 504},
        "color": C.R,
    },
}


class HttpProbeModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("http_probe", {})

    def run(self, resolved: list[str]) -> tuple[list[str], list[str], list[dict]]:
        """
        Probe HTTP/HTTPS sobre hosts resueltos.
        Retorna (alive_urls, dead_hosts, httpx_json_data).
        """
        banner("STEP 3 → HTTP Probe (httpx)")

        resolved_file = self.ws.path / ".httpx_input.txt"
        resolved_file.write_text("\n".join(resolved))

        match_codes = self.mod_cfg.get(
            "match_codes",
            [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503],
        )

        cmd = [
            get_tool(self.cfg, "httpx"),
            "-l", str(resolved_file),
            "-silent",
            "-t", str(self.mod_cfg.get("threads", 50)),
            "-timeout", str(self.mod_cfg.get("timeout", 10)),
            "-json",
            "-td",             # tech detect
            "-server",
            "-title",
            "-status-code",
            "-content-length",
            "-location",       # header Location (para redirects)
            "-follow-redirects",
            "-random-agent",
            "-mc", ",".join(str(c) for c in match_codes),
        ]

        info(f"Probing {len(resolved)} hosts...")
        t0 = time.time()
        output = run_cmd(cmd, timeout=len(resolved) * 3 + 120)
        elapsed = time.time() - t0

        # ── Parsear JSON lines ────────────────────────────────
        alive_urls = []
        httpx_data = []

        # Clasificación por status
        classified: dict[str, list[dict]] = {
            "200": [],
            "redirect": [],
            "forbidden": [],
            "error": [],
            "other": [],
        }

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                httpx_data.append(data)

                url = data.get("url", "")
                status = data.get("status_code", 0)

                if url:
                    alive_urls.append(url)

                    # Clasificar
                    entry = {
                        "url": url,
                        "status": status,
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "server": data.get("webserver", ""),
                        "location": data.get("location", ""),
                        "content_length": data.get("content_length", 0),
                    }

                    placed = False
                    for group_key, group in STATUS_GROUPS.items():
                        if status in group["codes"]:
                            classified[group_key].append(entry)
                            placed = True
                            break
                    if not placed:
                        classified["other"].append(entry)

            except json.JSONDecodeError:
                if line.startswith("http"):
                    alive_urls.append(line)

        alive_urls = sorted(set(alive_urls))
        good(f"{len(alive_urls)} hosts vivos ({elapsed:.1f}s)")

        # ── Clasificar muertos ────────────────────────────────
        alive_hosts = set()
        for u in alive_urls:
            host = u.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            alive_hosts.add(host)
        dead = sorted(set(resolved) - alive_hosts)

        # ── Guardar archivos ──────────────────────────────────

        # alive.txt — TODOS (input para recon)
        self.ws.save_lines("alive.txt", alive_urls)
        info(f"Guardado: alive.txt ({len(alive_urls)}) ← TODOS los vivos")

        # Archivos por grupo de status
        for group_key, group in STATUS_GROUPS.items():
            entries = classified[group_key]
            if entries:
                urls = [e["url"] for e in entries]
                self.ws.save_lines(group["file"], urls)
                info(f"Guardado: {group['file']} ({len(entries)})")

        # Redirects con detalle (a dónde redirigen)
        if classified["redirect"]:
            redirect_detail = []
            for e in classified["redirect"]:
                location = e.get("location", "?")
                redirect_detail.append(f"{e['url']} → {location}")
            self.ws.save_lines("redirect_details.txt", redirect_detail)
            info(f"Guardado: redirect_details.txt (detalle de redirects)")

        # Dead
        if dead:
            self.ws.save_lines("dead.txt", dead)
            info(f"Guardado: dead.txt ({len(dead)})")

        # JSON completo
        if httpx_data:
            self.ws.save_json("httpx_results.json", httpx_data)
            info("Guardado: httpx_results.json")

        # Limpiar
        resolved_file.unlink(missing_ok=True)

        # ── Resumen visual ────────────────────────────────────
        self._print_status_summary(classified, dead)

        return alive_urls, dead, httpx_data

    def _print_status_summary(self, classified: dict, dead: list[str]):
        """Resumen visual de la clasificación."""
        print()
        for group_key, group in STATUS_GROUPS.items():
            entries = classified[group_key]
            if entries:
                color = group["color"]
                print(f"    {color}{group['name']:>15}: {len(entries)}{C.END}")
                for e in entries[:5]:
                    status = e["status"]
                    title = e.get("title", "")[:40]
                    extra = ""
                    if group_key == "redirect":
                        loc = e.get("location", "")[:50]
                        extra = f" → {loc}"
                    elif title:
                        extra = f" ({title})"
                    print(f"      {C.DIM}[{status}] {e['url']}{extra}{C.END}")
                if len(entries) > 5:
                    print(f"      {C.DIM}... y {len(entries)-5} más{C.END}")

        other = classified.get("other", [])
        if other:
            print(f"    {C.DIM}          Other: {len(other)}{C.END}")

        if dead:
            print(f"    {C.R}           Dead: {len(dead)}{C.END}")
        print()

    def print_tech_summary(self, httpx_data: list[dict], limit: int = 20):
        """Imprime tecnologías detectadas."""
        techs_found = {}
        for r in httpx_data:
            url = r.get("url", "?")
            tech = r.get("tech", [])
            if tech:
                techs_found[url] = (tech, r.get("status_code", "?"))

        if not techs_found:
            return

        banner("TECNOLOGÍAS DETECTADAS")
        for url, (techs, status) in sorted(techs_found.items())[:limit]:
            tech_str = ", ".join(techs[:5])
            print(f"    {C.DIM}[{status}]{C.END} {url}")
            print(f"         {C.Y}{tech_str}{C.END}")

        if len(techs_found) > limit:
            print(f"\n    {C.DIM}... y {len(techs_found)-limit} más{C.END}")