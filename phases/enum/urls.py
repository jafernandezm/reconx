"""
Módulo: URL Harvesting pasivo (gau + waybackurls)

Cambio clave vs versión anterior:
  Antes → todo iba a recon/harvested_urls.txt (mezclado)
  Ahora → cada host tiene su propia carpeta con sus URLs clasificadas

Estructura que genera:
  recon/
    _all/
      all_urls.txt
      xss_candidates.txt
      sqli_candidates.txt
      ...
    autenticacion_gestora_bo/
      urls/
        all.txt
        with_params.txt
        js_files.txt
        interesting.txt
      vuln/
        xss_candidates.txt
        sqli_candidates.txt
        lfi_candidates.txt
        open_redirect_candidates.txt
        ssrf_candidates.txt
    gestora_bo/
      urls/
        ...
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, banner, separator, Colors
from core.workspace import Workspace

C = Colors

# Extensiones que no aportan nada al recon
_BLACKLIST_EXT = {
    "png", "jpg", "jpeg", "gif", "css", "woff", "woff2",
    "svg", "ico", "ttf", "eot", "mp4", "webp", "mp3",
    "pdf", "doc", "docx", "xls", "xlsx",
}

# Endpoints que siempre vale la pena revisar manualmente
_INTERESTING = re.compile(
    r"(admin|panel|dashboard|login|logout|signup|register|upload|import|"
    r"export|backup|dump|config|setup|install|api|graphql|swagger|openapi|"
    r"debug|test|dev|staging|internal|secret|token|key|password|passwd|"
    r"redirect|callback|oauth|auth|sso|saml|reset|forgot|\.git|\.env|"
    r"\.sql|\.bak|\.zip|\.tar|phpinfo|web\.config|wp-admin|wp-login)",
    re.IGNORECASE,
)


class UrlsModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("urls", {})

    # ── Recolección ───────────────────────────────────────────

    def _run_gau(self, host: str) -> set[str]:
        """gau para un host específico."""
        import shutil
        if not shutil.which(get_tool(self.cfg, "gau")):
            return set()

        blacklist = self.mod_cfg.get("blacklist_extensions", list(_BLACKLIST_EXT))
        cmd = [
            get_tool(self.cfg, "gau"),
            "--threads", str(self.mod_cfg.get("threads", 5)),
            "--subs",
            "--retries", "2",
        ]
        for ext in blacklist:
            cmd.extend(["--blacklist", ext])
        cmd.append(host)

        out = run_cmd(cmd, timeout=self.mod_cfg.get("timeout", 180), silent=True)
        return {l.strip() for l in out.splitlines() if l.strip()}

    def _run_waybackurls(self, host: str) -> set[str]:
        """waybackurls para un host específico."""
        import shutil
        if not shutil.which(get_tool(self.cfg, "waybackurls")):
            return set()

        out = run_cmd(
            [get_tool(self.cfg, "waybackurls")],
            timeout=self.mod_cfg.get("timeout", 180),
            stdin_data=host,
            silent=True,
        )
        return {l.strip() for l in out.splitlines() if l.strip()}

    # ── Filtrado ──────────────────────────────────────────────

    def _filter(self, urls: set[str]) -> list[str]:
        """Filtra extensiones inútiles y aplica cap."""
        blacklist = set(self.mod_cfg.get("blacklist_extensions",
                                          list(_BLACKLIST_EXT)))
        max_urls = self.mod_cfg.get("max_urls_per_domain", 10000)

        result = []
        for u in urls:
            try:
                path = urlparse(u).path.lower()
                ext = path.rsplit(".", 1)[-1] if "." in path else ""
                if ext not in blacklist:
                    result.append(u)
            except Exception:
                continue

        if len(result) > max_urls:
            result = result[:max_urls]

        return sorted(result)

    # ── Clasificación ─────────────────────────────────────────

    def _classify(self, urls: list[str]) -> dict[str, list[str]]:
        """Separa URLs por tipo para los módulos siguientes."""
        classified = {
            "with_params": [],
            "js_files":    [],
            "interesting": [],
        }
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()

                if parsed.query or "=" in url:
                    classified["with_params"].append(url)
                if path.endswith(".js"):
                    classified["js_files"].append(url)
                if _INTERESTING.search(url):
                    classified["interesting"].append(url)
            except Exception:
                continue
        return classified

    # ── Run principal ─────────────────────────────────────────

    def run(self, alive_urls: list[str]) -> list[str]:
        """
        Para cada host vivo:
          1. Corre gau + waybackurls
          2. Filtra extensiones inútiles
          3. Clasifica por tipo (params, JS, interesting)
          4. Guarda en carpeta propia del host
          5. Clasifica por vuln (XSS, SQLi, LFI, etc.)

        Al final agrega todo en _all/ para tener vista global.
        """
        banner("URL HARVESTING (gau + waybackurls)")

        all_urls_global: list[str] = []
        all_params_global: list[str] = []

        for url in alive_urls:
            # Extraer hostname limpio
            host = (urlparse(url).netloc or url).split(":")[0]

            info(f"  → {C.BOLD}{url}{C.END}")
            t0 = time.time()

            # Recolectar
            gau_urls  = self._run_gau(host)
            wb_urls   = self._run_waybackurls(host)

            raw = gau_urls | wb_urls
            filtered = self._filter(raw)

            good(f"    gau: {len(gau_urls)} | wayback: {len(wb_urls)} "
                 f"→ {len(filtered)} útiles ({time.time()-t0:.1f}s)")

            if not filtered:
                continue

            # Clasificar
            classified = self._classify(filtered)

            # Workspace del host
            ws_host = self.ws.for_host(url)

            # Guardar urls/
            ws_host.save_lines("urls/all.txt", filtered)
            if classified["with_params"]:
                ws_host.save_lines("urls/with_params.txt",
                                   classified["with_params"])
                info(f"    {len(classified['with_params'])} URLs con params")
            if classified["js_files"]:
                ws_host.save_lines("urls/js_files.txt",
                                   classified["js_files"])
                info(f"    {len(classified['js_files'])} archivos JS")
            if classified["interesting"]:
                ws_host.save_lines("urls/interesting.txt",
                                   classified["interesting"])
                good(f"    {C.Y}{len(classified['interesting'])} endpoints interesantes{C.END}")

            # Clasificar por vuln y guardar en vuln/
            if classified["with_params"]:
                ws_host.save_vuln_candidates(classified["with_params"])

            # Acumular para el global
            all_urls_global.extend(filtered)
            all_params_global.extend(classified["with_params"])

            separator()

        # ── Resumen global en _all/ ───────────────────────────
        if all_urls_global:
            good(f"Total global: {len(all_urls_global)} URLs "
                 f"en {len(alive_urls)} hosts")
            self.ws.save_global_vuln_summary(all_params_global)

            # Guardar también harvested_urls.txt global para compatibilidad
            self.ws.save_lines("harvested_urls.txt",
                               sorted(set(all_urls_global)))

        return all_urls_global