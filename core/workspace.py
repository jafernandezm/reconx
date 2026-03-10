"""
Workspace — Manejo de carpetas de output.

Estructura:
  output/
    gestora_bo/
      subs/
        all_subdomains.txt
        resolved.txt
        alive.txt
        dead.txt
        httpx_results.json
      recon/
        _all/                               <- resumen global
          all_urls.txt
          xss_candidates.txt
          sqli_candidates.txt
          lfi_candidates.txt
          open_redirect_candidates.txt
          ssrf_candidates.txt
          summary.json
        autenticacion_gestora_bo/           <- por host
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
          ffuf/
          arjun/
          nuclei/
        moodle_gestora_bo/
          ...
"""
from __future__ import annotations

import json
import re
import sys
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from core.utils import info, good, warn, error, read_lines, write_lines
from core.config import get_tool


# ══════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════

def _host_to_dirname(url_or_host: str) -> str:
    """
    Convierte una URL o hostname en nombre de carpeta seguro.
    https://api.gestora.bo  →  api_gestora_bo
    api.gestora.bo          →  api_gestora_bo
    """
    host = urlparse(url_or_host).netloc or url_or_host
    return (
        host.replace(".", "_")
            .replace(":", "_")
            .replace("/", "_")
            .strip("_")
    )


# ══════════════════════════════════════════════════════════════
# Clasificación de URLs por tipo de vulnerabilidad
#
# Lógica: analiza el NOMBRE del parámetro para predecir
# qué tipo de vuln es más probable.
# No es perfecto pero es 10x más útil que un grep manual.
# ══════════════════════════════════════════════════════════════

# XSS — params que reflejan input en la página
_XSS_PARAMS = re.compile(
    r"^(q|query|search|s|keyword|term|text|input|data|content|message|"
    r"comment|title|name|value|description|html|body|page|view|template|"
    r"callback|jsonp|next|url|return|redirect|ref|from|to|lang|locale)$",
    re.IGNORECASE,
)

# SQLi — params que típicamente van a consultas de DB
_SQLI_PARAMS = re.compile(
    r"^(id|user_?id|item_?id|product_?id|cat|category|order|sort|by|"
    r"limit|offset|page|num|number|count|start|end|year|month|day|"
    r"type|mode|status|filter|col|table|field|row|"
    r"uid|pid|sid|tid|cid|mid|rid|nid|gid|fid)$",
    re.IGNORECASE,
)

# LFI / Path Traversal — params que cargan archivos o rutas
_LFI_PARAMS = re.compile(
    r"^(file|path|dir|folder|include|require|load|read|open|fetch|"
    r"template|document|page|view|layout|theme|module|plugin|lang|"
    r"language|locale|conf|config|setting|resource|src|source|"
    r"dest|destination|root|base|prefix|suffix|ext|extension)$",
    re.IGNORECASE,
)

# Open Redirect / SSRF — params que contienen URLs o dominios
_REDIRECT_PARAMS = re.compile(
    r"^(url|uri|link|href|src|source|dest|destination|target|to|from|"
    r"next|prev|previous|return|return_?url|return_?to|redirect|"
    r"redirect_?url|goto|forward|continue|back|ref|referer|referrer|"
    r"callback|webhook|endpoint|host|domain|site|proxy|remote|external)$",
    re.IGNORECASE,
)


def _classify_url(url: str) -> dict[str, bool]:
    """
    Analiza los parámetros de una URL y retorna qué vulns son candidatas.
    """
    result = {
        "xss":           False,
        "sqli":          False,
        "lfi":           False,
        "open_redirect": False,
        "ssrf":          False,
    }

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return result

        for param_name, values in params.items():
            if _XSS_PARAMS.search(param_name):
                result["xss"] = True
            if _SQLI_PARAMS.search(param_name):
                result["sqli"] = True
            if _LFI_PARAMS.search(param_name):
                result["lfi"] = True
            if _REDIRECT_PARAMS.search(param_name):
                result["open_redirect"] = True
                # SSRF si el valor del param parece una URL externa
                for v in values:
                    if v.startswith("http") or "://" in v:
                        result["ssrf"] = True

        # Contexto de path suma pistas
        path = parsed.path.lower()
        if any(x in path for x in ["/api/", "/v1/", "/v2/", "/graphql"]):
            result["sqli"] = True
        if any(x in path for x in ["/redirect", "/goto", "/out", "/link"]):
            result["open_redirect"] = True

    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════
class Workspace:
# ══════════════════════════════════════════════════════════════

    def __init__(self, cfg: dict, target: str, phase: str = "",
                 _custom_path: Path | None = None):
        """
        cfg:          config.yaml cargado
        target:       dominio base (ej: gestora.bo)
        phase:        "subs" | "recon" | ""
        _custom_path: uso interno para workspaces de host
        """
        self.cfg = cfg
        self.target = target
        self.phase = phase

        if _custom_path is not None:
            self.path = _custom_path
        else:
            base = cfg.get("output", {}).get("base_dir", "./output")
            safe_target = target.replace(".", "_").replace("/", "_")
            self.path = Path(base) / safe_target
            if phase:
                self.path = self.path / phase

    # ── Creación de workspaces hijo ───────────────────────────

    def for_host(self, host_url: str) -> "Workspace":
        """
        Retorna un Workspace para un host específico dentro de recon/.
        Crea la carpeta automáticamente.

        Uso:
          ws_host = ws.for_host("https://api.gestora.bo")
          ws_host.save_lines("urls/all.txt", urls)
          ws_host.save_vuln_candidates(param_urls)
        """
        host_dir = self.path / _host_to_dirname(host_url)
        host_dir.mkdir(parents=True, exist_ok=True)
        child = Workspace(self.cfg, self.target, self.phase,
                          _custom_path=host_dir)
        return child

    def global_ws(self) -> "Workspace":
        """
        Retorna workspace para _all/ — resultados globales de todos los hosts.
        """
        global_dir = self.path / "_all"
        global_dir.mkdir(parents=True, exist_ok=True)
        return Workspace(self.cfg, self.target, self.phase,
                         _custom_path=global_dir)

    # ── I/O básico ────────────────────────────────────────────

    def setup(self):
        """Crea la carpeta del workspace."""
        self.path.mkdir(parents=True, exist_ok=True)

    def save_lines(self, filename: str, lines: list[str]):
        """Guarda líneas. Crea subdirectorios si el filename los incluye."""
        target_path = self.path / filename
        target_path.parent.mkdir(parents=True, exist_ok=True)
        write_lines(target_path, lines)

    def load_lines(self, filename: str) -> list[str]:
        return read_lines(self.path / filename)

    def save_json(self, filename: str, data):
        target_path = self.path / filename
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def count_lines(self, filename: str) -> Optional[int]:
        f = self.path / filename
        if not f.exists():
            return None
        return len(read_lines(f))

    def subdir(self, name: str) -> Path:
        """Crea y retorna un subdirectorio."""
        p = self.path / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    # ── Clasificación de vulns ────────────────────────────────

    def save_vuln_candidates(self, param_urls: list[str]):
        """
        Clasifica URLs con parámetros por tipo de vulnerabilidad
        y las guarda en vuln/ dentro del workspace actual.

        Llamar desde el workspace de cada host:
          ws_host.save_vuln_candidates(urls_con_params)
        """
        if not param_urls:
            return

        vuln_dir = self.subdir("vuln")

        buckets: dict[str, list[str]] = {
            "xss_candidates.txt":           [],
            "sqli_candidates.txt":          [],
            "lfi_candidates.txt":           [],
            "open_redirect_candidates.txt": [],
            "ssrf_candidates.txt":          [],
        }

        for url in param_urls:
            flags = _classify_url(url)
            if flags["xss"]:
                buckets["xss_candidates.txt"].append(url)
            if flags["sqli"]:
                buckets["sqli_candidates.txt"].append(url)
            if flags["lfi"]:
                buckets["lfi_candidates.txt"].append(url)
            if flags["open_redirect"]:
                buckets["open_redirect_candidates.txt"].append(url)
            if flags["ssrf"]:
                buckets["ssrf_candidates.txt"].append(url)

        for filename, urls in buckets.items():
            if urls:
                unique = sorted(set(urls))
                write_lines(vuln_dir / filename, unique)
                label = filename.replace("_candidates.txt", "").upper()
                good(f"    [{label}] {len(unique)} candidatos → vuln/{filename}")

    def save_global_vuln_summary(self, all_urls: list[str]):
        """
        Genera el resumen global de candidatos en _all/.
        Llamar al final del recon con TODAS las URLs de todos los hosts.
        """
        g = self.global_ws()
        g.save_vuln_candidates(all_urls)
        g.save_lines("all_urls.txt", sorted(set(all_urls)))
        good(f"Resumen global guardado en: {g.path}")

    # ── Preflight ─────────────────────────────────────────────

    def preflight(self, tools: list[str]):
        """Verifica tools obligatorias. Sale si alguna falta."""
        missing = [
            name for name in tools
            if not shutil.which(get_tool(self.cfg, name))
        ]
        if missing:
            error(f"Herramientas faltantes: {', '.join(missing)}")
            print("    Instalá con: ./install.sh")
            print("    O ajustá 'tools:' en config.yaml")
            sys.exit(1)
        good(f"Herramientas OK: {', '.join(tools)}")

    def preflight_optional(self, tools: list[str]):
        """Verifica tools opcionales. Avisa pero no falla."""
        for name in tools:
            if shutil.which(get_tool(self.cfg, name)):
                good(f"{name} disponible")
            else:
                warn(f"{name} no encontrado (opcional)")

    # ── Búsqueda de runs previos ──────────────────────────────

    @staticmethod
    def find_alive(cfg: dict, target: str) -> Optional[Path]:
        """Busca alive.txt de un run previo de subs."""
        base = cfg.get("output", {}).get("base_dir", "./output")
        safe = target.replace(".", "_").replace("/", "_")
        alive = Path(base) / safe / "subs" / "alive.txt"
        return alive if alive.exists() else None