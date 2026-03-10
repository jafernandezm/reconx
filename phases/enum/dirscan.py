"""
Módulo: Directory Fuzzing (ffuf)
Con detección de WAF antes de fuzzear.

Lógica por target:
  Sin WAF           → ffuf normal   (threads config, sin delay)
  WAF leve          → modo stealth  (threads bajos, delay, headers evasión)
  WAF estricto      → skip + aviso  (Cloudflare/Akamai en modo bloqueo)

Flujo de wordlists:
  1. unique_paths.txt (paths reales del target desde wayback/gau)  ← más efectiva
  2. Wordlist estándar (raft-medium) como complemento
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, error, banner, separator, Colors
from core.workspace import Workspace

C = Colors

# WAFs que bloquean fuzzing completamente — no vale la pena intentar
_WAF_STRICT = {
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
}

# WAFs que se pueden bypassear con stealth
_WAF_STEALTH = {
    "sucuri",
    "wordfence",
    "modsecurity",
    "aws waf",
    "f5",
    "barracuda",
}


class DirscanModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("dirscan", {})

    # ══════════════════════════════════════════════════════════
    # Detección de WAF
    # ══════════════════════════════════════════════════════════

    def _load_tech_map(self) -> dict[str, list[str]]:
        """
        Lee httpx_results.json del paso subs.
        Retorna dict url → lista de tecnologías en minúscula.
        """
        httpx_json = self.ws.path.parent.parent / "subs" / "httpx_results.json"
        if not httpx_json.exists():
            return {}

        try:
            data = json.loads(httpx_json.read_text())
            result = {}
            for entry in data:
                url = entry.get("url", "")
                techs = [t.lower() for t in entry.get("tech", [])]
                if url:
                    result[url] = techs
            return result
        except Exception:
            return {}

    def _detect_waf(self, url: str,
                    tech_map: dict[str, list[str]]) -> tuple[str, str]:
        """
        Detecta WAF de un target.
        Retorna (tipo, nombre):
          ("strict",  "cloudflare")  → skip fuzzing
          ("stealth", "sucuri")      → fuzzing con evasión
          ("none",    "")            → fuzzing normal
        """
        techs = tech_map.get(url, [])

        for tech in techs:
            for waf in _WAF_STRICT:
                if waf in tech:
                    return ("strict", waf)

        for tech in techs:
            for waf in _WAF_STEALTH:
                if waf in tech:
                    return ("stealth", waf)

        return ("none", "")

    # ══════════════════════════════════════════════════════════
    # Wordlists
    # ══════════════════════════════════════════════════════════

    def _resolve_wordlist(self) -> str | None:
        """Encuentra wordlist estándar disponible."""
        wl = self.mod_cfg.get("wordlist", "")
        if Path(wl).exists():
            return wl

        fallback = self.mod_cfg.get("wordlist_fallback", "")
        if Path(fallback).exists():
            warn("Wordlist principal no encontrada, usando fallback")
            return fallback

        error(f"No se encontró wordlist: {wl}")
        warn("Instalá seclists o ajustá dirscan.wordlist en config.yaml")
        return None

    def _get_custom_wordlist(self, url: str) -> str | None:
        """
        Busca unique_paths.txt del host específico (generado por urls.py).
        Paths reales del target → mucho más efectivos que lista genérica.
        """
        from core.workspace import _host_to_dirname
        host_dir = self.ws.path / _host_to_dirname(url)
        custom = host_dir / "urls" / "unique_paths.txt"

        # Fallback: unique_paths.txt global (versión anterior)
        if not custom.exists():
            custom = self.ws.path / "unique_paths.txt"

        if custom.exists() and custom.stat().st_size > 0:
            count = len(custom.read_text().splitlines())
            info(f"  Wordlist custom: {count} paths reales del target")
            return str(custom)
        return None

    # ══════════════════════════════════════════════════════════
    # Fuzzing
    # ══════════════════════════════════════════════════════════

    def _build_cmd(self, url: str, wordlist: str, out_file: Path,
                   waf_type: str) -> list[str]:
        """
        Construye el comando ffuf adaptado al tipo de WAF detectado.
        """
        match_codes = self.mod_cfg.get(
            "match_codes", [200, 201, 204, 301, 302, 307, 401, 403, 405]
        )
        mc_str = ",".join(str(c) for c in match_codes)
        extensions = self.mod_cfg.get("extensions", [])
        ext_str = ",".join(extensions) if extensions else ""

        if waf_type == "stealth":
            # Modo evasión: menos threads, delay, headers que parecen browser real
            threads  = min(self.mod_cfg.get("threads", 50), 5)
            delay    = "500-1500"   # delay aleatorio en ms entre requests
            ua       = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36")
        else:
            # Modo normal
            threads  = self.mod_cfg.get("threads", 50)
            delay    = None
            ua       = "Mozilla/5.0 (ReconX Scanner)"

        cmd = [
            get_tool(self.cfg, "ffuf"),
            "-u",       f"{url.rstrip('/')}/FUZZ",
            "-w",       wordlist,
            "-mc",      mc_str,
            "-t",       str(threads),
            "-timeout", str(self.mod_cfg.get("timeout", 300)),
            "-o",       str(out_file),
            "-of",      "json",
            "-s",
            "-ac",                          # auto-calibrate
            "-H",       f"User-Agent: {ua}",
        ]

        if waf_type == "stealth":
            cmd.extend([
                "-p",    delay,             # delay entre requests
                "-H",    "Accept-Language: en-US,en;q=0.9",
                "-H",    "Accept: text/html,application/xhtml+xml,*/*",
                "-recursion-depth", "0",    # sin recursión en stealth
            ])

        if ext_str:
            cmd.extend(["-e", ext_str])

        return cmd

    def _fuzz_target(self, url: str, wordlist: str, label: str,
                     ffuf_dir: Path, idx: int, total: int,
                     waf_type: str = "none") -> list[str]:
        """Ejecuta ffuf contra un target. Retorna URLs encontradas."""
        safe = (url.replace("https://", "").replace("http://", "")
                   .replace("/", "_").replace(":", "_"))
        out_file = ffuf_dir / f"{safe}_{label}.json"

        cmd = self._build_cmd(url, wordlist, out_file, waf_type)

        print(f"    {C.DIM}[{idx}/{total}] {url} [{label}]{C.END}",
              end="", flush=True)

        run_cmd(cmd, timeout=self.mod_cfg.get("timeout", 300) + 60, silent=True)

        found = []
        if out_file.exists():
            try:
                data   = json.loads(out_file.read_text())
                results = data.get("results", [])
                found  = [r.get("url", "") for r in results if r.get("url")]
                status = f"{C.G}{len(found)} encontrados{C.END}" if found else "0"
                print(f" → {status}")
            except json.JSONDecodeError:
                print(f" → {C.Y}parse error{C.END}")
        else:
            print(f" → {C.DIM}sin output{C.END}")

        return found

    # ══════════════════════════════════════════════════════════
    # Run principal
    # ══════════════════════════════════════════════════════════

    def run(self, alive_urls: list[str]):
        """
        Para cada target:
          1. Detecta WAF desde httpx_results.json
          2. Decide modo: skip / stealth / normal
          3. Ronda 1 con paths reales del target
          4. Ronda 2 con wordlist estándar
        """
        banner("DIRECTORY FUZZING (ffuf)")

        # Cargar tech map una sola vez
        tech_map = self._load_tech_map()
        if tech_map:
            info("Tech map cargado desde httpx_results.json")
        else:
            warn("Sin tech map — no se puede detectar WAF (corré subs primero)")

        max_targets = self.mod_cfg.get("max_targets", 15)
        targets = alive_urls[:max_targets]
        if len(alive_urls) > max_targets:
            warn(f"Limitando a {max_targets} targets (config: dirscan.max_targets)")

        ffuf_dir = self.ws.subdir("ffuf")
        std_wl   = self._resolve_wordlist()
        all_found = []

        for i, url in enumerate(targets, 1):

            # ── Detección de WAF ──────────────────────────────
            waf_type, waf_name = self._detect_waf(url, tech_map)

            if waf_type == "strict":
                warn(f"[{i}/{len(targets)}] {url}")
                warn(f"  WAF ESTRICTO detectado: {C.R}{waf_name}{C.END} "
                     f"— skipping fuzzing (bloqueará todo)")
                warn(f"  Tip: probá manualmente con Burp + extensión CF bypass")
                separator()
                continue

            if waf_type == "stealth":
                warn(f"[{i}/{len(targets)}] {url}")
                warn(f"  WAF detectado: {C.Y}{waf_name}{C.END} "
                     f"— modo stealth activado (lento pero evasivo)")
            else:
                info(f"[{i}/{len(targets)}] {url} — sin WAF detectado")

            target_found = []

            # ── Ronda 1: paths reales del target ──────────────
            custom_wl = self._get_custom_wordlist(url)
            if custom_wl:
                info("  [Ronda 1] Paths reales del target...")
                found = self._fuzz_target(
                    url, custom_wl, "custom",
                    ffuf_dir, i, len(targets), waf_type,
                )
                target_found.extend(found)
            else:
                info("  Sin wordlist custom — corré 'urls' primero")

            # ── Ronda 2: wordlist estándar ────────────────────
            if std_wl:
                info("  [Ronda 2] Wordlist estándar...")
                found = self._fuzz_target(
                    url, std_wl, "std",
                    ffuf_dir, i, len(targets), waf_type,
                )
                # Solo nuevos
                new = [u for u in found if u not in target_found]
                target_found.extend(new)

            if target_found:
                good(f"  Total {url}: {C.G}{len(target_found)}{C.END} paths")
            all_found.extend(target_found)
            separator()

        # ── Guardar resultados globales ───────────────────────
        if all_found:
            unique = sorted(set(all_found))
            self.ws.save_lines("ffuf_found.txt", unique)
            good(f"Total dirs/files únicos: {C.G}{len(unique)}{C.END}")
            self._save_by_status(ffuf_dir)
        else:
            info("ffuf: sin resultados")

        separator()

    # ══════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════

    def _save_by_status(self, ffuf_dir: Path):
        """Agrupa resultados por código HTTP. 200 > 403 > 301 en prioridad."""
        by_status: dict[int, list[str]] = {}

        for json_file in ffuf_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                for r in data.get("results", []):
                    code = r.get("status", 0)
                    url  = r.get("url", "")
                    if url:
                        by_status.setdefault(code, []).append(url)
            except Exception:
                continue

        if not by_status:
            return

        info("Breakdown por código HTTP:")
        for code, urls in sorted(by_status.items()):
            color = (C.G   if code == 200 else
                     C.Y   if code in (301, 302, 403) else
                     C.DIM)
            info(f"  [{color}{code}{C.END}] {len(urls)} paths")