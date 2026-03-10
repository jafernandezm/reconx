"""
Módulo: Parameter Discovery (arjun)
Mejora clave: prioriza urls_with_params.txt de urls.py.
Si ya tenemos URLs con parámetros reales del target (wayback/gau),
arjun las usa como base — encuentra parámetros ocultos ADICIONALES.
Lógica:
  1. urls_with_params.txt (URLs reales con params) → alta prioridad
  2. alive_urls como fallback si no hay params conocidos
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, banner, separator, Colors
from core.workspace import Workspace

C = Colors


class ParamsModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("params", {})

    def _get_priority_targets(self, alive_urls: list[str]) -> list[str]:
        """
        Prioriza URLs con parámetros reales del target.
        Estas son más interesantes para arjun porque ya tienen
        endpoints activos con parámetros conocidos.
        """
        # Buscar urls_with_params.txt de urls.py
        params_file = self.ws.path / "urls_with_params.txt"
        if params_file.exists():
            lines = [l.strip() for l in params_file.read_text().splitlines()
                     if l.strip()]
            if lines:
                info(f"Usando {len(lines)} URLs con params conocidos (de wayback/gau)")
                # Deduplicar por base URL (sin query string)
                seen_bases = set()
                unique = []
                for url in lines:
                    base = url.split("?")[0]
                    if base not in seen_bases:
                        seen_bases.add(base)
                        unique.append(url)
                info(f"  → {len(unique)} URLs únicas por base path")
                return unique

        # Fallback: alive_urls directas
        warn("No hay urls_with_params.txt — usando alive_urls como base")
        warn("  Corré el módulo 'urls' primero para mejores resultados")
        return alive_urls

    def _run_arjun(self, url: str, out_file: Path) -> dict:
        """
        Ejecuta arjun en una URL y retorna los resultados.
        """
        cmd = [
            get_tool(self.cfg, "arjun"),
            "-u", url,
            "-oJ", str(out_file),
            "-t", str(self.mod_cfg.get("threads", 10)),
            "--timeout", str(self.mod_cfg.get("timeout", 180)),
            "-q",  # quiet
        ]
        if self.mod_cfg.get("stable", True):
            cmd.append("--stable")

        run_cmd(cmd, timeout=self.mod_cfg.get("timeout", 180) + 30, silent=True)

        if out_file.exists():
            try:
                return json.loads(out_file.read_text())
            except Exception:
                pass
        return {}

    def run(self, alive_urls: list[str]):
        """
        Descubre parámetros ocultos con arjun.
        Prioriza endpoints con parámetros ya conocidos.
        """
        banner("PARAMETER DISCOVERY (arjun)")

        targets = self._get_priority_targets(alive_urls)

        max_targets = self.mod_cfg.get("max_targets", 5)
        if len(targets) > max_targets:
            warn(f"Limitando a {max_targets} targets (arjun es lento — ajustá params.max_targets)")
            targets = targets[:max_targets]

        arjun_dir = self.ws.subdir("arjun")

        info(f"Descubriendo params en {len(targets)} targets...")
        t0 = time.time()

        all_params_found = []

        for i, url in enumerate(targets, 1):
            safe = (url.replace("https://", "").replace("http://", "")
                       .replace("/", "_").replace(":", "_").replace("?", "_")
                       .replace("=", "_")[:100])
            out_file = arjun_dir / f"{safe}.json"

            print(f"    {C.DIM}[{i}/{len(targets)}] {url[:80]}{C.END}",
                  end="", flush=True)

            result = self._run_arjun(url, out_file)

            # Extraer parámetros encontrados
            params = []
            if isinstance(result, dict):
                for endpoint_data in result.values():
                    if isinstance(endpoint_data, dict):
                        params.extend(endpoint_data.get("params", []))
                    elif isinstance(endpoint_data, list):
                        params.extend(endpoint_data)

            if params:
                print(f" → {C.G}{len(params)} params: {', '.join(params[:5])}"
                      f"{'...' if len(params) > 5 else ''}{C.END}")
                all_params_found.append({
                    "url": url,
                    "params": params,
                })
            else:
                print(f" → {C.DIM}sin params{C.END}")

        elapsed = time.time() - t0
        good(f"arjun completado ({elapsed:.1f}s)")

        # ── Guardar resultados ────────────────────────────────
        if all_params_found:
            # Guardar resumen legible
            summary_lines = []
            for item in all_params_found:
                summary_lines.append(item["url"])
                for p in item["params"]:
                    summary_lines.append(f"  → {p}")
                summary_lines.append("")

            self.ws.save_lines("params_found.txt", summary_lines)
            good(f"Guardado: params_found.txt — "
                 f"{sum(len(i['params']) for i in all_params_found)} parámetros totales")

            # Guardar JSON completo
            self.ws.save_json("params_found.json", all_params_found)

            # URLs con params nuevos → wordlist para fuzzing posterior
            fuzz_urls = []
            for item in all_params_found:
                base = item["url"].split("?")[0]
                for p in item["params"]:
                    fuzz_urls.append(f"{base}?{p}=FUZZ")
            if fuzz_urls:
                self.ws.save_lines("param_fuzz_urls.txt", fuzz_urls)
                info(f"Guardado: param_fuzz_urls.txt ({len(fuzz_urls)}) "
                     f"{C.DIM}→ listo para fuzzing de valores{C.END}")
        else:
            info("arjun: no se encontraron parámetros ocultos")

        info(f"Resultados en: {arjun_dir}/")
        separator()