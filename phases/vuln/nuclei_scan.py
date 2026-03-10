"""
Módulo: Vulnerability Scanning (nuclei)
Mejora clave: adapta templates según tecnología detectada en httpx.
Si httpx detectó Keycloak → lanza templates de Keycloak.
Si detectó WordPress  → lanza templates de WordPress.
Si detectó Nginx      → lanza templates de Nginx.
Lógica:
  1. Lee httpx_results.json del paso subs (tecnologías detectadas)
  2. Mapea tech → templates específicos de nuclei
  3. Corre templates genéricos + templates específicos por tech
  4. Prioriza targets sin WAF (Cloudflare los filtra al final)
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

# Mapeo tecnología → templates nuclei específicos
# Cuanto más específico el template, menos falsos positivos
_TECH_TEMPLATES: dict[str, list[str]] = {
    "keycloak":          ["http/cves/keycloak", "http/exposures/keycloak"],
    "wordpress":         ["http/cves/wordpress", "http/vulnerabilities/wordpress",
                          "http/exposed-panels/wordpress-login.yaml"],
    "moodle":            ["http/cves/moodle", "http/vulnerabilities/moodle"],
    "joomla":            ["http/cves/joomla", "http/vulnerabilities/joomla"],
    "drupal":            ["http/cves/drupal"],
    "nginx":             ["http/misconfiguration/nginx", "http/cves/nginx"],
    "apache":            ["http/misconfiguration/apache", "http/cves/apache"],
    "iis":               ["http/cves/iis", "http/misconfiguration/iis"],
    "tomcat":            ["http/cves/tomcat", "http/exposed-panels/tomcat-manager.yaml"],
    "jenkins":           ["http/cves/jenkins", "http/exposed-panels/jenkins.yaml",
                          "http/default-logins/jenkins"],
    "grafana":           ["http/cves/grafana", "http/default-logins/grafana"],
    "phpmyadmin":        ["http/cves/phpmyadmin", "http/default-logins/phpmyadmin"],
    "microsoft asp.net": ["http/cves/asp", "http/misconfiguration/asp-net"],
    "laravel":           ["http/cves/laravel", "http/exposures/laravel-debug.yaml"],
    "spring":            ["http/cves/spring", "http/vulnerabilities/spring"],
    "gitlab":            ["http/cves/gitlab", "http/default-logins/gitlab"],
    "bitbucket":         ["http/cves/bitbucket"],
    "confluence":        ["http/cves/confluence", "http/default-logins/confluence"],
    "jira":              ["http/cves/jira", "http/exposed-panels/jira.yaml"],
    "elasticsearch":     ["http/cves/elasticsearch", "http/misconfiguration/elasticsearch"],
    "kibana":            ["http/exposed-panels/kibana.yaml", "http/cves/kibana"],
    "grafana":           ["http/cves/grafana"],
    "redis":             ["network/redis-unauth.yaml"],
    "mongodb":           ["network/mongodb-unauth.yaml"],
    "php":               ["http/cves/php", "http/misconfiguration/php"],
    "openssl":           ["ssl/deprecated-tls.yaml", "ssl/tls-version.yaml"],
}


class NucleiScanModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("nuclei", {})

    # ── Leer tecnologías detectadas ───────────────────────────

    def _load_tech_map(self) -> dict[str, list[str]]:
        """
        Lee httpx_results.json del paso subs y retorna
        dict url → lista de tecnologías detectadas.
        """
        # Buscar en output/<target>/subs/httpx_results.json
        subs_path = self.ws.path.parent / "subs" / "httpx_results.json"
        if not subs_path.exists():
            warn("No encontré httpx_results.json — sin tech-specific templates")
            return {}

        try:
            data = json.loads(subs_path.read_text())
            tech_map = {}
            for entry in data:
                url = entry.get("url", "")
                techs = [t.lower() for t in entry.get("tech", [])]
                if url and techs:
                    tech_map[url] = techs
            info(f"Tech map cargado: {len(tech_map)} hosts con tecnologías detectadas")
            return tech_map
        except Exception as e:
            warn(f"Error leyendo httpx_results.json: {e}")
            return {}

    def _get_tech_templates(self, tech_map: dict[str, list[str]]) -> list[str]:
        """
        Dado el mapa de tecnologías, retorna lista de templates
        específicos de nuclei a usar.
        """
        templates = set()
        for url, techs in tech_map.items():
            for tech in techs:
                # Buscar coincidencia en el mapeo
                for key, tpls in _TECH_TEMPLATES.items():
                    if key in tech:
                        templates.update(tpls)
                        info(f"  Tech detectada: {C.Y}{tech}{C.END} "
                             f"→ {len(tpls)} templates específicos")

        return list(templates)

    def _prioritize_targets(self, alive_urls: list[str],
                             tech_map: dict[str, list[str]]) -> list[str]:
        """
        Prioriza targets sin WAF.
        Cloudflare/Akamai bloquean la mayoría de los scans de nuclei —
        ponerlos al final evita que consuman tiempo de los resultados útiles.
        """
        waf_keywords = ["cloudflare", "akamai", "imperva", "sucuri", "fastly"]

        no_waf = []
        with_waf = []

        for url in alive_urls:
            techs = tech_map.get(url, [])
            has_waf = any(waf in t for t in techs for waf in waf_keywords)
            if has_waf:
                with_waf.append(url)
            else:
                no_waf.append(url)

        if with_waf:
            warn(f"{len(with_waf)} targets con WAF detectado — se escanearán al final")
            for u in with_waf:
                info(f"  {C.Y}[WAF]{C.END} {u}")

        return no_waf + with_waf

    def _run_nuclei(self, targets: list[str], extra_templates: list[str],
                    label: str, out_suffix: str) -> list[str]:
        """
        Ejecuta nuclei contra targets con templates dados.
        Retorna findings como lista de strings.
        """
        if not targets:
            return []

        input_file = self.ws.path / f".nuclei_input_{out_suffix}.txt"
        input_file.write_text("\n".join(targets))

        severity = self.mod_cfg.get("severity", ["critical", "high", "medium"])
        base_templates = self.mod_cfg.get(
            "templates", ["cves", "exposures", "misconfigurations",
                          "vulnerabilities", "default-logins"]
        )

        out_json = self.ws.path / f"nuclei_results_{out_suffix}.json"

        cmd = [
            get_tool(self.cfg, "nuclei"),
            "-l", str(input_file),
            "-s", ",".join(severity),
            "-rl", str(self.mod_cfg.get("rate_limit", 100)),
            "-bs", str(self.mod_cfg.get("bulk_size", 25)),
            "-c", str(self.mod_cfg.get("concurrency", 10)),
            "-timeout", str(self.mod_cfg.get("timeout", 900)),
            "-je", str(out_json),
            "-silent",
            "-no-color",
        ]

        # Templates base
        for tpl in base_templates:
            cmd.extend(["-t", tpl])

        # Templates específicos por tech (adicionales)
        for tpl in extra_templates:
            cmd.extend(["-t", tpl])

        info(f"[{label}] Scanning {len(targets)} targets...")
        if extra_templates:
            info(f"  + {len(extra_templates)} templates específicos por tecnología")

        t0 = time.time()
        output = run_cmd(cmd, timeout=self.mod_cfg.get("timeout", 900) + 120)
        elapsed = time.time() - t0

        findings = [l.strip() for l in output.splitlines() if l.strip()]
        info(f"  Completado en {elapsed:.1f}s")

        input_file.unlink(missing_ok=True)
        return findings

    def _print_severity_breakdown(self, findings: list[str]):
        """Desglose por severidad con colores."""
        sev_colors = {
            "critical": C.R,
            "high":     C.R,
            "medium":   C.Y,
            "low":      C.B,
            "info":     C.DIM,
        }
        for sev, color in sev_colors.items():
            matched = [f for f in findings if f"[{sev}]" in f.lower()]
            if not matched:
                continue
            print(f"    {color}{sev.upper():>10}: {len(matched)}{C.END}")
            for f in matched[:3]:
                print(f"              {C.DIM}{f[:100]}{C.END}")
            if len(matched) > 3:
                print(f"              {C.DIM}... y {len(matched)-3} más{C.END}")

    def run(self, alive_urls: list[str]):
        """
        Escaneo inteligente:
          1. Carga tecnologías detectadas por httpx
          2. Selecciona templates específicos por tech
          3. Prioriza targets sin WAF
          4. Corre nuclei con templates genéricos + específicos
        """
        banner("VULNERABILITY SCANNING (nuclei)")

        # Actualizar templates
        if self.mod_cfg.get("update_templates", True):
            info("Actualizando nuclei templates...")
            run_cmd([get_tool(self.cfg, "nuclei"), "-ut"],
                    timeout=120, silent=True)
            good("Templates actualizados")

        # Cargar tech map y determinar templates específicos
        tech_map = self._load_tech_map()
        tech_templates = self._get_tech_templates(tech_map)

        if tech_templates:
            good(f"{len(tech_templates)} templates específicos por tecnología detectada")

        # Priorizar targets (sin WAF primero)
        targets = self._prioritize_targets(alive_urls, tech_map)

        # Ejecutar scan
        findings = self._run_nuclei(
            targets=targets,
            extra_templates=tech_templates,
            label="FULL SCAN",
            out_suffix="main",
        )

        # ── Guardar y mostrar resultados ──────────────────────
        if findings:
            # Deduplicar
            unique_findings = sorted(set(findings))

            self.ws.save_lines("nuclei_findings.txt", unique_findings)
            good(f"{C.R}{C.BOLD}{len(unique_findings)} vulnerabilidades encontradas!{C.END}")
            self._print_severity_breakdown(unique_findings)

            # Separar críticos para atención inmediata
            critical = [f for f in unique_findings
                        if "[critical]" in f.lower() or "[high]" in f.lower()]
            if critical:
                self.ws.save_lines("nuclei_critical.txt", critical)
                good(f"{C.R}Críticos/Altos guardados en: nuclei_critical.txt{C.END}")
        else:
            good("No se encontraron vulnerabilidades")

        separator()