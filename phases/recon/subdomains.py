"""
Módulo: Subdomain Discovery
Fuentes:
  1. subfinder     (tool externa — múltiples fuentes)
  2. crt.sh        (Certificate Transparency logs — pasivo, sin tool)
  3. urlscan.io    (API pública — pasivo, sin tool)
  4. gotator       (permutaciones activas — genera variantes DNS)
  5. dnsgen        (permutaciones activas — alternativa/complemento a gotator)

Las fuentes pasivas (1-3) se corren primero.
Sus resultados alimentan las permutaciones (4-5).
Todo se combina, deduplica y valida con dnsx.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
import urllib.request
import urllib.parse
import ssl
from pathlib import Path

from core.config import get_tool
from core.runner import run_cmd
from core.utils import info, good, warn, banner
from core.workspace import Workspace


class SubdomainsModule:

    def __init__(self, cfg: dict, ws: Workspace):
        self.cfg = cfg
        self.ws = ws
        self.mod_cfg = cfg.get("subdomains", {})

    # ══════════════════════════════════════════════════════════
    # FUENTES PASIVAS
    # ══════════════════════════════════════════════════════════

    # ── Fuente 1: Subfinder ───────────────────────────────────
    def _run_subfinder(self, target: str, wildcard: bool) -> set[str]:
        """Subdomain discovery con subfinder."""
        if not shutil.which(get_tool(self.cfg, "subfinder")):
            warn("subfinder no disponible, saltando")
            return set()

        cmd = [
            get_tool(self.cfg, "subfinder"),
            "-d", target,
            "-silent",
            "-t", str(self.mod_cfg.get("threads", 10)),
            "-timeout", str(self.mod_cfg.get("timeout", 300)),
        ]
        if self.mod_cfg.get("all_sources", True):
            cmd.append("-all")
        if self.mod_cfg.get("recursive", True) or wildcard:
            cmd.append("-recursive")

        info("subfinder...")
        t0 = time.time()
        output = run_cmd(cmd, timeout=self.mod_cfg.get("timeout", 300) + 30)
        subs = set(
            line.strip().lower()
            for line in output.splitlines()
            if line.strip()
        )
        good(f"subfinder: {len(subs)} subdominios ({time.time()-t0:.1f}s)")
        return subs

    # ── Fuente 2: crt.sh (Certificate Transparency) ──────────
    def _run_crtsh(self, target: str) -> set[str]:
        """Consulta crt.sh — busca certificados TLS emitidos para el dominio."""
        info("crt.sh...")
        t0 = time.time()
        subs = set()

        try:
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(target)}&output=json"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (ReconX Subdomain Scanner)"
            })
            timeout = self.mod_cfg.get("crtsh_timeout", 30)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for entry in data:
                name = entry.get("name_value", "")
                for domain in name.split("\n"):
                    domain = domain.strip().lower()
                    if domain and not domain.startswith("*"):
                        if domain == target or domain.endswith(f".{target}"):
                            subs.add(domain)

            good(f"crt.sh: {len(subs)} subdominios ({time.time()-t0:.1f}s)")

        except urllib.error.HTTPError as e:
            warn(f"crt.sh HTTP error: {e.code}")
        except urllib.error.URLError as e:
            warn(f"crt.sh connection error: {e.reason}")
        except json.JSONDecodeError:
            warn("crt.sh devolvió respuesta inválida")
        except Exception as e:
            warn(f"crt.sh error: {e}")

        return subs

    # ── Fuente 3: urlscan.io ──────────────────────────────────
    def _run_urlscan(self, target: str) -> set[str]:
        """Consulta urlscan.io — scans públicos del dominio."""
        info("urlscan.io...")
        t0 = time.time()
        subs = set()

        try:
            query = urllib.parse.quote(f"domain:{target}")
            url = f"https://urlscan.io/api/v1/search/?q={query}&size=1000"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (ReconX Subdomain Scanner)"
            })
            timeout = self.mod_cfg.get("urlscan_timeout", 30)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for result in data.get("results", []):
                page = result.get("page", {})
                domain = page.get("domain", "").strip().lower()
                if domain and (domain == target or domain.endswith(f".{target}")):
                    subs.add(domain)

                task_url = result.get("task", {}).get("url", "")
                if task_url:
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(task_url).hostname
                        if host and (host == target or host.endswith(f".{target}")):
                            subs.add(host.lower())
                    except Exception:
                        pass

            good(f"urlscan.io: {len(subs)} subdominios ({time.time()-t0:.1f}s)")

        except urllib.error.HTTPError as e:
            if e.code == 429:
                warn("urlscan.io rate limited — saltando")
            else:
                warn(f"urlscan.io HTTP error: {e.code}")
        except urllib.error.URLError as e:
            warn(f"urlscan.io connection error: {e.reason}")
        except Exception as e:
            warn(f"urlscan.io error: {e}")

        return subs

    # ══════════════════════════════════════════════════════════
    # PERMUTACIONES ACTIVAS
    # Toman los subs pasivos como base y generan variantes.
    # Cada variante se valida con dnsx — solo quedan las reales.
    # Sin validación dnsx tendrías miles de falsos positivos.
    # ══════════════════════════════════════════════════════════

    def _validate_with_dnsx(self, candidates: list[str]) -> set[str]:
        """
        Valida candidatos con dnsx. Retorna solo los que resuelven DNS.
        Es el filtro crítico que convierte miles de candidatos en hits reales.
        """
        if not candidates:
            return set()

        dnsx_bin = get_tool(self.cfg, "dnsx")
        if not shutil.which(dnsx_bin):
            warn("dnsx no disponible — no se pueden validar permutaciones")
            return set()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as tmp:
            tmp.write("\n".join(candidates))
            tmp_path = tmp.name

        try:
            dns_cfg = self.cfg.get("dns", {})
            cmd = [
                dnsx_bin,
                "-l", tmp_path,
                "-silent",
                "-t", str(dns_cfg.get("threads", 50)),
                "-timeout", str(dns_cfg.get("timeout", 10)),
                "-retry", str(dns_cfg.get("retries", 2)),
            ]
            output = run_cmd(cmd, timeout=300)
            resolved = set(
                line.strip().lower()
                for line in output.splitlines()
                if line.strip()
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return resolved

    # ── Fuente 4: gotator ─────────────────────────────────────
    def _run_gotator(self, current_subs: set[str], target: str) -> set[str]:
        """
        Permutaciones con gotator.

        Toma tus subs encontrados y genera variantes combinando
        palabras comunes: dev, staging, prod, api, v2, internal...

          mail.target.com  → mail-dev, mail2, mailstaging, webmail...
          api.target.com   → api-v2, api-prod, api2, api-test...

        Config en config.yaml (bajo subdomains:):
          use_gotator: true
          gotator_depth: 1        # 1=rápido  2=exhaustivo
          gotator_prefixes: true  # prefijos comunes
          gotator_numbers: true   # variantes numéricas (dev1, dev2...)
          gotator_md: true        # mutaciones de nivel medio
          gotator_wordlist: ""    # wordlist custom (vacío = interna de gotator)
        """
        gotator_bin = get_tool(self.cfg, "gotator")
        if not shutil.which(gotator_bin):
            warn("gotator no encontrado — agregá $HOME/go/bin al PATH")
            warn("  export PATH=$PATH:$HOME/go/bin")
            return set()

        if not current_subs:
            return set()

        info(f"gotator: permutando {len(current_subs)} subs base...")
        t0 = time.time()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False) as tmp:
            tmp.write("\n".join(sorted(current_subs)))
            subs_file = tmp.name

        try:
            cmd = [
                gotator_bin,
                "-sub", subs_file,
                "-silent",
                "-depth", str(self.mod_cfg.get("gotator_depth", 1)),
            ]

            # Wordlist custom o interna de gotator
            wordlist = self.mod_cfg.get("gotator_wordlist", "")
            if wordlist and Path(wordlist).exists():
                cmd += ["-perm", wordlist]

            # Flags booleanos — gotator los acepta como -flag=true
            if self.mod_cfg.get("gotator_prefixes", True):
                cmd += ["-prefixes=true"]
            if self.mod_cfg.get("gotator_numbers", True):
                cmd += ["-numbers=true"]
            if self.mod_cfg.get("gotator_adv", False):
                cmd += ["-adv=true"]

            output = run_cmd(cmd, timeout=300)

            # Filtrar solo subdominios del target
            candidates = [
                line.strip().lower()
                for line in output.splitlines()
                if line.strip() and (
                    line.strip().lower() == target or
                    line.strip().lower().endswith(f".{target}")
                )
            ]

            gen_count = len(candidates)
            info(f"  {gen_count} candidatos generados → validando con dnsx...")

            resolved = self._validate_with_dnsx(candidates)
            new_subs = resolved - current_subs

            good(f"gotator: {len(new_subs)} nuevos "
                 f"({gen_count} generados → {len(resolved)} resuelven DNS) "
                 f"({time.time()-t0:.1f}s)")

        finally:
            Path(subs_file).unlink(missing_ok=True)

        return new_subs

    # ── Fuente 5: dnsgen ──────────────────────────────────────
    def _run_dnsgen(self, current_subs: set[str], target: str) -> set[str]:
        """
        Permutaciones con dnsgen (Python — pip install dnsgen).

        Usa un algoritmo distinto a gotator — se complementan bien.
        Encuentra variantes que gotator no genera y viceversa.

          autenticacion.target.com → auth, authentication, autenticacion2...
          moodle.target.com        → moodle2, moodle-dev, lms, elearning...
        """
        try:
            import dnsgen  # type: ignore
        except ImportError:
            warn("dnsgen no instalado — pip install dnsgen")
            return set()

        if not current_subs:
            return set()

        info(f"dnsgen: permutando {len(current_subs)} subs base...")
        t0 = time.time()

        try:
            candidates = list(dnsgen.generate(list(current_subs)))
        except Exception as e:
            warn(f"dnsgen error generando permutaciones: {e}")
            return set()

        # Filtrar solo subdominios del target
        candidates = [
            c.strip().lower() for c in candidates
            if c.strip().lower() == target or
               c.strip().lower().endswith(f".{target}")
        ]

        gen_count = len(candidates)
        info(f"  {gen_count} candidatos generados → validando con dnsx...")

        resolved = self._validate_with_dnsx(candidates)
        new_subs = resolved - current_subs

        good(f"dnsgen: {len(new_subs)} nuevos "
             f"({gen_count} generados → {len(resolved)} resuelven DNS) "
             f"({time.time()-t0:.1f}s)")

        return new_subs

    # ══════════════════════════════════════════════════════════
    # RUN PRINCIPAL
    # ══════════════════════════════════════════════════════════

    def run(self, target: str, exclude: list[str] = None,
            wildcard: bool = False) -> list[str]:
        """
        Orden de ejecución:
          1. Pasivo: subfinder + crt.sh + urlscan.io
          2. Activo: gotator + dnsgen sobre los resultados pasivos
             (más subs base = mejores permutaciones)

        Retorna lista de subdominios únicos encontrados.
        """
        banner("STEP 1 → Subdomain Discovery")

        all_subs = set()

        # ── Pasivo ────────────────────────────────────────────
        subfinder_subs = self._run_subfinder(target, wildcard)
        all_subs.update(subfinder_subs)

        crtsh_subs = set()
        if self.mod_cfg.get("use_crtsh", True):
            crtsh_subs = self._run_crtsh(target)
            new = crtsh_subs - all_subs
            if new:
                info(f"  ↳ {len(new)} nuevos de crt.sh")
            all_subs.update(crtsh_subs)

        urlscan_subs = set()
        if self.mod_cfg.get("use_urlscan", True):
            urlscan_subs = self._run_urlscan(target)
            new = urlscan_subs - all_subs
            if new:
                info(f"  ↳ {len(new)} nuevos de urlscan.io")
            all_subs.update(urlscan_subs)

        all_subs.add(target)
        info(f"Pasivo total: {len(all_subs)} subdominios — iniciando permutaciones...")

        # ── Permutaciones ─────────────────────────────────────
        # gotator y dnsgen usan TODO lo encontrado en pasivo como base.
        # Cuantos más subs base haya, mejores permutaciones generan.

        gotator_subs = set()
        if self.mod_cfg.get("use_gotator", True):
            gotator_subs = self._run_gotator(all_subs, target)
            all_subs.update(gotator_subs)

        dnsgen_subs = set()
        if self.mod_cfg.get("use_dnsgen", True):
            # dnsgen también usa el set actualizado (incluye hits de gotator)
            dnsgen_subs = self._run_dnsgen(all_subs, target)
            all_subs.update(dnsgen_subs)

        # ── Post-procesado ────────────────────────────────────
        subs = sorted(all_subs)

        max_results = self.mod_cfg.get("max_results", 5000)
        if wildcard:
            max_results = max(max_results, 10000)
        if len(subs) > max_results:
            warn(f"Muchos subdominios ({len(subs)}), capped a {max_results}")
            subs = subs[:max_results]

        good(f"TOTAL: {len(subs)} subdominios únicos")

        if exclude:
            before = len(subs)
            subs = [
                s for s in subs
                if not any(s == exc or s.endswith(f".{exc}") for exc in exclude)
            ]
            diff = before - len(subs)
            if diff:
                warn(f"{diff} subdominios excluidos del scope")

        # ── Guardar ───────────────────────────────────────────
        self.ws.save_lines("all_subdomains.txt", subs)
        info(f"Guardado: all_subdomains.txt ({len(subs)})")

        # Por fuente — útil para ver qué encontró cada una
        if subfinder_subs:
            self.ws.save_lines("src_subfinder.txt", sorted(subfinder_subs))
        if crtsh_subs:
            self.ws.save_lines("src_crtsh.txt", sorted(crtsh_subs))
        if urlscan_subs:
            self.ws.save_lines("src_urlscan.txt", sorted(urlscan_subs))
        if gotator_subs:
            self.ws.save_lines("src_gotator.txt", sorted(gotator_subs))
        if dnsgen_subs:
            self.ws.save_lines("src_dnsgen.txt", sorted(dnsgen_subs))

        return subs