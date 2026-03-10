#!/usr/bin/env python3
"""
ReconX — Automated Reconnaissance Framework
─────────────────────────────────────────────
  reconx.py subs  -t target.com              Subdominios → vivos/muertos
  reconx.py recon -t target.com              Recon profundo sobre vivos
  reconx.py recon -sL output/target/alive.txt   Desde lista custom
"""

from __future__ import annotations

import sys
import argparse
import time

from core.utils import Colors, info, good, warn, error, banner, separator
from core.workspace import Workspace
from core.config import load_config

VERSION = "0.2.0"
LOGO = rf"""
╦═╗╔═╗╔═╗╔═╗╔╗╔═╗ ╦
╠╦╝║╣ ║  ║ ║║║║╔╩╦╝
╩╚═╚═╝╚═╝╚═╝╝╚╝ ╩  v{VERSION}
"""
C = Colors


# ══════════════════════════════════════════════════════════════
# COMMAND: subs
# Flujo: subfinder → dnsx → httpx → alive.txt / dead.txt
# ══════════════════════════════════════════════════════════════

def cmd_subs(args: argparse.Namespace):
    cfg = load_config(args.config)
    target = args.target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    banner(f"SUBDOMAIN ENUMERATION — {target}")
    separator()

    # Workspace: output/<target>/subs/
    ws = Workspace(cfg, target, phase="subs")
    ws.setup()
    info(f"Output → {ws.path}")

    # Preflight: verificar tools necesarias
    ws.preflight(["subfinder", "dnsx", "httpx"])

    # Guardar scope (wildcard, exclusiones) para que recon lo sepa
    import json
    scope_data = {
        "target": target,
        "wildcard": args.wildcard,
        "exclude": args.exclude or [],
    }
    ws.save_json("scope.json", scope_data)
    if args.wildcard:
        info("Wildcard activado: *.{} en scope".format(target))

    # ── Step 1: Subfinder ─────────────────────────────────────
    from phases.recon.subdomains import SubdomainsModule
    subs_mod = SubdomainsModule(cfg, ws)
    all_subs = subs_mod.run(target, exclude=args.exclude or [],
                            wildcard=args.wildcard)

    if not all_subs:
        warn("No se encontraron subdominios. Verificá el target.")
        return

    # ── Step 2: DNS Resolution ────────────────────────────────
    from phases.recon.dns import DnsModule
    dns_mod = DnsModule(cfg, ws)
    resolved, no_resolve = dns_mod.run(all_subs)

    if not resolved:
        warn("Ningún subdominio resuelve DNS.")
        return

    # ── Step 3: HTTP Probe ────────────────────────────────────
    from phases.recon.http_probe import HttpProbeModule
    http_mod = HttpProbeModule(cfg, ws)
    alive, dead, httpx_data = http_mod.run(resolved)

    # ── Resumen ───────────────────────────────────────────────
    separator()
    banner("RESUMEN")
    print(f"""
  Subdominios encontrados:  {len(all_subs)}
  Resuelven DNS:            {len(resolved)}
  Vivos (HTTP):             {C.G}{len(alive)}{C.END}
  Muertos:                  {C.R}{len(dead)}{C.END}
  No resuelven:             {len(no_resolve)}

  {C.DIM}Archivos en: {ws.path}{C.END}
    """)

    # Mostrar tech detectada
    http_mod.print_tech_summary(httpx_data)

    separator()
    print(f"\n  {C.BOLD}Siguiente paso:{C.END}")
    print(f"  {C.G}reconx.py recon -t {target}{C.END}")
    print(f"  {C.DIM}o: reconx.py recon -sL {ws.path}/alive.txt{C.END}\n")


# ══════════════════════════════════════════════════════════════
# COMMAND: recon
# Toma alive.txt → gau + wayback → katana → ffuf → arjun → nuclei
# ══════════════════════════════════════════════════════════════

def cmd_recon(args: argparse.Namespace):
    cfg = load_config(args.config)

    # Resolver targets: desde -t (busca alive.txt previo) o -sL (lista custom)
    target, alive_urls = _resolve_recon_targets(args, cfg)

    if not alive_urls:
        error("No hay URLs para analizar.")
        sys.exit(1)

    banner(f"WEB RECON — {target} ({len(alive_urls)} hosts)")
    separator()

    # Workspace: output/<target>/recon/
    ws = Workspace(cfg, target, phase="recon")
    ws.setup()
    ws.save_lines("input_urls.txt", alive_urls)
    info(f"Output → {ws.path}")

    # ── Seleccionar módulos ───────────────────────────────────
    all_modules = ["urls", "katana", "ffuf", "arjun", "nuclei"]
    modules = _select_modules(args, all_modules)
    info(f"Módulos: {', '.join(modules)}")
    separator()

    # Timestamp de inicio para summary
    _recon_start = time.time()

    # Acumulador de URLs descubiertas (se pasa entre módulos)
    all_discovered_urls: list[str] = []

    # ── 1. URL Harvesting (gau + waybackurls) ─────────────────
    if "urls" in modules:
        from phases.enum.urls import UrlsModule
        urls_mod = UrlsModule(cfg, ws)
        harvested = urls_mod.run(alive_urls)
        all_discovered_urls.extend(harvested)

    # ── 2. Web Crawling (katana) ──────────────────────────────
    if "katana" in modules:
        from phases.enum.crawl import CrawlModule
        crawl_mod = CrawlModule(cfg, ws)
        crawled = crawl_mod.run(alive_urls)
        all_discovered_urls.extend(crawled)

    # Merge todas las URLs descubiertas
    if all_discovered_urls:
        unique = sorted(set(all_discovered_urls))
        ws.save_lines("all_urls.txt", unique)
        good(f"Total URLs únicas descubiertas: {len(unique)}")
        separator()

    # ── 3. Directory Fuzzing (ffuf) ───────────────────────────
    if "ffuf" in modules:
        from phases.enum.dirscan import DirscanModule
        dir_mod = DirscanModule(cfg, ws)
        dir_mod.run(alive_urls)

    # ── 4. Parameter Discovery (arjun) ────────────────────────
    if "arjun" in modules:
        from phases.enum.params import ParamsModule
        params_mod = ParamsModule(cfg, ws)
        params_mod.run(alive_urls)

    # ── 5. Vulnerability Scan (nuclei) ────────────────────────
    if "nuclei" in modules:
        from phases.vuln.nuclei_scan import NucleiScanModule
        nuclei_mod = NucleiScanModule(cfg, ws)
        nuclei_mod.run(alive_urls)

    # ── Resumen final ─────────────────────────────────────────
    _print_recon_summary(ws, target, modules, alive_urls, _recon_start)


# ══════════════════════════════════════════════════════════════
# HELPERS (privados al orquestador)
# ══════════════════════════════════════════════════════════════

def _resolve_recon_targets(args, cfg) -> tuple[str, list[str]]:
    """Resuelve de dónde sacar las URLs vivas."""
    if args.subs_list:
        from core.utils import read_lines
        alive = read_lines(args.subs_list)
        # Inferir target del primer URL
        first = alive[0].replace("https://", "").replace("http://", "")
        host = first.split("/")[0].split(":")[0]
        parts = host.split(".")
        target = ".".join(parts[-2:]) if len(parts) > 2 else host
        return target, alive

    if args.target:
        target = args.target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
        # Buscar alive.txt del comando subs anterior
        alive_path = Workspace.find_alive(cfg, target)
        if alive_path:
            from core.utils import read_lines
            alive = read_lines(alive_path)
            info(f"Cargando {len(alive)} URLs desde: {alive_path}")
            return target, alive
        else:
            warn(f"No encontré alive.txt para {target}")
            warn(f"Corré primero: reconx.py subs -t {target}")
            warn(f"O pasá una lista: reconx.py recon -sL archivo.txt")
            sys.exit(1)

    error("Necesitás -t <target> o -sL <alive.txt>")
    sys.exit(1)


def _select_modules(args, all_modules: list[str]) -> list[str]:
    """Filtra módulos según --only / --skip."""
    modules = list(all_modules)
    if args.only:
        modules = [m for m in args.only if m in all_modules]
        invalid = [m for m in args.only if m not in all_modules]
        if invalid:
            warn(f"Módulos no válidos ignorados: {', '.join(invalid)}")
        if not modules:
            error(f"Ningún módulo válido. Disponibles: {', '.join(all_modules)}")
            sys.exit(1)
    if args.skip:
        modules = [m for m in modules if m not in args.skip]
    return modules


def _print_recon_summary(ws: "Workspace", target: str, modules: list[str],
                         alive_urls: list[str], start_time: float):
    """Imprime resumen final del recon y guarda summary.json."""
    separator()
    banner("RECON COMPLETO")

    file_counts = [
        ("URLs recolectadas",  "harvested_urls.txt"),
        ("URLs crawleadas",    "crawled_urls.txt"),
        ("URLs totales",       "all_urls.txt"),
        ("URLs con params",    "urls_with_params.txt"),
        ("Dirs/files (ffuf)",  "ffuf_found.txt"),
        ("Vulns (nuclei)",     "nuclei_findings.txt"),
    ]

    # Construir summary
    import json
    summary = {
        "target": target,
        "urls_input": len(alive_urls),
        "modules": modules,
        "elapsed_seconds": round(time.time() - start_time, 1),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    print()
    for label, filename in file_counts:
        count = ws.count_lines(filename)
        if count is not None:
            color = C.G if count > 0 else C.DIM
            print(f"    {label:<25} {color}{count}{C.END}")
            summary[filename.replace(".txt", "")] = count

    # Guardar summary.json
    ws.save_json("summary.json", summary)

    print(f"\n  {C.DIM}Resultados en: {ws.path}{C.END}")
    separator()
    print()


# ══════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ReconX — Automated Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"ReconX v{VERSION}")

    sub = p.add_subparsers(dest="command", help="Comandos")

    # subs
    s = sub.add_parser("subs", help="Subdominios → vivos/muertos")
    s.add_argument("-t", "--target", required=True, help="Dominio objetivo")
    s.add_argument("-w", "--wildcard", action="store_true")
    s.add_argument("--exclude", nargs="+", default=[], help="Subdominios a excluir")
    s.add_argument("--config", default="config.yaml", help="Path al config.yaml")

    # recon
    r = sub.add_parser("recon", help="Recon profundo sobre vivos")
    r_tgt = r.add_mutually_exclusive_group()
    r_tgt.add_argument("-t", "--target", help="Dominio (busca alive.txt previo)")
    r_tgt.add_argument("-sL", "--subs-list", help="Lista de URLs vivas")
    r.add_argument("--only", nargs="+", help="Solo estos módulos")
    r.add_argument("--skip", nargs="+", help="Saltear estos módulos")
    r.add_argument("--config", default="config.yaml", help="Path al config.yaml")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print(LOGO)
        parser.print_help()
        print(f"\n  {C.BOLD}Flujo:{C.END}")
        print(f"  {C.G}1.{C.END} reconx.py subs -t target.com")
        print(f"  {C.G}2.{C.END} reconx.py recon -t target.com\n")
        sys.exit(0)

    print(LOGO)

    if args.command == "subs":
        cmd_subs(args)
    elif args.command == "recon":
        cmd_recon(args)


if __name__ == "__main__":
    main()