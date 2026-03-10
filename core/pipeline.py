"""
ReconX Pipeline Engine
─────────────────────
Orquesta la ejecución de fases con lógica de decisión.
Cada paso recibe el contexto acumulado y decide qué correr.
"""

from __future__ import annotations
import time
import json
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from core.logger import get_logger
from core.workspace import Workspace

log = get_logger(__name__)


# ── Profiles ──────────────────────────────────────────────────
class Profile(str, Enum):
    """
    Define qué tan agresivo es el scan.
    Cada módulo consulta el profile para ajustar su comportamiento.
    """
    PASSIVE  = "passive"    # Solo OSINT. No envía un solo paquete al target.
    LIGHT    = "light"      # Recon básico: DNS, subs, probe HTTP. Sin fuzz.
    STANDARD = "standard"   # Recon + Enum. Nuclei solo medium+.
    FULL     = "full"       # Todo. Dirscan, params, crawl, nuclei completo.

    @property
    def phases(self) -> list[str]:
        """Qué fases se ejecutan según el profile."""
        mapping = {
            Profile.PASSIVE:  ["recon"],
            Profile.LIGHT:    ["recon"],
            Profile.STANDARD: ["recon", "enum"],
            Profile.FULL:     ["recon", "enum", "vuln"],
        }
        return mapping[self]

    @property
    def allowed_modules(self) -> dict[str, list[str]]:
        """Qué módulos se corren en cada fase según el profile."""
        return {
            Profile.PASSIVE: {
                "recon": ["subdomains", "dns", "asn", "urls"],
            },
            Profile.LIGHT: {
                "recon": ["subdomains", "dns", "asn", "ports", "http_probe",
                          "tech", "urls", "screenshots"],
            },
            Profile.STANDARD: {
                "recon": ["subdomains", "dns", "asn", "ports", "http_probe",
                          "tech", "urls", "screenshots"],
                "enum":  ["dirscan", "crawl"],
            },
            Profile.FULL: {
                "recon": ["subdomains", "dns", "asn", "ports", "http_probe",
                          "tech", "urls", "screenshots"],
                "enum":  ["dirscan", "params", "crawl"],
                "vuln":  ["nuclei_scan"],
            },
        }[self]


# ── Scope ─────────────────────────────────────────────────────
@dataclass
class Scope:
    """
    Valida que un asset esté dentro del alcance autorizado.
    NUNCA tocar algo fuera de scope — esto es ley en ethical hacking.
    """
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_ips: list[str] = field(default_factory=list)
    wildcard: bool = False  # Si True, *.domain está en scope

    def is_in_scope(self, asset: str) -> bool:
        """Verifica si un dominio/IP está dentro del scope."""
        import ipaddress

        # Check exclusiones primero (siempre ganan)
        for exc in self.exclude_domains:
            if asset == exc or asset.endswith(f".{exc}"):
                return False
        for exc in self.exclude_ips:
            try:
                if ipaddress.ip_address(asset) == ipaddress.ip_address(exc):
                    return False
            except ValueError:
                pass

        # Check dominios
        for d in self.domains:
            if asset == d:
                return True
            if self.wildcard and asset.endswith(f".{d}"):
                return True

        # Check IPs directas
        if asset in self.ips:
            return True

        # Check CIDRs
        try:
            ip = ipaddress.ip_address(asset)
            for cidr in self.cidrs:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass

        return False

    def filter_assets(self, assets: list[str]) -> tuple[list[str], list[str]]:
        """Retorna (in_scope, out_of_scope) para logging."""
        in_s, out_s = [], []
        for a in assets:
            (in_s if self.is_in_scope(a) else out_s).append(a)
        if out_s:
            log.warning(f"[SCOPE] {len(out_s)} assets fuera de scope descartados")
            for o in out_s[:5]:
                log.warning(f"  ✗ {o}")
            if len(out_s) > 5:
                log.warning(f"  ... y {len(out_s)-5} más")
        return in_s, out_s


# ── Context ───────────────────────────────────────────────────
@dataclass
class PipelineContext:
    """
    Estado acumulado del pipeline. Cada módulo lee y escribe acá.
    Esto es lo que permite tomar decisiones inteligentes entre fases.
    """
    target: str = ""
    profile: Profile = Profile.STANDARD
    scope: Scope = field(default_factory=Scope)
    workspace: Optional[Workspace] = None

    # Datos acumulados por los módulos
    subdomains: list[str] = field(default_factory=list)
    resolved_hosts: dict = field(default_factory=dict)   # domain -> [IPs]
    asn_info: dict = field(default_factory=dict)
    open_ports: dict = field(default_factory=dict)        # host -> [ports]
    live_urls: list[str] = field(default_factory=list)
    technologies: dict = field(default_factory=dict)      # url -> [techs]
    has_waf: dict = field(default_factory=dict)            # url -> waf_name|None
    collected_urls: list[str] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    dirscan_results: dict = field(default_factory=dict)
    params_found: dict = field(default_factory=dict)
    crawl_results: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)

    # Estado del pipeline
    completed_modules: list[str] = field(default_factory=list)
    skipped_modules: dict = field(default_factory=dict)   # module -> reason
    errors: list[dict] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)

    def save_state(self, path: Path):
        """Guarda estado para poder retomar."""
        import dataclasses
        state = dataclasses.asdict(self)
        state.pop("workspace", None)
        state["profile"] = self.profile.value
        state["start_time"] = self.start_time
        path.write_text(json.dumps(state, indent=2, default=str))
        log.info(f"[STATE] Estado guardado en {path}")

    @classmethod
    def load_state(cls, path: Path, workspace: Workspace) -> "PipelineContext":
        """Carga estado previo para retomar un scan."""
        data = json.loads(path.read_text())
        data["profile"] = Profile(data["profile"])
        data["scope"] = Scope(**data.get("scope", {}))
        data["workspace"] = workspace
        return cls(**data)

    @property
    def hosts_with_web(self) -> list[str]:
        """Hosts que tienen puertos web abiertos (80, 443, 8080, 8443, etc.)."""
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}
        return [
            h for h, ports in self.open_ports.items()
            if any(p in web_ports for p in ports)
        ]

    @property
    def hosts_without_waf(self) -> list[str]:
        """URLs live que NO tienen WAF detectado."""
        return [u for u in self.live_urls if not self.has_waf.get(u)]

    @property
    def high_value_targets(self) -> list[str]:
        """
        URLs que merecen atención extra:
        - Tienen tech interesante (admin panels, CMS, frameworks)
        - Retornan 401/403 (posible bypass)
        - Tienen muchos parámetros
        """
        interesting_tech = {"wordpress", "joomla", "drupal", "phpmyadmin",
                           "tomcat", "jenkins", "grafana", "kibana", "elastic",
                           "spring", "django", "laravel", "aspnet"}
        hvt = set()
        for url, techs in self.technologies.items():
            if any(t.lower() in interesting_tech for t in techs):
                hvt.add(url)
        return list(hvt)


# ── Pipeline Engine ───────────────────────────────────────────

# Orden de ejecución y dependencias
MODULE_ORDER = {
    "recon": [
        ("subdomains",  []),
        ("dns",         ["subdomains"]),
        ("asn",         []),
        ("ports",       ["dns"]),
        ("http_probe",  ["ports"]),
        ("tech",        ["http_probe"]),
        ("urls",        ["subdomains"]),
        ("screenshots", ["http_probe"]),
    ],
    "enum": [
        ("dirscan",     ["http_probe"]),
        ("params",      ["http_probe", "urls"]),
        ("crawl",       ["http_probe"]),
    ],
    "vuln": [
        ("nuclei_scan", ["http_probe"]),
    ],
}


class Pipeline:
    """
    Ejecuta módulos en orden respetando:
    1. El profile seleccionado
    2. Las dependencias entre módulos
    3. Decisiones inteligentes basadas en el contexto
    """

    def __init__(self, ctx: PipelineContext):
        self.ctx = ctx
        self._module_registry: dict = {}

    def register_module(self, name: str, module):
        """Registra un módulo ejecutable."""
        self._module_registry[name] = module

    def _should_skip(self, module_name: str) -> Optional[str]:
        """
        Lógica de decisión: ¿hay razón para saltear este módulo?
        Retorna None si debe correr, o un string con la razón del skip.
        """
        ctx = self.ctx

        # Ya se completó (resume)
        if module_name in ctx.completed_modules:
            return "ya completado en run anterior"

        # Screenshots sin URLs live
        if module_name == "screenshots" and not ctx.live_urls:
            return "no hay URLs live para screenshootear"

        # Dirscan: no correr si no hay hosts web
        if module_name == "dirscan" and not ctx.live_urls:
            return "no hay URLs live para fuzzear"

        # Params: solo si hay URLs con parámetros potenciales
        if module_name == "params" and not ctx.live_urls:
            return "no hay URLs live para descubrir params"

        # Crawl: no tiene sentido sin hosts live
        if module_name == "crawl" and not ctx.live_urls:
            return "no hay URLs live para crawlear"

        # Nuclei: skip si no hay nada que escanear
        if module_name == "nuclei_scan" and not ctx.live_urls:
            return "no hay URLs live para escanear vulns"

        # Ports: si profile es passive, no escanear puertos
        if module_name == "ports" and ctx.profile == Profile.PASSIVE:
            return "profile passive — no se escanean puertos"

        return None

    def run(self):
        """Ejecuta el pipeline completo."""
        log.info(f"{'='*60}")
        log.info(f"ReconX Pipeline — Target: {self.ctx.target}")
        log.info(f"Profile: {self.ctx.profile.value}")
        log.info(f"{'='*60}")

        allowed = self.ctx.profile.allowed_modules
        state_path = None
        if self.ctx.workspace:
            state_path = self.ctx.workspace.path / "pipeline_state.json"

        for phase in self.ctx.profile.phases:
            log.info(f"\n▶ PHASE: {phase.upper()}")
            modules = MODULE_ORDER.get(phase, [])

            for mod_name, deps in modules:
                # ¿Está permitido por el profile?
                if mod_name not in allowed.get(phase, []):
                    continue

                # ¿Dependencias cumplidas?
                missing = [d for d in deps if d not in self.ctx.completed_modules]
                if missing:
                    reason = f"dependencias no cumplidas: {missing}"
                    self.ctx.skipped_modules[mod_name] = reason
                    log.warning(f"  ⏭ {mod_name}: {reason}")
                    continue

                # ¿Lógica de decisión dice skip?
                skip_reason = self._should_skip(mod_name)
                if skip_reason:
                    self.ctx.skipped_modules[mod_name] = skip_reason
                    log.info(f"  ⏭ {mod_name}: {skip_reason}")
                    continue

                # Ejecutar
                if mod_name not in self._module_registry:
                    log.error(f"  ✗ {mod_name}: módulo no registrado")
                    continue

                log.info(f"  ▸ {mod_name}...")
                t0 = time.time()
                try:
                    self._module_registry[mod_name].run(self.ctx)
                    elapsed = time.time() - t0
                    self.ctx.completed_modules.append(mod_name)
                    log.info(f"  ✓ {mod_name} ({elapsed:.1f}s)")
                except Exception as e:
                    elapsed = time.time() - t0
                    self.ctx.errors.append({
                        "module": mod_name,
                        "error": str(e),
                        "elapsed": elapsed,
                    })
                    log.error(f"  ✗ {mod_name} falló ({elapsed:.1f}s): {e}")

                # Guardar estado después de cada módulo (para resume)
                if state_path:
                    self.ctx.save_state(state_path)

                # Pausa entre módulos (evita picos de tráfico)
                time.sleep(self.ctx.workspace.config.get(
                    "rate", {}).get("delay_between_modules", 1)
                    if self.ctx.workspace else 1
                )

        total = time.time() - self.ctx.start_time
        log.info(f"\n{'='*60}")
        log.info(f"Pipeline completado en {total:.0f}s")
        log.info(f"Módulos OK: {len(self.ctx.completed_modules)}")
        log.info(f"Módulos skip: {len(self.ctx.skipped_modules)}")
        log.info(f"Errores: {len(self.ctx.errors)}")
        log.info(f"{'='*60}")