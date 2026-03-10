# ReconX

Framework de reconocimiento automatizado para ethical hacking. Dos comandos, un flujo claro: primero mapeás la superficie, después atacás lo que está vivo.

```
reconx.py subs  →  Subdominios → DNS → HTTP probe → alive.txt / dead.txt
reconx.py recon →  URLs pasivas → Crawl → Fuzz dirs → Params → Vulns
```

---

## Instalación

```bash
git clone https://github.com/tu-user/reconx.git
cd reconx
chmod +x install.sh reconx.py

# Instalar todo (Go tools + Python deps + wordlists)
./install.sh

# Solo verificar qué tenés instalado
./install.sh --check

# Instalar por partes
./install.sh --tools        # Solo herramientas
./install.sh --python       # Solo dependencias Python
./install.sh --wordlists    # Solo SecLists
```

### Requisitos

- Go 1.21+
- Python 3.8+
- Git
- Chrome/Chromium (para katana headless)

---

## Flujo de uso

### Paso 1 — Enumerar subdominios

```bash
./reconx.py subs -t target.com
```

Esto corre `subfinder` + `crt.sh` + `urlscan.io` → `dnsx` → `httpx` y genera:

```
output/target_com/subs/
├── all_subdomains.txt      # Todo lo encontrado (todas las fuentes)
├── src_subfinder.txt       # Subdominios de subfinder
├── src_crtsh.txt           # Subdominios de crt.sh
├── src_urlscan.txt         # Subdominios de urlscan.io
├── resolved.txt            # Los que resuelven DNS
├── alive.txt               # TODOS los que responden HTTP ← INPUT PARA RECON
├── alive_200.txt           # OK (200, 201, 204) — funcionando normal
├── alive_redirect.txt      # Redirects (301, 302, 307) — ¿a dónde van?
├── alive_forbidden.txt     # Denegados (401, 403) — candidatos a bypass
├── alive_error.txt         # Errores de servidor (500, 502, 503)
├── redirect_details.txt    # Detalle: URL → destino del redirect
├── dead.txt                # Resuelven DNS pero no responden HTTP
├── no_resolve.txt          # No resuelven DNS
├── httpx_results.json      # Data completa (tech, status, server, etc)
└── scope.json              # Scope usado (wildcard, exclusiones)
```

### Paso 2 — Recon profundo

```bash
./reconx.py recon -t target.com
```

Toma `alive.txt` del paso anterior y corre `gau` + `waybackurls` → `katana` → `ffuf` → `arjun` → `nuclei`:

```
output/target_com/recon/
├── input_urls.txt          # URLs que se analizaron
├── harvested_urls.txt      # URLs pasivas (gau + waybackurls)
├── urls_with_params.txt    # URLs con parámetros (interesantes)
├── unique_paths.txt        # Paths únicos (wordlist custom)
├── crawled_urls.txt        # URLs descubiertas por katana
├── all_urls.txt            # Merge de todas las URLs
├── ffuf_found.txt          # Dirs/files encontrados
├── ffuf/                   # Resultados por target
│   ├── https_admin_target_com.json
│   └── https_api_target_com.json
├── arjun/                  # Params descubiertos por target
│   └── https_target_com.json
├── nuclei_findings.txt     # Vulnerabilidades encontradas
├── nuclei_results.json     # Detalle completo de vulns
└── summary.json            # Resumen del scan
```

---

## Comandos

### `subs` — Subdomain Enumeration

```bash
# Scan básico
./reconx.py subs -t target.com

# Con wildcard (incluye *.target.com en scope)
./reconx.py subs -t target.com -w

# Excluir subdominios específicos
./reconx.py subs -t target.com --exclude cdn.target.com staging.target.com

# Excluir + wildcard
./reconx.py subs -t target.com -w --exclude internal.target.com
```

| Flag | Descripción |
|------|-------------|
| `-t, --target` | Dominio objetivo (obligatorio) |
| `-w, --wildcard` | Incluir `*.domain` en scope (enumeración más agresiva) |
| `--exclude` | Subdominios a excluir (acepta varios) |
| `--config` | Path al `config.yaml` (default: `config.yaml`) |

---

### `recon` — Web Reconnaissance

```bash
# Recon completo (toma alive.txt del paso anterior)
./reconx.py recon -t target.com

# Desde una lista custom de URLs
./reconx.py recon -sL mis_urls.txt

# Solo módulos específicos
./reconx.py recon -t target.com --only urls katana
./reconx.py recon -t target.com --only ffuf
./reconx.py recon -t target.com --only nuclei

# Todo MENOS nuclei (quiero revisar antes)
./reconx.py recon -t target.com --skip nuclei

# Solo harvesting pasivo (no toca el target)
./reconx.py recon -t target.com --only urls

# Combinar: solo crawl + fuzz
./reconx.py recon -t target.com --only katana ffuf
```

| Flag | Descripción |
|------|-------------|
| `-t, --target` | Dominio (busca `alive.txt` previo) |
| `-sL, --subs-list` | Lista custom de URLs vivas |
| `--only` | Correr SOLO estos módulos |
| `--skip` | Saltear estos módulos |
| `--config` | Path al `config.yaml` |

#### Módulos disponibles para `--only` / `--skip`

| Módulo | Herramienta | Tipo | Qué hace |
|--------|-------------|------|----------|
| `urls` | gau + waybackurls | Pasivo | Recolecta URLs históricas |
| `katana` | katana | Activo | Crawl web + JS rendering |
| `ffuf` | ffuf | Activo | Fuzz de directorios/archivos |
| `arjun` | arjun | Activo | Descubre parámetros ocultos |
| `nuclei` | nuclei | Activo | Escaneo de vulnerabilidades |

---

## Ejemplos reales

### Bug Bounty — Target con wildcard

```bash
# 1. Encontrar todos los subdominios
./reconx.py subs -t example.com -w

# 2. Revisar qué encontró
cat output/example_com/subs/alive.txt

# 3. Recon pasivo primero (no querés triggerear WAF)
./reconx.py recon -t example.com --only urls

# 4. Revisar URLs interesantes
cat output/example_com/recon/urls_with_params.txt

# 5. Ahora sí, crawl + nuclei
./reconx.py recon -t example.com --only katana nuclei
```

### Pentest — Dominio único

```bash
# 1. Subdominios
./reconx.py subs -t empresa.com --exclude mail.empresa.com vpn.empresa.com

# 2. Recon completo
./reconx.py recon -t empresa.com

# 3. Revisar vulnerabilidades
cat output/empresa_com/recon/nuclei_findings.txt
```

### Recon rápido — Solo quiero saber qué hay

```bash
# Solo subdominios + qué tecnologías usan
./reconx.py subs -t target.com

# Ver tecnologías detectadas
cat output/target_com/subs/httpx_results.json | python3 -m json.tool | grep -A2 '"tech"'
```

### Lista custom — Ya tengo mis URLs

```bash
# Tengo una lista de URLs de otra herramienta
echo "https://admin.target.com" > mis_urls.txt
echo "https://api.target.com" >> mis_urls.txt
echo "https://dev.target.com" >> mis_urls.txt

# Recon directo sobre esas URLs
./reconx.py recon -sL mis_urls.txt

# Solo fuzz de directorios en esas URLs
./reconx.py recon -sL mis_urls.txt --only ffuf
```

### Solo nuclei — Ya tengo todo mapeado

```bash
# Correr nuclei sobre los vivos
./reconx.py recon -t target.com --only nuclei

# O sobre una lista específica
./reconx.py recon -sL urls_interesantes.txt --only nuclei
```

---

## Configuración

Todo se controla desde `config.yaml`. Los valores más importantes:

### Fuentes de subdominios

```yaml
# Desactivar fuentes pasivas si no querés usarlas
subdomains:
  use_crtsh: true        # Certificate Transparency (crt.sh)
  use_urlscan: true      # urlscan.io API pública
  crtsh_timeout: 30      # Timeout para crt.sh
  urlscan_timeout: 30    # Timeout para urlscan.io
```

### Ajustar velocidad

```yaml
# Red lenta o target sensible
rate:
  max_rps: 50

# Reducir threads de httpx
http_probe:
  threads: 20

# Reducir rate de nuclei (evitar WAF)
nuclei:
  rate_limit: 50
```

### Limitar targets en módulos pesados

```yaml
# ffuf en máximo 10 URLs (default: 15)
dirscan:
  max_targets: 10

# arjun en máximo 3 URLs (default: 5)
params:
  max_targets: 3

# katana en máximo 5 URLs (default: 10)
crawl:
  max_targets: 5
```

### Cambiar wordlist de ffuf

```yaml
dirscan:
  wordlist: /ruta/a/mi/wordlist.txt
  wordlist_fallback: /ruta/alternativa.txt
```

### Cambiar severidades de nuclei

```yaml
# Solo critical y high
nuclei:
  severity:
    - critical
    - high
```

### Cambiar templates de nuclei

```yaml
nuclei:
  templates:
    - cves
    - exposures
    - misconfigurations
    - default-logins
```

---

## Estructura del proyecto

```
reconx/
├── reconx.py                  # CLI + orquestador (flaco)
├── config.yaml                # Todas las variables
├── install.sh                 # Instalador
├── requirements.txt           # Deps Python
│
├── core/
│   ├── config.py              # Carga config.yaml
│   ├── utils.py               # Colors, I/O helpers
│   ├── runner.py              # Ejecuta comandos externos
│   └── workspace.py           # Manejo de carpetas output
│
├── phases/
│   ├── recon/                 # Fase 1: mapear superficie
│   │   ├── subdomains.py      # subfinder
│   │   ├── dns.py             # dnsx
│   │   └── http_probe.py      # httpx (vivos/muertos + tech)
│   │
│   ├── enum/                  # Fase 2: enumerar lo vivo
│   │   ├── urls.py            # gau + waybackurls (pasivo)
│   │   ├── crawl.py           # katana (activo)
│   │   ├── dirscan.py         # ffuf (dirs/files)
│   │   └── params.py          # arjun (params ocultos)
│   │
│   └── vuln/                  # Fase 3: vulnerabilidades
│       └── nuclei_scan.py     # nuclei
│
└── output/                    # Resultados (se genera automáticamente)
    └── target_com/
        ├── subs/              # Output de reconx.py subs
        └── recon/             # Output de reconx.py recon
```

---

## Tips

- **Siempre corré `subs` antes de `recon`.** El comando `recon` busca el `alive.txt` generado por `subs`. Si querés saltear este paso, usá `-sL` con tu propia lista.

- **Empezá pasivo, después activo.** Usá `--only urls` primero para recolectar URLs sin tocar el target. Después agregá los módulos activos.

- **Revisá antes de correr nuclei.** Usá `--skip nuclei` en el primer run, revisá qué encontró ffuf/katana, y después corré `--only nuclei` cuando estés listo.

- **Ajustá `max_targets` en el config.** Si tenés 200 subdominios vivos, no querés que ffuf corra en los 200. El default de 15 es razonable, bajalo si querés ir más rápido.

- **Revisá `httpx_results.json`.** Tiene toda la data: tecnologías, status codes, headers, TLS info. Es oro para planificar el ataque.

---

## Herramientas utilizadas

| Herramienta | Función | Repo |
|-------------|---------|------|
| subfinder | Subdomain discovery | github.com/projectdiscovery/subfinder |
| dnsx | DNS resolution | github.com/projectdiscovery/dnsx |
| httpx | HTTP probe + tech detect | github.com/projectdiscovery/httpx |
| gau | URL harvesting (AlienVault, Wayback, Common Crawl) | github.com/lc/gau |
| waybackurls | URL harvesting (Wayback Machine) | github.com/tomnomnom/waybackurls |
| katana | Web crawler + JS rendering | github.com/projectdiscovery/katana |
| ffuf | Directory/file fuzzing | github.com/ffuf/ffuf |
| arjun | Parameter discovery | github.com/s0md3v/Arjun |
| nuclei | Vulnerability scanning | github.com/projectdiscovery/nuclei |