#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
# ReconX — Instalador
# Instala todas las dependencias: Go tools, Python deps, wordlists
#
# Uso:
#   chmod +x install.sh
#   ./install.sh              Instalar todo
#   ./install.sh --tools      Solo tools de Go
#   ./install.sh --python     Solo dependencias Python
#   ./install.sh --wordlists  Solo wordlists
#   ./install.sh --check      Verificar qué está instalado
# ══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
END='\033[0m'

info()  { echo -e "  ${BLUE}[*]${END} $1"; }
good()  { echo -e "  ${GREEN}[✓]${END} $1"; }
warn()  { echo -e "  ${YELLOW}[!]${END} $1"; }
fail()  { echo -e "  ${RED}[✗]${END} $1"; }
head()  { echo -e "\n  ${BOLD}${CYAN}$1${END}"; }
line()  { echo -e "  ${DIM}────────────────────────────────────────────────${END}"; }

BANNER=$(cat << 'EOF'

  ╦═╗╔═╗╔═╗╔═╗╔╗╔═╗ ╦
  ╠╦╝║╣ ║  ║ ║║║║╔╩╦╝
  ╩╚═╚═╝╚═╝╚═╝╝╚╝ ╩   Installer

EOF
)

# ── Detección de OS ───────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    elif [[ "$(uname)" == "Darwin" ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    ARCH=$(uname -m)
    echo "$OS"
}

# ── Verificar requisitos base ─────────────────────────────────
check_base_deps() {
    head "REQUISITOS BASE"

    local missing=()

    # Go (necesario para casi todas las tools)
    if command -v go &>/dev/null; then
        local go_ver=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        good "Go ${go_ver}"
    else
        missing+=("go")
        fail "Go no instalado"
    fi

    # Python 3.8+
    if command -v python3 &>/dev/null; then
        local py_ver=$(python3 --version | cut -d' ' -f2)
        good "Python ${py_ver}"
    else
        missing+=("python3")
        fail "Python3 no instalado"
    fi

    # pip
    if command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null 2>&1; then
        good "pip3"
    else
        missing+=("pip3")
        fail "pip3 no instalado"
    fi

    # git
    if command -v git &>/dev/null; then
        good "git"
    else
        missing+=("git")
        fail "git no instalado"
    fi

    # Chrome/Chromium (para katana headless + gowitness)
    if command -v google-chrome &>/dev/null || command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null; then
        good "Chrome/Chromium (para katana headless)"
    else
        warn "Chrome/Chromium no encontrado — katana headless no va a funcionar"
        warn "Instalá con: apt install chromium-browser  (o desde google.com/chrome)"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        fail "Dependencias faltantes: ${missing[*]}"
        echo ""
        info "Instalá primero:"

        local os=$(detect_os)
        case $os in
            ubuntu|debian|kali)
                info "  sudo apt update && sudo apt install -y golang python3 python3-pip git"
                ;;
            fedora|centos|rhel)
                info "  sudo dnf install -y golang python3 python3-pip git"
                ;;
            arch|manjaro)
                info "  sudo pacman -S go python python-pip git"
                ;;
            macos)
                info "  brew install go python git"
                ;;
            *)
                info "  Instalá go, python3, pip3 y git manualmente"
                ;;
        esac
        echo ""
        exit 1
    fi

    line
}


# ══════════════════════════════════════════════════════════════
# GO TOOLS
# ══════════════════════════════════════════════════════════════

# Formato: "nombre|repo@version"
# Usamos latest si no hay versión específica requerida
GO_TOOLS=(
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
    "asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "ffuf|github.com/ffuf/ffuf/v2@latest"
    "gau|github.com/lc/gau/v2/cmd/gau@latest"
    "waybackurls|github.com/tomnomnom/waybackurls@latest"
    "gowitness|github.com/sensepost/gowitness@latest"
)

install_go_tools() {
    head "GO TOOLS"

    # Asegurar que GOPATH/bin está en PATH
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$GOPATH/bin:$PATH"

    local installed=0
    local failed=0
    local skipped=0
    local count=0

    for entry in "${GO_TOOLS[@]}"; do
        local name="${entry%%|*}"
        local repo="${entry##*|}"

        if command -v "$name" &>/dev/null; then
            good "${name} (ya instalado)"
            skipped=$((skipped + 1))
            continue
        fi

        info "Instalando ${name}..."
        if go install -v "$repo" 2>/dev/null; then
            if command -v "$name" &>/dev/null || [[ -f "$GOPATH/bin/$name" ]]; then
                good "${name}"
                installed=$((installed + 1))
            else
                fail "${name} — se compiló pero no se encuentra en PATH"
                failed=$((failed + 1))
            fi
        else
            fail "${name} — error de compilación"
            failed=$((failed + 1))
        fi
    done

    echo ""
    info "Instalados: ${installed} | Ya existían: ${skipped} | Fallaron: ${failed}"

    # Arjun es Python, no Go
    line
    head "PYTHON TOOLS (arjun)"

    if command -v arjun &>/dev/null; then
        good "arjun (ya instalado)"
    else
        info "Instalando arjun..."
        if pip3 install arjun --break-system-packages 2>/dev/null || pip3 install arjun 2>/dev/null; then
            good "arjun"
        else
            fail "arjun — probá: pip3 install arjun"
        fi
    fi

    line
}


# ══════════════════════════════════════════════════════════════
# PYTHON DEPS (para ReconX mismo)
# ══════════════════════════════════════════════════════════════

install_python_deps() {
    head "DEPENDENCIAS PYTHON (ReconX)"

    if [[ -f requirements.txt ]]; then
        info "Instalando desde requirements.txt..."
        if pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null; then
            good "Dependencias Python instaladas"
        else
            fail "Error instalando dependencias Python"
            warn "Probá con: pip3 install -r requirements.txt"
        fi
    else
        # Instalar mínimo necesario
        info "requirements.txt no encontrado, instalando mínimo..."
        local deps="pyyaml"
        if pip3 install $deps --break-system-packages 2>/dev/null || pip3 install $deps 2>/dev/null; then
            good "PyYAML instalado"
        else
            fail "Error instalando PyYAML"
        fi
    fi

    line
}


# ══════════════════════════════════════════════════════════════
# WORDLISTS
# ══════════════════════════════════════════════════════════════

install_wordlists() {
    head "WORDLISTS"

    local seclists_dir="/usr/share/seclists"
    local wordlists_dir="/usr/share/wordlists"

    # SecLists
    if [[ -d "$seclists_dir" ]]; then
        good "SecLists ya instalado en ${seclists_dir}"
    else
        info "Instalando SecLists..."
        info "Esto puede tardar (es ~800MB)..."

        local os=$(detect_os)
        case $os in
            ubuntu|debian|kali)
                if sudo apt install -y seclists 2>/dev/null; then
                    good "SecLists (apt)"
                else
                    warn "apt falló, clonando desde GitHub..."
                    _clone_seclists "$seclists_dir"
                fi
                ;;
            arch|manjaro)
                if sudo pacman -S --noconfirm seclists 2>/dev/null; then
                    good "SecLists (pacman)"
                else
                    _clone_seclists "$seclists_dir"
                fi
                ;;
            *)
                _clone_seclists "$seclists_dir"
                ;;
        esac
    fi

    # Verificar que la wordlist que usa ffuf existe
    local ffuf_wl="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    if [[ -f "$ffuf_wl" ]]; then
        good "Wordlist ffuf: raft-medium-directories.txt"
    else
        warn "Wordlist ffuf no encontrada en: ${ffuf_wl}"
        warn "ffuf va a usar el fallback (dirb/common.txt)"

        # Asegurar que al menos dirb está
        if [[ ! -f "/usr/share/wordlists/dirb/common.txt" ]]; then
            local os=$(detect_os)
            if [[ "$os" == "ubuntu" || "$os" == "debian" || "$os" == "kali" ]]; then
                info "Instalando dirb wordlists..."
                sudo apt install -y dirb 2>/dev/null && good "dirb wordlists" || warn "No se pudo instalar dirb"
            fi
        fi
    fi

    line
}

_clone_seclists() {
    local target="$1"
    if sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$target" 2>/dev/null; then
        good "SecLists (git clone)"
    else
        fail "No se pudo instalar SecLists"
        warn "Instalá manualmente: git clone https://github.com/danielmiessler/SecLists.git ${target}"
    fi
}


# ══════════════════════════════════════════════════════════════
# NUCLEI TEMPLATES
# ══════════════════════════════════════════════════════════════

update_nuclei_templates() {
    head "NUCLEI TEMPLATES"

    if command -v nuclei &>/dev/null; then
        info "Actualizando templates..."
        if nuclei -ut 2>/dev/null; then
            good "Templates actualizados"
        else
            warn "No se pudieron actualizar (puede necesitar internet)"
        fi
    else
        warn "nuclei no instalado — saltando templates"
    fi

    line
}


# ══════════════════════════════════════════════════════════════
# POST-INSTALL: PATH + permisos
# ══════════════════════════════════════════════════════════════

post_install() {
    head "POST-INSTALACIÓN"

    # Verificar GOPATH en PATH
    local gobin="${GOPATH:-$HOME/go}/bin"
    if [[ ":$PATH:" != *":$gobin:"* ]]; then
        warn "GOPATH/bin no está en PATH"
        info "Agregá esto a tu ~/.bashrc o ~/.zshrc:"
        echo ""
        echo "    export PATH=\"\$HOME/go/bin:\$PATH\""
        echo ""

        # Intentar agregar automáticamente
        local shell_rc=""
        if [[ -f "$HOME/.zshrc" ]]; then
            shell_rc="$HOME/.zshrc"
        elif [[ -f "$HOME/.bashrc" ]]; then
            shell_rc="$HOME/.bashrc"
        fi

        if [[ -n "$shell_rc" ]]; then
            if ! grep -q 'go/bin' "$shell_rc" 2>/dev/null; then
                echo 'export PATH="$HOME/go/bin:$PATH"' >> "$shell_rc"
                good "Agregado a ${shell_rc} (recargá con: source ${shell_rc})"
            fi
        fi
    else
        good "GOPATH/bin en PATH"
    fi

    # Hacer reconx.py ejecutable
    if [[ -f "reconx.py" ]]; then
        chmod +x reconx.py
        good "reconx.py marcado como ejecutable"
    fi

    line
}


# ══════════════════════════════════════════════════════════════
# CHECK: Verificar estado de todo
# ══════════════════════════════════════════════════════════════

check_all() {
    head "VERIFICACIÓN DE HERRAMIENTAS"
    line

    local total=0
    local ok=0
    local missing=0

    # Go tools + arjun
    local tools=("subfinder" "dnsx" "httpx" "naabu" "nuclei" "katana"
                 "asnmap" "ffuf" "gau" "waybackurls" "gowitness" "arjun")

    for tool in "${tools[@]}"; do
        total=$((total + 1))
        if command -v "$tool" &>/dev/null; then
            local version=""
            version=$($tool -version 2>/dev/null | head -1 || echo "")
            if [[ -z "$version" ]]; then
                version=$($tool --version 2>/dev/null | head -1 || echo "installed")
            fi
            good "${tool} ${DIM}${version}${END}"
            ok=$((ok + 1))
        else
            fail "${tool}"
            missing=$((missing + 1))
        fi
    done

    line

    # Wordlists
    head "WORDLISTS"
    local wl_files=(
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        "/usr/share/wordlists/dirb/common.txt"
    )
    for wl in "${wl_files[@]}"; do
        if [[ -f "$wl" ]]; then
            local count=$(wc -l < "$wl")
            good "${wl##*/} ${DIM}(${count} líneas)${END}"
        else
            fail "${wl##*/}"
        fi
    done

    line

    # Chrome
    head "BROWSER (headless)"
    if command -v google-chrome &>/dev/null; then
        good "Google Chrome"
    elif command -v chromium-browser &>/dev/null; then
        good "Chromium"
    elif command -v chromium &>/dev/null; then
        good "Chromium"
    else
        fail "Chrome/Chromium no encontrado"
    fi

    line

    # Python deps
    head "PYTHON"
    if python3 -c "import yaml" 2>/dev/null; then
        good "PyYAML"
    else
        fail "PyYAML"
    fi

    # Resumen
    line
    echo ""
    if [[ $missing -eq 0 ]]; then
        good "${BOLD}Todo listo! ${ok}/${total} herramientas instaladas${END}"
        echo ""
        info "Empezá con:"
        echo -e "    ${GREEN}./reconx.py subs -t target.com${END}"
    else
        warn "${ok}/${total} herramientas instaladas, ${RED}${missing} faltantes${END}"
        echo ""
        info "Instalá lo faltante con:"
        echo -e "    ${GREEN}./install.sh --tools${END}"
    fi
    echo ""
}


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

main() {
    echo "$BANNER"

    local mode="${1:-all}"

    case "$mode" in
        --tools|-t)
            check_base_deps
            install_go_tools
            post_install
            ;;
        --python|-p)
            install_python_deps
            ;;
        --wordlists|-w)
            install_wordlists
            ;;
        --check|-c)
            check_all
            ;;
        --help|-h)
            echo "  Uso: ./install.sh [opción]"
            echo ""
            echo "  Opciones:"
            echo "    (sin args)     Instalar todo"
            echo "    --tools   -t   Solo tools (Go + arjun)"
            echo "    --python  -p   Solo dependencias Python"
            echo "    --wordlists -w Solo wordlists (SecLists)"
            echo "    --check   -c   Verificar qué está instalado"
            echo "    --help    -h   Esta ayuda"
            echo ""
            ;;
        all|"")
            check_base_deps
            install_go_tools
            install_python_deps
            install_wordlists
            update_nuclei_templates
            post_install
            echo ""
            good "${BOLD}Instalación completa!${END}"
            echo ""
            info "Verificá con:  ./install.sh --check"
            info "Empezá con:    ./reconx.py subs -t target.com"
            echo ""
            ;;
        *)
            fail "Opción desconocida: $mode"
            info "Usá: ./install.sh --help"
            exit 1
            ;;
    esac
}

main "$@"