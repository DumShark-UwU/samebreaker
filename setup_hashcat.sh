#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  SameBreaker — Installation hashcat (Debian 13 Trixie)
#  Usage : sudo bash setup_hashcat.sh [options]
#
#  Options :
#    --force-cpu      Installe uniquement pocl (OpenCL CPU, ignore GPU)
#    --force-nvidia   Force le mode NVIDIA (si la détection auto échoue)
#    --no-wordlists   Skip le téléchargement des wordlists
#
#  Ce script installe :
#    • hashcat + hashcat-utils (compilé depuis les sources)
#    • Drivers GPU adaptés au matériel détecté (NVIDIA CUDA / AMD OpenCL / pocl)
#    • name-that-hash (requis par SameBreaker)
#    • Wordlists dans WORDLIST_DIR (rockyou + règles hashcat)
#
#  Chemins reconnus par SameBreaker :
#    Wordlists  → WORDLIST_DIR  (et /usr/share/wordlists)
#    Règles     → HASHCAT_RULES
#    Hashcat    → détecté auto via PATH (/usr/bin/hashcat)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'; BLD='\033[1m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[  OK]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
step()  { echo -e "\n${BLD}${CYN}━━ $* ${NC}"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Configuration (modifiables) ───────────────────────────────────────────────
# Toutes ces valeurs peuvent être surchargées par les args CLI ci-dessous.

WORDLIST_DIR="/opt/wordlists"            # Répertoire d'installation des wordlists
HASHCAT_RULES="/usr/share/hashcat/rules" # Répertoire des règles hashcat
HASHCAT_UTILS_DEST="/usr/local/bin"      # Destination des binaires hashcat-utils

# ── Args ──────────────────────────────────────────────────────────────────────
FORCE_CPU=0
FORCE_NVIDIA=0
SKIP_WORDLISTS=0

for arg in "$@"; do
    case "$arg" in
        --force-cpu)    FORCE_CPU=1 ;;
        --force-nvidia) FORCE_NVIDIA=1 ;;
        --no-wordlists) SKIP_WORDLISTS=1 ;;
        --wordlist-dir=*) WORDLIST_DIR="${arg#*=}" ;;
        --help|-h)
            echo "Usage: sudo bash $0 [options]"
            echo ""
            echo "Options GPU :"
            echo "  --force-cpu           Installe uniquement pocl (OpenCL CPU)"
            echo "  --force-nvidia        Force le mode NVIDIA (si détection auto échoue)"
            echo ""
            echo "Options installation :"
            echo "  --no-wordlists        Skip le téléchargement des wordlists"
            echo "  --wordlist-dir=PATH   Répertoire wordlists (défaut: $WORDLIST_DIR)"
            echo ""
            echo "Variables configurables (éditer le script) :"
            echo "  WORDLIST_DIR         = $WORDLIST_DIR"
            echo "  HASHCAT_RULES        = $HASHCAT_RULES"
            echo "  HASHCAT_UTILS_DEST   = $HASHCAT_UTILS_DEST"
            exit 0 ;;
    esac
done

# ── Prérequis ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Ce script doit être lancé en root : sudo bash $0"

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID" != "debian" ]]; then
        warn "Distribution : $ID (optimisé pour Debian 13)"
    else
        info "OS : ${PRETTY_NAME:-$ID $VERSION_ID}"
        [[ "${VERSION_ID:-0}" -lt 13 ]] && warn "Debian < 13 — le script devrait fonctionner mais n'est pas garanti"
    fi
fi

echo ""
echo -e "${BLD}${CYN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${CYN}║      SameBreaker — Installation hashcat              ║${NC}"
echo -e "${BLD}${CYN}║      Debian 13 Trixie                                ║${NC}"
echo -e "${BLD}${CYN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
info "Wordlists      : $WORDLIST_DIR"
info "Règles hashcat : $HASHCAT_RULES"
info "hashcat-utils  : $HASHCAT_UTILS_DEST"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
step "1 / 6 — Mise à jour APT + outils de base"
# ─────────────────────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y --no-install-recommends \
    wget curl ca-certificates pciutils clinfo \
    build-essential pkg-config git
ok "Outils de base installés"

# ─────────────────────────────────────────────────────────────────────────────
step "2 / 6 — Détection GPU"
# ─────────────────────────────────────────────────────────────────────────────
GPU_TYPE="cpu"

if [[ $FORCE_CPU -eq 1 ]]; then
    warn "Mode --force-cpu : OpenCL CPU uniquement"
elif [[ $FORCE_NVIDIA -eq 1 ]]; then
    GPU_TYPE="nvidia"
    warn "Mode --force-nvidia activé manuellement"
else
    # Méthode 1 : /sys/bus/pci (NVIDIA=0x10de, AMD=0x1002)
    # { grep || true } évite l'exit de set -euo pipefail quand grep ne trouve rien
    _nvidia_count=$( { grep -rl "0x10de" /sys/bus/pci/devices/*/vendor 2>/dev/null || true; } | wc -l )
    _amd_count=$( {    grep -rl "0x1002" /sys/bus/pci/devices/*/vendor 2>/dev/null || true; } | wc -l )

    if [[ $_nvidia_count -gt 0 ]]; then
        GPU_TYPE="nvidia"
        ok "GPU NVIDIA détecté via /sys ($_nvidia_count device(s) PCI 0x10de)"

    elif [[ $_amd_count -gt 0 ]]; then
        GPU_TYPE="amd"
        ok "GPU AMD détecté via /sys ($_amd_count device(s) PCI 0x1002)"

    # Méthode 2 : nvidia-smi / module kernel / /dev
    elif command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
        GPU_TYPE="nvidia"
        ok "GPU NVIDIA détecté via nvidia-smi"
    elif lsmod 2>/dev/null | grep -q "^nvidia"; then
        GPU_TYPE="nvidia"
        ok "GPU NVIDIA détecté via module kernel"
    elif lsmod 2>/dev/null | grep -qE "^(amdgpu|radeon)"; then
        GPU_TYPE="amd"
        ok "GPU AMD détecté via module kernel"
    elif ls /dev/nvidia* &>/dev/null 2>&1; then
        GPU_TYPE="nvidia"
        ok "GPU NVIDIA détecté via /dev/nvidia*"
    else
        warn "Pas de GPU dédié détecté — hashcat tournera sur CPU (lent)"
        warn "GPU NVIDIA présent ? Relancez : sudo bash $0 --force-nvidia"
    fi
fi

info "Type GPU sélectionné : $GPU_TYPE"

# ─────────────────────────────────────────────────────────────────────────────
step "3 / 6 — hashcat + OpenCL"
# ─────────────────────────────────────────────────────────────────────────────
info "Installation de hashcat..."
apt-get install -y --no-install-recommends hashcat

# hashcat-utils absent des repos Debian 13 → compilation depuis les sources
# Les binaires sont dans bin/ (pas src/) après make
if command -v combinator.bin &>/dev/null; then
    ok "hashcat-utils déjà installé"
else
    info "Compilation de hashcat-utils depuis les sources (GitHub)..."
    _tmpdir=$(mktemp -d)
    if git clone --depth=1 https://github.com/hashcat/hashcat-utils.git "$_tmpdir/hashcat-utils" 2>/dev/null; then
        if make -C "$_tmpdir/hashcat-utils" 2>/dev/null; then
            install -m755 "$_tmpdir/hashcat-utils/bin/"*.bin "$HASHCAT_UTILS_DEST/"
            ok "hashcat-utils compilé → $HASHCAT_UTILS_DEST/"
        else
            warn "Échec compilation hashcat-utils (non bloquant)"
        fi
    else
        warn "Impossible de cloner hashcat-utils (réseau ?) — non bloquant"
    fi
    rm -rf "$_tmpdir"
fi

# Loader OpenCL universel
apt-get install -y --no-install-recommends ocl-icd-libopencl1 opencl-headers 2>/dev/null || true

case "$GPU_TYPE" in

    nvidia)
        # ── Drivers NVIDIA propriétaires ──────────────────────────────────────
        if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
            _drv=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
            ok "Drivers NVIDIA déjà installés (v${_drv})"
        else
            info "Installation des drivers NVIDIA propriétaires..."

            # Activer contrib/non-free si absent
            # Note : " non-free( |$)" évite de matcher "non-free-firmware" uniquement
            if ! grep -qE " non-free( |$)" /etc/apt/sources.list 2>/dev/null; then
                info "Activation des dépôts contrib/non-free..."
                sed -i 's/^\(deb http[^#]*\) main\b.*/\1 main contrib non-free non-free-firmware/' \
                    /etc/apt/sources.list
                apt-get update -qq
            fi

            # Kernel headers pour DKMS
            _kver=$(uname -r)
            apt-get install -y --no-install-recommends "linux-headers-${_kver}" 2>/dev/null \
                || apt-get install -y --no-install-recommends linux-headers-amd64 2>/dev/null \
                || warn "linux-headers non installés — le module NVIDIA pourrait échouer"

            # Driver + firmware
            if DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-driver firmware-misc-nonfree; then
                ok "Driver NVIDIA installé"
            else
                warn "Échec driver NVIDIA via apt — vérifiez manuellement"
            fi

            # CUDA toolkit
            info "Installation CUDA toolkit..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                nvidia-cuda-toolkit 2>/dev/null \
                && ok "CUDA toolkit installé" \
                || warn "nvidia-cuda-toolkit non disponible — hashcat utilisera OpenCL uniquement"

            # Build DKMS
            info "Compilation du module DKMS NVIDIA..."
            dkms autoinstall -k "$(uname -r)" 2>/dev/null \
                && ok "Module DKMS compilé" \
                || warn "dkms autoinstall échoué (peut nécessiter un reboot)"

            # Blacklist nouveau dans l'initramfs
            info "Rebuild initramfs (blacklist nouveau persistant)..."
            update-initramfs -u -k all 2>/dev/null \
                && ok "initramfs mis à jour" \
                || warn "update-initramfs échoué"

            warn "═══════════════════════════════════════════════════════"
            warn "  REBOOT REQUIS pour activer les drivers NVIDIA !"
            warn "  Après reboot : sudo bash $0 --no-wordlists"
            warn "  Alternative sans reboot :"
            warn "    modprobe -r nouveau && modprobe nvidia"
            warn "═══════════════════════════════════════════════════════"
        fi

        # pocl fallback CPU (pendant le reboot ou si OpenCL GPU indisponible)
        apt-get install -y --no-install-recommends pocl-opencl-icd 2>/dev/null \
            && ok "pocl installé (fallback CPU)" || true
        ;;

    amd)
        info "Installation OpenCL AMD (Mesa)..."
        if apt-get install -y --no-install-recommends mesa-opencl-icd 2>/dev/null; then
            ok "mesa-opencl-icd installé"
        else
            warn "mesa-opencl-icd non disponible."
            warn "GPU AMD récent ? Installez ROCm : https://rocm.docs.amd.com/"
        fi
        apt-get install -y --no-install-recommends pocl-opencl-icd 2>/dev/null \
            && ok "pocl installé (fallback CPU)" || true
        ;;

    cpu)
        info "Installation OpenCL CPU (pocl)..."
        if apt-get install -y --no-install-recommends pocl-opencl-icd 2>/dev/null; then
            ok "pocl-opencl-icd installé — hashcat disponible sur CPU"
        else
            warn "hashcat fonctionnera avec --force (mode dégradé sans OpenCL)"
        fi
        ;;
esac

ok "hashcat : $(hashcat --version 2>/dev/null || echo 'installé')"

# ─────────────────────────────────────────────────────────────────────────────
step "4 / 6 — Python + name-that-hash (requis par SameBreaker)"
# ─────────────────────────────────────────────────────────────────────────────
apt-get install -y --no-install-recommends python3 python3-pip python3-venv

if python3 -c "import name_that_hash" 2>/dev/null; then
    ok "name-that-hash déjà installé"
else
    info "Installation de name-that-hash..."
    pip3 install name-that-hash --break-system-packages 2>/dev/null \
        || pip3 install name-that-hash \
        || {
            warn "pip3 échoué — tentative via pipx..."
            apt-get install -y pipx 2>/dev/null \
                && pipx install name-that-hash \
                || warn "name-that-hash non installé — détection auto hash indisponible"
        }
fi

command -v nth &>/dev/null \
    && ok "nth : $(nth --version 2>/dev/null | head -1)" || true

# ─────────────────────────────────────────────────────────────────────────────
step "5 / 6 — Wordlists → $WORDLIST_DIR"
# ─────────────────────────────────────────────────────────────────────────────
if [[ $SKIP_WORDLISTS -eq 1 ]]; then
    warn "Skip wordlists (--no-wordlists)"
else
    mkdir -p "$WORDLIST_DIR"

    # — rockyou.txt ─────────────────────────────────────────────────────────
    if [[ -f "$WORDLIST_DIR/rockyou.txt" ]]; then
        ok "rockyou.txt déjà présent ($(wc -l < "$WORDLIST_DIR/rockyou.txt" | tr -d ' ') lignes)"
    else
        info "Recherche de rockyou.txt..."

        # 1) Paquet apt wordlists (Debian / Kali)
        if apt-get install -y --no-install-recommends wordlists 2>/dev/null; then
            if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
                info "Décompression rockyou.txt.gz..."
                gunzip -k /usr/share/wordlists/rockyou.txt.gz
                cp /usr/share/wordlists/rockyou.txt "$WORDLIST_DIR/"
                ok "rockyou.txt installé via apt"
            elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
                cp /usr/share/wordlists/rockyou.txt "$WORDLIST_DIR/"
                ok "rockyou.txt copié depuis /usr/share/wordlists/"
            fi
        fi

        # 2) Téléchargement direct si toujours absent
        if [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
            info "Téléchargement de rockyou.txt (~134 MB)..."
            wget -q --show-progress \
                "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
                -O "$WORDLIST_DIR/rockyou.txt" \
            && ok "rockyou.txt téléchargé ($(wc -l < "$WORDLIST_DIR/rockyou.txt" | tr -d ' ') lignes)" \
            || warn "Impossible de télécharger rockyou.txt — à récupérer manuellement dans $WORDLIST_DIR"
        fi
    fi

    # — Lien symbolique vers les règles hashcat ──────────────────────────────
    if [[ -d "$HASHCAT_RULES" ]]; then
        ln -sfn "$HASHCAT_RULES" "$WORDLIST_DIR/rules"
        ok "Lien : $WORDLIST_DIR/rules → $HASHCAT_RULES"
        info "Règles disponibles :"
        ls "$HASHCAT_RULES/"*.rule 2>/dev/null | while read -r f; do
            printf "    ${GRN}•${NC} %s\n" "$(basename "$f")"
        done
    else
        warn "Répertoire règles introuvable ($HASHCAT_RULES)"
    fi

    chmod -R 755 "$WORDLIST_DIR"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "6 / 6 — Vérification finale"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "Devices OpenCL/CUDA :"
clinfo -l 2>/dev/null || warn "Aucun device OpenCL — vérifiez les drivers"

if [[ $GPU_TYPE == "nvidia" ]] && command -v nvidia-smi &>/dev/null; then
    echo ""
    info "Devices NVIDIA (nvidia-smi) :"
    nvidia-smi --query-gpu=index,name,driver_version --format=csv,noheader 2>/dev/null \
        | while IFS=, read -r idx name drv; do
            printf "    ${GRN}•${NC} GPU %s : %s (driver %s)\n" "$idx" "$name" "$drv"
        done
fi

# Test hashcat
echo ""
info "Test hashcat (benchmark MD5, 3 secondes)..."
if hashcat -b -m 0 --runtime 3 --quiet 2>/dev/null | grep -q "Speed"; then
    ok "hashcat fonctionnel avec accélération"
elif hashcat -b -m 0 --runtime 3 --force --quiet 2>/dev/null | grep -q "Speed"; then
    warn "hashcat fonctionne uniquement en mode --force"
    warn "Activez 'hashcat_force: true' dans instance/config.json de SameBreaker"
else
    warn "Impossible de tester hashcat — vérifiez manuellement : hashcat -b -m 0"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}${CYN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${CYN}║  Installation hashcat terminée                       ║${NC}"
echo -e "${BLD}${CYN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLD}hashcat    ${NC}: $(command -v hashcat)"
echo -e "  ${BLD}version    ${NC}: $(hashcat --version 2>/dev/null)"
echo -e "  ${BLD}wordlists  ${NC}: $WORDLIST_DIR"
echo -e "  ${BLD}règles     ${NC}: $HASHCAT_RULES"
echo -e "  ${BLD}GPU        ${NC}: $GPU_TYPE"
echo ""
if [[ $GPU_TYPE == "cpu" ]]; then
    echo -e "  ${YLW}Mode CPU — le crackage sera lent.${NC}"
    echo -e "  ${YLW}Un GPU NVIDIA/AMD multipliera les perfs par x10 à x1000.${NC}"
    echo ""
fi
echo -e "  ${BLU}Étape suivante : installer SameBreaker${NC}"
echo -e "    sudo bash setup.sh"
echo ""
