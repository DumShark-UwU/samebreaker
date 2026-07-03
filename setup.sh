#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  SameBreaker — Script d'installation (Debian 13 Trixie)
#  Usage : sudo bash setup.sh [options]
#
#  Options :
#    --port=PORT           Port Flask interne (défaut : 6660)
#    --install-dir=PATH    Répertoire d'installation (défaut : /opt/samebreaker)
#    --user=USER           Utilisateur système (défaut : samebreaker)
#    --service=NAME        Nom du service systemd (défaut : samebreaker)
#    --local               Installe depuis le répertoire courant (dev)
#    --update              Met à jour un install existant (git pull + pip)
#    --no-wordlists        Ne pas configurer les liens wordlists
#    --no-https            Ne pas configurer nginx/TLS (accès HTTP direct)
#
#  Install par défaut :
#    • Crée l'utilisateur système
#    • Clone le dépôt GitHub dans INSTALL_DIR
#    • Crée le venv Python et installe les deps
#    • Génère la config + initialise la DB
#    • Crée et active le service systemd
#    • Configure nginx + HTTPS (mkcert ou auto-signé)
#
#  Prérequis : hashcat installé (lancez d'abord setup_hashcat.sh)
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
# Ces valeurs ont toutes un défaut raisonnable.
# Elles peuvent être surchargées via les args CLI (voir --help).

INSTALL_DIR="/opt/samebreaker"           # Répertoire d'installation de l'application
SB_USER="samebreaker"                    # Utilisateur système (sans shell, no-login)
SB_GROUP="samebreaker"                   # Groupe système associé
SERVICE_NAME="samebreaker"              # Nom du service systemd
REPO_URL="https://github.com/DumShark-UwU/samebreaker"  # Dépôt source GitHub

APP_PORT=6660                            # Port d'écoute Flask (interne, derrière nginx)
HTTP_PORT=80                             # Port nginx HTTP → redirige vers HTTPS
HTTPS_PORT=443                           # Port nginx HTTPS (exposé au réseau)
SSL_DIR="/etc/ssl/samebreaker"           # Répertoire des certificats TLS

# ── Args ──────────────────────────────────────────────────────────────────────
USE_LOCAL=0
UPDATE_ONLY=0
SETUP_WORDLISTS=1
SETUP_HTTPS=1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
    case "$arg" in
        --port=*)         APP_PORT="${arg#*=}" ;;
        --install-dir=*)  INSTALL_DIR="${arg#*=}" ;;
        --user=*)         SB_USER="${arg#*=}"; SB_GROUP="${arg#*=}" ;;
        --service=*)      SERVICE_NAME="${arg#*=}" ;;
        --repo=*)         REPO_URL="${arg#*=}" ;;
        --ssl-dir=*)      SSL_DIR="${arg#*=}" ;;
        --https-port=*)   HTTPS_PORT="${arg#*=}" ;;
        --local)          USE_LOCAL=1 ;;
        --update)         UPDATE_ONLY=1 ;;
        --no-wordlists)   SETUP_WORDLISTS=0 ;;
        --no-https)       SETUP_HTTPS=0 ;;
        --help|-h)
            echo "Usage: sudo bash $0 [options]"
            echo ""
            echo "Chemins :"
            echo "  --install-dir=PATH    Répertoire d'installation (défaut: $INSTALL_DIR)"
            echo "  --ssl-dir=PATH        Répertoire certificats TLS (défaut: $SSL_DIR)"
            echo ""
            echo "Réseau :"
            echo "  --port=PORT           Port Flask interne (défaut: $APP_PORT)"
            echo "  --https-port=PORT     Port HTTPS nginx (défaut: $HTTPS_PORT)"
            echo ""
            echo "Système :"
            echo "  --user=USER           Utilisateur système (défaut: $SB_USER)"
            echo "  --service=NAME        Nom du service systemd (défaut: $SERVICE_NAME)"
            echo "  --repo=URL            Dépôt GitHub source (défaut: $REPO_URL)"
            echo ""
            echo "Mode :"
            echo "  --local               Source = répertoire courant (dev/test)"
            echo "  --update              Met à jour une installation existante"
            echo "  --no-wordlists        Ne pas configurer les liens wordlists"
            echo "  --no-https            Ne pas configurer nginx/TLS"
            exit 0 ;;
    esac
done

# Chemins dérivés (ne pas modifier directement)
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
VENV_DIR="$INSTALL_DIR/venv"
INSTANCE_DIR="$INSTALL_DIR/instance"

# ── Prérequis ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Ce script doit être lancé en root : sudo bash $0"

echo ""
echo -e "${BLD}${CYN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${CYN}║      SameBreaker — Installation                      ║${NC}"
echo -e "${BLD}${CYN}║      Debian 13 Trixie                                ║${NC}"
echo -e "${BLD}${CYN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    [[ "$ID" != "debian" ]] && warn "Distribution : $ID (optimisé pour Debian 13)"
    info "OS             : ${PRETTY_NAME:-$ID $VERSION_ID}"
fi

info "Répertoire     : $INSTALL_DIR"
info "Utilisateur    : $SB_USER"
info "Service        : $SERVICE_NAME"
info "Port Flask     : $APP_PORT (interne)"
[[ $SETUP_HTTPS -eq 1 ]] && info "HTTPS          : nginx :$HTTPS_PORT → Flask :$APP_PORT"
[[ $USE_LOCAL   -eq 1 ]] && info "Source         : local ($SCRIPT_DIR)"
[[ $UPDATE_ONLY -eq 1 ]] && info "Mode           : mise à jour uniquement"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
step "1 / 6 — Dépendances système"
# ─────────────────────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    git curl ca-certificates libsqlite3-dev gcc
ok "Python $(python3 --version | grep -oP '\d+\.\d+\.\d+') + git installés"

if command -v hashcat &>/dev/null; then
    ok "hashcat : $(hashcat --version 2>/dev/null)"
else
    warn "hashcat introuvable — lancez setup_hashcat.sh en premier"
    warn "SameBreaker démarrera mais les jobs de crackage échoueront"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "2 / 6 — Utilisateur système '$SB_USER'"
# ─────────────────────────────────────────────────────────────────────────────
if id "$SB_USER" &>/dev/null; then
    ok "Utilisateur '$SB_USER' existe déjà"
else
    useradd \
        --system \
        --home-dir "$INSTALL_DIR" \
        --shell /usr/sbin/nologin \
        --comment "SameBreaker service account" \
        "$SB_USER"
    ok "Utilisateur '$SB_USER' créé (sans shell de connexion)"
fi

# Accès GPU pour hashcat
for grp in video render; do
    if getent group "$grp" &>/dev/null; then
        if id -nG "$SB_USER" | grep -qw "$grp"; then
            info "'$SB_USER' est déjà dans le groupe '$grp'"
        else
            usermod -aG "$grp" "$SB_USER"
            ok "'$SB_USER' ajouté au groupe '$grp' (accès GPU)"
        fi
    else
        warn "Groupe '$grp' inexistant — ignoré"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
step "3 / 6 — Dépôt Git + Venv Python"
# ─────────────────────────────────────────────────────────────────────────────

# ── 3a : sources ──────────────────────────────────────────────────────────────
if [[ $UPDATE_ONLY -eq 1 ]]; then
    [[ -d "$INSTALL_DIR/.git" ]] || die "Aucune installation trouvée dans $INSTALL_DIR (--update impossible)"
    info "Mise à jour du dépôt git..."
    sudo -u "$SB_USER" git -C "$INSTALL_DIR" pull --ff-only
    ok "Dépôt mis à jour : $(sudo -u "$SB_USER" git -C "$INSTALL_DIR" log -1 --format='%h %s')"

elif [[ $USE_LOCAL -eq 1 ]]; then
    info "Synchronisation depuis $SCRIPT_DIR → $INSTALL_DIR (mode --local)..."
    mkdir -p "$INSTALL_DIR"
    rsync -a --exclude='instance/' --exclude='venv/' --exclude='__pycache__/' \
              --exclude='*.pyc' --exclude='.git/' \
              "$SCRIPT_DIR/" "$INSTALL_DIR/"
    chown -R "$SB_USER:$SB_GROUP" "$INSTALL_DIR"
    ok "Fichiers copiés"

else
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Dépôt existant — mise à jour..."
        sudo -u "$SB_USER" git -C "$INSTALL_DIR" pull --ff-only \
            && ok "Dépôt mis à jour" \
            || warn "git pull échoué — installation existante conservée"
    else
        info "Clonage de $REPO_URL..."
        mkdir -p "$INSTALL_DIR"
        chown "$SB_USER:$SB_GROUP" "$INSTALL_DIR"
        sudo -u "$SB_USER" git clone "$REPO_URL" "$INSTALL_DIR"
        ok "Dépôt cloné dans $INSTALL_DIR"
        info "Commit : $(sudo -u "$SB_USER" git -C "$INSTALL_DIR" log -1 --format='%h %s')"
    fi
fi

# ── 3b : venv ─────────────────────────────────────────────────────────────────
if [[ -d "$VENV_DIR" ]]; then
    info "venv existant — mise à jour des dépendances..."
else
    info "Création du venv Python..."
    sudo -u "$SB_USER" python3 -m venv "$VENV_DIR"
fi

sudo -u "$SB_USER" "$VENV_DIR/bin/pip" install --upgrade pip --quiet
sudo -u "$SB_USER" "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
ok "Dépendances Python installées :"
"$VENV_DIR/bin/pip" list --format=columns 2>/dev/null \
    | grep -iE "flask|werkzeug|name-that-hash|pyotp|wtforms" \
    | while read -r line; do printf "    ${GRN}•${NC} %s\n" "$line"; done

# ─────────────────────────────────────────────────────────────────────────────
step "4 / 6 — Configuration, DB & Wordlists"
# ─────────────────────────────────────────────────────────────────────────────

# ── 4a : structure instance/ ──────────────────────────────────────────────────
# hashcat lit son home depuis /etc/passwd (getpwuid), pas $HOME.
# XDG_DATA_HOME et XDG_CACHE_HOME redirigent sessions/kernels vers instance/
# qui est le seul répertoire accessible en écriture (ProtectSystem=strict).
sudo -u "$SB_USER" mkdir -p \
    "$INSTANCE_DIR/jobs" \
    "$INSTANCE_DIR/wordlists" \
    "$INSTANCE_DIR/.local/share/hashcat/sessions" \
    "$INSTANCE_DIR/.cache/hashcat/kernels"

CONFIG_FILE="$INSTANCE_DIR/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    ok "config.json conservé (pas de réécriture)"
else
    info "Génération de config.json avec secret_key aléatoire..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$CONFIG_FILE" <<EOF
{
  "secret_key": "$SECRET",
  "require_2fa": false,
  "hashcat_force": true,
  "max_concurrent_jobs": 3,
  "max_upload_mb": 50,
  "session_timeout_minutes": 60
}
EOF
    chown "$SB_USER:$SB_GROUP" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    ok "config.json généré"
fi

# ── 4b : base de données ──────────────────────────────────────────────────────
info "Initialisation de la base de données..."
cd "$INSTALL_DIR"
sudo -u "$SB_USER" "$VENV_DIR/bin/python3" -c "
from app.db import init_db, seed_default_admin
init_db()
seed_default_admin()
print('  DB initialisée + compte admin créé')
"
ok "admin / admin créé (changement de mot de passe obligatoire à la première connexion)"

# ── 4c : accès aux wordlists ──────────────────────────────────────────────────
if [[ $SETUP_WORDLISTS -eq 1 ]]; then
    info "Configuration des accès wordlists..."

    for wdir in "/opt/wordlists" "/usr/share/wordlists"; do
        if [[ -d "$wdir" ]]; then
            chmod -R o+rX "$wdir" 2>/dev/null || true
            ok "Accès lecture : $wdir"
            LINK_NAME="$INSTANCE_DIR/wordlists/$(basename "$wdir")"
            if [[ ! -L "$LINK_NAME" ]]; then
                sudo -u "$SB_USER" ln -sfn "$wdir" "$LINK_NAME"
                ok "Lien → $LINK_NAME"
            fi
        else
            warn "$wdir inexistant — lancez setup_hashcat.sh pour télécharger les wordlists"
        fi
    done

    RULES_DIR="/usr/share/hashcat/rules"
    if [[ -d "$RULES_DIR" ]]; then
        RULES_LINK="$INSTANCE_DIR/wordlists/rules"
        [[ -L "$RULES_LINK" ]] || sudo -u "$SB_USER" ln -sfn "$RULES_DIR" "$RULES_LINK"
        ok "Règles hashcat liées : $RULES_LINK"
    fi
fi

# Permissions finales instance/
chown -R "$SB_USER:$SB_GROUP" "$INSTANCE_DIR"
chmod 750 "$INSTANCE_DIR"
chmod 750 "$INSTANCE_DIR/jobs"

# ─────────────────────────────────────────────────────────────────────────────
step "5 / 6 — Service systemd"
# ─────────────────────────────────────────────────────────────────────────────
_FLASK_HOST="127.0.0.1"
[[ $SETUP_HTTPS -eq 0 ]] && _FLASK_HOST="0.0.0.0"

info "Écriture de $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SameBreaker — Hashcat Web UI
Documentation=$REPO_URL
After=network.target

[Service]
Type=simple
User=${SB_USER}
Group=${SB_GROUP}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="FLASK_ENV=production"
# hashcat lit le home depuis /etc/passwd (getpwuid), pas \$HOME.
# XDG_DATA_HOME + XDG_CACHE_HOME redirigent sessions/kernels dans instance/ (ReadWritePaths)
Environment="HOME=${INSTALL_DIR}/instance"
Environment="XDG_DATA_HOME=${INSTALL_DIR}/instance/.local/share"
Environment="XDG_CACHE_HOME=${INSTALL_DIR}/instance/.cache"
ExecStart=${VENV_DIR}/bin/python3 ${INSTALL_DIR}/run.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Accès GPU pour hashcat
SupplementaryGroups=video render

# Sécurité — seul instance/ est accessible en écriture
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/instance

[Install]
WantedBy=multi-user.target
EOF

# Liaison du host Flask avec le mode HTTPS (nginx en frontal = 127.0.0.1 uniquement)
_RUNPY="$INSTALL_DIR/run.py"
if [[ $SETUP_HTTPS -eq 1 ]]; then
    if grep -q 'host="0.0.0.0"' "$_RUNPY" 2>/dev/null; then
        sed -i 's/host="0\.0\.0\.0"/host="127.0.0.1"/' "$_RUNPY"
    elif ! grep -q 'host=' "$_RUNPY" 2>/dev/null; then
        sed -i 's/app\.run(/app.run(host="127.0.0.1", /' "$_RUNPY"
    fi
    info "run.py : Flask en écoute 127.0.0.1 (nginx en frontal)"
else
    if grep -q 'host="127.0.0.1"' "$_RUNPY" 2>/dev/null; then
        sed -i 's/host="127\.0\.0\.1"/host="0.0.0.0"/' "$_RUNPY"
    elif ! grep -q 'host=' "$_RUNPY" 2>/dev/null; then
        sed -i 's/app\.run(/app.run(host="0.0.0.0", /' "$_RUNPY"
    fi
    info "run.py : Flask en écoute 0.0.0.0 (pas de nginx)"
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
ok "Service $SERVICE_NAME activé (démarrage auto)"

if [[ $UPDATE_ONLY -eq 1 ]]; then
    systemctl restart "$SERVICE_NAME"
else
    systemctl start "$SERVICE_NAME"
fi

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service démarré et actif"
else
    warn "Le service n'a pas démarré correctement :"
    journalctl -u "$SERVICE_NAME" -n 15 --no-pager || true
fi

# ─────────────────────────────────────────────────────────────────────────────
if [[ $SETUP_HTTPS -eq 1 ]]; then
step "6 / 6 — HTTPS (nginx + mkcert)"
# ─────────────────────────────────────────────────────────────────────────────

_SERVER_IP=$(hostname -I | awk '{print $1}')
mkdir -p "$SSL_DIR"

# ── nginx ──────────────────────────────────────────────────────────────────
apt-get install -y --no-install-recommends nginx 2>/dev/null
ok "nginx : $(nginx -v 2>&1 | grep -oP 'nginx/[\d.]+')"

# ── certificat : mkcert (CA de confiance) ou auto-signé ───────────────────
_MKCERT_OK=0
if apt-get install -y --no-install-recommends mkcert 2>/dev/null \
        && command -v mkcert &>/dev/null; then
    _MKCERT_OK=1
    ok "mkcert installé (apt)"
elif curl -fsSL "https://dl.filippo.io/mkcert/latest?for=linux/amd64" \
         -o /usr/local/bin/mkcert 2>/dev/null; then
    chmod +x /usr/local/bin/mkcert
    _MKCERT_OK=1
    ok "mkcert installé (binaire GitHub)"
fi

if [[ $_MKCERT_OK -eq 1 ]]; then
    CAROOT=$(mkcert -CAROOT)
    mkcert -install 2>/dev/null || true
    mkcert -cert-file "$SSL_DIR/cert.pem" \
           -key-file  "$SSL_DIR/key.pem"  \
           "$_SERVER_IP" localhost 127.0.0.1 2>/dev/null
    ok "Certificat mkcert généré pour $_SERVER_IP (valide 2 ans)"
    # CA copiée dans instance/ pour distribution aux clients du réseau
    if [[ -f "$CAROOT/rootCA.pem" ]]; then
        cp "$CAROOT/rootCA.pem" "$INSTANCE_DIR/rootCA.pem"
        chown "$SB_USER:$SB_GROUP" "$INSTANCE_DIR/rootCA.pem"
        ok "CA client → $INSTANCE_DIR/rootCA.pem"
    fi
else
    warn "mkcert indisponible — génération d'un certificat auto-signé (3650 jours)"
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout "$SSL_DIR/key.pem" \
        -out    "$SSL_DIR/cert.pem" \
        -subj   "/CN=${_SERVER_IP}" \
        -addext "subjectAltName=IP:${_SERVER_IP},IP:127.0.0.1,DNS:localhost" 2>/dev/null
    ok "Certificat auto-signé généré"
fi

chmod 640 "$SSL_DIR/key.pem"
chown root:www-data "$SSL_DIR/key.pem" "$SSL_DIR/cert.pem"

# ── config nginx ──────────────────────────────────────────────────────────
python3 -c "
import pathlib
conf = '''server {{
    listen ${HTTP_PORT} default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}}

server {{
    listen ${HTTPS_PORT} ssl default_server;
    server_name _;

    ssl_certificate     ${SSL_DIR}/cert.pem;
    ssl_certificate_key ${SSL_DIR}/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    client_max_body_size 200M;

    # SSE & streams — pas de buffering pour le live-log
    location ~* ^/api/(jobs|benchmark)/ {{
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 600;
        chunked_transfer_encoding on;
    }}

    location / {{
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
    }}
}}
'''
pathlib.Path('/etc/nginx/sites-available/${SERVICE_NAME}').write_text(conf)
print('Config nginx écrite')
"

ln -sfn "/etc/nginx/sites-available/${SERVICE_NAME}" \
        "/etc/nginx/sites-enabled/${SERVICE_NAME}"
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>/dev/null; then
    systemctl enable nginx --quiet
    systemctl restart nginx
    ok "nginx démarré — HTTPS sur le port ${HTTPS_PORT}"
else
    warn "Config nginx invalide — vérifiez /etc/nginx/sites-available/${SERVICE_NAME}"
    nginx -t 2>&1 || true
fi

# Redémarrer Flask pour la nouvelle config host
systemctl restart "$SERVICE_NAME"
sleep 2
systemctl is-active --quiet "$SERVICE_NAME" && ok "Service redémarré OK" || warn "Vérifiez : journalctl -u $SERVICE_NAME -n 20"

fi  # SETUP_HTTPS

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}${CYN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${CYN}║  Installation terminée                               ║${NC}"
echo -e "${BLD}${CYN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $SETUP_HTTPS -eq 1 ]]; then
    _DISP_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo -e "  ${BLD}URL réseau       ${NC}: ${GRN}https://${_DISP_IP}${NC}  (port ${HTTPS_PORT})"
    echo -e "  ${BLD}URL locale       ${NC}: https://localhost"
    echo -e ""
    echo -e "  ${BLD}Certificat TLS   ${NC}: ${SSL_DIR}/cert.pem"
    if [[ -f "$INSTANCE_DIR/rootCA.pem" ]]; then
        echo -e "  ${YLW}⚠  Clients LAN : installez la CA pour éviter l'avertissement TLS${NC}"
        echo -e "     ${CYN}# Linux (client) :${NC}"
        echo -e "     scp ${SB_USER}@${_DISP_IP}:${INSTANCE_DIR}/rootCA.pem ."
        echo -e "     sudo cp rootCA.pem /usr/local/share/ca-certificates/samebreaker.crt"
        echo -e "     sudo update-ca-certificates"
    fi
else
    echo -e "  ${BLD}URL              ${NC}: http://0.0.0.0:${APP_PORT}"
    echo -e "  ${YLW}⚠  HTTPS désactivé — accès non chiffré${NC}"
fi

echo ""
echo -e "  ${BLD}Login par défaut ${NC}: admin / admin"
echo -e "  ${BLD}Utilisateur OS   ${NC}: $SB_USER (nologin)"
echo -e "  ${BLD}Répertoire       ${NC}: $INSTALL_DIR"
echo -e "  ${BLD}Config           ${NC}: $INSTANCE_DIR/config.json"
echo -e "  ${BLD}Base de données  ${NC}: $INSTANCE_DIR/samebreaker.db"
echo -e "  ${BLD}Wordlists        ${NC}: $INSTANCE_DIR/wordlists/"
echo -e "  ${BLD}Logs             ${NC}: journalctl -u $SERVICE_NAME -f"
echo ""
echo -e "  ${BLD}Commandes utiles :${NC}"
echo -e "    systemctl status  $SERVICE_NAME"
echo -e "    systemctl restart $SERVICE_NAME"
echo -e "    journalctl -u $SERVICE_NAME -f"
echo -e "    sudo bash $INSTALL_DIR/setup.sh --update   ${CYN}# maj depuis GitHub${NC}"
echo ""
echo -e "  ${YLW}⚠  Changez le mot de passe admin à la première connexion !${NC}"
if ! command -v hashcat &>/dev/null; then
    echo -e "  ${RED}⚠  hashcat manquant — sudo bash $INSTALL_DIR/setup_hashcat.sh${NC}"
fi
echo ""
