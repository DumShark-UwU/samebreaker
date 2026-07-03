# SameBreaker — Documentation technique ![](img/gura.png)

> *Ver 1.2.0*

---

## Architecture générale ![](img/Emote-gura8.png)

SameBreaker est une application **Flask** structurée en **Application Factory** (`create_app()`), avec authentification via **Flask-Login**, protection CSRF via **Flask-WTF**, et persistance via **SQLite** (accès par context manager `db_conn()`).

En production, nginx est placé en reverse proxy devant Flask pour terminer le TLS.

```
Navigateur (HTTPS)
    │  :443
    ▼
nginx (reverse proxy + TLS)
    │  :6660 (127.0.0.1 uniquement)
    ▼
Flask (run.py → create_app())
    ├── Blueprint auth   — /login, /logout, /2fa/setup, /2fa/verify
    ├── Blueprint main   — /, /attack/*, /api/*, /benchmark, /profile, /system
    └── Blueprint admin  — /admin/users/*, /admin/jobs, /admin/config
            │
            ▼
    SQLite (instance/samebreaker.db)
    hashcat subprocess (Popen + threading)
```

---

## Installation ![](img/Emote-gura18.png)

### Prérequis

- Debian 13 (Trixie) — autres distros possibles mais non testées
- Root (`sudo`)
- GPU NVIDIA recommandé (8x GTX 1660 SUPER ou équivalent) — CPU possible mais lent

### 1. Installer hashcat + GPU

```bash
sudo bash setup_hashcat.sh
```

**Variables configurables dans le script :**

| Variable | Défaut | Description |
|----------|--------|-------------|
| `WORDLIST_DIR` | `/opt/wordlists` | Répertoire d'installation des wordlists |
| `HASHCAT_RULES` | `/usr/share/hashcat/rules` | Répertoire des règles hashcat |
| `HASHCAT_UTILS_DEST` | `/usr/local/bin` | Destination des binaires hashcat-utils |

**Options CLI :**

```
--force-cpu            Installe pocl uniquement (mode CPU, ignore GPU)
--force-nvidia         Force le mode NVIDIA si la détection auto échoue
--no-wordlists         Skip le téléchargement des wordlists
--wordlist-dir=PATH    Surcharge WORDLIST_DIR
```

> **NVIDIA :** un reboot peut être nécessaire après l'installation des drivers. Relancez ensuite `setup_hashcat.sh --no-wordlists`.

### 2. Installer SameBreaker

```bash
sudo bash setup.sh
```

**Variables configurables dans le script :**

| Variable | Défaut | Description |
|----------|--------|-------------|
| `INSTALL_DIR` | `/opt/samebreaker` | Répertoire d'installation de l'application |
| `SB_USER` | `samebreaker` | Utilisateur système (sans shell) |
| `SB_GROUP` | `samebreaker` | Groupe système |
| `SERVICE_NAME` | `samebreaker` | Nom du service systemd |
| `REPO_URL` | GitHub DumShark-UwU/samebreaker | Dépôt source |
| `APP_PORT` | `6660` | Port Flask interne (derrière nginx) |
| `HTTP_PORT` | `80` | Port nginx HTTP (→ redirect HTTPS) |
| `HTTPS_PORT` | `443` | Port nginx HTTPS (exposé réseau) |
| `SSL_DIR` | `/etc/ssl/samebreaker` | Répertoire des certificats TLS |

**Options CLI :**

```
--install-dir=PATH     Surcharge INSTALL_DIR
--user=USER            Surcharge SB_USER + SB_GROUP
--service=NAME         Surcharge SERVICE_NAME
--repo=URL             Surcharge REPO_URL
--port=PORT            Surcharge APP_PORT
--https-port=PORT      Surcharge HTTPS_PORT
--ssl-dir=PATH         Surcharge SSL_DIR
--local                Source = répertoire courant (dev/test)
--update               Met à jour une installation existante (git pull + pip)
--no-wordlists         Ne pas configurer les liens wordlists
--no-https             Ne pas configurer nginx/TLS (accès HTTP direct)
```

### HTTPS et certificats TLS

`setup.sh` installe nginx en reverse proxy et génère un certificat via `mkcert` (CA locale de confiance) ou OpenSSL (auto-signé en fallback).

La CA générée par mkcert est copiée dans `instance/rootCA.pem`. Pour que les navigateurs clients fassent confiance au certificat sans avertissement, installer la CA une fois sur chaque machine cliente :

```bash
# Récupérer la CA depuis le serveur
scp samebreaker@<IP_SERVEUR>:/opt/samebreaker/instance/rootCA.pem .

# Linux (Debian/Ubuntu)
sudo cp rootCA.pem /usr/local/share/ca-certificates/samebreaker.crt
sudo update-ca-certificates

# Arch Linux
sudo cp rootCA.pem /etc/ca-certificates/trust-source/anchors/samebreaker.crt
sudo update-ca-trust

# Windows : double-clic sur rootCA.pem → Installer → "Autorités de certification racines de confiance"
# macOS : double-clic → Trousseau → Approuver
```

### Mise à jour

```bash
sudo bash /opt/samebreaker/setup.sh --update
```

---

## Schéma de base de données ![](img/Emote-gura15.png)

### Table `users`

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | INTEGER PK | Identifiant auto-incrémenté |
| `username` | TEXT UNIQUE | Nom d'utilisateur |
| `password` | TEXT | Hash bcrypt (werkzeug) |
| `role` | TEXT | `admin` ou `user` |
| `allowed_devices` | TEXT | IDs GPU séparés par virgule (`"1,2"`) |
| `workload_profile` | INTEGER | Profil hashcat `-w` (1–4, défaut 2) |
| `totp_secret` | TEXT | Secret TOTP Base32 (null si 2FA non configuré) |
| `must_change_password` | INTEGER | `1` = bannière de changement obligatoire |
| `created_at` | DATETIME | Date de création |

### Table `jobs`

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | INTEGER PK | Identifiant auto-incrémenté |
| `name` | TEXT | Nom affiché du job |
| `status` | TEXT | `pending` / `running` / `completed` / `failed` / `stopped` |
| `hash_type` | INTEGER | Mode `-m` hashcat |
| `hash_type_name` | TEXT | Nom lisible du type de hash |
| `attack_mode` | INTEGER | Mode `-a` hashcat (0/1/3/6/7) |
| `hash_file` | TEXT | Chemin vers le fichier de hashes (supprimé après démarrage) |
| `wordlist` | TEXT | Chemin vers la wordlist |
| `mask` | TEXT | Mask brute-force |
| `rules` | TEXT | Fichier de règles hashcat |
| `devices` | TEXT | IDs GPU utilisés (`"1,2"`) |
| `extra_args` | TEXT | Arguments supplémentaires (admin uniquement) |
| `log_file` | TEXT | Chemin vers le fichier de log |
| `pot_file` | TEXT | Chemin vers le pot file (résultats) |
| `workload` | INTEGER | Profil `-w` utilisé pour ce job |
| `created_at` | DATETIME | Date de création |
| `started_at` | DATETIME | Date de démarrage effectif |
| `finished_at` | DATETIME | Date de fin |
| `created_by` | INTEGER | FK → `users.id` |
| `pid` | INTEGER | PID du process hashcat |
| `hidden` | INTEGER | `1` = masqué du dashboard (soft delete) |
| `hidden_at` | DATETIME | Date du masquage |
| `hidden_by` | INTEGER | FK → `users.id` (qui a masqué) |

### Table `webhooks`

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | INTEGER PK | Identifiant |
| `user_id` | INTEGER | FK → `users.id` (ON DELETE CASCADE) |
| `label` | TEXT | Libellé (64 chars max) |
| `url` | TEXT | URL webhook |
| `events` | TEXT | Événements CSV (`job_done`, `password_found`) |
| `created_at` | DATETIME | Date de création |

---

## Modules ![](img/Emote-gura11.png)

### `app/db.py`

Point d'accès unique à SQLite.

| Fonction | Description |
|----------|-------------|
| `db_conn()` | Context manager — ouvre, yield, ferme garantie (try/finally) |
| `init_db()` | Crée les tables + lance les migrations de colonnes |
| `_run_migrations()` | `ALTER TABLE … ADD COLUMN` — idempotent via `except OperationalError` |
| `reset_stale_jobs()` | Remet tous les jobs `running` en `failed` au démarrage (crash recovery) |
| `seed_default_admin()` | Crée `admin` / `admin` avec `must_change_password=1` si la table users est vide |

> `get_db()` a été retiré (v1.2.0) — utiliser exclusivement `db_conn()` (context manager).

**Pattern d'accès :**
```python
with db_conn() as conn:
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
```

**Migrations :** les colonnes ajoutées en cours de vie de l'application (ex. `hidden`, `workload`, `totp_secret`) sont ajoutées via `_run_migrations()` qui tente un `ALTER TABLE ADD COLUMN` et ignore l'`OperationalError` si la colonne existe déjà — garantissant la compatibilité avec les bases existantes.

---

### `app/models.py`

Classe `User` (hérite de `UserMixin` Flask-Login).

| Attribut | Type | Description |
|----------|------|-------------|
| `id` | int | Identifiant BDD |
| `username` | str | Nom d'utilisateur |
| `role` | str | `admin` ou `user` |
| `allowed_devices` | str | Devices autorisés (CSV) |
| `workload_profile` | int | Profil workload validé (1–4) |
| `must_change_password` | bool | True = bannière active |

| Méthode | Description |
|---------|-------------|
| `is_admin()` | `role == "admin"` |
| `get_allowed_device_ids()` | Parse `allowed_devices` → `list[int]` |
| `get(user_id)` | Charge depuis BDD par ID (utilisé par `user_loader`) |
| `get_by_username(username)` | Charge la row brute pour vérification mot de passe |

---

### `app/auth.py`

Authentification + rate limiting + 2FA TOTP.

**Classe `RateLimiter`** — compteur glissant par clé (IP), thread-safe :
```python
class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: int): ...
    def is_limited(self, key: str) -> bool: ...
```
Instanciée dans `auth.py` (`_login_limiter`, 10/5 min) et `main.py` (`_detect_limiter`, 30/min).

| Route | Description |
|-------|-------------|
| `/login` | Identifiant + mot de passe. Si `REQUIRE_2FA` : redirige vers `/2fa/verify` ou `/2fa/setup` |
| `/2fa/setup` | GET : QR code + clé manuelle. POST : vérifie code, sauvegarde secret, connecte |
| `/2fa/verify` | GET : formulaire TOTP. POST : vérifie code → connexion |
| `/logout` | POST uniquement. Nettoie la session 2FA |

**Flux 2FA :**
```
login (mdp OK) → REQUIRE_2FA ?
  ├─ oui + totp_secret défini  → /2fa/verify  → code OK → login_user()
  ├─ oui + pas de totp_secret  → /2fa/setup   → QR + code OK → UPDATE users SET totp_secret=? → login_user()
  └─ non                       → login_user() direct
```

---

### `app/jobs.py`

Cycle de vie des jobs hashcat.

**Constantes de statut :**

```python
STATUS_PENDING   = "pending"
STATUS_RUNNING   = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED    = "failed"
STATUS_STOPPED   = "stopped"

TERMINAL_STATUSES   = {STATUS_COMPLETED, STATUS_FAILED, STATUS_STOPPED}
MAX_CONCURRENT_JOBS = 5   # configurable depuis config.json
_HASHCAT_OK_CODES   = {0, 1}
```

| Fonction | Description |
|----------|-------------|
| `get_busy_devices()` | Retourne les IDs de GPU utilisés par des jobs `running` |
| `create_job(...)` | Insère le job, écrit le fichier hash, retourne `job_id` |
| `start_job(job_id)` | Vérifie `MAX_CONCURRENT_JOBS`, lance hashcat en thread daemon — retourne `bool` |
| `resume_job(job_id)` | Vérifie `MAX_CONCURRENT_JOBS` + existence `.restore`, reprend via `--restore` — retourne `bool` |
| `can_resume(job_id)` | Vérifie l'existence du fichier `.restore` |
| `stop_job(job_id)` | `proc.terminate()` (sous `_procs_lock`) + update statut `stopped` |
| `get_job(job_id)` | Fetch une row depuis BDD (inclut les jobs masqués) |
| `list_jobs(user_id, include_hidden)` | Liste les jobs — filtre `hidden=0` par défaut (dashboard), `include_hidden=True` pour l'audit |
| `hide_job(job_id, hidden_by)` | Soft-delete : `hidden=1` + timestamp — seuls les statuts terminaux acceptés |
| `get_results(job)` | Lit le pot file — retourne `list[str]` |

**Race condition `stop_job` (corrigée v1.2.0) :**
Quand un job est stoppé manuellement, le thread `_run()` voit un code de retour SIGTERM et aurait réécrit `status='failed'` par-dessus `'stopped'`. Correction : `_run()` consulte le statut courant en BDD avant la mise à jour finale et ne l'écrase pas si `status='stopped'`.

**Webhooks sur `resume_job` (ajouté v1.2.0) :**
`resume_job` déclenche désormais les mêmes webhooks que `start_job` : `password_found` (tous les 100 lignes + fin) et `job_done` (fin de job). Les webhooks sont chargés depuis la table `webhooks` avant le lancement du thread.

**Soft-delete (masquage) :**
```python
# Le dashboard ne voit que les jobs visibles
list_jobs(user_id=uid)                 # hidden=0 uniquement
# L'audit admin voit tout
list_jobs(user_id=None, include_hidden=True)  # pas de filtre
# Masquer un job (statut terminal requis)
hide_job(job_id, hidden_by=current_user.id)   # retourne False si job actif
```

**Thread-safety :** toutes les opérations sur `_procs` (dict PID → process) sont protégées par `_procs_lock`.

**Fichiers de session / reprise :**
- Chaque job reçoit `--restore-file-path instance/jobs/<id>.restore`
- `can_resume(id)` → `os.path.exists("instance/jobs/<id>.restore")`
- `resume_job(id)` → `hashcat --restore --restore-file-path instance/jobs/<id>.restore`

---

### `app/hashcat_utils.py`

Interface avec hashcat + détection de hash.

| Fonction | Description |
|----------|-------------|
| `hashcat_available()` | `hashcat --version` → `(bool, version_str)` |
| `get_devices()` | Parse `hashcat -I` → `list[{id, name, type}]` |
| `get_wordlists()` | Scan des `WORDLIST_DIRS` → `list[{path, name, size}]` |
| `detect_hash(hash_str)` | `nth.runner.api_return_hashes_as_dict([h])` → `list[{name, hashcat, john, description, extended}]` |
| `build_command(job)` | Construit la liste d'arguments hashcat complète |

**Variables configurables (propagées depuis `__init__.py`) :**

```python
HASHCAT_BIN:   str  # shutil.which("hashcat") ou HASHCAT_PATH env
HASHCAT_FORCE: bool # True par défaut — ajouté via config.json → hashcat_force
```

**`build_command()` — flags systématiques :**
```
--status --status-timer=2 --outfile-format=2 -w <workload>
--potfile-path instance/jobs/<id>.pot
--restore-file-path instance/jobs/<id>.restore
[--force]  ← si HASHCAT_FORCE
```

**Note XDG :** hashcat lit son home depuis `/etc/passwd` via `getpwuid()` (pas `$HOME` env). Les variables `XDG_DATA_HOME` et `XDG_CACHE_HOME` sont définies dans le service systemd pour rediriger sessions et kernels compilés vers `instance/` (seul répertoire writable avec `ProtectSystem=strict`).

---

### `app/main.py`

Blueprint principal — routes utilisateur + API.

**Sécurité des inputs (POST `/attack/new`) :**

| Champ | Validation |
|-------|-----------|
| `hash_type` | `int >= 0` |
| `attack_mode` | Dans `_ALLOWED_ATTACK_MODES` (frozenset) |
| `workload` | Dans `{1,2,3,4}` (admin uniquement, sinon profil user) |
| `wordlist` | `_is_safe_path()` contre `WORDLIST_DIRS` — chemin résolu via `current_app.instance_path` pour les uploads |
| `rules` | `_is_safe_path()` contre `_RULES_DIRS` |
| `devices` | Revalidés contre les IDs autorisés du user |
| `extra_args` | Admin uniquement |

**Routes job :**

| Route | Description |
|-------|-------------|
| `GET /` | Dashboard — liste des jobs (`hidden=0` uniquement) |
| `POST /attack/new` | Crée + démarre un job |
| `GET /attack/<id>` | Détail d'un job (log live SSE, résultats, boutons action) |
| `POST /attack/<id>/stop` | Arrête le job (`proc.terminate()`) |
| `POST /attack/<id>/resume` | Reprend un job stoppé ou échoué |
| `POST /attack/<id>/hide` | Masque le job du dashboard (soft delete, statut terminal requis) |
| `GET /attack/<id>/download` | Télécharge les résultats (pot file) |

**Pré-remplissage (`?from_job=<id>`) :**
```python
prefill_job = job_mgr.get_job(int(from_job_id))
if prefill_job and _can_access_job(prefill_job):
    prefill = dict(prefill_job)
```

---

### `app/admin.py`

Gestion des utilisateurs + audit log (admin uniquement).

| Route | Description |
|-------|-------------|
| `/admin/users` | Liste des utilisateurs (avec statut 2FA) |
| `/admin/users/new` | Création d'utilisateur |
| `/admin/users/<id>/edit` | Modification (username, mdp, rôle, GPU, workload) |
| `/admin/users/<id>/delete` | Suppression (sauf soi-même) |
| `/admin/users/<id>/reset-2fa` | Réinitialise le secret TOTP |
| `/admin/jobs` | **Audit log** — tous les jobs, y compris masqués (`LEFT JOIN users`) |
| `/admin/config` | GET/POST — édition de `config.json` avec application à chaud |

**Audit log (`/admin/jobs`) :**
- Affiche **tous** les jobs sans filtre sur `hidden` — trace complète
- Jobs masqués affichés avec opacité réduite + badge `masqué`
- Filtre "Masqués" dédié dans la barre de filtres (en plus des filtres par statut)

---

### `app/__init__.py`

Factory Flask.

**Séquence de démarrage :**
```
create_app()
    → _load_instance_config(app)   # lit/génère SECRET_KEY, propage HASHCAT_FORCE + MAX_CONCURRENT_JOBS
                                   # configure REQUIRE_2FA, SESSION_PERMANENT + PERMANENT_SESSION_LIFETIME
    → init_db()                    # crée les tables + migrations (hidden, workload, totp_secret…)
    → reset_stale_jobs()           # recovery après crash serveur
    → seed_default_admin()         # admin/admin si DB vide
    → register blueprints
    → @before_request : session.modified = True (refresh idle timeout)
    → @after_request : security headers
    → @context_processor : running_jobs_count (badge sidebar)
```

**Security headers :**
```python
resp.headers["X-Frame-Options"]           = "DENY"
resp.headers["X-Content-Type-Options"]    = "nosniff"
resp.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
resp.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
```

---

## Sécurité ![](img/Emote-gura20.png)

| Vecteur | Mitigation |
|---------|-----------|
| Forgery de session | SECRET_KEY aléatoire 256 bits, persistée dans `instance/config.json` |
| CSRF | Flask-WTF sur tous les formulaires + API POST |
| Brute-force login | `RateLimiter` — 10 req / 5 min par IP |
| Brute-force detect API | `_detect_limiter` — 30 req / min par IP → HTTP 429 |
| 2FA TOTP (optionnel) | `pyotp` TOTP RFC 6238, `valid_window=1` (±30 s drift), secret en BDD |
| Session idle | `PERMANENT_SESSION_LIFETIME` + refresh `session.modified` à chaque requête |
| Path traversal | `_is_safe_path()` via `os.path.realpath()` |
| Injection SQL | Paramètres liés (`?`) systématiquement |
| Accès inter-users | `_can_access_job()` vérifie `created_by == user.id` |
| Élévation de rôle | `admin_required` decorator sur toutes les routes admin |
| Extra args arbitraires | Réservés aux admins (template + serveur) |
| Devices non autorisés | Revalidation côté serveur des IDs sélectionnés |
| Upload malveillant | `secure_filename()` + `MAX_CONTENT_LENGTH` |
| Mot de passe par défaut | Bannière persistante + flag `must_change_password` |
| Clickjacking / sniffing | X-Frame-Options DENY, X-Content-Type-Options, HSTS via `@after_request` |
| Thread-safety | `_procs_lock` protège toutes les opérations sur le dict des processus |
| Transport réseau | TLS 1.2/1.3 via nginx (mkcert ou auto-signé) |
| Flask isolation | `ProtectSystem=strict` + `PrivateTmp=true` + `NoNewPrivileges=true` systemd |

---

## Configuration runtime ![](img/Emote-gura13.png)

### `instance/config.json`

```json
{
  "secret_key": "...",
  "require_2fa": false,
  "hashcat_force": true,
  "max_concurrent_jobs": 3,
  "max_upload_mb": 50,
  "session_timeout_minutes": 60
}
```

| Clé | Défaut | Description |
|-----|--------|-------------|
| `require_2fa` | `false` | Active le 2FA TOTP pour tous les utilisateurs |
| `hashcat_force` | `true` | Ajoute `--force` aux commandes hashcat |
| `max_concurrent_jobs` | `3` | Limite de jobs simultanés |
| `max_upload_mb` | `50` | Taille max des uploads |
| `session_timeout_minutes` | `60` | Déconnexion après X minutes d'inactivité |

Tous les changements de config sont **appliqués à chaud** depuis `/admin/config` sans redémarrage du service.

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `FLASK_DEBUG` | `0` | Mode debug Flask si `1` |
| `DB_PATH` | `instance/samebreaker.db` | Chemin base SQLite |
| `HASHCAT_PATH` | `hashcat` | Fallback si hashcat hors PATH |
| `HOME` | (via systemd) | Overridé par `instance/` pour isoler hashcat |
| `XDG_DATA_HOME` | (via systemd) | Redirige les sessions hashcat vers `instance/.local/share/` |
| `XDG_CACHE_HOME` | (via systemd) | Redirige le cache kernels hashcat vers `instance/.cache/` |

---

## 2FA TOTP ![](img/Emote-gura3.png)

### Activation

Dans `instance/config.json`, passer `require_2fa` à `true` et redémarrer :

```json
{ "require_2fa": true, ... }
```

Ou via `/admin/config` (appliqué à chaud).

### Flux pour les utilisateurs

1. Connexion avec identifiant + mot de passe
2. **Première connexion après activation :**
   - Redirection vers `/2fa/setup` → QR code (Google Authenticator, Aegis, Bitwarden…)
   - Scan + code 6 chiffres → secret sauvegardé en BDD, session ouverte
3. **Connexions suivantes :** `/2fa/verify` → code TOTP requis

### Gestion admin

- Colonne **2FA** dans `/admin/users` : `✓ actif`, `en attente`, `désactivé`
- **Reset 2FA** : force la reconfiguration (perte ou changement d'appareil)

### Sécurité TOTP

| Propriété | Valeur |
|-----------|--------|
| Algorithme | RFC 6238 TOTP (HMAC-SHA1) |
| Période | 30 secondes |
| Drift horaire toléré | ±30 secondes (`valid_window=1`) |
| Secret | Base32, 32 octets aléatoires (`pyotp.random_base32()`) |

---

## Déploiement ![](img/Emote-gura13.png)

### Production (recommandé — nginx + systemd)

```bash
sudo bash setup_hashcat.sh       # drivers GPU + wordlists
sudo bash setup.sh               # app + nginx + HTTPS
```

### Développement

```bash
FLASK_DEBUG=1 python run.py
# → http://localhost:6660
```

### Mise à jour

```bash
sudo bash /opt/samebreaker/setup.sh --update
```

### Données persistées

| Chemin | Contenu | Gitignored |
|--------|---------|-----------|
| `instance/config.json` | SECRET_KEY + config runtime | ✅ |
| `instance/samebreaker.db` | BDD complète | ✅ |
| `instance/jobs/` | Hash files, logs, pot files, restore files | ✅ |
| `instance/wordlists/` | Liens symboliques vers wordlists + uploads | ✅ |
| `instance/.local/share/hashcat/sessions/` | Sessions hashcat (restore) | ✅ |
| `instance/.cache/hashcat/kernels/` | Kernels GPU compilés | ✅ |
| `instance/rootCA.pem` | CA mkcert (distribution aux clients) | ✅ |

### Service systemd

```bash
systemctl status  samebreaker
systemctl restart samebreaker
journalctl -u samebreaker -f        # logs live
systemctl status nginx               # reverse proxy TLS
```

---

## Changelog

### v1.2.0 (2026-07-03)

**Nouvelles fonctionnalités**
- HTTPS via nginx reverse proxy + mkcert (CA de confiance locale, auto-signé en fallback)
- Soft-delete jobs : masquage du dashboard (`/attack/<id>/hide`) tout en conservant l'entrée dans l'audit admin
- Pages d'erreur custom (400 / 403 / 404 / 413 / 429 / 500 + CSRFError) avec handler centralisé

**Corrections de bugs**
- Race condition `stop_job` : le thread `_run()` ne réécrit plus `status='failed'` par-dessus un `'stopped'` posé manuellement
- `resume_job` déclenche maintenant les webhooks `password_found` et `job_done` (manquants depuis v1.0.0)
- Upload wordlist utilisait un chemin relatif (`instance/wordlists/`) — migré vers `current_app.instance_path`
- Fix Jinja2 `map(attribute='__str__')` sur `job_detail.html` : les résultats étaient des objets méthode non sérialisables en JSON
- Fix CSRF manquant sur le formulaire "masquer job" dans `dashboard.html` (400 Bad Request)

**Nettoyage**
- `get_db()` supprimé de `db.py` (jamais utilisé, remplacé par `db_conn()`)
- Alias `_TERMINAL_STATUSES` supprimé de `jobs.py`
- Migrations orphelines `webhook_url`/`webhook_events` supprimées (colonnes legacy de la table `users`)
- Query `profile` simplifiée (ne sélectionne plus les colonnes legacy)
- Scripts d'install (`setup.sh`, `setup_hashcat.sh`) : variables configurables, options CLI, résumé final

**Infrastructure**
- nginx : redirect HTTP→HTTPS, proxy SSE sans buffering (`proxy_buffering off`), timeout 600 s
- systemd : `XDG_DATA_HOME` + `XDG_CACHE_HOME` pour isoler hashcat dans `instance/`
- setup.sh : écriture de la config nginx via Python (`pathlib`) pour éviter l'expansion des variables shell

### v1.1.0
- Benchmark, webhooks Discord/HTTP, 2FA TOTP, workload profiles, détection hash (name-that-hash), reprise de job, upload wordlist, responsive sidebar, rate limiting sur detect API

### v1.0.0
- Release initiale

---

## Conventions de code ![](img/Emote-gura6.png)

- `from __future__ import annotations` dans chaque module
- Toutes les fonctions typées (`def f(x: int) -> Optional[str]`)
- Accès SQLite exclusivement via `with db_conn() as conn:`
- Constantes de statut centralisées dans `jobs.py` (`STATUS_*`, `TERMINAL_STATUSES`)
- Valeurs autorisées via `frozenset` (`_ALLOWED_ROLES`, `_ALLOWED_WORKLOADS`, etc.)
- Exceptions spécifiques uniquement — pas de `except Exception: pass`
- Variables configurables propagées au niveau module (`HASHCAT_FORCE`, `MAX_CONCURRENT_JOBS`)
- Boutons UI unifiés via classes `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-success`, `.btn-warn`
