# SameBreaker — Documentation technique ![](img/gura.png)

> *Ver 1.0.0*

---

## Architecture générale ![](img/Emote-gura8.png)

SameBreaker est une application **Flask** structurée en **Application Factory** (`create_app()`), avec authentification via **Flask-Login**, protection CSRF via **Flask-WTF**, et persistance via **SQLite** (accès par context manager `db_conn()`).

```
Navigateur
    │  HTTP / SSE
    ▼
Flask (run.py → create_app())
    ├── Blueprint auth   — /login, /logout
    ├── Blueprint main   — /, /attack/*, /api/*, /benchmark, /profile, /system
    └── Blueprint admin  — /admin/users/*, /admin/jobs
            │
            ▼
    SQLite (instance/samebreaker.db)
    hashcat subprocess (Popen + threading)
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
| `totp_secret` | TEXT | Réservé 2FA (non implémenté) |
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

**Pattern d'accès :**
```python
with db_conn() as conn:
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
```

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

**Classe `RateLimiter`** — compteur glissant par clé (IP), thread-safe, réutilisable :
```python
class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: int): ...
    def is_limited(self, key: str) -> bool: ...
```
Instanciée dans `auth.py` (`_login_limiter`, 10/5 min) et `main.py` (`_detect_limiter`, 30/min).

| Route | Description |
|-------|-------------|
| `/login` | Identifiant + mot de passe. Si `REQUIRE_2FA` : redirige vers `/2fa/verify` ou `/2fa/setup` |
| `/2fa/setup` | GET : QR code + clé manuelle. POST : vérifie code, sauvegarde secret, connecte l'utilisateur |
| `/2fa/verify` | GET : formulaire TOTP. POST : vérifie code → connexion |
| `/logout` | POST uniquement. Nettoie la session 2FA (`_2fa_pending_user_id`) |

**Flux 2FA :**
```
login (mdp OK) → REQUIRE_2FA ?
  ├─ oui + totp_secret défini  → /2fa/verify  → code OK → login_user()
  ├─ oui + pas de totp_secret  → /2fa/setup   → QR + code OK → UPDATE users SET totp_secret=? → login_user()
  └─ non                       → login_user() direct
```

**Protection drift horaire :** `pyotp.TOTP.verify(code, valid_window=1)` accepte ±30 secondes.

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
| `get_job(job_id)` | Fetch une row depuis BDD |
| `list_jobs(user_id)` | Liste tous les jobs (admin) ou ceux d'un user |
| `get_results(job)` | Lit le pot file — retourne `list[str]` |

**Thread-safety :** toutes les opérations sur `_procs` (dict PID → process) sont protégées par `_procs_lock`.

**Limite de jobs simultanés :**
```python
if _running_count() >= MAX_CONCURRENT_JOBS:
    return False  # job créé mais non démarré (status = pending)
```

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

---

### `app/main.py`

Blueprint principal — routes utilisateur + API.

**Sécurité des inputs (POST `/attack/new`) :**

| Champ | Validation |
|-------|-----------|
| `hash_type` | `int >= 0` |
| `attack_mode` | Dans `_ALLOWED_ATTACK_MODES` (frozenset) |
| `workload` | Dans `{1,2,3,4}` (admin uniquement, sinon profil user) |
| `wordlist` | `_is_safe_path()` contre `WORDLIST_DIRS` |
| `rules` | `_is_safe_path()` contre `_RULES_DIRS` |
| `devices` | Revalidés contre les IDs autorisés du user |
| `extra_args` | Admin uniquement |

**Pré-remplissage (`?from_job=<id>`) :**
```python
prefill_job = job_mgr.get_job(int(from_job_id))
if prefill_job and _can_access_job(prefill_job):
    prefill = dict(prefill_job)
```
Le dict est passé en `{{ prefill | tojson }}` au template, qui initialise le formulaire via JS.

**Gestion du retour de `start_job()` :**
```python
started = job_mgr.start_job(job_id)
if started:
    flash(f"Job #{job_id} lancé.", "success")
else:
    flash(f"Job #{job_id} en attente — limite de {MAX_CONCURRENT_JOBS} atteinte.", "warn")
```

---

### `app/admin.py`

Gestion des utilisateurs + audit log (admin uniquement).

| Route | Description |
|-------|-------------|
| `/admin/users` | Liste des utilisateurs (avec statut 2FA si activé) |
| `/admin/users/new` | Création d'utilisateur |
| `/admin/users/<id>/edit` | Modification (username, mdp, rôle, GPU, workload) |
| `/admin/users/<id>/delete` | Suppression (sauf soi-même) |
| `/admin/users/<id>/reset-2fa` | Réinitialise le secret TOTP — l'utilisateur devra le reconfigurer |
| `/admin/jobs` | Audit log — tous les jobs avec `LEFT JOIN users` |

**Validation centralisée :**
```python
def _validate_user_form(username, password, role, workload, require_password) -> Optional[str]
```

**Exceptions spécifiques :** `sqlite3.IntegrityError` (username dupliqué) et `sqlite3.OperationalError` (BDD), jamais `except Exception`.

---

### `app/__init__.py`

Factory Flask.

**Séquence de démarrage :**
```
create_app()
    → _load_instance_config(app)   # lit/génère SECRET_KEY, propage HASHCAT_FORCE + MAX_CONCURRENT_JOBS
                                   # configure REQUIRE_2FA, SESSION_PERMANENT + PERMANENT_SESSION_LIFETIME
    → init_db()                    # crée les tables + migrations
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

**Session idle timeout :**
- `PERMANENT_SESSION_LIFETIME = timedelta(minutes=session_timeout_minutes)` (défaut : 60 min)
- `@before_request` : `session.modified = True` — chaque requête refresh le TTL de la session
- Résultat : déconnexion automatique après `session_timeout_minutes` d'inactivité

**Context processor :**
```python
# Injecté dans tous les templates
{"running_jobs_count": <int>}  # utilisé pour le badge sidebar
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
| Compte sans 2FA configuré | Si `REQUIRE_2FA` actif : redirigé vers setup obligatoire avant connexion |
| Session idle | `PERMANENT_SESSION_LIFETIME` + refresh `session.modified` à chaque requête |
| Path traversal | `_is_safe_path()` via `os.path.realpath()` |
| Injection SQL | Paramètres liés (`?`) systématiquement |
| Accès inter-users | `_can_access_job()` vérifie `created_by == user.id` |
| Élévation de rôle | `admin_required` decorator sur toutes les routes admin |
| Extra args arbitraires | Réservés aux admins (template + serveur) |
| Devices non autorisés | Revalidation côté serveur des IDs sélectionnés |
| Upload malveillant | `secure_filename()` + `MAX_CONTENT_LENGTH = 50 MB` |
| Mot de passe par défaut | Bannière persistante + flag `must_change_password` |
| Clickjacking / sniffing / transport | X-Frame-Options DENY, X-Content-Type-Options, HSTS via `@after_request` |
| Thread-safety | `_procs_lock` protège toutes les opérations sur le dict des processus |

---

## Configuration runtime ![](img/Emote-gura13.png)

### `instance/config.json`

```json
{
  "secret_key": "...",
  "require_2fa": false,
  "max_upload_mb": 50,
  "hashcat_force": true,
  "max_concurrent_jobs": 5,
  "session_timeout_minutes": 60
}
```

| Clé | Défaut | Description |
|-----|--------|-------------|
| `require_2fa` | `false` | Active le 2FA TOTP pour tous les utilisateurs |
| `hashcat_force` | `true` | Ajoute `--force` aux commandes hashcat |
| `max_concurrent_jobs` | `5` | Limite de jobs simultanés |
| `max_upload_mb` | `50` | Taille max des uploads |
| `session_timeout_minutes` | `60` | Déconnexion après X minutes d'inactivité |

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `FLASK_DEBUG` | `0` | Mode debug Flask si `1` |
| `DB_PATH` | `instance/samebreaker.db` | Chemin base SQLite |
| `HASHCAT_PATH` | `hashcat` | Fallback si hashcat hors PATH |

---

## 2FA TOTP ![](img/Emote-gura3.png)

### Activation

Dans `instance/config.json`, passer `require_2fa` à `true` et redémarrer le serveur :

```json
{
  "require_2fa": true,
  ...
}
```

### Flux pour les utilisateurs

1. L'utilisateur se connecte avec son identifiant + mot de passe
2. **Première connexion après activation :**
   - Redirection vers `/2fa/setup`
   - QR code affiché (compatible Google Authenticator, Authy, Bitwarden…)
   - L'utilisateur scanne, entre le code à 6 chiffres pour confirmer
   - Le secret est sauvegardé en BDD (`totp_secret`), la session démarre
3. **Connexions suivantes :**
   - Redirection vers `/2fa/verify` après le mot de passe
   - Code TOTP requis pour accéder à l'application

### Gestion admin

- La colonne **2FA** dans `/admin/users` indique : `✓ actif`, `en attente` ou `désactivé`
- Le bouton **Reset 2FA** force un utilisateur à reconfigurer son authentificateur (perte ou changement d'appareil)
- Un admin peut désactiver le 2FA globalement en repassant `require_2fa` à `false` dans `config.json`

### Sécurité TOTP

| Propriété | Valeur |
|-----------|--------|
| Algorithme | RFC 6238 TOTP (HMAC-SHA1) |
| Période | 30 secondes |
| Drift horaire toléré | ±30 secondes (`valid_window=1`) |
| Longueur du code | 6 chiffres |
| Secret | Base32, 32 octets aléatoires (`pyotp.random_base32()`) |
| Stockage | Champ `totp_secret` dans `users` (texte, BDD SQLite chiffrée recommandée en prod) |

### QR Code

Généré côté client via la bibliothèque [qrcode.js](https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js) depuis l'URI de provisionnement `otpauth://totp/...`. Aucune dépendance serveur Python (pas de Pillow).

---

## Déploiement ![](img/Emote-gura18.png)

### Développement

```bash
FLASK_DEBUG=1 python run.py
```

### Production (Gunicorn)

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:6660 "app:create_app()"
```

> **Note :** utiliser `-w 1` — le benchmark et les jobs utilisent des variables globales en mémoire (`_bm_proc`, `_procs`) qui ne sont pas partagées entre workers.

### Données persistées

| Chemin | Contenu | Gitignored |
|--------|---------|-----------|
| `instance/config.json` | SECRET_KEY + config | ✅ |
| `instance/samebreaker.db` | BDD complète | ✅ |
| `instance/jobs/` | Hash files, logs, pot files, restore files | ✅ |
| `instance/wordlists/` | Wordlists uploadées | ✅ |

---

## Conventions de code ![](img/Emote-gura6.png)

- `from __future__ import annotations` dans chaque module
- Toutes les fonctions typées (`def f(x: int) -> Optional[str]`)
- Accès SQLite exclusivement via `with db_conn() as conn:`
- Constantes de statut centralisées dans `jobs.py` (`STATUS_*`, `TERMINAL_STATUSES`)
- Valeurs autorisées via `frozenset` (`_ALLOWED_ROLES`, `_ALLOWED_WORKLOADS`, etc.)
- Patterns regex compilés en constantes de module
- Exceptions spécifiques uniquement — pas de `except Exception: pass`
- Variables configurables propagées au niveau module (`HASHCAT_FORCE`, `MAX_CONCURRENT_JOBS`)
- Boutons UI unifiés via classes `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-success`, `.btn-warn` dans `base.html`
