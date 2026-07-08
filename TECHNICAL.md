# SameBreaker — Documentation Technique

Interface web multi-utilisateurs pour hashcat | v1.3.0 | By DumShark-UwU

Pipeline de cassage de hash avec gestion de jobs, supervision GPU en temps réel, streaming SSE, 2FA TOTP, bibliothèque de ressources et webhooks multi-services.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture des modules](#2-architecture-des-modules)
3. [Schéma de base de données](#3-schéma-de-base-de-données)
4. [Cycle de vie d'un job](#4-cycle-de-vie-dun-job)
5. [Parseur hashcat -I](#5-parseur-hashcat--i)
6. [Streaming SSE](#6-streaming-sse)
7. [Authentification & 2FA](#7-authentification--2fa)
8. [Rate limiting](#8-rate-limiting)
9. [Webhooks](#9-webhooks)
10. [Bibliothèque de ressources](#10-bibliothèque-de-ressources)
11. [Métriques système](#11-métriques-système)
12. [Sécurité](#12-sécurité)
13. [Configuration](#13-configuration)
14. [Déploiement production](#14-déploiement-production)
15. [Flux de données complet](#15-flux-de-données-complet)
16. [Dépendances](#16-dépendances)
17. [Changelog](#17-changelog)

---

## 1. Vue d'ensemble

SameBreaker est une interface web Flask multi-utilisateurs pour piloter hashcat depuis un navigateur. Il orchestre des processus hashcat en arrière-plan via des threads Python, streame leur sortie en temps réel par SSE, et notifie via webhooks à chaque crack détecté.

### Architecture globale

```
Browser ──HTTP/SSE──► Flask (Gunicorn -w 1)
                              │
                    ┌─────────┼──────────────┬──────────────┐
                    ▼         ▼              ▼              ▼
                 SQLite   hashcat         Webhooks       Bibliothèque
               (jobs,    subprocess     (Discord /      (téléchargement
               users,    (threads)       Slack /         urllib, extraction
               webhooks)                 Teams /         7z/tarfile/gzip)
                                         ntfy /
                                         Signal)
```

### Couches logiques

| Couche | Modules | Rôle |
|--------|---------|------|
| Entrée HTTP | `auth.py`, `main.py`, `admin.py`, `library.py` | Blueprints Flask, CSRF, `@login_required` |
| Modèles | `models.py` | `User` (Flask-Login) |
| Persistance | `db.py` | `db_conn()`, `init_db()`, migrations idempotentes |
| Jobs | `jobs.py` | Cycle de vie hashcat, threading, polling pot, webhooks |
| Utilitaires | `hashcat_utils.py` | Détection devices, parsing `-I`, construction commande |
| Notifications | `notify.py` | Payloads et envoi webhooks multi-services |
| Bibliothèque | `library.py` | Catalogue, téléchargement streamé, extraction multi-format |
| Application | `__init__.py` | `create_app()`, config, security headers |

---

## 2. Architecture des modules

### `app/__init__.py` — Factory Flask

`create_app()` est le point d'entrée. Ordre d'initialisation :

1. Flask-Login (`login_view = "auth.login"`) + Flask-WTF CSRF
2. `_load_instance_config()` : charge `instance/config.json`, génère `SECRET_KEY` si absente, propage les settings vers `jobs.py` et `hashcat_utils.py`
3. `init_db()` → `reset_stale_jobs()` → `seed_default_admin()`
4. Enregistrement des 3 blueprints (`auth`, `main`, `admin`)
5. `@before_request` : `session.modified = True` (rafraîchit le TTL idle timeout)
6. `@after_request` : injection des security headers
7. Gestionnaires d'erreur 400 / 403 / 404 / 413 / 429 / 500 / CSRFError

**`_load_instance_config(app)`**

Lit `instance/config.json`. Si `secret_key` est absent, génère via `secrets.token_hex(32)` et l'écrit immédiatement. Propage `hashcat_force` et `max_concurrent_jobs` vers les modules concernés — le rechargement depuis `/admin/config` rappelle cette fonction pour appliquer à chaud sans redémarrage.

---

### `app/db.py` — Base de données

**`db_conn()`** — context manager SQLite. Ouvre une connexion, yield, ferme. `row_factory = sqlite3.Row` pour l'accès par nom de colonne.

**`init_db()`** — crée les tables (`users`, `jobs`, `webhooks`) via `CREATE TABLE IF NOT EXISTS`, puis appelle `_run_migrations()`.

**`_run_migrations(conn)`** — liste de triplets `(table, colonne, définition)`. Chaque `ALTER TABLE ADD COLUMN` est enveloppé dans un `try/except OperationalError` : si la colonne existe déjà, l'erreur est silencieusement ignorée. Garantit la compatibilité descendante sans système de migration lourd.

**`reset_stale_jobs()`** — au démarrage, tous les jobs en statut `running` sont passés à `failed`. Un message est ajouté dans leur log file. Gère le cas du crash serveur.

**`seed_default_admin()`** — crée `admin/admin` (avec `must_change_password=1`) uniquement si la table `users` est vide.

---

### `app/models.py` — Modèle utilisateur

```python
class User(UserMixin):
    def __init__(self, id, username, role, allowed_devices,
                 workload_profile, must_change_password): ...

    @staticmethod
    def get(user_id: int) -> Optional["User"]: ...

    @staticmethod
    def get_by_username(username: str) -> Optional[sqlite3.Row]: ...
```

Pas d'ORM — accès SQLite direct via `db_conn()`. `allowed_devices` est une chaîne `"1,2,3"` filtrée à l'affichage des GPU disponibles.

---

### `app/auth.py` — Authentification

Blueprint sans préfixe. Routes : `/login`, `/logout`, `/2fa/setup`, `/2fa/verify`.

**`RateLimiter`** — compteur glissant par IP avec `threading.Lock`. 10 tentatives de login / 5 min.

**Flux 2FA :**

```
POST /login → credentials OK
  │
  ├─[REQUIRE_2FA = False]─────────────────► login_user() → /
  │
  └─[REQUIRE_2FA = True]
       │
       ├─[totp_secret NULL]──► session["_2fa_pending_user_id"]
       │                          → /2fa/setup
       │                          GET : génère secret Base32, affiche QR
       │                          POST : vérifie code → stocke secret → login_user()
       │
       └─[totp_secret SET]───► session["_2fa_pending_user_id"]
                                  → /2fa/verify
                                  POST : vérifie code → login_user()
```

`valid_window=1` dans pyotp accepte le code précédent et suivant (±30 secondes) pour compenser la dérive d'horloge.

---

### `app/jobs.py` — Cycle de vie des jobs

Voir section [4. Cycle de vie d'un job](#4-cycle-de-vie-dun-job).

Variables module-level :

```python
_procs: dict[int, subprocess.Popen] = {}   # job_id → processus hashcat
_procs_lock = threading.Lock()             # protège _procs
MAX_CONCURRENT_JOBS: int = 5               # configurable via config.json
```

---

### `app/hashcat_utils.py` — Utilitaires hashcat

Voir section [5. Parseur hashcat -I](#5-parseur-hashcat--i).

`build_command(job)` construit la liste d'arguments hashcat selon le mode d'attaque :

| Mode | Arguments positionnels |
|------|----------------------|
| 0 | `hash_file wordlist` |
| 1 | `hash_file wordlist1 wordlist2` |
| 3 | `hash_file mask` |
| 6 | `hash_file wordlist mask` |
| 7 | `hash_file mask wordlist` |

---

### `app/notify.py` — Webhooks

Payloads Discord-compatible. Envoi via `urllib.request` (zéro dépendance externe).

Voir section [9. Webhooks](#9-webhooks).

---

### `app/main.py` — Routes principales

Blueprint `/`. Points notables :

- **Upload hash file / wordlist** : chemins absolus via `current_app.instance_path` (`instance/jobs/` et `instance/wordlists/`). `secure_filename` + filtre d'extension.
- **Rate limiting détection** : `_detect_limiter` — 30 requêtes / 5 min par IP sur `POST /api/detect`.
- **SSE jobs** : `GET /api/jobs/<id>/stream` — poll `readline()` sur le log file toutes les 500 ms, envoie `[DONE]` quand le job atteint un statut terminal.
- **SSE benchmark** : `GET /api/benchmark/stream` — poll sur `_bm_output` (liste en mémoire) depuis un offset mémorisé.
- **Résultats** : lecture du `.pot` file via `get_results(job)`.

---

### `app/admin.py` — Administration

Blueprint `/admin`. Toutes les routes protégées par `@admin_required` (vérifie `current_user.role == "admin"`).

- CRUD utilisateurs (create, edit, delete, reset-2fa)
- Audit log — vue de tous les jobs de tous les utilisateurs
- Éditeur `config.json` — lit/écrit `instance/config.json` et recharge à chaud via `_load_instance_config()`

---

## 3. Schéma de base de données

### Table `users`

```sql
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT    NOT NULL UNIQUE,
    password             TEXT    NOT NULL,                    -- PBKDF2-SHA256 (Werkzeug)
    role                 TEXT    NOT NULL DEFAULT 'user',     -- 'user' | 'admin'
    allowed_devices      TEXT    NOT NULL DEFAULT '',         -- ex: "1,2,3"
    workload_profile     INTEGER NOT NULL DEFAULT 2,          -- profil hashcat -w (1-4)
    totp_secret          TEXT,                                -- Base32 TOTP (NULL = non configuré)
    must_change_password INTEGER NOT NULL DEFAULT 0,          -- 1 = bannière warning affichée
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table `jobs`

```sql
CREATE TABLE IF NOT EXISTS jobs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'pending',    -- pending|running|completed|failed|stopped
    hash_type      INTEGER,                               -- code hashcat (-m)
    hash_type_name TEXT,
    attack_mode    INTEGER NOT NULL DEFAULT 0,            -- 0|1|3|6|7
    hash_file      TEXT,                                  -- instance/jobs/<id>.hash
    wordlist       TEXT,
    mask           TEXT,
    rules          TEXT,
    devices        TEXT,                                  -- ex: "1,2" (IDs GPU)
    extra_args     TEXT,                                  -- args hashcat libres (admin uniquement)
    log_file       TEXT,                                  -- instance/jobs/<id>.log
    pot_file       TEXT,                                  -- instance/jobs/<id>.pot
    workload       INTEGER DEFAULT 2,                     -- profil -w (1=light, 4=nightmare)
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at     DATETIME,
    finished_at    DATETIME,
    created_by     INTEGER REFERENCES users(id),
    pid            INTEGER,                               -- PID du processus hashcat
    hidden         INTEGER NOT NULL DEFAULT 0,            -- soft-delete
    hidden_at      DATETIME,
    hidden_by      INTEGER
);
```

### Table `webhooks`

```sql
CREATE TABLE IF NOT EXISTS webhooks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT    NOT NULL DEFAULT '',
    url          TEXT    NOT NULL,
    events       TEXT    NOT NULL DEFAULT '',             -- ex: "password_found,job_done"
    webhook_type TEXT    NOT NULL DEFAULT 'auto',         -- discord|slack|teams|ntfy|signal|generic|auto
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. Cycle de vie d'un job

### Transitions de statut

```
            create_job()
                │
                ▼
           [pending]
                │
           start_job()
                │
          ┌─────▼──────┐
          │  [running]  │◄── resume_job() ────────────────┐
          └─────┬───────┘                                 │
                │                                         │
      ┌─────────┼──────────┐                        [stopped]
      ▼         ▼          ▼                              │
[completed] [failed]   stop_job()──────────────────► [stopped]
```

| Transition | Déclencheur |
|------------|-------------|
| `pending` → `running` | `start_job()` ou `resume_job()` (sous réserve de `MAX_CONCURRENT_JOBS`) |
| `running` → `completed` | hashcat retourne code `0` ou `1` (`_HASHCAT_OK_CODES`) |
| `running` → `failed` | Autre code retour, `FileNotFoundError`, `OSError` |
| `running` → `stopped` | `stop_job()` : `proc.terminate()` (SIGTERM) + UPDATE immédiat en BDD |
| `stopped` → `running` | `resume_job()` : `hashcat --restore --restore-file-path <id>.restore` |
| `running` → `failed` | `reset_stale_jobs()` au démarrage (recovery crash) |

### Race condition stop → failed

Quand `stop_job()` envoie SIGTERM, hashcat sort avec un code non-nul, ce qui ferait transiter le statut vers `failed` dans le thread `_run()`. Fix : avant l'UPDATE final, vérification du statut courant en BDD :

```python
with db_conn() as conn:
    current = conn.execute(
        "SELECT status FROM jobs WHERE id=?", (job_id,)
    ).fetchone()
    if not current or current["status"] != STATUS_STOPPED:
        conn.execute(
            "UPDATE jobs SET status=?, finished_at=? WHERE id=?",
            (status, datetime.utcnow(), job_id),
        )
        conn.commit()
```

Si le statut est déjà `stopped` (positionné par `stop_job()`), le thread n'écrase pas.

### Fichiers par job

| Fichier | Path | Cycle |
|---------|------|-------|
| Hash file | `instance/jobs/<id>.hash` | Créé à `create_job()`, supprimé à la fin de `_run()` |
| Log file | `instance/jobs/<id>.log` | Créé au lancement, streamé en SSE, appendé à la reprise |
| Pot file | `instance/jobs/<id>.pot` | Créé par hashcat, lu par `get_results()` et le polling webhook |
| Restore file | `instance/jobs/<id>.restore` | Créé par hashcat, requis pour `resume_job()` |

### Polling pot pendant l'exécution

Toutes les 100 lignes de log, `_poll_pot(pot_seen)` compare le contenu du `.pot` avec l'ensemble `pot_seen` (déjà vu). Les nouvelles lignes déclenchent un webhook `password_found`. Évite la duplication de notifications en cas de reprise.

---

## 5. Parseur hashcat -I

`hashcat -I` liste les devices disponibles. Son format mélange des sections CUDA et OpenCL, dont des headers de plateforme qui peuvent contaminer un parsing naïf.

### Exemple de sortie problématique

```
CUDA Info:
==========

Backend Device ID #8
  Name...........: NVIDIA GeForce GTX 1660 SUPER   ← correct en mémoire

OpenCL Info:
============

OpenCL Platform ID #1
  Name....: NVIDIA CUDA                             ← 4 points, regex naïve matchait ici
                                                       et écrasait le nom du device #8

  OpenCL Device ID #1 (platform #1 device #0)
    Name.........: NVIDIA GeForce GTX 1660 SUPER    ← ≥5 points — device légitime
    Type.........: GPU
```

La regex naïve `r"\s*Name\.*:\s*(.+)"` matchait `Name....: NVIDIA CUDA` (4 points) et écrasait le nom du device #8 avec la plateforme OpenCL suivante (`"Portable Computing Language"`).

### Solution — double protection

```python
_DEVICE_ID_PATTERN   = re.compile(r"\s*Backend Device ID #(\d+)")
_DEVICE_NAME_PATTERN = re.compile(r"\s*Name\.{5,}:\s*(.+)")   # ≥ 5 points
_DEVICE_TYPE_PATTERN = re.compile(r"\s*Type\.{5,}:\s*(.+)")   # ≥ 5 points
_SECTION_PATTERN     = re.compile(r"^[A-Za-z]")               # début de ligne sans indentation
```

**Logique du parseur :**

1. `_SECTION_PATTERN` : toute ligne commençant par une lettre sans indentation est un header de section (`CUDA Info:`, `OpenCL Info:`, etc.) → clôture le device courant, remet le contexte à zéro.
2. `\.{5,}` : requiert au minimum 5 points. `Name....:` (4 points, format plateforme) est ignoré ; `Name........:` (≥5 points, format device) est capturé.
3. Filtrage final des CPUs : `[d for d in devices if d.get("type", "").upper() != "CPU"]`.

---

## 6. Streaming SSE

Les logs de job et le benchmark utilisent Server-Sent Events (SSE) pour pousser les données sans polling JS.

### Format du protocole

```
data: <ligne de texte>\n\n
data: [DONE]\n\n
```

### Jobs — `/api/jobs/<id>/stream`

```python
def _generate():
    with open(log_file, "r") as f:
        while True:
            line = f.readline()
            if line:
                yield f"data: {line.rstrip()}\n\n"
            else:
                if job_status in TERMINAL_STATUSES:
                    yield "data: [DONE]\n\n"
                    return
                time.sleep(0.5)
```

Le générateur poll le fichier log toutes les 500 ms. Quand le job atteint un statut terminal et qu'il n'y a plus de nouvelles lignes, il envoie `[DONE]` et se ferme proprement.

### Benchmark — `/api/benchmark/stream`

Le benchmark écrit dans `_bm_output` (liste Python en mémoire partagée). Le stream envoie les nouvelles lignes depuis un offset mémorisé, sans accès fichier.

### Configuration nginx

Pour les SSE derrière un reverse proxy nginx, désactiver le buffering :

```nginx
proxy_buffering off;
proxy_cache off;
proxy_read_timeout 3600;
```

---

## 7. Authentification & 2FA

**Sessions** : cookie signé (HMAC avec `SECRET_KEY`). Durée = `PERMANENT_SESSION_LIFETIME` (défaut 60 min). Chaque requête authentifiée appelle `session.modified = True` pour remettre à zéro le compteur d'inactivité (idle timeout).

**Mots de passe** : `werkzeug.security.generate_password_hash` / `check_password_hash` — PBKDF2-SHA256 avec sel aléatoire par hash.

**TOTP** : `pyotp.random_base32()` pour la génération du secret. Provisioning URI compatible Google Authenticator, Authy, Bitwarden. `valid_window=1` = ±30 secondes de dérive d'horloge acceptée.

### Flux complet 2FA

```
POST /login → credentials OK
  │
  ├─[REQUIRE_2FA = False]──────────────────────────► login_user() → /
  │
  └─[REQUIRE_2FA = True]
       │
       ├─[totp_secret NULL]──► session["_2fa_pending_user_id"] = id
       │                           ↓
       │                       GET /2fa/setup
       │                           génère secret Base32 (session["_2fa_temp_secret"])
       │                           affiche QR code (provisioning_uri)
       │                           ↓
       │                       POST /2fa/setup
       │                           pyotp.TOTP(secret).verify(code, valid_window=1)
       │                           → UPDATE users SET totp_secret = secret
       │                           → login_user() → /
       │
       └─[totp_secret SET]───► session["_2fa_pending_user_id"] = id
                                   ↓
                               POST /2fa/verify
                                   pyotp.TOTP(totp_secret).verify(code, valid_window=1)
                                   → login_user() → /
```

**Auto-gestion depuis `/profile`** : chaque utilisateur peut activer, reconfigurer ou désactiver son propre 2FA. La désactivation est bloquée si `require_2fa = true` dans la config.

**Reset admin** : `/admin/users/<id>/reset-2fa` vide `totp_secret` en BDD, forçant une reconfiguration au prochain login.

---

## 8. Rate limiting

Implémentation custom sans dépendance externe (`flask-limiter`, `redis`). Deux instances de `RateLimiter` dans `auth.py` et `main.py`.

```python
class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: int): ...
    def is_limited(self, key: str) -> bool: ...
```

**Fonctionnement** : les timestamps des appels sont stockés par clé (IP). À chaque appel, les timestamps hors fenêtre sont purgés. `threading.Lock` garantit la thread-safety sous Gunicorn `-w 1`.

| Endpoint | Limite | Fenêtre | Clé |
|----------|--------|---------|-----|
| `POST /login` | 10 tentatives | 5 min | IP |
| `POST /api/detect` | 30 requêtes | 5 min | IP |

---

## 9. Webhooks

Envoi via `urllib.request.urlopen` — aucune dépendance externe (`requests` non requis). Le payload interne est toujours au format Discord (`content` + `embeds`) et converti selon le `webhook_type` avant l'envoi.

### Services supportés

| Type | Détection URL automatique | Format envoyé |
|------|--------------------------|---------------|
| `discord` | `discord.com/api/webhooks` | `content` + `embeds` (natif) |
| `slack` | `hooks.slack.com` | `text` + `attachments` |
| `teams` | `webhook.office.com` | MessageCard (`@type`, `sections`, `facts`) |
| `ntfy` | `ntfy.sh` | JSON `message`/`title`/`priority`/`tags` |
| `signal` | `signal.callmebot.com` | GET avec `&text=` en paramètre URL |
| `generic` | (fallback) | `content` + `embeds` (format Discord) |
| `auto` | — | Détection automatique par URL, fallback `generic` |

### Événements

| Événement | Déclencheur | Fréquence |
|-----------|-------------|-----------|
| `password_found` | Nouvelles lignes détectées dans le `.pot` | Toutes les 100 lignes de log |
| `job_done` | Fin du thread `_run()` (completed, failed ou après stop) | Une fois par job |

### Payload interne `job_done` (format Discord, base pour toutes les conversions)

```json
{
  "content": "✅ **MonJob** terminé — 3 mot(s) de passe trouvé(s)",
  "embeds": [{
    "title": "Job #42 — completed",
    "color": 4637912,
    "fields": [
      {"name": "Statut",        "value": "completed", "inline": true},
      {"name": "Mots de passe", "value": "3",         "inline": true}
    ]
  }]
}
```

### Exemple converti Teams (MessageCard)

```json
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "00b4d8",
  "summary": "✅ **MonJob** terminé — 3 mot(s) de passe trouvé(s)",
  "sections": [{
    "activityTitle": "Job #42 — completed",
    "facts": [
      {"name": "Statut",        "value": "completed"},
      {"name": "Mots de passe", "value": "3"}
    ]
  }]
}
```

### Exemple converti Slack

```json
{
  "text": "✅ **MonJob** terminé — 3 mot(s) de passe trouvé(s)",
  "attachments": [{
    "color": "#00b4d8",
    "text": "*Job #42 — completed*",
    "fields": [
      {"title": "Statut",        "value": "completed", "short": true},
      {"title": "Mots de passe", "value": "3",         "short": true}
    ]
  }]
}
```

### Chargement avant thread

Les webhooks (url + events + webhook_type) sont chargés depuis la BDD **avant** le démarrage du thread `_run()`. Cela évite les accès BDD répétés dans la boucle de lecture et garantit que la liste est cohérente pour toute la durée du job.

---

## 10. Bibliothèque de ressources

Blueprint Flask `library_bp` monté sur `/library`. Gère le téléchargement, l'extraction et la suppression de wordlists, règles et masks depuis un catalogue curé.

### Catalogue (`CATALOG`)

Dictionnaire Python statique de 13 entrées. Champs par entrée :

| Champ | Type | Description |
|-------|------|-------------|
| `name` | str | Nom affiché |
| `type` | str | `wordlist` / `rule` / `mask` |
| `rating` | str | S / A / B / C |
| `count` | str | Nombre de mots/règles/patterns |
| `size_dl` | str | Taille compressée |
| `size_raw` | str | Taille après extraction |
| `rate` | float | Crack rate réel (wordlists uniquement, source weakpass.com) |
| `url` | str\|None | URL de téléchargement (None pour les masks générés) |
| `filename` | str | Nom du fichier final extrait |
| `compressed` | str\|None | Nom du fichier compressé (None si pas d'extraction) |
| `extract` | bool | True si extraction nécessaire |
| `generated` | bool | True si généré localement (masks) |
| `masks` | list | Patterns hcmask (masks uniquement) |

### Cycle de téléchargement

```
POST /library/download/<rid>
    │
    ├─ Vérifie statut idle
    ├─ _state[rid] = {status: 'downloading', progress: 0}
    └─ threading.Thread(_download_thread).start()
         │
         ▼
_download_thread()
    ├─ urllib.request : stream → instance/wordlists/.downloads/<filename>
    │   (mise à jour _state.progress toutes les 256 KB)
    ├─ _state = {status: 'extracting'}
    ├─ Extraction selon extension :
    │   ├─ .tar.gz → tarfile (filtre path traversal + flatten)
    │   ├─ .gz     → gzip (stream decompress)
    │   └─ .7z     → subprocess 7z/7za/7zz (auto-détection binaire)
    ├─ dest_dl.unlink() — archive supprimée immédiatement après extraction
    └─ _state = {status: 'ready'}

GET /library/status/<rid>  → polling JSON toutes les 1.5 s (JS)
```

### État thread-safe

`_state` (dict global) + `_state_lock` (`threading.Lock`). Toutes les lectures/écritures sur `_state` sont protégées. Le thread ne touche jamais directement à Flask `current_app` après sa création (context passé en paramètre `app`).

### Destinations

| Type | Dossier |
|------|---------|
| Wordlists | `instance/wordlists/` |
| Règles | `instance/rules/` |
| Masks | `instance/masks/` |

---

## 11. Métriques système

Route `GET /api/sysinfo` dans `main.py`. Retourne un objet JSON sans dépendance externe (pas de `psutil`).

| Métrique | Source | Calcul |
|----------|--------|--------|
| `cpu_pct` | `/proc/loadavg` (load avg 1 min) | `min(100, load1 / cpu_count * 100)` |
| `cpu_load1` | `/proc/loadavg` | première valeur brute |
| `cpu_count` | `os.cpu_count()` | — |
| `ram_pct` | `/proc/meminfo` | `(MemTotal - MemAvailable) / MemTotal * 100` |
| `ram_total_gb` | `/proc/meminfo` (MemTotal kB) | `/1024/1024`, arrondi 1 décimale |
| `ram_used_gb` | `/proc/meminfo` | `MemTotal - MemAvailable` converti |
| `disk_root` | `shutil.disk_usage("/")` | `pct`, `total_gb`, `used_gb`, `free_gb` |

Le front-end (`system.html`) poll `/api/sysinfo` toutes les **4 s** via `setInterval`. Les barres changent de couleur dynamiquement : bleu/vert/amber par défaut → orange ≥70% → rouge ≥90%.

---

## 12. Sécurité

| Mécanisme | Implémentation |
|-----------|---------------|
| CSRF | Flask-WTF `CSRFProtect` — token injecté dans tous les formulaires et vérifié sur chaque POST |
| XSS | Jinja2 auto-escape HTML par défaut |
| Mots de passe | PBKDF2-SHA256 (Werkzeug) — sel aléatoire par hash |
| Sessions | Cookie signé HMAC-SHA1 + idle timeout configurable |
| 2FA | TOTP pyotp — optionnel ou obligatoire via `require_2fa` |
| Rate limiting | Compteur glissant custom par IP (login + détection de hash) |
| Upload | `secure_filename` + filtre d'extension + `MAX_CONTENT_LENGTH` |
| Injection commande | `subprocess.Popen(cmd_list)` sans `shell=True` — pas d'interpolation shell |
| Headers HTTP | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `Strict-Transport-Security` |
| Isolation des données | Un `user` ne voit que ses propres jobs ; seul `admin` accède à l'audit log complet |
| Stockage fichiers | Tout dans `instance/` (gitignored) — pas d'accès URL direct aux fichiers de job |

---

## 13. Configuration

Fichier `instance/config.json` — généré automatiquement au premier démarrage :

```json
{
  "secret_key": "<généré — ne pas modifier>",
  "require_2fa": false,
  "max_upload_mb": 50,
  "hashcat_force": true,
  "max_concurrent_jobs": 5,
  "session_timeout_minutes": 60
}
```

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `secret_key` | string | auto | Clé de signature des sessions Flask. Régénérée si absente. |
| `require_2fa` | bool | `false` | Force le 2FA TOTP pour tous les comptes. |
| `hashcat_force` | bool | `true` | Ajoute `--force` aux commandes hashcat. |
| `max_concurrent_jobs` | int | `5` | Limite de processus hashcat simultanés. |
| `max_upload_mb` | int | `50` | Taille max des uploads. |
| `session_timeout_minutes` | int | `60` | Déconnexion automatique après X minutes d'inactivité. |

Variables d'environnement (prioritaires sur `config.json`) :

| Variable | Défaut | Description |
|----------|--------|-------------|
| `DB_PATH` | `instance/samebreaker.db` | Chemin vers la base SQLite |
| `HASHCAT_PATH` | `hashcat` | Chemin vers le binaire hashcat |
| `FLASK_DEBUG` | `0` | Mode debug Flask si `1` |

---

## 14. Déploiement production

### Gunicorn

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:6660 "app:create_app()"
```

**Impératif : `-w 1` (un seul worker).** `_procs` (dict des processus hashcat actifs) et `_bm_proc` (processus benchmark) sont des variables Python en mémoire. Plusieurs workers Gunicorn ne partagent pas cette mémoire — les jobs deviendraient impossibles à stopper et le benchmark serait invisible entre workers.

### systemd

```ini
[Unit]
Description=SameBreaker
After=network.target

[Service]
User=samebreaker
Group=samebreaker
WorkingDirectory=/opt/samebreaker
ExecStart=/opt/samebreaker/venv/bin/gunicorn -w 1 -b 127.0.0.1:6660 "app:create_app()"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### nginx (reverse proxy)

```nginx
server {
    listen 443 ssl;
    server_name samebreaker.local;

    ssl_certificate     /etc/ssl/certs/samebreaker.crt;
    ssl_certificate_key /etc/ssl/private/samebreaker.key;

    location / {
        proxy_pass http://127.0.0.1:6660;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Requis pour les Server-Sent Events
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600;
    }
}
```

---

## 15. Flux de données complet

```
Utilisateur
    │  POST /attack/new (form multipart)
    ▼
main.py
    ├─ create_job() → INSERT jobs (status=pending)
    │   Écrit hash_file → instance/jobs/<id>.hash
    └─ start_job(job_id)
         ▼
jobs.py: start_job()
    ├─ Vérifie MAX_CONCURRENT_JOBS
    ├─ build_command(job_dict) → [hashcat, -m X, -a Y, hash_file, wordlist, ...]
    ├─ Charge webhooks de l'utilisateur (SELECT webhooks WHERE user_id=?)
    └─ threading.Thread(target=_run).start()
         ▼
jobs.py: _run() [thread background]
    ├─ Popen(cmd) → UPDATE status=running, pid=<pid>
    ├─ Lit stdout ligne par ligne → écrit log_file
    ├─ Toutes les 100 lignes : _poll_pot()
    │   └─ Nouvelles lignes → webhook password_found
    ├─ proc.wait() → status = completed | failed
    ├─ Vérifie status BDD ≠ stopped → UPDATE status, finished_at
    ├─ webhook job_done
    └─ Supprime hash_file

Browser
    │  GET /api/jobs/<id>/stream  (EventSource SSE)
    ▼
main.py: stream SSE
    ├─ readline() sur log_file toutes les 500 ms
    ├─ yield "data: <ligne>\n\n"
    └─ yield "data: [DONE]\n\n" quand statut terminal + EOF

    ▼
UI
    ├─ appendLine() → coloration syntaxique (Speed, ERROR, Device…)
    ├─ Smart auto-scroll (pause si l'utilisateur scrolle manuellement)
    └─ Notification navigateur (Notification API) à la réception de [DONE]
```

---

## 16. Dépendances

| Package | Usage |
|---------|-------|
| `flask` | Framework web, routing, templating Jinja2 |
| `flask-login` | Gestion de session utilisateur (`UserMixin`, `@login_required`) |
| `flask-wtf` | Protection CSRF |
| `werkzeug` | Hash de mots de passe (PBKDF2-SHA256), `secure_filename` |
| `pyotp` | TOTP 2FA — génération et vérification de codes |
| `name_that_hash` | Identification automatique du type de hash |
| `gunicorn` | Serveur WSGI production (`-w 1` impératif) |

Aucune dépendance JS externe — l'UI utilise uniquement Tailwind CSS (CDN) et des EventSource/fetch natifs.

---

## 17. Changelog

| Version | Changements |
|---------|-------------|
| **v1.3.0** | **Bibliothèque** (`library.py` + `/library`) : catalogue 13 ressources, téléchargement streamé urllib, extraction `.7z`/`.tar.gz`/`.gz`, archives supprimées après extraction, état thread-safe, polling JS 1.5 s, crack rate visuel par wordlist. **Métriques système** : `/api/sysinfo` (CPU/RAM/Disk via `/proc`, poll 4 s, barres colorées). **Webhooks multi-services** : `webhook_type` en BDD, conversion Slack/Teams/ntfy/Signal (CallMeBot), détection auto par URL, sélecteur + liens docs dans le profil. **Cap DOM log** 200 éléments. |
| **v1.2.2** | Tooltips CSS sur les boutons de mode d'attaque (descriptions inline au survol, CSS pur, aucune dépendance JS) |
| **v1.2.1** | Fix parseur GPU : `_SECTION_PATTERN` + regex `\.{5,}` corrigeant la corruption du nom device #8 par les headers de plateforme OpenCL ; smart scroll benchmark (auto-scroll désactivable, bouton "Suivre", hauteur 640 px, bouton "Copier tout") |
| **v1.2.0** | Fix race condition stop→failed (vérification statut BDD avant UPDATE final) ; webhooks sur `resume_job` ; refactoring `db.py` (suppression `get_db()`, migrations propres) ; fix upload wordlist (chemin absolu via `instance_path`) ; fix SELECT profil (colonnes supprimées) ; ajout `setup.sh` / `setup_hashcat.sh` |
| **v1.1.0** | Durée live dashboard, tri des colonnes, auto-refresh 30 s, barre de progression + ETA, copier résultats, notification navigateur, compteur de hash live, 2FA auto-gestion depuis profil, éditeur de configuration admin |
| **v1.0.0** | Release initiale — UI Tailwind, multi-user, détection hash auto, streaming SSE, GPU busy, workload chips admin, audit log, filtres dashboard, relancer/reprendre job, badge sidebar, recovery crash, limite jobs simultanés, security headers |
