# SameBreaker ![](img/gura.png)

Interface web multi-utilisateurs pour hashcat — gestion de jobs de cassage de hash, détection automatique de type, supervision GPU en temps réel.

> *サメ！サメ！サメ、サメ！ サメに気をつけろ！* — DumShark-UwU

---

## Fonctionnalités ![](img/Emote-gura8.png)

- **Interface web complète** — dashboard, nouvelle attaque, détail de job, benchmark, profil
- **Multi-utilisateurs** — rôles `admin` / `user`, accès par GPU assigné, workload profile par user
- **Détection automatique de hash** — via `name_that_hash`, déclenchée au collé + bouton manuel, avec compteur de hash live
- **Gestion GPU** — détection live des devices, GPU occupé grisé et non-sélectionnable
- **5 modes d'attaque** — Dictionnaire, Combinateur, Brute-force/Mask, Hybride ×2
- **Streaming de logs en temps réel** — Server-Sent Events directement depuis le fichier log hashcat
- **Barre de progression + ETA** — parsing live du statut hashcat (vitesse, avancement %, temps restant)
- **Dashboard amélioré** — colonne Durée mise à jour chaque seconde, colonnes triables, auto-refresh toutes les 30 s si jobs actifs
- **Filtres dashboard** — filtrage JS par statut (running, completed, failed, stopped, pending)
- **Relancer un job** — pré-remplit le formulaire avec les paramètres d'un job existant
- **Reprendre un job** — reprise via fichier de session hashcat (`--restore-file-path`)
- **Copier les résultats** — bouton par ligne + "Tout copier" via Clipboard API
- **Notification navigateur** — alerte native à la fin d'un job (Notification API)
- **Confirmation d'arrêt** — UI inline, sans dialog navigateur
- **Badge sidebar** — compteur animé des jobs en cours sur le lien Dashboard
- **Audit log** — vue admin de tous les jobs avec utilisateur associé
- **Limite de jobs simultanés** — configurable (`max_concurrent_jobs`, défaut : 5)
- **Recovery au démarrage** — les jobs `running` au crash sont automatiquement marqués `failed`
- **Upload de hash / wordlist** — via formulaire ou fichier
- **Résultats téléchargeables** — export `.txt` des credentials crackés
- **Benchmark** — lancement/arrêt admin, streaming de sortie en live
- **Compte par défaut** — `admin` / `admin` créé automatiquement au premier démarrage
- **Bannière de sécurité** — notification persistante tant que le mot de passe par défaut n'est pas changé
- **2FA TOTP optionnel** — activable via `config.json`, setup QR code à la première connexion, compatible Google Authenticator / Authy / Bitwarden ; auto-gestion depuis le profil utilisateur
- **Éditeur de configuration** — interface web admin (`/admin/config`) pour modifier `config.json` à chaud, sans redémarrage
- **Rate limiting** — 10 tentatives de login / 30 détections de hash par IP sur fenêtre glissante
- **Session idle timeout** — déconnexion automatique après inactivité (configurable, défaut 60 min)
- **CSRF** — protection sur tous les formulaires et endpoints POST
- **Security headers** — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS

---

## Prérequis ![](img/Emote-gura17.png)

```
Python 3.10+
hashcat (dans le PATH ou via HASHCAT_PATH env)
```

Dépendances Python :

```
flask
flask-login
flask-wtf
werkzeug
name_that_hash
```

---

## Installation ![](img/Emote-gura16.png)

```bash
git clone <repo>
cd samebreaker

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## Lancement ![](img/Emote-gura9.png)

```bash
# Démarrage normal
python run.py

# Mode debug
FLASK_DEBUG=1 python run.py
```

L'application démarre sur `http://127.0.0.1:6660`.

Au **premier démarrage**, le compte `admin` / `admin` est créé automatiquement.
Une bannière d'avertissement s'affiche jusqu'à ce que le mot de passe soit changé depuis le profil.

Pour créer un compte admin manuellement (optionnel) :

```bash
python seed_admin.py
```

---

## Rôles et permissions ![](img/Emote-gura11.png)

| Fonctionnalité | `user` | `admin` |
|----------------|--------|---------|
| Voir ses propres jobs | ✅ | ✅ |
| Voir tous les jobs | ❌ | ✅ |
| Lancer une attaque | ✅ | ✅ |
| Relancer / reprendre un job | ✅ | ✅ |
| Choisir ses GPU assignés | ✅ | ✅ (tous) |
| Sélectionner le workload | ❌ (profil fixe) | ✅ (chips) |
| Utiliser `extra_args` | ❌ | ✅ |
| Lancer / arrêter le benchmark | ❌ | ✅ |
| Gérer les utilisateurs | ❌ | ✅ |
| Audit log (tous les jobs) | ❌ | ✅ |
| Éditeur de configuration | ❌ | ✅ |
| Réinitialiser le 2FA d'un user | ❌ | ✅ |

---

## Modes d'attaque ![](img/Emote-gura7.png)

| Mode | `-a` | Description |
|------|------|-------------|
| Dictionnaire | `0` | Wordlist → hash |
| Combinateur | `1` | Wordlist × Wordlist |
| Brute-force / Mask | `3` | Pattern mask (`?l?u?d…`) |
| Hybride wordlist + mask | `6` | Wordlist + suffixe mask |
| Hybride mask + wordlist | `7` | Préfixe mask + wordlist |

---

## Routes principales ![](img/Emote-gura15.png)

| Route | Méthode | Accès | Description |
|-------|---------|-------|-------------|
| `/` | GET | Auth | Dashboard — liste des jobs + filtres |
| `/attack/new` | GET / POST | Auth | Créer et lancer un job |
| `/attack/new?from_job=<id>` | GET | Auth | Pré-remplir depuis un job existant |
| `/attack/<id>` | GET | Auth | Détail + logs d'un job |
| `/attack/<id>/stop` | POST | Auth | Stopper un job (confirmation inline) |
| `/attack/<id>/resume` | POST | Auth | Reprendre un job stoppé/failed |
| `/attack/<id>/download` | GET | Auth | Télécharger les résultats |
| `/system` | GET | Auth | Infos système (GPU, wordlists) |
| `/benchmark` | GET | Auth | Page benchmark |
| `/profile` | GET / POST | Auth | Profil + changement de mot de passe |
| `/profile/2fa/setup` | POST | Auth | Activer / reconfigurer son propre 2FA depuis le profil |
| `/profile/2fa/disable` | POST | Auth | Désactiver son propre 2FA (bloqué si `require_2fa` actif) |
| `/admin/users` | GET | Admin | Liste des utilisateurs |
| `/admin/users/new` | GET / POST | Admin | Créer un utilisateur |
| `/admin/users/<id>/edit` | GET / POST | Admin | Modifier un utilisateur |
| `/admin/users/<id>/delete` | POST | Admin | Supprimer un utilisateur |
| `/admin/users/<id>/reset-2fa` | POST | Admin | Réinitialiser le secret TOTP d'un utilisateur |
| `/admin/jobs` | GET | Admin | Audit log — tous les jobs |
| `/admin/config` | GET / POST | Admin | Éditeur de configuration (config.json, appliqué à chaud) |
| `/login` | GET / POST | Public | Authentification |
| `/2fa/setup` | GET / POST | Session 2FA | Configuration TOTP (QR code + vérification) |
| `/2fa/verify` | GET / POST | Session 2FA | Saisie du code TOTP lors du login |
| `/logout` | POST | Auth | Déconnexion |

### API JSON

| Route | Méthode | Description |
|-------|---------|-------------|
| `/api/detect` | POST | Détection de type de hash |
| `/api/jobs/<id>/results` | GET | Résultats JSON d'un job |
| `/api/jobs/<id>/stream` | GET (SSE) | Stream de logs en temps réel |
| `/api/devices` | GET | Liste des GPU détectés |
| `/api/wordlists` | GET | Liste des wordlists disponibles |
| `/api/benchmark/start` | POST | Démarrer le benchmark (admin) |
| `/api/benchmark/stop` | POST | Stopper le benchmark (admin) |
| `/api/benchmark/status` | GET | Statut + output du benchmark |
| `/api/benchmark/stream` | GET (SSE) | Stream benchmark en temps réel |

---

## Structure du projet ![](img/Emote-gura6.png)

```
samebreaker/
├── app/
│   ├── __init__.py         # Factory Flask, headers sécu, context processor
│   ├── db.py               # db_conn(), init_db(), reset_stale_jobs(), seed_default_admin()
│   ├── models.py           # Classe User (Flask-Login)
│   ├── auth.py             # Login / logout + rate limiting
│   ├── main.py             # Routes principales + API
│   ├── admin.py            # Gestion utilisateurs + audit jobs (admin)
│   ├── jobs.py             # Cycle de vie des jobs hashcat
│   ├── hashcat_utils.py    # detect_hash, get_devices, build_command
│   ├── static/
│   │   └── assets/
│   │       └── logo.png
│   └── templates/
│       ├── base.html
│       ├── auth/
│       │   ├── login.html
│       │   ├── 2fa_setup.html
│       │   └── 2fa_verify.html
│       ├── main/
│       │   ├── dashboard.html
│       │   ├── new_attack.html
│       │   ├── job_detail.html
│       │   ├── system.html
│       │   ├── benchmark.html
│       │   └── profile.html
│       └── admin/
│           ├── users.html
│           ├── user_form.html
│           ├── jobs.html
│           └── config.html
├── instance/               # Généré au runtime (gitignored)
│   ├── config.json         # SECRET_KEY persistée
│   ├── samebreaker.db      # Base SQLite
│   ├── jobs/               # Hash files, logs, pot files, restore files
│   └── wordlists/          # Wordlists uploadées
├── img/                    # Emotes Gawr Gura
├── run.py                  # Point d'entrée
├── seed_admin.py           # Création manuelle d'un admin
├── requirements.txt
└── .gitignore
```

---

## Configuration ![](img/Emote-gura18.png)

La configuration est stockée dans `instance/config.json` (généré automatiquement) :

```json
{
  "secret_key": "<généré automatiquement>",
  "require_2fa": false,
  "max_upload_mb": 50,
  "hashcat_force": true,
  "max_concurrent_jobs": 5,
  "session_timeout_minutes": 60
}
```

| Clé config | Défaut | Description |
|---|---|---|
| `require_2fa` | `false` | Active le 2FA TOTP pour tous les utilisateurs |
| `hashcat_force` | `true` | Ajoute `--force` aux commandes hashcat |
| `max_concurrent_jobs` | `5` | Limite de jobs hashcat simultanés |
| `max_upload_mb` | `50` | Taille max des uploads |
| `session_timeout_minutes` | `60` | Déconnexion après X minutes d'inactivité |

| Variable env | Défaut | Description |
|---|---|---|
| `FLASK_DEBUG` | `0` | Active le mode debug si `1` |
| `DB_PATH` | `instance/samebreaker.db` | Chemin de la base SQLite |
| `HASHCAT_PATH` | `hashcat` | Chemin vers le binaire hashcat |

---

## 2FA TOTP ![](img/Emote-gura3.png)

Pour activer le 2FA, éditer `instance/config.json` et passer `require_2fa` à `true`, puis redémarrer :

```json
{ "require_2fa": true, ... }
```

**Flux :**
1. Login avec identifiant + mot de passe
2. **Première connexion** → QR code à scanner (Google Authenticator, Authy, Bitwarden…)
3. **Connexions suivantes** → code TOTP à 6 chiffres requis

**Auto-gestion :** depuis `/profile`, chaque utilisateur peut activer, reconfigurer ou désactiver son propre 2FA sans passer par un admin (la désactivation est bloquée si `require_2fa` est actif).

**Admin :** la page `/admin/users` affiche le statut 2FA de chaque utilisateur. Le bouton **Reset 2FA** force une reconfiguration (perte d'appareil). La page `/admin/config` permet de basculer `require_2fa` depuis l'interface web, sans éditer `config.json` à la main.

```
pip install -r requirements.txt  # inclut pyotp==2.9.0
```

---

## Déploiement production ![](img/Emote-gura13.png)

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:6660 "app:create_app()"
```

> **Important :** utiliser `-w 1` — les jobs et le benchmark utilisent des variables en mémoire (`_procs`, `_bm_proc`) non partagées entre workers.

---

## Historique des versions ![](img/Emote-gura19.png)

| Version | Changement principal |
|---------|---------------------|
| v1.1.0 | Durée live dashboard, tri des colonnes, auto-refresh, barre de progression + ETA, copier résultats, notification navigateur, compteur de hash, 2FA profil, éditeur config admin |
| v1.0.0 | Version initiale — UI Tailwind, multi-user, détection hash auto, streaming SSE, GPU busy, workload chips admin, audit sécu, filtres dashboard, relancer/reprendre job, badge sidebar, audit log admin, recovery crash, limite jobs simultanés, security headers |
