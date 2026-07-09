# SameBreaker ![](img/gura.png)

Interface web multi-utilisateurs pour hashcat — gestion de jobs de cassage de hash, détection automatique de type, supervision GPU en temps réel.

> *サメ！サメ！サメ、サメ！ サメに気をつけろ！* — DumShark-UwU

---

## Captures d'écran ![](img/Emote-gura8.png)

### Page de connexion

![Login](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/01_login.png)

Authentification avec identifiant / mot de passe. Support 2FA TOTP optionnel (Google Authenticator, Authy, Bitwarden). Rate limiting intégré (10 tentatives / IP). Bannière persistante tant que le mot de passe par défaut `admin/admin` n'est pas changé.

---

### Dashboard

![Dashboard](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/02_dashboard.png)

Vue centrale de tous les jobs. Filtres par statut (En cours / Terminés / Échoués / Stoppés / En attente / **Planifiés**). Colonne Durée mise à jour chaque seconde. Auto-refresh 30 s si des jobs sont actifs. Import ZIP depuis le bouton en haut à droite. Badge sidebar animé quand des jobs tournent.

---

### Nouvelle attaque

![Nouvelle attaque](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/03_new_attack.png)

Formulaire complet d'une attaque :
- **Hash** : coller ou uploader un `.txt`, détection automatique du type au collé (via `name_that_hash`), compteur de hash live
- **Mode** : 5 boutons avec tooltips explicatifs au survol
- **Wordlist** : sélection dans les wordlists installées ou upload à la volée
- **Règles** : dropdown + **builder de règles** (voir ci-dessous)
- **GPU** : cases à cocher, GPU occupés grisés automatiquement
- **Workload** : chips `-w1` à `-w4` (admin uniquement)
- **Extra args** : champ libre hashcat (admin uniquement)
- **Templates** : sauvegarder et recharger une configuration complète
- **Scheduler** : datetime-local pour planifier l'attaque à une heure précise

---

### Mask Builder

![Mask Builder](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/03b_mask_builder.png)

Constructeur visuel de mask (mode 3, 6, 7). Boutons `?l ?u ?d ?s ?a ?b ?1 ?2 ?3 ?4` pour composer le mask position par position. Preview live du mask construit et compteur de positions. Touches ⌫ (supprimer dernier token) et ✕ (effacer tout). Synchronisation bidirectionnelle avec le champ texte.

---

### Charsets personnalisés (`?1`–`?4`)

![Custom charset](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/03c_custom_charset.png)

Dès qu'un token `?1`, `?2`, `?3` ou `?4` apparaît dans le mask, la section **Charsets personnalisés** s'affiche automatiquement sous le builder. Chaque ligne active propose des boutons rapides (`?l ?u ?d ?s ?a ?b`) et un champ texte libre pour composer le charset (ex: `?l?u` = minuscules + majuscules, ou `abc123` littéral). Les valeurs sont injectées automatiquement dans la commande hashcat via `--custom-charset1=...` au moment du submit — pour tous les rôles, sans passer par les extra args.

---

### Rule Builder

![Rule Builder](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/03d_rule_builder.png)

Constructeur de règles hashcat intégré. 12 fonctions sans paramètre (`: l u c C r d f { } [ ]`) et 4 avec paramètre (`$ ^ s @`) via une dialog HTML native (sans `window.prompt()`). Les lignes s'accumulent dans une textarea éditable. **Sauvegarder et utiliser** envoie la règle vers `instance/rules/` et la sélectionne automatiquement dans le dropdown.

---

### Détail d'un job

![Job detail](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/11_job_detail.png)

Page de suivi d'un job avec :
- Résultats crackés en temps réel avec **copie par ligne** + "Tout copier"
- Export en `.txt`, `.csv` et `.json`
- Logs hashcat en streaming SSE (barre de progression, vitesse, ETA)
- Boutons Stopper / Reprendre / Relancer / Exporter (ZIP)
- Pour les jobs planifiés : bloc avec date et bouton Annuler

---

### Bibliothèque

![Bibliothèque](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/04_library.png)

Catalogue curaté de wordlists (rockyou, weakpass, SecLists…), règles (best64, OneRuleToRuleThemAll…) et masks. Téléchargement streamé avec barre de progression, extraction automatique (`.7z` / `.tar.gz` / `.gz`). **Crack rate visuel** par barre colorée (vert ≥30 %, orange ≥15 %, rouge <15 %) basé sur les statistiques weakpass.com.

---

### Benchmark

![Benchmark](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/05_benchmark.png)

Lancement/arrêt par l'admin, output hashcat streamen en temps réel via SSE. Permet de mesurer les performances GPU pour chaque algorithme avant de lancer une vraie attaque.

---

### Potfile

![Potfile](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/06_potfile.png)

Liste de tous les jobs ayant des résultats crackés. Un clic sur `#id` ouvre le détail du job. Les boutons **TXT / CSV / JSON** téléchargent directement le potfile de cette attaque, sans passer par une vue agrégée.

---

### Administration

![Admin](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/07_admin.png)

![Admin — Utilisateurs](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/08_admin_users.png)

Panel admin avec gestion des utilisateurs (rôle, GPU assignés, workload profile, statut 2FA, reset TOTP), audit log de tous les jobs, et éditeur de configuration (`config.json`) appliqué à chaud sans redémarrage.

---

### Profil utilisateur

![Profil](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/10_profile.png)

Chaque utilisateur peut changer son mot de passe, configurer ses **webhooks** (Discord, Slack, Teams, ntfy, Signal, Générique), gérer ses **tokens API** (création / révocation, `last_used` tracké), et activer / désactiver son **2FA TOTP**.

---

### Système

![Système](https://github.com/DumShark-UwU/samebreaker/releases/download/v1.4.1/12_system.png)

Métriques en temps réel : CPU, RAM, Disk, GPU détectés, wordlists et règles installées. Polling toutes les 4 secondes, sans dépendance externe.

---

## Fonctionnalités ![](img/Emote-gura8.png)

- **Interface web complète** — dashboard, nouvelle attaque, détail de job, benchmark, profil
- **Multi-utilisateurs** — rôles `admin` / `user`, accès par GPU assigné, workload profile par user
- **Parse auto à l'upload** — détection et extraction des formats secretsdump et mimikatz ; aperçu des rejets par catégorie, blocage si 0 hash valide, bypass "Brut"
- **Détection automatique de hash** — via `name_that_hash`, déclenchée au collé + après parse + bouton manuel, compteur de hash live
- **Gestion GPU** — détection live des devices, GPU occupé grisé et non-sélectionnable
- **5 modes d'attaque** — Dictionnaire, Combinateur, Brute-force/Mask, Hybride ×2, avec tooltips explicatifs au survol
- **Streaming de logs en temps réel** — Server-Sent Events directement depuis le fichier log hashcat
- **Barre de progression + ETA** — parsing live du statut hashcat (vitesse, avancement %, temps restant)
- **Statistiques de cracking** — snapshots toutes les 30 s, graphique Chart.js dual-axe (vitesse / progression)
- **Dashboard amélioré** — colonne Durée mise à jour chaque seconde, colonnes triables, auto-refresh toutes les 30 s si jobs actifs, badge planifié
- **Filtres dashboard** — filtrage JS par statut (running, completed, failed, stopped, pending, scheduled)
- **Scheduler** — planification d'attaque à date/heure précises, annulation depuis le détail
- **Relancer un job** — pré-remplit le formulaire avec les paramètres d'un job existant
- **Reprendre un job** — reprise via fichier de session hashcat (`--restore-file-path`)
- **User:hash → user:clearpass** — détection automatique `user:hash` (≥80%), `--username` auto, résultats en `user:clearpass`
- **Copier les résultats** — bouton par ligne + "Tout copier" via Clipboard API
- **Export résultats** — `.txt`, `.csv`, `.json` depuis le détail de job
- **Export/Import de job** — archive ZIP complète (params + hashes + résultats), import pré-remplit le formulaire
- **Tokens API** — `X-API-Token` / `?token=`, création/révocation depuis le profil, `last_used` tracké
- **Templates de jobs** — sauvegarde/chargement de configurations réutilisables
- **Mask builder** — sélecteur visuel, charsets `?1–?4` auto-injectés (`--custom-charset{N}`)
- **Rule builder** — 16 fonctions hashcat, dialog HTML natif, sauvegarde `instance/rules/`
- **Potfile** — liste des jobs crackés, téléchargement TXT/CSV/JSON par attaque
- **Notification navigateur** — alerte native à la fin d'un job (Notification API)
- **Badge sidebar** — compteur animé des jobs en cours sur le lien Dashboard
- **Audit log** — vue admin de tous les jobs avec utilisateur associé
- **Limite de jobs simultanés** — configurable (`max_concurrent_jobs`, défaut : 5)
- **Recovery au démarrage** — les jobs `running` au crash sont automatiquement marqués `failed`
- **Benchmark** — lancement/arrêt admin, streaming de sortie en live
- **Compte par défaut** — `admin` / `admin` créé automatiquement au premier démarrage
- **Bannière de sécurité** — notification persistante tant que le mot de passe par défaut n'est pas changé
- **2FA TOTP optionnel** — activable via `config.json`, setup QR code, compatible Google Authenticator / Authy / Bitwarden ; auto-gestion depuis le profil
- **Éditeur de configuration** — interface web admin (`/admin/config`) pour modifier `config.json` à chaud
- **Rate limiting** — 10 tentatives de login / 30 détections de hash par IP sur fenêtre glissante
- **Session idle timeout** — déconnexion automatique après inactivité (configurable, défaut 60 min)
- **CSRF** — protection sur tous les formulaires et endpoints POST
- **Security headers** — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS
- **Bibliothèque de ressources** — catalogue de wordlists/règles/masks curatés (`/library`) ; téléchargement streamé avec progression, extraction multi-format (`.7z` via py7zr, `.tar.gz`, `.gz`), archives supprimées automatiquement
- **Crack rate visuel** — barre colorée par wordlist (taux réel weakpass.com) : vert ≥30%, orange ≥15%, rouge <15%
- **Métriques système en temps réel** — widgets CPU/RAM/Disk sur la page Système, polling 4 s, sans dépendance externe
- **Webhooks multi-services** — Discord, Slack, Microsoft Teams, ntfy, Signal (via CallMeBot), Générique ; détection automatique par URL, conversion de payload par type

### v1.4.0 — Nouveautés

- **Parse auto à l'upload** — détection et extraction automatique des formats **secretsdump** (`DOMAIN\user:RID:LM:NT:::`) et **mimikatz** (`* NTLM : <hash>`) au moment du dépôt du fichier ; seuil 50 % pour secretsdump, 5 % pour mimikatz. Le formulaire affiche le format détecté, le nombre de hashes extraits, les stats de rejets par catégorie (NT vide, null, LM, métadonnées) avec aperçu des lignes pertinentes et lien de téléchargement. Blocage du submit si 0 hash valide extrait. Le bouton "Brut" permet de contourner le parsing.
- **Auto-détection `-m`** après extraction — `name_that_hash` est appelé sur le premier hash extrait, résultat affiché et pré-sélectionné comme pour la détection manuelle
- **Tokens API** — authentification stateless par `X-API-Token` ou `?token=` ; création/révocation depuis le profil, `last_used` tracké
- **Scheduler** — planification d'attaque à date et heure précises, thread daemon 30 s, badge violet dans le dashboard, annulation depuis le détail
- **Statistiques de cracking** — snapshots toutes les 30 s + snapshot final ; cartes métriques (progression, crackés, vitesse max, points) + graphique dual-axe Chart.js (vitesse/progression)
- **Mask builder** — sélecteur visuel de charsets (?l, ?u, ?d, ?s, ?a, ?b, ?1–?4), preview live, compteur de positions ; **auto-injection de `--custom-charset1..4`** : les inputs s'affichent dynamiquement quand ?1–?4 sont utilisés, valeurs injectées automatiquement à la soumission pour tous les rôles
- **Rule builder** — constructeur de règles hashcat (16 fonctions intégrées), dialog HTML natif pour les paramètres, sauvegarde vers `instance/rules/` et sélection automatique
- **Import / Export de jobs** — archive ZIP (job.json + hashes.txt + results.txt) ; import pré-remplit le formulaire
- **User:hash → user:clearpass** — détection automatique du format `user:hash` (≥80% de correspondance), mapping stocké en `.usermap`, `--username` injecté automatiquement dans hashcat, résultats retournés en `user:clearpass`
- **Téléchargement log complet** — bouton depuis le détail de job
- **Export CSV/JSON** — résultats téléchargeables en `.txt`, `.csv` et `.json` depuis le détail de job
- **Potfile** (`/potfile`) — liste des jobs avec résultats crackés ; boutons TXT/CSV/JSON par attaque pour télécharger directement le potfile de chaque job
- **Templates de jobs** — sauvegarde/chargement de configurations d'attaque réutilisables, suppression depuis le formulaire
- **Tests automatisés** — 65 tests pytest couvrant DB, jobs, auth, API, parse secretsdump/mimikatz, endpoint `/api/parse_hashes`

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
| `/attack/new?from_import=1` | GET | Auth | Pré-remplir depuis un import ZIP (via session) |
| `/attack/<id>` | GET | Auth | Détail + logs d'un job |
| `/attack/<id>/stop` | POST | Auth | Stopper un job (confirmation inline) |
| `/attack/<id>/resume` | POST | Auth | Reprendre un job stoppé/failed |
| `/attack/<id>/download` | GET | Auth | Télécharger les résultats (`.txt`, `?format=csv`, `?format=json`) |
| `/attack/<id>/log` | GET | Auth | Télécharger le log brut hashcat |
| `/attack/<id>/cancel` | POST | Auth | Annuler un job planifié |
| `/attack/<id>/export` | GET | Auth | Exporter le job en ZIP (params + hashes + résultats) |
| `/attack/import` | POST | Auth | Importer un job depuis un ZIP |
| `/potfile` | GET | Auth | Liste des jobs avec résultats crackés |
| `/system` | GET | Auth | Infos système (GPU, wordlists, règles, masks, métriques CPU/RAM/Disk) |
| `/system/delete` | POST | Auth | Supprimer une wordlist / règle / mask installé |
| `/benchmark` | GET | Auth | Page benchmark |
| `/library` | GET | Auth | Bibliothèque — catalogue wordlists/règles/masks |
| `/library/download/<rid>` | POST | Auth | Lancer le téléchargement d'une ressource |
| `/library/status/<rid>` | GET | Auth | Statut JSON du téléchargement en cours |
| `/library/delete/<rid>` | POST | Auth | Supprimer une ressource installée |
| `/profile` | GET / POST | Auth | Profil + changement de mot de passe + webhooks + tokens API + 2FA |
| `/profile/token/create` | POST | Auth | Créer un token API |
| `/profile/token/<id>/delete` | POST | Auth | Révoquer un token API |
| `/profile/2fa/setup` | POST | Auth | Activer / reconfigurer son propre 2FA depuis le profil |
| `/profile/2fa/disable` | POST | Auth | Désactiver son propre 2FA (bloqué si `require_2fa` actif) |
| `/templates/save` | POST | Auth | Sauvegarder un template de job |
| `/templates/<id>/delete` | POST | Auth | Supprimer un template de job |
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
| `/api/parse_hashes` | POST | Parse auto secretsdump / mimikatz / raw — retourne hashes, usermap, rejets par catégorie |
| `/api/detect` | POST | Détection de type de hash via `name_that_hash` |
| `/api/jobs/<id>/results` | GET | Résultats JSON d'un job |
| `/api/jobs/<id>/stream` | GET (SSE) | Stream de logs en temps réel |
| `/api/jobs/<id>/stats` | GET | Snapshots de progression (vitesse, %, crackés) |
| `/api/jobs/status` | GET | Statut de tous les jobs de l'utilisateur |
| `/api/templates` | GET | Liste des templates de jobs |
| `/api/devices` | GET | Liste des GPU détectés |
| `/api/wordlists` | GET | Liste des wordlists disponibles |
| `/api/rules/save` | POST | Sauvegarder une règle hashcat dans `instance/rules/` |
| `/api/benchmark/start` | POST | Démarrer le benchmark (admin) |
| `/api/benchmark/stop` | POST | Stopper le benchmark (admin) |
| `/api/benchmark/status` | GET | Statut + output du benchmark |
| `/api/benchmark/stream` | GET (SSE) | Stream benchmark en temps réel |
| `/api/sysinfo` | GET | Métriques CPU / RAM / Disk (JSON) |

---

## Structure du projet ![](img/Emote-gura6.png)

```
samebreaker/
├── app/
│   ├── __init__.py         # Factory Flask, scheduler daemon, token request_loader, headers sécu
│   ├── db.py               # db_conn(), init_db(), migrations, reset_stale_jobs(), seed_default_admin()
│   ├── models.py           # Classe User (Flask-Login)
│   ├── auth.py             # Login / logout + rate limiting
│   ├── main.py             # Routes principales + API (parse, detect, sysinfo, profil, tokens, webhooks…)
│   ├── admin.py            # Gestion utilisateurs + audit jobs (admin)
│   ├── jobs.py             # Cycle de vie des jobs hashcat, snapshots, scheduler, usermap
│   ├── hashcat_utils.py    # detect_hash, parse_hashes, get_devices, build_command
│   ├── library.py          # Blueprint /library — catalogue, téléchargement, extraction py7zr/tarfile/gzip
│   ├── notify.py           # Webhooks multi-services (Discord/Slack/Teams/ntfy/Signal)
│   ├── static/
│   │   └── assets/
│   │       ├── logo.png
│   │       ├── chart.min.js     # Chart.js pour les graphiques de stats
│   │       └── tailwind.min.js  # Tailwind CSS
│   └── templates/
│       ├── base.html
│       ├── auth/
│       │   ├── login.html
│       │   ├── 2fa_setup.html
│       │   └── 2fa_verify.html
│       ├── main/
│       │   ├── dashboard.html
│       │   ├── new_attack.html  # Formulaire + parse banner + mask/rule builder
│       │   ├── job_detail.html  # Logs SSE + stats Chart.js + export
│       │   ├── potfile.html
│       │   ├── system.html
│       │   ├── benchmark.html
│       │   ├── library.html
│       │   └── profile.html     # Webhooks + tokens API + 2FA
│       └── admin/
│           ├── users.html
│           ├── user_form.html
│           ├── jobs.html
│           └── config.html
├── tests/
│   ├── conftest.py              # Fixtures Flask, DB isolée, auth_client, api_token
│   ├── test_api.py              # Tests auth, routes, API detect/jobs/rules
│   ├── test_jobs.py             # Tests cycle de vie jobs, usermap, scheduler
│   ├── test_parse_hashes.py     # Tests parse secretsdump/mimikatz/raw + endpoint /api/parse_hashes
│   └── hash_samples/
│       ├── secretsdump_sample.txt
│       └── mimikatz_sample.txt
├── instance/               # Généré au runtime (gitignored)
│   ├── config.json         # SECRET_KEY persistée
│   ├── samebreaker.db      # Base SQLite
│   ├── jobs/               # Hash files, logs, pot files, restore files, usermaps
│   ├── wordlists/          # Wordlists uploadées + téléchargées via /library
│   ├── rules/              # Règles hashcat (library + rule builder)
│   ├── masks/              # Masks générés via /library
│   └── import_tmp/         # Fichiers temporaires import ZIP (nettoyés après redirection)
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
  "session_timeout_minutes": 60,
  "user_hash_auto": true
}
```

| Clé config | Défaut | Description |
|---|---|---|
| `require_2fa` | `false` | Active le 2FA TOTP pour tous les utilisateurs |
| `hashcat_force` | `true` | Ajoute `--force` aux commandes hashcat |
| `max_concurrent_jobs` | `5` | Limite de jobs hashcat simultanés |
| `max_upload_mb` | `50` | Taille max des uploads |
| `session_timeout_minutes` | `60` | Déconnexion après X minutes d'inactivité |
| `user_hash_auto` | `true` | Détection auto format `user:hash` et mapping `--username` |

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

## Documentation technique ![](img/Emote-gura6.png)

Pour les détails d'architecture interne, le schéma de base de données, le cycle de vie des jobs, le parseur hashcat -I, le streaming SSE, la sécurité et les webhooks : **[TECHNICAL.md](TECHNICAL.md)**

---

## Historique des versions ![](img/Emote-gura19.png)

| Version | Changement principal |
|---------|---------------------|
| v1.4.1 | Fix bannière parse cachée après extraction (parse-banner hors hash-file-zone) ; captures d'écran v1.4.1 |
| v1.4.0 | Parse auto secretsdump/mimikatz à l'upload ; tokens API ; scheduler ; stats Chart.js ; mask/rule builder ; import/export ZIP ; user:hash→user:clearpass ; potfile ; templates de jobs ; 65 tests pytest ; extraction 7z via py7zr |
| v1.3.0 | Bibliothèque wordlists/règles/masks avec téléchargement streamé et crack rate visuel ; métriques système temps réel (CPU/RAM/Disk) ; webhooks multi-services (Slack, Teams, ntfy, Signal) ; cap DOM log 200 éléments |
| v1.2.2 | Tooltips CSS sur les boutons de mode d'attaque |
| v1.2.1 | Fix détection GPU (device #8) ; smart scroll benchmark ; bouton "Copier tout" |
| v1.2.0 | Fix race condition stop→failed ; webhooks sur reprise de job ; refactoring db.py ; fix upload wordlist |
| v1.1.0 | Durée live dashboard, tri des colonnes, auto-refresh, barre de progression + ETA, copier résultats, notification navigateur, compteur de hash, 2FA profil, éditeur config admin |
| v1.0.0 | Version initiale — UI Tailwind, multi-user, détection hash auto, streaming SSE, GPU busy, workload chips admin, audit sécu, filtres dashboard, relancer/reprendre job, badge sidebar, audit log admin, recovery crash, limite jobs simultanés, security headers |
