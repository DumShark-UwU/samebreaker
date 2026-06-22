"""Crée le compte admin initial. Usage: python seed_admin.py"""
from __future__ import annotations

import getpass
import sqlite3

from werkzeug.security import generate_password_hash

from app.db import init_db, db_conn

init_db()

username = input("Username admin : ").strip()
if not username:
    raise SystemExit("Le nom d'utilisateur ne peut pas être vide.")

password = getpass.getpass("Mot de passe : ")
if len(password) < 8:
    raise SystemExit("Le mot de passe doit faire au moins 8 caractères.")

try:
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password)),
        )
        conn.commit()
    print(f"[OK] Admin '{username}' créé.")
except sqlite3.IntegrityError:
    print(f"[ERREUR] L'utilisateur '{username}' existe déjà.")
except sqlite3.OperationalError as exc:
    print(f"[ERREUR] Problème base de données : {exc}")
