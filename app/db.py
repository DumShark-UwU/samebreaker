from __future__ import annotations

import sqlite3
import os
from contextlib import contextmanager
from typing import Generator

DB_PATH        = os.environ.get("DB_PATH", "instance/samebreaker.db")
_JOBS_DIR      = "instance/jobs"
_WORDLISTS_DIR = "instance/wordlists"


@contextmanager
def db_conn() -> Generator[sqlite3.Connection, None, None]:
    """Context manager garantissant la fermeture de la connexion SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(_JOBS_DIR, exist_ok=True)
    os.makedirs(_WORDLISTS_DIR, exist_ok=True)

    with db_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                username             TEXT    NOT NULL UNIQUE,
                password             TEXT    NOT NULL,
                role                 TEXT    NOT NULL DEFAULT 'user',
                allowed_devices      TEXT    NOT NULL DEFAULT '',
                workload_profile     INTEGER NOT NULL DEFAULT 2,
                totp_secret          TEXT,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS webhooks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label      TEXT    NOT NULL DEFAULT '',
                url        TEXT    NOT NULL,
                events     TEXT    NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT    NOT NULL,
                status         TEXT    NOT NULL DEFAULT 'pending',
                hash_type      INTEGER,
                hash_type_name TEXT,
                attack_mode    INTEGER NOT NULL DEFAULT 0,
                hash_file      TEXT,
                wordlist       TEXT,
                mask           TEXT,
                rules          TEXT,
                devices        TEXT,
                extra_args     TEXT,
                log_file       TEXT,
                pot_file       TEXT,
                workload       INTEGER DEFAULT 2,
                created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
                started_at     DATETIME,
                finished_at    DATETIME,
                created_by     INTEGER REFERENCES users(id),
                pid            INTEGER
            );
        """)
        conn.commit()

        _run_migrations(conn)


def _run_migrations(conn: sqlite3.Connection) -> None:
    """Ajoute les colonnes manquantes sur les anciennes bases de données."""
    migrations = [
        ("users", "allowed_devices",      "TEXT NOT NULL DEFAULT ''"),
        ("users", "workload_profile",     "INTEGER NOT NULL DEFAULT 2"),
        ("users", "totp_secret",          "TEXT"),
        ("users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("jobs",  "workload",             "INTEGER DEFAULT 2"),
        ("jobs",  "hidden",              "INTEGER NOT NULL DEFAULT 0"),
        ("jobs",  "hidden_at",           "DATETIME"),
        ("jobs",  "hidden_by",           "INTEGER"),
    ]
    for table, col, definition in migrations:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")
            conn.commit()
        except sqlite3.OperationalError:
            # La colonne existe déjà — comportement attendu sur une base existante.
            pass


def reset_stale_jobs() -> None:
    """Remet tous les jobs 'running' en 'failed' au démarrage — recovery après crash serveur."""
    try:
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT id, log_file FROM jobs WHERE status = 'running'"
            ).fetchall()
            if not rows:
                return
            for row in rows:
                if row["log_file"] and os.path.exists(row["log_file"]):
                    try:
                        with open(row["log_file"], "a") as f:
                            f.write(
                                "\n[SameBreaker] Job interrompu par arrêt serveur — statut: failed\n"
                            )
                    except OSError:
                        pass
            conn.execute(
                "UPDATE jobs SET status='failed', finished_at=CURRENT_TIMESTAMP"
                " WHERE status='running'"
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass  # Table absente au premier démarrage — ignoré.


def seed_default_admin() -> None:
    """Crée le compte admin/admin si aucun utilisateur n'existe (premier démarrage)."""
    from werkzeug.security import generate_password_hash  # import local pour éviter les imports circulaires

    with db_conn() as conn:
        count: int = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            conn.execute(
                "INSERT INTO users"
                " (username, password, role, must_change_password)"
                " VALUES (?, ?, 'admin', 1)",
                ("admin", generate_password_hash("admin")),
            )
            conn.commit()
