from __future__ import annotations

import os
import subprocess
import threading
from datetime import datetime
from typing import Optional

from .db import db_conn, _JOBS_DIR
from .hashcat_utils import build_command, HASHCAT_BIN, HASHCAT_FORCE
from .notify import send_webhook, job_done_payload, password_found_payload

# ── Statuts ───────────────────────────────────────────────────────────────────
STATUS_PENDING   = "pending"
STATUS_RUNNING   = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED    = "failed"
STATUS_STOPPED   = "stopped"

TERMINAL_STATUSES = {STATUS_COMPLETED, STATUS_FAILED, STATUS_STOPPED}

# Hashcat retourne 0 (succès) ou 1 (aucun hash cracké).
_HASHCAT_OK_CODES = {0, 1}

# Configurable depuis __init__.py via config.json
MAX_CONCURRENT_JOBS: int = 5

_procs: dict[int, subprocess.Popen] = {}
_procs_lock = threading.Lock()


def _restore_path(job_id: int) -> str:
    return f"{_JOBS_DIR}/{job_id}.restore"


def can_resume(job_id: int) -> bool:
    """Vérifie si un fichier de session hashcat existe pour ce job."""
    return os.path.exists(_restore_path(job_id))


def get_busy_devices() -> set[int]:
    """Retourne les IDs de devices utilisés par des jobs en cours."""
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT devices FROM jobs WHERE status=? AND devices IS NOT NULL AND devices != ''",
            (STATUS_RUNNING,),
        ).fetchall()
    busy: set[int] = set()
    for row in rows:
        for part in row["devices"].split(","):
            if part.strip().isdigit():
                busy.add(int(part.strip()))
    return busy


def create_job(
    name: str,
    hash_type: int,
    hash_type_name: str,
    attack_mode: int,
    hash_content: str,
    wordlist: Optional[str],
    mask: Optional[str],
    rules: Optional[str],
    devices: Optional[str],
    extra_args: Optional[str],
    created_by: int,
    workload: int = 2,
) -> int:
    with db_conn() as conn:
        cur = conn.execute(
            """INSERT INTO jobs
               (name, hash_type, hash_type_name, attack_mode,
                wordlist, mask, rules, devices, extra_args, created_by, workload)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (name, hash_type, hash_type_name, attack_mode,
             wordlist, mask, rules, devices, extra_args, created_by, workload),
        )
        job_id = cur.lastrowid
        conn.commit()

        hash_file = f"{_JOBS_DIR}/{job_id}.hash"
        log_file  = f"{_JOBS_DIR}/{job_id}.log"
        pot_file  = f"{_JOBS_DIR}/{job_id}.pot"

        with open(hash_file, "w") as f:
            f.write(hash_content.strip() + "\n")

        conn.execute(
            "UPDATE jobs SET hash_file=?, log_file=?, pot_file=? WHERE id=?",
            (hash_file, log_file, pot_file, job_id),
        )
        conn.commit()

    return job_id


def _running_count() -> int:
    with db_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status=?", (STATUS_RUNNING,)
        ).fetchone()[0]


def start_job(job_id: int) -> bool:
    """Lance le job en arrière-plan. Retourne False si la limite de jobs simultanés est atteinte."""
    if _running_count() >= MAX_CONCURRENT_JOBS:
        return False

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return False

    job_dict = dict(row)
    job_dict.setdefault("workload", 2)
    job_dict["restore_file"] = _restore_path(job_id)
    cmd       = build_command(job_dict)
    log_file  = row["log_file"]
    hash_file = row["hash_file"]
    pot_file  = row["pot_file"]
    job_name  = row["name"]
    created_by = row["created_by"]

    # Charger tous les webhooks de l'utilisateur une seule fois avant le thread
    user_webhooks: list[dict] = []
    if created_by:
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT url, events, webhook_type FROM webhooks WHERE user_id=?", (created_by,)
            ).fetchall()
        user_webhooks = [
            {
                "url":          r["url"],
                "events":       {e.strip() for e in (r["events"] or "").split(",") if e.strip()},
                "webhook_type": r["webhook_type"] or "auto",
            }
            for r in rows if r["url"]
        ]

    def _poll_pot(pot_seen: set[str]) -> list[str]:
        """Retourne les nouvelles lignes du .pot depuis la dernière vérification."""
        if not pot_file or not os.path.exists(pot_file):
            return []
        try:
            with open(pot_file) as f:
                lines = [l.strip() for l in f if l.strip()]
        except OSError:
            return []
        new = [l for l in lines if l not in pot_seen]
        pot_seen.update(new)
        return new

    def _run() -> None:
        with open(log_file, "w") as lf:
            lf.write(f"[SameBreaker] Starting: {' '.join(cmd)}\n\n")
            lf.flush()
            status = STATUS_FAILED
            pot_seen: set[str] = set()
            line_count = 0
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                with _procs_lock:
                    _procs[job_id] = proc

                with db_conn() as conn:
                    conn.execute(
                        "UPDATE jobs SET status=?, started_at=?, pid=? WHERE id=?",
                        (STATUS_RUNNING, datetime.utcnow(), proc.pid, job_id),
                    )
                    conn.commit()

                for line in proc.stdout:
                    lf.write(line)
                    lf.flush()
                    line_count += 1
                    if line_count % 100 == 0:
                        new = _poll_pot(pot_seen)
                        if new:
                            payload = password_found_payload(job_name, job_id, new)
                            for wh in user_webhooks:
                                if "password_found" in wh["events"]:
                                    send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))

                proc.wait()
                status = STATUS_COMPLETED if proc.returncode in _HASHCAT_OK_CODES else STATUS_FAILED

                # Vérification finale du pot avant de clore
                new = _poll_pot(pot_seen)
                if new:
                    payload = password_found_payload(job_name, job_id, new)
                    for wh in user_webhooks:
                        if "password_found" in wh["events"]:
                            send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))

            except FileNotFoundError:
                lf.write("[SameBreaker] ERREUR : hashcat introuvable dans le PATH.\n")
            except OSError as exc:
                lf.write(f"[SameBreaker] ERREUR OS : {exc}\n")
            finally:
                with _procs_lock:
                    _procs.pop(job_id, None)

        with db_conn() as conn:
            current = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not current or current["status"] != STATUS_STOPPED:
                conn.execute(
                    "UPDATE jobs SET status=?, finished_at=? WHERE id=?",
                    (status, datetime.utcnow(), job_id),
                )
                conn.commit()

        found_count = len(pot_seen)
        done_payload = job_done_payload(job_name, job_id, status, found_count)
        for wh in user_webhooks:
            if "job_done" in wh["events"]:
                send_webhook(wh["url"], done_payload, wh.get("webhook_type", "auto"))

        if hash_file and os.path.exists(hash_file):
            try:
                os.remove(hash_file)
            except OSError:
                pass

    threading.Thread(target=_run, daemon=True).start()
    return True


def resume_job(job_id: int) -> bool:
    """Reprend un job arrêté. Retourne False si la limite de jobs simultanés est atteinte."""
    if _running_count() >= MAX_CONCURRENT_JOBS:
        return False

    restore_file = _restore_path(job_id)
    if not os.path.exists(restore_file):
        raise FileNotFoundError(restore_file)

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return False

    log_file   = row["log_file"]
    pot_file   = row["pot_file"]
    job_name   = row["name"]
    created_by = row["created_by"]
    cmd = [HASHCAT_BIN, "--restore", "--restore-file-path", restore_file]
    if HASHCAT_FORCE:
        cmd.append("--force")

    user_webhooks: list[dict] = []
    if created_by:
        with db_conn() as conn:
            wh_rows = conn.execute(
                "SELECT url, events, webhook_type FROM webhooks WHERE user_id=?", (created_by,)
            ).fetchall()
        user_webhooks = [
            {
                "url":          r["url"],
                "events":       {e.strip() for e in (r["events"] or "").split(",") if e.strip()},
                "webhook_type": r["webhook_type"] or "auto",
            }
            for r in wh_rows if r["url"]
        ]

    def _poll_pot(pot_seen: set[str]) -> list[str]:
        if not pot_file or not os.path.exists(pot_file):
            return []
        try:
            with open(pot_file) as f:
                lines = [l.strip() for l in f if l.strip()]
        except OSError:
            return []
        new = [l for l in lines if l not in pot_seen]
        pot_seen.update(new)
        return new

    def _run() -> None:
        with open(log_file, "a") as lf:
            lf.write(f"\n[SameBreaker] Reprise : {' '.join(cmd)}\n\n")
            lf.flush()
            status = STATUS_FAILED
            pot_seen: set[str] = set()
            line_count = 0
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                with _procs_lock:
                    _procs[job_id] = proc
                with db_conn() as conn:
                    conn.execute(
                        "UPDATE jobs SET status=?, started_at=?, pid=? WHERE id=?",
                        (STATUS_RUNNING, datetime.utcnow(), proc.pid, job_id),
                    )
                    conn.commit()
                for line in proc.stdout:
                    lf.write(line)
                    lf.flush()
                    line_count += 1
                    if line_count % 100 == 0:
                        new = _poll_pot(pot_seen)
                        if new:
                            payload = password_found_payload(job_name, job_id, new)
                            for wh in user_webhooks:
                                if "password_found" in wh["events"]:
                                    send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))
                proc.wait()
                status = STATUS_COMPLETED if proc.returncode in _HASHCAT_OK_CODES else STATUS_FAILED
                new = _poll_pot(pot_seen)
                if new:
                    payload = password_found_payload(job_name, job_id, new)
                    for wh in user_webhooks:
                        if "password_found" in wh["events"]:
                            send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))
            except FileNotFoundError:
                lf.write("[SameBreaker] ERREUR : hashcat introuvable.\n")
            except OSError as exc:
                lf.write(f"[SameBreaker] ERREUR OS : {exc}\n")
            finally:
                with _procs_lock:
                    _procs.pop(job_id, None)

        with db_conn() as conn:
            current = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not current or current["status"] != STATUS_STOPPED:
                conn.execute(
                    "UPDATE jobs SET status=?, finished_at=? WHERE id=?",
                    (status, datetime.utcnow(), job_id),
                )
                conn.commit()

        found_count = len(pot_seen)
        done_payload = job_done_payload(job_name, job_id, status, found_count)
        for wh in user_webhooks:
            if "job_done" in wh["events"]:
                send_webhook(wh["url"], done_payload, wh.get("webhook_type", "auto"))

    threading.Thread(target=_run, daemon=True).start()
    return True


def stop_job(job_id: int) -> None:
    with _procs_lock:
        proc = _procs.get(job_id)
    if proc:
        proc.terminate()
    with db_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status=?, finished_at=? WHERE id=?",
            (STATUS_STOPPED, datetime.utcnow(), job_id),
        )
        conn.commit()


def get_job(job_id: int):
    with db_conn() as conn:
        return conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()


def list_jobs(user_id: Optional[int] = None, include_hidden: bool = False) -> list:
    with db_conn() as conn:
        hidden_clause = "" if include_hidden else " AND hidden=0"
        if user_id is None:
            return conn.execute(
                f"SELECT * FROM jobs WHERE 1=1{hidden_clause} ORDER BY created_at DESC"
            ).fetchall()
        return conn.execute(
            f"SELECT * FROM jobs WHERE created_by=?{hidden_clause} ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()


def hide_job(job_id: int, hidden_by: int) -> bool:
    with db_conn() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row or row["status"] not in TERMINAL_STATUSES:
            return False
        conn.execute(
            "UPDATE jobs SET hidden=1, hidden_at=CURRENT_TIMESTAMP, hidden_by=? WHERE id=?",
            (hidden_by, job_id),
        )
        conn.commit()
    return True


def get_results(job) -> list[str]:
    pot = job["pot_file"]
    if pot and os.path.exists(pot):
        with open(pot) as f:
            return [line.strip() for line in f if line.strip()]
    return []
