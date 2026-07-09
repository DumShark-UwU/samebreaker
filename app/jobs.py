from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
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
STATUS_SCHEDULED = "scheduled"

TERMINAL_STATUSES = {STATUS_COMPLETED, STATUS_FAILED, STATUS_STOPPED}

# Hashcat retourne 0 (succès) ou 1 (aucun hash cracké).
_HASHCAT_OK_CODES = {0, 1}

# Configurable depuis __init__.py via config.json
MAX_CONCURRENT_JOBS: int = 5
USER_HASH_AUTO: bool = True

_procs: dict[int, subprocess.Popen] = {}
_procs_lock = threading.Lock()

# Détecte user:hash (ex: admin:5f4dcc3b... ou user:$2y$10$...)
_USER_HASH_RE = re.compile(
    r'^([^:\s]+):(\$[^\s:]+|[0-9a-fA-F]{16,})$', re.I
)

_RE_SPEED = re.compile(r'Speed\.#[\d*]+\.+:\s+([\d.]+)\s+([A-Za-z]*H/s)', re.I)
_RE_PROG  = re.compile(r'Progress\.+:\s*\d+/\d+\s*\((\d+\.\d+)%\)', re.I)
_RE_REC   = re.compile(r'Recovered\.+:\s*(\d+)/', re.I)
_SNAP_SEC = 30


def _to_hs(val: str, unit: str) -> float:
    mult = {'h/s': 1, 'kh/s': 1e3, 'mh/s': 1e6, 'gh/s': 1e9, 'th/s': 1e12, 'ph/s': 1e15}
    return float(val) * mult.get(unit.lower(), 1)


def _restore_path(job_id: int) -> str:
    return f"{_JOBS_DIR}/{job_id}.restore"


def _parse_user_hash(lines: list[str]) -> Optional[dict]:
    """
    Détecte le format user:hash et retourne {hash: [users]}.
    Retourne None si < 80% des lignes correspondent.
    """
    non_empty = [l for l in lines if l]
    if not non_empty:
        return None
    pairs = []
    for line in non_empty:
        m = _USER_HASH_RE.match(line)
        if m:
            pairs.append((m.group(1), m.group(2)))
    if len(pairs) < len(non_empty) * 0.8:
        return None
    mapping: dict[str, list[str]] = {}
    for user, h in pairs:
        mapping.setdefault(h, []).append(user)
    return mapping


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

        # Détection user:hash : activée si USER_HASH_AUTO ou --username explicite dans extra_args
        _force_username = bool(extra_args and "--username" in extra_args.split())
        if USER_HASH_AUTO or _force_username:
            input_lines = [l.strip() for l in hash_content.strip().splitlines() if l.strip()]
            usermap = _parse_user_hash(input_lines)
            if usermap:
                with open(f"{_JOBS_DIR}/{job_id}.usermap", "w") as _uf:
                    json.dump(usermap, _uf)

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
    job_dict["has_usermap"]  = os.path.exists(f"{_JOBS_DIR}/{job_id}.usermap")
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
            _last_snap = 0.0
            _snap_speed: Optional[float] = None
            _snap_prog:  Optional[float] = None
            _snap_crak:  int = 0
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
                    m = _RE_SPEED.search(line)
                    if m:
                        try: _snap_speed = _to_hs(m.group(1), m.group(2))
                        except Exception: pass
                    m = _RE_PROG.search(line)
                    if m:
                        try: _snap_prog = float(m.group(1))
                        except Exception: pass
                    m = _RE_REC.search(line)
                    if m:
                        try: _snap_crak = int(m.group(1))
                        except Exception: pass
                    _now = time.time()
                    if _snap_prog is not None and _now - _last_snap >= _SNAP_SEC:
                        _last_snap = _now
                        try:
                            with db_conn() as _sc:
                                _sc.execute(
                                    "INSERT INTO job_snapshots (job_id, speed_hs, progress_pct, cracked)"
                                    " VALUES (?,?,?,?)",
                                    (job_id, _snap_speed, _snap_prog, _snap_crak),
                                )
                                _sc.commit()
                        except Exception:
                            pass

                proc.wait()
                status = STATUS_COMPLETED if proc.returncode in _HASHCAT_OK_CODES else STATUS_FAILED

                # Vérification finale du pot avant de clore
                new = _poll_pot(pot_seen)
                if new:
                    payload = password_found_payload(job_name, job_id, new)
                    for wh in user_webhooks:
                        if "password_found" in wh["events"]:
                            send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))

                # Snapshot final — capturé même si hashcat a tout trouvé en potfile
                _final_prog = _snap_prog if _snap_prog is not None else (
                    100.0 if status == STATUS_COMPLETED else 0.0
                )
                try:
                    with db_conn() as _sc:
                        _sc.execute(
                            "INSERT INTO job_snapshots (job_id, speed_hs, progress_pct, cracked)"
                            " VALUES (?,?,?,?)",
                            (job_id, _snap_speed, _final_prog, len(pot_seen)),
                        )
                        _sc.commit()
                except Exception:
                    pass

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
            _last_snap = 0.0
            _snap_speed: Optional[float] = None
            _snap_prog:  Optional[float] = None
            _snap_crak:  int = 0
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
                    m = _RE_SPEED.search(line)
                    if m:
                        try: _snap_speed = _to_hs(m.group(1), m.group(2))
                        except Exception: pass
                    m = _RE_PROG.search(line)
                    if m:
                        try: _snap_prog = float(m.group(1))
                        except Exception: pass
                    m = _RE_REC.search(line)
                    if m:
                        try: _snap_crak = int(m.group(1))
                        except Exception: pass
                    _now = time.time()
                    if _snap_prog is not None and _now - _last_snap >= _SNAP_SEC:
                        _last_snap = _now
                        try:
                            with db_conn() as _sc:
                                _sc.execute(
                                    "INSERT INTO job_snapshots (job_id, speed_hs, progress_pct, cracked)"
                                    " VALUES (?,?,?,?)",
                                    (job_id, _snap_speed, _snap_prog, _snap_crak),
                                )
                                _sc.commit()
                        except Exception:
                            pass
                proc.wait()
                status = STATUS_COMPLETED if proc.returncode in _HASHCAT_OK_CODES else STATUS_FAILED
                new = _poll_pot(pot_seen)
                if new:
                    payload = password_found_payload(job_name, job_id, new)
                    for wh in user_webhooks:
                        if "password_found" in wh["events"]:
                            send_webhook(wh["url"], payload, wh.get("webhook_type", "auto"))

                _final_prog = _snap_prog if _snap_prog is not None else (
                    100.0 if status == STATUS_COMPLETED else 0.0
                )
                try:
                    with db_conn() as _sc:
                        _sc.execute(
                            "INSERT INTO job_snapshots (job_id, speed_hs, progress_pct, cracked)"
                            " VALUES (?,?,?,?)",
                            (job_id, _snap_speed, _final_prog, len(pot_seen)),
                        )
                        _sc.commit()
                except Exception:
                    pass

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


def schedule_job(job_id: int, scheduled_at: str) -> None:
    """Bascule un job en statut 'scheduled' avec une date d'exécution différée."""
    with db_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status=?, scheduled_at=? WHERE id=?",
            (STATUS_SCHEDULED, scheduled_at, job_id),
        )
        conn.commit()


def cancel_scheduled(job_id: int) -> bool:
    """Annule un job planifié (status → stopped). Retourne False si non planifié."""
    with db_conn() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row or row["status"] != STATUS_SCHEDULED:
            return False
        conn.execute(
            "UPDATE jobs SET status=?, finished_at=CURRENT_TIMESTAMP WHERE id=?",
            (STATUS_STOPPED, job_id),
        )
        conn.commit()
    return True


def get_results(job) -> list[str]:
    pot = job["pot_file"]
    if not pot or not os.path.exists(pot):
        return []

    with open(pot) as f:
        lines = [l.strip() for l in f if l.strip()]

    usermap_path = f"{_JOBS_DIR}/{job['id']}.usermap"
    if not os.path.exists(usermap_path):
        return lines

    try:
        with open(usermap_path) as f:
            usermap: dict[str, list[str]] = json.load(f)
    except Exception:
        return lines

    sorted_hashes = sorted(usermap.keys(), key=len, reverse=True)
    results: list[str] = []
    for line in lines:
        matched = False
        for h in sorted_hashes:
            if line.startswith(h + ':'):
                clearpass = line[len(h) + 1:]
                for user in usermap[h]:
                    results.append(f"{user}:{clearpass}")
                matched = True
                break
        if not matched:
            results.append(line)
    return results
