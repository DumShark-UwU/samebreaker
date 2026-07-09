from __future__ import annotations

import json
import os

import pytest

from app import jobs as job_mgr
from app.db import db_conn


# ── _parse_user_hash ──────────────────────────────────────────────────────────

def test_parse_user_hash_detects_format():
    lines = [
        "alice:5f4dcc3b5aa765d61d8327deb882cf99",
        "bob:5f4dcc3b5aa765d61d8327deb882cf99",
        "charlie:5f4dcc3b5aa765d61d8327deb882cf99",
    ]
    result = job_mgr._parse_user_hash(lines)
    assert result is not None
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in result
    assert "alice" in result["5f4dcc3b5aa765d61d8327deb882cf99"]


def test_parse_user_hash_groups_same_hash():
    lines = [
        "alice:5f4dcc3b5aa765d61d8327deb882cf99",
        "bob:5f4dcc3b5aa765d61d8327deb882cf99",
    ]
    result = job_mgr._parse_user_hash(lines)
    assert result is not None
    users = result["5f4dcc3b5aa765d61d8327deb882cf99"]
    assert set(users) == {"alice", "bob"}


def test_parse_user_hash_rejects_plain_hashes():
    lines = [
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "aad3b435b51404eeaad3b435b51404ee",
    ]
    result = job_mgr._parse_user_hash(lines)
    assert result is None


def test_parse_user_hash_empty():
    assert job_mgr._parse_user_hash([]) is None


def test_parse_user_hash_threshold():
    # 2 user:hash + 1 plain = 66% → below 80% threshold → None
    lines = [
        "alice:5f4dcc3b5aa765d61d8327deb882cf99",
        "bob:5f4dcc3b5aa765d61d8327deb882cf99",
        "5f4dcc3b5aa765d61d8327deb882cf99",
    ]
    assert job_mgr._parse_user_hash(lines) is None


def test_parse_user_hash_bcrypt():
    lines = ["admin:$2y$10$abcdefghijklmnopqrstuvuVwxyzABCDEFGHIJKLMNOPQRSTUVW"]
    result = job_mgr._parse_user_hash(lines)
    assert result is not None


# ── get_results ───────────────────────────────────────────────────────────────

def _make_job(job_id: int, pot_content: str, usermap: dict | None = None) -> dict:
    jobs_dir = job_mgr._JOBS_DIR
    pot_path = os.path.join(jobs_dir, f"{job_id}.pot")
    with open(pot_path, "w") as f:
        f.write(pot_content)
    if usermap:
        with open(os.path.join(jobs_dir, f"{job_id}.usermap"), "w") as f:
            json.dump(usermap, f)
    return {
        "id":       job_id,
        "pot_file": pot_path,
    }


def test_get_results_no_pot():
    job = {"id": 999, "pot_file": "/nonexistent/path.pot"}
    assert job_mgr.get_results(job) == []


def test_get_results_plain_hashes():
    job = _make_job(1, "5f4dcc3b5aa765d61d8327deb882cf99:password\n")
    result = job_mgr.get_results(job)
    assert result == ["5f4dcc3b5aa765d61d8327deb882cf99:password"]


def test_get_results_with_usermap():
    usermap = {"5f4dcc3b5aa765d61d8327deb882cf99": ["alice", "bob"]}
    job = _make_job(2, "5f4dcc3b5aa765d61d8327deb882cf99:password\n", usermap)
    result = job_mgr.get_results(job)
    assert "alice:password" in result
    assert "bob:password" in result
    assert len(result) == 2


def test_get_results_usermap_no_match_fallback():
    usermap = {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": ["charlie"]}
    job = _make_job(3, "5f4dcc3b5aa765d61d8327deb882cf99:password\n", usermap)
    result = job_mgr.get_results(job)
    assert result == ["5f4dcc3b5aa765d61d8327deb882cf99:password"]


# ── schedule_job / cancel_scheduled ───────────────────────────────────────────

def test_schedule_job():
    with db_conn() as conn:
        uid = conn.execute("SELECT id FROM users LIMIT 1").fetchone()["id"]
    job_id = job_mgr.create_job(
        name="sched-test", hash_type=0, hash_type_name="",
        attack_mode=0, hash_content="5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist=None, mask=None, rules=None, devices=None,
        extra_args=None, created_by=uid,
    )
    job_mgr.schedule_job(job_id, "2099-01-01 03:00:00")
    with db_conn() as conn:
        row = conn.execute("SELECT status, scheduled_at FROM jobs WHERE id=?", (job_id,)).fetchone()
    assert row["status"] == "scheduled"
    assert "2099" in row["scheduled_at"]


def test_cancel_scheduled():
    with db_conn() as conn:
        uid = conn.execute("SELECT id FROM users LIMIT 1").fetchone()["id"]
    job_id = job_mgr.create_job(
        name="cancel-test", hash_type=0, hash_type_name="",
        attack_mode=0, hash_content="5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist=None, mask=None, rules=None, devices=None,
        extra_args=None, created_by=uid,
    )
    job_mgr.schedule_job(job_id, "2099-01-01 03:00:00")
    assert job_mgr.cancel_scheduled(job_id) is True
    with db_conn() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
    assert row["status"] == "stopped"


def test_cancel_non_scheduled_returns_false():
    with db_conn() as conn:
        uid = conn.execute("SELECT id FROM users LIMIT 1").fetchone()["id"]
    job_id = job_mgr.create_job(
        name="no-cancel", hash_type=0, hash_type_name="",
        attack_mode=0, hash_content="5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist=None, mask=None, rules=None, devices=None,
        extra_args=None, created_by=uid,
    )
    assert job_mgr.cancel_scheduled(job_id) is False


# ── DB migration ───────────────────────────────────────────────────────────────

def test_db_has_scheduled_at_column():
    with db_conn() as conn:
        cols = conn.execute("PRAGMA table_info(jobs)").fetchall()
    col_names = [c["name"] for c in cols]
    assert "scheduled_at" in col_names


def test_api_tokens_table_exists():
    with db_conn() as conn:
        cols = conn.execute("PRAGMA table_info(api_tokens)").fetchall()
    assert len(cols) > 0


def test_job_snapshots_table_exists():
    with db_conn() as conn:
        cols = conn.execute("PRAGMA table_info(job_snapshots)").fetchall()
    assert len(cols) > 0
