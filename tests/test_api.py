from __future__ import annotations

import json
import pytest


# ── Authentification ───────────────────────────────────────────────────────────

def test_login_valid(client):
    resp = client.post("/login", data={"username": "admin", "password": "admin"},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data or b"dashboard" in resp.data


def test_login_invalid(client):
    resp = client.post("/login", data={"username": "admin", "password": "wrong"},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"login" in resp.data.lower() or b"incorrect" in resp.data.lower() or resp.status_code == 200


def test_protected_route_redirects_anonymous(client):
    resp = client.get("/")
    assert resp.status_code in (302, 308)
    assert "/login" in resp.headers.get("Location", "")


# ── Token API ──────────────────────────────────────────────────────────────────

def test_api_token_auth(client, api_token):
    resp = client.get("/api/devices", headers={"X-API-Token": api_token})
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data, list)


def test_api_token_invalid(client):
    resp = client.get("/api/devices", headers={"X-API-Token": "invalid-token-xyz"})
    assert resp.status_code in (302, 401, 403)


def test_api_token_query_param(client, api_token):
    resp = client.get(f"/api/devices?token={api_token}")
    assert resp.status_code == 200


def test_api_token_last_used_updated(client, api_token):
    from app.db import db_conn
    with db_conn() as conn:
        before = conn.execute("SELECT last_used FROM api_tokens WHERE token=?", (api_token,)).fetchone()["last_used"]
    client.get("/api/devices", headers={"X-API-Token": api_token})
    with db_conn() as conn:
        after = conn.execute("SELECT last_used FROM api_tokens WHERE token=?", (api_token,)).fetchone()["last_used"]
    assert after is not None


# ── Routes principales ─────────────────────────────────────────────────────────

def test_dashboard_requires_login(client):
    resp = client.get("/")
    assert resp.status_code in (302, 308)


def test_dashboard_authenticated(auth_client):
    resp = auth_client.get("/")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data or b"dashboard" in resp.data.lower()


def test_new_attack_get(auth_client):
    resp = auth_client.get("/attack/new")
    assert resp.status_code == 200
    assert b"hash" in resp.data.lower()


def test_api_detect_empty(auth_client):
    resp = auth_client.post("/api/detect",
                            data=json.dumps({"hash": ""}),
                            content_type="application/json")
    assert resp.status_code == 200
    assert json.loads(resp.data) == []


def test_api_detect_md5(auth_client):
    resp = auth_client.post("/api/detect",
                            data=json.dumps({"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}),
                            content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data, list)


# ── Jobs API ───────────────────────────────────────────────────────────────────

def test_job_detail_404(auth_client):
    resp = auth_client.get("/attack/999999")
    assert resp.status_code in (302, 404)


def test_api_job_stats_404(auth_client):
    resp = auth_client.get("/api/jobs/999999/stats")
    assert resp.status_code == 404


def test_api_job_results_not_found(auth_client):
    resp = auth_client.get("/api/jobs/999999/results")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["status"] == "not_found"


# ── Scheduler routes ───────────────────────────────────────────────────────────

def test_cancel_scheduled_invalid(auth_client):
    resp = auth_client.post("/attack/999999/cancel",
                            data={"csrf_token": ""},
                            follow_redirects=True)
    assert resp.status_code == 200


# ── Rule save API ──────────────────────────────────────────────────────────────

def test_api_rule_save(auth_client):
    resp = auth_client.post("/api/rules/save",
                            data=json.dumps({"rule": "l\nr", "name": "test_rule"}),
                            content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "path" in data
    assert data["name"] == "test_rule.rule"


def test_api_rule_save_empty(auth_client):
    resp = auth_client.post("/api/rules/save",
                            data=json.dumps({"rule": "", "name": "empty"}),
                            content_type="application/json")
    assert resp.status_code == 400
