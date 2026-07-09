from __future__ import annotations

import io
import json
import os
import pytest

from app.hashcat_utils import parse_hashes


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sample(name: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "hash_samples", name)
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── parse_hashes — entrée vide ─────────────────────────────────────────────────

def test_empty_string():
    r = parse_hashes("")
    assert r["format"] == "raw"
    assert r["hashes"] == []
    assert r["rejected"] == []


def test_whitespace_only():
    r = parse_hashes("   \n\n\t  \n")
    assert r["format"] == "raw"
    assert r["hashes"] == []


# ── parse_hashes — raw passthrough ────────────────────────────────────────────

def test_raw_plain_md5():
    content = "\n".join([
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "098f6bcd4621d373cade4e832627b4f6",
        "d8578edf8458ce06fbc5bb76a58c5ca4",
    ])
    r = parse_hashes(content)
    assert r["format"] == "raw"
    assert len(r["hashes"]) == 3
    assert r["usermap"] == {}
    assert r["rejected"] == []


def test_raw_single_hash():
    r = parse_hashes("5f4dcc3b5aa765d61d8327deb882cf99")
    assert r["format"] == "raw"
    assert r["hashes"] == ["5f4dcc3b5aa765d61d8327deb882cf99"]


def test_raw_bcrypt():
    content = "$2y$10$abcdefghijklmnopqrstuvuVwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12"
    r = parse_hashes(content)
    assert r["format"] == "raw"


# ── parse_hashes — secretsdump ─────────────────────────────────────────────────

def test_secretsdump_with_domain():
    content = "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
    r = parse_hashes(content)
    assert r["format"] == "secretsdump"
    assert "8846f7eaee8fb117ad06bdd830b7586c" in r["hashes"]
    assert "Administrator" in r["usermap"]["8846f7eaee8fb117ad06bdd830b7586c"]


def test_secretsdump_without_domain():
    content = "lbernard:1004:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::"
    r = parse_hashes(content)
    assert r["format"] == "secretsdump"
    assert "cf3a5525ee9414229e66279623ed5c58" in r["hashes"]
    assert "lbernard" in r["usermap"]["cf3a5525ee9414229e66279623ed5c58"]


def test_secretsdump_empty_nt_rejected():
    content = "guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    r = parse_hashes(content)
    # Only 1 line and it's rejected → but sd_ratio is still 1.0 so detected as secretsdump
    assert r["format"] == "secretsdump"
    assert r["hashes"] == []
    assert len(r["rejected"]) == 1
    assert "Compte désactivé" in list(r["rejected_cat"].keys())[0]


def test_secretsdump_sample_file():
    content = _sample("secretsdump_sample.txt")
    r = parse_hashes(content)
    assert r["format"] == "secretsdump"
    # 10 valid NT hashes (3 empty NT + 1 comment line rejected)
    assert len(r["hashes"]) == 10
    # 3 empty NT: guest, krbtgt, disabled_user
    nt_empty_rejections = r["rejected_cat"].get(
        "Compte désactivé / mot de passe vide (NT vide)", 0
    )
    assert nt_empty_rejections == 3
    # 1 comment line
    unrecognized = r["rejected_cat"].get("Format non reconnu", 0)
    assert unrecognized == 1


def test_secretsdump_usermap_domain_stripped():
    """Le domaine ne doit pas apparaître dans le username du usermap."""
    content = "CORP\\jdupont:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::"
    r = parse_hashes(content)
    users = r["usermap"]["64f12cddaa88057e06a81b54e73b949b"]
    assert "jdupont" in users
    assert all("\\" not in u for u in users)


def test_secretsdump_dedup_same_hash_different_users():
    lines = [
        "CORP\\alice:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "bob:1002:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
    ]
    r = parse_hashes("\n".join(lines))
    assert r["format"] == "secretsdump"
    assert len(r["hashes"]) == 2  # hashes list has duplicates (one per entry)
    users = r["usermap"]["8846f7eaee8fb117ad06bdd830b7586c"]
    assert set(users) == {"alice", "bob"}


def test_secretsdump_mixed_domain_no_domain():
    """Mélange de lignes avec et sans préfixe domaine."""
    lines = [
        "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "lbernard:1004:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::",
        "CORP\\mmartin:1002:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::",
    ]
    r = parse_hashes("\n".join(lines))
    assert r["format"] == "secretsdump"
    assert len(r["hashes"]) == 3
    assert "Administrator" in r["usermap"]["8846f7eaee8fb117ad06bdd830b7586c"]
    assert "lbernard" in r["usermap"]["cf3a5525ee9414229e66279623ed5c58"]
    assert "mmartin" in r["usermap"]["32ed87bdb5fdc5e9cba88547376818d4"]


# ── parse_hashes — mimikatz ────────────────────────────────────────────────────

def test_mimikatz_sample_file():
    content = _sample("mimikatz_sample.txt")
    r = parse_hashes(content)
    assert r["format"] == "mimikatz"
    # 6 NTLM valides
    assert len(r["hashes"]) == 6
    expected_hashes = {
        "8846f7eaee8fb117ad06bdd830b7586c",  # Administrator
        "64f12cddaa88057e06a81b54e73b949b",  # jdupont
        "32ed87bdb5fdc5e9cba88547376818d4",  # mmartin
        "209c6174da490caeb422f3fa5a7ae634",  # svcbackup
        "cf3a5525ee9414229e66279623ed5c58",  # lbernard
        "72f0eefcc213ea8f350773b831cf2c9c",  # abousquet
    }
    assert set(r["hashes"]) == expected_hashes


def test_mimikatz_sample_usermap():
    content = _sample("mimikatz_sample.txt")
    r = parse_hashes(content)
    assert "Administrator" in r["usermap"]["8846f7eaee8fb117ad06bdd830b7586c"]
    assert "jdupont" in r["usermap"]["64f12cddaa88057e06a81b54e73b949b"]


def test_mimikatz_null_ntlm_rejected():
    content = _sample("mimikatz_sample.txt")
    r = parse_hashes(content)
    null_count = r["rejected_cat"].get("NTLM (null) — pas de creds en mémoire", 0)
    assert null_count == 2  # guest et WORKGROUP$


def test_mimikatz_lm_empty_rejected():
    content = _sample("mimikatz_sample.txt")
    r = parse_hashes(content)
    lm_empty_count = r["rejected_cat"].get("LM vide (hash nul)", 0)
    assert lm_empty_count == 1  # WORKGROUP$ LM


def test_mimikatz_metadata_rejected():
    content = _sample("mimikatz_sample.txt")
    r = parse_hashes(content)
    assert r["rejected_cat"].get("Métadonnées / contexte", 0) > 0


def test_mimikatz_minimal():
    """Bloc mimikatz minimal — un seul user/hash."""
    content = "\n".join([
        "\t * Username : testuser",
        "\t * Domain   : CORP",
        "\t * NTLM     : aaaabbbbccccddddaaaabbbbccccdddd",
        "\t * SHA1     : aabbccddee1122334455aabbccddee1122334455",
        "some metadata",
        "more metadata",
    ])
    r = parse_hashes(content)
    assert r["format"] == "mimikatz"
    assert "aaaabbbbccccddddaaaabbbbccccdddd" in r["hashes"]
    assert "testuser" in r["usermap"]["aaaabbbbccccddddaaaabbbbccccdddd"]


def test_mimikatz_ntlm_no_username_context():
    """NTLM sans Username précédent → extrait sans usermap entry."""
    content = "\n".join([
        "Authentication Id : 0 ; 999",
        "Session : Service from 0",
        "\t * NTLM     : aaaabbbbccccddddaaaabbbbccccdddd",
        "metadata",
        "metadata",
    ])
    r = parse_hashes(content)
    assert r["format"] == "mimikatz"
    assert "aaaabbbbccccddddaaaabbbbccccdddd" in r["hashes"]
    assert "aaaabbbbccccddddaaaabbbbccccdddd" not in r["usermap"]


def test_mimikatz_lm_real_hash_rejected_separate_category():
    """Un vrai LM hash (non nul) doit être rejeté dans la bonne catégorie."""
    content = "\n".join([
        "\t * Username : user1",
        "\t * NTLM     : aaaabbbbccccddddaaaabbbbccccdddd",
        "\t * LM       : e52cac67419a9a224a3b108f3fa6cb6d",
        "metadata",
        "metadata",
    ])
    r = parse_hashes(content)
    assert r["format"] == "mimikatz"
    assert "e52cac67419a9a224a3b108f3fa6cb6d" not in r["hashes"]
    assert r["rejected_cat"].get("LM hash (type différent, -m 3000)", 0) == 1


# ── parse_hashes — detection threshold ───────────────────────────────────────

def test_secretsdump_below_threshold_falls_to_mimikatz_or_raw():
    """Moins de 50% de lignes secretsdump → pas détecté comme secretsdump."""
    lines = [
        "CORP\\user1:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "plaintext line one",
        "plaintext line two",
        "plaintext line three",
    ]
    r = parse_hashes("\n".join(lines))
    assert r["format"] != "secretsdump"


def test_secretsdump_exactly_50pct():
    """Exactement 50% de lignes valides → détecté comme secretsdump."""
    lines = [
        "CORP\\user1:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "# comment",
    ]
    r = parse_hashes("\n".join(lines))
    assert r["format"] == "secretsdump"


# ── /api/parse_hashes endpoint ────────────────────────────────────────────────

def test_api_parse_hashes_requires_auth(client):
    resp = client.post("/api/parse_hashes",
                       data=json.dumps({"content": "test"}),
                       content_type="application/json")
    assert resp.status_code in (302, 401, 403)


def test_api_parse_hashes_json_secretsdump(auth_client):
    content = "\n".join([
        "CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
        "CORP\\user1:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::",
    ])
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": content}),
                            content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["format"] == "secretsdump"
    assert data["hash_count"] == 2
    assert isinstance(data["hashes"], str)
    assert len(data["hashes"].splitlines()) == 2


def test_api_parse_hashes_json_mimikatz(auth_client):
    content = "\n".join([
        "\t * Username : admin",
        "\t * Domain   : CORP",
        "\t * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c",
        "metadata line",
        "metadata line",
        "metadata line",
    ])
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": content}),
                            content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["format"] == "mimikatz"
    assert data["hash_count"] == 1


def test_api_parse_hashes_file_upload(auth_client):
    content = _sample("secretsdump_sample.txt")
    resp = auth_client.post(
        "/api/parse_hashes",
        data={"file": (io.BytesIO(content.encode()), "secretsdump_sample.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["format"] == "secretsdump"
    assert data["hash_count"] == 10


def test_api_parse_hashes_zero_hashes(auth_client):
    """Si aucun hash extrait (comptes tous désactivés), hash_count == 0."""
    content = "\n".join([
        "guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    ])
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": content}),
                            content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["hash_count"] == 0


def test_api_parse_hashes_rejected_stats(auth_client):
    content = _sample("secretsdump_sample.txt")
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": content}),
                            content_type="application/json")
    data = json.loads(resp.data)
    assert data["rejected_count"] > 0
    assert isinstance(data["rejected_cat"], dict)
    assert isinstance(data["rejected_preview"], list)
    assert len(data["rejected_preview"]) <= 10


def test_api_parse_hashes_candidates_returned(auth_client):
    """Le champ candidates doit être renseigné pour des NT hashes (NTLM = type connu)."""
    content = "CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": content}),
                            content_type="application/json")
    data = json.loads(resp.data)
    assert isinstance(data.get("candidates"), list)


def test_api_parse_hashes_empty_body(auth_client):
    resp = auth_client.post("/api/parse_hashes",
                            data=json.dumps({"content": ""}),
                            content_type="application/json")
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert "error" in data


def test_api_parse_hashes_mimikatz_file_upload(auth_client):
    content = _sample("mimikatz_sample.txt")
    resp = auth_client.post(
        "/api/parse_hashes",
        data={"file": (io.BytesIO(content.encode()), "mimikatz_sample.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["format"] == "mimikatz"
    assert data["hash_count"] == 6
    assert data["rejected_count"] > 0
