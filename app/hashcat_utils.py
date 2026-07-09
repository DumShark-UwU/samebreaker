from __future__ import annotations

import os
import re
import shlex
import subprocess
import shutil
from typing import Optional

HASHCAT_BIN  = shutil.which("hashcat") or os.environ.get("HASHCAT_PATH", "hashcat")
HASHCAT_FORCE: bool = True  # peut être désactivé via config.json → hashcat_force: false

WORDLIST_DIRS: list[str] = [
    "/usr/share/wordlists",
    "/opt/wordlists",
    os.path.expanduser("~/wordlists"),
    "wordlists",
    "instance/wordlists",
]

ATTACK_MODES: dict[int, str] = {
    0: "Dictionnaire",
    1: "Combinateur",
    3: "Brute-force / Mask",
    6: "Hybride wordlist + mask",
    7: "Hybride mask + wordlist",
}

_DEVICE_ID_PATTERN   = re.compile(r"\s*Backend Device ID #(\d+)")
_DEVICE_NAME_PATTERN = re.compile(r"\s*Name\.{5,}:\s*(.+)")
_DEVICE_TYPE_PATTERN = re.compile(r"\s*Type\.{5,}:\s*(.+)")
_SECTION_PATTERN     = re.compile(r"^[A-Za-z]")

_MAX_HASH_CANDIDATES = 12


def hashcat_available() -> tuple[bool, Optional[str]]:
    try:
        result = subprocess.run(
            [HASHCAT_BIN, "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0, result.stdout.decode().strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, None


def get_devices() -> list[dict]:
    ok, _ = hashcat_available()
    if not ok:
        return []
    try:
        result = subprocess.run([HASHCAT_BIN, "-I"], capture_output=True, timeout=10)
        output = result.stdout.decode()
        devices: list[dict] = []
        current: dict = {}
        for line in output.splitlines():
            # Header de section top-level (ex : "OpenCL Info:", "OpenCL Platform ID #1")
            # → clôture le device courant et remet le contexte à zéro
            if _SECTION_PATTERN.match(line) and not _DEVICE_ID_PATTERN.match(line):
                if current:
                    devices.append(current)
                current = {}
                continue
            m = _DEVICE_ID_PATTERN.match(line)
            if m:
                if current:
                    devices.append(current)
                current = {"id": int(m.group(1)), "name": "", "type": ""}
                continue
            m = _DEVICE_NAME_PATTERN.match(line)
            if m and current:
                current["name"] = m.group(1).strip()
                continue
            m = _DEVICE_TYPE_PATTERN.match(line)
            if m and current:
                current["type"] = m.group(1).strip()
        if current:
            devices.append(current)
        return [d for d in devices if d.get("type", "").upper() != "CPU"]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def get_wordlists() -> list[dict]:
    found: list[dict] = []
    for directory in WORDLIST_DIRS:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            full_path = os.path.join(directory, filename)
            if os.path.isfile(full_path) and not filename.endswith(".7z"):
                found.append({
                    "path": full_path,
                    "name": filename,
                    "size": os.path.getsize(full_path),
                })
    return found


_LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"

# secretsdump: [DOMAIN\]user:RID:LM32:NT32::: (avec ou sans domaine)
_RE_SECRETSDUMP = re.compile(
    r'^(?:[^:\\]+\\)?([^:]+):\d+:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$'
)
# mimikatz sekurlsa — lignes hash
_RE_MIMI_NTLM = re.compile(r'^\s*\*?\s*(?:Hash\s+)?NTLM\s*:\s*([0-9a-fA-F]{32})\s*$', re.I)
_RE_MIMI_LM   = re.compile(r'^\s*\*?\s*(?:Hash\s+)?LM\s*:\s*([0-9a-fA-F]{32})\s*$', re.I)
_RE_MIMI_USER = re.compile(r'^\s*\*?\s*Username\s*:\s*(.+)$', re.I)
_RE_MIMI_NULL = re.compile(r'^\s*\*?\s*(?:Hash\s+)?NTLM\s*:\s*\(null\)\s*$', re.I)


def parse_hashes(content: str) -> dict:
    """
    Détecte et parse les formats secretsdump et mimikatz.
    Retourne un dict avec :
      format           : "secretsdump" | "mimikatz" | "raw"
      hashes           : list[str]  — hashes propres prêts pour hashcat
      usermap          : dict[hash, list[str]]  — mapping hash→[users]
      rejected         : list[str]  — lignes rejetées brutes
      rejected_cat     : dict[str, int]  — catégories de rejets avec compteurs
      rejected_details : list[tuple[str, str]]  — (ligne, catégorie) par ligne rejetée
    """
    lines = [l for l in content.splitlines() if l.strip()]
    if not lines:
        return {"format": "raw", "hashes": [], "usermap": {}, "rejected": [],
                "rejected_cat": {}, "rejected_details": []}

    def _empty() -> dict:
        return {"hashes": [], "usermap": {}, "rejected": [], "rejected_cat": {}, "rejected_details": []}

    def _reject(state: dict, line: str, cat: str) -> None:
        state["rejected"].append(line)
        state["rejected_details"].append((line, cat))
        state["rejected_cat"][cat] = state["rejected_cat"].get(cat, 0) + 1

    # ── Détection secretsdump ──────────────────────────────────────────────
    sd_matches = [_RE_SECRETSDUMP.match(l) for l in lines]
    sd_ratio   = sum(1 for m in sd_matches if m) / len(lines)
    if sd_ratio >= 0.5:
        s = _empty()
        for line, m in zip(lines, sd_matches):
            if not m:
                _reject(s, line, "Format non reconnu")
                continue
            user, lm, nt = m.group(1), m.group(2).lower(), m.group(3).lower()
            if nt == "31d6cfe0d16ae931b73c59d7e0c089c0":
                _reject(s, line, "Compte désactivé / mot de passe vide (NT vide)")
                continue
            s["hashes"].append(nt)
            s["usermap"].setdefault(nt, []).append(user)
        return {"format": "secretsdump", **s}

    # ── Détection mimikatz ─────────────────────────────────────────────────
    mimi_score = sum(1 for l in lines
                     if _RE_MIMI_NTLM.match(l) or _RE_MIMI_NULL.match(l)
                     or _RE_MIMI_USER.match(l) or _RE_MIMI_LM.match(l))
    if mimi_score / len(lines) >= 0.05:
        s = _empty()
        current_user: Optional[str] = None
        for line in lines:
            if _RE_MIMI_USER.match(line):
                current_user = _RE_MIMI_USER.match(line).group(1).strip()
                continue
            if _RE_MIMI_NULL.match(line):
                _reject(s, line, "NTLM (null) — pas de creds en mémoire")
                current_user = None
                continue
            m = _RE_MIMI_NTLM.match(line)
            if m:
                nt = m.group(1).lower()
                s["hashes"].append(nt)
                if current_user:
                    s["usermap"].setdefault(nt, []).append(current_user)
                current_user = None
                continue
            m = _RE_MIMI_LM.match(line)
            if m:
                lm = m.group(1).lower()
                cat = "LM vide (hash nul)" if lm == _LM_EMPTY else "LM hash (type différent, -m 3000)"
                _reject(s, line, cat)
                continue
            _reject(s, line, "Métadonnées / contexte")
        return {"format": "mimikatz", **s}

    return {"format": "raw", "hashes": lines, "usermap": {}, "rejected": [],
            "rejected_cat": {}, "rejected_details": []}


def detect_hash(hash_str: str) -> list[dict]:
    """Identifie les types de hash possibles, classés par probabilité décroissante."""
    try:
        import name_that_hash as nth
        h = hash_str.strip()
        raw = nth.runner.api_return_hashes_as_dict([h])
        candidates: list[dict] = raw.get(h, [])

        def _sort_key(c: dict) -> tuple[int, int]:
            return (int(c.get("extended", False)), int(c.get("hashcat") is None))

        candidates = sorted(candidates, key=_sort_key)
        return [
            {
                "name":        c.get("name", ""),
                "hashcat":     c.get("hashcat"),
                "john":        c.get("john"),
                "description": c.get("description") or "",
                "extended":    c.get("extended", False),
            }
            for c in candidates[:_MAX_HASH_CANDIDATES]
        ]
    except ImportError:
        return []
    except Exception:
        return []


def build_command(job: dict) -> list[str]:
    cmd: list[str] = [HASHCAT_BIN]
    cmd += ["-m", str(job["hash_type"])]
    cmd += ["-a", str(job["attack_mode"])]
    cmd.append(job["hash_file"])

    mode = job["attack_mode"]
    # Positional args vary by attack mode (hashcat syntax):
    #   0: hash_file wordlist
    #   1: hash_file wordlist1 wordlist2
    #   3: hash_file mask
    #   6: hash_file wordlist mask
    #   7: hash_file mask wordlist
    if mode == 0 and job.get("wordlist"):
        cmd.append(job["wordlist"])
    elif mode == 1 and job.get("wordlist"):
        cmd += job["wordlist"].split("|")[:2]
    elif mode == 3 and job.get("mask"):
        cmd.append(job["mask"])
    elif mode == 6:
        if job.get("wordlist"):
            cmd.append(job["wordlist"])
        if job.get("mask"):
            cmd.append(job["mask"])
    elif mode == 7:
        if job.get("mask"):
            cmd.append(job["mask"])
        if job.get("wordlist"):
            cmd.append(job["wordlist"])

    if job.get("rules"):
        cmd += ["-r", job["rules"]]
    if job.get("devices"):
        cmd += ["-d", job["devices"]]
    if job.get("pot_file"):
        cmd += ["--potfile-path", job["pot_file"]]
    if job.get("restore_file"):
        cmd += ["--restore-file-path", job["restore_file"]]

    workload = job.get("workload") or 2
    cmd += [
        "--status",
        "--status-timer=2",
        "--outfile-format=2",
        "-w", str(workload),
    ]
    if HASHCAT_FORCE:
        cmd.append("--force")

    # Ajouter --username si format user:hash détecté et pas déjà dans extra_args
    extra = job.get("extra_args") or ""
    try:
        extra_parts = shlex.split(extra)
    except ValueError:
        extra_parts = [extra] if extra else []
    if job.get("has_usermap") and "--username" not in extra_parts:
        cmd.append("--username")

    if extra_parts:
        cmd += extra_parts

    return cmd
