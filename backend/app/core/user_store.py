"""
Persistencia simple de usuarios y token blacklist en JSON.
En produccion se recomienda usar PostgreSQL/Redis.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core.config import settings

DATA_DIR = Path(os.environ.get("DATA_DIR", "."))
USERS_FILE = DATA_DIR / "users.json"
BLACKLIST_FILE = DATA_DIR / "token_blacklist.json"


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def load_users() -> dict:
    return _load_json(USERS_FILE)


def save_users(users: dict):
    _save_json(USERS_FILE, users)


def load_blacklist() -> set:
    data = _load_json(BLACKLIST_FILE)
    return set(data.keys())


def save_blacklist(blacklist: set):
    data = {jti: datetime.utcnow().isoformat() for jti in blacklist}
    _save_json(BLACKLIST_FILE, data)


# In-memory cache with persistence helpers
_users_cache: Optional[dict] = None
_blacklist_cache: Optional[set] = None


def get_users() -> dict:
    global _users_cache
    if _users_cache is None:
        _users_cache = load_users()
    return _users_cache


def set_users(users: dict):
    global _users_cache
    _users_cache = users
    save_users(users)


def get_blacklist() -> set:
    global _blacklist_cache
    if _blacklist_cache is None:
        _blacklist_cache = load_blacklist()
    return _blacklist_cache


def add_to_blacklist(jti: str):
    blacklist = get_blacklist()
    blacklist.add(jti)
    save_blacklist(blacklist)


def is_blacklisted(jti: str) -> bool:
    return jti in get_blacklist()
