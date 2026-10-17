"""
Historial de analisis POR USUARIO, persistido en JSON (data/history.json).

Reemplaza la lista global en memoria del orquestador, que mezclaba los
escaneos de todos los usuarios y se perdia al reiniciar.

Notas:
- Reutiliza la resolucion de DATA_DIR de user_store (mismo directorio).
- Thread-safe (lock) y escritura atomica (tmp + os.replace).
- Solo apto para proceso UNICO (ver Dockerfile: --workers 1).
En produccion se recomienda PostgreSQL/Redis.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional

# Same data dir as user_store (DATA_DIR env var or <backend>/data).
from app.core.user_store import DATA_DIR

HISTORY_FILE = DATA_DIR / "history.json"

# Max entries kept per user; oldest are dropped first.
MAX_ENTRIES_PER_USER = 100
# Target summaries are truncated; full payloads (e.g. file bytes) must never
# reach this store.
MAX_TARGET_LENGTH = 200
# How many entries the dashboard "recent" list returns.
RECENT_LIMIT = 10
# Metadata keys that can grow very large (external API responses); they are
# stripped before persisting.
BULKY_METADATA_KEYS = {"virustotal_results", "hibp_result", "breaches"}

_lock = threading.Lock()
_cache: Optional[dict[str, list[dict]]] = None


def _load() -> dict[str, list[dict]]:
    if not HISTORY_FILE.exists():
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return {
            str(user_id): [e for e in entries if isinstance(e, dict)]
            for user_id, entries in data.items()
            if isinstance(entries, list)
        }
    except Exception:
        return {}


def _save(data: dict[str, list[dict]]):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = HISTORY_FILE.with_name(HISTORY_FILE.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, HISTORY_FILE)


def _get() -> dict[str, list[dict]]:
    global _cache
    if _cache is None:
        _cache = _load()
    return _cache


def add_entry(user_id: str, entry: dict):
    """Append an analysis entry for a user, capping the per-user history."""
    if not user_id or not isinstance(entry, dict):
        return
    with _lock:
        data = _get()
        entries = data.setdefault(user_id, [])
        entries.append(entry)
        if len(entries) > MAX_ENTRIES_PER_USER:
            # Drop the oldest entries first.
            del entries[: len(entries) - MAX_ENTRIES_PER_USER]
        _save(data)


def get_entries(user_id: str) -> list[dict]:
    """Return the user's entries, oldest first."""
    if not user_id:
        return []
    with _lock:
        return list(_get().get(user_id, []))


def get_stats(user_id: str) -> dict:
    """Aggregates needed by the dashboard for a single user."""
    entries = get_entries(user_id)
    total = len(entries)
    distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    threats = 0
    risk_sum = 0.0

    for entry in entries:
        risk_score = entry.get("risk_score") or {}
        level = risk_score.get("level", "low")
        if level not in distribution:
            level = "low"
        distribution[level] += 1
        if level in ("high", "critical"):
            threats += 1
        try:
            risk_sum += float(risk_score.get("total", 0) or 0)
        except (TypeError, ValueError):
            pass

    return {
        "total_scans": total,
        "threats_detected": threats,
        "average_risk": round(risk_sum / total, 1) if total else 0.0,
        "risk_distribution": distribution,
        # Newest first, limited to the dashboard's recent window.
        "recent_analyses": list(reversed(entries))[:RECENT_LIMIT],
    }
