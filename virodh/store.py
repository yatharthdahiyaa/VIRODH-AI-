"""
SQLite persistence: API keys, policies, request log, rate-limit windows.

Why SQLite: zero extra services, and it is correct across uvicorn worker processes on one host
(writers are serialised by SQLite's lock, WAL lets readers run while one process writes).
Inside a process all writes go through ONE thread, so the event loop never waits on the DB lock
and writers in the same process never contend with each other.

API keys are stored as SHA-256 hashes (keys carry 256 bits of entropy, so a slow hash is not needed);
the secret is shown once at creation and cannot be recovered.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from virodh.policy import Policy

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, prefix TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
  policy TEXT NOT NULL, rpm INTEGER NOT NULL, rpd INTEGER NOT NULL, allowed_models TEXT NOT NULL DEFAULT '[]',
  created REAL NOT NULL, last_used REAL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS policies (name TEXT PRIMARY KEY, json TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, ts REAL NOT NULL, key_id TEXT, key_name TEXT, endpoint TEXT, model TEXT, policy TEXT,
  mode TEXT, decision TEXT, action TEXT, status INTEGER, risk REAL, category TEXT, reasons TEXT,
  operator_hits TEXT, adversarial TEXT, output_guard TEXT, fail_safe INTEGER, cache_hits INTEGER, units INTEGER,
  n_images INTEGER, guard_ms REAL, upstream_ms REAL, total_ms REAL, tokens_in INTEGER, tokens_out INTEGER,
  prompt_sha TEXT, image_shas TEXT, prompt_preview TEXT, error TEXT, worker INTEGER
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_key ON requests(key_id, ts);
CREATE TABLE IF NOT EXISTS rate (key_id TEXT NOT NULL, win TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (key_id, win));
"""

KEY_PREFIX = "vk_"
LOG_FIELDS = (
    "id",
    "ts",
    "key_id",
    "key_name",
    "endpoint",
    "model",
    "policy",
    "mode",
    "decision",
    "action",
    "status",
    "risk",
    "category",
    "reasons",
    "operator_hits",
    "adversarial",
    "output_guard",
    "fail_safe",
    "cache_hits",
    "units",
    "n_images",
    "guard_ms",
    "upstream_ms",
    "total_ms",
    "tokens_in",
    "tokens_out",
    "prompt_sha",
    "image_shas",
    "prompt_preview",
    "error",
    "worker",
)
JSON_FIELDS = ("reasons", "operator_hits", "adversarial", "output_guard", "image_shas")


def hash_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class KeyRecord:
    id: str
    name: str
    prefix: str
    policy: str
    rpm: int
    rpd: int
    allowed_models: list[str] = field(default_factory=list)
    created: float = 0.0
    last_used: float | None = None
    revoked: bool = False

    def public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "prefix": self.prefix,
            "policy": self.policy,
            "rpm": self.rpm,
            "rpd": self.rpd,
            "allowed_models": self.allowed_models,
            "created": self.created,
            "last_used": self.last_used,
            "revoked": self.revoked,
        }


def _key_row(r: sqlite3.Row) -> KeyRecord:
    return KeyRecord(
        id=r["id"],
        name=r["name"],
        prefix=r["prefix"],
        policy=r["policy"],
        rpm=r["rpm"],
        rpd=r["rpd"],
        allowed_models=json.loads(r["allowed_models"] or "[]"),
        created=r["created"],
        last_used=r["last_used"],
        revoked=bool(r["revoked"]),
    )


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._writer = ThreadPoolExecutor(max_workers=1, thread_name_prefix="virodh-db-writer")
        self._readers = ThreadPoolExecutor(max_workers=4, thread_name_prefix="virodh-db-reader")
        c = self._conn()
        c.executescript(SCHEMA)
        self._key_cache: dict[str, tuple[float, KeyRecord | None]] = {}
        self._policy_cache: dict[str, tuple[float, Policy | None]] = {}
        self._hits_since_prune = 0

    # ---------------- connections ----------------
    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=15000")
            self._local.conn = c
        return c

    async def write(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(self._writer, fn, *args)

    async def read(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(self._readers, fn, *args)

    def close(self) -> None:
        self._writer.shutdown(wait=True)
        self._readers.shutdown(wait=True)

    # ---------------- policies ----------------
    def seed_policies(self, seeds: dict[str, dict]) -> None:
        c = self._conn()
        for name, spec in (seeds or {}).items():
            p = Policy(name=name, **spec)
            c.execute(
                "INSERT OR IGNORE INTO policies(name, json, updated) VALUES (?,?,?)",
                (name, p.model_dump_json(), time.time()),
            )

    def get_policy(self, name: str, ttl: float = 3.0) -> Policy | None:
        hit = self._policy_cache.get(name)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        row = self._conn().execute("SELECT json FROM policies WHERE name=?", (name,)).fetchone()
        p = Policy.model_validate_json(row["json"]) if row else None
        self._policy_cache[name] = (time.monotonic(), p)
        return p

    def list_policies(self) -> list[dict]:
        rows = self._conn().execute("SELECT json, updated FROM policies ORDER BY name").fetchall()
        used = dict(
            self._conn().execute("SELECT policy, COUNT(*) FROM api_keys WHERE revoked=0 GROUP BY policy").fetchall()
        )
        return [
            {**json.loads(r["json"]), "updated": r["updated"], "keys_using": used.get(json.loads(r["json"])["name"], 0)}
            for r in rows
        ]

    def upsert_policy(self, p: Policy) -> None:
        self._conn().execute(
            "INSERT INTO policies(name, json, updated) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE "
            "SET json=excluded.json, updated=excluded.updated",
            (p.name, p.model_dump_json(), time.time()),
        )
        self._policy_cache.pop(p.name, None)

    def delete_policy(self, name: str) -> str:
        c = self._conn()
        if name == "default":
            return "the default policy cannot be deleted"
        n = c.execute("SELECT COUNT(*) FROM api_keys WHERE policy=? AND revoked=0", (name,)).fetchone()[0]
        if n:
            return f"{n} active API key(s) use this policy"
        c.execute("DELETE FROM policies WHERE name=?", (name,))
        self._policy_cache.pop(name, None)
        return ""

    # ---------------- API keys ----------------
    def create_key(
        self, name: str, policy: str, rpm: int, rpd: int, allowed_models: list[str]
    ) -> tuple[str, KeyRecord]:
        secret = KEY_PREFIX + secrets.token_urlsafe(32)
        rec = KeyRecord(
            id="key_" + secrets.token_hex(6),
            name=name,
            prefix=secret[:11] + "…",
            policy=policy,
            rpm=rpm,
            rpd=rpd,
            allowed_models=allowed_models,
            created=time.time(),
        )
        self._conn().execute(
            "INSERT INTO api_keys(id,name,prefix,hash,policy,rpm,rpd,allowed_models,created) VALUES (?,?,?,?,?,?,?,?,?)",
            (rec.id, rec.name, rec.prefix, hash_key(secret), policy, rpm, rpd, json.dumps(allowed_models), rec.created),
        )
        return secret, rec

    def find_key(self, secret: str, ttl: float = 5.0) -> KeyRecord | None:
        """Lookup by hash. Cached for a few seconds, so a revocation reaches every worker within `ttl`."""
        if not secret or not secret.startswith(KEY_PREFIX) or len(secret) > 100:
            return None
        h = hash_key(secret)
        hit = self._key_cache.get(h)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        row = self._conn().execute("SELECT * FROM api_keys WHERE hash=?", (h,)).fetchone()
        rec = _key_row(row) if row else None
        if len(self._key_cache) > 10_000:
            self._key_cache.clear()
        self._key_cache[h] = (time.monotonic(), rec)
        return rec

    def list_keys(self) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM api_keys ORDER BY created DESC").fetchall()
        return [_key_row(r).public() for r in rows]

    def update_key(self, key_id: str, **fields) -> bool:
        allowed = {"name", "policy", "rpm", "rpd", "allowed_models", "revoked"}
        sets = {
            k: (json.dumps(v) if k == "allowed_models" else int(v) if k == "revoked" else v)
            for k, v in fields.items()
            if k in allowed and v is not None
        }
        if not sets:
            return False
        cur = self._conn().execute(
            f"UPDATE api_keys SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?", (*sets.values(), key_id)
        )
        self._key_cache.clear()
        return cur.rowcount > 0

    # ---------------- rate limiting (fixed windows, shared by all workers) ----------------
    def rate_hit(self, key_id: str, rpm: int, rpd: int, now: float | None = None) -> tuple[bool, int, int]:
        """Atomically count one request against the minute and day windows.
        Returns (allowed, retry_after_seconds, remaining_this_minute). Rejected requests are not counted."""
        now = now or time.time()
        m_win, d_win = f"m:{int(now // 60)}", "d:" + time.strftime("%Y-%m-%d", time.gmtime(now))
        c = self._conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            got = dict(
                c.execute("SELECT win, n FROM rate WHERE key_id=? AND win IN (?,?)", (key_id, m_win, d_win)).fetchall()
            )
            used_m, used_d = got.get(m_win, 0), got.get(d_win, 0)
            if rpm and used_m >= rpm:
                c.execute("ROLLBACK")
                return False, max(1, int(60 - now % 60)), 0
            if rpd and used_d >= rpd:
                c.execute("ROLLBACK")
                return False, max(1, int(86400 - now % 86400)), 0
            c.executemany(
                "INSERT INTO rate(key_id, win, n) VALUES (?,?,1) ON CONFLICT(key_id, win) DO UPDATE SET n=n+1",
                [(key_id, m_win), (key_id, d_win)],
            )
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        self._hits_since_prune += 1
        if self._hits_since_prune >= 500:
            self._hits_since_prune = 0
            c.execute(
                "DELETE FROM rate WHERE win LIKE 'm:%' AND CAST(substr(win, 3) AS INTEGER) < ?", (int(now // 60) - 5,)
            )
        return True, 0, max(0, rpm - used_m - 1) if rpm else -1

    # ---------------- request log ----------------
    def log_request(self, row: dict) -> None:
        vals = [
            json.dumps(row.get(f), ensure_ascii=False) if f in JSON_FIELDS and row.get(f) is not None else row.get(f)
            for f in LOG_FIELDS
        ]
        c = self._conn()
        c.execute(
            f"INSERT OR REPLACE INTO requests({','.join(LOG_FIELDS)}) VALUES ({','.join('?' * len(LOG_FIELDS))})", vals
        )
        if row.get("key_id"):
            c.execute("UPDATE api_keys SET last_used=? WHERE id=?", (row["ts"], row["key_id"]))

    def prune(self, retention_days: int) -> int:
        cur = self._conn().execute("DELETE FROM requests WHERE ts < ?", (time.time() - retention_days * 86400,))
        return cur.rowcount

    @staticmethod
    def _decode(r: sqlite3.Row) -> dict:
        d = dict(r)
        for f in JSON_FIELDS:
            if d.get(f):
                with contextlib.suppress(ValueError):
                    d[f] = json.loads(d[f])
        return d

    def list_requests(
        self,
        limit: int = 50,
        offset: int = 0,
        decision: str = "",
        key_id: str = "",
        action: str = "",
        owner_key_ids: list[str] | None = None,
        owner_key_name: str = "",
    ) -> dict:
        """owner_*: restrict to one user's keys and/or playground label (used by the Node dashboard for members)."""
        where, args = [], []
        if decision:
            where.append("decision=?")
            args.append(decision)
        if key_id:
            where.append("key_id=?")
            args.append(key_id)
        if owner_key_ids is not None or owner_key_name:
            ids = list(owner_key_ids or [])
            parts = []
            if ids:
                parts.append(f"key_id IN ({','.join('?' * len(ids))})")
                args.extend(ids)
            if owner_key_name:
                parts.append("key_name=?")
                args.append(owner_key_name)
            where.append("(" + " OR ".join(parts) + ")" if parts else "0")
        if action:
            where.append("action=?")
            args.append(action)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        c = self._conn()
        total = c.execute(f"SELECT COUNT(*) FROM requests {w}", args).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM requests {w} ORDER BY ts DESC LIMIT ? OFFSET ?", (*args, limit, offset)
        ).fetchall()
        return {"total": total, "items": [self._decode(r) for r in rows]}

    def get_request(self, rid: str) -> dict | None:
        r = self._conn().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return self._decode(r) if r else None

    def usage(self, hours: int = 24) -> dict:
        """Aggregates over ALL workers (the DB is shared), bucketed per hour."""
        now = time.time()
        since = now - hours * 3600
        c = self._conn()
        buckets = c.execute(
            "SELECT CAST(ts / 3600 AS INTEGER) AS h, decision, action, COUNT(*) AS n FROM requests WHERE ts >= ? "
            "GROUP BY h, decision, action",
            (since,),
        ).fetchall()
        series: dict[int, dict[str, int]] = {}
        for b in buckets:
            s = series.setdefault(b["h"], {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0, "rejected": 0})
            key = b["decision"] if b["decision"] in ("ALLOW", "REVIEW", "BLOCK") else "rejected"
            s[key] += b["n"]
        first = int(since // 3600) + 1
        hourly = [
            {"hour": h * 3600, **series.get(h, {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0, "rejected": 0})}
            for h in range(first, int(now // 3600) + 1)
        ]
        per_key = [
            dict(r)
            for r in c.execute(
                "SELECT COALESCE(key_name, '-') AS key_name, COUNT(*) AS requests, "
                "SUM(decision='BLOCK') AS blocked, SUM(decision='REVIEW') AS review, SUM(action='forwarded') AS forwarded, "
                "SUM(COALESCE(tokens_in,0)) AS tokens_in, SUM(COALESCE(tokens_out,0)) AS tokens_out "
                "FROM requests WHERE ts >= ? GROUP BY key_name ORDER BY requests DESC LIMIT 20",
                (since,),
            ).fetchall()
        ]
        per_model = [
            dict(r)
            for r in c.execute(
                "SELECT COALESCE(model, '-') AS model, COUNT(*) AS requests, SUM(action='forwarded') AS forwarded, "
                "AVG(upstream_ms) AS avg_upstream_ms FROM requests WHERE ts >= ? GROUP BY model ORDER BY requests DESC",
                (since,),
            ).fetchall()
        ]
        return {"hours": hours, "hourly": hourly, "per_key": per_key, "per_model": per_model}

    def overview(self, hours: int = 24) -> dict:
        since = time.time() - hours * 3600
        c = self._conn()
        rows = c.execute(
            "SELECT decision, action, category, guard_ms, total_ms, cache_hits, units, fail_safe, output_guard "
            "FROM requests WHERE ts >= ?",
            (since,),
        ).fetchall()
        dec = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
        actions: dict[str, int] = {}
        cats: dict[str, int] = {}
        guard_ms, total_ms = [], []
        hits = units = fail_safe = withheld = 0
        for r in rows:
            if r["decision"] in dec:
                dec[r["decision"]] += 1
            actions[r["action"] or "-"] = actions.get(r["action"] or "-", 0) + 1
            if r["category"]:
                k = r["category"].split(" | ")[0].split(":")[0].split(" (")[0][:40]
                cats[k] = cats.get(k, 0) + 1
            if r["guard_ms"] is not None:
                guard_ms.append(r["guard_ms"])
            if r["total_ms"] is not None:
                total_ms.append(r["total_ms"])
            hits += r["cache_hits"] or 0
            units += r["units"] or 0
            fail_safe += r["fail_safe"] or 0
            withheld += int(r["action"] == "withheld")

        def pct(vals, q):
            if not vals:
                return None
            s = sorted(vals)
            return round(s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))], 1)

        keys = c.execute("SELECT COUNT(*) FROM api_keys WHERE revoked=0").fetchone()[0]
        return {
            "hours": hours,
            "requests": len(rows),
            "decisions": dec,
            "actions": actions,
            "top_categories": sorted(cats.items(), key=lambda kv: -kv[1])[:6],
            "guard_ms_p50": pct(guard_ms, 0.5),
            "guard_ms_p95": pct(guard_ms, 0.95),
            "total_ms_p50": pct(total_ms, 0.5),
            "total_ms_p95": pct(total_ms, 0.95),
            "cache_hit_rate": round(hits / units, 3) if units else None,
            "fail_safe": fail_safe,
            "withheld_by_output_guard": withheld,
            "active_keys": keys,
        }
