"""Durable completion records and provider response cache."""

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


class State:
    def __init__(self, path: Path, vt_quota_path: Path | None = None):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        if vt_quota_path is None or vt_quota_path == path:
            self.quota_db = self.db
        else:
            vt_quota_path.parent.mkdir(parents=True, exist_ok=True)
            self.quota_db = sqlite3.connect(vt_quota_path, timeout=30)
        self.db.execute("""CREATE TABLE IF NOT EXISTS captures (
            sha256 TEXT NOT NULL, profile TEXT NOT NULL, json_path TEXT NOT NULL,
            csv_path TEXT NOT NULL, completed_at REAL NOT NULL,
            PRIMARY KEY (sha256, profile))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS cache (
            provider TEXT NOT NULL, ip TEXT NOT NULL, result_json TEXT NOT NULL,
            expires_at REAL NOT NULL, PRIMARY KEY (provider, ip))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS virustotal_cache (
            ip TEXT PRIMARY KEY, result_json TEXT NOT NULL,
            looked_up_at TEXT NOT NULL, expires_at REAL NOT NULL)""")
        self.quota_db.execute("""CREATE TABLE IF NOT EXISTS virustotal_requests (
            requested_at REAL NOT NULL, utc_day TEXT NOT NULL)""")
        self.quota_db.execute("CREATE INDEX IF NOT EXISTS vt_requests_time ON virustotal_requests(requested_at)")
        self.quota_db.execute("CREATE INDEX IF NOT EXISTS vt_requests_day ON virustotal_requests(utc_day)")
        self.db.commit()
        if self.quota_db is not self.db:
            self.quota_db.commit()

    def completed(self, sha256: str, profile: str) -> tuple[Path, Path] | None:
        row = self.db.execute("SELECT json_path, csv_path FROM captures WHERE sha256=? AND profile=?",
                              (sha256, profile)).fetchone()
        if row and all(Path(item).is_file() for item in row):
            return Path(row[0]), Path(row[1])
        return None

    def mark_complete(self, sha256: str, profile: str, json_path: Path, csv_path: Path):
        with self.db:
            self.db.execute("REPLACE INTO captures VALUES (?, ?, ?, ?, ?)",
                            (sha256, profile, str(json_path), str(csv_path), time.time()))

    def cached(self, provider: str, ip: str) -> dict | None:
        row = self.db.execute("SELECT result_json FROM cache WHERE provider=? AND ip=? AND expires_at>?",
                              (provider, ip, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def save_cache(self, provider: str, ip: str, result: dict, hours: float):
        if result["status"] not in ("found", "no_result"):
            return
        with self.db:
            self.db.execute("REPLACE INTO cache VALUES (?, ?, ?, ?)",
                            (provider, ip, json.dumps(result), time.time() + hours * 3600))

    def vt_cached(self, ip: str) -> dict | None:
        row = self.db.execute(
            "SELECT result_json FROM virustotal_cache WHERE ip=? AND expires_at>?",
            (ip, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def vt_save_cache(self, ip: str, result: dict, hours: float):
        if result["status"] not in ("found", "no_result"):
            return
        with self.db:
            self.db.execute("REPLACE INTO virustotal_cache VALUES (?, ?, ?, ?)",
                            (ip, json.dumps(result), result["looked_up_at"],
                             time.time() + hours * 3600))

    def vt_reserve_request(self, now: float | None = None) -> float | None:
        """Reserve one request. Return wait seconds, zero if reserved, or None at daily cap."""
        now = time.time() if now is None else now
        day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
        db = self.quota_db
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("DELETE FROM virustotal_requests WHERE requested_at < ? AND utc_day != ?",
                            (now - 60, day))
            daily = db.execute(
                "SELECT COUNT(*) FROM virustotal_requests WHERE utc_day=?", (day,)).fetchone()[0]
            if daily >= 500:
                db.commit()
                return None
            recent = db.execute(
                "SELECT requested_at FROM virustotal_requests WHERE requested_at > ? "
                "ORDER BY requested_at", (now - 60,)).fetchall()
            if len(recent) >= 4:
                delay = max(0.001, recent[0][0] + 60.001 - now)
                db.commit()
                return delay
            db.execute("INSERT INTO virustotal_requests VALUES (?, ?)", (now, day))
            db.commit()
            return 0.0
        except Exception:
            db.rollback()
            raise

    def close(self):
        if self.quota_db is not self.db:
            self.quota_db.close()
        self.db.close()

