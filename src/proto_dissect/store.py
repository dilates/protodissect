"""Session store: SQLite + content-addressed blobs (ADR-0008)."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
    kind TEXT NOT NULL,
    blob_sha TEXT NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (kind, blob_sha)
);
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_cache_root() -> Path:
    return Path(os.environ.get("PROTODISSECT_CACHE", Path.home() / ".cache" / "protodissect"))


class Store:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_cache_root()
        self.objects = self.root / "objects"
        self.sessions = self.root / "sessions"

    def put_blob(self, data: bytes) -> str:
        sha = sha256_bytes(data)
        blob = self.objects / sha[:2] / sha
        if not blob.exists():
            blob.parent.mkdir(parents=True, exist_ok=True)
            tmp = blob.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, blob)
        return sha

    def get_blob(self, sha: str) -> bytes:
        blob = self.objects / sha[:2] / sha
        if not blob.exists():
            raise FileNotFoundError(f"blob {sha} missing from store")
        return blob.read_bytes()

    def put_json(self, obj: object) -> str:
        return self.put_blob(json.dumps(obj, sort_keys=True, indent=2).encode())

    def session_paths(self, session_id: str) -> Path:
        return self.sessions / session_id

    def create_session(self, session_id: str) -> Path:
        sdir = self.session_paths(session_id)
        sdir.mkdir(parents=True, exist_ok=True)
        return sdir

    def session_db(self, session_id: str) -> sqlite3.Connection:
        sdir = self.create_session(session_id)
        conn = sqlite3.connect(sdir / "session.db")
        conn.executescript(_SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('created', ?)",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),),
        )
        conn.commit()
        return conn

    def add_artifact(self, session_id: str, kind: str, blob_sha: str) -> None:
        conn = self.session_db(session_id)
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO artifacts (kind, blob_sha, created) VALUES (?, ?, ?)",
                (kind, blob_sha, time.time()),
            )
        conn.close()

    def get_artifacts(self, session_id: str, kind: str | None = None) -> list[tuple[str, str]]:
        conn = self.session_db(session_id)
        if kind is None:
            rows = conn.execute("SELECT kind, blob_sha FROM artifacts").fetchall()
        else:
            rows = conn.execute(
                "SELECT kind, blob_sha FROM artifacts WHERE kind = ?", (kind,)
            ).fetchall()
        conn.close()
        return sorted(rows)

    def list_sessions(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        if not self.sessions.exists():
            return out
        for sdir in sorted(self.sessions.iterdir()):
            db = sdir / "session.db"
            if not db.exists():
                continue
            try:
                conn = sqlite3.connect(db)
                row = conn.execute("SELECT value FROM meta WHERE key = 'created'").fetchone()
                conn.close()
                out.append({"id": sdir.name, "created": row[0] if row else "?"})
            except sqlite3.DatabaseError:
                continue
        return out

    def remove_session(self, session_id: str) -> bool:
        sdir = self.sessions / session_id
        if not sdir.exists():
            return False
        import shutil

        shutil.rmtree(sdir, ignore_errors=True)
        return True
