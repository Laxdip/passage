"""SQLite database layer for Passage.

The database is kept encrypted on disk. A session opens the vault (decrypts
to an in-memory SQLite connection), performs operations, then re-encrypts on
close.
"""

from __future__ import annotations

import io
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Generator, Optional

from passage.core.crypto import decrypt_db, encrypt_db, setup_master_password
from passage.core.config import get_db_path


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS account (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    url         TEXT,
    username    TEXT,
    category    TEXT    DEFAULT 'other',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_record (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id       INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    bcrypt_hash      TEXT    NOT NULL,
    fuzzy_hash       INTEGER NOT NULL,
    sha1_prefix      TEXT    NOT NULL,   -- first 5 chars of SHA1 for HIBP
    strength_score   INTEGER DEFAULT 0,
    last_changed     TEXT    NOT NULL DEFAULT (date('now')),
    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS breach_check (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    last_check_date TEXT    NOT NULL DEFAULT (datetime('now')),
    breach_count    INTEGER DEFAULT 0,
    breach_names    TEXT,               -- JSON array of breach names
    UNIQUE(account_id)
);

CREATE TABLE IF NOT EXISTS reuse_group (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    signature INTEGER NOT NULL           -- representative fuzzy hash
);

CREATE TABLE IF NOT EXISTS reuse_member (
    group_id   INTEGER NOT NULL REFERENCES reuse_group(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, account_id)
);
"""


# ---------------------------------------------------------------------------
# Session – encrypted vault wrapper
# ---------------------------------------------------------------------------

class VaultSession:
    """Holds a decrypted in-memory SQLite connection for the duration of a CLI command."""

    def __init__(self, master_password: str, db_path: Path | None = None, iterations: int = 310_000):
        self._password = master_password
        self._db_path = db_path or get_db_path()
        self._iterations = iterations
        self._conn: sqlite3.Connection | None = None
        self._opened_at: float = 0.0

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "VaultSession":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Open / close
    # ------------------------------------------------------------------

    def open(self) -> None:
        if self._conn is not None:
            return

        if self._db_path.exists():
            raw = decrypt_db(self._password, self._db_path, self._iterations)
            self._conn = sqlite3.connect(":memory:")
            self._conn.row_factory = sqlite3.Row
            # Restore from backup bytes
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.write(raw)
            tmp.flush()
            tmp_path = Path(tmp.name)
            tmp.close()
            disk_conn = sqlite3.connect(str(tmp_path))
            disk_conn.backup(self._conn)
            disk_conn.close()
            tmp_path.unlink(missing_ok=True)
        else:
            # Brand new vault
            self._conn = sqlite3.connect(":memory:")
            self._conn.row_factory = sqlite3.Row
            setup_master_password(self._password, self._db_path, self._iterations)

        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._opened_at = time.monotonic()

    def close(self) -> None:
        if self._conn is None:
            return
        self._flush_to_disk()
        self._conn.close()
        self._conn = None

    def _flush_to_disk(self) -> None:
        """Serialize in-memory DB and encrypt to disk."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()

        disk_conn = sqlite3.connect(str(tmp_path))
        self._conn.backup(disk_conn)  # type: ignore[union-attr]
        disk_conn.close()

        plain_bytes = tmp_path.read_bytes()
        tmp_path.unlink(missing_ok=True)
        encrypt_db(plain_bytes, self._password, self._db_path, self._iterations)

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Vault is not open. Call open() first.")
        return self._conn

    # ------------------------------------------------------------------
    # Auto-lock check
    # ------------------------------------------------------------------

    def is_expired(self, auto_lock_minutes: int) -> bool:
        return time.monotonic() - self._opened_at > auto_lock_minutes * 60


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def add_account(conn: sqlite3.Connection, name: str, url: str | None,
                username: str | None, category: str) -> int:
    cur = conn.execute(
        "INSERT INTO account (name, url, username, category) VALUES (?,?,?,?)",
        (name, url, username, category),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def list_accounts(conn: sqlite3.Connection, category: str | None = None) -> list[sqlite3.Row]:
    if category:
        return conn.execute(
            "SELECT * FROM account WHERE category=? ORDER BY name", (category,)
        ).fetchall()
    return conn.execute("SELECT * FROM account ORDER BY name").fetchall()


def get_account(conn: sqlite3.Connection, account_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM account WHERE id=?", (account_id,)).fetchone()


def edit_account(conn: sqlite3.Connection, account_id: int, **kwargs: str) -> bool:
    allowed = {"name", "url", "username", "category"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    updates["updated_at"] = datetime.now().isoformat()
    cols = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [account_id]
    conn.execute(f"UPDATE account SET {cols} WHERE id=?", vals)
    conn.commit()
    return True


def remove_account(conn: sqlite3.Connection, account_id: int) -> bool:
    cur = conn.execute("DELETE FROM account WHERE id=?", (account_id,))
    conn.commit()
    return cur.rowcount > 0


def upsert_password_record(
    conn: sqlite3.Connection,
    account_id: int,
    bcrypt_hash: str,
    fuzzy_hash_val: int,
    sha1_prefix: str,
    strength_score: int,
) -> None:
    conn.execute(
        """INSERT INTO password_record
               (account_id, bcrypt_hash, fuzzy_hash, sha1_prefix, strength_score, last_changed)
           VALUES (?,?,?,?,?,date('now'))""",
        (account_id, bcrypt_hash, fuzzy_hash_val, sha1_prefix, strength_score),
    )
    conn.commit()


def get_latest_password(conn: sqlite3.Connection, account_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """SELECT * FROM password_record WHERE account_id=?
           ORDER BY created_at DESC LIMIT 1""",
        (account_id,),
    ).fetchone()


def get_all_passwords(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT pr.*, a.name AS account_name, a.category
           FROM password_record pr
           JOIN account a ON a.id = pr.account_id
           WHERE pr.id IN (
               SELECT MAX(id) FROM password_record GROUP BY account_id
           )
           ORDER BY a.name"""
    ).fetchall()


def upsert_breach_check(
    conn: sqlite3.Connection,
    account_id: int,
    breach_count: int,
    breach_names: str,
) -> None:
    conn.execute(
        """INSERT INTO breach_check (account_id, breach_count, breach_names)
           VALUES (?,?,?)
           ON CONFLICT(account_id) DO UPDATE SET
               last_check_date=datetime('now'),
               breach_count=excluded.breach_count,
               breach_names=excluded.breach_names""",
        (account_id, breach_count, breach_names),
    )
    conn.commit()


def get_breach_check(conn: sqlite3.Connection, account_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM breach_check WHERE account_id=?", (account_id,)
    ).fetchone()


def find_reuse_groups(conn: sqlite3.Connection) -> list[dict]:
    """Return list of {group_id, account_ids, account_names}."""
    groups = conn.execute("SELECT * FROM reuse_group").fetchall()
    results = []
    for g in groups:
        members = conn.execute(
            """SELECT a.id, a.name FROM reuse_member rm
               JOIN account a ON a.id = rm.account_id
               WHERE rm.group_id=?""",
            (g["id"],),
        ).fetchall()
        if len(members) > 1:
            results.append({
                "group_id": g["id"],
                "accounts": [{"id": m["id"], "name": m["name"]} for m in members],
            })
    return results


def update_reuse_groups(conn: sqlite3.Connection, threshold: float = 0.85) -> None:
    """Recompute reuse groups from scratch based on fuzzy hashes."""
    from passage.core.crypto import fuzzy_similarity

    # Clear existing groups
    conn.execute("DELETE FROM reuse_member")
    conn.execute("DELETE FROM reuse_group")
    conn.commit()

    records = get_all_passwords(conn)
    if not records:
        return

    # Build clusters greedily
    clusters: list[dict] = []  # [{signature, account_ids}]
    for rec in records:
        fh = rec["fuzzy_hash"]
        placed = False
        for cluster in clusters:
            if fuzzy_similarity(fh, cluster["signature"]) >= threshold:
                cluster["account_ids"].append(rec["account_id"])
                placed = True
                break
        if not placed:
            clusters.append({"signature": fh, "account_ids": [rec["account_id"]]})

    # Persist only groups with >1 member
    for cluster in clusters:
        if len(cluster["account_ids"]) > 1:
            cur = conn.execute(
                "INSERT INTO reuse_group (signature) VALUES (?)", (cluster["signature"],)
            )
            gid = cur.lastrowid
            for aid in cluster["account_ids"]:
                conn.execute(
                    "INSERT OR IGNORE INTO reuse_member (group_id, account_id) VALUES (?,?)",
                    (gid, aid),
                )
    conn.commit()
