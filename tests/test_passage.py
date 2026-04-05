"""Passage test suite."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─────────────────────────────────────────────
# Crypto tests
# ─────────────────────────────────────────────

from passage.core.crypto import (
    fuzzy_hash,
    fuzzy_similarity,
    hash_password_bcrypt,
    sha1_hex,
    verify_bcrypt,
)


def test_sha1_hex_known():
    # SHA1("password") is known
    assert sha1_hex("password") == hashlib.sha1(b"password").hexdigest().upper()


def test_bcrypt_roundtrip():
    h = hash_password_bcrypt("my-secret-pass")
    assert verify_bcrypt("my-secret-pass", h)
    assert not verify_bcrypt("wrong", h)


def test_fuzzy_hash_identical():
    h1 = fuzzy_hash("hunter2")
    h2 = fuzzy_hash("hunter2")
    assert h1 == h2
    assert fuzzy_similarity(h1, h2) == 1.0


def test_fuzzy_hash_similar():
    h1 = fuzzy_hash("hunter2!")
    h2 = fuzzy_hash("hunter2@")
    sim = fuzzy_similarity(h1, h2)
    assert 0.0 <= sim <= 1.0


def test_fuzzy_hash_different():
    h1 = fuzzy_hash("aaaaaaaaaaa")
    h2 = fuzzy_hash("ZZZZZZZZZZZZ")
    sim = fuzzy_similarity(h1, h2)
    assert sim < 0.9  # should be clearly different


def test_fuzzy_similarity_range():
    for pw1, pw2 in [("abc", "xyz"), ("Pass1!", "Pass1@"), ("a" * 30, "b" * 30)]:
        s = fuzzy_similarity(fuzzy_hash(pw1), fuzzy_hash(pw2))
        assert 0.0 <= s <= 1.0


# ─────────────────────────────────────────────
# Strength tests
# ─────────────────────────────────────────────

from passage.core.strength import generate_password, score_password


def test_score_weak_password():
    r = score_password("abc")
    assert r.score < 40
    assert r.grade in ("D", "F")


def test_score_strong_password():
    r = score_password("X#9kLm$vQ2!rPzWn")
    assert r.score >= 70


def test_score_all_digits_penalty():
    r = score_password("12345678")
    assert r.score < 50


def test_generate_password_length():
    for length in [12, 16, 20, 32]:
        pw = generate_password(length=length)
        assert len(pw) == length


def test_generate_password_uniqueness():
    passwords = {generate_password() for _ in range(20)}
    assert len(passwords) == 20  # all unique


def test_generate_has_symbol():
    for _ in range(10):
        pw = generate_password(length=20, use_symbols=True)
        assert any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)


def test_generate_no_symbols():
    for _ in range(10):
        pw = generate_password(length=16, use_symbols=False)
        assert pw.isalnum()


# ─────────────────────────────────────────────
# Database tests
# ─────────────────────────────────────────────

from passage.core.database import (
    SCHEMA,
    add_account,
    edit_account,
    find_reuse_groups,
    get_account,
    get_latest_password,
    list_accounts,
    remove_account,
    update_reuse_groups,
    upsert_breach_check,
    upsert_password_record,
)


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def test_add_and_list_accounts():
    conn = _make_conn()
    add_account(conn, "Google", "google.com", "user@gmail.com", "email")
    add_account(conn, "GitHub", "github.com", "dev@example.com", "dev")
    accounts = list_accounts(conn)
    assert len(accounts) == 2
    names = [a["name"] for a in accounts]
    assert "Google" in names and "GitHub" in names


def test_list_accounts_by_category():
    conn = _make_conn()
    add_account(conn, "Bank", "bank.com", "u", "finance")
    add_account(conn, "Twitter", "twitter.com", "u", "social")
    finance = list_accounts(conn, category="finance")
    assert len(finance) == 1
    assert finance[0]["name"] == "Bank"


def test_get_account():
    conn = _make_conn()
    aid = add_account(conn, "PayPal", "paypal.com", "u", "finance")
    row = get_account(conn, aid)
    assert row is not None
    assert row["name"] == "PayPal"


def test_edit_account():
    conn = _make_conn()
    aid = add_account(conn, "Old Name", None, None, "other")
    edit_account(conn, aid, name="New Name", category="work")
    row = get_account(conn, aid)
    assert row["name"] == "New Name"
    assert row["category"] == "work"


def test_remove_account():
    conn = _make_conn()
    aid = add_account(conn, "ToDelete", None, None, "other")
    assert remove_account(conn, aid)
    assert get_account(conn, aid) is None


def test_password_record_cascade_delete():
    conn = _make_conn()
    aid = add_account(conn, "Test", None, None, "other")
    upsert_password_record(conn, aid, "hash", 12345, "ABCDE", 80)
    remove_account(conn, aid)
    pw = get_latest_password(conn, aid)
    assert pw is None


def test_upsert_breach_check():
    conn = _make_conn()
    aid = add_account(conn, "BreachedSite", None, None, "other")
    upsert_breach_check(conn, aid, 3, json.dumps(["breach1", "breach2"]))
    from passage.core.database import get_breach_check
    row = get_breach_check(conn, aid)
    assert row["breach_count"] == 3


def test_reuse_groups_detected():
    conn = _make_conn()
    # Two accounts with identical fuzzy hashes → reuse
    pw = "SamePassword123!"
    fh = fuzzy_hash(pw)
    aid1 = add_account(conn, "Site1", None, None, "other")
    aid2 = add_account(conn, "Site2", None, None, "other")
    upsert_password_record(conn, aid1, "h1", fh, "AAAAA", 70)
    upsert_password_record(conn, aid2, "h2", fh, "AAAAA", 70)
    update_reuse_groups(conn, threshold=0.85)
    groups = find_reuse_groups(conn)
    assert len(groups) >= 1


def test_no_reuse_groups_when_unique():
    conn = _make_conn()
    # Very different passwords
    passwords = ["aaaaaaaaaaaaa", "ZZZZZZZZZZZZZ", "111111111111"]
    for i, pw in enumerate(passwords):
        aid = add_account(conn, f"Site{i}", None, None, "other")
        upsert_password_record(conn, aid, f"h{i}", fuzzy_hash(pw), "AAAAA", 50)
    update_reuse_groups(conn, threshold=0.85)
    groups = find_reuse_groups(conn)
    assert len(groups) == 0


# ─────────────────────────────────────────────
# HIBP tests (mocked)
# ─────────────────────────────────────────────

from passage.core.hibp import _parse_hibp_response, should_refresh_breach_check


def test_parse_hibp_found():
    response = "ABC12:5\nDEF34:100\nGHI56:0\n"
    count = _parse_hibp_response(response, "ABC12")
    assert count == 5


def test_parse_hibp_not_found():
    response = "ABC12:5\nDEF34:100\n"
    count = _parse_hibp_response(response, "ZZZZZ")
    assert count == 0


def test_should_refresh_never_checked():
    assert should_refresh_breach_check(None, cache_days=30) is True


def test_should_refresh_recent():
    from datetime import datetime, timedelta
    recent = (datetime.now() - timedelta(days=5)).isoformat()
    assert should_refresh_breach_check(recent, cache_days=30) is False


def test_should_refresh_stale():
    from datetime import datetime, timedelta
    old = (datetime.now() - timedelta(days=60)).isoformat()
    assert should_refresh_breach_check(old, cache_days=30) is True


# ─────────────────────────────────────────────
# Render / health-score tests
# ─────────────────────────────────────────────

from passage.utils.render import health_score, password_age_days, risk_level


def test_health_score_perfect():
    accounts = [{"age_days": 10, "breached": False, "reused": False} for _ in range(10)]
    score, grade = health_score(accounts)
    assert score >= 90
    assert grade == "A"


def test_health_score_all_breached():
    accounts = [{"age_days": 10, "breached": True, "reused": False} for _ in range(5)]
    score, grade = health_score(accounts)
    assert score <= 60


def test_risk_level_green():
    assert risk_level(30) == "GREEN"


def test_risk_level_yellow():
    assert risk_level(100) == "YELLOW"


def test_risk_level_orange():
    assert risk_level(200) == "ORANGE"


def test_risk_level_red():
    assert risk_level(400) == "RED"


def test_password_age_days():
    from datetime import date, timedelta
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    assert password_age_days(yesterday) == 1


# ─────────────────────────────────────────────
# Performance test
# ─────────────────────────────────────────────

def test_performance_500_accounts():
    """Adding and listing 500 accounts should complete quickly."""
    import time
    conn = _make_conn()

    start = time.monotonic()
    for i in range(500):
        aid = add_account(conn, f"Account{i}", f"site{i}.com", f"user{i}@test.com", "other")
        # Use a precomputed placeholder hash (avoids slow bcrypt in perf test)
        upsert_password_record(
            conn, aid,
            bcrypt_hash=f"$pbkdf2${'aa'*16}${'bb'*32}",   # fake hash, no hashing cost
            fuzzy_hash_val=fuzzy_hash(f"pass{i}!XY"),
            sha1_prefix=sha1_hex(f"pass{i}!XY")[:5],
            strength_score=70,
        )
    elapsed = time.monotonic() - start
    assert elapsed < 30, f"Inserting 500 accounts took {elapsed:.1f}s (too slow)"

    start2 = time.monotonic()
    accounts = list_accounts(conn)
    assert len(accounts) == 500
    elapsed2 = time.monotonic() - start2
    assert elapsed2 < 1.0, f"Listing 500 accounts took {elapsed2:.2f}s (too slow)"


# ─────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────

def test_zero_accounts():
    conn = _make_conn()
    assert list_accounts(conn) == []
    groups = find_reuse_groups(conn)
    assert groups == []
    score, grade = health_score([])
    assert score == 100
    assert grade == "A"


def test_remove_nonexistent_account():
    conn = _make_conn()
    assert remove_account(conn, 9999) is False


def test_edit_nonexistent_account():
    conn = _make_conn()
    # Should not raise regardless of whether id exists
    try:
        result = edit_account(conn, 9999, name="Ghost")
        assert result in (True, False)
    except Exception as e:
        raise AssertionError(f"edit_account raised unexpectedly: {e}")


def test_get_nonexistent_account():
    conn = _make_conn()
    assert get_account(conn, 9999) is None
