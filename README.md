# 🔐 Passage – Password Decay Tracker

A production-grade CLI tool for tracking password age, detecting reuse, and checking breach exposure — **without ever storing plaintext passwords**.

---

## Features

- **Password age tracking** with GREEN / YELLOW / ORANGE / RED risk levels
- **HIBP breach checking** via k-anonymity (only first 5 chars of SHA-1 sent)
- **Reuse detection** using fuzzy SimHash — no plaintext stored or compared
- **Encrypted vault** — AES-256 via PBKDF2-derived key from master password
- **Beautiful Rich terminal output** with summary dashboards
- **HTML / CSV / JSON reports**
- **Password generator** with strength scoring
- **Security audit** for weak or old passwords
- **Shell completion** for bash and zsh

---

## Installation

### From source

```bash
git clone https://github.com/yourname/passage.git
cd passage
pip install -e ".[dev]"
```

### With pipx (recommended)

```bash
pipx install passage-cli
```

---

## Quick Start

```bash
# Add an account (you'll be prompted for the password)
passage add --name "Google" --url "google.com" --username "me@gmail.com" --category email

# List all accounts
passage list

# Check all passwords for age, breaches, reuse
passage check --all

# Check a single account
passage check --id 1

# Find only reused passwords
passage check --reused

# Generate a strong password
passage generate --length 20

# Generate and immediately replace passwords for accounts 1, 2, 5
passage generate --length 20 --replace 1,2,5

# Run a security audit (weak/old passwords)
passage audit --weak

# Reports
passage report                            # Rich table
passage report --format json              # JSON to stdout
passage report --format csv               # CSV to stdout
passage report --export report.html       # Full HTML dashboard
passage report --summary                  # One-line summary

# Configuration
passage config --show
passage config --reset

# Generate a cron line for daily checks
passage remind
```

---

## Data Model

Passage stores **zero plaintext passwords**. Only:

| What | Why |
|------|-----|
| `bcrypt` hash | Change detection (did the password change?) |
| `fuzzy_hash` (SimHash 64-bit) | Reuse detection without comparing plaintext |
| `sha1_prefix` (first 5 chars) | HIBP k-anonymity lookup |
| Metadata (age, category, username) | Reporting and alerts |

---

## Security Architecture

```
Master Password
      │
      ▼
PBKDF2-HMAC-SHA256 (310,000 iterations)
      │
      ▼
AES-256 key (via Fernet)
      │
      ▼
Encrypted SQLite on disk (~/.passage/passage.db)
```

- The vault is decrypted **entirely in memory** for the duration of each CLI command.
- Re-encrypted and written to disk on exit.
- Auto-lock after 5 minutes (configurable).
- 3 wrong master-password attempts → 5-second cooldown.

---

## Configuration

Default config is created at `~/.passage/config.yaml` on first run. See `config.example.yaml` for all options.

```yaml
security:
  pbkdf2_iterations: 310000
  reuse_threshold: 0.85
  auto_lock_minutes: 5

hibp:
  enabled: true
  cache_days: 30
  timeout_seconds: 10

alerts:
  age_warning_days: 90
  age_critical_days: 365
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v --cov=passage
```

Tests cover:
- Fuzzy hash comparison and similarity
- bcrypt roundtrip
- Password strength scoring
- Password generation
- Database CRUD (zero accounts, many accounts, edge cases)
- HIBP parsing and cache logic (mocked)
- Health score calculation
- Performance: 500 accounts insert + list

---

## Shell Completion

```bash
# Bash
source scripts/completion.sh bash

# Zsh
source scripts/completion.sh zsh

# Or use Typer's built-in
passage --install-completion
```

---

## File Structure

```
passage/
├── src/passage/
│   ├── cli.py                  # Main Typer app
│   ├── commands/
│   │   ├── account.py          # add, list, edit, remove
│   │   ├── check.py            # check --all / --id / --reused
│   │   ├── report.py           # report --format table|json|csv|html
│   │   ├── tools.py            # generate, audit
│   │   └── config_cmd.py       # config, remind
│   ├── core/
│   │   ├── config.py           # YAML config + defaults
│   │   ├── crypto.py           # PBKDF2, Fernet, bcrypt, SimHash
│   │   ├── database.py         # SQLite schema + CRUD
│   │   ├── hibp.py             # HIBP async batch checking
│   │   ├── session.py          # Master password prompting + VaultSession
│   │   └── strength.py         # Strength scoring + password generation
│   └── utils/
│       └── render.py           # Rich terminal rendering helpers
├── tests/
│   └── test_passage.py         # Full test suite (35+ tests)
├── scripts/
│   └── completion.sh           # Shell completion installer
├── config.example.yaml
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## License

MIT
