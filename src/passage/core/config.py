"""Configuration management for Passage."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "security": {
        "pbkdf2_iterations": 310_000,
        "reuse_threshold": 0.85,
        "auto_lock_minutes": 5,
    },
    "hibp": {
        "enabled": True,
        "cache_days": 30,
        "timeout_seconds": 10,
    },
    "alerts": {
        "age_warning_days": 90,
        "age_critical_days": 365,
        "notify_reused": True,
        "notify_breached": True,
    },
    "output": {
        "color": True,
        "table_style": "rounded",
    },
}

_PASSAGE_DIR = Path(os.environ.get("PASSAGE_DIR", "~/.passage")).expanduser()
_CONFIG_FILE = _PASSAGE_DIR / "config.yaml"


def get_passage_dir() -> Path:
    _PASSAGE_DIR.mkdir(parents=True, exist_ok=True)
    return _PASSAGE_DIR


def get_db_path() -> Path:
    return get_passage_dir() / "passage.db"


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load config from YAML file, falling back to defaults."""
    path = config_path or _CONFIG_FILE
    if not path.exists():
        save_config(DEFAULT_CONFIG, path)
        return DEFAULT_CONFIG

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    # Deep-merge with defaults
    return _deep_merge(DEFAULT_CONFIG, data)


def save_config(config: dict[str, Any], path: Path | None = None) -> None:
    path = path or _CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
