"""Run-artifact helpers: hashing, manifests, deterministic JSON."""

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def sha256_file(path: Path, block_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)
    return h.hexdigest()


def git_commit(cwd: Optional[Path] = None) -> Optional[str]:
    """Best-effort current commit hash; None if unavailable."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None


def environment_versions() -> Dict[str, str]:
    import numpy
    import pandas

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pandas": pandas.__version__,
        "numpy": numpy.__version__,
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True, default=str)
        f.write("\n")


def write_manifest(path: Path, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Writes a manifest with environment, commit, and a UTC timestamp.

    ``created_at_utc`` is the only wall-clock field; exclude it when comparing runs.
    """
    manifest = dict(payload)
    manifest["environment"] = environment_versions()
    manifest["git_commit"] = git_commit(path.parent)
    manifest["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(path, manifest)
    return manifest
