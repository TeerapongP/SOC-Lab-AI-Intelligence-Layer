from __future__ import annotations

from pathlib import Path

_ENRICH_DIR = Path(__file__).resolve().parent
_SERVICE_ROOT = _ENRICH_DIR.parent


__path__ = [str(_ENRICH_DIR), str(_SERVICE_ROOT)]
