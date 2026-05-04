from __future__ import annotations

from pathlib import Path

_ENRICH_DIR = Path(__file__).resolve().parent
_SERVICE_ROOT = _ENRICH_DIR.parent

# The project keeps config/, cti/, kafka/, pipeline/, rag/, and utils/ beside
# enrich/. Extending the package path preserves the existing import style:
# `from enrich.config import settings`, `from enrich.cti.client import ...`.
__path__ = [str(_ENRICH_DIR), str(_SERVICE_ROOT)]
