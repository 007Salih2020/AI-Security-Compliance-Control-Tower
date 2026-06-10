from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_for_payload(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
