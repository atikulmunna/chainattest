from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def log(self, event_type: str, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": int(time.time()),
            "event_type": event_type,
            **payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
