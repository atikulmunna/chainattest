from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any

from coordinator.chainattest_coordinator.storage import append_line


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def log(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "timestamp": int(time.time()),
            "event_type": event_type,
            **payload,
        }
        append_line(self.path, json.dumps(record) + "\n")
