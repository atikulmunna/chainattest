from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import time
from typing import Iterator


class FileLockTimeoutError(TimeoutError):
    pass


@contextmanager
def file_lock(path: Path, timeout_seconds: float = 5.0, poll_interval_seconds: float = 0.05) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout_seconds
    lock_fd: int | None = None

    while lock_fd is None:
        try:
            lock_fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            if time.time() >= deadline:
                raise FileLockTimeoutError(f"timed out waiting for lock: {path}")
            time.sleep(poll_interval_seconds)

    try:
        os.write(lock_fd, str(os.getpid()).encode("utf-8"))
        yield
    finally:
        os.close(lock_fd)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(contents)
        temp_path = Path(handle.name)
    os.replace(temp_path, path)


def append_line(path: Path, line: str, lock_timeout_seconds: float = 5.0) -> None:
    lock_path = path.with_name(f"{path.name}.lock")
    with file_lock(lock_path, timeout_seconds=lock_timeout_seconds):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
