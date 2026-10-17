"""Small cross-process file lock shared by factory repositories."""

from __future__ import annotations

import errno
import importlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from os import open as open_descriptor
from pathlib import Path


def _acquire_lock(descriptor: int) -> None:
    if os.name != "nt":
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return

    msvcrt = importlib.import_module("msvcrt")
    while True:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                raise
            time.sleep(0.05)


def _release_lock(descriptor: int) -> None:
    if os.name != "nt":
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return

    msvcrt = importlib.import_module("msvcrt")
    os.lseek(descriptor, 0, os.SEEK_SET)
    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)


def _ensure_windows_lock_byte(descriptor: int) -> None:
    while os.fstat(descriptor).st_size == 0:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                raise
            time.sleep(0.05)


@contextmanager
def exclusive_file_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive advisory lock on one byte of ``path``."""

    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if os.name == "nt":
        flags |= os.O_BINARY
    descriptor = open_descriptor(lock_path, flags, 0o600)
    acquired = False
    try:
        if os.name == "nt":
            _ensure_windows_lock_byte(descriptor)
        _acquire_lock(descriptor)
        acquired = True
        yield
    finally:
        if acquired:
            _release_lock(descriptor)
        os.close(descriptor)


__all__ = ["exclusive_file_lock"]
