"""
Security utilities — secure memory handling and temporary files.

Ensures that sensitive data (private keys, passwords, decrypted content)
is zeroed from memory after use and temporary files are securely deleted.
"""

import ctypes
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


class SecureBytes:
    """
    A wrapper around a bytearray that zeros memory on deletion.

    Usage:
        sb = SecureBytes(private_key_bytes)
        # ... use sb.data ...
        del sb  # memory is zeroed
    """

    def __init__(self, data: bytes | bytearray):
        self._data = bytearray(data)

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        """Explicitly zero out the buffer."""
        for i in range(len(self._data)):
            self._data[i] = 0

    def __del__(self) -> None:
        self.clear()

    def __repr__(self) -> str:
        return f"SecureBytes(length={len(self._data)})"


def secure_zero_memory(data: bytearray) -> None:
    """
    Attempt to zero a bytearray in-place.

    This is a best-effort approach — Python's GC may retain copies,
    but this eliminates the primary buffer.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


@contextmanager
def secure_temp_file(suffix: str = ".tmp", dir: str | Path | None = None):
    """
    Context manager that creates a temporary file and securely
    deletes it (overwrite + unlink) on exit.

    Usage:
        with secure_temp_file(suffix=".xml") as tmp_path:
            tmp_path.write_bytes(data)
            # ... process tmp_path ...
        # File is securely deleted here
    """
    fd, path = tempfile.mkstemp(suffix=suffix, dir=dir)
    tmp_path = Path(path)
    try:
        os.close(fd)
        yield tmp_path
    finally:
        _secure_delete(tmp_path)


def _secure_delete(path: Path) -> None:
    """Overwrite file contents with zeros, then delete."""
    try:
        if path.exists():
            size = path.stat().st_size
            if size > 0:
                with open(path, "wb") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
    except OSError:
        # Best-effort — try plain unlink as fallback
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
