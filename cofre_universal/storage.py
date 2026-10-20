"""Abstrações de armazenamento para cache local e provedores remotos."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from .security import protect, unprotect


class VaultStore(Protocol):
    def load(self) -> bytes | None: ...
    def save(self, encrypted_document: bytes) -> None: ...


def app_data_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "CofreUniversal"
    root.mkdir(parents=True, exist_ok=True)
    return root


class DpapiFileStore:
    """Cache local contém somente envelope já cifrado, encapsulado pelo DPAPI."""
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or app_data_dir() / "vault.cache")

    def load(self) -> bytes | None:
        if not self.path.exists():
            return None
        return unprotect(self.path.read_bytes())

    def save(self, encrypted_document: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_bytes(protect(encrypted_document))
        temporary.replace(self.path)
