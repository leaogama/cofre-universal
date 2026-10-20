"""Preferências MCP independentes do SDK de servidor MCP."""
from __future__ import annotations

import json
from pathlib import Path

from .security import protect, unprotect
from .storage import app_data_dir


class AgentPolicyStore:
    """Consentimento MCP separado do acesso humano ao cofre."""

    def __init__(self, path=None):
        self.path = path or app_data_dir() / "agent-policy.dpapi"

    def enabled(self) -> bool:
        path = Path(self.path)
        if not path.exists():
            return False
        return json.loads(unprotect(path.read_bytes())).get("metadata_access") is True

    def drafts_enabled(self) -> bool:
        path = Path(self.path)
        if not path.exists():
            return False
        return json.loads(unprotect(path.read_bytes())).get("draft_creation") is True

    def any_enabled(self) -> bool:
        return self.enabled() or self.drafts_enabled()

    def set_enabled(self, enabled: bool) -> None:
        self._update("metadata_access", enabled)

    def set_drafts_enabled(self, enabled: bool) -> None:
        self._update("draft_creation", enabled)

    def _update(self, permission: str, enabled: bool) -> None:
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        try:
            settings = json.loads(unprotect(path.read_bytes())) if path.exists() else {}
        except (ValueError, OSError):
            settings = {}
        settings[permission] = bool(enabled)
        payload = json.dumps(settings).encode("utf-8")
        temp.write_bytes(protect(payload))
        temp.replace(path)
