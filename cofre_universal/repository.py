"""Gerencia sessões e CRUD sobre envelopes cifrados; backend de armazenamento injetável."""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import uuid
from contextlib import closing
from typing import Any

from .crypto import create_envelope, decrypt_payload, encrypt_payload
from .models import Credential
from .security import unprotect
from .storage import DpapiFileStore, VaultStore, app_data_dir


class VaultLocked(RuntimeError):
    pass


class CredentialRepository:
    def __init__(self, path=None, store: VaultStore | None = None):
        # `path` mantém a injeção de destino usada em testes e ferramentas locais.
        self.store = store or DpapiFileStore(path)
        self._key: bytearray | None = None
        self._salt: bytes | None = None
        self._credentials: list[dict[str, Any]] = []

    def vault_exists(self) -> bool:
        return self.store.load() is not None

    def is_unlocked(self) -> bool:
        return self._key is not None

    @staticmethod
    def legacy_database_path():
        return app_data_dir() / "cofre.db"

    def legacy_available(self) -> bool:
        return self.legacy_database_path().exists()

    def read_legacy_credentials(self, old_password: str) -> list[dict[str, Any]]:
        """Lê o formato da etapa anterior sem modificar nem apagar o banco original."""
        path = self.legacy_database_path()
        with closing(sqlite3.connect(path)) as db:
            auth = db.execute("SELECT salt,verifier FROM local_auth WHERE id=1").fetchone()
            rows = db.execute("SELECT id,name,service,project,environment,usage_notes,secret FROM credentials").fetchall()
        if not auth:
            raise ValueError("O banco antigo não contém configuração de senha.")
        actual = hashlib.pbkdf2_hmac("sha256", old_password.encode("utf-8"), auth[0], 310_000)
        if not hmac.compare_digest(actual, auth[1]):
            raise ValueError("Senha antiga incorreta.")
        return [{"id": row[0], "name": row[1], "service": row[2], "project": row[3],
                 "environment": row[4], "usage_notes": row[5], "secret": unprotect(row[6]).decode("utf-8")}
                for row in rows]

    def create(self, master_password: str, credentials: list[dict[str, Any]] | None = None) -> None:
        envelope, key = create_envelope(master_password, {"version": 1, "credentials": credentials or []})
        self.store.save(envelope)
        from .crypto import decrypt_payload
        _, _, self._salt = decrypt_payload(envelope, key=key)
        self._key = bytearray(key)
        self._credentials = credentials or []

    def unlock(self, master_password: str, encrypted_document: bytes | None = None) -> None:
        envelope = encrypted_document if encrypted_document is not None else self.store.load()
        if envelope is None:
            raise FileNotFoundError("Nenhum cofre local ou remoto foi encontrado.")
        payload, key, salt = decrypt_payload(envelope, password=master_password)
        if encrypted_document is not None:
            self.store.save(envelope)
        self._key = bytearray(key)
        self._salt = salt
        self._credentials = payload["credentials"]

    def lock(self) -> None:
        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
        self._key = None
        self._salt = None
        self._credentials.clear()

    def encrypted_document(self) -> bytes:
        self._require_unlocked()
        return encrypt_payload({"version": 1, "credentials": self._credentials}, bytes(self._key), self._salt)

    def load_remote_document(self, encrypted_document: bytes, master_password: str | None = None) -> None:
        self._require_unlocked()
        payload, key, salt = decrypt_payload(encrypted_document, password=master_password, key=None if master_password is not None else bytes(self._key))
        credentials = payload["credentials"]
        self.store.save(encrypted_document)
        if master_password is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
            self._key = bytearray(key)
            self._salt = salt
        self._credentials = credentials

    def _require_unlocked(self):
        if self._key is None:
            raise VaultLocked("Desbloqueie o cofre para continuar.")

    @staticmethod
    def _credential(data: dict[str, Any]) -> Credential:
        return Credential(data["id"], data["name"], data["service"], data["project"],
                          data["environment"], data.get("usage_notes", ""), data["secret"])

    def list_credentials(self, query: str = "") -> list[Credential]:
        self._require_unlocked()
        items = [self._credential(item) for item in self._credentials]
        q = query.casefold().strip()
        if q:
            items = [c for c in items if q in " ".join((c.name,c.service,c.project,c.environment,c.usage_notes)).casefold()]
        return sorted(items, key=lambda c: (c.service.casefold(), c.name.casefold()))

    def list_metadata(self, query: str = "") -> list[dict[str, str]]:
        self._require_unlocked()
        fields = ("id", "name", "service", "project", "environment", "usage_notes")
        items = [{field: str(item.get(field, "")) for field in fields} for item in self._credentials]
        q = query.casefold().strip()
        if q:
            items = [item for item in items if q in " ".join(item.values()).casefold()]
        return sorted(items, key=lambda item: (item["service"].casefold(), item["name"].casefold()))

    def save(self, item: Credential) -> Credential:
        self._require_unlocked()
        ident = item.id or str(uuid.uuid4())
        data = {"id": ident, "name": item.name, "service": item.service, "project": item.project,
                "environment": item.environment, "usage_notes": item.usage_notes, "secret": item.secret}
        credentials = list(self._credentials)
        for index, existing in enumerate(self._credentials):
            if existing["id"] == ident:
                credentials[index] = data
                break
        else:
            credentials.append(data)
        document = encrypt_payload({"version": 1, "credentials": credentials}, bytes(self._key), self._salt)
        self.store.save(document)
        self._credentials = credentials
        return self._credential(data)

    def delete(self, ident: str) -> None:
        self._require_unlocked()
        credentials = [item for item in self._credentials if item["id"] != ident]
        document = encrypt_payload({"version": 1, "credentials": credentials}, bytes(self._key), self._salt)
        self.store.save(document)
        self._credentials = credentials

    def get(self, ident: str) -> Credential | None:
        self._require_unlocked()
        item = next((item for item in self._credentials if item["id"] == ident), None)
        return self._credential(item) if item else None
