"""Sincronização de um único envelope cifrado via GitHub Contents API."""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from .repository import CredentialRepository
from .crypto import InvalidMasterPassword
from .security import protect, unprotect
from .storage import app_data_dir


class GitHubError(RuntimeError):
    pass


class GitHubConflict(GitHubError):
    """Estado local e remoto foram alterados desde a última sincronização."""


@dataclass(frozen=True, slots=True)
class RemoteDocument:
    content: bytes
    sha: str


@dataclass(frozen=True, slots=True)
class SyncBaseline:
    content: bytes
    sha: str


class GitHubConfigStore:
    """Guarda token e configuração em arquivo protegido por DPAPI."""
    def __init__(self, path=None):
        self.path = path or app_data_dir() / "github-config.dpapi"

    def load(self) -> dict[str, str] | None:
        from pathlib import Path
        path = Path(self.path)
        if not path.exists(): return None
        return json.loads(unprotect(path.read_bytes()))

    def save(self, owner: str, repo: str, token: str) -> None:
        from pathlib import Path
        path = Path(self.path); path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"owner": owner.strip(), "repo": repo.strip(), "token": token.strip()}, separators=(",", ":")).encode()
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(protect(data)); temporary.replace(path)

    def clear(self) -> None:
        from pathlib import Path
        Path(self.path).unlink(missing_ok=True)


class SyncStateStore:
    def __init__(self, path=None):
        self.path = path or app_data_dir() / "github-sync-state.dpapi"

    def load(self) -> SyncBaseline | None:
        from pathlib import Path
        path = Path(self.path)
        if not path.exists(): return None
        data = json.loads(unprotect(path.read_bytes()))
        return SyncBaseline(base64.b64decode(data["content"]), data["sha"])

    def save(self, baseline: SyncBaseline) -> None:
        from pathlib import Path
        path = Path(self.path); path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"content": base64.b64encode(baseline.content).decode("ascii"), "sha": baseline.sha}, separators=(",", ":")).encode()
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(protect(data)); temporary.replace(path)


class GitHubContentsClient:
    API = "https://api.github.com"

    def __init__(self, owner: str, repo: str, token: str, timeout: int = 20):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
            raise ValueError("Informe owner e nome de repositório GitHub válidos.")
        if not token.strip(): raise ValueError("Token GitHub não configurado.")
        self.owner, self.repo, self.token, self.timeout = owner, repo, token, timeout

    def _request(self, method: str, path: str, body: dict | None = None):
        url = f"{self.API}/repos/{urllib.parse.quote(self.owner)}/{urllib.parse.quote(self.repo)}/contents/{path}"
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=payload, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Cofre-Universal",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read()) if response.status != 204 else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (409, 422): raise GitHubConflict("O arquivo remoto mudou durante a sincronização.") from None
            if exc.code == 404: return None
            if exc.code in (401, 403): raise GitHubError("GitHub recusou a autenticação ou a permissão do repositório.") from None
            raise GitHubError(f"Falha na API GitHub (HTTP {exc.code}).") from None
        except (urllib.error.URLError, TimeoutError):
            raise GitHubError("Não foi possível conectar à API do GitHub.") from None

    def verify_private_repository(self):
        req = urllib.request.Request(f"{self.API}/repos/{urllib.parse.quote(self.owner)}/{urllib.parse.quote(self.repo)}", headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Cofre-Universal",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                repo = json.loads(response.read())
            if repo.get("private") is not True: raise GitHubError("O repositório configurado não é privado.")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404): raise GitHubError("Repositório inacessível; verifique token e permissões.") from None
            raise GitHubError(f"Falha na API GitHub (HTTP {exc.code}).") from None
        except urllib.error.URLError:
            raise GitHubError("Não foi possível conectar à API do GitHub.") from None

    def read_vault(self) -> RemoteDocument | None:
        result = self._request("GET", "vault.json")
        if result is None: return None
        if result.get("type") != "file": raise GitHubError("vault.json não é um arquivo regular.")
        try:
            content = base64.b64decode(result["content"], validate=False)
            json.loads(content)  # valida JSON do envelope; não interpreta segredo em texto claro
            return RemoteDocument(content, result["sha"])
        except (KeyError, ValueError, json.JSONDecodeError):
            raise GitHubError("O arquivo remoto do cofre está inválido.") from None

    def write_document(self, path: str, content: bytes, sha: str | None, message: str):
        body = {"message": message, "content": base64.b64encode(content).decode("ascii")}
        if sha: body["sha"] = sha
        result = self._request("PUT", path, body)
        if not result or not result.get("content", {}).get("sha"):
            raise GitHubError("GitHub não confirmou a gravação do envelope.")
        return result["content"]["sha"]


class GitHubSyncService:
    def __init__(self, client: GitHubContentsClient, state_store: SyncStateStore | None = None):
        self.client = client
        if state_store is None:
            from .storage import app_data_dir
            self.state_store = SyncStateStore(app_data_dir() / f"github-sync-{client.owner.lower()}-{client.repo.lower()}.dpapi")
        else:
            self.state_store = state_store

    def sync(self, repository: CredentialRepository) -> str:
        self.client.verify_private_repository()
        local = repository.store.load()
        if local is None: raise GitHubError("Cache local do cofre não encontrado.")
        remote = self.client.read_vault()
        base = self.state_store.load()
        if remote is None:
            if base is not None: raise GitHubConflict("O cofre remoto foi removido. Nada foi sobrescrito.")
            sha = self.client.write_document("vault.json", local, None, "Criar cofre cifrado")
            self.state_store.save(SyncBaseline(local, sha)); return "Sincronizado com o GitHub."
        if remote.content == local:
            self.state_store.save(SyncBaseline(remote.content, remote.sha)); return "Cofre já estava sincronizado."
        if base is None:
            raise GitHubConflict("Há um cofre local e outro remoto, sem histórico comum. Escolha qual manter.")
        if remote.content == base.content:
            sha = self.client.write_document("vault.json", local, remote.sha, "Atualizar cofre cifrado")
            self.state_store.save(SyncBaseline(local, sha)); return "Alterações locais sincronizadas."
        if local == base.content:
            try:
                repository.load_remote_document(remote.content)
            except InvalidMasterPassword:
                raise GitHubConflict("O arquivo remoto mudou e exige uma senha mestra para importar. Escolha a versão remota para informá-la.") from None
            self.state_store.save(SyncBaseline(remote.content, remote.sha)); return "Atualizações remotas baixadas."
        raise GitHubConflict("Há alterações locais e remotas. Escolha qual versão manter; uma cópia cifrada será preservada.")

    def resolve_conflict(self, repository: CredentialRepository, keep: str, master_password: str | None = None) -> str:
        if keep not in {"local", "remote"}: raise ValueError("Escolha 'local' ou 'remote'.")
        remote = self.client.read_vault()
        if remote is None: raise GitHubConflict("O cofre remoto deixou de existir. Nada foi sobrescrito.")
        local = repository.store.load()
        if local is None: raise GitHubError("Cache local não encontrado.")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = f"backups/vault-conflict-{timestamp}-{uuid.uuid4().hex[:8]}.json"
        if keep == "local":
            self.client.write_document(backup_path, remote.content, None, "Backup cifrado do conflito remoto")
            sha = self.client.write_document("vault.json", local, remote.sha, "Resolver conflito mantendo cofre local")
            self.state_store.save(SyncBaseline(local, sha))
            return "Versão remota preservada em backup cifrado; versão local mantida."
        self.client.write_document(backup_path, local, None, "Backup cifrado do conflito local")
        repository.load_remote_document(remote.content, master_password=master_password)
        self.state_store.save(SyncBaseline(remote.content, remote.sha))
        return "Versão local preservada em backup cifrado; versão remota mantida."
