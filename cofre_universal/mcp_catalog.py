"""Servidor MCP local: metadados explícitos e broker sem operações genéricas."""
from __future__ import annotations

import json
from collections.abc import Callable

from .models import environment_variable_for_name
from .repository import CredentialRepository
from .security import protect, unprotect
from .storage import app_data_dir


class AgentPolicyStore:
    """Consentimento MCP separado do acesso humano ao cofre."""
    def __init__(self, path=None): self.path = path or app_data_dir() / "agent-policy.dpapi"

    def enabled(self) -> bool:
        from pathlib import Path
        path = Path(self.path)
        if not path.exists(): return False
        return json.loads(unprotect(path.read_bytes())).get("metadata_access") is True

    def set_enabled(self, enabled: bool) -> None:
        from pathlib import Path
        path = Path(self.path); path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_bytes(protect(json.dumps({"metadata_access": bool(enabled)}).encode("utf-8")))
        temp.replace(path)


class OperationBroker:
    """Despachante por pares serviço/operação registrados explicitamente."""
    def __init__(self): self._handlers: dict[tuple[str, str], Callable[[dict], dict]] = {}

    def register(self, service: str, operation: str, handler: Callable[[dict], dict]) -> None:
        self._handlers[(service.casefold(), operation.casefold())] = handler

    def execute(self, service: str, operation: str, payload: dict) -> dict:
        handler = self._handlers.get((service.casefold(), operation.casefold()))
        if handler is None:
            raise PermissionError("Esta operação não foi explicitamente autorizada no Cofre Universal.")
        result = handler(payload)
        if not isinstance(result, dict): raise TypeError("O intermediador retornou um formato inválido.")
        return result


def list_available_credentials(repository: CredentialRepository) -> list[dict[str, str]]:
    return [_agent_metadata(item) for item in repository.list_metadata()]


def search_credentials(repository: CredentialRepository, query: str) -> list[dict[str, str]]:
    return [_agent_metadata(item) for item in repository.list_metadata(query)]


def _agent_metadata(item: dict[str, str]) -> dict[str, str]:
    """Whitelist MCP exclui notas livres que poderiam conter valores colados por engano."""
    return {field: item[field] for field in ("id", "name", "service", "project", "environment")}


def build_server(repository: CredentialRepository, *, allow_metadata: bool, broker: OperationBroker | None = None):
    """MCP começa desativado; quando permitido, registra apenas operações seguras."""
    if not allow_metadata:
        raise PermissionError("O acesso MCP está desativado nas permissões independentes do Cofre.")
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise RuntimeError("Instale o extra opcional: pip install '.[mcp]'") from exc
    server = MCPServer("Cofre Universal")
    broker = broker or OperationBroker()

    @server.tool()
    def listar_credenciais() -> list[dict[str, str]]:
        """Lista nome, serviço, projeto, ambiente e instruções, sem valores secretos."""
        return list_available_credentials(repository)

    @server.tool()
    def pesquisar_credenciais(termo: str) -> list[dict[str, str]]:
        """Pesquisa credenciais pelos metadados; nunca retorna valores."""
        return search_credentials(repository, termo)

    @server.tool()
    def nomes_de_variaveis(projeto: str) -> list[dict[str, str]]:
        """Informa apenas nomes de variáveis configuradas para um projeto."""
        matches = [c for c in repository.list_metadata() if c["project"].casefold() == projeto.casefold()]
        return [{"name": c["name"], "environment_variable": environment_variable_for_name(c["name"])} for c in matches]

    @server.tool()
    def credencial_configurada(nome: str) -> dict[str, bool]:
        """Indica se existe uma credencial com esse nome, sem revelar seu valor."""
        found = any(c["name"].casefold() == nome.casefold() for c in repository.list_metadata())
        return {"configured": found}

    @server.tool()
    def instrucoes_de_uso(nome: str) -> dict[str, str | bool]:
        """Retorna instruções e identificador de variável de ambiente, sem segredo."""
        item = next((c for c in repository.list_metadata() if c["name"].casefold() == nome.casefold()), None)
        if not item: return {"configured": False}
        return {"configured": True, "project": item["project"], "environment_variable": environment_variable_for_name(item["name"]),
                "instructions": "Leia a variável no processo usando cofre run; não imprima nem registre seu valor."}

    @server.tool()
    def solicitar_operacao_autorizada(servico: str, operacao: str, parametros: dict) -> dict:
        """Solicita operação que o aplicativo registrou explicitamente na lista permitida."""
        return broker.execute(servico, operacao, parametros)

    return server
