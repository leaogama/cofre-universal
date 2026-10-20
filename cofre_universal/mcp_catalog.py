"""Servidor MCP local para metadados seguros e rascunhos sem valores secretos."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from typing import Literal

from .models import environment_variable_for_name
from .repository import CredentialRepository


CredentialType = Literal[
    "API Key", "API Token", "OAuth Client Secret", "Webhook Signing Secret",
    "Database Connection String", "Service Account Key", "Other Secret",
]

SERVICE_ALIASES = {
    "openai": "OpenAI", "github": "GitHub", "aws": "AWS",
    "amazon web services": "AWS", "anthropic": "Anthropic",
    "google gemini": "Google Gemini", "gemini": "Google Gemini",
    "google cloud": "Google Cloud", "gcp": "Google Cloud",
    "microsoft azure": "Microsoft Azure", "azure": "Microsoft Azure",
    "stripe": "Stripe", "supabase": "Supabase", "firebase": "Firebase",
    "hugging face": "Hugging Face", "mistral": "Mistral AI",
    "mistral ai": "Mistral AI", "elevenlabs": "ElevenLabs",
}

ENVIRONMENTS = {
    "dev": "Desenvolvimento", "development": "Desenvolvimento",
    "develop": "Desenvolvimento", "desenvolvimento": "Desenvolvimento",
    "test": "Testes", "testing": "Testes", "qa": "Testes", "teste": "Testes",
    "testes": "Testes", "stage": "Homologação", "staging": "Homologação",
    "homologacao": "Homologação", "prod": "Produção", "production": "Produção",
    "producao": "Produção", "sandbox": "Sandbox", "local": "Local",
}

TYPE_ALIASES = {
    "api key": "API Key", "api token": "API Token",
    "oauth client secret": "OAuth Client Secret",
    "webhook signing secret": "Webhook Signing Secret",
    "database connection string": "Database Connection String",
    "service account key": "Service Account Key", "other secret": "Other Secret",
}


def _ascii_fold(value: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", value)
                   if not unicodedata.combining(ch)).casefold()


def _safe_label(value: str, field: str, *, max_length: int = 80) -> str:
    value = " ".join(value.split())
    if not value or len(value) > max_length or not re.fullmatch(r"[\w .&/+\-]+", value, re.UNICODE):
        raise ValueError(f"{field} inválido. Não inclua valores de chaves nesses campos.")
    # Rejeita formatos frequentes de tokens para evitar que um segredo colado por engano
    # entre em metadados enviados ao modelo.
    if re.search(r"(?i)(?:sk-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9_]{12,}|github_pat_[a-z0-9_]{12,}|AIza[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16})", value):
        raise ValueError(f"{field} parece conter um segredo. Remova-o e envie somente metadados.")
    return value


def normalize_service(value: str) -> str:
    value = _safe_label(value, "Provedor", max_length=48)
    folded = _ascii_fold(value)
    if folded in SERVICE_ALIASES:
        return SERVICE_ALIASES[folded]
    acronyms = {"api": "API", "ai": "AI", "aws": "AWS", "gcp": "GCP", "mcp": "MCP"}
    return " ".join(acronyms.get(word.casefold(), word.capitalize()) for word in value.split())


def normalize_project(value: str) -> str:
    value = _safe_label(value, "Projeto", max_length=80)
    slug = re.sub(r"[^a-z0-9]+", "-", _ascii_fold(value)).strip("-")
    if not slug or len(slug) > 48:
        raise ValueError("Projeto inválido; use um nome de até 48 caracteres.")
    return slug


def normalize_environment(value: str) -> str:
    value = _safe_label(value, "Ambiente", max_length=40)
    canonical = ENVIRONMENTS.get(_ascii_fold(value))
    if canonical is None:
        raise ValueError("Ambiente inválido. Use Desenvolvimento, Testes, Homologação, Produção, Sandbox ou Local.")
    return canonical


def prepare_credential_draft(repository: CredentialRepository, *, provider: str,
                             credential_type: CredentialType, project: str,
                             environment: str) -> dict[str, str | bool]:
    service = normalize_service(provider)
    project_slug = normalize_project(project)
    env = normalize_environment(environment)
    try:
        type_name = TYPE_ALIASES[credential_type.casefold()]
    except (AttributeError, KeyError):
        raise ValueError("Tipo de credencial não permitido.") from None
    name = f"{service} {type_name}"
    variable = environment_variable_for_name(name)
    notes = f"Leia {variable} via cofre run --project {project_slug}; não registre seu valor."
    draft, created = repository.create_draft(name=name, service=service, project=project_slug,
                                             environment=env, usage_notes=notes)
    return {
        "draft_created": created,
        "already_configured": not created and not draft.pending_secret,
        "id": draft.id,
        "name": draft.name,
        "service": draft.service,
        "project": draft.project,
        "environment": draft.environment,
        "secret_pending": draft.pending_secret,
        "next_step": "Abra o Cofre Universal, edite este rascunho e preencha o valor secreto diretamente na interface.",
    }


class OperationBroker:
    """Despachante por pares serviço/operação registrados explicitamente."""

    def __init__(self):
        self._handlers: dict[tuple[str, str], Callable[[dict], dict]] = {}

    def register(self, service: str, operation: str, handler: Callable[[dict], dict]) -> None:
        self._handlers[(service.casefold(), operation.casefold())] = handler

    def execute(self, service: str, operation: str, payload: dict) -> dict:
        handler = self._handlers.get((service.casefold(), operation.casefold()))
        if handler is None:
            raise PermissionError("Esta operação não foi explicitamente autorizada no Cofre Universal.")
        result = handler(payload)
        if not isinstance(result, dict):
            raise TypeError("O intermediador retornou um formato inválido.")
        return result


def list_available_credentials(repository: CredentialRepository) -> list[dict[str, str | bool]]:
    return [_agent_metadata(item) for item in repository.list_metadata()]


def search_credentials(repository: CredentialRepository, query: str) -> list[dict[str, str | bool]]:
    return [_agent_metadata(item) for item in repository.list_metadata(query)]


def _agent_metadata(item: dict) -> dict[str, str | bool]:
    """Whitelist exclui segredos e notas livres que poderiam conter valores colados."""
    fields = ("id", "name", "service", "project", "environment")
    return {**{field: item[field] for field in fields},
            "secret_pending": bool(item.get("secret_pending", False))}


def build_server(repository: CredentialRepository, *, allow_metadata: bool,
                 allow_drafts: bool = False, broker: OperationBroker | None = None):
    """MCP começa desativado; metadados e criação de rascunhos têm permissões distintas."""
    if not allow_metadata and not allow_drafts:
        raise PermissionError("O acesso MCP está desativado nas permissões independentes do Cofre.")
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise RuntimeError("Instale o extra opcional: pip install '.[mcp]'") from exc
    server = MCPServer("Cofre Universal")
    broker = broker or OperationBroker()

    if allow_metadata:
        @server.tool()
        def listar_credenciais() -> list[dict[str, str | bool]]:
            """Lista metadados e estado de preenchimento; nunca retorna valores secretos."""
            return list_available_credentials(repository)

        @server.tool()
        def pesquisar_credenciais(termo: str) -> list[dict[str, str | bool]]:
            """Pesquisa metadados e estado de preenchimento; nunca retorna valores."""
            return search_credentials(repository, termo)

        @server.tool()
        def nomes_de_variaveis(projeto: str) -> list[dict[str, str]]:
            """Informa somente nomes de variáveis de um projeto."""
            project_name = projeto.strip().casefold()
            matches = [c for c in repository.list_metadata()
                       if c["project"].casefold() == project_name]
            return [{"name": c["name"], "environment_variable": environment_variable_for_name(c["name"])} for c in matches]

        @server.tool()
        def credencial_configurada(nome: str) -> dict[str, bool]:
            """Indica se existe uma credencial com esse nome, sem revelar seu valor."""
            found = any(c["name"].casefold() == nome.casefold() for c in repository.list_metadata())
            return {"configured": found}

        @server.tool()
        def instrucoes_de_uso(nome: str) -> dict[str, str | bool]:
            """Retorna instruções e identificador de variável, sem segredo."""
            item = next((c for c in repository.list_metadata() if c["name"].casefold() == nome.casefold()), None)
            if not item:
                return {"configured": False}
            return {"configured": True, "project": item["project"],
                    "environment_variable": environment_variable_for_name(item["name"]),
                    "instructions": "Leia a variável no processo usando cofre run; não imprima nem registre seu valor."}

        @server.tool()
        def solicitar_operacao_autorizada(servico: str, operacao: str, parametros: dict) -> dict:
            """Solicita operação previamente autorizada por combinação serviço/operação."""
            return broker.execute(servico, operacao, parametros)

    if allow_drafts:
        @server.tool()
        def preparar_credencial(provedor: str, tipo: CredentialType,
                                projeto: str, ambiente: str) -> dict[str, str | bool]:
            """Prepara metadados padronizados. Não aceite nem envie o valor da chave; ele é digitado na GUI."""
            return prepare_credential_draft(repository, provider=provedor, credential_type=tipo,
                                            project=projeto, environment=ambiente)

    return server
