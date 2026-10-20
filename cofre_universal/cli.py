"""Comando cofre run para iniciar processos com variáveis de ambiente."""
from __future__ import annotations
import argparse
import getpass
import os
import subprocess
import sys
from .repository import CredentialRepository
from .mcp_catalog import build_server
from .mcp_policy import AgentPolicyStore


def run_app(project: str, command: list[str], db_path: str | None = None) -> int:
    if not command:
        raise ValueError("Informe o comando da aplicação após --.")
    repo = CredentialRepository(db_path)
    repo.unlock(getpass.getpass("Senha mestra do Cofre Universal: "))
    env = os.environ.copy()
    injected_names = set()
    for credential in repo.list_credentials():
        if credential.project.casefold() == project.casefold():
            if getattr(credential, "pending_secret", False) or not credential.secret:
                raise ValueError(f"O projeto contém um rascunho sem valor secreto: {credential.name}")
            variable = credential.environment_name
            if variable:
                if variable in injected_names:
                    raise ValueError(f"Nomes de variáveis duplicados no projeto: {variable}")
                injected_names.add(variable)
                env[variable] = credential.secret
    return subprocess.run(command, env=env, check=False).returncode


def env_example(project: str, db_path: str | None = None) -> list[str]:
    repo = CredentialRepository(db_path)
    repo.unlock(getpass.getpass("Senha mestra do Cofre Universal: "))
    credentials = [c for c in repo.list_credentials() if c.project.casefold() == project.casefold()]
    names = [c.environment_name for c in credentials if c.environment_name]
    if len(set(names)) != len(names):
        raise ValueError("Há nomes de variáveis duplicados no projeto.")
    return sorted(set(names))


def main() -> None:
    parser = argparse.ArgumentParser(prog="cofre")
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="Executa uma aplicação com as chaves do projeto")
    run.add_argument("--project", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    env_parser = sub.add_parser("env-example", help="Lista somente nomes de variáveis de um projeto")
    env_parser.add_argument("--project", required=True)
    sub.add_parser("mcp", help="Inicia o servidor MCP local conforme permissões habilitadas")
    args = parser.parse_args()
    if args.action == "mcp":
        try:
            run_mcp()
        except Exception as exc:
            print(f"cofre mcp: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return
    if args.action == "env-example":
        try:
            for name in env_example(args.project): print(name)
        except Exception as exc:
            print(f"cofre env-example: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        raise SystemExit(run_app(args.project, command))
    except Exception as exc:
        print(f"cofre: {exc}", file=sys.stderr)
        raise SystemExit(2)


def run_mcp() -> None:
    """Autentica por janela segura antes de abrir o transporte stdio MCP."""
    from PySide6.QtWidgets import QApplication, QInputDialog, QLineEdit
    app = QApplication.instance() or QApplication([])
    policy = AgentPolicyStore()
    if not policy.any_enabled():
        raise PermissionError("Acesso MCP desativado. Ative as permissões desejadas na interface humana.")
    repo = CredentialRepository()
    password, ok = QInputDialog.getText(None, "Desbloquear para MCP", "Senha mestra do Cofre Universal:", QLineEdit.EchoMode.Password)
    if not ok: return
    try:
        repo.unlock(password)
        server = build_server(repo, allow_metadata=policy.enabled(),
                              allow_drafts=policy.drafts_enabled())
        server.run("stdio")
    finally:
        repo.lock()


if __name__ == "__main__":
    main()
