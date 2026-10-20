# Cofre Universal

Gerenciador pessoal de credenciais para Windows 11, escrito em Python 3.13 e PySide6. O cofre não depende de serviços pagos ou de provedores externos de senhas: sua cópia remota é um envelope cifrado guardado em um repositório privado do GitHub.

## Segurança e armazenamento

- O conteúdo inteiro do cofre, inclusive nomes e metadados, é cifrado com XChaCha20-Poly1305 via PyNaCl/libsodium. A chave é derivada da senha mestra com Argon2id.
- A senha mestra e a chave derivada nunca são enviados ao GitHub. Em outra máquina, informe a senha mestra para abrir o arquivo remoto.
- O envelope cifrado e os dados de configuração locais ficam protegidos pelo Windows DPAPI. O token GitHub é armazenado em arquivo DPAPI, fora do repositório de código.
- A sincronização usa GitHub Contents API e exige um repositório **privado**.
- Conflitos não são sobrescritos silenciosamente. A interface oferece manter a versão local ou a remota e grava a cópia substituída como backup cifrado.
- O banco SQLite da versão local anterior, se existir, é preservado. A migração pede a senha antiga e copia os registros para o formato novo sem excluir o arquivo de origem. Se os blobs DPAPI legados estiverem malformados, a migração para sem modificar o original.

O DPAPI vincula cache e token ao perfil Windows que os protegeu. Em outro computador, configure novamente o repositório e token; o cofre criptografado remoto pode ser aberto com a senha mestra. Se esquecer essa senha, o conteúdo remoto não pode ser recuperado.

## Requisitos e instalação

- Windows 11 x64
- Python 3.13 x64
- Conta GitHub com acesso a um repositório privado exclusivo para o Cofre

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev,mcp]"
python -m cofre_universal.app
```

No primeiro uso, escolha uma senha mestra com pelo menos 12 caracteres. A interface permite sincronizar imediatamente ou configurar o GitHub depois.

## Configuração do GitHub

1. Crie um repositório privado vazio para o cofre. Não use o repositório de código do aplicativo.
2. Crie um Fine-grained personal access token restrito somente a esse repositório, com `Metadata: read` e `Contents: read and write`.
3. Na interface, abra **Configurar GitHub**, informe proprietário, repositório e token. A aplicação verifica que o repositório é privado e protege a configuração com DPAPI.
4. Use **Sincronizar agora**. A sincronização automática também verifica alterações ao iniciar e a cada cinco minutos enquanto o cofre está desbloqueado.

O token é digitado somente na interface local. Não o envie por chat, não o inclua em configuração de agente e não o salve no repositório. GitHub pode conservar o histórico de commits; as versões guardadas são envelopes cifrados.

## Uso

Cadastre credenciais por nome, serviço, projeto e ambiente. O valor só aparece ao clicar **Mostrar** e é ocultado após 15 segundos. **Copiar** agenda uma limpeza após 30 segundos, se a área de transferência ainda contiver a mesma chave. O histórico e a sincronização da área de transferência do Windows podem conservar cópias; a aplicação informa esse limite.

Execute programas com as chaves do projeto:

```powershell
cofre run --project hermes -- python app.py
cofre run --project hermes -- node app.js
cofre env-example --project hermes > .env.example
```

O comando solicita a senha mestra e injeta as credenciais desse projeto somente no processo filho. Nomes de variáveis derivam do nome da credencial, em maiúsculas; colisões são rejeitadas. Processos filhos e subprocessos ainda podem ler as variáveis fornecidas. Use apenas com programas confiáveis.

O arquivo `.env.example` lista somente nomes de variáveis e não contém valores.

## Servidor MCP

Ative **Permitir ao MCP consultar metadados** na interface humana. Essa permissão é separada da visualização humana e fica protegida por DPAPI. Configure o host para iniciar `cofre mcp`; o processo pede a senha mestra em uma janela antes de iniciar o transporte stdio.

As ferramentas MCP podem listar e pesquisar metadados, informar nomes de variáveis, indicar se uma credencial existe e retornar instruções de uso. O MCP não tem uma ferramenta para revelar, copiar ou exportar valores. Há um intermediador que exige uma combinação serviço/operação registrada explicitamente; nenhuma operação externa vem autorizada por padrão.

Um agente que tenha controle irrestrito da sessão Windows ainda pode automatizar a interface, ler a memória do processo ou inspecionar variáveis de ambiente de processos que iniciou. MCP não fornece isolamento contra um agente com essas permissões.

### Cadastro assistido por IA

Na interface, habilite **Permitir à IA preparar rascunhos sem valores secretos**. Essa autorização é independente da consulta de metadados e começa desativada. Configure o host de IA para iniciar `cofre mcp` e peça, por exemplo: “Prepare uma credencial OpenAI do tipo API Key para o projeto atendimento, no ambiente produção.” A ferramenta MCP aceita somente provedor, tipo, projeto e ambiente; não possui campo para receber o valor da chave.

O cadastro padroniza provedores conhecidos (por exemplo, `openai` vira `OpenAI`), projetos em minúsculas com hífens e ambientes em português. Os tipos permitidos são API Key, API Token, OAuth Client Secret, Webhook Signing Secret, Database Connection String, Service Account Key e Other Secret. O agente pode criar o rascunho ou detectar um registro existente. Depois, abra o Cofre Universal, clique em **Preencher valor** e digite o segredo localmente. Rascunhos sem valor aparecem como pendentes e impedem `cofre run` para aquele projeto até serem preenchidos.

O agente recebe apenas os metadados necessários para esse fluxo. Não cole segredos em prompts, conversas ou respostas. Se um agente tiver controle irrestrito da sessão Windows, ele ainda pode automatizar a interface após o desbloqueio; a permissão MCP não limita capacidades concedidas diretamente pelo Windows.

## Testes e executável

```powershell
pytest
python -m nuitka run_app.py --follow-imports --enable-plugin=pyside6 --output-dir=deployment --quiet --noinclude-qt-translations --onefile --windows-console-mode=disable --noinclude-dlls=*.cpp.o --noinclude-dlls=*.qsb --include-qt-plugins=platforminputcontexts --assume-yes-for-downloads
pyinstaller --noconfirm --console --onefile --name cofre --collect-all nacl run_cli.py
```

A construção gera `deployment/run_app.exe` (interface) e `dist/cofre.exe` (CLI). A interface usa Nuitka com o plugin PySide6; a CLI usa PyInstaller. Não publique credenciais ou arquivos de cache; `.gitignore` exclui bancos, logs, builds, ambientes e `.env`.

## Estado

- Implementados: interface CRUD, senha mestra, criptografia local/remota, DPAPI, sincronização REST manual/automática e resolução de conflito com backup cifrado, execução por projeto, consentimento MCP separado e ferramentas sem valores secretos.
- Validado localmente: Python 3.13.15 em Windows 11 (build 26200), 18 testes passando, UI smoke em modo offscreen, round-trip DPAPI, GUI Nuitka 0.2.0 iniciada sem erro de importação Qt e CLI PyInstaller 0.2.0; `cofre.exe --help` executado.
- Ainda não validado: sincronização autenticada com um repositório GitHub real, fluxo visual completo em desktop e conexão a um host MCP externo. Os testes da API usam respostas mockadas e tokens fictícios.
- Nenhuma credencial real foi solicitada ou usada no desenvolvimento.

## Compatibilidade consultada

PyNaCl fornece bindings para libsodium, Argon2id e construções AEAD como XChaCha20-Poly1305; o projeto delega a criptografia à biblioteca consolidada. [Documentação PyNaCl](https://pynacl.readthedocs.io/en/latest/).

A API GitHub Contents aceita Fine-grained tokens com permissão `Contents: write` para criar ou atualizar arquivos; leitura do cofre também requer `Contents: read`. [Documentação oficial da API](https://docs.github.com/en/rest/repos/contents).

O servidor usa o SDK MCP Python oficial, versão principal 2 (`mcp>=2,<3`), cujo servidor `MCPServer` oferece transporte stdio. [Documentação oficial MCP](https://py.sdk.modelcontextprotocol.io/).
