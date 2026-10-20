# Orientações para agentes

- Leia `README.md` e `docs/SEGURANCA.md` antes de alterar armazenamento, criptografia, sincronização ou permissões.
- Nunca solicite, cole ou use chaves reais de API. Use marcadores explicitamente fictícios em testes.
- Não implemente primitivas criptográficas próprias. Preserve PyNaCl/libsodium, Argon2id e XChaCha20-Poly1305.
- Nunca envie senha mestra, chave derivada ou payload descriptografado ao GitHub, MCP, logs, issues ou contexto de modelo.
- Cache e token local devem permanecer protegidos por DPAPI no Windows; não crie fallback de texto puro.
- O repositório remoto de cofre deve ser privado e dedicado. Tokens devem ter escopo fine-grained limitado a esse repositório e só as permissões necessárias.
- MCP deve permanecer desativado por padrão. Não registre ferramentas genéricas para revelar, copiar, exportar ou descriptografar credenciais.
- A permissão MCP para consultar metadados deve continuar separada da permissão para criar rascunhos. Rascunhos só recebem metadados padronizados; o valor secreto é digitado pela pessoa na interface local.
- Nunca adicione um parâmetro secreto à ferramenta MCP de cadastro nem envie valores secretos ao modelo. `cofre run` deve rejeitar projetos com rascunhos pendentes.
- Operações para agentes devem exigir pares serviço/operação registrados explicitamente e nunca retornar segredos.
- Preserve dados existentes. Migrações devem copiar e validar antes de qualquer limpeza; não apague bancos/cache/backups sem autorização explícita.
- Preserve compatibilidade Windows 11 e Python 3.13. Não declare validação Windows sem executar no Windows.
- Execute testes pertinentes após alterações; não imprima segredos em falhas ou logs.
