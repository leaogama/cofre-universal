# Modelo de segurança

## Conteúdo e chaves

- O JSON completo de credenciais é cifrado com libsodium, chamado por PyNaCl: Argon2id deriva uma chave de 32 bytes e XChaCha20-Poly1305 cifra cada envelope com nonce aleatório e autenticação de dados associada.
- O GitHub recebe apenas o envelope cifrado. A senha mestra, chave derivada, valores e metadados não são enviados em claro.
- Senha incorreta e conteúdo adulterado produzem erro genérico de abertura. Os parâmetros KDF aceitos são fixos no formato atual para impedir que um envelope não confiável peça consumo arbitrário de memória.
- Valores ficam em memória enquanto o cofre está desbloqueado. Python não garante zeragem de todas as cópias imutáveis; bloquear limpa a sessão e zera o buffer da chave, mas malware ou um processo com controle da sessão pode inspecionar memória.

## Windows e GitHub

- DPAPI protege o cache do envelope cifrado, token GitHub, permissões MCP e estado de sincronização no perfil Windows atual.
- Em novo computador, token e configuração devem ser definidos novamente. Baixe o envelope pelo GitHub e use a senha mestra original para recuperá-lo.
- Configure um Fine-grained PAT com acesso a um só repositório privado, permissões `Metadata: read` e `Contents: read/write`. O cliente exige que o repositório seja privado e envia somente arquivos cifrados.
- GitHub mantém histórico de commits e as cópias de conflito são arquivos separados. Esses arquivos continuam cifrados, mas não são apagados automaticamente.
- Se o token for revogado, a cópia local continua disponível. Se a senha mestra for esquecida, nem o operador do GitHub consegue abrir o cofre.

## Conflitos e recuperação

O aplicativo compara o envelope local, o remoto e a última base sincronizada. Se ambos mudaram, não escolhe silenciosamente. Para resolver, pode preservar uma das versões em backup cifrado e adotar explicitamente a outra. Uma cópia remota sem base comum exige escolha humana antes da substituição.

A importação do SQLite antigo é opcional e não apaga nem altera o banco original. Ela exige a senha antiga e cria um novo envelope criptografado.

## Permissões de agente

MCP fica desativado por padrão e tem uma permissão de metadados separada do uso humano. As ferramentas não retornam valores secretos. O intermediador de operações exige handlers explicitamente registrados; a configuração inicial não autoriza provedores ou operações externos.

Um agente com controle irrestrito do Windows pode automação de interface, leitura de memória, captura de tela ou inspeção de processos/variáveis de ambiente. Estas proteções não isolam contra esse nível de acesso.

## Logs e testes

O projeto não registra valores, tokens, senhas, payloads de ambiente ou corpos de arquivos remotos. Testes devem usar somente marcadores fictícios como `FAKE_SECRET`. Nunca inclua objetos completos `Credential` ou envelope descriptografado em logs, exceções ou mensagens MCP.
