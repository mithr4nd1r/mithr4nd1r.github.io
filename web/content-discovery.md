---
title: "Content Discovery"
---

# Content Discovery - Fuzzing e Enumeração de Conteúdo

---

## Contexto: Descoberta de Endpoints Não Linkados — A Superfície Oculta

Content discovery parte de uma premissa simples mas poderosa: **o que não está linkado na UI ainda pode estar acessível no servidor**. A raiz do problema é arquitetural — desenvolvedores frequentemente implementam controle de acesso na camada de interface, não na camada de back-end.

**Por que endpoints não protegidos existem — a causa raiz:**

Quando um desenvolvedor remove um botão de administração da navbar ou esconde um menu de debug, a tendência natural é acreditar que o endpoint foi "protegido". Mas o que foi feito foi apenas remover o *link* — o endpoint continua existindo no servidor e respondendo a requisições diretas. A proteção real exige validação de autorização no back-end, em cada endpoint, independentemente de como o usuário chegou até ele.

Isso cria uma classe enorme de vulnerabilidades por negligência. Painéis de admin implementados durante desenvolvimento nunca são removidos de produção. Versões antigas de APIs como `/api/v1/` são mantidas por compatibilidade mas sem o mesmo controle de acesso da versão atual. Arquivos de backup, dumps de banco e configs são deixados no webroot por engano. Funcionalidades de debug permanecem ativas em produção. Endpoints de integração com terceiros são implementados sem autenticação adequada porque "só serão chamados internamente".

**Endpoint que não está na navbar ainda está acessível — fuzzing encontra o que a UI esconde:**

O fuzzing de conteúdo automatiza o processo de testar centenas ou milhares de paths possíveis contra o servidor. A lógica é direta: se o servidor retorna algo diferente de 404, o recurso existe. Status 200 indica conteúdo acessível, 403 indica que o recurso existe mas o acesso é negado (ainda é uma descoberta útil — às vezes o controle pode ser bypassado), 301/302 indica redirecionamento para outro recurso.

**Como content discovery se conecta com vulnerabilidades:**

Cada tipo de endpoint descoberto tem sua classe de vulnerabilidade associada. Um `/admin/` exposto indica painel sem autenticação adequada, vetor direto para auth bypass e IDOR. `/.git/` exposto é um repositório completo acessível, revelando código-fonte e credenciais. `/.env` contém variáveis de ambiente com credenciais de banco e API keys em texto claro. `/api/v1/internal/` é um endpoint não documentado tipicamente sem controle de acesso. `/backup.sql` é um dump de banco de dados com acesso direto a todos os dados armazenados. `/phpinfo.php` expõe versões, paths e configurações do servidor que orientam a exploração subsequente.

Sem content discovery, você vai perder:
- `/admin/` — painel de administração não linkado
- `/backup/db.sql.gz` — backup completo do banco de dados
- `/api/v2/internal/users` — endpoint de API não documentado
- `/.git/` — repositório Git exposto (código-fonte completo)
- `/config.php.bak` — arquivo de configuração com credenciais
- `/.env` — variáveis de ambiente com senhas e chaves de API
- `/phpinfo.php` — informações detalhadas do servidor PHP

Content discovery eficaz multiplica drasticamente a superfície de ataque disponível.

---

## Tipos de Content Discovery: Directory, File, Subdomain e Parameter Fuzzing

### Tipos de Content Discovery

| Tipo | Método | Ferramentas |
|------|--------|-------------|
| **Directory fuzzing** | Testar nomes de diretórios conhecidos | ffuf, gobuster, dirsearch |
| **File fuzzing** | Testar nomes de arquivos + extensões | ffuf, gobuster, dirsearch |
| **Extension fuzzing** | Testar extensões em arquivos conhecidos | ffuf |
| **Recursive fuzzing** | Fuzzing dentro de diretórios descobertos | ffuf (-recursion) |
| **Subdomain fuzzing** | Testar subdomínios via DNS ou vhost | ffuf, gobuster dns |
| **VHost fuzzing** | Testar virtual hosts via header Host | ffuf, gobuster vhost |
| **Parameter fuzzing** | Descobrir parâmetros GET/POST não documentados | ffuf, Arjun, Paramspider |

---

## Na Prática

### ffuf - Fuzz Faster U Fool

ffuf é a ferramenta de fuzzing web mais rápida e flexível. A palavra `FUZZ` na URL/header/body é substituída por cada item da wordlist.

**Instalação:**

```bash
# Go install
go install github.com/ffuf/ffuf/v2@latest

# Apt (pode estar desatualizado)
sudo apt install ffuf

# Download binário direto
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz
tar xzf ffuf_*.tar.gz
sudo mv ffuf /usr/local/bin/
```

**Referência completa de flags:**

| Flag | Descrição | Exemplo |
|------|-----------|---------|
| `-u` | URL alvo com FUZZ | `-u https://site.com/FUZZ` |
| `-w` | Wordlist (caminho:KEYWORD) | `-w wordlist.txt` ou `-w list.txt:WORD` |
| `-H` | Header adicional | `-H "Cookie: session=abc"` |
| `-X` | Método HTTP | `-X POST` |
| `-d` | Dados do body (POST) | `-d "user=FUZZ&pass=admin"` |
| `-b` | Cookie | `-b "PHPSESSID=abc123"` |
| `-t` | Threads | `-t 40` |
| `-p` | Delay entre requests | `-p 0.1` |
| `-r` | Seguir redirects | `-r` |
| `-recursion` | Fuzzing recursivo | `-recursion` |
| `-recursion-depth` | Profundidade recursiva | `-recursion-depth 3` |
| `-e` | Extensões a adicionar | `-e .php,.html,.txt` |
| `-ic` | Ignorar comentários na wordlist | `-ic` |
| `-v` | Output verbose (mostra URL completa) | `-v` |
| `-o` | Arquivo de output | `-o results.txt` |
| `-of` | Formato de output | `-of json` |
| `-fs` | Filtrar por tamanho (bytes) | `-fs 0,1234` |
| `-fc` | Filtrar por código HTTP | `-fc 404` |
| `-fw` | Filtrar por número de palavras | `-fw 10` |
| `-fl` | Filtrar por número de linhas | `-fl 5` |
| `-fr` | Filtrar por regex | `-fr "Not Found"` |
| `-ms` | Match por tamanho | `-ms 1234` |
| `-mc` | Match por código HTTP | `-mc 200,301` |
| `-mw` | Match por palavras | `-mw 100` |
| `-ml` | Match por linhas | `-ml 50` |
| `-mr` | Match por regex | `-mr "Welcome"` |
| `-ac` | Auto-calibrar filtros | `-ac` |
| `-timeout` | Timeout por request | `-timeout 10` |
| `-maxtime` | Tempo total máximo | `-maxtime 60` |
| `-s` | Modo silencioso (menos output) | `-s` |
| `-c` | Output colorido | `-c` |

### Wordlists - SecLists

SecLists é o repositório padrão de wordlists para pentest:

```bash
# Instalação
sudo apt install seclists
# Fica em: /usr/share/seclists/

# Clone manual para versão mais recente
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

**Wordlists principais:**

| Arquivo | Uso | Tamanho |
|---------|-----|---------|
| `/usr/share/seclists/Discovery/Web-Content/common.txt` | Diretórios/arquivos mais comuns | ~4.7k |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Diretórios médio | ~220k |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` | Diretórios pequeno | ~87k |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` | Raft directories | ~30k |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` | Raft files | ~37k |
| `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt` | Extensões web | ~200 |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Subdomínios top 5k | ~5k |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` | Subdomínios top 20k | ~20k |
| `/usr/share/seclists/Fuzzing/` | Payloads de injeção | variável |
| `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz` | Senhas vazadas | ~14M |

---

## Exemplos

### 1. Directory Fuzzing Básico

```bash
# Descobrir diretórios com wordlist padrão
ffuf -u http://SERVER_IP:PORT/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Output típico:
# [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 45ms]
# * FUZZ: admin
# [Status: 200, Size: 1234, Words: 56, Lines: 42, Duration: 32ms]
# * FUZZ: images
# [Status: 200, Size: 789, Words: 23, Lines: 18, Duration: 28ms]
# * FUZZ: backup

# Com threading aumentado e output mais limpo
ffuf -u http://SERVER_IP:PORT/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -t 40 \
     -c \
     -v

# Filtrar 404 (padrão) e ignorar tamanho específico de "página não encontrada"
ffuf -u http://SERVER_IP:PORT/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -fc 404 \
     -fs 1234
```

### 2. Extension Fuzzing

Quando você sabe que um arquivo existe mas não sabe a extensão:

```bash
# Testar extensões em arquivo específico
ffuf -u http://SERVER_IP:PORT/indexFUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt

# Output:
# [Status: 200, Size: 4523] * FUZZ: .php
# [Status: 200, Size: 156]  * FUZZ: .php.bak

# Wordlist de extensões manual (inline)
ffuf -u http://SERVER_IP:PORT/indexFUZZ \
     -w - <<< $'.php\n.html\n.txt\n.asp\n.aspx\n.jsp\n.bak\n.old\n.config\n.sql\n.xml\n.json'
```

### 3. Page Fuzzing (arquivo + extensão simultâneos)

```bash
# Combinar nome de arquivo E extensão
ffuf -u http://SERVER_IP:PORT/blog/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -e .php,.html,.txt,.bak,.config

# Isso testa: wordlist/item, wordlist/item.php, wordlist/item.html, etc.

# Output:
# [Status: 200] * FUZZ: index.php
# [Status: 200] * FUZZ: about.html
# [Status: 200] * FUZZ: config.php.bak  ← arquivo de backup!
# [Status: 200] * FUZZ: admin.php
```

### 4. Recursive Fuzzing

Automaticamente fazer fuzzing dentro dos diretórios descobertos:

```bash
# Recursivo (cuidado: pode ser muito lento em sites grandes)
ffuf -u http://SERVER_IP:PORT/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -e .php \
     -recursion \
     -recursion-depth 3 \
     -v \
     -t 20

# Output:
# [INFO] Adding a new job to the queue: http://SERVER_IP:PORT/admin/FUZZ
# [Status: 200] * FUZZ: admin/users.php
# [Status: 200] * FUZZ: admin/config.php
# [INFO] Adding a new job to the queue: http://SERVER_IP:PORT/admin/upload/FUZZ
# [Status: 200] * FUZZ: admin/upload/shell.php
```

### 5. Subdomain Fuzzing (DNS)

```bash
# Subdomain brute-force via DNS
ffuf -u http://FUZZ.inlanefreight.com/ \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.inlanefreight.com"

# Filtrar respostas de "not found" (geralmente tamanho fixo)
ffuf -u http://inlanefreight.com/ \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.inlanefreight.com" \
     -fs 0

# Usar DNS resolver específico
ffuf -u http://FUZZ.inlanefreight.com/ \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -t 50

# Output:
# [Status: 200, Size: 15348] * FUZZ: www
# [Status: 200, Size: 8923]  * FUZZ: mail
# [Status: 301, Size: 0]     * FUZZ: admin
# [Status: 200, Size: 3421]  * FUZZ: dev
```

### 6. VHost Fuzzing

VHost fuzzing descobre virtual hosts no mesmo IP — subdomínios que não resolvem via DNS mas existem no servidor:

```bash
# VHost fuzzing via header Host
ffuf -u http://SERVER_IP:PORT/ \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.inlanefreight.com" \
     -fs 15234

# O -fs filtra o tamanho da resposta padrão (medir primeiro):
curl -s http://SERVER_IP:PORT/ | wc -c
# 15234 → usar -fs 15234

# Output:
# [Status: 200, Size: 8743] * FUZZ: admin
# [Status: 200, Size: 4521] * FUZZ: portal
# [Status: 200, Size: 12456] * FUZZ: internal

# Verificar com curl
curl -H "Host: admin.inlanefreight.com" http://SERVER_IP:PORT/
```

### 7. Parameter Fuzzing GET

Descobrir parâmetros GET não documentados:

```bash
# Fuzzing de parâmetros GET
ffuf -u http://admin.inlanefreight.com/admin/admin.php?FUZZ=key \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs 798

# Onde 798 é o tamanho da resposta sem parâmetro válido
# Medir: curl -s "http://admin.inlanefreight.com/admin/admin.php" | wc -c

# Output:
# [Status: 200, Size: 1234] * FUZZ: user
# [Status: 200, Size: 2341] * FUZZ: debug
# [Status: 200, Size: 456]  * FUZZ: id
```

### 8. Parameter Fuzzing POST

```bash
# Fuzzing de parâmetros POST (Content-Type: application/x-www-form-urlencoded)
ffuf -u http://admin.inlanefreight.com/admin/admin.php \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -X POST \
     -d "FUZZ=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs 798

# POST com JSON
ffuf -u http://api.inlanefreight.com/v1/endpoint \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -X POST \
     -d '{"FUZZ":"test"}' \
     -H "Content-Type: application/json" \
     -fs 150
```

### 9. Value Fuzzing (fuzz valores, não parâmetros)

```bash
# Descobrir IDs válidos (IDOR)
ffuf -u http://admin.inlanefreight.com/admin/admin.php?user_id=FUZZ \
     -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
     -fs 798

# Brute force de campo específico
ffuf -u http://site.com/login \
     -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
     -X POST \
     -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fr "Invalid credentials" \
     -t 10
```

### 10. Auto-Calibrate (-ac)

ffuf pode detectar automaticamente qual tamanho de resposta filtrar:

```bash
# -ac testa alguns payloads inválidos para detectar "not found" automaticamente
ffuf -u http://SERVER_IP:PORT/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -ac \
     -c
```

### Ferramentas Alternativas

**gobuster**

```bash
# Directory brute-force
gobuster dir \
    -u http://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 50 \
    -x php,html,txt \
    -o gobuster_results.txt

# Com autenticação
gobuster dir \
    -u http://target.com/admin \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -U admin \
    -P password123

# DNS mode
gobuster dns \
    -d target.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50

# Vhost mode
gobuster vhost \
    --domain target.com \
    -u http://TARGET_IP \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**dirsearch**

```bash
# Instalação
pip install dirsearch
# ou
git clone https://github.com/maurosoria/dirsearch

# Uso básico
dirsearch -u http://target.com

# Extensões específicas
dirsearch -u http://target.com -e php,html,txt,bak

# Wordlist customizada
dirsearch -u http://target.com \
          -w /usr/share/seclists/Discovery/Web-Content/common.txt \
          -e php \
          -t 50

# Excluir status codes
dirsearch -u http://target.com --exclude-status=400,403,500

# Salvar output
dirsearch -u http://target.com -o results.txt --format plain
```

**feroxbuster**

```bash
# Instalação
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Directory fuzzing
feroxbuster --url http://target.com \
            --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
            --extensions php html txt

# Recursive fuzzing (nativo)
feroxbuster --url http://target.com \
            --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
            --depth 3 \
            --threads 50 \
            --filter-status 404,403

# Com filtro de tamanho
feroxbuster --url http://target.com \
            -w /usr/share/seclists/Discovery/Web-Content/common.txt \
            --filter-size 1234
```

**Comparação de ferramentas:**

| Ferramenta | Velocidade | Recursão | Vhost | Flexibilidade | Linguagem |
|-----------|-----------|---------|-------|---------------|-----------|
| ffuf | Muito alta | Sim | Sim | Muito alta | Go |
| gobuster | Alta | Não nativo | Sim | Média | Go |
| dirsearch | Média | Sim | Não | Média | Python |
| feroxbuster | Alta | Sim (nativo) | Não | Alta | Rust |
| wfuzz | Alta | Sim | Sim | Alta | Python |

### Parameter Discovery com Arjun

Arjun é especializado em descoberta de parâmetros HTTP:

```bash
# Instalação
pip install arjun

# Scan básico GET
arjun -u http://target.com/search

# POST
arjun -u http://target.com/api/data -m POST

# Headers auth
arjun -u http://target.com/api/profile \
      --headers "Authorization: Bearer TOKEN123"

# Wordlist customizada
arjun -u http://target.com/api \
      -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Output em JSON
arjun -u http://target.com -o results.json

# Múltiplas URLs
arjun -u "http://target.com/api1" "http://target.com/api2"

# Output típico:
# [*] Scanning 3000 parameters
# [+] Heuristic scan done. found 3 potential parameters
# [+] Identified 2 valid parameters: id, user
```

### robots.txt e sitemap.xml

Antes de qualquer fuzzing, verificar esses arquivos:

```bash
# robots.txt pode revelar diretórios "proibidos"
curl -s http://target.com/robots.txt

# Output típico:
# User-agent: *
# Disallow: /admin/
# Disallow: /backup/
# Disallow: /config/
# Disallow: /api/internal/
# Sitemap: http://target.com/sitemap.xml
# → Esses Disallow são pistas de onde procurar!

# sitemap.xml lista URLs da aplicação
curl -s http://target.com/sitemap.xml | grep -oP 'https?://[^<]+'

# Sitemaps alternativos
curl -s http://target.com/sitemap_index.xml
curl -s http://target.com/sitemaps/sitemap-0.xml
```

### Arquivos de Interesse

Lista de arquivos que sempre devem ser verificados:

```bash
# Script para verificar arquivos sensíveis comuns
FILES=(
    "/.git/HEAD"
    "/.git/config"
    "/.env"
    "/.env.local"
    "/.env.production"
    "/config.php"
    "/config.php.bak"
    "/wp-config.php"
    "/wp-config.php.bak"
    "/config.yml"
    "/config.yaml"
    "/settings.py"
    "/app/config/parameters.yml"
    "/phpinfo.php"
    "/info.php"
    "/test.php"
    "/debug.php"
    "/backup.zip"
    "/backup.tar.gz"
    "/dump.sql"
    "/db.sql"
    "/database.sql"
    "/.htaccess"
    "/.htpasswd"
    "/crossdomain.xml"
    "/clientaccesspolicy.xml"
    "/security.txt"
    "/.well-known/security.txt"
    "/humans.txt"
    "/README.md"
    "/CHANGELOG.md"
    "/package.json"
    "/composer.json"
    "/Gemfile"
)

TARGET="http://target.com"
for file in "${FILES[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$file")
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ]; then
        echo "[$STATUS] $TARGET$file"
    fi
done
```

### Salvando e Processando Resultados ffuf

```bash
# Salvar em JSON para processamento
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -o ffuf_results.json \
     -of json

# Processar JSON
jq -r '.results[] | "\(.status) \(.url)"' ffuf_results.json

# Extrair só URLs encontradas
jq -r '.results[].url' ffuf_results.json

# Filtrar por status
jq -r '.results[] | select(.status==200) | .url' ffuf_results.json
```

---

## Módulos Relacionados

Information Gathering (`01_information_gathering.md`) alimenta diretamente este módulo: cada subdomínio ativo descoberto durante o recon se torna um alvo independente de content discovery. O módulo de HTTP Protocolo (`../01_fundamentos_web/01_http_protocolo.md`) é a base teórica do ffuf — entender headers, métodos e status codes é essencial para interpretar o que cada resposta de fuzzing significa. Web Proxies (`../01_fundamentos_web/03_web_proxies.md`) permitem rotear o tráfego do ffuf pelo Burp para análise manual detalhada dos resultados mais interessantes. JavaScript Analysis (`03_javascript_analysis.md`) complementa o fuzzing porque endpoints descobertos via wordlist frequentemente também aparecem hardcoded nos bundles JS da aplicação. Parâmetros descobertos via parameter fuzzing são candidatos diretos a SQL Injection e a parâmetros do tipo `file=`, `page=` ou `include=` que indicam LFI, enquanto IDs numéricos encontrados via value fuzzing são candidatos a IDOR.

**Ferramentas mencionadas:**
- `ffuf` — principal ferramenta de fuzzing web
- `gobuster` — alternativa ao ffuf
- `dirsearch` — Python-based directory fuzzer
- `feroxbuster` — Rust-based recursive fuzzer
- `arjun` — parameter discovery
- `wfuzz` — fuzzer Python flexível
- SecLists — repositório de wordlists

**Referências HTB:**
- HTB Module: Attacking Web Applications with Ffuf
- HTB Module: Web Fuzzing
