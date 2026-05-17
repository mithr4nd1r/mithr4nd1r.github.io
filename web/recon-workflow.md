---
title: "Recon Workflow"
---

# Recon Workflow - Bug Bounty

## Contexto: Pipeline de Recon como Multiplicador de Superficie

Recon nao e fase opcional — e o que determina quantos alvos voce tem para testar. Cada camada do pipeline revela um tipo diferente de superficie que corresponde a uma classe de vulnerabilidade especifica.

**Por que automatizacao importa:**

Para alvos grandes (Fortune 500 com *.empresa.com), a superficie real e de dezenas de milhares de subdominios. Sem automacao de recon, voce esta testando os mesmos endpoints que todos os outros hunters ja testaram — o que foi reportado e foi corrigido. O diferencial e encontrar o subdominio novo que surgiu ontem, o endpoint legado que ninguem notou, o JS file que foi deployado na semana passada com uma API key hardcoded.

**Mapeamento de cada etapa do pipeline para o tipo de vulnerabilidade que ela revela:**

| Etapa do Pipeline | O que revela | Classe de vulnerabilidade |
|---|---|---|
| Subdominios passivos (CT logs, APIs) | Domínios de terceiros, staging, legados | Subdomain takeover, versoes antigas, admin exposto |
| DNS brute force | Subdominios internos nao publicos | Admin panels, dev environments |
| httpx + tech detection | Stack tecnologico de cada host | CVEs especificos de framework/versao |
| GAU + waybackurls | URLs historicas que ainda existem | Endpoints removidos da UI mas ainda ativos no backend |
| JS analysis | Endpoints e parametros nao documentados | IDOR em APIs internas, secrets expostos, business logic |
| Nuclei templates | Misconfigurações conhecidas em massa | CVEs, default creds, info disclosure |
| Monitoramento de mudancas | Assets novos adicionados ao scope | Primeiros a testar = menor competicao |

**O principio fundamental:**

Superficie de ataque descoberta = oportunidade de bug. Subdomínio novo = servidor possivelmente desatualizado ou com controles mais fracos. Parametro novo encontrado em URL historica = input nao testado pelos scanners. Endpoint legado = codigo escrito antes das preocupacoes de seguranca atuais. Cada etapa do pipeline recon amplifica o numero de alvos disponiveis para testes manuais.

**Por que cada camada importa:**

```
Nivel 1: Dominios e Subdominios
└── Nivel 2: IPs, Portas, Servicos
    └── Nivel 3: Paths, Endpoints, Parametros
        └── Nivel 4: JavaScript, APIs ocultas, Secrets
            └── Nivel 5: Funcionalidades, Logica, Dados
```

Hunters que param no Nivel 1-2 competem com todos os outros. Hunters que chegam ao Nivel 4-5 encontram bugs que ferramentas automaticas nao alcancam — porque JavaScript analysis e analise de logica de negocio requerem raciocinio humano sobre o que cada endpoint deveria fazer.

---

## Camadas de Reconhecimento e Fontes de Dados

### Camadas de Reconhecimento

```
Nivel 1: Dominios e Subdominios
└── Nivel 2: IPs, Portas, Servicos
    └── Nivel 3: Paths, Endpoints, Parametros
        └── Nivel 4: JavaScript, APIs ocultas, Secrets
            └── Nivel 5: Funcionalidades, Logica, Dados
```

### Fontes de Dados para Recon

| Fonte | Tipo | Dados obtidos |
|-------|------|---------------|
| **Certificate Transparency** | Passivo | Subdominios via SSL certs |
| **DNS brute force** | Ativo | Subdominios nao publicos |
| **Wayback Machine** | Passivo | URLs historicas |
| **GitHub/GitLab** | Passivo | Codigo, secrets, endpoints |
| **Shodan/Censys** | Passivo | IPs, ports, banners |
| **Google dorking** | Passivo | Assets indexados, erros |
| **ASN lookup** | Passivo | IP ranges do alvo |
| **JavaScript analysis** | Semi-ativo | APIs ocultas, endpoints |

---

## Na Pratica

### 1. Reconhecimento de Dominio e Subdominios

```bash
# Subfinder - subdominios via APIs passivas
subfinder -d target.com -o subdomains_subfinder.txt
subfinder -d target.com -all -o subdomains_all.txt   # Todas as fontes

# Amass - mais completo (mais lento)
amass enum -d target.com -passive -o subdomains_amass.txt
amass enum -d target.com -active -o subdomains_amass_active.txt

# Assetfinder - rapido e simples
assetfinder --subs-only target.com > subdomains_assetfinder.txt

# Certificate Transparency
# Via crt.sh (manual)
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  grep -v "\*" > subdomains_crt.txt

# Via ferramenta
crtfind target.com

# DNS brute force (quando dominio tem wildcard desabilitado)
gobuster dns -d target.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Consolidar todas as fontes
cat subdomains_*.txt | sort -u > all_subdomains.txt
wc -l all_subdomains.txt
```

### 2. Verificar Quais Subdominios Estao Ativos

```bash
# httpx - verificar status, titulo, tecnologia
cat all_subdomains.txt | httpx -title -status-code -content-length -tech-detect \
    -o live_subdomains.txt

# Filtrar apenas ativos
cat all_subdomains.txt | httpx -silent > live_hosts.txt

# Verificar com porta especifica
cat all_subdomains.txt | httpx -ports 80,443,8080,8443 -silent > live_hosts_ports.txt

# Screenshot em massa (ver visualmente)
gowitness file -f live_hosts.txt -P screenshots/
cat live_hosts.txt | gowitness file -f - --delay 3

# Alternativa: aquatone
cat all_subdomains.txt | aquatone -scan-timeout 300
```

### 3. Reconhecimento de IPs e ASN

```bash
# Descobrir ASN do alvo (IP range inteiro)
# Via whois
whois TARGET_IP | grep -i "ASN\|AS Number\|OrgName"

# Via ferramentas
curl "https://api.bgpview.io/search?query_term=target.com" | jq
curl "https://ipinfo.io/TARGET_IP/json"

# CIDR ranges do alvo
amass intel -org "Target Inc" -o asn_results.txt

# Scan de IP range com nmap
nmap -iL ip_range.txt -sV --open -oA nmap_range
```

### 4. Descoberta de URLs e Parametros

```bash
# GAU - Get All URLs (Wayback + gau + etc.)
gau target.com | tee gau_urls.txt
gau --threads 5 --subs target.com > gau_all.txt

# Waybackurls
waybackurls target.com | tee wayback.txt

# Katana - crawler moderno (ProjectDiscovery)
katana -u https://target.com -o katana_urls.txt
katana -u https://target.com -js-crawl -o katana_js.txt   # Inclui JS

# Extrair URLs com parametros
cat gau_urls.txt wayback.txt | grep "?" | sort -u > urls_with_params.txt

# Extrair parametros unicos
cat urls_with_params.txt | grep -oP "(?<=\?)[^#]+" | \
  tr "&" "\n" | \
  cut -d= -f1 | \
  sort -u > unique_params.txt

# Extrair extensoes interessantes
cat gau_urls.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|txt|bak|old|zip|sql|env)" > interesting_ext.txt

# Extrair endpoints de API
cat gau_urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/swagger" > api_endpoints.txt
```

### 5. Analise de JavaScript

```bash
# Extrair URLs de arquivos JS
# hakrawler
echo "https://target.com" | hakrawler -js -d 3 | tee js_crawl.txt

# LinkFinder
python3 linkfinder.py -i https://target.com/app.js -o cli

# Para multiplos JS files
cat live_hosts.txt | while read host; do
    echo "=== $host ==="
    curl -s "$host" | grep -oE 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2
done > js_files.txt

# Secrets em JS
trufflehog filesystem /path/to/js --json | jq

# Buscar endpoints manualmente
cat app.js | grep -oE '"(/[^"]+)"' | sort -u
cat app.js | grep -oE "fetch\(['\"]([^'\"]+)['\"]" | sort -u
cat app.js | grep -oE "axios\.[a-z]+\(['\"]([^'\"]+)['\"]" | sort -u

# gf (go-fuzzer patterns) - extrair URLs com padroes
gau target.com | gf xss    # URLs com parametros provaveis para XSS
gau target.com | gf sqli   # URLs com parametros provaveis para SQLi
gau target.com | gf lfi    # URLs com parametros provaveis para LFI
gau target.com | gf ssrf   # URLs com parametros provaveis para SSRF
gau target.com | gf redirect # URLs com parametros para redirect
```

### 6. Google Dorking

```bash
# Dorks basicos para bug bounty
site:target.com                          # Todos os assets indexados
site:*.target.com                        # Subdominios indexados
site:target.com filetype:pdf             # PDFs (pode conter info)
site:target.com filetype:xlsx            # Excel (dados)
site:target.com inurl:admin              # Paineis admin
site:target.com inurl:login              # Paginas de login
site:target.com inurl:api               # Endpoints API
site:target.com ext:php                  # Arquivos PHP
site:target.com ext:json                 # JSON endpoints
site:target.com "swagger"                # Swagger UI
site:target.com "api documentation"     # Docs de API
site:target.com "Internal Server Error" # Erros expostos

# GitHub dorking
site:github.com "target.com" "password"
site:github.com "target.com" "api_key"
site:github.com "target.com" "secret"
site:github.com "target.com" "token"

# Pastebin
site:pastebin.com "target.com"
```

### 7. Shodan e OSINT

```bash
# Shodan CLI
shodan search "org:Target Inc"
shodan search "hostname:target.com"
shodan search "ssl:target.com"
shodan host TARGET_IP

# Filtros uteis
shodan search "org:Target Inc" --fields ip_str,port,hostnames
shodan search "org:Target Inc port:8080"
shodan search "ssl:target.com" --fields ip_str,port,ssl.cert.subject.cn

# Censys (alternativa ao Shodan)
# Web UI: censys.io

# VirusTotal para subdominios
curl "https://www.virustotal.com/api/v3/domains/target.com/subdomains" \
     -H "x-apikey: SUA_API_KEY"
```

### 8. Fuzzing de Endpoints Descobertos

```bash
# Depois do recon, fazer fuzzing direcionado
# Fuzzing de diretorios nos subdominios descobertos
cat live_hosts.txt | while read host; do
    ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
         -u "$host/FUZZ" \
         -mc 200,301,302,403 \
         -o "ffuf_${host//\//-}.json" \
         -of json \
         -t 50 \
         -s
done

# Nuclei - scan de vulnerabilidades em massa
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_results.txt
nuclei -l live_hosts.txt -t cves/ -severity critical,high -o nuclei_cves.txt

# Param Miner (Burp) - descobrir parametros ocultos
# No Burp: Extensions -> Param Miner -> Right click em request -> Guess params
```

### 9. Monitoramento de Mudancas

```bash
# Monitor subdominios novos com notify
subfinder -d target.com -silent | \
  notify -provider-config ~/.config/notify/provider-config.yaml -bulk

# Monitorar mudancas em JS files
# Comparar snapshots semanais
cat app.js | sha256sum > app_js_hash.txt
# Na proxima semana:
cat app_new.js | sha256sum > app_js_hash_new.txt
diff app_js_hash.txt app_js_hash_new.txt   # Se diferente, analisar o novo

# Monitorar endpoints novos
diff old_gau_urls.txt new_gau_urls.txt | grep "^>" > new_endpoints.txt

# Changelog de programas no HackerOne/Bugcrowd
# Verificar: "Recently added to scope"
# Novo asset = poucos hunters testaram ainda
```

---

## Ferramentas

| Ferramenta | Comando | Instalacao |
|------------|---------|-----------|
| **subfinder** | `subfinder -d domain.com` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | `cat subs.txt \| httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **gau** | `gau domain.com` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **katana** | `katana -u URL` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | `nuclei -l hosts.txt` | `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |
| **amass** | `amass enum -d domain` | `go install github.com/owasp-amass/amass/v4/...@latest` |
| **hakrawler** | `echo URL \| hakrawler` | `go install github.com/hakluke/hakrawler@latest` |
| **gowitness** | `gowitness file -f hosts.txt` | `go install github.com/sensepost/gowitness@latest` |
| **trufflehog** | `trufflehog github --org=target` | `brew install trufflehog` |

---

## Deteccao

### Organizacao de Resultados

```bash
# Estrutura de pasta recomendada
target/
├── recon/
│   ├── subdomains.txt          # Todos os subdominios
│   ├── live_hosts.txt          # Subdominios ativos
│   ├── urls.txt                # Todas as URLs encontradas
│   ├── params.txt              # Parametros unicos
│   ├── js_files.txt            # Arquivos JavaScript
│   └── interesting.txt         # URLs/endpoints de interesse
├── screenshots/                # Screenshots dos hosts
├── nuclei/                     # Resultados do Nuclei
└── findings/                   # Vulnerabilidades encontradas

# Pipeline completo automatizado
TARGET="target.com"
mkdir -p $TARGET/{recon,screenshots,nuclei,findings}

subfinder -d $TARGET -silent | \
  tee $TARGET/recon/subdomains.txt | \
  httpx -silent -title -status-code | \
  tee $TARGET/recon/live_hosts.txt

# Extrair so URLs para httpx (sem titulos)
cat $TARGET/recon/live_hosts.txt | awk '{print $1}' > /tmp/live_urls.txt

nuclei -l /tmp/live_urls.txt \
       -t ~/nuclei-templates/ \
       -severity critical,high,medium \
       -o $TARGET/nuclei/results.txt
```
