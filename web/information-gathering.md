---
title: "Information Gathering"
---

# Information Gathering - Reconhecimento Web

---

## Contexto: Mapeamento de Superfície de Ataque Antes da Exploração

Reconhecimento é a fase mais crítica de qualquer pentest ou bug bounty — e também a mais subestimada. O princípio fundamental é direto: **superfície que você não conhece é vetor que você não testa**. Organizações grandes têm centenas de subdomínios, APIs esquecidas, sistemas legados e ativos abandonados que nunca foram mencionados no escopo formal.

**Por que recon é a fase mais crítica:**

A maioria das vulnerabilidades de alto impacto não está na aplicação principal, que é testada com frequência. Está nos sistemas periféricos: o servidor de staging com versão desatualizada do framework, a API interna esquecida sem autenticação, o subdomínio de uma aquisição antiga rodando software vulnerável, o painel de administração acessível via virtual host não documentado.

APIs esquecidas, subdomínios abandonados e versões antigas de endpoints são vulnerabilidades por negligência — um padrão documentado no OWASP API Security Top 10 como "Gerenciamento impróprio de inventário". O time de desenvolvimento não as removeu do servidor porque não sabia que ainda existiam. O time de segurança não as testou porque não sabia que eram parte do escopo. O atacante as encontra via recon automatizado.

**Como recon se encaixa no processo mais amplo:**

Recon eficaz resulta em descoberta de subdomínios esquecidos com versões desatualizadas de software, identificação de tecnologias específicas e suas versões para correlacionar com CVEs correspondentes, e localização de credenciais e dados sensíveis em fontes públicas. Permite também mapear infraestrutura — IPs, ASNs, ranges de rede — para descobrir ativos adicionais, identificar funcionários e emails como alvos de phishing ou credential stuffing, e encontrar arquivos de configuração, backups e código-fonte expostos acidentalmente em repositórios públicos ou servidores mal configurados.

**A progressão lógica de expansão de superfície:**

Subdomain discovery → Content discovery → JS analysis é uma progressão natural que expande o escopo em cada etapa. O subdomain discovery revela novos alvos — servidores inteiros que não estavam mapeados. Content discovery aplicado a cada servidor revela endpoints e arquivos ocultos que não aparecem na UI. JS analysis em cada endpoint revela APIs internas, parâmetros não documentados e segredos hardcoded no código cliente.

Cada etapa alimenta a próxima. Recon não é uma fase que termina — é contínua durante todo o engajamento.

Recon define a qualidade de todo o restante do engajamento.

---

## Tipos de Reconhecimento: Passivo, Semi-Passivo e Ativo

### Tipos de Reconhecimento

| Tipo | Definição | Contato com Alvo? | Risco de Detecção |
|------|-----------|------------------|-------------------|
| **Passivo** | Usar fontes públicas existentes | Não | Mínimo |
| **Ativo** | Interagir diretamente com sistemas do alvo | Sim | Alto |
| **Semi-passivo** | Interação normal de usuário (parece tráfego legítimo) | Indireto | Baixo |

**Recon Passivo — Fontes:**
- WHOIS, registros DNS públicos
- Google, Bing, DuckDuckGo (dorks)
- Shodan, Censys, FOFA
- Certificate Transparency Logs
- Wayback Machine / archive.org
- GitHub, GitLab (código-fonte público)
- LinkedIn, redes sociais (OSINT pessoal)
- theHarvester, Maltego

**Recon Ativo — Técnicas:**
- DNS brute-force (dnsenum, fierce, gobuster dns)
- Port scanning (nmap)
- Web crawling/spidering
- Directory/file fuzzing (ffuf, gobuster)
- Zone transfer (AXFR)
- Banner grabbing

---

## Na Prática

### WHOIS

WHOIS é um protocolo de consulta que retorna informações sobre registro de domínios e endereços IP.

**Informações disponíveis:**
- Registrante (nome, email, organização, telefone, endereço)
- Registrar (empresa que registrou o domínio)
- Datas (criação, atualização, expiração)
- Name servers autoritativos
- Status do domínio

```bash
# Consulta básica
whois inlanefreight.com

# Output típico:
# Domain Name: INLANEFREIGHT.COM
# Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
# Registrar: GoDaddy.com, LLC
# Updated Date: 2021-09-01T19:19:02Z
# Creation Date: 2019-09-01T19:19:01Z
# Registry Expiry Date: 2023-09-01T19:19:01Z
# Registrant Name: Registration Private
# Registrant Organization: Domains By Proxy, LLC
# Name Server: NS1.INLANEFREIGHT.COM
# Name Server: NS2.INLANEFREIGHT.COM

# WHOIS de IP (ARIN para América, RIPE para Europa, APNIC para Ásia)
whois 8.8.8.8

# WHOIS via web
# whois.domaintools.com
# lookup.icann.org
```

**Informações úteis para pentest:**
- Email do administrador → alvo de phishing, busca em HaveIBeenPwned
- Name servers próprios → servidor DNS gerenciado internamente
- Endereço físico → engenharia social
- Data de criação → infraestrutura antiga = software desatualizado?
- Privacy Guard (Domains By Proxy) → organização tenta esconder identidade

### DNS - Sistema de Nomes de Domínio

DNS traduz nomes de domínio em endereços IP e vice-versa. Para pentest, DNS revela infraestrutura completa.

**Tipos de Registros DNS:**

| Tipo | Descrição | Exemplo |
|------|-----------|---------|
| **A** | Nome → IPv4 | `inlanefreight.com → 134.209.24.248` |
| **AAAA** | Nome → IPv6 | `inlanefreight.com → 2001:db8::1` |
| **CNAME** | Alias de outro nome | `www.site.com → site.com` |
| **MX** | Servidores de email | `site.com → mail.google.com (priority 10)` |
| **NS** | Name servers autoritativos | `site.com → ns1.site.com` |
| **TXT** | Texto livre (SPF, DKIM, verificações) | `v=spf1 include:google.com ~all` |
| **SOA** | Start of Authority (info da zona DNS) | Zona + TTL + admin email |
| **SRV** | Serviços específicos (SIP, XMPP) | `_sip._tcp.site.com → sip.site.com:5060` |
| **PTR** | IP → Nome (DNS reverso) | `248.24.209.134.in-addr.arpa → site.com` |
| **CAA** | Autoridades de CA permitidas | `site.com → letsencrypt.org` |

### dig - DNS Interrogation Tool

`dig` é a ferramenta principal para consultas DNS manuais.

```bash
# Consulta padrão (registro A)
dig inlanefreight.com

# Output:
# ;; ANSWER SECTION:
# inlanefreight.com.	300	IN	A	134.209.24.248

# Consulta de tipo específico
dig inlanefreight.com A
dig inlanefreight.com AAAA
dig inlanefreight.com MX
dig inlanefreight.com NS
dig inlanefreight.com TXT
dig inlanefreight.com SOA
dig inlanefreight.com ANY     # todos os registros (muitos servidores bloqueiam)

# Especificar servidor DNS
dig @8.8.8.8 inlanefreight.com A      # usar Google DNS
dig @1.1.1.1 inlanefreight.com A      # usar Cloudflare DNS
dig @ns1.inlanefreight.com inlanefreight.com A  # consultar NS autoritativo

# Output limpo (só a resposta)
dig inlanefreight.com A +short
# 134.209.24.248

# DNS reverso (PTR)
dig -x 134.209.24.248
dig -x 134.209.24.248 +short

# Múltiplos domínios de uma vez
dig inlanefreight.com htb.com google.com A +short

# Trace completo (ver delegação DNS passo a passo)
dig inlanefreight.com A +trace

# Desativar recursão (consulta ao NS autoritativo apenas)
dig @ns1.inlanefreight.com inlanefreight.com A +norecurse
```

**Análise de saída dig completa:**

```bash
dig inlanefreight.com MX

# ; <<>> DiG 9.18.0 <<>> inlanefreight.com MX
# ;; global options: +cmd
# ;; Got answer:
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
# ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

# ;; QUESTION SECTION:
# ;inlanefreight.com.			IN	MX

# ;; ANSWER SECTION:
# inlanefreight.com.	3600	IN	MX	10 aspmx.l.google.com.
# inlanefreight.com.	3600	IN	MX	20 alt1.aspmx.l.google.com.
# → Email hospedado no Google (Gmail/Workspace)
# → Útil para phishing: saber provedor de email do alvo

# ;; Query time: 45 msec
# ;; SERVER: 127.0.0.53#53(127.0.0.53)  ← DNS local (systemd-resolved)
# ;; WHEN: Sun Jan 01 00:00:00 UTC 2025
# ;; MSG SIZE  rcvd: 88
```

### nslookup

Alternativa ao dig, disponível em Windows e Linux:

```bash
# Uso básico
nslookup inlanefreight.com
nslookup inlanefreight.com 8.8.8.8   # Especificar servidor

# Modo interativo
nslookup
> server 8.8.8.8
> set type=MX
> inlanefreight.com
> set type=NS
> inlanefreight.com
> exit

# No Windows (PowerShell)
Resolve-DnsName inlanefreight.com -Type A
Resolve-DnsName inlanefreight.com -Type MX -Server 8.8.8.8
```

### host - Ferramenta Simples de DNS

```bash
host inlanefreight.com            # Registro A
host -t MX inlanefreight.com      # Registros MX
host -t NS inlanefreight.com      # Name servers
host -t TXT inlanefreight.com     # Registros TXT (SPF, DKIM)
host -a inlanefreight.com         # Todos os tipos

# DNS reverso
host 134.209.24.248               # PTR lookup
```

### Zone Transfer - AXFR

Zone transfer é uma função de replicação de DNS. Se mal configurado, um servidor DNS responde a qualquer consulta AXFR revelando TODOS os registros da zona — mapa completo da infraestrutura.

```bash
# Tentar zone transfer
dig @ns1.inlanefreight.com inlanefreight.com AXFR

# Sucesso (vulnerável):
# inlanefreight.com.	3600	IN	SOA	ns1.inlanefreight.com. ...
# admin.inlanefreight.com.	3600	IN	A	10.10.10.5
# dev.inlanefreight.com.	3600	IN	A	10.10.10.10
# mail.inlanefreight.com.	3600	IN	A	10.10.10.15
# staging.inlanefreight.com.	3600	IN	A	10.10.10.20
# vpn.inlanefreight.com.	3600	IN	A	10.10.10.25
# → Todos os subdomínios expostos!

# Falhou (bem configurado):
# ; Transfer failed.

# Usando host
host -l inlanefreight.com ns1.inlanefreight.com

# Identificar name servers primeiro, depois tentar AXFR em cada um
dig inlanefreight.com NS +short
# ns1.inlanefreight.com.
# ns2.inlanefreight.com.

for ns in $(dig inlanefreight.com NS +short); do
    echo "=== Tentando AXFR em $ns ==="
    dig @$ns inlanefreight.com AXFR
done
```

### Enumeração de Subdomínios

**dnsenum**

```bash
# Enumeração básica
dnsenum inlanefreight.com

# Especificar wordlist
dnsenum --dnsserver 8.8.8.8 \
        --enum \
        -p 0 \
        -s 0 \
        -o resultados.txt \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        inlanefreight.com

# O que faz:
# 1. Consulta NS, MX, registros A
# 2. Tenta zone transfer
# 3. Brute-force com wordlist
# 4. Busca Google (limitado)
```

**fierce**

```bash
# Enumeração com brute-force DNS
fierce --domain inlanefreight.com

# Usar wordlist customizada
fierce --domain inlanefreight.com \
       --subdomain-file /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

# Especificar DNS resolver
fierce --domain inlanefreight.com --dns-servers 8.8.8.8
```

**dnsrecon**

```bash
# Enumeração completa padrão
dnsrecon -d inlanefreight.com

# Brute-force com wordlist
dnsrecon -d inlanefreight.com \
         -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
         -t brt

# Zone transfer
dnsrecon -d inlanefreight.com -t axfr

# Reverse lookup de range IP
dnsrecon -r 134.209.24.0/24

# Output em JSON/CSV
dnsrecon -d inlanefreight.com -j output.json
```

**gobuster dns**

```bash
# DNS brute-force com gobuster
gobuster dns \
    -d inlanefreight.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50

# Output:
# Found: admin.inlanefreight.com
# Found: mail.inlanefreight.com
# Found: vpn.inlanefreight.com
```

**amass**

```bash
# Enumeração passiva (sem brute-force)
amass enum -passive -d inlanefreight.com

# Enumeração ativa (brute-force)
amass enum -active -d inlanefreight.com \
           -brute \
           -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Incluir fontes externas (Certificate Transparency, etc.)
amass enum -d inlanefreight.com -src

# Output em JSON
amass enum -d inlanefreight.com -json output.json
```

**subfinder**

```bash
# Instalação
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Uso básico (fontes passivas)
subfinder -d inlanefreight.com

# Com múltiplos domínios
subfinder -dL domains.txt

# Output verboso com fonte
subfinder -d inlanefreight.com -v

# Output em arquivo
subfinder -d inlanefreight.com -o subdomains.txt
```

### theHarvester - OSINT Abrangente

theHarvester coleta emails, nomes, subdomínios, IPs de múltiplas fontes públicas.

```bash
# Busca básica
theHarvester -d inlanefreight.com -b all

# Fontes específicas
theHarvester -d inlanefreight.com -b google,bing,linkedin,shodan

# Limitar resultados
theHarvester -d inlanefreight.com -b google -l 500

# Salvar resultado XML/HTML
theHarvester -d inlanefreight.com -b all -f resultados

# Fontes disponíveis:
# google, bing, yahoo, duckduckgo, baidu
# linkedin, twitter
# shodan, censys
# hunter, emailformat
# github-code
# virustotal, threatcrowd
# dnsdumpster, crtsh
```

**Output típico:**
```
[*] Emails found: 3
--------------------
john.doe@inlanefreight.com
admin@inlanefreight.com
info@inlanefreight.com

[*] Hosts found: 8
---------------------
admin.inlanefreight.com:134.209.24.10
mail.inlanefreight.com:134.209.24.15
vpn.inlanefreight.com:134.209.24.20
```

### Google Dorks

Operadores de busca avançada do Google para encontrar informações sensíveis:

| Operador | Função | Exemplo |
|----------|--------|---------|
| `site:` | Limitar a domínio | `site:inlanefreight.com` |
| `inurl:` | Texto na URL | `inurl:admin site:inlanefreight.com` |
| `intitle:` | Texto no título | `intitle:"index of"` |
| `intext:` | Texto no body | `intext:"api_key"` |
| `filetype:` | Tipo de arquivo | `filetype:pdf site:inlanefreight.com` |
| `ext:` | Extensão | `ext:sql site:inlanefreight.com` |
| `cache:` | Versão em cache | `cache:inlanefreight.com` |
| `-` | Exclusão | `site:inlanefreight.com -www` |
| `"` | Frase exata | `"password" filetype:log` |
| `*` | Wildcard | `site:*.inlanefreight.com` |

**Dorks úteis em pentest:**

```
# Subdomínios
site:*.inlanefreight.com -www

# Arquivos sensíveis
site:inlanefreight.com filetype:pdf
site:inlanefreight.com filetype:xlsx
site:inlanefreight.com ext:bak
site:inlanefreight.com ext:sql
site:inlanefreight.com ext:env
site:inlanefreight.com ext:config

# Páginas de admin/login
site:inlanefreight.com inurl:admin
site:inlanefreight.com inurl:login
site:inlanefreight.com intitle:"Admin Panel"

# Erros e debug
site:inlanefreight.com "Warning: mysql_"
site:inlanefreight.com "Fatal error"
site:inlanefreight.com intext:"SQL syntax"

# Câmeras, dispositivos
intitle:"webcamXP" inurl:8080
inurl:"/view/index.shtml"

# Credenciais expostas
"password" ext:log site:inlanefreight.com
"api_key" filetype:env
"DB_PASSWORD" filetype:env site:github.com

# Painéis de administração expostos
intitle:"phpMyAdmin" inurl:phpmyadmin
intitle:"Kibana" inurl:5601
intitle:"Grafana" inurl:3000
```

**Google Hacking Database (GHDB):**
```
https://www.exploit-db.com/google-hacking-database
```
Banco de dorks categorizados por tipo (Files Containing Passwords, Web Server Detection, etc.)

### Shodan - Motor de Busca de Dispositivos

Shodan indexa banners de serviços de toda a internet (porta 80, 443, 22, etc.).

```bash
# CLI (requer API key)
pip install shodan
shodan init <API_KEY>

# Busca básica
shodan search "inlanefreight.com"
shodan search "org:Inlanefreight"

# Buscar por produto/versão
shodan search "product:Apache httpd 2.2"
shodan search "apache 2.4.49"  # versão com CVE específica

# Info sobre IP
shodan host 134.209.24.248

# Subdomínios de organização
shodan search "org:Inlanefreight" --fields ip_str,port,hostnames,os

# Contar resultados
shodan count "org:Inlanefreight"

# ASN lookup
shodan search "asn:AS12345"

# Filtros úteis
shodan search "org:Target ssl.cert.subject.cn:*.target.com"
shodan search "org:Target http.title:Admin"
shodan search "org:Target product:Tomcat"
```

**Shodan Web UI — filtros úteis:**

```
org:"Inlanefreight"
hostname:inlanefreight.com
net:134.209.24.0/24
port:8080 org:"Inlanefreight"
ssl:"inlanefreight.com"
http.title:"Dashboard" org:"Inlanefreight"
```

### Certificate Transparency

CAs publicam certificados TLS emitidos em logs públicos. Ferramenta para descobrir subdomínios:

```bash
# crt.sh — busca por domínio
curl -s "https://crt.sh/?q=%.inlanefreight.com&output=json" | \
    jq -r '.[].name_value' | sort -u

# Output:
# admin.inlanefreight.com
# api.inlanefreight.com
# dev.inlanefreight.com
# mail.inlanefreight.com

# Via browser
# https://crt.sh/?q=%.inlanefreight.com

# Filtrar apenas subdomínios únicos
curl -s "https://crt.sh/?q=%.inlanefreight.com&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    grep -v "^inlanefreight.com$" | \
    sort -u > subdomains_ct.txt

# Outros logs CT
# transparencyreport.google.com/https/certificates
# censys.io/certificates
```

### Wayback Machine / Web Archive

Encontrar conteúdo antigo, endpoints removidos e versões antigas de aplicações:

```bash
# Buscar URLs arquivadas
curl -s "http://web.archive.org/cdx/search/cdx?url=*.inlanefreight.com/*&output=text&fl=original&collapse=urlkey" | \
    sort -u | head -100

# Filtrar por tipo de arquivo
curl -s "http://web.archive.org/cdx/search/cdx?url=*.inlanefreight.com/*&output=text&fl=original&collapse=urlkey&filter=mimetype:text/html" | \
    sort -u

# waybackurls (ferramenta go)
go install github.com/tomnomnom/waybackurls@latest
waybackurls inlanefreight.com | tee wayback_urls.txt

# gau - Get All URLs
go install github.com/lc/gau/v2/cmd/gau@latest
gau inlanefreight.com | tee gau_urls.txt
gau --subs inlanefreight.com | tee gau_subs.txt

# Combinar resultados
cat wayback_urls.txt gau_urls.txt | sort -u | grep -v "\.jpg\|\.png\|\.css\|\.js" > urls.txt
```

**O que procurar no Wayback Machine:**
- Endpoints removidos mas possivelmente ainda ativos no servidor
- Páginas de admin antigas
- Arquivos de configuração expostos
- Versões antigas com vulnerabilidades conhecidas
- Emails e informações de contato antigas

### Censys - Alternativa ao Shodan

```bash
# Via CLI (pip install censys)
censys search "inlanefreight.com" --index hosts

# Web UI
# https://search.censys.io
# search.censys.io/search?resource=hosts&q=inlanefreight.com

# Certificados
# search.censys.io/search?resource=certificates&q=parsed.names:inlanefreight.com
```

---

## Exemplos

### Workflow Completo de Recon Passivo

```bash
TARGET="inlanefreight.com"

# 1. WHOIS
whois $TARGET > recon/whois.txt 2>&1

# 2. DNS básico
dig $TARGET A +short > recon/dns_a.txt
dig $TARGET NS +short > recon/dns_ns.txt
dig $TARGET MX +short > recon/dns_mx.txt
dig $TARGET TXT +short > recon/dns_txt.txt

# 3. Zone transfer em todos os NS
for ns in $(dig $TARGET NS +short); do
    dig @$ns $TARGET AXFR >> recon/axfr.txt 2>&1
done

# 4. Certificate Transparency
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > recon/crt_subdomains.txt

# 5. theHarvester
theHarvester -d $TARGET -b google,bing,linkedin -f recon/harvester

# 6. Subdomínios via ferramentas passivas
subfinder -d $TARGET -o recon/subfinder.txt

# 7. Wayback Machine URLs
waybackurls $TARGET > recon/wayback.txt
gau $TARGET > recon/gau.txt

# 8. Combinar todos os subdomínios
cat recon/crt_subdomains.txt recon/subfinder.txt | sort -u > recon/all_subdomains.txt

# 9. Verificar quais estão ativos (DNS resolução)
while read subdomain; do
    ip=$(dig $subdomain A +short | head -1)
    if [ -n "$ip" ]; then
        echo "$subdomain -> $ip"
    fi
done < recon/all_subdomains.txt > recon/active_subdomains.txt
```

### Recon Ativo com dnsenum

```bash
dnsenum --dnsserver 8.8.8.8 \
        --enum \
        -p 0 \
        -s 0 \
        -o recon/dnsenum_output.txt \
        -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        inlanefreight.com

# Verificar output
cat recon/dnsenum_output.txt | grep "IN A" | awk '{print $1, $5}'
```

### Tabela de Ferramentas de Recon DNS

| Ferramenta | Tipo | Melhor Para | Instalação |
|-----------|------|-------------|------------|
| dig | Ativa | Consultas precisas, scripting | Padrão Linux |
| nslookup | Ativa | Consultas simples, Windows | Padrão Win/Linux |
| host | Ativa | Consultas rápidas | Padrão Linux |
| dnsenum | Ativa | Enumeração completa + AXFR | `apt install dnsenum` |
| fierce | Ativa | Brute-force DNS | `pip install fierce` |
| dnsrecon | Ativa | Múltiplas técnicas | `apt install dnsrecon` |
| gobuster dns | Ativa | Brute-force paralelo | `apt install gobuster` |
| amass | Passiva+Ativa | Enumeração abrangente | `apt install amass` |
| subfinder | Passiva | Fontes passivas, velocidade | `go install subfinder` |
| theHarvester | Passiva | OSINT multi-fonte | `apt install theharvester` |
| crt.sh | Passiva | Certificate Transparency | Web/API |
| shodan | Passiva | Banners, portas, versões | Web/CLI |
| waybackurls | Passiva | URLs históricas | `go install` |
| gau | Passiva | URLs de múltiplas fontes | `go install` |

### Análise de Registros TXT para Configuração

```bash
# SPF - quais servidores podem enviar email pelo domínio
dig inlanefreight.com TXT +short | grep "v=spf1"
# v=spf1 include:_spf.google.com ~all
# → Email hospedado no Google

# DKIM - validação de email assinado
dig default._domainkey.inlanefreight.com TXT +short

# DMARC - política para email não autenticado
dig _dmarc.inlanefreight.com TXT +short
# v=DMARC1; p=quarantine; rua=mailto:admin@inlanefreight.com
# → email do DMARC report é endereço real de admin

# Verificações de domínio (Google, Microsoft, etc.)
dig inlanefreight.com TXT +short | grep -E "google|microsoft|facebook|verify"
# google-site-verification=... → site usa Google Workspace
```

---

## Módulos Relacionados

O módulo de Web App Fundamentos (`../01_fundamentos_web/02_web_app_fundamentos.md`) recebe o stack tecnológico identificado durante o recon e o transforma em vetores de ataque concretos — saber que um subdomínio roda PHP 7.4 ou Apache 2.4.41 direciona quais CVEs testar. Content Discovery (`02_content_discovery.md`) é a etapa seguinte natural: após mapear subdomínios ativos, cada um se torna alvo de fuzzing de diretórios e arquivos. Web Proxies (`../01_fundamentos_web/03_web_proxies.md`) entram em cena para interceptar e analisar o tráfego dos alvos descobertos no recon. JavaScript Analysis (`03_javascript_analysis.md`) aprofunda a investigação nos subdomínios encontrados, extraindo endpoints e segredos dos bundles JS. IPs internos expostos via registros DNS são candidatos a SSRF, e subdomínios com CNAME apontando para serviços extintos como GitHub Pages ou Heroku são candidatos a Subdomain Takeover.

**Ferramentas mencionadas:**
- `whois`, `dig`, `nslookup`, `host`
- `dnsenum`, `fierce`, `dnsrecon`
- `gobuster` (mode dns)
- `amass`, `subfinder`
- `theHarvester`
- `waybackurls`, `gau`
- Shodan, Censys, crt.sh
- Google Dorks / GHDB

**Referências HTB:**
- HTB Module: Information Gathering — Web Edition
- HTB Module: Footprinting
