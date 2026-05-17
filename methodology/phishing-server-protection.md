---
title: "Server Protection"
---

# 04. Proteção e Hardening do Servidor de Phishing

## Scanners Varrem IPv4 Continuamente: Defesa em Camadas

Scanners de internet varrem o IPv4 space continuamente. Sem proteção adequada, o servidor é descoberto, analisado e bloqueado em minutos após o lançamento. Defesas em camadas — redirectores, WAF, mod_rewrite/Nginx/Caddy — reduzem exposição e prolongam a vida útil da campanha.

---

## Análise de Segurança do Servidor

### Problemas Comuns a Corrigir

1. **HTTP sem redirecionamento para HTTPS** — browsers alertam usuários; scanners flaggem como suspeito.
2. **Portas abertas desnecessárias** — cada serviço é vetor de fingerprinting e ataque.
3. **Disclosure de versão** — header `Server: Apache/2.4.58` ajuda defensores a fingerprint.
4. **Acesso direto por IP** — scanners que varrem IPv4 acessam o site sem precisar descobrir o hostname.
5. **Vulnerabilidades no aplicativo** — SQLi, XSS expõem o servidor.

---

## Forçar HTTPS (Desabilitar HTTP)

### Via Firewall UFW

```bash
# Bloquear porta 80 completamente
sudo ufw deny http

# Verificar regras
sudo ufw status numbered
```

### Via Configuração Apache (Desabilitar Listen)

```bash
sudo nano /etc/apache2/ports.conf
# Comentar a linha:
# Listen 80

sudo systemctl reload apache2
```

### Via Apache mod_rewrite (Redirecionar HTTP → HTTPS)

```bash
# Habilitar módulo
sudo a2enmod rewrite
sudo systemctl restart apache2
```

No virtual host HTTP:
```apache
<VirtualHost *:80>
    ServerName domain.com
    RewriteEngine on
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>
```

---

## Bloquear Acesso Direto por IP

### Método 1: Host Header Check (Apache mod_rewrite)

```bash
sudo a2enmod rewrite
sudo systemctl restart apache2
```

No virtual host HTTPS:
```apache
<VirtualHost *:443>
    ServerName www.realhealthysnacks.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/domain.crt
    SSLCertificateKeyFile /etc/ssl/private/domain.key
    SSLCertificateChainFile /etc/ssl/certs/domain.ca-bundle.crt

    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # Bloquear acesso direto via IP
    RewriteEngine On
    # Retornar 403 se Host header não for o domínio correto
    RewriteCond %{HTTP_HOST} !^(www\.)?realhealthysnacks\.com$ [NC]
    RewriteCond %{HTTP_HOST} !=""
    RewriteRule ^ - [F]
</VirtualHost>
```

### Método 2: Firewall para Phishing Server (quando usando redirector)

No servidor de phishing backend, permitir HTTP apenas do IP do redirector:

```bash
# Remover regras HTTP/HTTPS existentes
sudo ufw status numbered
sudo ufw delete <número-da-regra-http>
sudo ufw delete <número-da-regra-https>

# Permitir apenas do redirector
sudo ufw allow from <IP_DO_REDIRECTOR> to any port 80
sudo ufw allow from <IP_DO_REDIRECTOR> to any port 443

sudo ufw reload
```

---

## Remover Disclosure de Versão

### Apache — Remover/Ofuscar Header Server

Editar `/etc/apache2/apache2.conf` (ou `/etc/apache2/apache2.conf`):
```apache
# Adicionar ao final:
ServerTokens Prod
ServerSignature Off
```

Restartar Apache:
```bash
sudo systemctl restart apache2
```

Resultado: `Server: Apache` em vez de `Server: Apache/2.4.58 (Ubuntu)`.

### Spoof do Header Server (ModSecurity)

Instalar ModSecurity:
```bash
sudo apt install libapache2-mod-security2
sudo systemctl restart apache2
```

Adicionar ao `/etc/apache2/apache2.conf`:
```apache
<IfModule security2_module>
    SecRuleEngine on
    ServerTokens Min
    SecServerSignature "LiteSpeed"
</IfModule>
```

**Resultado**: scanners Nmap veem "LiteSpeed" em vez de Apache.

**Cuidado**: não usar header Server único/incomum — torna o servidor identificável via fingerprint do header único.

### SSH — Reduzir Banner

Em `/etc/ssh/sshd_config`:
```
DebianBanner no
```

Reiniciar SSH:
```bash
sudo systemctl restart sshd
```

**Antes**: `OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)`
**Depois**: versão básica sem info do OS.

---

## Cloudflare WAF (Web Application Firewall)

### Configuração Inicial

1. Criar conta em [dash.cloudflare.com](https://dash.cloudflare.com).
2. Adicionar domínio → Cloudflare importa DNS records automaticamente.
3. Atualizar `NS` records no registrar para os nameservers da Cloudflare.
4. Aguardar verificação dos nameservers.

### SSL via Cloudflare

Navigation: SSL/TLS > Overview > Configure > **Full (Strict)**.

Cloudflare emite certificado automaticamente para domínio primário e subdomínios (1 nível). Subdomínios com 2+ níveis requerem plano pago.

### Configurações de Segurança

**Security > Bots**:
- Habilitar **Bot Fight Mode**.
- Habilitar **Block AI Bots**.

**Security > Settings**:
- Security Level: **High**.
- Challenge Passage: **5 minutes**.
- Opcional: **Under Attack Mode** (maior scrutínio, pode impactar UX).

### Custom WAF Rules

Navigation: Security > WAF > Custom rules > Create rule.

**Exemplo de regra**: bloquear bots conhecidos + acessos de fora dos EUA + ASN específico:

```
Ação: Block (HTTP 403)
Condições:
  - (Bot Score) é menor que 30  [bot conhecido]
  OR
  - (Country) não é "United States"
  OR
  - (ASN) é igual a "AS1335"
```

**Casos de uso de regras**:
- Bloquear por país (whitelist apenas países-alvo).
- Bloquear ASNs de provedores de scanner conhecidos.
- Bloquear user agents suspeitos.
- Rate limiting em endpoints de login.
- Bloquear CIDRs de scanners de segurança.

---

## Apache mod_rewrite — Redirector

### O Que É um Redirector

Servidor intermediário entre cliente e servidor de phishing backend. Funções:
- Ocultar IP/domínio do servidor de phishing.
- Filtrar scanners e defensores antes de servir conteúdo malicioso.
- Rotear tráfego baseado em variáveis do cliente.
- Se queimado, substituir sem reconstruir infraestrutura principal.

```
[Target] → [Redirector (Apache mod_rewrite)] → [Backend Phishing Server]
                        ↓
              [Scanner/Defender] → [google.com (benign redirect)]
```

### Habilitando mod_rewrite + proxy

```bash
sudo a2enmod rewrite proxy proxy_http
sudo systemctl restart apache2
```

### Configuração de Redirector com mod_rewrite

`.htaccess` ou virtual host:

```apache
RewriteEngine On

# Log de acesso (opcional)
# CustomLog /var/log/apache2/redirector.log combined

# Bloquear por User-Agent
RewriteCond %{HTTP_USER_AGENT} (curl|python|wget|nmap|nikto|masscan) [NC]
RewriteRule ^ https://www.google.com [L,R=302]

# Bloquear por país (via GeoIP2 module)
# RewriteCond %{ENV:GEOIP_COUNTRY_CODE} !^(US|GB|DE)$
# RewriteRule ^ https://www.google.com [L,R=302]

# Encaminhar tráfego legítimo para backend phishing server
RewriteRule ^ http://<PHISHING_SERVER_IP>%{REQUEST_URI} [P,L]

# Headers para passar info do cliente original ao backend
RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
```

### Sintaxe de Regras mod_rewrite

```apache
# Estrutura básica:
RewriteEngine On                       # Habilitar engine

RewriteCond %{VARIÁVEL} PADRÃO [FLAGS] # Condição
RewriteRule PADRÃO SUBSTITUIÇÃO [FLAGS] # Regra

# Variáveis comuns:
%{HTTP_USER_AGENT}  # User-Agent header
%{REMOTE_ADDR}      # IP do cliente
%{HTTP_HOST}        # Host header
%{REQUEST_URI}      # Path da URL
%{HTTP_REFERER}     # Referer header
%{QUERY_STRING}     # Query string

# Flags comuns:
[L]    # Last rule — parar de processar regras
[R=301] # Redirect permanente
[R=302] # Redirect temporário
[P]    # Proxy para URL de substituição
[NC]   # Case-insensitive
[F]    # Forbidden (403)
```

---

## Nginx como Redirector/Reverse Proxy

### Por Que Nginx

Nginx é nativamente projetado como reverse proxy — mais simples que configurar Apache para isso. Vantagens sobre Apache para este uso:
- Configuração mais enxuta.
- Melhor performance para proxying.
- `proxy_pass` nativo sem módulos extras.

### Configuração Nginx como Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name domain.com;
    
    ssl_certificate /etc/letsencrypt/live/domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain.com/privkey.pem;
    
    # Logs
    access_log /var/log/nginx/phishing.log;
    
    # Filtrar User Agents suspeitos
    if ($http_user_agent ~* (curl|python|wget|nmap|masscan|nikto)) {
        return 302 https://www.google.com;
    }
    
    # Encaminhar para phishing server backend
    location / {
        proxy_pass http://<PHISHING_SERVER_IP>;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Conteúdo benigno no path raiz (opcional)
    # location = / {
    #     proxy_pass https://example.com;
    # }
}
```

### Demo: Nginx Reverse Proxying Site Externo

Útil para exibir conteúdo benigno no path raiz enquanto phishing em path específico:

```nginx
server {
    listen 443 ssl;
    server_name domain.com;
    
    # Path raiz → conteúdo benigno de site externo
    location / {
        proxy_pass https://example.com;
        proxy_set_header Host example.com;
    }
    
    # Path específico → phishing server
    location /auth/ {
        proxy_pass http://<PHISHING_SERVER_IP>;
        proxy_set_header Host $host;
    }
}
```

---

## Caddy — Web Server Seguro por Padrão

### Instalação (Ubuntu/Debian)

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
    sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
    sudo tee /etc/apt/sources.list.d/caddy-stable.list

sudo apt update && sudo apt install caddy
```

### Caddyfile Básico

`/etc/caddy/Caddyfile`:
```caddyfile
domain.com {
    root * /var/www/html
    file_server
    encode gzip
}
```

Caddy:
- Redireciona HTTP → HTTPS automaticamente.
- Obtém certificado Let's Encrypt automaticamente.
- Sem directory listing por padrão (seguro por padrão).

### Caddy como Redirector para Phishing Server

```caddyfile
domain.com {
    # Logs JSON
    log {
        output file /var/caddy/logs/access.json
        format json
    }
    
    # Headers customizados
    header {
        import filters/headers.caddy
    }
    
    # Matcher: IPs bloqueados
    @blocked_ips {
        import filters/ips.caddy
    }
    
    # Matcher: User agents bloqueados
    @blocked_user_agents {
        import filters/ua.caddy
    }
    
    # Bloquear IPs maliciosos
    handle @blocked_ips {
        respond "Forbidden" 403 {
            close
        }
    }
    
    # Bloquear user agents suspeitos
    handle @blocked_user_agents {
        respond "Forbidden" 403 {
            close
        }
    }
    
    # Encaminhar /auth/* para phishing server
    handle /auth/* {
        reverse_proxy http://PHISHING_SERVER_IP {
            header_up Host {upstream_hostport}
        }
    }
    
    # Default: página não encontrada
    handle {
        respond "Page not found" 404
    }
}
```

**filters/headers.caddy** (exemplo):
```caddyfile
-Server
-X-Powered-By
X-Frame-Options "SAMEORIGIN"
X-Content-Type-Options "nosniff"
```

**filters/ua.caddy** (User Agents bloqueados):
```caddyfile
header User-Agent curl*
header User-Agent python*
header User-Agent wget*
header User-Agent *nmap*
header User-Agent *masscan*
header User-Agent *nikto*
```

**filters/ips.caddy** (IPs de scanners conhecidos — importar listas):
```caddyfile
remote_ip 1.2.3.4 5.6.7.8 9.10.11.12
```

---

## Referrer-Policy — Ocultar Domínio de Phishing

Quando redirecionamos usuário para site legítimo após harvest, o `Referer` header expõe nosso domínio ao servidor de destino. Alguns serviços (ex: Bolster.ai) analisam Referer URLs para detectar phishing.

### Configurar Referrer-Policy: no-referrer

**Nginx**:
```nginx
server {
    listen 443 ssl;
    server_name example.com;
    
    add_header Referrer-Policy "no-referrer";
    
    location / {
        root /var/www/html;
    }
}
```

**Apache**:
```apache
<VirtualHost *:443>
    ServerName example.com
    
    <IfModule mod_headers.c>
        Header set Referrer-Policy "no-referrer"
    </IfModule>
</VirtualHost>
```

Habilitar módulo headers Apache:
```bash
sudo a2enmod headers
sudo systemctl restart apache2
```

**Caddy**:
```caddyfile
domain.com {
    header Referrer-Policy "no-referrer"
}
```

---

## Comparação de Soluções de Redirector

| Feature | Apache mod_rewrite | Nginx | Caddy |
|---------|-------------------|-------|-------|
| Curva de aprendizado | Média | Média | Baixa |
| Configuração padrão segura | Não | Não | Sim |
| SSL automático | Não (Certbot) | Não (Certbot) | Sim |
| Reverse proxy | Via módulos | Nativo | Nativo |
| Filtros customizados | Avançados | Avançados | Moderados |
| Performance | Boa | Excelente | Boa |
| Use case recomendado | Compatibilidade | Alta performance | Simplicidade/OPSEC |

---

## Leitura Complementar

- [Apache mod_rewrite Documentation](https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html)
- [Nginx Reverse Proxy Docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [Caddy Documentation](https://caddyserver.com/docs/)
- [Cloudflare WAF](https://developers.cloudflare.com/waf/)
- ATT&CK T1583 — Acquire Infrastructure
- ATT&CK T1090 — Proxy
- ATT&CK T1090.004 — Domain Fronting
