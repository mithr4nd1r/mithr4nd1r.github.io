---
title: "Phishing Infrastructure"
---

# 02. Infraestrutura e Hospedagem para Phishing

## ASN, Reputação de IP e Longevidade da Campanha

A escolha de infraestrutura impacta diretamente o sucesso e a longevidade de uma campanha. IP com histórico de abuse, ASN bloqueado ou provedor sem credibilidade comprometem a operação antes do primeiro clique.

---

## Tipos de Provedores de Hospedagem

### Shared Hosting

Múltiplos sites compartilham mesmo servidor, CPU, memória e bandwidth.

**Vantagens**:
- Custo reduzido.
- Setup simples via painel de controle.
- IP compartilhado com outros domínios — se tiverem boa reputação, pode beneficiar o phishing site.

**Desvantagens**:
- Monitoramento contínuo do provedor — domínio suspeito é derrubado rapidamente.
- Limitações de configuração comparado a VPS.
- Recursos compartilhados (geralmente não é problema para sites de phishing de baixo tráfego).

### Cloud Hosting (VPS/VM)

AWS, Azure, DigitalOcean, Vultr, Linode.

**Vantagens**:
- Maior controle sobre infraestrutura.
- Deploy e destroy rápidos (útil para campanhas curtas).
- Pay-as-you-go — custo-efetivo.

**Desvantagens**:
- Verificação de conta mais rigorosa para prevenir abuse.
- Detecção de abuse pode levar à derrubada de toda a conta.
- Muitos serviços disponíveis = maior complexidade.
- IPs de cloud providers frequentemente scaneados por ferramentas como Shodan.

**Mitigação**: dedicar uma conta separada para cada campanha.

### Serverless Computing

AWS Lambda, Azure Functions, Google Cloud Functions, Cloudflare Workers.

**Vantagens**:
- Sem gerenciamento de servidor.
- Provedor gerencia IP, domínio e SSL.
- Pay-as-you-go.

**Exemplo — Cloudflare Workers**:
- Domínio automaticamente criado: `<worker-name>.workers.dev`
- Domínio confiável + SSL + IP gerenciados pela Cloudflare.
- Muito abusado por atacantes → maior scrutínio.

### Bulletproof Hosting

Provedores que ignoram reclamações de abuse e priorizam privacidade do cliente.

**Vantagens**:
- Política de não-interferência — não derrubam servidores por denúncias.
- Continuidade de serviço.
- Alguns notificam sobre denúncias recebidas.

**Desvantagens severas**:
- IP de baixíssima reputação → bloqueado por soluções de segurança.
- Potencial seizure por autoridades.
- Mais caros que hospedagem regular.

#### DROP Lists (Spamhaus)

Spamhaus mantém listas de IPs/ASNs considerados maliciosos:
- DROP: `https://www.spamhaus.org/drop/drop_v4.json`
- DROPv6: `https://www.spamhaus.org/drop/drop_v6.json`
- ASN-DROP: `https://www.spamhaus.org/drop/asndrop.json`

Bulletproof providers frequentemente aparecem nessas listas. Organizações as usam para bloquear tráfego automaticamente.

### Recomendação

Usar provedores legítimos e conhecidos com processo de takedown definido — aparência mais legítima. Pesquisar provedores com processo de takedown mais lento. Usar múltiplos provedores para diversificar infraestrutura.

---

## Seleção de Domínio

### Estratégias de Nomeação

| Estratégia | Exemplo | Risco |
|------------|---------|-------|
| Keywords de marca | `o365login.com` | Detecção imediata por DNS Hunting |
| Neutro/ambíguo | `healthyapetite.com` | Melhor OPSEC |
| Supplier impersonation | `docusign-portal.com` | Menos comum → menos defesas |
| Typosquatting | `gogle.com` | Detectado por ferramentas automáticas |
| TLD diferente | `company.co` | Organização pode caçar ativamente |
| Subdomínio neutro | `docusign.healthyfoods.com` | Menos suspeito — subdomain keyword legítimo |

**Regra geral**: domínios com keywords como "login", "portal", "password", "microsoftonline" são detectáveis por DNS Hunting antes de qualquer acesso ao conteúdo.

### TLD Selection

TLDs comuns em malware (`.xyz`, `.top`, `.tk`, `.club`) têm reputação mais baixa. Algumas organizações bloqueiam TLDs incomuns por política.

TLDs recomendados: `.com`, `.net`, `.org`, `.io` (amplamente reconhecidos).

**Cuidado com `.zip`**: parece extensão de arquivo, mas organizações podem bloquear todo `.zip` TLD.

### Domain Add-ons a Considerar

- **Privacy/WHOIS** — sempre comprar. WHOIS expõe informações ao defensor.
- **Duração** — 1 ano normalmente suficiente; domínios de phishing raramente sobrevivem 1 ano sem ser queimados.
- **SSL Certificate** — comprar diretamente do provedor para evitar Let's Encrypt.
- **Email** — opcional, pode ser necessário para validação de SSL.

---

## Análise Histórica do Domínio

### Antes de Comprar

1. **DomainTools** — lookup de WHOIS histórico. Domínios sem histórico = menos risco de abuse anterior.
2. **VirusTotal** — verificar detecções e categorização anterior.
3. **URLScan.io** — verificar scans anteriores.
4. **Wayback Machine** — snapshots históricos do conteúdo do domínio.

### Após Comprar — WHOIS Lookup

Campos a monitorar como defensor pode ver:
- **Registrar** — provedor de registro (Name.com, NameCheap, etc.). Padrões de campanha podem ser correlacionados via registrar.
- **Creation date** — domínios novos são mais suspeitos.
- **Name servers** — servidores DNS autoritativos.
- **IP address** — pode expor outros domínios no mesmo servidor via virtual hosting.
- **IP location** — localização inconsistente com alvo levanta suspeita.
- **ASN** — defensores podem bloquear ASN inteiro.

---

## Deploy de Infraestrutura (Exemplo: Vultr)

### Passo a Passo

1. **Selecionar VM** — "Virtual Machine" ou "Compute" nos providers.
2. **Tipo de servidor** — tier básico suficiente para phishing (baixo tráfego).
3. **Localização** — mesmo país/região do alvo.
4. **OS** — Ubuntu (compatibilidade ampla com ferramentas necessárias).
5. **Acessar servidor** — via SSH (`ssh username@ip`).

### Análise do IP

Verificar sequencialmente:
```bash
# 1. AbuseIPDB
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>" -H "Key: <API_KEY>"

# 2. VirusTotal
# Verificar manualmente em virustotal.com

# 3. Blacklist Check
# https://whatismyipaddress.com/blacklist-check
```

Se o IP tem histórico de abuse → trocar por outro. Isso é além do seu controle mas impacta a efetividade da campanha.

---

## Configuração do Servidor Web — Apache

### Instalação

```bash
sudo apt update
sudo apt install apache2
sudo apt install php libapache2-mod-php  # Para PHP backend
```

### Virtual Hosts

Arquivo em `/etc/apache2/sites-available/`:

```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com/public_html
    ErrorLog ${APACHE_LOG_DIR}/example.com_error.log
    CustomLog ${APACHE_LOG_DIR}/example.com_access.log combined
</VirtualHost>
```

Comandos essenciais:
```bash
# Testar sintaxe
sudo apache2ctl configtest

# Habilitar site
sudo a2ensite example.com.conf

# Desabilitar site
sudo a2dissite example.com.conf

# Recarregar Apache
sudo systemctl reload apache2
```

### Múltiplos Virtual Hosts

```apache
<VirtualHost *:80>
    ServerName site1.com
    DocumentRoot /var/www/site1/
</VirtualHost>

<VirtualHost *:80>
    ServerName site2.com
    DocumentRoot /var/www/site2/
</VirtualHost>
```

---

## Configuração DNS

### A Record (IPv4)

```
Type: A
Host: @ (ou subdomain)
Value: <SERVER_IP>
TTL: 300
```

### Subdomínio

```
Type: A
Host: portal
Value: <SERVER_IP>
# Resulta em: portal.domain.com
```

### Aguardar Propagação

Propagação DNS: minutos a horas. Testar com:
```bash
dig domain.com +short
nslookup domain.com
```

---

## Configuração SSL — Let's Encrypt (Certbot)

### Pré-Requisitos

1. Apache rodando na porta 80.
2. DNS A record apontando para o servidor.
3. `ServerName` configurado no Apache.

### Instalação

```bash
sudo apt install certbot python3-certbot-apache
```

### Configurar ServerName

Editar `/etc/apache2/sites-available/000-default.conf`:
```apache
ServerName healthyapetite.com
```

### Solicitar Certificado

```bash
certbot --apache
# Selecionar domínio quando solicitado
```

### Ativar módulo SSL

```bash
sudo a2enmod ssl
sudo systemctl restart apache2
```

### Certificate Transparency (CT Logs)

Quando o certificado é emitido, o domínio aparece **imediatamente** em CT logs públicos (crt.sh, Censys, SSLMate). Scanners de segurança monitoram CT logs em tempo real → scans começam em minutos após emissão.

**Mitigação**: Usar **Wildcard Certificate** (`*.domain.com`) — aparece apenas como wildcard nos CT logs, sem expor subdomínios específicos.

### Certificado Wildcard

```bash
sudo certbot certonly --manual -d "*.domain.com" -d domain.com --preferred-challenges dns
```

Requer criação de registro TXT para validação:
```
Type: TXT
Host: _acme-challenge
Value: <valor_fornecido_pelo_certbot>
```

Aguardar propagação do TXT antes de continuar o certbot.

Configurar Apache para usar o certificado wildcard:
```apache
SSLCertificateFile /etc/letsencrypt/live/healthyapetite.com/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/healthyapetite.com/privkey.pem
```

**Resultado**: wildcard reduz drasticamente o tráfego de scanners — apenas scanners que varriam o IPv4 space ou IP ranges específicos do provedor ainda acessam o site.

---

## Configuração SSL — Certificado Pago (Comodo/Sectigo)

### Tipos de Certificados

| Tipo | Validação | Velocidade | Custo |
|------|-----------|------------|-------|
| DV (Domain Validation) | Ownership do domínio | Rápido | Baixo |
| EV (Extended Validation) | Legal + físico + operacional | Lento | Alto |
| Wildcard | Todos os subdomínios | Variável | Médio |

Para phishing: DV ou Wildcard são suficientes.

### Processo

1. Gerar CSR (Certificate Signing Request):
```bash
openssl req -new -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr
```

Preencher com informações razoáveis (defensores e threat hunters podem ver):
- Country Name, State, Locality
- Organization Name, Organizational Unit
- Common Name (nome do domínio)
- Email Address

2. Submeter CSR ao provedor de SSL.
3. Validar ownership via DNS ou email.
4. Receber arquivos: `domain.crt` e `domain.ca-bundle.crt`.

### Estrutura de Arquivos no Servidor

```
/etc/ssl/
├── private/
│   └── domain.key
├── certs/
│   └── domain.crt
│   └── domain.ca-bundle.crt
```

### Configuração Apache (SSL Pago)

```apache
<VirtualHost *:443>
    ServerName domain.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/domain.crt
    SSLCertificateKeyFile /etc/ssl/private/domain.key
    SSLCertificateChainFile /etc/ssl/certs/domain.ca-bundle.crt
</VirtualHost>
```

---

## Database MySQL (Para Logging de Credenciais)

### Instalação

```bash
sudo apt install php mysql-server php-mysql
sudo mysql_secure_installation
```

### Configuração Inicial

```sql
-- Alterar senha do root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'SENHA_SEGURA';
FLUSH PRIVILEGES;

-- Criar usuário para scripts PHP
CREATE USER 'maldev'@'localhost' IDENTIFIED BY 'SENHA_PHP';
GRANT ALL PRIVILEGES ON *.* TO 'maldev'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Conexão PHP

```php
<?php
$servername = "localhost";
$username = "maldev";
$password = "SENHA_PHP";
$dbname = "phishdb";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
```

---

## Nginx + Flask (Stack Alternativa)

Arquitetura: **Nginx** (reverse proxy) → **Gunicorn** (HTTP server) → **Flask** (Python app).

### Instalação

```bash
# Python e ambiente virtual
sudo apt install python3 python3-pip python3-venv

# Criar usuário dedicado (boa prática)
adduser flaskdemo
su - flaskdemo

# Criar projeto e venv
mkdir flaskapp && cd flaskapp
python3 -m venv flaskenv
source flaskenv/bin/activate

# Flask e Gunicorn
pip install Flask gunicorn
```

### App Flask Básica

```python
# app.py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home_page():
    return 'Hello from Maldev Academy'

if __name__ == '__main__':
    app.run(host='127.0.0.1')
```

### Executar com Gunicorn

```bash
gunicorn --bind 127.0.0.1:5000 app:app
```

### Nginx como Reverse Proxy para Flask

```nginx
server {
    listen 80;
    server_name domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Service para Gunicorn (Persistência)

```ini
# /etc/systemd/system/flaskapp.service
[Unit]
Description=Flask App via Gunicorn
After=network.target

[Service]
User=flaskdemo
WorkingDirectory=/home/flaskdemo/flaskapp
Environment="PATH=/home/flaskdemo/flaskapp/flaskenv/bin"
ExecStart=/home/flaskdemo/flaskapp/flaskenv/bin/gunicorn --bind 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl start flaskapp
sudo systemctl enable flaskapp
```

---

## Uso de Múltiplos Provedores

Diversificar infraestrutura entre provedores diferentes:

**Benefícios**:
- Mitiga risco de shutdown total.
- Dificulta correlação de atividades por defensores.
- Mesmo ASN para múltiplos servidores = facilmente fingerprinted e bloqueado.
- Redundância: se um provedor derruba, outros continuam operacionais.

**Estratégia prática**:
- Usar provedor A para servidor de phishing.
- Usar provedor B para redirector.
- Usar provedor C para segundo redirector.
- Domínios em registrars diferentes.

---

## Leitura Complementar

- [Vultr](https://www.vultr.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Spamhaus DROP Lists](https://www.spamhaus.org/drop/)
- [LOTS Project - Trusted Domains](https://lots-project.com)
- [Certbot Documentation](https://certbot.eff.org/)
- [crt.sh - Certificate Transparency Search](https://crt.sh/)
- ATT&CK T1583 — Acquire Infrastructure
- ATT&CK T1583.001 — Domains
- ATT&CK T1583.004 — Server
