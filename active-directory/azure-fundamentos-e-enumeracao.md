---
layout: cyber
section: active-directory
title: "Azure/Entra ID — Fundamentos para Atacantes e Enumeração"
---

# Azure/Entra ID — Fundamentos para Atacantes e Enumeração

# O que é?

Microsoft Entra ID — renomeado em 2023, anteriormente conhecido como Azure Active Directory (Azure AD) — é o **Identity Provider (IdP) cloud da Microsoft**, responsável por autenticação e autorização em todo o ecossistema Microsoft 365 e Azure. É fundamentalmente diferente do Active Directory on-premises que profissionais de segurança conhecem do ambiente corporativo tradicional.

O AD on-premises opera sobre Kerberos e LDAP — protocolos de rede dos anos 1980-1990 projetados para ambientes de rede local. O Entra ID opera sobre protocolos modernos de identidade web:

```
Protocolo        Uso Principal                              Padrão
-----------      ----------------------------------------   --------
OAuth 2.0        Autorização de acesso a recursos           RFC 6749
OpenID Connect   Autenticação de usuários (sobre OAuth 2.0) OpenID Foundation
SAML 2.0         SSO para aplicações enterprise legacy      OASIS
WS-Federation    Federação com ADFS e sistemas legados      OASIS
```

Os componentes centrais do Entra ID:

```
Tenant
  --> Instância isolada do Entra ID para uma organização
  --> Identificado por Tenant ID (GUID) e domínio *.onmicrosoft.com
  --> Toda empresa que usa Microsoft 365 tem pelo menos um Tenant

Users
  --> Contas de usuário interno (Members) ou externo (Guests via B2B)
  --> Atributos: userPrincipalName, objectId, mail, assignedRoles

Groups
  --> Security Groups (para RBAC e permissões)
  --> Microsoft 365 Groups (Teams + SharePoint + Exchange)
  --> Membership: assigned (manual) ou dynamic (baseado em atributos)

Service Principals
  --> Identidade para aplicações (não para humanos)
  --> 3 tipos: Application, Managed Identity, Legacy

Managed Identities
  --> Identidade para recursos Azure (VM, Function, AKS node)
  --> System-Assigned: vinculada ao ciclo de vida do recurso
  --> User-Assigned: independente, reutilizável em múltiplos recursos
  --> Token disponível via IMDS endpoint sem credenciais

App Registrations
  --> Blueprint da aplicação (definido no tenant do desenvolvedor)
  --> Define permissões, redirect URIs, segredos

Enterprise Applications
  --> Service Principal no tenant do cliente
  --> Instância de uma App Registration
  --> Onde se configuram permissões concedidas (consent)
```

**Azure RBAC** controla acesso a recursos Azure (ARM — Azure Resource Manager): VMs, Storage, Key Vaults, etc. Roles: Owner, Contributor, Reader, e roles específicas de serviço. É diferente do Entra ID.

**Azure AD Roles** (agora Entra ID Roles) controlam permissões dentro do diretório: Global Administrator, User Administrator, Application Administrator, Privileged Role Administrator, etc. Aplicam-se ao plano de controle do Entra ID, não aos recursos Azure.

# Onde é implementado?

O Entra ID está presente em toda organização que usa qualquer serviço Microsoft moderno. Na prática, isso significa praticamente toda empresa corporativa no mundo ocidental.

**Microsoft 365** é o caso de uso mais massivo. Teams, SharePoint, Exchange Online, OneDrive, Planner, Viva — todos autenticam via Entra ID. Um usuário que faz login no Outlook Web App passa pelo Entra ID, recebe um access token para `https://outlook.office365.com/`, e o Exchange Online valida esse token a cada requisição. Estima-se que mais de 300 milhões de usuários acessam M365 mensalmente.

**Azure Resources** são controlados via Azure RBAC sobre o Azure Resource Manager (`management.azure.com`). Toda operação em VMs, Storage Accounts, Key Vaults, App Services, AKS clusters passa pelo ARM, que valida tokens do Entra ID. A separação entre identidade (Entra ID) e recursos (ARM) cria oportunidades para configurações incorretas onde uma identidade tem mais permissão em um plano que no outro.

**Hybrid environments** são extremamente comuns em empresas que iniciaram sua jornada cloud a partir de infraestrutura on-premises existente. O **Azure AD Connect** (agora Microsoft Entra Connect) sincroniza objetos do AD on-premises com o Entra ID:

```
AD On-Premises (Kerberos/LDAP)          Entra ID (OAuth/OIDC)
+-----------------------------+         +---------------------------+
|  Domain Controller          |         |  Tenant                   |
|  CORP.LOCAL                 |         |  corp.onmicrosoft.com     |
|                             |         |                           |
|  Users: john.doe            | ------> |  john.doe@corp.com        |
|  Groups: Domain Admins      | ------> |  Domain Admins (sincron.) |
|  Computers: WORKSTATION01   | ------> |  (dispositivos via HAADJ) |
+-----------------------------+         +---------------------------+
           ^                                        ^
           |              Azure AD Connect          |
           |         (sincronização periódica)      |
           +----------------------------------------+

Modos de sincronização:
  Password Hash Sync (PHS): hashes de senha sincronizados para Entra ID
  Pass-Through Auth (PTA): autenticação on-prem transparente para cloud
  Federation (ADFS): ADFS on-prem emite tokens aceitos pelo Entra ID
```

**SSO para SaaS** é implementado via SAML 2.0 ou OIDC. Salesforce, ServiceNow, Workday, AWS (via SAML federation), GitHub Enterprise, Slack — todos podem ser configurados como Enterprise Applications no Entra ID, usando-o como IdP único. Um comprometimento de Entra ID com permissões de Global Administrator permite criar credenciais para essas aplicações externas.

**Conditional Access Policies** são o mecanismo de controle de acesso adaptativo. Cada tentativa de autenticação é avaliada contra políticas que consideram: usuário/grupo solicitante, aplicação alvo, plataforma do dispositivo, localização geográfica (IP), risco de sign-in (calculado por Machine Learning do Entra ID Protection), status de compliance do dispositivo (via Intune). O resultado é Grant (com ou sem MFA), Block, ou Session Controls.

# Como funciona de forma adequada?

## Componentes do Entra ID e suas relações

```
Tenant (contoso.onmicrosoft.com)
|
+-- Entra ID
|   |
|   +-- Users (john.doe@contoso.com, jane.smith@contoso.com)
|   |
|   +-- Groups (IT-Admins, Finance-Team, All-Employees)
|   |
|   +-- App Registrations (MyApp, ReportingTool)
|   |
|   +-- Enterprise Applications / Service Principals
|   |   +-- Microsoft Graph (service principal interno da Microsoft)
|   |   +-- Salesforce (SP criado ao federar com Salesforce)
|   |   +-- MyApp (SP criado pela App Registration)
|   |
|   +-- Managed Identities
|       +-- SystemAssigned-VM-Prod-01
|       +-- UserAssigned-FunctionApp-Identity
|
+-- Azure Subscriptions (plano de recursos)
|   |
|   +-- Subscription: Production (ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
|   |   +-- Resource Group: rg-network
|   |   |   +-- Virtual Network, NSG
|   |   +-- Resource Group: rg-compute
|   |   |   +-- VM: prod-app-01 (com Managed Identity)
|   |   +-- Resource Group: rg-data
|   |       +-- Storage Account: prodstorage
|   |       +-- Key Vault: prod-secrets
|   |
|   +-- Subscription: Development
|       +-- Resource Group: rg-dev
|
+-- M365 Services (authenticam via Entra ID)
|   +-- Exchange Online (email)
|   +-- SharePoint Online (documentos)
|   +-- Teams (comunicação)
|   +-- OneDrive (armazenamento pessoal)
|
+-- External SaaS (federam via SAML/OIDC)
    +-- Salesforce
    +-- ServiceNow
    +-- AWS (via SAML federation)
```

## Como OAuth 2.0 / OpenID Connect funciona no Entra ID

```
Fluxo Authorization Code (para usuários interativos):

Usuário             Browser/App         Entra ID              Recurso
  |                     |                   |                    |
  |--[1] Acessar app--> |                   |                    |
  |                     |--[2] GET /authorize?                   |
  |                     |   client_id=...   |                    |
  |                     |   scope=openid+Mail.Read               |
  |                     |   redirect_uri=.. |                    |
  |                     |   state=...       |                    |
  |<---[3] Tela login---|                   |                    |
  |--[4] Credenciais--> |                   |                    |
  |                     |--[5] POST credenciais--->              |
  |                     |         (+ MFA se requerido)          |
  |                     |<--[6] 302 redirect?code=AUTHCODE----  |
  |                     |--[7] POST /token                       |
  |                     |   code=AUTHCODE                       |
  |                     |   client_secret=..                    |
  |                     |<--[8] {                               |
  |                     |   "access_token": "eyJ0...",          |
  |                     |   "id_token": "eyJ0...",              |
  |                     |   "refresh_token": "0.ARo...",        |
  |                     |   "expires_in": 3600                  |
  |                     | }                                      |
  |                     |--[9] GET /api/data                     |
  |                     |   Authorization: Bearer eyJ0...--->   |
  |                     |                               valida  |
  |                     |                               JWT     |
  |<---[10] Dados-------|<---------------------------------      |
```

## Como Managed Identity funciona (sem credenciais)

```
VM no Azure com System-Assigned Managed Identity
+--------------------------------------------------+
|  VM: prod-app-01                                 |
|                                                  |
|  Aplicação rodando na VM:                        |
|                                                  |
|  [1] GET http://169.254.169.254/metadata/        |
|         identity/oauth2/token                   |
|         ?api-version=2018-02-01                 |
|         &resource=https://vault.azure.net/      |
|      Header: Metadata: true                      |
|                                                  |
|  IMDS (Instance Metadata Service)               |
|  169.254.169.254:80 (link-local, não roteável)  |
|                                                  |
|  [2] Azure fabric valida identidade da VM       |
|      (sem credencial do usuário envolvida)       |
|                                                  |
|  [3] Resposta: {                                 |
|    "access_token": "eyJ0...",                    |
|    "expires_in": "86399",                        |
|    "token_type": "Bearer",                       |
|    "resource": "https://vault.azure.net/"        |
|  }                                               |
|                                                  |
|  [4] Aplicação usa token para acessar Key Vault  |
|      GET https://prod-secrets.vault.azure.net/   |
|          secrets/DbPassword                      |
|      Authorization: Bearer eyJ0...              |
+--------------------------------------------------+

O resource pode ser trocado para:
  https://management.azure.com/   --> Azure Resource Manager
  https://graph.microsoft.com/    --> Microsoft Graph
  https://storage.azure.com/      --> Azure Storage
  https://vault.azure.net/        --> Azure Key Vault
```

## Como Conditional Access avalia cada autenticação

```
Solicitação de autenticação
    |
    v
+------------------------------------------+
|  Coleta de sinais (Signal Collection)    |
|                                          |
|  Quem:  usuario@contoso.com             |
|  App:   Microsoft Teams                  |
|  Dispos: Windows 11, joined domain      |
|  Local: IP 203.0.113.42 (Brasil)        |
|  Risco:  Low (calculado pelo ML)        |
+------------------------------------------+
    |
    v
+------------------------------------------+
|  Avaliação de Políticas (Policy Engine)  |
|                                          |
|  Política 1: "Require MFA for Admins"   |
|    Condição: usuario é Global Admin?     |
|    --> NÃO (usuário é membro normal)     |
|    Resultado: não aplicável              |
|                                          |
|  Política 2: "Block Legacy Auth"         |
|    Condição: protocolo é Basic Auth?     |
|    --> NÃO (é OAuth 2.0)                 |
|    Resultado: não aplicável              |
|                                          |
|  Política 3: "MFA for all users"        |
|    Condição: qualquer usuário            |
|    --> SIM                               |
|    Controle: Require MFA                 |
|    Resultado: APLICÁVEL                  |
+------------------------------------------+
    |
    v
+------------------------------------------+
|  Decisão Final                           |
|                                          |
|  GRANT + MFA Required                    |
|  --> Entra ID emite challenge de MFA     |
|  --> Usuário completa MFA               |
|  --> Tokens emitidos                     |
|                                          |
|  Alternativas:                           |
|  BLOCK --> acesso negado                 |
|  GRANT (sem condições)                   |
|  SESSION CONTROLS (ex: no download)      |
+------------------------------------------+
```

## Como Azure AD Connect sincroniza identidades

```
Ambiente Híbrido:

On-Premises                              Cloud
+------------------+                    +------------------+
| Active Directory |                    | Entra ID         |
| CORP.LOCAL       |                    | corp.com         |
|                  |                    |                  |
| john.doe         |  -- sync cycle --> | john.doe@corp.com|
| jane.smith       |  (a cada 30 min)  | jane.smith@corp.com|
|                  |                    |                  |
| samAccountName   |  --> maps to -->   | userPrincipalName|
| objectGUID       |  --> maps to -->   | onPremisesObjectId|
| pwdLastSet       |  --> maps to -->   | (se PHS ativo)   |
+------------------+                    +------------------+
         ^
         |
+------------------+
| Azure AD Connect |  Servidor Windows on-premises
| (agora: Entra    |  Roda como serviço
|  Connect)        |
|                  |  Modos:
|  Módulos:        |  PHS: sincroniza hash de senha
|  - Sync Engine   |  PTA: agent on-prem valida senha
|  - AD Connector  |  Federation: ADFS emite tokens
|  - AAD Connector |
+------------------+

Implicação ofensiva: se hash de senha é sincronizado (PHS),
comprometer Entra ID = acesso a hash = comprometer on-prem.
Golden SAML attack: comprometer ADFS = forjar tokens aceitos pelo Azure.
```

---

## Tenant, Subscriptions e Resource Groups: A Hierarquia do Azure

```
Tenant (Entra ID)
├── Subscription 1
│   ├── Resource Group A
│   │   ├── VM (Máquina Virtual)
│   │   ├── Storage Account
│   │   └── Key Vault
│   └── Resource Group B
│       └── App Service
└── Subscription 2
    └── Resource Group C
        └── AKS Cluster
```

- **Tenant**: Instância isolada do Entra ID. Identificado pelo Tenant ID (GUID) e pelo domínio (ex: `contoso.onmicrosoft.com`). Toda organização tem pelo menos um tenant.
- **Subscription**: Unidade de cobrança e limite de recursos ARM (Azure Resource Manager). Um tenant pode ter múltiplas subscriptions.
- **Resource Group**: Container lógico para recursos ARM. RBAC pode ser aplicado no nível de RG.
- **Recursos ARM**: VMs, Storage Accounts, Key Vaults, App Services, etc. Gerenciados via ARM API (`management.azure.com`).

---

## Entra ID — Identidades e Objetos

### Usuários
- Contas internas (membros do tenant) ou externas (guests via B2B).
- Atributos importantes para ataque: `userPrincipalName`, `objectId`, `mail`, `assignedRoles`, `memberOf`.

### Grupos
- Security Groups: usados para RBAC no Azure e permissões no Entra ID.
- Microsoft 365 Groups: combinam equipe + SharePoint + Teams.
- Grupos podem ter membros dinâmicos (baseado em atributos).

### Service Principals
Existem 3 tipos:

| Tipo | Descrição | Relevância Ofensiva |
|------|-----------|---------------------|
| **Application** | Representa uma App Registration no tenant | Pode ter permissões elevadas (Mail.Read.All, etc.) sem MFA |
| **Managed Identity** | Identidade para recursos Azure (VM, Function App, etc.) | Token obtido via IMDS sem credenciais |
| **Legacy** | Aplicações antigas (ADFS, etc.) | Menos comum, mas pode ter permissões herdadas |

### App Registrations vs Enterprise Applications
- **App Registration**: O "blueprint" da aplicação (definido no tenant do desenvolvedor).
- **Enterprise Application / Service Principal**: A instância da app no tenant do cliente.
- Uma App Registration cria automaticamente um Service Principal no tenant onde é registrada.

---

## Managed Identities — Pivô Silencioso

Managed Identities são identidades atribuídas a recursos Azure que permitem autenticação sem gerenciar credenciais explícitas.

**System-Assigned**: Vinculada ao ciclo de vida do recurso. Se o recurso é deletado, a identidade some.

**User-Assigned**: Identidade standalone que pode ser atribuída a múltiplos recursos. Persiste independentemente.

```
# Para atacantes: se você comprometeu uma VM com managed identity,
# o token está disponível via IMDS endpoint sem autenticação adicional:

curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool
```

O token retornado é um access token JWT válido para o recurso especificado. O `resource` pode ser trocado para:
- `https://graph.microsoft.com/` — Microsoft Graph
- `https://vault.azure.net/` — Key Vault
- `https://storage.azure.com/` — Storage

---

## OAuth 2.0 — Os Três Tokens

Esta é a base de todo ataque a identidade Azure. Cada token tem características distintas:

### ID Token
- **Propósito**: Informações sobre o usuário autenticado (quem você é).
- **Conteúdo**: Claims como `name`, `email`, `oid` (object ID), `tid` (tenant ID).
- **Uso**: Autenticação em aplicações (OpenID Connect). Não usado para autorizar acesso a APIs.
- **Validade**: Curta (tipicamente 1 hora).
- **Formato**: JWT decodificável em `jwt.io` ou `base64 -d`.

### Access Token
- **Propósito**: Autorizar acesso a um recurso específico.
- **Características**:
  - Válido por 1-2 horas (padrão).
  - Bound a 1 usuário + 1 recurso (audience = `aud` claim).
  - **Não revogável** durante a validade (a menos que CAE — Continuous Access Evaluation — esteja ativo).
  - Opaco para o recurso: o recurso valida a assinatura, não consulta o Entra ID.
- **Uso ofensivo**: Roubado uma vez, pode ser replayed durante toda a validade, mesmo após reset de senha (sem CAE).

### Refresh Token
- **Propósito**: Obter novos access tokens sem re-autenticação do usuário.
- **Características**:
  - Válido por 90 dias, renovável continuamente.
  - Revogável: reset de senha, revogação explícita, expiração de sessão.
  - **Family Refresh Token (FRT)**: Versão especial não vinculada a client_id — permite obter tokens para qualquer app da FOCI family.
- **Uso ofensivo**: Com um FRT, o atacante tem acesso persistente por 90 dias (renovável) sem MFA.

```
Diagrama de Tokens:

[Usuário autentica] --> [Entra ID emite:]
                         ├── ID Token      (1h, quem você é)
                         ├── Access Token  (1-2h, o que pode acessar)
                         └── Refresh Token (90 dias, renovável)

Attacker steals RT --> polls /token --> novo Access Token (sem MFA)
```

---

## Microsoft Graph API — Superfície de Ataque Principal

O Microsoft Graph é o endpoint único para acessar dados do Microsoft 365 e Entra ID.

- **Endpoint**: `https://graph.microsoft.com/v1.0/` e `https://graph.microsoft.com/beta/`
- **Autenticação**: Bearer token (access token com audience `https://graph.microsoft.com/`)

Operações críticas possíveis via Graph com as permissões corretas:
- Ler emails e anexos de qualquer usuário (Mail.Read.All)
- Listar todos os usuários, grupos e aplicações
- Adicionar membros a grupos (GroupMember.ReadWrite.All)
- Criar/modificar aplicações e seus secrets
- Ler arquivos do SharePoint/OneDrive (Files.ReadWrite.All)
- Enumerar Conditional Access Policies (Policy.Read.All)
- Criar Temporary Access Passes (UserAuthenticationMethod.ReadWrite.All)

---

## Módulo Microsoft.Graph (PowerShell)

### Instalação
```powershell
# Instalar o módulo principal
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Instalar submodules específicos (mais leve)
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
```

### Variantes de Conexão

```powershell
# 1. Interativo com scopes (abre browser)
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All"

# 2. Device Code Flow (para ambientes sem browser)
Connect-MgGraph -UseDeviceAuthentication

# 3. Com Access Token roubado
Connect-MgGraph -AccessToken (ConvertTo-SecureString "eyJ0..." -AsPlainText -Force)

# 4. Com Managed Identity (dentro de VM/Function App)
Connect-MgGraph -Identity

# 5. Com Service Principal (ClientId + Certificate)
Connect-MgGraph -ClientId "app-id" -TenantId "tenant-id" -CertificateThumbprint "thumb"

# 6. Com Client Secret
$credential = New-Object System.Management.Automation.PSCredential("client-id", (ConvertTo-SecureString "secret" -AsPlainText -Force))
Connect-MgGraph -TenantId "tenant-id" -ClientSecretCredential $credential
```

---

## Comandos de Enumeração — Mg Module

```powershell
# Informações básicas do contexto atual
Get-MgContext

# ===== USUÁRIOS =====
# Listar todos os usuários
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, Id, JobTitle

# Detalhes de um usuário específico
Get-MgUser -UserId "user@domain.com" | Format-List *

# Buscar usuários por atributo
Get-MgUser -Filter "startsWith(displayName,'Admin')" -All

# Membros de diretório (usuários E guests)
Get-MgDirectoryMember -All

# ===== GRUPOS =====
# Listar todos os grupos
Get-MgGroup -All | Select-Object DisplayName, Id, GroupTypes, SecurityEnabled

# Membros de um grupo
Get-MgGroupMember -GroupId "group-id" -All | Select-Object Id, "@odata.type"

# Grupos de um usuário
Get-MgUserMemberOf -UserId "user-id" -All

# ===== APLICAÇÕES E SERVICE PRINCIPALS =====
# App Registrations
Get-MgApplication -All | Select-Object DisplayName, AppId, Id

# Enterprise Apps / Service Principals
Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, Id, ServicePrincipalType

# Permissões de uma aplicação
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "sp-id" -All

# ===== ROLES =====
# Roles do Entra ID ativas
Get-MgDirectoryRole -All | Select-Object DisplayName, Id, RoleTemplateId

# Membros de uma role
Get-MgDirectoryRoleMember -DirectoryRoleId "role-id" -All

# ===== CONDITIONAL ACCESS =====
# (Requer Policy.Read.ConditionalAccess + AuditLog.Read.All + Directory.Read.All)
Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName, State, Id

# ===== KEY VAULTS (via ARM API) =====
# Listar key vaults via Az CLI (veja seção Az CLI abaixo)
```

---

## Az CLI — Comandos Essenciais

```bash
# Login interativo
az login

# Login com device code (sem browser)
az login --use-device-code

# Login com service principal
az login --service-principal -u "client-id" -p "secret" --tenant "tenant-id"

# Login com certificado
az login --service-principal -u "client-id" --certificate @cert.pem --tenant "tenant-id"

# ===== CONTEXTO =====
# Listar subscriptions
az account list --output table

# Definir subscription ativa
az account set --subscription "subscription-id"

# Obter access token para ARM
az account get-access-token
az account get-access-token --resource "https://graph.microsoft.com/"
az account get-access-token --resource "https://vault.azure.net/"

# ===== ENUMERAÇÃO ENTRA ID =====
# Listar usuários
az ad user list --output table
az ad user show --id "user@domain.com"

# Listar grupos
az ad group list --output table
az ad group member list --group "GroupName"

# Listar service principals
az ad sp list --all --output table
az ad sp show --id "app-id"

# ===== ENUMERAÇÃO ARM =====
# Recursos acessíveis
az resource list --output table

# VMs
az vm list --output table
az vm list-ip-addresses

# Role assignments
az role assignment list --all --output table
az role assignment list --assignee "user@domain.com" --all

# Key Vaults
az keyvault list --output table
az keyvault secret list --vault-name "VaultName"
az keyvault secret show --vault-name "VaultName" --name "SecretName"

# Storage Accounts
az storage account list --output table

# ===== MANAGED IDENTITY =====
# Ver managed identities de uma VM
az vm identity show --name "VMName" --resource-group "RG"
```

---

## ROADtools — Enumeração Completa do Tenant

ROADtools é a ferramenta mais completa para dump e análise do Entra ID. Cria um banco SQLite local com todos os objetos do tenant.

```bash
# Instalação
pip install roadtools

# Autenticação com usuário/senha
roadrecon auth -u user@domain.com -p 'Password123'

# Autenticação com access token
roadrecon auth --access-token "eyJ0..."

# Autenticação com refresh token
roadrecon auth --refresh-token "0.ARo..." --client "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Coletar TODOS os dados do tenant
roadrecon gather

# Lançar interface web para análise
roadrecon gui

# Análise via CLI
roadrecon plugin policies   # Conditional Access Policies
roadrecon plugin bloodhound # Exportar para BloodHound
```

---

## AzureHound — BloodHound para Azure

AzureHound coleta dados do Azure e Entra ID no formato compatível com BloodHound, permitindo análise visual de attack paths.

```bash
# Download: https://github.com/BloodHoundAD/AzureHound

# Autenticação com usuário/senha
./AzureHound -u "user@domain.com" -p "Password123" list --tenant "tenant-id" -o output.json

# Autenticação com refresh token
./AzureHound -r "refresh-token" list --tenant "tenant-id" -o output.json

# Autenticação com client secret
./AzureHound -a "client-id" -s "client-secret" list --tenant "tenant-id" -o output.json

# Coletar tudo
./AzureHound list all --tenant "tenant-id" -o full-output.json

# Importar no BloodHound
# Upload via interface web do BloodHound ou bloodhound-python --zip
```

---

## Enumeração via ARM API Direta

```bash
# Obter token ARM
TOKEN=$(az account get-access-token --query accessToken -o tsv)

# Listar subscriptions
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Listar recursos de uma subscription
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/{sub-id}/resources?api-version=2021-04-01"

# Listar role assignments
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/{sub-id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

# Key Vault secrets
curl -H "Authorization: Bearer $TOKEN_VAULT" \
  "https://{vault-name}.vault.azure.net/secrets?api-version=7.4"
```

---

## Decodificando JWTs

```bash
# Método 1: via base64 (Linux)
echo "eyJ0..." | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Método 2: via PowerShell
$token = "eyJ0..."
$parts = $token.Split(".")
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($parts[1] + "==")) | ConvertFrom-Json

# Claims importantes:
# oid  = Object ID do usuário/SP
# tid  = Tenant ID
# aud  = Audience (recurso alvo)
# scp  = Scopes delegados
# roles = App roles
# iss  = Issuer
# exp  = Expiration (Unix timestamp)
# iat  = Issued at
# upn  = User Principal Name
```

---

## Detecção e OPSEC

### O Que é Logado

| Ação | Log Gerado | Onde |
|------|-----------|-------|
| Login interativo | Sign-in Log | Entra ID > Sign-ins |
| Device Code Flow | Sign-in Log (Authentication Protocol: Device Code) | Entra ID > Sign-ins |
| Access token refresh | Sign-in Log (token refresh) | Entra ID > Sign-ins |
| Leitura de usuários via Graph | Audit Log | Entra ID > Audit Logs |
| Modificação de grupo | Audit Log | Entra ID > Audit Logs |
| Acesso a Key Vault | Activity Log + Diagnostics | Key Vault > Insights |
| Operações ARM | Activity Log | Monitor > Activity Log |
| Ativação de role PIM | Audit Log + Notificação | PIM > Audit History |

### O Que NÃO é Logado por Padrão
- Aquisição de access token (só é logado o refresh/login inicial).
- Leitura de dados via Graph (sem Microsoft Purview Audit logging habilitado).
- Consultas ao IMDS endpoint (internas à VM).

### OPSEC Recomendado
1. **Use client_ids legítimos** (Microsoft Office, Teams) ao fazer device code phishing — o login aparece como a app legítima.
2. **Evite operações de escrita** durante a fase de enumeração — leituras geram menos alertas.
3. **Espaçe as requisições** ao enumerar via Graph — queries muito rápidas podem triggerar alertas de anomalia.
4. **O IP logado no Sign-in é o IP do ATACANTE** no device code phishing (não o da vítima) — use VPNs/proxies coerentes com a geolocalização esperada.
5. **roadrecon** usa AAD Graph interno (api-version=1.61-internal) para enumerar CAPs com qualquer usuário autenticado.

---

## Módulos Relacionados

`13_azure_acesso_inicial.md` cobre acesso inicial e device code phishing. `14_azure_enum_privesc.md` aprofunda pós-autenticação e PrivEsc com tokens. `15_azure_lateral_movement.md` cobre lateral movement e Managed Identity pivot. `16_azure_bypass_defesas.md` lida com bypass de Conditional Access. `18_azure_cheatsheet.md` é o quick reference completo de comandos.
