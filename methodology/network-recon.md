---
title: "Network Recon & Discovery"
---

# Reconhecimento de Rede e Discovery

## De Acesso Cego a Visibilidade Tática

Após comprometimento inicial em workstation Windows, o atacante está em território desconhecido. Sabe que está dentro — mas não sabe onde. Quantas sub-redes existem? Onde ficam os Domain Controllers? Quais servidores hospedam dados sensíveis? Qual a topologia lógica do ambiente? Network reconnaissance interno é a fase que transforma acesso cego em visibilidade tática.

APTs profissionais tratam essa fase com rigor de operação de inteligência militar: antes de mover, mapear o terreno. O objetivo não é varrer tudo de uma vez — é construir mapa progressivamente, preferindo métodos que se confundem com tráfego legítimo e deixam mínimo de log. MITRE ATT&CK relevantes: T1018 (Remote System Discovery), T1046 (Network Service Discovery), T1016 (Network Config Discovery), T1049 (Network Connections Discovery), T1069 (Permission Groups Discovery), T1087 (Account Discovery), T1082 (System Information Discovery), T1482 (Domain Trust Discovery).

Onde `09_active_directory/08_bloodhound_e_enumeracao.md` cobre coleta via BloodHound/SharpHound e PowerView, este módulo foca no que vem **antes** ou **em paralelo** com BloodHound: reconhecimento de rede na camada IP/TCP, descoberta de hosts e serviços via ferramentas nativas (LotL), e enumeração cirúrgica de AD via LDAP sem depender de ferramenta especializada que possa cair em AV/EDR.

---

## Da Orientação Local ao Mapeamento de Domínio: Como APTs Expandem Visibilidade

### A Progressão de Discovery em Operações Reais

APTs não chegam a um host e imediatamente rodam `nmap -A 10.0.0.0/8`. Esse comportamento é detectável, registra eventos de conexão em massa em logs de firewall, e gera alertas em qualquer SIEM decente.

A progressão típica observada em incidentes documentados (APT29, APT41, Lazarus Group) segue uma lógica de expansão gradual:

**Etapa 1 — Orientação local** (sem tráfego de rede adicional):
- Identificar a sub-rede local e o gateway
- Mapear entradas da tabela ARP (hosts que já comunicaram com a máquina)
- Verificar conexões de rede ativas e portas em escuta
- Identificar nome do domínio e DC via ipconfig/nslookup

**Etapa 2 — Passive discovery** (tráfego mínimo):
- Consultar DNS para resolver nomes de servidores de alto valor
- Usar consultas LDAP ao DC para listar computadores do domínio
- Verificar shares acessíveis via UNC sem varredura

**Etapa 3 — Active discovery (restrito e temporizado)**:
- Ping sweep restrito a sub-redes específicas, com delay
- Port scan cirúrgico em alvos específicos (portas 445, 3389, 1433, 8080)
- Enumeração SMB/NetBIOS em hosts de interesse

**Etapa 4 — Service enumeration** (autenticado):
- Usar credenciais obtidas para enumerar shares, sessões, usuários via SMB/RPC
- Consultas LDAP autenticadas para mapear o AD sem BloodHound

### Por Que Living-off-the-Land Importa

Ferramentas como `net.exe`, `nltest.exe`, `nslookup.exe`, `ipconfig.exe`, `arp.exe` e `route.exe` são binários assinados pela Microsoft, presentes em todas as instalações do Windows. Eles:

- Não acionam alertas de "arquivo malicioso" em EDRs
- São executados com frequência por usuários e scripts legítimos
- Geram logs de processo (Sysmon Event 1), mas os argumentos não são incomuns em contextos normais
- Não requerem download de ferramentas, reduzindo a superfície de detecção

O conceito de **LOLBins** (Living-Off-the-Land Binaries) — usar binários legítimos do sistema para fins ofensivos — é central para OPSEC em engagements modernos.

### Hierarquia de Ruído por Técnica

Do menos para o mais barulhento:

```
SILENCIOSO                          BARULHENTO
    |                                   |
    v                                   v
Leitura de tabela ARP local         Nmap -A em toda a sub-rede
Consulta DNS (nslookup)             Ping sweep com ICMP em /16
Consulta LDAP ao DC                 NetSessionEnum em todos os hosts
ipconfig / route print              BloodHound --CollectionMethods All
net view (SMB browse)               Port scan em range completo
Test-NetConnection (porta única)    nbtscan em toda a rede
```

---

## Na Prática

### Fase 1: Orientação Local — Qual Rede Estou?

O primeiro passo ao ganhar acesso a uma máquina é entender onde você está sem gerar tráfego:

**Identificar interfaces e IPs:**
- `ipconfig /all` — todas as interfaces, IPs, máscaras, gateways, DNS servers
- O campo "DNS Suffix Search List" frequentemente revela o nome do domínio AD
- O campo "DNS Servers" aponta para os Domain Controllers (DCs geralmente são os servidores DNS)

**Mapear hosts que já comunicaram com essa máquina:**
- `arp -a` — tabela ARP local, lista IPs e MACs de hosts recentemente vistos na rede
- Essa tabela é gerada por tráfego legítimo — não gera nenhum tráfego novo
- Em ambiente corporativo, a tabela ARP frequentemente já contém dezenas de hosts da sub-rede

**Verificar rotas de rede:**
- `route print` — tabela de roteamento completa, revela outras sub-redes acessíveis
- Sub-redes listadas em rotas estáticas são candidatas para pivoting

**Verificar conexões ativas:**
- `netstat -ano` — conexões TCP estabelecidas, revela com quais IPs a máquina se comunica
- `netstat -ano | findstr ESTABLISHED` — apenas conexões estabelecidas
- Conexões estabelecidas indicam hosts ativos que já confiam nesta máquina

### Fase 2: Identificar o Domínio e os Domain Controllers

Com o nome do domínio em mãos (obtido via `ipconfig /all`), o próximo passo é localizar os DCs:

**Via DNS:**
- `nslookup -type=SRV _ldap._tcp.corp.local` — retorna todos os DCs do domínio
- `nslookup -type=SRV _kerberos._tcp.corp.local` — DCs com serviço Kerberos

**Via nltest:**
- `nltest /dclist:corp.local` — lista todos os DCs do domínio
- `nltest /dsgetdc:corp.local` — retorna o DC preferido
- `nltest /domain_trusts` — lista trusts com outros domínios (essencial para forest attacks)

**Via net.exe:**
- `net group "Domain Controllers" /domain` — lista DCs como membros do grupo

### Fase 3: Host Discovery — Encontrar Alvos na Rede

Antes de qualquer scan ativo, verificar o que já está visível via ARP e DNS.

**Descoberta passiva via DNS reverso (sem ICMP):**
- Resolver nomes para IPs conhecidos da sub-rede via `nslookup 10.10.10.X`
- Hosts com registros DNS PTR provavelmente são servidores gerenciados

**Descoberta de hosts via SMB Browse:**
- `net view /domain:corp.local` — lista computadores anunciados no domínio via NetBIOS
- `net view \\\\10.10.10.10` — lista shares em host específico

**Identificar servidores de alto valor via DNS:**
```
nslookup exchange.corp.local       # Exchange / mail server
nslookup sql.corp.local            # SQL Server
nslookup fs01.corp.local           # File Server
nslookup sharepoint.corp.local     # SharePoint
nslookup webserver.corp.local      # Web Server interno
nslookup backup.corp.local         # Backup Server
nslookup vcenter.corp.local        # VMware vCenter
```

### Fase 4: Identificar Alvos de Alto Valor

Um operador experiente não tenta comprometer tudo — foca nos alvos que maximizam o impacto:

**Domain Controllers**: geralmente têm nomes como DC01, DC02, ADDC, PDC. Hospedam NTDS.dit (todos os hashes do domínio) e são o objetivo final para obter DCSync.

**Servidores de arquivo (File Servers)**: hospedam dados sensíveis. Nomes comuns: FS01, FILESERVER, NAS, STORAGE. Acessíveis via SMB na porta 445.

**SQL Servers**: hospedam bancos de dados de aplicações. Porta padrão 1433. Nomes comuns: SQL01, SQLSRV, DBSERVER. Frequentemente têm service accounts com privilégios elevados.

**Exchange / Mail Servers**: hospedam emails corporativos. Porta 443 (OWA/EWS). Nomes comuns: EXCH01, MAIL, EXCHANGE.

**Jump Servers / Bastion Hosts**: usados por admins para acessar outros sistemas. Concentram sessões de contas privilegiadas — alvo ideal para credential theft.

**vCenter / Hypervisors**: controle total de todas as VMs. Comprometer o vCenter equivale a comprometer todos os servidores virtualizados.

---

## Exemplos de Código / Comandos

### Bloco 1: Orientação Local com LOLBins

```cmd
REM ================================================================
REM RECONHECIMENTO LOCAL — sem gerar tráfego externo

REM Informações completas de rede (IPs, DNS, domínio, gateway)
ipconfig /all

REM Tabela ARP — hosts que já comunicaram com esta máquina (sem tráfego)
arp -a

REM Tabela de roteamento — sub-redes acessíveis
route print

REM Conexões TCP estabelecidas (hosts com confiança já estabelecida)
netstat -ano
netstat -ano | findstr ESTABLISHED
netstat -ano | findstr LISTENING

REM Sessões SMB abertas nesta máquina
net session

REM Shares locais desta máquina
net share

REM Usuário atual e grupos locais
whoami /all
net user %username%
net localgroup Administrators

REM Nome da máquina e domínio
hostname
echo %USERDOMAIN%
echo %LOGONSERVER%
```

```powershell
# ================================================================
# ORIENTAÇÃO LOCAL — PowerShell equivalente

# Informações de rede estruturadas
Get-NetIPConfiguration
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
Get-NetRoute | Where-Object {$_.DestinationPrefix -ne "0.0.0.0/0"}

# Tabela ARP local
Get-NetNeighbor -State Reachable | Select-Object IPAddress, LinkLayerAddress, State

# Conexões TCP ativas
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Sort-Object RemoteAddress

# Identificar processos por PID das conexões
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Local  = "$($_.LocalAddress):$($_.LocalPort)"
        Remote = "$($_.RemoteAddress):$($_.RemotePort)"
        PID    = $_.OwningProcess
        Process = $proc.Name
    }
} | Sort-Object Remote

# DNS configurado (frequentemente aponta para DCs)
(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
```

---

### Bloco 2: Descoberta de Domínio e Domain Controllers

```cmd
REM ================================================================
REM DESCOBERTA DO AD VIA FERRAMENTAS NATIVAS

REM Localizar DCs via DNS SRV records
nslookup -type=SRV _ldap._tcp.corp.local
nslookup -type=SRV _kerberos._tcp.corp.local
nslookup -type=SRV _gc._tcp.corp.local

REM Localizar DCs via nltest
nltest /dclist:corp.local
nltest /dsgetdc:corp.local /force
nltest /domain_trusts
nltest /trusted_domains

REM Enumerar DCs via net.exe
net group "Domain Controllers" /domain
net group "Enterprise Admins" /domain
net group "Domain Admins" /domain

REM Informações do domínio
net config workstation
wmic computersystem get domain, domainrole, name

REM Listar computadores do domínio (pode ser bloqueado em ambientes com restrições)
net view /domain:corp.local
net view /domain

REM Visualizar PDC (Primary Domain Controller)
netdom query pdc
```

```powershell
# ================================================================
# DESCOBERTA DE AD VIA POWERSHELL NATIVO (sem ferramentas externas)

# Localizar DCs via DNS
Resolve-DnsName -Name "_ldap._tcp.corp.local" -Type SRV
Resolve-DnsName -Name "_kerberos._tcp.corp.local" -Type SRV

# Localizar DCs via .NET (não requer módulo ActiveDirectory)
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers |
    Select-Object Name, IPAddress, OSVersion, Roles

# Info do domínio via .NET
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain.Name
$domain.DomainControllers
$domain.Forest.Name

# Trusts de domínio via .NET
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships() |
    Select-Object TargetName, TrustDirection, TrustType

# Verificar conectividade com o DC
Test-NetConnection -ComputerName DC01.corp.local -Port 389   # LDAP
Test-NetConnection -ComputerName DC01.corp.local -Port 636   # LDAPS
Test-NetConnection -ComputerName DC01.corp.local -Port 88    # Kerberos
Test-NetConnection -ComputerName DC01.corp.local -Port 445   # SMB
Test-NetConnection -ComputerName DC01.corp.local -Port 3268  # Global Catalog
```

---

### Bloco 3: Enumeração AD via LDAP sem BloodHound

O módulo `08_bloodhound_e_enumeracao.md` cobre BloodHound, SharpHound e PowerView em profundidade. Aqui estão as alternativas que funcionam **sem instalar nada** — usando apenas o .NET Framework presente no Windows.

```powershell
# ================================================================
# CONSULTAS LDAP DIRETAS VIA [ADSISEARCHER] — sem ferramentas externas
# Funciona em qualquer Windows com acesso ao DC

# Conexão ao LDAP do DC atual
$searcher = [ADSISearcher]""
$searcher.SearchRoot = [ADSI]"LDAP://corp.local"
$searcher.PageSize = 1000

# ----------------------------------------------------------------
# Listar TODOS os usuários do domínio
Write-Host "Domain Users:`n-------------"
([ADSISearcher]"(ObjectClass=User)").FindAll() | ForEach-Object {
    Write-Host $_.Properties.name
}

# Versão com mais atributos
$searcher.Filter = "(objectCategory=person)(objectClass=user)"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","mail","memberof","pwdlastset","lastlogon","description","userAccountControl"))
$results = $searcher.FindAll()
foreach ($r in $results) {
    [PSCustomObject]@{
        Username    = $r.Properties["samaccountname"][0]
        Email       = $r.Properties["mail"][0]
        Description = $r.Properties["description"][0]
        LastLogon   = if ($r.Properties["lastlogon"][0]) { [DateTime]::FromFileTime($r.Properties["lastlogon"][0]) } else { "Never" }
    }
}

# ----------------------------------------------------------------
# Listar membros do grupo Domain Admins
Write-Host "Domain Admins:`n-------------"
([ADSISearcher]"(&(objectCategory=User)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))").FindAll() |
    ForEach-Object { Write-Host $_.Properties.name }

# Mais robusto — suporta grupos aninhados
$searcher.Filter = "(&(objectCategory=User)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local))"
$searcher.FindAll() | ForEach-Object {
    Write-Host $_.Properties["samaccountname"][0]
}

# ----------------------------------------------------------------
# Listar TODOS os computadores do domínio
$searcher.Filter = "(objectCategory=computer)"
$searcher.PropertiesToLoad.AddRange(@("dnshostname","operatingsystem","operatingsystemversion","lastlogon","userAccountControl"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.Properties["dnshostname"][0]
        OS      = $_.Properties["operatingsystem"][0]
        Version = $_.Properties["operatingsystemversion"][0]
        LastLogon = if ($_.Properties["lastlogon"][0]) { [DateTime]::FromFileTime($_.Properties["lastlogon"][0]) } else { "Never" }
    }
} | Sort-Object OS | Format-Table -AutoSize

# ----------------------------------------------------------------
# Encontrar Domain Controllers especificamente
$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
$searcher.PropertiesToLoad.AddRange(@("dnshostname","operatingsystem","description"))
$searcher.FindAll() | ForEach-Object {
    Write-Host "[DC] $($_.Properties['dnshostname'][0]) — $($_.Properties['operatingsystem'][0])"
}

# ----------------------------------------------------------------
# Usuários com SPN (alvo para Kerberoasting) — sem PowerView
$searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","memberof","pwdlastset"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Username = $_.Properties["samaccountname"][0]
        SPNs     = ($_.Properties["serviceprincipalname"] -join ", ")
        PwdLastSet = if ($_.Properties["pwdlastset"][0]) { [DateTime]::FromFileTime($_.Properties["pwdlastset"][0]) } else { "N/A" }
    }
}

# ----------------------------------------------------------------
# Usuários sem pré-autenticação Kerberos (AS-REP Roastable)
$searcher.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.FindAll() | ForEach-Object {
    Write-Host "[AS-REP] $($_.Properties['samaccountname'][0])"
}

# ----------------------------------------------------------------
# Contas com senha que nunca expira
$searcher.Filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.FindAll() | ForEach-Object {
    Write-Host "[NoExpire] $($_.Properties['samaccountname'][0])"
}

# ----------------------------------------------------------------
# Contas com senha na descrição (erro de admin comum)
$searcher.Filter = "(&(objectCategory=user)(description=*pass*))"
$searcher.FindAll() | ForEach-Object {
    Write-Host "[!] $($_.Properties['samaccountname'][0]): $($_.Properties['description'][0])"
}

# Repetir com outros termos
foreach ($term in @("pwd", "senha", "secret", "admin", "123")) {
    $searcher.Filter = "(&(objectCategory=user)(description=*$term*))"
    $searcher.FindAll() | ForEach-Object {
        Write-Host "[DescPass:$term] $($_.Properties['samaccountname'][0]): $($_.Properties['description'][0])"
    }
}
```

```powershell
# ================================================================
# MÓDULO ACTIVEDIRECTORY (se disponível em DC ou RSAT instalado)
# Mostrado no slide do MalTrak Module 12

Import-Module ActiveDirectory

# Listar todos os usuários do domínio (slide: Get-ADUsers -Filter *)
Get-ADUser -Filter * -Properties mail, Description, MemberOf, PasswordNeverExpires, LastLogonDate |
    Select-Object SamAccountName, Mail, Description, PasswordNeverExpires, LastLogonDate

# Listar Domain Admins recursivamente (slide: Get-ADGroupMember -Recursive)
Get-ADGroupMember -Server "DC01.corp.local" -Identity "Domain Admins" -Recursive | Get-ADUser |
    Select-Object SamAccountName, Name, Enabled

# Todos os computadores com SO
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate |
    Sort-Object OperatingSystem |
    Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate

# Grupos de alto interesse
$groups = @("Domain Admins","Enterprise Admins","Schema Admins","Backup Operators",
            "Account Operators","Server Operators","Print Operators","DNSAdmins")
foreach ($g in $groups) {
    $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue
    if ($members) {
        Write-Host "`n[GROUP] $g ($($members.Count) members):"
        $members | Select-Object SamAccountName, Name | Format-Table -AutoSize
    }
}
```

---

### Bloco 4: Host Discovery com OPSEC

```powershell
# ================================================================
# PING SWEEP — OPSEC consciente

# RUIM — gera muito ruído, fácil de detectar
# 1..254 | ForEach-Object { ping -n 1 10.10.10.$_ }

# MELHOR — paralelo mas com throttle e usando Test-NetConnection
# Test-NetConnection verifica conectividade TCP (sem ICMP puro)
$subnet = "10.10.10"
$results = @()
1..254 | ForEach-Object -ThrottleLimit 10 -Parallel {
    $ip = "$using:subnet.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1
    if ($ping) {
        $hostname = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { "N/A" }
        [PSCustomObject]@{ IP = $ip; Hostname = $hostname; Status = "Up" }
    }
} | Sort-Object { [System.Version]$_.IP }

$results | Format-Table -AutoSize

# ================================================================
# PORT SCAN CIRÚRGICO — apenas portas de alto valor em alvos específicos
# Muito mais silencioso que varredura completa

$targets = @("10.10.10.10", "10.10.10.20", "10.10.10.30")
$ports = @(
    @{Port=22;   Name="SSH"},
    @{Port=80;   Name="HTTP"},
    @{Port=135;  Name="RPC"},
    @{Port=139;  Name="NetBIOS"},
    @{Port=389;  Name="LDAP"},
    @{Port=443;  Name="HTTPS"},
    @{Port=445;  Name="SMB"},
    @{Port=636;  Name="LDAPS"},
    @{Port=1433; Name="MSSQL"},
    @{Port=1521; Name="Oracle"},
    @{Port=3268; Name="GlobalCatalog"},
    @{Port=3306; Name="MySQL"},
    @{Port=3389; Name="RDP"},
    @{Port=5985; Name="WinRM-HTTP"},
    @{Port=5986; Name="WinRM-HTTPS"},
    @{Port=8080; Name="HTTP-Alt"},
    @{Port=8443; Name="HTTPS-Alt"}
)

foreach ($target in $targets) {
    Write-Host "`n[*] Scanning $target" -ForegroundColor Cyan
    foreach ($p in $ports) {
        $result = Test-NetConnection -ComputerName $target -Port $p.Port -WarningAction SilentlyContinue -InformationLevel Quiet
        if ($result) {
            Write-Host "  [OPEN] $($p.Port)/tcp ($($p.Name))" -ForegroundColor Green
        }
        # Delay entre portas para reduzir ruído
        Start-Sleep -Milliseconds 200
    }
}

# ================================================================
# DESCOBERTA DE SMB/NETBIOS EM SUB-REDE
# Porta 445 é um indicador forte de Windows/Samba ativo

$subnet = "10.10.10"
1..254 | ForEach-Object {
    $ip = "$subnet.$_"
    $smb = Test-NetConnection -ComputerName $ip -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($smb) {
        $hostname = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $ip }
        Write-Host "[SMB] $ip — $hostname"
    }
}
```

```cmd
REM ================================================================
REM HOST DISCOVERY VIA FERRAMENTAS NATIVAS (cmd.exe)

REM Descoberta de hosts via NetBIOS (sem autenticação)
nbtstat -A 10.10.10.10

REM Listar computadores no domínio via net view
net view /domain:corp.local
net view /domain

REM Resolver nome para IP e vice-versa
nslookup fileserver01.corp.local
nslookup 10.10.10.20

REM Verificar se SMB está acessível em host específico
net use \\10.10.10.10\IPC$ /user:corp\usuario Senha123

REM Listar shares em host específico
net view \\10.10.10.10

REM Limpar conexão
net use \\10.10.10.10\IPC$ /delete
```

---

### Bloco 5: Enumeração de Serviços — SMB, NetBIOS, RPC

```cmd
REM ================================================================
REM ENUMERAÇÃO SMB/NETBIOS VIA NET.EXE

REM Listar shares disponíveis em host
net view \\DC01.corp.local /all

REM Mapear share temporariamente para listar conteúdo
net use Z: \\DC01.corp.local\SYSVOL
dir Z:\corp.local\Policies\
net use Z: /delete

REM Acessar SYSVOL para buscar GPPs com credenciais (MS14-025)
dir \\DC01.corp.local\SYSVOL\corp.local\Policies\ /s /b | findstr "Groups.xml"
REM Se encontrar Groups.xml, pode conter senhas de contas locais cifradas com AES-256
REM A chave é pública: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref

REM Sessões ativas via net session
net session

REM Usuários com sessão em host remoto (requer admin)
net use \\servidor01\IPC$ /user:corp\usuario Senha123
wmic /node:servidor01 path Win32_LogonSession get LogonType, StartTime
net use \\servidor01\IPC$ /delete
```

```powershell
# ================================================================
# ENUMERAÇÃO SMB VIA POWERSHELL

# Listar shares em host
Get-SmbShare -CimSession servidor01.corp.local

# Verificar acesso a shares em lista de hosts
$hosts = @("dc01", "fileserver01", "sql01", "exchange01")
foreach ($h in $hosts) {
    $shares = Get-SmbShare -CimSession $h -ErrorAction SilentlyContinue
    if ($shares) {
        Write-Host "`n[SHARES] $h" -ForegroundColor Cyan
        $shares | Select-Object Name, Path, Description | Format-Table -AutoSize
    }
}

# Verificar acesso de leitura em shares conhecidos
$shares_to_check = @(
    "\\dc01\SYSVOL",
    "\\dc01\NETLOGON",
    "\\fileserver01\Data",
    "\\fileserver01\Backup",
    "\\fileserver01\IT"
)
foreach ($share in $shares_to_check) {
    try {
        $items = Get-ChildItem $share -ErrorAction Stop
        Write-Host "[READABLE] $share ($($items.Count) items)" -ForegroundColor Green
    } catch {
        Write-Host "[DENIED] $share" -ForegroundColor Red
    }
}

# Buscar arquivos interessantes em shares acessíveis
$share_path = "\\fileserver01\Data"
Get-ChildItem -Path $share_path -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match "\.(txt|ini|config|xml|ps1|bat|cmd|xlsx|docx)$" -or
        $_.Name -match "(password|credential|secret|backup|config|key|vpn)"
    } |
    Select-Object FullName, LastWriteTime, Length |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 50
```

---

### Bloco 6: Enumeração de DNS

```powershell
# ================================================================
# DNS ENUMERATION — mapear infraestrutura via DNS

# Resolver nomes comuns de servidores de alto valor
$targets = @(
    "dc01", "dc02", "pdc",
    "exchange", "exch01", "mail",
    "sql01", "sql", "sqlserver", "db01",
    "fileserver", "fs01", "nas", "storage",
    "sharepoint", "sp01",
    "vcenter", "vmware", "esxi",
    "backup", "veeam",
    "vpn", "remote",
    "jumpbox", "bastion",
    "proxy", "web", "iis",
    "mgmt", "monitoring", "sccm"
)

$domain = (Get-WmiObject Win32_ComputerSystem).Domain
foreach ($t in $targets) {
    $fqdn = "$t.$domain"
    try {
        $r = [System.Net.Dns]::GetHostAddresses($fqdn)
        Write-Host "[+] $fqdn -> $($r.IPAddressToString -join ', ')" -ForegroundColor Green
    } catch { }
}

# ----------------------------------------------------------------
# Usar Resolve-DnsName para consultas avançadas
Resolve-DnsName -Name "corp.local" -Type ANY
Resolve-DnsName -Name "_msdcs.corp.local" -Type NS
Resolve-DnsName -Name "_ldap._tcp.corp.local" -Type SRV
Resolve-DnsName -Name "_gc._tcp.corp.local" -Type SRV    # Global Catalog

# DNS reverso em sub-rede (descoberta passiva de hosts)
$subnet = "10.10.10"
1..254 | ForEach-Object {
    $ip = "$subnet.$_"
    try {
        $name = [System.Net.Dns]::GetHostEntry($ip).HostName
        Write-Host "[PTR] $ip -> $name"
    } catch { }
}

# ----------------------------------------------------------------
# Verificar se DNS permite transferência de zona (AXFR)
# Geralmente bloqueado, mas vale tentar em ambientes antigos
nslookup
> server dc01.corp.local
> set type=any
> ls -d corp.local
```

---

### Bloco 7: Sessões Ativas e Identificação de Alvos para Credential Theft

```cmd
REM ================================================================
REM IDENTIFICAR ONDE DOMAIN ADMINS TÊM SESSÃO (para credential theft)

REM Listar sessões ativas em host (requer NetSessionEnum)
REM O Windows expõe isso via UNC path
net session \\servidor01
```

```powershell
# ================================================================
# IDENTIFICAR SESSÕES VIA POWERSHELL

# Sessões em host específico via WMI
Get-WmiObject -Class Win32_LogonSession -ComputerName servidor01.corp.local |
    Where-Object { $_.LogonType -in @(2, 10) } |  # 2=Interactive, 10=RemoteInteractive
    Select-Object LogonType, StartTime

# Verificar quem está logado via query.exe
# (funciona em hosts com Remote Desktop Services)
Invoke-Command -ComputerName servidor01.corp.local -ScriptBlock {
    query user 2>&1
}

# Verificar processos em execução como outros usuários
Invoke-Command -ComputerName servidor01.corp.local -ScriptBlock {
    Get-Process | Select-Object Name, Id, @{N="User";E={$_.GetOwner().User}} |
    Where-Object { $_.User -ne $null }
} -ErrorAction SilentlyContinue

# ================================================================
# USANDO NETSESSIONENUM NATIVO (o que BloodHound usa internamente)
# Disponível via .NET P/Invoke ou via net.exe

# Via PowerShell com compilação dinâmica de P/Invoke
$code = @"
using System;
using System.Runtime.InteropServices;
public class NetAPI {
    [DllImport("NetAPI32.dll")]
    public static extern int NetSessionEnum(
        string servername, string UncClientName, string username,
        int level, ref IntPtr bufptr, int prefmaxlen,
        ref int entriesread, ref int totalentries, ref IntPtr resume_handle);
    [DllImport("NetAPI32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);
}
"@
# (implementação completa é mais extensa — PowerView já abstrai isso via Get-NetSession)
```

---

### Bloco 8: Ferramentas Especializadas com Contexto de Uso

```bash
# ================================================================
# NMAP — quando speed/sigilo não é crítico (ex: ambiente segmentado, lab)
# Observação: nmap gera logs em firewalls e NDR — usar apenas quando justificado

# Descoberta rápida de hosts ativos (ARP scan — apenas na mesma sub-rede)
sudo nmap -sn -PR 10.10.10.0/24

# Host discovery sem porta scan (ICMP + TCP SYN probe)
nmap -sn 10.10.10.0/24 --min-hostgroup 64 -T2

# Port scan furtivo em alvo específico (SYN scan, timing T2)
nmap -sS -T2 -p 22,80,135,139,389,443,445,1433,3268,3389,5985,8080 10.10.10.10

# Detecção de versão em portas abertas (mais barulhento)
nmap -sV -T2 -p 445,1433,3389 10.10.10.10

# Script NSE para enumeração SMB (útil para identificar SO sem autenticação)
nmap --script smb-os-discovery -p 445 10.10.10.0/24

# Script NSE para listar shares SMB
nmap --script smb-enum-shares --script-args smbuser=usuario,smbpass=Senha123 -p 445 10.10.10.10

# Identificar Domain Controllers via serviços Kerberos/LDAP
nmap -sV -p 88,389,636,3268,3269 10.10.10.0/24

# ================================================================
# CRACKMAPEXEC — enumeração SMB/LDAP autenticada em escala

# Descoberta de hosts ativos via SMB (porta 445)
crackmapexec smb 10.10.10.0/24

# Com credenciais — identificar acesso de admin
crackmapexec smb 10.10.10.0/24 -u usuario -p 'Senha123'

# Enumeração de usuários via SMB
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --users

# Enumeração de grupos
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --groups

# Política de senhas (útil para calibrar password spray)
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --pass-pol

# Listar shares
crackmapexec smb 10.10.10.0/24 -u usuario -p 'Senha123' --shares

# Sessões ativas (revela onde usuários estão logados)
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' --sessions

# Usuários logados em hosts
crackmapexec smb 10.10.10.0/24 -u usuario -p 'Senha123' --loggedon-users

# Spider de shares (busca arquivos interessantes)
crackmapexec smb DC01.corp.local -u usuario -p 'Senha123' -M spider_plus

# Com hash NT (Pass-the-Hash)
crackmapexec smb 10.10.10.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# ================================================================
# RPCCLIENT — enumeração via MS-RPC (porta 135/445)

rpcclient -U "usuario%Senha123" DC01.corp.local

# Comandos dentro do rpcclient:
# enumdomusers          — listar todos os usuários do domínio
# enumdomgroups         — listar grupos do domínio
# querydominfo          — informações gerais do domínio
# getdompwinfo          — política de senhas
# netshareenum          — shares disponíveis
# netshareenumall       — todos os shares (incluindo admin)
# queryuser 0x1f4       — info do usuário Administrator (RID 500)
# enumprinters          — impressoras (revela servidores de impressão)
# lsaenumsid            — SIDs conhecidos
# lookupsids S-1-5-21-...  — resolver SID para nome

# Sem modo interativo:
rpcclient -U "usuario%Senha123" DC01.corp.local -c "enumdomusers"
rpcclient -U "usuario%Senha123" DC01.corp.local -c "enumdomgroups"
rpcclient -U "usuario%Senha123" DC01.corp.local -c "getdompwinfo"

# ================================================================
# AD EXPLORER (Sysinternals) — como mostrado no slide do MalTrak
# Ferramenta GUI, assinada digitalmente pela Microsoft
# Pode ser usada quando OPSEC permite execução de ferramentas com UI

# Características:
# - Gratuita, da Sysinternals (confiável para AV)
# - Permite navegar no AD como uma árvore
# - Pode exportar snapshots para análise offline
# - Útil quando você tem acesso RDP a uma máquina dentro do domínio

# Download: https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer
# Uso: ADExplorer.exe -> conectar em DC01.corp.local -> navegar a árvore AD

# ================================================================
# PINGCASTLE — análise de segurança do AD (mostrado no slide do MalTrak)
# Ferramenta assinada digitalmente, gera relatório de risco do AD
# Score 0-100 (menor é melhor)
# Detecta: objetos obsoletos, contas privilegiadas, trusts, anomalias

# Uso básico (executa como usuário de domínio):
PingCastle.exe --healthcheck --server DC01.corp.local

# Gera relatório HTML com:
# - Domain Risk Level (score geral)
# - Stale Objects (usuários/computadores inativos)
# - Privileged Accounts (contas com privilégios excessivos)
# - Trusts (trusts com outros domínios)
# - Anomalies (configurações inseguras)

# Uso ofensivo: identifica rapidamente vulnerabilidades no AD sem precisar
# de BloodHound, e o relatório HTML é fácil de exfiltrar e analisar offline
```

---

### Bloco 9: Workflow Completo de Network Recon — Do Zero ao Mapa

```powershell
# ================================================================
# WORKFLOW SEQUENCIAL — adaptado para OPSEC
# Executar em ordem, analisar antes de avançar

Write-Host "=== FASE 1: ORIENTAÇÃO LOCAL ===" -ForegroundColor Yellow

# 1.1 Identificar rede e domínio
$netinfo = Get-NetIPConfiguration
$dns_servers = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-Host "[NET] IP: $($netinfo.IPv4Address.IPAddress)"
Write-Host "[NET] Gateway: $($netinfo.IPv4DefaultGateway.NextHop)"
Write-Host "[DNS] Servers: $($dns_servers -join ', ')"
Write-Host "[DOMAIN] $domain"

# 1.2 Tabela ARP (hosts já vistos)
Write-Host "`n=== FASE 2: ARP TABLE (hosts sem tráfego extra) ===" -ForegroundColor Yellow
Get-NetNeighbor -State Reachable | Select-Object IPAddress, LinkLayerAddress | Format-Table

# 1.3 Localizar DCs
Write-Host "`n=== FASE 3: DOMAIN CONTROLLERS ===" -ForegroundColor Yellow
$dc_svr = Resolve-DnsName -Name "_ldap._tcp.$domain" -Type SRV -ErrorAction SilentlyContinue
$dc_svr | Select-Object NameTarget, Port | Format-Table

# 1.4 Enumerar computadores via LDAP (sem ferramentas externas)
Write-Host "`n=== FASE 4: COMPUTADORES DO DOMÍNIO (LDAP) ===" -ForegroundColor Yellow
$s = [ADSISearcher]"(objectCategory=computer)"
$s.PropertiesToLoad.AddRange(@("dnshostname","operatingsystem","lastlogon"))
$s.PageSize = 1000
$computers = $s.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Properties["dnshostname"][0]
        OS   = $_.Properties["operatingsystem"][0]
        LastSeen = if ($_.Properties["lastlogon"][0]) { [DateTime]::FromFileTime($_.Properties["lastlogon"][0]) } else { "Never" }
    }
}
$computers | Sort-Object OS | Format-Table -AutoSize

# Extrair apenas IPs para próximas fases
$computer_names = $computers | Where-Object { $_.LastSeen -gt (Get-Date).AddDays(-90) } | Select-Object -ExpandProperty Name

# 1.5 Verificar portas de alto valor em DCs identificados
Write-Host "`n=== FASE 5: VERIFICAÇÃO DE SERVIÇOS NOS ALVOS ===" -ForegroundColor Yellow
$dc_ip = ($dc_svr | Select-Object -First 1).NameTarget
$key_ports = @(88, 135, 389, 445, 636, 3268, 3389, 5985)
foreach ($port in $key_ports) {
    $r = Test-NetConnection -ComputerName $dc_ip -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
    $status = if ($r) { "OPEN" } else { "CLOSED" }
    Write-Host "  [$status] $dc_ip`:$port"
}

Write-Host "`n=== RECON CONCLUIDO — Pronto para fase de enumeração aprofundada ===" -ForegroundColor Green
```

---

## Detecção e OPSEC

### O Que Gera Alertas — Tabela de Detecção por Técnica

| Técnica | Event IDs Gerados | Nível de Ruído | Detectado por Defender Identity? |
|---------|------------------|----------------|----------------------------------|
| `ipconfig /all` | Sysmon 1 (process create) | Baixo | Nao |
| `arp -a` | Sysmon 1 | Baixo | Nao |
| `nslookup` (DNS query) | Sysmon 22 (DNS query) | Baixo | Nao |
| `nltest /dclist` | Sysmon 1, 4662 | Medio | Possivel |
| `net group` (domínio) | Sysmon 1, 4662 (LDAP) | Medio | Sim (LDAP Recon) |
| `[ADSISearcher]` queries | 4662 (LDAP object access) | Medio | Sim (LDAP Recon) |
| `net view` (browse) | 5145 (share access) | Alto | Possivel |
| Ping sweep ICMP | Firewall logs | Alto | Sim (Network Recon) |
| Port scan TCP | Firewall/NDR | Alto | Sim |
| `NetSessionEnum` em todos os hosts | 4624, 5145 por host | Muito alto | Sim |

### Regras de OPSEC para Network Recon

**Regra 1 — Passive antes de Active**: Sempre extraia o máximo de informações de fontes passivas (tabela ARP, DNS, LDAP ao DC) antes de fazer qualquer scan ativo.

**Regra 2 — Cirúrgico, não abrangente**: Prefira consultas LDAP ao DC para listar computadores do domínio em vez de ping sweep. A lista LDAP é mais completa e não gera tráfego de rede visível para os hosts alvo.

**Regra 3 — Respeitar horários**: Tráfego de reconhecimento durante a madrugada (quando não há usuários logados gerando tráfego legítimo) é mais fácil de detectar. Fazer recon durante horário de expediente mistura com tráfego normal.

**Regra 4 — Delay entre operações**: Consultas LDAP em rajada rápida (SharpHound All) são detectadas pelo Defender for Identity pelo padrão de timing. Introduzir delays de 5-30 segundos entre queries reduz a detectabilidade.

**Regra 5 — Limitar NetSessionEnum**: NetSessionEnum em todos os computadores do domínio é a técnica mais detectável. Preferir DCOnly para BloodHound e limitar consultas de sessão a servidores de alto valor específicos.

```powershell
# ================================================================
# OPSEC: Como reduzir detecção em consultas LDAP

# RUIM — rajada rápida, detectável pelo padrão de queries
$searcher = [ADSISearcher]"(objectCategory=computer)"
$searcher.FindAll()   # gera muitas queries LDAP em sequência rápida

# MELHOR — consultas mais espaçadas com filtros específicos
function Invoke-LDAPQuery {
    param($filter, $properties)
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)  # delay aleatório
    $s = [ADSISearcher]$filter
    $s.PropertiesToLoad.AddRange($properties)
    $s.PageSize = 200   # páginas menores, menos LDAP traffic burst
    return $s.FindAll()
}

# Consultar DCs primeiro — menos barulhento que consultar todos os computadores
$dcs = Invoke-LDAPQuery -filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" `
    -properties @("dnshostname","operatingsystem")

# Depois servidores (excluindo workstations) — por nome ou OU
$servers = Invoke-LDAPQuery -filter "(&(objectCategory=computer)(operatingSystem=*Server*))" `
    -properties @("dnshostname","operatingsystem","lastlogon")
```

### Eventos Específicos Gerados por Cada Ferramenta

```
EVENTOS DE DESCOBERTA LOCAL (sem tráfego de rede):
- Sysmon Event 1 (Process Create): ipconfig, arp, route, netstat, whoami, net.exe
  Campos: Image, CommandLine, User, ParentImage
  Regra de detecção: CommandLine contains "domain" AND Image = "net.exe"

EVENTOS DE CONSULTA LDAP:
- Event 4662 (Object Operation): toda leitura de atributos LDAP
  Campos: ObjectDN, ObjectType, AccessMask, SubjectUserName
  Regra: múltiplos 4662 em < 60s do mesmo usuário = enumeração

EVENTOS DE ACESSO A SHARE:
- Event 5145 (Network Share Access): toda conexão SMB a share
  Campos: ShareName, RelativeTargetName, IpAddress
  Regra: ShareName = IPC$ + múltiplos hosts = enumeração SMB

EVENTOS DE AUTENTICAÇÃO EM HOSTS REMOTOS:
- Event 4624 Type 3 (Network Logon): conexão autenticada via rede
  Regra: mesmo usuário autenticando em 10+ hosts em 5 min = lateral movement

DETECÇÃO PELO MICROSOFT DEFENDER FOR IDENTITY:
- "Reconnaissance using LDAP queries" — quando ADSISearcher/ldapsearch faz queries em massa
- "Account enumeration reconnaissance" — quando net group /domain é chamado várias vezes
- "Network mapping reconnaissance (DNS)" — consultas DNS em massa para hosts internos
- "User and IP address reconnaissance (SMB)" — NetSessionEnum em múltiplos hosts
```

### Mitigações do Lado Defensivo

Para blue teamers que precisam entender o que detectar:

```
1. RESTRINGIR NETSESSIONENUM:
   - KB2871997: muda visibilidade padrão de sessões remotas
   - RestrictRemoteSAM: limitar quem pode chamar NetSamrEnumerateAliasesInDomain
   - Configurar via GPO: Network access: Restrict clients allowed to make remote calls to SAM

2. AUDITAR ACESSO LDAP:
   - Habilitar "Directory Service Access" em Domain Controller Policy
   - Criar SACL no objeto de domínio para auditar reads em massa
   - Usar Defender for Identity para correlacionar padrões de query

3. MONITORING DE EXECUTÁVEIS:
   - Sysmon com regras para nltest.exe /domain_trusts (T1482)
   - Alertar em: net.exe com argumentos "group", "user" + "/domain"
   - PowerShell Script Block Logging para detectar [ADSISearcher] em scripts

4. NETWORK DETECTION:
   - IDS/NDR para detectar port scan (múltiplas SYN em sequência para IPs diferentes)
   - NetFlow analysis para detectar beacon/sweep pattern
   - DNS Query analysis: muitas queries NX_DOMAIN (hosts inexistentes) = recon
```

---

## Módulos Relacionados

`09_active_directory/08_bloodhound_e_enumeracao.md` é o passo seguinte — SharpHound/BloodHound/PowerView consomem os dados que este recon identifica (lista de hosts, DCs, servidores). `01_enumeracao_e_situational_awareness.md` traz o contexto de onde começa o recon (imediatamente após acesso inicial). `02_escalada_de_privilegio.md` é frequentemente necessária pra executar recon mais aprofundado (NetSessionEnum requer admin local). `08_movimentacao_lateral/01_lateral_movement_windows.md` é o passo subsequente — alvos identificados aqui alimentam Pass-the-Hash, Pass-the-Ticket. `03_credenciais_windows.md` é o objetivo natural — sessão de Domain Admin identificada é alvo de credential harvesting. MITRE ATT&CK: T1018, T1046, T1016, T1049, T1069, T1087, T1482.

---

## Leitura Complementar

- CrackMapExec — https://github.com/byt3bl33d3r/CrackMapExec
- Impacket — https://github.com/fortra/impacket
- PingCastle — https://www.pingcastle.com/
- AD Explorer (Sysinternals) — https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer
- LOLBAS Project — https://lolbas-project.github.io/
- KB2871997 (NetSessionEnum restrictions) — https://support.microsoft.com/en-us/topic/kb2871997
