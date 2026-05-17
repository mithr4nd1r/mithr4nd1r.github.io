---
layout: cyber
section: injecao-processo
title: "PE Format e Parsing Manual"
---

# 05 - PE Format e Parsing Manual

> Portable Executable é o formato base de `.exe`, `.dll`, `.sys`, `.scr` no Windows. Conhecer cada header + parsing manual é pré-requisito para: reflective loading, IAT hiding, manual mapping, sRDI, process hollowing, herpaderping, function stomping. Fonte: MalDev Academy módulos 8 + 50.

---

## Por Que Parsing Manual

EDRs hookam `LoadLibrary` / `GetProcAddress`. Para evadir:
- Resolver APIs via parsing manual do PEB → loaded modules → export table
- Reflective DLL injection — carregar DLL sem `LoadLibrary`
- Manual mapping — alocar memória, copiar sections, processar relocations, resolver imports, executar entrypoint
- IAT hiding — armazenar hash em vez de string da API; resolver em runtime

Todos esses workflows requerem parsing manual da estrutura PE.

---

## Estrutura PE — Layout Completo

```
+-------------------------+
| DOS Header (MZ)         |  ← IMAGE_DOS_HEADER (offset 0)
+-------------------------+
| DOS Stub                |  ← "This program cannot be run in DOS mode"
+-------------------------+
| NT Header (PE)          |  ← IMAGE_NT_HEADERS (offset = e_lfanew)
|   - Signature           |
|   - FileHeader          |  ← IMAGE_FILE_HEADER
|   - OptionalHeader      |  ← IMAGE_OPTIONAL_HEADER
|     - DataDirectory[16] |  ← array de IMAGE_DATA_DIRECTORY
+-------------------------+
| Section Headers         |  ← IMAGE_SECTION_HEADER[NumberOfSections]
+-------------------------+
| Section Data            |  ← .text, .data, .rdata, .rsrc, .reloc, etc.
+-------------------------+
```

---

## RVA — Relative Virtual Address

RVA = offset de 32 bits a partir do **base address** do módulo carregado. Permite que o mesmo PE seja carregado em endereços diferentes sem reescrita.

```
VA = ImageBase + RVA
```

Quase todo ponteiro dentro do PE é RVA, não VA. Confundir os dois = crash imediato.

---

## DOS Header — IMAGE_DOS_HEADER

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;       // "MZ" = 0x5A4D (IMAGE_DOS_SIGNATURE)
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;      // offset → IMAGE_NT_HEADERS (sempre @ 0x3C)
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

Membros que importam:
- `e_magic` = `0x5A4D` (string "MZ") — sanity check de PE válido
- `e_lfanew` = offset (a partir do base) para `IMAGE_NT_HEADERS`

Retrieval:

```c
PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
    return -1;
}
```

---

## NT Header — IMAGE_NT_HEADERS

Wraps `FileHeader` + `OptionalHeader`. Signature = `0x00004550` ("PE\0\0").

### Struct (depende da arch)

```c
// 32-bit
typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// 64-bit
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

### Retrieval

```c
PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {  // 0x00004550
    return -1;
}
```

---

## File Header — IMAGE_FILE_HEADER

```c
IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;
```

Membros:

| Campo | Significado |
|-------|-------------|
| `Machine` | Arch alvo (0x8664 = AMD64, 0x14C = i386) |
| `NumberOfSections` | Quantas sections no PE |
| `TimeDateStamp` | Timestamp de compile |
| `PointerToSymbolTable` | Offset symbol table (raramente presente) |
| `NumberOfSymbols` | Count symbols |
| `SizeOfOptionalHeader` | Sizeof do OptionalHeader (32 vs 64 bit) |
| `Characteristics` | Flags `IMAGE_FILE_*` — `EXECUTABLE_IMAGE`, `DLL`, etc. |

---

## Optional Header — IMAGE_OPTIONAL_HEADER

Apesar do nome, é **obrigatório**. Contém info crítica de runtime.

```c
IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
    return -1;
}
```

Magic depende da arch:
- `IMAGE_NT_OPTIONAL_HDR32_MAGIC` = 0x10B
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC` = 0x20B

Membros críticos:

| Campo | Significado |
|-------|-------------|
| `Magic` | 32-bit vs 64-bit identifier |
| `MajorLinkerVersion` / `MinorLinkerVersion` | Versão do linker (signature defensivo) |
| `SizeOfCode` | Tamanho da seção .text |
| `SizeOfInitializedData` | .data |
| `SizeOfUninitializedData` | .bss |
| `AddressOfEntryPoint` | **RVA** do entrypoint (DllMain / main) |
| `BaseOfCode` | RVA do início da .text |
| `ImageBase` | Endereço **preferido** de carga (ASLR pode override) |
| `MajorOperatingSystemVersion` | OS min req |
| `MajorImageVersion` | Versão do binário |
| `DataDirectory[16]` | **Array de 16 IMAGE_DATA_DIRECTORY** — chave para tudo |

---

## Data Directory — IMAGE_DATA_DIRECTORY

Array de 16 entradas no `OptionalHeader.DataDirectory[]`. Cada entrada aponta para uma estrutura especial.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;   // RVA da estrutura
    DWORD   Size;             // tamanho em bytes
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

### Índices Importantes

```c
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Table
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Address Table (IAT)
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // .rsrc — icons, strings, manifests
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // .pdata
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Authenticode signature
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base relocations (.reloc)
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS callbacks (anti-debug)
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // .NET CLR header
```

### Acesso

```c
IMAGE_DATA_DIRECTORY ExpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
// ExpDataDir.VirtualAddress = RVA do IMAGE_EXPORT_DIRECTORY
// ExpDataDir.Size           = tamanho da export table
```

---

## Export Table — IMAGE_EXPORT_DIRECTORY

**Não oficialmente documentado** pela Microsoft, mas obrigatório para resolução manual de funções exportadas (GetProcAddress sem hookable API).

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;                    // RVA da string com nome da DLL
    DWORD   Base;                    // ordinal base
    DWORD   NumberOfFunctions;       // contagem de funções exportadas
    DWORD   NumberOfNames;           // contagem de nomes
    DWORD   AddressOfFunctions;      // RVA → array de RVAs das funções
    DWORD   AddressOfNames;          // RVA → array de RVAs de nomes
    DWORD   AddressOfNameOrdinals;   // RVA → array de ordinais
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

### Retrieval

```c
PIMAGE_EXPORT_DIRECTORY pImgExportDir =
    (PIMAGE_EXPORT_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
```

### Membros Críticos

- `NumberOfFunctions` — total de exports (alguns podem ser ordinal-only)
- `NumberOfNames` — total com nomes (≤ NumberOfFunctions)
- `AddressOfFunctions` — array de RVAs apontando para o código de cada função
- `AddressOfNames` — array paralelo de RVAs apontando para C-strings com nomes
- `AddressOfNameOrdinals` — array paralelo de WORDs com índice em AddressOfFunctions

### Resolução Manual de Função (GetProcAddress Replacement)

```c
// Resolver "MessageBoxW" em USER32.dll
HMODULE hMod = LoadLibraryA("user32.dll");  // ou via PEB walk se LoadLibrary hookado
PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod +
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

DWORD* names    = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
DWORD* funcs    = (DWORD*)((BYTE*)hMod + pExp->AddressOfFunctions);
WORD*  ordinals = (WORD*) ((BYTE*)hMod + pExp->AddressOfNameOrdinals);

for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
    char* funcName = (char*)((BYTE*)hMod + names[i]);
    if (strcmp(funcName, "MessageBoxW") == 0) {
        FARPROC fn = (FARPROC)((BYTE*)hMod + funcs[ordinals[i]]);
        // fn = ponteiro para MessageBoxW resolvido sem GetProcAddress
        break;
    }
}
```

OPSEC: trocar `strcmp(funcName, "MessageBoxW")` por comparação de hash (string hashing) → string `"MessageBoxW"` não aparece no binário compilado.

---

## Import Address Table — IMAGE_IMPORT_DESCRIPTOR

Array terminado em estrutura toda-zero. Cada entrada = uma DLL importada.

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;   // RVA → IMAGE_THUNK_DATA[] (INT — Import Name Table)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;                     // RVA → C-string com nome da DLL
    DWORD   FirstThunk;               // RVA → IMAGE_THUNK_DATA[] (IAT — Import Address Table)
} IMAGE_IMPORT_DESCRIPTOR;
```

### Retrieval

```c
PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPE +
    ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

while (pImgImpDesc->Name) {
    char* dllName = (char*)(pPE + pImgImpDesc->Name);
    printf("Imports from: %s\n", dllName);

    // Walk THUNK_DATA array
    PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(pPE + pImgImpDesc->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pIAT       = (PIMAGE_THUNK_DATA)(pPE + pImgImpDesc->FirstThunk);

    while (pOrigThunk->u1.AddressOfData) {
        if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
            // Imported by ordinal
            printf("  Ord: %lld\n", pOrigThunk->u1.Ordinal & 0xFFFF);
        } else {
            // Imported by name
            PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)(pPE + pOrigThunk->u1.AddressOfData);
            printf("  Name: %s\n", pByName->Name);
        }
        pOrigThunk++;
        pIAT++;
    }
    pImgImpDesc++;
}
```

OPSEC para malware: zerar/criptografar o IAT no PE → reconstrução em runtime via parsing manual de exports.

---

## Estruturas Adicionais (Undocumented)

### TLS Directory — IMAGE_TLS_DIRECTORY

Thread Local Storage callbacks executam **antes** de `main`/`DllMain`. Usado para anti-debug (módulo MalDev Extra #34).

```c
PIMAGE_TLS_DIRECTORY pImgTlsDir = (PIMAGE_TLS_DIRECTORY)(pPE +
    ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
```

### Runtime Function Entry — IMAGE_RUNTIME_FUNCTION_ENTRY

Tabela de exception handling. Importante para stack walking em x64.

```c
PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRunFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPE +
    ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
```

### Base Relocation — IMAGE_BASE_RELOCATION

Patch list para quando ImageBase preferido não é honrado (ASLR). Manual mapping precisa processar para realocar todos ponteiros absolutos.

```c
PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPE +
    ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
```

Processo de relocation:
```c
// delta = ActualBase - PreferredBase
ULONG_PTR delta = (ULONG_PTR)allocBase - pNt->OptionalHeader.ImageBase;

while (pReloc->VirtualAddress != 0) {
    DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    WORD* entries = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

    for (DWORD i = 0; i < numEntries; i++) {
        WORD type   = entries[i] >> 12;
        WORD offset = entries[i] & 0xFFF;
        if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
            ULONG_PTR* fixup = (ULONG_PTR*)((BYTE*)allocBase + pReloc->VirtualAddress + offset);
            *fixup += delta;
        }
    }
    pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
}
```

---

## PE Sections — IMAGE_SECTION_HEADER

Cada section (.text, .data, .rdata, .reloc, .rsrc, etc.) tem um header com metadata.

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];  // 8 bytes — nome ASCII
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;                 // tamanho em memória
    } Misc;
    DWORD VirtualAddress;                  // RVA na memória
    DWORD SizeOfRawData;                   // tamanho no arquivo (em disco)
    DWORD PointerToRawData;                // offset no arquivo (em disco)
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;                 // flags — IMAGE_SCN_MEM_EXECUTE/READ/WRITE
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

### Sections Padrão

| Nome | Conteúdo | Characteristics típicas |
|------|----------|--------------------------|
| `.text` | Código executável | R-X |
| `.data` | Globais inicializadas (read-write) | RW- |
| `.rdata` | Read-only data (strings, IAT, imports) | R-- |
| `.bss` | Globais não-inicializadas | RW- |
| `.rsrc` | Resources (icons, manifests, strings) | R-- |
| `.reloc` | Base relocations | R-- |
| `.pdata` | Exception unwind info (x64) | R-- |
| `.tls` | TLS callbacks | R-- |

### Retrieval — Primeiro Section Header

Localizado **imediatamente após** o IMAGE_NT_HEADERS:

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)
    (((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
```

### Iteração Sobre Todas Sections

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)
    (((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
    printf("Section [%zu]: %.8s\n", i, pImgSectionHdr->Name);
    printf("  RVA: 0x%lx, Size: 0x%lx, Raw: 0x%lx\n",
           pImgSectionHdr->VirtualAddress,
           pImgSectionHdr->Misc.VirtualSize,
           pImgSectionHdr->SizeOfRawData);
    pImgSectionHdr++;
}
```

---

## Caso de Uso: Manual Mapping (Reflective DLL Load)

PE parsing é pré-requisito para **manual mapping** — carregar DLL sem `LoadLibrary` (que é hookada por EDRs):

```
1. Ler DLL bytes (file/buffer/embedded)
2. Parse DOS + NT + Optional headers
3. VirtualAlloc(SizeOfImage, RWX) — alocar memória contínua
4. Copiar headers + cada section para os RVAs corretos
5. Processar relocations (IMAGE_DIRECTORY_ENTRY_BASERELOC)
   - delta = actualBase - preferredImageBase
   - patch cada relocation entry
6. Resolver imports (IMAGE_DIRECTORY_ENTRY_IMPORT)
   - Para cada DLL importada: LoadLibrary (ou manual)
   - Para cada função: GetProcAddress (ou export walk)
   - Escrever endereço no FirstThunk (IAT)
7. Mudar protections de cada section (VirtualProtect)
   - .text → R-X, .data → RW-, .rdata → R--
8. Executar TLS callbacks (se existirem)
9. Chamar EntryPoint (DllMain com DLL_PROCESS_ATTACH)
```

Modules MalDev relevantes: 28 (DLL injection theory), 29 (shellcode injection), Extra 28 (Local PE injection), Extra 29 (Reflective DLL Injection), Extra 43 (sRDI).

---

## Caso de Uso: IAT Hiding (String Hashing)

Em vez de armazenar `"VirtualAlloc"` como string no binário (detectável estaticamente), armazenar hash e calcular em runtime:

```c
// Compile-time hash
#define HASH_VIRTUALALLOC 0xE553A458   // hash("VirtualAlloc")

DWORD hash_djb2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

FARPROC resolveByHash(HMODULE hMod, DWORD targetHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names    = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
    DWORD* funcs    = (DWORD*)((BYTE*)hMod + pExp->AddressOfFunctions);
    WORD*  ordinals = (WORD*) ((BYTE*)hMod + pExp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)hMod + names[i]);
        if (hash_djb2(funcName) == targetHash) {
            return (FARPROC)((BYTE*)hMod + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

// Uso
HMODULE hKernel = GetModuleHandleA("kernel32.dll");
PFN_VIRTUALALLOC pVA = (PFN_VIRTUALALLOC)resolveByHash(hKernel, HASH_VIRTUALALLOC);
LPVOID buf = pVA(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

Strings sensíveis (`"VirtualAlloc"`, `"WriteProcessMemory"`, `"CreateRemoteThread"`) desaparecem do `strings` output do binário.

---

## Ferramentas para Inspeção

| Ferramenta | Uso |
|------------|-----|
| **PE-bear** | GUI visual — todos headers + sections + import/export hex view |
| **CFF Explorer** | Editor PE — modificar headers, hex edit, signature |
| **dumpbin** | CLI da Microsoft — `dumpbin /headers`, `/imports`, `/exports` |
| **pefile** (Python) | Parsing programático — `pefile.PE("file.exe")` |
| **Detect It Easy (DIE)** | Identificar packer/compiler |
| **PEStudio** | Análise estática + flagging de imports suspeitas |

---

## Módulos Relacionados

`02_tecnicas_classicas_e_avancadas.md` consome o parsing PE em Reflective DLL Injection, Manual Mapping e sRDI. `04_evasao/07_load_time_evasion.md` aprofunda IAT hiding via string hashing e API resolution sem GetProcAddress. `04_evasao/16_pe_packer.md` cobre construção de packer (cifrar sections, unpack stub em runtime). `04_evasao/10_payload_placement.md` lida com payload em `.data`/`.rdata`/`.text`/`.rsrc`.

---

## Leitura Complementar

- MalDev Academy — Module 8 (Portable Executable Format) + Module 50 (Parsing PE Headers)
