---
layout: writeup
title: Alquymia CTF 2023
platform: ctf
difficulty: ctf
os: linux
---

Evento | Ano | Dificuldade | 📅 Data
:--:|:--:|:--:|:--:
Alquymia CTF | 2023 | Variada | 2023

## Desafios de Jogos

### Chegue a 1000! — 10pts

Desafio web com um jogo em JavaScript. O placar é controlado por uma variável no frontend.

```js
// No console do navegador:
score = 1000
```

Ao atingir 1000 pontos, a flag é revelada.

**Flag:** `ALQ{GameOver}`

---

### 25% — 50pts

Binário fornecido. Análise com `radare2` e `strings` revela a flag diretamente nos dados do executável.

```bash
strings chall | grep ALQ
```

**Flag:** `ALQ{TMC_END}`

---

### Adivinhação — 100pts

Binário que exige uma resposta correta. `strings` revela um valor codificado em **base58**. Decodificando via CyberChef:

```
Base58 → string legível → flag
```

**Flag:** `ALQ{responde_perguntas}`

---

### Pong — 200pts

Aplicação web. Fuzzing com `feroxbuster` revela diretório `/mobile` não documentado. O JS da página contém a flag em cadeia de encodings:

```bash
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# /mobile encontrado

# No JS: base64 → base32 → flag
echo "base64string" | base64 -d | base32 -d
```

**Flag:** `ALQ{jogo_mobile_pong}`

---

## Desafios de Mini Web

### Login Básico — 10pts

Inspeção do código-fonte da página de login revela a flag em comentário HTML ou variável JS exposta.

**Flag:** `ALQ{Web_e_facil}`

---

### Login Exposto — 50pts

Formulário de login vulnerável a brute force. Após autenticar, comentário HTML no dashboard expõe a flag.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "..."
```

**Flag:** `ALQ{COMENTARIO_do_SIMPLE}`

---

### Em desenvolvimento — 100pts

API REST com vulnerabilidade de **IDOR**. O `user_id` do usuário autenticado vaza na resposta. Trocando pelo ID de outro usuário:

```bash
curl -H "Authorization: Bearer <token>" http://api/user/1
# Resposta vaza user_id de outros usuários
curl -H "Authorization: Bearer <token>" http://api/user/0
```

**Flag:** `ALQ{API_vuln}`

---

### Simple Search — 200pts

Campo de busca vulnerável a **command injection**. Wordlist LFI-Jhaddix via Burp Intruder para identificar o payload correto:

```bash
# Burp Intruder com LFI-Jhaddix.txt
# Payload: ; id ; ou similar
# RCE confirmado → flag no sistema de arquivos
```

**Flag:** `ALQ{INJECAO_command3r}`

---

## Desafios de Outros

### Um código estranho — 10pts

Texto codificado em múltiplas camadas. Análise com CyberChef:

```
ASCII85 → hex decode → base62 → flag
```

**Flag:** `ALQ{S0LDIER}`

---

### Breaking The Air — 50pts

Arquivo `.cap` de captura Wi-Fi fornecido. Cracking com `aircrack-ng` usando `rockyou.txt`:

```bash
aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt
```

**Flag:** `ALQ{greeneggsandham}`

---

### Um professor de férias — 100pts

Engenharia social / análise de e-mail. Endereço de e-mail da vítima configurado com **auto-reply** revelando informações. O auto-reply contém ou aponta para um arquivo `.xlsm`. Extração de macro do Excel:

```bash
# Extrair macro do .xlsm (zip)
unzip professor.xlsm -d macro_extracted
# Ler VBA em xl/vbaProject.bin
strings vbaProject.bin | grep ALQ
```

**Flag:** `ALQ{Exc3l_e_legal}`

---

### Na Deep Web — 200pts

Desafio multi-etapa com esteganografia e análise de áudio:

1. **Arquivo BMP corrompido** — header inválido. Corrigir magic bytes para `42 4D`:
```bash
printf '\x42\x4D' | dd of=imagem.bmp bs=1 count=2 conv=notrunc
```

2. **OpenStego** — extrair arquivo oculto na imagem corrigida:
```bash
openstego extract -sf imagem.bmp -p "" -xf extraido.zip
```

3. **zip protegido** — cracking com `zip2john` + `john`:
```bash
zip2john extraido.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

4. **Arquivo de áudio** — análise de espectrograma no Audacity ou Sonic Visualiser revela a flag visualmente.

**Flag:** `ALQ{ME-ESCUTE}`
