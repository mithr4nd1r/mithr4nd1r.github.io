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

---

## Desafios de Reverse

### APK — 10pts

APK fornecido. Descompilado com `apktool`, depois `strings` para localizar a flag.

```bash
apktool d chall.apk -o out/
strings -r out/ | grep ALQ
```

**Flag:** `ALQ{R3verse_@PK}`

---

### Hexdump — 50pts

Arquivo com hexdump de programa assembly. Conteúdo colado no CyberChef para limpeza. Análise do código assembly via ChatGPT revela que o programa imprime os dados da seção `.data` — valor `ALQ{Reverse_in_hex}`.

**Flag:** `ALQ{Reverse_in_hex}`

---

### Sequência Matemática — 100pts

Binário que exige entrada numérica. Nome do desafio sugere sequência matemática. Testando Fibonacci sequencialmente (1, 1, 2, 3, 5…) até o valor 82 libera a flag.

**Flag:** `ALQ{FIBONACCI}`

---

### Malware — 200pts

Binário `malware_c2` fornecido. `strings` revela a flag diretamente.

```bash
strings malware_c2
```

**Flag:** `ALQ{Foorense_investiga_porta}`

---

## Desafios de Forense

### Uma carta de amor — 10pts

Arquivo de imagem fornecido. `exiftool` revela string em base32 nos metadados:

```
IFGFC63BNVXXEX3QMVZGMZLJORXX2CQ=
```

Decodificado via CyberChef (From Base32).

**Flag:** `ALQ{amor_perfeito}`

---

### Convite para Evento — 50pts

Arquivo de convite fornecido. Texto da flag estava presente mas com cor idêntica ao fundo. Bastou alterar a cor da fonte para revelar.

**Flag:** `ALQ{KAZAM-EMAIL}`

---

### Uma investigação delicada — 100pts

Dump de pendrive fornecido. Análise com Autopsy extrai arquivo `.7z` oculto. Senha `123456` descomprime o arquivo com a flag.

```bash
# Autopsy → File Analysis → export .7z
7z x arquivo.7z  # senha: 123456
```

**Flag:** `ALQ{foorense_the_best}`

---

### Um Dump de Memória — 200pts

Dump de memória fornecido. `strings` com `less` para navegação revela string em base64. Decodificada via CyberChef.

```bash
strings memory_dump.271 | less
# Base64 → decode → flag
```

**Flag:** `ALQ{REVERSE_memory}`

---

## Desafios de OSINT

### Um lugar romântico — 10pts

Foto fornecida. Busca reversa via Google Imagens identifica o local: Rothenburg ob der Tauber, Alemanha.

**Flag:** `ALQ{ROTHENBURG OB DER TAUBER}`

---

### Uma vaga lembrança — 50pts

Site `carros.pt` extinto. Busca no Wayback Machine com data de maio de 2010 → post encontrado exibe o usuário das publicações.

**Flag:** `ALQ{ADMIN}`

---

### Carro Suspeito — 100pts

Placa Mercosul fornecida em imagem. Consulta no site "Olho no Carro" retorna modelo, ano e marca.

**Flag:** `ALQ{VOYAGE-2016-VOLKSWAGEN}`

---

## Desafios de Criptografia

### Simple Cripto — 10pts

Texto cifrado por substituição por deslocamento (ROT). CyberChef para ROT inicial, mas caracteres especiais exigiram brute force completo via `dcode.fr` com tabela ASCII.

**Flag:** `ALQ{roda_roda_roda}`

---

### Medium Cripto — 50pts

Cifra Caesar implementada em C fornecida. Texto cifrado: `XIN{ZOFMQLZOFMQL}`. Script Python de brute force sobre todas as 26 chaves revela o plaintext na chave 23.

```python
ciphertext = "XIN{ZOFMQLZOFMQL}"
for key in range(26):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            plaintext += chr((ord(c) - key - base) % 26 + base)
        else:
            plaintext += c
    print(f"Key {key}: {plaintext}")
# Key 23: ALQ{CRIPTOCRIPTO}
```

**Flag:** `ALQ{CRIPTOCRIPTO}`

---

### Vazamento de API — 100pts

JSON com parâmetros AES-256-CBC vazados (`key`, `iv`, `ciphertext`). Primeiro conjunto de parâmetros descriptografado via ferramenta online de AES.

**Flag:** `ALQ{Cripto_is_cripto}`

---

### Nem sempre o que parece é! — 200pts

Arquivo `cripto.txt`: `U2FsdGVkX19t3DveqApSjK8H/qOPL4o1S0hhJ4Y7x/ATxj4=`. Dica do CTF: ano 1987, cifra com duas letras e um número → RC4. Ferramenta online de RC4 decriptografa.

**Flag:** `ALQ{RC4_Encriptado}`

---

## Desafios de Esteganografia

### Um pinguim solitário — 10pts

Imagem PNG fornecida. AperiSolve analisa as camadas de cor e revela a flag visualmente nas camadas de bits.

**Flag:** `ALQ{stego_easy}`

---

### Café da manhã — 50pts

Imagem PNG. `zsteg` revela a flag no canal `b1,rgb,lsb,xy`.

```bash
zsteg stego_2.png
# b1,rgb,lsb,xy .. text: "ALQ{UM_Lug4r}"
```

**Flag:** `ALQ{UM_Lug4r}`

---

### Uma sequência de cores — 100pts

Imagem com dado escondido no MSB. StegSolve analisa o bit mais significativo e extrai texto que, montado, forma a flag.

```bash
java -jar StegSolve-1.4.jar
# Bit Plane → MSB → salvar texto → montar flag
```

**Flag:** `ALQ{TextPRAImaG3m}`

---

### Joia do Tempo — 200pts

Imagem PNG. Enunciado menciona "diamante, esmeralda e turmalinas" — três senhas. OpenPuff exige exatamente 3 senhas para extrair dado oculto.

**Flag:** `ALQ{Stego_Puff1}`
