---
title: "JavaScript Analysis"
---

# JavaScript Analysis - Análise e Deobfuscação

---

## Contexto: JavaScript como Fonte de Verdade sobre a API da Aplicação

JavaScript é a única parte do back-end que o atacante pode ver. Todo o código que processa dados no servidor é invisível — mas o código que faz requisições para esse servidor, que constrói as URLs, que gerencia tokens de autenticação e que contém a lógica de validação do lado cliente: tudo isso está disponível para análise direta.

**Por que segredos aparecem em JS — a causa raiz:**

A causa raiz de secret exposure em JavaScript é conceitual: desenvolvedores não percebem (ou esquecem) que código front-end é público. Não é código que fica no servidor — é código que o servidor *envia para o browser do usuário*. Qualquer arquivo `.js` carregado pelo browser pode ser lido por qualquer pessoa com DevTools aberto.

As categorias principais de secret exposure em JavaScript são quatro. API keys hardcoded são chaves de serviços de terceiros como Stripe, Twilio, SendGrid e AWS inseridas diretamente no código porque "é mais fácil que usar variáveis de ambiente". Endpoints internos são URLs de APIs que o time de desenvolvimento acredita serem "segredos" — como `http://internal-api:8080/v2/admin/` — mas que ficam visíveis em qualquer bundle JS. Lógica de negócio refere-se a validações implementadas apenas em JS que assumem que o servidor vai rejeitar qualquer coisa inválida, quando na prática o servidor não revalida. Credenciais de ambiente são variáveis do tipo `REACT_APP_*` injetadas em build time que ficam literalmente no bundle JS em texto claro.

Do ponto de vista de prevenção: qualquer valor que, se exposto, permite acesso não autorizado a sistemas ou dados — API keys, tokens de acesso, URLs de endpoints internos, credenciais de banco em casos extremos — nunca deve ser injetado em código front-end. API keys de terceiros com acesso privilegiado devem ser proxiadas pelo back-end, nunca expostas ao browser.

**JS como mapa da API:**

Análise de JavaScript permite descobrir endpoints de API não documentados — frequentemente mais vulneráveis que os documentados — e encontrar chaves de API, tokens e credenciais hardcoded. Também possibilita entender o fluxo de autenticação para identificar bypasses, detectar bibliotecas com CVEs conhecidos, mapear completamente a aplicação em termos de URLs, parâmetros e funções, e compreender a lógica de validação do lado cliente para contorná-la.

Código JS obfuscado não oferece proteção real — é apenas ofuscação. Com as ferramentas certas, deobfuscar é questão de minutos.

---

## Localização de Arquivos JavaScript e Tipos de Código

### Onde Encontrar JavaScript

```html
<!-- JS inline no HTML -->
<script>
var apiKey = "sk-live-abc123";
var endpoint = "/api/v2/internal/users";
</script>

<!-- JS externo (arquivo separado) -->
<script src="/static/js/app.js"></script>
<script src="/static/js/chunk-vendors.abc123.js"></script>
<script src="https://cdn.site.com/bundle.min.js"></script>

<!-- JS em atributos HTML (event handlers) -->
<button onclick="validateToken(document.getElementById('token').value)">Submit</button>
<form onsubmit="return checkAuth(this)">
```

**Como identificar arquivos JS de uma aplicação:**

```bash
# Buscar tags script no HTML
curl -s https://target.com | grep -oP 'src="[^"]+\.js[^"]*"' | sort -u

# Buscar em código fonte
curl -s https://target.com | grep -E '<script'

# No Burp Suite: Target -> Site Map -> filtrar por extensão .js
# No DevTools: Network tab -> JS filter

# Ferramenta automática (gau + filtro)
gau target.com | grep "\.js$" | sort -u

# Waybackurls + filtro
waybackurls target.com | grep "\.js" | sort -u
```

### Tipos de Código JavaScript

**Código limpo (não processado):**
```javascript
// Fácil de ler, variáveis com nomes descritivos
function checkLogin(username, password) {
    if (username === 'admin' && password === 'SuperSecret123') {
        window.location.href = '/dashboard';
    } else {
        alert('Invalid credentials');
    }
}
```

**Código minificado:**
```javascript
// Funcional, mas comprimido — sem whitespace, nomes curtos
function checkLogin(u,p){if(u==='admin'&&p==='SuperSecret123'){window.location.href='/dashboard'}else{alert('Invalid credentials')}}
```

**Código obfuscado (packer):**
```
// Padrão p,a,c,k,e,d - ilegível mas pode ser deobfuscado via UnPacker
// eval() + função de decodificação inline — código fonte escondido dentro
```

---

## Na Prática

### Beautification (Formatação)

Primeiro passo: tornar o código legível com formatação adequada.

**Browser DevTools:**

```
1. Abrir DevTools (F12)
2. Aba Sources
3. Localizar arquivo .js
4. Clicar no botão { } (Pretty-print) na barra inferior
5. Código é formatado com indentação adequada
6. Usar Ctrl+F para buscar: "api", "key", "secret", "password", "token", "url"
```

**Prettier - Formatador online:**
```
https://prettier.io/playground/
```

**Beautifier.io:**
```
https://beautifier.io/
```

**CLI com Prettier:**
```bash
# Instalar
npm install -g prettier

# Formatar arquivo
prettier --write app.js
prettier --parser babel app.min.js > app_pretty.js
```

**js-beautify:**
```bash
# Instalar
npm install -g js-beautify

# Uso
js-beautify app.min.js > app_pretty.js
js-beautify -o app_pretty.js app.min.js

# Com opções
js-beautify --indent-size 4 --end-with-newline app.min.js
```

### Minificação vs Obfuscação

| Técnica | Objetivo | Revertível? | Impacto em Performance |
|---------|----------|-------------|----------------------|
| **Minificação** | Reduzir tamanho (remover whitespace, comentários) | Sim (beautify) | Melhora load time |
| **Obfuscação** | Dificultar leitura (renomear vars, encoding) | Parcialmente | Pode piorar |
| **Packing** | Comprimir + ofuscar (decodificação em runtime) | Sim (UnPacker) | Overhead de decode |
| **Advanced** | JJEncode, AAEncode, strings base64 | Com ferramentas específicas | Alto overhead |

### Obfuscação com obfuscator.io

Site para ofuscar código JS: `https://obfuscator.io`

**Técnicas disponíveis:**
- **String Array**: Strings são colocadas em array com índices numéricos
- **Dead Code Injection**: Código inútil inserido para confundir
- **Control Flow Flattening**: Estrutura de controle embaralhada
- **Numbers to Expressions**: `1` -> `0x1` ou `(+!+[]+!+[])`
- **Domain Lock**: Código só executa em domínio específico

**Exemplo de transformação:**

```javascript
// Original
console.log("Hello, World!");
var apiKey = "sk-live-abc123";
fetch('/api/users/' + userId);

// Após obfuscation (String Array)
// Strings ficam em array _0x3f2a, referenciadas por índice
// Nomes de funções e variáveis substituídos por _0xXXXX
// Strings originais ainda presentes no array mas embaralhadas
```

### Packing - Padrão p,a,c,k,e,d

O packer mais comum encapsula o código em uma função com parâmetros `p,a,c,k,e,d`:

```
Identificação: código começa com a sequência eval(function(p,a,c,k,e,d)
```

**Deobfuscação de packer:**

**UnPacker online:** `https://matthewfl.com/unPacker.html`
1. Colar o código obfuscado
2. Clicar em UnPack
3. Código fonte deobfuscado aparece

**Método manual via DevTools:**
```
1. Copiar o código obfuscado
2. No DevTools Console, substituir a chamada de execução por console.log()
3. O decodificador interno executa e retorna o código original como string
4. Copiar o resultado e formatar com js-beautify
```

### Técnicas de Obfuscação Avançadas

**JJEncode**

Usa apenas os caracteres `j`, `J`, `+`, `(`, `)`, `[`, `]`, `;`, `=`, `"`, `'`, `,`:

```
Identificação: código começa com $=~[] ou similar, usa apenas caracteres especiais
Deobfuscação: https://www.jj2.link/ — colar código e decodificar
```

**AAEncode**

Usa emoticons/caracteres japoneses para representar código:

```
Identificação: presença de caracteres como ﾟωﾟﾉ, ﾟΘﾟ, ﾟｰﾟ
Deobfuscação: https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html
```

### Encoding em JavaScript

**Base64:**

```javascript
// Encoding
btoa("Hello World")          // "SGVsbG8gV29ybGQ="
btoa("admin:password123")    // "YWRtaW46cGFzc3dvcmQxMjM="

// Decoding
atob("SGVsbG8gV29ybGQ=")    // "Hello World"
atob("YWRtaW46cGFzc3dvcmQxMjM=")  // "admin:password123"

// Identificação: caracteres alfanuméricos + / e = no final
// Tamanho sempre múltiplo de 4
```

```bash
# CLI Linux
echo -n "admin:password123" | base64    # YWRtaW46cGFzc3dvcmQxMjM=
echo "YWRtaW46cGFzc3dvcmQxMjM=" | base64 -d  # admin:password123

# Python
python3 -c "import base64; print(base64.b64decode('YWRtaW46cGFzc3dvcmQxMjM=').decode())"
```

**Hex Encoding:**

```javascript
// Encoding (string to hex)
"admin".split('').map(c => c.charCodeAt(0).toString(16)).join('')
// "61646d696e"

// Em strings JS obfuscadas hex aparece como:
// "\x61\x64\x6d\x69\x6e" === "admin"
// 0x61 === 97 === 'a'
```

```bash
# CLI
echo "61646d696e" | xxd -r -p    # admin
echo -n "admin" | xxd -p          # 61646d696e

# Python
python3 -c "print(bytes.fromhex('61646d696e').decode())"
```

**ROT13:**

```bash
# CLI
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # Hello
echo "Hello" | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # Uryyb

# Python
python3 -c "import codecs; print(codecs.decode('Uryyb', 'rot_13'))"
```

---

## Exemplos

### Workflow Completo de Análise JS

```bash
TARGET="https://target.com"

# 1. Extrair todos os arquivos JS
curl -s $TARGET | grep -oP 'src="[^"]+\.js[^"]*"' | \
    sed 's/src="//g;s/"//g' | \
    while read path; do
        if [[ $path == http* ]]; then
            echo $path
        else
            echo "$TARGET$path"
        fi
    done > js_files.txt

# 2. Baixar todos os arquivos JS
mkdir -p js_analysis
cat js_files.txt | while read url; do
    filename=$(echo $url | md5sum | cut -d' ' -f1).js
    curl -s "$url" -o "js_analysis/$filename"
    echo "$filename <- $url" >> js_analysis/index.txt
done

# 3. Buscar por secrets e endpoints
grep -r "api_key\|apiKey\|api-key\|secret\|password\|token\|credential" js_analysis/ --include="*.js"
grep -r "/api/\|/v1/\|/v2/\|/internal/" js_analysis/ --include="*.js"

# 4. Buscar por endpoints de API (padrões comuns)
grep -roP '(/[a-z0-9_-]+){2,}' js_analysis/ | grep -v "node_modules" | sort -u

# 5. Buscar configurações específicas
grep -r "AWS_ACCESS\|AWS_SECRET\|STRIPE_\|SENDGRID_\|TWILIO_" js_analysis/
grep -r "BEGIN RSA\|BEGIN PRIVATE KEY" js_analysis/
```

### Busca em DevTools (Sources Tab)

```
1. Abrir DevTools -> Sources -> Page
2. Localizar main.js ou bundle.js
3. Clicar { } para pretty-print
4. Ctrl+F para buscar:
   - "api"        -> endpoints de API
   - "key"        -> chaves de API
   - "secret"     -> segredos
   - "password"   -> senhas hardcoded
   - "token"      -> tokens de auth
   - "url"        -> URLs hardcoded
   - "internal"   -> endpoints internos
   - "admin"      -> funcionalidades de admin
   - "debug"      -> modo debug
   - "test"       -> código de teste esquecido
   - "TODO"       -> comentários com hints
   - "FIXME"      -> bugs conhecidos
   - "http"       -> URLs hardcoded
```

### Deobfuscar String Array - Passo a Passo

**Cenário: encontrar credenciais em código obfuscado**

```javascript
// Código encontrado (obfuscado com string array)
var _0x1a2b=['user','pass','admin','S3cr3tP@ss'];
var _0x3c4d=function(_0x5e6f){return _0x1a2b[_0x5e6f-0x1f4]};
if(document.getElementById(_0x3c4d(0x1f4)).value===_0x3c4d(0x1f6)&&
   document.getElementById(_0x3c4d(0x1f5)).value===_0x3c4d(0x1f7)){
    // login success
}
```

**Passos de deobfuscação:**

```javascript
// 1. Identificar o array de strings
// var _0x1a2b = ['user', 'pass', 'admin', 'S3cr3tP@ss'];
//                  [0]     [1]      [2]         [3]

// 2. Calcular os índices (0x1f4 = 500 decimal)
// _0x3c4d(0x1f4) -> _0x1a2b[500 - 500] -> _0x1a2b[0] -> 'user'
// _0x3c4d(0x1f5) -> _0x1a2b[501 - 500] -> _0x1a2b[1] -> 'pass'
// _0x3c4d(0x1f6) -> _0x1a2b[502 - 500] -> _0x1a2b[2] -> 'admin'
// _0x3c4d(0x1f7) -> _0x1a2b[503 - 500] -> _0x1a2b[3] -> 'S3cr3tP@ss'

// 3. Código deobfuscado:
if(document.getElementById('user').value === 'admin' &&
   document.getElementById('pass').value === 'S3cr3tP@ss') {
    // login success
}
// Credenciais encontradas: admin / S3cr3tP@ss
```

### Analisar XMLHttpRequest (XHR)

```javascript
// Código JS que faz requisições ao back-end
// Analisar para descobrir endpoints, parâmetros e lógica

// Padrão antigo (XHR)
var xhr = new XMLHttpRequest();
xhr.open("POST", "/api/v2/auth/login", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.setRequestHeader("X-API-Key", "live_key_abc123def456");
// ACHADO: chave de API hardcoded no código!
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
        var response = JSON.parse(xhr.responseText);
        localStorage.setItem("auth_token", response.token);
        // ACHADO: token JWT salvo em localStorage (sem HttpOnly = vulnerável a XSS)
        window.location.href = "/dashboard";
    }
};
xhr.send(JSON.stringify({
    username: document.getElementById("user").value,
    password: document.getElementById("pass").value
}));

// Resumo de achados:
// Endpoint: POST /api/v2/auth/login
// Header hardcoded: X-API-Key: live_key_abc123def456
// Token armazenado: localStorage['auth_token'] (acessível via XSS)
```

```javascript
// Padrão moderno (Fetch API)
fetch('/api/internal/admin/users', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('auth_token'),
        'X-Internal-Key': 'internal_secret_do_not_share'
        // ACHADO: segredo hardcoded no código cliente!
    }
})
.then(response => response.json())
.then(data => renderAdminPanel(data));

// Achados:
// Endpoint interno: GET /api/internal/admin/users
// Header secreto necessário: X-Internal-Key: internal_secret_do_not_share
```

### Source Maps - Recuperar Código Original

Source maps mapeiam código minificado/transpilado de volta ao código fonte original (TypeScript, ES6+).

```bash
# Verificar se source map está exposto
curl -s https://target.com/static/js/app.js | tail -1
# //# sourceMappingURL=app.js.map

# Download do source map
curl -s https://target.com/static/js/app.js.map -o app.js.map

# Source maps revelam:
# - Código TypeScript/React/Vue original
# - Nomes de arquivos e estrutura de diretórios
# - Comentários e código de desenvolvimento

# Ferramenta para reconstruir source do map
npm install -g source-map-explorer
source-map-explorer app.js app.js.map

# Inspecionar manualmente (source map é JSON)
python3 -c "
import json, sys
with open('app.js.map') as f:
    sm = json.load(f)
print('Arquivos originais no source map:')
for src in sm.get('sources', []):
    print(' ', src)
"
```

### Análise de Webpack Bundles

Aplicações React/Vue/Angular geram bundles Webpack grandes:

```bash
# Identificar bundle Webpack
curl -s https://target.com | grep -oP 'src="[^"]*chunk[^"]*\.js"'

# Buscar configuração exposta (REACT_APP_* é comum em React)
curl -s https://target.com/static/js/main.abc123.js | \
    grep -oP 'REACT_APP_[A-Z_]+:"[^"]*"' | sort -u

# Output comum:
# REACT_APP_API_URL:"https://api.target.com"
# REACT_APP_STRIPE_KEY:"pk_live_abc123"
# REACT_APP_SENTRY_DSN:"https://key@sentry.io/project"

# Buscar endpoints hardcoded em bundle
curl -s https://target.com/static/js/main.abc123.js | \
    grep -oP '"(/[a-z0-9_/-]{3,})"' | sort -u | head -50
```

### Debugging no DevTools

```
1. DevTools -> Sources -> Localizar arquivo JS
2. Clicar no número da linha para adicionar breakpoint
3. Recarregar página ou interagir com formulário
4. Execução pausa no breakpoint
5. Painel direito:
   - Watch: monitorar variáveis específicas
   - Call Stack: ver cadeia de chamadas
   - Scope: ver todas as variáveis no contexto atual
6. Usar console durante pause:
   > username  -> ver valor atual da variável
   > document.cookie  -> ver cookies
   > localStorage  -> ver storage

# Conditional breakpoint (pausa só se condição for verdadeira)
# Right-click na linha -> Add conditional breakpoint
# Condição: username === "admin"
```

### Ferramentas de Análise JS

```bash
# retire.js - detecta bibliotecas JS com CVEs
npm install -g retire
retire --path ./js_analysis/

# Output:
# app.js
#   jquery 1.12.4 has known vulnerabilities:
#   severity: medium; CVE: CVE-2019-11358
#   severity: high; CVE: CVE-2020-11022

# linkfinder - extrai endpoints de arquivos JS
git clone https://github.com/GerbenJavado/LinkFinder
cd LinkFinder
pip install -r requirements.txt
python linkfinder.py -i https://target.com/static/js/app.js -o cli

# Output:
# /api/v1/users
# /api/v1/products
# /admin/dashboard
# /api/internal/health
# https://api.otherdomain.com/data

# SecretFinder - buscar segredos em JS
git clone https://github.com/m4ll0k/SecretFinder
python SecretFinder.py -i https://target.com/static/js/app.js -o cli
```

### Checklist de Análise JS

```
[ ] Mapear todos os arquivos .js carregados (DevTools -> Network -> JS filter)
[ ] Verificar source maps expostos (arquivo.js.map)
[ ] Beautify/pretty-print todos os arquivos principais
[ ] Buscar por: api_key, apiKey, secret, password, token, credential, auth
[ ] Buscar por endpoints de API: /api/, /v1/, /v2/, /internal/, /admin/
[ ] Analisar código XHR/Fetch para mapear chamadas ao back-end
[ ] Verificar localStorage/sessionStorage no Console
[ ] Buscar por lógica de autenticação condicional
[ ] Verificar bibliotecas com retire.js (CVEs)
[ ] Deobfuscar código se necessário (UnPacker, obfuscator.io)
[ ] Buscar por informações de ambiente: NODE_ENV, REACT_APP_*, VUE_APP_*
[ ] Verificar comentários: TODO, FIXME, HACK, NOTE, DEBUG
[ ] Analisar módulos Webpack expostos (window.webpackJsonp)
```

### Tabela de Referência — Tipos de Encoding

| Encoding | Input | Output | Detecção |
|----------|-------|--------|----------|
| Base64 | `admin` | `YWRtaW4=` | `[A-Za-z0-9+/]+=*` |
| Hex | `admin` | `61646d696e` | `[0-9a-f]+` (comprimento par) |
| ROT13 | `admin` | `nqzva` | Apenas letras deslocadas |
| URL Encode | `<script>` | `%3Cscript%3E` | `%XX` |
| HTML Entities | `<script>` | `&lt;script&gt;` | `&name;` ou `&#num;` |
| Unicode | `A` | `A` | `\uXXXX` |
| Octal | `A` | `\101` | `\ddd` |

---

## Módulos Relacionados

Content Discovery (`02_content_discovery.md`) e análise de JavaScript são complementares: endpoints encontrados em bundles JS são alvos imediatos de fuzzing, e fuzzing às vezes encontra arquivos JS não linkados que revelam ainda mais endpoints. Web App Fundamentos (`../01_fundamentos_web/02_web_app_fundamentos.md`) fornece o contexto de como DOM manipulation e cookies funcionam no navegador, base necessária para interpretar o que o código JS está fazendo. HTTP Protocolo (`../01_fundamentos_web/01_http_protocolo.md`) é relevante porque toda chamada XHR ou Fetch no JS é uma requisição HTTP — entender o protocolo permite decodificar o que cada chamada significa. Web Proxies (`../01_fundamentos_web/03_web_proxies.md`) permitem interceptar essas chamadas XHR no Burp em tempo real, correlacionando o código JS com as requisições que ele gera. Lógica de validação implementada apenas em JS é vetor direto de XSS e de bypass de controles do lado cliente. Endpoints internos descobertos nos bundles são candidatos a SSRF. Chaves de API e credenciais hardcoded em JavaScript constituem Sensitive Data Exposure direta — achados de alta severidade sem necessidade de exploração adicional.

**Ferramentas mencionadas:**
- Browser DevTools (F12)
- Prettier / js-beautify
- UnPacker (`matthewfl.com/unPacker.html`)
- obfuscator.io
- LinkFinder
- SecretFinder
- retire.js
- source-map-explorer
- Burp Suite (JS Miner extension)
- `gau`, `waybackurls`

**Referências HTB:**
- HTB Module: JavaScript Deobfuscation
- HTB Module: Cross-Site Scripting (XSS)
