---
title: "HTTP Protocol"
---

# HTTP - Protocolo de Transferência de Hipertexto

---

## Contexto: HTTP como Protocolo de Transporte da Web — Fundamento de Toda Vulnerabilidade

HTTP é o alicerce de toda comunicação web — e também o campo de batalha onde a maioria das vulnerabilidades acontece. Entender HTTP em profundidade não é apenas saber "como funciona a web": é entender a superfície de ataque completa antes mesmo de olhar para uma aplicação específica.

**Por que HTTP importa para segurança:**

O protocolo é stateless por design — cada requisição é independente e o servidor não tem memória do cliente. Isso significa que toda noção de "sessão", "autenticação" e "identidade" é construída por cima do HTTP usando cookies, headers e tokens. E o ponto crítico: o protocolo em si não autentica nada. Qualquer cliente pode enviar qualquer requisição com qualquer header, cookie ou body que queira.

Essa delegação total para a camada de aplicação é a raiz de uma classe enorme de vulnerabilidades. Cookies são controláveis pelo cliente — CSRF explora o fato de que o browser os envia automaticamente em cross-site requests. Headers também são controláveis — X-Forwarded-For pode ser falsificado e o Host header pode ser manipulado para cache poisoning. O body da requisição é igualmente controlável pelo cliente, e injeções ocorrem quando o servidor processa esse conteúdo sem validação adequada. Finalmente, o protocolo não verifica identidade: tokens e sessões são responsabilidade exclusiva da aplicação, não do HTTP.

**Cada vulnerabilidade web manipula algum aspecto do HTTP:** SQLi manipula o body ou parâmetros GET para injetar código SQL no back-end. XSS explora como o servidor retorna conteúdo do cliente no body de resposta sem sanitização. CSRF explora o mecanismo automático de envio de cookies do browser em requisições cross-site. SSRF manipula a URL para que o servidor faça requisições HTTP internas em nome do atacante. Cache Poisoning manipula headers para envenenar respostas cacheadas que serão servidas a outros usuários.

Entender o protocolo é entender por onde esses vetores entram. Sem HTTP, nenhuma dessas vulnerabilidades existe.

**HTTP/2 e a nova superfície de ataque:**

HTTP/2 introduziu multiplexing e binary framing — múltiplas requisições em uma única conexão TCP. Isso mudou a superfície: request smuggling entre HTTP/1.1 e HTTP/2 (H2.CL, H2.TE) criou uma classe de ataques inteiramente nova onde um intermediário (load balancer, proxy) e o servidor back-end "discordam" sobre onde uma requisição termina e outra começa.

Sem entender os fundamentos de HTTP, usar ferramentas como Burp Suite, ffuf e curl se torna mecânico sem compreensão — você não sabe o que está modificando nem por que funciona.

---

## Modelo Request-Response, URLs e Versões HTTP

### Modelo Cliente-Servidor

HTTP segue modelo request-response. Cliente envia requisição, servidor processa e retorna resposta. Stateless por design — cada requisição é independente. Cookies foram criados para simular estado.

```
Cliente (Browser/curl)  →  Requisição HTTP  →  Servidor Web
Servidor Web            →  Resposta HTTP    →  Cliente
```

### URL - Uniform Resource Locator

Estrutura completa de uma URL:

```
http://admin:password@inlanefreight.com:80/dashboard/index.php?login=true#status
|----| |------------| |---------------| |-| |------------------| |-----------| |-----|
Scheme   Credentials        Host        Port       Path             Query     Fragment
```

| Componente | Descrição | Exemplo |
|-----------|-----------|---------|
| Scheme | Protocolo usado | `http://`, `https://`, `ftp://` |
| Credentials | user:password (raro, inseguro) | `admin:pass@` |
| Host | Domínio ou IP do servidor | `inlanefreight.com` |
| Port | Porta TCP (padrão: 80/HTTP, 443/HTTPS) | `:8080` |
| Path | Recurso no servidor | `/dashboard/index.php` |
| Query String | Parâmetros GET | `?user=admin&pass=123` |
| Fragment | Âncora no lado cliente (não enviado ao servidor) | `#section1` |

### HTTP/1.1 vs HTTP/2 vs HTTP/3

| Característica | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---------------|----------|--------|--------|
| Protocolo base | TCP | TCP | UDP (QUIC) |
| Multiplexing | Não (uma req/vez por conexão) | Sim (múltiplas streams) | Sim |
| Compressão de headers | Não | HPACK | QPACK |
| Server Push | Não | Sim | Sim |
| Formato | Texto | Binário | Binário |
| TLS obrigatório | Não | Não (mas na prática sim) | Sim |
| Head-of-line blocking | Sim | Parcial (nível TCP) | Não |
| Ano | 1997 | 2015 | 2022 |

HTTP/2 em texto plano (sem TLS) existe mas é raro. Browsers só implementam HTTP/2 com TLS.

---

## Na Prática

### Estrutura de Requisição HTTP

```http
GET /index.html HTTP/1.1
Host: www.inlanefreight.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: PHPSESSID=abc123def456
```

Linha 1: `MÉTODO /caminho HTTP/versão`
Linha 2+: Headers no formato `Nome: Valor`
Linha em branco: Separa headers do body
Body: Dados (presente em POST/PUT/PATCH)

### Estrutura de Resposta HTTP

```http
HTTP/1.1 200 OK
Date: Mon, 27 Jan 2025 10:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 4523
Set-Cookie: PHPSESSID=xyz789; Path=/; HttpOnly; Secure
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains

<!DOCTYPE html>
<html>...
```

---

## Exemplos

### Métodos HTTP

| Método | Descrição | Idempotente | Safe | Tem Body |
|--------|-----------|-------------|------|----------|
| GET | Recupera recurso | Sim | Sim | Não |
| POST | Envia dados, cria recurso | Não | Não | Sim |
| PUT | Substitui recurso completo | Sim | Não | Sim |
| PATCH | Modifica recurso parcialmente | Não | Não | Sim |
| DELETE | Remove recurso | Sim | Não | Não |
| HEAD | GET sem body na resposta | Sim | Sim | Não |
| OPTIONS | Lista métodos permitidos | Sim | Sim | Não |
| CONNECT | Tunelamento TCP via proxy | Não | Não | Não |
| TRACE | Echo da requisição (debugging) | Sim | Sim | Não |

**Segurança**: TRACE pode vazar cookies via XST (Cross-Site Tracing). OPTIONS pode revelar métodos perigosos habilitados. PUT/DELETE raramente devem estar expostos.

### Códigos de Status HTTP

**1xx - Informacional**

| Código | Significado |
|--------|-------------|
| 100 | Continue |
| 101 | Switching Protocols (upgrade para WebSocket) |

**2xx - Sucesso**

| Código | Significado | Notas |
|--------|-------------|-------|
| 200 | OK | Resposta padrão de sucesso |
| 201 | Created | Recurso criado (POST bem-sucedido) |
| 204 | No Content | Sucesso sem body na resposta |
| 206 | Partial Content | Range requests |

**3xx - Redirecionamento**

| Código | Significado | Notas de Segurança |
|--------|-------------|-------------------|
| 301 | Moved Permanently | Muda método? Não (teoricamente) |
| 302 | Found (Temporary) | Explorado em OAuth redirect attacks |
| 303 | See Other | Força GET no redirect |
| 307 | Temporary Redirect | Preserva método e body |
| 308 | Permanent Redirect | Preserva método e body |

**4xx - Erro do Cliente**

| Código | Significado | Pentest |
|--------|-------------|---------|
| 400 | Bad Request | Parâmetro malformado |
| 401 | Unauthorized | Autenticação necessária |
| 403 | Forbidden | Autenticado mas sem permissão |
| 404 | Not Found | Recurso não existe |
| 405 | Method Not Allowed | Método proibido |
| 408 | Request Timeout | |
| 429 | Too Many Requests | Rate limiting ativo |

**5xx - Erro do Servidor**

| Código | Significado | Pentest |
|--------|-------------|---------|
| 500 | Internal Server Error | Possível bug/vuln exposto |
| 502 | Bad Gateway | Proxy/load balancer error |
| 503 | Service Unavailable | DoS ou manutenção |

### Headers HTTP Importantes

**Request Headers**

| Header | Descrição | Valor Exemplo |
|--------|-----------|---------------|
| `Host` | Hostname destino (obrigatório HTTP/1.1) | `inlanefreight.com` |
| `User-Agent` | Identificação do cliente | `Mozilla/5.0 ...` |
| `Accept` | Tipos de conteúdo aceitos | `text/html,*/*` |
| `Accept-Encoding` | Compressões aceitas | `gzip, deflate, br` |
| `Cookie` | Cookies armazenados | `session=abc123` |
| `Authorization` | Credenciais de auth | `Bearer eyJ...` |
| `Content-Type` | Tipo do body da requisição | `application/json` |
| `Content-Length` | Tamanho do body em bytes | `127` |
| `Referer` | URL de origem da requisição | `https://site.com/login` |
| `Origin` | Origem para CORS | `https://site.com` |
| `X-Forwarded-For` | IP real atrás de proxy | `1.2.3.4` |

**Response Headers**

| Header | Descrição | Valor Exemplo |
|--------|-----------|---------------|
| `Server` | Software do servidor (info disclosure) | `Apache/2.4.41` |
| `Content-Type` | Tipo do conteúdo retornado | `text/html; charset=UTF-8` |
| `Set-Cookie` | Define cookie no cliente | `session=xyz; HttpOnly` |
| `Location` | URL para redirect 3xx | `https://site.com/home` |
| `WWW-Authenticate` | Método de auth exigido | `Basic realm="Admin"` |
| `Access-Control-Allow-Origin` | CORS policy | `*` ou `https://trusted.com` |

**Security Headers**

| Header | Proteção | Valor Seguro |
|--------|----------|--------------|
| `Strict-Transport-Security` | Força HTTPS (HSTS) | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | Anti-clickjacking | `SAMEORIGIN` ou `DENY` |
| `X-Content-Type-Options` | Anti-MIME sniffing | `nosniff` |
| `Content-Security-Policy` | Anti-XSS | `default-src 'self'` |
| `X-XSS-Protection` | XSS filter (legado) | `1; mode=block` |
| `Referrer-Policy` | Controle do header Referer | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Controle de APIs do browser | `geolocation=(), microphone=()` |

### cURL - Referência Completa

cURL é a ferramenta principal para interagir com HTTP via CLI. Essencial em pentest.

**Requisições básicas**

```bash
# GET básico
curl https://inlanefreight.com

# GET com output mais limpo
curl -s https://inlanefreight.com | head -50

# Mostrar apenas headers da resposta
curl -I https://inlanefreight.com

# Mostrar headers de requisição E resposta (-v = verbose)
curl -v https://inlanefreight.com

# Verbose extra detalhado (vv = mais detalhes TLS)
curl -vv https://inlanefreight.com
```

**POST e manipulação de dados**

```bash
# POST com dados de formulário
curl -X POST -d 'username=admin&password=admin' http://site.com/login

# POST com JSON
curl -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  http://api.site.com/login

# POST com arquivo de dados
curl -X POST -d @payload.json http://api.site.com/upload

# PUT para atualizar recurso
curl -X PUT -d '{"status":"active"}' -H 'Content-Type: application/json' \
  http://api.site.com/users/1

# DELETE
curl -X DELETE http://api.site.com/users/1
```

**Headers e cookies**

```bash
# Adicionar header customizado
curl -H 'Authorization: Bearer eyJhbGc...' https://api.site.com/data

# Adicionar múltiplos headers
curl -H 'X-Custom: value' -H 'Cookie: session=abc123' https://site.com

# Enviar cookie específico
curl -b 'PHPSESSID=abc123;role=admin' https://site.com/admin

# Salvar cookies em arquivo (cookie jar)
curl -c cookies.txt https://site.com/login

# Usar cookies salvos em arquivo
curl -b cookies.txt https://site.com/dashboard

# Seguir redirects
curl -L https://site.com/redirect
```

**Autenticação**

```bash
# HTTP Basic Auth
curl -u admin:password https://site.com/admin

# HTTP Basic Auth (URL encoded)
curl https://admin:password@site.com/admin

# Bearer token
curl -H 'Authorization: Bearer TOKEN123' https://api.site.com/

# Digest auth
curl --digest -u admin:password https://site.com/admin
```

**Proxy e intercepção (Burp Suite)**

```bash
# Rotear tráfego pelo Burp Suite
curl -x http://127.0.0.1:8080 https://site.com

# Ignorar verificação de certificado TLS (HTTPS via proxy)
curl -k https://site.com
curl --insecure https://site.com

# Proxy + ignorar certificado (padrão para Burp)
curl -x http://127.0.0.1:8080 -k https://site.com
```

**Controle de output**

```bash
# Salvar resposta em arquivo
curl -o resposta.html https://site.com

# Salvar com nome original do servidor
curl -O https://site.com/arquivo.pdf

# Silencioso (sem barra de progresso)
curl -s https://site.com

# Mostrar código de status apenas
curl -s -o /dev/null -w "%{http_code}" https://site.com

# Mostrar headers + body
curl -i https://site.com

# Headers apenas
curl -I https://site.com
```

**TLS/SSL**

```bash
# Ver certificado TLS
curl -vI https://site.com 2>&1 | grep -E "subject|issuer|expire"

# Especificar versão TLS
curl --tlsv1.2 https://site.com
curl --tlsv1.3 https://site.com

# Usar certificado cliente
curl --cert client.crt --key client.key https://site.com

# CA bundle customizado
curl --cacert /path/to/ca-bundle.crt https://site.com
```

**Referência de flags cURL**

| Flag | Longa | Descrição |
|------|-------|-----------|
| `-v` | `--verbose` | Output detalhado com headers |
| `-vv` | | Extra verbose (debug TLS) |
| `-s` | `--silent` | Sem barra de progresso |
| `-S` | `--show-error` | Mostra erros mesmo com -s |
| `-I` | `--head` | Só headers da resposta |
| `-i` | `--include` | Headers + body na resposta |
| `-o` | `--output` | Salva em arquivo |
| `-O` | `--remote-name` | Salva com nome original |
| `-L` | `--location` | Segue redirects |
| `-X` | `--request` | Especifica método HTTP |
| `-d` | `--data` | Dados do body |
| `-H` | `--header` | Adiciona header |
| `-b` | `--cookie` | Envia cookie |
| `-c` | `--cookie-jar` | Salva cookies em arquivo |
| `-u` | `--user` | Credenciais user:pass |
| `-x` | `--proxy` | Usa proxy |
| `-k` | `--insecure` | Ignora erros TLS |
| `-A` | `--user-agent` | Define User-Agent |
| `-e` | `--referer` | Define Referer |
| `-w` | `--write-out` | Formato de output pós-req |
| `-T` | `--upload-file` | Upload de arquivo |
| `--max-time` | | Timeout em segundos |
| `--connect-timeout` | | Timeout de conexão |

### HTTPS e TLS

HTTPS = HTTP sobre TLS (Transport Layer Security). TLS versão 1.3 é o padrão atual.

**Handshake TLS 1.3 simplificado:**

```
Cliente                          Servidor
  |                                 |
  |--- ClientHello (cipher suites) -->|
  |<-- ServerHello + Certificate  ---|
  |<-- ServerHelloDone            ---|
  |--- [Verifica certificado]        |
  |--- Finished (chave sessão)    -->|
  |<-- Finished                   ---|
  |                                 |
  |=== Comunicação encriptada ======|
```

**HSTS - HTTP Strict Transport Security**

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age`: Quantos segundos o browser deve forçar HTTPS (31536000 = 1 ano)
- `includeSubDomains`: Aplica a todos os subdomínios
- `preload`: Solicita inclusão na lista prebuilt dos browsers

Primeiro acesso em HTTP pode ser interceptado (SSLStrip attack). HSTS resolve isso após primeiro contato seguro.

### Cookies e Segurança

```http
Set-Cookie: session=abc123; Path=/; Domain=site.com; Expires=Wed, 01 Jan 2025 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict
```

| Atributo | Efeito de Segurança |
|----------|---------------------|
| `HttpOnly` | Inacessível via JavaScript (mitiga XSS) |
| `Secure` | Só enviado em HTTPS |
| `SameSite=Strict` | Não enviado em cross-site requests (mitiga CSRF) |
| `SameSite=Lax` | Enviado em navegação top-level (menos restritivo) |
| `SameSite=None` | Enviado sempre (requer Secure) |

**Por que cada flag importa:** `HttpOnly` previne que um XSS roube o cookie de sessão via `document.cookie`. `Secure` garante que o cookie nunca seja transmitido em HTTP claro, impedindo interceptação por MITM. `SameSite=Strict` previne CSRF porque o cookie não acompanha requisições originadas de outros domínios, eliminando o vetor de forjamento cross-site.

### URL Encoding (Percent-Encoding)

Caracteres especiais em URLs devem ser codificados com `%XX` onde XX é o valor hexadecimal ASCII.

| Caractere | Encoded | Uso |
|-----------|---------|-----|
| Espaço | `%20` ou `+` | Separador em query string |
| `#` | `%23` | Fragment identifier |
| `%` | `%25` | Escape do próprio escape |
| `&` | `%26` | Separador de parâmetros |
| `+` | `%2B` | Literal plus sign |
| `/` | `%2F` | Path separator |
| `?` | `%3F` | Início da query string |
| `=` | `%3D` | Atribuição de parâmetro |
| `@` | `%40` | Separador de credenciais |
| `:` | `%3A` | Separador de porta |
| `<` | `%3C` | Bracket (XSS relevante) |
| `>` | `%3E` | Bracket (XSS relevante) |
| `'` | `%27` | Aspas simples (SQLi relevante) |
| `"` | `%22` | Aspas duplas |
| `\n` | `%0A` | Newline (header injection) |
| `\r` | `%0D` | Carriage return (header injection) |

```bash
# Encode manual com curl
curl --data-urlencode "param=value with spaces&special" http://site.com/

# Python para URL encode
python3 -c "import urllib.parse; print(urllib.parse.quote('test<script>'))"
# Output: test%3Cscript%3E
```

### Comparação HTTP/1.1 vs HTTP/2 em Wireshark/BurpSuite

**HTTP/1.1 (texto plano)**
```
GET /api/users HTTP/1.1
Host: api.site.com
Accept: application/json

```

**HTTP/2 (binário - representação em Burp)**
```
:method: GET
:path: /api/users
:authority: api.site.com
:scheme: https
accept: application/json
```

Pseudo-headers em HTTP/2 começam com `:`. Em Burp Suite, HTTP/2 requests são mostradas em formato human-readable mas enviadas em binário.

### Exemplos de Uso Real em Pentest

**Identificar tecnologias via headers**
```bash
curl -sI https://target.com | grep -E "Server:|X-Powered-By:|X-Generator:"
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
```

**Testar métodos HTTP permitidos**
```bash
curl -X OPTIONS https://target.com -v 2>&1 | grep "Allow:"
# Allow: GET, POST, HEAD, OPTIONS
```

**Testar autenticação Basic**
```bash
curl -u admin:admin https://target.com/admin
curl -u admin:password123 https://target.com/admin
```

**Forçar HTTP/2**
```bash
curl --http2 -v https://target.com
curl --http1.1 -v https://target.com
```

**Download silencioso de arquivo**
```bash
curl -s -o /tmp/index.html https://target.com/
curl -s https://target.com/robots.txt
```

**Verificar redirecionamentos passo a passo**
```bash
curl -v -L https://target.com 2>&1 | grep -E "Location:|HTTP/"
```

**Teste de header injection**
```bash
# Testar CRLF injection em parâmetro
curl "https://target.com/redirect?url=https://evil.com%0d%0aSet-Cookie:session=hijacked"
```

---

## Módulos Relacionados

O módulo de Web App Fundamentos (`02_web_app_fundamentos.md`) descreve como o back-end processa as requisições HTTP abordadas aqui. O módulo de Web Proxies (`03_web_proxies.md`) mostra como interceptar e modificar essas requisições com o Burp Suite. Content Discovery (`../02_reconhecimento/02_content_discovery.md`) usa HTTP diretamente — o ffuf dispara requisições HTTP para cada entrada da wordlist. As vulnerabilidades de SQL Injection exploram parâmetros GET e POST como vetores de injeção, XSS se manifesta quando respostas HTTP retornam conteúdo do cliente sem sanitização, CSRF explora o mecanismo automático de envio de cookies do browser em cross-site requests, e SSRF força o servidor a emitir requisições HTTP internas usando os mesmos fundamentos de protocolo descritos neste módulo.

**Ferramentas mencionadas:**
- `curl` - CLI para requisições HTTP
- `wget` - Download de arquivos via HTTP
- `httpie` - Alternativa ao curl mais amigável (`http GET site.com`)
- Burp Suite - Proxy para interceptar e manipular HTTP
- Wireshark - Análise de pacotes de rede (HTTP/TCP)

**Referências HTB:**
- HTB Module: Web Requests
- HTB Module: Introduction to Web Applications
