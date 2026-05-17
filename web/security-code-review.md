---
title: "Security Code Review"
---

# Security Code Review

> Metodologia de análise estática manual: seguir input do usuário, identificar sinks perigosos, avaliar controles em middlewares e funções de sistema.

---

## Metodologia

### Abordagem Top-Down

```
1. Ponto de entrada: routes/controllers → identificar endpoints
2. Seguir o input: rastrear parâmetro do request até onde é usado
3. Identificar sinks: funções que executam o input (SQL, OS, template, desserialização)
4. Verificar controles: validação, sanitização, autenticação, autorização estão presentes?
5. Documentar: anotar caminho de ataque, impacto, mitigação
```

### Source-to-Sink

```
Source (input controlado pelo usuário):
  request.args.get('param')      Flask GET param
  request.form.get('field')      Flask POST form
  request.json.get('key')        Flask JSON body
  request.headers.get('Header')  Header HTTP
  cookies

Sink (onde o input pode causar dano):
  SQL:          cursor.execute(f"SELECT ... {input}")
  OS:           os.system(input), subprocess.run(input, shell=True)
  File:         open(input) sem sanitização de path
  Template:     render_template_string(input) — SSTI
  Deserialize:  pickle.loads(input), yaml.load(input)
  URL fetch:    requests.get(input) — SSRF
```

---

## Seguindo o Input do Usuário

### Exemplo: Path Traversal via Parâmetro `file`

```python
# views.py — Rota /read
@app.route('/read')
def read_file():
    """Fornece acesso a relatórios financeiros para pessoas autorizadas."""
    filename = request.args.get('file')      # SOURCE: parâmetro GET 'file'

    if not filename:
        return jsonify({'error': 'file required'}), 400

    try:
        with open(filename, 'r', encoding='utf-8') as f:   # SINK: open() sem sanitizar
            content = f.read()
        return jsonify({'content': content})
    except FileNotFoundError:
        return jsonify({'error': 'not found'}), 404
    except PermissionError:
        return jsonify({'error': 'permission denied'}), 403
```

**Vulnerabilidade**: `filename` direto do request sem sanitização → path traversal.

```
GET /read?file=../../../etc/passwd
GET /read?file=/etc/shadow
GET /read?file=../config/database.ini
```

**Mitigação**:
```python
import os

REPORTS_DIR = '/app/reports/'

def read_file():
    filename = request.args.get('file')
    if not filename:
        return jsonify({'error': 'required'}), 400

    # resolver path canônico e verificar confinamento ao diretório
    safe_path = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    if not safe_path.startswith(REPORTS_DIR):
        return jsonify({'error': 'invalid path'}), 400

    with open(safe_path, 'r') as f:
        return jsonify({'content': f.read()})
```

---

## Funções de Sistema — Sinks Perigosos

Padrões de execução OS que indicam possível command injection:

**Python**:
```python
# PERIGOSO — shell injection
os.system(cmd)
subprocess.run(cmd, shell=True)
subprocess.Popen(cmd, shell=True)

# SEGURO — lista de argumentos, sem shell
subprocess.run(['ls', '-la', user_input], shell=False)
```

**Java**:
```java
// PERIGOSO se cmd inclui input sem separação
Runtime.getRuntime().exec(cmd)

// MAIS SEGURO — array separado
new ProcessBuilder(Arrays.asList("/bin/ls", user_input))
```

**PHP** — funções que executam OS: `system()`, `passthru()`, `shell_exec()`, `` `cmd` `` (backtick), `popen()`.

**Grep para encontrar**:
```bash
# Python sinks
grep -rn "os\.system\|subprocess.*shell=True\|os\.popen" .

# Java sinks
grep -rn "Runtime\.getRuntime\(\)\.exec\|ProcessBuilder" .

# PHP sinks (pattern regex)
grep -rPn "system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(" .
```

---

## Middlewares — Controles Centralizados

Middlewares interceptam requisições antes dos controllers. São onde autenticação e autorização devem acontecer.

### O que verificar

```python
# Flask — middleware de autenticação
@app.before_request
def auth_middleware():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return  # whitelist explícita de endpoints públicos

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401

    # VERIFICAR: valida assinatura do token?
    user = verify_token(token)  # ← deve verificar assinatura, expiração, revogação
    if not user:
        return jsonify({'error': 'Invalid token'}), 401

    g.current_user = user
```

**Falhas comuns**: a mais crítica é `JWT com verification=False`, que faz o servidor aceitar qualquer payload sem verificar a assinatura. Whitelists de endpoints públicos que incluem rotas sensíveis por engano deixam recursos protegidos expostos. Um middleware não aplicado globalmente significa que algumas rotas escapam inteiramente da verificação. Tokens com expiração não verificada permanecem válidos indefinidamente após comprometimento. Por fim, o header `Authorization` ignorado quando presente em formato inesperado cria bypass silencioso de autenticação.

### Default Deny

```python
# VULNERÁVEL — middleware só executa se header presente
# request sem header → middleware pula completamente

# CORRETO — rejeitar ausência, não apenas inválidos
if not token:
    return jsonify({'error': 'Unauthorized'}), 401
```

---

## Segredos Expostos

```bash
# busca rápida no código
grep -rn "password\|secret\|api_key\|private_key" . \
  --include="*.py" --include="*.js" --include="*.yaml" --include="*.env"

# histórico git — segredos removidos mas ainda no log
git log --all --full-history -S "password" -- "*.py"

# ferramentas especializadas
gitleaks detect --source . --verbose
trufflehog git file://. --only-verified
```

**Padrão seguro**:
```python
# VULNERÁVEL
SECRET_KEY = "minha-chave-hardcoded-123"
DB_PASSWORD = "admin123"

# CORRETO
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
```

---

## Dependências Inseguras

```bash
# Python
pip audit
pip-audit --requirement requirements.txt

# Node.js
npm audit
yarn audit

# Java (Maven)
mvn dependency-check:check

# multi-linguagem
snyk test
```

**Processo ao encontrar CVE em dependência**:
1. Verificar se o app usa a função/feature vulnerável
2. Verificar se o path de código é atingível externamente
3. Atualizar para versão com fix
4. Se sem fix: workaround ou substituição de lib

---

## Case Study: CVE-2023-28838 — Python Pickle Deserialization

### Contexto

Aplicação de e-commerce usa `pickle` (serialização binária Python) para armazenar carrinho de compras. Cliente recebe o dado serializado, pode modificá-lo e enviar de volta no checkout.

### Fluxo Vulnerável

```python
# /cart/add — serializa com pickle, retorna ao cliente em base64
cart = {'product_id': product_id, 'quantity': quantity}
serialized = pickle.dumps(cart)
encoded = base64.b64encode(serialized).decode()
return jsonify({'cart_data': encoded})   # cliente recebe e controla esse valor

# /checkout — desserializa cartData do request SEM validação de integridade
cart_data = request.form.get('cartData')
decoded = base64.b64decode(cart_data)
cart = pickle.loads(decoded)             # ← SINK: executa código se payload malicioso
```

### Por que é RCE

`pickle.loads()` executa `__reduce__` do objeto ao desserializar. Um payload malicioso pode executar comandos:

```
Estrutura do exploit: criar objeto Python com __reduce__ apontando para os.system('comando')
Serializar → base64 encode → enviar como cartData → pickle.loads() executa o comando
```

### Mitigação com HMAC

```python
import hmac, hashlib, os

SECRET = os.environ.get('CART_SECRET').encode()

def sign_cart(data: bytes) -> str:
    sig = hmac.new(SECRET, data, hashlib.sha256).hexdigest()
    return base64.b64encode(data).decode() + '.' + sig

def verify_and_load(cart_str: str):
    parts = cart_str.split('.')
    if len(parts) != 2:
        raise ValueError("Invalid format")
    data = base64.b64decode(parts[0])
    expected = hmac.new(SECRET, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(parts[1], expected):   # timing-safe
        raise ValueError("Integrity check failed")
    return pickle.loads(data)  # só executa se assinatura válida

# Alternativa preferida: JSON em vez de pickle (JSON não executa código)
cart_json = json.loads(request.form.get('cartData'))
```

### Identificação — Padrões de Desserialização Insegura

```bash
# Python
grep -rn "pickle\.loads\|yaml\.load\|marshal\.loads" .

# PHP
grep -rn "unserialize\s*(" .

# Java
grep -rn "ObjectInputStream\|readObject\(\|XMLDecoder" .
```

**Regra geral**: `loads/unserialize/readObject` aplicado a dados do usuário sem validação de integridade → vulnerável a RCE.

---

## Checklist de Code Review

```
INPUTS:
[ ] Todos os parâmetros de request identificados (GET, POST, headers, cookies)?
[ ] Validação de tipo e formato antes do uso?
[ ] Sanitização antes de passar para sinks?

SINKS:
[ ] SQL usa prepared statements / ORM com parâmetros (não f-string)?
[ ] Comandos OS usam lista de args (não string interpolada com shell)?
[ ] Operações de arquivo verificam path canonical (sem traversal)?
[ ] Desserialização valida integridade (HMAC ou equivalente)?
[ ] Renderização de template usa dados como contexto, não como template dinâmico?
[ ] URLs externas vêm de whitelist (não de input direto)?

CONTROLES:
[ ] Autenticação verificada em todos os endpoints protegidos?
[ ] Autorização por objeto (BOLA — não apenas por papel)?
[ ] Rate limiting em endpoints de autenticação e operações custosas?
[ ] Logs de eventos de segurança (login, falha, acesso negado)?

SEGREDOS:
[ ] Nenhuma credencial hardcoded?
[ ] .env não commitado (verificar .gitignore)?

DEPENDÊNCIAS:
[ ] pip/npm audit sem CVEs críticos/altos?
[ ] Versões de dependências fixadas (não `>=` abertas)?
```

---

## Ferramentas

| Ferramenta | Uso |
|-----------|-----|
| Semgrep | SAST com regras customizáveis, CI-friendly |
| Bandit | SAST Python |
| Sonarqube | SAST multi-linguagem |
| Gitleaks | Segredos em repositório e histórico git |
| Trufflehog | Segredos com verificação de validade |
| pip-audit / npm audit | Dependências vulneráveis |
| OWASP Dependency Check | Dependências Java |
| Snyk | Dependências multi-linguagem + containers |

---

## Módulos Relacionados

Security code review é a técnica de verificação manual que valida o que os controles automáticos não alcançam. O módulo `02_threat_modeling.md` é o antecessor direto: o threat model define os controles que precisam existir, e o code review é onde se verifica se eles foram implementados corretamente no código. Para aprofundamento em análise whitebox de aplicações compiladas, `../12_whitebox_pentesting/01_whitebox_intro.md` cobre análise de WAR Java e uso de dnSpy para .NET. O módulo `../09_deserialization/01_deserialization_intro.md` expande o caso de desserialização insegura com PHPGGC e RCE em Python detalhado. Para path traversal e LFI com PHP wrappers, `../06_file_attacks/01_file_inclusion.md` é a referência completa.
