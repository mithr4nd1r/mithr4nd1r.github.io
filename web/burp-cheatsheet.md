---
title: "Burp Cheatsheet"
---

# Burp Suite Cheatsheet - Referência Rápida

## Workflow por Tipo de Vulnerabilidade

Burp nao e so proxy — e uma plataforma de analise onde cada modulo tem um papel especifico dependendo do tipo de vulnerabilidade investigada. Saber qual modulo usar para cada classe de bug acelera o trabalho.

| Vulnerabilidade | Modulos Principais | Extensoes Uteis |
|---|---|---|
| SQLi | Repeater (testes manuais), Intruder (boolean blind automation) | sqlmap via Burp proxy |
| XSS Refletido | Repeater, Intruder (Sniper com payload list) | DOM Invader (DOM XSS), XSS Validator |
| XSS Stored | Proxy (HTTP History), Scanner | DOM Invader |
| IDOR | Repeater (trocar IDs), Autorize (automacao) | Autorize, Logger++ |
| Race Condition | Turbo Intruder (gate sincronizado) | Turbo Intruder |
| SSRF | Collaborator (out-of-band), Repeater | Collaborator Everywhere, interactsh |
| JWT | Repeater (modificar claims), Decoder | JSON Web Tokens extension |
| Prototype Pollution | Browser DevTools + DOM Invader | DOM Invader |
| Business Logic | Repeater (manipular parametros manualmente) | Match and Replace |
| Mass Assignment | Repeater (adicionar campos extras no body) | Content Type Converter |

**Workflow geral por funcionalidade nova:**

1. Mapear no Site Map navegando com Proxy ON
2. Identificar inputs: req.body, parametros de URL, headers, cookies
3. Send to Repeater → testar payloads basicos manualmente
4. Se promissor: Send to Intruder para automatizar variações
5. Para blind out-of-band: usar Collaborator/interactsh

**Burp como ferramenta de analise (nao so ataque):**

HTTP History com filtros por endpoint, method, e content-type permite entender o fluxo da aplicacao antes de atacar. Site Map mostra a hierarquia de endpoints descobertos. Match and Replace automatiza modificacoes recorrentes (trocar role, adicionar header) sem intervencao manual em cada request.

---

## Configuração Inicial

```bash
# Iniciar Burp
java -jar burpsuite_community.jar
java -Xmx4g -jar burpsuite_pro.jar   # Mais memória

# Configurar proxy
# Burp: Proxy -> Options -> Listener -> 127.0.0.1:8080
# Browser: configurar proxy HTTP 127.0.0.1:8080

# Instalar certificado CA
# Acessar: http://burpsuite ou http://127.0.0.1:8080
# Baixar certificado CA -> instalar no browser
# Firefox: Preferences -> Privacy -> Certificates -> Import
# Chrome: Settings -> Security -> Manage certs -> Import

# FoxyProxy (Firefox) - gerenciar proxy facilmente
# Configurar perfil para 127.0.0.1:8080
```

---

## Proxy - Atalhos e Dicas

```
CTRL+I    - Interceptar ON/OFF
CTRL+F    - Encaminhar request interceptado
CTRL+D    - Descartar request interceptado

Botão Direito -> Send to:
- Repeater (CTRL+R)
- Intruder (CTRL+I)
- Scanner (Pro)
- Sequencer
- Decoder
- Comparer

Aba HTTP History:
- Filtros por método, status, tipo de conteúdo
- CTRL+F para buscar no histórico
- Botão direito -> "Save item" para exportar

Match and Replace (Proxy -> Options):
- Modificar automaticamente requests/responses
- Útil para: adicionar header, alterar User-Agent, injetar payloads
```

---

## Repeater

```
CTRL+R      - Enviar para Repeater (do Proxy)
CTRL+Space  - Enviar request (no Repeater)
CTRL+Z      - Desfazer modificação
CTRL+Y      - Refazer modificação
CTRL+A      - Selecionar todo o request
CTRL+U      - URL decode seleção
CTRL+SHIFT+U - URL encode seleção
CTRL+B      - Base64 encode
CTRL+SHIFT+B - Base64 decode
CTRL+H      - HTML decode
CTRL+SHIFT+H - HTML encode

Dicas:
- "+" para abrir nova aba, organizar requests por vulntype
- Clicar direito -> "Add to scope" para manter no escopo
- Comparar responses com "Previous Response" button
```

---

## Intruder

### Tipos de Ataque

| Tipo | Comportamento | Uso |
|------|---------------|-----|
| Sniper | Um campo por vez, itera payload list | Fuzzing de parâmetro único |
| Battering Ram | Mesmo valor em todos os campos | Quando usuário = senha |
| Pitchfork | Campo 1 = Lista 1[n], Campo 2 = Lista 2[n] | Credential stuffing |
| Cluster Bomb | Todas combinações de todas listas | Brute force completo |

```
Setup no Intruder:
1. Positions tab: marcar §payload§ nos campos a injetar
2. Payloads tab: adicionar lista de payloads
3. Options tab: configurar threads, delays, grep
4. Start Attack: botão vermelho

Grep - Match: configurar string de sucesso/falha
Grep - Extract: extrair informação da resposta

Payload Types úteis:
- Simple list      - Lista manual ou arquivo
- Numbers          - Range numérico (1 a 100)
- Runtime file     - Arquivo lido durante ataque
- Dates            - Datas em formato configurável
- Brute forcer     - Charset + tamanho (força bruta pura)
- Bit flipper      - Inversão de bits
```

---

## Decoder

```
Codificações disponíveis:
- URL encode/decode
- HTML encode/decode
- Base64 encode/decode
- ASCII hex encode/decode
- Hex encode/decode
- Octal encode/decode
- Binary encode/decode
- Gzip compress/decompress
- Hash: MD5, SHA1, SHA256, SHA512

Uso manual:
- Colar texto -> selecionar operação -> resultado aparece
- Encadear: resultado de uma op vira input da próxima
```

---

## Scanner (Pro)

```bash
# Scan passivo: automático no Proxy (não faz requests extras)
# Scan ativo: envia payloads de teste (Active Scan)

# Via GUI: botão direito em request -> "Active Scan"
# Scan completo de site: Target -> Site map -> botão direito -> "Active Scan this host"

# Configurações recomendadas para scan:
# Scanner -> Options:
#   - Thoroughness: 1-3 para speed, 4-5 para coverage
#   - Insertion Points: checar todos habilitados
#   - Issues Reported: verificar quais categorias quer

# Scan via linha de comando (Pro)
# burp-rest-api para automação CI/CD
```

---

## Extensions (BApp Store) - Essenciais

| Extensão | Função |
|----------|--------|
| **Autorize** | Testa IDOR/broken access control automaticamente |
| **InQL** | Scanner e client GraphQL |
| **JSON Web Tokens** | Decodifica e edita JWTs |
| **Logger++** | Log avançado de requests com filtros |
| **Turbo Intruder** | Intruder avançado, high-speed, race conditions |
| **Active Scan++** | Adiciona checks ao Scanner (Pro) |
| **Collaborator Everywhere** | Injeta Burp Collaborator em todos headers |
| **Hackvertor** | Transformações e encoding avançados |
| **Content Type Converter** | Converter JSON <-> XML <-> form-data |
| **Upload Scanner** | Analisa endpoints de upload |
| **JS Miner** | Extrai endpoints e secrets de JavaScript |
| **DOM Invader** | Detecta DOM XSS e prototype pollution |
| **SHELLING** | Detecta command injection |
| **Param Miner** | Descobre parâmetros ocultos em requests |

---

## Turbo Intruder - Race Conditions

```python
# Script para race condition (enviar requests simultaneamente)
# No Repeater: Extensions -> Turbo Intruder -> Send to Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)

    for i in range(20):
        engine.queue(target.req, target.baseInput, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

# Para brute force rápido
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False)

    for password in open('/usr/share/wordlists/rockyou.txt'):
        engine.queue(target.req, password.rstrip())

def handleResponse(req, interesting):
    if '302' in req.response or 'welcome' in req.response.lower():
        table.add(req)
```

---

## Autorize - Teste de IDOR/Access Control

```
Configuração:
1. Instalar Autorize via BApp
2. Fazer login com User A (admin/privileged)
3. Copiar cookies do User B (non-admin) para "Cookies of attacker header"
4. Habilitar "Intercept Requests"
5. Navegar como User A
6. Autorize automaticamente repete requests com cookies do User B
7. Verificar coluna "Auth Bypass?" nas respostas

Cores:
- Verde   = autorizado (esperado)
- Amarelo = bypass detectado! (verificar manualmente)
- Vermelho = não autorizado (esperado)
```

---

## Collaborator - SSRF e Blind Injection

```bash
# Burp Collaborator = servidor externo que recebe requisições de back-end
# Útil para: Blind SSRF, Blind XXE, Blind OS injection, DNS exfiltration

# Pro: Burp -> Project Options -> Misc -> Burp Collaborator Server
# Community: usar interactsh ou webhook.site como alternativa

# Payload colaborador (Pro gera automaticamente):
# xxxxx.burpcollaborator.net

# Interactsh (open source alternativo)
interactsh-client    # Gera URL única, escuta interações
# URL: abc123.oast.pro

# Exemplo uso manual
# 1. Substituir URL em campo vulnerável
curl -X POST http://TARGET/api/webhook \
     -d '{"url": "http://abc123.oast.pro/test"}'

# 2. Verificar no interactsh se houve request
# DNS, HTTP, SMTP interactions logadas
```

---

## Dicas de Workflow

```
Para cada funcionalidade nova encontrada:
1. Mapear no Site Map (navegar com Proxy ON)
2. Identificar parâmetros de entrada
3. Send to Repeater -> testar payloads básicos manualmente
4. Se promissor, Send to Intruder -> automatizar

Para cada request:
- Verificar todos os métodos HTTP (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Remover parâmetros um a um (pode mudar comportamento)
- Adicionar parâmetros extras (mass assignment)
- Alterar Content-Type (JSON -> XML -> form-data)
- Verificar response headers (versões, tecnologias)

Match and Replace automáticos úteis:
- Tipo: Request Header, Match: User-Agent, Replace: GoogleBot
- Tipo: Request Header, Match: ^, Replace: X-Forwarded-For: 127.0.0.1
- Tipo: Response Header, Match: X-Frame-Options: DENY, Replace: (remover para clickjacking test)
```

---

## Scope e Exclusões

```
Target -> Scope:
- Adicionar host/URL ao escopo
- Burp filtra histórico por escopo
- Scanner só testa itens no escopo

Regex de escopo úteis:
- ^https?://target\.com/.*$    # Target principal
- ^https?://.*\.target\.com/.*$  # Todos subdomínios

Exclusões comuns:
- /logout (evitar deslogar durante scan)
- /account/delete (ações destrutivas)
- /api/v1/admin/drop (endpoints destrutivos)
- Qualquer path com "delete", "destroy", "remove"
```
