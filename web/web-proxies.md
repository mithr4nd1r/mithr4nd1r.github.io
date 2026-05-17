---
title: "Web Proxies"
---

# Web Proxies - Burp Suite e ZAP

---

## Contexto: Proxy Interceptador como Ferramenta Central de Análise

O proxy interceptador é a ferramenta que muda fundamentalmente como você enxerga uma aplicação web. Sem proxy, você está limitado ao que o browser mostra — que é o que o desenvolvedor *quer* que você veja. Com proxy, você vê e controla cada byte que trafega entre o cliente e o servidor.

**Por que o proxy é fundamental — a ilusão da UI:**

Desenvolvedores constroem interfaces gráficas pensando em usuários legítimos. Botões desabilitados, menus ocultos, campos read-only — tudo isso é controle de UI que não tem nenhuma relação com controle de segurança no back-end. O proxy quebra essa ilusão completamente: você não está mais interagindo via UI, está interagindo diretamente com o protocolo.

Um campo `disabled` no HTML não impede que você envie o parâmetro na requisição. Uma validação de formulário em JavaScript não protege o endpoint se o back-end não revalida. Um menu de administração escondido via CSS ainda responde se você souber a URL. O proxy expõe tudo isso.

**Burp como ferramenta de análise, não só de ataque:**

A mentalidade errada é usar o Burp apenas para lançar ataques. O uso mais valioso é para *entender o fluxo da aplicação*. O Site Map constrói um mapa automático de todos os endpoints visitados, enquanto o HTTP History registra todas as requisições em ordem cronológica — permitindo reconstruir exatamente o que a aplicação faz em cada ação do usuário. Navegando com Intercept OFF em modo logging passivo, você acumula um mapa completo da superfície antes de iniciar qualquer teste; parâmetros ocultos, tokens anti-CSRF, IDs internos e versões de API — tudo aparece no histórico do proxy.

Isso é especialmente valioso para aplicações complexas com múltiplos fluxos: pagamento, autenticação, upload, integração com terceiros. Cada fluxo tem suas próprias vulnerabilidades — e o proxy é o único jeito de ver cada passo.

**Por que proxy é pré-requisito para pentest web:** o proxy permite interceptar e modificar qualquer requisição antes de chegar ao servidor, repetir ataques com variações controladas para fuzzing manual, automatizar testes de brute force e injeção via Intruder, mapear a aplicação completa via spider e crawl, detectar vulnerabilidades de forma passiva ou ativa, e manipular tokens, cookies e headers em tempo real durante cada interação com a aplicação.

---

## Arquitetura de Proxy Interceptador e Versões do Burp Suite

### Arquitetura de Proxy

```
Browser  →  Proxy (127.0.0.1:8080)  →  Servidor Web
Browser  ←  Proxy (modificada)       ←  Servidor Web
```

O browser é configurado para enviar todo tráfego ao proxy local. O proxy:
1. Intercepta a requisição (pode modificar antes de reencaminhar)
2. Encaminha ao servidor de destino
3. Recebe a resposta
4. Intercepta a resposta (pode modificar antes de retornar ao browser)
5. Retorna a resposta ao browser

Para HTTPS, o proxy realiza um ataque MITM controlado usando seu próprio certificado CA. Por isso é necessário importar o certificado CA do Burp/ZAP no browser.

### Burp Suite Community vs Professional

| Feature | Community | Professional |
|---------|-----------|--------------|
| Preço | Gratuito | ~$449/ano |
| Proxy | Sim | Sim |
| Intercept | Sim | Sim |
| Repeater | Sim | Sim |
| Intruder | Sim (throttled) | Sim (sem limite) |
| Scanner | Não | Sim (passivo + ativo) |
| Collaborator | Não | Sim (SSRF, XXE OOB) |
| Project save | Temporário | Sim (.burp files) |
| Extensions BApp | Limitado | Completo |
| Macro/Session | Limitado | Completo |

---

## Na Prática

### Configuração Inicial

**FoxyProxy (extensão Firefox/Chrome)**

FoxyProxy é a forma mais prática de alternar entre proxy e conexão direta:

1. Instalar extensão FoxyProxy Standard
2. Abrir configurações FoxyProxy
3. Adicionar novo proxy:
   - Title: `Burp Suite`
   - Type: `HTTP`
   - Hostname: `127.0.0.1`
   - Port: `8080`
4. Ativar o perfil quando precisar interceptar

**Importar certificado CA do Burp**

Sem isso, HTTPS mostrará erro de certificado:

```
1. Com Burp rodando, acessar: http://burpsuite (ou http://127.0.0.1:8080)
2. Clicar em "CA Certificate" → Download
3. Firefox: Settings → Privacy → View Certificates → Import
4. Marcar: "Trust this CA to identify websites"
5. Reiniciar Firefox
```

Para Chrome/Chromium:
```
Settings → Privacy → Security → Manage certificates → Authorities → Import
```

**Linha de comando — configurar proxy sem browser:**

```bash
# curl com proxy Burp
curl -x http://127.0.0.1:8080 -k https://target.com

# Variáveis de ambiente (afeta ferramentas que respeitam)
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export BURP_PROXY=http://127.0.0.1:8080

# Python requests
import requests
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("https://target.com", proxies=proxies, verify=False)
```

### Burp Suite — Módulos Principais

#### 1. Proxy — Intercept

O coração do Burp. Cada requisição pode ser pausada, modificada e reencaminhada.

**Fluxo de trabalho:**

```
1. Ligar Intercept: Proxy → Intercept → "Intercept is on"
2. Navegar no browser
3. Requisição aparece no Burp
4. Modificar o que precisar
5. Clicar "Forward" para enviar ao servidor
6. "Drop" para descartar a requisição
```

**Botões principais:**
- `Forward` — envia requisição modificada ao servidor
- `Drop` — descarta requisição
- `Intercept is on/off` — toggle de interceptação
- `Action` — menu de ações (send to Repeater, Scanner, etc.)

**Filtros de interceptação (Proxy → Options → Intercept Client Requests):**

```
URL match: .*target\.com.*       # Só intercepta target.com
File extension: não .jpg .css .png .woff  # Ignora recursos estáticos
```

#### 2. Repeater

Permite reenviar requisições manualmente com modificações. Essencial para testes iterativos.

**Workflow:**
```
1. Interceptar requisição no Proxy
2. Ctrl+R (ou Action → Send to Repeater)
3. Ir para aba Repeater
4. Modificar parâmetros manualmente
5. Clicar "Send"
6. Analisar resposta no painel direito
7. Repetir com variações
```

**Atalhos:**
- `Ctrl+R` — Send to Repeater
- `Ctrl+Shift+R` — Go to Repeater
- `Ctrl+Space` — Enviar requisição no Repeater
- `Ctrl+Z` — Desfazer modificação

**Uso típico em pentest:**

```http
# Testando SQLi — modificar parâmetro no Repeater:
GET /users?id=1 HTTP/1.1        # Original
GET /users?id=1' HTTP/1.1       # Teste aspas
GET /users?id=1 OR 1=1-- HTTP/1.1  # Bypass
GET /users?id=1 AND SLEEP(5)-- HTTP/1.1  # Blind time-based

# Testando XSS
GET /search?q=<script>alert(1)</script> HTTP/1.1
GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1

# Testando IDOR
GET /api/profile?user_id=100 HTTP/1.1
GET /api/profile?user_id=101 HTTP/1.1
GET /api/profile?user_id=1 HTTP/1.1
```

#### 3. Intruder

Automatiza ataques de fuzzing. Quatro tipos de ataque:

**Definir posições (positions):**

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=§admin§&password=§password§
```

Os `§` marcam onde os payloads serão inseridos.

**Tipos de Ataque:**

| Tipo | Comportamento | Uso |
|------|--------------|-----|
| **Sniper** | Uma posição por vez, mesmo payload list em cada | Fuzzing de um parâmetro |
| **Battering Ram** | Mesmo payload em todas posições simultaneamente | Username = Password |
| **Pitchfork** | Payload list 1 para posição 1, list 2 para posição 2 (em paralelo) | Login com listas correspondentes user:pass |
| **Cluster Bomb** | Produto cartesiano de todas listas | Brute force completo de múltiplos campos |

**Exemplos de uso:**

```
Sniper: Testar SQLi em um parâmetro
  → posição: id=§1§
  → payload: lista de vetores SQLi

Battering Ram: Teste de username igual a password
  → posições: username=§test§&password=§test§
  → payload: lista de usernames comuns

Pitchfork: Login com credential stuffing
  → posição 1: username=§§, posição 2: password=§§
  → payload list 1: usernames.txt, list 2: passwords.txt (mesma linha)

Cluster Bomb: Brute force completo
  → posição 1: username=§§, posição 2: password=§§
  → payload list 1: top-users.txt (10 itens)
  → payload list 2: top-passwords.txt (100 itens)
  → Total: 1000 requisições
```

**Payloads no Intruder:**

| Tipo de Payload | Uso |
|----------------|-----|
| Simple list | Wordlist de arquivo ou colada |
| Runtime file | Arquivo lido em tempo real (wordlists grandes) |
| Numbers | Range numérico (IDOR: 1 a 9999) |
| Dates | Datas em formato customizado |
| Brute forcer | Combinações de caracteres (charset + comprimento) |
| Null payloads | Repetir mesma requisição N vezes |
| Character frobber | Modifica um caractere por vez (fuzzing de tokens) |

**Configurações úteis:**

```
Payloads → Payload Processing:
  - Add prefix: "admin"  → "admin" + payload
  - Encode: URL-encode    → evitar problemas de encoding
  - Hash: MD5            → testar hashes

Options → Request Engine:
  - Thread count: 1      # Community limita a 1
  - Delay: 100ms         # Evitar rate limiting

Options → Grep - Match:
  - "Invalid password"   # Detectar login falho
  - "Welcome"            # Detectar login bem-sucedido
```

**Nota Community:** Intruder na versão Community é artificialmente limitado (throttling de ~1 req/seg). Para velocidade, usar ffuf ou hydra.

#### 4. Scanner (Pro Only)

Scanner ativo testa automaticamente para:
- SQL Injection
- XSS (Reflected, Stored, DOM)
- Path Traversal
- Command Injection
- SSRF
- XXE
- Open Redirects

```
Configuração básica:
1. Right-click em requisição → Scan
2. Audit configuration: escolher checks
3. Aguardar resultados em Dashboard
```

#### 5. Target — Site Map

Mapeia toda a aplicação. Construído automaticamente à medida que você navega:

```
Target → Site Map
  → Organizado por domínio
  → Cada endpoint descoberto aparece aqui
  → Right-click → Spider this host (Pro)
  → Right-click → Send to Scanner
  → Filtros: only in-scope, only with responses
```

**Scope:**
```
Target → Scope → Add
  Include: https://target.com
  Exclude: https://target.com/logout
```

Definir scope impede acidente de atacar sistemas fora do escopo.

#### 6. Decoder

Encode/decode de dados em múltiplos formatos:

```
Decoder → Colar dado → selecionar operação:

Encode as: URL, HTML, Base64, ASCII hex, Hex, Octet, Binary, Gzip
Decode as: mesmos + Smart decode (detecta automaticamente)
Hash: MD5, SHA1, SHA2-256, SHA2-512
```

**Casos de uso:**
```
Base64 decode de JWT: eyJhbGciOiJIUzI1NiJ9... → {"alg":"HS256"}
URL decode de payload: %3Cscript%3E → <script>
Hex decode: 61646d696e → admin
```

#### 7. Comparer

Compara duas requisições ou respostas para identificar diferenças:

```
Uso: 
1. Send to Comparer (duas requests diferentes)
2. Compare by words ou bytes
3. Diferenças destacadas em cores

Exemplo: comparar resposta de login admin válido vs inválido
→ Identificar diferença sutil que indica success
```

#### 8. Logger

Registra todas as requisições passando pelo proxy:

```
Logger → Log all requests (incluindo não interceptadas)
→ Buscar por URL, método, status code
→ Filtrar: apenas requisições em scope
```

### Extensions — BApp Store

**Extensões gratuitas essenciais:**

| Extensão | Função |
|----------|--------|
| **Turbo Intruder** | Intruder sem throttling (substitui Community limit) |
| **Active Scan++** | Scanner adicional para Community |
| **Logger++** | Logger avançado com filtros e exportação |
| **Autorize** | Testa autorização automaticamente (IDOR/auth bypass) |
| **Param Miner** | Descobre parâmetros hidden em requisições |
| **JS Miner** | Extrai endpoints e secrets de arquivos JavaScript |
| **JSON Beautifier** | Formata JSON em responses |
| **JWT Editor** | Modifica e assina JWTs |
| **JWT4B** | Análise de JWT tokens |
| **Retire.js** | Detecta bibliotecas JS vulneráveis |
| **Copy as curl** | Converte req do Burp para comando curl |
| **Hackvector** | Encoding avançado e geração de payloads |

**Instalação:**
```
Extender → BApp Store → buscar → Install
```

### Turbo Intruder (Substituto do Intruder Pro)

```python
# Script básico para Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    for word in open('/usr/share/seclists/Discovery/Web-Content/common.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

### Atalhos Importantes do Burp

| Ação | Atalho |
|------|--------|
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Forward (Intercept) | `Ctrl+F` |
| Go to Proxy | `Ctrl+Shift+P` |
| Go to Repeater | `Ctrl+Shift+R` |
| Go to Intruder | `Ctrl+Shift+I` |
| Search | `Ctrl+F` (em texto) |
| Toggle Intercept | (botão na aba Proxy) |

### Macros e Session Handling

Para aplicações com anti-CSRF tokens ou sessões que expiram:

```
Project → Session Handling Rules → Add
  Rule Actions: Run a macro
  
Macros → Add:
  1. Gravar requisição de obtenção do token
  2. Extrair token via regex: name="csrf_token" value="([^"]+)"
  3. Usar token extraído em requisições subsequentes
```

---

## Exemplos

### Workflow Completo — Teste de Login

```
1. Configurar FoxyProxy → Burp
2. Navegar para página de login
3. Interceptar requisição POST /login
4. Analisar parâmetros: username=admin&password=test&csrf_token=abc123
5. Send to Repeater (Ctrl+R)
6. Testar manualmente:
   - username=admin' OR '1'='1'-- → SQLi
   - username=admin&password=anypass → auth bypass?
7. Send to Intruder (Ctrl+I)
8. Marcar posição: password=§test§
9. Payload: SimpleList → /usr/share/wordlists/rockyou.txt (primeiras 1000)
10. Grep Match: "Dashboard" ou "Welcome" (success indicator)
11. Start Attack → ordenar por comprimento/grep
```

### Manipulação de JWT com JWT Editor

```
1. Interceptar requisição com JWT no header:
   Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.hash

2. Send to Decoder → Base64 decode payload:
   {"user":"admin","role":"user","exp":1700000000}

3. No Repeater, com JWT Editor instalado:
   → Aba JSON Web Token aparece automaticamente
   → Modificar payload: {"user":"admin","role":"admin"}
   → Tentar "None" algorithm attack
   → Se chave fraca: brute force com wordlist

4. Reenviar com token modificado
```

### Proxychains — Rotear Ferramentas pelo Burp

```bash
# /etc/proxychains4.conf
[ProxyList]
http 127.0.0.1 8080

# Usar qualquer ferramenta via Burp
proxychains curl https://target.com
proxychains sqlmap -u "https://target.com/search?q=test"
proxychains nikto -h https://target.com
proxychains python3 exploit.py
```

### ZAP (OWASP Zed Attack Proxy) — Alternativa Open-Source

ZAP é totalmente gratuito e tem scanner ativo sem limitações.

**Instalação:**
```bash
# Debian/Ubuntu
sudo apt install zaproxy

# Download direto
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
```

**Configuração inicial ZAP:**
```
1. Tools → Options → Local Proxies → Port: 8090 (evitar conflito com Burp)
2. Configurar browser para proxy 127.0.0.1:8090
3. Importar CA: Tools → Options → Dynamic SSL Certificates → Save
4. Importar CA no browser
```

**Comparação ZAP vs Burp:**

| Feature | ZAP | Burp Suite |
|---------|-----|-----------|
| Preço | Gratuito | Community grátis / Pro pago |
| Scanner ativo | Sim (gratuito) | Só Pro |
| Burp Collaborator | Não | Só Pro |
| Interface | GUI + headless | GUI |
| CI/CD integration | Sim (Docker) | Limitado |
| API | REST API completa | Sim |
| Extensões | Marketplace | BApp Store |
| Spider | Sim | Pro only (Community parcial) |
| Fuzzer | Sim | Intruder (throttled) |

**ZAP Active Scan:**
```
1. Navegar na aplicação com proxy configurado
2. Sites tree → right-click → Attack → Active Scan
3. Aguardar resultados
4. Alerts → ordenar por risk (High, Medium, Low, Informational)
```

**ZAP via CLI (automação):**
```bash
# Scan passivo + ativo via CLI
docker run -t owasp/zap2docker-stable zap-full-scan.py \
    -t https://target.com \
    -r report.html \
    -I

# Quick scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
    -t https://target.com
```

### Burp Suite com Linha de Comando

```bash
# Iniciar Burp sem GUI (headless) com REST API
java -jar burpsuite_community.jar --unpause-spider-and-scanner

# Exportar arquivo de projeto
# File → Save Project (Pro apenas)

# Importar configurações
# Project → Import
```

### Checklist de Pentest com Burp

```
[ ] FoxyProxy configurado e ativo
[ ] Certificado CA importado no browser
[ ] Scope definido no Target
[ ] Navegar pela aplicação com Intercept OFF (logging passivo)
[ ] Analisar Site Map — endpoints descobertos
[ ] Interceptar fluxos críticos: login, registro, reset de senha, upload
[ ] Testar cada parâmetro no Repeater
[ ] Buscar campos hidden, cookies, tokens JWT
[ ] Verificar headers de segurança (Security > Inspector)
[ ] Testar CORS com Origin header manipulado
[ ] Checar responses por info disclosure (versões, stack traces, comentários)
[ ] Intruder em campos de login para brute force
[ ] Param Miner em todas as requisições
[ ] Autorize para testes de IDOR e autorização
```

---

## Módulos Relacionados

O módulo de HTTP Protocolo (`01_http_protocolo.md`) descreve as requisições e respostas que o Burp intercepta — entender a estrutura do protocolo é pré-requisito para usar o proxy de forma eficaz. Web App Fundamentos (`02_web_app_fundamentos.md`) cobre as tecnologias que geram essas requisições, contextualizando o que aparece no HTTP History. Information Gathering (`../02_reconhecimento/01_information_gathering.md`) mapeia a superfície antes de usar o proxy para exploração — recon define o escopo que se configura no Burp Target. Content Discovery (`../02_reconhecimento/02_content_discovery.md`) complementa o Intruder: o ffuf realiza em escala o mesmo fuzzing que o Repeater e o Intruder fazem manualmente. SQL Injection usa o Repeater como ferramenta principal para testes manuais iterativos. O proxy permite manipular respostas para testar reflexão de payloads de XSS, verificar headers SameSite, tokens anti-CSRF e configurações CORS, e o Burp Collaborator (versão Pro) detecta callbacks out-of-band em ataques de SSRF.

**Ferramentas mencionadas:**
- Burp Suite Community/Pro
- OWASP ZAP
- FoxyProxy (extensão browser)
- Proxychains
- Turbo Intruder (extensão Burp)
- Autorize (extensão Burp)
- JWT Editor (extensão Burp)
- Param Miner (extensão Burp)

**Referências:**
- HTB Module: Using Web Proxies
- Burp Suite Documentation: portswigger.net/burp/documentation
- OWASP ZAP: zaproxy.org
