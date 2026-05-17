---
layout: cyber
section: acesso-inicial
title: "Enumeração Ativa"
---

# 07 - Enumeração Ativa

> DNS, port scanning, enumeração de serviços e vulnerability scanning — gera tráfego no alvo.

---

## DNS — Enumeração Ativa

### Consultas Básicas com host

```bash
host -t ns target.com          # Name servers
host -t mx target.com          # Mail servers (alvos de phishing)
host -t A target.com           # IPv4 do domínio principal
host -t AAAA target.com        # IPv6
host -t TXT target.com         # SPF, DKIM, verificações de domínio
host 192.168.1.10              # Reverse lookup (PTR)
```

### Zone Transfer (AXFR)

Zone transfer replica toda a zona DNS. Quando mal configurado, expõe todos os hosts internos.

```bash
# Listar name servers primeiro
host -t ns target.com

# Tentar zone transfer em cada NS
host -l target.com ns1.target.com
host -l target.com ns2.target.com

# Com dig
dig axfr target.com @ns1.target.com
```

Se bem-sucedido: retorna lista completa de A, CNAME, MX, PTR records — mapa completo da rede interna.

### DNSRecon

Ferramenta completa para enumeração DNS.

```bash
dnsrecon -d target.com -t std         # NS, MX, SOA, A, AAAA padrão
dnsrecon -d target.com -t axfr        # tentar zone transfer
dnsrecon -d target.com -t brt \       # brute force de subdomínios
  -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsrecon -r 192.168.1.0/24            # reverse lookup em range
dnsrecon -d target.com -t goo         # Google scraping para subdomínios
```

### DNSEnum

All-in-one: NS, MX, zone transfer, brute force, Google scraping em um comando.

```bash
dnsenum target.com
dnsenum --dnsserver ns1.target.com target.com
dnsenum --enum target.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Port Scanning — Nmap

### Tipos de Scan

```bash
# SYN Scan (stealth — não completa handshake; requer root)
sudo nmap -sS 192.168.1.10                     # top 1000 portas
sudo nmap -sS -p- --open 192.168.1.10          # todas as 65535 portas
sudo nmap -sS -p 22,80,443,445,3389 192.168.1.10

# TCP Connect (não requer root; aparece em logs de conexão)
nmap -sT 192.168.1.10

# UDP (lento — serviços críticos: SNMP 161, DNS 53, DHCP 67, NTP 123)
sudo nmap -sU --top-ports=20 192.168.1.10
sudo nmap -sU -p 53,67,68,161,162 192.168.1.10

# Combinado TCP + UDP
sudo nmap -sS -sU -p T:22,80,443,U:53,161 192.168.1.10
```

### Detecção de Versões e OS

```bash
sudo nmap -sV 192.168.1.10          # versão dos serviços
sudo nmap -O 192.168.1.10           # OS fingerprinting
sudo nmap -A 192.168.1.10           # agressivo: OS + versão + NSE default + traceroute
```

### NSE Scripts

Scripts em `/usr/share/nmap/scripts/` (extensão `.nse`). Índice em `script.db`. Cada script tem uma ou mais **categorias** — escolha define risco e propósito.

#### Categorias NSE

| Categoria | Função | Risco |
|-----------|--------|-------|
| `safe` | Não interferem no alvo | Baixo |
| `vuln` | Detectam vulnerabilidades conhecidas | Médio (alguns intrusivos) |
| `exploit` | Tentam explorar a vulnerabilidade | Alto — pode comprometer alvo |
| `intrusive` | Geram alto tráfego, podem crashar serviço | Alto |
| `auth` | Bypass/teste de autenticação, credenciais default | Médio |
| `brute` | Brute force de credenciais | Médio — gera lockout |
| `discovery` | Descoberta de serviços, hosts, recursos | Baixo |
| `dos` | Denial of Service | **Não usar em prod** |
| `fuzzer` | Fuzzing de protocolos | Alto |
| `malware` | Detecta backdoors/malware no alvo | Baixo |
| `default` | Roda com `-sC` ou `-A` | Misto |

Listar scripts de uma categoria:

```bash
cd /usr/share/nmap/scripts/
cat script.db | grep '"vuln"'
# Entry { filename = "smb-vuln-ms17-010.nse", categories = { "intrusive", "vuln", } }
```

#### Uso

```bash
# Por categoria
nmap -sV --script "vuln" 192.168.1.10
nmap --script "vuln and safe" 192.168.1.10     # sem risco de crash
nmap --script "not intrusive" 192.168.1.10

# Por serviço (wildcards)
nmap --script smb-vuln-* -p 445 192.168.1.10
nmap --script "smb-* and not brute" -p 445 192.168.1.10

# Script específico
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10
nmap --script smb-enum-shares,smb-enum-users -p 445 192.168.1.10
nmap --script http-title,http-headers,http-enum -p 80,443,8080 192.168.1.10
nmap --script ssh-hostkey -p 22 192.168.1.10
nmap --script ftp-anon -p 21 192.168.1.10

# Com argumentos
nmap --script smtp-enum-users --script-args smtp-enum-users.methods=VRFY,EXPN,RCPT -p 25 IP
```

#### vulners — Vulnerability Scanner Lightweight

Script `vulners.nse` consulta o database Vulners online com base no **version banner** detectado pelo `-sV`. Categorias: `safe`, `vuln`, `external`.

```bash
sudo nmap -sV --script vulners 192.168.1.10

# Output exemplo:
# 443/tcp open  http  Apache httpd 2.4.49 ((Unix))
# | vulners:
# |   cpe:/a:apache:http_server:2.4.49:
# |       CVE-2021-41773  4.3  https://vulners.com/cve/CVE-2021-41773  *EXPLOIT*
```

Marcação `*EXPLOIT*` = PoC público disponível. CVSS exibido lado a lado.

Limitações: depende totalmente do `-sV` acertar a versão. Para versão genérica (sem banner detalhado), retorna vazio.

#### Custom NSE Scripts por CVE

Quando NSE built-in não cobre um CVE específico:

```bash
# 1. Buscar script no GitHub
# "CVE-2021-41773 nse" → encontrar repo

# 2. Copiar para diretório padrão
sudo cp http-vuln-cve2021-41773.nse /usr/share/nmap/scripts/

# 3. Atualizar índice
sudo nmap --script-updatedb

# 4. Executar
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.1.10
```

Verificar antes de rodar: ler o `.nse` (Lua) — script malicioso pode executar comandos arbitrários no host atacante.

### Performance

```bash
-T4              # agressivo — bom para labs e redes locais
-T2              # furtivo — ambientes com IDS/IPS
--min-rate 1000  # mínimo 1000 pacotes/segundo
--max-retries 1  # reduzir retransmissões
-Pn              # pular host discovery (assumir host up)
-n               # sem resolução DNS (mais rápido)
--open           # mostrar apenas portas abertas
```

### Output e Workflow

```bash
# Salvar em todos os formatos (texto, XML, grepável)
sudo nmap -sS -sV -A 192.168.1.0/24 -oA scan_resultado

# Workflow recomendado
# 1. Discovery rápido
sudo nmap -sn 192.168.1.0/24 -oA hosts_vivos

# 2. Scan top portas na subnet
sudo nmap -sS --top-ports=100 --open -T4 192.168.1.0/24 -oA scan_rapido

# 3. Scan completo nos hosts de interesse
sudo nmap -sS -p- -sV -A -T4 192.168.1.10 -oA scan_completo

# 4. Scripts por serviço encontrado
sudo nmap --script smb-vuln-* -p 445 192.168.1.10
```

---

## Enumeração de Serviços

### SMB / NetBIOS (Porta 445, 139)

```bash
# Vulnerabilidades SMB
nmap --script smb-vuln-ms17-010 -p 445 IP       # EternalBlue
nmap --script smb-security-mode -p 445 IP        # SMB signing (necessário para relay)

# Enumeração completa
enum4linux -a IP                    # usuários, grupos, shares, políticas de senha
enum4linux -U IP                    # usuários apenas
enum4linux -S IP                    # shares
enum4linux -P IP                    # políticas de lockout

# Hosts NetBIOS na rede
nbtscan -r 192.168.1.0/24

# Acesso a shares
smbclient -L //IP/ -N               # listar (null session)
smbclient //IP/share -N             # conectar sem credenciais
smbclient //IP/share -U DOMAIN\\usuario

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u usuario -p senha --shares
crackmapexec smb IP -u usuario -p senha -x "whoami"
```

### SMTP (Porta 25, 587, 465)

```bash
# Banner grabbing
nc -nv IP 25

# Enumeração de usuários via VRFY
VRFY admin
VRFY root

# Via RCPT TO (mais universal)
MAIL FROM: test@test.com
RCPT TO: admin@target.com
# 250 OK → usuário existe; 550 User unknown → não existe

# Via Nmap
nmap --script smtp-enum-users \
  --script-args smtp-enum-users.methods=VRFY,EXPN,RCPT \
  -p 25 IP
```

### SNMP (Porta UDP 161)

```bash
# Descoberta de community strings (padrão: public, private)
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt IP
onesixtyone -c community_list.txt 192.168.1.0/24

# Dump completo da árvore MIB
snmpwalk -c public -v1 IP
snmpwalk -c public -v2c IP

# Output formatado (usuários, processos, software, interfaces)
snmp-check IP -c public
```

MIBs úteis para Windows:

| OID | Conteúdo |
|-----|---------|
| `1.3.6.1.4.1.77.1.2.25` | Usuários locais |
| `1.3.6.1.2.1.25.4.2.1.2` | Processos em execução |
| `1.3.6.1.2.1.25.6.3.1.2` | Software instalado |
| `1.3.6.1.2.1.6.13.1.3` | Portas TCP abertas |

```bash
snmpwalk -c public -v1 IP 1.3.6.1.4.1.77.1.2.25     # usuários
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.4.2.1.2    # processos
```

### Outros Serviços

```bash
# FTP (21)
nmap --script ftp-anon -p 21 IP
ftp IP  # user: anonymous, pass: email@mail.com

# RDP (3389)
nmap --script rdp-enum-encryption -p 3389 IP
nmap --script rdp-vuln-ms12-020 -p 3389 IP

# LDAP (389, 636)
ldapsearch -x -H ldap://IP -b "dc=target,dc=com"
nmap --script ldap-search -p 389 IP

# MySQL (3306)
nmap --script mysql-info,mysql-enum -p 3306 IP
```

---

## Vulnerability Scanning

### Nessus

```bash
sudo systemctl start nessusd
# Acessar: https://127.0.0.1:8834
```

Tipos de scan:

| Tipo | Quando usar |
|------|------------|
| Basic Network Scan | Sem credenciais — visão externa |
| Credentialed Scan | Com usuário/senha — cobertura muito maior (patches, configs) |
| Web Application Tests | Foco em aplicações web |

Priorização de CVSS:
- **≥ 9.0** (Crítico) → explorar diretamente
- **7.0–8.9** (Alto) → verificar contexto antes
- **4.0–6.9** (Médio) → encadear com outros vetores
- **< 4.0** → documentar, não priorizar

### Nikto — Web Servers

```bash
nikto -h http://IP
nikto -h http://IP -p 8080
nikto -h https://IP -ssl
nikto -h http://IP -o resultado.txt -Format txt
```

Encontra: versões desatualizadas, diretórios padrão (`/phpmyadmin`), arquivos de config expostos, métodos HTTP inseguros (PUT/DELETE).

### Workflow Completo

```bash
# 1. Scan de serviços com versões
sudo nmap -sS -sV -p- --open -T4 192.168.1.10 -oA scan_alvo

# 2. Scripts NSE por serviço
sudo nmap --script smb-vuln-* -p 445 192.168.1.10
sudo nmap --script http-enum,http-headers -p 80,443 192.168.1.10

# 3. Nikto nas portas web
nikto -h http://192.168.1.10

# 4. SearchSploit nas versões identificadas
searchsploit apache 2.4.49
searchsploit openssh 7.2

# 5. Nessus credentialed para cobertura total
```

---

## Ataques de Senha em Serviços de Rede

### Hydra — Multi-protocolo

```bash
# SSH
sudo hydra -l george -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
sudo hydra -l admin -P wordlist.txt -t 4 ssh://192.168.1.10   # menos agressivo

# RDP
sudo hydra -l administrator -P wordlist.txt rdp://192.168.1.10
sudo hydra -L users.txt -p "Password123" rdp://192.168.1.10

# HTTP POST Form
sudo hydra -l admin -P wordlist.txt 192.168.1.10 \
  http-post-form "/login:username=^USER^&password=^PASS^:Login failed"

# SMTP
sudo hydra -l admin@target.com -P wordlist.txt smtp://192.168.1.10:587

# Flags essenciais
# -t 4   → threads (padrão 16 — reduzir para evitar lockout)
# -f     → parar na primeira credencial válida
# -V     → verbose (cada tentativa)
```

### Password Spray — Evitar Lockout

Testar uma senha em muitos usuários — evita bloqueio por usuário.

```bash
# Via Hydra
sudo hydra -L users.txt -p "Password123" rdp://192.168.1.10 -t 4

# Via CrackMapExec (SMB)
crackmapexec smb 192.168.1.10 -u users.txt -p 'Password123' --continue-on-success
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success

# "(Pwn3d!)" no output = administrador local confirmado
```

### Medusa — Alternativa

```bash
medusa -h 192.168.1.10 -u admin -P wordlist.txt -M ssh
medusa -h 192.168.1.10 -U users.txt -p Password123 -M rdp
```

### Cuidados Operacionais

```
[ ] Verificar política de lockout antes (enum4linux -P IP)
[ ] Começar com password spray (1 senha / usuário)
[ ] Usar -t 4 ou menos em ambientes com IDS
[ ] Monitorar mudança no padrão de resposta (sinal de lockout)
[ ] Para HTTP: verificar CAPTCHA ou rate limiting antes de iniciar
```

---

## Módulos Relacionados

`06_reconhecimento_passivo.md` é a fase anterior — OSINT deve completar antes da enumeração ativa pra reduzir ruído inicial. `04_password_spraying_owa.md` é spray específico pra OWA/Exchange usando o conhecimento obtido aqui. `09_active_directory/08_bloodhound_e_enumeracao.md` cobre enumeração AD após acesso inicial.
