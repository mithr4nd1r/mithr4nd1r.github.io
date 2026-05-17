---
layout: cyber
section: active-directory
title: "Kerberos: Fundamentos e Arquitetura"
---

# Kerberos: Fundamentos e Arquitetura

# O que é?

Kerberos é um protocolo de autenticação de rede baseado em criptografia simétrica e no modelo de trusted third party. Foi desenvolvido no MIT (Massachusetts Institute of Technology) no final da década de 1980 como parte do Projeto Athena — uma iniciativa de computação distribuída que precisava resolver o problema de autenticação segura em redes abertas onde qualquer nó poderia interceptar pacotes.

O nome Kerberos vem da mitologia grega: Cérbero, o cão de três cabeças que guarda a entrada do submundo. A escolha é deliberada — o protocolo envolve três partes fundamentais: o cliente (quem quer se autenticar), o servidor de autenticação (quem verifica a identidade), e o serviço alvo (quem concede ou nega acesso). Sem a aprovação das três cabeças, o acesso não acontece.

A versão utilizada em ambientes modernos é o Kerberos 5, definida pelo RFC 4120 (publicado em 2005, substituindo o RFC 1510 de 1993). Extensões proprietárias da Microsoft ao protocolo são especificadas em documentos MS-KILE (Microsoft Kerberos Protocol Extension) e MS-PAC (Privilege Attribute Certificate Data Structure), disponíveis publicamente no Open Specifications da Microsoft.

**Diferença fundamental em relação ao NTLM:**

NTLM é um protocolo challenge-response: o servidor emite um desafio, o cliente responde provando que conhece a senha sem enviar a senha diretamente. O problema é que esse modelo exige que o servidor valide a resposta — frequentemente indo até um Domain Controller a cada autenticação. Além disso, o hash NTLM capturado pode ser reutilizado diretamente (Pass-the-Hash) sem conhecer a senha real.

Kerberos adota um modelo de tickets: a autenticação ocorre uma única vez perante uma autoridade central (o KDC), que emite tickets criptografados. Esses tickets são apresentados aos serviços como prova de identidade. A senha nunca trafega na rede — nem mesmo o hash. O que circula são timestamps e tickets cifrados com chaves derivadas da senha, que expiram e não podem ser reutilizados além do lifetime configurado.

**PKI vs Kerberos:**

Infraestrutura de chave pública (PKI) resolve autenticação com certificados digitais e criptografia assimétrica. Kerberos usa exclusivamente criptografia simétrica (chaves compartilhadas), o que o torna mais eficiente computacionalmente mas exige que a autoridade central (KDC) compartilhe uma chave secreta com cada participante. Em ambientes AD, a chave de cada conta é derivada do hash NT da senha da conta.

**RFCs e especificações relevantes:**
- RFC 4120: The Kerberos Network Authentication Service (V5) — especificação base
- RFC 4121: The Kerberos Version 5 GSS-API Mechanism — integração com GSSAPI
- RFC 6113: A Generalized Framework for Kerberos Pre-Authentication
- RFC 6806: Kerberos Principal Name Canonicalization and Cross-Realm Referrals
- MS-KILE: Microsoft Kerberos Protocol Extension — extensões proprietárias (PAC, S4U, etc.)
- MS-PAC: Privilege Attribute Certificate Data Structure — estrutura de autorização Microsoft
- MS-APDS: Authentication Protocol Domain Support Specification

**Por que Kerberos é mais seguro que NTLM na teoria:**
- A senha nunca trafega na rede em nenhuma forma
- Tickets têm lifetime limitado (padrão 10 horas no AD) e expiram
- Suporte a autenticação mútua — cliente verifica identidade do servidor também
- Replay attacks são prevenidos por timestamps e nonces
- Chaves AES256 derivadas via PBKDF2 são computacionalmente custosas de quebrar

# Onde é implementado?

Kerberos é o protocolo de autenticação padrão de todo domínio Active Directory desde o Windows 2000. Antes disso, domínios Windows usavam exclusivamente NTLM (LM/NT via NetLogon). Com o AD, a Microsoft adotou Kerberos como mecanismo primário, mantendo NTLM apenas como fallback para cenários de compatibilidade.

**Presença em ambientes Windows:**

Todo Domain Controller Windows Server executa o KDC (Key Distribution Center) na porta 88/TCP+UDP. Não é um serviço opcional — é um dos serviços fundamentais do AD. Cada DC é simultaneamente um servidor Kerberos completo. A conta `krbtgt` existe em todo domínio AD e é a chave mestra que assina todos os TGTs.

Serviços que dependem de autenticação Kerberos em ambientes AD corporativos:
- SMB/CIFS (acesso a file shares, `\\servidor\share`) — SPN: `cifs/hostname`
- LDAP (consultas ao Active Directory) — SPN: `ldap/dc.domain.com`
- HTTP com Windows Authentication/Negotiate — SPN: `http/webapp.domain.com`
- Microsoft SQL Server — SPN: `MSSQLSvc/sql.domain.com:1433`
- Microsoft Exchange — SPN: `exchangeMDB/mail.domain.com`
- Remote Desktop (RDP com NLA) — SPN: `TERMSRV/server.domain.com`
- WMI e PowerShell Remoting — SPN: `host/server.domain.com`
- Global Catalog — SPN: `gc/dc.domain.com`

**Presença em ambientes não-Windows:**

Samba 4 (em Linux/BSD) implementa um KDC Kerberos completo e é compatível com Active Directory. Ambientes Linux integrados ao AD via SSSD ou Winbind usam Kerberos para autenticação. macOS integra natively ao AD via MIT Kerberos embutido no sistema operacional. Qualquer sistema Unix que usa PAM com pam_krb5 participa de um domínio Kerberos.

MIT Kerberos (krb5) e Heimdal são as implementações open source mais comuns. MIT Kerberos é padrão no RHEL, Debian/Ubuntu, e macOS. Heimdal é padrão no FreeBSD.

**Ambiente híbrido e cloud:**

Azure Active Directory não usa Kerberos nativamente para autenticação cloud — usa OAuth 2.0 e SAML. Porém, para integração híbrida (on-premises AD + Azure AD), a Microsoft introduziu o Azure AD Kerberos: o Azure AD pode emitir tickets Kerberos para usuários que precisam acessar recursos locais a partir de dispositivos não-ingressados no domínio AD. Isso é configurado pelo Azure AD Kerberos Server Object no AD on-premises.

**Portas relevantes:**
```
88/TCP   Kerberos — autenticação AS e TGS (principal)
88/UDP   Kerberos — também suportado (pacotes menores)
464/TCP  kpasswd — troca de senha via Kerberos
464/UDP  kpasswd — também suportado
749/TCP  kadmin — administração do KDC (MIT Kerberos, não usado no AD)
```

**Por que praticamente todo ambiente corporativo médio/grande usa Kerberos:**

Qualquer empresa que usa Windows com Active Directory usa Kerberos automaticamente. Cada login de usuário, cada acesso a um file server, cada query LDAP, cada conexão SQL autenticada por AD — todos passam por Kerberos. Em uma empresa com 500 usuários, o DC processa dezenas de milhares de requisições Kerberos por dia.

# Como funciona de forma adequada?

O Kerberos legítimo opera sobre um modelo de triângulo de confiança entre três entidades. A beleza do design é que o serviço alvo nunca precisa contatar o KDC diretamente para validar uma autenticação — basta ter a chave compartilhada certa.

**O triângulo de confiança:**

```
                    +---------------------------+
                    |      KDC (no DC)          |
                    |                           |
                    |  Conhece chave de Alice   |
                    |  Conhece chave do Servico |
                    |  Assina TGTs com krbtgt   |
                    +---------------------------+
                      /                       \
          Fase 1: Alice                   Fase 2: Alice
          pede TGT                        pede TGS
          (AS-REQ/REP)                    (TGS-REQ/REP)
                    /                       \
    +--------------+                         +--------------+
    |    ALICE     |------- Fase 3: -------->|   SERVICO    |
    |  (cliente)   |   apresenta TGS         |  (IIS/SQL/   |
    |              |   (AP-REQ/REP)          |   CIFS/LDAP) |
    +--------------+                         +--------------+
```

**O TGT como passe de transporte:**

O TGT (Ticket Granting Ticket) é o "passe de transporte" que Alice carrega após o login. Com ele, Alice pode solicitar acesso a qualquer serviço do domínio sem precisar redigitar a senha. O TGT é criptografado com o hash da conta `krbtgt` — Alice não consegue ler seu conteúdo, mas pode apresentá-lo ao KDC como prova de que foi autenticada.

Analogia: o TGT é como um bilhete de metrô — você o compra uma vez (provando que pagou), e depois pode usá-lo múltiplas vezes para acessar os trens (serviços) sem passar pela bilheteria novamente.

**O TGS como bilhete de acesso ao serviço:**

O TGS (Ticket Granting Service ticket, também chamado de Service Ticket) é o bilhete específico para um serviço. Alice apresenta o TGT ao KDC pedindo acesso ao SQL Server — o KDC emite um TGS criptografado com o hash da conta de serviço do SQL. Alice apresenta esse TGS ao SQL Server, que o decripta com sua própria chave e confirma a identidade de Alice.

**Fluxo simplificado legítimo:**

```
FASE 1 — Login (AS Exchange):
    Alice            KDC (AS)
      |                  |
      |--- AS-REQ ------>|  Alice prova identidade com timestamp
      |                  |  cifrado com hash NT da senha de Alice
      |<-- AS-REP -------|  KDC retorna:
      |                  |    - TGT (cifrado com hash do krbtgt)
      |                  |    - Session Key 1 (cifrada com hash de Alice)

FASE 2 — Solicitar acesso a servico (TGS Exchange):
    Alice            KDC (TGS)
      |                  |
      |--- TGS-REQ ----->|  Alice apresenta TGT + autenticador
      |                  |  e pede ticket para SPN especifico
      |<-- TGS-REP ------|  KDC retorna:
      |                  |    - TGS (cifrado com hash do servico alvo)
      |                  |    - Session Key 2 (cifrada com Session Key 1)

FASE 3 — Acessar o servico (AP Exchange):
    Alice           Servico
      |                  |
      |--- AP-REQ ------>|  Alice apresenta TGS + autenticador
      |                  |  Servico decifra TGS com sua propria chave
      |<-- AP-REP --------|  Servico confirma autenticacao mutua
      |                  |
      |  [acesso concedido baseado no PAC dentro do TGS]
```

**Por que Kerberos evita envio de senha na rede:**

Em nenhum momento a senha de Alice trafega. Na Fase 1, Alice envia um timestamp cifrado com o hash da senha — o KDC decifra com o hash armazenado no AD e verifica se o timestamp é recente (tolerância de 5 minutos). Isso prova posse do hash sem transmiti-lo. O hash NT é tecnicamente a "chave" de Alice no protocolo.

**Pré-autenticação (PA-ENC-TIMESTAMP):**

Por padrão, o KDC exige pré-autenticação antes de emitir um TGT. O cliente deve incluir no AS-REQ um campo `padata` contendo um timestamp cifrado com o hash NT do usuário. O KDC decifra esse timestamp e verifica:
1. O timestamp é recente (dentro de 5 minutos do relógio do DC)
2. Não foi reutilizado (proteção anti-replay)

Sem pré-autenticação habilitada (`DONT_REQUIRE_PREAUTH`), o KDC emite o AS-REP sem verificação — o que possibilita AS-REP Roasting.

**Lifetime e renovação de tickets:**

Tickets Kerberos têm lifetime configurável por política de domínio. Os padrões do AD:
```
TGT maximum lifetime:    10 horas (600 minutos)
TGT maximum renewal:     7 dias (10080 minutos)
Service Ticket lifetime: 10 horas (segue o TGT pai)
```

Ao expirar, Alice pode renovar o TGT (sem redigitar a senha) até atingir o `renewmax`. Após isso, é necessária nova autenticação completa.

**Autenticação mútua:**

Quando Alice solicita `MUTUAL-REQUIRED` no AP-REQ, o serviço retorna um AP-REP contendo o timestamp de Alice cifrado com a Session Key 2. Isso prova que o serviço genuinamente decifrou o TGS (tem a chave correta) — protegendo Alice contra servidores falsos.

**O papel do PAC (Privilege Attribute Certificate):**

O PAC é uma extensão Microsoft incluída no campo `authorization-data` dos tickets. Contém o SID do usuário, RIDs dos grupos, e informações de logon. O serviço lê o PAC para determinar permissões de acesso — sem precisar consultar o AD a cada requisição. O PAC carrega assinaturas do KDC e do serviço para garantir integridade.

---

## A Arquitetura Kerberos no AD

### Visão Geral da Arquitetura

```
┌──────────────────────────────────────────────────────────────────────┐
│                     ACTIVE DIRECTORY / KDC                           │
│                                                                      │
│   ┌─────────────────────┐      ┌──────────────────────────────────┐  │
│   │  AS - Authentication │      │  TGS - Ticket Granting Service   │  │
│   │      Service         │      │                                  │  │
│   │  (porta 88/TCP+UDP)  │      │  (porta 88/TCP+UDP, mesmo DC)    │  │
│   └─────────────────────┘      └──────────────────────────────────┘  │
│                                                                      │
│   Chave secreta krbtgt (hash NT do account krbtgt) ← segredo do KDC  │
└──────────────────────────────────────────────────────────────────────┘
          ↑↓ AS-REQ / AS-REP                ↑↓ TGS-REQ / TGS-REP
┌──────────────────┐                 ┌──────────────────────────────┐
│     CLIENTE      │ ──AP-REQ──────▶ │        SERVIÇO ALVO          │
│  (workstation,   │ ◀─AP-REP─────── │  (IIS, SQL, CIFS, LDAP...)   │
│   usuário)       │                 │  Chave = hash NT do svc acct │
└──────────────────┘                 └──────────────────────────────┘
```

### Componentes Fundamentais

**KDC (Key Distribution Center)**: Em Active Directory, o KDC é executado em todo Domain Controller. Não é um servidor separado. O KDC contém dois serviços lógicos:
- **AS (Authentication Service)**: Lida com AS-REQ e AS-REP. Emite TGTs.
- **TGS (Ticket Granting Service)**: Lida com TGS-REQ e TGS-REP. Emite Service Tickets.

**krbtgt**: Conta de serviço especial criada automaticamente em toda instalação de AD. Seu hash NT é usado para assinar e criptografar todos os TGTs emitidos pelo KDC. É o segredo mais crítico do domínio. Comprometer o hash do krbtgt = comprometer o domínio de forma permanente até rotação manual.

**SPN (Service Principal Name)**: Identificador único de uma instância de serviço. Formato:
```
serviceclass/host:port/servicename@REALM

Exemplos reais:
HTTP/webserver.corp.local:80@CORP.LOCAL
MSSQLSvc/sqlserver.corp.local:1433@CORP.LOCAL
CIFS/fileserver.corp.local@CORP.LOCAL
HOST/dc01.corp.local@CORP.LOCAL
LDAP/dc01.corp.local@CORP.LOCAL
GC/dc01.corp.local/corp.local@CORP.LOCAL   ← Global Catalog
```

SPNs são registrados no atributo `servicePrincipalName` de objetos de usuário ou computador no AD. Um service account de SQL Server, por exemplo, terá `MSSQLSvc/hostname:1433` registrado no seu objeto de usuário.

---

### Fluxo Completo Kerberos — Passo a Passo

```
╔═══════════════════════════════════════════════════════════════════════╗
║                    FLUXO KERBEROS COMPLETO                           ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  FASE 1: OBTENÇÃO DO TGT (Authentication Service Exchange)           ║
║                                                                       ║
║  Cliente                           KDC (AS)                          ║
║     │                                  │                             ║
║     │──── AS-REQ ───────────────────▶  │                             ║
║     │  {                               │                             ║
║     │    cname: "alice",               │                             ║
║     │    realm: "CORP.LOCAL",          │                             ║
║     │    sname: "krbtgt/CORP.LOCAL",   │                             ║
║     │    till: <expiração>,            │                             ║
║     │    nonce: <random>,              │                             ║
║     │    padata: [PA-ENC-TIMESTAMP]    │  ← pre-auth                 ║
║     │      (timestamp cifrado com      │                             ║
║     │       hash NT de alice)          │                             ║
║     │  }                               │                             ║
║     │                                  │                             ║
║     │                                  │  KDC verifica:              ║
║     │                                  │  1. alice existe no AD      ║
║     │                                  │  2. decifra timestamp com   ║
║     │                                  │     hash de alice           ║
║     │                                  │  3. valida timestamp (±5min)║
║     │                                  │                             ║
║     │  ◀─── AS-REP ──────────────────  │                             ║
║     │  {                               │                             ║
║     │    crealm: "CORP.LOCAL",         │                             ║
║     │    cname: "alice",               │                             ║
║     │    ticket: TGT {                 │  ← cifrado com hash krbtgt  ║
║     │      tkt-vno: 5,                 │    (cliente NÃO pode ler)   ║
║     │      realm: "CORP.LOCAL",        │                             ║
║     │      sname: "krbtgt/CORP.LOCAL", │                             ║
║     │      enc-part: {                 │                             ║
║     │        flags: [FORWARDABLE,      │                             ║
║     │                RENEWABLE,        │                             ║
║     │                PRE-AUTHENT],     │                             ║
║     │        key: session_key_1,       │                             ║
║     │        crealm: "CORP.LOCAL",     │                             ║
║     │        cname: "alice",           │                             ║
║     │        authtime: <agora>,        │                             ║
║     │        starttime: <agora>,       │                             ║
║     │        endtime: <+10h>,          │                             ║
║     │        renew-till: <+7d>,        │                             ║
║     │        caddr: [IP do cliente],   │                             ║
║     │        authorization-data: [PAC] │  ← PAC dentro do TGT       ║
║     │      }                           │                             ║
║     │    },                            │                             ║
║     │    enc-part: {                   │  ← cifrado com hash de alice║
║     │      key: session_key_1,         │    (cliente pode ler)       ║
║     │      last-req: [...],            │                             ║
║     │      nonce: <mesmo do req>,      │                             ║
║     │      key-expiration: <data>,     │                             ║
║     │      flags: [...],               │                             ║
║     │      authtime: <agora>           │                             ║
║     │    }                             │                             ║
║     │  }                               │                             ║
║     │                                  │                             ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  FASE 2: OBTENÇÃO DO SERVICE TICKET (TGS Exchange)                   ║
║                                                                       ║
║  Cliente                           KDC (TGS)                         ║
║     │                                  │                             ║
║     │──── TGS-REQ ──────────────────▶  │                             ║
║     │  {                               │                             ║
║     │    padata: [PA-TGS-REQ] {        │                             ║
║     │      ap-req: {                   │                             ║
║     │        ticket: <TGT>,            │  ← TGT opaco (cifrado)      ║
║     │        authenticator: {          │  ← cifrado com session_key_1║
║     │          crealm: "CORP.LOCAL",   │                             ║
║     │          cname: "alice",         │                             ║
║     │          cksum: <checksum>,      │                             ║
║     │          cusec: <microsegundos>, │                             ║
║     │          ctime: <timestamp>      │                             ║
║     │        }                         │                             ║
║     │      }                           │                             ║
║     │    },                            │                             ║
║     │    req-body: {                   │                             ║
║     │      kdc-options: [FORWARDABLE], │                             ║
║     │      sname: "HTTP/web.corp.local"│  ← SPN do serviço desejado  ║
║     │      realm: "CORP.LOCAL",        │                             ║
║     │      till: <expiração>,          │                             ║
║     │      nonce: <random>,            │                             ║
║     │      etype: [AES256, AES128,     │                             ║
║     │               RC4-HMAC]          │  ← tipos aceitos            ║
║     │    }                             │                             ║
║     │  }                               │                             ║
║     │                                  │                             ║
║     │                                  │  KDC verifica:              ║
║     │                                  │  1. decifra TGT com krbtgt  ║
║     │                                  │  2. extrai session_key_1    ║
║     │                                  │  3. decifra authenticator   ║
║     │                                  │  4. valida timestamp (±5min)║
║     │                                  │  5. busca SPN no AD         ║
║     │                                  │  6. encontra service account║
║     │                                  │  7. obtém hash do svc acct  ║
║     │                                  │                             ║
║     │  ◀─── TGS-REP ──────────────────  │                             ║
║     │  {                               │                             ║
║     │    ticket: ServiceTicket {       │  ← cifrado com hash do svc  ║
║     │      sname: "HTTP/web.corp.local"│    account (NÃO com krbtgt) ║
║     │      enc-part: {                 │                             ║
║     │        flags: [...],             │                             ║
║     │        key: session_key_2,       │                             ║
║     │        crealm: "CORP.LOCAL",     │                             ║
║     │        cname: "alice",           │                             ║
║     │        transited: [...],         │                             ║
║     │        authtime: <agora>,        │                             ║
║     │        endtime: <+10h>,          │                             ║
║     │        authorization-data: [PAC] │                             ║
║     │      }                           │                             ║
║     │    },                            │                             ║
║     │    enc-part: {                   │  ← cifrado com session_key_1║
║     │      key: session_key_2,         │    (cliente pode ler)       ║
║     │      nonce: <mesmo do req>,      │                             ║
║     │      flags: [...]                │                             ║
║     │    }                             │                             ║
║     │  }                               │                             ║
║     │                                  │                             ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  FASE 3: ACESSO AO SERVIÇO (Application Exchange)                    ║
║                                                                       ║
║  Cliente                                            Serviço          ║
║     │                                                  │             ║
║     │──── AP-REQ ─────────────────────────────────▶   │             ║
║     │  {                                               │             ║
║     │    pvno: 5,                                      │             ║
║     │    ap-options: [MUTUAL-REQUIRED],                │             ║
║     │    ticket: <ServiceTicket>,                      │ ← opaco     ║
║     │    authenticator: {                              │ ← cifrado   ║
║     │      crealm: "CORP.LOCAL",                      │   com       ║
║     │      cname: "alice",                             │   session_  ║
║     │      cksum: <checksum da req>,                  │   key_2     ║
║     │      cusec: <microsegundos>,                    │             ║
║     │      ctime: <timestamp>,                        │             ║
║     │      subkey: <optional subkey>,                 │             ║
║     │      seq-number: <seq>,                         │             ║
║     │      authorization-data: [...]                  │             ║
║     │    }                                             │             ║
║     │  }                                               │             ║
║     │                                                  │             ║
║     │                                                  │ Serviço:    ║
║     │                                                  │ 1. decifra  ║
║     │                                                  │    ticket   ║
║     │                                                  │    com seu  ║
║     │                                                  │    próprio  ║
║     │                                                  │    hash     ║
║     │                                                  │ 2. extrai   ║
║     │                                                  │    session_ ║
║     │                                                  │    key_2    ║
║     │                                                  │ 3. decifra  ║
║     │                                                  │    authen-  ║
║     │                                                  │    ticator  ║
║     │                                                  │ 4. valida   ║
║     │                                                  │    timestamp║
║     │                                                  │ 5. verifica ║
║     │                                                  │    PAC      ║
║     │                                                  │    (opc.)   ║
║     │  ◀─── AP-REP ──────────────────────────────────  │             ║
║     │  {                                               │             ║
║     │    enc-part: {                                   │             ║
║     │      ctime: <echo do client>,                   │             ║
║     │      cusec: <echo>,                              │             ║
║     │      subkey: <server subkey>,                   │             ║
║     │      seq-number: <seq>                           │             ║
║     │    }                                             │             ║
║     │  }                                               │             ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

### PAC — Privilege Attribute Certificate

O PAC é uma extensão Microsoft ao protocolo Kerberos padrão (definido em MS-PAC). É incluído no campo `authorization-data` dos tickets e contém informações de autorização do usuário.

**Conteúdo do PAC:**
```
PAC (Privilege Attribute Certificate)
├── LOGON_INFO (PAC_LOGON_INFO)
│   ├── LogonTime, LogoffTime, PasswordLastSet
│   ├── EffectiveName (sAMAccountName)
│   ├── FullName, LogonScript, ProfilePath
│   ├── HomeDirectory, HomeDrive
│   ├── LogonCount, BadPasswordCount
│   ├── UserId (RID do usuário, ex: 1105)
│   ├── PrimaryGroupId (RID do grupo primário, ex: 513)
│   ├── GroupCount + GroupIds[] (RIDs dos grupos)
│   │   └── [513 (Domain Users), 512 (Domain Admins), ...]
│   ├── UserFlags
│   ├── UserSessionKey
│   ├── LogonServer, LogonDomainName
│   ├── LogonDomainId (Domain SID, ex: S-1-5-21-...)
│   ├── UserAccountControl
│   ├── SidCount + ExtraSids[]  ← SIDs adicionais (cross-domain)
│   └── ResourceGroupCount + ResourceGroupIds[]
│
├── CLIENT_INFO (PAC_CLIENT_INFO)
│   ├── ClientId (timestamp de autenticação)
│   └── Name (nome do cliente)
│
├── UPN_DNS_INFO
│   ├── UPN (User Principal Name, ex: alice@corp.local)
│   └── DnsDomainName (CORP.LOCAL)
│
├── SERVER_CHECKSUM    ← HMAC-MD5 ou HMAC-SHA1 assinado com hash do service account
└── KDC_CHECKSUM      ← HMAC-MD5 ou HMAC-SHA1 assinado com hash do krbtgt
```

**Como o PAC é verificado:**

Quando um serviço recebe um AP-REQ:
1. Decifra o Service Ticket com seu próprio hash
2. Lê o PAC do `authorization-data`
3. **Opcionalmente** contacta o KDC via Netlogon (`NetrLogonSamLogon`) para validar o PAC — isso é raro na prática
4. A maioria dos serviços Windows verifica apenas o `SERVER_CHECKSUM` com sua própria chave
5. O `KDC_CHECKSUM` é verificado apenas pelo KDC (e pelo Netlogon)

Implicação para ataques: como a maioria dos serviços NÃO valida o PAC com o KDC, um Silver Ticket forjado com PAC falso é aceito pelo serviço sem que o KDC saiba.

---

### Tipos de Criptografia (Encryption Types / etypes)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ETYPE  │  NOME                          │  CHAVE BASE              │
├─────────┼────────────────────────────────┼──────────────────────────┤
│   17    │  AES128-CTS-HMAC-SHA1-96       │  Derivada da senha       │
│   18    │  AES256-CTS-HMAC-SHA1-96       │  Derivada da senha       │
│   23    │  RC4-HMAC                      │  = Hash NT (MD4 da senha)│
│    3    │  DES-CBC-MD5 (obsoleto)        │  Derivada da senha       │
│    1    │  DES-CBC-CRC (obsoleto)        │  Derivada da senha       │
└─────────┴────────────────────────────────┴──────────────────────────┘
```

**RC4-HMAC (etype 23)**: A chave é diretamente o hash NT (NTLM hash) da senha do usuário. Isso é importante porque:
- O hash NT é armazenado no AD
- É idêntico à chave usada para criptografar tickets RC4
- Crackear um ticket RC4 offline = obter o hash NT = pass-the-hash possível

**AES128/AES256 (etypes 17 e 18)**: A chave é derivada da senha usando PBKDF2 com parâmetros específicos do Kerberos. O hash NT não é suficiente — precisamos da senha em plaintext (ou crackear o hash AES). Por isso são mais seguros para Kerberoasting.

**Verificação de etypes suportados**: O KDC verifica os etypes listados no `etype` do AS-REQ. Se o DC suporta AES e RC4, e o cliente pede ambos, o DC pode escolher qualquer um. Forçar downgrade para RC4 é possível em alguns cenários.

---

### Flags de Ticket

As flags determinam o comportamento do ticket. São transmitidas no campo `flags` dos tickets e requests:

```
┌──────────────────┬──────────────────────────────────────────────────┐
│  FLAG            │  SIGNIFICADO                                      │
├──────────────────┼──────────────────────────────────────────────────┤
│  FORWARDABLE     │  Pode ser encaminhado para outro host (delegação) │
│  FORWARDED       │  É um ticket forwarded (foi delegado)             │
│  PROXIABLE       │  Pode ser usado como proxy (delegação de rede)    │
│  PROXY           │  É um proxy ticket                                │
│  MAY-POSTDATE    │  Pode ser pós-datado (criado antes do starttime)  │
│  POSTDATED       │  É um ticket pós-datado                           │
│  INVALID         │  Ticket inválido (pós-datado, não ativado ainda)  │
│  RENEWABLE       │  Pode ser renovado (TGT renovável)                │
│  INITIAL         │  Obtido diretamente do AS (não via TGS)           │
│  PRE-AUTHENT     │  Cliente passou por pré-autenticação              │
│  HW-AUTHENT      │  Autenticação por hardware (smart card)           │
│  TRANSITED-POLICY-CHECKED │ KDC verificou realm transitado          │
│  OK-AS-DELEGATE  │  Serviço pode delegar (unconstrained delegation)  │
│  REQUEST-ANONYMOUS│ Pedido anônimo                                   │
│  NAME-CANONICALIZE│ Permite canonicalização do nome                  │
└──────────────────┴──────────────────────────────────────────────────┘
```

**OK-AS-DELEGATE**: Quando um objeto de computador tem esta flag, qualquer usuário que se autenticar a um serviço nesse computador terá seu TGT delegado ao serviço. Isso habilita Unconstrained Delegation — o serviço pode impersonar o usuário para qualquer recurso.

---

### Pré-Autenticação (Pre-Authentication)

Por padrão, Kerberos requer pré-autenticação. Sem ela, qualquer um poderia solicitar um AS-REP para qualquer usuário, e a resposta seria parcialmente criptografada com a senha do usuário — permitindo cracking offline (AS-REP Roasting).

O mecanismo de pré-autenticação funciona da seguinte forma: o cliente cifra um timestamp com o hash NT da senha do usuário e o envia no campo `PA-ENC-TIMESTAMP` do AS-REQ. O KDC tenta decifrar esse timestamp usando o hash NT que possui armazenado no AD. Se conseguir decifrar e o timestamp estiver dentro da janela de 5 minutos, comprova que o cliente conhece a senha sem transmiti-la. A diferença criptográfica crítica é que **com** pré-auth o enc-part do AS-REP retorna cifrado com uma session key derivada do intercâmbio — não diretamente com o hash do usuário. **Sem** pré-auth o KDC emite o AS-REP cifrado diretamente com o hash NT do usuário sem qualquer prova de identidade, tornando esse blob capturável e quebrável offline sem interação adicional com o alvo.

**Com pré-autenticação (padrão):**
```
AS-REQ inclui:
padata: PA-ENC-TIMESTAMP {
    patimestamp: <timestamp atual>  ← cifrado com hash NT do usuário
    pausec: <microsegundos>
}

KDC valida:
1. Decifra o timestamp com o hash NT armazenado no AD
2. Verifica se o timestamp está dentro de 5 minutos do horário atual
3. Só então emite o TGT
```

**Sem pré-autenticação (flag DONT_REQUIRE_PREAUTH):**
```
AS-REQ não precisa incluir PA-ENC-TIMESTAMP
KDC retorna AS-REP imediatamente
AS-REP enc-part é criptografado com hash do usuário
→ Atacante pode capturar e crackear offline
```

---

### S4U Extensions — Delegação Kerberos

S4U (Service for User) são extensões Microsoft ao protocolo Kerberos que permitem delegação avançada:

**S4U2Self (Service for User to Self):**
```
Permite que um serviço obtenha um Service Ticket para si mesmo
em nome de um usuário ARBITRÁRIO, sem que o usuário precise
ter se autenticado via Kerberos antes.

Caso de uso legítimo: IIS com autenticação NTLM ou certificado
precisa obter um ticket Kerberos para acessar recursos como
se fosse o usuário.

Caso de uso malicioso: se um atacante comprometeu uma conta
com TrustedToAuthForDelegation, pode obter tickets para qualquer
usuário para qualquer serviço (Constrained Delegation abuse com S4U2Self).
```

**S4U2Proxy (Service for User to Proxy):**
```
Permite que um serviço use um ticket obtido via S4U2Self
(ou um forwarded TGT) para solicitar tickets para outros
serviços específicos (constrained delegation list).

Requer que o serviço esteja na lista msDS-AllowedToDelegateTo
do service account.
```

---

### Formatos de Ticket

**Formato .kirbi (Windows):**
```
Estrutura ASN.1 binária, pode ser representada em base64.
Usada pelo Mimikatz, Rubeus, e Windows nativamente.
Localização: LSASS memory (inacessível diretamente pelo usuário)

Estrutura interna:
KRB-CRED ::= SEQUENCE {
    pvno     [0] INTEGER (5),
    msg-type [1] INTEGER (22),     ← 22 = KRB-CRED
    tickets  [2] SEQUENCE OF Ticket,
    enc-part [3] EncryptedData     ← cifrado com chave zero (frequente)
}
```

**Formato .ccache (Linux):**
```
Credential Cache format - usado pelo MIT Kerberos e Heimdal.
Arquivo binário com header + credenciais.
Localização padrão: /tmp/krb5cc_<UID>

Header:
  file_format_version: 0x0504
  tags: (endianness, KDC offset)

Credential entry:
  client: (realm, name)
  server: (realm, name)
  keyblock: (enctype, data)
  auth_time, start_time, end_time, renew_till
  ticket_flags
  ticket: (raw DER encoded)
```

**Outras localizações de cache no Linux:**
```
FILE:/tmp/krb5cc_1000        ← padrão baseado em arquivo
DIR:/tmp/krb5cc_dir/         ← diretório com múltiplos tickets
KEYRING:persistent:1000      ← kernel keyring (mais seguro)
KCM:                         ← Kerberos Credential Manager (systemd)
API:                         ← SSPI (Windows compatibility layer)
```

---

## Na Prática

### Cenário Completo de Autenticação

Ao fazer login em uma máquina Windows ingressada no domínio:

1. Windows (Winlogon) captura credenciais
2. LSASS cria AS-REQ com pré-autenticação
3. AS-REP retorna TGT + session key (armazenados no LSASS)
4. Ao acessar `\\fileserver\share`, Windows automaticamente faz TGS-REQ com SPN `CIFS/fileserver`
5. TGS-REP retorna Service Ticket (armazenado no LSASS)
6. Windows envia AP-REQ ao fileserver
7. Fileserver valida, acesso concedido

Toda essa comunicação acontece de forma transparente, sem o usuário perceber.

### Localização dos Tickets

**Windows:**
```
Tickets vivem no processo LSASS (Local Security Authority Subsystem Service)
PID: variável, mas processo protegido (PPL - Protected Process Light)
Path: HKLM\SECURITY\Policy\Secrets (registry, inacessível)
Memória: lsass.exe process memory

Para ver tickets sem comprometer LSASS:
  klist                          ← nativo, sem privilégio elevado
  klist -li 0x3e7               ← tickets da sessão SYSTEM

Para extrair tickets (requer privilégio elevado ou SeDebugPrivilege):
  Mimikatz:  sekurlsa::tickets /export
  Rubeus:    Rubeus.exe triage
  Rubeus:    Rubeus.exe dump /service:krbtgt
```

**Linux:**
```
Default credential cache: /tmp/krb5cc_<UID>
  ex: /tmp/krb5cc_1000         ← usuário com UID 1000

Ver tickets:
  klist                        ← lista tickets no cache atual
  klist -c /tmp/krb5cc_1000   ← especificar cache

Definir cache ativo:
  export KRB5CCNAME=/tmp/krb5cc_1000
  export KRB5CCNAME=FILE:/tmp/meu_ticket.ccache

Destruir tickets:
  kdestroy                     ← apaga cache atual
  kdestroy -A                  ← apaga todos os caches
```

---

## Exemplos de Código / Comandos

### Listar Tickets

**Windows — klist:**
```cmd
# Listar tickets do usuário atual
klist

# Saída típica:
# Cached Tickets: (2)
# #0>     Client: alice @ CORP.LOCAL
#         Server: krbtgt/CORP.LOCAL @ CORP.LOCAL
#         KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#         Ticket Flags 0x60a10000 -> forwardable forwarded renewable
#         Start Time: 5/2/2026 8:00:00 (local)
#         End Time:   5/2/2026 18:00:00 (local)
#         Renew Time: 5/9/2026 8:00:00 (local)
#
# #1>     Client: alice @ CORP.LOCAL
#         Server: cifs/fileserver.corp.local @ CORP.LOCAL
#         KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#         Ticket Flags 0x40a10000 -> forwardable renewable
#         Start Time: 5/2/2026 8:05:00 (local)
#         End Time:   5/2/2026 18:00:00 (local)

# Listar tickets de outra sessão (requer admin)
klist -li 0x3e7              # sessão NETWORK SERVICE
klist sessions               # listar todas as sessões
```

**Windows — Rubeus:**
```powershell
# Triagem de todos os tickets em todas as sessões (requer admin)
.\Rubeus.exe triage

# Dump de todos os tickets
.\Rubeus.exe dump

# Dump de ticket específico por serviço
.\Rubeus.exe dump /service:krbtgt

# Dump por LUID de sessão
.\Rubeus.exe dump /luid:0x3e4

# Exportar ticket para arquivo .kirbi
.\Rubeus.exe dump /service:cifs /nowrap

# Monitorar novas autenticações (para capturar tickets)
.\Rubeus.exe monitor /interval:5 /targetuser:Administrator
```

**Windows — Mimikatz:**
```
# Listar tickets no LSASS (precisa de SYSTEM ou SeDebugPrivilege)
mimikatz # sekurlsa::tickets

# Exportar tickets para arquivos .kirbi
mimikatz # sekurlsa::tickets /export
# Gera arquivos como: [0;xxxxx]-2-0-60a10000-alice@krbtgt-CORP.LOCAL.kirbi

# Listar tickets da sessão atual (sem SYSTEM)
mimikatz # kerberos::list
mimikatz # kerberos::list /export   ← exporta para .kirbi

# Ver cache de tickets
mimikatz # kerberos::tgt
```

**Linux — klist e comandos nativos:**
```bash
# Listar tickets (requer KRB5CCNAME ou /tmp/krb5cc_UID)
klist

# Listar com detalhes de enctype e flags
klist -e -f

# Saída típica:
# Credentials cache: FILE:/tmp/krb5cc_1000
#         Principal: alice@CORP.LOCAL
#
#   Issued                Expires               Principal
# May  2 08:00:00 2026  May  2 18:00:00 2026  krbtgt/CORP.LOCAL@CORP.LOCAL
# May  2 08:05:00 2026  May  2 18:00:00 2026  cifs/fileserver.corp.local@CORP.LOCAL

# Obter novo TGT via kinit
kinit alice@CORP.LOCAL               # solicita senha
kinit -k -t alice.keytab alice@CORP.LOCAL  # usando keytab

# Destruir tickets
kdestroy

# Ver tickets em cache específico
klist -c /tmp/krb5cc_1000

# Listar todos os caches conhecidos
klist -A
```

### Conversão de Formatos de Ticket

**Impacket — ticketConverter:**
```bash
# .ccache (Linux) → .kirbi (Windows)
impacket-ticketConverter ticket.ccache ticket.kirbi

# .kirbi (Windows) → .ccache (Linux)
impacket-ticketConverter ticket.kirbi ticket.ccache

# Ou diretamente:
python3 /opt/impacket/examples/ticketConverter.py ticket.ccache ticket.kirbi
```

**Rubeus — encode/decode:**
```powershell
# Converter base64 kirbi → usar direto
.\Rubeus.exe ptt /ticket:<base64_do_kirbi>

# Exibir ticket em base64 (para transferir via texto)
.\Rubeus.exe dump /service:krbtgt /nowrap

# Converter .kirbi arquivo → carregar
.\Rubeus.exe ptt /ticket:C:\path\ticket.kirbi

# Describ conteúdo de ticket sem usar
.\Rubeus.exe describe /ticket:<base64>
```

**Passar tickets (Pass-the-Ticket):**
```powershell
# Windows — Mimikatz
mimikatz # kerberos::ptt golden.kirbi

# Windows — Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe ptt /ticket:<base64_kirbi>

# Verificar após PTT
klist

# Linux — exportar ccache e usar com Impacket
export KRB5CCNAME=/tmp/ticket.ccache
python3 psexec.py -k -no-pass CORP.LOCAL/Administrator@dc01.corp.local
python3 smbclient.py -k -no-pass CORP.LOCAL/Administrator@fileserver.corp.local
python3 wmiexec.py -k -no-pass CORP.LOCAL/Administrator@server.corp.local
```

### Analisar Estrutura de Ticket com Python

```python
#!/usr/bin/env python3
"""
Analisar ticket Kerberos .ccache e exibir informações
Requer: impacket
"""
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from datetime import datetime, timezone
import sys

def analisar_ccache(arquivo):
    ccache = CCache.loadFile(arquivo)
    
    print(f"[*] Cache principal: {ccache.principal.prettyPrint()}")
    print(f"[*] Total de credenciais: {len(ccache.credentials)}")
    print()
    
    for i, cred in enumerate(ccache.credentials):
        print(f"--- Credencial #{i} ---")
        print(f"  Cliente: {cred.header['client'].prettyPrint()}")
        print(f"  Servidor: {cred.header['server'].prettyPrint()}")
        
        # Flags
        flags = cred.header['tktflags']
        flag_names = []
        if flags & 0x40000000: flag_names.append("FORWARDABLE")
        if flags & 0x20000000: flag_names.append("FORWARDED")
        if flags & 0x10000000: flag_names.append("PROXIABLE")
        if flags & 0x08000000: flag_names.append("PROXY")
        if flags & 0x04000000: flag_names.append("RENEWABLE")
        if flags & 0x00200000: flag_names.append("PRE-AUTHENT")
        if flags & 0x00100000: flag_names.append("HW-AUTHENT")
        if flags & 0x00040000: flag_names.append("OK-AS-DELEGATE")
        print(f"  Flags: {' | '.join(flag_names)}")
        
        # Timestamps
        auth_time = datetime.fromtimestamp(cred.header['authtime'], timezone.utc)
        end_time = datetime.fromtimestamp(cred.header['endtime'], timezone.utc)
        print(f"  Auth Time: {auth_time}")
        print(f"  End Time:  {end_time}")
        
        # Encryption type
        etype = cred.header['keyblock']['keytype']
        etype_names = {17: "AES128", 18: "AES256", 23: "RC4-HMAC", 3: "DES-CBC-MD5"}
        print(f"  Enc Type:  {etype_names.get(etype, f'Unknown({etype})')}")
        print()

if __name__ == "__main__":
    arquivo = sys.argv[1] if len(sys.argv) > 1 else "/tmp/krb5cc_1000"
    analisar_ccache(arquivo)
```

### Solicitar TGT Manualmente com Impacket

```python
#!/usr/bin/env python3
"""
Solicitar TGT e salvar como .ccache
Útil para entender o fluxo ou automatizar
"""
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
import datetime

def obter_tgt(username, password, domain, dc_ip):
    # Criar principal
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    
    # Solicitar TGT
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
        clientName=userName,
        password=password,
        domain=domain,
        lmhash='',
        nthash='',          # ou fornecer hash diretamente
        aesKey='',
        kdcHost=dc_ip,
        requestPAC=True
    )
    
    print(f"[+] TGT obtido para {username}@{domain}")
    print(f"[+] Session Key etype: {sessionKey['keytype']}")
    
    # Salvar como .ccache
    ccache = CCache.parseKRBCRED(tgt)
    ccache.saveFile(f"/tmp/{username}.ccache")
    print(f"[+] Salvo em /tmp/{username}.ccache")
    
    return tgt, sessionKey

# Uso:
# obter_tgt("alice", "Senha123!", "CORP.LOCAL", "192.168.1.10")
```

---

## Detecção e OPSEC

### Eventos Windows Relevantes

```
┌────────┬─────────────────────────────────────────────────────────────┐
│ EVENT  │  DESCRIÇÃO                                                  │
├────────┼─────────────────────────────────────────────────────────────┤
│  4768  │  AS-REQ: pedido de TGT (Kerberos Authentication Ticket Req) │
│  4769  │  TGS-REQ: pedido de Service Ticket                          │
│  4770  │  TGS-REQ: renovação de Service Ticket                       │
│  4771  │  Falha no AS-REQ (ex: pré-auth falhou, usuário bloqueado)   │
│  4772  │  Falha no AS-REP (ticket inválido)                          │
│  4820  │  TGT negado (conta não permitida naquele DC)                │
└────────┴─────────────────────────────────────────────────────────────┘
```

**Event 4768 (AS-REQ) — campos importantes:**
```
Account Name: alice
Service Name: krbtgt
Ticket Options: 0x40810010   ← decodificar flags
Ticket Encryption Type: 0x12  ← 0x12 = AES256, 0x17 = RC4
Failure Code: 0x0             ← 0x0 = sucesso
Client Address: ::ffff:192.168.1.50  ← IP do cliente

Anomalias:
- Ticket Encryption Type 0x17 (RC4) em ambientes que só usam AES
- IP do cliente inesperado (não é a workstation do usuário)
- Usuário requisitando TGT fora do horário normal
- TicketOptions incluindo flags incomuns (0x50800000 = forwardable+renewable+canonicalize)
```

**Event 4769 (TGS-REQ) — campos importantes:**
```
Account Name: alice
Service Name: HTTP/webserver.corp.local   ← SPN
Ticket Options: 0x40800000
Ticket Encryption Type: 0x17   ← RC4 para Kerberoasting
Failure Code: 0x0

Anomalias para Kerberoasting:
- Um único usuário fazendo múltiplos TGS-REQ para SPNs diferentes em curto tempo
- Encryption Type = 0x17 (RC4) quando serviço suporta AES (downgrade)
- Source IP não condiz com a workstation do usuário
```

### Considerações de OPSEC para Red Team

**Reduzir footprint em Kerberos:**
```
1. Preferir AES sobre RC4 em ambientes modernos
   - RC4 em ambiente AES é anomalia detectável

2. Limitar TGS-REQs desnecessários
   - Cada acesso gera Event 4769 no DC
   - Agrupar acessos para reduzir volume

3. Usar tickets forwarded ao invés de novas requisições
   - Reaproveitar tickets já obtidos

4. Respeitar lifetime dos tickets
   - Renovar ao invés de obter novos quando possível
   - TGTs com lifetime muito longo (ex: 10 anos) são bandeira vermelha

5. Não usar usernames inexistentes em Golden Tickets
   - Correlação com eventos de logon no AD expõe o username fictício
   - Usar usernames legítimos mas inativos é mais furtivo

6. Timestamp accuracy
   - Kerberos rejeita timestamps com diferença > 5 minutos
   - Sincronizar clock com NTP do domínio antes de operar
```

**Detecção de anomalias Kerberos comuns:**
```
- Tickets com endtime muito além do normal (Golden Ticket: 10 anos)
- Tickets com cname que não existe no AD (Golden Ticket com user fictício)
- TGS-REQ sem AS-REQ prévio (Pass-the-Ticket com TGT externo)
- IP de origem do TGS-REQ diferente do AS-REQ (ticket copiado)
- Muitos TGS-REQ de usuário com baixo privilégio (Kerberoasting)
- AS-REP sem pré-autenticação (AS-REP Roasting setup ou ataque)
- Uso de RC4 quando ambiente usa AES (downgrade forçado)
- Renovações de TGT fora do horário de trabalho
- TGT emitido para usuário desabilitado no AD
```

---

## Módulos Relacionados

`02_kerberoasting_e_asrep.md` aprofunda os ataques que exploram a estrutura de TGS-REP e AS-REP. `03_golden_e_silver_tickets.md` cobre forja de tickets explorando hash do krbtgt e service accounts. `04_dcsync_e_dominancia.md` mostra como obter o hash do krbtgt via DCSync. MITRE ATT&CK: T1558 (Steal or Forge Kerberos Tickets), T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting).

---

## Leitura Complementar

- RFC 4120 — The Kerberos Network Authentication Service (V5)
- MS-KILE — Microsoft Kerberos Protocol Extension
- MS-PAC — Privilege Attribute Certificate Data Structure
- MS-APDS — Authentication Protocol Domain Support Specification
