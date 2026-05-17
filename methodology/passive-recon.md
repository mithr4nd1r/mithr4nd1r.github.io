---
title: "Passive Reconnaissance"
---

# 06 - Reconhecimento Passivo

> Coleta de informações sem conexão direta ao alvo — zero logs nos sistemas da vítima.

---

## Por Que Passivo Primeiro

Reconhecimento passivo não dispara alertas no alvo. Executar antes de qualquer scan ativo para mapear a superfície de ataque e identificar vetores promissores antes de gerar qualquer tráfego suspeito.

Objetivo: construir um mapa de `domínio → subdomínios → IPs → tecnologias → pessoas → vetores`.

---

## whois

Consulta registros de domínio e blocos de IP.

```bash
whois target.com
whois 192.168.1.0/24
```

**O que extrair**:
- Registrar, datas de criação/expiração
- Name servers (NS) → alvos de zone transfer
- Email do responsável → formato de email corporativo (`nome.sobrenome@empresa.com`)
- Endereço físico → jurisdição legal, localização de DCs

---

## Google Dorks

Operadores avançados do Google para encontrar informações expostas.

| Operador | Uso |
|----------|-----|
| `site:target.com` | Limitar busca ao domínio |
| `filetype:pdf site:target.com` | PDFs do domínio |
| `ext:sql site:target.com` | Arquivos SQL expostos |
| `intitle:"index of" site:target.com` | Directory listing |
| `inurl:admin site:target.com` | Painéis admin |

**Hunting de segredos expostos**:
```
site:target.com filetype:env
site:target.com ext:conf OR ext:config OR ext:ini
site:target.com inurl:login OR inurl:signin
"target.com" password filetype:xlsx
site:pastebin.com "target.com" password
site:target.com inurl:phpinfo.php
```

---

## Netcraft

Site report em `https://searchdns.netcraft.com/`:
- Tecnologias do servidor (linguagem, framework, OS, versão)
- Histórico de hosting e mudanças de IP (identifica IPs históricos antes de CDN)
- Subdomínios descobertos por rastreamento
- Certificados SSL e quando emitidos

---

## Shodan

Motor de busca para dispositivos conectados à internet. Indexa banners, certificados, versões.

```
hostname:target.com
org:"Target Company"
port:22 hostname:target.com
port:3389 country:BR
net:192.168.1.0/24
```

**O que interpretar**:
- Banners de serviço com versões → buscar CVEs
- Portas abertas não-padrão → shadow IT, serviços não documentados
- Certificados SSL → subdomínios via SAN (Subject Alternative Names)
- Tags: `vuln:CVE-YYYY-NNNNN` → Shodan já correlacionou CVEs

---

## GitHub Dorking

Repositórios públicos frequentemente contêm segredos corporativos: chaves de API, credenciais, configurações de infra.

```
org:empresa password
org:empresa filename:.env
org:empresa extension:sql
org:empresa extension:key
org:empresa "BEGIN RSA PRIVATE KEY"
org:empresa "api_key" OR "api_secret"
org:empresa "jdbc:mysql" password
org:empresa "AWS_SECRET_ACCESS_KEY"
```

**Ferramentas automatizadas**:
```bash
# Varredura de histórico completo de repo (commits, branches, tags)
trufflehog git https://github.com/org/repo

# Detecção em repo local ou clonado
gitleaks detect --source . --verbose

# Secrets em histórico git mesmo após remoção do commit atual
git log --all --full-history --oneline
```

---

## theHarvester

Coleta emails, subdomínios, IPs e nomes de funcionários de fontes públicas.

```bash
theHarvester -d target.com -b google,linkedin,bing,certspotter
theHarvester -d target.com -b all -l 500
```

**Fontes úteis**: `google`, `bing`, `linkedin`, `certspotter`, `crtsh`, `dnsdumpster`

Resultado útil: lista de emails do formato `nome@empresa.com` → inferir todos os usuários AD da empresa.

---

## Certificate Transparency (crt.sh)

Logs públicos de certificados SSL revelam subdomínios — sem consultar diretamente o alvo.

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# Filtrar wildcards e verificar quais resolvem
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u | \
  while read sub; do host $sub 2>/dev/null | grep "has address" && echo "$sub"; done
```

---

## Metodologia Completa

```
1. whois → registrar, NS, emails, blocos IP, jurisdição
2. Netcraft / Shodan → tecnologias, serviços expostos, IPs históricos
3. crt.sh + theHarvester → subdomínios, emails
4. GitHub dorking + trufflehog → segredos expostos em código
5. Google dorks → arquivos sensíveis, painéis admin, logins
6. Mapear: subdomínios → IPs → tecnologias → potenciais vetores → pessoas
```

**Regra operacional**: completar fase passiva antes de qualquer conexão direta ao alvo.

---

## Módulos Relacionados

`07_enumeracao_ativa.md` é a etapa seguinte — após mapear IPs e subdomínios via OSINT, iniciar enumeração ativa com Nmap e serviços. `01_phishing_e_engenharia_social.md` consome emails e nomes coletados aqui como input pro pretexto. `04_password_spraying_owa.md` usa o formato de email confirmado aqui no spray.
