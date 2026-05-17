---
layout: cyber
section: evasao
title: "Evasão de Antivírus — Introdução e Fundamentos"
---

# Evasão de Antivírus — Introdução e Fundamentos

## Payload Detectado Nunca Executa

Durante operações de red team realistas — especialmente nos cenários cobrados pelo CRTO I, CRTO II e OSEP — um payload que não passa pela proteção de endpoint nunca chega a ser executado. Compreender como o antivírus funciona internamente é o pré-requisito absoluto para qualquer técnica de evasão. Sem esse conhecimento, o operador fica tentando técnicas ao acaso, sem entender por que algo é detectado ou por que uma modificação funcionou.

O Windows Defender, presente em todos os ambientes Windows modernos, combina múltiplas camadas de detecção: análise estática, análise heurística, emulação em sandbox e machine learning. Cada camada precisa ser compreendida separadamente, pois cada uma exige abordagem de evasão diferente. Um payload que evade a análise estática pode ser detectado pela análise comportamental, e vice-versa.

Nesta seção do curso, o objetivo não é apenas "passar pelo AV" — é entender o modelo mental correto para abordar evasão de forma iterativa e controlada, da mesma forma que um engenheiro de malware profissional opera.

---

## As Camadas Internas do Antivírus

### Análise Estática

A análise estática ocorre sem executar o arquivo. O AV examina o binário em disco antes de qualquer execução.

**Hash de arquivo (File Hash)**

O método mais simples: o AV mantém um banco de dados de hashes (MD5, SHA1, SHA256) de arquivos maliciosos conhecidos. Se o hash do arquivo corresponder a uma entrada no banco, o arquivo é bloqueado imediatamente.

- Vantagem do AV: extremamente rápido, zero falso positivo para arquivos conhecidos.
- Limitação do AV: qualquer modificação no arquivo — mesmo um único byte — muda o hash completamente. Por isso, simplesmente recompilar um payload já pode contornar essa camada.
- Implicação para o operador: nunca use payloads gerados diretamente pelo Metasploit ou Cobalt Strike sem modificação. Eles são catalogados há anos.

**Assinaturas de bytes (Byte Signatures)**

O AV mantém padrões de bytes específicos que identificam malware. Em vez de verificar o arquivo inteiro, o scanner procura sequências de bytes em posições específicas ou em qualquer posição do arquivo.

Por exemplo, uma assinatura pode ser: "se os bytes `FC 48 83 E4 F0 E8` aparecerem nos primeiros 4KB do arquivo, é shellcode Meterpreter". Essa sequência é o prelúdo clássico do shellcode x64 do Metasploit.

O scanner divide o arquivo em blocos e faz correspondência de padrões. Ferramentas modernas como YARA permitem regras complexas com múltiplas condições.

**Regras YARA**

YARA é a linguagem padrão para escrita de regras de detecção baseadas em padrões. O Windows Defender e a maioria dos AVs comerciais usam regras YARA (ou equivalentes proprietários) internamente.

Exemplo de regra YARA simples:
```
rule Meterpreter_Reverse_TCP {
    meta:
        description = "Detecta shellcode Meterpreter reverse TCP"
    strings:
        $s1 = { FC 48 83 E4 F0 E8 }
        $s2 = "METERPRETER" wide ascii
        $s3 = { 60 89 E5 31 D2 64 8B 52 30 }
    condition:
        any of them
}
```

O AV aplica centenas de milhares de regras YARA em paralelo usando algoritmos de correspondência eficientes como Aho-Corasick.

### Análise Heurística

A análise heurística examina o comportamento potencial do código sem executá-lo completamente. O mecanismo busca padrões suspeitos:

**Padrões de comportamento suspeito:**
- Código que decifra a si mesmo em tempo de execução (indicador de packer/obfuscator)
- Chamadas para APIs consideradas suspeitas em combinação: `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`
- Arquivos que importam APIs de rede e APIs de criptografia simultaneamente
- Código que itera sobre processos em execução (`CreateToolhelp32Snapshot` + `Process32Next`)
- Acesso a regiões de memória de outros processos
- Modificação de entradas do registro em locais de persistência conhecidos

**APIs suspeitas (red flags para heurística):**
```
VirtualAlloc / VirtualAllocEx       -> alocação de memória executável
WriteProcessMemory                  -> escrita em outro processo
CreateRemoteThread / NtCreateThreadEx -> injeção de thread
OpenProcess com PROCESS_ALL_ACCESS  -> acesso total a processo
AdjustTokenPrivileges               -> elevação de privilégios
SetWindowsHookEx                    -> hooking de teclado/mouse
RegSetValueEx em Run keys           -> persistência via registro
```

O heurístico atribui uma pontuação de risco a cada comportamento. Se a pontuação total ultrapassar um threshold, o arquivo é sinalizado.

### Emulação / Sandbox

O AV executa o arquivo em uma mini-VM interna por um tempo limitado (geralmente 1 a 5 segundos) para observar comportamento real.

**Como funciona internamente:**
1. O arquivo é carregado em um ambiente emulado com APIs do Windows simuladas
2. O emulador executa as instruções do arquivo e registra chamadas de API
3. Se o comportamento observado corresponder a padrões maliciosos, o arquivo é bloqueado

**Limitações do emulador (exploráveis pelo atacante):**
- Timeout limitado: se o malware dorme por mais de 5-10 segundos no início, o emulador para antes de ver o comportamento malicioso
- APIs não implementadas: emuladores não implementam 100% das APIs do Windows; chamadas a APIs obscuras podem falhar silenciosamente no emulador mas funcionar normalmente
- Detecção de ambiente: o emulador frequentemente não tem artefatos reais de ambiente (nome de usuário específico, domínio AD, processos específicos). Malware pode verificar essas condições antes de executar.
- Recursos limitados: sem acesso real à rede, sem disco real (às vezes)

**Técnicas de anti-emulação:**
- Sleep longo antes da execução: `Sleep(30000)` — 30 segundos é mais que suficiente
- Verificação de tempo real: chamar `GetTickCount` antes e depois do sleep; se a diferença não corresponder, está em emulador
- Verificação de artefatos de ambiente: checar se existe `C:\Windows\System32\calc.exe`, verificar nome de usuário, checar número de processos ativos

### Machine Learning

AVs modernos (Windows Defender, CrowdStrike, SentinelOne) usam modelos de ML para classificação de binários.

**Features usadas pelo modelo:**
- Seções PE: entropia de cada seção, tamanho relativo, permissões (R/W/X)
- Tabela de imports: quais DLLs são importadas, quais funções específicas
- Strings extraídas: presença de IPs, URLs, comandos suspeitos
- Características do header PE: timestamp, subsystem, características
- Entropia geral: alta entropia indica código criptografado/comprimido (suspeito)
- Ratio de código executável vs dados

**Implicação:** um loader em C com código legítimo mínimo, baixa entropia e imports normais terá score baixo de ML mesmo que carregue shellcode criptografado em runtime — pois o ML avalia o binário em repouso, não o comportamento dinâmico (essa é a responsabilidade da camada heurística/comportamental).

### O Processo de Scanning

**On-Access Scanning (tempo real):**
Ativado por padrão no Windows Defender. O driver do AV registra callbacks no kernel:

```
IRP_MJ_CREATE  -> quando um arquivo é aberto
IRP_MJ_WRITE   -> quando um arquivo é escrito
IRP_MJ_READ    -> quando um arquivo é lido (em alguns AVs)
```

Quando qualquer processo tenta abrir um arquivo executável, o kernel notifica o AV antes de concluir a operação. O AV faz o scan e retorna ALLOW ou DENY. Se DENY, o processo recebe `ACCESS_DENIED`.

**On-Demand Scanning:**
Scan manual iniciado pelo usuário ou agendado. Não é em tempo real; examina todos os arquivos no disco ou em um diretório específico.

**Kernel Hooks e Minifilter Drivers:**
O Windows Defender opera como um minifilter driver no kernel:
- Registra-se no Filter Manager (`FltRegisterFilter`)
- Recebe notificações de I/O antes e depois de operações de arquivo
- Pode bloquear operações retornando `STATUS_ACCESS_DENIED`

Além disso, o Defender usa:
- **ELAM (Early Launch Anti-Malware):** driver carregado antes de qualquer outro driver de boot, garantindo que o AV esteja ativo desde o início do boot
- **PPL (Protected Process Light):** o processo `MsMpEng.exe` roda como PPL, impedindo que processos não-PPL façam debugging ou injeção nele

---

## Na Prática

### Windows Defender — Visão Detalhada

O Windows Defender é a solução de endpoint padrão em ambientes corporativos modernos e o principal obstáculo em operações de red team.

**Componentes principais:**
- `MsMpEng.exe` — processo principal do mecanismo antivírus (Protected Process)
- `MpCmdRun.exe` — interface de linha de comando para operações manuais
- `WdFilter.sys` — driver de filtro do kernel (minifilter)
- `WdNisDrv.sys` — driver de inspeção de rede
- `SecurityHealthService.exe` — serviço de saúde do Windows Security Center

**AMSI Integration:**
O Antimalware Scan Interface (AMSI) é um ponto de integração que permite ao Defender inspecionar conteúdo em memória. Quando PowerShell, WScript ou qualquer aplicação com suporte a AMSI executa código, ela chama `AmsiScanBuffer` passando o conteúdo antes da execução. Isso significa que o Defender pode detectar scripts maliciosos mesmo que nunca sejam escritos em disco.

**Cloud-Delivered Protection:**
Quando um arquivo desconhecido é encontrado, o Defender pode enviar amostras para a Microsoft Cloud para análise. A resposta vem em segundos e pode resultar em bloqueio de arquivos que passaram pelas checagens locais. Em ambientes corporativos, isso frequentemente está habilitado.

**Behavioral Monitoring:**
O Defender monitora comportamentos em runtime. Mesmo que o payload passe pela análise estática, comportamentos como:
- Injeção em processos
- Criação de threads remotas
- Modificação de memória de processos
- Comunicação de rede suspeita

podem acionar detecção comportamental após a execução.

**Comandos úteis para verificar status:**
```powershell
# Verificar status do Defender
Get-MpComputerStatus

# Verificar definições atuais
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, NISSignatureLastUpdated

# Verificar configurações de proteção em tempo real
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring

# Verificar ameaças detectadas
Get-MpThreat

# Scan manual de um arquivo
MpCmdRun.exe -Scan -ScanType 3 -File C:\path\to\file.exe

# Verificar exclusões configuradas
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
```

---

## Exemplos de Código / Comandos

### ThreatCheck — Identificando Bytes Detectados

ThreatCheck é a ferramenta mais importante para análise de detecção estática. Ela realiza uma busca binária no arquivo para identificar exatamente qual região de bytes está causando a detecção.

**Instalação:**
```
# Baixar do repositório RastaMouse
https://github.com/rasta-mouse/ThreatCheck

# Compilar com Visual Studio ou dotnet
dotnet build -c Release

# Ou usar o binário pré-compilado (cuidado: pode ser detectado ele mesmo)
```

**Uso básico:**
```cmd
# Testar um executável contra o Windows Defender
ThreatCheck.exe -f payload.exe

# Testar contra AMSI (útil para scripts PowerShell)
ThreatCheck.exe -f script.ps1 -e AMSI

# Especificar mecanismo (defender ou AMSI)
ThreatCheck.exe -f payload.exe -e Defender
ThreatCheck.exe -f payload.bin -e Defender
```

**Como ThreatCheck funciona internamente:**

ThreatCheck implementa busca binária sobre o arquivo:
1. Divide o arquivo ao meio
2. Testa a primeira metade: detectada? Se sim, o problema está nessa metade.
3. Divide essa metade ao meio novamente
4. Repete até isolar os bytes exatos que causam a detecção

**Saída típica do ThreatCheck:**
```
[+] Target file size: 73216 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x3B20
00000000   4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00   MZ..............
...
[*] Bytes at bad offset:
00003B10   FC 48 83 E4 F0 E8 C0 00  00 00 41 51 41 50 52 51   .H......AQAPRQ
```

**Processo iterativo de evasão com ThreatCheck:**

```
1. Gerar payload inicial
2. ThreatCheck.exe -f payload.exe  -> identificar offset do problema
3. Examinar os bytes detectados no Ghidra ou hex editor
4. Modificar aquela região (XOR, substituir instrução equivalente, etc.)
5. Recompilar
6. ThreatCheck.exe -f payload_v2.exe  -> novo teste
7. Repetir até passar
```

### DefenderCheck

DefenderCheck é similar ao ThreatCheck mas com interface diferente:

```cmd
# Testar arquivo
DefenderCheck.exe payload.exe

# A saída mostra os bytes problemáticos em hex e ASCII
```

### Verificar Detecção Manualmente com MpCmdRun

```cmd
# Scan específico de arquivo
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\temp\payload.exe

# Verificar resultado no Event Log
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 10 |
    Where-Object {$_.Id -eq 1116 -or $_.Id -eq 1117} |
    Select-Object TimeCreated, Message
```

### Verificar Detecção por Hash

```powershell
# Obter hashes do arquivo
$file = "C:\temp\payload.exe"
Get-FileHash $file -Algorithm MD5
Get-FileHash $file -Algorithm SHA256

# Verificar no VirusTotal via API (para análise offline/OPSEC)
# NUNCA envie arquivos de operação reais para o VirusTotal público
# Use apenas hashes para consulta discreta
```

### Análise de Entropia

Alta entropia (>7.0 de um máximo de 8.0) em seções PE é um forte indicador para ML:

```python
import math
import struct

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy

# Ler seções PE e calcular entropia
with open("payload.exe", "rb") as f:
    data = f.read()

print(f"Entropia total: {calculate_entropy(data):.2f}")
# Acima de 7.2 é suspeito para ML-based AVs
```

---

## Detecção e OPSEC

### O Que os Defensores Veem

**Event IDs relevantes do Windows Defender:**
```
1116  - Malware detected (ameaça encontrada)
1117  - Malware removed (ameaça removida/bloqueada)
1118  - Malware removal failed
2001  - AntiSpyware signature update started
2002  - AntiSpyware signature update completed
5001  - Real-time protection disabled (alerta crítico para defensores)
5007  - Settings changed (pode indicar tampering)
```

**Logs no SIEM:**
Um SOC bem configurado alerta para:
- Múltiplas detecções do Defender em curto período
- Tentativas de desabilitar o Defender (Event 5001)
- Arquivos com alta entropia sendo criados em paths temporários
- Processos legítimos fazendo chamadas de API suspeitas em sequência

### OPSEC Durante Testes

**Nunca faça:**
- Submeter payloads de operação reais ao VirusTotal (telemetria é compartilhada)
- Testar payloads em máquinas com cloud-delivered protection habilitada sem entender as implicações
- Usar hashes ou nomes de arquivo identificáveis

**Abordagem correta:**
1. Configurar VM isolada com Defender atualizado mas sem cloud-delivered protection
2. Usar ThreatCheck localmente na VM de desenvolvimento
3. Testar em ambiente de staging antes de usar em produção
4. Snapshots antes de cada teste para restaurar estado limpo

**Configurar VM de teste:**
```powershell
# Desabilitar cloud-delivered protection (apenas em VM de laboratório)
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend

# Manter proteção em tempo real habilitada para teste realista
# NÃO desabilite o real-time monitoring durante testes

# Atualizar definições para versão mais recente
Update-MpSignature
```

### Detecção de Ferramentas de Análise

ThreatCheck e DefenderCheck podem ser detectados pelo Defender. Em alguns ambientes, até a execução dessas ferramentas gera alertas.

Alternativas discretas:
- Compilar ThreatCheck a partir do código fonte em cada engajamento
- Usar exclusões de diretório no ambiente de desenvolvimento (apenas para lab)
- Manter a VM de desenvolvimento completamente isolada da rede do cliente

---

---

## Mitigações de Hardware/OS — DEP, ASLR, SEHOP

> Camada de mitigação do OS que complementa o AV. Entender essas proteções explica por que ROP, section injection, e shellcode requerem abordagens específicas.

### DEP / NX — Data Execution Prevention

Hardware-enforced via **NX bit (AMD) / XD bit (Intel)** nas PTEs (Page Table Entries). Impede execução de código em páginas marcadas como dados.

- Permanente por padrão desde Windows 8 (`PROCESS_MITIGATION_DEP_POLICY.Permanent = 1`)
- Kernel-mode DEP sempre ativo desde Vista
- **Bypass:** ROP (Return-Oriented Programming) — reutiliza gadgets de código já mapeado em páginas exec (não precisa executar nova memória)
- **JIT Spraying:** engines JIT escrevem em páginas exec → poluir com gadgets controlados
- **VirtualProtect:** marcar região como `PAGE_EXECUTE_READWRITE` — bloqueado por ACG quando ativo

### ASLR — Address Space Layout Randomization

| Variante | Descrição | Bits de Entropia |
|----------|-----------|-----------------|
| Bottom-Up | Heap, stack, mappings anônimos | 8 bits (x86), 17 bits (x64) |
| Force Relocate | Força relocalização mesmo sem `DYNAMIC_BASE` | — |
| HEASLR | Base de imagens 64-bit | **24 bits** (x64) |
| Stack ASLR | Base da stack por thread | — |

**Onde falha:**
- DLLs sem `/DYNAMICBASE` → endereço fixo → `dumpbin /headers dll.dll | grep "dynamic base"`
- x86: 8 bits = 256 possibilidades → brute force viável
- **Info leak** vaza endereço → calcula base → bypass completo sem ROP

```powershell
# Verificar ASLR/High Entropy de módulo
dumpbin /headers module.dll | grep -i "dynamic base\|high entropy"
Get-ProcessMitigation -Id (Get-Process explorer).Id | Select ASLR
```

### SEHOP — Structured Exception Handler Overwrite Protection

Protege contra overflow que sobrescreve ponteiros da cadeia SEH (x86 apenas).

**Mecanismo:** antes de despachar exceção, percorre toda a cadeia SEH → verifica que o último handler aponta para `ntdll!FinalExceptionHandler` → cadeia corrompida = processo termina.

**Limitações:** apenas x86 (x64 usa table-based exception handling — não vulnerável a SEH overwrite).

---

## Módulos Relacionados

`02_av_evasao_avancada.md` aprofunda em Artifact Kit, shellcode obfuscation e custom loaders. `03_amsi_bypass.md` cobre bypass específico do AMSI pra scripts PowerShell e .NET. `04_applocker_bypass.md` lida com whitelisting de aplicações, complementar à evasão de AV. MITRE ATT&CK relevantes: T1562 (Impair Defenses), T1027 (Obfuscated Files), T1055 (Process Injection).

---

## Leitura Complementar

- Microsoft Defender for Endpoint docs — https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
- ThreatCheck — https://github.com/rasta-mouse/ThreatCheck
- YARA — https://virustotal.github.io/yara/
- CRTO I — Payload Development
- CRTO II — Defense Evasion avançado
- OSEP (PEN-300) — capítulo Antivirus Evasion
