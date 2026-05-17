---
title: "Automation & Tooling"
---

# Automacao e Tooling em Bug Bounty

## Contexto: Infraestrutura de Recon Distribuido

Para alvos grandes — programas com escopo *.empresa.com cobrindo centenas de subdominios — automacao de recon deixa de ser conforto e se torna necessidade operacional. A diferenca entre testar 50 hosts manualmente e ter uma pipeline processando 50.000 subdominios nao e velocidade: e a escala de superficie acessivel.

**Por que distribuicao e velocidade importam para grandes alvos:**

O Bug Bounty e competitivo. Quando um programa adiciona um novo asset ao escopo, os primeiros hunters a encontrar vulnerabilidades naquele asset tem vantagem de nao duplicata. Infraestrutura automatizada que monitora mudancas de scope e processa novos assets em minutos vs horas e uma vantagem real de tempo.

Para alvos com 100.000+ subdominios (grandes empresas de tecnologia, telecomunicacoes, financas), processar a lista com httpx sequencialmente leva horas. Com concorrencia adequada e rate limiting, cai para minutos.

**Trade-offs de velocidade vs ruido:**

| Parametro | Mais velocidade | Mais cuidado |
|---|---|---|
| Threads/concurrencia | 50-100 | 5-10 |
| Rate limit por host | Sem limite | 10-50 req/s |
| Timeout | Curto (5s) | Longo (30s) |
| Risco | Pode causar DoS acidental, bloqueio de IP | Mais lento, mais seguro |

Regra geral: quanto mais critico e o alvo (producao de empresa grande), menor a agressividade. Ferramentas mal configuradas podem causar DoS acidental — o que e violacao das regras de qualquer programa de bug bounty.

**Por que automacao nao substitui analise manual:**

As vulnerabilidades de maior impacto (logica de negocio, deserializacao insegura, race conditions) nao sao detectaveis por scanners automaticos. Nuclei encontra misconfigurações conhecidas — ele nao entende se o campo `quantity` em uma devolucao aceita valores arbitrarios.

A piramide correta: automacao no fundo (recon, scan de CVEs conhecidos) — liberando tempo humano para o topo (analise de logica, encadeamento de vulns, bypass criativo).

**Estrutura de custo-beneficio de automacao:**

```
AUTOMACAO BOA:
- Recon de novos subdominios -> alerta
- Scan de CVEs conhecidos (nuclei) -> triagem manual
- Monitoramento de JS files novos -> analise manual
- Extracao de parametros -> fuzzing direcionado

AUTOMACAO QUE NAO FUNCIONA:
- Submeter output de scanner diretamente (falsos positivos)
- SQLmap em todos os parametros sem verificacao previa
- Nuclei resultados sem confirmacao manual
```

---

## Pirâmide de Automação e Stack de Ferramentas

### Piramide de Automacao

```
                +-----------------+
                |  Analise Manual |  <- Voce (tempo valioso)
                |   (40% tempo)   |
                +--------+--------+
               +---------+---------+
               |  Testes Dirigidos |  <- Semi-automatico
               |   (30% tempo)    |
               +---------+--------+
          +--------------+--------------+
          |  Recon e Scan Automatizado  |  <- Automatico
          |        (30% tempo)          |
          +-----------------------------+

Regra: Automacao boa = voce recebe alertas de mudancas
       Automacao ruim = voce fica gerenciando a automacao
```

### Stack de Ferramentas por Fase

| Fase | Ferramenta | Proposito |
|------|-----------|-----------|
| Subdominios | subfinder + amass | Descoberta passiva |
| Verificacao | httpx | Hosts ativos + info |
| URLs | gau + waybackurls + katana | Superficie de URL |
| Vulnerabilidades | nuclei | Scan em massa |
| Screenshots | gowitness | Revisao visual |
| Notificacoes | notify | Alertas Slack/Telegram |
| Orquestracao | bash scripts | Coordenacao |

---

## Na Pratica

### 1. Setup do Ambiente

```bash
# Instalacao completa do stack (Ubuntu/Debian)
# Go toolchain
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -xzf go1.21.0.linux-amd64.tar.gz -C /usr/local
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Ferramentas ProjectDiscovery
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Outras ferramentas
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/sensepost/gowitness@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/anew@latest       # Append New - evita duplicatas
go install github.com/tomnomnom/unfurl@latest     # Extrair partes de URL
go install github.com/tomnomnom/qsreplace@latest  # Substituir query strings

# Templates do nuclei
nuclei -update-templates

# Patterns do gf
mkdir -p ~/.gf
cp /root/go/pkg/mod/github.com/tomnomnom/gf*/examples/*.json ~/.gf/
# Download patterns extras
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-extra
cp ~/.gf-extra/*.json ~/.gf/
```

### 2. Script de Recon Automatizado

```bash
#!/bin/bash
# recon.sh - Script de reconhecimento automatizado
# Uso: ./recon.sh target.com

TARGET=$1
WORKDIR="$HOME/bugbounty/$TARGET"
NOTIFY_CONFIG="$HOME/.config/notify/provider-config.yaml"

mkdir -p $WORKDIR/{recon,screenshots,nuclei,findings}

echo "[*] Iniciando recon para: $TARGET"
echo "[*] Diretorio: $WORKDIR"

# FASE 1: Subdominios
echo "[*] Fase 1: Subdominios"
subfinder -d $TARGET -silent 2>/dev/null | anew $WORKDIR/recon/subdomains.txt
amass enum -d $TARGET -passive -silent 2>/dev/null | anew $WORKDIR/recon/subdomains.txt

TOTAL=$(wc -l < $WORKDIR/recon/subdomains.txt)
echo "[+] Total subdominios: $TOTAL"

# FASE 2: Hosts ativos
echo "[*] Fase 2: Verificando hosts ativos"
cat $WORKDIR/recon/subdomains.txt | \
    httpx -silent -title -status-code -content-length -tech-detect \
    2>/dev/null | tee $WORKDIR/recon/live_hosts_full.txt | \
    awk '{print $1}' | anew $WORKDIR/recon/live_hosts.txt

LIVE=$(wc -l < $WORKDIR/recon/live_hosts.txt)
echo "[+] Hosts ativos: $LIVE"

# FASE 3: Screenshots
echo "[*] Fase 3: Screenshots"
gowitness file -f $WORKDIR/recon/live_hosts.txt \
    -P $WORKDIR/screenshots/ \
    --delay 3 \
    --threads 5 \
    2>/dev/null

# FASE 4: URLs historicas
echo "[*] Fase 4: URLs historicas"
cat $WORKDIR/recon/subdomains.txt | \
    gau --threads 5 --subs 2>/dev/null | \
    anew $WORKDIR/recon/urls.txt

URLS=$(wc -l < $WORKDIR/recon/urls.txt)
echo "[+] URLs encontradas: $URLS"

# FASE 5: Nuclei scan
echo "[*] Fase 5: Nuclei scan"
nuclei -l $WORKDIR/recon/live_hosts.txt \
    -t ~/nuclei-templates/ \
    -severity critical,high,medium \
    -o $WORKDIR/nuclei/results.txt \
    -silent 2>/dev/null

VULNS=$(wc -l < $WORKDIR/nuclei/results.txt 2>/dev/null || echo 0)
echo "[+] Vulnerabilidades potenciais: $VULNS"

# FASE 6: Notificacao
if [ -f "$NOTIFY_CONFIG" ]; then
    echo "Recon concluido para $TARGET: $LIVE hosts ativos, $URLS URLs, $VULNS potenciais vulns" | \
        notify -provider-config $NOTIFY_CONFIG -silent
fi

echo "[*] Recon concluido! Resultados em: $WORKDIR"
```

### 3. Pipeline de Monitoramento Continuo

```bash
#!/bin/bash
# monitor.sh - Monitorar novos assets
# Executar via cron: 0 */6 * * * /path/to/monitor.sh target.com

TARGET=$1
WORKDIR="$HOME/bugbounty/$TARGET"
NEW_SUBS="$WORKDIR/recon/new_subdomains.txt"

# Descobrir novos subdominios (comparar com lista atual)
subfinder -d $TARGET -silent 2>/dev/null | \
    anew $WORKDIR/recon/subdomains.txt | \
    tee $NEW_SUBS

# Se houver novos subdominios
if [ -s $NEW_SUBS ]; then
    NEW_COUNT=$(wc -l < $NEW_SUBS)
    echo "[!] $NEW_COUNT novos subdominios para $TARGET:"
    cat $NEW_SUBS

    # Verificar se sao ativos
    cat $NEW_SUBS | httpx -silent | tee -a $WORKDIR/recon/live_hosts.txt

    # Scan nuclei nos novos hosts
    cat $NEW_SUBS | httpx -silent | \
        nuclei -t ~/nuclei-templates/ \
               -severity critical,high \
               -o $WORKDIR/nuclei/new_results.txt \
               -silent

    # Notificar
    echo "[$TARGET] $NEW_COUNT novos subdominios descobertos: $(cat $NEW_SUBS | tr '\n' ', ')" | \
        notify -provider-config ~/.config/notify/provider-config.yaml

    # Limpar
    rm -f $NEW_SUBS
fi
```

### 4. Configuracao de Notificacoes (notify)

```yaml
# ~/.config/notify/provider-config.yaml
slack:
  - id: "main"
    slack_webhook_url: "https://hooks.slack.com/services/T.../B.../..."
    slack_username: "BugBot"
    slack_channel: "#bug-bounty"
    slack_format: "{{data}}"

telegram:
  - id: "telegram_main"
    telegram_api_key: "SEU_BOT_API_KEY"
    telegram_chat_id: "@SEU_CANAL"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown"

discord:
  - id: "discord_main"
    discord_webhook_url: "https://discord.com/api/webhooks/..."
    discord_username: "BugBot"
    discord_format: "{{data}}"
```

```bash
# Usar notify
echo "Novo subdominio: dev.target.com" | notify -provider-config ~/.config/notify/provider-config.yaml
echo "Critical vuln found!" | notify -id telegram_main
```

### 5. Fuzzing em Massa Automatizado

```bash
#!/bin/bash
# fuzz_mass.sh - Fuzzing de diretorios em massa
# Uso: ./fuzz_mass.sh live_hosts.txt

HOSTS_FILE=$1
WORDLIST="/opt/SecLists/Discovery/Web-Content/common.txt"
OUTPUT_DIR="./fuzz_results"

mkdir -p $OUTPUT_DIR

cat $HOSTS_FILE | while read host; do
    # Sanitizar nome de arquivo
    SAFE_NAME=$(echo $host | sed 's/[^a-zA-Z0-9]/_/g')

    echo "[*] Fuzzing: $host"
    ffuf -w $WORDLIST \
         -u "$host/FUZZ" \
         -mc 200,201,301,302,403 \
         -t 50 \
         -rate 100 \
         -o "$OUTPUT_DIR/$SAFE_NAME.json" \
         -of json \
         -s 2>/dev/null

    # Aguardar entre hosts para nao ser bloqueado
    sleep 1
done

# Consolidar resultados
cat $OUTPUT_DIR/*.json | jq -r '.results[]?.url' 2>/dev/null | sort -u > all_found_paths.txt
echo "[+] Total paths encontrados: $(wc -l < all_found_paths.txt)"
```

### 6. Extracao de Parametros para Fuzzing

```bash
#!/bin/bash
# param_extract.sh - Extrair e categorizar parametros

TARGET=$1
GAU_URLS="$TARGET/recon/urls.txt"

echo "[*] Extraindo parametros de URLs..."

# Parametros gerais
cat $GAU_URLS | grep "?" | \
    unfurl --unique keys 2>/dev/null | \
    sort -u > "$TARGET/recon/params_all.txt"

echo "[+] Total parametros unicos: $(wc -l < $TARGET/recon/params_all.txt)"

# Categorizar com gf (patterns de vulnerabilidade)
cat $GAU_URLS | gf xss | tee "$TARGET/recon/params_xss.txt" | wc -l | xargs echo "[+] URLs XSS-likely:"
cat $GAU_URLS | gf sqli | tee "$TARGET/recon/params_sqli.txt" | wc -l | xargs echo "[+] URLs SQLi-likely:"
cat $GAU_URLS | gf lfi | tee "$TARGET/recon/params_lfi.txt" | wc -l | xargs echo "[+] URLs LFI-likely:"
cat $GAU_URLS | gf ssrf | tee "$TARGET/recon/params_ssrf.txt" | wc -l | xargs echo "[+] URLs SSRF-likely:"
cat $GAU_URLS | gf rce | tee "$TARGET/recon/params_rce.txt" | wc -l | xargs echo "[+] URLs RCE-likely:"
cat $GAU_URLS | gf redirect | tee "$TARGET/recon/params_redirect.txt" | wc -l | xargs echo "[+] URLs Redirect-likely:"
```

### 7. Nuclei - Uso Avancado

```bash
# Scan basico em massa
nuclei -l hosts.txt -t ~/nuclei-templates/ -o results.txt

# Apenas alta/critica
nuclei -l hosts.txt -t ~/nuclei-templates/ -severity critical,high

# Templates especificos
nuclei -l hosts.txt -t ~/nuclei-templates/cves/
nuclei -l hosts.txt -t ~/nuclei-templates/misconfiguration/
nuclei -l hosts.txt -t ~/nuclei-templates/exposures/
nuclei -l hosts.txt -t ~/nuclei-templates/technologies/

# Scan com tags especificas
nuclei -l hosts.txt -tags sqli,xss,ssrf

# Rate limiting (respeitar limites)
nuclei -l hosts.txt -t ~/nuclei-templates/ -rate-limit 100 -bulk-size 10

# Output em JSON para processamento
nuclei -l hosts.txt -t ~/nuclei-templates/ -json | jq .

# Template customizado basico
cat > ~/nuclei-templates/custom/custom-header-check.yaml << 'EOF'
id: custom-header-check
info:
  name: Custom Security Header Check
  author: hunter
  severity: info
  
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "X-Frame-Options"
        part: header
        negative: true
      - type: status
        status:
          - 200
EOF
nuclei -l hosts.txt -t ~/nuclei-templates/custom/custom-header-check.yaml
```

### 8. Interactsh - OAST (Out-of-Band Testing)

```bash
# Para blind SSRF, blind XXE, blind RCE
# Configurar servidor OAST
interactsh-client -v

# Output: [INF] Listing on xxxxx.oast.pro
# Usar xxxxx.oast.pro como URL nos payloads

# Exemplo: testar blind SSRF
# URL do payload: http://xxxxx.oast.pro/ssrf-test
curl -X POST http://TARGET/webhook \
     -d '{"url": "http://xxxxx.oast.pro/ssrf-test"}'

# interactsh-client mostrara quando receber request:
# [DNS] xxxxx.oast.pro from 1.2.3.4
# [HTTP] GET /ssrf-test from 1.2.3.4
```

---

## Ferramentas

```bash
# Instalacao completa em um comando
go install github.com/projectdiscovery/{subfinder/v2/cmd/subfinder,httpx/cmd/httpx,nuclei/v2/cmd/nuclei,katana/cmd/katana,notify/cmd/notify,interactsh/cmd/interactsh-client,dnsx/cmd/dnsx,naabu/v2/cmd/naabu}@latest && go install github.com/lc/gau/v2/cmd/gau@latest && go install github.com/hakluke/hakrawler@latest && go install github.com/sensepost/gowitness@latest && go install github.com/tomnomnom/{waybackurls,gf,anew,unfurl,qsreplace}@latest

# Verificar instalacao
subfinder -version
httpx -version
nuclei -version
```

---

## Deteccao

### Melhores Praticas de Automacao

```
FAZER:
+ Rate limiting em todas as ferramentas (respeitar o alvo)
+ Monitoramento continuo (alertas de novos assets)
+ Salvar todos os resultados para comparacao futura
+ Usar anew para evitar processamento duplicado
+ Separar por programa (nao misturar alvos)
+ Atualizar templates do nuclei semanalmente

NAO FAZER:
X Automacao sem rate limiting (pode causar DoS acidental)
X Testar fora do escopo (automatizacoes nao respeitam escopo sozinhas)
X Confiar cegamente nos resultados (falsos positivos sao comuns)
X Submeter relatorio gerado por nuclei sem verificar manualmente
X Esquecer de atualizar templates (templates velhos = missed vulns)

REGRA DE OURO:
Nuclei encontra -> voce verifica manualmente -> depois voce reporta
NUNCA reportar diretamente o output de scanner sem verificacao
```
