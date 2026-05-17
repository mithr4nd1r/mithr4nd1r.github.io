---
title: "Visibility & Monitoring"
---

# Visibility e Monitoramento de Segurança

> Segurança reativa: detectar ataques em andamento e reconstruir incidentes via indicadores históricos e instantâneos.

---

## Por Que Visibility Importa

Controles preventivos inevitavelmente falham — 0-days, misconfigurations e insiders contornam defesas perimetrais por definição. Sem logs adequados, um incidente ocorre mas não é detectado: o tempo médio de detecção é de 197 dias segundo o IBM Cost of Breach 2023. Com logs bem estruturados, é possível detectar o ataque em tempo real, contê-lo antes do dano total, e reconstruir a cadeia de eventos para forense pós-incidente.

---

## Indicadores Históricos

Dados coletados ao longo do tempo para análise retrospectiva e detecção de tendências.

### Tipos e Fontes

| Indicador | Fonte | O que revela |
|-----------|-------|-------------|
| Vulnerabilidades por severidade | SAST scan (Semgrep, GitLab CI) | Tendência de débito técnico de segurança |
| CVEs em dependências | pip-audit, npm audit, Snyk | Exposição por supply chain |
| Vulnerabilidades por repositório | Dashboard SAST/DAST | Sistemas de maior risco |
| Cobertura de threat models | Tracker interno | % de sistemas com modelo de ameaças |
| SLA de remediação | Ticket tracker (Jira, Linear) | Velocidade de resposta a vulnerabilidades |
| Findings de pen test | Relatórios | Distribuição por categoria (OWASP) |

### Dashboard de Indicadores Históricos

Métricas típicas de AppSec dashboard:

```
Vulnerabilidades por severidade (mês a mês):
  Crítico:  3 → 2 → 1 → 0   ✓ tendência positiva
  Alto:     12 → 9 → 8 → 6
  Médio:    45 → 48 → 42 → 38
  Baixo:    89 → 91 → 95 → 87

Por tipo de scan:
  SAST:           65%
  Dependência:    28%
  DAST:           7%

Top 5 repositórios mais vulneráveis:
  1. api-gateway      — 12 findings (3 críticos)
  2. auth-service     — 8 findings (1 crítico)
  3. payment-service  — 6 findings (0 críticos)
  ...

Cobertura de threat modeling:
  Sistemas modelados: 31% (12/39)
  Ameaças identificadas: 46
  Controles definidos: 35 (76%)
```

### Automação com Flask + CSV

```python
# Dashboard automatizado — ingere CSV de scan do GitLab/Semgrep
from flask import Flask, request
import csv, io

app = Flask(__name__)

@app.route('/upload-scan', methods=['POST'])
def upload():
    file = request.files['report']
    content = file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(content))

    vulns_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    vulns_by_repo = {}

    for row in reader:
        sev = row.get('severity', 'low').lower()
        repo = row.get('repository', 'unknown')
        vulns_by_severity[sev] = vulns_by_severity.get(sev, 0) + 1
        vulns_by_repo[repo] = vulns_by_repo.get(repo, 0) + 1

    return jsonify({
        'by_severity': vulns_by_severity,
        'top_repos': sorted(vulns_by_repo.items(), key=lambda x: -x[1])[:10]
    })
```

---

## Indicadores Instantâneos

Alertas em tempo real baseados em comportamento anômalo durante operação.

### Eventos Críticos para Monitorar

```
AUTENTICAÇÃO:
[ ] N falhas de login consecutivas do mesmo IP (brute force)
[ ] Login bem-sucedido de IP/geolocation nova para o usuário
[ ] Login de conta inativa há > 90 dias
[ ] Múltiplas contas com senha reset em < 5 min (credential stuffing)

AUTORIZAÇÃO:
[ ] Requisições com 403 acima de threshold por usuário
[ ] Acesso a recursos de outros usuários (BOLA detection)
[ ] Acesso a endpoints admin por usuários sem privilégio

ANOMALIAS DE REQUEST:
[ ] Mesma URL com IDs incrementais em sequência (enumeração)
[ ] Rate acima do threshold por endpoint por IP/usuário
[ ] Payload > tamanho esperado (buffer overflow attempt)
[ ] Caracteres suspeitos em parâmetros (' " ; < > ..)

INFRAESTRUTURA:
[ ] Novo processo iniciado pelo processo da aplicação
[ ] Conexão de rede de saída em porta não esperada
[ ] Acesso a arquivo sensível (/etc/passwd, /etc/shadow)
[ ] Aumento anormal de consumo de CPU/memória
```

### Implementação — Structured Logging

```python
import logging, json
from datetime import datetime

logger = logging.getLogger('security')

def log_security_event(event_type, user_id, ip, details):
    logger.warning(json.dumps({
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'source_ip': ip,
        'details': details
    }))

# Uso em endpoints
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.json)
    if not user:
        log_security_event('AUTH_FAILURE', None, request.remote_addr,
                           {'email': request.json.get('email')})
        return jsonify({'error': 'Invalid credentials'}), 401

    log_security_event('AUTH_SUCCESS', user.id, request.remote_addr, {})
    return jsonify({'token': generate_token(user)})
```

### Regras de Alerta (SIEM)

```yaml
# Exemplo Sigma rule — brute force detection
title: API Brute Force Login Attempt
status: experimental
logsource:
  category: webserver
detection:
  selection:
    event_type: AUTH_FAILURE
  timeframe: 60s
  condition: selection | count() by source_ip > 10
level: high
```

---

## Gerenciamento de Sessão — O que Monitorar

```
[ ] Sessions criadas por IP inesperado após autenticação
[ ] Token usado de dois IPs diferentes simultaneamente
[ ] Session ativa além do timeout configurado
[ ] JWT com `exp` vencido sendo aceito (bug de validação)
[ ] Uso do mesmo token para dois usuários diferentes
```

---

## Testes de Requisitos — Validação dos Controles

Após threat modeling, transformar controles em testes verificáveis:

### Exemplo: Controles C01–C06

```python
# C01: Input validation
def test_sql_injection_blocked():
    r = requests.post('/login', json={'email': "' OR 1=1 --", 'password': 'x'})
    assert r.status_code == 400   # deve rejeitar, não processar

# C02: Rate limiting
def test_rate_limit_login():
    for i in range(15):
        requests.post('/login', json={'email': 'test@test.com', 'password': 'wrong'})
    r = requests.post('/login', json={'email': 'test@test.com', 'password': 'wrong'})
    assert r.status_code == 429   # Too Many Requests

# C04: Object-level authorization
def test_bola_blocked():
    # usuário A tenta acessar recurso do usuário B
    headers = {'Authorization': f'Bearer {user_a_token}'}
    r = requests.get(f'/api/users/{user_b_id}/data', headers=headers)
    assert r.status_code == 403   # deve rejeitar

# C05: Generic error messages
def test_no_user_enumeration():
    r1 = requests.post('/login', json={'email': 'naoexiste@test.com', 'password': 'x'})
    r2 = requests.post('/login', json={'email': 'existe@test.com', 'password': 'wrong'})
    # ambas devem retornar a mesma mensagem
    assert r1.json()['error'] == r2.json()['error']
```

### Checklist de Teste de Requisitos

```
[ ] SAST rodou sem novos findings críticos/altos?
[ ] Tests de requisitos do threat model passaram?
[ ] Nenhuma credencial hardcoded no código (gitleaks)?
[ ] Dependências sem CVEs ativos exploráveis?
[ ] DAST (Nuclei/ZAP) rodou contra staging sem novos findings críticos?
[ ] Revisão manual de endpoints de autenticação e autorização?
[ ] Rate limiting testado sob carga?
[ ] CORS configurado corretamente (não wildcard em endpoint autenticado)?
```

---

## Métricas de Maturidade AppSec

```
Nível 1 (inicial):
  - Scan de dependências automatizado no CI
  - Logging estruturado implementado
  - Processo de resposta a incidentes documentado

Nível 2 (gerenciado):
  - SAST integrado ao CI com gates de qualidade
  - Threat model para sistemas críticos
  - DAST em staging antes de cada release
  - SLA de remediação por severidade (Crítico: 24h, Alto: 7d, Médio: 30d)

Nível 3 (otimizado):
  - Threat model para todos os sistemas
  - Bug bounty program
  - Red team exercises
  - Métricas de MTTR (Mean Time To Remediate) < target
  - Security champions por time de desenvolvimento
```

---

## Ferramentas de Visibilidade

| Ferramenta | Uso |
|-----------|-----|
| Elasticsearch + Kibana | Agregação e visualização de logs |
| Grafana + Loki | Logs e métricas em tempo real |
| Splunk | SIEM enterprise |
| Wazuh | SIEM open-source com EDR básico |
| Datadog | APM + security monitoring |
| GitLab Security Dashboard | Findings de SAST/DAST/dependency scan |
| Semgrep Cloud | Dashboard de findings com tendência histórica |

---

## Módulos Relacionados

Visibility e monitoramento são a camada operacional que fecha o ciclo do SSDLC. O módulo `01_ssdlc_e_frameworks.md` fornece o framework: o pilar SAMM.Operations cobre formalmente gestão de incidentes e controle operacional, que o monitoramento instrumenta na prática. O módulo `02_threat_modeling.md` é o ponto de partida para o que monitorar: os controles definidos no threat model (C01–C06 e similares) são exatamente os comportamentos que os alertas de SIEM devem detectar quando violados, e a cobertura de threat models é uma das métricas de maturidade AppSec rastreadas nos dashboards históricos. Para priorização de findings encontrados em runtime, `../13_bug_bounty_metodologia/04_relatorios_e_impacto.md` cobre CVSS scoring em contexto de relatório e impacto. As referências normativas são o OWASP Logging Cheat Sheet e o OWASP Testing Guide — OTG-CONFIG-001.
