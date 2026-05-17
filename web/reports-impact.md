---
title: "Reports & Impact"
---

# Relatorios e Impacto em Bug Bounty

## Contexto: Comunicacao de Impacto - Transformar Tecnica em Risco de Negocio

Encontrar a vulnerabilidade e metade do trabalho. A outra metade e convencer o triager de que ela importa — e o quanto ela importa. Programas de bug bounty sao operados por times de seguranca que leem dezenas de reports por dia. Um report confuso, mal estruturado, ou com impacto nao demonstrado perde recompensa por cansaco cognitivo, mesmo que a vulnerabilidade seja real e critica.

**Por que impacto de negocio supera severidade tecnica:**

CVSS e uma escala tecnica. Recompensas sao decisoes de negocio. Um IDOR com CVSS 7.5 em dados de cartao de credito vale mais do que um IDOR com CVSS 7.5 em dados de preferencias de notificacao — porque o impacto ao negocio (risco financeiro, risco de compliance com PCI-DSS) e diferente.

O triager precisa justificar internamente a recompensa que paga. Quanto mais claro voce torna o impacto em termos de negocio — dados em risco, usuarios afetados, regulacoes violadas (LGPD, HIPAA, PCI-DSS) — mais facil e a aprovacao de recompensa alta.

**A traducao CVSS -> impacto de negocio:**

| Metrica CVSS | Valor tecnico | Traducao para negocio |
|---|---|---|
| AV:N (Attack Vector: Network) | Exploravel remotamente | Qualquer atacante na internet pode explorar |
| PR:N (Privileges Required: None) | Sem autenticacao | Nao precisa ter conta — qualquer pessoa |
| UI:N (User Interaction: None) | Sem interacao de vitima | Ataque silencioso, vitima nao precisa clicar em nada |
| C:H (Confidentiality: High) | Dados confidenciais expostos | PII, dados financeiros, credenciais de outros usuarios |
| I:H (Integrity: High) | Dados podem ser modificados | Fraude, corrupcao de registros, falsificacao |
| A:H (Availability: High) | Servico pode ser derrubado | Indisponibilidade de producao, perda de receita |

**Por que o report e a vulnerabilidade, do ponto de vista da empresa:**

A empresa nao consegue corrigir o que nao entende. Um report com passos confusos atrasa o fix. Um report com impacto mal demonstrado pode resultar em triagem incorreta como "Informational". Um report com remediacao clara acelera o patch — o que beneficia o programa (vulnerabilidade corrigida mais rapido) e o hunter (recompensa paga mais rapido).

**Conectar com OWASP ASVS:**

Referenciar controles especificos do OWASP ASVS na remediacao sugerida aumenta credibilidade tecnica. Exemplo: "Este finding viola ASVS V4.1 — verificacao de controle de acesso deve ser feita no backend, nao apenas na interface". Isso demonstra conhecimento do padrao e facilita o trabalho do time de desenvolvimento na correcao.

---

## Ciclo de Vida de um Report e Sistema de Severidade CVSS

### Ciclo de Vida de um Report

```
Hunter encontra bug
       |
Draft do relatorio
       |
Verificacao do PoC (funciona em conta de teste?)
       |
Submissao na plataforma
       |
Triagem (24-72h) -> Needs More Info / Duplicate / Accepted
       |
Avaliacao de severidade (pode contestar)
       |
Correcao pelo time de desenvolvimento
       |
Validacao da correcao
       |
Recompensa paga
       |
Divulgacao publica (opcional, apos acordo)
```

### Sistema CVSS (Common Vulnerability Scoring System)

| Severidade | Score CVSS | Recompensa Tipica |
|------------|-----------|------------------|
| **Critical** | 9.0-10.0 | $5,000-$50,000+ |
| **High** | 7.0-8.9 | $1,000-$10,000 |
| **Medium** | 4.0-6.9 | $200-$1,500 |
| **Low** | 0.1-3.9 | $50-$500 |
| **Informational** | N/A | $0 |

### Fatores CVSS Principais

| Fator | Opcoes | Impacto no Score |
|-------|--------|-----------------|
| Attack Vector | Network > Adjacent > Local > Physical | Network = mais alto |
| Attack Complexity | Low > High | Low = mais alto |
| Privileges Required | None > Low > High | None = mais alto |
| User Interaction | None > Required | None = mais alto |
| Confidentiality | High > Low > None | - |
| Integrity | High > Low > None | - |
| Availability | High > Low > None | - |

---

## Na Pratica

### 1. Estrutura de um Relatorio Excelente

```markdown
# [TIPO DE VULNERABILIDADE] em [ENDPOINT] - [IMPACTO EM UMA LINHA]

## Resumo
[2-3 paragrafos descrevendo: o que e, onde esta, qual o impacto]

## Severidade
**Sugerida: High (CVSS 8.1)**

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

Justificativa:
- AV:N - Exploravel via internet, sem acesso fisico
- AC:L - Sem condicoes especiais de ataque
- PR:L - Requer autenticacao como usuario regular
- UI:N - Sem interacao de outra vitima necessaria
- C:H - Acesso a dados confidenciais de outros usuarios
- I:H - Pode modificar dados de outros usuarios
- A:N - Sem impacto em disponibilidade

## Impacto
Um atacante autenticado pode:
1. Acessar dados pessoais de qualquer usuario (CPF, endereco, cartao)
2. Modificar dados de perfil de qualquer conta
3. Potencialmente realizar fraudes financeiras em contas de terceiros

**Dados em risco:** [NUMERO ESTIMADO] usuarios registrados na plataforma.

## Passos para Reproduzir

### Pre-requisitos
- Conta de usuario regular (usuario: test1@test.com)
- Outro usuario alvo (ID: 12345)

### Reproducao

**1.** Fazer login como usuario regular:
   - Acesse: https://app.target.com/login
   - Email: test1@test.com
   - Senha: Test@123

**2.** Interceptar request de perfil no Burp Suite:
   - Acesse: https://app.target.com/api/profile
   - Observe o parametro `user_id` no request

**3.** Modificar o user_id para o ID da vitima:
   - Original: GET /api/profile?user_id=99999 (meu ID)
   - Modificado: GET /api/profile?user_id=12345 (vitima)

**4.** Observar dados da vitima na resposta:
   - Nome completo: Joao Silva
   - Email: joao@email.com
   - CPF: 123.456.789-00
   - Cartao: **** **** **** 1234

## Request e Response

### Request Malicioso
GET /api/profile?user_id=12345 HTTP/1.1
Host: app.target.com
Authorization: Bearer eyJ...meu_token...
Content-Type: application/json

### Response (dados da vitima)
{
    "id": 12345,
    "name": "Joao Silva",
    "email": "joao@email.com",
    "cpf": "123.456.789-00",
    "card_last4": "1234"
}

## Prova de Conceito
[Screenshot ou video mostrando a exploracao]

## Remediacao Sugerida
Verificar no servidor que o user_id da request corresponde ao usuario autenticado no token JWT.
Este finding viola OWASP ASVS V4.1 (Access Control): verificacao deve ser feita no backend, nao via parametro controlado pelo usuario.

## Leitura Complementar
- OWASP Top 10 2021 - A01:2021 Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP ASVS V4.1: Verify access control checks are performed server-side
```

### 2. Titulos Eficazes

```
PADRAO: [Tipo Vuln] via [Vetor/Endpoint] permite [Impacto]

BOM:
+ IDOR via /api/users/{id}/profile expoe dados financeiros de qualquer usuario
+ Stored XSS em campo de nome permite sequestro de conta de admin
+ SQL Injection em /api/search/?q= permite extracao de toda a base de dados
+ Auth bypass via token null em /api/password-reset causa account takeover
+ Race condition em /api/coupon/redeem permite uso ilimitado de cupons

RUIM:
X IDOR found
X Security vulnerability in profile page
X XSS
X Found a bug
X SQL injection vulnerability
```

### 3. Demonstrando Impacto Adequado

```
REGRA: Nunca deixar o triager adivinhar o impacto

TABELA DE IMPACTO POR TIPO DE VULN:

SQL Injection:
- Mostrar extracao de tabela de usuarios (com hash de senha)
- Quantos registros existem?
- Que dados estao expostos? (PII, financeiro, medico)
- E write? Mostrar modificacao de dados
- E file read? Mostrar leitura de /etc/passwd

IDOR:
- Quantos usuarios afetados?
- Que dados sao expostos?
- Qual a classe dos dados? (PII, financeiro, privado)
- E possivel modificar dados? Deletar conta?

XSS (Stored):
- Onde fica armazenado? Quem ve?
- Admin panel? -> maior severidade
- Todos os usuarios? -> maior severidade
- Demonstrar roubo de cookie: document.cookie
- Demonstrar CSRF via XSS

Auth Bypass:
- O que o atacante ganha acesso?
- Painel admin? -> Critical
- Dados de outro usuario? -> High
- Area de pagamento? -> Critical
```

### 4. Linguagem e Tom

```
PROFISSIONAL:
- Neutro, objetivo, tecnico
- Sem julgamento ("este e o pior codigo que ja vi")
- Sem ameacas implicitas ("posso fazer muito dano")
- Oferecer colaboracao ("fico disponivel para esclarecer duvidas")

TECNICO:
- Mencionar CVE/CWE quando aplicavel
- Referenciar OWASP e ASVS
- Explicar o mecanismo, nao so o sintoma
- Propor correcao com codigo quando possivel

OBJETIVO:
- PoC funcional e minimo
- Steps enxutos (sem passos desnecessarios)
- Screenshots marcados com setas onde relevante
- Video para bugs complexos ou de timing
```

### 5. Escalando Severidade Adequadamente

```
IDOR de dados nao sensiveis = Medium
IDOR de dados financeiros = High
IDOR de dados medicos = Critical (HIPAA/LGPD)
IDOR + modificacao = Higher than only read

XSS refletido = Low/Medium
XSS stored em perfil = Medium
XSS stored em admin panel = High/Critical
XSS stored + bypass HttpOnly via cookie theft = Critical

SQLi read-only = High
SQLi + database dump = High/Critical
SQLi + file write = Critical
SQLi + RCE = Critical

Auth bypass = High
Auth bypass + admin access = Critical
Auth bypass + data exfiltration = Critical

SSRF interno = Medium
SSRF + acesso a metadados cloud (AWS/GCP/Azure) = High/Critical
SSRF + RCE via redis/memcached = Critical
```

### 6. Respondendo a Triagem

```
SE: "Duplicate"
RESPOSTA: "Entendo que existe um report anterior. Posso ver o report para confirmar 
           que e a mesma vulnerabilidade/endpoint? As vezes a mesma classe de bug 
           existe em multiplos lugares."

SE: "Informational" para algo que voce acha Medium/High
RESPOSTA: "Gostaria de entender o racional para Informational. Com base nos criterios 
           CVSS, classifico como High porque: [explicar C/I/A]. Poderia reavaliar com 
           base nessa perspectiva?"

SE: "Won't Fix"
RESPOSTA: "Poderia explicar o racional para Won't Fix? Se e uma decisao de aceitar o risco, 
           entendo. Mas se houver alguma informacao adicional que eu possa fornecer para 
           ajudar na avaliacao, estou disponivel."

SE: "Needs More Info"
RESPOSTA: Fornecer exatamente o que pediram + qualquer informacao adicional que possa 
          ajudar. Perguntar se ha algo mais necessario antes de fornecer.

NUNCA:
X Ser agressivo ou ameacador
X Comentar sobre disclosure publica como pressao
X Spammar updates sem nova informacao
X Escalar para redes sociais antes de esgotar canais oficiais
```

### 7. Calculando Recompensa Esperada

```python
# Estimativa basica de recompensa
# (baseado em programas publicos populares)

SEVERIDADE_BASE = {
    "critical": 5000,  # Range: $2000-$50000
    "high": 1500,      # Range: $500-$10000
    "medium": 400,     # Range: $100-$2000
    "low": 100,        # Range: $50-$500
}

MULTIPLICADORES = {
    "RCE": 3.0,
    "data_exfiltration_pii": 2.5,
    "financial_data": 2.5,
    "auth_bypass_admin": 2.0,
    "stored_xss_admin": 1.8,
    "idor_financeiro": 1.5,
    "no_auth_required": 1.5,
}

# Exemplo: IDOR financeiro, High, sem autenticacao adicional
base = SEVERIDADE_BASE["high"]  # 1500
mult = MULTIPLICADORES["financial_data"] * MULTIPLICADORES["no_auth_required"]
estimado = base * mult  # 1500 * 2.5 * 1.5 = $5625
```

---

## Ferramentas

```bash
# markdown preview para revisar report antes de submeter
grip report.md    # GitHub-style rendering local
# ou
mdp report.md

# Captura de tela com anotacoes
flameshot gui     # Linux - screenshot + anotacao

# Gravacao de video PoC
obs              # OBS Studio
simplescreenrecorder  # Alternativa simples Linux

# Curl para reproduzir requests em one-liner
curl -v -X GET "http://TARGET/api/profile?user_id=12345" \
     -H "Authorization: Bearer TOKEN" \
     2>&1 | tee poc_output.txt
```

---

## Deteccao

### Checklist Final Antes de Submeter

```
VERIFICACAO TECNICA:
[ ] Reproduzi o bug na conta de teste (nao na minha conta pessoal)
[ ] Os passos estao ordenados e completos
[ ] Request e response estao copiados do Burp (nao do curl)
[ ] Usei dados de teste, nao dados reais de outros usuarios
[ ] O PoC demonstra o impacto, nao so a existencia do bug

VERIFICACAO DE QUALIDADE:
[ ] Titulo e descritivo e especifico
[ ] Severidade esta justificada com CVSS
[ ] Impacto esta descrito em termos de negocio
[ ] Remediacao sugerida e tecnica e implementavel
[ ] Ortografia e gramatica estao corretas

VERIFICACAO DE ESCOPO:
[ ] O endpoint esta explicitamente no escopo
[ ] Nao e um bug em software de terceiro fora do controle do alvo
[ ] Nao e um self-XSS (so afeta o proprio atacante)
[ ] Nao requer engenharia social ou acesso fisico

VERIFICACAO LEGAL:
[ ] Nao danifiquei dados do alvo
[ ] Nao acessei mais dados do que o necessario para o PoC
[ ] Nao mantive copia de dados reais de usuarios
[ ] Nao testei alem do necessario para confirmar o bug

VERIFICACAO DE IMPACTO:
[ ] Impacto esta em termos de negocio, nao so tecnico?
[ ] Numero de usuarios afetados esta estimado?
[ ] Regulacoes violadas estao mencionadas (LGPD, HIPAA, PCI-DSS)?
[ ] OWASP ASVS ou Top 10 estao referenciados na remediacao?
```
