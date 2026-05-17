---
title: "SSDLC & Frameworks"
---

# AppSec — SSDLC e Frameworks (SAMM / ASVS)

> Fonte: curso AppSec PT-BR (CySource / Web CySource). Perspectiva defensiva: integrar segurança no ciclo de desenvolvimento.

---

## AppSec — O que é na prática

AppSec (Application Security) cobre segurança de software desde o design até operação. O escopo varia por empresa:

| Modelo | O que o time faz |
|--------|-----------------|
| Pentesting-focused | Pen test de aplicações internas antes do deploy |
| DevSecOps | Coloca security gates na esteira CI/CD |
| Governance | Security Champions, políticas, treinamento |
| Gestão de Vulnerabilidades | Triagem de findings de SAST/DAST, SLA de remediação |

---

## SSDLC — Secure Software Development Lifecycle

Integra atividades de segurança em **cada fase** do desenvolvimento:

```
Análise de Requisitos → Design → Implementação → Testes → Deploy → Operação
        ↓                  ↓           ↓             ↓        ↓        ↓
   Req. segurança    Threat Model   SAST/DAST    Pen test  Scan    SIEM/Alertas
   Classificação     Arq. segura    Code Review  ASVS     Supply   Incident resp
   de dados          Revisão ARQ    Dep scanning  checks   chain
```

**Diferença chave**: SDLC tradicional trata segurança como fase final ("bolinha de neve"); SSDLC é shift-left — encontrar falhas quando são mais baratas de corrigir.

**DevSecOps** = SSDLC aplicado em pipeline CI/CD:
- Pre-commit hooks: Semgrep, secret scanning (gitleaks)
- CI: SAST (Semgrep, Sonarqube), dependency scan (Snyk, OWASP Dependency Check)
- CD: DAST (OWASP ZAP, Nuclei), container scanning (Trivy)
- Post-deploy: DAST contínuo, monitoramento de runtime

---

## OWASP SAMM — Software Assurance Maturity Model

Questionário de maturidade de segurança organizacional. Avalia em 5 pilares:

### Pilares e Práticas

| Pilar | Práticas |
|-------|---------|
| **Governance** | Políticas, treinamento/educação, métricas |
| **Design** | Threat modeling, requisitos de segurança, arquitetura segura |
| **Implementation** | Build seguro, deploy seguro, gestão de bugs/SLA |
| **Verification** | Revisão de arquitetura, teste de requisitos, pen testing/SAST/DAST |
| **Operations** | Gestão de incidentes, isolamento de ambientes, controle operacional |

### Escala de Maturidade

```
0 — Nenhuma prática implementada
1 — Feito de forma ad-hoc para poucos sistemas
2 — Maioria dos sistemas cobertos com processo definido
3 — Todos os sistemas cobertos, processo otimizado e medido
```

### Como usar

- Formato de questionário/entrevista com o time
- Dependências entre níveis: threat modeling (Design L1) é pré-requisito para teste de requisitos (Verification L2)
- Adaptar ao contexto: nem toda organização precisa de L3 em tudo
- Output: roadmap de melhoria de segurança com priorização

---

## OWASP ASVS — Application Security Verification Standard

Padrão de requisitos de segurança verificáveis. Usos:

- Guia de desenvolvimento seguro
- Base para threat modeling
- Checklist de pen testing
- Critério de aceitação de software adquirido

### Níveis

| Nível | Descrição | Tipo de app | Método de teste |
|-------|-----------|-------------|-----------------|
| **L1** | Vulnerabilidades básicas (OWASP Top 10), dados não sensíveis | Low-risk | Black-box, ferramentas automáticas |
| **L2** | Maioria dos riscos, dados pessoais/financeiros | Padrão recomendado | Gray/white-box |
| **L3** | Proteção máxima, zero tolerance | Bancos, saúde, infra crítica | White-box completo + manual |

### 14 Domínios de Controle (v4.0.3)

```
V1  — Arquitetura, Design e Threat Modeling
V2  — Autenticação
V3  — Gerenciamento de Sessão
V4  — Controle de Acesso
V5  — Validação, Sanitização e Encoding
V6  — Criptografia Armazenada
V7  — Tratamento de Erros e Logging
V8  — Proteção de Dados
V9  — Comunicações
V10 — Código Malicioso
V11 — Lógica de Negócio
V12 — Arquivos e Recursos
V13 — API e Web Service
V14 — Configuração
```

### Validação

Obrigatoriamente combinar:
- **Automático**: SAST (Semgrep, Sonarqube), dependency scan, Nuclei
- **Manual**: code review (lógica de negócio, fluxos complexos), pen testing
- SAST não detecta: race conditions, lógica de negócio, controle de acesso insuficiente
- Manual não escala: findings repetitivos, checagem de configuração → automatizar

---

## Módulos Relacionados

O SSDLC fornece o framework organizacional que os demais módulos de AppSec preenchem com técnica. O módulo `02_threat_modeling.md` implementa o pilar SAMM.Design na prática — threat modeling é a atividade central da fase de Design do SSDLC e corresponde ao domínio V1 do ASVS. O módulo `04_security_code_review.md` cobre o pilar SAMM.Verification: code review manual e SAST são as técnicas de verificação que o ASVS orienta, e o ASVS serve diretamente como guia de o que revisar. Para as ferramentas de análise estática em contexto de whitebox, `../12_whitebox_pentesting/01_whitebox_intro.md` detalha o uso prático de Semgrep e JD-GUI. As referências normativas são OWASP SAMM (https://owaspsamm.org) e OWASP ASVS (https://owasp.org/www-project-application-security-verification-standard/).
