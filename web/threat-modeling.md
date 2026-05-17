---
title: "Threat Modeling"
---

# Threat Modeling — Modelagem de Ameaças

> Processo sistemático de identificar e priorizar ameaças antes que virem vulnerabilidades reais.

---

## Por Que Fazer

Organizações que aplicam threat modeling reduzem drasticamente o custo de remediação: uma vulnerabilidade corrigida na fase de design custa aproximadamente 1× em esforço, enquanto a mesma vulnerabilidade corrigida em produção custa ~100×. O lugar correto do threat modeling no SSDLC é a **fase de Design**, após a definição da arquitetura e antes do início da implementação.

---

## As 4 Perguntas (Threat Model Manifest)

```
1. O que estamos construindo?    → Delimitar ativos e fluxo de dados
2. O que pode dar errado?        → Mapear ameaças por ativo
3. O que faremos a respeito?     → Definir controles de mitigação
4. Fizemos um bom trabalho?      → Validar via testes de requisitos
```

---

## STRIDE — Classificação de Ameaças (Microsoft)

| Categoria | O que é | Exemplo |
|-----------|---------|---------|
| **S**poofing | Falsificação de identidade | Usar credenciais de outro usuário |
| **T**ampering | Modificação não autorizada de dados | Alterar valor de campo sensível |
| **R**epudiation | Impossibilidade de rastrear ação | Ausência de logging de operação crítica |
| **I**nformation Disclosure | Acesso a dados confidenciais | BOLA, path traversal, verbose errors |
| **D**enial of Service | Impedir usuários legítimos | Rate limit ausente, amplificação de requisição |
| **E**levation of Privilege | Ganhar nível de acesso maior | Broken Function Level Authorization |

---

## Processo Prático — Passo a Passo

### Passo 1 — Delimitar Ativos

Mapear os componentes que precisam de proteção. Nomenclatura sistemática (A01, A02...):

```
A01 — Credenciais de autenticação (email + senha)
A02 — Dados de cadastro do usuário (nome, CPF, endereço)
A03 — Banco de dados (credenciais + transações)
A04 — Microserviço de dados financeiros/investimentos
A05 — Backend de registro de transações
```

Perguntas para identificar ativos:
- O que o sistema armazena que teria valor para um atacante?
- Quais componentes, se comprometidos, impactam outros?
- O que tem dados regulados (LGPD, PCI-DSS, HIPAA)?

### Passo 2 — Mapear Ameaças

Para cada ativo, listar ameaças. Nomenclatura sistemática (T01, T02...):

```
T01 — SQL Injection (via form de login, cadastro)           → A01, A03
T02 — Brute Force (endpoints de login/cadastro)             → A01
T03 — Bypass de autenticação (manipulação de sessão)        → A01
T04 — BOLA / IDOR (enumeração de ID de usuário)             → A02, A04
T05 — Enumeração de usuário (mensagem de erro diferencial)  → A01
T06 — XSS (campos de input)                                 → A02
T07 — SSRF (campos que recebem URL)                         → A03, A04, A05
```

### Passo 3 — Classificar e Priorizar

Aplicar STRIDE + CVSS por ameaça:

```
T01 SQLi         → Information Disclosure + Tampering    → CVSS: 9.1 (Crítico)
T02 Brute Force  → Spoofing                              → CVSS: 7.5 (Alto)
T03 Auth Bypass  → Elevation of Privilege                → CVSS: 9.8 (Crítico)
T04 BOLA         → Information Disclosure                → CVSS: 6.5 (Médio)
T05 User Enum    → Information Disclosure                → CVSS: 5.3 (Médio)
T06 XSS          → Information Disclosure + Tampering    → CVSS: 6.1 (Médio)
```

Priorizar: Crítico → Alto → Médio → Baixo. Dentro do mesmo nível: impacto no negócio.

### Passo 4 — Definir Controles

Para cada ameaça, um ou mais controles (C01, C02...):

```
C01 — Validação e sanitização de input       → mitiga: T01, T06
C02 — Rate limiting                          → mitiga: T02, T07 (parcial)
C03 — Controle de acesso robusto (AuthN)     → mitiga: T03
C04 — Autorização a nível de objeto          → mitiga: T04
C05 — Mensagens de erro genéricas            → mitiga: T05
C06 — Whitelist de URLs permitidas           → mitiga: T07
```

**Princípio**: um controle pode mitigar múltiplas ameaças; defesa em profundidade = múltiplos controles por ameaça.

### Passo 5 — Validar (Testes de Requisitos)

Criar checklist derivado dos controles:

```
[ ] C01: Input com ' " ; <script> retorna erro 400 sem refletir no response?
[ ] C02: 10+ requests consecutivos para /login em <1s são bloqueados?
[ ] C03: Token expirado retorna 401 em todos os endpoints protegidos?
[ ] C04: Usuário A consegue acessar recurso do usuário B trocando ID? (deve retornar 403)
[ ] C05: Mensagem de erro para email inválido == mensagem para senha incorreta?
[ ] C06: URL externa em campo mechanic_api retorna erro de validação?
```

---

## Template de Threat Model

```markdown
## [Nome do Sistema]
**Data**: YYYY-MM-DD  
**Revisão**: vX

### Ativos
| ID | Ativo | Dados | Criticidade |
|----|-------|-------|-------------|
| A01 | ... | ... | Alta/Média/Baixa |

### Ameaças
| ID | Ameaça | Ativos | STRIDE | CVSS |
|----|--------|--------|--------|------|
| T01 | ... | A01, A02 | InfoDisc | 7.5 |

### Controles
| ID | Controle | Mitiga | Status |
|----|---------|--------|--------|
| C01 | ... | T01, T02 | Implementado/Pendente |

### Testes de Requisitos
- [ ] ...
```

---

## Ferramentas

| Ferramenta | Uso |
|-----------|-----|
| OWASP Threat Dragon | Diagramas + threat model em JSON |
| Microsoft Threat Modeling Tool | Gera ameaças STRIDE automático via DFD |
| Threagile | Threat modeling as code (YAML) |
| CVSS Calculator (NVD) | Calcular score de cada ameaça |

---

## Módulos Relacionados

Threat modeling é a atividade de design que alimenta todos os outros módulos de AppSec. O módulo `01_ssdlc_e_frameworks.md` fornece o contexto organizacional: SAMM.Design é o pilar que formaliza threat modeling como prática, e o domínio V1 do ASVS (Arquitetura, Design e Threat Modeling) define os controles que o processo deve validar. O módulo `05_visibility_e_monitoramento.md` fecha o ciclo: os indicadores de cobertura de ameaças e os testes de requisitos derivados do threat model são o que o monitoramento de maturidade AppSec mede ao longo do tempo. As referências externas são o OWASP Threat Modeling Cheat Sheet e o Threat Model Manifest (https://www.threatmodelingmanifesto.org).
