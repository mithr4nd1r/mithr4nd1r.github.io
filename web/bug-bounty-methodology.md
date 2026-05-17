---
title: "Bug Bounty Methodology"
---

# Metodologia e Mindset em Bug Bounty

## Contexto: Bug Bounty como Pratica Estruturada de Pesquisa de Vulnerabilidades

Bug Bounty nao e "testar tudo e esperar o melhor". E pesquisa estruturada com ROI de tempo — escolher onde investir esforco baseado na probabilidade de encontrar algo valido e no impacto que isso teria.

**O que diferencia hunters que ganham de hunters que nao ganham:**

A diferenca raramente e conhecimento tecnico bruto. E metodologia. Hunters que ganham consistentemente fazem tres coisas que outros nao fazem:

1. **Priorizam superficie, nao escopo total**: Nao tentam "testar tudo". Identificam onde a probabilidade de bug e maior — funcionalidades novas (menos testadas), integrações com terceiros (contexto diferente dos desenvolvedores originais), fluxos de negocio criticos (onde erros custam dinheiro diretamente).

2. **Entendem impacto de negocio, nao so severidade tecnica**: Uma SQLi em tabela sem dados sensiveis vale menos do que um IDOR em endpoint de pagamento. Severidade tecnica (CVSS) e o ponto de partida; impacto ao negocio e o que determina a recompensa real.

3. **Comunicam vulnerabilidades, nao so exploits**: Um report bem estruturado com impacto claro pode transformar uma recompensa de $200 em $1000. O triager precisa entender por que aquilo importa sem ter que adivinhar.

**Surface prioritization — onde buscar antes:**

| Tipo de Asset | Por que priorizar | Vulnerabilidades tipicas |
|---|---|---|
| Funcionalidades recentes | Menos testadas, mais propensas a erros | Logic bugs, validation gaps |
| APIs nao documentadas | Descobertas via JS analysis, menos hardened | IDOR, mass assignment, auth gaps |
| Integracoes OAuth/pagamentos | Contexto diferente, bugs de estado e callback | Auth bypass, CSRF em fluxos criticos |
| Subdomínios antigos/legados | Esquecidos, software desatualizado | Exposicao de admin, versoes vulneraveis |
| Fluxos de devolucao/cancelamento | Business logic frequentemente mal testada | Race condition, manipulacao de status |

**OWASP SAMM como framework de expectativas:**

O OWASP SAMM (Software Assurance Maturity Model) descreve o que organizacoes maduras em seguranca implementam nos pilares de governanca, design, implementacao, verificacao e operacoes. Para o hunter, SAMM funciona inversamente: quanto menos madura e a organizacao em cada pilar, mais superficie vulneravel existe.

Organizacao sem modelagem de ameacas (pilar Design) = fluxos de negocio criticos sem controles. Organizacao sem scans no pipeline (pilar Implementacao) = CVEs conhecidos em dependencias. Organizacao sem avaliacao recorrente de arquitetura (pilar Verificacao) = bugs novos chegam a producao sem revisao.

**OWASP ASVS como guia de onde checar:**

O ASVS (Application Security Verification Standard) e um checklist estruturado por categoria (autenticacao, controle de acesso, validacao de input, criptografia). Para bug bounty blackbox, o ASVS guia quais controles verificar em cada categoria sem acesso ao codigo. Se a categoria V2 (autenticacao) lista "tokens devem ter expiracao" — isso e um item a verificar. Se a categoria V4 (controle de acesso) lista "verificacao no backend, nao so na UI" — isso guia onde testar.

---

## Plataformas e Tipos de Programas Bug Bounty

### O Ecossistema Bug Bounty

| Plataforma | Caracteristicas | URL |
|------------|----------------|-----|
| **HackerOne** | Maior plataforma, muitas Fortune 500 | hackerone.com |
| **Bugcrowd** | Foco enterprise, good VDP programs | bugcrowd.com |
| **Intigriti** | Forte na Europa, escopo geralmente melhor | intigriti.com |
| **YesWeHack** | Europeia, crescendo rapido | yeswehack.com |
| **Synack** | Privado, triagem rigorosa, paga bem | synack.com |
| **Immunefi** | Web3/blockchain, recompensas massivas | immunefi.com |
| **Proprio (private)** | Via disclosure direto | - |

### Tipos de Programas

| Tipo | Descricao | Vantagem |
|------|-----------|----------|
| **Bug Bounty** | Paga por vulnerabilidade encontrada | Sem limite de ganho |
| **VDP** (Vulnerability Disclosure) | Sem pagamento, so reconhecimento | Sem pressao, bom para treinar |
| **Private** | Convite apenas | Menos competicao |
| **Public** | Aberto a todos | Mais facil entrar |
| **CTF-style** | Desafios com flags | Treino estruturado |

---

## Na Pratica

### 1. Escolha do Alvo (Target Selection)

```
CRITERIOS PARA ESCOLHA:
+-------------------------------------------------------------+
| Pontuacao (maior = melhor alvo)                             |
|                                                             |
| Escopo amplo          +3 pontos                             |
| Recompensas altas     +3 pontos                             |
| Programa maduro       +2 pontos (muitos reports = aprendizado) |
| VRT claro             +2 pontos (sabe o que conta)          |
| Resposta rapida       +2 pontos                             |
| Assets menos testados +3 pontos                             |
|                                                             |
| Escopo muito restrito -3 pontos                             |
| "Informational only"  -5 pontos                             |
| Programa pausado      -5 pontos                             |
+-------------------------------------------------------------+

TIPOS DE ESCOPO:
- *.target.com           -> Todos subdominios (otimo)
- app.target.com         -> So um subdominio (limitado)
- Android/iOS app        -> App movel + APIs
- Source code review     -> Whitebox (alto valor)
```

### 2. Leitura do Programa (Fase Critica)

```
ANTES DE QUALQUER TESTE, LER:
[ ] Scope - o que esta dentro/fora do escopo
[ ] Out of scope - o que explicitamente NAO testar
[ ] Rules of engagement - como testar
[ ] VRT (Vulnerability Rating Taxonomy) - o que eles consideram valido
[ ] Resolved/Informational - ver reports antigos de outros hunters
[ ] Recompensas por severidade - saber o que priorizar

ERROS COMUNS DE INICIANTE:
X Testar fora do escopo
X Fazer scan agressivo sem verificar politicas
X Testar em producao sem cuidado
X Nao verificar duplicatas antes de reportar
X Submeter sem PoC completo
X Exagerar severidade para aumentar recompensa
```

### 3. Mindset de Hunter Eficiente

```
PRINCIPIO 1: Procurar onde outros nao procuram
- Funcionalidades antigas/legadas (xmlrpc.php, swagger, etc.)
- Fluxos menos usados (recuperar conta, mudar email, etc.)
- Integracoes de terceiros (OAuth, payments, webhooks)
- APIs nao documentadas descobertas via JS analysis

PRINCIPIO 2: Seguir o dinheiro / seguir os dados
- Onde dados sensiveis entram?
- Onde dados financeiros sao processados?
- Onde autenticacao/autorizacao e verificada?
- Vulnerabilidades perto de dados criticos = maior recompensa

PRINCIPIO 3: "Business Logic" paga mais
- Bugs de logica de negocio sao hard to patch + hard to automate detect
- Bypasses de limites (comprar mais do que disponivel, pontos negativos)
- Race conditions em transacoes
- Privilege escalation por manipulacao de fluxo

PRINCIPIO 4: Profundidade > Largura
- Entender bem UM sistema e mais valioso que conhecer N superficialmente
- Mesmo sistema por semanas = encontra bugs que scanner nunca acharia

PRINCIPIO 5: Persistencia diferenciada
- Primeiro bug em sistema novo leva semanas
- Segundo bug leva dias (voce conhece o sistema)
- Terceiro bug leva horas (voce entende a mentalidade do dev)
```

### 4. Priorizacao de Vulnerabilidades

```
SEVERIDADE VS DIFICULDADE:

Alta Recompensa + Baixa Dificuldade (PRIORIDADE):
- IDOR em dados financeiros/medicos
- Auth bypass simples
- SQL injection com SQLmap confirmado
- Stored XSS em painel admin

Alta Recompensa + Alta Dificuldade (SECUNDARIO):
- RCE via cadeia de vulnerabilidades
- Bypass de 2FA
- Business logic critica

Baixa Recompensa + Baixa Dificuldade (EVITAR):
- XSS em pagina de erro sem impact real
- Rate limiting em endpoints nao sensiveis
- CORS misconfiguration sem impacto real
- Missing security headers (geralmente informational)

NUNCA REPORTAR (perda de tempo):
- "Missing X-Frame-Options" sozinho
- "Missing Content-Security-Policy"
- Vulnerabilidades em software de terceiros fora do controle do alvo
- Self-XSS
- Bugs que requerem acesso fisico
- Bugs que requerem acesso admin para atacar admin
```

### 5. Fluxo de Trabalho Diario

```
SESSAO DE HUNTING (3-4 horas):

0:00-0:30  Escolha/revisao do alvo
           - Selecionar programa
           - Ler updates/changelog
           - Verificar se escopo mudou

0:30-1:30  Reconhecimento
           - Subdominios novos (subfinder, amass)
           - Novos endpoints (GAU, waybackurls)
           - Novos parametros (Param Miner passivo)
           - JS files novos (analise manual)

1:30-3:30  Testes direcionados
           - Uma funcionalidade especifica por sessao
           - Nao pular entre funcionalidades
           - Testar variacoes do mesmo bug

3:30-4:00  Documentacao
           - Anotar findings (mesmo informativos)
           - Preparar PoC se necessario
           - Proximos passos
```

### 6. Impacto - Como Pensar

```
CALCULADORA DE IMPACTO:

Confidencialidade:
- Dados de outros usuarios visiveis? -> Alto
- Apenas dados proprios? -> Baixo
- Dados de todos os usuarios? -> Critico

Integridade:
- Modificar dados de outros usuarios? -> Alto
- Modificar dados do sistema? -> Critico
- Apenas ler? -> Medio no maximo

Disponibilidade:
- Derrubar o servico inteiro? -> Alto
- Derrubar funcionalidade especifica? -> Medio
- Apenas minha conta? -> Baixo

AUTENTICACAO IMPORTA:
- Bug sem autenticacao > Bug com autenticacao
- Bug acessivel a qualquer usuario > Bug que requer role especifico
- Bug em producao > Bug em staging

CALCULO CVSS RAPIDO:
Critical: RCE, SQLi completo, bypass de auth em dados criticos
High: IDOR em dados financeiros, Auth bypass, Stored XSS em admin
Medium: IDOR em dados nao-sensiveis, Reflected XSS em usuario, CSRF
Low: Open redirect, missing headers, info disclosure menor
```

---

## Ferramentas

| Ferramenta | Uso | Link |
|------------|-----|------|
| **Burp Suite** | Core: proxy, scanner, intruder | portswigger.net |
| **ffuf** | Fuzzing de endpoints e parametros | github.com/ffuf/ffuf |
| **subfinder** | Descoberta de subdominios | github.com/projectdiscovery/subfinder |
| **httpx** | Verificacao de hosts em massa | github.com/projectdiscovery/httpx |
| **GAU** | URLs historicas (Wayback + outros) | github.com/lc/gau |
| **Nuclei** | Scanner de vulnerabilidades em massa | github.com/projectdiscovery/nuclei |
| **Amass** | OSINT e reconhecimento DNS | github.com/owasp-amass/amass |
| **hakrawler** | Crawl de JavaScript | github.com/hakluke/hakrawler |

---

## Deteccao

### Sinais de Bug Bounty vs Pentest

```
EM BUG BOUNTY:
- Voce nao sabe o codigo-fonte (blackbox geralmente)
- Sem prazo fixo - voce escolhe quando trabalhar
- Concorrencia com outros hunters
- Apenas pagamento se encontrar algo valido
- Responsabilidade de auto-gerenciar escopo

DIFERENCAS NA ABORDAGEM:
Bug Bounty:
+ Foco em impacto de negocio (paga mais)
+ Testes nao destrutivos sempre
+ Priorizar funcionalidades core (mais testadas = mais seguras? Nem sempre)
+ Funcionalidades novas = menos testadas = mais bugs

Pentest:
+ Escopo definido e limitado
+ Prazo fixo
+ Relatorio completo obrigatorio
+ Pode incluir social engineering e fisica
+ Metodologia mais sistematica
```

### Checklist de Submissao

```
ANTES DE SUBMETER:
[ ] Li as regras do programa completamente
[ ] O endpoint esta no escopo?
[ ] Ja existe report duplicado? (pesquisar via Hacktivity/historico)
[ ] O bug e real e reproduzivel?
[ ] Tenho PoC completo?
[ ] A severidade esta correta (nao exagerada)?
[ ] O impacto esta claramente descrito?
[ ] Os passos para reproduzir sao claros?
[ ] Tirei screenshots ou gravei video?
[ ] Ha informacao sensivel real no PoC? (usar dados de teste)

ESTRUTURA DO REPORT:
1. Titulo claro: [Vuln Type] - [Endpoint/Funcionalidade] - [Impacto]
2. Severidade sugerida + justificativa CVSS
3. Descricao em 2-3 paragrafos
4. Passos para reproduzir (numerados, detalhados)
5. Impacto (o que o atacante consegue fazer)
6. Request/Response de evidencia
7. Remediacao sugerida
```
