---
title: "Phishing Operations — Intro"
---

# 01. Introdução e Fundamentos de Phishing

## 31% dos Acessos Iniciais: O Vetor Que Não Para de Crescer

Phishing é o vetor de acesso inicial mais dominante em engagements ofensivos. Em 2023, ~31% dos vetores de acesso inicial foram via phishing. Mesmo com treinamento de conscientização, operações sofisticadas conseguem enganar usuários bem treinados — especialmente quando exploram redirecionamentos abertos em domínios confiáveis.

---

## Pré-Requisitos do Curso

O curso assume conhecimento de HTML, CSS, JavaScript, PHP e linha de comando Linux, além de experiência com configuração de servidores. Módulos específicos podem exigir outras linguagens.

Níveis de dificuldade:
- **Verde** — Módulo iniciante: conceitos fundamentais e técnicas introdutórias.
- **Laranja** — Módulo intermediário: técnicas mais complexas com melhores resultados práticos.
- **Vermelho** — Módulo avançado: requer base teórica sólida.

---

## Por Que Phishing Funciona

Funcionários de empresas interagem constantemente com fornecedores, organizações e indivíduos externos. Durante dias de trabalho intensos, segurança não é a prioridade principal. Mesmo com treinamento eficaz, sofisticação de campanha pode contornar até usuários alertas.

**Exemplo prático**: treinamento ensina funcionários a hoverar links antes de clicar. Atacante explora um *open redirect* no domínio legítimo da empresa — o link parece seguro mas redireciona para site malicioso. Funcionário seguiu o protocolo e ainda assim foi enganado.

Outro fator: segurança é frequentemente percebida como obstáculo à produtividade. Quando gestão não prioriza cibersegurança, essa percepção se dissemina.

---

## Detecção de Phishing — Panorama Geral

Na última década, scanning da internet intensificou-se significativamente. Sites de phishing são detectados por:
- **Scanners de internet** — varrem proativamente o espaço IPv4.
- **Scanners de email** — analisam links em emails antes da entrega.
- **Navegadores** — Google Safe Browsing, SmartScreen.
- **Provedores de segurança** — integram CT logs, análise de reputação e AI.

Esses mecanismos forçam atacantes a reiniciar campanhas e reinvestir em infraestrutura.

---

## Componentes Básicos de Uma Campanha de Phishing

### 1. Infraestrutura

Ambiente de servidor que hospeda os arquivos de phishing, código backend e recursos necessários. Opções:
- **Cloud hosting** (AWS, Azure, DigitalOcean, Vultr) — escalável, pay-as-you-go.
- **Shared hosting** — mais barato, limitado.
- **Serverless** (Cloudflare Workers, AWS Lambda) — domínio e SSL gerenciados pelo provedor.
- **Bulletproof hosting** — ignora reclamações de abuse, mas IP de baixa reputação.

### 2. Nome de Domínio

URL que o usuário verá no navegador. Deve criar sensação de legitimidade. Considerações:
- Evitar palavras-chave óbvias como "microsoft", "password", "login" no domínio — detectáveis por DNS Hunting.
- **Supplier impersonation**: usar nome de fornecedor da empresa-alvo (defesas menos robustas contra impersonação de terceiros).
- **Typosquatting**: `gogle.com` em vez de `google.com` — muitas soluções detectam automaticamente.
- **TLD confusion**: registrar o mesmo domínio com TLD diferente (`.com` → `.co`).
- **Subdomínios**: registrar domínio neutro e usar subdomínio com keyword da empresa (`docusign.healthyfoods.com`).

### 3. Certificado TLS/SSL

Obrigatório em campanhas modernas — sem HTTPS, browsers exibem aviso de segurança. Opções:
- **Let's Encrypt** — gratuito, muito utilizado por atacantes → maior scrutínio por soluções de segurança.
- **Comodo/Sectigo** — pago, aparência mais legítima.
- **Wildcard** (`*.domain.com`) — recomendado para não expor subdomínios via CT logs.

### 4. Arquivos de Phishing

Frontend (HTML/CSS/JS) + backend (PHP/Python). Opções:
- **Templates públicos do GitHub** — altamente assinados, não recomendados sem modificação.
- **Clone de site legítimo** — rápido, mas clones de marcas populares (Microsoft, Google, Facebook) são facilmente detectados por análise visual.
- **Página customizada** — melhor OPSEC, aparência diferente mas que induz credenciais.

### 5. Payload

Para campanhas de entrega de payload (em vez de credential harvesting), o payload precisa ser preparado antecipadamente.

### 6. Segurança do Servidor

Mecanismos para proteger o servidor de scanners e analistas:
- Firewall e WAF.
- Anti-bot (CAPTCHA).
- Bloqueio por país, ASN, IP.
- Configuração segura (sem directory listing).
- Redirectors.

---

## Análise Estratégica de Requisitos

### Localização Geográfica da Infraestrutura

Escolher data center no mesmo país/região da organização-alvo. Evitar países com alta reputação de abuso (Rússia, China para alvos americanos).

### ASN (Autonomous System Number)

ASN é identificador único de cada rede na internet. Soluções de segurança bloqueiam ASNs inteiros associados a atividade maliciosa (ex: `AS40401 = backblaze.com`). Verificar ASN do IP antes de usar.

### Infraestrutura Confiável

Serviços SaaS oferecem subdomínios em seus domínios confiáveis:
- Azure App Service: `*.azurewebsites.net`
- Cloudflare Workers: `*.workers.dev`
- GitHub Pages: `*.github.io`

Lista completa: [LOTS Project](https://lots-project.com).

### Infraestrutura Comprometida

Usar XSS ou RCE em infraestrutura legítima de terceiro. **Requer autorização explícita** — uso não autorizado é ilegal.

### Verificação de Reputação do IP

Sempre verificar reputação do IP antes de usar:
- [AbuseIPDB](https://www.abuseipdb.com/)
- [VirusTotal](https://virustotal.com)
- [Whatismyipaddress Blacklist Check](https://whatismyipaddress.com/blacklist-check)

### SSL Certificate

Certificados gratuitos (Let's Encrypt) são mais escrutinados. A Elastic tem regra de detecção específica para conexões com provedores de SSL gratuito. Certificado pago melhora aparência de legitimidade.

### Templates

Templates públicos do GitHub são altamente assinados. Construir do zero é preferível. Mesmo clones customizados de sites populares são detectados por análise visual. Recomendação: página visual diferente mas que induz ação de login com credenciais Microsoft/Google.

---

## Métodos de Detecção de Phishing

### 1. Detecção por Assinatura (Signature Detection)

Bancos de dados de assinaturas conhecidas. Se encontradas no site → imediatamente flagged.

O que pode ser assinado:
- **Conteúdo do site** — HTML, CSS, JavaScript.
- **Título do site** — tags `<title>`.
- **Favicon** — hash do ícone na aba do navegador.
- **URLs e paths** — keywords no URL (ex: busca por "microsoftonline").
- **Meta tags e headers**.
- **Informação do certificado SSL**.
- **Imagens e gráficos** — imagem de background do Microsoft login.
- **Fingerprints** — hash do body HTML, hash do favicon, hash dos HTTP headers.

**Visual Signature**: processamento de imagem para gerar fingerprint visual. Se site visual parece com Microsoft 365 mas URL não é `login.microsoftonline.com` → phishing.

**URL Signature**: Google Safe Browsing e outros analisam URLs contra database de keywords.
```
# Detectável
https://microsoftonline.phishing.com/common/oauth2/v2.0/index.php
https://phishing.com/microsoftonline/common/oauth/v2.0/login.php
```

### 2. DNS Hunting

Defensores buscam proativamente domínios com keywords específicas. Ferramentas como [Phishing Catcher](https://github.com/x0rz/phishing_catcher) atribuem "suspicious score" baseado em keywords.

Domínios são detectados **apenas pelo nome** antes de qualquer acesso ao conteúdo.

### 3. URL Filtering

Análise de cada aspecto do URL:
- **Typosquatting detection** — `copany.com` vs `company.com`.
- **TLD analysis** — TLDs maliciosos comuns (`.xyz`, `.top`, `.tk`) pontuam mais baixo.
- **Misspellings** — organizações legítimas não usam domínios com erros de digitação.
- **Características anormais** — subdomínios excessivos, muitos dígitos, portas não-padrão, IPs diretos.
- **Comprimento do URL** — URLs >54 caracteres = indicador de phishing (Mohammad et al. 2012).

### 4. TLS/SSL Fingerprinting (JA3/JA4/JARM)

Análise de atributos do handshake TLS/SSL:
- Ordem dos cipher suites.
- Extensões suportadas.
- Detalhes do protocolo.

Gera fingerprint único. Útil para detectar Evilginx2 e outros frameworks de phishing.

### 5. Reputação e Categorização de Domínio

Métricas avaliadas:
- Global pagerank, country pagerank.
- Estimativa de visitas diárias/semanais.
- Average pageviews por visita, duração média.
- Distribuição de tráfego por país.
- Número de referências de redes sociais.
- **Idade do domínio** — domínios recém-registrados recebem maior scrutínio.

### 6. Características do Servidor

- **Reputação do IP** — histórico de uso malicioso.
- **Localização do servidor** — países conhecidos por alto abuso.
- **Provider do servidor** — provedores que permitem uso malicioso ou bulletproof hosting.
- **Passive DNS history** — IPs historicamente associados a domínios maliciosos.

### 7. OCR Detection

Ferramentas avançadas usam OCR para analisar imagens e extrair texto. Links e texto em imagens são verificados contra databases de URLs maliciosas e keywords de phishing.

### 8. Sandbox Detection

Análise comportamental em ambiente virtualizado que imita browser e OS reais. O sandbox:
- Registra redirecionamentos, scripts executados, downloads.
- Identifica tentativas de coletar credenciais.
- Analisa comportamento, não apenas assinaturas.

Soluções: [Joe Sandbox](https://www.joesandbox.com/), VirusTotal.

### 9. Machine Learning / AI Detection

Análise de múltiplos aspectos:
- Similaridade visual com sites legítimos.
- Análise de conteúdo.
- Análise de URL.
- Campos de input.

Score de risco calculado por AI.

### 10. Técnicas Diversas

- Ausência de meta tags (`<meta name="robots">`, `<meta description>`) — indica descuido com SEO → suspeito.
- Site com apenas imagens (sem texto) → evasão de scanner → categorizado como malicioso.
- Poucos links confiáveis no HTML body.
- Baixo número de links externos para sites reconhecidos.

---

## Exemplos Práticos de Detecção

### Exemplo 1: Cenário Genérico (Alta Detecção)

Setup típico facilmente detectável:
1. Server cloud (AWS/DigitalOcean/Vultr).
2. Domínio: `microsoftforgotpassword.xyz`.
3. SSL gratuito: Let's Encrypt.
4. Template GitHub não modificado.

**Análise de detecção**:
- **Cloud provider** — abusado frequentemente, IP pode ter histórico de abuse.
- **Domínio** — keywords "microsoft" e "password" + TLD `.xyz` → flagged imediatamente.
- **SSL Let's Encrypt** — aparece em CT logs → scanners começam em minutos.
- **Template público** — assinado por scanners anti-phishing.

Todos os riscos existem **antes** da tentativa de entrega do link.

### Exemplo 2: Outlook Phishing (Score 92/100 - Joe Sandbox)

Regras acionadas:

**Alta severidade**:
- AI detectou phishing — URL usa IP em vez de domínio + visual = clone do Outlook.
- Antivirus/Scanner detection — content signature match.
- Favicon image match — "Outlook matched with high similarity".
- YARA Detected HtmlPhish10.

**Média severidade**:
- AI detectou JavaScript suspeito — objetos ActiveX criados.
- Phishing site (logo match) — visual signature do logo Outlook.
- YARA Detected Outlook Phishing page.

**Baixa severidade**:
- HTML body com poucos links de qualidade.
- HTML body com muitas imagens embedded.
- HTML title não bate com URL.
- Página não-HTTPS coletando dados sensíveis.

**Lições**: remover logos originais, evitar IP como host, sempre usar HTTPS com redirecionamento, adicionar links para sites legítimos no HTML.

### Exemplo 3: Facebook Phishing (Score 72/100 - Joe Sandbox)

Regras acionadas:
- Antivirus/Scanner detection.
- Antivirus detection for URL/domain.
- Multi AV Scanner detection.
- Phishing site detected (favicon match) — "Facebook matched with high similarity".

**Lição**: substituir o favicon sempre que clonar sites de marcas populares.

---

## Leitura Complementar

- [kwm.me - Top Initial Access Vectors 2023](https://kwm.me/posts/top-initial-access-vectors-2023/)
- [Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [LOTS Project](https://lots-project.com)
- [Joe Sandbox](https://www.joesandbox.com/)
- [Typosquatting Finder](https://typosquatting-finder.circl.lu/)
- ATT&CK T1566 — Phishing
- ATT&CK T1566.001 — Spearphishing Attachment
- ATT&CK T1566.002 — Spearphishing Link
