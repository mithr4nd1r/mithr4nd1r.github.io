---
layout: page
title: Web Security
description: "Web application security — SQLi, XSS, SSRF, deserialization, APIs, bug bounty, and AppSec."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · WEB</div>
  <h1 class="section-title">Web <em>Security</em></h1>
  <p class="section-lede">Web application attacks, bug bounty methodology, and AppSec — from SQLi fundamentals to whitebox pentesting.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="01">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'web' %}{% for p in group.pages %}
    <a href="{{ '/web/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
