---
layout: page
title: Phishing Operations
description: "Phishing operations — templates, evasion, delivery, tracking."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · PHISHING</div>
  <h1 class="section-title">Phishing <em>Operations</em></h1>
  <p class="section-lede">Operações de phishing: infraestrutura, templates, anti-análise, reputação de domínio, bypass de MFA e técnicas avançadas.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="13">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'phishing' %}{% for p in group.pages %}
    <a href="{{ '/phishing/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
