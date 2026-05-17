---
layout: page
title: Evasão
description: "AV/EDR evasion — AMSI bypass, AppLocker, payload obfuscation, sleep masking."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · EVASÃO</div>
  <h1 class="section-title">Evasão <em>AV/EDR</em></h1>
  <p class="section-lede">Evasão de antivírus e EDR: AMSI bypass, AppLocker, WDAC, obfuscação de payload e sleep masking.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="04">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'evasao' %}{% for p in group.pages %}
    <a href="{{ '/evasao/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
