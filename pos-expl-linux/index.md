---
layout: page
title: Pós-Exploração Linux
description: "Pós-exploração Linux — enumeração, escalada, credenciais, kiosk breakouts."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · PÓS·LIN</div>
  <h1 class="section-title">Pós-Exploração <em>Linux</em></h1>
  <p class="section-lede">Pós-exploração em Linux: enumeração completa, escalada de privilégio, credenciais e kiosk breakouts.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="07">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'pos-expl-linux' %}{% for p in group.pages %}
    <a href="{{ '/pos-expl-linux/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
