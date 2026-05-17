---
layout: page
title: Pós-Exploração Windows
description: "Pós-exploração Windows — privilégio, credenciais, persistence, living off the land."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · PÓS·WIN</div>
  <h1 class="section-title">Pós-Exploração <em>Windows</em></h1>
  <p class="section-lede">Pós-exploração em Windows: escalada de privilégio, credenciais, persistência, token impersonation e living off the land.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="06">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'pos-expl-windows' %}{% for p in group.pages %}
    <a href="{{ '/pos-expl-windows/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
