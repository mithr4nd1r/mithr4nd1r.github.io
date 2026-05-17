---
layout: page
title: Fundamentos
description: "Fundamentos de red team — Windows/Linux internals, rede, protocolos e ferramentas base."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · FUNDAMENTOS</div>
  <h1 class="section-title">Red Team <em>Fundamentos</em></h1>
  <p class="section-lede">Fundamentos técnicos de red team: rede, protocolos, Windows/Linux internals e ferramentas essenciais.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="01">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'fundamentos' %}{% for p in group.pages %}
    <a href="{{ '/fundamentos/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
