---
layout: page
title: C2 & Infraestrutura
description: "Command & Control — infraestrutura, frameworks (Cobalt Strike, Sliver, Havoc), staging e OPSEC."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · C2</div>
  <h1 class="section-title">Command <em>&amp; Control</em></h1>
  <p class="section-lede">Infraestrutura C2: frameworks, staging, redirectors, Malleable profiles e OPSEC operacional.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="02">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'c2' %}{% for p in group.pages %}
    <a href="{{ '/c2/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
