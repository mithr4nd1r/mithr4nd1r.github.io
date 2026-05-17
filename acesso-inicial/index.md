---
layout: page
title: Acesso Inicial
description: "Acesso inicial — phishing, exploits públicos, web attacks e vectores de entrada."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · ACESSO INICIAL</div>
  <h1 class="section-title">Acesso <em>Inicial</em></h1>
  <p class="section-lede">Vectores de acesso inicial: phishing, macros, password spraying, reconhecimento e exploração de perímetro.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="03">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'acesso-inicial' %}{% for p in group.pages %}
    <a href="{{ '/acesso-inicial/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
