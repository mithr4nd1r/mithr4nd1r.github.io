---
layout: page
title: Cheatsheets
description: "Cheatsheets — comandos rápidos por categoria para uso em engagements."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · CHEAT</div>
  <h1 class="section-title">Red Team <em>Cheatsheets</em></h1>
  <p class="section-lede">Referências rápidas para uso em engagements: Cobalt Strike, Kerberos, credenciais, ferramentas e pivoting.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="12">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'cheatsheets' %}{% for p in group.pages %}
    <a href="{{ '/cheatsheets/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
