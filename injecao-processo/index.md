---
layout: page
title: Injeção de Processo
description: "Process injection — DLL injection, shellcode injection, hollowing, BOFs."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · INJ.PROC</div>
  <h1 class="section-title">Injeção de <em>Processo</em></h1>
  <p class="section-lede">Técnicas de injeção de processo: DLL injection, shellcode injection, process hollowing, BOFs e evasão pós-exploração.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="05">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'injecao-processo' %}{% for p in group.pages %}
    <a href="{{ '/injecao-processo/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
