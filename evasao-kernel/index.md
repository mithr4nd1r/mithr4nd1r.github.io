---
layout: page
title: Evasão de Kernel
description: "Evasão de nível kernel — drivers, BYOVD, callback removal, ETW patching."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · KERNEL</div>
  <h1 class="section-title">Evasão de <em>Kernel</em></h1>
  <p class="section-lede">Evasão avançada em nível kernel: BYOVD, remoção de callbacks, ETW patching e bypass de Credential Guard.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="11">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'evasao-kernel' %}{% for p in group.pages %}
    <a href="{{ '/evasao-kernel/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
