---
layout: page
title: Movimentação Lateral
description: "Movimentação lateral — pass-the-hash, pass-the-ticket, WMI, DCOM, SMB."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · LATERAL</div>
  <h1 class="section-title">Movimentação <em>Lateral</em></h1>
  <p class="section-lede">Movimentação lateral: pass-the-hash, pass-the-ticket, WMI, DCOM, SMB, pivoting e bypass de filtros de rede.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="08">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'lateral' %}{% for p in group.pages %}
    <a href="{{ '/lateral/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
