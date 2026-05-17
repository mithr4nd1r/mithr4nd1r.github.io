---
layout: page
title: Toolkit
description: "Tools, scripts, and references for red team operations."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · TOOLKIT</div>
  <h1 class="section-title">Toolkit <em>&amp; References</em></h1>
  <p class="section-lede">Curated tools, custom scripts, and operational references for red team engagements.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="01">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'toolkit' %}{% for p in group.pages %}
    <a href="{{ '/toolkit/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
