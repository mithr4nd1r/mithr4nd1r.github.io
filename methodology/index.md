---
layout: page
title: Methodology
description: "Red team methodology — AD attacks, Kerberos abuse, lateral movement."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · METHODOLOGY</div>
  <h1 class="section-title">Red Team <em>Methodology</em></h1>
  <p class="section-lede">Active Directory enumeration, Kerberos abuse, lateral movement, and full-scope red team TTPs.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="01">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'methodology' %}{% for p in group.pages %}
    <a href="{{ '/methodology/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
