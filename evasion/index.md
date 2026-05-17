---
layout: page
title: Evasion
description: "EDR/AV evasion techniques — AMSI, ETW, syscalls, unhooking, and more."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · EVASION</div>
  <h1 class="section-title">Evasion <em>&amp; Bypass</em></h1>
  <p class="section-lede">Techniques for evading endpoint detection — from AMSI internals to full EDR bypass chains.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="01">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'evasion' %}{% for p in group.pages %}
    <a href="{{ '/evasion/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
