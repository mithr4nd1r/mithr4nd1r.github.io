---
layout: page
title: Writeups
description: "HTB, TryHackMe, and ProvingGrounds machine walkthroughs."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · WRITEUPS</div>
  <h1 class="section-title">Writeups <em>&amp; Walkthroughs</em></h1>
  <p class="section-lede">Machine walkthroughs from HackTheBox, TryHackMe, and ProvingGrounds. Focus on methodology over tool output.</p>
</div>

{% for group in site.data.writeups %}
<div class="section-group diff-section {{ group.difficulty }}">
  <div class="section-group-label" data-num="{{ group.difficulty }}">{{ group.difficulty }}</div>
  <div class="entry-list">
    {% for m in group.machines %}
    {% assign url = '/writeups/' | append: m.slug | append: '/' %}
    <a href="{{ url | relative_url }}">
      <span class="idx">{{ m.platform }}</span>
      <span>
        <img src="{{ '/assets/icons/' | append: m.os | append: '.svg' | relative_url }}" class="os-icon-sm" alt="{{ m.os }}">
        {{ m.name }}
      </span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}
  </div>
</div>
{% endfor %}
