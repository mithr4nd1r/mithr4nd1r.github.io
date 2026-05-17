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

{% assign platforms = "htb,thm,pg,ctf" | split: "," %}
{% assign platform_labels = "HackTheBox,TryHackMe,ProvingGrounds,CTF Events" | split: "," %}

{% for platform in platforms %}
{% assign pidx = forloop.index0 %}
{% assign plabel = platform_labels[pidx] %}

{% assign platform_total = 0 %}
{% for group in site.data.writeups %}
  {% assign n = group.machines | where: "platform", platform | size %}
  {% assign platform_total = platform_total | plus: n %}
{% endfor %}
{% if platform_total == 0 %}{% continue %}{% endif %}

<div class="platform-section">
  <h2 class="platform-heading">{{ plabel }}</h2>

  {% for group in site.data.writeups %}
    {% assign machines = group.machines | where: "platform", platform %}
    {% if machines.size == 0 %}{% continue %}{% endif %}
    <div class="section-group diff-section {{ group.difficulty }}">
      <div class="section-group-label" data-num="{{ group.difficulty }}">{{ group.difficulty }}</div>
      <div class="entry-list">
        {% for m in machines %}
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

</div>
{% endfor %}
