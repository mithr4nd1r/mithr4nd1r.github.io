---
layout: page
title: SQL Server
description: "SQL Server — privilege escalation via SQL, linked servers, CLR assemblies."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · SQL</div>
  <h1 class="section-title">SQL <em>Server</em></h1>
  <p class="section-lede">Ataques a SQL Server: escalada de privilégio, linked servers, CLR assemblies, movimento lateral e Exchange/SCCM.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="10">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'sql-server' %}{% for p in group.pages %}
    <a href="{{ '/sql-server/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
