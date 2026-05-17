---
layout: page
title: Active Directory
description: "Active Directory — Kerberos, ADCS, BloodHound, DACL, RBCD, Azure AD."
---

<div class="section-hero">
  <div class="section-kicker">SIG/MTND · AD</div>
  <h1 class="section-title">Active <em>Directory</em></h1>
  <p class="section-lede">Active Directory e Azure AD: Kerberos, ADCS, BloodHound, DACL, delegação, forest trusts e Azure red team.</p>
</div>

<div class="section-group">
  <div class="section-group-label" data-num="09">index</div>
  <div class="entry-list">
    {% for group in site.data.cyber %}{% if group.section == 'active-directory' %}{% for p in group.pages %}
    <a href="{{ '/active-directory/' | append: p.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
      <span>{{ p.title }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}{% endif %}{% endfor %}
  </div>
</div>
