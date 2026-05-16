# Terminal Hacker Redesign — Design Spec

**Date:** 2026-05-13
**Project:** mithr4nd1r.github.io
**Status:** Approved — pending implementation plan

---

## Goal

Transform mithr4nd1r.github.io from default Chirpy theme into a professional terminal-hacker themed personal blog/portfolio for an offensive security practitioner. Preserve Chirpy's blogging infrastructure while overriding visual identity, adding interactive terminal hero, and introducing new sections (Skills, Certifications, CTF Stats) — all as customizations on top of the unmodified Chirpy theme.

## Non-Goals

- Not forking Chirpy theme internals
- Not adding heavy JavaScript dependencies (typed.js, Three.js, AOS, etc.)
- Not migrating to another static site generator
- Not redesigning post content layout beyond minor card styling
- Not implementing comments, analytics, or backend features

## Decisions Captured

| Decision | Choice |
|----------|--------|
| Approach | Custom theme overrides on top of Chirpy (no fork) |
| Aesthetic | Terminal hacker — Matrix green-on-black, JetBrains Mono, CRT effects |
| Hero | Interactive typewriter terminal with ASCII banner |
| New sections | Skills, Certifications, CTF Stats, expanded About |
| Content | Placeholders (user fills later via markdown edits) |
| Implementation | SCSS override + vanilla JS (no external libs) |

## Architecture

Three layers of customization, kept isolated to survive future Chirpy upgrades:

1. **Theme variables layer** — `_sass/addon/_terminal-theme.scss` overrides Chirpy's CSS custom properties (colors, fonts). No structural changes to Chirpy partials.
2. **Visual effects layer** — `_sass/addon/_crt-effects.scss` adds scanlines, flicker, glow as additive layers via `::before` overlays and CSS animations. Respects `prefers-reduced-motion`.
3. **Component layer** — Selective overrides of specific Chirpy layouts/includes (`_layouts/home.html`, `_includes/sidebar.html`) and new components (`_javascript/modules/terminal-hero.js`).

All overrides are imported into `_sass/jekyll-theme-chirpy.scss` after Chirpy's own imports so cascade resolves correctly.

## Components

### 1. Theme Variables (`_sass/addon/_terminal-theme.scss`)

Override Chirpy dark-mode CSS custom properties:

```scss
:root,
html[data-mode='dark'] {
  --main-bg:              #0a0e0a;
  --mask-bg:              #050505;
  --text-color:           #B8C5B8;
  --text-muted-color:     #6a8a6a;
  --heading-color:        #00FF41;
  --link-color:           #00FF41;
  --link-underline-color: #00FF41;
  --link-hover-color:     #FFB000;
  --btn-border-color:     #00FF41;
  --card-bg:              #0f1410;
  --card-border-color:    #1a2a1a;
  --card-box-shadow:      0 0 12px rgba(0, 255, 65, 0.08);
  --code-color:           #00FF41;
  --code-bg:              #050505;
  --kbd-text-color:       #00FF41;
  --kbd-bg-color:         #050505;
  --kbd-wrap-color:       #00FF41;
  --prompt-info-color:    #00FF41;
  --prompt-warning-color: #FFB000;
  --prompt-danger-color:  #FF3333;
  --prompt-tip-color:     #00CFFF;
}

body, .post-content, .sidebar {
  font-family: 'JetBrains Mono', 'IBM Plex Mono', 'Cascadia Code', monospace;
}
```

Force dark mode default in `_config.yml` (`theme_mode: dark`) — light mode discarded to maintain aesthetic integrity.

### 2. CRT Effects (`_sass/addon/_crt-effects.scss`)

Three additive effects, each disable-able via `prefers-reduced-motion`:

- **Scanlines:** `body::before` fixed overlay with `repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.15) 3px)`, `pointer-events: none`, `z-index: 9998`.
- **Flicker:** Subtle `@keyframes` opacity animation on overlay (0.97 → 1.0 over 8s).
- **Text glow:** `h1, h2, h3, .post-title { text-shadow: 0 0 8px rgba(0, 255, 65, 0.4); }`. Reduced glow on body text (none) to preserve readability.

```scss
@media (prefers-reduced-motion: reduce) {
  body::before { animation: none; }
}
```

### 3. Terminal Hero (`_layouts/home.html` + `_javascript/modules/terminal-hero.js`)

Override Chirpy's `home.html` to insert a terminal hero block above the post list.

**HTML structure:**

```html
<div class="terminal-hero" aria-label="Terminal hero">
  <pre class="ascii-banner">
   ███╗   ███╗██╗████████╗██╗  ██╗██████╗ 
   ████╗ ████║██║╚══██╔══╝██║  ██║██╔══██╗
   ██╔████╔██║██║   ██║   ███████║██████╔╝
   ...
  </pre>
  <div class="terminal-window">
    <div class="terminal-titlebar">
      <span class="dot red"></span>
      <span class="dot yellow"></span>
      <span class="dot green"></span>
      <span class="terminal-title">guest@mithr4nd1r.io:~</span>
    </div>
    <div class="terminal-body" id="terminal-output">
      <!-- populated by JS -->
    </div>
  </div>
</div>
```

**JS behavior (`terminal-hero.js`):**

Vanilla typewriter — no dependencies. Sequential commands:

1. `$ whoami` → "osvaldo \"mithr4nd1r\" tenorio — red team / offensive security"
2. `$ cat skills.txt` → bullet list (pentest, red team, AD attacks, web app, CTFs, malware dev)
3. `$ ls -la writeups/` → recent 4 posts injected from Jekyll data via `data-posts` JSON attribute
4. Final blinking `$ _` prompt

Speed: ~30ms/char with 600ms pause between commands. Skip animation when `prefers-reduced-motion: reduce` OR viewport < 768px — render final state immediately.

**Mobile fallback:** On viewport width < 768px, hide ASCII banner (only show terminal window) and skip typewriter animation (render static).

### 4. New Tabs (`_tabs/`)

Four new/expanded tab pages, all using Chirpy's `page` layout:

**`_tabs/about.md` (expanded):**

```markdown
---
title: Sobre
icon: fas fa-info-circle
order: 4
---

## $ whoami

Osvaldo Tenorio — also known as **mithr4nd1r**. Offensive security practitioner focused on red team operations, AD attacks, and CTF challenges.

## $ cat ~/.journey

[Placeholder narrative: como entrei na área, motivações, foco atual]

## $ cat ~/.contact

| Channel | Link |
|---------|------|
| Email | osvaldo.tenorio91@gmail.com |
| LinkedIn | [@osvaldo-tenorio](...) |
| GitHub | [@osvaldotenorio](...) |
| TryHackMe | [@mithr4nd1r](...) |
| HackTheBox | [TBD](...) |
```

**`_tabs/skills.md` (new, order: 5):**

```markdown
---
title: Skills
icon: fas fa-terminal
order: 5
---

## $ cat skills/offensive.txt

| Category | Skills |
|----------|--------|
| Offensive | Pentest, Red Team, Web App Pentest, AD Attacks, Network Pentest |
| Tools | Burp Suite, Metasploit, Cobalt Strike, BloodHound, Mimikatz, Impacket |
| Languages | Python, Bash, PowerShell, C/C++, JavaScript |
| Platforms | Linux, Windows, Active Directory, AWS, Azure |
| Specialties | Privilege Escalation, Lateral Movement, Evasion, OSINT |
```

**`_tabs/certifications.md` (new, order: 6):**

```markdown
---
title: Certificações
icon: fas fa-certificate
order: 6
---

## $ ls -la certifications/

### Conquistadas
- [TBD — placeholder]

### Em Progresso
- [TBD — placeholder, ex: OSCP, CRTO]

### Planejadas
- [TBD — placeholder, ex: OSEP, CRTL]
```

**`_tabs/ctf-stats.md` (new, order: 7):**

```markdown
---
title: CTF Stats
icon: fas fa-flag
order: 7
---

## $ curl https://tryhackme.com/api/u/mithr4nd1r

![TryHackMe](https://tryhackme-badges.s3.amazonaws.com/mithr4nd1r.png)

## $ curl https://app.hackthebox.com/profile/

[HTB profile badge — placeholder]

## $ cat ~/.ctf-stats

| Platform | Username | Rooms/Boxes | Rank |
|----------|----------|-------------|------|
| TryHackMe | mithr4nd1r | TBD | TBD |
| HackTheBox | TBD | TBD | TBD |
| Proving Grounds | TBD | TBD | TBD |
```

### 5. Sidebar Override (`_includes/sidebar.html`)

Copy Chirpy's `_includes/sidebar.html` and modify:

- Avatar: wrap in `<div class="avatar-glow">` for green border + glow effect (CSS).
- Site title: prefix with `~/` and apply terminal color.
- Tagline: prefix with `> ` and italic.
- Nav links: prefix each `<li>` with `<span class="nav-prompt">&gt;</span>` and apply hover underline effect.
- Social links: keep but recolor to match palette.

### 6. Post Cards (`_sass/addon/_terminal-cards.scss`)

Style `.card.post-preview` (used by Chirpy on home and tag pages) as terminal windows:

```scss
.card.post-preview {
  position: relative;
  background: var(--card-bg);
  border: 1px solid var(--card-border-color);
  padding-top: 32px;  // room for titlebar
  
  &::before {  // titlebar
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 24px;
    background: linear-gradient(to bottom, #1a1f1a, #0a0e0a);
    border-bottom: 1px solid var(--card-border-color);
  }
  
  &::after {  // 3 dots
    content: '';
    position: absolute;
    top: 8px; left: 12px;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #FF5F56;
    box-shadow: 16px 0 0 #FFBD2E, 32px 0 0 #27C93F;
  }
  
  &:hover {
    box-shadow: 0 0 16px rgba(0, 255, 65, 0.15);
    border-color: rgba(0, 255, 65, 0.4);
  }
}
```

### 7. Config Fixes (`_config.yml`)

- Fix typo: `tryhackme.username: mithr4ad1r` → `mithr4nd1r`
- Add `hackthebox` social block (placeholder username, user fills later)
- Set `theme_mode: dark` (force dark only)
- Update `description` to reflect new positioning if user wants (optional, ask during implementation)

## Data Flow

Terminal hero needs the 4 most recent posts. Jekyll renders post titles + dates into a JSON data attribute on the terminal element:

```liquid
{% raw %}
<div id="terminal-output"
     data-posts='[
       {% for post in site.posts limit:4 %}
         {"title": "{{ post.title | escape }}", "url": "{{ post.url }}", "date": "{{ post.date | date: "%Y-%m-%d" }}"}{% unless forloop.last %},{% endunless %}
       {% endfor %}
     ]'>
</div>
{% endraw %}
```

JS reads `dataset.posts`, formats as `-rw-r--r-- 1 mithr4nd1r ctf <date> <title>` lines, types them out.

## Error Handling

- **JS disabled:** Terminal hero renders ASCII banner + static text "Welcome. Visit /writeups/ for content." as `<noscript>` fallback. Posts remain accessible via Chirpy's normal post list below.
- **Reduced motion:** All animations (typewriter, scanline flicker, text glow pulse) disabled. Final state rendered immediately.
- **Mobile (< 768px):** Skip ASCII banner (too wide), skip typewriter animation, render static terminal output.
- **Chirpy upgrade conflicts:** All overrides isolated to `_sass/addon/` and selectively overridden layouts/includes. Document affected Chirpy files in spec for future merge resolution.

## Testing

Manual verification only (no automated tests — Jekyll static site, low risk):

1. **Local build:** `bundle exec jekyll serve` — no SCSS errors, no Liquid errors, site builds.
2. **Visual smoke test:** Open `http://127.0.0.1:4000` in browser, verify:
   - Terminal hero renders with ASCII banner and typewriter animation
   - All 4 new tabs accessible from sidebar
   - Post cards have terminal window styling
   - Scanline overlay visible but not obstructive
   - Text readable, no color contrast issues
3. **Responsive:** Resize browser to mobile width (375px) — ASCII banner hidden, terminal still readable, no horizontal scroll.
4. **Reduced motion:** OS-level enable "Reduce motion" — verify animations disabled.
5. **Each existing post still renders correctly** — open one of the 4 writeups, verify content, code blocks, images all display with new theme.
6. **Build for production:** `JEKYLL_ENV=production bundle exec jekyll build` — verify `_site/` output clean.

## Files Affected

```
mithr4nd1r.github.io/
├── _config.yml                              [modify]
├── _sass/
│   ├── jekyll-theme-chirpy.scss             [modify: add @imports]
│   └── addon/
│       ├── _terminal-theme.scss             [new]
│       ├── _crt-effects.scss                [new]
│       ├── _terminal-hero.scss              [new]
│       └── _terminal-cards.scss             [new]
├── _layouts/
│   └── home.html                            [new: override]
├── _includes/
│   └── sidebar.html                         [new: override]
├── _javascript/
│   └── modules/
│       └── terminal-hero.js                 [new]
├── _tabs/
│   ├── about.md                             [modify: expand]
│   ├── skills.md                            [new]
│   ├── certifications.md                    [new]
│   └── ctf-stats.md                         [new]
└── assets/
    └── img/
        └── favicons/                        [optional: replace with green terminal favicon]
```

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Chirpy upgrade breaks overrides | Isolated `_sass/addon/` partials; document overridden files |
| CRT effects hurt accessibility | Honor `prefers-reduced-motion`, low-opacity scanlines, no flicker on text |
| Typewriter feels gimmicky after first visit | Skip animation after first visit using `sessionStorage` flag |
| Mobile screen too narrow for ASCII banner | Hide banner < 768px, show only terminal window |
| Custom favicon time-consuming | Optional in v1, default Chirpy favicons acceptable initially |
| Theme too dark for some readers | Force dark mode = intentional design decision (matches identity); not a usability bug |

## Out of Scope (Deferred)

- Custom favicon set (use Chirpy default for v1; replace later)
- Light mode variant (intentionally removed)
- Search override (use Chirpy default search)
- Comments integration (Chirpy default disabled)
- Analytics
- RSS feed customization
- Post-specific terminal styling (per-post custom layouts)
- Animated typing on every page (only home hero)
