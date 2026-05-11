# Stone & Birch — Website Files

## What's included

| File | Page |
|------|------|
| `index.html` | Homepage — hero slider, intro, featured projects, services, about preview |
| `projects.html` | Projects gallery — full grid with hover effects |
| `project.html` | Individual project template — photo layouts, details, next/prev nav |
| `about.html` | About page — bio, values, team grid |
| `process.html` | Process page — numbered steps with images |
| `connect.html` | Contact page — sticky image + detailed form |
| `style.css` | All shared styles |
| `main.js` | Menu toggle, nav scroll behaviour, hero slider |

---

## How to add your images

Every placeholder `<div class="img-box">` should be replaced with an `<img>` tag:

```html
<!-- Replace this: -->
<div class="img-box">Your Hero Image 1</div>

<!-- With this: -->
<img src="images/hero-1.jpg" alt="Description of image">
```

Create an `images/` folder alongside the HTML files and put all your photos there.

**Recommended image sizes:**
- Hero slider images: 2400 × 1600px (landscape)
- Project grid cards: 1600 × 1200px
- Full-width project photos: 2400 × 1350px
- Portrait / team photos: 800 × 1067px (3:4 ratio)
- Page hero banners: 2400 × 1000px

---

## How to update copy

All copy is written as placeholder text. Search for phrases like "Your Name", "Your Address", "Replace this with..." and substitute your own content.

**Key places to update:**
- Phone number: `604 555 1234` → your number (in nav overlay, footer, connect page)
- Email: `hello@stoneandbirch.com` → your email
- Address: update in footer and connect page
- Social links: replace `href="#"` with your actual profile URLs

---

## Adding more projects

To add a project card on `projects.html`, copy one `.proj-item` block and update:
- The cover image src
- The hover image src
- Project name, type, and description
- The `href` pointing to the project's own page

To create a new project page, duplicate `project.html` and:
- Update the `<title>` tag
- Update the `.proj-header` name and description
- Update the `.proj-details` items
- Replace all `.img-box` placeholders with your photos
- Update the "Next project" link at the bottom

---

## Fonts & colours

Fonts are loaded from Google Fonts:
- **Cormorant Garamond** — headings, display text
- **Jost** — body, labels, navigation

Colours are defined as CSS variables in `style.css`:
```css
--cream: #f5f2ed;      /* light backgrounds */
--stone: #b5a898;      /* muted accent, labels */
--charcoal: #2a2825;   /* dark backgrounds, primary text */
--warm-white: #faf8f5; /* page background */
--mid: #7a6f65;        /* body text */
```

---

## Hosting

These are plain HTML/CSS/JS files — no build step, no framework. You can:
- Upload directly to any web host (Squarespace custom code, Cloudflare Pages, Netlify, etc.)
- Open `index.html` locally in a browser to preview
- Connect a custom domain pointing to wherever you upload the files

For contact form submissions, connect the `<form>` to a service like **Netlify Forms**, **Formspree**, or **EmailJS** — just add their required attributes/script to the form in `connect.html`.
