# Arai Notes

Arai Notes is a clean, lightweight Jekyll blog for a personal daily knowledge journal. It is built from scratch for `araisantai.github.io` without a forked theme or heavy front-end framework.

## Topics

- Personal development
- Cybersecurity
- Technology
- Finance
- Workout
- Learning languages
- Media management
- Islam

## Local development

Install dependencies:

```bash
bundle install
```

Run the local server:

```bash
bundle exec jekyll serve
```

Then open `http://localhost:4000`.

## Deployment

This repository uses GitHub Actions to deploy to GitHub Pages from the `main` branch. The workflow is located at `.github/workflows/pages-deploy.yml`.

In GitHub repository settings:

1. Go to **Settings → Pages**.
2. Set **Build and deployment → Source** to **GitHub Actions**.
3. Push changes to `main`.

## Content notes

- Cybersecurity posts should stay ethical, educational, and defensive-focused.
- Finance posts are personal learning and journaling, not financial advice.
- Islam posts should be respectful and source-aware. Add Qur’an, Hadith, or reliable source references when needed.

## Structure

- `_layouts/` contains reusable page layouts.
- `_includes/` contains shared partials.
- `_posts/` contains dated blog posts.
- `categories/` contains category landing pages.
- `assets/css/main.scss` contains the responsive theme.
- `assets/js/main.js` contains dark mode and local search behavior.
- `search.json` exposes a simple search index for client-side search.
