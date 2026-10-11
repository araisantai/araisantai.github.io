# Arai Notes

A lightweight Jekyll site built from scratch. The homepage introduces Arai, and three independent notebooks hold the writing:

| Page | URL | Source |
| --- | --- | --- |
| About me | `/` | `_layouts/home.html` |
| Cyber Security | `/cybersecurity/` | `cybersecurity/index.md` |
| Finance | `/finance/` | `finance/index.md` |
| Books | `/books/` | `books/index.md` |

Each notebook shows only its own posts and search results. The header lets visitors switch notebooks; footers and post navigation stay within the current topic.

## Local development

Install Ruby and Bundler, then run:

```bash
bundle install
bundle exec jekyll serve
```

Open `http://localhost:4000`.

## Writing

Add dated Markdown files to `_posts/`. Use exactly one category: `cybersecurity`, `finance`, or `books`. Jekyll generates post URLs under that category, for example `/books/2024/01/09/reading-with-a-notebook/`.

```yaml
---
title: My Reading Notes
description: A short summary of this entry.
date: 2026-10-11 07:00:00 +0700
categories: [books]
tags: [reading]
---
```

- Keep cybersecurity writing ethical, educational, and defensive.
- Include a personal learning / not financial advice note in finance entries.
- Write book reflections in your own words and identify the title, author, and page or chapter references when discussing a specific book.

Edit `_layouts/home.html` to personalize the about page. The starter copy avoids invented credentials or biographical claims.

## Deployment

The workflow at `.github/workflows/pages-deploy.yml` builds and deploys from `main`. In GitHub, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**, then push changes to `main`. Ruby is installed by the workflow, so a local Ruby installation is optional if you build only on GitHub.

The current site URL is `https://araisantai.github.io`. The three notebooks are served from folders, with canonical trailing slashes. URLs such as `/finance` normally redirect to `/finance/` on GitHub Pages.

When you connect `arainotes.com`, configure that custom domain in GitHub Pages and change `url` in `_config.yml` to `https://arainotes.com`. Keep `baseurl` empty for this root site. The domain is not enabled yet.

## Future subdomains

The `blog_categories` entries in `_config.yml` hold each notebook's navigation URL. Folder URLs are used today. Later, those links can point to subdomains such as `https://finance.arainotes.com/`.

Changing links alone does not deploy a subdomain. Each notebook will need its own deployment, domain configuration, and matching canonical/post URLs. The topic-specific landing pages and search indexes already separate the content for that future work.

## Structure

- `_layouts/` and `_includes/`: shared templates.
- `_posts/`: writing with one topic per post.
- `cybersecurity/`, `finance/`, `books/`: landing pages and separate search indexes.
- `assets/css/main.scss`: responsive styles and dark mode.
- `assets/js/main.js`: theme toggle and local search.
