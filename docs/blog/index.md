---
title: Blog
description: Writing from the Tenuo team on task-scoped authorization for AI agents.
permalink: /blog/
---

<style>
.blog-intro {
  font-size: 1rem;
  color: var(--text-muted);
  margin: 0.25rem 0 2.5rem;
  line-height: 1.6;
}

.blog-list {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
  margin-top: 0.5rem;
}

.blog-card {
  background: var(--surface);
  padding: 1.5rem 1.75rem;
  border-bottom: 1px solid var(--border);
  display: grid;
  gap: 0.5rem;
  transition: background 0.15s;
}

.blog-card:last-child {
  border-bottom: none;
}

.blog-card:hover {
  background: var(--surface-2);
}

.blog-title {
  font-size: 1.05rem;
  font-weight: 600;
  line-height: 1.4;
}

.blog-title a {
  color: var(--text);
  text-decoration: none;
}

.blog-title a:hover {
  color: var(--accent);
}

.blog-meta {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.blog-description {
  font-size: 0.9rem;
  color: var(--text);
  opacity: 0.8;
  margin: 0;
  line-height: 1.6;
}

.blog-link {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--accent);
  text-decoration: none;
  width: fit-content;
}

.blog-link:hover {
  color: var(--accent-dim);
  text-decoration: underline;
}

.blog-section-heading {
  font-size: 1.15rem;
  font-weight: 600;
  margin: 3rem 0 0.35rem;
}

.blog-section-note {
  font-size: 0.9rem;
  color: var(--text-muted);
  margin: 0 0 1rem;
  line-height: 1.6;
}
</style>

# Blog

<p class="blog-intro">Writing from the Tenuo team on task-scoped authorization for AI agents.</p>

{% comment %}
  Collect by URL, not by directory. Posts publish to /blog/ from more than one
  place in the tree, so globbing docs/blog/ would miss them.
{% endcomment %}
{% assign blog_posts = site.pages
  | where_exp: "p", "p.url contains '/blog/'"
  | where_exp: "p", "p.url != '/blog/'"
  | sort: "date"
  | reverse %}

<div class="blog-list">
{% for post in blog_posts %}
  <div class="blog-card">
    <div class="blog-title"><a href="{{ post.url }}">{{ post.title }}</a></div>
    <div class="blog-meta">
      {%- if post.date %}{{ post.date | date: "%B %-d, %Y" }}{% endif -%}
      {%- if post.date and post.author %} · {% endif -%}
      {%- if post.author %}{{ post.author }}{% endif -%}
    </div>
    {% if post.description %}<p class="blog-description">{{ post.description }}</p>{% endif %}
    <a class="blog-link" href="{{ post.url }}">Read the post →</a>
  </div>
{% endfor %}
</div>

<h2 class="blog-section-heading">Longer pieces</h2>
<p class="blog-section-note">Essays and standards mappings that live in the docs rather than the post stream.</p>

{% comment %}
  Listed by URL so these keep their existing, already-indexed locations.
  Titles and descriptions are read from the pages themselves.
{% endcomment %}
{% assign extra_urls = "/thesis.html,/eu-act.html,/owasp.html" | split: "," %}

<div class="blog-list">
{% for extra_url in extra_urls %}
  {% assign matches = site.pages | where_exp: "p", "p.url == extra_url" %}
  {% assign piece = matches.first %}
  {% if piece %}
  <div class="blog-card">
    <div class="blog-title"><a href="{{ piece.url }}">{{ piece.title }}</a></div>
    {% if piece.date or piece.author %}
    <div class="blog-meta">
      {%- if piece.date %}{{ piece.date | date: "%B %-d, %Y" }}{% endif -%}
      {%- if piece.date and piece.author %} · {% endif -%}
      {%- if piece.author %}{{ piece.author }}{% endif -%}
    </div>
    {% endif %}
    {% if piece.description %}<p class="blog-description">{{ piece.description }}</p>{% endif %}
    <a class="blog-link" href="{{ piece.url }}">Read it →</a>
  </div>
  {% endif %}
{% endfor %}
</div>
