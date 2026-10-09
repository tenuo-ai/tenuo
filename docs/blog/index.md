---
layout: blog-index
title: "Engineering Blog"
description: "Engineering notes on task-scoped authorization, delegated authority, and secure AI agent workflows."
permalink: /blog/
blog_index: true
---

<style>
  .engineering-blog-header {
    max-width: 720px;
    margin-bottom: 48px;
  }

  .engineering-blog-header h1 {
    margin: 0 0 14px;
    color: var(--text-bright);
    font-size: clamp(2rem, 5vw, 3.4rem);
    line-height: 1.05;
    letter-spacing: -0.045em;
  }

  .engineering-blog-intro {
    margin: 0;
    color: var(--muted);
    font-size: 1.02rem;
    line-height: 1.7;
  }

  .newsletter-signup {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
    gap: 24px;
    align-items: center;
    margin: 0 0 40px;
    padding: 20px 24px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }

  .newsletter-label {
    margin: 0 0 6px;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .newsletter-copy h2 {
    margin: 0 0 4px;
    color: var(--text-bright);
    font-size: 1.2rem;
    line-height: 1.35;
    letter-spacing: -0.02em;
  }

  .newsletter-copy > p:last-child {
    margin: 0;
    color: var(--muted);
    font-size: 0.86rem;
  }

  .newsletter-form {
    display: flex;
    gap: 8px;
  }

  .newsletter-form input {
    min-width: 0;
    flex: 1;
    padding: 11px 12px;
    color: var(--text-bright);
    background: var(--bg);
    border: 1px solid rgba(122, 154, 170, 0.35);
    border-radius: 7px;
    font: inherit;
    font-size: 0.82rem;
    outline: none;
  }

  .newsletter-form input::placeholder {
    color: var(--muted-dim);
  }

  .newsletter-form input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.12);
  }

  .newsletter-form button {
    padding: 11px 16px;
    color: var(--text-bright);
    background: var(--surface-2);
    border: 1px solid rgba(122, 154, 170, 0.45);
    border-radius: 7px;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .newsletter-form button:hover {
    background: #14202b;
    border-color: rgba(56, 189, 248, 0.55);
  }

  .newsletter-note {
    margin: 8px 0 0;
    color: var(--muted);
    font-size: 0.74rem;
  }

  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .engineering-posts {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .engineering-post {
    display: flex;
    min-height: 220px;
    padding: 26px;
    flex-direction: column;
    color: inherit;
    text-decoration: none;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    transition: border-color 0.16s ease, background 0.16s ease;
  }

  .engineering-post:hover {
    background: var(--surface-2);
    border-color: rgba(56, 189, 248, 0.25);
    text-decoration: none;
  }

  .engineering-post-meta {
    display: flex;
    flex-wrap: wrap;
    min-height: 20px;
    margin-bottom: 18px;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .engineering-post-meta time {
    white-space: nowrap;
  }

  .engineering-post h2 {
    margin: 0 0 12px;
    color: var(--text-bright);
    font-size: 1.28rem;
    line-height: 1.3;
    letter-spacing: -0.025em;
  }

  .engineering-post-description {
    margin: 0 0 24px;
    color: var(--muted);
    font-size: 0.9rem;
    line-height: 1.65;
  }

  .engineering-post-link {
    margin-top: auto;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem;
  }

  .section-label {
    margin: 0 0 10px;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .featured-post {
    position: relative;
    display: flex;
    flex-direction: column;
    margin-bottom: 16px;
    padding: 32px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    transition: border-color 0.16s ease, background 0.16s ease;
  }

  .featured-post:hover {
    background: var(--surface-2);
    border-color: rgba(56, 189, 248, 0.25);
  }

  .featured-post h2 {
    margin: 0 0 12px;
    color: var(--text-bright);
    font-size: clamp(1.55rem, 4vw, 2.1rem);
    line-height: 1.2;
    letter-spacing: -0.03em;
  }

  .featured-post h2 a {
    color: inherit;
    text-decoration: none;
  }

  .featured-post h2 a::after {
    content: '';
    position: absolute;
    inset: 0;
  }

  .featured-post .engineering-post-description {
    margin-bottom: 0;
  }

  .featured-post .engineering-post-link {
    margin-top: 24px;
    text-align: left;
  }

  .resources {
    margin-top: 64px;
  }

  .resources-heading {
    margin-bottom: 20px;
  }

  .resources-heading h2 {
    margin: 0;
    color: var(--text-bright);
    font-size: 1.6rem;
    letter-spacing: -0.025em;
  }

  .resources-heading > p {
    max-width: 520px;
    margin: 8px 0 0;
    color: var(--muted);
    font-size: 0.88rem;
  }

  .resource-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .featured-resource {
    position: relative;
    display: flex;
    flex-direction: column;
    margin-bottom: 16px;
    padding: 30px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    transition: border-color 0.16s ease, background 0.16s ease;
  }

  .featured-resource:hover {
    background: var(--surface-2);
    border-color: rgba(56, 189, 248, 0.25);
  }

  .featured-resource h3 {
    margin: 0 0 10px;
    color: var(--text-bright);
    font-size: 1.45rem;
    line-height: 1.3;
    letter-spacing: -0.02em;
  }

  .featured-resource h3 a {
    color: inherit;
    text-decoration: none;
  }

  .featured-resource h3 a::after {
    content: '';
    position: absolute;
    inset: 0;
  }

  .featured-resource p:not(.section-label) {
    margin: 0;
    color: var(--muted);
    font-size: 0.9rem;
    line-height: 1.65;
  }

  .featured-resource .engineering-post-link {
    margin-top: 22px;
    text-align: left;
  }

  .resource-card {
    display: block;
    padding: 24px;
    color: inherit;
    text-decoration: none;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    transition: border-color 0.16s ease, background 0.16s ease;
  }

  .resource-card:hover {
    color: inherit;
    text-decoration: none;
    background: var(--surface-2);
    border-color: rgba(56, 189, 248, 0.25);
  }

  .resource-card h3 {
    margin: 0 0 10px;
    color: var(--text-bright);
    font-size: 1.05rem;
    line-height: 1.4;
  }

  .resource-card p {
    margin: 0;
    color: var(--muted);
    font-size: 0.84rem;
    line-height: 1.6;
  }

  @media (max-width: 720px) {
    .blog-index-content {
      padding: 44px 0 64px;
    }

    .engineering-blog-header {
      margin-bottom: 34px;
    }

    .newsletter-signup {
      grid-template-columns: 1fr;
      gap: 16px;
      margin-bottom: 34px;
      padding: 20px;
    }

    .engineering-posts {
      grid-template-columns: 1fr;
    }

    .resource-grid {
      grid-template-columns: 1fr;
    }

    .engineering-post {
      min-height: 0;
    }
  }

  @media (max-width: 440px) {
    .newsletter-form {
      flex-direction: column;
    }

    .newsletter-form button {
      width: 100%;
    }
  }
</style>

<header class="engineering-blog-header">
  <h1>Engineering Blog</h1>
  <p class="engineering-blog-intro">Notes on building task-scoped authorization for AI agents, from protocol design through SDKs and integrations to production implementation patterns.</p>
</header>

{% include newsletter-signup.html location="blog-index" %}

{% assign engineering_posts = site.pages
  | where_exp: "post", "post.url contains '/blog/'"
  | where_exp: "post", "post.url != '/blog/'"
  | where_exp: "post", "post.blog_index_exclude != true"
  | sort: "date"
  | reverse %}
{% assign featured_post = engineering_posts.first %}

{% if featured_post %}
<p class="section-label">Latest article</p>
<article class="featured-post">
  <div>
    <div class="engineering-post-meta">
      <span>{{ featured_post.author | default: "Tenuo Engineering" }}</span>
      {% if featured_post.date %}<span aria-hidden="true">·</span><time datetime="{{ featured_post.date | date_to_xmlschema }}">{{ featured_post.date | date: "%B %-d, %Y" }}</time>{% endif %}
    </div>
    <h2><a href="{{ featured_post.url | relative_url }}">{{ featured_post.title }}</a></h2>
    <p class="engineering-post-description">{{ featured_post.description }}</p>
  </div>
  <span class="engineering-post-link">Read article →</span>
</article>
{% endif %}

<section class="engineering-posts" aria-label="Engineering articles">
  {% for post in engineering_posts offset:1 %}
    <a class="engineering-post" href="{{ post.url | relative_url }}">
      <div class="engineering-post-meta">
        <span>{{ post.author | default: "Tenuo Engineering" }}</span>
        {% if post.date %}<span aria-hidden="true">·</span><time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%B %-d, %Y" }}</time>{% endif %}
      </div>
      <h2>{{ post.title }}</h2>
      <p class="engineering-post-description">{{ post.description }}</p>
      <span class="engineering-post-link">Read article →</span>
    </a>
  {% endfor %}
</section>

<section class="resources" aria-labelledby="resources-title">
  <div class="resources-heading">
    <p class="section-label">Resources</p>
    <h2 id="resources-title">Guides and research</h2>
    <p>Deeper technical arguments, standards mappings, and practical guidance from the Tenuo team.</p>
  </div>

  {% assign resources = site.pages | where: "blog_resource", true | sort: "resource_order" %}
  {% assign featured_resource = resources | where: "featured_resource", true | first %}
  {% assign remaining_resources = resources | where_exp: "resource", "resource.featured_resource != true" %}

  {% if featured_resource %}
  <article class="featured-resource">
    <div>
      <p class="section-label">Featured resource</p>
      <h3><a href="{{ featured_resource.url | relative_url }}">{{ featured_resource.title }}</a></h3>
      {% if featured_resource.description %}<p>{{ featured_resource.description }}</p>{% endif %}
    </div>
    <span class="engineering-post-link">Read resource →</span>
  </article>
  {% endif %}

  <div class="resource-grid">
  {% for resource in remaining_resources %}
    <a class="resource-card" href="{{ resource.url | relative_url }}">
      <h3>{{ resource.title }}</h3>
      {% if resource.description %}<p>{{ resource.description }}</p>{% endif %}
    </a>
  {% endfor %}
  </div>
</section>
