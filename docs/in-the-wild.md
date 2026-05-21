---
title: Tenuo in the Wild
description: External writing, talks, and coverage about Tenuo
---

<style>
.wild-intro {
  font-size: 1rem;
  color: var(--text-muted);
  margin: 0.25rem 0 2.5rem;
  line-height: 1.6;
}

.wild-list {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
  margin-top: 0.5rem;
}

.wild-card {
  background: var(--surface);
  padding: 1.5rem 1.75rem;
  border-bottom: 1px solid var(--border);
  display: grid;
  gap: 0.5rem;
  transition: background 0.15s;
}

.wild-card:last-child {
  border-bottom: none;
}

.wild-card:hover {
  background: var(--surface-2);
}

.wild-badge {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 2px 8px;
  border-radius: 3px;
  width: fit-content;
}

.wild-badge--case-study {
  background: rgba(0, 212, 255, 0.1);
  color: var(--accent);
  border: 1px solid rgba(0, 212, 255, 0.25);
}

.wild-badge--mention {
  background: rgba(136, 136, 136, 0.1);
  color: var(--text-muted);
  border: 1px solid rgba(136, 136, 136, 0.25);
}

.wild-badge--standards {
  background: rgba(59, 130, 246, 0.1);
  color: #3b82f6;
  border: 1px solid rgba(59, 130, 246, 0.25);
}

.wild-badge--talk {
  background: rgba(168, 85, 247, 0.1);
  color: #a855f7;
  border: 1px solid rgba(168, 85, 247, 0.25);
}

.wild-title {
  font-size: 1.05rem;
  font-weight: 600;
  line-height: 1.4;
}

.wild-title a {
  color: var(--text);
  text-decoration: none;
}

.wild-title a:hover {
  color: var(--accent);
}

.wild-attribution {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.wild-description {
  font-size: 0.9rem;
  color: var(--text);
  opacity: 0.8;
  margin: 0;
  line-height: 1.6;
}

.wild-link {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--accent);
  text-decoration: none;
  width: fit-content;
}

.wild-link:hover {
  color: var(--accent-dim);
  text-decoration: underline;
}
</style>

# Tenuo in the Wild

<p class="wild-intro">External mentions, write-ups, and recognition.</p>

<div class="wild-list">

  <div class="wild-card">
    <span class="wild-badge wild-badge--case-study">Case study</span>
    <div class="wild-title"><a href="https://brooksmcmillin.com/blog/wiring-capability-warrants-autonomous-agents/">Wiring capability warrants into autonomous agents</a></div>
    <div class="wild-attribution">Brooks McMillin · Staff Engineer, Dropbox</div>
    <p class="wild-description">End-to-end warrant gating for MCP tool calls on Kubernetes, with Tenuo Cloud handling trigger minting and cross-cluster audit. Scope-gated rollout across 16 agents, multi-hop delegation at depth 2 and 3, and a live prompt injection the warrant catches.</p>
    <a class="wild-link" href="https://brooksmcmillin.com/blog/wiring-capability-warrants-autonomous-agents/">Read the post →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="#">OAuth multi-hop delegation for AI agents</a></div>
    <div class="wild-attribution">WorkOS Engineering</div>
    <p class="wild-description">Survey of emerging standards for multi-hop agent delegation. The AAT Internet-Draft is cited as a standards-track approach to offline-verifiable attenuation chains.</p>
    <a class="wild-link" href="#">Read the post →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="#">AAC Construction Specification: Non-Human Identity Series</a></div>
    <div class="wild-attribution">Mohamad Amin Hasbini · Independent researcher, Paris</div>
    <p class="wild-description">Technical paper on privacy-preserving authorization for AI agents. The AAT Internet-Draft is surveyed as the primary prior art on delegation-chain attenuation, with an accurate technical comparison of the disclosure models.</p>
    <a class="wild-link" href="#">Read the paper →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--standards">Standards</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/">draft-niyikiza-oauth-attenuating-agent-tokens-00</a></div>
    <div class="wild-attribution">IETF OAuth Working Group</div>
    <p class="wild-description">Individual Internet-Draft published in the IETF OAuth Working Group defining Attenuating Authorization Tokens for agentic delegation chains. Tenuo is the canonical reference implementation.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/">View on IETF Datatracker →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--talk">Talk</span>
    <div class="wild-title"><a href="https://greptalks.ai/c/unprompted-2026/D2-S2-03/">Capability-Based Authorization for AI Agents: Warrants That Survive Prompt Injection</a></div>
    <div class="wild-attribution">GrepTalks · Unprompted 2026 editor's picks</div>
    <p class="wild-description">Talk by Niki Aimable Niyikiza. Ranked #3 of 12 must-see talks at Unprompted 2026. Includes a live demo where a prompt injection is stopped at the execution layer without touching the model.</p>
    <a class="wild-link" href="https://greptalks.ai/c/unprompted-2026/D2-S2-03/">View on GrepTalks →</a>
  </div>

</div>
