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
    <div class="wild-title"><a href="https://workos.com/blog/oauth-multi-hop-delegation-ai-agents">OAuth multi-hop delegation for AI agents</a></div>
    <div class="wild-attribution">WorkOS Engineering</div>
    <p class="wild-description">Survey of emerging standards for multi-hop agent delegation. The AAT Internet-Draft is cited as a standards-track approach to offline-verifiable attenuation chains.</p>
    <a class="wild-link" href="https://workos.com/blog/oauth-multi-hop-delegation-ai-agents">Read the post →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://www.agentpatternscatalog.org/patterns/attenuating-delegation-chain/">Attenuating Delegation Chain</a></div>
    <div class="wild-attribution">Agent Patterns Catalog</div>
    <p class="wild-description">Independent pattern write-up of signed, append-only delegation chains that a verifier can reject for widening without calling the issuer. The AAT Internet-Draft is listed as a known use.</p>
    <a class="wild-link" href="https://www.agentpatternscatalog.org/patterns/attenuating-delegation-chain/">Read the pattern →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://1password.github.io/agent-identity-specs/draft-1password-agent-identity-local-delegated.html#section-12-2.3.1">Local Delegated Agent Identity Architecture</a></div>
    <div class="wild-attribution">Malnick, Meller, Menke · 1Password</div>
    <p class="wild-description">1Password reference architecture for local delegated agents. The AAT Internet-Draft is cited as prior art for attenuating tokens in sub-agent flows.</p>
    <a class="wild-link" href="https://1password.github.io/agent-identity-specs/draft-1password-agent-identity-local-delegated.html#section-12-2.3.1">Read the draft →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/">Verifiable Attenuated Delegation for AI Agent Chains</a></div>
    <div class="wild-attribution">R. Asor · IETF WIMSE</div>
    <p class="wild-description">WIMSE individual draft for offline-verifiable attenuated delegation chains. It shares its approach with the AAT Internet-Draft and is intended to converge with it.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/">Read the draft →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/">Credential Delegation Protocol for AI Agents</a></div>
    <div class="wild-attribution">K. Sweeney · IETF WIMSE</div>
    <p class="wild-description">WIMSE individual draft for an online Delegation Server. AAT is cited as the offline, holder-attenuable counterpart with the same goal and a different trust model.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/">Read the draft →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/">Mission-Bound Authorization for OAuth 2.0</a></div>
    <div class="wild-attribution">Karl McGuinness</div>
    <p class="wild-description">OAuth profile for mission-bound grants. The AAT Internet-Draft is cited as the nearby work that carries offline capability attenuation and typed per-argument constraints.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/">Read the draft →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-sharif-attp/">ATTP: Agent Trust Transport Protocol</a></div>
    <div class="wild-attribution">R. Sharif · CyberSecAI</div>
    <p class="wild-description">Trust-decision protocol for agent actions. It treats AAT chains as a capability-attenuation input and says it does not define a competing delegation format.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-sharif-attp/">Read the draft →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--mention">Mention</span>
    <div class="wild-title"><a href="https://www.windley.com/archives/2026/06/internet_identity_workshop_xlii_report.shtml">Internet Identity Workshop XLII Report</a></div>
    <div class="wild-attribution">Phil Windley · IIW Organizer</div>
    <p class="wild-description">Report from IIW 42 at the Computer History Museum. Covers the Demo Hour where Niki Niyikiza showed Tenuo's attenuating authorization tokens that cryptographically narrow an agent's capabilities at each delegation hop.</p>
    <a class="wild-link" href="https://www.windley.com/archives/2026/06/internet_identity_workshop_xlii_report.shtml#:~:text=This%20time%2C%20the%20demo%20tables,capabilities%20at%20each%20delegation%20hop.">Read the report →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--standards">Standards</span>
    <div class="wild-title"><a href="https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/">draft-niyikiza-oauth-attenuating-agent-tokens-01</a></div>
    <div class="wild-attribution">IETF OAuth Working Group</div>
    <p class="wild-description">Individual Internet-Draft published in the IETF OAuth Working Group defining Attenuating Authorization Tokens for agentic delegation chains. Tenuo is the canonical reference implementation.</p>
    <a class="wild-link" href="https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/01/">View on IETF Datatracker →</a>
  </div>

  <div class="wild-card">
    <span class="wild-badge wild-badge--talk">Talk</span>
    <div class="wild-title"><a href="https://greptalks.ai/c/unprompted-2026/D2-S2-03/">Capability-Based Authorization for AI Agents: Warrants That Survive Prompt Injection</a></div>
    <div class="wild-attribution">GrepTalks · Unprompted 2026 editor's picks</div>
    <p class="wild-description">Talk by Niki Aimable Niyikiza. Ranked #3 of 12 must-see talks at Unprompted 2026. Includes a live demo where a prompt injection is stopped at the execution layer without touching the model.</p>
    <a class="wild-link" href="https://greptalks.ai/c/unprompted-2026/D2-S2-03/">View on GrepTalks →</a>
  </div>

</div>
