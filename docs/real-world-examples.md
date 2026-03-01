---
title: Real-World Examples
description: How warrant-based authorization protects AI systems in healthcare, finance, and infrastructure
---

# Real-World Examples

See how Tenuo protects AI systems in three critical industries. Each example shows the threat, what goes wrong without protection, and how Tenuo stops it.

---

## 1. Healthcare: Stopping Patient Data Theft

### The Scenario

A hospital uses an AI assistant to help doctors look up patient records and send reports to referring physicians. A malicious instruction is hidden inside a patient's intake form. When the AI reads the form, the hidden instruction tells it to secretly email every patient record to an outside address.

### Without Protection

The AI has permanent access to **all tools** — reading records *and* sending emails. So the hidden instruction succeeds:

- AI reads the patient intake form
- Hidden instruction activates
- AI silently emails patient records to the attacker
- **No safeguard prevents this** — email is a legitimate tool the AI can always use

### With Tenuo

Tenuo gives the AI a **time-limited warrant** scoped to the current task. For a record lookup, the warrant includes:

- **Allowed:** Read patient records for the specific patient
- **Allowed:** Generate a summary report
- **Not included:** Send email

The hidden instruction tries to send an email — **denied**. When the doctor actually needs to email a report, a separate warrant is issued that restricts recipients to known physician addresses only.

### Business Impact

| | Without Protection | With Tenuo |
|---|---|---|
| **Patient data** | Leaked to attacker | Exfiltration blocked |
| **Regulatory** | HIPAA violation triggered | Full compliance maintained |
| **Financial** | Multi-million dollar fine exposure | Zero breach, zero fine |
| **Reputation** | Hospital trust damaged | Patient confidence preserved |

---

## 2. Finance: Preventing Unauthorized Trades

### The Scenario

A hedge fund uses two AI agents: a **Research Agent** that analyzes market data, and a **Trading Agent** that executes trades. The research agent reads a news article containing a hidden instruction that tells it to buy 100,000 shares of a fraudulent stock.

### Without Protection

Both agents share the same tool registry. The research agent's compromised output reaches the trading tools:

- Research agent fetches a poisoned news article
- Hidden instruction activates
- Research agent calls the trading tool directly
- **100,000 shares of a fraudulent stock are purchased**
- No boundary separates research tools from trading tools

### With Tenuo

Tenuo issues **separate warrants** for each agent with strict boundaries:

- **Research Agent warrant:**
  - **Allowed:** Fetch market data from approved sources (e.g., Bloomberg, Reuters)
  - **Allowed:** Analyze sentiment, write memos
  - **Not included:** Any trading tools
- **Trading Agent warrant:**
  - **Allowed:** Trade only pre-approved stocks (e.g., AAPL, GOOGL, MSFT)
  - **Allowed:** Maximum quantity per trade (e.g., 1,000 shares)
  - **Not included:** Any research tools

Even if the research agent is compromised, it has no trading tools. Even the trading agent can't buy a fraudulent stock — it's not on the approved list.

### Business Impact

| | Without Protection | With Tenuo |
|---|---|---|
| **Trades** | 100K shares of fraudulent stock purchased | Trade attempt blocked |
| **Regulatory** | SEC investigation triggered | Full compliance with trading rules |
| **Financial** | Significant capital loss | Zero unauthorized transactions |
| **Investor trust** | Confidence destroyed | Trading controls verified |

---

## 3. Infrastructure: Blocking Malicious Deployments

### The Scenario

A DevOps team uses an AI agent for CI/CD — building code, running tests, and deploying to staging. A developer submits a pull request with hidden instructions in the README that tell the AI to deploy a malicious container image directly to production.

### Without Protection

The CI agent has deploy permissions for **all environments**. Nothing distinguishes a test run from a production deployment:

- CI agent reads the pull request
- Hidden instruction in the README activates
- Agent deploys a backdoored container image to production
- **Malicious code is now running in the live system**
- Customers and data are exposed

### With Tenuo

Tenuo's warrant for the CI pipeline only allows specific actions:

- **Allowed:** Run tests
- **Allowed:** Build container images from the organization's own registry
- **Allowed:** Deploy to staging
- **Not included:** Deploy to production

The hidden instruction tries to deploy to production — **denied**. Production deployment requires a **separate warrant** that is only issued after explicit human approval in the workflow.

### Business Impact

| | Without Protection | With Tenuo |
|---|---|---|
| **Production** | Malicious code deployed | Deployment blocked at staging gate |
| **Security** | Backdoor in live system | Only approved images from trusted registry |
| **Supply chain** | Full compromise possible | Production requires human approval |
| **Customer data** | Exposed to attacker | Infrastructure integrity maintained |

---

## Summary

The pattern is the same across all three industries:

- **Without Tenuo:** AI agents have broad, permanent access to all tools. A single hidden instruction can abuse any capability at any time.
- **With Tenuo:** Each task gets a time-limited warrant that grants only the specific tools and parameters needed. Everything else is denied by default.

| Industry | Threat | How Tenuo Stops It |
|---|---|---|
| **Healthcare** | Hidden instructions steal patient data | Warrant excludes email — exfiltration blocked |
| **Finance** | Compromised research triggers unauthorized trades | Separate warrants per agent — trading tools isolated |
| **Infrastructure** | Malicious PR deploys backdoor to production | Warrant limits deploy to staging — production requires human approval |

> **Ready to protect your AI systems?** [Get started with Tenuo](./quickstart) in under 5 minutes.
