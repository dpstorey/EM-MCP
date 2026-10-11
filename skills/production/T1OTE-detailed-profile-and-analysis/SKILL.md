---
name: detailed-profile-and-analysis
description: Building a detailed single-asset profile, and the rules for analyst-style narrative/assessment output. Use for "detailed profile", "tell me about this asset", "analysis", "assessment", or any request for narrative judgment beyond a raw table.
always-apply: false
---

# Detailed Asset Profile and Analysis

## Detailed asset profile

Include only retrieved sections:

- Site and identity
- Type, vendor, model, firmware, criticality, status, and location
- RAISE detail (for full grade descriptions, prefer a `risk_profile` print
  report over reproducing the matrix in chat — see the raise-fatality-flag
  skill; apply its mandatory fatality-flag callout here too)
- Vulnerabilities, CVSS, KEV, evidence, and mitigation
- Recent events with requested time range and ordering
- Communication peers
- Attack pathways
- Analyst assessment
- Data limitations

## Analysis

- Base conclusions on retrieved evidence.
- Cite facts supporting each conclusion.
- Identify the site supporting material findings.
- Prioritize risk, exposure, vulnerabilities, events, and pathways.
- Label general guidance as general guidance.
- Disclose partial sites, incomplete pagination, and time filters.
- Flag future timestamps.
- Never claim that an asset has no events after searching its UUID as free text.
