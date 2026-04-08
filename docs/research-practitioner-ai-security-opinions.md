# What Practitioners Actually Think About AI Security (March 2026)

Research compiled from Reddit, Hacker News, security conferences, practitioner blogs, and respected community voices.

---

## TL;DR: The Split

The practitioner community is **neither rolling their eyes nor blindly buying in**. The consensus is closer to: "The threats are real and novel, but vendor solutions are 90% hype, and the fundamentals haven't changed." AI security is being taken seriously by people doing the work, but the marketing-to-reality ratio is generating significant fatigue.

---

## 1. The Voices That Matter

### Bruce Schneier (January/February 2026)

Schneier has been the most technically rigorous voice. His key positions:

- **Prompt injection is architecturally unsolvable**: "General safeguards are impossible with today's LLMs" and "there's an endless array of prompt injection attacks waiting to be discovered."
- **LLMs flatten context into token similarity**: "They see 'tokens,' not hierarchies and intentions." Unlike humans who develop defenses through instincts and social learning, LLMs have no "interruption reflex."
- **The "Promptware Kill Chain"**: Schneier argues "prompt injection" is too narrow a framing. He proposes a seven-stage kill chain (initial access, privilege escalation, reconnaissance, persistence, C2, lateral movement, actions on objective) treating LLM attacks as a distinct class of malware.
- **Defense-in-depth, not prevention**: Rather than fixing prompt injection, break the chain at subsequent stages by limiting escalation, constraining reconnaissance, and restricting agent permissions.
- **Co-authored with Barath Raghavan (IEEE Spectrum, Jan 2026)**: "Prompt injection is unlikely to ever be fully solved with current LLM architectures because the distinction between code and data that tamed SQL injection simply does not exist inside the model."

Sources:
- https://www.schneier.com/essays/archives/2026/01/why-ai-keeps-falling-for-prompt-injection-attacks.html
- https://www.schneier.com/blog/archives/2026/02/the-promptware-kill-chain.html

### Simon Willison (2025, ongoing)

Willison coined "The Lethal Trifecta" (June 2025): any AI agent that combines (1) access to private data, (2) exposure to untrusted content, and (3) ability to externally communicate is trivially exploitable. His key positions:

- **MCP is not the problem, but MCP makes it worse**: "These vulnerabilities are not inherent to the MCP protocol itself. They're present any time we provide tools to an LLM that can potentially be exposed to untrusted inputs."
- **Basic coding failures**: "It's 2025, we should know not to pass arbitrary unescaped strings to os.system() by now!" on MCP server implementations.
- **Pessimism on solutions**: "We still don't have convincing mitigations for handling [prompt injection]... the lack of progress over the past two and a half years doesn't fill me with confidence."
- **Proposed the Dual LLM pattern**: A quarantined LLM (Q-LLM) processes risky inputs but cannot act, while a privileged LLM (P-LLM) accepts only validated inputs and has tool access. Framed as mitigation, not solution.

Sources:
- https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/

### Daniel Miessler (December 2025 / ongoing)

Miessler takes AI security seriously but frames it differently:

- **The real question**: "The primary security question for a company is how good their attackers' AI is vs. their own."
- **Models aren't the bottleneck**: "It's not actually models that we are waiting on to get good enough. It's the entire Agentic scaffolding layer."
- **Asset management breakthrough**: "Asset Management becomes possible for the first time because of Agents," calling it "an extraordinarily easy problem to improve on."
- **The zombie agent problem**: Volume creates chaos. Auditors will drown in change logs as agents make "one to two changes per second" across systems, potentially destroying the transparency AI promised.
- **Workforce bifurcation**: Top-tier security people become invaluable, while junior talent faces severe devaluation. Winners are "high-IQ, high-agency generalists" who direct armies of AI agents.

Sources:
- https://danielmiessler.com/blog/cybersecurity-ai-changes-2026
- https://danielmiessler.com/blog/ai-changes-2026

### Clint Gibler / tl;dr sec (ongoing)

Gibler's newsletter reflects the practitioner sweet spot: engaged but evidence-demanding.

- Highlighted "Why AI offense is beating defense" (December 2025), signaling the asymmetry is real.
- Attended [un]prompted (AI for security practitioners conference, March 2026), called it "one of the highest quality density in both talks and attendees of conferences he's attended."
- **Critical of vendor claims**: On OpenAI Codex Security's "50% fewer false positives" claim, he questioned: Does that represent actual improvement if the baseline was already problematic? Advocates for transparency about ground truth data.
- On Claude's Firefox 0-day findings: "Pretty cool" but unknowns remain: total spending, timeline, human triage time required, false positive rates.
- Amplified Alex Stamos's prediction: "Five to ten years ago, only ~25 of the Fortune 500 had to seriously worry about 0-day. In 6-9 months it'll be everyone."

Sources:
- https://tldrsec.com/p/tldr-sec-319
- https://tldrsec.com/p/tldr-sec-315

### Brian Krebs (March 2026)

Krebs's coverage of the OpenClaw crisis was the mainstream signal that AI agent security is now a real-world problem:

- "The speed at which these tools have been deployed has far outpaced the development of security frameworks designed to contain them, and that gap is where the trouble lives."
- Documented real incidents: Meta's AI safety director Summer Yue had OpenClaw autonomously mass-delete her email. She stated: "Nothing humbles you like telling your OpenClaw 'confirm before acting' and watching it speedrun deleting your inbox."
- DVULN founder Jamieson O'Reilly: "The robot butlers are useful, they're not going away and the economics of AI agents make widespread adoption inevitable regardless of the security tradeoffs involved."

Source: https://krebsonsecurity.com/2026/03/how-ai-assistants-are-moving-the-security-goalposts/

---

## 2. The OpenClaw Crisis: The Incident That Changed Minds

The single biggest event that moved practitioner opinion from "theoretical" to "this is happening now":

- **OpenClaw** (formerly ClawdBot/Moltbot): Open-source AI agent released November 2025, went viral January 2026 (180K GitHub stars, 2M visitors in one week).
- **CVE-2026-25253** (CVSS 8.8): Token exfiltration via WebSocket leading to full gateway compromise.
- **ClawHavoc supply chain attack**: 341+ malicious skills discovered in ClawHub marketplace (12-20% of registry), delivering Atomic macOS Stealer (AMOS).
- **135,000+ instances** exposed on the public internet, 15,000+ directly vulnerable to RCE.
- **Cline CLI supply chain attack** (February 2026): Compromised npm publish token used to stealthily install OpenClaw on developer systems.

This was the "Log4Shell moment" for AI agents. It made the theoretical real.

Sources:
- https://www.adminbyrequest.com/en/blogs/openclaw-went-from-viral-ai-agent-to-security-crisis-in-just-three-weeks
- https://thehackernews.com/2026/02/cline-cli-230-supply-chain-attack.html

---

## 3. MCP Security: Practitioner Consensus

The Model Context Protocol has generated genuine security concern (not just vendor FUD):

- **Invariant Labs** demonstrated a malicious MCP server silently exfiltrating a user's entire WhatsApp history via "tool poisoning" combined with a legitimate whatsapp-mcp server.
- **GitHub MCP integration exploit** (May 2025): Attackers could hijack AI agents by creating malicious GitHub issues in public repositories.
- **MCPTox benchmark** (2025): Tested 20 LLM agents against 45 real-world MCP servers with 353 tools. o1-mini showed 72.8% attack success rate. More capable models were often more vulnerable because the attack exploits their superior instruction-following abilities.
- **Supabase/Cursor incident** (mid-2025): Cursor agent running with privileged service-role access processed support tickets containing SQL injection, exfiltrating sensitive integration tokens.

Practitioner consensus: MCP itself is not uniquely broken, but the combination of MCP + tool access + untrusted input + eager model compliance = reliable exploitation.

Sources:
- https://www.practical-devsecops.com/mcp-security-vulnerabilities/
- https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
- https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/

---

## 4. Reddit / Hacker News Practitioner Sentiment

### Reddit r/cybersecurity and r/netsec (early 2026)

- **Historical pattern-matching**: "Reddit voices caution against hype, recalling firewall and endpoint 'revolutions' that merely shifted burdens."
- **Operator vs. executive disconnect**: Only 25% of hands-on security operators strongly agree AI tools improve their work, compared to 56% of CISOs. The people closest to the tools are the hardest to impress.
- **AI as force multiplier, not new threat class**: Practitioners see AI amplifying existing attack methods (phishing, vuln scanning, exploit chaining) rather than creating entirely new categories. Top concern: hyper-personalized phishing (50%), followed by automated vulnerability scanning and exploit chaining (45%).
- **"AI hygiene" as governance's new frontier**: Worry about staff summarizing sensitive documents via ChatGPT unaware of retention policies.
- **"AI-washing" as genuinely dangerous**: Every cybersecurity vendor slapping an AI label on their product.

### Hacker News (NIST AI Agent Security thread)

- **Framework skepticism**: "Registration is a compliance checkbox. It tells you an agent exists, not what it's doing." Practitioners advocate runtime behavioral monitoring over pre-deployment certification.
- **API models don't fit**: "API security assumes you can enumerate what a system can do. Agents are different: the action space expands dynamically."
- **Practical validation**: "Every model I tested popped almost every OWASP top 10 challenge we had."
- Overall tone: engaged practitioners taking the problem seriously while criticizing incremental policy responses.

Sources:
- https://elnion.com/2026/01/27/from-phishing-to-ai-chaos-what-my-analysis-of-all-reddit-cybersecurity-discussions-so-far-in-2026-revealed/
- https://news.ycombinator.com/item?id=47131689

---

## 5. Conference Reactions

### RSAC 2026 (March 2026, upcoming/just started)

- **"AI oozing out of every pore"**: Vendor fatigue is palpable.
- **90% of orgs claim AI in security stack, but 75% apply it to less than 10% of their portfolio.** AI is present but not scaled.
- **Cameron Camp (SecureIQLab)**: "Ask for an independent assessment. Right now, many vendors grade their own papers and produce surprisingly good results, but self-testing is as likely to survive real adversarial traffic as not testing at all."
- **Practitioner observation**: "AI fatigue hits hardest when it's presented as some kind of universal deus ex machina for all of our workloads and cyber woes."
- **Frontier AI agents fail 70-95% of real-world tasks** due to consistency issues, hallucinations, and inability to handle complex dependencies.

### fwd:cloudsec 2025

- Vendor-agnostic, practitioner-focused. No sales pitches.
- Specific talk on how AI summarization tools in Google Cloud can become phishing/exfiltration vectors for defenders.
- Community specifically asked: "What AI/ML/LLM security problems do you face in your day job and what sort of knowledge are you lacking?"

### DEF CON AI Village / BSides

- 60+ AI-related talks at 2024 Hacker Summer Camp.
- BSides TLV 2025 had a dedicated AI Hacking Village focused on real-world attack surfaces: model red teaming, prompt injection, data poisoning, adversarial manipulation.
- CoSAI panel at DEF CON 32 highlighted first technical workstreams on advancing AI security.

Sources:
- https://siliconangle.com/2026/03/21/rsac-2026-preview-ai-hype-meets-operating-model-reality/
- https://securityboulevard.com/2026/03/rsa-2026-ai-oozing-out-of-every-pore/
- https://fwdcloudsec.org/conference/north-america/speakers.html

---

## 6. The Prompt Injection Problem: Industry-Wide Acknowledgment

This is now consensus across practitioners, vendors, and researchers:

- **OpenAI** (December 2025): "Prompt injection, much like scams and social engineering on the web, is unlikely to ever be fully 'solved.'"
- **UK NCSC**: LLMs are "inherently confusable deputies." Prompt injection is unlikely to be mitigated the way SQL injection was because there is no robust internal separation between trusted instructions and untrusted content.
- **NVIDIA researchers**: Describe the problem as "control-data plane confusion." There is no principled way for current models to distinguish between instructions and data.
- **Schneier + Raghavan**: The code/data distinction that tamed SQL injection does not exist inside the model.

---

## 7. Are Security Teams Actually Staffing for This?

Mixed signals:

- **88% of organizations** reported confirmed or suspected AI agent security incidents in the last year (92.7% in healthcare).
- **82% of executives** report confidence their existing policies protect against unauthorized agent actions, but only **14.4% of organizations** sent agents to production with full security/IT approval.
- **92% of security professionals** say they're concerned about AI agents across the workforce.
- **44%** are extremely or very concerned about third-party LLMs like Copilot or ChatGPT.
- The [un]prompted conference (March 2026, dedicated to AI for security practitioners) signals a real community forming.
- **BUT**: No clear evidence of widespread "AI security engineer" hiring at the practitioner level. Most orgs are trying to bolt AI security onto existing AppSec/product security roles.

---

## 8. Key Takeaways: The Real Practitioner Consensus

### What's genuinely real:
1. **Prompt injection is architecturally unsolvable** with current LLMs. This is consensus from Schneier, Willison, OpenAI, NCSC, and NVIDIA.
2. **Supply chain attacks on AI tooling are happening now**. OpenClaw/ClawHavoc, Cline CLI compromise, malicious MCP servers.
3. **The Lethal Trifecta is a useful framework**: private data + untrusted input + external communication = exploitable agent.
4. **AI dramatically accelerates offensive capability**: 0-day discovery, phishing personalization, exploit chaining.
5. **Non-human identity management is a real gap**: Agents operate outside traditional IAM, creating ungoverned access.

### What's vendor hype:
1. **"Autonomous SOC"**: At peak of Gartner hype cycle. Agents fail 70-95% of real-world tasks.
2. **"AI-powered" labels**: Most vendor products are existing technology with marketing.
3. **Executive confidence**: 82% of execs say they're covered; 14.4% actually have proper approval processes. This gap is the real risk.
4. **"AI solves security"**: The fundamentals still matter more than whatever's trending.

### What changed practitioners' minds:
1. **OpenClaw crisis** (Jan-Feb 2026): 135K exposed instances, supply chain poisoning, real RCE.
2. **MCPTox research**: 72.8% attack success rate against real MCP servers.
3. **Supabase/Cursor incident**: Real credential exfiltration via AI agent.
4. **Meta incident**: AI safety director's own inbox deleted by misconfigured agent.
5. **Schneier's Promptware Kill Chain**: Reframed the problem from "bug" to "malware class."

### The practitioner mood:
- Not rolling their eyes. Not panicking.
- Frustrated by vendor hype drowning out real technical work.
- Taking concrete threats seriously (supply chain, prompt injection, NHI).
- Skeptical of solutions, demanding evidence and ground truth.
- Drawing parallels to past hype cycles but acknowledging this one has teeth.
- The operator/executive disconnect (25% vs 56% satisfaction) is a major undercurrent.
