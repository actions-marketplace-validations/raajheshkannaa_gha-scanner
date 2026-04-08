# Competitive Intelligence Report: Areas 6, 10, 11
## As of March 2026

---

# AREA 6: SBOM Vulnerability Prioritization with Reachability Context

This space has exploded. Gartner's 2025 Hype Cycle for Application Security named "Reachability Analysis" a high-benefit innovation nearing mainstream adoption, declaring tools without it will be considered outdated. The market is converging around the idea that 90%+ of CVEs are noise. Everyone is racing to prove they can cut through it.

---

## Tier 1: Dominant Commercial Players with Deep Reachability

### Endor Labs
- **URL**: https://www.endorlabs.com
- **What it does**: AI-native AppSec platform with function-level reachability analysis across 40+ languages. Pre-computed reachability without requiring code compilation. Proprietary vulnerability database with function-level annotations back to 2005.
- **Open source / Commercial**: Commercial (freemium)
- **GitHub stars**: N/A (proprietary)
- **Funding/Maturity**: Well-funded startup. Acquired Autonomous Plane (Feb 2026) for full-stack reachability from code to container. Claims 97% alert noise reduction.
- **Covers**: Function-level static reachability, SBOM generation, SCA, secrets, SAST. Now extends reachability into container images post-acquisition.
- **Misses**: No runtime validation (partnered with Oligo for that). Static-only reachability has inherent limits. Newer platform, still building enterprise trust. No DAST.

### Snyk
- **URL**: https://snyk.io
- **What it does**: Developer-first security platform. Reachability analysis for SCA using DeepCode AI. Risk Score combines reachability + CVSS + EPSS + asset context + exploit availability.
- **Open source / Commercial**: Commercial (free tier available)
- **GitHub stars**: N/A (proprietary platform)
- **Funding/Maturity**: Mature. IPO-track. Massive developer adoption (millions of users). One of the largest AppSec companies.
- **Covers**: SCA, SAST, container scanning, IaC scanning, reachability for Java (GA), JavaScript/TypeScript (Early Access). Holistic risk scoring beyond just reachability.
- **Misses**: Reachability language support still limited vs. Endor Labs' 40+. JS/TS reachability still in early access. Less depth in function-level reachability compared to Endor Labs. Sunsetting Snyk Advisor (Jan 2026).

### Semgrep (Semgrep Supply Chain)
- **URL**: https://semgrep.dev
- **What it does**: Lightweight SAST + SCA. Supply Chain product uses reachability rules to determine if vulnerable functions are actually called. Autofix in public beta (2026).
- **Open source / Commercial**: Core engine open source (14,549 GitHub stars, 896 forks). Supply Chain reachability is commercial.
- **GitHub stars**: 14,549
- **Funding/Maturity**: Mature startup. Controversial license change in 2025 (moved cross-function taint analysis to commercial), triggering Opengrep fork.
- **Covers**: SAST, SCA with reachability for Java/Python/Ruby/Go/C#/PHP/JS. 95% false positive reduction claimed. Dataflow-level reachability (not just function-level).
- **Misses**: Reachability rules curated per-vulnerability (not auto-generated), so coverage depends on rule library. Commercial-only for real reachability. PHP reachability only GA mid-2025. No runtime component.

### Wiz
- **URL**: https://www.wiz.io
- **What it does**: Cloud security platform (CNAPP) with agentless + runtime sensor. Wiz Code adds dependency vulnerability scanning with runtime context from Wiz Defend sensor.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Dominant CNAPP. Valued at $12B+. Most well-funded cloud security company.
- **Covers**: Cloud context (internet exposure, identity paths, data sensitivity), runtime validation via sensor (confirms if vulnerable code paths are executed), ASM, code-to-cloud reachability. Attack path analysis.
- **Misses**: Reachability is cloud-context-first, not deep function-level call-graph analysis like Endor Labs. Primarily cloud workload focused. SBOM is secondary to cloud posture. Less depth for non-cloud-deployed applications.

### Apiiro
- **URL**: https://apiiro.com
- **What it does**: ASPM platform with deep code analysis, call flow + data flow + reachability analysis combined with AI reasoning. AI Threat Modeling (March 2026) for design-phase security.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Strong growth: 104% ARR increase in 2025. Recognized as #1 ASPM platform. Named Leader in Latio 2026 AppSec Report.
- **Covers**: Code-to-runtime context, XBOM generation, material change detection, risk graph, AI SAST with reachability-based validation. Prevents risks at design phase.
- **Misses**: Expensive enterprise play. Less runtime depth than Wiz/Oligo. Newer AI threat modeling capabilities unproven at scale.

---

## Tier 2: Runtime Reachability Specialists

### Oligo Security
- **URL**: https://www.oligo.security
- **What it does**: Runtime application security. Observes which functions are actually executed in production using eBPF-based monitoring. Partners with Endor Labs to combine static + runtime reachability.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Funded startup. Partnership with Endor Labs is their key go-to-market strategy. Also partnered with NVIDIA for AI-accelerated vulnerability intelligence.
- **Covers**: Runtime function-level execution monitoring, production reachability validation, AI runtime security. Identifies 1,100+ more vulnerable functions than static analysis alone.
- **Misses**: Requires runtime agent/sensor. Only validates what runs in production (doesn't help with pre-deployment). Dependent on Endor Labs partnership for static side.

### Rezilion
- **URL**: https://www.rezilion.com
- **What it does**: Vulnerability validation through Dynamic SBOM. Uses proprietary forensic methods to reverse-engineer code loading and execution history from host/container snapshots.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Established startup. Launched agentless runtime monitoring. Integrated with GitLab.
- **Covers**: Runtime exploitability validation across 12 languages. Agentless option (snapshot-based forensics). Dynamic SBOM showing both components and execution state. 85% noise reduction claimed. Windows + Linux support.
- **Misses**: Agentless approach may miss transient runtime behavior. Forensic snapshot approach is inherently point-in-time. Smaller vendor compared to Snyk/Wiz.

### Kodem
- **URL**: https://www.kodemsecurity.com
- **What it does**: Runtime intelligence platform that confirms vulnerable code was actually executed in production with function-level evidence. Launched "Kai" agentic AI security engineer at RSAC 2025.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Early-stage startup. Part of Opengrep consortium. Agentic AI positioning (2025-2026).
- **Covers**: Runtime execution evidence, dev-to-prod security. Proves code was executed AND exploited, not just reachable.
- **Misses**: Smaller company, limited market penetration. Requires runtime instrumentation. Less ecosystem integration than larger players.

---

## Tier 3: Cloud/CNAPP Players with Reachability Features

### Orca Security
- **URL**: https://orca.security
- **What it does**: Cloud security platform with patent-pending agentless static reachability analysis (April 2025) plus dynamic runtime reachability. Opengrep backer.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Major CNAPP player. Well-funded.
- **Covers**: Agentless reachability for production workloads, dynamic runtime reachability via telemetry. 90% vulnerability reduction claimed. One customer went from 2.1M vulns to 6 container images to fix.
- **Misses**: Cloud-first focus. Reachability is add-on to CNAPP, not core SCA product. Less depth in call-graph analysis vs Endor Labs.

### ARMO (Kubescape)
- **URL**: https://www.armosec.io
- **What it does**: Kubernetes security platform using eBPF sensors. Kubescape is the open-source foundation (CNCF project). Runtime reachability identifies which libraries are loaded and executed in containers.
- **Open source / Commercial**: Kubescape open source (11,261 stars, 900 forks). ARMO platform is commercial.
- **GitHub stars**: 11,261 (Kubescape)
- **Covers**: Kubernetes-native runtime reachability, 60-80% CVE reduction, auto-generated VEX documents. Integrating EPSS + KEV. 90%+ noise reduction.
- **Misses**: Kubernetes-only. Not useful for non-containerized workloads. VEX auto-generation is innovative but limited to container context.

### Qualys (TruRisk / TruConfirm)
- **URL**: https://www.qualys.com
- **What it does**: Enterprise vulnerability management with TruRisk scoring (combines exploitability, threat intel, asset criticality). TruConfirm (H1 2026 GA) adds automated exploit validation. Agent Val is agentic AI for prioritization.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Public company ($5B+ market cap). Legacy VM leader evolving into exposure management.
- **Covers**: Broad vulnerability management (not just SCA), exploit validation, risk scoring, remediation orchestration. 48K+ CVEs in 2025 context.
- **Misses**: Not SCA-specific. Reachability is network/exploit-path focused, not code-level function reachability. TruConfirm still not GA. Legacy architecture being modernized.

---

## Tier 4: ASPM / Vulnerability Aggregation Platforms

### Ox Security
- **URL**: https://www.ox.security
- **What it does**: Active ASPM with Pipeline Bill of Materials (PBOM). Multi-factor risk prioritization using exploitability, reachability, and business impact. Focuses on "5% of vulns that matter."
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Funded startup. Published 2026 AppSec Benchmark (216M findings across 250 orgs).
- **Covers**: SBOM/PBOM generation (SPDX + CycloneDX), pipeline-level risk, business context prioritization, unified data lake. Organizations face 865K alerts on average, reduced to 795 critical.
- **Misses**: Aggregator, not scanner. Depends on other tools for actual scanning. Reachability via integration, not native analysis.

### Nucleus Security
- **URL**: https://nucleussec.com
- **What it does**: Vulnerability and exposure management platform. Aggregates findings from 160+ tools. Custom risk scoring algorithms. Nucleus 3.0 launched Dec 2025.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: $20M Series C (Feb 2026). FedRAMP Moderate Authorized. Named Strong Performer in Forrester Wave Q3 2025.
- **Covers**: Tool aggregation, custom risk scoring, automation engine, vulnerability intelligence (Nucleus Insights). Wiz integration partner.
- **Misses**: Aggregation platform, not a scanner. No native reachability analysis. Depends on other tools for context.

### Vulcan Cyber (now Tenable)
- **URL**: Acquired by Tenable
- **What it does**: Was a vulnerability remediation platform. Acquired by Tenable for $147M (Feb 2025). ~$25M ARR, ~100 enterprise customers at time of acquisition.
- **Open source / Commercial**: Commercial (now part of Tenable)
- **Funding/Maturity**: Absorbed into Tenable's Exposure Management platform. No longer independent.
- **Covers**: Risk prioritization, third-party data integration, automated remediation orchestration.
- **Misses**: No longer standalone. Subsumed into Tenable's broader platform.

### Seemplicity
- **URL**: https://seemplicity.io
- **What it does**: Remediation orchestration platform. AI agents autonomously prioritize and drive remediation across teams. Processes 1.5B security findings daily.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: $50M Series B (Aug 2025). 800% ARR growth since Series A. 3x customer acquisition growth.
- **Covers**: Vendor-agnostic remediation orchestration, AI-driven prioritization, bottleneck detection, 4x remediation speed improvement.
- **Misses**: Orchestration layer, not scanner. No native reachability. Depends on upstream tools for vuln data.

### Cycode
- **URL**: https://cycode.com
- **What it does**: ASPM platform with SCA reachability analysis. Risk Intelligence Graph (RIG) correlates reachability and exploitability across entire SDLC.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Named Leader in 2025 IDC ASPM MarketScape, 2025 Gartner MQ for AST, and Frost Radar ASPM 2025. Acquired Bearer for AI-powered SAST.
- **Covers**: SCA with reachability, SAST, secrets detection, pipeline security, ASPM. Function-level reachability analysis.
- **Misses**: Reachability coverage depth unclear vs Endor Labs. Newer ASPM entrant compared to established players.

### Legit Security
- **URL**: https://www.legitsecurity.com
- **What it does**: AI-native ASPM. Maps entire SDLC pipeline from source to runtime. Built-in scanners for secrets, IaC, pipeline misconfigurations.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Named Leader in IDC MarketScape ASPM 2025.
- **Covers**: SDLC pipeline security, supply chain attack prevention, ASPM, vulnerability prevention dashboard.
- **Misses**: Less depth in SCA reachability compared to Endor Labs/Semgrep. More pipeline-security focused than vuln prioritization.

---

## Tier 5: Specialized / Niche Players

### Backslash Security
- **URL**: https://www.backslash.security
- **What it does**: ASPM with "triggerability analysis" (reachable AND exploitable). Digital twin approach (Backslash App Graph). LLM-driven business process impact analysis.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Early-stage. Pivoting to "Vibe Coding Security" and MCP/Agentic AI in 2026.
- **Covers**: Code-to-cloud reachability, triggerability (beyond reachability), SAST+SCA fusion, 80% vulnerability reduction claimed.
- **Misses**: Small company. Unproven at scale. "Triggerability" branding is unique but market adoption unclear.

### Finite State
- **URL**: https://finitestate.io
- **What it does**: SBOM and vulnerability management for firmware/connected devices. Reachability coverage expanded to 90%+ of detected CVEs.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: Niche player in firmware/IoT security.
- **Covers**: Firmware binary analysis, SBOM lifecycle, reachability for connected products, CRA compliance.
- **Misses**: Firmware-only focus. Not applicable to general application security.

### Mend.io (formerly WhiteSource)
- **URL**: https://www.mend.io
- **What it does**: SCA with reachability analysis for direct and transitive dependencies. Call graph analysis. EPSS integration.
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A (Renovate Bot is open source)
- **Funding/Maturity**: Mature. Forrester Wave Strong Performer for SCA (Q4 2024). Gartner MQ Visionary for AST (2025).
- **Covers**: SCA, reachability, auto-remediation (Merge Confidence), EPSS scoring, license compliance.
- **Misses**: Reachability depth unclear vs Endor Labs. Less buzz in 2025-2026 market compared to newer entrants.

### Xygeni
- **URL**: https://xygeni.io
- **What it does**: All-in-one AppSec platform covering code, pipelines, cloud, and supply chain. SLSA and in-toto attestation support.
- **Open source / Commercial**: Commercial
- **GitHub stars**: Minimal
- **Funding/Maturity**: Smaller European vendor.
- **Covers**: SCA, pipeline composition analysis, build attestation, SLSA compliance, malicious package detection.
- **Misses**: Limited reachability analysis. Smaller market presence. Trying to cover too many areas.

---

## Open Source SBOM & Vulnerability Tools

### Syft (Anchore)
- **URL**: https://github.com/anchore/syft
- **What it does**: CLI tool and library for generating SBOMs from container images and filesystems. Supports SPDX and CycloneDX output.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: 8,555 / 787 forks
- **Funding/Maturity**: Backed by Anchore (commercial parent). Very active. 219 contributors. v1.42.0 (Feb 2026).
- **Covers**: SBOM generation across dozens of package ecosystems. Offline operation. Signed SBOM attestations. GitHub Action available.
- **Misses**: Generation only. No vulnerability scanning (pair with Grype). No reachability analysis. No prioritization.

### Grype (Anchore)
- **URL**: https://github.com/anchore/grype
- **What it does**: Vulnerability scanner for container images and filesystems. Consumes SBOMs from Syft to match against vulnerability databases.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: 11,802 / 759 forks
- **Funding/Maturity**: Very active. Backed by Anchore. Locally cached SQLite vulnerability database.
- **Covers**: OS and language-specific package scanning, VEX consumption, CI/CD integration. Fast local scanning.
- **Misses**: No reachability analysis. No prioritization beyond severity. No call-graph analysis. Simple match-and-report.

### Trivy (Aqua Security)
- **URL**: https://github.com/aquasecurity/trivy
- **What it does**: All-in-one security scanner. Vulnerability, misconfiguration, secrets, SBOM generation, license scanning.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: 33,979 / 192 forks (Note: low fork count may be API anomaly)
- **Funding/Maturity**: Very mature. Backed by Aqua Security. CNCF project. Most popular open-source vulnerability scanner.
- **Covers**: Container images, filesystems, git repos, Kubernetes, IaC. SBOM in CycloneDX/SPDX. VEX support for filtering results.
- **Misses**: No reachability analysis. Basic severity-based prioritization. VEX consumption but not generation.

### OWASP Dependency-Track
- **URL**: https://dependencytrack.org
- **What it does**: Continuous SBOM analysis platform. Ingests SBOMs and continuously monitors for new vulnerabilities. Integrates with NVD, OSV, GitHub, Snyk, VulnDB.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: 3,684 / 715 forks
- **Funding/Maturity**: OWASP Flagship project. Mature and widely deployed.
- **Covers**: Persistent component inventory, continuous monitoring, VEX production/consumption (CycloneDX), policy evaluation, multi-project portfolio management.
- **Misses**: No reachability analysis. No call-graph analysis. SBOM consumer, not generator. Basic prioritization.

### cdxgen (CycloneDX Generator)
- **URL**: https://github.com/CycloneDX/cdxgen
- **What it does**: Multi-ecosystem SBOM generator in CycloneDX format. Supports 20+ package ecosystems.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: ~700+
- **Funding/Maturity**: Part of CycloneDX project. Active development.
- **Covers**: SBOM generation across many ecosystems. CI/CD friendly.
- **Misses**: Generation only. No scanning, no reachability, no prioritization.

### OWASP dep-scan
- **URL**: https://github.com/owasp-dep-scan/dep-scan
- **What it does**: Security and risk audit tool. Generates SBOM with VDR info, produces CSAF 2.0 VEX documents. Package risk audit for npm/PyPI. Claims reachability analysis for multiple languages.
- **Open source / Commercial**: Open source
- **GitHub stars**: 1,212 / 127 forks
- **Funding/Maturity**: OWASP project. NLnet funded. Active development.
- **Covers**: SBOM generation, VEX/CSAF production, vulnerability scanning, package risk audit, reachability analysis. Unusually feature-rich for OSS.
- **Misses**: Less proven reachability compared to commercial tools. Smaller community than Trivy/Grype.

### Narrow (Duo Labs)
- **URL**: https://github.com/duo-labs/narrow
- **What it does**: Low-effort reachability analysis for third-party code vulnerabilities.
- **Open source / Commercial**: Open source
- **GitHub stars**: 22
- **Funding/Maturity**: Minimal activity. Research project from Duo Labs.
- **Covers**: Basic reachability checking.
- **Misses**: Essentially abandoned. Very limited scope.

---

## VEX (Vulnerability Exploitability Exchange) Tools

### OpenVEX
- **URL**: https://openssf.org/projects/openvex/
- **What it does**: OpenSSF project defining an open, minimal VEX format. Tooling for creating and consuming VEX documents.
- **Open source / Commercial**: Open source
- **Funding/Maturity**: OpenSSF project. Growing adoption.

### CycloneDX VEX
- **URL**: https://cyclonedx.org/capabilities/vex/
- **What it does**: VEX capabilities built into CycloneDX SBOM standard. Inline vulnerability exploitability status in SBOMs.
- **Open source / Commercial**: Open source standard
- **Funding/Maturity**: OWASP project. ISO-standardized. Widely supported.

### CSAF VEX
- **What it does**: Common Security Advisory Framework for VEX. Used by large vendors (Microsoft, Red Hat).
- **Maturity**: Microsoft began publishing machine-readable VEX for Azure Linux (Oct 2025).

### vexy
- **URL**: https://github.com/madpah/vexy
- **What it does**: Generate VEX CycloneDX documents from Python projects.
- **Open source / Commercial**: Open source
- **GitHub stars**: 23

---

## EPSS Integration

### FIRST EPSS
- **URL**: https://www.first.org/epss/
- **What it does**: Exploit Prediction Scoring System. ML model predicting 0-1 probability of CVE exploitation within 30 days. Version 4 released March 2025. Free CSV/API.
- **Covers**: Daily probability scores for every CVE. Free and open data. Integrated into Snyk, Endor Labs, Mend, Qualys, ARMO, Arnica, and most commercial tools.
- **Misses**: Probabilistic model, not deterministic. Does not consider your specific environment. Supplement to, not replacement for, reachability.

---

# AREA 10: Context-Aware Developer Security (Shift-Left That Actually Works)

This space is in a gold rush. The thesis: developers will only fix security issues if the tools are embedded in their workflow, low-noise, and auto-fixable. Every vendor claims "developer-first." The real differentiator is noise reduction + auto-remediation quality.

---

## Tier 1: Platform Leaders

### Snyk
- **URL**: https://snyk.io
- **What it does**: The original "developer-first security" platform. SCA, SAST (DeepCode AI), container scanning, IaC scanning. IDE plugins, PR checks, CLI.
- **Open source / Commercial**: Commercial (free tier)
- **Funding/Maturity**: IPO-track. Millions of developers. The benchmark everyone else is measured against.
- **Covers**: Full AppSec stack. IDE integration (VS Code, IntelliJ). PR decoration. CLI scanning. Reachability. Auto-fix PRs via Dependabot-style upgrades. Snyk Learn for developer education.
- **Misses**: Alert fatigue complaints from users despite reachability. Pricing increases have frustrated smaller teams. JS/TS reachability still early access. Advisor being sunset.

### GitHub Advanced Security (CodeQL + Dependabot + Secret Scanning)
- **URL**: https://github.com/security/plans
- **What it does**: Native security built into GitHub. Restructured April 2025 into GitHub Secret Protection ($19/committer/mo) and GitHub Code Security (separate product).
- **Open source / Commercial**: CodeQL engine is open source. GitHub Advanced Security features are commercial (included in GitHub Enterprise, new standalone products for Team plan).
- **GitHub stars**: N/A (platform)
- **Funding/Maturity**: Microsoft-backed. Ubiquitous. Dependabot is the most widely used dependency update tool globally.
- **Covers**: CodeQL (semantic SAST), Dependabot (dependency updates + alerts), secret scanning with push protection, AI-detected passwords, dependency review, security overview dashboard. Copilot Autofix for CodeQL findings.
- **Misses**: CodeQL limited to supported languages. No reachability analysis for SCA. Dependabot is upgrade-focused, not vuln-prioritization-focused. Secret scanning scope limited to known patterns. Tied to GitHub ecosystem.

### GitLab Security
- **URL**: https://about.gitlab.com/solutions/application-security-testing/
- **What it does**: Built-in SAST, DAST, SCA, container scanning, IaC scanning, secret detection in GitLab CI/CD. Advanced SAST replacing legacy Semgrep-based analyzers.
- **Open source / Commercial**: GitLab Ultimate tier (commercial). Some features in free tier.
- **GitHub stars**: N/A (platform)
- **Funding/Maturity**: Public company. One-platform DevSecOps approach.
- **Covers**: Full security suite in single platform. AI false positive flagging (Duo add-on). Agentic SAST vulnerability resolution (auto-fix MRs). Incremental scanning on 2026 roadmap. Security Dashboard.
- **Misses**: Requires GitLab Ultimate for full features ($99/user/mo). Advanced SAST limited language support (C/C++/C#/Go/Java/JS/Python/Ruby/TS). Quality of scanners historically behind dedicated tools. Tied to GitLab ecosystem.

### Semgrep
- **URL**: https://semgrep.dev
- **What it does**: Lightweight, pattern-based SAST + SCA. Rules look like source code. Supply Chain product adds reachability. Autofix in public beta (2026).
- **Open source / Commercial**: Core engine open source (14,549 stars). Pro features commercial.
- **GitHub stars**: 14,549
- **Funding/Maturity**: Established. 2025 license controversy led to Opengrep fork, but company continues growing.
- **Covers**: Fast SAST with custom rules, SCA with reachability, secrets detection, autofix. PR-level integration. IDE support. Supply chain malicious dependency detection.
- **Misses**: License change alienated open-source community. Cross-function taint analysis now commercial-only. Rule-based reachability requires curated rules per vulnerability. No runtime component.

### Aikido Security
- **URL**: https://www.aikido.dev
- **What it does**: Unified security platform from code to cloud to runtime. "No BS" approach. Replaces fragmented tools with single platform.
- **Open source / Commercial**: Commercial ($50/dev/mo with all features). Opengrep backer.
- **GitHub stars**: N/A (proprietary)
- **Funding/Maturity**: $60M Series B at $1B valuation (Jan 2026). 100K+ teams. Customers include Premier League, SoundCloud, Revolut. 5x revenue growth in past year.
- **Covers**: SAST (via Opengrep), SCA, secrets, IaC, DAST, CSPM, container scanning, malware detection, runtime protection. All-in-one at flat rate.
- **Misses**: Jack-of-all-trades risk. Depth of individual scanners may not match dedicated tools. Young platform (founded 2022). European company, less US enterprise penetration.

---

## Tier 2: Auto-Remediation Specialists

### Moderne (OpenRewrite)
- **URL**: https://www.moderne.ai / https://github.com/openrewrite/rewrite
- **What it does**: Automated large-scale code refactoring. Deterministic, AST-based recipes for security fixes, framework migrations, dependency upgrades across thousands of repos simultaneously.
- **Open source / Commercial**: OpenRewrite is open source (3,354 stars, 516 forks). Moderne platform is commercial.
- **GitHub stars**: 3,354 (OpenRewrite core)
- **Funding/Maturity**: Established. Growing ecosystem. AI agent "Moddy" combines recipes with LLM.
- **Covers**: OWASP Top 10 remediation recipes, SCA remediation, framework migration, code compliance. Deterministic (not AI-hallucination-prone). Multi-repo at scale.
- **Misses**: Primarily Java/JVM ecosystem. Recipe library depth varies by language. Remediation only, not detection. Requires existing scanner for findings.

### Mobb
- **URL**: https://mobb.ai
- **What it does**: Vendor-agnostic auto-remediation. Ingests SAST results from Checkmarx, CodeQL, Fortify, Snyk and produces code fixes. Combines semantic analysis with GenAI.
- **Open source / Commercial**: Commercial (community edition available). Bugsy CLI is open source (66 stars).
- **GitHub stars**: 66 (Bugsy)
- **Funding/Maturity**: Startup. Checkmarx partnership. Part of Opengrep consortium.
- **Covers**: 100+ issue types. "PowerUp" batch fixing. 99% time-to-remediation reduction claimed. Scanner-agnostic.
- **Misses**: Depends on upstream scanner quality. Fix accuracy varies by issue type. Small company.

### Pixee
- **URL**: https://www.pixee.ai
- **What it does**: "Automated product security engineer." Triages and fixes issues from code scanning tools. Opens ready-to-merge PRs. Agentic AI + deterministic techniques.
- **Open source / Commercial**: Commercial. On-premises deployment option.
- **GitHub stars**: Some open source components on github.com/pixee
- **Funding/Maturity**: $15M seed (May 2025). Early stage but growing fast.
- **Covers**: 95% noise reduction, 76% PR merge rate, 91% developer remediation time reclaimed. Integrates with existing scanners. GitHub, GitLab, Azure DevOps support.
- **Misses**: Early stage. Merge rate implies 24% of fixes are rejected. Depends on upstream scanner quality.

### Seal Security
- **URL**: https://www.seal.security
- **What it does**: Standalone security patches for open source vulnerabilities. Patches can be applied independently from regular version upgrades. Autonomous agentic remediation (March 2026).
- **Open source / Commercial**: Commercial
- **GitHub stars**: N/A
- **Funding/Maturity**: $13M raised (July 2025). Israeli startup. Wiz partnership for pre-patched base images.
- **Covers**: 95%+ critical/high vuln remediation. 72-hour SLA. Standalone patches (no version upgrade required). Autonomous agent that finds gaps, applies patches, runs tests, asks human for approval. Seal OS for Linux.
- **Misses**: Patch approach may have compatibility risks. Standalone patches diverge from upstream. Limited to known CVEs.

---

## Tier 3: PR Security Review / AI Code Review

### CodeRabbit
- **URL**: https://www.coderabbit.ai
- **What it does**: AI-powered PR review bot. Most installed AI app on GitHub/GitLab. 40+ linters and SAST tools under the hood with LLM filtering.
- **Open source / Commercial**: Commercial (free for open source). ai-pr-reviewer open source (2,072 stars, 518 forks).
- **GitHub stars**: 2,072 (ai-pr-reviewer)
- **Funding/Maturity**: 2M+ repos connected, 13M+ PRs reviewed. SOC 2 Type II certified. Had security vulnerability (RCE) in Jan 2025, quickly remediated.
- **Covers**: Automated PR review with security focus, 40+ integrated scanners, line-by-line comments, summary generation, zero data retention.
- **Misses**: Security is secondary to code quality. LLM-based review has false positive/negative rates. Jan 2025 RCE vulnerability raises trust questions. Not a dedicated security tool.

### Opengrep
- **URL**: https://www.opengrep.dev / https://github.com/opengrep/opengrep
- **What it does**: Open-source SAST engine forked from Semgrep CE (Jan 2025) after Semgrep's license change. Backed by 10+ AppSec companies (Aikido, Endor Labs, Jit, Orca, Kodem, Legit, Mobb, etc.).
- **Open source / Commercial**: Open source (LGPL-2.1)
- **GitHub stars**: 2,303 / 187 forks
- **Funding/Maturity**: Consortium-backed. Dedicated OCaml dev team. Fully backward-compatible with Semgrep rules.
- **Covers**: Cross-function taint tracking across 12 languages (restored from Semgrep commercial), Visual Basic support, SARIF output. Drop-in Semgrep replacement.
- **Misses**: Young fork. Community momentum unclear long-term. No commercial platform wrapping it (each backer integrates differently). No reachability analysis (engine only).

### Jit Security
- **URL**: https://www.jit.io
- **What it does**: Agentic ASPM platform. 11 scanners (SAST, SCA, secrets, IaC, CSPM, K8s, DAST) unified. MCP Server for developer integration. AI agents for investigation and remediation.
- **Open source / Commercial**: Commercial ($50/dev/mo). Opengrep backer.
- **GitHub stars**: N/A
- **Funding/Maturity**: Funded startup. Strong Gartner Peer Insights reviews.
- **Covers**: Multi-scanner orchestration, agentic AI remediation, MCP Server for IDE integration, human-in-the-loop fixes.
- **Misses**: Orchestrator, not scanner. Depends on underlying tool quality. Smaller vendor.

### Arnica
- **URL**: https://www.arnica.io
- **What it does**: AppSec platform with developer behavior analysis. Anomalous behavior detection, automatic security champion identification, dynamic backlog management.
- **Open source / Commercial**: Commercial. Opengrep backer.
- **GitHub stars**: N/A
- **Funding/Maturity**: Startup. Launched "Arnie AI" (Nov 2025) for agentic AppSec.
- **Covers**: SAST, SCA, IaC, secrets. Unique: developer behavior scoring, insider threat detection, security champion identification based on actual behavior. Dynamic risk re-evaluation.
- **Misses**: Behavior analysis is novel but unproven at scale. Smaller company. Developer profiling may face privacy pushback.

---

## Tier 4: Supply Chain Focused

### Socket
- **URL**: https://socket.dev
- **What it does**: Proactive supply chain security. Detects malicious packages by analyzing behavior (network access, filesystem ops, obfuscated code) rather than CVE matching.
- **Open source / Commercial**: Commercial (free for open source)
- **GitHub stars**: N/A (proprietary)
- **Funding/Maturity**: 10K+ organizations. ~100 employees. Fortune Cyber 60. Joined TC54 for CycloneDX/PURL standards. npm registry integration (Feb 2026).
- **Covers**: 10+ ecosystems. Real-time malicious package detection. Behavioral analysis for JS and Python. npm registry now links to Socket analysis. Active research team exposing campaigns.
- **Misses**: Behavioral analysis depth varies by ecosystem (full for JS/Python, limited for others). Not a traditional SCA tool. Doesn't do SAST or secrets.

### Phylum (now Veracode)
- **URL**: Acquired by Veracode (Jan 2025)
- **What it does**: ML-powered malicious package detection. Typosquatting, dependency confusion, compromised maintainer detection.
- **Open source / Commercial**: Technology acquired by Veracode. Some open source tools on GitHub (github.com/phylum-dev).
- **Funding/Maturity**: No longer independent. 60% more accurate malicious package detection claimed post-integration.
- **Covers**: Malicious package detection across npm, PyPI, and more. Now integrated into Veracode SCA.
- **Misses**: No longer standalone product. Requires Veracode subscription.

### Chainguard
- **URL**: https://www.chainguard.dev
- **What it does**: Zero-CVE container base images, libraries, and VMs. 1,700+ minimal images across modern stacks. Built from source with full provenance.
- **Open source / Commercial**: Commercial (images). Wolfi OS is open source.
- **GitHub stars**: N/A (images, not traditional OSS project)
- **Funding/Maturity**: $356M Series D at $3.5B valuation. Total funding $892M. $40M ARR growing to $100M+ by end 2026. 150+ customers for VMs.
- **Covers**: Container images, libraries, VMs. Zero known CVEs at build time. Cloud marketplace integration. SBOM included with every image.
- **Misses**: Preventive approach (zero-CVE images) vs. detection approach. Doesn't scan your code. Doesn't help with first-party vulnerabilities. Expensive compared to community images.

### Sonatype Repository Firewall
- **URL**: https://www.sonatype.com/products/sonatype-repository-firewall
- **What it does**: Blocks malicious packages at the repository proxy level before they enter development environments. AI/ML-powered detection.
- **Open source / Commercial**: Commercial. Nexus Repository OSS is open source.
- **GitHub stars**: N/A (commercial)
- **Funding/Maturity**: Long-established. Discovered 845K+ malicious packages total. Blocked 120K malware attacks in Q4 2025 alone. Q4 2025 saw 394,877 new malicious packages (476% increase vs prior 3 quarters).
- **Covers**: npm, PyPI, and more. Hugging Face model protection (2025). Zscaler integration. API for real-time malware insights. Repository-level blocking.
- **Misses**: Proxy-based architecture requires deployment in front of package managers. Expensive enterprise product. Detection focused on malware, not vulnerabilities.

---

## Tier 5: Policy-as-Code / Security-as-Code Tools

### OPA (Open Policy Agent)
- **What it does**: General-purpose policy engine. Rego language for expressing security policies.
- **Maturity**: CNCF Graduated. Foundation for many security-as-code tools.

### Checkov (Prisma Cloud)
- **What it does**: Open-source static analysis for IaC. Policy-as-code for Terraform, CloudFormation, Kubernetes, Helm, Pulumi.
- **Maturity**: Widely adopted. Part of Palo Alto's Prisma Cloud.

### Terrascan (Tenable)
- **What it does**: Open-source IaC static analysis with policy enforcement.
- **Maturity**: Part of Tenable portfolio.

### Biome
- **URL**: https://biomejs.dev
- **What it does**: Rust-based linter + formatter for JavaScript/TypeScript. 423+ lint rules including security-relevant rules. 10-56x faster than ESLint.
- **Open source / Commercial**: Open source
- **Funding/Maturity**: v2.3 (Jan 2026). Type-aware lint rules on 2026 roadmap. Vercel-sponsored.
- **Covers**: JS/TS linting with some security rules. Extremely fast. All-in-one replacement for ESLint + Prettier.
- **Misses**: Security rules are basic (correctness/suspicious patterns, not vuln-specific). Not a security tool. No SAST-level analysis. No SCA.

---

# AREA 11: Open Source Dependency Health Scoring

This space is fragmented. No single tool provides a comprehensive, real-time "health score" for every dependency. Most tools cover a subset of signals. The market is consolidating (Sonar acquired Tidelift, Veracode acquired Phylum, Snyk sunsetting Advisor).

---

## Tier 1: The Big Players

### OpenSSF Scorecard
- **URL**: https://scorecard.dev / https://github.com/ossf/scorecard
- **What it does**: Automated security health metrics for open source projects. Runs 20+ checks (CI tests, branch protection, dependency pinning, fuzzing, signed releases, maintained status, vulnerabilities, license, etc.). Scores each check 0-10.
- **Open source / Commercial**: Open source (Apache 2.0)
- **GitHub stars**: 5,323 / 617 forks
- **Funding/Maturity**: OpenSSF flagship project. CISA endorsement. Weekly scan of 1M most critical OSS projects. V5 released with structured results. BigQuery public dataset.
- **Covers**: Project-level security health across GitHub repos. Checks: Binary Artifacts, Branch Protection, CI Tests, CII Best Practices, Code Review, Contributors, Dangerous Workflow, Dependency Update Tool, Fuzzing, License, Maintained, Packaging, Pinned Dependencies, SAST, Security Policy, Signed Releases, Token Permissions, Vulnerabilities, Webhooks.
- **Misses**: GitHub-only (no PyPI/npm package-level scoring directly). Checks are heuristic-based. A high score doesn't guarantee the code is secure. Doesn't check code quality. Binary scoring (some checks are pass/fail disguised as 0-10). No malicious package detection. Repo-level, not package-version-level.

### deps.dev (Google Open Source Insights)
- **URL**: https://deps.dev
- **What it does**: Visualization and analysis of open source package dependency graphs. Shows vulnerabilities, licenses, OpenSSF Scorecard data, and dependency relationships.
- **Open source / Commercial**: Free service by Google. API and BigQuery dataset available.
- **GitHub stars**: N/A (web service)
- **Funding/Maturity**: Google-backed. Covers Cargo, Go, Maven, npm, NuGet, PyPI, RubyGems. Integrates GitHub, GitLab, Bitbucket, and OSV advisories.
- **Covers**: Dependency graph visualization, version comparison, vulnerability advisories, license info, Scorecard integration, "code health and safety" signals.
- **Misses**: Read-only visualization. No blocking/enforcement. No malicious package detection. No maintainer health scoring. No "bus factor" analysis. Limited to indexed ecosystems.

### Snyk Advisor (sunsetting)
- **URL**: https://snyk.io/advisor
- **What it does**: Package health scoring across npm, PyPI, Go, and more. Scores based on security, maintenance, community engagement, popularity.
- **Open source / Commercial**: Free (was part of Snyk's free tier)
- **GitHub stars**: N/A
- **Funding/Maturity**: Being sunset January 2026, replaced by Snyk Security DB.
- **Covers**: Health score categories (Healthy/Sustainable/Risky). Security vulnerability status, maintenance frequency, community size, download trends.
- **Misses**: Being discontinued. Replacement (Security DB) scope unclear. Was one of the best free package health tools.

### Socket
- **URL**: https://socket.dev
- **What it does**: Beyond health scoring, performs behavioral analysis of packages. Detects malicious code, typosquatting, dependency confusion, install scripts, network access, filesystem operations.
- **Open source / Commercial**: Commercial (free for open source)
- **Funding/Maturity**: 10K+ orgs. npm registry integration. Fortune Cyber 60.
- **Covers**: Real-time package behavior analysis. Proactive detection of malicious packages. Package metadata analysis. 10+ ecosystems.
- **Misses**: Not a traditional "health score" tool. Focused on malicious/suspicious behavior, not maintainer health or community metrics.

### Libraries.io
- **URL**: https://libraries.io
- **What it does**: Monitors 2M+ packages across 36 package managers. Tracks releases, dependencies, contributors, licenses.
- **Open source / Commercial**: Open source (GitHub stars: 1,145)
- **GitHub stars**: 1,145 / 212 forks
- **Funding/Maturity**: Long-standing project. Dataset available on Zenodo. Volunteer-maintained.
- **Covers**: Release monitoring, dependency mapping, license detection, outdated/deprecated/unmaintained package flagging, SourceRank scoring.
- **Misses**: Limited active development. No malicious package detection. No security-specific scoring. Dataset can lag. No enforcement capabilities. Volunteer-maintained means uncertain future.

---

## Tier 2: Enterprise/Commercial Platforms

### Sonatype (Nexus + Repository Firewall)
- **URL**: https://www.sonatype.com
- **What it does**: Repository management + malicious package blocking + vulnerability intelligence. OSS Index provides free vulnerability data.
- **Open source / Commercial**: Nexus Repository OSS is open source. Lifecycle and Firewall are commercial.
- **Funding/Maturity**: Long-established market leader. Discovered 845K+ malicious packages. Published annual State of Software Supply Chain reports for 10+ years.
- **Covers**: Component intelligence, malicious package detection (AI/ML), policy enforcement, Hugging Face model scanning, repository proxy with blocking. Q4 2025: 394K new malicious packages detected.
- **Misses**: Expensive enterprise product. OSS Index is limited. Full value requires Nexus Lifecycle + Firewall. More focused on blocking than health scoring.

### Tidelift (now Sonar)
- **URL**: https://tidelift.com (acquired by Sonar, Dec 2024)
- **What it does**: Pays open source maintainers to implement security and maintenance practices. Provides health assessments based on maintainer partnerships.
- **Open source / Commercial**: Commercial
- **Funding/Maturity**: Acquired by Sonar (SonarSource). Previously raised $27M+. Unique maintainer-partnership model.
- **Covers**: Maintainer health verification, paid maintainer incentives (55% more likely to implement security practices), license compliance, security attestations. Tracks "independently maintained" vs "partnered" status.
- **Misses**: Coverage limited to packages with Tidelift-partnered maintainers. Now absorbed into Sonar, future direction unclear. Doesn't cover all packages. Model depends on maintainer participation.

---

## Tier 3: Malicious Package Detection Tools

### GuardDog (Datadog)
- **URL**: https://github.com/DataDog/guarddog
- **What it does**: CLI tool to identify malicious PyPI and npm packages using static code analysis heuristics.
- **Open source / Commercial**: Open source
- **GitHub stars**: 1,022 / 85 forks
- **Funding/Maturity**: Backed by Datadog Security Labs. Active development.
- **Covers**: Malicious code detection in PyPI and npm. Typosquatting detection. Install script analysis. Network behavior analysis.
- **Misses**: PyPI and npm only. Heuristic-based (false positives). No health scoring. CLI tool, not platform.

### OpenSSF Package Analysis
- **URL**: https://github.com/ossf/package-analysis
- **What it does**: Sandboxed execution of packages from PyPI, npm, and others. Captures commands, network traffic, filesystem access to detect malicious behavior.
- **Open source / Commercial**: Open source
- **GitHub stars**: 867 / 64 forks
- **Funding/Maturity**: OpenSSF project. Powers the Malicious Packages Repository.
- **Covers**: Dynamic analysis of newly published packages. Behavioral detection. Results published to OpenSSF Malicious Packages repo (OSV format).
- **Misses**: Detection-focused, not scoring. Limited to newly published packages. Dynamic analysis has execution risks. Not meant for direct developer consumption.

### OpenSSF Malicious Packages Repository
- **URL**: https://github.com/ossf/malicious-packages
- **What it does**: Cross-ecosystem database of reported malicious packages in OSV format.
- **Open source / Commercial**: Open source
- **Funding/Maturity**: OpenSSF project. Feeds into OSV.dev.
- **Covers**: Known malicious package reports across ecosystems. Machine-readable (OSV format).
- **Misses**: Reactive (reports after discovery). Not real-time blocking. Incomplete coverage.

---

## Tier 4: Specialized / Niche Tools

### NodeSecure
- **URL**: https://github.com/NodeSecure
- **What it does**: JavaScript/Node.js security CLI. Deep dependency tree analysis with security flags, license detection, SPDX conformance, first-class OpenSSF Scorecard support.
- **Open source / Commercial**: Open source
- **GitHub stars**: ~200 (across repos)
- **Funding/Maturity**: Community project. 20 contributors on scanner package. Active (Jan 2025 updates).
- **Covers**: npm dependency analysis, security threat flags, license detection, vulnerability linking, Scorecard integration.
- **Misses**: npm-only. Small community. Not enterprise-ready.

### dep-age
- **URL**: https://github.com/AdametherzLab/dep-age
- **What it does**: Detect abandoned npm dependencies. Health scores, CLI, GitHub Action.
- **Open source / Commercial**: Open source
- **GitHub stars**: 1
- **Misses**: Extremely early. npm-only.

### still_active
- **URL**: https://github.com/SeanLF/still_active
- **What it does**: Audit Gemfile for dependency health: maintenance activity, outdated versions, archived repos, OpenSSF Scorecard.
- **Open source / Commercial**: Open source
- **GitHub stars**: 9
- **Misses**: Ruby/Gemfile only. Tiny project.

### PkgPulse
- **URL**: https://www.pkgpulse.com
- **What it does**: Blog/analysis platform comparing package ecosystem health and tooling decisions.
- **Misses**: Not a tool, just analysis content.

---

## Cross-Cutting: SBOM Standards

| Standard | Status | Best For |
|----------|--------|----------|
| **CycloneDX** (OWASP) | 1.6+ (2025). Developer-friendly. Best vuln correlation. VEX support. | Application security, developer workflows |
| **SPDX** (Linux Foundation) | 3.0 (2024). ISO/IEC 5962:2021. | License compliance, regulatory, government |
| **SWID Tags** (ISO) | Legacy. | Asset management |

---

## Summary: Key Market Dynamics (March 2026)

### Area 6 (SBOM Vuln Prioritization)
1. **Reachability is table stakes.** Every serious SCA vendor now has or is building reachability analysis. The differentiation is shifting to runtime validation (Oligo, Kodem, Rezilion) and agentic auto-fix.
2. **Static vs. Runtime split.** Endor Labs and Semgrep lead static reachability. Oligo and Kodem lead runtime. Wiz and Orca blend both via cloud context. The winners will combine all three.
3. **VEX is maturing.** Microsoft publishing VEX for Azure Linux (Oct 2025) was a watershed. ARMO/Kubescape auto-generating VEX is innovative. Expect VEX to become mandatory in regulated industries.
4. **EPSS is now standard.** Integrated into nearly every commercial tool. V4 (March 2025) improved accuracy. Free and open.
5. **Consolidation accelerating.** Tenable acquired Vulcan Cyber ($147M). Endor Labs acquired Autonomous Plane. Sonar acquired Tidelift. Veracode acquired Phylum.

### Area 10 (Developer Security)
1. **Auto-remediation is the new battleground.** Pixee (76% merge rate), Mobb (99% time reduction), Seal Security (autonomous patches), Moderne/OpenRewrite (deterministic refactoring) are all attacking the "last mile" problem.
2. **Agentic AI is everywhere.** Kodem's Kai, Arnica's Arnie, Jit's AI Agents, Qualys Agent Val, Apiiro Guardian Agent. Every vendor launched an "agentic" product in 2025-2026.
3. **Opengrep is a real fork.** 2,303 stars, 10+ backing companies, dedicated dev team. The open-source SAST engine now has a viable alternative to Semgrep CE.
4. **Aikido is the fastest-growing challenger.** $1B valuation, 100K+ teams, $50/dev/mo all-inclusive. The anti-Snyk.
5. **GitHub and GitLab are the sleeping giants.** Native platform security (CodeQL, Dependabot, secret scanning, Advanced SAST) reaches every developer by default. Limited depth but unmatched distribution.

### Area 11 (Dependency Health Scoring)
1. **No comprehensive solution exists.** OpenSSF Scorecard is the closest but is repo-level, GitHub-only, and heuristic-based. deps.dev is read-only. Snyk Advisor is being sunset. Libraries.io is volunteer-maintained.
2. **Malicious package detection is the hot sub-segment.** Socket, Sonatype, Phylum/Veracode, GuardDog, OpenSSF Package Analysis. Sonatype discovered 394K malicious packages in Q4 2025 alone (476% QoQ increase).
3. **"Bus factor" and maintainer health remain unsolved.** Tidelift was the only company seriously addressing maintainer sustainability, and they got acquired by Sonar. No one else is paying maintainers.
4. **The gap is real.** There is no free, comprehensive, real-time, multi-ecosystem dependency health scoring platform that combines: security vulns + maintainer activity + community health + malicious package detection + license compliance + bus factor analysis + EPSS/KEV data.

Sources:
- [Endor Labs Reachability SCA](https://www.endorlabs.com/use-cases/reachability-sca)
- [Endor Labs Acquires Autonomous Plane](https://www.prnewswire.com/news-releases/endor-labs-acquires-autonomous-plane-expanding-ai-native-application-security-with-full-stack-reachability-from-code-to-container-302684888.html)
- [Semgrep Reachability Blog](https://semgrep.dev/blog/2025/what-you-should-know-about-dependency-reachability-in-sca/)
- [Snyk Reachability Analysis Docs](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis)
- [Wiz Code](https://www.wiz.io/platform/wiz-code)
- [Rezilion Agentless Runtime Monitoring](https://www.devopsdigest.com/rezilion-launches-agentless-runtime-monitoring-solution-for-vulnerability-management)
- [Oligo Security](https://www.oligo.security/solution/runtime-vulnerability-management)
- [Kodem From Reachability to Reality](https://www.kodemsecurity.com/resources/from-reachability-to-reality-proving-vulnerable-code-was-executed-exploited-in-production)
- [Backslash Security](https://www.backslash.security/backslash-reachability-analysis)
- [Orca Agentless Reachability](https://orca.security/resources/press-releases/orca-security-reduce-vulnerabilities-agentless-analysis/)
- [ARMO Vulnerability Prioritization](https://www.armosec.io/blog/best-vulnerability-prioritization-tools/)
- [Qualys TruConfirm](https://blog.qualys.com/product-tech/2026/02/04/truconfirm-ending-vulnerability-guesswork-with-proof-inside-etm)
- [Apiiro 104% ARR Growth](https://www.globenewswire.com/news-release/2026/01/08/3215425/0/en/Apiiro-Achieves-104-ARR-Growth-in-2025-as-Fortune-500-Adopt-Agentic-AppSec-to-Reduce-Massive-Risk-Across-the-Software-Development-Lifecycle.html)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [deps.dev](https://deps.dev/)
- [Socket.dev](https://socket.dev/)
- [Aikido $60M Series B](https://www.aikido.dev/blog/aikido-funding-series-b)
- [Opengrep Fork](https://www.opengrep.dev/)
- [GitHub Secret Protection and Code Security](https://github.blog/changelog/2025-03-04-introducing-github-secret-protection-and-github-code-security/)
- [GitLab SAST](https://docs.gitlab.com/user/application_security/sast/)
- [Pixee Funding](https://fintech.global/2025/05/23/application-security-startup-pixee-secures-15m-to-automate-code-remediation-with-ai/)
- [Moderne / OpenRewrite](https://www.moderne.ai/)
- [Mobb Auto-Fix](https://mobb.ai/)
- [Seal Security Autonomous Agent](https://www.prnewswire.com/news-releases/seal-security-introduces-a-fully-autonomous-agent-for-open-source-vulnerability-remediation-302718635.html)
- [CodeRabbit](https://www.coderabbit.ai/)
- [Chainguard Series D](https://www.chainguard.dev/unchained/announcing-chainguards-series-d-building-the-safe-source-for-all-open-source)
- [Sonatype Repository Firewall](https://www.sonatype.com/products/sonatype-repository-firewall)
- [Sonatype Q4 2025 Malware Index](https://www.sonatype.com/blog/open-source-malware-index-q4-2025-automation-overwhelms-ecosystems)
- [Tidelift Acquired by Sonar](https://socket.dev/blog/sonar-to-acquire-tidelift)
- [Nucleus Security Series C](https://www.prnewswire.com/news-releases/nucleus-security-secures-20m-series-c-to-meet-surging-enterprise-demand-for-exposure-management-302684628.html)
- [Tenable Acquires Vulcan Cyber](https://www.tenable.com/press-releases/tenable-completes-acquisition-of-vulcan-cyber)
- [Veracode Acquires Phylum](https://www.businesswire.com/news/home/20250106967344/en/Veracode-Acquires-Phylum-Inc.-Technology-to-Transform-Software-Supply-Chain-Security)
- [FIRST EPSS](https://www.first.org/epss/)
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
- [OpenVEX](https://openssf.org/projects/openvex/)
- [Microsoft VEX for Azure Linux](https://www.microsoft.com/en-us/msrc/blog/2025/10/toward-greater-transparency-machine-readable-vulnerability-exploitability-xchange-for-azure-linux)
- [Syft](https://github.com/anchore/syft)
- [Grype](https://github.com/anchore/grype)
- [Trivy](https://github.com/aquasecurity/trivy)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan)
- [GuardDog](https://github.com/DataDog/guarddog)
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis)
- [Libraries.io](https://libraries.io/)
- [Seemplicity $50M Series B](https://www.prnewswire.com/news-releases/seemplicity-raises-50m-to-democratize-exposure-management-with-ai-302533968.html)
- [Cycode ASPM](https://cycode.com/aspm-application-security-posture-management/)
- [Mend.io SCA Reachability](https://docs.mend.io/legacy-sca/latest/sca-reachability)
- [OX Security 2026 Benchmark](https://www.prnewswire.com/news-releases/critical-security-findings-nearly-quadrupled-year-over-year-ox-securitys-2026-application-security-benchmark-finds-302715348.html)
- [Xygeni](https://xygeni.io/)
- [Legit Security](https://www.legitsecurity.com/)
- [Arnica](https://www.arnica.io)
- [Finite State Reachability](https://finitestate.io/blog/expanded-reachability-impact)
- [Biome Roadmap 2026](https://biomejs.dev/blog/roadmap-2026/)
