# Competitive Intelligence: Area 5 & Area 9
## Cloud IR Playbook-as-Code with Simulation + Multi-Cloud IR Evidence Preservation and Forensics Automation
### As of March 24, 2026

---

# AREA 5: Cloud IR Playbook-as-Code with Simulation

## Category A: AWS-Native IR Services and Tools

### 1. AWS Security Incident Response (Official Service)
- **URL**: https://aws.amazon.com/security/incident-response/
- **What it does**: Managed IR service that auto-triages GuardDuty and Security Hub findings, provides centralized case coordination console, messaging, data transfer, video conferencing. Includes AI investigative agent (launched re:Invent 2025) that automates investigation. Direct 24/7 access to AWS security experts who can perform containment on your behalf.
- **Type**: Commercial (AWS managed service)
- **Pricing**: Metered pricing with free tier (first 10,000 findings/month free), launched Nov 2025
- **Maturity**: GA, backed by AWS. Partner integrations with Unit 42 (Palo Alto) for retainer-based IR
- **Covers**: Automated triage, finding correlation, case management, expert escalation, AI-driven investigation
- **Misses**: No playbook-as-code paradigm, no simulation/testing capability, no custom runbook authoring, limited to AWS-only, no "pre-breach" readiness validation

### 2. AWS Automated Forensics Orchestrator for EC2 and EKS
- **URL**: https://github.com/aws-solutions-library-samples/automated-forensic-orchestrator-for-amazon-ec2
- **GitHub Stars**: 66
- **What it does**: CDK-based solution that deploys Step Functions workflows for automated evidence capture from EC2/EKS. Captures memory dumps, disk images, isolates instances, stores evidence in S3.
- **Type**: Open source (Apache 2.0), AWS Solutions Library
- **Maturity**: Production-ready reference architecture, but limited community contributions
- **Covers**: Automated disk/memory capture, instance isolation, evidence chain for EC2/EKS
- **Misses**: EC2/EKS only (no Lambda, Fargate, RDS, S3), no multi-cloud, no playbook authoring framework, no simulation, no timeline reconstruction

### 3. Amazon GuardDuty Tester
- **URL**: https://github.com/awslabs/amazon-guardduty-tester
- **GitHub Stars**: 420
- **What it does**: CDK-deployed tool that generates GuardDuty findings via real attack simulation. Supports filtering by resource, tactic, feature, log source. Deployed via SSM.
- **Type**: Open source (Apache 2.0)
- **Maturity**: Actively maintained by AWS, regularly updated
- **Covers**: GuardDuty finding generation, detection validation for GuardDuty-specific detections
- **Misses**: Only tests GuardDuty (not Security Hub, custom detections, or third-party tools), not a general-purpose IR simulation framework

### 4. AWS Incident Response Playbooks (aws-samples)
- **URL**: https://github.com/aws-samples/aws-incident-response-playbooks
- **GitHub Stars**: 1,052
- **What it does**: Markdown-based incident response playbooks for common AWS scenarios. Community reference material.
- **Type**: Open source (MIT-0)
- **Maturity**: High star count but documentation-only, not executable code
- **Covers**: Playbook documentation for common AWS IR scenarios
- **Misses**: Not executable, no automation, no simulation, no as-code framework. These are PDFs/markdown, not runnable playbooks.

### 5. AWS Incident Response Automation CDK
- **URL**: https://github.com/AWS-Incident-Response-Automation-CDK/aws-incident-response-automation-cdk
- **GitHub Stars**: 5
- **What it does**: CDK-based IR automation tool for AWS
- **Type**: Open source
- **Maturity**: Very early stage, minimal community adoption
- **Covers**: Basic IR automation via CDK
- **Misses**: Minimal functionality, negligible adoption

### 6. Sample AWS Security Incident Response Integrations
- **URL**: https://github.com/aws-samples/sample-aws-security-incident-response-integrations
- **GitHub Stars**: 20
- **What it does**: Integration samples for the new AWS Security Incident Response service
- **Type**: Open source (AWS samples)
- **Maturity**: New (late 2025), reference code
- **Covers**: Integration patterns for the managed service
- **Misses**: Samples only, not a framework

---

## Category B: Cloud Attack Simulation / Red Team Tools

### 7. Stratus Red Team (Datadog)
- **URL**: https://github.com/DataDog/stratus-red-team
- **Website**: https://stratus-red-team.cloud/
- **GitHub Stars**: 2,286
- **What it does**: "Atomic Red Team for the cloud." Self-contained Go binary that emulates offensive attack techniques for AWS, Azure, GCP, Kubernetes. Manages full lifecycle: warm up (create infra), detonate (execute TTP), clean up.
- **Type**: Open source (Apache 2.0)
- **Maturity**: High. Active development, strong community, Black Hat presented. The de facto standard for cloud attack emulation.
- **Covers**: Granular cloud TTPs mapped to MITRE ATT&CK, multi-cloud, self-contained, CI/CD friendly
- **Misses**: Offensive only (no detection validation loop), no IR playbook execution, no automated response testing, no evidence preservation testing

### 8. Atomic Red Team (Red Canary)
- **URL**: https://github.com/redcanaryco/atomic-red-team
- **GitHub Stars**: 11,727
- **What it does**: Library of tests mapped to MITRE ATT&CK. Includes cloud-specific techniques for AWS, Azure, GCP, Office 365 (EC2 enumeration, CloudTrail evasion, etc.)
- **Type**: Open source (MIT)
- **Maturity**: Very high. Industry standard for endpoint attack testing, cloud coverage growing
- **Covers**: Massive TTP library, well-documented, easy to execute
- **Misses**: Cloud coverage is secondary to endpoint focus, no lifecycle management for cloud infra, simpler than Stratus for cloud-specific testing

### 9. Leonidas (WithSecure)
- **URL**: https://github.com/WithSecureLabs/leonidas
- **Website**: https://detectioninthe.cloud/
- **What it does**: YAML-based framework for defining cloud attacker TTPs with associated detection properties. Compiles to web API + Sigma rules + documentation. Supports AWS and Kubernetes.
- **Type**: Open source
- **Maturity**: Moderate. Interesting "definition-as-code" approach but lower adoption than Stratus
- **Covers**: TTP-as-YAML with auto-generated Sigma detection rules, API-driven execution
- **Misses**: Primarily AWS, smaller TTP library than Stratus, less active maintenance

### 10. Halberd (Vectra AI)
- **URL**: https://github.com/vectra-ai-research/Halberd
- **GitHub Stars**: 335
- **What it does**: Multi-cloud agentic attack emulation tool. Supports AWS, Azure, GCP, Entra ID, M365. Features playbook engine, scheduling, access management, real-time dashboards.
- **Type**: Open source
- **Maturity**: Growing, backed by Vectra AI research. Active 2025 development
- **Covers**: True multi-cloud attack emulation, playbook chaining, scheduling, reporting
- **Misses**: Newer tool, smaller community than Stratus, no native detection/response validation

### 11. MITRE Caldera
- **URL**: https://github.com/mitre/caldera
- **GitHub Stars**: 6,842
- **What it does**: Automated adversary emulation platform. Agent-based C2 framework with plugin architecture. Can run multi-stage campaigns. Available on AWS Marketplace.
- **Type**: Open source (Apache 2.0)
- **Maturity**: Very high. MITRE-backed, enterprise-grade, large community
- **Covers**: Full adversary emulation lifecycle, plugin extensibility, multi-stage campaigns, visual tracking
- **Misses**: Primarily endpoint/network focused. Cloud-native attack techniques are limited compared to Stratus. Requires agent deployment. Bounty Hunter plugin adds some cloud but not core focus.

### 12. Cado Security Cloud & Container Compromise Simulator
- **URL**: https://github.com/cado-security/CloudAndContainerCompromiseSimulator
- **GitHub Stars**: 34
- **What it does**: Simulates compromise scenarios in cloud and container environments
- **Type**: Open source
- **Maturity**: Low adoption, proof-of-concept level
- **Covers**: Basic cloud/container compromise scenarios
- **Misses**: Limited scope, minimal community

---

## Category C: Commercial BAS (Breach and Attack Simulation) Platforms

### 13. AttackIQ
- **URL**: https://www.attackiq.com/
- **What it does**: Security optimization platform built on MITRE ATT&CK. Continuous security validation across on-prem, cloud, hybrid. Available on AWS Marketplace.
- **Type**: Commercial
- **Funding/Maturity**: Series C+, established enterprise player
- **Covers**: Continuous validation, MITRE ATT&CK alignment, cloud and hybrid testing
- **Misses**: Expensive, primarily commercial. Cloud-native depth may lag cloud-specific tools.

### 14. SafeBreach
- **URL**: https://www.safebreach.com/
- **What it does**: Creates "digital twin" of security environment, runs continuous non-disruptive simulations from "Hacker's Playbook" library with thousands of attack scenarios.
- **Type**: Commercial
- **Funding/Maturity**: Well-funded, established enterprise vendor
- **Covers**: Large attack library, continuous testing, digital twin concept
- **Misses**: Enterprise pricing, cloud-specific depth varies

### 15. Cymulate
- **URL**: https://cymulate.com/
- **What it does**: Exposure validation platform. Launched Cloud Vector Module (Q2 2023) for AWS, Azure, GCP. Ran 250K+ cloud attack scenarios in first 6 months (IAM misconfigs, lateral movement, S3 exposures).
- **Type**: Commercial
- **Funding/Maturity**: Well-funded, growing enterprise presence
- **Covers**: Multi-cloud attack simulation, WAF/EDR/email gateway testing, broad attack surface
- **Misses**: Enterprise pricing, cloud module is add-on not core

### 16. Picus Security
- **URL**: https://www.picussecurity.com/
- **What it does**: AI-powered BAS platform. #1 in G2 Winter 2026 BAS Grid. Numi AI assistant for natural language simulation control. Multi-agent orchestration for automated TTP research.
- **Type**: Commercial
- **Funding/Maturity**: Strong market position, G2 leader
- **Covers**: AI-generated adversary emulation, cloud/endpoint/network testing, evidence-based reporting
- **Misses**: Commercial pricing, cloud depth relative to cloud-native tools unclear

### 17. Pentera
- **URL**: https://pentera.io/
- **What it does**: Automated penetration testing and exposure validation. Pentera Cloud maps AWS/Azure environments, emulates cloud-native attacks (identity compromise, role escalation, lateral movement, RCE).
- **Type**: Commercial
- **Funding/Maturity**: $315M+ raised, major enterprise player
- **Covers**: Agentless, real exploit execution (not simulation), cloud + on-prem lateral movement
- **Misses**: GCP not yet supported, enterprise pricing, more pentest than IR playbook testing

### 18. SCYTHE
- **URL**: https://scythe.io/
- **What it does**: Adversary emulation and validation (BAS+). Multi-stage emulation, dynamic campaign building, production-scale continuous testing. Created Purple Team Exercise Framework (PTEF). SaaS and on-prem.
- **Type**: Commercial
- **Funding/Maturity**: Established, government and enterprise focused
- **Covers**: Advanced multi-stage emulation, purple team framework, campaign management
- **Misses**: Cloud-native techniques less emphasized than endpoint

### 19. XM Cyber
- **URL**: https://xmcyber.com/
- **What it does**: Continuous exposure management with attack path visualization across hybrid cloud. Visual battleground showing chronological attack paths. Simulates on-prem to cloud pivots.
- **Type**: Commercial (acquired by Schwarz Group)
- **Funding/Maturity**: Acquired, Gartner Challenger in Exposure Assessment
- **Covers**: Hybrid cloud attack path analysis, continuous simulation, visual mapping
- **Misses**: More focused on exposure management than IR playbook testing

### 20. Mandiant Security Validation (Google Cloud)
- **URL**: https://cloud.google.com/security/products/mandiant-security-validation
- **What it does**: Intelligence-led security control validation. Continuous emulation of real attacks based on Mandiant frontline IR intelligence. Ransomware Defense Validation (launched March 2025).
- **Type**: Commercial (Google Cloud)
- **Funding/Maturity**: Google-backed, Mandiant intelligence-fed
- **Covers**: Threat-intelligence-driven validation, ransomware-specific testing, M-Trends integration
- **Misses**: Google Cloud ecosystem focus, enterprise pricing

---

## Category D: Security Chaos Engineering

### 21. Mitigant
- **URL**: https://mitigant.io/
- **What it does**: Cloud security validation through attack emulation and security chaos engineering. CSPM + KSPM + Cloud Attack Emulation. Supports AWS, Azure, Kubernetes. Threat Catalog with 91 techniques across 32 AWS services. Cloud Attack Language for multi-step attacks.
- **Type**: Commercial (SaaS)
- **Funding/Maturity**: German startup, Hasso Plattner Institute origins, growing
- **Covers**: Security chaos engineering specifically for cloud, MITRE ATT&CK + ATLAS mapping, multi-cloud, free Threat Catalog
- **Misses**: Smaller vendor, no IR playbook execution/testing, focused on posture validation not response validation

### 22. Gremlin
- **URL**: https://www.gremlin.com/
- **What it does**: Enterprise chaos engineering platform. Fault injection for infrastructure resilience. AI-driven Reliability Intelligence (Aug 2025). Private Edition for on-prem. SOC II compliant.
- **Type**: Commercial
- **Funding/Maturity**: $69M+ raised, category creator for commercial chaos engineering
- **Covers**: Infrastructure resilience testing, AI experiment analysis, broad fault injection
- **Misses**: NOT security-focused. Tests reliability, not security controls. No attack simulation, no IR validation, no security-specific scenarios.

### 23. AWS Fault Injection Simulator (FIS)
- **URL**: https://aws.amazon.com/fis/
- **What it does**: Managed fault injection service. Pre-built experiment scenarios for resilience testing.
- **Type**: Commercial (AWS native)
- **Covers**: AWS infrastructure fault injection, pre-built scenarios
- **Misses**: Reliability focused, not security focused. No attack simulation, no IR playbook testing.

### 24. ChaoSlingr
- **URL**: https://github.com/Optum/ChaoSlingr
- **What it does**: Security chaos engineering experiments on AWS infrastructure
- **Type**: Open source
- **Maturity**: Low, minimal recent activity
- **Covers**: AWS security chaos experiments
- **Misses**: Very niche, limited community, unclear maintenance status

---

## Category E: SOAR Platforms (Playbook Execution)

### 25. Shuffle
- **URL**: https://shuffler.io/
- **GitHub Stars**: 2,223
- **What it does**: Open source SOAR. 2,500+ apps, OpenAPI-based, 200+ pre-built integrations. Wazuh partnership (Sep 2025). Often called "open source Tines" or "IFTTT for cybersecurity."
- **Type**: Open source
- **Maturity**: Industry standard for open source SOAR, strong community
- **Covers**: Workflow automation, broad integrations, visual workflow builder, detection-to-response automation
- **Misses**: General purpose SOAR, not cloud-IR-specific. No built-in simulation, no cloud forensics, no evidence preservation. You build playbooks manually.

### 26. Tines
- **URL**: https://www.tines.com/
- **What it does**: No-code automation platform for security teams. Generous free tier. Hundreds of integrations. Strong in phishing response, alert triage, user provisioning.
- **Type**: Commercial with free community tier
- **Funding/Maturity**: Well-funded, rapidly growing, strong enterprise adoption
- **Covers**: Flexible workflow automation, extensive templates, API-first design
- **Misses**: General SOAR, not cloud-IR specific. No simulation capability. No forensics integration. You must build cloud IR playbooks from scratch.

### 27. TheHive + Cortex
- **URL**: https://strangebee.com/thehive/ / https://strangebee.com/cortex/
- **GitHub Stars**: 3,897 (TheHive)
- **What it does**: TheHive = case management for IR. Cortex = automation/enrichment engine with REST API. Cloud Platform (THCP) available. IaaS images for cloud deployment.
- **Type**: Open source (TheHive 5 has more restrictive license) + Commercial cloud
- **Maturity**: Established, widely used in SOCs globally
- **Covers**: Case management, automated enrichment, collaborative IR, observable analysis
- **Misses**: Not cloud-native IR. No cloud-specific forensics, no AWS/Azure native integrations for evidence capture. Cortex analyzers are primarily for IOC enrichment, not cloud API automation.

### 28. DFIR-IRIS
- **URL**: https://www.dfir-iris.org/
- **GitHub Stars**: 1,448
- **What it does**: Open source collaborative IR platform. Case management, evidence tracking, reporting. Module system for extensions. Wazuh integration. Active development (v2.4.27).
- **Type**: Open source
- **Maturity**: Growing, well-maintained, community-backed
- **Covers**: IR case management, evidence management, collaborative investigation, reporting
- **Misses**: No cloud-native forensics automation, no playbook execution engine, no simulation

### 29. StackStorm
- **URL**: https://github.com/StackStorm/st2
- **GitHub Stars**: 6,436
- **What it does**: Event-driven automation platform. 160 integration packs, 6,000+ actions. Rules engine, workflow engine, ChatOps. Used by Netflix, Cisco, Target.
- **Type**: Open source (Linux Foundation)
- **Maturity**: Battle-tested enterprise platform, but broader than security
- **Covers**: Event-driven automation, massive integration library, code-first, Git-versionable
- **Misses**: Not security-specific. Requires significant engineering effort to build IR playbooks. No built-in detection or simulation.

### 30. n8n
- **URL**: https://n8n.io/
- **What it does**: Open source workflow automation platform. Low-code with coding capability. CRITICAL: CVE-2026-21858 ("Ni8mare") CVSS 10.0 disclosed for self-hosted instances.
- **Type**: Open source (fair-code license)
- **Maturity**: Large community, but security vulnerabilities raise concerns
- **Covers**: General workflow automation, can build security workflows
- **Misses**: Not a SOAR. No native case management, alert correlation, or entity profiling. Critical security vulnerabilities. Not recommended for security-critical IR automation.

### 31. OpenSecOps SOAR
- **URL**: https://github.com/OpenSecOps-Org/SOAR
- **GitHub Stars**: 6
- **What it does**: AWS-native SOAR processing Security Hub ASFF findings. Nested Step Functions state machines. Auto-remediation, incident management, weekly AI reports.
- **Type**: Open source
- **Maturity**: Very early, minimal adoption. Claims to have passed AWS Foundational Technical Reviews.
- **Covers**: AWS Security Hub integration, auto-remediation, serverless architecture
- **Misses**: Tiny community, unclear production readiness, no simulation

---

## Category F: Cloud-Native Detection & Response Platforms

### 32. Wiz Defend + Wiz Incident Response
- **URL**: https://www.wiz.io/platform/wiz-defend
- **What it does**: Cloud detection and response (CDR) with eBPF-based Runtime Sensor. Agentless CDR since 2022, Wiz Defend (from Gem Security acquisition 2024). Wiz IR service launched Sep 2025 (public preview). Runtime Sensor for Windows (Feb 2026).
- **Type**: Commercial (mega-vendor, $32B Google acquisition pending)
- **Maturity**: Very high. Market leader in cloud security.
- **Covers**: Runtime threat detection, forensic collection, incident readiness, cloud-native threat intel, investigation, response
- **Misses**: Proprietary, very expensive. No playbook-as-code paradigm. No simulation capability. Vendor lock-in.

### 33. Sysdig + Falco
- **URL**: https://www.sysdig.com/ / https://github.com/falcosecurity/falco
- **GitHub Stars**: 8,770 (Falco)
- **What it does**: Falco = open source runtime threat detection (eBPF). Sysdig Secure = commercial CDR platform. New: SCAP file recording on rule trigger for forensics. Stratoshark integration for event analysis. MCP server integration.
- **Type**: Falco is open source (CNCF graduated). Sysdig Secure is commercial.
- **Maturity**: Very high. Falco is CNCF graduated project, used by 60%+ Fortune 500.
- **Covers**: Runtime detection, container security, forensic capture, AWS Fargate support, 5-5-5 benchmark
- **Misses**: Commercial platform expensive. Falco alone needs integration work. No playbook-as-code framework. No attack simulation built in.

### 34. Sysdig aws-ireveal-mcp
- **URL**: https://github.com/sysdiglabs/aws-ireveal-mcp
- **GitHub Stars**: 17
- **What it does**: MCP server for AI-assisted AWS incident response. Integrates with CloudTrail, Athena, CloudWatch, GuardDuty, Config, VPC Flow Logs, Network Access Analyzer, IAM Access Analyzer. Works with Claude Desktop or Cline.
- **Type**: Open source
- **Maturity**: New (2025), proof-of-concept level but innovative
- **Covers**: AI-assisted cloud investigation, multi-service AWS querying via natural language
- **Misses**: Experimental, tiny community, depends on MCP client, no playbook automation

### 35. Panther
- **URL**: https://panther.com/
- **What it does**: Cloud-native SIEM with detection-as-code (Python). AI agents for triage, investigation, detection creation, threat hunting. Serverless architecture. Integrations with Duo, Okta, Slack, Google Workspace.
- **Type**: Commercial
- **Funding/Maturity**: $165M+ raised, strong enterprise adoption
- **Covers**: Detection-as-code, AI-driven SOC automation, cloud-native architecture, reduced false positives
- **Misses**: SIEM, not IR platform. No playbook execution, no forensics, no simulation. Expensive.

### 36. Matano
- **URL**: https://github.com/matanolabs/matano / https://www.matanosecurity.com/
- **GitHub Stars**: 1,663
- **What it does**: Open source security data lake for AWS. Apache Iceberg format, ECS schema, Python detections-as-code. Hundreds of prebuilt integrations. Commercial managed Cloud SIEM.
- **Type**: Open source (Apache 2.0) + Commercial
- **Funding/Maturity**: YC W23. Open source is active but commercial product still in waitlist/rollout phase.
- **Covers**: Petabyte-scale log storage, detection-as-code, open data formats, AWS-native
- **Misses**: Data platform, not IR automation. No playbook execution, no forensics, no simulation.

### 37. Permiso
- **URL**: https://permiso.io/
- **What it does**: Identity threat detection and response for cloud. Universal Identity Graph across cloud, SaaS, CI/CD. P0 Labs threat research. P0LR Espresso (open source log normalization tool, Oct 2025).
- **Type**: Commercial + some open source tools
- **Funding/Maturity**: SC Awards 2026 finalist, 2025 Most Promising Startup winner
- **Covers**: Cloud identity threats, ITDR, behavioral analytics, multi-cloud identity monitoring
- **Misses**: Identity-focused only, not general IR automation, no playbook framework, no forensics

---

## Category G: Cloud Log Analysis and Threat Hunting

### 38. Suzaku (Yamato Security)
- **URL**: https://github.com/Yamato-Security/suzaku
- **GitHub Stars**: 171
- **What it does**: Sigma-based threat hunting and fast forensics timeline generator for cloud logs. Currently supports AWS CloudTrail. Plans for Azure and GCP. Sigma correlation rules support (v1.0.0). Selected for Black Hat USA 2025 Arsenal.
- **Type**: Open source
- **Maturity**: Active development, recognized at Black Hat. Young but promising.
- **Covers**: CloudTrail log analysis, Sigma rule native support, DFIR timeline generation, correlation rules
- **Misses**: CloudTrail only (Azure/GCP planned), no response automation, no simulation, no evidence preservation

### 39. Invictus-AWS
- **URL**: https://github.com/invictus-ir/Invictus-AWS
- **GitHub Stars**: 198
- **What it does**: Python tool for AWS IR. Enumerates services, acquires logs, analyzes CloudTrail via Athena with predefined queries. Can run on specific or all regions. Local or S3 output.
- **Type**: Open source
- **Maturity**: Active development by Invictus IR (Dutch cloud IR firm)
- **Covers**: AWS service enumeration, log acquisition, Athena-based CloudTrail analysis, modular step execution
- **Misses**: AWS only, no response automation, no playbook framework, no simulation, investigation tool only

### 40. Invictus Sigma-AWS
- **URL**: https://github.com/invictus-ir/Sigma-AWS
- **GitHub Stars**: 31
- **What it does**: Research and tooling for using Sigma rules in AWS incident response
- **Type**: Open source
- **Maturity**: Research/experimental
- **Covers**: Sigma rule adaptation for AWS CloudTrail
- **Misses**: Research project, not production tool

### 41. Prowler
- **URL**: https://github.com/prowler-cloud/prowler
- **GitHub Stars**: 13,393
- **What it does**: Open source cloud security assessment for AWS, Azure, GCP, K8s, M365. Hundreds of CIS/PCI-DSS/HIPAA controls. Attack path analysis with Neo4j.
- **Type**: Open source + Commercial (Prowler SaaS)
- **Maturity**: Very high. Major open source cloud security tool.
- **Covers**: Security posture assessment, compliance, forensics readiness checks, attack path visualization
- **Misses**: Assessment tool, not IR automation. No playbook execution, no simulation, no real-time response.

---

## Category H: Purple Team Platforms

### 42. PurpleOps
- **URL**: https://purpleops.app/
- **What it does**: Free, open source purple team management platform. Quantifies organization-wide cyber security controls to assess and close gaps.
- **Type**: Open source
- **Maturity**: Active, niche community
- **Covers**: Purple team exercise management, gap tracking, collaborative assessment
- **Misses**: Management platform, not automated simulation. No cloud-specific capabilities.

---

## Category I: Other Notable IR Tools

### 43. Incident Response Consortium
- **URL**: https://www.incidentresponse.com/
- **What it does**: Community resource for open source playbooks, runbooks, response plans, flowcharts, scripts, orchestration connectors.
- **Type**: Community/Open source
- **Covers**: Playbook templates and community resources
- **Misses**: Documentation only, not executable, no cloud-specific focus

### 44. Scoutflo SRE Playbooks
- **URL**: https://github.com/Scoutflo/Scoutflo-SRE-Playbooks
- **GitHub Stars**: 46
- **What it does**: SRE incident response playbooks for AWS and Kubernetes troubleshooting
- **Type**: Open source
- **Covers**: Step-by-step troubleshooting for AWS/K8s
- **Misses**: SRE focused (not security), markdown playbooks only

### 45. DevOps Security Agent Skills (BagelHole)
- **URL**: https://github.com/BagelHole/DevOps-Security-Agent-Skills
- **GitHub Stars**: 14
- **What it does**: Agent-ready knowledge base with 80+ skills across K8s, Terraform, AWS, compliance, IR
- **Type**: Open source
- **Maturity**: Very new, minimal adoption
- **Covers**: Broad security knowledge templates
- **Misses**: Knowledge base, not executable automation

---

---

# AREA 9: Multi-Cloud IR Evidence Preservation and Forensics Automation

## Category A: Commercial Cloud Forensics Platforms

### 1. Darktrace / Forensic Acquisition & Investigation (formerly Cado Security)
- **URL**: https://www.darktrace.com/forensic-acquisition-investigation / https://docs.cadosecurity.com/
- **What it does**: "Industry's first fully automated cloud forensics platform." Broad support for multi-cloud, container, serverless, SaaS, on-prem. Automated evidence capture and forensic investigation. Integrated with Darktrace ActiveAI Security Platform.
- **Type**: Commercial (Darktrace acquired Cado Security, completed Feb 2025)
- **Funding/Maturity**: Darktrace is publicly traded (~$5B+ market cap). Cado was VC-backed before acquisition.
- **Covers**: Multi-cloud forensic capture, container/serverless/SaaS coverage, automated investigation, integration with Darktrace CDR. THE most complete commercial cloud forensics tool.
- **Misses**: Expensive, Darktrace platform lock-in, proprietary, no open source components, no playbook-as-code paradigm

### 2. Binalyze AIR
- **URL**: https://www.binalyze.com/
- **What it does**: Cloud-native automated investigation and response. Collects 650+ evidence types (240+ in 7-10 minutes average) from Windows, Linux, macOS, Chromebook, ESXi, AWS, Azure. Cloud Investigation and Response Automation (CIRA) category creator.
- **Type**: Commercial
- **Funding/Maturity**: $19M Series A (2023), growing enterprise presence. Gartner CIRA category.
- **Covers**: Rapid multi-platform evidence collection, remote forensic acquisition, automated investigation, broad OS/cloud support
- **Misses**: Commercial pricing, less deep on cloud-native services (Lambda, Fargate) vs. VMs, no open source component

### 3. Magnet Forensics (Magnet One)
- **URL**: https://www.magnetforensics.com/
- **What it does**: Traditional digital forensics leader expanding to cloud. Magnet One Process (cloud processing engine, beta 2025). Magnet One Mobile Case Stream for real-time mobile evidence.
- **Type**: Commercial
- **Funding/Maturity**: Major forensics vendor, merged with Grayshift
- **Covers**: Deep forensic analysis, mobile forensics, cloud processing
- **Misses**: Historically endpoint-focused, cloud forensics capabilities are newer and still in beta. Not cloud-native architecture. Expensive enterprise licensing.

### 4. Wiz Defend (Forensic Collection)
- **URL**: https://www.wiz.io/platform/wiz-defend
- **What it does**: Cloud-native forensic collection as part of Wiz Defend CDR. Automated evidence collection with secure chain of custody, maintains raw log integrity.
- **Type**: Commercial
- **Funding/Maturity**: See Area 5 entry above
- **Covers**: Cloud-native evidence capture, chain of custody, integration with Wiz security graph
- **Misses**: Wiz platform only, very expensive, forensic depth unclear vs. dedicated forensics tools

### 5. Sysdig Secure (Forensic Capture)
- **URL**: https://www.sysdig.com/
- **What it does**: Runtime forensic capture via SCAP files on rule triggers. Container forensics (terminate, pause, quarantine, download captures). Integration with XSOAR.
- **Type**: Commercial + Falco (open source)
- **Covers**: Container/runtime forensic capture, evidence preservation on detection trigger
- **Misses**: Container-focused, less coverage for cloud API/control plane forensics

---

## Category B: Open Source Forensics Tools for Cloud

### 6. Google cloud-forensics-utils (libcloudforensics)
- **URL**: https://github.com/google/cloud-forensics-utils
- **GitHub Stars**: 502
- **What it does**: Python library for DFIR in cloud. Supports GCP, Azure, AWS. CLI wrapper. Functions: list instances, list disks, create disk copies, start forensic VMs, query logs, extract metadata, create forensic disk images.
- **Type**: Open source (Apache 2.0)
- **Maturity**: Google-maintained, stable, well-documented
- **Covers**: Multi-cloud disk forensics, VM snapshot creation, programmatic forensic operations
- **Misses**: Library, not a complete platform. No chain of custody, no timeline reconstruction, no memory forensics, no automated orchestration. Requires custom code to build workflows.

### 7. Velociraptor (Rapid7)
- **URL**: https://github.com/Velocidex/velociraptor
- **GitHub Stars**: 3,842
- **What it does**: Advanced endpoint monitoring, DFIR, and response platform. VQL query language for custom hunts. Scalable architecture for fleet-wide forensic hunting. MCP Server for AI integration (2025). CISA recommended.
- **Type**: Open source (AGPL v3), Rapid7 acquired
- **Maturity**: Very high. Production-grade, CISA endorsed, enterprise-scale
- **Covers**: Endpoint forensic collection at scale, custom artifact hunting, YARA scanning, file/registry search, AI integration via MCP
- **Misses**: ENDPOINT focused, not cloud-API focused. Cannot natively capture CloudTrail, S3 access logs, Lambda execution context. Excellent for EC2 instances but not for cloud control plane forensics.

### 8. GRR Rapid Response (Google)
- **URL**: https://github.com/google/grr
- **GitHub Stars**: 5,048
- **What it does**: Incident response framework for remote live forensics at scale. Python client agent on targets, server infrastructure for management. Memory analysis (YARA), file search, enterprise hunting.
- **Type**: Open source (Apache 2.0)
- **Maturity**: Mature, Google-built, CISA recommended, but aging architecture
- **Covers**: Remote live forensics, memory analysis, fleet hunting, scalable architecture
- **Misses**: Like Velociraptor, ENDPOINT focused. Not designed for cloud control plane forensics. Older architecture vs. Velociraptor. No cloud service integration for evidence capture.

### 9. AWS Automated Forensics Orchestrator for EC2 and EKS
- **URL**: See Area 5 entry #2 above
- **GitHub Stars**: 66
- **What it does**: CDK Step Functions for automated EC2/EKS evidence capture
- **Type**: Open source (AWS reference architecture)
- **Covers**: EC2/EKS disk/memory capture, instance isolation, S3 evidence storage
- **Misses**: EC2/EKS only, no Lambda/Fargate/RDS/S3, no multi-cloud, no timeline, no chain-of-custody tracking

### 10. JPCERT MemoryForensic-on-Cloud
- **URL**: https://github.com/JPCERTCC/MemoryForensic-on-Cloud
- **GitHub Stars**: 92
- **What it does**: Terraform-deployed system for cloud-based memory forensics. S3 trigger -> AWS Batch -> Docker -> Volatility analysis -> HTML report + SNS notification. Parallel analysis of multiple memory images.
- **Type**: Open source
- **Maturity**: Proof of concept from JPCERT/CC (Japan CERT), minimal updates since 2023
- **Covers**: Scalable memory forensics on AWS, Infrastructure-as-Code (Terraform), parallel processing
- **Misses**: Memory analysis only (Windows), no disk forensics, no cloud API forensics, no chain of custody, aging codebase

### 11. CISAGOV Sparrow
- **URL**: https://github.com/cisagov/Sparrow
- **GitHub Stars**: 1,428
- **What it does**: PowerShell tool from CISA's Cloud Forensics team to detect compromised accounts/apps in Azure/M365
- **Type**: Open source (government)
- **Maturity**: Created post-SolarWinds, but Azure/M365 specific
- **Covers**: Azure/M365 compromise detection, account forensics
- **Misses**: Azure/M365 only, no AWS, no GCP, PowerShell-based, aging

### 12. Hawk
- **URL**: https://github.com/T0pCyber/hawk
- **GitHub Stars**: 930
- **What it does**: PowerShell tool for gathering information related to O365 intrusions and potential breaches
- **Type**: Open source
- **Maturity**: Active maintenance, established tool
- **Covers**: O365/M365 breach investigation
- **Misses**: O365 only, no AWS/GCP, PowerShell-based

### 13. AzureHunter
- **URL**: https://github.com/darkquasar/AzureHunter
- **GitHub Stars**: 790
- **What it does**: Cloud forensics PowerShell module for threat hunting playbooks on Azure and O365 data
- **Type**: Open source
- **Maturity**: Moderate, Azure-specific
- **Covers**: Azure/O365 threat hunting
- **Misses**: Azure/O365 only, no AWS/GCP

### 14. ALFA (Invictus IR)
- **URL**: https://github.com/invictus-ir/ALFA
- **GitHub Stars**: 175
- **What it does**: Automated Audit Log Forensic Analysis for Google Workspace. Acquires all Google Workspace audit logs and performs automated forensic analysis using MITRE ATT&CK Cloud Framework.
- **Type**: Open source
- **Maturity**: Actively maintained by Invictus IR
- **Covers**: Google Workspace forensics, MITRE ATT&CK mapping, automated analysis
- **Misses**: Google Workspace only, no AWS/Azure/GCP infrastructure

### 15. DFORC2 (RAND Corporation)
- **URL**: https://github.com/RANDCorporation/DFORC2
- **GitHub Stars**: 13
- **What it does**: Cloud-based digital forensics platform on AWS with Kubernetes. Uses Autopsy and The Sleuth Kit backend.
- **Type**: Open source (research)
- **Maturity**: Research project, minimal adoption
- **Covers**: Cloud-hosted traditional forensic analysis
- **Misses**: Traditional forensics in cloud, not cloud-native forensics

### 16. auto-cloud-digital-forensics-incident-response (aws-samples)
- **URL**: https://github.com/aws-samples/auto-cloud-digital-forensics-incident-response
- **GitHub Stars**: 7
- **What it does**: AWS sample for automated cloud DFIR
- **Type**: Open source (AWS sample)
- **Maturity**: Minimal, sample code
- **Covers**: Basic automated DFIR patterns on AWS
- **Misses**: Sample only, not production-ready

### 17. CAFIR (Cloud Automated Forensics & Incident Response)
- **URL**: https://github.com/ArborBytes/CAFIR
- **GitHub Stars**: 4
- **What it does**: Cloud automated forensics and incident response
- **Type**: Open source
- **Maturity**: Very early, negligible adoption
- **Covers**: Basic cloud forensics automation
- **Misses**: Minimal functionality, no community

### 18. awesome-aws-forensics
- **URL**: https://github.com/wannacryforensics/awesome-aws-forensics
- **GitHub Stars**: 4
- **What it does**: Curated list of AWS forensics tools
- **Type**: Open source (list)
- **Covers**: Reference list
- **Misses**: List only, not a tool

---

## Category C: Platforms with IR Case Management + Forensics Integration

### 19. DFIR-IRIS
- **URL**: See Area 5 entry #28
- **Covers**: Case management, evidence tracking, pipeline modules for evidence processing
- **Misses**: No cloud-native evidence capture

### 20. TheHive + Cortex
- **URL**: See Area 5 entry #27
- **Covers**: Case management, enrichment automation
- **Misses**: No cloud forensics, no evidence capture automation

---

## Category D: Cloud Log Timeline and Reconstruction

### 21. Suzaku (Yamato Security)
- **URL**: See Area 5 entry #38
- **Covers**: CloudTrail timeline generation, Sigma-based detection
- **Misses**: CloudTrail only, no evidence preservation

### 22. Invictus-AWS
- **URL**: See Area 5 entry #39
- **Covers**: AWS log acquisition and Athena analysis
- **Misses**: Investigation only, no evidence preservation or chain of custody

### 23. CloudQuery
- **URL**: https://github.com/cloudquery/cloudquery
- **GitHub Stars**: 6,350
- **What it does**: Data pipelines for cloud config and security data. 70+ cloud/SaaS sources. Full-text search across inventory. Event-driven workflows.
- **Type**: Open source (MPL 2.0) + Commercial
- **Funding/Maturity**: Well-funded, growing fast
- **Covers**: Multi-cloud asset inventory, configuration snapshot, IR data collection
- **Misses**: Asset inventory, not forensics. No evidence chain of custody, no disk/memory capture, no timeline reconstruction

### 24. P0LR Espresso (Permiso)
- **URL**: Open source log normalization tool
- **What it does**: Unifies critical fields (identity, IP, user agent, action) across cloud log formats into consistent schema
- **Type**: Open source
- **Maturity**: New (Oct 2025)
- **Covers**: Cloud log normalization for investigation
- **Misses**: Normalization only, not forensics or evidence preservation

---

## Category E: Azure-Specific Forensic Architecture

### 25. Microsoft Azure Computer Forensics Chain of Custody
- **URL**: https://learn.microsoft.com/en-us/azure/architecture/example-scenario/forensics/
- **What it does**: Reference architecture for evidence preservation in Azure using immutable blob storage, hash verification, access controls
- **Type**: Reference architecture (free)
- **Covers**: Chain of custody for Azure VM disk snapshots, tamper-proof storage
- **Misses**: Azure only, architecture guidance not a tool, no automation

---

## Category F: Enterprise Forensic Suites with Some Cloud Coverage

### 26. Cyber Triage (Basis Technology)
- **URL**: https://www.cybertriage.com/
- **What it does**: Automated DFIR triage tool. Velociraptor integration.
- **Type**: Commercial
- **Covers**: Automated endpoint triage, Velociraptor integration
- **Misses**: Endpoint focused, limited cloud-native capability

---

# SUMMARY: CRITICAL GAPS IN THE MARKET

## What exists is fragmented across:
1. **Attack simulation** (Stratus, Caldera, Halberd) that does NOT connect to IR playbook testing
2. **SOAR platforms** (Shuffle, Tines, TheHive) that require manual playbook building with no simulation
3. **Cloud forensics tools** (Cado/Darktrace, Binalyze) that are commercial and expensive
4. **AWS reference architectures** that are narrow (EC2/EKS only) and not frameworks
5. **Log analysis tools** (Suzaku, Invictus-AWS) that investigate but do not automate response
6. **BAS vendors** (Picus, AttackIQ, etc.) focused on control validation, not IR workflow testing

## What NOBODY does today (March 2026):

### For Area 5 (IR Playbook-as-Code with Simulation):
- **No tool lets you define IR playbooks as code AND simulate incidents to test them end-to-end**
- No tool connects attack simulation output to automated IR playbook execution and measures response effectiveness
- No tool provides "IR playbook CI/CD" where response procedures are tested against simulated attacks in a pipeline
- No open source framework treats IR playbooks as first-class code artifacts with testing, versioning, and validation
- The closest is manually wiring Stratus Red Team -> GuardDuty -> Security Hub -> Shuffle/Tines, but nobody packages this

### For Area 9 (Multi-Cloud Evidence Preservation):
- **No open source tool provides automated, multi-cloud evidence preservation with chain of custody**
- Google cloud-forensics-utils is the closest but is a library, not a framework, and has no chain of custody
- AWS Forensics Orchestrator only covers EC2/EKS, not Lambda/Fargate/S3/RDS
- No tool captures cloud control plane evidence (CloudTrail, Config snapshots) + data plane evidence (disk, memory) + SaaS evidence in a unified, court-ready chain of custody
- Darktrace/Cado is the only near-complete solution but is proprietary and expensive
- No IaC-based "forensic readiness kit" that deploys logging, evidence buckets, cross-account roles, and automated capture workflows
- No tool supports evidence preservation for serverless (Lambda), managed databases (RDS), or managed services in general

---

Sources:
- [AWS Security Incident Response](https://aws.amazon.com/blogs/aws/new-aws-security-incident-response-helps-organizations-respond-to-and-recover-from-security-events/)
- [AWS re:Invent 2025 Security Innovations](https://aws.amazon.com/blogs/security/aws-launches-ai-enhanced-security-innovations-at-reinvent-2025/)
- [Darktrace Acquires Cado Security](https://www.darktrace.com/news/darktrace-announces-proposed-acquisition-of-cado-security-a-cloud-investigation-and-response-specialist)
- [Darktrace Forensic Acquisition](https://www.darktrace.com/forensic-acquisition-investigation)
- [Matano Security](https://www.matanosecurity.com/)
- [Panther SIEM](https://panther.com/)
- [Wiz Defend](https://www.wiz.io/platform/wiz-defend)
- [Wiz Incident Response](https://www.wiz.io/blog/introducing-wiz-incident-response)
- [Stratus Red Team](https://stratus-red-team.cloud/)
- [Mitigant Security Chaos Engineering](https://mitigant.io/en)
- [Picus Security BAS](https://www.picussecurity.com/)
- [Shuffle SOAR](https://shuffler.io/)
- [Tines Automation](https://www.tines.com/)
- [TheHive / StrangeBee](https://strangebee.com/thehive/)
- [DFIR-IRIS](https://www.dfir-iris.org/)
- [Binalyze AIR](https://www.binalyze.com/)
- [Magnet Forensics](https://magnetusersummit.com/)
- [Velociraptor DFIR](https://www.rapid7.com/products/velociraptor/)
- [GRR Rapid Response](https://github.com/google/grr)
- [Suzaku Cloud Log Hunter](https://github.com/Yamato-Security/suzaku)
- [Invictus-AWS](https://github.com/invictus-ir/Invictus-AWS)
- [Sysdig CDR](https://www.sysdig.com/)
- [Falco Runtime Security](https://github.com/falcosecurity/falco)
- [aws-ireveal-mcp](https://github.com/sysdiglabs/aws-ireveal-mcp)
- [MITRE Caldera](https://github.com/mitre/caldera)
- [Halberd Multi-Cloud Attack](https://github.com/vectra-ai-research/Halberd)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Leonidas Attack Simulation](https://github.com/WithSecureLabs/leonidas)
- [Amazon GuardDuty Tester](https://github.com/awslabs/amazon-guardduty-tester)
- [AWS Automated Forensics Orchestrator](https://github.com/aws-solutions-library-samples/automated-forensic-orchestrator-for-amazon-ec2)
- [Google cloud-forensics-utils](https://github.com/google/cloud-forensics-utils)
- [Permiso ITDR](https://permiso.io/)
- [Prowler Cloud Security](https://github.com/prowler-cloud/prowler)
- [OpenSecOps SOAR](https://github.com/OpenSecOps-Org/SOAR)
- [StackStorm](https://github.com/StackStorm/st2)
- [CloudQuery](https://github.com/cloudquery/cloudquery)
- [JPCERT MemoryForensic-on-Cloud](https://github.com/JPCERTCC/MemoryForensic-on-Cloud)
- [Gremlin Chaos Engineering](https://www.gremlin.com/)
- [AttackIQ BAS](https://www.attackiq.com/)
- [SafeBreach BAS](https://www.safebreach.com/)
- [Cymulate BAS](https://cymulate.com/)
- [Pentera Cloud](https://pentera.io/pentera-cloud/)
- [SCYTHE Purple Team](https://scythe.io/)
- [XM Cyber Attack Path](https://xmcyber.com/)
- [Mandiant Security Validation](https://cloud.google.com/security/products/mandiant-security-validation)
- [n8n Automation](https://n8n.io/)
- [PurpleOps](https://purpleops.app/)
- [CISAGOV Sparrow](https://github.com/cisagov/Sparrow)
- [Hawk O365 Forensics](https://github.com/T0pCyber/hawk)
