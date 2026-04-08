# Area 8: Cloud Security Skills Lab Platform Competitive Intelligence

**Research Date:** March 24, 2026
**Purpose:** Exhaustive competitive landscape for DefensiveWorks cloud security education platform (Attack + Defend, AWS-Native)

---

## SECTION 1: OFFENSIVE / CTF PLATFORMS

### 1.1 Hack The Box (HTB)
- **URL:** https://www.hackthebox.com
- **What it offers:** Hacking labs, CTF challenges, Academy courses, certifications (CPTS, CDSA, CBBH). Cloud-specific: BlackSky cloud labs (Hailstorm/AWS, Cyclone/Azure, Blizzard/GCP) offering both offensive and defensive cloud training.
- **Pricing:**
  - Labs VIP+: ~$49/month or ~$490/year (ProLabs)
  - Academy: Student $8/mo; Silver Annual $490/yr (includes CPTS voucher); Gold Annual $1,260/yr
  - Enterprise: $250/seat/month (Build tier), custom for Grow/Scale
  - BlackSky Cloud Labs: Custom enterprise pricing only, minimum 10 concurrent users
- **Target audience:** Pentesters, red teamers, SOC analysts (Academy), enterprise teams
- **Covers:** Network pentesting, web app security, Active Directory, some cloud modules. Cloud labs are enterprise-only.
- **Misses:** Cloud labs not accessible to individual subscribers. No dedicated AWS-focused attack+defend path for individuals. Cloud content is a bolt-on, not the core product.

### 1.2 TryHackMe
- **URL:** https://tryhackme.com
- **What it offers:** Guided cybersecurity rooms, learning paths, certifications (SAL1 at $349, PT1 at $297). Some cloud security rooms available.
- **Pricing:**
  - Free: Limited rooms
  - Premium: ~$14/month or ~$10/month annually (~$126/year)
  - Student annual: ~$100/year
- **Target audience:** Beginners to intermediate. Entry-level cybersecurity learners.
- **Covers:** Broad cybersecurity fundamentals, some cloud rooms (AWS basics, Azure), SOC analyst path
- **Misses:** Cloud security is a small fraction of content. No deep AWS attack chains. No real cloud infrastructure labs (simulated browser-based). Not for practitioners who need production-realistic cloud environments.

### 1.3 PentesterLab
- **URL:** https://pentesterlab.com
- **What it offers:** Web application security exercises, code review training, progressive difficulty. New content weekly.
- **Pricing:**
  - PRO Monthly: $19.99/month
  - PRO Annual: $199.99/year (2 months free)
- **Target audience:** Web pentesters, bug bounty hunters, code reviewers
- **Covers:** Web app vulns (SQLi, XSS, auth bypass, deserialization), some API security
- **Misses:** Virtually no cloud security content. No AWS/Azure/GCP labs. Purely web-focused.

### 1.4 Pwned Labs
- **URL:** https://pwnedlabs.io
- **What it offers:** Hands-on cloud and AI security training. 30+ free labs. Premium "Thunderdome" cyber range (multi-cloud enterprise sim with 9 flags). Bootcamps for AWS, Azure/M365, and GCP.
- **Pricing:**
  - Free: 30+ labs
  - Premium: $200/year (includes Thunderdome range)
  - Bootcamps: $349 each (4 live sessions + 2 exam vouchers)
    - AWS Bootcamp: March 2026
    - Microsoft Cloud Professional (MCRTP): Feb 2026
    - Microsoft Cloud Expert (MCRTE): May 2026
    - GCP Bootcamp: Available
- **Target audience:** Cloud security practitioners, pentesters moving to cloud, blue teamers wanting attack understanding
- **Covers:** AWS assume-breach scenarios, Azure/M365 attack tradecraft, GCP exploitation, multi-cloud. Both attack and defense (bootcamps cover detection/containment).
- **Misses:** Relatively new platform, content library still growing. No formal certifications yet (bootcamps issue badges). UI/platform appears basic (nginx default page observed on main domain). AWS content is bootcamp-only, not self-paced depth.
- **KEY COMPETITOR:** Closest to the DefensiveWorks vision. Attack+Defend, multi-cloud, affordable. But lacks structured self-paced AWS curriculum and formal certification.

### 1.5 CyberWarFare Labs
- **URL:** https://cyberwarfare.live
- **What it offers:** Red team, blue team, and purple team certifications. Cloud-specific: CARTS (AWS Cloud Red Team Specialist), MCRTA (Multi-Cloud Red Team Analyst), CPTA (Purple Team Analyst). "Infinity" platform for end-to-end attack/defense scenarios.
- **Pricing:**
  - CARTS: $599 (premium), 30-day lab access, lifetime course access, 2 exam attempts
  - MCRTA: ~$49
  - Individual certs range from $49-$599
  - Frequent 50% off sales (e.g., CWLXMAS50)
  - Infinity platform: Subscription-based (pricing not publicly listed)
- **Target audience:** Red teamers, cloud pentesters, purple teamers
- **Covers:** AWS red teaming (CARTS), Azure/GCP (MCRTA), purple team operations, APT simulation labs. CARTS covers IAM, VPC, EC2, Lambda, S3, RDS, containers, SSO aligned to MITRE ATT&CK Cloud.
- **Misses:** Content quality inconsistent (you failed CARTS first try). Documentation can be sparse. Exam stability reported as issue. No defensive-only path. Platform UX is rough. AWS defense coverage is minimal.
- **KEY COMPETITOR:** Direct competitor for AWS offensive cloud security. But weak on defense side and platform quality.

### 1.6 CloudBreach
- **URL:** https://cloudbreach.io
- **What it offers:** Offensive cloud security training and certifications. Breaching AWS (OAWSP cert), Breaching Azure (OASP cert). Real cloud environment labs.
- **Pricing:**
  - Breaching AWS: $599 (30-day labs, 1 exam) / $799 (60-day labs, 1 exam) / $1,000 (60-day labs, 2 exams, priority support)
  - OAWSP exam: 24-hour practical exam
  - Breaching Azure: Similar tiers (details on site)
  - Enterprise/custom pricing available
- **Target audience:** Cloud security professionals, pentesters transitioning to cloud
- **Covers:** AWS recon, phishing, secrets extraction, container/K8s misconfig, IAM abuse, Lambda exploitation, EC2 compromise. Real AWS environments.
- **Misses:** Offense only, no defense content. Labs are time-limited and cannot be paused. Expensive per-course model. No subscription access. No GCP content. Small course catalog (2 courses).
- **KEY COMPETITOR:** You passed OAWSP. High quality but narrow (offense only, 2 courses). No path to blue team or purple team.

### 1.7 Altered Security
- **URL:** https://www.alteredsecurity.com
- **What it offers:** Red team training focused on Active Directory and Azure. CARTP (Certified Azure Red Team Professional), CARTE (Certified Azure Red Team Expert).
- **Pricing:**
  - CARTP: $449 standalone / $499 bootcamp (4-week live sessions)
  - CARTE: Similar range (advanced, 48-hour exam)
  - Re-attempts: $99 each
  - Discounts: AZURE20OFF (20% off), up to 10% bundle discount
- **Target audience:** Red teamers, Azure security professionals
- **Covers:** Azure AD exploitation, Entra ID, Azure privilege escalation, persistence, lateral movement. Both beginner (CARTP) and advanced (CARTE).
- **Misses:** Azure only, no AWS or GCP. Offense only. No blue team/defense content. No cloud-native service exploitation (focused on identity/AD aspects of Azure).

### 1.8 INE Security (formerly eLearnSecurity)
- **URL:** https://ine.com/security
- **What it offers:** Comprehensive cybersecurity training platform. 3,500+ hours of content. Certifications: eJPT, eCPPT, eWPT, eMAPT. Cloud security within broader curriculum.
- **Pricing:**
  - INE Premium: $749/year (promotional: sometimes $499)
  - Includes 1 free cert exam voucher
  - No monthly option confirmed
- **Target audience:** Broad cybersecurity professionals, from junior to senior
- **Covers:** Pentesting, web app security, network security, some cloud modules within broader paths
- **Misses:** Cloud security is a small portion of the total library. No dedicated cloud certifications. No hands-on cloud labs (simulated environments). Generalist platform, not cloud-specialized.

### 1.9 OffSec
- **URL:** https://www.offsec.com
- **What it offers:** Industry-leading pentesting certifications (OSCP+, OSEP, OSED, OSWA, OSWE). PEN-200 now includes AWS cloud module (beta, not on exam).
- **Pricing:**
  - Learn One: $2,749/year (1 course + 2 exam attempts)
  - Learn Unlimited: $6,099/year (all courses, unlimited exams)
- **Target audience:** Serious pentesters, red teamers, security professionals
- **Covers:** Network pentesting, web apps, exploit development, Active Directory. AWS module added to PEN-200 but NOT on exam yet.
- **Misses:** Cloud is an afterthought (beta module). Extremely expensive. No Azure/GCP. No cloud defense. The OSCP is not a cloud cert. Cloud content will take years to mature.

### 1.10 Wiz CTF Challenges
- **URL:** https://www.wiz.io/ctf / https://cloudsecuritychampionship.com
- **What it offers:** Free monthly CTF challenges built by Wiz researchers. CloudSec Academy (free educational content). Wiz Certified program.
- **Pricing:** FREE
- **Available CTFs:**
  - Cloud Security Championship (monthly expert-level challenges)
  - Big IAM Challenge
  - Kubernetes LAN Party
  - Cloud Hunting Games (IR-focused)
  - Prompt Airlines (AI security)
  - EKS Cluster Games
- **Target audience:** Cloud security practitioners of all levels
- **Covers:** IAM misconfigurations, K8s security, cloud IR, AI security, Entra ID. Expert-level monthly challenges.
- **Misses:** No structured learning path. One-off challenges, not a curriculum. No hands-on persistent labs. No certifications. Marketing tool for Wiz product. Limited to what Wiz researchers find interesting.
- **IMPORTANT:** Sets the bar for "free cloud security CTF." DefensiveWorks would need to differentiate with structured curriculum, not just challenges.

### 1.11 flAWS and flAWS2
- **URL:** http://flaws.cloud / http://flaws2.cloud
- **What it offers:** Free guided AWS security CTFs. flAWS: 6 levels of AWS misconfigs. flAWS2: Attacker path (Lambda/ECS Fargate exploitation) + Defender path (incident response).
- **Pricing:** FREE
- **Status (March 2026):** Sites still accessible. Created by Scott Piper (Summit Route). NOT actively maintained, content is static from ~2018-2019 era.
- **Target audience:** AWS security beginners
- **Covers:** S3 bucket misconfigs, metadata service abuse, basic IAM issues, serverless exploitation
- **Misses:** Outdated (pre-IMDSv2, pre-many AWS security features). No modern attack techniques. No ongoing updates. Very limited scope (6-12 challenges total). No defense coverage beyond flAWS2 defender path.

### 1.12 CloudGoat (Rhino Security Labs)
- **URL:** https://github.com/RhinoSecurityLabs/cloudgoat
- **What it offers:** "Vulnerable by Design" AWS deployment tool. Deploy CTF-style scenarios in your own AWS account.
- **Pricing:** FREE (open source, but you pay for AWS resources)
- **Status (March 2026):** Actively maintained. 3,523 GitHub stars, 741 forks. Latest release v2.3.1 (Sept 2025). Updated March 23, 2026.
- **Target audience:** AWS pentesters, security researchers
- **Covers:** IAM privilege escalation, S3 exploitation, EC2 SSRF, Lambda security, multiple attack scenarios
- **Misses:** Self-hosted only (need your own AWS account + incur costs). No guided learning. No defense content. No UI/platform. Requires Terraform knowledge. No certifications.

### 1.13 CloudFoxable (Bishop Fox)
- **URL:** https://github.com/BishopFox/cloudfoxable
- **What it offers:** Vulnerable-by-design AWS pentesting playground in CTF format. Inspired by CloudGoat and flAWS.
- **Pricing:** FREE (open source, AWS costs apply)
- **Target audience:** Cloud pentesters
- **Covers:** AWS IAM exploitation, privilege escalation, multiple flags to capture
- **Misses:** Self-hosted. No guided curriculum. No defense. No platform/UI. Requires AWS account.

### 1.14 IAM Vulnerable (Bishop Fox)
- **URL:** https://github.com/BishopFox/iam-vulnerable
- **What it offers:** Terraform-deployed vulnerable IAM privilege escalation playground.
- **Pricing:** FREE (open source)
- **Target audience:** AWS security practitioners focused on IAM
- **Covers:** 31+ IAM privilege escalation paths
- **Misses:** IAM only. Self-hosted. No guided learning. No UI. Very narrow scope.

### 1.15 AWSGoat / GCPGoat (INE Labs)
- **URL:** https://github.com/ine-labs/AWSGoat / https://github.com/ine-labs/GCPGoat
- **What it offers:** Damn Vulnerable cloud infrastructure. OWASP Top 10 + cloud misconfigs. Attack and defense manuals included.
- **Pricing:** FREE (open source, cloud costs apply)
- **Target audience:** Cloud security learners, pentesters
- **Covers:** AWSGoat: IAM, S3, API Gateway, Lambda, EC2, ECS. GCPGoat: IAM, Storage, Cloud Functions, Compute Engine.
- **Misses:** Self-hosted. Basic documentation. Limited scenarios. No platform. No community.

### 1.16 Sadcloud
- **URL:** https://github.com/nccgroup/sadcloud (NCC Group)
- **What it offers:** Creates vulnerable AWS services via Terraform. No guided walkthrough.
- **Pricing:** FREE (open source)
- **Misses:** No learning guidance, just deploys vulnerable resources. Minimal documentation.

### 1.17 Thunder CTF
- **URL:** https://thunder-ctf.cloud
- **What it offers:** GCP cloud security CTF. Deploys level infrastructure on demand to your GCP project.
- **Pricing:** FREE (open source, GCP costs apply)
- **Status:** Accessible but unclear if actively maintained in 2026.
- **Covers:** GCP security misconfigurations, privilege escalation
- **Misses:** GCP only. Academic project. Limited scenarios. Self-hosted.

---

## SECTION 2: DEFENSIVE / BLUE TEAM PLATFORMS

### 2.1 SANS Institute Cloud Security Courses
- **URL:** https://www.sans.org/cloud-security/
- **What it offers:** Gold-standard cloud security training. Key courses:
  - SEC510: Cloud Security Engineering and Controls ($8,780 + $999 cert)
  - SEC541: Cloud Security ($8,260 + $999 cert)
  - SEC588: Cloud Penetration Testing (similar range)
  - SEC502: Cloud Security Tactical Defense (new)
  - SEC598: AI and Security Automation for Red, Blue, and Purple Teams
- **Pricing:** $8,260-$9,779 per course (course + certification). OnDemand options available.
- **Target audience:** Senior security professionals, enterprise teams with training budgets
- **Covers:** Comprehensive cloud security engineering, cloud pentesting, multi-cloud defense, compliance, architecture
- **Misses:** Extremely expensive ($8K-10K per course). Not accessible to individual practitioners. Course-based (not subscription). Limited hands-on time relative to cost. No always-on lab environment.

### 2.2 AWS Security Specialty Training
- **Stephane Maarek (Udemy):** https://www.udemy.com/course/ultimate-aws-certified-security-specialty/
  - Updated Feb 2026 for SCS-C03
  - Pricing: ~$15-50 on Udemy (frequent sales)
  - Covers: AWS Security Specialty cert prep, IAM, KMS, GuardDuty, Security Hub, etc.
  - Misses: Video-only, no hands-on labs. Cert prep, not practical skills.

- **A Cloud Guru (Pluralsight):** ~$35/month
  - Cloud-focused training platform (now part of Pluralsight)
  - Covers: AWS, Azure, GCP cert prep with some labs
  - Misses: Labs are sandboxed/simplified. Not security-focused. Cert prep oriented.

### 2.3 Cloud Security Alliance (CSA)
- **URL:** https://cloudsecurityalliance.org/education
- **What it offers:**
  - CCSK (Certificate of Cloud Security Knowledge): $395-$445 (exam, 2 attempts)
  - Advanced Cloud Security Practitioner: $2,195 training
- **Target audience:** Cloud security managers, architects, compliance professionals
- **Covers:** Cloud security governance, risk, compliance, shared responsibility model, cloud architecture security
- **Misses:** Theoretical/governance focused. No hands-on labs. No offensive content. No AWS-specific depth.

### 2.4 ISC2 CCSP
- **URL:** https://www.isc2.org/certifications/ccsp
- **What it offers:** Certified Cloud Security Professional certification. The "CISSP of cloud."
- **Pricing:** Exam: $599. Training: varies ($2,000-$4,000 for bootcamps)
- **Target audience:** Senior cloud security professionals, architects
- **Covers:** Cloud concepts, architecture, data security, platform/infrastructure security, operations, legal/compliance
- **Misses:** Theoretical exam (multiple choice). No hands-on component. Management/governance focus. New exam outline effective Aug 2026.

### 2.5 Immersive Labs
- **URL:** https://www.immersivelabs.com
- **What it offers:** 2,500+ hands-on labs covering offensive, defensive, and cloud security. Cloud security training for AWS, Azure, GCP.
- **Pricing:** Enterprise only (not publicly listed). Estimated $15K+ annually.
- **Target audience:** Enterprise security teams
- **Covers:** Cloud security fundamentals, advanced threats, secure coding, incident response
- **Misses:** Enterprise-only pricing. Not accessible to individuals. Pricing opaque.

### 2.6 RangeForce
- **URL:** https://www.rangeforce.com
- **What it offers:** Cloud-based cyber range for defensive team training. Skills labs and team exercises in quarterly cycles.
- **Pricing:** Enterprise only. Estimated starting ~$15K/year.
- **Target audience:** Enterprise security teams, SOC teams
- **Covers:** Defensive skills, team exercises, soft skills, cloud security modules
- **Misses:** Enterprise-only. No individual access. Cloud security is subset of broader offering. No offensive content.

### 2.7 Cybrary
- **URL:** https://www.cybrary.it
- **What it offers:** Cybersecurity courses and certification prep. Free tier available. Cloud security courses including CCSK prep (free), CCSP prep, cloud fundamentals.
- **Pricing:**
  - Free: Limited courses (including CCSK)
  - Insider Pro: $39-59/month
- **Target audience:** Beginners to mid-level cybersecurity professionals
- **Covers:** Broad cybersecurity, some cloud modules, cert prep
- **Misses:** Cloud content is thin. Labs are basic. Video-heavy, limited hands-on. Not cloud-specialized.

### 2.8 Pluralsight
- **URL:** https://www.pluralsight.com
- **What it offers:** Massive course library including 14+ cloud security courses. Acquired A Cloud Guru.
- **Pricing:**
  - Individual: ~$33/user/month annually (~$468/year)
  - 10-day free trial
- **Target audience:** Broad tech professionals
- **Covers:** Cloud security fundamentals, AWS/Azure/GCP security, IAM, network security, compliance
- **Misses:** Generalist platform. Cloud security is a fraction of offering. Limited hands-on labs. No practical certifications. Video-lecture focused.

### 2.9 Security Blue Team
- **URL:** https://www.securityblue.team
- **What it offers:** Defensive cybersecurity certifications. BTL1 (junior) and BTL2 (advanced). Practical, hands-on exams.
- **Pricing:**
  - BTL1: $490 (training + labs + 2 exam attempts)
  - BTL2: Not publicly listed (estimated $800-1,200). 5 months access, 231 lessons, 28 browser labs, 72-hour practical exam.
  - Corporate/volume discounts available (~15% savings)
- **Target audience:** Blue teamers, SOC analysts, defensive security professionals
- **Covers:** Threat intelligence, SIEM, incident response, digital forensics, network analysis
- **Misses:** No cloud-specific content or path. Traditional infrastructure focused. No AWS/Azure/GCP labs. No offensive content.

---

## SECTION 3: PURPLE TEAM / COMBINED PLATFORMS

### 3.1 AppSecEngineer
- **URL:** https://www.appsecengineer.com
- **What it offers:** Purple Team AWS Training with "Attack, Detect and Defence" cyber-ranges. Dedicated AWS, Azure, GCP security learning paths. Cloud sandboxes.
- **Pricing:**
  - Pro: $399/year ($33.25/mo) - All courses + unlimited labs (no cloud sandboxes)
  - Pro Plus: $499/year ($41.58/mo) - Everything + AWS/Azure/GCP cloud sandboxes + AI/LLM labs
  - DevSecOps Cert + Pro: $599/year
  - DevSecOps Cert + Pro Plus: $699/year
- **Target audience:** Security engineers, DevSecOps professionals, cloud security practitioners
- **Covers:** AWS security (attack + detect + defend), Azure security, GCP security, Kubernetes security, DevSecOps. Cookbook-style attack-detect-defend methodology.
- **Misses:** Relatively unknown brand. No standalone cloud security certifications (DevSecOps cert only). Enterprise purple team AWS training pricing not public. Quality and depth of AWS-specific content unclear.
- **KEY COMPETITOR:** Most similar to DefensiveWorks vision in approach (attack+detect+defend for AWS). Affordable at $499/yr with cloud sandboxes. But lacks brand recognition and cloud-specific certs.

### 3.2 CyberWarFare Labs Infinity Platform
- **URL:** https://cyberwarfare.live
- **What it offers:** End-to-end platform combining Offensive, Defensive, Cloud, K8s, APT, and AI security in simulated enterprise scenarios. Purple Team path with CPTA (Purple Team Analyst) certification.
- **Pricing:** Subscription-based (not publicly listed for Infinity). Individual certs: $49-$599.
- **Target audience:** Red/blue/purple teamers
- **Covers:** Full attack lifecycle + detection + response in single scenarios. Cloud security across providers.
- **Misses:** Platform quality concerns. Content inconsistency. UX issues. Pricing opacity for Infinity platform.

### 3.3 Antisyphon Training
- **URL:** https://www.antisyphontraining.com
- **What it offers:** "Pay What You Can" model for live training. Cloud courses include "Defending M365 and Azure."
- **Pricing:**
  - Pay What You Can (PWYC) model
  - Specific courses: $825-$1,450 for 16-hour live courses
- **Target audience:** Broad cybersecurity community, budget-conscious learners
- **Covers:** M365/Azure defense, general security operations, threat hunting
- **Misses:** Limited cloud catalog. No AWS-specific courses found. No self-paced labs. No certifications. Live-event dependent (scheduling constraint).

### 3.4 AttackIQ Academy
- **URL:** https://www.academy.attackiq.com
- **What it offers:** Free cybersecurity training. 70,000+ students in 192 countries. MITRE ATT&CK focused. Enterprise reporting launched April 2025.
- **Pricing:** FREE
- **Target audience:** Security operations teams, defenders
- **Covers:** MITRE ATT&CK framework, threat-informed defense, some cloud threat content, AI security fundamentals
- **Misses:** Cloud security is minimal. Users have requested more cloud content. Marketing vehicle for AttackIQ product. No hands-on cloud labs.

### 3.5 NotSoSecure
- **URL:** https://notsosecure.com
- **What it offers:** "Hacking and Securing Cloud Infrastructure" course. Defense by Offense methodology.
- **Pricing:** Not publicly listed (estimated $2,000-$4,000 per course)
- **Target audience:** Cloud security professionals, pentesters
- **Covers:** Cloud infrastructure hacking and securing using offensive research
- **Misses:** Single course offering. Pricing opaque. Limited availability.

### 3.6 Hacking The Cloud
- **URL:** https://hackingthe.cloud
- **What it offers:** Free, community-driven encyclopedia of cloud attack tactics/techniques. 41 contributors as of 2025. Associated with fwd:cloudsec conference.
- **Pricing:** FREE (open source)
- **Target audience:** Offensive cloud security professionals
- **Covers:** AWS, Azure, GCP attack techniques, Docker, Terraform, K8s. Community contributed.
- **Misses:** Reference material, not a training platform. No labs. No structured curriculum. No defense content. No certifications.

---

## SECTION 4: SELF-HOSTED / OPEN SOURCE TOOLS SUMMARY

| Tool | Cloud | Type | Status (2026) | Stars | Self-Hosted |
|------|-------|------|---------------|-------|-------------|
| CloudGoat | AWS | Vuln-by-design | Active (Mar 2026) | 3,523 | Yes |
| CloudFoxable | AWS | CTF playground | Active | ~1K | Yes |
| IAM Vulnerable | AWS | IAM priv-esc | Active | ~1K | Yes |
| AWSGoat | AWS | Vuln infra | Active | ~1K | Yes |
| GCPGoat | GCP | Vuln infra | Active | ~500 | Yes |
| Sadcloud | AWS | Vuln deployer | Maintenance | ~500 | Yes |
| flAWS/flAWS2 | AWS | Hosted CTF | Static (2018-19) | N/A | No (hosted) |
| Thunder CTF | GCP | CTF | Unclear | ~500 | Yes |
| Wiz CTFs | Multi | Hosted CTF | Active (monthly) | N/A | No (hosted) |

---

## SECTION 5: PRICING LANDSCAPE ANALYSIS

### The Pricing Spectrum (Individual Practitioner)

| Price Tier | Platforms | Format |
|-----------|-----------|--------|
| **FREE** | Wiz CTFs, flAWS, CloudGoat, CloudFoxable, IAM Vulnerable, AWSGoat, AttackIQ Academy, Hacking The Cloud, TryHackMe (limited) | CTFs, self-hosted tools, limited content |
| **$8-20/mo** ($96-240/yr) | TryHackMe ($126/yr), PentesterLab ($200/yr) | Broad security, minimal cloud |
| **$15-50/mo** ($180-600/yr) | Pwned Labs ($200/yr), Cybrary ($39-59/mo), Pluralsight ($33/mo), A Cloud Guru ($35/mo), Udemy courses ($15-50 one-time) | Mix of video + some labs, cloud as subset |
| **$33-42/mo** ($399-499/yr) | AppSecEngineer ($399-499/yr) | Purple team, cloud sandboxes, structured paths |
| **$50-65/mo** ($490-749/yr) | HTB Academy ($490/yr), Security Blue Team BTL1 ($490), INE ($749/yr) | Certifications, structured paths |
| **$450-600** (one-time) | Altered Security CARTP ($449), CyberWarFare CARTS ($599), CloudBreach OAWSP ($599-$1,000), CCSK ($395-445), CCSP ($599 exam) | Individual certifications |
| **$2,000-3,000/yr** | OffSec Learn One ($2,749/yr), CSA Advanced ($2,195) | Premium individual |
| **$6,000+/yr** | OffSec Learn Unlimited ($6,099/yr) | All-access premium |
| **$8,000-10,000** (per course) | SANS SEC510/SEC541/SEC588 ($8,260-$9,779) | Enterprise-funded, gold standard |

### THE GAP: $30-100/month for Individual Practitioners

**The critical gap is clear.** There are very few platforms serving the individual cloud security practitioner at $30-100/month that provide:
1. Hands-on cloud labs (not simulated)
2. Both attack AND defense content
3. AWS-specific depth (not cloud-as-a-subset)
4. Structured curriculum (not random CTFs)
5. Meaningful certification

**Who currently serves this tier:**
- **Pwned Labs** ($200/yr = $17/mo) - Closest, but limited self-paced AWS depth
- **AppSecEngineer** ($499/yr = $42/mo) - Has the model but lacks brand/recognition/cloud certs
- **CyberWarFare Labs** ($599 one-time for CARTS) - Has AWS cert but quality concerns

**Who does NOT serve this tier:**
- SANS ($8K+ per course) - priced out
- OffSec ($2,749-$6,099/yr) - cloud is an afterthought
- HTB (cloud labs enterprise-only) - individual can't access cloud content
- CloudBreach ($599-$1,000 per course) - offense only, no subscription model

---

## SECTION 6: MARKET DATA

### Cloud Security Training Market
- Market size (2024): $1.27 billion
- Projected (2033): $5.94 billion
- CAGR: 18.2%
- Cloud-based delivery: 73.65% of training (2025), growing at 18.72% CAGR

### Cybersecurity Skills Gap
- Global unfilled cybersecurity positions: **4.8 million** (2026)
- Organizations reporting active shortage: **74%**
- Teams reporting skills gaps (especially cloud + AI): **90%**
- Organizations in early-stage cloud security maturity: **59%**
- Organizations citing tool sprawl/visibility as top barrier: **69%**
- Skills gap worsening: 59% report critical/significant gaps, up from 44% prior year

### Cloud Security Demand
- Cloud security: **#1 technical skill** hiring managers prioritize (29%)
- 77% of security leaders express high concern about cloud skills gap
- Top roles 2026: Cloud Security Engineer, AI Security Specialist, Zero Trust Architect
- ISC2 workforce study (16,029 professionals surveyed): Cloud security certification demand remains robust

### AI Impact
- 63% of companies considering GenAI to support cybersecurity staffing shortages
- 41% already leveraging GenAI to address skills gap
- SANS SEC598 now integrates AI into purple team automation

---

## SECTION 7: COMPETITIVE POSITIONING MATRIX

### What Exists vs. What's Missing

| Capability | Who Does It | Who Does It for AWS Specifically | Gap? |
|-----------|-------------|----------------------------------|------|
| Offensive cloud labs | HTB, Pwned Labs, CloudBreach, CloudGoat, CWL | CloudBreach (OAWSP), CWL (CARTS), CloudGoat | Covered but fragmented |
| Defensive cloud labs | SANS, Immersive, RangeForce | SANS SEC510 ($9K) | MASSIVE GAP at affordable tier |
| Both attack+defend | AppSecEngineer, CWL Infinity, Pwned Labs bootcamps | AppSecEngineer (limited), CWL (quality issues) | MAJOR GAP, especially for AWS |
| Structured AWS curriculum | CloudBreach (offense), SANS (defense) | CloudBreach, SANS | Gap in combined attack+defend |
| AWS-specific certification | CloudBreach OAWSP, CWL CARTS, AWS Security Specialty | Yes, but offense-only (OAWSP/CARTS) or theory (AWS cert) | No hands-on attack+defend AWS cert |
| $30-100/mo subscription | AppSecEngineer, Pwned Labs | AppSecEngineer ($42/mo) | Barely served |
| Individual practitioner focus | Most platforms | Few with AWS depth | Significant gap |
| Purple team cloud | AppSecEngineer, CWL, SANS SEC598 | AppSecEngineer (limited brand) | Underserved |

### The Specific Gaps DefensiveWorks Can Fill

1. **No affordable, structured, AWS-specific Attack+Defend curriculum exists.** CloudBreach is offense-only. SANS defense is $9K. AppSecEngineer comes closest but lacks brand, community, and AWS certification.

2. **No cloud security certification validates both offensive AND defensive AWS skills.** OAWSP/CARTS are offense-only. AWS Security Specialty is theory. CCSP/CCSK are governance. There is NO "OSCP for AWS" that tests both attack and defense.

3. **The $30-100/month tier for individual cloud security practitioners is nearly empty.** Most platforms either serve the free/hobbyist tier or the $8K enterprise tier. The working professional who wants to upskill on their own dime has few options.

4. **No platform combines AI-assisted learning with cloud security labs.** All platforms are traditional video+lab or CTF format. None leverage AI for adaptive difficulty, personalized learning paths, or AI-powered hints.

5. **Defense content at affordable prices is virtually nonexistent.** Cloud security defense training is trapped behind SANS ($9K) or enterprise-only platforms (Immersive, RangeForce). Individual defenders have almost no options for hands-on cloud defense practice.

---

## SECTION 8: KEY TAKEAWAYS FOR DEFENSIVEWORKS

### Direct Competitors (ranked by threat level)
1. **Pwned Labs** - Closest model (attack+defend bootcamps, multi-cloud, affordable). Growing fast. Watch closely.
2. **AppSecEngineer** - Purple team AWS at $499/yr with cloud sandboxes. Right model, weak execution/brand.
3. **CyberWarFare Labs** - AWS cert (CARTS) + Infinity platform. Quality/UX concerns but has the concept.
4. **CloudBreach** - High quality AWS offense but offense-only and expensive per-course.

### Indirect Competitors
5. **Wiz CTFs** - Sets free cloud CTF standard. Brand/marketing advantage.
6. **HTB** - Could expand BlackSky cloud to individuals at any time.
7. **SANS** - Gold standard but priced out. Validates that demand exists.

### Differentiation Opportunities
- **Combined attack+defend AWS certification** (nobody has this)
- **$49-99/month subscription with real AWS labs** (massive gap)
- **AI-assisted learning** (nobody is doing this in cloud security)
- **Individual practitioner focus** (most competitors are enterprise or course-based)
- **Community-driven with open source components** (like CloudGoat but with platform/curriculum)

---

*Sources compiled from direct platform websites, G2, Capterra, web searches, and platform documentation as of March 24, 2026.*
