# 🛡️ KQL Sentinel Queries

A curated collection of KQL (Kusto Query Language) queries for Microsoft Sentinel, focused on threat detection, incident response, and security operations.

Built from real-world SOC experience and Microsoft SC-200 certification preparation.

##  About

**Etienne Moreau** | Support Center Team Lead → Aspiring SOC Analyst  
📜 SC-200 | SC-900 | MS-900 | AZ-900 | Security+ | Network+  
🔄 SC-300 In Progress  
🌐 Bilingual FR/EN | Quebec, Canada  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/etienne-moreau-136642a9/)

---

##  Repository Structure
kql-sentinel-queries/

├── identity-attacks/

│   ├── brute-force.kql

│   ├── password-spray.kql

│   ├── impossible-travel.kql

│   └── golden-ticket.kql

├── threat-intelligence/

│   ├── malicious-ip-correlation.kql

│   └── threat-intel-signin.kql

├── endpoint/

│   ├── suspicious-process.kql

│   └── lateral-movement.kql

└── incident-response/

└── aitm-detection.kql

---

##  Query Categories

### Identity Attacks
Detection rules for common identity-based attacks targeting Azure AD / Microsoft Entra ID.

| Query | Description | MITRE Tactic |
|-------|-------------|--------------|
| brute-force.kql | Detects failed sign-in attempts > 10 per user per hour | Credential Access |
| password-spray.kql | Identifies IPs targeting multiple accounts with failures | Credential Access |
| impossible-travel.kql | Flags sign-ins from 2+ countries within 1 hour | Initial Access |
| golden-ticket.kql | Detects anomalous Kerberos ticket usage | Lateral Movement |

### Threat Intelligence
Correlation queries matching logs against threat intelligence indicators.

| Query | Description | MITRE Tactic |
|-------|-------------|--------------|
| malicious-ip-correlation.kql | Cross-references SigninLogs with ThreatIntelligenceIndicator | Initial Access |
| threat-intel-signin.kql | Detects sign-ins from known malicious IPs | Initial Access |

### Endpoint
Detection rules for suspicious activity on devices via Microsoft Defender for Endpoint.

| Query | Description | MITRE Tactic |
|-------|-------------|--------------|
| suspicious-process.kql | Detects child processes spawned by Office applications | Execution |
| lateral-movement.kql | Identifies Pass-the-Hash and lateral movement patterns | Lateral Movement |

### Incident Response
Queries designed for active incident investigation and threat hunting.

| Query | Description |
|-------|-------------|
| aitm-detection.kql | Detects Adversary-in-the-Middle phishing token theft |

---

## How to Use

1. Open **Microsoft Sentinel** or **Azure Log Analytics**
2. Navigate to **Logs**
3. Copy and paste any `.kql` file content
4. Adjust time ranges and thresholds as needed for your environment

---

##  Example Query — Password Spray Detection

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType != 0
| summarize
    DistinctUserCount = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName)
    by IPAddress
| where DistinctUserCount > 10
| sort by DistinctUserCount desc
```

---

## 🛠️ Tools & Technologies

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto%20Query%20Language-blue)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoft-azure&logoColor=white)
![Defender XDR](https://img.shields.io/badge/Defender%20XDR-00B4D8?style=flat&logo=microsoft&logoColor=white)

---

##  Roadmap

- [x] Identity attack queries
- [x] Threat intelligence correlation
- [x] Endpoint detection queries
- [ ] Workbook templates
- [ ] Automation rule templates
- [ ] PowerShell IR scripts

---

##  License

MIT License — Feel free to use, modify, and share with attribution.

---

> *"Detection is only as good as the query behind it."*
