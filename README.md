# Post-Graduate Portfolio Development Plan - Cybersecurity Projects

## Overview
This document outlines my planned portfolio development strategy as a graduate with a Master's in Cybersecurity & Information Assurance from WGU. By implementing these projects, I aim to demonstrate practical skills that complement my academic knowledge and appeal to potential employers.

## Current Projects in Progress

- **KQL Query Generator** - Command-line tool for generating KQL queries from natural language prompts (✅ Completed)
- **The Overwatch Protocol** - Personal development framework book (currently in draft)
- **Cybersecurity Homelab Setup** - Creating virtualized environment for security testing
- **Certification Preparation** - CYSA+, Security+, Pentest+ study materials
- **Second Brain with Capacities** - Knowledge management system implementation

## Education

**Western Governors University**  
*Master's in Cybersecurity & Information Assurance*  
Graduated: May 2025

---

## Featured Project: KQL Query Generator

### Overview
*Command-line tool for generating KQL (Kusto Query Language) queries from natural language prompts*

**Description:** A Python-based CLI application designed for cybersecurity professionals working with Azure Sentinel, Microsoft Defender, and other KQL-enabled platforms. The tool translates natural language descriptions into properly formatted KQL queries for threat hunting, incident response, and security monitoring.

**Key Features:**
- Interactive query building with step-by-step prompts
- Natural language processing for query generation
- Pre-built templates for common cybersecurity scenarios
- Support for failed login analysis, process monitoring, network traffic analysis
- Export capabilities and customizable parameters

**Technologies:** `Python 3` `KQL` `Azure Sentinel` `Microsoft Defender` `CLI`

**Usage Examples:**
```bash
# Generate query from natural language
python3 kql_generator.py --prompt "failed logins in the last 24 hours"

# Interactive mode with guided prompts
python3 kql_generator.py --interactive

# Use predefined security templates
python3 kql_generator.py --template suspicious_processes
```

**Sample Output:**
```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| order by TimeGenerated desc
```

**Documentation:** See [KQL_GENERATOR_README.md](KQL_GENERATOR_README.md) for detailed usage instructions.

---
## Larger-Scale Integration Projects

### Home Security Operations Center
*Implementation of SOC capabilities in home lab environment*

**Implementation Plan:**
- Deploy Security Onion as monitoring platform
- Configure network sensors and log collectors
- Create custom detection rules
- Develop incident response playbooks
- Build automated alerting system

**Technologies:** `Security Onion` `Suricata` `Zeek` `ELK Stack` `Sigma Rules`

**Project Timeline:** 2026

---

### Cloud Security Architecture
*Secure cloud environment design*

**Implementation Plan:**
- Design multi-account architecture
- Implement infrastructure-as-code with security controls
- Create compliance automation
- Deploy centralized logging
- Establish secure CI/CD pipelines

**Technologies:** `AWS` `Terraform` `CloudTrail` `CloudWatch` `Config Rules`

**Project Timeline:** 2026

*This plan outlines my strategy for developing a comprehensive cybersecurity portfolio.*
