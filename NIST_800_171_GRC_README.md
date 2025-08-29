# NIST 800-171 GRC Compliance Tool

A command-line tool for automated assessment and monitoring of NIST SP 800-171 controls in Azure environments. Designed for cybersecurity professionals managing compliance with Controlled Unclassified Information (CUI) requirements.

## Features

- **Automated Control Assessment**: Evaluate implementation of NIST 800-171 security controls
- **Azure Integration**: Specific mappings to Azure security services and capabilities
- **Gap Analysis**: Identify compliance gaps and prioritize remediation efforts
- **Compliance Reporting**: Generate detailed reports in multiple formats
- **Control Family Assessment**: Focus on specific control families for targeted reviews
- **Remediation Guidance**: Actionable recommendations for improving compliance posture

## Installation

No additional dependencies required. This tool uses only Python standard library modules.

```bash
# Clone the repository
git clone https://github.com/cybergilly/cybergilly.git
cd cybergilly

# Make the script executable
chmod +x nist_800_171_grc.py

# Run the tool
python3 nist_800_171_grc.py --help
```

## Usage

### Quick Start

```bash
# Run full compliance assessment
python3 nist_800_171_grc.py --assess

# Generate summary report
python3 nist_800_171_grc.py --report --format summary

# Perform gap analysis
python3 nist_800_171_grc.py --gap-analysis
```

### Command Line Options

```bash
# Assessment Options
--assess, -a                 Run full compliance assessment
--control, -c CONTROL_ID     Assess specific control (e.g., 3.1.1)
--control-family, -f FAMILY  Assess specific control family (e.g., 3.1)

# Reporting Options
--report, -r                 Generate compliance report
--gap-analysis, -g           Generate gap analysis report
--format FORMAT              Output format: json, summary (default: summary)
--detailed, -d               Show detailed assessment results

# Output Options
--output, -o FILE            Save output to file
```

## NIST 800-171 Control Families

The tool supports assessment of the following NIST SP 800-171 control families:

### Access Control (3.1)
- **3.1.1**: Limit system access to authorized users
- **3.1.2**: Limit transaction and function access

### Configuration Management (3.4)
- **3.4.1**: Establish and maintain baseline configurations

### System and Communications Protection (3.13)
- **3.13.1**: Monitor, control, and protect communications

### System and Information Integrity (3.14)
- **3.14.1**: Identify, report, and correct system flaws

*Additional controls can be easily added to expand coverage.*

## Azure Service Mappings

Each NIST 800-171 control includes mappings to relevant Azure services:

| Control | Azure Services |
|---------|----------------|
| 3.1.1 | Azure Active Directory, Conditional Access, Azure RBAC, PIM |
| 3.1.2 | Azure RBAC, Azure Policy, Application Gateway, API Management |
| 3.4.1 | Security Center, Azure Policy, ARM Templates, Azure Automation |
| 3.13.1 | Azure Firewall, NSGs, Application Gateway, Azure Monitor |
| 3.14.1 | Security Center, Update Management, Vulnerability Assessment |

## Examples

### Basic Assessment

```bash
# Assess all controls and generate summary report
python3 nist_800_171_grc.py --assess --format summary
```

### Control Family Assessment

```bash
# Assess Access Control family with detailed results
python3 nist_800_171_grc.py --control-family "3.1" --detailed

# Output:
# Control Family 3.1 Assessment Results:
# ==================================================
# 
# 3.1.1: Limit system access to authorized users
# Status: Compliant
# Findings: Azure AD authentication properly configured
# Recommendations: Consider implementing MFA for all users
```

### Specific Control Assessment

```bash
# Assess specific control and save to file
python3 nist_800_171_grc.py --control "3.4.1" --format json --output control_3-4-1.json
```

### Gap Analysis

```bash
# Generate gap analysis to identify compliance issues
python3 nist_800_171_grc.py --gap-analysis

# Output:
# NIST 800-171 Gap Analysis Report
# ========================================
# 
# High Priority Gaps:
#   • 3.4.1: Establish and maintain baseline configurations
# 
# Medium Priority Gaps:
#   • 3.1.2: Limit transaction and function access
```

## Sample Output

### Summary Report

```
NIST 800-171 Compliance Assessment Report
========================================
Assessment Date: 2024-01-15T10:30:00
Total Controls Assessed: 5

Compliance Summary:
- Compliant: 3 (60.0%)
- Partially Compliant: 1 (20.0%)
- Non-Compliant: 1 (20.0%)
- Not Assessed: 0 (0.0%)

High Priority Remediation Items:
- 3.4.1: Establish and maintain baseline configurations
```

### JSON Report

```json
{
  "assessment_date": "2024-01-15T10:30:00",
  "total_controls": 5,
  "compliance_summary": {
    "compliant": 3,
    "partially_compliant": 1,
    "non_compliant": 1,
    "not_applicable": 0,
    "not_assessed": 0
  },
  "controls": {
    "3.1.1": {
      "title": "Limit system access to authorized users",
      "family": "3.1",
      "status": "compliant",
      "azure_mappings": [
        "Azure Active Directory",
        "Conditional Access Policies",
        "Azure RBAC",
        "Privileged Identity Management"
      ],
      "findings": ["Azure AD authentication properly configured"],
      "recommendations": ["Consider implementing MFA for all users"]
    }
  }
}
```

## Control Status Types

- **Compliant**: Control is fully implemented and effective
- **Partially Compliant**: Control is implemented but has gaps or weaknesses
- **Non-Compliant**: Control is not implemented or ineffective
- **Not Applicable**: Control does not apply to the current environment
- **Not Assessed**: Control has not been evaluated

## Implementation Notes

### Azure Environment Assessment

The tool provides a framework for assessing NIST 800-171 compliance in Azure environments. In a production implementation, you would integrate with:

- **Azure Resource Graph**: Query Azure resources and configurations
- **Azure Security Center**: Retrieve security recommendations and findings
- **Azure Policy**: Evaluate policy compliance status
- **Azure Monitor**: Collect and analyze security logs
- **Microsoft Graph API**: Access identity and access management data

### Customization

The tool is designed to be easily extensible:

1. **Add New Controls**: Extend the `_initialize_controls()` method
2. **Custom Assessment Logic**: Modify the `assess_control()` method
3. **Additional Report Formats**: Extend the `generate_compliance_report()` method
4. **Azure API Integration**: Add Azure SDK calls for real-time assessment

## Testing

Run the included test suite to verify functionality:

```bash
python3 test_nist_800_171_grc.py
```

## Contributing

This tool is part of a cybersecurity portfolio project. Contributions and suggestions are welcome!

### Future Enhancements

- Integration with Azure APIs for real-time assessment
- Additional NIST 800-171 controls coverage
- Automated remediation recommendations
- Integration with SIEM and security orchestration tools
- Compliance tracking over time

## License

This project is part of a personal portfolio and is available for educational and professional use.

---

*Part of the Cybersecurity Portfolio by CyberGilly*