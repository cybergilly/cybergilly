#!/usr/bin/env python3
"""
NIST 800-171 GRC Compliance Tool
A command-line tool for automated assessment and monitoring of NIST SP 800-171 controls in Azure environments.
Designed for cybersecurity professionals managing compliance with Controlled Unclassified Information (CUI) requirements.
"""

import argparse
import json
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class ControlStatus(Enum):
    """Status of NIST 800-171 control implementation."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"


class ControlFamily(Enum):
    """NIST 800-171 control families."""
    ACCESS_CONTROL = "3.1"
    AWARENESS_TRAINING = "3.2"
    AUDIT_ACCOUNTABILITY = "3.3"
    CONFIGURATION_MANAGEMENT = "3.4"
    IDENTIFICATION_AUTHENTICATION = "3.5"
    INCIDENT_RESPONSE = "3.6"
    MAINTENANCE = "3.7"
    MEDIA_PROTECTION = "3.8"
    PERSONNEL_SECURITY = "3.9"
    PHYSICAL_PROTECTION = "3.10"
    RISK_ASSESSMENT = "3.11"
    SECURITY_ASSESSMENT = "3.12"
    SYSTEM_COMMUNICATIONS_PROTECTION = "3.13"
    SYSTEM_INTEGRITY = "3.14"


@dataclass
class NISTControl:
    """Represents a NIST 800-171 control."""
    control_id: str
    family: ControlFamily
    title: str
    description: str
    azure_mappings: List[str]
    assessment_method: str
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    findings: List[str] = None
    recommendations: List[str] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.recommendations is None:
            self.recommendations = []


class NISTGRCAssessment:
    """Main class for NIST 800-171 GRC compliance assessment."""
    
    def __init__(self):
        self.controls = self._initialize_controls()
        self.assessment_date = datetime.now()
        
    def _initialize_controls(self) -> Dict[str, NISTControl]:
        """Initialize NIST 800-171 controls with Azure mappings."""
        controls = {}
        
        # Access Control Family (3.1)
        controls["3.1.1"] = NISTControl(
            control_id="3.1.1",
            family=ControlFamily.ACCESS_CONTROL,
            title="Limit system access to authorized users",
            description="Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
            azure_mappings=[
                "Azure Active Directory",
                "Conditional Access Policies",
                "Azure RBAC",
                "Privileged Identity Management"
            ],
            assessment_method="Review user access controls and authentication mechanisms"
        )
        
        controls["3.1.2"] = NISTControl(
            control_id="3.1.2",
            family=ControlFamily.ACCESS_CONTROL,
            title="Limit transaction and function access",
            description="Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
            azure_mappings=[
                "Azure RBAC",
                "Azure Policy",
                "Application Gateway",
                "API Management"
            ],
            assessment_method="Review role-based access controls and function restrictions"
        )
        
        # Configuration Management Family (3.4)
        controls["3.4.1"] = NISTControl(
            control_id="3.4.1",
            family=ControlFamily.CONFIGURATION_MANAGEMENT,
            title="Establish configuration baselines",
            description="Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation).",
            azure_mappings=[
                "Azure Security Center",
                "Azure Policy",
                "Azure Resource Manager Templates",
                "Azure Automation"
            ],
            assessment_method="Review configuration management policies and baseline documentation"
        )
        
        # System and Communications Protection Family (3.13)
        controls["3.13.1"] = NISTControl(
            control_id="3.13.1",
            family=ControlFamily.SYSTEM_COMMUNICATIONS_PROTECTION,
            title="Monitor communications at system boundaries",
            description="Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems).",
            azure_mappings=[
                "Azure Firewall",
                "Network Security Groups",
                "Application Gateway",
                "Azure Monitor"
            ],
            assessment_method="Review network monitoring and communication protection controls"
        )
        
        # System and Information Integrity Family (3.14)
        controls["3.14.1"] = NISTControl(
            control_id="3.14.1",
            family=ControlFamily.SYSTEM_INTEGRITY,
            title="Identify and correct system flaws",
            description="Identify, report, and correct information and information system flaws in a timely manner.",
            azure_mappings=[
                "Azure Security Center",
                "Azure Update Management",
                "Vulnerability Assessment",
                "Microsoft Defender for Cloud"
            ],
            assessment_method="Review vulnerability management and patch management processes"
        )
        
        return controls
    
    def assess_control(self, control_id: str) -> NISTControl:
        """Assess a specific NIST 800-171 control."""
        if control_id not in self.controls:
            raise ValueError(f"Control {control_id} not found")
        
        control = self.controls[control_id]
        
        # Simulate assessment logic (in real implementation, this would check Azure resources)
        if control_id == "3.1.1":
            control.status = ControlStatus.COMPLIANT
            control.findings = ["Azure AD authentication properly configured"]
            control.recommendations = ["Consider implementing MFA for all users"]
        elif control_id == "3.1.2":
            control.status = ControlStatus.PARTIALLY_COMPLIANT
            control.findings = ["RBAC roles defined but some over-privileged accounts found"]
            control.recommendations = ["Review and right-size user permissions", "Implement least privilege access"]
        elif control_id == "3.4.1":
            control.status = ControlStatus.NON_COMPLIANT
            control.findings = ["Configuration baselines not formally documented"]
            control.recommendations = ["Establish formal configuration baselines", "Implement Infrastructure as Code"]
        elif control_id == "3.13.1":
            control.status = ControlStatus.COMPLIANT
            control.findings = ["Network monitoring configured via Azure Monitor"]
            control.recommendations = ["Consider implementing additional DDoS protection"]
        elif control_id == "3.14.1":
            control.status = ControlStatus.COMPLIANT
            control.findings = ["Vulnerability assessment enabled", "Update management configured"]
            control.recommendations = ["Automate patch deployment where possible"]
        
        return control
    
    def assess_control_family(self, family: ControlFamily) -> List[NISTControl]:
        """Assess all controls in a specific family."""
        family_controls = []
        for control_id, control in self.controls.items():
            if control.family == family:
                assessed_control = self.assess_control(control_id)
                family_controls.append(assessed_control)
        return family_controls
    
    def assess_all_controls(self) -> Dict[str, NISTControl]:
        """Assess all NIST 800-171 controls."""
        for control_id in self.controls:
            self.assess_control(control_id)
        return self.controls
    
    def generate_gap_analysis(self) -> Dict[str, List[str]]:
        """Generate gap analysis based on assessment results."""
        gaps = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for control_id, control in self.controls.items():
            if control.status == ControlStatus.NON_COMPLIANT:
                gaps["high"].append(f"{control_id}: {control.title}")
            elif control.status == ControlStatus.PARTIALLY_COMPLIANT:
                gaps["medium"].append(f"{control_id}: {control.title}")
        
        return gaps
    
    def generate_compliance_report(self, format: str = "json") -> str:
        """Generate compliance assessment report."""
        report_data = {
            "assessment_date": self.assessment_date.isoformat(),
            "total_controls": len(self.controls),
            "compliance_summary": self._get_compliance_summary(),
            "controls": {}
        }
        
        for control_id, control in self.controls.items():
            report_data["controls"][control_id] = {
                "title": control.title,
                "family": control.family.value,
                "status": control.status.value,
                "azure_mappings": control.azure_mappings,
                "findings": control.findings,
                "recommendations": control.recommendations
            }
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        elif format == "summary":
            return self._generate_summary_report(report_data)
        else:
            return json.dumps(report_data, indent=2)
    
    def _get_compliance_summary(self) -> Dict[str, int]:
        """Get summary of compliance status."""
        summary = {status.value: 0 for status in ControlStatus}
        
        for control in self.controls.values():
            summary[control.status.value] += 1
        
        return summary
    
    def _generate_summary_report(self, report_data: Dict) -> str:
        """Generate a human-readable summary report."""
        summary = report_data["compliance_summary"]
        total = report_data["total_controls"]
        
        report = f"""
NIST 800-171 Compliance Assessment Report
========================================
Assessment Date: {report_data["assessment_date"]}
Total Controls Assessed: {total}

Compliance Summary:
- Compliant: {summary.get('compliant', 0)} ({(summary.get('compliant', 0)/total)*100:.1f}%)
- Partially Compliant: {summary.get('partially_compliant', 0)} ({(summary.get('partially_compliant', 0)/total)*100:.1f}%)
- Non-Compliant: {summary.get('non_compliant', 0)} ({(summary.get('non_compliant', 0)/total)*100:.1f}%)
- Not Assessed: {summary.get('not_assessed', 0)} ({(summary.get('not_assessed', 0)/total)*100:.1f}%)

High Priority Remediation Items:
"""
        
        for control_id, control_data in report_data["controls"].items():
            if control_data["status"] == "non_compliant":
                report += f"- {control_id}: {control_data['title']}\n"
        
        return report


def main():
    """Main entry point for the NIST 800-171 GRC CLI."""
    parser = argparse.ArgumentParser(
        description="NIST 800-171 GRC Compliance Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nist_800_171_grc.py --assess
  python nist_800_171_grc.py --control-family "3.1" --detailed
  python nist_800_171_grc.py --report --format summary
  python nist_800_171_grc.py --gap-analysis
        """
    )
    
    parser.add_argument(
        "--assess", "-a",
        action="store_true",
        help="Run full compliance assessment"
    )
    
    parser.add_argument(
        "--control", "-c",
        type=str,
        help="Assess specific control (e.g., 3.1.1)"
    )
    
    parser.add_argument(
        "--control-family", "-f",
        type=str,
        help="Assess specific control family (e.g., 3.1, 3.4)"
    )
    
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Generate compliance report"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "summary"],
        default="summary",
        help="Output format for reports"
    )
    
    parser.add_argument(
        "--gap-analysis", "-g",
        action="store_true",
        help="Generate gap analysis report"
    )
    
    parser.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Show detailed assessment results"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Save output to file"
    )
    
    args = parser.parse_args()
    
    # Create assessment instance
    assessment = NISTGRCAssessment()
    output = ""
    
    try:
        if args.assess:
            print("🔍 Running NIST 800-171 compliance assessment...")
            assessment.assess_all_controls()
            output = assessment.generate_compliance_report(args.format)
            print("✅ Assessment completed")
            
        elif args.control:
            print(f"🔍 Assessing control {args.control}...")
            control = assessment.assess_control(args.control)
            control_data = {
                "control_id": control.control_id,
                "title": control.title,
                "status": control.status.value,
                "findings": control.findings,
                "recommendations": control.recommendations
            }
            output = json.dumps(control_data, indent=2) if args.format == "json" else f"""
Control {control.control_id}: {control.title}
Status: {control.status.value.title()}
Findings: {', '.join(control.findings) if control.findings else 'None'}
Recommendations: {', '.join(control.recommendations) if control.recommendations else 'None'}
"""
            
        elif args.control_family:
            family_map = {cf.value: cf for cf in ControlFamily}
            if args.control_family in family_map:
                family = family_map[args.control_family]
                print(f"🔍 Assessing control family {args.control_family}...")
                controls = assessment.assess_control_family(family)
                
                if args.format == "json":
                    family_data = {}
                    for control in controls:
                        family_data[control.control_id] = {
                            "title": control.title,
                            "status": control.status.value,
                            "findings": control.findings,
                            "recommendations": control.recommendations
                        }
                    output = json.dumps(family_data, indent=2)
                else:
                    output = f"\nControl Family {args.control_family} Assessment Results:\n"
                    output += "=" * 50 + "\n"
                    for control in controls:
                        output += f"\n{control.control_id}: {control.title}\n"
                        output += f"Status: {control.status.value.title()}\n"
                        if args.detailed:
                            output += f"Findings: {', '.join(control.findings) if control.findings else 'None'}\n"
                            output += f"Recommendations: {', '.join(control.recommendations) if control.recommendations else 'None'}\n"
                        output += "-" * 30 + "\n"
            else:
                print(f"❌ Invalid control family: {args.control_family}")
                print("Valid families:", [cf.value for cf in ControlFamily])
                sys.exit(1)
                
        elif args.gap_analysis:
            print("🔍 Generating gap analysis...")
            assessment.assess_all_controls()
            gaps = assessment.generate_gap_analysis()
            
            output = "\nNIST 800-171 Gap Analysis Report\n"
            output += "=" * 40 + "\n"
            for severity, items in gaps.items():
                if items:
                    output += f"\n{severity.title()} Priority Gaps:\n"
                    for item in items:
                        output += f"  • {item}\n"
            
        elif args.report:
            print("📊 Generating compliance report...")
            assessment.assess_all_controls()
            output = assessment.generate_compliance_report(args.format)
            
        else:
            parser.print_help()
            sys.exit(1)
        
        # Output results
        if output:
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                print(f"✅ Output saved to {args.output}")
            else:
                print(output)
                
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()