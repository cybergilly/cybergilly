#!/usr/bin/env python3
"""
Demo script to showcase NIST 800-171 GRC Compliance Tool functionality
"""

from nist_800_171_grc import NISTGRCAssessment, ControlFamily


def demo_compliance_assessment():
    """Demonstrate full compliance assessment."""
    print("🔍 NIST 800-171 GRC Demo - Full Compliance Assessment")
    print("=" * 70)
    
    assessment = NISTGRCAssessment()
    
    print("\n📋 Available NIST 800-171 Controls:")
    for control_id, control in assessment.controls.items():
        print(f"• {control_id}: {control.title}")
    
    print(f"\n🎯 Running assessment on {len(assessment.controls)} controls...")
    assessment.assess_all_controls()
    
    print("\n📊 Assessment Results:")
    print("-" * 50)
    summary = assessment._get_compliance_summary()
    total = len(assessment.controls)
    
    for status, count in summary.items():
        if count > 0:
            percentage = (count / total) * 100
            print(f"• {status.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")


def demo_control_family_assessment():
    """Demonstrate control family assessment."""
    print("\n🛠️ NIST 800-171 GRC Demo - Control Family Assessment")
    print("=" * 70)
    
    assessment = NISTGRCAssessment()
    
    print("\n📋 Assessing Access Control Family (3.1):")
    print("-" * 40)
    
    family_controls = assessment.assess_control_family(ControlFamily.ACCESS_CONTROL)
    
    for control in family_controls:
        print(f"\n{control.control_id}: {control.title}")
        print(f"Status: {control.status.value.title()}")
        print(f"Azure Services: {', '.join(control.azure_mappings[:3])}...")
        if control.findings:
            print(f"Key Finding: {control.findings[0]}")


def demo_gap_analysis():
    """Demonstrate gap analysis functionality."""
    print("\n📈 NIST 800-171 GRC Demo - Gap Analysis")
    print("=" * 70)
    
    assessment = NISTGRCAssessment()
    assessment.assess_all_controls()
    
    gaps = assessment.generate_gap_analysis()
    
    print("\n🎯 Compliance Gaps by Priority:")
    print("-" * 40)
    
    for priority, items in gaps.items():
        if items:
            print(f"\n{priority.title()} Priority ({len(items)} items):")
            for item in items:
                print(f"  • {item}")


def demo_azure_mappings():
    """Demonstrate Azure service mappings."""
    print("\n☁️ NIST 800-171 GRC Demo - Azure Service Mappings")
    print("=" * 70)
    
    assessment = NISTGRCAssessment()
    
    print("\n🔗 NIST Controls → Azure Services Mapping:")
    print("-" * 50)
    
    for control_id, control in list(assessment.controls.items())[:3]:  # Show first 3
        print(f"\n{control_id}: {control.title}")
        print("Azure Services:")
        for service in control.azure_mappings:
            print(f"  • {service}")


def demo_reporting():
    """Demonstrate reporting capabilities."""
    print("\n📊 NIST 800-171 GRC Demo - Compliance Reporting")
    print("=" * 70)
    
    assessment = NISTGRCAssessment()
    assessment.assess_all_controls()
    
    print("\n📋 Sample Summary Report:")
    print("-" * 30)
    
    summary_report = assessment.generate_compliance_report("summary")
    # Show first part of the report
    lines = summary_report.split('\n')
    for line in lines[:15]:  # Show first 15 lines
        print(line)
    
    if len(lines) > 15:
        print("... (truncated)")


def main():
    """Run the demo."""
    print("🎯 NIST 800-171 GRC Compliance Tool - Functionality Demo")
    print("=" * 80)
    print("This demo showcases automated compliance assessment capabilities")
    print("for NIST SP 800-171 (Protecting Controlled Unclassified Information)")
    print("in Azure cloud environments.")
    print()
    
    demo_compliance_assessment()
    demo_control_family_assessment()
    demo_gap_analysis()
    demo_azure_mappings()
    demo_reporting()
    
    print("\n✅ Demo completed successfully!")
    print("\nTo try the tool yourself, run:")
    print("python3 nist_800_171_grc.py --help")
    print("\nQuick start examples:")
    print("python3 nist_800_171_grc.py --assess")
    print("python3 nist_800_171_grc.py --gap-analysis")
    print("python3 nist_800_171_grc.py --control-family '3.1' --detailed")


if __name__ == "__main__":
    main()