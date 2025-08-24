#!/usr/bin/env python3
"""
Demo script to showcase KQL Generator functionality
"""

from kql_generator import KQLQueryGenerator


def demo_prompt_generation():
    """Demonstrate query generation from prompts."""
    print("🔍 KQL Generator Demo - Prompt-based Generation")
    print("=" * 60)
    
    generator = KQLQueryGenerator()
    
    test_prompts = [
        "failed login attempts",
        "suspicious process execution", 
        "network connections to external IPs",
        "file modifications in system directories",
        "privilege escalation events",
        "general threat hunting for malware"
    ]
    
    for prompt in test_prompts:
        print(f"\n📝 Prompt: '{prompt}'")
        print("-" * 40)
        query = generator.generate_from_prompt(prompt)
        print(query)
        print()


def demo_template_usage():
    """Demonstrate template-based generation."""
    print("\n🛠️ KQL Generator Demo - Template Usage")
    print("=" * 60)
    
    generator = KQLQueryGenerator()
    
    # Show available templates
    print("\nAvailable Templates:")
    for name, template in generator.query_templates.items():
        print(f"• {name}: {template['description']}")
    
    print("\n📋 Sample Template Output (failed_logins with defaults):")
    print("-" * 50)
    
    # Generate a sample query with default parameters
    query = generator.query_templates["failed_logins"]["template"].format(
        timeframe="7d", 
        user_filter="admin"
    )
    print(query)


def main():
    """Run the demo."""
    print("🎯 KQL Query Generator - Functionality Demo")
    print("=" * 70)
    print("This demo showcases the KQL generator's capabilities for")
    print("cybersecurity professionals working with Azure Sentinel,")
    print("Microsoft Defender, and other KQL-enabled platforms.")
    print()
    
    demo_prompt_generation()
    demo_template_usage()
    
    print("\n✅ Demo completed successfully!")
    print("\nTo try the interactive mode, run:")
    print("python3 kql_generator.py --interactive")


if __name__ == "__main__":
    main()