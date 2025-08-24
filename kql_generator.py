#!/usr/bin/env python3
"""
KQL Query Generator
A command-line tool for generating KQL (Kusto Query Language) queries based on user prompts.
Designed for cybersecurity professionals working with Azure Sentinel, Microsoft Defender, and other KQL-enabled platforms.
"""

import argparse
import sys
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class KQLQueryGenerator:
    """Main class for generating KQL queries based on user prompts."""
    
    def __init__(self):
        self.query_templates = {
            "failed_logins": {
                "description": "Query for failed login attempts",
                "template": """SigninLogs
| where TimeGenerated >= ago({timeframe})
| where ResultType != "0"
| where UserPrincipalName contains "{user_filter}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| order by TimeGenerated desc""",
                "parameters": ["timeframe", "user_filter"]
            },
            "suspicious_processes": {
                "description": "Query for suspicious process execution",
                "template": """DeviceProcessEvents
| where TimeGenerated >= ago({timeframe})
| where ProcessCommandLine has_any ({suspicious_commands})
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated desc""",
                "parameters": ["timeframe", "suspicious_commands"]
            },
            "network_connections": {
                "description": "Query for outbound network connections",
                "template": """DeviceNetworkEvents
| where TimeGenerated >= ago({timeframe})
| where ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| where RemotePort in ({ports})
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, InitiatingProcessFileName
| order by TimeGenerated desc""",
                "parameters": ["timeframe", "ports"]
            },
            "file_modifications": {
                "description": "Query for file creation/modification events",
                "template": """DeviceFileEvents
| where TimeGenerated >= ago({timeframe})
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any ({file_paths})
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated desc""",
                "parameters": ["timeframe", "file_paths"]
            },
            "privilege_escalation": {
                "description": "Query for potential privilege escalation attempts",
                "template": """SecurityEvent
| where TimeGenerated >= ago({timeframe})
| where EventID in (4728, 4729, 4732, 4733, 4756, 4757)
| where Account !endswith "$"
| project TimeGenerated, Computer, Account, Activity, SubjectUserName
| order by TimeGenerated desc""",
                "parameters": ["timeframe"]
            },
            "threat_hunting": {
                "description": "General threat hunting query",
                "template": """{table_name}
| where TimeGenerated >= ago({timeframe})
| where {search_field} has "{search_term}"
| project TimeGenerated, {display_fields}
| order by TimeGenerated desc
| take {limit}""",
                "parameters": ["table_name", "timeframe", "search_field", "search_term", "display_fields", "limit"]
            }
        }
        
        self.common_tables = [
            "SigninLogs", "AuditLogs", "SecurityEvent", "DeviceProcessEvents",
            "DeviceNetworkEvents", "DeviceFileEvents", "DeviceLogonEvents",
            "ThreatIntelligenceIndicator", "SecurityAlert", "SecurityIncident"
        ]
    
    def list_templates(self) -> None:
        """Display available query templates."""
        print("\nAvailable KQL Query Templates:")
        print("=" * 50)
        for key, template in self.query_templates.items():
            print(f"• {key}: {template['description']}")
        print()
    
    def generate_interactive_query(self) -> str:
        """Interactive mode for generating KQL queries."""
        print("\n🔍 KQL Query Generator - Interactive Mode")
        print("=" * 50)
        
        # Show available templates
        self.list_templates()
        
        # Get user choice
        template_choice = input("Enter template name (or 'custom' for custom query): ").strip().lower()
        
        if template_choice == 'custom':
            return self._generate_custom_query()
        elif template_choice in self.query_templates:
            return self._generate_from_template(template_choice)
        else:
            print(f"❌ Template '{template_choice}' not found.")
            return ""
    
    def _generate_from_template(self, template_name: str) -> str:
        """Generate query from a specific template."""
        template = self.query_templates[template_name]
        query = template["template"]
        
        print(f"\n📝 Configuring '{template_name}' query...")
        print(f"Description: {template['description']}")
        
        # Get parameters from user
        parameters = {}
        for param in template["parameters"]:
            if param == "timeframe":
                timeframe = input("Enter timeframe (e.g., 24h, 7d, 30d) [default: 24h]: ").strip() or "24h"
                parameters[param] = timeframe
            elif param == "user_filter":
                user_filter = input("Enter user filter (partial username or * for all): ").strip() or "*"
                parameters[param] = user_filter
            elif param == "suspicious_commands":
                commands = input("Enter suspicious commands (comma-separated): ").strip()
                if commands:
                    cmd_list = [f'"{cmd.strip()}"' for cmd in commands.split(',')]
                    parameters[param] = f"({', '.join(cmd_list)})"
                else:
                    parameters[param] = '("powershell", "cmd", "wscript", "cscript")'
            elif param == "ports":
                ports = input("Enter ports to monitor (comma-separated) [default: 80,443,22,3389]: ").strip()
                if ports:
                    parameters[param] = ports
                else:
                    parameters[param] = "80,443,22,3389"
            elif param == "file_paths":
                paths = input("Enter file paths to monitor (comma-separated): ").strip()
                if paths:
                    path_list = [f'"{path.strip()}"' for path in paths.split(',')]
                    parameters[param] = f"({', '.join(path_list)})"
                else:
                    parameters[param] = '("C:\\\\Windows\\\\System32", "C:\\\\Users", "C:\\\\Temp")'
            else:
                value = input(f"Enter value for {param}: ").strip()
                parameters[param] = value
        
        # Replace parameters in template
        try:
            formatted_query = query.format(**parameters)
            return formatted_query
        except KeyError as e:
            print(f"❌ Missing parameter: {e}")
            return ""
    
    def _generate_custom_query(self) -> str:
        """Generate a custom KQL query based on user input."""
        print("\n🛠️ Custom Query Builder")
        print("Available tables:", ", ".join(self.common_tables))
        
        table = input("\nEnter table name: ").strip()
        timeframe = input("Enter timeframe (e.g., 24h, 7d, 30d) [default: 24h]: ").strip() or "24h"
        search_field = input("Enter field to search in: ").strip()
        search_term = input("Enter search term: ").strip()
        limit = input("Enter result limit [default: 100]: ").strip() or "100"
        
        # Build custom query
        query = f"""{table}
| where TimeGenerated >= ago({timeframe})"""
        
        if search_field and search_term:
            query += f"""
| where {search_field} has "{search_term}" """
        
        query += f"""
| take {limit}"""
        
        return query
    
    def generate_from_prompt(self, prompt: str) -> str:
        """Generate KQL query from a natural language prompt."""
        prompt_lower = prompt.lower()
        
        # Simple keyword-based matching
        if any(word in prompt_lower for word in ["failed", "login", "signin", "authentication"]):
            return self.query_templates["failed_logins"]["template"].format(
                timeframe="24h", user_filter="*"
            )
        elif any(word in prompt_lower for word in ["process", "execution", "command"]):
            return self.query_templates["suspicious_processes"]["template"].format(
                timeframe="24h", suspicious_commands='("powershell", "cmd", "wscript")'
            )
        elif any(word in prompt_lower for word in ["network", "connection", "traffic"]):
            return self.query_templates["network_connections"]["template"].format(
                timeframe="24h", ports="80,443,22,3389"
            )
        elif any(word in prompt_lower for word in ["file", "creation", "modification"]):
            return self.query_templates["file_modifications"]["template"].format(
                timeframe="24h", file_paths='("C:\\\\Windows\\\\System32", "C:\\\\Temp")'
            )
        elif any(word in prompt_lower for word in ["privilege", "escalation", "admin"]):
            return self.query_templates["privilege_escalation"]["template"].format(timeframe="24h")
        else:
            # Default to threat hunting template
            return self.query_templates["threat_hunting"]["template"].format(
                table_name="SecurityEvent",
                timeframe="24h",
                search_field="Activity",
                search_term=prompt,
                display_fields="TimeGenerated, Computer, Account, Activity",
                limit="100"
            )


def main():
    """Main entry point for the KQL Generator CLI."""
    parser = argparse.ArgumentParser(
        description="Generate KQL queries for cybersecurity analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kql_generator.py --interactive
  python kql_generator.py --prompt "failed logins in the last 24 hours"
  python kql_generator.py --template failed_logins
  python kql_generator.py --list-templates
        """
    )
    
    parser.add_argument(
        "--interactive", "-i", 
        action="store_true",
        help="Run in interactive mode"
    )
    
    parser.add_argument(
        "--prompt", "-p",
        type=str,
        help="Generate query from natural language prompt"
    )
    
    parser.add_argument(
        "--template", "-t",
        type=str,
        help="Use specific template (use --list-templates to see available options)"
    )
    
    parser.add_argument(
        "--list-templates", "-l",
        action="store_true",
        help="List available query templates"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Save query to file"
    )
    
    args = parser.parse_args()
    
    generator = KQLQueryGenerator()
    query = ""
    
    if args.list_templates:
        generator.list_templates()
        return
    
    if args.interactive:
        query = generator.generate_interactive_query()
    elif args.prompt:
        query = generator.generate_from_prompt(args.prompt)
    elif args.template:
        if args.template in generator.query_templates:
            query = generator._generate_from_template(args.template)
        else:
            print(f"❌ Template '{args.template}' not found.")
            generator.list_templates()
            return
    else:
        # Default to interactive mode
        query = generator.generate_interactive_query()
    
    if query:
        print("\n" + "="*60)
        print("🔍 Generated KQL Query:")
        print("="*60)
        print(query)
        print("="*60)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(query)
            print(f"✅ Query saved to {args.output}")
    else:
        print("❌ No query generated.")


if __name__ == "__main__":
    main()