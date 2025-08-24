# KQL Query Generator

A command-line tool for generating KQL (Kusto Query Language) queries based on user prompts. Designed for cybersecurity professionals working with Azure Sentinel, Microsoft Defender, and other KQL-enabled platforms.

## Features

- **Interactive Mode**: Step-by-step query building with prompts
- **Natural Language Processing**: Generate queries from simple English descriptions
- **Pre-built Templates**: Ready-to-use templates for common cybersecurity scenarios
- **Customizable Parameters**: Flexible timeframes, filters, and search criteria
- **Multiple Output Options**: Display in terminal or save to file

## Installation

No external dependencies required! This tool uses only Python standard library modules.

```bash
# Clone the repository
git clone https://github.com/cybergilly/cybergilly.git
cd cybergilly

# Make the script executable (optional)
chmod +x kql_generator.py
```

## Usage

### Quick Start

```bash
# Interactive mode (recommended for beginners)
python3 kql_generator.py --interactive

# Generate from natural language prompt
python3 kql_generator.py --prompt "failed logins in the last 24 hours"

# Use a specific template
python3 kql_generator.py --template failed_logins

# List all available templates
python3 kql_generator.py --list-templates
```

### Command Line Options

```
usage: kql_generator.py [-h] [--interactive] [--prompt PROMPT] [--template TEMPLATE] [--list-templates] [--output OUTPUT]

Generate KQL queries for cybersecurity analysis

options:
  -h, --help            show this help message and exit
  --interactive, -i     Run in interactive mode
  --prompt PROMPT, -p PROMPT
                        Generate query from natural language prompt
  --template TEMPLATE, -t TEMPLATE
                        Use specific template (use --list-templates to see available options)
  --list-templates, -l  List available query templates
  --output OUTPUT, -o OUTPUT
                        Save query to file
```

## Available Templates

### Security Event Analysis
- **failed_logins**: Query for failed login attempts
- **privilege_escalation**: Query for potential privilege escalation attempts

### Endpoint Security
- **suspicious_processes**: Query for suspicious process execution
- **file_modifications**: Query for file creation/modification events

### Network Security
- **network_connections**: Query for outbound network connections

### General
- **threat_hunting**: General threat hunting query with customizable parameters

## Examples

### Example 1: Failed Login Analysis
```bash
python3 kql_generator.py --prompt "show me failed login attempts"
```

Generated Query:
```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| where UserPrincipalName contains "*"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| order by TimeGenerated desc
```

### Example 2: Suspicious Process Monitoring
```bash
python3 kql_generator.py --template suspicious_processes
```

Interactive prompts will guide you through:
- Timeframe selection (e.g., 24h, 7d, 30d)
- Suspicious commands to monitor
- Additional filters

### Example 3: Custom Network Analysis
```bash
python3 kql_generator.py --interactive
# Select 'network_connections' template
# Configure specific ports and timeframes
```

## Interactive Mode Walkthrough

1. **Template Selection**: Choose from predefined templates or create custom queries
2. **Parameter Configuration**: Set timeframes, filters, and search criteria
3. **Query Generation**: Get a fully formatted KQL query ready for use
4. **Export Options**: Save to file or copy to clipboard

## Supported Platforms

This tool generates KQL queries compatible with:
- **Azure Sentinel / Microsoft Sentinel**
- **Microsoft Defender for Endpoint**
- **Microsoft Defender for Cloud**
- **Azure Data Explorer**
- **Azure Monitor Logs**

## Common Use Cases

### Threat Hunting
- Identify suspicious process execution patterns
- Detect unusual network connections
- Monitor file system changes in sensitive directories

### Incident Response
- Investigate failed authentication attempts
- Track privilege escalation activities
- Analyze timeline of security events

### Compliance & Monitoring
- Generate reports for security audits
- Monitor critical system changes
- Track user access patterns

## Sample Queries Generated

### Failed Login Detection
```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
| order by TimeGenerated desc
```

### Process Execution Monitoring
```kql
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where ProcessCommandLine has_any ("powershell", "cmd", "wscript")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

## Testing

Run the included test suite to verify functionality:

```bash
python3 test_kql_generator.py
```

## Contributing

This tool is part of a cybersecurity portfolio project. Contributions and suggestions are welcome!

## License

This project is part of a personal portfolio and is available for educational and professional use.

---

*Part of the Cybersecurity Portfolio by CyberGilly*