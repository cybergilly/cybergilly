#!/usr/bin/env python3
"""
Test script for KQL Query Generator
Simple validation tests to ensure the generator works correctly.
"""

import os
import sys
import subprocess
from kql_generator import KQLQueryGenerator


def test_generator_creation():
    """Test that the generator can be created."""
    generator = KQLQueryGenerator()
    assert generator is not None
    assert len(generator.query_templates) > 0
    print("✅ Generator creation test passed")


def test_template_listing():
    """Test that templates can be listed."""
    generator = KQLQueryGenerator()
    templates = generator.query_templates.keys()
    expected_templates = ["failed_logins", "suspicious_processes", "network_connections", 
                         "file_modifications", "privilege_escalation", "threat_hunting"]
    
    for template in expected_templates:
        assert template in templates, f"Template {template} not found"
    
    print("✅ Template listing test passed")


def test_prompt_generation():
    """Test generating queries from prompts."""
    generator = KQLQueryGenerator()
    
    test_cases = [
        ("failed logins", "SigninLogs"),
        ("suspicious process", "DeviceProcessEvents"),
        ("network traffic", "DeviceNetworkEvents"),
        ("file creation", "DeviceFileEvents"),
        ("privilege escalation", "SecurityEvent")
    ]
    
    for prompt, expected_table in test_cases:
        query = generator.generate_from_prompt(prompt)
        assert query is not None and len(query) > 0, f"No query generated for prompt: {prompt}"
        assert expected_table in query, f"Expected table {expected_table} not found in query for prompt: {prompt}"
    
    print("✅ Prompt generation test passed")


def test_cli_functionality():
    """Test the CLI interface."""
    # Test help
    result = subprocess.run([sys.executable, "kql_generator.py", "--help"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Help command failed"
    
    # Test list templates
    result = subprocess.run([sys.executable, "kql_generator.py", "--list-templates"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "List templates command failed"
    assert "failed_logins" in result.stdout, "Template not found in output"
    
    # Test prompt
    result = subprocess.run([sys.executable, "kql_generator.py", "--prompt", "failed logins"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Prompt command failed"
    assert "SigninLogs" in result.stdout, "Expected query output not found"
    
    print("✅ CLI functionality test passed")


def run_tests():
    """Run all tests."""
    print("🧪 Running KQL Generator Tests")
    print("=" * 40)
    
    try:
        test_generator_creation()
        test_template_listing()
        test_prompt_generation()
        test_cli_functionality()
        
        print("\n🎉 All tests passed!")
        return True
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)