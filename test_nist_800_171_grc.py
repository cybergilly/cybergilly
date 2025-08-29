#!/usr/bin/env python3
"""
Test script for NIST 800-171 GRC Compliance Tool
Validation tests to ensure the compliance assessment tool works correctly.
"""

import os
import sys
import subprocess
import json
from nist_800_171_grc import NISTGRCAssessment, ControlFamily, ControlStatus


def test_assessment_creation():
    """Test that the assessment can be created."""
    assessment = NISTGRCAssessment()
    assert assessment is not None
    assert len(assessment.controls) > 0
    assert assessment.assessment_date is not None
    print("✅ Assessment creation test passed")


def test_control_initialization():
    """Test that controls are properly initialized."""
    assessment = NISTGRCAssessment()
    
    # Check that expected controls exist
    expected_controls = ["3.1.1", "3.1.2", "3.4.1", "3.13.1", "3.14.1"]
    for control_id in expected_controls:
        assert control_id in assessment.controls, f"Control {control_id} not found"
        control = assessment.controls[control_id]
        assert control.control_id == control_id
        assert control.title is not None and len(control.title) > 0
        assert control.description is not None and len(control.description) > 0
        assert len(control.azure_mappings) > 0
    
    print("✅ Control initialization test passed")


def test_single_control_assessment():
    """Test assessing a single control."""
    assessment = NISTGRCAssessment()
    
    # Test assessing a specific control
    control = assessment.assess_control("3.1.1")
    assert control is not None
    assert control.control_id == "3.1.1"
    assert control.status != ControlStatus.NOT_ASSESSED
    assert isinstance(control.findings, list)
    assert isinstance(control.recommendations, list)
    
    # Test invalid control
    try:
        assessment.assess_control("999.999")
        assert False, "Should have raised ValueError for invalid control"
    except ValueError:
        pass  # Expected
    
    print("✅ Single control assessment test passed")


def test_control_family_assessment():
    """Test assessing a control family."""
    assessment = NISTGRCAssessment()
    
    # Test Access Control family
    family_controls = assessment.assess_control_family(ControlFamily.ACCESS_CONTROL)
    assert len(family_controls) > 0
    
    for control in family_controls:
        assert control.family == ControlFamily.ACCESS_CONTROL
        assert control.status != ControlStatus.NOT_ASSESSED
    
    print("✅ Control family assessment test passed")


def test_full_assessment():
    """Test full compliance assessment."""
    assessment = NISTGRCAssessment()
    
    # Run full assessment
    assessed_controls = assessment.assess_all_controls()
    assert len(assessed_controls) == len(assessment.controls)
    
    # Check that all controls have been assessed
    for control_id, control in assessed_controls.items():
        assert control.status != ControlStatus.NOT_ASSESSED
    
    print("✅ Full assessment test passed")


def test_compliance_summary():
    """Test compliance summary generation."""
    assessment = NISTGRCAssessment()
    assessment.assess_all_controls()
    
    summary = assessment._get_compliance_summary()
    assert isinstance(summary, dict)
    
    # Check that summary contains expected keys
    expected_statuses = [status.value for status in ControlStatus]
    for status in expected_statuses:
        assert status in summary
    
    # Check that counts add up to total controls
    total_count = sum(summary.values())
    assert total_count == len(assessment.controls)
    
    print("✅ Compliance summary test passed")


def test_gap_analysis():
    """Test gap analysis generation."""
    assessment = NISTGRCAssessment()
    assessment.assess_all_controls()
    
    gaps = assessment.generate_gap_analysis()
    assert isinstance(gaps, dict)
    
    # Check expected gap categories
    expected_categories = ["critical", "high", "medium", "low"]
    for category in expected_categories:
        assert category in gaps
        assert isinstance(gaps[category], list)
    
    print("✅ Gap analysis test passed")


def test_report_generation():
    """Test compliance report generation."""
    assessment = NISTGRCAssessment()
    assessment.assess_all_controls()
    
    # Test JSON report
    json_report = assessment.generate_compliance_report("json")
    assert json_report is not None and len(json_report) > 0
    
    # Validate JSON format
    report_data = json.loads(json_report)
    assert "assessment_date" in report_data
    assert "total_controls" in report_data
    assert "compliance_summary" in report_data
    assert "controls" in report_data
    
    # Test summary report
    summary_report = assessment.generate_compliance_report("summary")
    assert summary_report is not None and len(summary_report) > 0
    assert "NIST 800-171 Compliance Assessment Report" in summary_report
    
    print("✅ Report generation test passed")


def test_cli_functionality():
    """Test the CLI interface."""
    # Test help
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--help"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Help command failed"
    
    # Test assess command
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--assess"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Assess command failed"
    assert "NIST 800-171 Compliance Assessment Report" in result.stdout
    
    # Test control assessment
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--control", "3.1.1"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Control assessment command failed"
    assert "3.1.1" in result.stdout
    
    # Test control family assessment
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--control-family", "3.1"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Control family assessment command failed"
    assert "Control Family 3.1" in result.stdout
    
    # Test gap analysis
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--gap-analysis"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Gap analysis command failed"
    assert "Gap Analysis Report" in result.stdout
    
    # Test report generation
    result = subprocess.run([sys.executable, "nist_800_171_grc.py", "--report", "--format", "json"], 
                          capture_output=True, text=True)
    assert result.returncode == 0, "Report generation command failed"
    assert "assessment_date" in result.stdout
    
    print("✅ CLI functionality test passed")


def test_control_status_types():
    """Test all control status types are handled correctly."""
    assessment = NISTGRCAssessment()
    
    # Test that all status types are represented in assessment
    assessment.assess_all_controls()
    statuses_found = set()
    
    for control in assessment.controls.values():
        statuses_found.add(control.status)
    
    # Should have at least compliant, non-compliant, and partially compliant
    expected_minimum = {ControlStatus.COMPLIANT, ControlStatus.NON_COMPLIANT, ControlStatus.PARTIALLY_COMPLIANT}
    assert expected_minimum.issubset(statuses_found), f"Missing expected statuses. Found: {statuses_found}"
    
    print("✅ Control status types test passed")


def test_azure_mappings():
    """Test that controls have proper Azure service mappings."""
    assessment = NISTGRCAssessment()
    
    for control_id, control in assessment.controls.items():
        assert len(control.azure_mappings) > 0, f"Control {control_id} has no Azure mappings"
        
        # Check that mappings are strings
        for mapping in control.azure_mappings:
            assert isinstance(mapping, str) and len(mapping) > 0
    
    print("✅ Azure mappings test passed")


def run_tests():
    """Run all tests."""
    print("🧪 Running NIST 800-171 GRC Tool Tests")
    print("=" * 60)
    
    test_functions = [
        test_assessment_creation,
        test_control_initialization,
        test_single_control_assessment,
        test_control_family_assessment,
        test_full_assessment,
        test_compliance_summary,
        test_gap_analysis,
        test_report_generation,
        test_azure_mappings,
        test_control_status_types,
        test_cli_functionality
    ]
    
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {test_func.__name__} failed: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed!")
        return True
    else:
        print("💥 Some tests failed!")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)