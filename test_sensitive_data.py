#!/usr/bin/env python3
"""
Test uitgebreide monitors met gevoelige data detectie
"""
import os
import sys

# Add src to path for local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from content_analyzer import ContentAnalyzer
from enhanced_content_analyzer import EnhancedContentAnalyzer

def test_sensitive_data_detection():
    """Test de uitgebreide gevoelige data detectie"""
    
    # Test content met verschillende types gevoelige data
    test_content = """
    Klantgegevens:
    Jan de Vries
    Hoofdstraat 123
    1234 AB Amsterdam
    06-12345678
    jan.devries@email.com
    Geboortedatum: 15-03-1985
    BSN: 123456789
    IBAN: NL91ABNA0417164300
    
    Bedrijfsgegevens:
    Customer ID: CUST001234
    Order nummer: ORD789456
    Salaris: €45000
    
    Medische info:
    Patient heeft diagnose diabetes
    Behandeling met medicijn X
    
    Kenteken: 12-AB-34
    """
    
    # Test originele content analyzer
    print("=== Testing Content Analyzer ===")
    analyzer = ContentAnalyzer({})
    findings = analyzer.analyze_content(test_content, "test_data.txt")
    
    print(f"Found {len(findings)} findings:")
    for finding in findings:
        print(f"- {finding['type']}: {finding['match']} (risk: {finding['risk_score']})")
    
    print("\n=== Testing Enhanced Content Analyzer ===")
    enhanced_analyzer = EnhancedContentAnalyzer([])
    enhanced_findings = enhanced_analyzer.analyze_content(test_content, "test_data.txt")
    
    print(f"Found {len(enhanced_findings)} enhanced findings:")
    for finding in enhanced_findings:
        print(f"- {finding['type']}: {finding['match']} (severity: {finding['severity']})")

if __name__ == "__main__":
    test_sensitive_data_detection()