#!/usr/bin/env python3
"""
Test to verify large file suspicion detection is working correctly
"""

import os
from src.enhanced_file_scanner import EnhancedFileScanner

def test_suspicion_detection():
    """Test if large files are correctly marked as suspicious"""
    print("=== Testing Large File Suspicion Detection ===\n")
    
    # Create test directory
    test_dir = "test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    # Create large SQL file (database dump simulation)
    large_sql = os.path.join(test_dir, "customer_database.sql")
    with open(large_sql, 'w') as f:
        f.write("-- Customer Database Export\n")
        # Create ~20MB file
        for i in range(650000):
            f.write(f"INSERT INTO customers VALUES ({i}, 'customer{i}@company.com', 'John Doe {i}', '555-0{i:06d}', '1990-01-01');\n")
    
    # Initialize scanner with scan rules
    scan_rules = {
        'max_text_size': 100 * 1024 * 1024,  # 100MB
        'max_binary_size': 500 * 1024 * 1024,  # 500MB
        'suspicious_extensions': ['.sql', '.db', '.backup', '.dump'],
        'patterns': {}
    }
    scanner = EnhancedFileScanner(scan_rules)
    
    # Test the large SQL file
    print(f"--- Testing: {large_sql} ---")
    file_size = os.path.getsize(large_sql)
    print(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
    
    # Get file info (this should trigger suspicion analysis)
    file_info = scanner.get_file_info(large_sql)
    
    print(f"Is suspicious: {file_info.get('is_suspicious', False)}")
    print("Suspicion reasons:")
    for reason in file_info.get('suspicion_reasons', []):
        print(f"  - {reason}")
    
    # Check thresholds
    print(f"\nThresholds:")
    print(f"Large text threshold: {scanner.large_text_threshold / 1024 / 1024:.1f}MB")
    print(f"Large binary threshold: {scanner.large_binary_threshold / 1024 / 1024:.1f}MB")
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)
    print(f"\nCleaned up test directory: {test_dir}")

if __name__ == "__main__":
    test_suspicion_detection()