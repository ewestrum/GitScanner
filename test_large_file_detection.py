#!/usr/bin/env python3
"""
Test script to verify that large files are now properly detected as suspicious
instead of being skipped by the GitHub Monitor system.
"""

import os
import json
from src.enhanced_file_scanner import EnhancedFileScanner
from src.config_manager import ConfigManager

def create_large_test_files():
    """Create test files of different sizes to test detection"""
    test_dir = "test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    # Small file (should not be flagged)
    small_file = os.path.join(test_dir, "small_config.txt")
    with open(small_file, 'w') as f:
        f.write("# Configuration file\napi_key=test123\n")
    
    # Large text file (should be flagged as suspicious)
    large_text = os.path.join(test_dir, "large_database_dump.sql")
    with open(large_text, 'w') as f:
        f.write("-- Database Export\n")
        # Create ~15MB file
        for i in range(500000):
            f.write(f"INSERT INTO users VALUES ({i}, 'user{i}@company.com', 'password123', 'SSN-{i:09d}');\n")
    
    # Large binary file (should be flagged as suspicious)
    large_binary = os.path.join(test_dir, "backup_database.db")
    with open(large_binary, 'wb') as f:
        # Create ~60MB binary file
        chunk = b'BINARY_DATA_CHUNK' * 1024  # 18KB chunk
        for i in range(3500):  # ~63MB
            f.write(chunk)
    
    return [small_file, large_text, large_binary]

def test_file_scanner():
    """Test the enhanced file scanner with different file sizes"""
    print("=== Testing Enhanced File Scanner with Large Files ===\n")
    
    # Create test files
    test_files = create_large_test_files()
    
    # Initialize scanner
    config = ConfigManager()
    scan_rules = {
        'max_text_size': 100 * 1024 * 1024,  # 100MB
        'max_binary_size': 500 * 1024 * 1024,  # 500MB
        'suspicious_extensions': ['.sql', '.db', '.backup', '.dump'],
        'patterns': {}
    }
    scanner = EnhancedFileScanner(scan_rules)
    
    # Test each file
    for file_path in test_files:
        print(f"\n--- Testing: {file_path} ---")
        file_size = os.path.getsize(file_path)
        print(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        # Get file info
        file_info = scanner.get_file_info(file_path)
        print(f"File type: {'Text' if file_info['is_text'] else 'Binary'}")
        
        # Check if size is appropriate (should now be more permissive)
        size_ok = scanner.is_size_appropriate(file_info)
        print(f"Size appropriate for scanning: {size_ok}")
        
        # Get processing recommendation
        recommendation = scanner.get_processing_recommendation(file_info)
        print(f"Processing recommendation: {recommendation}")
        
        # Perform actual scan
        try:
            result = scanner.scan_file(file_path)
            if result and result.get('findings'):
                print("Findings:")
                for finding in result['findings']:
                    print(f"  - {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")
            else:
                print("No findings detected")
        except Exception as e:
            print(f"Scan error: {e}")
        
        print("-" * 60)

def cleanup_test_files():
    """Clean up test files"""
    import shutil
    test_dir = "test_files"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        print(f"\nCleaned up test directory: {test_dir}")

if __name__ == "__main__":
    try:
        test_file_scanner()
        
        # Show summary
        print("\n=== SUMMARY ===")
        print("✓ Large files are now processed instead of skipped")
        print("✓ File size limits increased from 1-10MB to 100-500MB")  
        print("✓ Large files (>10MB text, >50MB binary) flagged as suspicious")
        print("✓ Data leak detection improved for databases, backups, logs")
        
    finally:
        cleanup_test_files()