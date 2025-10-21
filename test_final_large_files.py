#!/usr/bin/env python3
"""
Final test: Create a test repository with large files and see if they get detected
"""

import os
import json

def create_test_repo_with_large_files():
    """Create a mock repository structure with large files that should be flagged"""
    test_repo = "test_large_files_repo"
    
    # Clean up if exists
    import shutil
    if os.path.exists(test_repo):
        try:
            shutil.rmtree(test_repo)
        except PermissionError:
            # Windows permission issue, ignore
            pass
    
    # Create directory structure
    os.makedirs(f"{test_repo}/data", exist_ok=True)
    os.makedirs(f"{test_repo}/backups", exist_ok=True)
    os.makedirs(f"{test_repo}/logs", exist_ok=True)
    
    # Create large suspicious files
    files_created = []
    
    # Large database dump
    db_dump = f"{test_repo}/data/users_export.sql"
    with open(db_dump, 'w') as f:
        f.write("-- USERS TABLE EXPORT\n")
        f.write("-- WARNING: Contains personal information\n")
        for i in range(400000):  # ~15MB
            f.write(f"INSERT INTO users VALUES ({i}, 'user{i}@company.com', 'password123', '{i:09d}', 'Some Address {i}');\n")
    files_created.append(db_dump)
    
    # Large log file with potential API keys
    log_file = f"{test_repo}/logs/application.log"
    with open(log_file, 'w') as f:
        f.write("Application Log File\n")
        for i in range(500000):  # ~20MB
            if i % 10000 == 0:
                f.write(f"2025-10-21 12:00:{i:02d} - API_KEY=sk-1234567890abcdef - User login\n")
            else:
                f.write(f"2025-10-21 12:00:{i:02d} - Regular log entry {i}\n")
    files_created.append(log_file)
    
    # Large backup file
    backup_file = f"{test_repo}/backups/database_backup.dump"
    with open(backup_file, 'wb') as f:
        # Create ~80MB binary file
        chunk = b'BACKUP_DATA_CHUNK_WITH_SENSITIVE_INFO' * 1024  # 38KB chunk  
        for i in range(2200):  # ~84MB
            f.write(chunk)
    files_created.append(backup_file)
    
    # Normal small files (should not be flagged for size)
    readme = f"{test_repo}/README.md"
    with open(readme, 'w') as f:
        f.write("# Test Repository\n\nThis is a test repository.\n")
    files_created.append(readme)
    
    config = f"{test_repo}/config.json"
    with open(config, 'w') as f:
        json.dump({"app_name": "test", "version": "1.0"}, f)
    files_created.append(config)
    
    print("=== Created Test Repository with Large Files ===")
    for file_path in files_created:
        size = os.path.getsize(file_path)
        print(f"{file_path}: {size:,} bytes ({size/1024/1024:.1f}MB)")
    
    return test_repo

def test_with_enhanced_scanner():
    """Test using the enhanced file scanner directly"""
    from src.enhanced_file_scanner import EnhancedFileScanner
    
    test_repo = create_test_repo_with_large_files()
    
    print(f"\n=== Testing Enhanced Scanner on {test_repo} ===")
    
    # Initialize scanner
    scan_rules = {
        'max_text_size': 100 * 1024 * 1024,  # 100MB
        'max_binary_size': 500 * 1024 * 1024,  # 500MB
        'suspicious_extensions': ['.sql', '.dump', '.log', '.backup'],
        'patterns': {
            'api_keys': r'API_KEY\s*=\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
            'passwords': r'password\s*[=:]\s*[\'"][^\'\"]{8,}[\'"]'
        }
    }
    scanner = EnhancedFileScanner(scan_rules)
    
    # Scan all files
    suspicious_files = []
    for root, dirs, files in os.walk(test_repo):
        for file in files:
            file_path = os.path.join(root, file)
            file_info = scanner.get_file_info(file_path)
            
            if file_info.get('is_suspicious', False):
                suspicious_files.append({
                    'path': file_path,
                    'size': file_info.get('size', 0),
                    'reasons': file_info.get('suspicion_reasons', [])
                })
    
    print(f"\nFound {len(suspicious_files)} suspicious files:")
    for file_data in suspicious_files:
        size = file_data['size'] or 0
        size_mb = size / 1024 / 1024
        print(f"\n📁 {file_data['path']} ({size_mb:.1f}MB)")
        for reason in file_data['reasons']:
            print(f"   ⚠️  {reason}")
    
    # Clean up
    import shutil
    shutil.rmtree(test_repo)
    print(f"\n✅ Cleaned up test repository: {test_repo}")

if __name__ == "__main__":
    test_with_enhanced_scanner()