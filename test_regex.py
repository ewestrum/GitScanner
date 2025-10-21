#!/usr/bin/env python3
"""Test regex patterns to find problematic ones"""

import re
import sys
from pathlib import Path

def extract_patterns_from_file(file_path):
    """Extract all regex patterns from the file"""
    patterns = []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        if 'pattern=r' in line:
            # Extract the pattern string
            start = line.find("pattern=r'") + 10
            if start == 9:  # not found
                start = line.find('pattern=r"') + 10
            if start == 9:  # not found
                continue
            
            quote_char = line[start-1]
            end = line.find(quote_char, start)
            if end != -1:
                pattern = line[start:end]
                patterns.append((i, pattern))
    
    return patterns

def test_patterns():
    """Test all patterns and report problematic ones"""
    patterns = extract_patterns_from_file('src/advanced_config_manager.py')
    
    for line_num, pattern in patterns:
        try:
            re.compile(pattern)
            print(f"✓ Line {line_num}: OK")
        except re.error as e:
            print(f"✗ Line {line_num}: ERROR - {e}")
            print(f"  Pattern: {pattern}")
            print()

if __name__ == "__main__":
    test_patterns()