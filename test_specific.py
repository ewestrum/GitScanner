#!/usr/bin/env python3
"""Better regex testing"""

import re
import sys
from pathlib import Path

def test_specific_line():
    """Test specific line that's causing issues"""
    with open('src/advanced_config_manager.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Print lines around problematic areas
    for line_num in [113, 164, 175, 184]:
        print(f"\n=== Line {line_num} ===")
        actual_line = lines[line_num-1]  # -1 for 0-based indexing
        print(f"Raw line: {repr(actual_line)}")
        
        # Try to extract pattern
        if 'pattern=r' in actual_line:
            start = actual_line.find("pattern=r'")
            if start != -1:
                start += 10
                quote_char = "'"
            else:
                start = actual_line.find('pattern=r"')
                if start != -1:
                    start += 10
                    quote_char = '"'
                else:
                    continue
            
            end = actual_line.find(quote_char, start)
            if end != -1:
                pattern = actual_line[start:end]
                print(f"Extracted pattern: {repr(pattern)}")
                try:
                    re.compile(pattern)
                    print("✓ Pattern compiles OK")
                except re.error as e:
                    print(f"✗ Pattern error: {e}")
            else:
                print("Could not find end quote")

if __name__ == "__main__":
    test_specific_line()