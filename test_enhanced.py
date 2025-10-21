#!/usr/bin/env python3
"""Test specific parts of enhanced_github_monitor"""

import sys
import traceback
import re

def test_enhanced_monitor():
    try:
        print("Testing enhanced_github_monitor imports...")
        
        # Import the enhanced monitor
        import enhanced_github_monitor
        print("✓ Import successful")
        
        # Test the main function step by step
        print("Testing main components...")
        
        # Check if there are any regex compiles in the main module
        import inspect
        source = inspect.getsource(enhanced_github_monitor)
        
        # Look for re.compile calls
        import re
        compile_calls = re.findall(r're\.compile\([^)]+\)', source)
        print(f"Found {len(compile_calls)} re.compile calls:")
        
        for i, call in enumerate(compile_calls):
            print(f"  {i+1}: {call}")
            # Extract the pattern and test it
            try:
                pattern_match = re.search(r're\.compile\([\'"]([^\'"]+)[\'"]', call)
                if pattern_match:
                    pattern = pattern_match.group(1)
                    print(f"     Testing pattern: {pattern}")
                    re.compile(pattern)
                    print("     ✓ OK")
                else:
                    print("     Could not extract pattern")
            except re.error as e:
                print(f"     ✗ ERROR: {e}")
                
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_enhanced_monitor()