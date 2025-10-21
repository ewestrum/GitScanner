#!/usr/bin/env python3
"""Test enhanced monitor main function with detailed error tracking"""

import sys
import traceback
import re

def test_main_function():
    try:
        print("Testing enhanced_github_monitor main function...")
        
        # Import and call main
        import enhanced_github_monitor
        
        # Override sys.argv to avoid command line issues
        old_argv = sys.argv.copy()
        sys.argv = ['enhanced_github_monitor.py', '--help']
        
        try:
            enhanced_github_monitor.main()
        except SystemExit:
            # Help was shown, that's OK
            print("✓ Help display successful")
            
        # Now try without help flag but catch the actual error
        sys.argv = ['enhanced_github_monitor.py']
        
        try:
            enhanced_github_monitor.main()
        except Exception as e:
            print(f"Main function error: {e}")
            print("Full traceback:")
            traceback.print_exc()
            
            # Look for the specific line causing the regex error
            tb = traceback.format_exc()
            if "multiple repeat" in tb:
                print("\nFound 'multiple repeat' in traceback!")
                # Try to find the problematic line
                lines = tb.split('\n')
                for i, line in enumerate(lines):
                    if 'multiple repeat' in line:
                        print(f"Error line: {line}")
                        if i > 0:
                            print(f"Previous line: {lines[i-1]}")
                        if i < len(lines) - 1:
                            print(f"Next line: {lines[i+1]}")
        finally:
            sys.argv = old_argv
                
    except Exception as e:
        print(f"Test error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_main_function()