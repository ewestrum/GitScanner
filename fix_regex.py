#!/usr/bin/env python3
"""Fix all double backslashes in enhanced_content_analyzer.py"""

import re

def fix_regex_patterns():
    file_path = 'src/enhanced_content_analyzer.py'
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix all double backslashes in regex patterns
    # Match r'...' or r"..." patterns and fix double backslashes
    def fix_pattern(match):
        full_match = match.group(0)
        quote_char = full_match[2]  # Get the quote character after r'
        
        # Extract the pattern content
        pattern = full_match[3:-1]  # Remove r' and '
        
        # Fix common double backslash issues
        pattern = pattern.replace('\\\\b', '\\b')
        pattern = pattern.replace('\\\\d', '\\d')
        pattern = pattern.replace('\\\\w', '\\w')
        pattern = pattern.replace('\\\\s', '\\s')
        pattern = pattern.replace('\\\\.', '\\.')
        pattern = pattern.replace('\\\\[', '\\[')
        pattern = pattern.replace('\\\\]', '\\]')
        
        return f'r{quote_char}{pattern}{quote_char}'
    
    # Find and fix all regex patterns
    content = re.sub(r"r['\"].*?['\"]", fix_pattern, content)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Fixed all regex patterns in enhanced_content_analyzer.py")

if __name__ == "__main__":
    fix_regex_patterns()