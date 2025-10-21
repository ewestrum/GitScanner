#!/usr/bin/env python3
"""Debug EnhancedGitHubMonitor initialization"""

import sys
import traceback
import logging

# Setup logging to see detailed errors
logging.basicConfig(level=logging.DEBUG)

def debug_monitor_init():
    try:
        print("1. Testing imports...")
        import os
        current_dir = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(current_dir, 'src')
        sys.path.insert(0, src_dir)
        
        from config_manager import ConfigManager
        print("✓ ConfigManager imported")
        
        from github_client import GitHubClient
        print("✓ GitHubClient imported")
        
        from enhanced_file_scanner import EnhancedFileScanner
        print("✓ EnhancedFileScanner imported")
        
        from enhanced_content_analyzer import EnhancedContentAnalyzer
        print("✓ EnhancedContentAnalyzer imported")
        
        from git_history_analyzer import GitHistoryAnalyzer
        print("✓ GitHistoryAnalyzer imported")
        
        from risk_scoring_engine import RiskScoringEngine, create_default_scoring_config
        print("✓ RiskScoringEngine imported")
        
        from output_formatters import ReportGenerator
        print("✓ ReportGenerator imported")
        
        from performance_optimizer import PerformanceOptimizer, create_default_performance_config
        print("✓ PerformanceOptimizer imported")
        
        from advanced_config_manager import AdvancedConfigManager
        print("✓ AdvancedConfigManager imported")
        
        from email_notifier import EmailNotifier
        print("✓ EmailNotifier imported")
        
        print("\n2. Testing ConfigManager...")
        config_manager = ConfigManager('.env')
        print("✓ ConfigManager initialized")
        
        print("\n3. Testing AdvancedConfigManager...")
        advanced_config_manager = AdvancedConfigManager()
        print("✓ AdvancedConfigManager initialized")
        
        print("\n4. Testing EnhancedGitHubMonitor import...")
        import enhanced_github_monitor
        print("✓ enhanced_github_monitor imported")
        
        print("\n5. Testing EnhancedGitHubMonitor initialization...")
        monitor = enhanced_github_monitor.EnhancedGitHubMonitor()
        print("✓ EnhancedGitHubMonitor initialized")
        
        print("\nAll tests passed!")
        
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    debug_monitor_init()