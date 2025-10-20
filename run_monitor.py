#!/usr/bin/env python3
"""
GitHub Monitor CLI - Simple command-line interface for the GitHub Monitor tool
"""

import sys
import argparse
import logging
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from github_monitor import GitHubMonitor
from config_manager import ConfigManager

def setup_logging(log_level: str = 'INFO'):
    """Setup logging configuration"""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('github_monitor.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def run_scan(args):
    """Run repository scan"""
    try:
        monitor = GitHubMonitor(args.config)
        
        if args.test_email:
            # Test email configuration
            print("Testing email configuration...")
            if monitor.email_notifier.test_connection():
                print("✅ Email test successful")
            else:
                print("❌ Email test failed")
            return
        
        print("🔍 Starting GitHub repository scan...")
        
        # Run scan
        results = monitor.scan_all_repositories()
        
        # Generate report
        report = monitor.generate_report(results)
        
        # Display results
        print(report)
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n📄 Report saved to: {args.output}")
        
        # Send summary email if configured
        if args.email_summary:
            monitor.email_notifier.send_summary_report(results)
            print("📧 Summary email sent")
        
        # Check for critical issues
        critical_repos = [r for r in results if r.get('risk_level') == 'CRITICAL']
        if critical_repos:
            print(f"\n⚠️  WARNING: {len(critical_repos)} repositories have CRITICAL security issues!")
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        return 1

def create_config(args):
    """Create sample configuration"""
    try:
        config = ConfigManager()
        config.create_sample_config(args.output or '.env.example')
        print("✅ Sample configuration created")
    except Exception as e:
        print(f"❌ Error creating config: {e}")
        return 1
    return 0

def validate_config(args):
    """Validate configuration"""
    try:
        config = ConfigManager(args.config)
        
        print("🔍 Validating configuration...")
        
        # Check GitHub token
        if config.get('GITHUB_TOKEN'):
            if config.validate_github_token():
                print("✅ GitHub token format is valid")
            else:
                print("⚠️  GitHub token format may be invalid")
        else:
            print("❌ GitHub token is missing")
        
        # Check email config
        email_config = config.get_email_config()
        if email_config['enabled']:
            if email_config['sender_email'] and email_config['sender_password']:
                print("✅ Email configuration looks complete")
            else:
                print("⚠️  Email configuration is incomplete")
        else:
            print("ℹ️  Email notifications are disabled")
        
        print("✅ Configuration validation complete")
        
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}")
        return 1
    return 0

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='GitHub Monitor - Scan repositories for sensitive information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan                    # Scan all repositories
  %(prog)s scan --output report.txt # Save report to file
  %(prog)s scan --email-summary    # Send email summary
  %(prog)s config                  # Create sample config
  %(prog)s validate                # Validate configuration
'''
    )
    
    # Global options
    parser.add_argument(
        '--config', 
        default='.env',
        help='Path to configuration file (default: .env)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan repositories for sensitive content')
    scan_parser.add_argument(
        '--output', '-o',
        help='Save report to file'
    )
    scan_parser.add_argument(
        '--email-summary',
        action='store_true',
        help='Send email summary report'
    )
    scan_parser.add_argument(
        '--test-email',
        action='store_true',
        help='Test email configuration only'
    )
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Create sample configuration file')
    config_parser.add_argument(
        '--output', '-o',
        help='Output file for sample config (default: .env.example)'
    )
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate configuration')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Handle commands
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == 'scan':
        return run_scan(args)
    elif args.command == 'config':
        return create_config(args)
    elif args.command == 'validate':
        return validate_config(args)
    else:
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())