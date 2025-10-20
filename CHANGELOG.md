# GitScanner - Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-10-20

### 🎉 Major Release - Extended Email Reporting System

### Added
- **Comprehensive Test Logs**: Detailed audit trail of all security checks performed per repository
- **Professional Email Templates**: Modern HTML formatting with CSS styling and responsive design
- **Extended Test Categories**:
  - 🔍 **Filename Analysis**: Config files, private keys, database files, logs
  - 🔐 **Content Security**: API keys, passwords, database strings, SSH keys  
  - 👤 **Personal Data Detection**: IBAN, BSN, postcodes, names, phone numbers, emails
  - 🏥 **Medical/Financial Data**: Medical terms, financial data, license plates
  - ⚡ **Code Quality**: Hardcoded secrets, debug code, test files with real data
- **Status Indicators**: Clear visual markers (✅ PASSED / ❌ FAILED / ⚠️ WARNING / ℹ️ INFO) for each test
- **Scan Statistics**: Complete metrics including files scanned, issues found, test results per repository
- **Multi-Repository Reports**: Summary reports with test logs for all scanned repositories
- **Enhanced Personal Data Detection**: Extended patterns for Dutch-specific data (BSN, postcodes)
- **Medical and Financial Screening**: Specialized detection for healthcare and financial sectors

### Enhanced
- **Email Notification System**: Complete rewrite with `EmailNotifier` class supporting extended reporting
- **API Rate Limiting**: Improved handling to prevent GitHub API rate limit issues
- **Performance Optimization**: More efficient repository scanning with selective file analysis
- **Content Analysis**: Enhanced pattern matching for various types of sensitive information
- **Template Engine**: Professional HTML email templates with modern CSS styling

### Technical Improvements
- **New Email Architecture**: `email_notifier_extended.py` with comprehensive templating system
- **Test Framework**: Systematic test execution with status tracking and reporting
- **Error Handling**: Improved error recovery and logging throughout the scanning process
- **Documentation**: Updated architecture documentation with new email system diagrams

### Configuration
- **Backward Compatible**: All existing configuration options remain functional
- **Extended Options**: New email template customization options available
- **Enhanced Logging**: More detailed logging for email delivery and test execution

### Files Changed
- `src/email_notifier_extended.py` - New comprehensive email notification system
- `simple_enhanced_monitor.py` - Updated to use extended email functionality
- `src/content_analyzer.py` - Enhanced with additional personal data patterns
- `src/enhanced_content_analyzer.py` - Extended personal data analysis methods
- `README.md` - Updated documentation with new features
- `ARCHITECTURE.md` - Added extended email system architecture
- `test_email_extended.py` - New test script for email functionality

### Migration Notes
- Existing users can continue using current setup without changes
- To enable extended email reporting, update import in monitor scripts to use `email_notifier_extended`
- New CSS styling in emails requires HTML-capable email clients for best experience
- Text-only email clients will receive comprehensive plain-text versions with full test logs

## [1.0.0] - 2025-10-19

### Initial Release
- Basic repository scanning functionality
- Simple email notifications
- HTML report generation
- Multi-monitor architecture (Simple, Enhanced, Advanced)
- Configuration management system
- GitHub API integration
- Basic security pattern detection

---

## Version Numbering

- **Major**: Breaking changes or significant new features
- **Minor**: New features that are backward compatible  
- **Patch**: Bug fixes and small improvements

## Support

For questions about specific versions or upgrade paths:
- Create an issue on GitHub
- Check the documentation for migration guides
- Review the architecture documentation for technical details