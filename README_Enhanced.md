# Enhanced GitHub Monitor 🔍

Enterprise-level GitHub repository security scanner with advanced threat detection, risk scoring, and comprehensive reporting capabilities.

## Features

### 🚀 Core Capabilities
- **Repository Scanning**: Comprehensive analysis of all accessible GitHub repositories
- **Multi-format Detection**: MIME type analysis, encoding detection, and file classification
- **Git History Analysis**: Deep dive into commit history to find leaked secrets
- **Risk Scoring**: Intelligent risk assessment with configurable scoring rules
- **Advanced Reporting**: JSON and SARIF output formats for CI/CD integration

### 🔬 Detection Capabilities
- **Deterministic Patterns**: High-confidence detection using proven regex patterns
- **Entropy Analysis**: Shannon entropy calculation for high-entropy secrets (≥4.5)
- **API Keys & Tokens**: AWS, GitHub, Google, OpenAI, Stripe, Slack, Discord
- **Private Keys**: RSA, EC, OpenSSH, PGP private keys
- **Database Credentials**: Connection strings for PostgreSQL, MySQL, MongoDB
- **Personal Data**: Email addresses, IP addresses, credit cards, IBAN numbers
- **Custom Rules**: Configurable regex-based detection rules

### ⚡ Performance Features
- **Smart Filtering**: Skip binary files, large files, and irrelevant directories
- **Encoding Detection**: Automatic character encoding detection using chardet
- **Parallel Processing**: Multi-threaded scanning for improved performance
- **Caching**: Intelligent caching of file content and analysis results
- **Progress Tracking**: Real-time scan progress and performance metrics

### 📊 Enterprise Features
- **Risk Scoring Engine**: Configurable scoring with severity thresholds
- **SARIF Compliance**: Industry-standard security reporting format
- **Git History Deep Scan**: Analyze up to 500 commits for historical leaks
- **Advanced Configuration**: YAML-based rules engine with path/content filtering
- **Email Notifications**: Beautiful HTML dashboard reports via email

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (for repository cloning)
- GitHub Personal Access Token

### Quick Install

```bash
# Clone the repository
git clone https://github.com/your-org/enhanced-github-monitor.git
cd enhanced-github-monitor

# Run installation script
python install.py

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings
```

### Manual Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# For Windows users, also install:
pip install python-magic-bin

# For Linux/macOS users, install system dependency:
# Ubuntu/Debian:
sudo apt-get install libmagic1

# macOS:
brew install libmagic

# RHEL/CentOS:
sudo yum install file-libs
```

## Configuration

### Environment Variables (.env)

```env
# Required: GitHub API access
GITHUB_TOKEN=ghp_your_token_here
GITHUB_API_URL=https://api.github.com

# Optional: Email notifications
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_FROM=your_email@gmail.com
EMAIL_TO=admin@company.com

# Performance tuning
MAX_WORKERS=4
MAX_FILE_SIZE=10485760  # 10MB
MAX_TEXT_FILE_SIZE=2097152  # 2MB

# Risk scoring thresholds
RISK_THRESHOLD_CRITICAL=100
RISK_THRESHOLD_HIGH=50
RISK_THRESHOLD_MEDIUM=20
RISK_THRESHOLD_LOW=5
```

### Advanced Rules Configuration (github_monitor_rules.yaml)

The enhanced monitor uses a sophisticated YAML-based rules engine:

```yaml
regex_rules:
  aws-access-key:
    pattern: '\\bAKIA[0-9A-Z]{16}\\b'
    severity: "CRITICAL"
    confidence: "HIGH"
    tags: ["aws", "credentials"]
    
path_filters:
  skip-test-files:
    patterns: ['.*test.*', '.*spec.*']
    action: "exclude"
    priority: 10

content_filters:
  exclude-placeholders:
    patterns: ['(?i)(placeholder|example|test)']
    action: "exclude"
    context: "any"
```

## Usage

### Basic Scan

```bash
# Scan all repositories
python enhanced_github_monitor.py

# Scan with filters
python enhanced_github_monitor.py --filter "config" --max-repos 10
```

### Advanced Usage

```python
from enhanced_github_monitor import EnhancedGitHubMonitor

# Initialize monitor
monitor = EnhancedGitHubMonitor()

# Scan with custom options
results = monitor.scan_all_repositories(
    include_git_history=True,
    max_repositories=50,
    repository_filter="production"
)

# Generate reports
monitor.save_report(results, "scan_results.json", "json")
monitor.save_report(results, "scan_results.sarif", "sarif")

# Send email notification
monitor.send_email_notification(results)
```

## Output Formats

### JSON Report Structure

```json
{
  "format": "github-monitor-json",
  "version": "1.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "total_repositories": 25,
    "repositories_with_issues": 3,
    "total_findings": 12,
    "critical_findings": 2,
    "high_risk_findings": 4
  },
  "repositories": [
    {
      "name": "web-app",
      "risk_assessment": {
        "overall_score": 85.5,
        "risk_level": "HIGH"
      },
      "findings": [
        {
          "type": "aws_credential",
          "severity": "CRITICAL",
          "file_path": "config/settings.py",
          "line_number": 15,
          "risk_score": 90.0
        }
      ]
    }
  ]
}
```

### SARIF Report

The monitor generates SARIF 2.1.0 compliant reports for integration with:
- GitHub Advanced Security
- Azure DevOps
- SonarQube
- CodeQL
- Other security scanning platforms

## Risk Scoring

### Scoring Algorithm

The risk scoring engine uses a multi-factor approach:

```
Final Score = Base Score × File Type Multiplier × Path Modifier × Context Modifier × Confidence Multiplier
```

### Base Scores
- Private Keys: 100 points
- AWS Credentials: 90 points
- API Keys: 80 points
- Database Connections: 70 points
- High Entropy Secrets: 60 points

### Modifiers
- **File Type**: `.env` files get 1.5x multiplier
- **Path Context**: `prod/` directories get 1.4x multiplier
- **Test Files**: Get 0.7x reduction
- **Confidence**: HIGH = 1.0x, MEDIUM = 0.8x, LOW = 0.6x

### Risk Levels
- **CRITICAL**: ≥100 points
- **HIGH**: 50-99 points  
- **MEDIUM**: 20-49 points
- **LOW**: 5-19 points
- **INFO**: <5 points

## Git History Analysis

The enhanced monitor can analyze commit history to find:

- **Historical Leaks**: Secrets committed and later removed
- **Commit Attribution**: Author information for leaked secrets  
- **Timeline Analysis**: When secrets were introduced/removed
- **Blob Deduplication**: Efficient analysis of unique content

### Configuration

```python
# Analyze last 30 days
results = monitor.analyze_recent_commits(repo_path, days=30)

# Analyze specific commits
results = monitor.analyze_specific_commits(repo_path, ["abc123", "def456"])

# Full history analysis (up to max_commits limit)
results = monitor.analyze_repository_history(repo_path)
```

## Performance Optimization

### File Filtering

The monitor automatically skips:
- Binary files (images, videos, executables)
- Large files (>10MB by default)
- Irrelevant directories (node_modules, .git, __pycache__)
- Minified files (.min.js, .min.css)

### Smart Scanning

- **Priority Files**: Scans .env, config files first
- **Encoding Detection**: Uses chardet for accurate text reading
- **Parallel Processing**: Multi-threaded file processing
- **Caching**: Avoids re-analyzing identical content

### Memory Management

- **Streaming**: Large files read in chunks
- **Cache Limits**: Automatic cache cleanup
- **Blob Deduplication**: Git history analysis optimizations

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python enhanced_github_monitor.py --output sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: scan_results.sarif
```

### API Usage

```python
# Custom integration
from enhanced_github_monitor import EnhancedGitHubMonitor

monitor = EnhancedGitHubMonitor()
results = monitor.scan_all_repositories()

# Process results
for repo in results['repositories']:
    if repo['risk_assessment']['risk_level'] == 'CRITICAL':
        send_alert(repo)
```

## Architecture

### Component Overview

```
Enhanced GitHub Monitor
├── GitHub Client (API integration)
├── Enhanced File Scanner (MIME detection, classification)
├── Enhanced Content Analyzer (deterministic patterns, entropy)
├── Git History Analyzer (commit scanning, blob caching)
├── Risk Scoring Engine (configurable scoring rules)
├── Advanced Config Manager (YAML rules engine)
├── Performance Optimizer (filtering, caching, parallel processing)
├── Output Formatters (JSON, SARIF)
└── Email Notifier (HTML dashboard reports)
```

### Key Enhancements

1. **Deterministic Detection**: Proven regex patterns with high confidence
2. **Entropy Analysis**: Shannon entropy ≥4.5 for potential secrets
3. **File Classification**: Smart detection of code vs data files
4. **Git History Deep Scan**: Historical leak detection
5. **Risk Scoring**: Multi-factor risk assessment
6. **Performance Optimization**: Smart filtering and parallel processing
7. **Advanced Configuration**: YAML-based rules engine
8. **Enterprise Reporting**: JSON and SARIF output formats

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Security

This tool is designed to find security issues. Please:
- Store your GitHub token securely
- Review scan results before sharing
- Use the redaction features in production
- Follow responsible disclosure for findings

## License

MIT License - see LICENSE file for details.

## Support

For issues, questions, or contributions:
- GitHub Issues: [Repository Issues](https://github.com/your-org/enhanced-github-monitor/issues)
- Documentation: [Wiki](https://github.com/your-org/enhanced-github-monitor/wiki)
- Security Issues: security@company.com

---

**⚠️ Important**: This tool is for authorized security testing only. Ensure you have permission to scan the repositories you're analyzing.