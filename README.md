# GitScanner 🔍

A comprehensive GitHub repository security monitoring tool that scans for sensitive files, credentials, and potential data leaks across your GitHub repositories.

![GitHub Security Scan](https://img.shields.io/badge/Security-Scanner-red)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## � Features

### Core Functionality
- **Multi-Repository Scanning**: Automatically scans all accessible GitHub repositories
- **Intelligent File Detection**: Identifies suspicious files based on names and patterns
- **Beautiful HTML Reports**: Generates professional security reports with severity ratings
- **Email Notifications**: Sends security alerts via email with detailed findings
- **Real-time Monitoring**: Configurable scanning intervals for continuous security monitoring

### Security Detection
- **Sensitive Files**: Detects `.env`, `.secret`, credentials files, private keys
- **Configuration Files**: Identifies `config.json`, `secrets.json`, database configs
- **Certificate Files**: Finds `.pem`, `.p12`, `.pfx`, SSH keys (`id_rsa`, etc.)
- **Risk Scoring**: Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL) to findings

### Advanced Features (Enhanced Version)
- **MIME Type Detection**: Advanced file classification with fallback support
- **Entropy Analysis**: Detects high-entropy strings that may contain secrets
- **Git History Scanning**: Deep analysis of commit history for leaked credentials
- **Pattern Recognition**: Deterministic regex rules for AWS keys, JWT tokens, API keys
- **Multiple Output Formats**: JSON, SARIF (Static Analysis Results Interchange Format)
- **Performance Optimization**: Smart filtering and parallel processing

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- GitHub Personal Access Token
- Git (for repository operations)

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/ewestrum/GitScanner.git
   cd GitScanner
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your actual credentials (see Configuration section)
   ```

4. **Run your first scan**
   ```bash
   python simple_enhanced_monitor.py
   ```

## ⚙️ Configuration

### GitHub Access Token

1. Go to [GitHub Settings → Tokens](https://github.com/settings/tokens)
2. Create a new Personal Access Token with these scopes:
   - `repo` (for private repositories)
   - `public_repo` (for public repositories only)
3. Copy the token to your `.env` file

### Email Configuration (Optional)

For Gmail users:
1. Enable 2-Factor Authentication
2. Generate an [App Password](https://myaccount.google.com/apppasswords)
3. Use the app password in your `.env` file

### Environment Variables

```bash
# Required
GITHUB_TOKEN=your_github_token_here
GITHUB_USERNAME=your_github_username

# Email notifications (optional)
EMAIL_ENABLED=true
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_password_here
RECIPIENT_EMAILS=alert1@example.com,alert2@example.com

# Scanning configuration
SCAN_PRIVATE_REPOS=true
SCAN_DEPTH=2
MAX_FILE_SIZE=1048576
RATE_LIMIT_DELAY=1.0

# Alert levels
ALERT_CRITICAL=true
ALERT_HIGH=true
ALERT_MEDIUM=false
```

## 📖 Documentation

- **[User Guide](README.md)** - Installation, configuration, and usage
- **[Technical Documentation](TECHNICAL_DOCS.md)** - Complete technical reference with data flow diagrams
- **[Architecture Guide](ARCHITECTURE.md)** - Advanced architecture and design patterns
- **[Enhanced Features](README_Enhanced.md)** - Enterprise features documentation

## 🏃‍♂️ Usage

### Basic Usage

```bash
# Simple scan with HTML report
python simple_enhanced_monitor.py

# Original monitor with text output
python github_monitor.py

# Enhanced monitor with advanced features
python enhanced_github_monitor.py
```

### Command Line Options

```bash
# Limit number of repositories
python simple_enhanced_monitor.py --max-repos 10

# Specific repository
python simple_enhanced_monitor.py --repo owner/repo-name

# Generate JSON output
python enhanced_github_monitor.py --output json
```

## 📊 Output Examples

### HTML Report
- Professional dashboard with severity color coding
- Repository-by-repository breakdown
- Issue categorization and risk scoring
- Generated timestamp and scan statistics

### Email Alerts
- Immediate notifications for high-risk findings
- Summary reports with actionable insights
- HTML formatted for easy reading

### SARIF Output (Enhanced)
```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "GitScanner",
        "version": "1.0.0"
      }
    },
    "results": [...]
  }]
}
```

## 🔧 Architecture

### Core Components

```
src/
├── config_manager.py          # Configuration management
├── github_client.py           # GitHub API interface
├── email_notifier.py          # Email alert system
├── file_scanner.py            # Basic file analysis
├── content_analyzer.py        # Content pattern detection
└── advanced_config_manager.py # Enterprise configuration

Enhanced Components:
├── enhanced_file_scanner.py   # MIME detection & entropy analysis
├── enhanced_content_analyzer.py # Advanced pattern recognition
├── git_history_analyzer.py    # Git commit history scanning
├── risk_scoring_engine.py     # Risk assessment system
├── output_formatters.py       # JSON/SARIF export
└── performance_optimizer.py   # Performance enhancements
```

### Scanning Flow

1. **Authentication**: Validate GitHub token and permissions
2. **Repository Discovery**: Fetch accessible repositories
3. **File Enumeration**: List all files in each repository
4. **Security Analysis**: Apply detection rules and patterns
5. **Risk Assessment**: Calculate severity scores
6. **Report Generation**: Create HTML/JSON/SARIF outputs
7. **Notification**: Send email alerts for high-risk findings

## 🚨 Detected Security Issues

### File-Based Detection
- Environment files (`.env`, `.secret`)
- Private keys (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`)
- Certificates (`.pem`, `.p12`, `.pfx`)
- Configuration files (`credentials.h`, `config.json`)
- Database configs (`database.yml`, `settings.py`)

### Content-Based Detection (Enhanced)
- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_...`, `gho_...`)
- JWT Tokens (`eyJ...`)
- API Keys (various patterns)
- High-entropy strings (potential secrets)
- Database connection strings

### Git History Analysis (Enhanced)
- Accidentally committed secrets in past commits
- Deleted sensitive files still in history
- Credential rotation tracking

## 🛡️ Security Best Practices

### For This Tool
- **Never commit your `.env` file** - it contains sensitive tokens
- Use minimal required GitHub token permissions
- Regularly rotate your GitHub tokens
- Enable email alerts for immediate notification
- Store sensitive config in system environment variables for production

### For Your Repositories
- Use `.gitignore` to exclude sensitive files
- Implement pre-commit hooks for secret detection
- Use secret management services (AWS Secrets Manager, Azure Key Vault)
- Regular security audits and access reviews
- Enable GitHub security features (Dependabot, Code Scanning)

## � Performance

### Benchmarks
- **Small repos** (< 100 files): ~2-5 seconds
- **Medium repos** (100-1000 files): ~10-30 seconds  
- **Large repos** (1000+ files): ~1-5 minutes
- **Rate limiting**: Respects GitHub API limits automatically

### Optimization Features
- Parallel file processing
- Smart file filtering (skips binaries, large files)
- Caching for git history analysis
- Configurable scanning depth

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/ewestrum/GitScanner.git
cd GitScanner
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests
```bash
python -m pytest tests/
python -m coverage run -m pytest
python -m coverage report
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- GitHub API for comprehensive repository access
- Python community for excellent security libraries
- SARIF specification for standardized security reporting
- Security research community for threat intelligence

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ewestrum/GitScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ewestrum/GitScanner/discussions)
- **Security**: Please report security vulnerabilities privately

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have permission to scan repositories and comply with applicable laws and terms of service.