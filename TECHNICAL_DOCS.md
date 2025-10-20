# GitScanner - Technical Documentation

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Data Flow Diagrams](#data-flow-diagrams)
- [Component Documentation](#component-documentation)
- [API Reference](#api-reference)
- [Security Architecture](#security-architecture)
- [Performance Specifications](#performance-specifications)
- [Development Guide](#development-guide)

## Architecture Overview

GitScanner is designed as a modular, extensible security monitoring system with three distinct scanning engines optimized for different use cases.

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         GitScanner System                       │
├─────────────────────────────────────────────────────────────────┤
│  User Interfaces                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ CLI Tools   │  │ Direct      │  │ Scheduled   │             │
│  │             │  │ Execution   │  │ Tasks       │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  Scanning Engines                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Simple      │  │ Enhanced    │  │ Enterprise  │             │
│  │ Monitor     │  │ Monitor     │  │ Monitor     │             │
│  │             │  │             │  │             │             │
│  │ • Basic     │  │ • MIME      │  │ • Advanced  │             │
│  │   patterns  │  │   detection │  │   regex     │             │
│  │ • File      │  │ • Entropy   │  │ • Git       │             │
│  │   analysis  │  │   analysis  │  │   history   │             │
│  │ • HTML      │  │ • Content   │  │ • SARIF     │             │
│  │   reports   │  │   scanning  │  │   output    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  Core Components                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ GitHub      │  │ Config      │  │ Security    │             │
│  │ Client      │  │ Manager     │  │ Analyzer    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Report      │  │ Email       │  │ Risk        │             │
│  │ Generator   │  │ Notifier    │  │ Engine      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  External Integrations                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ GitHub API  │  │ SMTP        │  │ File        │             │
│  │             │  │ Services    │  │ System      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagrams

### High-Level Data Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User      │    │  GitScanner │    │   GitHub    │    │   Email     │
│ Execution   │───▶│   System    │───▶│     API     │    │  Service    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                  │                  ▲
                          ▼                  ▼                  │
                   ┌─────────────┐    ┌─────────────┐           │
                   │   Local     │    │ Repository  │           │
                   │   Reports   │    │    Data     │───────────┘
                   └─────────────┘    └─────────────┘
```

### Detailed Scanning Flow

```
START
  │
  ▼
┌─────────────────┐
│ Load            │
│ Configuration   │
│ (.env file)     │
└─────────────────┘
  │
  ▼
┌─────────────────┐
│ Initialize      │
│ GitHub Client   │
│ (Auth Token)    │
└─────────────────┘
  │
  ▼
┌─────────────────┐
│ Fetch User      │
│ Repositories    │
│ (API Call)      │
└─────────────────┘
  │
  ▼
┌─────────────────┐    ┌─────────────────┐
│ For Each        │───▶│ Get Repository  │
│ Repository      │    │ Contents        │
│                 │    │ (Files & Dirs)  │
└─────────────────┘    └─────────────────┘
  │                              │
  ▼                              ▼
┌─────────────────┐    ┌─────────────────┐
│ Filter Files    │◀───│ Analyze Each    │
│ (Skip Binary,   │    │ File            │
│  Large Files)   │    │ • Name Pattern  │
└─────────────────┘    │ • Content Scan  │
  │                    │ • Risk Score    │
  ▼                    └─────────────────┘
┌─────────────────┐              │
│ Security        │              │
│ Analysis        │◀─────────────┘
│ • Pattern Match │
│ • Risk Assess   │
│ • Categorize    │
└─────────────────┘
  │
  ▼
┌─────────────────┐
│ Generate        │
│ Report          │
│ • HTML/JSON     │
│ • SARIF         │
└─────────────────┘
  │
  ▼
┌─────────────────┐
│ Send            │
│ Notifications   │
│ (Email Alerts)  │
└─────────────────┘
  │
  ▼
END
```

### Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GitScanner Internal Flow                         │
└─────────────────────────────────────────────────────────────────────────┘

ConfigManager          GitHubClient          SecurityAnalyzer
     │                       │                       │
     │ 1. load_config()      │                       │
     │────────────────────────────────────────────────────────────────────┐
     │                       │                       │                   │
     │                  2. authenticate()            │                   │
     │                       │────────────────────────────────────────────┼──▶ GitHub API
     │                       │                       │                   │
     │                  3. get_repositories()        │                   │
     │                       │────────────────────────────────────────────┼──▶ GitHub API
     │                       │                       │                   │
     │                       │◀───────────────────────────────────────────┼──── Repository List
     │                       │                       │                   │
     │                       │  4. get_contents()    │                   │
     │                       │────────────────────────────────────────────┼──▶ GitHub API
     │                       │                       │                   │
     │                       │◀───────────────────────────────────────────┼──── File Contents
     │                       │                       │                   │
     │                       │    5. analyze_file()  │                   │
     │                       │──────────────────────▶│                   │
     │                       │                       │                   │
     │                       │                       │ 6. pattern_match()│
     │                       │                       │────────────────────┼──▶ Local Analysis
     │                       │                       │                   │
     │                       │                       │ 7. risk_score()   │
     │                       │                       │────────────────────┼──▶ Risk Engine
     │                       │                       │                   │
     │                       │ ◀─────────────────────│                   │
     │                       │    Analysis Results   │                   │
     │                       │                       │                   │

ReportGenerator         EmailNotifier         FileSystem
     │                       │                       │
     │ 8. generate_report()  │                       │
     │────────────────────────────────────────────────────────────────────┼──▶ Local Storage
     │                       │                       │                   │
     │                  9. send_alert()              │                   │
     │                       │────────────────────────────────────────────┼──▶ SMTP Server
     │                       │                       │                   │
```

## Component Documentation

### Core Components

#### 1. Configuration Manager (`src/config_manager.py`)

**Purpose**: Centralized configuration management and validation.

**Key Methods**:
```python
class ConfigManager:
    def __init__(self, config_path: str = '.env')
    def load_config(self) -> Dict[str, Any]
    def validate_config(self) -> bool
    def get_github_config(self) -> Dict[str, str]
    def get_email_config(self) -> Dict[str, Any]
```

**Data Flow**:
```
.env file → load_config() → validate_config() → config_data (dict)
```

**Configuration Schema**:
```yaml
github:
  token: string (required)
  username: string (optional)
  
email:
  enabled: boolean
  smtp_server: string
  smtp_port: integer
  sender_email: string
  sender_password: string
  recipient_emails: array
  
scanning:
  scan_private_repos: boolean
  scan_depth: integer
  max_file_size: integer
  rate_limit_delay: float
  
alerts:
  critical: boolean
  high: boolean
  medium: boolean
  
logging:
  level: string
  file: string
```

#### 2. GitHub Client (`src/github_client.py`)

**Purpose**: GitHub API integration with rate limiting and error handling.

**Key Methods**:
```python
class GitHubClient:
    def __init__(self, token: str)
    def get_user_repositories(self) -> List[Dict[str, Any]]
    def get_repository_contents(self, full_name: str, path: str = "") -> List[Dict[str, Any]]
    def get_file_content(self, download_url: str) -> Optional[str]
    def get_repository_info(self, full_name: str) -> Optional[Dict[str, Any]]
```

**API Call Flow**:
```
authenticate() → get_user_repositories() → get_repository_contents() → get_file_content()
     │                     │                        │                        │
     ▼                     ▼                        ▼                        ▼
GitHub API         GitHub API              GitHub API              GitHub API
/user              /user/repos             /repos/.../contents     raw.githubusercontent.com
```

**Rate Limiting Strategy**:
- Automatic retry with exponential backoff
- Configurable delay between requests
- Respect GitHub API rate limits (5000/hour authenticated)

#### 3. Security Analyzer Components

##### File Scanner (`src/file_scanner.py` / `src/enhanced_file_scanner.py`)

**Purpose**: File-level security analysis and classification.

**Analysis Pipeline**:
```
File Path → Name Analysis → Extension Check → Size Validation → Suspicion Score
    │             │              │               │                    │
    ▼             ▼              ▼               ▼                    ▼
Pattern        Known           Binary         Size Limits         Risk Level
Matching      Suspicious       Detection      Enforcement         (0-100)
              Extensions
```

**Detection Patterns**:
```python
SUSPICIOUS_PATTERNS = {
    'credentials': ['.env', '.secret', '.private', 'credentials', 'password'],
    'keys': ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '.pem', '.p12', '.pfx'],
    'configs': ['config.json', 'secrets.json', 'database.yml', 'settings.py'],
    'certificates': ['.crt', '.cer', '.key', '.jks', '.keystore']
}
```

##### Content Analyzer (`src/content_analyzer.py` / `src/enhanced_content_analyzer.py`)

**Purpose**: Deep content analysis for sensitive data patterns.

**Analysis Flow**:
```
File Content → Encoding Detection → Pattern Matching → Context Analysis → Confidence Score
     │               │                    │                 │                 │
     ▼               ▼                    ▼                 ▼                 ▼
UTF-8/ASCII    Charset Detection    Regex Patterns    Surrounding Text   Weighted Score
  Fallback        (chardet)         (Credentials)      Analysis          (0.0-1.0)
```

**Pattern Categories**:
```python
PATTERN_CATEGORIES = {
    'api_keys': {
        'aws_access_key': r'\bAKIA[0-9A-Z]{16}\b',
        'github_token': r'\bghp_[a-zA-Z0-9]{36}\b',
        'openai_key': r'\bsk-[a-zA-Z0-9]{48}\b'
    },
    'secrets': {
        'jwt_token': r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b',
        'private_key': r'-----BEGIN (RSA )?PRIVATE KEY-----'
    },
    'personal_data': {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'
    }
}
```

#### 4. Risk Scoring Engine (`src/risk_scoring_engine.py`)

**Purpose**: Quantitative risk assessment and prioritization.

**Scoring Algorithm**:
```
Base Score = Pattern Weight × Confidence × Context Multiplier

Risk Factors:
├── Pattern Type Weight (0-100)
│   ├── Private Keys: 100
│   ├── API Keys: 80
│   ├── Passwords: 70
│   └── Email Addresses: 30
│
├── Confidence Level (0.0-1.0)
│   ├── Exact Match: 1.0
│   ├── High Probability: 0.8
│   ├── Medium Probability: 0.6
│   └── Low Probability: 0.4
│
└── Context Multiplier (0.5-2.0)
    ├── Production Files: 2.0
    ├── Configuration Files: 1.5
    ├── Source Code: 1.0
    └── Documentation: 0.5

Final Score = min(100, Base Score)

Risk Levels:
├── CRITICAL: 85-100
├── HIGH: 65-84
├── MEDIUM: 35-64
└── LOW: 0-34
```

#### 5. Report Generator (`simple_enhanced_monitor.py` / `src/output_formatters.py`)

**Purpose**: Multi-format report generation and presentation.

**Report Generation Flow**:
```
Scan Results → Data Aggregation → Format Selection → Template Rendering → Output File
     │               │                  │               │                 │
     ▼               ▼                  ▼               ▼                 ▼
Raw Findings    Summary Stats      HTML/JSON/SARIF   Jinja2/Custom   Local Storage
Repository      Risk Distribution   Format Choice     Templates       File System
File Issues     Timeline Data       User Preference   Styling         Email Attachment
```

**Output Formats**:

1. **HTML Report**:
   ```html
   ├── Executive Summary
   ├── Risk Distribution Chart
   ├── Repository-by-Repository Details
   ├── Issue Categorization
   └── Remediation Recommendations
   ```

2. **JSON Report**:
   ```json
   {
     "scan_metadata": {...},
     "summary": {...},
     "repositories": [...],
     "issues": [...],
     "recommendations": [...]
   }
   ```

3. **SARIF Report** (Static Analysis Results Interchange Format):
   ```json
   {
     "version": "2.1.0",
     "runs": [{
       "tool": {...},
       "results": [...],
       "properties": {...}
     }]
   }
   ```

## API Reference

### Main Entry Points

#### Simple Enhanced Monitor
```python
from simple_enhanced_monitor import SimpleEnhancedMonitor

monitor = SimpleEnhancedMonitor(config_path='.env')
results = monitor.scan_all_repositories(max_repositories=10)
report = monitor.generate_report(results, output_format='html')
monitor.send_notifications(results)
```

#### Enhanced Monitor (Enterprise)
```python
from enhanced_github_monitor import EnhancedGitHubMonitor

monitor = EnhancedGitHubMonitor(config_path='.env')
results = monitor.scan_all_repositories(
    include_git_history=True,
    max_repositories=None,
    repository_filter=".*web.*"
)
```

### Configuration API

```python
from src.config_manager import ConfigManager

config = ConfigManager('.env')
github_config = config.get_github_config()
email_config = config.get_email_config()
```

### GitHub Client API

```python
from src.github_client import GitHubClient

client = GitHubClient(token='your_token')
repos = client.get_user_repositories()
contents = client.get_repository_contents('owner/repo')
```

### Security Analysis API

```python
from src.file_scanner import FileScanner
from src.content_analyzer import ContentAnalyzer

file_scanner = FileScanner()
content_analyzer = ContentAnalyzer()

# File analysis
file_risk = file_scanner.analyze_file_path('/path/to/file')

# Content analysis
content_issues = content_analyzer.analyze_content('file content here')
```

## Security Architecture

### Authentication Flow

```
User Credentials → ConfigManager → GitHubClient → GitHub API
      │                │              │             │
      ▼                ▼              ▼             ▼
   .env file      Validation     Authorization   API Calls
  (Local Only)    (Required)      (Bearer)      (HTTPS)
```

### Data Protection

**Sensitive Data Handling**:
1. **Credentials**: Never logged or stored outside .env
2. **API Tokens**: Masked in logs (`****` + last 4 chars)
3. **File Contents**: Analyzed locally, never transmitted
4. **Email Passwords**: Encrypted in memory, cleared after use

**Security Principles**:
- **Principle of Least Privilege**: Minimal GitHub token scopes
- **Defense in Depth**: Multiple validation layers
- **Data Minimization**: Only necessary data processed
- **Secure by Default**: Conservative security settings

### Threat Model

**Assets**:
- GitHub repositories and metadata
- User credentials and API tokens
- Security findings and reports

**Threats**:
- Credential exposure in logs/reports
- Unauthorized repository access
- Data leakage through network traffic
- Report tampering or unauthorized access

**Mitigations**:
- Token masking in all output
- HTTPS-only communication
- Local processing and storage
- Input validation and sanitization

## Performance Specifications

### Scalability Metrics

**Repository Scanning Performance**:
```
Repository Size    | Scan Time   | Memory Usage | API Calls
Small (< 100 files)| 2-5 sec     | < 50 MB      | 5-10
Medium (100-1K)    | 10-30 sec   | < 100 MB     | 20-50
Large (1K-10K)     | 1-5 min     | < 200 MB     | 100-500
Very Large (10K+)  | 5-30 min    | < 500 MB     | 500+
```

**Rate Limiting**:
- GitHub API: 5000 requests/hour (authenticated)
- Default delay: 1.0 second between requests
- Exponential backoff on rate limit hits
- Automatic retry with jitter

**Memory Optimization**:
- Streaming file processing
- Lazy loading of repository contents
- Garbage collection between repositories
- Configurable memory limits

### Optimization Strategies

**Smart Filtering**:
```python
SKIP_PATTERNS = {
    'binary_extensions': ['.jpg', '.png', '.pdf', '.zip', '.exe'],
    'large_files': 'size > MAX_FILE_SIZE',
    'generated_files': ['node_modules/', 'vendor/', '.git/'],
    'cache_directories': ['.cache/', 'tmp/', 'build/']
}
```

**Parallel Processing**:
- Concurrent repository scanning
- Asynchronous API calls
- Thread-safe shared resources
- Configurable worker pool size

**Caching Strategy**:
- Repository metadata caching
- Content hash-based deduplication
- Incremental scanning support
- TTL-based cache invalidation

## Development Guide

### Project Structure

```
GitScanner/
├── src/                          # Core library code
│   ├── __init__.py              # Package initialization
│   ├── config_manager.py        # Configuration management
│   ├── github_client.py         # GitHub API client
│   ├── file_scanner.py          # Basic file analysis
│   ├── enhanced_file_scanner.py # Advanced file analysis
│   ├── content_analyzer.py      # Content pattern matching
│   ├── enhanced_content_analyzer.py # Advanced content analysis
│   ├── email_notifier.py        # Email notification system
│   ├── risk_scoring_engine.py   # Risk assessment
│   ├── git_history_analyzer.py  # Git commit analysis
│   ├── output_formatters.py     # Report formatting
│   ├── performance_optimizer.py # Performance enhancements
│   └── advanced_config_manager.py # Enterprise configuration
├── github_monitor.py            # Original simple monitor
├── simple_enhanced_monitor.py   # Improved simple monitor
├── enhanced_github_monitor.py   # Enterprise monitor
├── run_monitor.py              # CLI interface
├── setup.py                    # Installation script
├── requirements.txt            # Python dependencies
├── .env.example               # Configuration template
├── .gitignore                 # Git ignore rules
├── LICENSE                    # MIT license
├── README.md                  # User documentation
└── TECHNICAL_DOCS.md          # This document
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/ewestrum/GitScanner.git
cd GitScanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Run tests
python -m pytest tests/

# Run development server
python simple_enhanced_monitor.py
```

### Testing Strategy

**Unit Tests**:
```python
tests/
├── test_config_manager.py
├── test_github_client.py
├── test_file_scanner.py
├── test_content_analyzer.py
├── test_risk_engine.py
└── test_integration.py
```

**Test Categories**:
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **API Tests**: GitHub API integration testing
- **Security Tests**: Credential handling validation
- **Performance Tests**: Scalability and memory usage

### Contributing Guidelines

**Code Style**:
- PEP 8 compliance
- Type hints for all functions
- Comprehensive docstrings
- Error handling and logging

**Security Requirements**:
- No hardcoded credentials
- Input validation and sanitization
- Secure default configurations
- Privacy-preserving logging

**Performance Standards**:
- Memory usage monitoring
- API rate limit compliance
- Efficient algorithm selection
- Scalability considerations

### Deployment Considerations

**Production Deployment**:
- Environment variable configuration
- Secure credential management
- Monitoring and alerting
- Log aggregation and analysis

**Docker Deployment**:
```dockerfile
FROM python:3.8-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "simple_enhanced_monitor.py"]
```

**Kubernetes Deployment**:
- ConfigMap for non-sensitive config
- Secret for credentials
- Resource limits and requests
- Health checks and readiness probes

---

**Document Version**: 1.0  
**Last Updated**: October 20, 2025  
**Maintainer**: Erik Westrum  
**Review Cycle**: Quarterly