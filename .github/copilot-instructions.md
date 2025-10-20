<!-- GitHub Monitor Tool Instructions -->

This is a Python-based GitHub monitoring tool designed to scan repositories for sensitive information and prevent data leaks.

## Project Overview
- **Language**: Python 3.8+
- **Purpose**: Monitor GitHub repositories for sensitive files and content
- **Features**: 
  - Repository scanning for suspicious files
  - Content analysis for personal data and sensitive information
  - Email notifications for security issues
  - Configuration-based rules for file detection

## Development Guidelines
- Use type hints throughout the codebase
- Follow PEP 8 style guidelines
- Implement proper error handling and logging
- Use environment variables for sensitive configuration
- Write secure code that handles GitHub API tokens safely

## Dependencies
- requests: GitHub API communication
- python-dotenv: Environment variable management
- smtplib: Email notifications (built-in)
- pathlib: File path handling (built-in)
- re: Pattern matching for content analysis (built-in)

## Security Considerations
- Never commit API tokens or passwords
- Use .env files for configuration
- Implement rate limiting for GitHub API calls
- Validate all user inputs and file paths