# Security Policy

## Supported Versions

This project is currently in active development. Security updates are provided for the latest release only.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this Azure network auditing tool, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

Send vulnerability reports to: **basfrankenn@gmail.com**

Include in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Initial Response**: Within 48-72 hours
- **Status Updates**: Every 5-7 days until resolved
- **Fix Timeline**: Depends on severity and complexity

### Scope

This tool performs read-only operations against Azure infrastructure with Reader permissions. Security concerns include:

- Authentication bypass or privilege escalation
- Credential exposure in logs or reports
- Code injection vulnerabilities in PowerShell modules
- Unauthorized data exfiltration
- Dependencies with known vulnerabilities

### Responsible Disclosure

Please allow reasonable time for vulnerabilities to be fixed before public disclosure. Credit will be given to researchers who report valid security issues.

## Security Best Practices for Users

When using this tool:

1. **Never commit credentials to version control**
   - Add `audit-config.json` to `.gitignore` if it contains secrets
   - Use environment variables for `AZURE_CLIENT_SECRET`
   - Consider Azure Key Vault for production environments

2. **Protect generated reports**
   - Reports contain network topology and configuration details
   - Store in secure locations with appropriate access controls
   - Implement retention policies for sensitive data

3. **Use least privilege**
   - Assign Reader role only to service principals
   - Avoid using Global Administrator accounts
   - Use dedicated identities for auditing

4. **Keep dependencies updated**
   - Update Azure PowerShell modules regularly
   - Monitor for security advisories on dependencies

5. **Secure execution environment**
   - Run from trusted systems only
   - Enable audit logging for script execution
   - Review generated reports before sharing
