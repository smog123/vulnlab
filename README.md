# VulnLab - Intentionally Vulnerable Web Application

A security training platform covering all OWASP Top 10 (2025) vulnerabilities with 3 difficulty levels.

## WARNING

**This application is intentionally vulnerable. Never deploy in production.**

## Quick Start

### Docker (Recommended)

```bash
docker compose up --build
```

### Manual

```bash
pip install -r requirements.txt
python seed_db.py
python app.py
```

Open http://localhost:5000

## Default Users

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| alice | user123 | user |
| bob | user123 | user |
| charlie | password | user |

## Difficulty Levels

- **LOW** - Trivially exploitable, no mitigations
- **MEDIUM** - Partial fixes, still bypassable
- **HIGH** - Secure implementations

Toggle via navbar or URL: `?level=LOW`

## OWASP Top 10 Coverage

| Category | Vulnerabilities |
|----------|----------------|
| A01 Broken Access Control | IDOR, Privilege Escalation, CORS, BOLA |
| A02 Security Misconfiguration | Directory Listing, Verbose Errors, Debug Console |
| A03 Supply Chain | Vulnerable Dependencies |
| A04 Cryptographic Failures | Weak Hashing, Plaintext, Hardcoded Keys |
| A05 Injection | SQLi, XSS (Stored/Reflected/DOM), Command Injection |
| A06 Insecure Design | Business Logic Bypass, Mass Assignment, No Rate Limit |
| A07 Authentication Failures | Brute Force, Weak Passwords, JWT Flaws |
| A08 Data Integrity Failures | Insecure Deserialization, Cookie Tampering |
| A09 Logging Failures | Silent Auth Failures, No Audit Trail |
| A10 Exceptional Conditions | Stack Trace Leaks, Verbose Errors |

## API Endpoints

See `/api/v1/docs` after starting the app.

## License

Educational use only.
