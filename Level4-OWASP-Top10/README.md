# Level 4 - OWASP Top 10 (Wajib Kuasai)

OWASP Top 10 adalah top 10 web application security risks paling umum. Wajib dikuasai untuk jadi web pentester yang kompeten.

## 📋 Daftar Vulnerability OWASP Top 10 (2021 Update)

### A01:2021 – Broken Access Control
**Description:** Restrictions pada akses user ke resources tidak proper atau tidak ada.

**Contoh vuln:**
- IDOR (Insecure Direct Object Reference): Mengakses objek milik user lain
- Privilege escalation: User normal access admin pages
- Horizontal/Vertical privilege bypass

**Testing example:**
```
# Access user data from another user
/vulnerable/profile.php?id=12345  // normal user
/vulnerable/profile.php?id=67890  // admin user
```

**Prevention:**
- Implement role-based access control (RBAC)
- Use session checks dan input validation
- Principle of least privilege

### A02:2021 – Cryptographic Failures
**Description:** Sensitive data tidak protected atau menggunakan cryptography lemah.

**Contoh:**
- Transmit sensitive data tanpa encryption (HTTP vs HTTPS)
- Weak crypto algorithms (MD5, SHA1)
- Hardcoded encryption keys

**Testing:**
- Check untuk non-HTTPS traffic
- Crack hashed passwords jika leak

### A03:2021 – Injection
**Description:** Hostile data injected ke interpreter.

**Types:**
- SQL Injection (SQLi)
- Command Injection
- LDAP Injection
- XPath Injection
- etc.

**Example payloads sudah dijelaskan di Level 3**

### A04:2021 – Insecure Design
**Description:** Architecture design yang vulnerable karena tidak mempertimbangkan security.

**Contoh:**
- Business logic flaws
- Mass assignment vulnerabilities
- CORS misconfiguration

**Prevention:**
- Threat modeling
- Secure design patterns
- Assume breach mindset

### A05:2021 – Security Misconfiguration
**Description:** Default configs, incomplete configs, atau misconfigured security.

**Contoh:**
- Debug mode enabled di production
- Default passwords tidak diganti
- Error messages verbose (info leak)

**Testing:**
- Check default credentials
- Review server headers untuk version leaks
- Test directory listing

### A06:2021 – Vulnerable & Outdated Components
**Description:** Component dengan vuln known atau outdated.

**Contoh:**
- Libraries versi lama dengan CVE
- DependencyChain vulnerable

**Prevention:**
- Dependency scanning tools (OWASP Dependency Checker)
- Regular updates
- Monitor vuln databases (NVD, CVE)

### A07:2021 – Identification & Authentication Failure
**Description:** Session management dan auth failures.

**Contoh:**
- Brute force attacks
- Password cracking
- Session fixation
- Weak password policies

**Prevention:**
- Multi-factor authentication (MFA)
- Strong password policies
- Account lockout mechanisms

### A08:2021 – Software & Data Integrity Failure
**Description:** Integrity dari software updates ataupun kritikal data rusak.

**Contoh:**
- Insecure CI/CD pipelines
- Auto-update tanpa verification
- Software supply chain attacks

**Prevention:**
- Code signing
- Update verification
- Secure CI/CD practices

### A09:2021 – Security Logging & Monitoring Failure
**Description:** Insufficient logging & monitoring untuk detect attacks.

**Contoh:**
- No logging pada critical functions
- Logs tidak dicatat incidents
- No alerting system

**Prevention:**
- Implement comprehensive logging
- Use SIEM systems
- Regular log analysis

### A10:2021 – Server-Side Request Forgery (SSRF)
**Description:** Application dapat membuat requests ke internal network.

**Contoh:**
```
?url=http://internal/admin
?url=file:///etc/passwd
```

**Prevention:**
- Whitelist allowed URLs
- Use URL validation libraries
- Network segmentation

## Learning Resources
- OWASP Top 10 Documentation: https://owasp.org/www-project-top-ten/
- Practice: PortSwigger labs, TryHackMe Web Fundamentals
- Certification: OSCP/OSCE (berguna untuk advance corruption)

## Notes
- Setiap vulnerability punya category, severity, dan impact tertentu
- Real world apps sering combine multiple vuln
- Test methodologies: Kali Linux, Burp Suite, usw.
