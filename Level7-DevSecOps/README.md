# Level 7 - DevSecOps & Defense (optional)

DevSecOps adalah integration security ke dalam development lifecycle. Optional tapi valuable untuk jadi security technologist vs hacker.

## 🔥 Defense Side: WAF, SIEM, Hardening

### Web Application Firewall (WAF)
**Lu udah pernah pakai :** Fortigate, Sophos, etc.

**Advanced WAF Concepts:**
- **ModSecurity:** Open-source WAF, Core Rules Set (CRS)
- **CloudFlare WAF:** Managed service, OWASP integration
- **AWS WAF/APIGee:** Cloud-native protection

**Implementation:**
- Rule tuning: Reduce false positives
- Custom rules untuk app-specific threats
- Integration dengan SIEM untuk alerts

**Bypassing (Pentester Perspective):**
- Understand evasion techniques untuk test WAF effectiveness
- Use modsecurity-cr-sec language

### Security Information & Event Management (SIEM)
**Lu udah pake Wazuh:**

**Advanced SIEM:**
- **Splunk:** Commercial, powerful correlation
- **ELK Stack:** Elasticsearch + Logstash + Kibana
- **QRadar:** IBM enterprise SIEM

**Key Components:**
- Log collection: Syslog, Windows events
- Correlation rules: Threat detection
- Dashboard creation: Visualization alerts
- Incident response integration

**Use Cases:**
- IDS/IPS correlation
- User behavior analytics
- Threat hunting queries

### System Hardening
**Server Hardening Steps:**
1. **OS Baseline:**
   - Remove unnecessary services
   - Disable root login
   - Keep updated (apt/yum update)

2. **Network Hardening:**
   - Firewall rules (ufw, iptables)
   - SSH config: key auth only, non-standard port
   - Disable IPv6 jika tidak perlu

3. **Application Security:**
   - Least privilege principle
   - Secure configs (PHP, Apache)
   - File permissions lockdown

**Tools:**
- Lynis: Audit security
- OpenSCAP: Automated compliance
- CIS Benchmarks: Standard hardening guides

## 🔧 DevSecOps Pipeline

### CI/CD Security Integration

**Security Gates in Pipeline:**
- **SAST (Static Application Security Testing):**
  - Code analysis tanpa execution
  - Tools: SonarQube, Fortify, Checkmarx
  - Cek vulnerabilities code level

- **DAST (Dynamic Application Security Testing):**
  - Runtime testing
  - Tools: OWASP ZAP, Burp Scanner
  - Simulate attacks pada running apps

- **SCA (Software Composition Analysis):**
  - Dependency scanning
  - Tools: OWASP Dependency-Check, Snyk
  - Monitor third-party libraries vuln

**Infrastructure as Code (IaC) Security:**
- Terraform/OpenTofu security
- CloudFormation scans
- Tools: Checkov, Terrascan

### Container Security

**Docker Security Best Practices:**
1. **Image Hardening:**
   - Use trusted base images
   - Minimize layers
   - Multi-stage builds untuk reduce size

2. **Runtime Security:**
   - Docker bench security audit
   - Security profiles (AppArmor, SELinux)
   - No privileged containers

3. **Scanning:**
   - Clair, Trivy untuk vuln scanning
   - Hadolint untuk Dockerfile linting

**Kubernetes Security:**
- RBAC configuration
- Network policies
- Pod security standards
- Image scanning di admission controllers

### API Security

**API-Specific Threats:**
- API rate limiting bypass
- JWT token attacks
- GraphQL injection
- Mass assignment

**Protection:**
- API gateways (Kong, Tyk, AWS API Gateway)
- OAuth2/OpenID implementation
- Input validation schemas
- WAF untuk API endpoints

## 🌐 Zero-Trust Network

### Zero-Trust Principles
- **Never trust, always verify**
- Least privilege access
- Micro-segmentation
- Continuous monitoring

**Implementation Steps:**
1. **Identity Management:**
   - MFA everywhere
   - Role-based access (RBAC/ABAC)
   - Session management

2. **Network Controls:**
   - Software-defined networking (SDN)
   - Next-gen firewalls
   - VPN everywhere

3. **Device Security:**
   - Endpoint protection (EDR)
   - Device certificates
   - Conditional access policies

**Tools:**
- BeyondTrust (privileged access)
- Cloudflare Access/ZTNA
- Microsoft Azure AD

## 📊 Logging & Monitoring

### Comprehensive Logging Strategy
**What to Log:**
- Authentication events
- Privilege escalation attempts
- Data access (CRUD operations)
- Unusual user behavior
- Admin actions

**Logging Best Practices:**
- Structured logging (JSON format)
- Centralized collection (rsyslog)
- Log rotation & retention policies
- Tamper-proof storage

### Security Monitoring
**Real-time Detection:**
- Failed login attempts
- Abnormal traffic patterns
- File integrity monitoring
- Malware detection

**Alerting:**
- Threshold-based alerts
- SIEM correlation
- Incident response playbooks

## 🎯 Career Path in DevSecOps

### Roles Available
- **DevSecOps Engineer:** CI/CD pipeline security
- **Security DevOps:** Infrastructure hardening
- **Application Security Engineer:** SAST/DAST implementation
- **Cloud Security Architect:** Cloud-native security
- **Compliance Engineer:** Regulatory requirements

### Certifications
- **CISSP:** Broad security knowledge
- **CISM:** Info security management
- **AWS Security Specialty:** Cloud security
- **CKA/CKS:** Kubernetes security
- **OSCP -> OSWE:** Offensive advanced

### Benefits
- Higher salaries (vs offensive only)
- Job stability (demand security everywhere)
- Positive impact: Building secure systems
- Career growth: Management/Architecture paths

### Learning Resources
- DevSecOps GitHub project
- OWASP DevSecOps Guideline
- SANS DevSecOps courses
- Kubernetes security best practices

**Note:** This level optional, tapi valuable untuk balance offensive (hacking) dengan defensive (protection) skills.
