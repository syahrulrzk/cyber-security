# Level 6 - Bug Bounty Starter

Level ini memulai transition ke real-world bug hunting. Setelah mahir technic, mulai hunt vuln di real applications untuk money.

## 🔍 Kalau Lu Mau Serius

Bug bounty adalah hunt vulnerabilities di applications real untuk mendapatkan bounty (uang reward). Average payout: $50-500 per vuln, high severity bisa $10k+.

### Preparation Sebelum Start
1. **Skill mastery:** OWASP Top 10 + advanced technics
2. **Methodology:** Recon, testing, reporting
3. **Tools:** Customisasi workflow (Burp, Nmap, custom scripts)
4. **Legal:** Read program policies, scope, out-of-scope

### Common Vulnerabilities & Payouts

#### 🔴 High Severity ($$$)
**SQL Injection** 
- Average payout: $2,500
- Impact: Data breach, arbitrary query execution
- Example programs: Shopify, Stripe, Coinbase

**IDOR (Broken Access Control)**
- Average: $1,000 - $3,000
- Most common in bug bounties
- Example: Access admin/user data via ID manipulation

**Remote Code Execution (RCE)**
- Avarage: $2,000 - $5,000+
- Critical: Execute arbitrary code pada server
- Rare tapi high reward

#### 🟠 Medium Severity ($)
**SSRF (Server-Side Request Forgery)**
- Average: $500 - $2,000
- Impact: Internal network access, info disclosure
- Methods: Bypass restrictions, protocol abuse

**Stored XSS**
- Average: $300 - $1,500
- Impact: Persistent attack pada users
- Tricky cations: DOM manipulation, exploit chains

#### 🟡 Low-Medium ($)
**Reflected XSS**
- Average: $150 - $500
- Basic web vuln, masih relevant
- Creative bypasses dapat higher reward

**Open Redirect**
- Average: $100 - $300
- Simple tapi banyak di real apps
- Combine dengan social engineering

**Weak Authentication Bypass**
- Average: $200 - $800
- Session management, credential stuffing
- Impact depends pada app

**Rate Limit Bypass**
- Average: $100 - $500
- Abuse APIs, denial service prevention
- Creative methods seperti time-baed attacks

### Bug Hunting Methodology

#### Phase 1: Reconnaissance
**Passive:**
- Google Dorking: site:target.com filetype:pdf inurl:admin
- Shodan: Toko vuln port/services
- GitHub: Source code leaks, configs
- Subdomain enumeration: sublist3r, amass, assetfinder

**Active:**
- Port scanning: Nmap untuk live services
- Directory brute: dirsearch, gobuster
- Parameter discovery: ParamSpider, waybackurls
- Content discovery: ferret.conf or similar

#### Phase 2: Vulnerability Assessment
1. **OWASP Top 10 Pulse:** Test semua category
2. **Business logic:** Test workflows anomali
3. **API hunting:** REST/SOAP pentesting
4. **Mobile apps:** Decompile APKs, intercept traffic

#### Phase 3: Exploitation & Proof of Concept
- Create minimal exploit
- Chain vulnerabilities untuk higher impact
- Document steps clearly
- Test mitigation bypass

#### Phase 4: Reporting
- Clean, professional report
- Include: Vulnerability description, steps to reproduce, impact, recommendation
- Follow program format
- Timeline awareness (some programs have 90 day disclosure)

### High-Paying Bug Bounty Programs

**Top Targets:**
- **Google:** $2,000+ average, complex apps
- **Facebook/Meta:** Generous payouts, $1,500+ average
- **Apple:** High rewards untuk iCloud/App Store
- **Uber:** API vuln, data exposure
- **Tesla:** IoT/security systems
- **Stripe/PayPal:** Financial, critical data

**Indonesian-specific:**
- Check Garuda Cybersecurity (Gov awards)
- Local fintech companies
- International programs accepting ID hunters

### Tools & Automation for Bug Bounty

**Custom Scripts:**
```bash
# Simple subdomain finder
subfinder -d target.com | httpx -status-code -title

# parameter mining
waybackurls target.com | grep "=" | tee params.txt

# JS analysis
cat javascript_files | grep -i token | secretfinder

# Nmap custom
nmap -sV -p- --script vuln target.com
```

**Essential Toolkit:**
- Nuclei: Automated vulnerability scanning
- SQLMap: SQL injection automation
- XSStrike: XSS scan tool
- aquatone: Visual site reconnaissance
- Burp Suite Professional

### Mindset & Ethics

**Ethical Hacking Rules:**
- Stay in scope
- No production impact
- Respect rate limits
- Use private programs untuk practice

**Mental Approach:**
- Patience: Some hunts take weeks
- Creativity: Think like attacker
- Document everything: Build portfolio
- Network: Discord, forums, conferences

### Building Portfolio
- Create GitHub repo demos
- Write detailed write-ups (no direct identify programs)
- Participate CTFs
- Obtain certifications (OSCP, OSCE, eCPPT)

### Legal Considerations
- Bug bounty programs is legal pentesting with permission
- No exploit without consent
- Respect NDA saat report

### Transition Path
1. Start dengan small programs
2. Focus pada quantity first, then quality
3. Collaborate via Discord bugbounty groups
4. Attend BSides conferences
5. Full-time vs part-time hunting

**Goal:** Consistent $1k+ monthly sebagai dedicated hunter.
