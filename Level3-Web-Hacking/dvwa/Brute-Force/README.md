# Brute Force - Authentication Attack Techniques

## 🎯 Apa Itu Brute Force Attack?

**Brute Force** adalah metode attack dimana attacker sistematis mencoba semua possible kombinasi untuk menebak credentials. Teknik ini menggunakan "brute strength" daripada intelligence untuk mendapatkan access.

## 🔬 Cara Kerja Brute Force

### Basic Flow
1. **Request Generation:** Systematis generate login attempts
2. **Response Analysis:** Parse untuk detect success/failure
3. **Iteration:** Continue sampai find valid credential

### Vulnerable Code
```php
// No protection - completely vulnerable
if ($_POST['password'] === 'admin') {
    echo "Login success!";
} else {
    echo "Invalid password";
}
```

## 🏗️ Teknologi Di Baliknya

### Session Management
- HTTP cookies untuk maintain sessions
- Stateless protocols vs stateful authentication
- Token-based auth (JWT, OAuth) immune ke basic brute force

### Authentication Libraries
- PHP: `password_verify()` dengan proper hashing
- .NET: ASP.NET Identity framework
- Node.js: Passport authentication

### Rate Limiting Systems
- nginx: `limit_req` module
- Apache: mod_security rules
- Application: Redis untuk counters

## 📊 Tipe Attacks

### Dictionary Attack
- **Wordlists:** rockyou.txt, haveibeenpwned lists
- **Custom Lists:** Bingo social engineering

### Credential Stuffing
- **Leaked Data:** Username:password pairs dari breaches
- **Automated Systems:** Selenium scripts untuk form submission

### Distributed Attack
- **Botnets:** Zombie machines untuk parallel attempts
- **Cloud Instances:** AWS/VPS untuk IP rotation

## 🛠️ Testing Tools

### Hydra
```bash
hydra -l username -P passwords.txt target.com http-post-form \
"/login:username=^USER^&password=^PASS^:F=invalid"
```

### Burp Intruder
1. Capture login request
2. Send to Intruder
3. Set payload positions
4. Configure wordlists
5. Analyze responses

### Custom Script
```python
import requests

def brute_force(url, userlist, passlist):
    for user in userlist:
        for pwd in passlist:
            data = {'user': user, 'pass': pwd}
            response = requests.post(url, data=data)
            if 'success' in response.text.lower():
                return f"Found: {user}:{pwd}"
    return "No match found"
```

## 🛡️ Prevention Methods

### Account Lockout
- Progressive delays (1s, 2s, 4s)
- Temporary lockouts (5-30 minutes)
- Permanent lock + admin unlock

### CAPTCHA
- Google reCAPTCHA v3 (invisible)
- hCaptcha (privacy-focused)
- Custom challenge-response

### MFA Requirements
- TOTP (Time-based One-Time Passwords)
- Push notifications
- Biometric factors

### Password Strength
- Min 12 characters, mixed case, numbers, symbols
- No common dictionaries
- Password history (no reuse)

### Anomaly Detection
- Geographic unusual login attempts
- Odd hours access patterns
- Failed attempt spikes

## 🔍 Real Cases

### 2013 Evernote Hack
- 50 million accounts compromised
- Weak password cracking

### 2020 Twitter VIP Breach
- Social engineering + brute force elements
- Super admin phishing

## 📚 Resources

- **Hydra Tutorial:** https://github.com/vanhauser-thc/thc-hydra
- **OWASP Brute Force:** https://owasp.org/www-community/attacks/Brute_force_attack
- **SecLists:** https://github.com/danielmiessler/SecLists

---

**Prevention > Detection untuk brute force.**
Implement MFA dan rate limiting fundamental security hygiene. 🛡️
