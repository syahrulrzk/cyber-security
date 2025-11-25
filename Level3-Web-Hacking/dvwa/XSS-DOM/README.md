# XSS (DOM) - Document Object Model Manipulation

## 🎯 DOM XSS Overview
DOM-based XSS occurs in client-side JavaScript where user input is dynamically written to the DOM. Unlike reflected XSS, DOM XSS never reaches server - it's completely client-side.

## 🔬 How DOM XSS Works

### Source-Sink Pattern
**Sources:** User-controlled data from URL fragments, forms, cookies
**Sinks:** DOM methods that execute JavaScript

```javascript
// Classic DOM XSS sink
function selectTab(tabName) {
    document.getElementById('tab').innerHTML = `<div>${tabName}</div>`;
}
// Attacker controls tabName = '<img src=x onerror=alert(1)>'
selectTab('<img src=x onerror=alert(1)>');
```

### Vulnerable Patterns
```javascript
// Direct assignment
document.getElementById('output').innerHTML = location.hash;

// Function execution
eval(location.hash.substr(1));

// Dynamic script creation
var script = document.createElement('script');
script.src = userInput;
document.head.appendChild(script);
```

## 🏗️ DOM XSS Techniques

### Location Object Exploitation
```javascript
// Hash fragments (#...)
window.location.hash     // #user_input_here
location.hash

// Search parameters (?...)
location.search          // ?param=value

// Full URL
location.href

// Path segments
location.pathname        // /path/user_input
```

### URL Fragment Attacks
```html
<!-- Vulnerable: fragment written to DOM -->
<script>
    var fragment = location.hash.substr(1);
    document.write('<h1>' + decodeURIComponent(fragment) + '</h1>');
</script>

<!-- Attack URL: index.html#<img src=x onerror=alert(1)> -->
```

### JSONP Callbacks
```javascript
// Vulnerable JSONP
function processData(data) {
    // Attacker controls jsonparam name
}

var script = document.createElement('script');
script.src = 'https://api.com/data?callback=processData';
document.head.appendChild(script);

// Attack: callback=processData);alert(1);//
```

## 🛠️ Detection & Testing

### DOM XSS Location
```javascript
// Common sinks to check
document.write
document.writeln
innerHTML
outerHTML
insertAdjacentHTML
eval
setTimeout(setInterval with string)
document.createElement('script') with controlled src
```

### Manual Testing
```bash
# Test location sources
curl "http://target.com/page?#test"
curl "http://target.com/page?param=<script>alert(1)</script>"

# Check if JavaScript executes without server interaction
```

### Automated Tools
```bash
# DOMinator - Firefox extension for DOM XSS hunting
# https://addons.mozilla.org/en-US/firefox/addon/dominator/

# Burp Suite DOM Invader
# Analyzes DOM sinks and sources
```

## 🛡️ Prevention

### Avoid Dangerous Sinks
```javascript
// DON'T DO THIS
element.innerHTML = userInput;
eval(userInput);
setTimeout(userInput, 1000);

// DO THIS INSTEAD
element.textContent = userInput;
element.textContent = sanitizeHtml(userInput);
safeFunction(userInput); // Direct function reference
```

### Input Sanitization
```javascript
// Location object sanitization
function getHashFragment() {
    var hash = location.hash.slice(1); // Remove #
    return hash.replace(/[<>\"']/, ''); // Strip dangerous chars
}
```

### CSP Implementation
```http
Content-Security-Policy: default-src 'self';
                      script-src 'self' 'unsafe-inline';
                      object-src 'none'
```

### Server-Side Prevention
```php
// Never echo user input without validation
$userInput = htmlspecialchars($_GET['param']);
```

## 🔍 Real Examples

### 2018: Gmail Session Hijacking
- DOM XSS via HTML email parsing
- Attacker gained persistent access
- Fixed with CSP improvements

### 2021: Shopify Admin Panel
- DOM XSS in product editor
- Could manipulate admin privileges
- Fixed with input sanitization

---

**DOM XSS invisible tapi dangerous.** Server-side filtering ineffective. Client-side defense critical: avoid unsafe DOM methods + input validation. 🔄🕵️
