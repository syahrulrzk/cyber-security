# Insecure CAPTCHA - Automation Bypass Techniques

## 🎯 Apa Itu CAPTCHA?

**CAPTCHA** adalah Turing test untuk mencegah automated attacks. **Insecure CAPTCHA** bisa bypassed dengan OCR, service abuse, atau logic flaws.

## 🔬 Cara Kerja CAPTCHA

### Implementation Types
- **Text Image:** Distorted text dalam image
- **Math/Math Expression:** Basic arithmetic
- **reCAPTCHA:** Google's modern solution
- **Invisible:** Background behavior analysis

### Vulnerable Code Example
```php
// Weak CAPTCHA implementation
session_start();

$captcha_text = generate_random_string(); // 'AB2X'
$_SESSION['captcha'] = $captcha_text;
create_image($captcha_text); // Create image file

// Validation
if ($_POST['captcha'] === $_SESSION['captcha']) {
    process_form();
}
// Attacker memorizes from session leak
```

## 📊 Attack Vectors

### OCR-Based Breaking
```python
# Tesseract OCR CAPTCHA solving
import pytesseract
from PIL import Image
import requests

def break_text_captcha(image_url):
    img_data = requests.get(image_url).content
    with open('captcha.png', 'wb') as f:
        f.write(img_data)

    # OCR processing
    image = Image.open('captcha.png')
    text = pytesseract.image_to_string(image)
    return text.strip()
```

### CAPTCHA Service Abuse
```python
# Using 2Captcha API
def solve_with_service(image_path):
    # Upload image to solving service
    files = {'file': open(image_path, 'rb')}
    response = requests.post('http://api.2captcha.com/createTask',
                           data={'key': API_KEY}, files=files)

    task_id = response.json()['taskId']

    # Poll for result
    while True:
        result = requests.get(f'http://api.2captcha.com/res?key={API_KEY}&action=get&id={task_id}')
        if result.json().get('status') == 'ready':
            return result.json()['request']
        time.sleep(5)
```

### Logic Flaws

#### No Server Validation
```html
<!-- CAPTCHA hanya client-side -->
<script>
function validateCaptcha() {
    if (document.getElementById('captcha').value !== '') {
        document.getElementById('form').submit();
    }
}
</script>
<!-- Bypass: Direct POST request tanpa check -->
```

#### CAPTCHA Reuse
```php
// CAPTCHA valid for entire session
if ($_POST['captcha'] === $_SESSION['captcha']) {
    // Process - valid forever in session!
}
```

#### Empty Input Allowed
```php
if (isset($_POST['captcha']) && $_POST['captcha'] !== '') {
    // Only checks presence, not accuracy
    register_user();
}
```

## 🛠️ Testing Methods

### Automated Breaking
```bash
# Using captcha2upload
curl -F "file=@captcha.jpg" http://solver.captcha2upload.com/

# Burp Intruder for CAPTCHA reuse testing
# Payload position on CAPTCHA field
# Test empty, random, and fixed values
```

### Manual Verification
1. **Input Empty Values:** Submit form tanpa solve
2. **Reuse Responses:** Use same CAPTCHA multiple times
3. **Random Strings:** Input arbitrary text
4. **Timing:** Submit immediately setelah load

## 🛡️ Prevention

### Modern CAPTCHA Solutions

#### Google reCAPTCHA v3
```html
<script src="https://www.google.com/recaptcha/api.js?render=site_key"></script>

<script>
    grecaptcha.ready(function() {
        grecaptcha.execute('site_key', {action: 'submit'}).then(function(token) {
            document.getElementById('g_token').value = token;
            document.getElementById('form').submit();
        });
    });
</script>

<input type="hidden" id="g_token" name="g_token">
```

#### Server Validation
```php
function verify_recaptcha($token) {
    $secret = 'your_secret_key';
    $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secret&response=$token&remoteip=" . $_SERVER['REMOTE_ADDR']);
    $result = json_decode($response);

    if (!$result->success) {
        die('CAPTCHA verification failed');
    }

    return $result->score; // v3 confidence score
}
```

### Additional Protections

#### Rate Limiting
```php
// CAPTCHA setelah beberapa failed attempts
$ip = $_SERVER['REMOTE_ADDR'];
$attempts = get_failed_attempts($ip);

if ($attempts > 5) {
    require_captcha_verification();
}
```

#### Behavioral Analysis
```javascript
// Track user interactions
var mouseMovements = [];
var keyPresses = [];
var copyOperations = 0;

document.addEventListener('mousemove', (e) => {
    mouseMovements.push([e.clientX, e.clientY]);
});

document.addEventListener('copy', () => {
    copyOperations++;
    // Human would copy answer, bot direct submit
});

// Send analysis to server
```

#### Progressive Challenge
```php
$suspicion_level = calculate_suspicion($_SERVER['REMOTE_ADDR']);

if ($suspicion_level < 3) {
    // No CAPTCHA
} elseif ($suspicion_level < 7) {
    // Easy CAPTCHA
} else {
    // Maximum security CAPTCHA
}
```

## 🔍 Real Cases

### 2018: Ticketmaster Bots
- CAPTCHA bypassed selama flash sales
- Legitimate users excluded
- $Millions lost revenue

### 2019: Government Portals
- Voter registration CAPTCHA broken
- Potential election fraud
- Multi-national impact

## 📚 Resources

- **reCAPTCHA Docs:** https://developers.google.com/recaptcha
- **2Captcha API:** Commercial CAPTCHA breaking service
- **OWASP Testing:** CAPTCHA bypass methodologies

---

**CAPTCHA often first line defense against automation.** If insecure, it becomes useless. Modern implementations with behavioral analysis essential. Master bypass techniques untuk realistic testing. 🤖🧠
