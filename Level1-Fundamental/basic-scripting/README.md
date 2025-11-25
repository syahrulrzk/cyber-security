# 🐍 Basic Scripting - Automation Power

## 🔍 Scripting Dalam Cyber Security

Scripting adalah jembatan antara manual tasks dan automated workflows. Dalam cyber security, scripting membantu:
- Automate reconnaissance
- Parse log files
- Generate payloads
- Custom tools development

**Two main players:** Bash (system level) vs Python (flexibility, libraries)

## 🐤 Bash Scripting Fundamentals

### File Structure & Shebang
```bash
#!/bin/bash
# Comments start with #

echo "Hello World"
```

**Make it executable:**
```bash
chmod +x script.sh
./script.sh
```

### Variables & Parameter Expansion
```bash
# Basic variables
NAME="World"
NUMBER=42

echo "Hello $NAME, the answer is $NUMBER"

# Special variables
echo "Script path: $0"
echo "First arg: $1"
echo "All args: $@"
echo "Args count: $#"
echo "PID: $$"
```

### Parameter Expansion Advanced
```bash
# Parameter expansion syntax
${var:-default}        # Use default jika unset/empty
${var:=default}        # Assign default jika unset/empty
${var:?message}        # Error message jika unset/empty

# String manipulation
${var:position}        # Starting position
${var:position:length} # Position with length

# Pattern removal
${var#pattern}         # Remove shortest prefix match
${var##pattern}        # Remove longest prefix match
${var%suffix}          # Remove shortest suffix match
${var%%suffix}         # Remove longest suffix match

# Examples
filename="somefile.txt.backup"
echo ${filename%%.*}          # somefile (remove all extension)
echo ${filename#*.}           # txt.backup (remove shortest prefix)
echo ${filename##*.}          # backup (remove longest prefix)
```

### Control Structures

#### Conditionals
```bash
# Basic if
if [ "$1" = "start" ]; then
    echo "Starting..."
elif [ "$1" = "stop" ]; then
    echo "Stopping..."
else
    echo "Usage: $0 {start|stop}"
fi

# File operators
if [ -f file.txt ]; then
    echo "File exists"
fi

# String tests
if [ -z "$var" ]; then
    echo "String is empty"
fi

# Numeric comparison
if [ "$num" -gt 5 ]; then
    echo "Greater than 5"
fi

# Logical operators
if [ condition1 ] && [ condition2 ] || [ condition3 ]; then
    echo "Complex logic"
fi
```

#### Loops
```bash
# For loops
for i in {1..5}; do
    echo "Number: $i"
done

# With command output
for file in $(ls *.txt); do
    echo "Processing $file"
done

# C-style
for ((i=1; i<=5; i++)); do
    echo "C-style: $i"
done

# While loops
counter=1
while [ $counter -le 5 ]; do
    echo "Counter: $counter"
    ((counter++))
done

# Until loops
counter=1
until [ $counter -gt 5 ]; do
    echo "Until: $counter"
    ((counter++))
done
```

### Functions
```bash
# Function definition
greet() {
    local name=$1
    echo "Hello $name!"
}

# Usage
greet "World"

# With return value
is_even() {
    if [ $(($1 % 2)) -eq 0 ]; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

# Checking return
if is_even 13; then
    echo "13 is even"
fi
```

### Array Operations
```bash
# Declare arrays
array=(one two three four)
files=(*.txt)

# Access elements
echo ${array[0]}      # First element
echo ${array[@]}      # All elements
echo ${array[*]}      # All elements (alternate)

# Operations
echo ${#array[@]}     # Length
array[3]="modified"   # Change element
array+=(five six)     # Append
unset array[2]        # Remove
```

### Trap & Signal Handling
```bash
# Trap signals
trap "echo 'Interrupted!'; cleanup; exit" SIGINT SIGTERM

# Function for cleanup
cleanup() {
    echo "Cleaning up..."
    # Remove temp files, etc
}

# Main script
echo "Press Ctrl+C to test trap"
sleep 100
```

### Pipes & Command Substitution
```bash
# Pipes
cat /etc/passwd | grep root | wc -l

# Command substitution
date_today=$(date +%Y-%m-%d)
echo "Today is $date_today"

# Alternative syntax
echo "Users: $(cut -d: -f1 /etc/passwd | wc -l)"
```

## 🐍 Python Scripting Mastery

### Why Python for Pentesting?
- Rich libraries ecosystem
- Cross-platform
- Socket programming native
- Easy to read/write

### Basic Syntax & Data Types
```python
# Variables & types
name = "Python"
number = 42
is_true = True
none_value = None

# Lists (arrays)
fruits = ["apple", "banana", "cherry"]
fruits.append("date")
fruits[0] = "grape"
print(fruits[1:3])  # Slice: ['banana', 'cherry']

# Dictionaries (hash maps)
person = {"name": "Alice", "age": 30}
person["job"] = "hacker"
print(person.get("name", "Unknown"))

# Tuples (immutable)
point = (10, 20)
x, y = point  # Unpacking
```

### Control Structures
```python
# Conditionals
age = 25
if age < 18:
    print("Minor")
elif age < 65:
    print("Adult")
else:
    print("Senior")

# Ternary operator
status = "adult" if age >= 18 else "minor"

# Loops
for item in fruits:
    print(f"Fruit: {item}")

# With range
for i in range(1, 6):
    print(f"Number: {i}")

# While loops
counter = 1
while counter <= 5:
    print(f"Count: {counter}")
    counter += 1

# List comprechensions (powerful!)
squares = [x**2 for x in range(10)]  # [0, 1, 4, 9, 16...]
evens = [x for x in range(10) if x % 2 == 0]  # [0, 2, 4, 6, 8]

# Dictionary comprehension
squares_dict = {x: x**2 for x in range(6)}  # {0: 0, 1: 1, 2: 4, ...}
```

### File Operations
```python
# Reading files
with open('file.txt', 'r') as f:
    content = f.read()              # All at once
    lines = f.readlines()           # List of lines

# Line by line (efficient)
with open('file.txt', 'r') as f:
    for line in f:
        print(line.strip())

# Writing
with open('output.txt', 'w') as f:
    f.write("Hello World\n")
    f.writelines(["Line 2\n", "Line 3\n"])

# Append
with open('log.txt', 'a') as f:
    f.write(f"[{datetime.now()}] Log entry\n")

# Binary files
with open('binary.bin', 'rb') as f:
    data = f.read(1024)  # Read 1024 bytes
```

### Exception Handling
```python
try:
    result = 10 / 0
    print("This won't print")
except ZeroDivisionError:
    print("Can't divide by zero")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    print("This runs always")
    # Cleanup code

# Custom exceptions
class CustomError(Exception):
    pass

try:
    if something_wrong:
        raise CustomError("Something wrong happened")
except CustomError as e:
    print(f"Custom error: {e}")
```

### Functions & Modules

#### Functions
```python
# Basic function
def greet(name):
    return f"Hello, {name}!"

# With optional parameters
def power(base, exponent=2):
    return base ** exponent

# Variable arguments
def add_all(*numbers):
    return sum(numbers)

# Keyword arguments
def config(**settings):
    return settings

# Usage
print(greet("Alice"))
print(power(4))         # 4^2 = 16
print(power(4, 3))      # 4^3 = 64
print(add_all(1,2,3,4)) # 10
config = config(debug=True, port=8080)
```

#### Modules & Imports
```python
# Import standard library
import os
import datetime
import sys

# Specific imports
from collections import Counter
from pathlib import Path

# Third-party (install via pip)
import requests  # pip install requests

# Custom modules
# Assume file mymodule.py exists
from mymodule import myfunction

# Relative imports
from .utils import helper_function
```

### Socket Programming Basics
```python
import socket

# TCP Client
def tcp_client(host, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        sock.send(message.encode())
        response = sock.recv(1024).decode()
        return response
    finally:
        sock.close()

# TCP Server
def tcp_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print(f"Listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"Connection from {addr}")

        data = client.recv(1024)
        print(f"Received: {data.decode()}")
        client.close()
```

### Web Requests (Pentesting Essential)
```python
import requests

# Basic GET
response = requests.get('https://httpbin.org/ip')
print(response.json())

# POST with data
data = {'key': 'value'}
resp = requests.post('https://httpbin.org/post', json=data)
print(resp.json())

# With headers
headers = {'User-Agent': 'Pentest-Script/1.0'}
resp = requests.get('https://api.github.com/user',
                   headers=headers,
                   auth=('user', 'pass'))

# Handle SSL verification
response = requests.get('https://example.com', verify=False)
```

## 🔧 Scripting for Pentesting Automation

### Simple Port Scanner
```python
#!/usr/bin/env python3

import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    """Simple port scan function."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def port_scanner(host, start_port=1, end_port=1024):
    """Multi-threaded port scanner."""
    open_ports = []

    print(f"Scanning {host} for open ports...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, host, port)
                  for port in range(start_port, end_port + 1)]

        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"Port {result} is open")

    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python port_scanner.py <host>")
        sys.exit(1)

    host = sys.argv[1]
    open_ports = port_scanner(host)
    print(f"\nOpen ports: {open_ports}")
```

### Log File Analyzer
```bash
#!/bin/bash

# Analyze auth log for failed logins
LOG_FILE="/var/log/auth.log"
OUTPUT_FILE="auth_analysis.txt"

echo "Analyzing failed login attempts..." > "$OUTPUT_FILE"

# Count by IP
echo -e "\n=== Failed logins by IP ===" >> "$OUTPUT_FILE"
grep "Failed password" "$LOG_FILE" |
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' |
    sort | uniq -c | sort -nr | head -10 >> "$OUTPUT_FILE"

# Count by username
echo -e "\n=== Failed logins by username ===" >> "$OUTPUT_FILE"
grep "Failed password" "$LOG_FILE" |
    cut -d' ' -f9 |
    sort | uniq -c | sort -nr | head -5 >> "$OUTPUT_FILE"

# Recent attacks
echo -e "\n=== Recent failed attempts (last 24h) ===" >> "$OUTPUT_FILE"
date_24h=$(date -d '24 hours ago' +%Y-%m-%d)
grep "$date_24h" "$LOG_FILE" |
    grep "Failed password" | wc -l >> "$OUTPUT_FILE"

echo "Analysis complete. Check $OUTPUT_FILE"
```

### Web Crawler
```python
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from collections import deque

class WebCrawler:
    def __init__(self, base_url, max_pages=50):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.queue = deque([base_url])
        self.max_pages = max_pages

    def is_valid_url(self, url):
        """Check if URL belongs to same domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.domain if parsed.netloc else True

    def extract_links(self, html, current_url):
        """Extract all links from HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        links = []

        for tag in soup.find_all('a', href=True):
            href = urljoin(current_url, tag['href'])
            if href not in self.visited and self.is_valid_url(href):
                links.append(href)

        return links

    def crawl(self):
        """Main crawling function."""
        page_count = 0

        while self.queue and page_count < self.max_pages:
            current_url = self.queue.popleft()

            if current_url in self.visited:
                continue

            try:
                print(f"Crawling: {current_url}")
                response = requests.get(current_url, timeout=5)
                response.raise_for_status()

                self.visited.add(current_url)
                new_links = self.extract_links(response.text, current_url)

                for link in new_links:
                    if link not in self.visited:
                        self.queue.append(link)

                page_count += 1

            except requests.RequestException as e:
                print(f"Error crawling {current_url}: {e}")
                continue

        return self.visited

if __name__ == "__main__":
    crawler = WebCrawler("https://example.com", max_pages=20)
    crawled_urls = crawler.crawl()

    print("\
Crawled URLs:")
    for url in crawled_urls:
        print(url)
```

## 💡 Pro Tips Scripting

1. **Error Checking:** Always check if commands succeed
2. **Input Sanitization:** Never trust user input blindly
3. **Logging:** Add logging to scripts for debugging
4. **Modular Code:** Break functions into reusable parts
5. **Documentation:** Comment complex logic
6. **Performance:** Use appropriate data structures
7. **Security:** Be careful with eval/exec in Python
8. **Testing:** Test scripts on safe environments first

## 📚 Learning Resources

### Books
- "Automate the Boring Stuff with Python" - Al Sweigart
- "The Linux Command Line" - William Shotts
- "Bash Cookbook" - Carl Albing

### Online Courses
- freeCodeCamp Python/Bash courses
- Automate boring stuff courses
- Real Python tutorials

### Practice
- Project Euler
- Automate user tasks
- Weekly scripting challenges

---

**Goal:** Implementasi scripting mindset: "If I do it more than twice manually, automate it!" Scripts yang robust, dokumentasi baik, security-aware. 💪✨

Remember: Scripting adalah bahasa untuk berbicara ke computer. Master scripting = unlimited power. 🚀
