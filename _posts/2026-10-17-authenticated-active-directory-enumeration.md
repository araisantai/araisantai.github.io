---
title: "Authenticated Active Directory Enumeration"
date: 2026-10-17 07:00:00 +0700
categories: [cybersecurity]
tags: []
image: "/assets/img/posts/authenticated-active-directory-enumeration/cover.png"
disclaimer: "Cybersecurity notes on Arai Notes are ethical, educational, and defensive-focused. They are intended to improve safety, awareness, and responsible system administration."
render_with_liquid: false
notion_id: "3a41d4b3b917806eb395dab96fd81c02"
notion_hash: "b7d6723d40e530c2"
notion_edited: "2026-10-17 09:05:23Z"
---

This post is just a cheatsheet for situations where we have access to an Active Directory domain. It provides a checklist of enumeration steps, useful commands, and key information to gather during the assessment.

## Windows basic enumeration

we need to know the groups and if there is possibility to escalation.

```shell
whoami
whoami /all
whoami /groups
whoami /priv
```

For domain information:

```shell
echo %USERDOMAIN%
echo %LOGONSERVER%
set
systeminfo
```

For users and groups:

```shell
net user /domain
net user username /domain

net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

For domain/workstation/DC discovery:

```shell
nltest /domain_trusts
nltest /dclist:domain.local
nltest /dsgetdc:domain.local
nltest /sc_query:domain.local
```

For Kerberos and SPNs:

```shell
klist
klist sessions
setspn -L username
setspn -Q */*
```

For shares and sessions:

```shell
net view /domain
net view \\HOSTNAME
net use
```

For GPO information:

```shell
gpresult /r
gpresult /scope computer /v
gpresult /scope user /v
```

If `dsquery` happens to already be installed on the host, you can use:

```shell
dsquery user
dsquery computer
dsquery group
dsquery server
```

You can also use built-in PowerShell/.NET without importing a module. For example, query LDAP directly:

```powershell
$root = [ADSI]"LDAP://RootDSE"
$root.defaultNamingContext
```

Enumerate users:

```powershell
$root = [ADSI]"LDAP://RootDSE"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]("LDAP://" + $root.defaultNamingContext)
$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"

$searcher.FindAll() | ForEach-Object {
    $_.Properties.samaccountname
}
```

Computers:

```powershell
$searcher.Filter = "(objectCategory=computer)"

$searcher.FindAll() | ForEach-Object {
    $_.Properties.name
}
```

Groups:

```powershell
$searcher.Filter = "(objectCategory=group)"

$searcher.FindAll() | ForEach-Object {
    $_.Properties.samaccountname
}
```

SPN-enabled accounts:

```powershell
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

$searcher.FindAll() | ForEach-Object {
    $_.Properties.samaccountname
    $_.Properties.serviceprincipalname
}
```

So for a **zero-download / living-off-the-land AD enumeration workflow**, I'd primarily rely on:

```text
whoami
net
nltest
klist
setspn
gpresult
PowerShell + System.DirectoryServices / ADSI
```

The most powerful option there is usually **PowerShell with ****`System.DirectoryServices.DirectorySearcher`**, because it lets you query LDAP directly without importing any external tool or AD module.

## adsisearcher

Yes. Think of `PswReaders` as a **capability clue**, not something you “run.”

You already established:

```text
INFINITY\PswReaders
└── ted
```

So the red-team question is:

```text
What object/attribute/resource has an ACL that grants
INFINITY\PswReaders some special read permission?
```

Given the name **`PswReaders`**, the first hypothesis I would test is **LAPS / managed local-admin password read access**.

### 1. Check whether LAPS exists in the domain

From the logged-in `ted` Windows session, you can query LDAP using the existing domain authentication — you do **not** need to know Ted's password again.

Try:

```powershell
([adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))").FindAll().Count
```

If that returns computers, legacy Microsoft LAPS is probably deployed.

For newer Windows LAPS:

```powershell
([adsisearcher]"(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*))").FindAll().Count
```

### 2. Identify machines with LAPS-related attributes

Legacy LAPS:

```powershell
$s = [adsisearcher]"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))"
$s.PropertiesToLoad.Add("name") | Out-Null
$s.PropertiesToLoad.Add("dnshostname") | Out-Null

$s.FindAll() | ForEach-Object {
    $_.Properties
}
```

New LAPS:

```powershell
$s = [adsisearcher]"(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*))"
$s.PropertiesToLoad.Add("name") | Out-Null
$s.PropertiesToLoad.Add("dnshostname") | Out-Null

$s.FindAll() | ForEach-Object {
    $_.Properties
}
```

### 3. Check whether Ted can read the protected password attribute

For legacy LAPS, test whether the attribute is returned for a specific computer:

```powershell
$s = [adsisearcher]"(&(objectCategory=computer)(name=COMPUTERNAME))"
$s.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null
$r = $s.FindOne()
$r.Properties.Keys
```

If you see:

```text
ms-mcs-admpwd
```

then your authenticated `ted` context has permission to read that attribute.

That would make the group name make a lot of sense:

```text
ted
 ↓
PswReaders
 ↓
read ms-Mcs-AdmPwd
 ↓
managed local administrator credential
```

For Windows LAPS, look for:

```text
msLAPS-Password
msLAPS-EncryptedPassword
```

instead.

### 4. Don't limit the hypothesis to LAPS

If LAPS isn't present, investigate where the group's SID is referenced.

You know the group SID:

```text
S-1-5-21-3616753307-3538385277-467097740-1108
```

Potential intended uses include:

```text
PswReaders
├── LAPS password readers          ← first thing I'd check
├── password/configuration share
├── ACL on a specific AD object
├── service-account secret storage
├── GPO-controlled resource
├── registry ACL
└── application-specific credential store
```

### 5. Check SYSVOL/GPO clues

Since Ted is domain-authenticated:

```shell
dir \\infinity.com\SYSVOL
dir \\infinity.com\NETLOGON
```

Search for the group name:

```shell
findstr /S /I "PswReaders" \\infinity.com\SYSVOL\*.xml
findstr /S /I "PswReaders" \\infinity.com\SYSVOL\*.inf
findstr /S /I "PswReaders" \\infinity.com\SYSVOL\*.ini
```

And search for LAPS policy indicators:

```shell
findstr /S /I "AdmPwd LAPS" \\infinity.com\SYSVOL\*.*
```

### 6. Find the DC and enumerate there

```shell
nltest /dsgetdc:infinity.com
```

Suppose it gives:

```text
DC01.infinity.com
```

Then:

```shell
net view \\DC01
```

and:

```shell
dir \\DC01\SYSVOL
dir \\DC01\NETLOGON
```

### What I'd prioritize

Based specifically on the name **`PswReaders`**, I would investigate in this order:

```text
1. Legacy LAPS
   ms-Mcs-AdmPwd

2. Windows LAPS
   msLAPS-Password / msLAPS-EncryptedPassword

3. SYSVOL / GPO references to PswReaders

4. Domain shares and application config

5. Other AD object ACLs
```

Your earlier SMB approach wasn't very useful because you were looking locally. `PswReaders` is a **domain group**, and the interesting permission is very likely attached to an AD/domain resource rather than `C:\Users\ted`.

If the first LAPS count command returns something above `0`, that's the branch I would pursue first.

`[adsisearcher]` is usually available on standard **Windows PowerShell 5.1** because it is a built-in PowerShell type accelerator for:

```powershell
System.DirectoryServices.DirectorySearcher
```

So on a typical domain-joined Windows workstation/server, you normally don't need to import anything:

```powershell
$s = [adsisearcher]"(objectClass=user)"
$s.FindAll()
```

But it is **not safe to assume it exists everywhere**. The important cases are:

- **Windows PowerShell 5.1:** generally available by default.
- **PowerShell 7 (****`pwsh`****) on Windows:** availability can depend on the .NET/System.DirectoryServices environment; don't assume it blindly.
- **Linux/macOS PowerShell:** ADSI/DirectoryServices functionality is not something you should expect to work like it does on Windows.
- **Restricted PowerShell environments:** Constrained Language Mode, AppLocker/WDAC, or other policy controls may limit what you can do.
- Even when `[adsisearcher]` exists, it still needs network/DNS/LDAP access to a domain controller to enumerate AD.

You can check it locally without importing anything:

```powershell
[adsisearcher]
```

or:

```powershell
[adsisearcher]"(objectClass=*)"
```

For a more explicit check:

```powershell
[System.Management.Automation.PSTypeName]'System.DirectoryServices.DirectorySearcher'
```

If you see a valid `.Type`, the underlying class is available.

You can also check the PowerShell version:

```powershell
$PSVersionTable
```

For a pentest where you want **maximum compatibility without dropping tools**, I would prefer this pattern:

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
```

over relying solely on:

```powershell
[adsisearcher]
```

because it's clearer what underlying .NET class you're using.

And `[ADSI]` is closely related but serves a slightly different purpose:

```powershell
[ADSI]"LDAP://RootDSE"
```

A useful zero-import combination is therefore:

```powershell
[ADSI]
[adsisearcher]
System.DirectoryServices.DirectorySearcher
```

With those alone, you can enumerate most LDAP-backed AD information such as users, groups, computers, SPNs, delegation attributes, GPO objects, and many ACL-related properties.
