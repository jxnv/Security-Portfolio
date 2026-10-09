// Title: New User Account Creation Attempt Via ADSI in CommandLine
// ID: 7c9fed65-039a-4055-8c23-fa763d94aff6
// Status: experimental
// Level: medium
// Author: William Gokah (idea), Raylee Hawkins, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-08-13
// Tags: attack.persistence, attack.t1136.001, attack.t1136.002
// Description: Detects PowerShell command line arguments containing ADSI (Active Directory Service Interfaces) patterns
// trying to create a new user account via the WinNT or LDAP provider. This is an uncommon method to create
// user accounts and may indicate an attempt to evade detection by avoiding more commonly monitored commands
// such as "net user", "New-LocalUser" or "New-ADUser".
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "[ADSI]") AND ((CommandLine contains "WinNT://" OR CommandLine contains "LDAP://")) AND ((CommandLine contains ".Create(\"user" OR CommandLine contains ".Create('user")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll"))))
