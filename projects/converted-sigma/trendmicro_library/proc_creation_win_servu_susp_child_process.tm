// Title: Suspicious Serv-U Process Pattern
// ID: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-14
// Tags: attack.credential-access, attack.t1555, cve.2021-35211
// Description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*\\Serv-U.exe" AND (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\schtasks.exe" OR Image="*\\regsvr32.exe" OR Image="*\\wmic.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\msiexec.exe" OR Image="*\\forfiles.exe" OR Image="*\\scriptrunner.exe"))
