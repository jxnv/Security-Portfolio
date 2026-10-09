// Title: Shadow Copies Creation Using Operating Systems Utilities
// ID: b17ea6f7-6e90-447e-a799-e6c0a493d6ce
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003, attack.t1003.002, attack.t1003.003
// Description: Shadow Copies creation using operating systems utilities, possible credential access
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "shadow" AND CommandLine contains "create")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wmic.exe" OR Image="*\\vssadmin.exe")) OR ((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll" OR OriginalFileName == "wmic.exe" OR OriginalFileName == "VSSADMIN.EXE"))))
