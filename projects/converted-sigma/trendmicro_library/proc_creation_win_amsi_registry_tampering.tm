// Title: Windows AMSI Related Registry Tampering Via CommandLine
// ID: 7dbbcac2-57a0-45ac-b306-ff30a8bd2981
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-12-25
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects tampering of AMSI (Anti-Malware Scan Interface) related registry values via command line tools such as reg.exe or PowerShell.
// AMSI provides a generic interface for applications and services to integrate with antimalware products.
// Adversaries may disable AMSI to evade detection of malicious scripts and code execution.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*\\Software\\Microsoft\\Windows Script\\Settings*" AND CommandLine: "*AmsiEnable*")) AND ((((CommandLine: "*Set-ItemProperty*" OR CommandLine: "*New-ItemProperty*" OR CommandLine: "*sp *")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName: "PowerShell.EXE" OR OriginalFileName: "pwsh.dll")))) OR ((CommandLine: "*add*") AND ((Image="*\\reg.exe") OR (OriginalFileName: "reg.exe")))))
