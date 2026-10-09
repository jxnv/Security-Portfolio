// Title: IIS WebServer Log Deletion via CommandLine Utilities
// ID: 0649be4a-aeb0-45b0-b89e-7f1668f6d9c0
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-09-02
// Tags: attack.stealth, attack.t1070
// Description: Detects attempts to delete Internet Information Services (IIS) log files via command line utilities, which is a common defense evasion technique used by attackers to cover their tracks.
// Threat actors often abuse vulnerabilities in web applications hosted on IIS servers to gain initial access and later delete IIS logs to evade detection.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "del " OR CommandLine contains "erase " OR CommandLine contains "rm " OR CommandLine contains "remove-item " OR CommandLine contains "rmdir ")) AND (CommandLine contains "\\inetpub\\logs\\") AND (((Image="*\\cmd.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "cmd.exe" OR OriginalFileName == "powershell.exe" OR OriginalFileName == "powershell_ise.exe" OR OriginalFileName == "pwsh.dll"))))
