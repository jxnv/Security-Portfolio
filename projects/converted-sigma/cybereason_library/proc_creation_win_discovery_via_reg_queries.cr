// Title: System Information Discovery via Registry Queries
// ID: 0022869c-49f7-4ff2-ba03-85ac42ddac58
// Status: experimental
// Level: low
// Author: lazarg
// Date: 2025-06-12
// Tags: attack.discovery, attack.t1082
// Description: Detects attempts to query system information directly from the Windows Registry.
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine contains "Get-ItemPropertyValue" OR CommandLine contains "gpv")) OR (Image="*\\reg.exe" AND CommandLine contains "query" AND (CommandLine contains "-v" OR CommandLine contains "/v"))) AND ((CommandLine contains "\\SOFTWARE\\Microsoft\\Windows Defender" OR CommandLine contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" OR CommandLine contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" OR CommandLine contains "\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" OR CommandLine contains "\\SYSTEM\\CurrentControlSet\\Services")))
