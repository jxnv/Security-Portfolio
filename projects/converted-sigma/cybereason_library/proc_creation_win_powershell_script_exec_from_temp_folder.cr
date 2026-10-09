// Title: Potentially Suspicious Powershell Script Execution From Temp Folder
// ID: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton
// Date: 2021-07-14
// Tags: attack.execution, attack.t1059.001
// Description: Detects a potentially suspicious powershell script executions from temporary folder
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine contains "\\Windows\\Temp" OR CommandLine contains "\\Temporary Internet" OR CommandLine contains "\\AppData\\Local\\Temp" OR CommandLine contains "\\AppData\\Roaming\\Temp" OR CommandLine contains "%TEMP%" OR CommandLine contains "%TMP%" OR CommandLine contains "%LocalAppData%\\Temp")) AND NOT (((CommandLine contains "\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\") OR ((ParentImage == "C:\\Windows\\System32\\Msiexec.exe" OR ParentImage == "C:\\Windows\\SysWOW64\\Msiexec.exe") AND Image="*\\powershell.exe" AND (CommandLine contains "-NoProfile -ExecutionPolicy Bypass -Command" AND CommandLine contains "AppData\\Local\\Temp\\" AND CommandLine contains "Install-Chocolatey.ps1")) OR ((CommandLine contains " >" OR CommandLine contains "Out-File" OR CommandLine contains "ConvertTo-Json")) OR (CommandLine contains "-WindowStyle hidden -Verb runAs"))))
