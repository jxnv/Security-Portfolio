// Title: Script Interpreter Execution From Suspicious Folder
// ID: 1228c958-e64e-4e71-92ad-7d429f4138ba
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-02-08
// Tags: attack.execution, attack.t1059
// Description: Detects suspicious script execution from suspicious directories or folders accessible by environment variables that may indicate malware activity.
// Script interpreters (cscript, wscript, mshta, powershell) executing from folders like Temp, Public, or user profile directories may suggest attempts to evade detection or execute malicious scripts.
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "* -ep bypass *" OR CommandLine: "* -ExecutionPolicy bypass *" OR CommandLine: "* -w hidden *" OR CommandLine: "*/e:javascript *" OR CommandLine: "*/e:Jscript *" OR CommandLine: "*/e:vbscript *")) OR ((Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\wscript.exe")) OR ((OriginalFileName: "cscript.exe" OR OriginalFileName: "mshta.exe" OR OriginalFileName: "wscript.exe"))) AND (((CommandLine: "*:\\Perflogs\\*" OR CommandLine: "*:\\Users\\Public\\*" OR CommandLine: "*\\%Public%*" OR CommandLine: "*\\AppData\\Local\\Temp*" OR CommandLine: "*\\AppData\\Roaming\\Temp*" OR CommandLine: "*\\Temporary Internet*" OR CommandLine: "*\\Windows\\Temp*" OR CommandLine: "*\\Start Menu\\Programs\\Startup\\*" OR CommandLine: "*%TEMP%*" OR CommandLine: "*%TMP%*" OR CommandLine: "*%LocalAppData%\\Temp*")) OR (((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Favorites\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Favourites\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Contacts\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Documents\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Music\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Pictures\\*")) OR ((CommandLine: "*:\\Users\\*" AND CommandLine: "*\\Videos\\*")))) AND NOT (((ParentImage: "C:\\Windows\\System32\\Msiexec.exe" OR ParentImage: "C:\\Windows\\SysWOW64\\Msiexec.exe") AND Image="*\\powershell.exe" AND (CommandLine: "*-NoProfile -ExecutionPolicy Bypass -Command*" AND CommandLine: "*AppData\\Local\\Temp\\*" AND CommandLine: "*Install-Chocolatey.ps1*"))))
