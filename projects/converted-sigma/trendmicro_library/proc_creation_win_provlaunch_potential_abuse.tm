// Title: Potential Provlaunch.EXE Binary Proxy Execution Abuse
// ID: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
// Date: 2023-08-08
// Tags: attack.stealth, attack.t1218
// Description: Detects child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\provlaunch.exe") AND NOT ((((Image="*\\calc.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\notepad.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((Image: "*:\\PerfLogs\\*" OR Image: "*:\\Temp\\*" OR Image: "*:\\Users\\Public\\*" OR Image: "*\\AppData\\Temp\\*" OR Image: "*\\Windows\\System32\\Tasks\\*" OR Image: "*\\Windows\\Tasks\\*" OR Image: "*\\Windows\\Temp\\*")))))
