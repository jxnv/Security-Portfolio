// Title: Suspicious Provlaunch.EXE Child Process
// ID: f9999590-1f94-4a34-a91e-951e47bedefd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-08
// Tags: attack.stealth, attack.t1218
// Description: Detects suspicious child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\calc.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\notepad.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((Image: "*:\\PerfLogs\\*" OR Image: "*:\\Temp\\*" OR Image: "*:\\Users\\Public\\*" OR Image: "*\\AppData\\Temp\\*" OR Image: "*\\Windows\\System32\\Tasks\\*" OR Image: "*\\Windows\\Tasks\\*" OR Image: "*\\Windows\\Temp\\*"))) AND (ParentImage="*\\provlaunch.exe"))
