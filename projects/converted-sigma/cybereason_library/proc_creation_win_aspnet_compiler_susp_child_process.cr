// Title: Suspicious Child Process of AspNetCompiler
// ID: 9ccba514-7cb6-4c5c-b377-700758f2f120
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-14
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects potentially suspicious child processes of "aspnet_compiler.exe".
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\calc.exe" OR Image="*\\notepad.exe")) OR ((Image contains "\\Users\\Public\\" OR Image contains "\\AppData\\Local\\Temp\\" OR Image contains "\\AppData\\Local\\Roaming\\" OR Image contains ":\\Temp\\" OR Image contains ":\\Windows\\Temp\\" OR Image contains ":\\Windows\\System32\\Tasks\\" OR Image contains ":\\Windows\\Tasks\\"))) AND (ParentImage="*\\aspnet_compiler.exe"))
