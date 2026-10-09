// Title: Diskshadow Script Mode - Execution From Potential Suspicious Location
// ID: fa1a7e52-3d02-435b-81b8-00da14dd66c1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-15
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of "Diskshadow.exe" in script mode using the "/s" flag where the script is located in a potentially suspicious location.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "-s " OR CommandLine contains "/s ")) AND ((OriginalFileName == "diskshadow.exe") OR (Image="*\\diskshadow.exe")) AND ((CommandLine contains ":\\Temp\\" OR CommandLine contains ":\\Windows\\Temp\\" OR CommandLine contains "\\AppData\\Local\\" OR CommandLine contains "\\AppData\\Roaming\\" OR CommandLine contains "\\ProgramData\\" OR CommandLine contains "\\Users\\Public\\")))
