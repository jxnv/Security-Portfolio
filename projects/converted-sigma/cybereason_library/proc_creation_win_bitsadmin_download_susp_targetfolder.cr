// Title: File Download Via Bitsadmin To A Suspicious Target Folder
// ID: 2ddef153-167b-4e89-86b6-757a9e65dcac
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-28
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003, attack.command-and-control, attack.t1105
// Description: Detects usage of bitsadmin downloading a file to a suspicious target folder
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " /transfer " OR CommandLine contains " /create " OR CommandLine contains " /addfile ")) AND ((CommandLine contains ":\\Perflogs" OR CommandLine contains ":\\ProgramData\\" OR CommandLine contains ":\\Temp\\" OR CommandLine contains ":\\Users\\Public\\" OR CommandLine contains ":\\Windows\\" OR CommandLine contains "\\$Recycle.Bin\\" OR CommandLine contains "\\AppData\\Local\\" OR CommandLine contains "\\AppData\\Roaming\\" OR CommandLine contains "\\Contacts\\" OR CommandLine contains "\\Desktop\\" OR CommandLine contains "\\Favorites\\" OR CommandLine contains "\\Favourites\\" OR CommandLine contains "\\inetpub\\wwwroot\\" OR CommandLine contains "\\Music\\" OR CommandLine contains "\\Pictures\\" OR CommandLine contains "\\Start Menu\\Programs\\Startup\\" OR CommandLine contains "\\Users\\Default\\" OR CommandLine contains "\\Videos\\" OR CommandLine contains "%ProgramData%" OR CommandLine contains "%public%" OR CommandLine contains "%temp%" OR CommandLine contains "%tmp%")) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName == "bitsadmin.exe")))
