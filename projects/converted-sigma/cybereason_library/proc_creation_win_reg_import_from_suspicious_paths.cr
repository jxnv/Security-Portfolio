// Title: Potential Suspicious Registry File Imported Via Reg.EXE
// ID: 62e0298b-e994-4189-bc87-bc699aa62d97
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-08-01
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains " import ") AND ((Image="*\\reg.exe") OR (OriginalFileName == "reg.exe")) AND ((CommandLine contains "C:\\Users\\" OR CommandLine contains "%temp%" OR CommandLine contains "%tmp%" OR CommandLine contains "%appdata%" OR CommandLine contains "\\AppData\\Local\\Temp\\" OR CommandLine contains "C:\\Windows\\Temp\\" OR CommandLine contains "C:\\ProgramData\\")))
