// Title: Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location
// ID: cc368ed0-2411-45dc-a222-510ace303cb2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-25
// Tags: attack.stealth, attack.t1218.009
// Description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "\\AppData\\Local\\Temp\\" OR CommandLine contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" OR CommandLine contains "\\PerfLogs\\" OR CommandLine contains "\\Users\\Public\\" OR CommandLine contains "\\Windows\\Temp\\")) AND (((Image="*\\Regsvcs.exe" OR Image="*\\Regasm.exe")) OR ((OriginalFileName == "RegSvcs.exe" OR OriginalFileName == "RegAsm.exe"))))
