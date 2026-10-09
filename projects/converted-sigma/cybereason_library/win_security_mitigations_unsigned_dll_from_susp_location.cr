// Title: Unsigned Binary Loaded From Suspicious Location
// ID: 8289bf8c-4aca-4f5a-9db3-dc3d7afe5c10
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-03
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects Code Integrity (CI) engine blocking processes from loading unsigned DLLs residing in suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "11" OR EventID == "12") AND (ImageName contains "\\Users\\Public\\" OR ImageName contains "\\PerfLogs\\" OR ImageName contains "\\Desktop\\" OR ImageName contains "\\Downloads\\" OR ImageName contains "\\AppData\\Local\\Temp\\" OR ImageName contains "C:\\Windows\\TEMP\\"))
