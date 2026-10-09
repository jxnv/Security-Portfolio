// Title: Suspicious Mstsc.EXE Execution With Local RDP File
// ID: 6e22722b-dfb1-4508-a911-49ac840b40f8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-18
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine="*.rdp" OR CommandLine="*.rdp\"")) AND ((Image="*\\mstsc.exe") OR (OriginalFileName == "mstsc.exe")) AND ((CommandLine contains ":\\Users\\Public\\" OR CommandLine contains ":\\Windows\\System32\\spool\\drivers\\color" OR CommandLine contains ":\\Windows\\System32\\Tasks_Migrated " OR CommandLine contains ":\\Windows\\Tasks\\" OR CommandLine contains ":\\Windows\\Temp\\" OR CommandLine contains ":\\Windows\\Tracing\\" OR CommandLine contains "\\AppData\\Local\\Temp\\" OR CommandLine contains "\\Downloads\\")))
