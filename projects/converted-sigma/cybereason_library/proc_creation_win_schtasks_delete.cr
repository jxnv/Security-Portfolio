// Title: Delete Important Scheduled Task
// ID: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.impact, attack.t1489
// Description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "/delete" OR CommandLine contains "-delete")) AND ((CommandLine contains "\\Windows\\BitLocker" OR CommandLine contains "\\Windows\\ExploitGuard" OR CommandLine contains "\\Windows\\SystemRestore\\SR" OR CommandLine contains "\\Windows\\UpdateOrchestrator\\" OR CommandLine contains "\\Windows\\Windows Defender\\" OR CommandLine contains "\\Windows\\WindowsBackup\\" OR CommandLine contains "\\Windows\\WindowsUpdate\\")) AND ((Image="*\\schtasks.exe") OR (OriginalFileName == "schtasks.exe")))
