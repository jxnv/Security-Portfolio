// Title: Important Scheduled Task Deleted or Disabled
// ID: 9e3cb244-bdb8-4632-8c90-6079c8f4f16d
// Status: test
// Level: high
// Author: frack113
// Date: 2023-01-13
// Tags: attack.impact, attack.t1489
// Description: Detects when adversaries try to stop system services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 141 or EventID = 142) and (TaskName contains "\\Windows\\SystemRestore\\SR" or TaskName contains "\\Windows\\Windows Defender\\" or TaskName contains "\\Windows\\BitLocker" or TaskName contains "\\Windows\\WindowsBackup\\" or TaskName contains "\\Windows\\WindowsUpdate\\" or TaskName contains "\\Windows\\UpdateOrchestrator\\" or TaskName contains "\\Windows\\ExploitGuard")) and not (((UserName contains "AUTHORI" or UserName contains "AUTORI"))))
