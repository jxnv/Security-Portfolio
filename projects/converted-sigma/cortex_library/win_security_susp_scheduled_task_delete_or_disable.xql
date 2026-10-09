// Title: Important Scheduled Task Deleted/Disabled
// ID: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-05
// Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
// Description: Detects when adversaries stop services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 4699 or EventID = 4701) and (TaskName contains "\\Windows\\SystemRestore\\SR" or TaskName contains "\\Windows\\Windows Defender\\" or TaskName contains "\\Windows\\BitLocker" or TaskName contains "\\Windows\\WindowsBackup\\" or TaskName contains "\\Windows\\WindowsUpdate\\" or TaskName contains "\\Windows\\UpdateOrchestrator\\Schedule" or TaskName contains "\\Windows\\ExploitGuard")) and not ((EventID = 4699 and SubjectUserName endswith "$" and TaskName contains "\\Windows\\Windows Defender\\")))
