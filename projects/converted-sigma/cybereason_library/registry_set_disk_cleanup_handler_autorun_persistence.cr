// Title: Persistence Via Disk Cleanup Handler - Autorun
// ID: d4e2745c-f0c6-4bde-a3ab-b553b3f693cc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-21
// Tags: attack.persistence
// Description: Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun.
// The disk cleanup manager is part of the operating system.
// It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
// Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
// Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
// Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\") AND ((TargetObject contains "\\Autorun" AND Details == "DWORD (0x00000001)") OR ((TargetObject contains "\\CleanupString" OR TargetObject contains "\\PreCleanupString") AND (Details contains "cmd" OR Details contains "powershell" OR Details contains "rundll32" OR Details contains "mshta" OR Details contains "cscript" OR Details contains "wscript" OR Details contains "wsl" OR Details contains "\\Users\\Public\\" OR Details contains "\\Windows\\TEMP\\" OR Details contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"))))
