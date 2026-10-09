// Title: Potential Persistence Via Disk Cleanup Handler - Registry
// ID: d4f4e0be-cf12-439f-9e25-4e2cdcf7df5a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-21
// Tags: attack.persistence
// Description: Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence.
// The disk cleanup manager is part of the operating system. It displays the dialog box […]
// The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
// Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
// Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
// Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventType = "CreateKey" and TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\") and not (((TargetObject endswith "\\Active Setup Temp Folders" or TargetObject endswith "\\BranchCache" or TargetObject endswith "\\Content Indexer Cleaner" or TargetObject endswith "\\D3D Shader Cache" or TargetObject endswith "\\Delivery Optimization Files" or TargetObject endswith "\\Device Driver Packages" or TargetObject endswith "\\Diagnostic Data Viewer database files" or TargetObject endswith "\\Downloaded Program Files" or TargetObject endswith "\\DownloadsFolder" or TargetObject endswith "\\Feedback Hub Archive log files" or TargetObject endswith "\\Internet Cache Files" or TargetObject endswith "\\Language Pack" or TargetObject endswith "\\Microsoft Office Temp Files" or TargetObject endswith "\\Offline Pages Files" or TargetObject endswith "\\Old ChkDsk Files" or TargetObject endswith "\\Previous Installations" or TargetObject endswith "\\Recycle Bin" or TargetObject endswith "\\RetailDemo Offline Content" or TargetObject endswith "\\Setup Log Files" or TargetObject endswith "\\System error memory dump files" or TargetObject endswith "\\System error minidump files" or TargetObject endswith "\\Temporary Files" or TargetObject endswith "\\Temporary Setup Files" or TargetObject endswith "\\Temporary Sync Files" or TargetObject endswith "\\Thumbnail Cache" or TargetObject endswith "\\Update Cleanup" or TargetObject endswith "\\Upgrade Discarded Files" or TargetObject endswith "\\User file versions" or TargetObject endswith "\\Windows Defender" or TargetObject endswith "\\Windows Error Reporting Files" or TargetObject endswith "\\Windows ESD installation files" or TargetObject endswith "\\Windows Upgrade Log Files"))))
