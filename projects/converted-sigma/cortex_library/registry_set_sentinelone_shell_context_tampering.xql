// Title: Potential SentinelOne Shell Context Menu Scan Command Tampering
// ID: 6c304b02-06e6-402d-8be4-d5833cdf8198
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-03-06
// Tags: attack.persistence
// Description: Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\shell\\SentinelOneScan\\command\\") and not ((((action_process_image_path endswith "C:\\Program Files\\SentinelOne\\" or action_process_image_path endswith "C:\\Program Files (x86)\\SentinelOne\\")) or ((Details startswith "C:\\Program Files\\SentinelOne\\Sentinel Agent" or Details startswith "C:\\Program Files (x86)\\SentinelOne\\Sentinel Agent") and Details contains "\\SentinelScanFromContextMenu.exe"))))
