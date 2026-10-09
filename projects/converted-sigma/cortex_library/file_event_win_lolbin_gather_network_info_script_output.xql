// Title: GatherNetworkInfo.VBS Reconnaissance Script Output
// ID: f92a6f1e-a512-4a15-9735-da09e78d7273
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-08
// Tags: attack.discovery
// Description: Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path startswith "C:\\Windows\\System32\\config" and (action_file_path endswith "\\Hotfixinfo.txt" or action_file_path endswith "\\netiostate.txt" or action_file_path endswith "\\sysportslog.txt" or action_file_path endswith "\\VmSwitchLog.evtx"))
