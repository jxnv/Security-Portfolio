// Title: ADSI-Cache File Creation By Uncommon Tool
// ID: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
// Status: test
// Level: medium
// Author: xknow @xknow_infosec, Tim Shelton
// Date: 2019-03-24
// Tags: attack.t1001.003, attack.command-and-control
// Description: Detects the creation of an "Active Directory Schema Cache File" (.sch) file by an uncommon tool.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\Local\\Microsoft\\Windows\\SchCache\\" and action_file_path endswith ".sch") and not (((((action_process_image_path endswith ":\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe" or action_process_image_path endswith ":\\Windows\\CCM\\CcmExec.exe" or action_process_image_path endswith ":\\windows\\system32\\dllhost.exe" or action_process_image_path endswith ":\\Windows\\system32\\dsac.exe" or action_process_image_path endswith ":\\Windows\\system32\\efsui.exe" or action_process_image_path endswith ":\\windows\\system32\\mmc.exe" or action_process_image_path endswith ":\\windows\\system32\\svchost.exe" or action_process_image_path endswith ":\\Windows\\System32\\wbem\\WmiPrvSE.exe" or action_process_image_path endswith ":\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe")) or ((action_process_image_path contains ":\\Windows\\ccmsetup\\autoupgrade\\ccmsetup" or action_process_image_path contains ":\\Program Files\\SentinelOne\\Sentinel Agent"))) or ((action_process_image_path contains ":\\Program Files\\" and action_process_image_path contains "\\Microsoft Office") and action_process_image_path endswith "\\OUTLOOK.EXE"))) and not (((action_process_image_path endswith ":\\Program Files\\Citrix\\Receiver StoreFront\\Services\\DefaultDomainServices\\Citrix.DeliveryServices.DomainServices.ServiceHost.exe") or (action_process_image_path endswith "\\LANDesk\\LDCLient\\ldapwhoami.exe"))))
