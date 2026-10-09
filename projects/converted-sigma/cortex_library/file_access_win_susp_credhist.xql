// Title: Access To Windows Credential History File By Uncommon Applications
// ID: 7a2a22ea-a203-4cd3-9abf-20eb1c5c6cd2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-17
// Tags: attack.credential-access, attack.t1555.004
// Description: Detects file access requests to the Windows Credential History File by an uncommon application.
// This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::credhist" function
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((FileName endswith "\\Microsoft\\Protect\\CREDHIST") and not (((action_process_image_path = "C:\\Windows\\explorer.exe") or ((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Windows\\system32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")))))
