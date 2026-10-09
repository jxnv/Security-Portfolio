// Title: Access To Windows DPAPI Master Keys By Uncommon Applications
// ID: 46612ae6-86be-4802-bc07-39b59feb1309
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-17
// Tags: attack.credential-access, attack.t1555.004
// Description: Detects file access requests to the the Windows Data Protection API Master keys by an uncommon application.
// This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::masterkey" function
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((FileName contains "\\Microsoft\\Protect\\S-1-5-18\\" or FileName contains "\\Microsoft\\Protect\\S-1-5-21-")) and not (((action_process_image_path = "C:\\Windows\\explorer.exe") or ((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Windows\\system32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")))))
