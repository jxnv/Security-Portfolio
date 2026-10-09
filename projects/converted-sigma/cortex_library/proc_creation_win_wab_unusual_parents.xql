// Title: Wab/Wabmig Unusual Parent Or Child Processes
// ID: 63d1ccc0-2a43-4f4b-9289-361b308991ff
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-12
// Tags: attack.execution, attack.stealth
// Description: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\wab.exe" or actor_process_image_path endswith "\\wabmig.exe")) or ((actor_process_image_path endswith "\\WmiPrvSE.exe" or actor_process_image_path endswith "\\svchost.exe" or actor_process_image_path endswith "\\dllhost.exe") and (action_process_image_path endswith "\\wab.exe" or action_process_image_path endswith "\\wabmig.exe")))
