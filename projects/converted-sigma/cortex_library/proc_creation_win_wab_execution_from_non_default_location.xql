// Title: Wab Execution From Non Default Location
// ID: 395907ee-96e5-4666-af2e-2ca91688e151
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-12
// Tags: attack.execution, attack.stealth
// Description: Detects execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\wab.exe" or action_process_image_path endswith "\\wabmig.exe")) and not (((action_process_image_path startswith "C:\\Windows\\WinSxS\\" or action_process_image_path startswith "C:\\Program Files\\Windows Mail\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Windows Mail\\"))))
