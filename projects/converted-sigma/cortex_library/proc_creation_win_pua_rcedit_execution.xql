// Title: PUA - Potential PE Metadata Tamper Using Rcedit
// ID: 0c92f2e6-f08f-4b73-9216-ecb0ca634689
// Status: test
// Level: medium
// Author: Micah Babinski
// Date: 2022-12-11
// Tags: attack.stealth, attack.t1036.003, attack.t1036, attack.t1027.005, attack.t1027
// Description: Detects the use of rcedit to potentially alter executable PE metadata properties, which could conceal efforts to rename system utilities for defense evasion.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "OriginalFileName" or action_process_image_command_line contains "CompanyName" or action_process_image_command_line contains "FileDescription" or action_process_image_command_line contains "ProductName" or action_process_image_command_line contains "ProductVersion" or action_process_image_command_line contains "LegalCopyright")) and (action_process_image_command_line contains "--set-") and (((action_process_image_path endswith "\\rcedit-x64.exe" or action_process_image_path endswith "\\rcedit-x86.exe")) or (Description = "Edit resources of exe") or (Product = "rcedit")))
