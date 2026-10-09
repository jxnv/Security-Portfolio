// Title: Uncommon File Created In Office Startup Folder
// ID: a10a2c40-2c4d-49f8-b557-1a946bc55d9d
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-05
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects the creation of a file with an uncommon extension in an Office application startup folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_file_path contains "\\Microsoft\\Word\\STARTUP") or ((action_file_path contains "\\Office" and action_file_path contains "\\Program Files" and action_file_path contains "\\STARTUP"))) and not (((action_file_path endswith ".docb" or action_file_path endswith ".docm" or action_file_path endswith ".docx" or action_file_path endswith ".dotm" or action_file_path endswith ".mdb" or action_file_path endswith ".mdw" or action_file_path endswith ".pdf" or action_file_path endswith ".wll" or action_file_path endswith ".wwl")))) or (((action_file_path contains "\\Microsoft\\Excel\\XLSTART") or ((action_file_path contains "\\Office" and action_file_path contains "\\Program Files" and action_file_path contains "\\XLSTART"))) and not (((action_file_path endswith ".xll" or action_file_path endswith ".xls" or action_file_path endswith ".xlsm" or action_file_path endswith ".xlsx" or action_file_path endswith ".xlt" or action_file_path endswith ".xltm" or action_file_path endswith ".xlw"))))) and not ((((action_process_image_path contains ":\\Program Files\\Microsoft Office\\" or action_process_image_path contains ":\\Program Files (x86)\\Microsoft Office\\") and (action_process_image_path endswith "\\winword.exe" or action_process_image_path endswith "\\excel.exe")) or (action_process_image_path contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" and action_process_image_path endswith "\\OfficeClickToRun.exe"))))
