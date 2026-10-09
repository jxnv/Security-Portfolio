// Title: Office Macro File Creation
// ID: 91174a41-dc8f-401b-be89-7bfc140612a0
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-23
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of a new office macro files on the systems
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith ".docm" or action_file_path endswith ".dotm" or action_file_path endswith ".xlsm" or action_file_path endswith ".xltm" or action_file_path endswith ".potm" or action_file_path endswith ".pptm")) and not (((action_process_image_path startswith "C:\\Program Files\\Microsoft Office\\" or action_process_image_path startswith "C:\\Program Files (x86)\\Microsoft Office\\") and (action_process_image_path endswith "\\WINWORD.EXE" or action_process_image_path endswith "\\EXCEL.EXE" or action_process_image_path endswith "\\POWERPNT.EXE") and action_file_path contains "\\~$")))
