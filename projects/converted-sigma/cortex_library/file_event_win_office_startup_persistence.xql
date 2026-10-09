// Title: Potential Persistence Via Microsoft Office Startup Folder
// ID: 0e20c89d-2264-44ae-8238-aeeaba609ece
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-02
// Tags: attack.persistence, attack.t1137
// Description: Detects creation of Microsoft Office files inside of one of the default startup folders in order to achieve persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_file_path endswith ".doc" or action_file_path endswith ".docm" or action_file_path endswith ".docx" or action_file_path endswith ".dot" or action_file_path endswith ".dotm" or action_file_path endswith ".rtf")) and ((action_file_path contains "\\Microsoft\\Word\\STARTUP") or ((action_file_path contains "\\Office" and action_file_path contains "\\Program Files" and action_file_path contains "\\STARTUP")))) or (((action_file_path endswith ".xls" or action_file_path endswith ".xlsm" or action_file_path endswith ".xlsx" or action_file_path endswith ".xlt" or action_file_path endswith ".xltm")) and ((action_file_path contains "\\Microsoft\\Excel\\XLSTART") or ((action_file_path contains "\\Office" and action_file_path contains "\\Program Files" and action_file_path contains "\\XLSTART"))))) and not (((action_process_image_path endswith "\\WINWORD.exe" or action_process_image_path endswith "\\EXCEL.exe"))))
