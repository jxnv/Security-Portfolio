// Title: Suspicious LNK Double Extension File Created
// ID: 3215aa19-f060-4332-86d5-5602511f3ca8
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2022-11-07
// Tags: attack.stealth, attack.t1036.007
// Description: Detects the creation of files with an "LNK" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the "LNK" extension by default.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith ".lnk" and (action_file_path contains ".doc." or action_file_path contains ".docx." or action_file_path contains ".jpg." or action_file_path contains ".pdf." or action_file_path contains ".ppt." or action_file_path contains ".pptx." or action_file_path contains ".xls." or action_file_path contains ".xlsx.")) and not ((action_file_path contains "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\")) and not (((action_process_image_path endswith "\\excel.exe" and action_file_path contains "\\AppData\\Roaming\\Microsoft\\Excel") or (action_process_image_path endswith "\\powerpnt.exe" and action_file_path contains "\\AppData\\Roaming\\Microsoft\\PowerPoint") or ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and action_file_path contains "\\AppData\\Roaming\\Microsoft\\Office\\Recent\\") or (action_process_image_path endswith "\\winword.exe" and action_file_path contains "\\AppData\\Roaming\\Microsoft\\Word"))))
