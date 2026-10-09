// Title: Suspicious Double Extension Files
// ID: b4926b47-a9d7-434c-b3a0-adc3fa0bd13e
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2022-06-19
// Tags: attack.stealth, attack.t1036.007
// Description: Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_file_path endswith ".rar.exe" or action_file_path endswith ".zip.exe")) or ((action_file_path endswith ".exe" or action_file_path endswith ".iso" or action_file_path endswith ".rar" or action_file_path endswith ".svg" or action_file_path endswith ".zip") and (action_file_path contains ".doc." or action_file_path contains ".docx." or action_file_path contains ".gif." or action_file_path contains ".jpeg." or action_file_path contains ".jpg." or action_file_path contains ".mp3." or action_file_path contains ".mp4." or action_file_path contains ".pdf." or action_file_path contains ".png." or action_file_path contains ".ppt." or action_file_path contains ".pptx." or action_file_path contains ".rtf." or action_file_path contains ".svg." or action_file_path contains ".txt." or action_file_path contains ".xls." or action_file_path contains ".xlsx."))) and not ((action_file_path startswith "/usr/share/icons/")))
