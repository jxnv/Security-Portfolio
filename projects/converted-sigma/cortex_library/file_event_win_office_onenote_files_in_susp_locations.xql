// Title: OneNote Attachment File Dropped In Suspicious Location
// ID: 7fd164ba-126a-4d9c-9392-0d4f7c243df0
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-22
// Tags: attack.stealth
// Description: Detects creation of files with the ".one"/".onepkg" extension in suspicious or uncommon locations. This could be a sign of attackers abusing OneNote attachments
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "\\AppData\\Local\\Temp\\" or action_file_path contains "\\Users\\Public\\" or action_file_path contains "\\Windows\\Temp\\" or action_file_path contains ":\\Temp\\") and (action_file_path endswith ".one" or action_file_path endswith ".onepkg")) and not ((action_process_image_path contains ":\\Program Files\\Microsoft Office\\" and action_process_image_path endswith "\\ONENOTE.EXE")))
