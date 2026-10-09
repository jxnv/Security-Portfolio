// Title: Suspicious Appended Extension
// ID: e3f673b3-65d1-4d80-9146-466f8b63fa99
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-07-16
// Tags: attack.impact, attack.t1486
// Description: Detects file renames where the target filename uses an uncommon double extension. Could indicate potential ransomware activity renaming files and adding a custom extension to the encrypted files, such as ".jpg.crypted", ".docx.locky", etc.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((SourceFilename endswith ".doc" or SourceFilename endswith ".docx" or SourceFilename endswith ".jpeg" or SourceFilename endswith ".jpg" or SourceFilename endswith ".lnk" or SourceFilename endswith ".pdf" or SourceFilename endswith ".png" or SourceFilename endswith ".pst" or SourceFilename endswith ".rtf" or SourceFilename endswith ".xls" or SourceFilename endswith ".xlsx") and (action_file_path contains ".doc." or action_file_path contains ".docx." or action_file_path contains ".jpeg." or action_file_path contains ".jpg." or action_file_path contains ".lnk." or action_file_path contains ".pdf." or action_file_path contains ".png." or action_file_path contains ".pst." or action_file_path contains ".rtf." or action_file_path contains ".xls." or action_file_path contains ".xlsx.")) and not (((action_file_path endswith ".backup" or action_file_path endswith ".bak" or action_file_path endswith ".old" or action_file_path endswith ".orig" or action_file_path endswith ".temp" or action_file_path endswith ".tmp"))) and not ((action_file_path contains ":\\ProgramData\\Anaconda3\\" and action_file_path endswith ".c~")))
