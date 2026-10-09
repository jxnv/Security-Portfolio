// Title: Publisher Attachment File Dropped In Suspicious Location
// ID: 3d2a2d59-929c-4b78-8c1a-145dfe9e07b1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-08
// Tags: attack.stealth
// Description: Detects creation of files with the ".pub" extension in suspicious or uncommon locations. This could be a sign of attackers abusing Publisher documents
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\AppData\\Local\\Temp\\" or action_file_path contains "\\Users\\Public\\" or action_file_path contains "\\Windows\\Temp\\" or action_file_path contains "C:\\Temp\\") and action_file_path endswith ".pub")
