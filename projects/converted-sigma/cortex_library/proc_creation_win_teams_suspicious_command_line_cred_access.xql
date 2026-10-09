// Title: Potentially Suspicious Command Targeting Teams Sensitive Files
// ID: d2eb17db-1d39-41dc-b57f-301f6512fa75
// Status: test
// Level: medium
// Author: @SerkinValery
// Date: 2022-09-16
// Tags: attack.credential-access, attack.t1528
// Description: Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
// The database might contain authentication tokens and other sensitive information about the logged in accounts.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\Microsoft\\Teams\\Cookies" or action_process_image_command_line contains "\\Microsoft\\Teams\\Local Storage\\leveldb")) and not ((action_process_image_path endswith "\\Microsoft\\Teams\\current\\Teams.exe")))
