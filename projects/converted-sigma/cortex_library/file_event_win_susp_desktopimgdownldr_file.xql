// Title: Suspicious Desktopimgdownldr Target File
// ID: fc4f4817-0c53-4683-a4ee-b17a64bc1039
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-07-03
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\svchost.exe" and action_file_path contains "\\Personalization\\LockScreenImage\\") and not ((action_file_path contains "C:\\Windows\\")) and not (((action_file_path contains ".jpg" or action_file_path contains ".jpeg" or action_file_path contains ".png"))))
