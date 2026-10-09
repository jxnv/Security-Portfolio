// Title: WinRAR Execution in Non-Standard Folder
// ID: 4ede543c-e098-43d9-a28f-dd784a13132f
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Tigzy
// Date: 2021-11-17
// Tags: attack.collection, attack.t1560.001
// Description: Detects a suspicious WinRAR execution in a folder which is not the default installation folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rar.exe" or action_process_image_path endswith "\\winrar.exe")) or ((Description = "Command line RAR" or Description = "WinRAR"))) and not ((((action_process_image_path contains ":\\Program Files (x86)\\WinRAR\\" or action_process_image_path contains ":\\Program Files\\WinRAR\\")) or (action_process_image_path endswith "\\UnRAR.exe"))) and not ((action_process_image_path contains ":\\Windows\\Temp\\")))
