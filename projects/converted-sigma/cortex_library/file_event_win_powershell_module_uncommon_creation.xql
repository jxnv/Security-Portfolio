// Title: PowerShell Module File Created By Non-PowerShell Process
// ID: e3845023-ca9a-4024-b2b2-5422156d5527
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-09
// Tags: attack.persistence
// Description: Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc. by a non-PowerShell process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "\\WindowsPowerShell\\Modules\\" or action_file_path contains "\\PowerShell\\7\\Modules\\")) and not ((((action_process_image_path = "C:\\Windows\\System32\\msiexec.exe" or action_process_image_path = "C:\\Windows\\SysWOW64\\msiexec.exe")) or ((action_process_image_path endswith ":\\Program Files\\PowerShell\\7-preview\\pwsh.exe" or action_process_image_path endswith ":\\Program Files\\PowerShell\\7\\pwsh.exe" or action_process_image_path endswith ":\\Windows\\System32\\poqexec.exe" or action_process_image_path endswith ":\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or action_process_image_path endswith ":\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\poqexec.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")))))
