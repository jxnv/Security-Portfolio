// Title: PowerShell Module File Created
// ID: e36941d0-c0f0-443f-bc6f-cb2952eb69ea
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-09
// Tags: attack.persistence
// Description: Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_file_path contains "\\WindowsPowerShell\\Modules\\" or action_file_path contains "\\PowerShell\\7\\Modules\\"))
