// Title: Potential Binary Or Script Dropper Via PowerShell
// ID: 7047d730-036f-4f40-b9d8-1c63e36d5e62
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-17
// Tags: attack.persistence
// Description: Detects PowerShell creating a binary executable or a script file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_file_path endswith ".bat" or action_file_path endswith ".chm" or action_file_path endswith ".cmd" or action_file_path endswith ".com" or action_file_path endswith ".dll" or action_file_path endswith ".exe" or action_file_path endswith ".hta" or action_file_path endswith ".jar" or action_file_path endswith ".js" or action_file_path endswith ".ocx" or action_file_path endswith ".scr" or action_file_path endswith ".sys" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf")) and not (((action_file_path startswith "C:\\Program Files\\PackageManagement\\ProviderAssemblies\\nuget\\" and action_file_path endswith "\\Microsoft.PackageManagement.NuGetProvider.dll") or ((action_file_path startswith "C:\\Windows\\Temp\\" or action_file_path startswith "C:\\Windows\\SystemTemp\\") and (action_file_path endswith ".dll" or action_file_path endswith ".exe")) or (action_file_path startswith "C:\\Users\\" and action_file_path contains "\\WindowsPowerShell\\Modules\\" and action_file_path endswith ".dll") or (action_file_path startswith "C:\\Users\\" and action_file_path contains "\\AppData\\Local\\Temp\\" and (action_file_path endswith ".dll" or action_file_path endswith ".exe")))))
