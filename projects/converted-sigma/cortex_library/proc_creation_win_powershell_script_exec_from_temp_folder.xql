// Title: Potentially Suspicious Powershell Script Execution From Temp Folder
// ID: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton
// Date: 2021-07-14
// Tags: attack.execution, attack.t1059.001
// Description: Detects a potentially suspicious powershell script executions from temporary folder
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "\\Windows\\Temp" or action_process_image_command_line contains "\\Temporary Internet" or action_process_image_command_line contains "\\AppData\\Local\\Temp" or action_process_image_command_line contains "\\AppData\\Roaming\\Temp" or action_process_image_command_line contains "%TEMP%" or action_process_image_command_line contains "%TMP%" or action_process_image_command_line contains "%LocalAppData%\\Temp")) and not (((action_process_image_command_line contains "\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp\\Amazon\\EC2-Windows\\") or ((actor_process_image_path = "C:\\Windows\\System32\\Msiexec.exe" or actor_process_image_path = "C:\\Windows\\SysWOW64\\Msiexec.exe") and action_process_image_path endswith "\\powershell.exe" and (action_process_image_command_line contains "-NoProfile -ExecutionPolicy Bypass -Command" and action_process_image_command_line contains "AppData\\Local\\Temp\\" and action_process_image_command_line contains "Install-Chocolatey.ps1")) or ((action_process_image_command_line contains " >" or action_process_image_command_line contains "Out-File" or action_process_image_command_line contains "ConvertTo-Json")) or (action_process_image_command_line contains "-WindowStyle hidden -Verb runAs"))))
