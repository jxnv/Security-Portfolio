// Title: Potentially Suspicious ASP.NET Compilation Via AspNetCompiler
// ID: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-14
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects execution of "aspnet_compiler.exe" with potentially suspicious paths for compilation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path contains ":\\Windows\\Microsoft.NET\\Framework\\" or action_process_image_path contains ":\\Windows\\Microsoft.NET\\Framework64\\" or action_process_image_path contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or action_process_image_path contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\") and action_process_image_path endswith "\\aspnet_compiler.exe" and (action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Roaming\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains ":\\Windows\\System32\\Tasks\\" or action_process_image_command_line contains ":\\Windows\\Tasks\\"))
