// Title: Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution
// ID: 7b582f1a-b318-4c6a-bf4e-66fe49bf55a5
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @Kostastsale
// Date: 2022-02-25
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects potentially suspicious child processes launched via the ScreenConnect client service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_command_line contains ":\\Windows\\TEMP\\ScreenConnect\\" and actor_process_command_line contains "run.cmd") and (action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\dllhost.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\nltest.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wevtutil.exe"))
