// Title: Suspicious AgentExecutor PowerShell Execution
// ID: c0b40568-b1e9-4b03-8d6c-b096da6da9ab
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), memory-shards
// Date: 2022-12-24
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy "Bypass" or any binary named "powershell.exe" located in the path provided by 6th positional argument
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " -powershell" or action_process_image_command_line contains " -remediationScript")) and ((action_process_image_path endswith "\\AgentExecutor.exe") or (action_process_image_name = "AgentExecutor.exe"))) and not (((actor_process_image_path endswith "\\Microsoft.Management.Services.IntuneWindowsAgent.exe") or ((action_process_image_command_line contains "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\" or action_process_image_command_line contains "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\")))))
