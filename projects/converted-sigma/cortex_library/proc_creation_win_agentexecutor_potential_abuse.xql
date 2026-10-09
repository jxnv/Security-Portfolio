// Title: AgentExecutor PowerShell Execution
// ID: 7efd2c8d-8b18-45b7-947d-adfe9ed04f61
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), memory-shards
// Date: 2022-12-24
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the AgentExecutor.exe binary. Which can be abused as a LOLBIN to execute powershell scripts with the ExecutionPolicy "Bypass" or any binary named "powershell.exe" located in the path provided by 6th positional argument
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " -powershell" or action_process_image_command_line contains " -remediationScript")) and ((action_process_image_path = "\\AgentExecutor.exe") or (action_process_image_name = "AgentExecutor.exe"))) and not ((actor_process_image_path endswith "\\Microsoft.Management.Services.IntuneWindowsAgent.exe")))
