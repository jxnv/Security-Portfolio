// Title: Potentially Suspicious Execution Of PDQDeployRunner
// ID: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-22
// Tags: attack.execution
// Description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\csc.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\dllhost.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\scriptrunner.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\wsl.exe")) or ((action_process_image_path contains ":\\ProgramData\\" or action_process_image_path contains ":\\Users\\Public\\" or action_process_image_path contains ":\\Windows\\TEMP\\" or action_process_image_path contains "\\AppData\\Local\\Temp")) or ((action_process_image_command_line contains " -decode " or action_process_image_command_line contains " -enc " or action_process_image_command_line contains " -encodedcommand " or action_process_image_command_line contains " -w hidden" or action_process_image_command_line contains "DownloadString" or action_process_image_command_line contains "FromBase64String" or action_process_image_command_line contains "http" or action_process_image_command_line contains "iex " or action_process_image_command_line contains "Invoke-"))) and (actor_process_image_path contains "\\PDQDeployRunner-"))
