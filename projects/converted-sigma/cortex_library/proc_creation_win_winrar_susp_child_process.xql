// Title: Potentially Suspicious Child Process Of WinRAR.EXE
// ID: 146aace8-9bd6-42ba-be7a-0070d8027b76
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-31
// Tags: attack.execution, attack.t1203
// Description: Detects potentially suspicious child processes of WinRAR.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "cscript.exe" or action_process_image_name = "mshta.exe" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "regsvr32.exe" or action_process_image_name = "RUNDLL32.EXE" or action_process_image_name = "wscript.exe"))) and (actor_process_image_path endswith "\\WinRAR.exe"))
