// Title: Cscript/Wscript Potentially Suspicious Child Process
// ID: b6676963-0353-4f88-90f5-36c20d443c6a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Alejandro Houspanossian ('@lekz86')
// Date: 2023-05-15
// Tags: attack.execution
// Description: Detects potentially suspicious child processes of Wscript/Cscript. These include processes such as rundll32 with uncommon exports or PowerShell spawning rundll32 or regsvr32.
// Malware such as Pikabot and Qakbot were seen using similar techniques as well as many others.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\wscript.exe" or actor_process_image_path endswith "\\cscript.exe")) and ((action_process_image_path endswith "\\rundll32.exe") or (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) and (((action_process_image_command_line contains "mshta" and action_process_image_command_line contains "http")) or ((action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "regsvr32" or action_process_image_command_line contains "msiexec"))))) and not ((action_process_image_path endswith "\\rundll32.exe" and (action_process_image_command_line contains "UpdatePerUserSystemParameters" or action_process_image_command_line contains "PrintUIEntry" or action_process_image_command_line contains "ClearMyTracksByProcess"))))
