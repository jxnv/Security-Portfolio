// Title: NTDS.DIT Creation By Uncommon Process
// ID: 11b1ed55-154d-4e82-8ad7-83739298f720
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-11
// Tags: attack.credential-access, attack.t1003.002, attack.t1003.003
// Description: Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon process or a process located in a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\ntds.dit") and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\wsl.exe" or action_process_image_path endswith "\\wt.exe")) or ((action_process_image_path contains "\\AppData\\" or action_process_image_path contains "\\Temp\\" or action_process_image_path contains "\\Public\\" or action_process_image_path contains "\\PerfLogs\\"))))
