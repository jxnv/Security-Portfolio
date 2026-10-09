// Title: Suspicious New Service Creation
// ID: 17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-14
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "New-Service" and action_process_image_command_line contains "-BinaryPathName")) or (action_process_image_path endswith "\\sc.exe" and (action_process_image_command_line contains "create" and action_process_image_command_line contains "binPath="))) and ((action_process_image_command_line contains "powershell" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "svchost" or action_process_image_command_line contains "dllhost" or action_process_image_command_line contains "cmd " or action_process_image_command_line contains "cmd.exe /c" or action_process_image_command_line contains "cmd.exe /k" or action_process_image_command_line contains "cmd.exe /r" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "C:\\Users\\Public" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or action_process_image_command_line contains "C:\\Windows\\TEMP\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp")))
