// Title: Suspicious Schtasks Execution AppData Folder
// ID: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-03-15
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
// Description: Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\schtasks.exe" and (action_process_image_command_line contains "/Create" and action_process_image_command_line contains "/RU" and action_process_image_command_line contains "/TR" and action_process_image_command_line contains "C:\\Users\\" and action_process_image_command_line contains "\\AppData\\Local\\") and (action_process_image_command_line contains "NT AUT" or action_process_image_command_line contains " SYSTEM ")) and not (((actor_process_image_path contains "\\AppData\\Local\\Temp\\" and actor_process_image_path contains "TeamViewer_.exe") and action_process_image_path endswith "\\schtasks.exe" and action_process_image_command_line contains "/TN TVInstallRestore")))
