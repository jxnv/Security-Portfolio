// Title: Suspicious Group And Account Reconnaissance Activity Using Net.EXE
// ID: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), omkar72, @svch0st, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-01-16
// Tags: attack.discovery, attack.t1087.001, attack.t1087.002
// Description: Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE
// Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe")) or ((action_process_image_name = "net.exe" or action_process_image_name = "net1.exe"))) and (((((action_process_image_command_line contains "domain admins" or action_process_image_command_line contains " administrator" or action_process_image_command_line contains " administrateur" or action_process_image_command_line contains "enterprise admins" or action_process_image_command_line contains "Exchange Trusted Subsystem" or action_process_image_command_line contains "Remote Desktop Users" or action_process_image_command_line contains "Utilisateurs du Bureau à distance" or action_process_image_command_line contains "Usuarios de escritorio remoto" or action_process_image_command_line contains " /do")) and ((action_process_image_command_line contains " group " or action_process_image_command_line contains " localgroup "))) and not ((action_process_image_command_line contains " /add"))) or ((action_process_image_command_line contains " /do") and (action_process_image_command_line contains " accounts "))))
