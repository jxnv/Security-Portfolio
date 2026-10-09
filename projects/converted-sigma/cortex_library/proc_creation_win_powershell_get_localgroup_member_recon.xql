// Title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
// ID: c8a180d6-47a3-4345-a609-53f9c3d834fc
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-10
// Tags: attack.discovery, attack.t1087.001
// Description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Get-LocalGroupMember ") and ((action_process_image_command_line contains "domain admins" or action_process_image_command_line contains " administrator" or action_process_image_command_line contains " administrateur" or action_process_image_command_line contains "enterprise admins" or action_process_image_command_line contains "Exchange Trusted Subsystem" or action_process_image_command_line contains "Remote Desktop Users" or action_process_image_command_line contains "Utilisateurs du Bureau à distance" or action_process_image_command_line contains "Usuarios de escritorio remoto")))
