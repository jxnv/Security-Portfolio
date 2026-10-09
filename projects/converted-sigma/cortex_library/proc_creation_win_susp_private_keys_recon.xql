// Title: Private Keys Reconnaissance Via CommandLine Tools
// ID: 213d6a77-3d55-4ce8-ba74-fcfef741974e
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-07-20
// Tags: attack.credential-access, attack.t1552.004
// Description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".key" or action_process_image_command_line contains ".pgp" or action_process_image_command_line contains ".gpg" or action_process_image_command_line contains ".ppk" or action_process_image_command_line contains ".p12" or action_process_image_command_line contains ".pem" or action_process_image_command_line contains ".pfx" or action_process_image_command_line contains ".cer" or action_process_image_command_line contains ".p7b" or action_process_image_command_line contains ".asc")) and (((action_process_image_command_line contains "dir ") and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe"))) or ((action_process_image_command_line contains "Get-ChildItem ") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")))) or ((action_process_image_path endswith "\\findstr.exe") or (action_process_image_name = "FINDSTR.EXE"))))
