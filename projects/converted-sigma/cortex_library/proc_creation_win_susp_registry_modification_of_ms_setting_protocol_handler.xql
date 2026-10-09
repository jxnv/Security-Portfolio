// Title: Registry Modification of MS-settings Protocol Handler
// ID: dd3ee8cc-f751-41c9-ba53-5a32ed47e563
// Status: test
// Level: medium
// Author: frack113, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2021-12-20
// Tags: attack.privilege-escalation, attack.persistence, attack.defense-impairment, attack.t1548.002, attack.t1546.001, attack.t1112
// Description: Detects registry modifications to the 'ms-settings' protocol handler, which is frequently targeted for UAC bypass or persistence.
// Attackers can modify this registry to execute malicious code with elevated privileges by hijacking the command execution path.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "add") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe"))) or (((action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "ni " or action_process_image_command_line contains "sp ")) and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll"))))) and (action_process_image_command_line contains "\\ms-settings\\shell\\open\\command"))
