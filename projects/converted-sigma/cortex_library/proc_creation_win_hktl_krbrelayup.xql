// Title: HackTool - KrbRelayUp Execution
// ID: 12827a56-61a4-476a-a9cb-f3068f191073
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-26
// Tags: attack.credential-access, attack.t1558.003, attack.lateral-movement, attack.t1550.003
// Description: Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " relay " and action_process_image_command_line contains " -Domain " and action_process_image_command_line contains " -ComputerName ")) or ((action_process_image_command_line contains " krbscm " and action_process_image_command_line contains " -sc ")) or ((action_process_image_command_line contains " spawn " and action_process_image_command_line contains " -d " and action_process_image_command_line contains " -cn " and action_process_image_command_line contains " -cp ")) or ((action_process_image_path endswith "\\KrbRelayUp.exe") or (action_process_image_name = "KrbRelayUp.exe")))
