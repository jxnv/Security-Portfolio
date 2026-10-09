// Title: Allow Service Access Using Security Descriptor Tampering Via Sc.EXE
// ID: 6c8fbee5-dee8-49bc-851d-c3142d02aa47
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-28
// Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
// Description: Detects suspicious DACL modifications to allow access to a service from a suspicious trustee. This can be used to override access restrictions set by previous ACLs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\sc.exe") or (action_process_image_name = "sc.exe")) and ((action_process_image_command_line contains "sdset" and action_process_image_command_line contains "A;")) and ((action_process_image_command_line contains ";IU" or action_process_image_command_line contains ";SU" or action_process_image_command_line contains ";BA" or action_process_image_command_line contains ";SY" or action_process_image_command_line contains ";WD"))) and not ((actor_process_image_path = "C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe")))
