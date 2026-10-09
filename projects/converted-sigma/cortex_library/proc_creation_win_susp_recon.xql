// Title: Recon Information for Export with Command Prompt
// ID: aa2efee7-34dd-446e-8a37-40790a66efd7
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-30
// Tags: attack.collection, attack.t1119
// Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\tree.com" or action_process_image_path endswith "\\WMIC.exe" or action_process_image_path endswith "\\doskey.exe" or action_process_image_path endswith "\\sc.exe")) or ((action_process_image_name = "wmic.exe" or action_process_image_name = "DOSKEY.EXE" or action_process_image_name = "sc.exe"))) and ((actor_process_command_line contains " > %TEMP%\\" or actor_process_command_line contains " > %TMP%\\")))
