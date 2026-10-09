// Title: Potential SMB Relay Attack Tool Execution
// ID: 5589ab4f-a767-433c-961d-c91f3f704db1
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-24
// Tags: attack.collection, attack.execution, attack.credential-access, attack.t1557.001
// Description: Detects different hacktools used for relay attacks on Windows for privilege escalation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".exe -c \"{" and action_process_image_command_line endswith "}\" -z") or ((action_process_image_path contains "PetitPotam" or action_process_image_path contains "RottenPotato" or action_process_image_path contains "HotPotato" or action_process_image_path contains "JuicyPotato" or action_process_image_path contains "\\just_dce_" or action_process_image_path contains "Juicy Potato" or action_process_image_path contains "\\temp\\rot.exe" or action_process_image_path contains "\\Potato.exe" or action_process_image_path contains "\\SpoolSample.exe" or action_process_image_path contains "\\Responder.exe" or action_process_image_path contains "\\smbrelayx" or action_process_image_path contains "\\ntlmrelayx" or action_process_image_path contains "\\LocalPotato")) or ((action_process_image_command_line contains "Invoke-Tater" or action_process_image_command_line contains " smbrelay" or action_process_image_command_line contains " ntlmrelay" or action_process_image_command_line contains "cme smb " or action_process_image_command_line contains " /ntlm:NTLMhash " or action_process_image_command_line contains "Invoke-PetitPotam" or action_process_image_command_line contains ".exe -t * -p "))) and not (((action_process_image_path contains "HotPotatoes6" or action_process_image_path contains "HotPotatoes7" or action_process_image_path contains "HotPotatoes "))))
