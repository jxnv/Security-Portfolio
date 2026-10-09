// Title: Execution Of Non-Existing File
// ID: 71158e3f-df67-472b-930e-7d287acaa3e1
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems)
// Date: 2021-12-09
// Tags: attack.stealth, attack.privilege-escalation, attack.t1055
// Description: Detects process creation events where the Image field lacks an absolute path,
// which occurs when the backing file no longer exists on disk at the time of
// logging - commonly caused by Process Ghosting or other unorthodox process creation techniques.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (not ((action_process_image_path contains "\\")) and not (((((action_process_image_path = "MemCompression" or action_process_image_path = "Registry" or action_process_image_path = "System" or action_process_image_path = "vmmem" or action_process_image_path = "vmmemWSL")) or ((action_process_image_command_line = "MemCompression" or action_process_image_command_line = "Registry" or action_process_image_command_line = "vmmem" or action_process_image_command_line = "vmmemWSL"))) or ((action_process_image_path = "-" or action_process_image_path = "")) or (action_process_image_path = null))))
