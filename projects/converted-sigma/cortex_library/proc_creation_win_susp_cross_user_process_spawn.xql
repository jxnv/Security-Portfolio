// Title: Suspicious Cross-User Process Spawn
// ID: d2b7a134-9c3e-4f8a-b56d-e0c1f8a29b47
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-07-23
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1134
// Description: Detects suspicious spawning of a process under a different user context than the parent process.
// Processes such as notepad.exe, calculator etc. are generally spawned under the same user context and
// also they are often targeted as sacrificial process or decoy process to check successful privilege escalation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\notepad.exe" or action_process_image_path endswith "\\calc.exe" or action_process_image_path endswith "\\mspaint.exe" or action_process_image_path endswith "\\wordpad.exe" or action_process_image_path endswith "\\write.exe")) and not ((action_process_username=ParentUser)) and not (((((ParentUser = "" or ParentUser = "-")) or ((action_process_username = "" or action_process_username = "-"))) or (ParentUser = null) or (action_process_username = null))))
