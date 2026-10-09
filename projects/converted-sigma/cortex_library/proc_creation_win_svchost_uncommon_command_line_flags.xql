// Title: Uncommon Svchost Command Line Parameter
// ID: f17211f1-1f24-4d0c-829f-31e28dc93cdd
// Status: experimental
// Level: high
// Author: Liran Ravich
// Date: 2025-11-14
// Tags: attack.privilege-escalation, attack.stealth, attack.t1036.005, attack.t1055, attack.t1055.012
// Description: Detects instances of svchost.exe running with an unusual or uncommon command line parameter by excluding known legitimate or common patterns.
// This could point at a file masquerading as svchost, a process injection, or hollowing of a legitimate svchost instance.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\svchost.exe") and not (((action_process_image_command_line = "") or (action_process_image_command_line ~= "-k\\s\\w{1,64}(?:\\s?(?:-p|-s))?") or (action_process_image_command_line = null))) and not (((actor_process_image_path endswith "\\MsMpEng.exe" and action_process_image_command_line contains "svchost.exe") or (actor_process_image_path endswith "\\MRT.exe" and action_process_image_command_line = "svchost.exe"))))
