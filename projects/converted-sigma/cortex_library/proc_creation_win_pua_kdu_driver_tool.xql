// Title: PUA - Kernel Driver Utility (KDU) Execution
// ID: e76ca062-4de0-4d79-8d90-160a0d335eca
// Status: experimental
// Level: high
// Author: Matt Anderson, Dray Agha, Anna Pham (Huntress)
// Date: 2026-01-02
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects execution of the Kernel Driver Utility (KDU) tool.
// KDU can be used to bypass driver signature enforcement and load unsigned or malicious drivers into the Windows kernel.
// Potentially allowing for privilege escalation, persistence, or evasion of security controls.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-map " or action_process_image_command_line contains "-prv " or action_process_image_command_line contains "-dse " or action_process_image_command_line contains "-ps ")) and (((action_process_image_path endswith "\\kdu.exe" or action_process_image_path endswith "\\hamakaze.exe")) or (action_process_image_name = "hamakaze.exe")))
