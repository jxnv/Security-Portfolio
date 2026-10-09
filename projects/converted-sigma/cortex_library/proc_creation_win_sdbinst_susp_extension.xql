// Title: Uncommon Extension Shim Database Installation Via Sdbinst.EXE
// ID: 18ee686c-38a3-4f65-9f44-48a077141f42
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-01
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.011
// Description: Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
// Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\sdbinst.exe") or (action_process_image_name = "sdbinst.exe")) and not (((action_process_image_command_line = "") or (action_process_image_command_line contains ".sdb") or (((action_process_image_command_line endswith " -c" or action_process_image_command_line endswith " -f" or action_process_image_command_line endswith " -mm" or action_process_image_command_line endswith " -t")) or (action_process_image_command_line contains " -m -bg")) or (action_process_image_command_line = null))))
