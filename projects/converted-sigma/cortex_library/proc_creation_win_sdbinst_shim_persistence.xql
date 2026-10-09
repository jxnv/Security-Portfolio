// Title: Potential Shim Database Persistence via Sdbinst.EXE
// ID: 517490a7-115a-48c6-8862-1a481504d5a8
// Status: test
// Level: medium
// Author: Markus Neis
// Date: 2019-01-16
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.011
// Description: Detects installation of a new shim using sdbinst.exe.
// Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".sdb") and ((action_process_image_path endswith "\\sdbinst.exe") or (action_process_image_name = "sdbinst.exe"))) and not ((actor_process_image_path endswith "\\msiexec.exe" and (action_process_image_command_line contains ":\\Program Files (x86)\\IIS Express\\iisexpressshim.sdb" or action_process_image_command_line contains ":\\Program Files\\IIS Express\\iisexpressshim.sdb"))))
