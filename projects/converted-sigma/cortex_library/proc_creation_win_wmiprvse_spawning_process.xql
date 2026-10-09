// Title: WmiPrvSE Spawned A Process
// ID: d21374ff-f574-44a7-9998-4a8c8bf33d7d
// Status: stable
// Level: medium
// Author: Roberto Rodriguez @Cyb3rWard0g
// Date: 2019-08-15
// Tags: attack.execution, attack.t1047
// Description: Detects WmiPrvSE spawning a process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\WmiPrvSe.exe") and not ((((LogonId = "0x3e7" or LogonId = "null")) or (LogonId = null) or ((action_process_username contains "AUTHORI" or action_process_username contains "AUTORI")) or (action_process_image_path endswith "\\WerFault.exe") or (action_process_image_path endswith "\\WmiPrvSE.exe"))))
