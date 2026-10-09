// Title: UAC Bypass Using Windows Media Player - Process
// ID: 0058b9e5-bcd7-40d4-9205-95ca5a16d7b2
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path = "C:\\Program Files\\Windows Media Player\\osk.exe") or (action_process_image_path = "C:\\Windows\\System32\\cmd.exe" and actor_process_command_line = "\"C:\\Windows\\system32\\mmc.exe\" \"C:\\Windows\\system32\\eventvwr.msc\" /s")) and ((IntegrityLevel = "High" or IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384" or IntegrityLevel = "S-1-16-12288")))
