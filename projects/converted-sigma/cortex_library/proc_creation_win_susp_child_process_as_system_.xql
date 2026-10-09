// Title: Suspicious Child Process Created as System
// ID: 590a5f4c-6c8c-4f10-8307-89afe9453a9d
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Roberto Rodriguez (@Cyb3rWard0g), Open Threat Research (OTR)
// Date: 2019-10-26
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.002
// Description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE accounts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ParentUser contains "AUTHORI" or ParentUser contains "AUTORI") and (ParentUser endswith "\\NETWORK SERVICE" or ParentUser endswith "\\LOCAL SERVICE") and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI") and (action_process_username endswith "\\SYSTEM" or action_process_username endswith "\\Système" or action_process_username endswith "\\СИСТЕМА") and (IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384")) and not ((action_process_image_path endswith "\\rundll32.exe" and action_process_image_command_line contains "DavSetCookie")))
