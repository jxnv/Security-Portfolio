// Title: Uncommon Sigverif.EXE Child Process
// ID: 7d4aaec2-08ed-4430-8b96-28420e030e04
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-19
// Tags: attack.stealth, attack.t1216
// Description: Detects uncommon child processes spawning from "sigverif.exe", which could indicate potential abuse of the latter as a living of the land binary in order to proxy execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\sigverif.exe") and not (((action_process_image_path = "C:\\Windows\\System32\\WerFault.exe" or action_process_image_path = "C:\\Windows\\SysWOW64\\WerFault.exe"))))
