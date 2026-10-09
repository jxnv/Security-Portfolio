// Title: Hiding Files with Attrib.exe
// ID: 4281cb20-2994-4580-aa63-c8b86d019934
// Status: test
// Level: medium
// Author: Sami Ruohonen
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1564.001
// Description: Detects usage of attrib.exe to hide files from users.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " +h ") and ((action_process_image_path endswith "\\attrib.exe") or (action_process_image_name = "ATTRIB.EXE"))) and not ((action_process_image_command_line contains "\\desktop.ini ")) and not ((actor_process_image_path endswith "\\cmd.exe" and action_process_image_command_line = "+R +H +S +A \\\\\\*.cui" and actor_process_command_line = "C:\\\\WINDOWS\\\\system32\\\\\\*.bat")))
