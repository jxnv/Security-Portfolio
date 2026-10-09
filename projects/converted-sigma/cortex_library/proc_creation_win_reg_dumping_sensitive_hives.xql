// Title: Dumping of Sensitive Hives Via Reg.EXE
// ID: fd877b94-9bb5-4191-bb25-d79cbd93c167
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community, frack113
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003.002, attack.t1003.004, attack.t1003.005, car.2013-07-001
// Description: Detects the usage of "reg.exe" in order to dump sensitive registry hives. This includes SAM, SYSTEM and SECURITY hives.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " save " or action_process_image_command_line contains " export " or action_process_image_command_line contains " ˢave " or action_process_image_command_line contains " eˣport ")) and ((action_process_image_command_line contains "\\system" or action_process_image_command_line contains "\\sam" or action_process_image_command_line contains "\\security" or action_process_image_command_line contains "\\ˢystem" or action_process_image_command_line contains "\\syˢtem" or action_process_image_command_line contains "\\ˢyˢtem" or action_process_image_command_line contains "\\ˢam" or action_process_image_command_line contains "\\ˢecurity")) and ((action_process_image_command_line contains "hklm" or action_process_image_command_line contains "hk˪m" or action_process_image_command_line contains "hkey_local_machine" or action_process_image_command_line contains "hkey_˪ocal_machine" or action_process_image_command_line contains "hkey_loca˪_machine" or action_process_image_command_line contains "hkey_˪oca˪_machine")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))
