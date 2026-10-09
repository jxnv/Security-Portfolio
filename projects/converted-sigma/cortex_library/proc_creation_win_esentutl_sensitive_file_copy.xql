// Title: Copying Sensitive Files with Credential Data
// ID: e7be6119-fc37-43f0-ad4f-1f3f99be2f9f
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003.002, attack.t1003.003, car.2013-07-001, attack.s0404
// Description: Files with well-known filenames (sensitive files with credential data) copying
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "vss" or action_process_image_command_line contains " /m " or action_process_image_command_line contains " /y ")) and ((action_process_image_path endswith "\\esentutl.exe") or (action_process_image_name = "\\esentutl.exe"))) or ((action_process_image_command_line contains "\\config\\RegBack\\sam" or action_process_image_command_line contains "\\config\\RegBack\\security" or action_process_image_command_line contains "\\config\\RegBack\\system" or action_process_image_command_line contains "\\config\\sam" or action_process_image_command_line contains "\\config\\security" or action_process_image_command_line contains "\\config\\system " or action_process_image_command_line contains "\\repair\\sam" or action_process_image_command_line contains "\\repair\\security" or action_process_image_command_line contains "\\repair\\system" or action_process_image_command_line contains "\\windows\\ntds\\ntds.dit")))
