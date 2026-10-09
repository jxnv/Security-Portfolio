// Title: Potential Arbitrary DLL Load Using Winword
// ID: f7375e28-5c14-432f-b8d1-1db26c832df3
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2020-10-09
// Tags: attack.stealth, attack.t1202
// Description: Detects potential DLL sideloading using the Microsoft Office winword process via the '/l' flag.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/l " and action_process_image_command_line contains ".dll")) and ((action_process_image_path endswith "\\WINWORD.exe") or (action_process_image_name = "WinWord.exe")))
