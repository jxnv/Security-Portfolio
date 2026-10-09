// Title: Potential Linux Process Code Injection Via DD Utility
// ID: 4cad6c64-d6df-42d6-8dae-eb78defdc415
// Status: test
// Level: medium
// Author: Joseph Kamau
// Date: 2023-12-01
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055.009
// Description: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/dd" and (action_process_image_command_line contains "of=" and action_process_image_command_line contains "/proc/" and action_process_image_command_line contains "/mem"))
