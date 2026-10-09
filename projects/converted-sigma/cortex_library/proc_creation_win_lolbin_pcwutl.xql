// Title: Code Execution via Pcwutl.dll
// ID: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-05
// Tags: attack.stealth, attack.t1218.011
// Description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "pcwutl" and action_process_image_command_line contains "LaunchApplication")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
