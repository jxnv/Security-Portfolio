// Title: Suspicious JavaScript Execution Via Mshta.EXE
// ID: 67f113fa-e23d-4271-befa-30113b3e08b1
// Status: test
// Level: high
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.stealth, attack.t1218.005
// Description: Detects execution of javascript code using "mshta.exe".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "javascript") and ((action_process_image_path endswith "\\mshta.exe") or (action_process_image_name = "MSHTA.EXE")))
