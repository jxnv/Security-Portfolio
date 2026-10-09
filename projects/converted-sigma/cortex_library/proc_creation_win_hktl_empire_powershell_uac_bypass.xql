// Title: HackTool - Empire PowerShell UAC Bypass
// ID: 3268b746-88d8-4cd3-bffc-30077d02c787
// Status: stable
// Level: critical
// Author: Ecco
// Date: 2019-08-30
// Tags: attack.privilege-escalation, attack.t1548.002, car.2019-04-001
// Description: Detects some Empire PowerShell UAC bypass methods
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)" or action_process_image_command_line contains " -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);"))
