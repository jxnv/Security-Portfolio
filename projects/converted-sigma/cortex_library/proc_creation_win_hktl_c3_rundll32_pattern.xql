// Title: HackTool - F-Secure C3 Load by Rundll32
// ID: b18c9d4c-fac9-4708-bd06-dd5bfacf200f
// Status: test
// Level: critical
// Author: Alfie Champion (ajpc500)
// Date: 2021-06-02
// Tags: attack.stealth, attack.t1218.011
// Description: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "rundll32.exe" and action_process_image_command_line contains ".dll" and action_process_image_command_line contains "StartNodeRelay"))
