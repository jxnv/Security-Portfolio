// Title: Potential DLL Injection Or Execution Using Tracker.exe
// ID: 148431ce-4b70-403d-8525-fcc2993f29ea
// Status: test
// Level: medium
// Author: Avneet Singh @v3t0_, oscd.community
// Date: 2020-10-18
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055.001
// Description: Detects potential DLL injection and execution using "Tracker.exe"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " /d " or action_process_image_command_line contains " /c ")) and ((action_process_image_path endswith "\\tracker.exe") or (Description = "Tracker"))) and not (((action_process_image_command_line contains " /ERRORREPORT:PROMPT ") or ((actor_process_image_path endswith "\\Msbuild\\Current\\Bin\\MSBuild.exe" or actor_process_image_path endswith "\\Msbuild\\Current\\Bin\\amd64\\MSBuild.exe")))))
