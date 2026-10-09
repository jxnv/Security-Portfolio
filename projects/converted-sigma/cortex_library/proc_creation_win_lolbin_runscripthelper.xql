// Title: Suspicious Runscripthelper.exe
// ID: eca49c87-8a75-4f13-9c73-a5a29e845f03
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2020-10-09
// Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
// Description: Detects execution of powershell scripts via Runscripthelper.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\Runscripthelper.exe" and action_process_image_command_line contains "surfacecheck")
