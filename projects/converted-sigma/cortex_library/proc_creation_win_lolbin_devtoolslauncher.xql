// Title: Devtoolslauncher.exe Executes Specified Binary
// ID: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
// Status: test
// Level: high
// Author: Beyu Denis, oscd.community (rule), @_felamos (idea)
// Date: 2019-10-12
// Tags: attack.stealth, attack.t1218
// Description: The Devtoolslauncher.exe executes other binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\devtoolslauncher.exe" and action_process_image_command_line contains "LaunchForDeploy")
