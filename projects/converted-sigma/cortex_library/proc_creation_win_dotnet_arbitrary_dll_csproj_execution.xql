// Title: Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE
// ID: d80d5c81-04ba-45b4-84e4-92eba40e0ad3
// Status: test
// Level: medium
// Author: Beyu Denis, oscd.community
// Date: 2020-10-18
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of arbitrary DLLs or unsigned code via a ".csproj" files via Dotnet.EXE.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line endswith ".csproj" or action_process_image_command_line endswith ".csproj\"" or action_process_image_command_line endswith ".dll" or action_process_image_command_line endswith ".dll\"" or action_process_image_command_line endswith ".csproj'" or action_process_image_command_line endswith ".dll'")) and ((action_process_image_path endswith "\\dotnet.exe") or (action_process_image_name = ".NET Host"))) and not (((actor_process_image_path = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe" or actor_process_image_path = "C:\\Program Files\\Notepad++\\notepad++.exe") and (action_process_image_command_line contains "C:\\ProgramData\\CSScriptNpp\\" and action_process_image_command_line contains "-cscs_path:" and action_process_image_command_line contains "\\cs-script\\cscs.dll"))))
