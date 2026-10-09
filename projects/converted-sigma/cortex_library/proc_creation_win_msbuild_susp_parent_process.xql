// Title: Suspicious Msbuild Execution By Uncommon Parent Process
// ID: 33be4333-2c6b-44f4-ae28-102cdbde0a31
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-11-17
// Tags: attack.stealth
// Description: Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\MSBuild.exe") or (action_process_image_name = "MSBuild.exe")) and not (((actor_process_image_path endswith "\\devenv.exe" or actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\msbuild.exe" or actor_process_image_path endswith "\\python.exe" or actor_process_image_path endswith "\\explorer.exe" or actor_process_image_path endswith "\\nuget.exe"))))
