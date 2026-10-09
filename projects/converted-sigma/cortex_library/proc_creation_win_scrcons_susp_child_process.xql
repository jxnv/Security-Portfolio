// Title: Script Event Consumer Spawning Process
// ID: f6d1dd2f-b8ce-40ca-bc23-062efb686b34
// Status: test
// Level: high
// Author: Sittikorn S
// Date: 2021-06-21
// Tags: attack.execution, attack.t1047
// Description: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\scrcons.exe" and (action_process_image_path endswith "\\svchost.exe" or action_process_image_path endswith "\\dllhost.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\msbuild.exe"))
