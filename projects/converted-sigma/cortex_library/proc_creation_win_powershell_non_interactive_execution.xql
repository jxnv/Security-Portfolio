// Title: Non Interactive PowerShell Process Spawned
// ID: f4bbd493-b796-416e-bbf2-121235348529
// Status: test
// Level: low
// Author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
// Date: 2019-09-12
// Tags: attack.execution, attack.t1059.001
// Description: Detects non-interactive PowerShell activity by looking at the "powershell" process with a non-user GUI process such as "explorer.exe" as a parent.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))) and not ((((actor_process_image_path endswith ":\\Windows\\explorer.exe" or actor_process_image_path endswith ":\\Windows\\System32\\CompatTelRunner.exe" or actor_process_image_path endswith ":\\Windows\\SysWOW64\\explorer.exe")) or (actor_process_image_path = ":\\$WINDOWS.~BT\\Sources\\SetupHost.exe"))) and not (((actor_process_image_path endswith ":\\Program Files\\Windows Defender Advanced Threat Protection\\SenseIR.exe") or (actor_process_image_path contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_" and actor_process_image_path endswith "\\WindowsTerminal.exe") or (actor_process_image_path endswith "\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" and actor_process_command_line contains " --ms-enable-electron-run-as-node "))))
