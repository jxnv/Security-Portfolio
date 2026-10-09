// Title: Potentially Suspicious Windows App Activity
// ID: f91ed517-a6ba-471d-9910-b3b4a398c0f3
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-12
// Tags: attack.stealth
// Description: Detects potentially suspicious child process of applications launched from inside the WindowsApps directory. This could be a sign of a rogue ".appx" package installation/execution
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path contains "C:\\Program Files\\WindowsApps\\") and (((action_process_image_command_line contains "cmd /c" or action_process_image_command_line contains "Invoke-" or action_process_image_command_line contains "Base64")) or ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe"))) and not (((actor_process_image_path startswith "C:\\Program Files\\WindowsApps\\Microsoft.SysinternalsSuite" and action_process_image_path endswith "\\cmd.exe") or (actor_process_image_path contains ":\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal" and actor_process_image_path endswith "\\WindowsTerminal.exe" and (action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\pwsh.exe")))))
