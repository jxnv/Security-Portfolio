// Title: Process Creation Using Sysnative Folder
// ID: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
// Status: test
// Level: medium
// Author: Max Altgelt (Nextron Systems)
// Date: 2022-08-23
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ":\\Windows\\Sysnative\\") or (action_process_image_path contains ":\\Windows\\Sysnative\\")) and not (((action_process_image_path contains "C:\\Windows\\Microsoft.NET\\Framework64\\v" or action_process_image_path contains "C:\\Windows\\Microsoft.NET\\Framework\\v" or action_process_image_path contains "C:\\Windows\\Microsoft.NET\\FrameworkArm\\v" or action_process_image_path contains "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v") and action_process_image_path endswith "\\ngen.exe" and action_process_image_command_line contains "install")) and not (((action_process_image_command_line contains "\"C:\\Windows\\sysnative\\cmd.exe\"" and action_process_image_command_line contains "\\xampp\\" and action_process_image_command_line contains "\\catalina_start.bat"))))
