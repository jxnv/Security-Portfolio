// Title: Shell32 DLL Execution in Suspicious Directory
// ID: 32b96012-7892-429e-b26c-ac2bf46066ff
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-11-24
// Tags: attack.execution, attack.stealth, attack.t1218.011
// Description: Detects shell32.dll executing a DLL in a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "shell32.dll" and action_process_image_command_line contains "Control_RunDLL") and (action_process_image_command_line contains "%AppData%" or action_process_image_command_line contains "%LocalAppData%" or action_process_image_command_line contains "%Temp%" or action_process_image_command_line contains "%tmp%" or action_process_image_command_line contains "\\AppData\\" or action_process_image_command_line contains "\\Temp\\" or action_process_image_command_line contains "\\Users\\Public\\")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
