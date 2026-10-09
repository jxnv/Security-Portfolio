// Title: Uncommon Child Process Of Appvlp.EXE
// ID: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-03-13
// Tags: attack.stealth, attack.t1218, attack.execution
// Description: Detects uncommon child processes of Appvlp.EXE
// Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
// Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
// or to mark a file as a system file.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\appvlp.exe") and not (((action_process_image_path endswith ":\\Windows\\SysWOW64\\rundll32.exe" or action_process_image_path endswith ":\\Windows\\System32\\rundll32.exe"))) and not (((action_process_image_path contains ":\\Program Files\\Microsoft Office" and action_process_image_path endswith "\\msoasb.exe") or (action_process_image_path contains ":\\Program Files\\Microsoft Office" and action_process_image_path endswith "\\MSOUC.EXE") or ((action_process_image_path contains ":\\Program Files\\Microsoft Office" and action_process_image_path contains "\\SkypeSrv\\") and action_process_image_path endswith "\\SKYPESERVER.EXE"))))
