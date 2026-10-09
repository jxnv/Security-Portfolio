// Title: Use NTFS Short Name in Command Line
// ID: dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-05
// Tags: attack.stealth, attack.t1564.004
// Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "~1.exe" or action_process_image_command_line contains "~1.bat" or action_process_image_command_line contains "~1.msi" or action_process_image_command_line contains "~1.vbe" or action_process_image_command_line contains "~1.vbs" or action_process_image_command_line contains "~1.dll" or action_process_image_command_line contains "~1.ps1" or action_process_image_command_line contains "~1.js" or action_process_image_command_line contains "~1.hta" or action_process_image_command_line contains "~2.exe" or action_process_image_command_line contains "~2.bat" or action_process_image_command_line contains "~2.msi" or action_process_image_command_line contains "~2.vbe" or action_process_image_command_line contains "~2.vbs" or action_process_image_command_line contains "~2.dll" or action_process_image_command_line contains "~2.ps1" or action_process_image_command_line contains "~2.js" or action_process_image_command_line contains "~2.hta")) and not ((((actor_process_image_path endswith "\\WebEx\\WebexHost.exe" or actor_process_image_path endswith "\\thor\\thor64.exe")) or (action_process_image_command_line contains "C:\\xampp\\vcredist\\VCREDI~1.EXE"))))
