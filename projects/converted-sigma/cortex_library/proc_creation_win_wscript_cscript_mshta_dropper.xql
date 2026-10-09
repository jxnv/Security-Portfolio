// Title: Potential Dropper Script Execution Via WScript/CScript/MSHTA
// ID: cea72823-df4d-4567-950c-0b579eaf0846
// Status: test
// Level: medium
// Author: Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems), Dave Johnson
// Date: 2019-01-16
// Tags: attack.execution, attack.t1059.005, attack.t1059.007
// Description: Detects wscript/cscript/mshta executions of scripts located in user directories
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe")) and ((action_process_image_command_line contains ".hta" or action_process_image_command_line contains ".js" or action_process_image_command_line contains ".jse" or action_process_image_command_line contains ".vba" or action_process_image_command_line contains ".vbe" or action_process_image_command_line contains ".vbs" or action_process_image_command_line contains ".wsf" or action_process_image_command_line contains ".wsh")) and ((action_process_image_command_line contains ":\\Perflogs\\" or action_process_image_command_line contains ":\\Temp\\" or action_process_image_command_line contains ":\\Tmp\\" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\AppData\\Roaming\\Temp\\" or action_process_image_command_line contains "\\Start Menu\\Programs\\Startup\\" or action_process_image_command_line contains "\\Temporary Internet" or action_process_image_command_line contains "\\Windows\\Temp" or action_process_image_command_line contains "%LocalAppData%\\Temp\\" or action_process_image_command_line contains "%TEMP%" or action_process_image_command_line contains "%TMP%")))
