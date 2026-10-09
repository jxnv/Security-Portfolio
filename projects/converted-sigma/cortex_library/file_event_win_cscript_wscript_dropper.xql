// Title: WScript or CScript Dropper - File
// ID: 002bdb95-0cf1-46a6-9e08-d38c128a6127
// Status: test
// Level: high
// Author: Tim Shelton
// Date: 2022-01-10
// Tags: attack.execution, attack.t1059.005, attack.t1059.007
// Description: Detects a file ending in jse, vbe, js, vba, vbs, wsf, wsh written by cscript.exe or wscript.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe") and (action_file_path contains ":\\Perflogs\\" or action_file_path contains ":\\ProgramData\\" or action_file_path contains ":\\Temp\\" or action_file_path contains ":\\Tmp\\" or action_file_path contains ":\\Users\\" or action_file_path contains ":\\Windows\\Temp\\" or action_file_path contains "\\AppData\\Local\\Temp" or action_file_path contains "\\AppData\\Roaming\\Temp" or action_file_path contains "\\Start Menu\\Programs\\Startup\\" or action_file_path contains "\\Temporary Internet") and (action_file_path endswith ".js" or action_file_path endswith ".jse" or action_file_path endswith ".vba" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs" or action_file_path endswith ".wsf" or action_file_path endswith ".wsh"))
