// Title: Windows Shell/Scripting Application File Write to Suspicious Folder
// ID: 1277f594-a7d1-4f28-a2d3-73af5cbeab43
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-11-20
// Tags: attack.execution, attack.t1059
// Description: Detects Windows shells and scripting applications that write files to suspicious folders
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\msbuild.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\wscript.exe") and (action_file_path startswith "C:\\PerfLogs\\" or action_file_path startswith "C:\\Users\\Public\\")) or ((action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\scriptrunner.exe" or action_process_image_path endswith "\\wmic.exe") and (action_file_path contains "C:\\PerfLogs\\" or action_file_path contains "C:\\Users\\Public\\" or action_file_path contains "C:\\Windows\\Temp\\")))
