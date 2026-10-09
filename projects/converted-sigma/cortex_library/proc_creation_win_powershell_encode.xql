// Title: Suspicious Execution of Powershell with Base64
// ID: fb843269-508c-4b76-8b8d-88679db22ce7
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-02
// Tags: attack.execution, attack.t1059.001
// Description: Commandline to launch powershell with a base64 payload
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains " -e " or action_process_image_command_line contains " -en " or action_process_image_command_line contains " -enc " or action_process_image_command_line contains " -enco" or action_process_image_command_line contains " -ec ")) and not ((((actor_process_image_path contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or actor_process_image_path contains "\\gc_worker.exe")) or (action_process_image_command_line contains " -Encoding "))))
