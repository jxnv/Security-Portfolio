// Title: Potentially Suspicious Mofcomp Execution
// ID: 1dd05363-104e-4b4a-b963-196a534b03a1
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-12
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline.
// The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
// Attackers abuse this utility to install malicious MOF scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\wsl.exe" or actor_process_image_path endswith "\\wscript.exe" or actor_process_image_path endswith "\\cscript.exe")) or ((action_process_image_command_line contains "\\AppData\\Local\\Temp" or action_process_image_command_line contains "\\Contacts\\" or action_process_image_command_line contains "\\Favorites\\" or action_process_image_command_line contains "\\Favourites\\" or action_process_image_command_line contains "\\Music\\" or action_process_image_command_line contains "\\Pictures\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Videos\\" or action_process_image_command_line contains "\\WINDOWS\\Temp\\" or action_process_image_command_line contains "%appdata%" or action_process_image_command_line contains "%temp%" or action_process_image_command_line contains "%tmp%"))) and ((action_process_image_path endswith "\\mofcomp.exe") or (action_process_image_name = "mofcomp.exe"))) and not (((actor_process_command_line endswith "\\InstallUtil.exe /Uninstall C:\\Windows\\CCM\\Microsoft.ConfigurationManager.SVProvider.dll" and actor_process_image_path endswith "\\InstallUtil.exe" and (action_process_image_command_line contains "C:\\Windows\\TEMP" and action_process_image_command_line contains ".tmp")) or (actor_process_image_path = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" and action_process_image_command_line contains "C:\\Windows\\TEMP\\" and action_process_image_command_line endswith ".mof"))) and not ((actor_process_command_line = null)))
