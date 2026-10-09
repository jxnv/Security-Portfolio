// Title: Suspicious Electron Application Child Processes
// ID: f26eb764-fd89-464b-85e2-dc4a8e6e77b8
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-21
// Tags: attack.execution
// Description: Detects suspicious child processes of electron apps (teams, discord, slack, etc.). This could be a potential sign of ".asar" file tampering (See reference section for more information) or binary execution proxy through specific CLI arguments (see related rule)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\chrome.exe" or actor_process_image_path endswith "\\discord.exe" or actor_process_image_path endswith "\\GitHubDesktop.exe" or actor_process_image_path endswith "\\keybase.exe" or actor_process_image_path endswith "\\msedge.exe" or actor_process_image_path endswith "\\msedgewebview2.exe" or actor_process_image_path endswith "\\msteams.exe" or actor_process_image_path endswith "\\slack.exe" or actor_process_image_path endswith "\\teams.exe")) and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_path contains ":\\ProgramData\\" or action_process_image_path contains ":\\Temp\\" or action_process_image_path contains "\\AppData\\Local\\Temp\\" or action_process_image_path contains "\\Users\\Public\\" or action_process_image_path contains "\\Windows\\Temp\\"))) and not ((actor_process_image_path endswith "\\Discord.exe" and action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line contains "\\NVSMI\\nvidia-smi.exe")))
