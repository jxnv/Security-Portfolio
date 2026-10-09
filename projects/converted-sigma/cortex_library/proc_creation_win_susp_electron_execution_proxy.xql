// Title: Potentially Suspicious Electron Application CommandLine
// ID: 378a05d8-963c-46c9-bcce-13c7657eac99
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-05
// Tags: attack.execution
// Description: Detects potentially suspicious CommandLine of electron apps (teams, discord, slack, etc.). This could be a sign of abuse to proxy execution through a signed binary.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "--browser-subprocess-path" or action_process_image_command_line contains "--gpu-launcher" or action_process_image_command_line contains "--renderer-cmd-prefix" or action_process_image_command_line contains "--utility-cmd-prefix")) and (((action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\code.exe" or action_process_image_path endswith "\\discord.exe" or action_process_image_path endswith "\\GitHubDesktop.exe" or action_process_image_path endswith "\\keybase.exe" or action_process_image_path endswith "\\msedge_proxy.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\msedgewebview2.exe" or action_process_image_path endswith "\\msteams.exe" or action_process_image_path endswith "\\slack.exe" or action_process_image_path endswith "\\Teams.exe")) or ((action_process_image_name = "chrome.exe" or action_process_image_name = "code.exe" or action_process_image_name = "discord.exe" or action_process_image_name = "GitHubDesktop.exe" or action_process_image_name = "keybase.exe" or action_process_image_name = "msedge_proxy.exe" or action_process_image_name = "msedge.exe" or action_process_image_name = "msedgewebview2.exe" or action_process_image_name = "msteams.exe" or action_process_image_name = "slack.exe" or action_process_image_name = "Teams.exe"))))
