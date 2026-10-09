// Title: Suspicious AddinUtil.EXE CommandLine Execution
// ID: 631b22a4-70f4-4e2f-9ea8-42f84d9df6d8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
// Date: 2023-09-18
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with suspicious Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\addinutil.exe") or (action_process_image_name = "AddInUtil.exe")) and ((((action_process_image_command_line contains "-AddInRoot:" or action_process_image_command_line contains "-PipelineRoot:")) and ((action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Windows\\Temp\\"))) or ((action_process_image_command_line contains "-AddInRoot:." or action_process_image_command_line contains "-AddInRoot:\".\"" or action_process_image_command_line contains "-PipelineRoot:." or action_process_image_command_line contains "-PipelineRoot:\".\"") and (CurrentDirectory contains "\\AppData\\Local\\Temp\\" or CurrentDirectory contains "\\Desktop\\" or CurrentDirectory contains "\\Downloads\\" or CurrentDirectory contains "\\Users\\Public\\" or CurrentDirectory contains "\\Windows\\Temp\\"))))
