// Title: Suspicious DotNET CLR Usage Log Artifact
// ID: e0b06658-7d1d-4cd3-bf15-03467507ff7c
// Status: test
// Level: high
// Author: frack113, omkar72, oscd.community, Wojciech Lesicki
// Date: 2022-11-18
// Tags: attack.stealth, attack.t1218
// Description: Detects the creation of Usage Log files by the CLR (clr.dll). These files are named after the executing process once the assembly is finished executing for the first time in the (user) session context.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\UsageLogs\\cmstp.exe.log" or action_file_path endswith "\\UsageLogs\\cscript.exe.log" or action_file_path endswith "\\UsageLogs\\mshta.exe.log" or action_file_path endswith "\\UsageLogs\\msxsl.exe.log" or action_file_path endswith "\\UsageLogs\\regsvr32.exe.log" or action_file_path endswith "\\UsageLogs\\rundll32.exe.log" or action_file_path endswith "\\UsageLogs\\svchost.exe.log" or action_file_path endswith "\\UsageLogs\\wscript.exe.log" or action_file_path endswith "\\UsageLogs\\wmic.exe.log")) and not ((actor_process_image_path endswith "\\MsiExec.exe" and actor_process_command_line contains " -Embedding" and action_process_image_path endswith "\\rundll32.exe" and (action_process_image_command_line contains "Temp" and action_process_image_command_line contains "zzzzInvokeManagedCustomActionOutOfProc"))))
