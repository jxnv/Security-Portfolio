// Title: Suspicious Outlook Child Process
// ID: 208748f7-881d-47ac-a29c-07ea84bf691d
// Status: test
// Level: high
// Author: Michael Haag, Florian Roth (Nextron Systems), Markus Neis, Elastic, FPT.EagleEye Team
// Date: 2022-02-28
// Tags: attack.execution, attack.t1204.002
// Description: Detects a suspicious process spawning from an Outlook process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\OUTLOOK.EXE" and (action_process_image_path endswith "\\AppVLP.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\hh.exe" or action_process_image_path endswith "\\mftrace.exe" or action_process_image_path endswith "\\msbuild.exe" or action_process_image_path endswith "\\msdt.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\scrcons.exe" or action_process_image_path endswith "\\scriptrunner.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\svchost.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe"))
