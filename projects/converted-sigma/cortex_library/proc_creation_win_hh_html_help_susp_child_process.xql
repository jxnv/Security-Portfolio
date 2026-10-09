// Title: HTML Help HH.EXE Suspicious Child Process
// ID: 52cad028-0ff0-4854-8f67-d25dfcbc78b4
// Status: test
// Level: high
// Author: Maxim Pavlunin, Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-04-01
// Tags: attack.execution, attack.initial-access, attack.stealth, attack.t1047, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.007, attack.t1218, attack.t1218.001, attack.t1218.010, attack.t1218.011, attack.t1566, attack.t1566.001
// Description: Detects a suspicious child process of a Microsoft HTML Help (HH.exe)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\hh.exe" and (action_process_image_path endswith "\\CertReq.exe" or action_process_image_path endswith "\\CertUtil.exe" or action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\installutil.exe" or action_process_image_path endswith "\\MSbuild.exe" or action_process_image_path endswith "\\MSHTA.EXE" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe"))
