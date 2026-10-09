// Title: Use of Scriptrunner.exe
// ID: 64760eef-87f7-4ed3-93fd-655668ea9420
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-01
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -appvscript ") and ((action_process_image_path endswith "\\ScriptRunner.exe") or (action_process_image_name = "ScriptRunner.exe")))
