// Title: Suspicious Use of CSharp Interactive Console
// ID: a9e416a8-e613-4f8b-88b8-a7d1d1af2f61
// Status: test
// Level: high
// Author: Michael R. (@nahamike01)
// Date: 2020-03-08
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects the execution of CSharp interactive console by PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\csi.exe" and (actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe" or actor_process_image_path endswith "\\powershell_ise.exe") and action_process_image_name = "csi.exe")
