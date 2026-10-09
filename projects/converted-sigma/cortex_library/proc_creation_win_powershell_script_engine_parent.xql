// Title: Suspicious PowerShell Invocation From Script Engines
// ID: 95eadcb2-92e4-4ed1-9031-92547773a6db
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-01-16
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious powershell invocations from interpreters or unusual programs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\wscript.exe" or actor_process_image_path endswith "\\cscript.exe") and (action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) and not ((CurrentDirectory contains "\\Health Service State\\")))
