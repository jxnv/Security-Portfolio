// Title: Potential DLL File Download Via PowerShell Invoke-WebRequest
// ID: 0f0450f3-8b47-441e-a31b-15a91dc243e2
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Hieu Tran
// Date: 2023-03-13
// Tags: attack.command-and-control, attack.execution, attack.t1059.001, attack.t1105
// Description: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Invoke-RestMethod " or action_process_image_command_line contains "Invoke-WebRequest " or action_process_image_command_line contains "IRM " or action_process_image_command_line contains "IWR ") and (action_process_image_command_line contains "http" and action_process_image_command_line contains "OutFile" and action_process_image_command_line contains ".dll"))
