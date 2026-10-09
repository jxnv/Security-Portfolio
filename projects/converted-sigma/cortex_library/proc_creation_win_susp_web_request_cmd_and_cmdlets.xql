// Title: Usage Of Web Request Commands And Cmdlets
// ID: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
// Status: test
// Level: medium
// Author: James Pemberton / @4A616D6573, Endgame, JHasenbusch, oscd.community, Austin Songer @austinsonger
// Date: 2019-10-24
// Tags: attack.execution, attack.t1059.001
// Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "[System.Net.WebRequest]::create" or action_process_image_command_line contains "curl " or action_process_image_command_line contains "Invoke-RestMethod" or action_process_image_command_line contains "Invoke-WebRequest" or action_process_image_command_line contains " irm " or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "Resume-BitsTransfer" or action_process_image_command_line contains "Start-BitsTransfer" or action_process_image_command_line contains "wget " or action_process_image_command_line contains "WinHttp.WinHttpRequest"))
