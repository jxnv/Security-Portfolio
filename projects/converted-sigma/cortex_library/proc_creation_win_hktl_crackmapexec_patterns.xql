// Title: HackTool - CrackMapExec Process Patterns
// ID: f26307d8-14cd-47e3-a26b-4b4769f24af6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-12
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects suspicious process patterns found in logs when CrackMapExec is used
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "tasklist /fi " and action_process_image_command_line contains "Imagename eq lsass.exe") and (action_process_image_command_line contains "cmd.exe /c " or action_process_image_command_line contains "cmd.exe /r " or action_process_image_command_line contains "cmd.exe /k " or action_process_image_command_line contains "cmd /c " or action_process_image_command_line contains "cmd /r " or action_process_image_command_line contains "cmd /k ") and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI")) or ((action_process_image_command_line contains "do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump" and action_process_image_command_line contains "\\Windows\\Temp\\" and action_process_image_command_line contains " full" and action_process_image_command_line contains "%%B")) or ((action_process_image_command_line contains "tasklist /v /fo csv" and action_process_image_command_line contains "findstr /i \"lsass\"")))
