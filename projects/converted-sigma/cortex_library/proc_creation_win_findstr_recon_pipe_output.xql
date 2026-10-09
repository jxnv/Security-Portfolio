// Title: Recon Command Output Piped To Findstr.EXE
// ID: ccb5742c-c248-4982-8c5c-5571b9275ad3
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2023-07-06
// Tags: attack.discovery, attack.t1057
// Description: Detects the execution of a potential recon command where the results are piped to "findstr". This is meant to trigger on inline calls of "cmd.exe" via the "/c" or "/k" for example.
// Attackers often time use this technique to extract specific information they require in their reconnaissance phase.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ipconfig*|*find" or action_process_image_command_line contains "net*|*find" or action_process_image_command_line contains "netstat*|*find" or action_process_image_command_line contains "ping*|*find" or action_process_image_command_line contains "systeminfo*|*find" or action_process_image_command_line contains "tasklist*|*find" or action_process_image_command_line contains "whoami*|*find")) and not (((action_process_image_command_line contains "cmd.exe /c TASKLIST /V |" and action_process_image_command_line contains "FIND /I" and action_process_image_command_line contains "\\xampp\\" and action_process_image_command_line contains "\\catalina_start.bat"))))
