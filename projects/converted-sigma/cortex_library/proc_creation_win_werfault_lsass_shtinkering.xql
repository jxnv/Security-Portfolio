// Title: Potential Credential Dumping Via WER
// ID: 9a4ccd1a-3526-4d99-b980-9f9c5d3a6ff3
// Status: test
// Level: high
// Author: @pbssubhash , Nasreddine Bencherchali
// Date: 2022-12-08
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects potential credential dumping via Windows Error Reporting LSASS Shtinkering technique which uses the Windows Error Reporting to dump lsass
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((ParentUser contains "AUTHORI" or ParentUser contains "AUTORI") and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI") and (action_process_image_command_line contains " -u -p " and action_process_image_command_line contains " -ip " and action_process_image_command_line contains " -s ")) and ((action_process_image_path endswith "\\Werfault.exe") or (action_process_image_name = "WerFault.exe"))) and not ((actor_process_image_path = "C:\\Windows\\System32\\lsass.exe")))
