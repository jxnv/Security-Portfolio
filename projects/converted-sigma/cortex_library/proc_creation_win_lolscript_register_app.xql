// Title: Potential Register_App.Vbs LOLScript Abuse
// ID: 28c8f68b-098d-45af-8d43-8089f3e35403
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-11-05
// Tags: attack.stealth, attack.t1218
// Description: Detects potential abuse of the "register_app.vbs" script that is part of the Windows SDK. The script offers the capability to register new VSS/VDS Provider as a COM+ application. Attackers can use this to install malicious DLLs for persistence and execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains ".vbs -register ") and (((action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\wscript.exe")) or ((action_process_image_name = "cscript.exe" or action_process_image_name = "wscript.exe"))))
