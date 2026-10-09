// Title: Access To Potentially Sensitive Sysvol Files By Uncommon Applications
// ID: d51694fe-484a-46ac-92d6-969e76d60d10
// Status: test
// Level: medium
// Author: frack113
// Date: 2023-12-21
// Tags: attack.credential-access, attack.t1552.006
// Description: Detects file access requests to potentially sensitive files hosted on the Windows Sysvol share.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((FileName startswith "\\\\" and (FileName contains "\\sysvol\\" and FileName contains "\\Policies\\") and (FileName endswith "audit.csv" or FileName endswith "Files.xml" or FileName endswith "GptTmpl.inf" or FileName endswith "groups.xml" or FileName endswith "Registry.pol" or FileName endswith "Registry.xml" or FileName endswith "scheduledtasks.xml" or FileName endswith "scripts.ini" or FileName endswith "services.xml")) and not (((action_process_image_path = "C:\\Windows\\explorer.exe") or ((action_process_image_path startswith "C:\\Program Files (x86)\\" or action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Windows\\system32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")))))
