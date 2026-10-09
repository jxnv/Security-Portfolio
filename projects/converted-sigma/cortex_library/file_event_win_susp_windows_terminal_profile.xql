// Title: Windows Terminal Profile Settings Modification By Uncommon Process
// ID: 9b64de98-9db3-4033-bd7a-f51430105f00
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-22
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.015
// Description: Detects the creation or modification of the Windows Terminal Profile settings file "settings.json" by an uncommon process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wscript.exe") and action_file_path endswith "\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\LocalState\\settings.json")
