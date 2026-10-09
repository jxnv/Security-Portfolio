// Title: Use Short Name Path in Image
// ID: a96970af-f126-420d-90e1-d37bf25e50e1
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-08-07
// Tags: attack.stealth, attack.t1564.004
// Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path contains "~1\\" or action_process_image_path contains "~2\\")) and not (((((action_process_image_path contains "\\AppData\\" and action_process_image_path contains "\\Temp\\")) or ((action_process_image_path endswith "~1\\unzip.exe" or action_process_image_path endswith "~1\\7zG.exe"))) or ((actor_process_image_path = "C:\\Windows\\System32\\Dism.exe" or actor_process_image_path = "C:\\Windows\\System32\\cleanmgr.exe")))) and not ((((Product = "InstallShield (R)") or (Description = "InstallShield (R) Setup Engine") or (Company = "InstallShield Software Corporation")) or (actor_process_image_path endswith "\\thor\\thor64.exe") or (actor_process_image_path endswith "\\WebEx\\WebexHost.exe"))))
