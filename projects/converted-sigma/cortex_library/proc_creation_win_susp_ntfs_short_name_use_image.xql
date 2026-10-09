// Title: Use NTFS Short Name in Image
// ID: 3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-06
// Tags: attack.stealth, attack.t1564.004
// Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path contains "~1.bat" or action_process_image_path contains "~1.dll" or action_process_image_path contains "~1.exe" or action_process_image_path contains "~1.hta" or action_process_image_path contains "~1.js" or action_process_image_path contains "~1.msi" or action_process_image_path contains "~1.ps1" or action_process_image_path contains "~1.tmp" or action_process_image_path contains "~1.vbe" or action_process_image_path contains "~1.vbs" or action_process_image_path contains "~2.bat" or action_process_image_path contains "~2.dll" or action_process_image_path contains "~2.exe" or action_process_image_path contains "~2.hta" or action_process_image_path contains "~2.js" or action_process_image_path contains "~2.msi" or action_process_image_path contains "~2.ps1" or action_process_image_path contains "~2.tmp" or action_process_image_path contains "~2.vbe" or action_process_image_path contains "~2.vbs")) and not ((actor_process_image_path = "C:\\Windows\\explorer.exe")) and not (((actor_process_image_path endswith "\\thor\\thor64.exe") or (action_process_image_path endswith "\\VCREDI~1.EXE") or (actor_process_image_path endswith "\\WebEx\\WebexHost.exe") or (action_process_image_path = "C:\\PROGRA~1\\WinZip\\WZPREL~1.EXE"))))
