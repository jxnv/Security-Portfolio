// Title: Internet Explorer DisableFirstRunCustomize Enabled
// ID: ab567429-1dfb-4674-b6d2-979fd2f9d125
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-16
// Tags: attack.defense-impairment
// Description: Detects changes to the Internet Explorer "DisableFirstRunCustomize" value, which prevents Internet Explorer from running the first run wizard the first time a user starts the browser after installing Internet Explorer or Windows.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject endswith "\\Microsoft\\Internet Explorer\\Main\\DisableFirstRunCustomize" and (Details = "DWORD (0x00000001)" or Details = "DWORD (0x00000002)")) and not (((action_process_image_path = "C:\\Windows\\explorer.exe" or action_process_image_path = "C:\\Windows\\System32\\ie4uinit.exe"))) and not ((((action_process_image_path contains "\\Temp\\" and action_process_image_path contains "\\.cr\\avira_") and Details contains "DWORD (0x00000001)") or ((action_process_image_path = "C:\\Program Files (x86)\\Foxit Software\\Foxit PDF Reader\\FoxitPDFReader.exe" or action_process_image_path = "C:\\Program Files\\Foxit Software\\Foxit PDF Reader\\FoxitPDFReader.exe") and Details contains "DWORD (0x00000001)"))))
