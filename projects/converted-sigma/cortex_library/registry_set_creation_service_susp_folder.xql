// Title: Service Binary in Suspicious Folder
// ID: a07f0359-4c90-4dc4-a681-8ffea40b4f47
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), frack113
// Date: 2022-05-02
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detect the creation of a service with a service binary located in a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject startswith "HKLM\\System\\CurrentControlSet\\Services\\" and TargetObject endswith "\\ImagePath" and (Details contains "\\Users\\Public\\" or Details contains "\\Perflogs\\" or Details contains "\\ADMIN$\\" or Details contains "\\Temp\\")) or (TargetObject startswith "HKLM\\System\\CurrentControlSet\\Services\\" and TargetObject endswith "\\Start" and (action_process_image_path contains "\\Users\\Public\\" or action_process_image_path contains "\\Perflogs\\" or action_process_image_path contains "\\ADMIN$\\" or action_process_image_path contains "\\Temp\\") and (Details = "DWORD (0x00000000)" or Details = "DWORD (0x00000001)" or Details = "DWORD (0x00000002)"))) and not ((((action_process_image_path contains "\\Common Files\\" and action_process_image_path contains "\\Temp\\")) or (TargetObject endswith "\\CurrentControlSet\\Services\\MBAMInstallerService\\ImagePath" and Details endswith "\\AppData\\Local\\Temp\\MBAMInstallerService.exe\"" and action_process_image_path = "C:\\Windows\\system32\\services.exe"))))
