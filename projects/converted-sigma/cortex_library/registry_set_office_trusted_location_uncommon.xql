// Title: Uncommon Microsoft Office Trusted Location Added
// ID: f742bde7-9528-42e5-bd82-84f51a8387d2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-21
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects changes to registry keys related to "Trusted Location" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "Security\\Trusted Locations\\Location" and TargetObject endswith "\\Path") and not ((((action_process_image_path contains ":\\Program Files\\Microsoft Office\\" or action_process_image_path contains ":\\Program Files (x86)\\Microsoft Office\\")) or (action_process_image_path contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" and action_process_image_path endswith "\\OfficeClickToRun.exe"))) and not (((Details contains "%APPDATA%\\Microsoft\\Templates" or Details contains "%%APPDATA%%\\Microsoft\\Templates" or Details contains "%APPDATA%\\Microsoft\\Word\\Startup" or Details contains "%%APPDATA%%\\Microsoft\\Word\\Startup" or Details contains ":\\Program Files (x86)\\Microsoft Office\\root\\Templates\\" or Details contains ":\\Program Files\\Microsoft Office (x86)\\Templates" or Details contains ":\\Program Files\\Microsoft Office\\root\\Templates\\" or Details contains ":\\Program Files\\Microsoft Office\\Templates\\"))))
