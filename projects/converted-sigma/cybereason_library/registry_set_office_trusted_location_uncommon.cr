// Title: Uncommon Microsoft Office Trusted Location Added
// ID: f742bde7-9528-42e5-bd82-84f51a8387d2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-21
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects changes to registry keys related to "Trusted Location" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject contains "Security\\Trusted Locations\\Location" AND TargetObject="*\\Path") AND NOT ((((Image contains ":\\Program Files\\Microsoft Office\\" OR Image contains ":\\Program Files (x86)\\Microsoft Office\\")) OR (Image contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" AND Image="*\\OfficeClickToRun.exe"))) AND NOT (((Details contains "%APPDATA%\\Microsoft\\Templates" OR Details contains "%%APPDATA%%\\Microsoft\\Templates" OR Details contains "%APPDATA%\\Microsoft\\Word\\Startup" OR Details contains "%%APPDATA%%\\Microsoft\\Word\\Startup" OR Details contains ":\\Program Files (x86)\\Microsoft Office\\root\\Templates\\" OR Details contains ":\\Program Files\\Microsoft Office (x86)\\Templates" OR Details contains ":\\Program Files\\Microsoft Office\\root\\Templates\\" OR Details contains ":\\Program Files\\Microsoft Office\\Templates\\"))))
