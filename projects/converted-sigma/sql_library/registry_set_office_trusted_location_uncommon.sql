-- Title: Uncommon Microsoft Office Trusted Location Added
-- ID: f742bde7-9528-42e5-bd82-84f51a8387d2
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-21
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects changes to registry keys related to "Trusted Location" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%Security\\Trusted Locations\\Location%' AND TargetObject ILIKE '%\\Path') AND NOT ((((Image ILIKE '%:\\Program Files\\Microsoft Office\\%' OR Image ILIKE '%:\\Program Files (x86)\\Microsoft Office\\%')) OR (Image ILIKE '%:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\%' AND Image ILIKE '%\\OfficeClickToRun.exe'))) AND NOT (((Details ILIKE '%%APPDATA%\\Microsoft\\Templates%' OR Details ILIKE '%%%APPDATA%%\\Microsoft\\Templates%' OR Details ILIKE '%%APPDATA%\\Microsoft\\Word\\Startup%' OR Details ILIKE '%%%APPDATA%%\\Microsoft\\Word\\Startup%' OR Details ILIKE '%:\\Program Files (x86)\\Microsoft Office\\root\\Templates\\%' OR Details ILIKE '%:\\Program Files\\Microsoft Office (x86)\\Templates%' OR Details ILIKE '%:\\Program Files\\Microsoft Office\\root\\Templates\\%' OR Details ILIKE '%:\\Program Files\\Microsoft Office\\Templates\\%'))))
