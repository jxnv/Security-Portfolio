-- Title: Modify User Shell Folders Startup Value
-- ID: 9c226817-8dc9-46c2-a58d-66655aafd7dc
-- Status: test
-- Level: high
-- Author: frack113, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2022-10-01
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1547.001
-- Description: Detect modification of the User Shell Folders registry values for Startup or Common Startup which could indicate persistence attempts.
-- Attackers may modify User Shell Folders registry keys to point to malicious executables or scripts that will be executed during startup.
-- This technique is often used to maintain persistence on a compromised system by ensuring that the malicious payload is executed automatically.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders%' OR TargetObject ILIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders%') AND (TargetObject ILIKE '%\\Common Startup' OR TargetObject ILIKE '%\\Startup')) AND NOT (((Details IS NULL) OR ((Details ILIKE '%C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%' OR Details ILIKE '%%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%')) OR ((Details ILIKE '%%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%' OR Details ILIKE '%%%USERPROFILE%%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%')) OR ((Details ILIKE '%C:\\Users\\%' AND Details ILIKE '%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%')))))
