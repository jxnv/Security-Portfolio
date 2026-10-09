-- Title: FileFix - Command Evidence in TypedPaths
-- ID: 4fee3d51-8069-4a4c-a0f7-924fcaff2c70
-- Status: experimental
-- Level: high
-- Author: Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-07-05
-- Tags: attack.execution, attack.t1204.004
-- Description: Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1" AND (Details LIKE '%#%' AND Details LIKE '%http%')) AND (((Details LIKE '%account%' OR Details LIKE '%anti-bot%' OR Details LIKE '%botcheck%' OR Details LIKE '%captcha%' OR Details LIKE '%challenge%' OR Details LIKE '%confirmation%' OR Details LIKE '%fraud%' OR Details LIKE '%human%' OR Details LIKE '%identification%' OR Details LIKE '%identificator%' OR Details LIKE '%identity%' OR Details LIKE '%robot%' OR Details LIKE '%validation%' OR Details LIKE '%verification%' OR Details LIKE '%verify%')) OR ((Details LIKE '%%comspec%%' OR Details LIKE '%bitsadmin%' OR Details LIKE '%certutil%' OR Details LIKE '%cmd%' OR Details LIKE '%cscript%' OR Details LIKE '%curl%' OR Details LIKE '%finger%' OR Details LIKE '%mshta%' OR Details LIKE '%powershell%' OR Details LIKE '%pwsh%' OR Details LIKE '%regsvr32%' OR Details LIKE '%rundll32%' OR Details LIKE '%schtasks%' OR Details LIKE '%wget%' OR Details LIKE '%wscript%'))))
