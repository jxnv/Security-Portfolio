-- Title: FileFix - Command Evidence in TypedPaths
-- ID: 4fee3d51-8069-4a4c-a0f7-924fcaff2c70
-- Status: experimental
-- Level: high
-- Author: Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-07-05
-- Tags: attack.execution, attack.t1204.004
-- Description: Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1' AND (Details ILIKE '%#%' AND Details ILIKE '%http%')) AND (((Details ILIKE '%account%' OR Details ILIKE '%anti-bot%' OR Details ILIKE '%botcheck%' OR Details ILIKE '%captcha%' OR Details ILIKE '%challenge%' OR Details ILIKE '%confirmation%' OR Details ILIKE '%fraud%' OR Details ILIKE '%human%' OR Details ILIKE '%identification%' OR Details ILIKE '%identificator%' OR Details ILIKE '%identity%' OR Details ILIKE '%robot%' OR Details ILIKE '%validation%' OR Details ILIKE '%verification%' OR Details ILIKE '%verify%')) OR ((Details ILIKE '%%comspec%%' OR Details ILIKE '%bitsadmin%' OR Details ILIKE '%certutil%' OR Details ILIKE '%cmd%' OR Details ILIKE '%cscript%' OR Details ILIKE '%curl%' OR Details ILIKE '%finger%' OR Details ILIKE '%mshta%' OR Details ILIKE '%powershell%' OR Details ILIKE '%pwsh%' OR Details ILIKE '%regsvr32%' OR Details ILIKE '%rundll32%' OR Details ILIKE '%schtasks%' OR Details ILIKE '%wget%' OR Details ILIKE '%wscript%'))))
